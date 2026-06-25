import { writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import { initializeHubDatabase, type HubDatabase } from "../src/database/index";
import { finalizeMetricsArchive } from "../src/metrics-archive/finalizer";
import { runMetricsArchiveAttempt } from "../src/metrics-archive/runtime";
import type { MetricsArchivePlannedSample } from "../src/metrics-archive/writer";

const tempRoots: string[] = [];

describe("Metrics Archive runtime attempts", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("contains archive writer failures, keeps hot Metrics, records the failed run, and emits a system audit failure", async () => {
    const { archiveDirectory, database } =
      await createAttemptDatabase("writer-failure");
    const plan = createMonthlyPlan({
      archiveDirectory,
      samples: [
        recordSample(database, {
          bootId: "boot-writer-failure",
          collectedAtMs: Date.UTC(2024, 7, 12, 12),
          sequence: 1,
        }),
      ],
    });

    const result = runMetricsArchiveAttempt({
      database: database.sqlite,
      metricsArchives: database.metricsArchives,
      audit: database.audit,
      nowMs: Date.UTC(2024, 8, 1, 0, 1),
      plan,
      writer: () => {
        throw new Error("archive writer disk is full");
      },
    });

    expect(result).toEqual({
      ok: false,
      errorMessage: "archive writer disk is full",
      run: expect.objectContaining({
        errorMessage: "archive writer disk is full",
        status: "failed",
      }),
    });
    if (!("run" in result)) {
      throw new Error("Expected archive attempt to create a failed run.");
    }
    expect(sampleIdentities(database)).toEqual(["boot-writer-failure:1"]);
    expect(observationIdentities(database)).toEqual(["boot-writer-failure:1"]);
    expect(database.metricsArchives.findRun(result.run.id)).toEqual(result.run);
    expect(database.audit.recent(1)).toEqual([
      expect.objectContaining({
        action: "metrics_archive.failed",
        actor: "system",
        outcome: "failure",
        subjectId: String(result.run.id),
        subjectType: "metrics_archive_run",
      }),
    ]);

    database.close();
  });

  it("contains validation failures during finalization and keeps the affected range retryable", async () => {
    const { archiveDirectory, database } =
      await createAttemptDatabase("validation-failure");
    const plan = createMonthlyPlan({
      archiveDirectory,
      samples: [
        recordSample(database, {
          bootId: "boot-validation-failure",
          collectedAtMs: Date.UTC(2024, 7, 12, 12),
          sequence: 1,
        }),
      ],
    });

    const failed = runMetricsArchiveAttempt({
      database: database.sqlite,
      metricsArchives: database.metricsArchives,
      audit: database.audit,
      nowMs: Date.UTC(2024, 8, 1, 0, 1),
      plan,
      finalizer: (input) => {
        const archive = new DatabaseSync(input.tempPath);
        try {
          archive.prepare("delete from metric_samples").run();
        } finally {
          archive.close();
        }
        return finalizeMetricsArchive(input);
      },
    });

    expect(failed).toEqual({
      ok: false,
      errorMessage:
        "Metrics Archive validation failed: expected 1 metric_samples rows, found 0.",
      run: expect.objectContaining({
        errorMessage:
          "Metrics Archive validation failed: expected 1 metric_samples rows, found 0.",
        status: "failed",
      }),
    });
    expect(sampleIdentities(database)).toEqual(["boot-validation-failure:1"]);
    expect(observationIdentities(database)).toEqual([
      "boot-validation-failure:1",
    ]);
    expect(database.audit.recent(1)[0]).toEqual(
      expect.objectContaining({
        action: "metrics_archive.failed",
        actor: "system",
        outcome: "failure",
      }),
    );

    const retried = runMetricsArchiveAttempt({
      database: database.sqlite,
      metricsArchives: database.metricsArchives,
      audit: database.audit,
      nowMs: Date.UTC(2024, 8, 1, 0, 2),
      plan,
    });

    expect(retried).toEqual({
      ok: true,
      run: expect.objectContaining({
        status: "succeeded",
      }),
    });
    expect(sampleIdentities(database)).toEqual([]);
    expect(observationIdentities(database)).toEqual([]);
    expect(database.audit.recent()).toHaveLength(1);

    database.close();
  });

  it("contains cleanup refusal after archive publication without deleting hot Metrics", async () => {
    const { archiveDirectory, database } =
      await createAttemptDatabase("cleanup-refusal");
    const plan = createMonthlyPlan({
      archiveDirectory,
      samples: [
        recordSample(database, {
          bootId: "boot-cleanup-refusal",
          collectedAtMs: Date.UTC(2024, 7, 12, 12),
          sequence: 1,
        }),
      ],
    });

    const result = runMetricsArchiveAttempt({
      database: database.sqlite,
      metricsArchives: database.metricsArchives,
      audit: database.audit,
      nowMs: Date.UTC(2024, 8, 1, 0, 1),
      plan,
      cleanup: () => {
        throw new Error(
          "Metrics Archive cleanup refused: finalized archive checksum does not match the archive file.",
        );
      },
    });

    expect(result).toEqual({
      ok: false,
      errorMessage:
        "Metrics Archive cleanup refused: finalized archive checksum does not match the archive file.",
      run: expect.objectContaining({
        cleanupStatus: "failed",
        status: "succeeded",
      }),
    });
    expect(sampleIdentities(database)).toEqual(["boot-cleanup-refusal:1"]);
    expect(observationIdentities(database)).toEqual(["boot-cleanup-refusal:1"]);
    expect(database.audit.recent(1)[0]).toEqual(
      expect.objectContaining({
        action: "metrics_archive.failed",
        actor: "system",
        outcome: "failure",
      }),
    );

    database.close();
  });

  it("retries cleanup for the same range after a published archive cleanup refusal", async () => {
    const { archiveDirectory, database } = await createAttemptDatabase(
      "cleanup-refusal-retry",
    );
    const sample = recordSample(database, {
      bootId: "boot-cleanup-refusal-retry",
      collectedAtMs: Date.UTC(2024, 7, 12, 12),
      sequence: 1,
    });
    const firstPlan = createMonthlyPlan({
      archiveDirectory,
      samples: [sample],
    });

    const refused = runMetricsArchiveAttempt({
      database: database.sqlite,
      metricsArchives: database.metricsArchives,
      audit: database.audit,
      nowMs: Date.UTC(2024, 8, 1, 0, 1),
      plan: firstPlan,
      finalizer: (input) => {
        const run = finalizeMetricsArchive(input);
        writeFileSync(input.finalPath, "corrupted after publication");
        return run;
      },
    });

    expect(refused).toEqual({
      ok: false,
      errorMessage:
        "Metrics Archive cleanup refused: finalized archive checksum does not match the archive file.",
      run: expect.objectContaining({
        archivePath: firstPlan.identity.path,
        cleanupStatus: "failed",
        status: "succeeded",
      }),
    });
    expect(sampleIdentities(database)).toEqual([
      "boot-cleanup-refusal-retry:1",
    ]);
    expect(observationIdentities(database)).toEqual([
      "boot-cleanup-refusal-retry:1",
    ]);

    const retryPlan = createMonthlyPlan({
      archiveDirectory,
      samples: [sample],
      sequence: 2,
    });
    const retried = runMetricsArchiveAttempt({
      database: database.sqlite,
      metricsArchives: database.metricsArchives,
      audit: database.audit,
      nowMs: Date.UTC(2024, 8, 1, 0, 2),
      plan: retryPlan,
    });

    expect(retried).toEqual({
      ok: true,
      run: expect.objectContaining({
        archivePath: retryPlan.identity.path,
        cleanupStatus: "succeeded",
        status: "succeeded",
      }),
    });
    expect(sampleIdentities(database)).toEqual([]);
    expect(observationIdentities(database)).toEqual([]);
    expect(database.audit.recent()).toHaveLength(1);

    database.close();
  });

  it("does not emit a routine Audit Log event for successful archive attempts", async () => {
    const { archiveDirectory, database } =
      await createAttemptDatabase("success");
    const plan = createMonthlyPlan({
      archiveDirectory,
      samples: [
        recordSample(database, {
          bootId: "boot-success",
          collectedAtMs: Date.UTC(2024, 7, 12, 12),
          sequence: 1,
        }),
      ],
    });

    const result = runMetricsArchiveAttempt({
      database: database.sqlite,
      metricsArchives: database.metricsArchives,
      audit: database.audit,
      nowMs: Date.UTC(2024, 8, 1, 0, 1),
      plan,
    });

    expect(result).toEqual({
      ok: true,
      run: expect.objectContaining({
        archivePath: plan.identity.path,
        status: "succeeded",
      }),
    });
    expect(sampleIdentities(database)).toEqual([]);
    expect(observationIdentities(database)).toEqual([]);
    expect(database.audit.recent()).toEqual([]);

    database.close();
  });
});

async function createAttemptDatabase(label: string) {
  const root = await mkdtemp(
    path.join(os.tmpdir(), `enoki-archive-runtime-${label}-`),
  );
  tempRoots.push(root);
  const database = initializeHubDatabase({
    dataRoot: root,
    sqlitePath: path.join(root, "enoki.db"),
  });
  database.hosts.create({
    clockSkewDetected: false,
    connectAddress: "10.0.0.7",
    createdAtMs: Date.UTC(2024, 7, 1),
    displayName: "Archive Runtime Host",
    displayNameEdited: false,
    id: 70,
    lastClockSkewMs: null,
    probeConfigurationVersion: "config-1",
    probeId: "probe-runtime",
    probeSecretHash: "secret-probe-runtime",
  });

  return {
    archiveDirectory: path.join(root, "metrics-archive"),
    database,
  };
}

function createMonthlyPlan(input: {
  archiveDirectory: string;
  samples: MetricsArchivePlannedSample[];
  sequence?: number;
}) {
  const rangeStartMs = Date.UTC(2024, 7, 1);
  const rangeEndMs = Date.UTC(2024, 8, 1);
  const sequence = input.sequence ?? 1;
  const archivePath = path.join(
    input.archiveDirectory,
    sequence === 1
      ? "metrics-archive-2024-08.sqlite"
      : `metrics-archive-2024-08-supplement-${sequence}.sqlite`,
  );

  return {
    identity: {
      fileName: path.basename(archivePath),
      path: archivePath,
      sequence,
    },
    period: "monthly" as const,
    rangeEndMs,
    rangeStartMs,
    samples: input.samples,
  };
}

function recordSample(
  database: HubDatabase,
  input: {
    bootId: string;
    collectedAtMs: number;
    sequence: number;
  },
): MetricsArchivePlannedSample {
  const receivedAtMs = input.collectedAtMs + 1_000;
  database.metrics.recordObservationSample({
    observation: {
      bootId: input.bootId,
      hostId: 70,
      probeId: "probe-runtime",
      receivedAtMs,
      sequence: input.sequence,
    },
    sample: {
      bootId: input.bootId,
      collectedAtMs: input.collectedAtMs,
      hostId: 70,
      memoryTotalBytes: 16_000,
      memoryUsedBytes: 8_000,
      probeId: "probe-runtime",
      receivedAtMs,
      sequence: input.sequence,
    },
  });

  return {
    bootId: input.bootId,
    collectedAtMs: input.collectedAtMs,
    probeId: "probe-runtime",
    receivedAtMs,
    sequence: input.sequence,
  };
}

function sampleIdentities(database: HubDatabase) {
  return database.sqlite
    .prepare("select boot_id, sequence from metric_samples order by sequence")
    .all()
    .map((row) => {
      const sample = row as { boot_id: string; sequence: number };
      return `${sample.boot_id}:${sample.sequence}`;
    });
}

function observationIdentities(database: HubDatabase) {
  return database.sqlite
    .prepare(
      "select boot_id, sequence from report_observations order by sequence",
    )
    .all()
    .map((row) => {
      const observation = row as { boot_id: string; sequence: number };
      return `${observation.boot_id}:${observation.sequence}`;
    });
}
