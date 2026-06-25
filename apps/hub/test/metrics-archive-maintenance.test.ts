import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { initializeHubDatabase, type HubDatabase } from "../src/database/index";
import { runMetricsArchiveMaintenance } from "../src/metrics-archive/maintenance";
import { runMetricsArchiveAttempt } from "../src/metrics-archive/runtime";
import type { MetricsArchivePlannedSample } from "../src/metrics-archive/writer";

const tempRoots: string[] = [];

describe("Metrics Archive maintenance service", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("directly cleans retention-eligible Metrics without archive runs or files when Metrics Archive is disabled", async () => {
    const { archiveDirectory, database, root } =
      await createMaintenanceDatabase("disabled");
    recordSample(database, {
      bootId: "boot-disabled-old",
      collectedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });

    const result = runMetricsArchiveMaintenance({
      database,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: false,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20),
      receivedGraceMs: 60_000,
    });

    expect(result).toEqual({
      deletedMetricSamples: 1,
      deletedReportObservations: 1,
      mode: "direct-cleanup",
      skipped: false,
    });
    expect(sampleIdentities(database)).toEqual([]);
    expect(observationIdentities(database)).toEqual([]);
    expect(countRows(database, "metrics_archive_runs")).toBe(0);
    expect(existsSync(archiveDirectory)).toBe(false);

    database.close();
    expect(existsSync(path.join(root, "enoki.db"))).toBe(true);
  });

  it("retention-cleans observation-only reports while Metrics Archive is enabled", async () => {
    const { archiveDirectory, database } = await createMaintenanceDatabase(
      "enabled-observation-only",
    );
    recordObservation(database, {
      bootId: "boot-observation-only-old",
      receivedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });
    recordObservation(database, {
      bootId: "boot-observation-only-grace",
      receivedAtMs: Date.UTC(2024, 7, 20) - 30_000,
      sequence: 2,
    });

    const result = runMetricsArchiveMaintenance({
      database,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: true,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20),
      receivedGraceMs: 60_000,
    });

    expect(result).toEqual({
      attemptedRuns: [],
      mode: "archive",
      skipped: false,
    });
    expect(observationIdentities(database)).toEqual([
      "boot-observation-only-grace:2",
    ]);
    expect(sampleIdentities(database)).toEqual([]);
    expect(countRows(database, "metrics_archive_runs")).toBe(0);
    expect(existsSync(archiveDirectory)).toBe(false);

    database.close();
  });

  it("skips cleanly when an archive run lock is already held", async () => {
    const { archiveDirectory, database } =
      await createMaintenanceDatabase("lock-held");
    recordSample(database, {
      bootId: "boot-lock-held",
      collectedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });
    recordObservation(database, {
      bootId: "boot-lock-held-observation-only",
      receivedAtMs: Date.UTC(2024, 7, 1),
      sequence: 2,
    });
    const active = database.metricsArchives.startRun({
      nowMs: Date.UTC(2024, 7, 20, 0, 1),
      period: "monthly",
      rangeEndMs: Date.UTC(2024, 8, 1),
      rangeStartMs: Date.UTC(2024, 7, 1),
    });
    if (!active.ok) {
      throw new Error("Expected active Metrics Archive run to start.");
    }

    const result = runMetricsArchiveMaintenance({
      database,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: true,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20),
      receivedGraceMs: 60_000,
    });

    expect(result).toEqual({
      conflictingRun: active.run,
      mode: "archive",
      reason: "conflict",
      skipped: true,
    });
    expect(sampleIdentities(database)).toEqual(["boot-lock-held:1"]);
    expect(observationIdentities(database)).toEqual([
      "boot-lock-held:1",
      "boot-lock-held-observation-only:2",
    ]);
    expect(countRows(database, "metrics_archive_runs")).toBe(1);

    database.close();
  });

  it("recovers stale archive run locks before archiving the blocked range", async () => {
    const { archiveDirectory, database } =
      await createMaintenanceDatabase("stale-lock");
    recordSample(database, {
      bootId: "boot-stale-lock",
      collectedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });
    const stale = database.metricsArchives.startRun({
      nowMs: Date.UTC(2024, 7, 19, 23),
      period: "monthly",
      rangeEndMs: Date.UTC(2024, 8, 1),
      rangeStartMs: Date.UTC(2024, 7, 1),
    });
    if (!stale.ok) {
      throw new Error("Expected stale Metrics Archive run to start.");
    }

    const result = runMetricsArchiveMaintenance({
      database,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: true,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20),
      receivedGraceMs: 60_000,
    });

    expect(database.metricsArchives.findRun(stale.run.id)).toEqual(
      expect.objectContaining({
        completedAtMs: Date.UTC(2024, 7, 20),
        errorMessage: expect.stringContaining("stale"),
        status: "failed",
      }),
    );
    expect(metricsArchiveFailureAudits(database)).toEqual([
      expect.objectContaining({
        action: "metrics_archive.failed",
        actor: "system",
        outcome: "failure",
        subjectId: String(stale.run.id),
        subjectType: "metrics_archive_run",
      }),
    ]);
    expect(result).toEqual({
      attemptedRuns: [
        expect.objectContaining({
          archivePath: path.join(
            archiveDirectory,
            "metrics-archive-2024-08.sqlite",
          ),
          cleanupStatus: "succeeded",
          status: "succeeded",
        }),
      ],
      mode: "archive",
      skipped: false,
    });
    expect(sampleIdentities(database)).toEqual([]);
    expect(countRows(database, "metrics_archive_runs")).toBe(2);

    database.close();
  });

  it("plans a supplemental archive when stale recovery finds an existing finalized archive file", async () => {
    const { archiveDirectory, database } = await createMaintenanceDatabase(
      "stale-lock-published-file",
    );
    recordSample(database, {
      bootId: "boot-stale-published-file",
      collectedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });
    const stale = database.metricsArchives.startRun({
      nowMs: Date.UTC(2024, 7, 19, 23),
      period: "monthly",
      rangeEndMs: Date.UTC(2024, 8, 1),
      rangeStartMs: Date.UTC(2024, 7, 1),
    });
    if (!stale.ok) {
      throw new Error("Expected stale Metrics Archive run to start.");
    }
    mkdirSync(archiveDirectory, { recursive: true });
    const primaryArchivePath = path.join(
      archiveDirectory,
      "metrics-archive-2024-08.sqlite",
    );
    writeFileSync(primaryArchivePath, "already published archive");

    const result = runMetricsArchiveMaintenance({
      database,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: true,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20),
      receivedGraceMs: 60_000,
    });

    expect(database.metricsArchives.findRun(stale.run.id)).toEqual(
      expect.objectContaining({
        completedAtMs: Date.UTC(2024, 7, 20),
        errorMessage: expect.stringContaining("stale"),
        status: "failed",
      }),
    );
    expect(result).toEqual({
      attemptedRuns: [
        expect.objectContaining({
          archivePath: path.join(
            archiveDirectory,
            "metrics-archive-2024-08-supplement-2.sqlite",
          ),
          cleanupStatus: "succeeded",
          status: "succeeded",
        }),
      ],
      mode: "archive",
      skipped: false,
    });
    expect(sampleIdentities(database)).toEqual([]);
    expect(readdirSync(archiveDirectory).sort()).toEqual([
      "metrics-archive-2024-08-supplement-2.sqlite",
      "metrics-archive-2024-08.sqlite",
    ]);

    database.close();
  });

  it("uses a supplemental archive identity when the primary archive path already exists", async () => {
    const { archiveDirectory, database } = await createMaintenanceDatabase(
      "retry-after-failure",
    );
    recordSample(database, {
      bootId: "boot-retry-after-failure",
      collectedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });
    mkdirSync(archiveDirectory, { recursive: true });
    const archivePath = path.join(
      archiveDirectory,
      "metrics-archive-2024-08.sqlite",
    );
    writeFileSync(archivePath, "pre-existing archive");

    const result = runMetricsArchiveMaintenance({
      database,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: true,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20),
      receivedGraceMs: 60_000,
    });

    expect(result).toEqual({
      attemptedRuns: [
        expect.objectContaining({
          archivePath: path.join(
            archiveDirectory,
            "metrics-archive-2024-08-supplement-2.sqlite",
          ),
          cleanupStatus: "succeeded",
          status: "succeeded",
        }),
      ],
      mode: "archive",
      skipped: false,
    });
    expect(sampleIdentities(database)).toEqual([]);
    expect(readdirSync(archiveDirectory).sort()).toEqual([
      "metrics-archive-2024-08-supplement-2.sqlite",
      "metrics-archive-2024-08.sqlite",
    ]);

    database.close();
  });

  it("ignores malformed archive filenames when reserving supplemental identities", async () => {
    const { archiveDirectory, database } = await createMaintenanceDatabase(
      "malformed-archive-filenames",
    );
    recordSample(database, {
      bootId: "boot-malformed-filename",
      collectedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });
    mkdirSync(archiveDirectory, { recursive: true });
    writeFileSync(
      path.join(archiveDirectory, "metrics-archive-2024-13.sqlite"),
      "not an archive for 2025-01",
    );
    writeFileSync(
      path.join(
        archiveDirectory,
        "metrics-archive-2024-08-supplement-0.sqlite",
      ),
      "invalid supplement sequence",
    );

    const result = runMetricsArchiveMaintenance({
      database,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: true,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20),
      receivedGraceMs: 60_000,
    });

    expect(result).toEqual({
      attemptedRuns: [
        expect.objectContaining({
          archivePath: path.join(
            archiveDirectory,
            "metrics-archive-2024-08.sqlite",
          ),
          cleanupStatus: "succeeded",
          status: "succeeded",
        }),
      ],
      mode: "archive",
      skipped: false,
    });
    expect(sampleIdentities(database)).toEqual([]);

    database.close();
  });

  it("retries cleanup for a finalized archive before planning supplemental archives", async () => {
    const { archiveDirectory, database } =
      await createMaintenanceDatabase("cleanup-retry");
    const sample = recordSample(database, {
      bootId: "boot-cleanup-retry",
      collectedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });
    const first = runMetricsArchiveAttempt({
      audit: database.audit,
      cleanup: () => {
        throw new Error("transient cleanup failure");
      },
      database: database.sqlite,
      metricsArchives: database.metricsArchives,
      nowMs: Date.UTC(2024, 7, 20),
      plan: monthlyPlan(archiveDirectory, [sample]),
    });

    expect(first).toEqual({
      errorMessage: "transient cleanup failure",
      ok: false,
      run: expect.objectContaining({
        archivePath: path.join(
          archiveDirectory,
          "metrics-archive-2024-08.sqlite",
        ),
        cleanupStatus: "failed",
        status: "succeeded",
      }),
    });
    if (!("run" in first)) {
      throw new Error("Expected transient cleanup failure to keep a run.");
    }
    expect(sampleIdentities(database)).toEqual(["boot-cleanup-retry:1"]);

    const retried = runMetricsArchiveMaintenance({
      database,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: true,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20, 0, 1),
      receivedGraceMs: 60_000,
    });

    expect(retried).toEqual({
      attemptedRuns: [
        expect.objectContaining({
          archivePath: path.join(
            archiveDirectory,
            "metrics-archive-2024-08.sqlite",
          ),
          cleanupStatus: "succeeded",
          id: first.run.id,
          status: "succeeded",
        }),
      ],
      mode: "archive",
      skipped: false,
    });
    expect(sampleIdentities(database)).toEqual([]);
    expect(observationIdentities(database)).toEqual([]);
    expect(readdirSync(archiveDirectory)).toEqual([
      "metrics-archive-2024-08.sqlite",
    ]);
    expect(countRows(database, "metrics_archive_runs")).toBe(1);
    expect(metricsArchiveFailureAudits(database)).toHaveLength(1);

    database.close();
  });

  it("emits an Audit Log failure when a finalized archive cleanup retry fails", async () => {
    const { archiveDirectory, database } = await createMaintenanceDatabase(
      "cleanup-retry-failure-audit",
    );
    const sample = recordSample(database, {
      bootId: "boot-cleanup-retry-failure-audit",
      collectedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });
    const first = runMetricsArchiveAttempt({
      audit: database.audit,
      cleanup: () => {
        throw new Error("initial cleanup failure");
      },
      database: database.sqlite,
      metricsArchives: database.metricsArchives,
      nowMs: Date.UTC(2024, 7, 20),
      plan: monthlyPlan(archiveDirectory, [sample]),
    });
    if (!("run" in first)) {
      throw new Error("Expected cleanup failure to keep a finalized run.");
    }
    if (!first.run.archivePath) {
      throw new Error("Expected cleanup failure to keep archive metadata.");
    }
    writeFileSync(first.run.archivePath, "corrupted before cleanup retry");

    const retried = runMetricsArchiveMaintenance({
      database,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: true,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20, 0, 1),
      receivedGraceMs: 60_000,
    });

    expect(retried).toEqual({
      attemptedRuns: [
        expect.objectContaining({
          cleanupErrorMessage: expect.stringContaining(
            "finalized archive checksum does not match",
          ),
          cleanupStatus: "failed",
          id: first.run.id,
          status: "succeeded",
        }),
      ],
      mode: "archive",
      skipped: false,
    });
    expect(metricsArchiveFailureAudits(database)).toEqual([
      expect.objectContaining({
        action: "metrics_archive.failed",
        actor: "system",
        outcome: "failure",
        subjectId: String(first.run.id),
        subjectType: "metrics_archive_run",
      }),
      expect.objectContaining({
        action: "metrics_archive.failed",
        actor: "system",
        outcome: "failure",
        subjectId: String(first.run.id),
        subjectType: "metrics_archive_run",
      }),
    ]);

    database.close();
  });
});

async function createMaintenanceDatabase(label: string) {
  const root = await mkdtemp(
    path.join(os.tmpdir(), `enoki-archive-maintenance-${label}-`),
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
    displayName: "Archive Maintenance Host",
    displayNameEdited: false,
    id: 90,
    lastClockSkewMs: null,
    probeConfigurationVersion: "config-1",
    probeId: "probe-maintenance",
    probeSecretHash: "secret-probe-maintenance",
  });

  return {
    archiveDirectory: path.join(root, "metrics-archive"),
    database,
    root,
  };
}

function recordObservation(
  database: HubDatabase,
  input: {
    bootId: string;
    receivedAtMs: number;
    sequence: number;
  },
) {
  database.metrics.recordObservation({
    bootId: input.bootId,
    hostId: 90,
    probeId: "probe-maintenance",
    receivedAtMs: input.receivedAtMs,
    sequence: input.sequence,
  });
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
      hostId: 90,
      probeId: "probe-maintenance",
      receivedAtMs,
      sequence: input.sequence,
    },
    sample: {
      bootId: input.bootId,
      collectedAtMs: input.collectedAtMs,
      hostId: 90,
      memoryTotalBytes: 16_000,
      memoryUsedBytes: 8_000,
      probeId: "probe-maintenance",
      receivedAtMs,
      sequence: input.sequence,
    },
  });

  return {
    bootId: input.bootId,
    collectedAtMs: input.collectedAtMs,
    probeId: "probe-maintenance",
    receivedAtMs,
    sequence: input.sequence,
  };
}

function monthlyPlan(
  archiveDirectory: string,
  samples: MetricsArchivePlannedSample[],
) {
  const archivePath = path.join(
    archiveDirectory,
    "metrics-archive-2024-08.sqlite",
  );
  return {
    identity: {
      fileName: path.basename(archivePath),
      path: archivePath,
      sequence: 1,
    },
    period: "monthly" as const,
    rangeEndMs: Date.UTC(2024, 8, 1),
    rangeStartMs: Date.UTC(2024, 7, 1),
    samples,
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

function metricsArchiveFailureAudits(database: HubDatabase) {
  return database.audit
    .recent()
    .filter((event) => event.action === "metrics_archive.failed");
}

function countRows(database: HubDatabase, table: string) {
  return (
    database.sqlite.prepare(`select count(*) as count from ${table}`).get() as {
      count: number;
    }
  ).count;
}
