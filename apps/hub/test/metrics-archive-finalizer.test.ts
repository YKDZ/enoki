import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import { initializeHubDatabase, type HubDatabase } from "../src/database/index";
import { finalizeMetricsArchive } from "../src/metrics-archive/finalizer";
import { writeMetricsArchiveFile } from "../src/metrics-archive/writer";

const tempRoots: string[] = [];

describe("Metrics Archive finalization", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("publishes a valid temporary archive and records the succeeded run with a post-publication checksum", async () => {
    const { database, root } = await createTestDatabase();
    const archiveDirectory = path.join(root, "metrics-archive");
    const finalPath = path.join(
      archiveDirectory,
      "metrics-archive-2024-08.sqlite",
    );
    const tempPath = `${finalPath}.tmp`;
    const host = createHost(database, { id: 51, probeId: "probe-finalize" });
    const collectedAtMs = Date.UTC(2024, 7, 12, 12);
    const receivedAtMs = Date.UTC(2024, 7, 12, 12, 0, 1);
    const plan = {
      identity: {
        fileName: path.basename(finalPath),
        path: finalPath,
        sequence: 1,
      },
      period: "monthly" as const,
      rangeEndMs: Date.UTC(2024, 8, 1),
      rangeStartMs: Date.UTC(2024, 7, 1),
      samples: [
        {
          bootId: "boot-finalize",
          collectedAtMs,
          probeId: host.probeId,
          receivedAtMs,
          sequence: 1,
        },
      ],
    };
    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-finalize",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 1,
      },
      sample: {
        bootId: "boot-finalize",
        collectedAtMs,
        hostId: host.id,
        memoryTotalBytes: 16_000,
        memoryUsedBytes: 8_000,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 1,
      },
    });
    const started = database.metricsArchives.startRun({
      nowMs: Date.UTC(2024, 8, 1, 0, 0, 1),
      period: plan.period,
      rangeEndMs: plan.rangeEndMs,
      rangeStartMs: plan.rangeStartMs,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }
    writeMetricsArchiveFile({
      archivePath: tempPath,
      database: database.sqlite,
      nowMs: Date.UTC(2024, 8, 1),
      plan,
    });

    const result = finalizeMetricsArchive({
      finalPath,
      nowMs: Date.UTC(2024, 8, 1, 0, 0, 2),
      plan,
      repository: database.metricsArchives,
      runId: started.run.id,
      tempPath,
    });

    expect(existsSync(tempPath)).toBe(false);
    expect(existsSync(finalPath)).toBe(true);
    const checksumSha256 = createHash("sha256")
      .update(readFileSync(finalPath))
      .digest("hex");
    expect(result).toEqual(
      expect.objectContaining({
        archivePath: finalPath,
        checksumSha256,
        completedAtMs: Date.UTC(2024, 8, 1, 0, 0, 2),
        rowCounts: expect.objectContaining({
          metric_samples: 1,
          report_observations: 1,
        }),
        status: "succeeded",
      }),
    );
    expect(database.metricsArchives.findRun(started.run.id)).toEqual(result);

    database.close();
  });

  it("marks the run failed and leaves no finalized archive when validation fails", async () => {
    const { database, root } = await createTestDatabase();
    const archiveDirectory = path.join(root, "metrics-archive");
    const finalPath = path.join(
      archiveDirectory,
      "metrics-archive-2024-08.sqlite",
    );
    const tempPath = `${finalPath}.tmp`;
    const host = createHost(database, { id: 52, probeId: "probe-invalid" });
    const collectedAtMs = Date.UTC(2024, 7, 12, 12);
    const receivedAtMs = Date.UTC(2024, 7, 12, 12, 0, 1);
    const plan = {
      identity: {
        fileName: path.basename(finalPath),
        path: finalPath,
        sequence: 1,
      },
      period: "monthly" as const,
      rangeEndMs: Date.UTC(2024, 8, 1),
      rangeStartMs: Date.UTC(2024, 7, 1),
      samples: [
        {
          bootId: "boot-invalid",
          collectedAtMs,
          probeId: host.probeId,
          receivedAtMs,
          sequence: 1,
        },
      ],
    };
    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-invalid",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 1,
      },
      sample: {
        bootId: "boot-invalid",
        collectedAtMs,
        hostId: host.id,
        memoryTotalBytes: 16_000,
        memoryUsedBytes: 8_000,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 1,
      },
    });
    const started = database.metricsArchives.startRun({
      nowMs: Date.UTC(2024, 8, 1, 0, 0, 1),
      period: plan.period,
      rangeEndMs: plan.rangeEndMs,
      rangeStartMs: plan.rangeStartMs,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }
    writeMetricsArchiveFile({
      archivePath: tempPath,
      database: database.sqlite,
      nowMs: Date.UTC(2024, 8, 1),
      plan,
    });
    const archive = new DatabaseSync(tempPath);
    try {
      archive.prepare("delete from metric_samples").run();
    } finally {
      archive.close();
    }

    expect(() =>
      finalizeMetricsArchive({
        finalPath,
        nowMs: Date.UTC(2024, 8, 1, 0, 0, 2),
        plan,
        repository: database.metricsArchives,
        runId: started.run.id,
        tempPath,
      }),
    ).toThrow("expected 1 metric_samples rows, found 0");

    expect(existsSync(finalPath)).toBe(false);
    expect(database.metricsArchives.findRun(started.run.id)).toEqual(
      expect.objectContaining({
        archivePath: null,
        checksumSha256: null,
        errorMessage: expect.stringContaining(
          "expected 1 metric_samples rows, found 0",
        ),
        rowCounts: null,
        status: "failed",
      }),
    );

    database.close();
  });

  it("marks the run failed when publishing the finalized archive fails", async () => {
    const { database, root } = await createTestDatabase();
    const tempDirectory = path.join(root, "metrics-archive");
    const finalPath = path.join(
      root,
      "missing-parent",
      "metrics-archive-2024-08.sqlite",
    );
    const tempPath = path.join(
      tempDirectory,
      "metrics-archive-2024-08.sqlite.tmp",
    );
    const host = createHost(database, { id: 53, probeId: "probe-rename-fail" });
    const collectedAtMs = Date.UTC(2024, 7, 12, 12);
    const receivedAtMs = Date.UTC(2024, 7, 12, 12, 0, 1);
    const plan = {
      identity: {
        fileName: path.basename(finalPath),
        path: finalPath,
        sequence: 1,
      },
      period: "monthly" as const,
      rangeEndMs: Date.UTC(2024, 8, 1),
      rangeStartMs: Date.UTC(2024, 7, 1),
      samples: [
        {
          bootId: "boot-rename-fail",
          collectedAtMs,
          probeId: host.probeId,
          receivedAtMs,
          sequence: 1,
        },
      ],
    };
    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-rename-fail",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 1,
      },
      sample: {
        bootId: "boot-rename-fail",
        collectedAtMs,
        hostId: host.id,
        memoryTotalBytes: 16_000,
        memoryUsedBytes: 8_000,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 1,
      },
    });
    const started = database.metricsArchives.startRun({
      nowMs: Date.UTC(2024, 8, 1, 0, 0, 1),
      period: plan.period,
      rangeEndMs: plan.rangeEndMs,
      rangeStartMs: plan.rangeStartMs,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }
    writeMetricsArchiveFile({
      archivePath: tempPath,
      database: database.sqlite,
      nowMs: Date.UTC(2024, 8, 1),
      plan,
    });

    expect(() =>
      finalizeMetricsArchive({
        finalPath,
        nowMs: Date.UTC(2024, 8, 1, 0, 0, 2),
        plan,
        repository: database.metricsArchives,
        runId: started.run.id,
        tempPath,
      }),
    ).toThrow();

    expect(existsSync(finalPath)).toBe(false);
    expect(database.metricsArchives.findRun(started.run.id)).toEqual(
      expect.objectContaining({
        archivePath: null,
        checksumSha256: null,
        errorMessage: expect.stringContaining("missing-parent"),
        rowCounts: null,
        status: "failed",
      }),
    );

    database.close();
  });

  it("does not overwrite an existing finalized archive path and marks the run failed", async () => {
    const archiveRun = await createWrittenArchiveRun({
      hostId: 56,
      probeId: "probe-existing-final",
    });
    writeFileSync(archiveRun.finalPath, "existing finalized archive");

    expect(() => finalizeMetricsArchive(archiveRun.finalizeInput())).toThrow(
      "finalized archive already exists",
    );

    expect(readFileSync(archiveRun.finalPath, "utf8")).toBe(
      "existing finalized archive",
    );
    expect(existsSync(archiveRun.tempPath)).toBe(true);
    expect(
      archiveRun.database.metricsArchives.findRun(archiveRun.runId),
    ).toEqual(
      expect.objectContaining({
        archivePath: null,
        checksumSha256: null,
        errorMessage: expect.stringContaining(
          "finalized archive already exists",
        ),
        rowCounts: null,
        status: "failed",
      }),
    );

    archiveRun.database.close();
  });

  it("fails validation when required archive observations are missing", async () => {
    const archiveRun = await createWrittenArchiveRun({
      hostId: 54,
      probeId: "probe-missing-observation",
    });
    const archive = new DatabaseSync(archiveRun.tempPath);
    try {
      archive.prepare("delete from report_observations").run();
    } finally {
      archive.close();
    }

    expect(() => finalizeMetricsArchive(archiveRun.finalizeInput())).toThrow(
      "expected 1 report_observations rows, found 0",
    );
    expect(
      archiveRun.database.metricsArchives.findRun(archiveRun.runId),
    ).toEqual(
      expect.objectContaining({
        errorMessage: expect.stringContaining(
          "expected 1 report_observations rows, found 0",
        ),
        status: "failed",
      }),
    );

    archiveRun.database.close();
  });

  it("fails validation when archived sample timestamps are outside the planned range", async () => {
    const archiveRun = await createWrittenArchiveRun({
      hostId: 55,
      probeId: "probe-outside-range",
    });
    const archive = new DatabaseSync(archiveRun.tempPath);
    try {
      archive
        .prepare("update metric_samples set collected_at_ms = ?")
        .run(archiveRun.plan.rangeEndMs);
    } finally {
      archive.close();
    }

    expect(() => finalizeMetricsArchive(archiveRun.finalizeInput())).toThrow(
      "outside planned range",
    );
    expect(
      archiveRun.database.metricsArchives.findRun(archiveRun.runId),
    ).toEqual(
      expect.objectContaining({
        errorMessage: expect.stringContaining("outside planned range"),
        status: "failed",
      }),
    );

    archiveRun.database.close();
  });

  it("fails validation when equal-count metric sample rows have the wrong planned identity", async () => {
    const archiveRun = await createWrittenArchiveRun({
      hostId: 57,
      probeId: "probe-wrong-sample-identity",
    });
    const archive = new DatabaseSync(archiveRun.tempPath);
    try {
      archive
        .prepare("update metric_samples set boot_id = ?")
        .run("wrong-boot-id");
    } finally {
      archive.close();
    }

    expect(() => finalizeMetricsArchive(archiveRun.finalizeInput())).toThrow(
      "missing planned metric_samples row",
    );
    expect(
      archiveRun.database.metricsArchives.findRun(archiveRun.runId),
    ).toEqual(
      expect.objectContaining({
        errorMessage: expect.stringContaining(
          "missing planned metric_samples row",
        ),
        status: "failed",
      }),
    );

    archiveRun.database.close();
  });

  it("fails validation when equal-count observation rows have the wrong planned identity", async () => {
    const archiveRun = await createWrittenArchiveRun({
      hostId: 58,
      probeId: "probe-wrong-observation-identity",
    });
    const archive = new DatabaseSync(archiveRun.tempPath);
    try {
      archive
        .prepare("update report_observations set boot_id = ?")
        .run("wrong-boot-id");
    } finally {
      archive.close();
    }

    expect(() => finalizeMetricsArchive(archiveRun.finalizeInput())).toThrow(
      "missing planned report_observations row",
    );
    expect(
      archiveRun.database.metricsArchives.findRun(archiveRun.runId),
    ).toEqual(
      expect.objectContaining({
        errorMessage: expect.stringContaining(
          "missing planned report_observations row",
        ),
        status: "failed",
      }),
    );

    archiveRun.database.close();
  });

  it("does not finalize a run whose recorded period range does not match the plan", async () => {
    const archiveRun = await createWrittenArchiveRun({
      hostId: 59,
      probeId: "probe-wrong-run-range",
    });
    const releasedOriginalRun = archiveRun.database.metricsArchives.markFailed({
      errorMessage: "released to verify wrong-range finalization",
      nowMs: Date.UTC(2024, 9, 1),
      runId: archiveRun.runId,
    });
    const wrongRun = archiveRun.database.metricsArchives.startRun({
      nowMs: Date.UTC(2024, 9, 1, 0, 0, 1),
      period: "monthly",
      rangeEndMs: Date.UTC(2024, 10, 1),
      rangeStartMs: Date.UTC(2024, 9, 1),
    });
    if (!wrongRun.ok) {
      throw new Error("Expected wrong-range Metrics Archive run to start.");
    }

    expect(() =>
      finalizeMetricsArchive({
        ...archiveRun.finalizeInput(),
        runId: wrongRun.run.id,
      }),
    ).toThrow("does not match planned archive range");

    expect(existsSync(archiveRun.finalPath)).toBe(false);
    expect(
      archiveRun.database.metricsArchives.findRun(archiveRun.runId),
    ).toEqual(releasedOriginalRun);
    expect(
      archiveRun.database.metricsArchives.findRun(wrongRun.run.id),
    ).toEqual(
      expect.objectContaining({
        errorMessage: expect.stringContaining(
          "does not match planned archive range",
        ),
        status: "failed",
      }),
    );

    archiveRun.database.close();
  });

  it("fails validation when archive_metadata is missing", async () => {
    const archiveRun = await createWrittenArchiveRun({
      hostId: 60,
      probeId: "probe-missing-metadata",
    });
    const archive = new DatabaseSync(archiveRun.tempPath);
    try {
      archive.prepare("delete from archive_metadata").run();
    } finally {
      archive.close();
    }

    expect(() => finalizeMetricsArchive(archiveRun.finalizeInput())).toThrow(
      "expected one archive_metadata row",
    );
    expect(
      archiveRun.database.metricsArchives.findRun(archiveRun.runId),
    ).toEqual(
      expect.objectContaining({
        errorMessage: expect.stringContaining(
          "expected one archive_metadata row",
        ),
        status: "failed",
      }),
    );

    archiveRun.database.close();
  });

  it("fails validation when archive_metadata does not match the planned range", async () => {
    const archiveRun = await createWrittenArchiveRun({
      hostId: 61,
      probeId: "probe-wrong-metadata-range",
    });
    const archive = new DatabaseSync(archiveRun.tempPath);
    try {
      archive
        .prepare("update archive_metadata set range_start_ms = ? where id = 1")
        .run(archiveRun.plan.rangeStartMs - 1);
    } finally {
      archive.close();
    }

    expect(() => finalizeMetricsArchive(archiveRun.finalizeInput())).toThrow(
      "archive_metadata does not match the planned archive range",
    );
    expect(
      archiveRun.database.metricsArchives.findRun(archiveRun.runId),
    ).toEqual(
      expect.objectContaining({
        errorMessage: expect.stringContaining(
          "archive_metadata does not match the planned archive range",
        ),
        status: "failed",
      }),
    );

    archiveRun.database.close();
  });

  it("fails validation when archive_metadata row counts do not match the archive contents", async () => {
    const archiveRun = await createWrittenArchiveRun({
      hostId: 62,
      probeId: "probe-wrong-metadata-counts",
    });
    const archive = new DatabaseSync(archiveRun.tempPath);
    try {
      archive
        .prepare("update archive_metadata set row_counts_json = ? where id = 1")
        .run(
          JSON.stringify({
            archive_metadata: 1,
            metric_samples: 2,
            report_observations: 1,
          }),
        );
    } finally {
      archive.close();
    }

    expect(() => finalizeMetricsArchive(archiveRun.finalizeInput())).toThrow(
      "archive_metadata row_counts_json does not match archive row counts",
    );
    expect(
      archiveRun.database.metricsArchives.findRun(archiveRun.runId),
    ).toEqual(
      expect.objectContaining({
        errorMessage: expect.stringContaining(
          "archive_metadata row_counts_json does not match archive row counts",
        ),
        status: "failed",
      }),
    );

    archiveRun.database.close();
  });
});

async function createTestDatabase() {
  const root = await mkdtemp(path.join(os.tmpdir(), "enoki-archive-finalize-"));
  tempRoots.push(root);

  return {
    database: initializeHubDatabase({
      dataRoot: root,
      sqlitePath: path.join(root, "enoki.db"),
    }),
    root,
  };
}

function createHost(
  database: HubDatabase,
  input: {
    id: number;
    probeId: string;
  },
) {
  return database.hosts.create({
    architecture: "x86_64",
    clockSkewDetected: false,
    connectAddress: `10.0.0.${input.id}`,
    connectAddressEdited: false,
    cpuCount: 2,
    cpuModel: "Test CPU",
    createdAtMs: Date.UTC(2024, 7, 1),
    deletedAtMs: null,
    description: "test Host",
    displayName: `Host ${input.id}`,
    displayNameEdited: false,
    hostname: `host-${input.id}`,
    kernel: "6.1",
    lastClockSkewMs: null,
    lastReportAtMs: Date.UTC(2024, 7, 12),
    memoryTotalBytes: 16_000,
    observedIp: "192.0.2.10",
    os: "linux",
    probeConfigurationErrorCode: null,
    probeConfigurationErrorFailedVersion: null,
    probeConfigurationErrorMessage: null,
    probeConfigurationErrorReportedAtMs: null,
    probeConfigurationVersion: "config-1",
    probeId: input.probeId,
    probePublicKeyPem: `secret-public-key-material-${input.id}`,
    probeSecretHash: `secret-probe-hash-${input.id}`,
    probeVersion: "1.2.3",
  });
}

async function createWrittenArchiveRun(input: {
  hostId: number;
  probeId: string;
}) {
  const { database, root } = await createTestDatabase();
  const archiveDirectory = path.join(root, "metrics-archive");
  const finalPath = path.join(
    archiveDirectory,
    "metrics-archive-2024-08.sqlite",
  );
  const tempPath = `${finalPath}.tmp`;
  const host = createHost(database, {
    id: input.hostId,
    probeId: input.probeId,
  });
  const collectedAtMs = Date.UTC(2024, 7, 12, 12);
  const receivedAtMs = Date.UTC(2024, 7, 12, 12, 0, 1);
  const plan = {
    identity: {
      fileName: path.basename(finalPath),
      path: finalPath,
      sequence: 1,
    },
    period: "monthly" as const,
    rangeEndMs: Date.UTC(2024, 8, 1),
    rangeStartMs: Date.UTC(2024, 7, 1),
    samples: [
      {
        bootId: `boot-${input.probeId}`,
        collectedAtMs,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 1,
      },
    ],
  };
  database.metrics.recordObservationSample({
    observation: {
      bootId: `boot-${input.probeId}`,
      hostId: host.id,
      probeId: host.probeId,
      receivedAtMs,
      sequence: 1,
    },
    sample: {
      bootId: `boot-${input.probeId}`,
      collectedAtMs,
      hostId: host.id,
      memoryTotalBytes: 16_000,
      memoryUsedBytes: 8_000,
      probeId: host.probeId,
      receivedAtMs,
      sequence: 1,
    },
  });
  const started = database.metricsArchives.startRun({
    nowMs: Date.UTC(2024, 8, 1, 0, 0, 1),
    period: plan.period,
    rangeEndMs: plan.rangeEndMs,
    rangeStartMs: plan.rangeStartMs,
  });
  if (!started.ok) {
    throw new Error("Expected Metrics Archive run to start.");
  }
  writeMetricsArchiveFile({
    archivePath: tempPath,
    database: database.sqlite,
    nowMs: Date.UTC(2024, 8, 1),
    plan,
  });

  return {
    database,
    finalizeInput: () => ({
      finalPath,
      nowMs: Date.UTC(2024, 8, 1, 0, 0, 2),
      plan,
      repository: database.metricsArchives,
      runId: started.run.id,
      tempPath,
    }),
    finalPath,
    plan,
    runId: started.run.id,
    tempPath,
  };
}
