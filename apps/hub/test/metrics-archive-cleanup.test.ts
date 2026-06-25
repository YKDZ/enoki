import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { initializeHubDatabase, type HubDatabase } from "../src/database/index";
import {
  cleanupArchivedMetrics,
  cleanupMetricsRetentionDirectly,
} from "../src/metrics-archive/cleanup";
import { writeMetricsArchiveFile } from "../src/metrics-archive/writer";

const tempRoots: string[] = [];

describe("Metrics Archive hot cleanup", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("deletes only archived hot Metrics after a succeeded finalized archive run", async () => {
    const database = await createTestDatabase();
    const host = createHost(database, { id: 61, probeId: "probe-cleanup" });
    const rangeStartMs = Date.UTC(2024, 7, 1);
    const rangeEndMs = Date.UTC(2024, 8, 1);

    recordSample(database, host, {
      bootId: "boot-before",
      collectedAtMs: rangeStartMs - 1,
      sequence: 1,
    });
    const archivedSample = recordSample(database, host, {
      bootId: "boot-archived",
      collectedAtMs: Date.UTC(2024, 7, 12, 12),
      sequence: 2,
      withChildren: true,
    });
    recordSample(database, host, {
      bootId: "boot-end",
      collectedAtMs: rangeEndMs,
      sequence: 3,
    });
    database.metrics.recordObservation({
      bootId: "boot-observation-only",
      hostId: host.id,
      probeId: host.probeId,
      receivedAtMs: Date.UTC(2024, 7, 12, 12, 0, 1),
      sequence: 4,
    });

    const archiveRun = await markArchiveSucceeded(database, {
      archiveFileName: "metrics-archive-2024-08.sqlite",
      rangeEndMs,
      rangeStartMs,
      samples: [archivedSample],
    });

    recordSample(database, host, {
      bootId: "boot-late",
      collectedAtMs: Date.UTC(2024, 7, 20, 12),
      sequence: 5,
      withChildren: true,
    });
    const execSpy = vi.spyOn(database.sqlite, "exec");

    const result = cleanupArchivedMetrics({
      database: database.sqlite,
      period: "monthly",
      rangeEndMs,
      rangeStartMs,
      runId: archiveRun.id,
    });

    expect(result).toEqual({
      deletedMetricSamples: 1,
      deletedReportObservations: 1,
    });
    expect(sampleIdentities(database)).toEqual([
      "boot-before:1",
      "boot-late:5",
      "boot-end:3",
    ]);
    expect(observationIdentities(database)).toEqual([
      "boot-before:1",
      "boot-end:3",
      "boot-observation-only:4",
      "boot-late:5",
    ]);
    expect(countRows(database, "official_metric_cpu")).toBe(3);
    expect(countRows(database, "official_metric_memory")).toBe(3);
    expect(countRows(database, "official_metric_load")).toBe(1);
    expect(countRows(database, "official_metric_uptime")).toBe(1);
    expect(countRows(database, "official_metric_thermal_power")).toBe(1);
    expect(countRows(database, "official_metric_disk_summary")).toBe(1);
    expect(countRows(database, "official_metric_network_summary")).toBe(1);
    expect(countRows(database, "metric_cpu_cores")).toBe(1);
    expect(countRows(database, "metric_disks")).toBe(1);
    expect(countRows(database, "metric_network_interfaces")).toBe(1);
    expect(countRows(database, "official_metric_disk_health")).toBe(1);
    expect(execSpy).toHaveBeenCalledWith("PRAGMA wal_checkpoint(TRUNCATE)");
    expect(execSpy).not.toHaveBeenCalledWith(expect.stringMatching(/vacuum/i));

    database.close();
  });

  it("refuses cleanup before a finalized archive run succeeds", async () => {
    const database = await createTestDatabase();
    const host = createHost(database, { id: 62, probeId: "probe-refuse" });
    const rangeStartMs = Date.UTC(2024, 7, 1);
    const rangeEndMs = Date.UTC(2024, 8, 1);
    recordSample(database, host, {
      bootId: "boot-started",
      collectedAtMs: Date.UTC(2024, 7, 12, 12),
      sequence: 1,
    });
    const started = database.metricsArchives.startRun({
      nowMs: Date.UTC(2024, 8, 1, 0, 1),
      period: "monthly",
      rangeEndMs,
      rangeStartMs,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }
    const execSpy = vi.spyOn(database.sqlite, "exec");

    expect(() =>
      cleanupArchivedMetrics({
        database: database.sqlite,
        period: "monthly",
        rangeEndMs,
        rangeStartMs,
        runId: started.run.id,
      }),
    ).toThrow(
      "Metrics Archive cleanup requires the exact succeeded finalized archive run for the same range.",
    );

    expect(sampleIdentities(database)).toEqual(["boot-started:1"]);
    expect(observationIdentities(database)).toEqual(["boot-started:1"]);
    expect(countRows(database, "official_metric_memory")).toBe(1);
    expect(countRows(database, "official_metric_cpu")).toBe(1);
    expect(execSpy).not.toHaveBeenCalledWith("PRAGMA wal_checkpoint(TRUNCATE)");
    expect(execSpy).not.toHaveBeenCalledWith(expect.stringMatching(/vacuum/i));

    database.close();
  });

  it("refuses cleanup when the succeeded archive run is for a different range", async () => {
    const database = await createTestDatabase();
    const host = createHost(database, { id: 63, probeId: "probe-wrong-range" });
    const rangeStartMs = Date.UTC(2024, 7, 1);
    const rangeEndMs = Date.UTC(2024, 8, 1);
    recordSample(database, host, {
      bootId: "boot-wrong-range",
      collectedAtMs: Date.UTC(2024, 7, 12, 12),
      sequence: 1,
    });
    const started = database.metricsArchives.startRun({
      nowMs: Date.UTC(2024, 8, 1, 0, 1),
      period: "monthly",
      rangeEndMs: Date.UTC(2024, 9, 1),
      rangeStartMs: rangeEndMs,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }
    database.metricsArchives.markSucceeded({
      archivePath: "/data/metrics-archive/metrics-archive-2024-09.sqlite",
      checksumSha256:
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      nowMs: Date.UTC(2024, 8, 1, 0, 2),
      period: "monthly",
      rangeEndMs: started.run.rangeEndMs,
      rangeStartMs: started.run.rangeStartMs,
      rowCounts: {
        metric_samples: 1,
      },
      runId: started.run.id,
    });

    expect(() =>
      cleanupArchivedMetrics({
        database: database.sqlite,
        period: "monthly",
        rangeEndMs,
        rangeStartMs,
        runId: started.run.id,
      }),
    ).toThrow(
      "Metrics Archive cleanup requires the exact succeeded finalized archive run for the same range.",
    );

    expect(sampleIdentities(database)).toEqual(["boot-wrong-range:1"]);
    expect(observationIdentities(database)).toEqual(["boot-wrong-range:1"]);

    database.close();
  });

  it("refuses cleanup when finalized row counts do not match archived identities", async () => {
    const database = await createTestDatabase();
    const host = createHost(database, {
      id: 64,
      probeId: "probe-count-mismatch",
    });
    const rangeStartMs = Date.UTC(2024, 7, 1);
    const rangeEndMs = Date.UTC(2024, 8, 1);
    const archivedSample = recordSample(database, host, {
      bootId: "boot-count-mismatch",
      collectedAtMs: Date.UTC(2024, 7, 12, 12),
      sequence: 1,
    });
    const archiveRun = await markArchiveSucceeded(database, {
      archiveFileName: "metrics-archive-count-mismatch.sqlite",
      overrideRowCounts: { metric_samples: 2 },
      rangeEndMs,
      rangeStartMs,
      samples: [archivedSample],
    });
    const execSpy = vi.spyOn(database.sqlite, "exec");

    expect(() =>
      cleanupArchivedMetrics({
        database: database.sqlite,
        period: "monthly",
        rangeEndMs,
        rangeStartMs,
        runId: archiveRun.id,
      }),
    ).toThrow(
      "Metrics Archive cleanup refused: finalized archive metric_samples row count 2 does not match 1 archived identities.",
    );

    expect(sampleIdentities(database)).toEqual(["boot-count-mismatch:1"]);
    expect(observationIdentities(database)).toEqual(["boot-count-mismatch:1"]);
    expect(execSpy).not.toHaveBeenCalledWith("PRAGMA wal_checkpoint(TRUNCATE)");

    database.close();
  });

  it("directly deletes retention-eligible hot Metrics when Metrics Archive is disabled", async () => {
    const database = await createTestDatabase();
    const host = createHost(database, { id: 65, probeId: "probe-direct" });
    const sqlitePath = database.sqlite.location();
    if (!sqlitePath) {
      throw new Error("Expected test database to be file-backed.");
    }
    const archiveDirectory = path.join(
      path.dirname(sqlitePath),
      "metrics-archive",
    );
    const nowMs = Date.UTC(2024, 7, 20, 12);
    const receivedGraceMs = 5 * 60_000;

    recordSample(database, host, {
      bootId: "boot-eligible",
      collectedAtMs: Date.UTC(2024, 7, 12, 11, 59),
      sequence: 1,
      withChildren: true,
    });
    recordSample(database, host, {
      bootId: "boot-retained-by-collected-at",
      collectedAtMs: Date.UTC(2024, 7, 13, 12),
      sequence: 2,
      withChildren: true,
    });
    recordSample(database, host, {
      bootId: "boot-retained-by-received-grace",
      collectedAtMs: Date.UTC(2024, 7, 1),
      receivedAtMs: nowMs - receivedGraceMs + 1,
      sequence: 3,
      withChildren: true,
    });
    database.metrics.recordObservation({
      bootId: "boot-observation-only",
      hostId: host.id,
      probeId: host.probeId,
      receivedAtMs: Date.UTC(2024, 7, 1),
      sequence: 4,
    });
    database.metrics.recordObservation({
      bootId: "boot-observation-only-grace",
      hostId: host.id,
      probeId: host.probeId,
      receivedAtMs: nowMs - receivedGraceMs + 1,
      sequence: 5,
    });
    const execSpy = vi.spyOn(database.sqlite, "exec");

    const result = cleanupMetricsRetentionDirectly({
      database: database.sqlite,
      metrics: {
        archive: {
          directory: archiveDirectory,
          enabled: false,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs,
      receivedGraceMs,
    });

    expect(result).toEqual({
      deletedMetricSamples: 1,
      deletedReportObservations: 2,
      skipped: false,
    });
    expect(sampleIdentities(database)).toEqual([
      "boot-retained-by-received-grace:3",
      "boot-retained-by-collected-at:2",
    ]);
    expect(observationIdentities(database)).toEqual([
      "boot-retained-by-collected-at:2",
      "boot-retained-by-received-grace:3",
      "boot-observation-only-grace:5",
    ]);
    expect(countRows(database, "official_metric_cpu")).toBe(2);
    expect(countRows(database, "official_metric_memory")).toBe(2);
    expect(countRows(database, "metric_cpu_cores")).toBe(2);
    expect(countRows(database, "metrics_archive_runs")).toBe(0);
    expect(
      existsSync(archiveDirectory) ? readdirSync(archiveDirectory) : [],
    ).toEqual([]);
    expect(execSpy).toHaveBeenCalledWith("PRAGMA wal_checkpoint(TRUNCATE)");
    expect(execSpy).not.toHaveBeenCalledWith(expect.stringMatching(/vacuum/i));

    database.close();
  });

  it("skips direct retention cleanup while Metrics Archive is enabled", async () => {
    const database = await createTestDatabase();
    const host = createHost(database, { id: 66, probeId: "probe-enabled" });
    recordSample(database, host, {
      bootId: "boot-enabled",
      collectedAtMs: Date.UTC(2024, 7, 1),
      sequence: 1,
    });
    const execSpy = vi.spyOn(database.sqlite, "exec");

    const result = cleanupMetricsRetentionDirectly({
      database: database.sqlite,
      metrics: {
        archive: {
          directory: "/data/metrics-archive",
          enabled: true,
          period: "monthly",
        },
        retentionDays: 7,
      },
      nowMs: Date.UTC(2024, 7, 20, 12),
      receivedGraceMs: 60_000,
    });

    expect(result).toEqual({
      deletedMetricSamples: 0,
      deletedReportObservations: 0,
      skipped: true,
    });
    expect(sampleIdentities(database)).toEqual(["boot-enabled:1"]);
    expect(observationIdentities(database)).toEqual(["boot-enabled:1"]);
    expect(execSpy).not.toHaveBeenCalledWith("PRAGMA wal_checkpoint(TRUNCATE)");
    expect(execSpy).not.toHaveBeenCalledWith(expect.stringMatching(/vacuum/i));

    database.close();
  });
});

async function createTestDatabase() {
  const dataRoot = await mkdtemp(
    path.join(os.tmpdir(), "enoki-archive-cleanup-"),
  );
  tempRoots.push(dataRoot);

  return initializeHubDatabase({
    dataRoot,
    sqlitePath: path.join(dataRoot, "enoki.db"),
  });
}

function createHost(
  database: HubDatabase,
  input: { id: number; probeId: string },
) {
  return database.hosts.create({
    clockSkewDetected: false,
    connectAddress: `10.0.0.${input.id}`,
    createdAtMs: Date.UTC(2024, 7, 1),
    displayName: `Host ${input.id}`,
    displayNameEdited: false,
    id: input.id,
    lastClockSkewMs: null,
    probeConfigurationVersion: "config-1",
    probeId: input.probeId,
    probeSecretHash: `secret-probe-hash-${input.id}`,
  });
}

function recordSample(
  database: HubDatabase,
  host: { id: number; probeId: string },
  input: {
    bootId: string;
    collectedAtMs: number;
    receivedAtMs?: number;
    sequence: number;
    withChildren?: boolean;
  },
) {
  const receivedAtMs = input.receivedAtMs ?? input.collectedAtMs + 1_000;
  database.metrics.recordObservationSample({
    observation: {
      bootId: input.bootId,
      hostId: host.id,
      probeId: host.probeId,
      receivedAtMs,
      sequence: input.sequence,
    },
    sample: {
      bootId: input.bootId,
      collectedAtMs: input.collectedAtMs,
      cpuPercent: 25,
      cpuCores: input.withChildren
        ? [
            {
              idle: 70,
              iowait: 1,
              irq: 0,
              name: "cpu0",
              nice: 0,
              softirq: 1,
              steal: 0,
              system: 8,
              usagePercent: 30,
              user: 20,
            },
          ]
        : undefined,
      diskHealth: input.withChildren
        ? [
            {
              deviceName: "nvme0n1",
              model: "Fast Disk",
              passed: true,
              serialNumber: `serial-${input.sequence}`,
            },
          ]
        : undefined,
      disks: input.withChildren
        ? [
            {
              availableBytes: 4_000,
              filesystemType: "ext4",
              mountPoint: "/",
              readBytesDelta: 300,
              totalBytes: 10_000,
              usedBytes: 6_000,
              writeBytesDelta: 700,
            },
          ]
        : undefined,
      diskTotalBytes: input.withChildren ? 10_000 : undefined,
      diskUsedBytes: input.withChildren ? 6_000 : undefined,
      hostId: host.id,
      load1: input.withChildren ? 0.2 : undefined,
      memoryTotalBytes: 16_000,
      memoryUsedBytes: 8_000,
      networkInterfaces: input.withChildren
        ? [
            {
              name: "eth0",
              rxBytes: 20_000,
              rxBytesDelta: 2_000,
              txBytes: 10_000,
              txBytesDelta: 1_000,
            },
          ]
        : undefined,
      networkRxBytesDelta: input.withChildren ? 2_000 : undefined,
      networkTxBytesDelta: input.withChildren ? 1_000 : undefined,
      probeId: host.probeId,
      receivedAtMs,
      sequence: input.sequence,
      temperatureCelsius: input.withChildren ? 40 : undefined,
      uptimeSeconds: input.withChildren ? 12_345 : undefined,
    },
  });

  return {
    bootId: input.bootId,
    collectedAtMs: input.collectedAtMs,
    probeId: host.probeId,
    receivedAtMs,
    sequence: input.sequence,
  };
}

async function markArchiveSucceeded(
  database: HubDatabase,
  input: {
    archiveFileName: string;
    overrideRowCounts?: Record<string, number>;
    rangeEndMs: number;
    rangeStartMs: number;
    samples: Array<{
      bootId: string;
      collectedAtMs: number;
      probeId: string;
      receivedAtMs: number;
      sequence: number;
    }>;
  },
) {
  const archiveRoot = await mkdtemp(
    path.join(os.tmpdir(), "enoki-archive-cleanup-file-"),
  );
  tempRoots.push(archiveRoot);
  const archivePath = path.join(archiveRoot, input.archiveFileName);
  const started = database.metricsArchives.startRun({
    nowMs: Date.UTC(2024, 8, 1, 0, 1),
    period: "monthly",
    rangeEndMs: input.rangeEndMs,
    rangeStartMs: input.rangeStartMs,
  });
  if (!started.ok) {
    throw new Error("Expected Metrics Archive run to start.");
  }

  const archive = writeMetricsArchiveFile({
    archivePath,
    database: database.sqlite,
    nowMs: Date.UTC(2024, 8, 1),
    plan: {
      identity: {
        fileName: path.basename(archivePath),
        path: archivePath,
        sequence: 1,
      },
      period: "monthly",
      rangeEndMs: input.rangeEndMs,
      rangeStartMs: input.rangeStartMs,
      samples: input.samples,
    },
  });

  return database.metricsArchives.markSucceeded({
    archivePath,
    checksumSha256: createHash("sha256")
      .update(readFileSync(archivePath))
      .digest("hex"),
    nowMs: Date.UTC(2024, 8, 1, 0, 2),
    period: "monthly",
    rangeEndMs: input.rangeEndMs,
    rangeStartMs: input.rangeStartMs,
    rowCounts: {
      ...archive.rowCounts,
      ...input.overrideRowCounts,
    },
    runId: started.run.id,
  });
}

function sampleIdentities(database: HubDatabase) {
  return database.sqlite
    .prepare(
      "select boot_id, sequence from metric_samples order by collected_at_ms",
    )
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

function countRows(database: HubDatabase, table: string) {
  return (
    database.sqlite.prepare(`select count(*) as count from ${table}`).get() as {
      count: number;
    }
  ).count;
}
