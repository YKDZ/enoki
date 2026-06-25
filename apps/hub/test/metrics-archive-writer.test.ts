import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import { initializeHubDatabase, type HubDatabase } from "../src/database/index";
import { writeMetricsArchiveFile } from "../src/metrics-archive/writer";

const tempRoots: string[] = [];

describe("Metrics Archive file writer", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("creates a temporary SQLite archive for one planned range with Metrics closure and de-sensitive Host snapshot", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-archive-writer-"));
    tempRoots.push(root);
    const archivePath = path.join(root, "metrics-archive-2024-08.sqlite.tmp");
    const database = initializeHubDatabase({
      dataRoot: root,
      sqlitePath: path.join(root, "enoki.db"),
    });
    const host = createHost(database, {
      displayName: "Archive Host",
      hostname: "archive-host",
      id: 42,
      observedIp: "203.0.113.7",
      probeId: "probe-archive",
    });
    const archivedCollectedAtMs = Date.UTC(2024, 7, 12, 12, 1, 0);
    const archivedReceivedAtMs = Date.UTC(2024, 7, 12, 12, 1, 1);
    const outsideHost = createHost(database, {
      id: 43,
      probeId: "probe-outside",
    });
    database.metrics.recordObservation({
      bootId: "boot-archive",
      hostId: host.id,
      probeId: host.probeId,
      receivedAtMs: Date.UTC(2024, 7, 12, 12, 0, 1),
      sequence: 1,
    });
    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-archive",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs: Date.UTC(2024, 7, 12, 12, 1, 1),
        sequence: 2,
      },
      sample: {
        bootId: "boot-archive",
        collectedAtMs: archivedCollectedAtMs,
        cpuCores: [
          {
            idle: 80,
            iowait: 1,
            irq: 0,
            name: "cpu0",
            nice: 0,
            softirq: 1,
            steal: 0,
            system: 8,
            usagePercent: 20,
            user: 10,
          },
        ],
        cpuPercent: 20,
        diskHealth: [
          {
            deviceName: "nvme0n1",
            model: "Fast Disk",
            passed: true,
            serialNumber: "serial-1",
          },
        ],
        disks: [
          {
            availableBytes: 4_000,
            filesystemType: "ext4",
            mountPoint: "/",
            readBytesDelta: 300,
            totalBytes: 10_000,
            usedBytes: 6_000,
            writeBytesDelta: 700,
          },
        ],
        diskTotalBytes: 10_000,
        diskUsedBytes: 6_000,
        hostId: host.id,
        load1: 0.2,
        memoryTotalBytes: 16_000,
        memoryUsedBytes: 8_000,
        networkInterfaces: [
          {
            name: "eth0",
            rxBytes: 20_000,
            rxBytesDelta: 2_000,
            txBytes: 10_000,
            txBytesDelta: 1_000,
          },
        ],
        networkRxBytesDelta: 2_000,
        networkTxBytesDelta: 1_000,
        probeId: host.probeId,
        receivedAtMs: archivedReceivedAtMs,
        sequence: 2,
        temperatureCelsius: 40,
        uptimeSeconds: 12_345,
      },
    });
    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-outside",
        hostId: outsideHost.id,
        probeId: outsideHost.probeId,
        receivedAtMs: Date.UTC(2024, 8, 2, 12, 0, 1),
        sequence: 1,
      },
      sample: {
        bootId: "boot-outside",
        collectedAtMs: Date.UTC(2024, 8, 2, 12, 0, 0),
        hostId: outsideHost.id,
        memoryTotalBytes: 32_000,
        memoryUsedBytes: 12_000,
        probeId: outsideHost.probeId,
        receivedAtMs: Date.UTC(2024, 8, 2, 12, 0, 1),
        sequence: 1,
      },
    });

    database.hosts.insertProbeRequestNonce({
      expiresAtMs: Date.UTC(2024, 7, 12, 13),
      nonce: "secret-nonce",
      nowMs: Date.UTC(2024, 7, 12, 12),
      probeId: host.probeId,
    });
    database.enrollments.createPending({
      createdAtMs: Date.UTC(2024, 7, 12, 12),
      expiresAtMs: Date.UTC(2024, 7, 13, 12),
      tokenHash: "secret-token-hash",
    });
    database.audit.record({
      action: "owner.login",
      actor: "owner",
      occurredAtMs: Date.UTC(2024, 7, 12, 12),
      outcome: "success",
    });

    const result = writeMetricsArchiveFile({
      archivePath,
      database: database.sqlite,
      hostSnapshotCapturedAtMs: Date.UTC(2024, 8, 1, 0, 0, 5),
      nowMs: Date.UTC(2024, 8, 1),
      plan: {
        identity: {
          fileName: path.basename(archivePath),
          path: archivePath,
          sequence: 1,
        },
        period: "monthly",
        rangeEndMs: Date.UTC(2024, 8, 1),
        rangeStartMs: Date.UTC(2024, 7, 1),
        samples: [
          {
            bootId: "boot-archive",
            collectedAtMs: archivedCollectedAtMs,
            probeId: host.probeId,
            receivedAtMs: archivedReceivedAtMs,
            sequence: 2,
          },
        ],
      },
    });

    expect(result).toEqual({
      archivePath,
      rowCounts: expect.objectContaining({
        archive_metadata: 1,
        archive_host_snapshots: 1,
        metric_samples: 1,
        metric_cpu_cores: 1,
        metric_disks: 1,
        metric_network_interfaces: 1,
        official_metric_cpu: 1,
        official_metric_disk_health: 1,
        official_metric_disk_summary: 1,
        official_metric_load: 1,
        official_metric_memory: 1,
        official_metric_network_summary: 1,
        official_metric_thermal_power: 1,
        official_metric_uptime: 1,
        report_observations: 1,
      }),
    });
    expect(existsSync(archivePath)).toBe(true);
    database.close();

    const archive = new DatabaseSync(archivePath, { readOnly: true });
    try {
      expect(archive.prepare("select * from archive_metadata").get()).toEqual(
        expect.objectContaining({
          archive_schema_version: 1,
          created_at_ms: Date.UTC(2024, 8, 1),
          host_snapshot_captured_at_ms: Date.UTC(2024, 8, 1, 0, 0, 5),
          period: "monthly",
          range_end_ms: Date.UTC(2024, 8, 1),
          range_start_ms: Date.UTC(2024, 7, 1),
          row_counts_json: expect.stringContaining('"metric_samples":1'),
          sequence: 1,
        }),
      );
      expect(
        archive
          .prepare(
            "select probe_id, boot_id, sequence, collected_at_ms from metric_samples",
          )
          .all(),
      ).toEqual([
        {
          boot_id: "boot-archive",
          collected_at_ms: Date.UTC(2024, 7, 12, 12, 1, 0),
          probe_id: "probe-archive",
          sequence: 2,
        },
      ]);
      expect(
        archive
          .prepare(
            "select probe_id, boot_id, sequence from report_observations order by sequence",
          )
          .all(),
      ).toEqual([
        { boot_id: "boot-archive", probe_id: "probe-archive", sequence: 2 },
      ]);
      expect(
        archive
          .prepare(
            "select display_name, hostname, connect_address, observed_ip from archive_host_snapshots",
          )
          .get(),
      ).toEqual({
        connect_address: "10.0.0.42",
        display_name: "Archive Host",
        hostname: "archive-host",
        observed_ip: "203.0.113.7",
      });
      expect(tableColumns(archive, "archive_host_snapshots")).not.toEqual(
        expect.arrayContaining(["probe_public_key_pem", "probe_secret_hash"]),
      );
      expect(
        archive
          .prepare("select name from sqlite_master where type = 'table'")
          .all()
          .map((row) => (row as { name: string }).name),
      ).not.toEqual(
        expect.arrayContaining([
          "audit_log",
          "enrollment_tokens",
          "probe_operations",
          "probe_operation_tokens",
          "probe_request_nonces",
          "owner_sessions",
        ]),
      );
      expect(indexNames(archive)).toEqual(
        expect.arrayContaining([
          "archive_host_snapshots_host_lookup_idx",
          "metric_samples_host_time_idx",
          "metric_samples_probe_boot_sequence_idx",
          "metric_cpu_cores_sample_idx",
          "metric_disks_sample_idx",
          "metric_network_interfaces_sample_idx",
          "official_metric_disk_health_sample_idx",
          "report_observations_probe_boot_sequence_idx",
        ]),
      );
    } finally {
      archive.close();
    }
  });

  it("archives an empty Metrics closure when the plan has no samples", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-archive-writer-"));
    tempRoots.push(root);
    const archivePath = path.join(root, "metrics-archive-2024-08.sqlite.tmp");
    const database = initializeHubDatabase({
      dataRoot: root,
      sqlitePath: path.join(root, "enoki.db"),
    });
    const host = createHost(database, { id: 47, probeId: "probe-empty-plan" });

    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-empty-plan",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs: Date.UTC(2024, 7, 12, 10, 0, 1),
        sequence: 1,
      },
      sample: {
        bootId: "boot-empty-plan",
        collectedAtMs: Date.UTC(2024, 7, 12, 10),
        hostId: host.id,
        memoryUsedBytes: 1_000,
        probeId: host.probeId,
        receivedAtMs: Date.UTC(2024, 7, 12, 10, 0, 1),
        sequence: 1,
      },
    });

    const result = writeMetricsArchiveFile({
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
        rangeEndMs: Date.UTC(2024, 8, 1),
        rangeStartMs: Date.UTC(2024, 7, 1),
        samples: [],
      },
    });
    database.close();

    expect(result.rowCounts).toEqual(
      expect.objectContaining({
        archive_host_snapshots: 0,
        archive_metadata: 1,
        metric_samples: 0,
        report_observations: 0,
      }),
    );
  });

  it("excludes same-period samples that are not in the plan", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-archive-writer-"));
    tempRoots.push(root);
    const archivePath = path.join(root, "metrics-archive-2024-08.sqlite.tmp");
    const database = initializeHubDatabase({
      dataRoot: root,
      sqlitePath: path.join(root, "enoki.db"),
    });
    const host = createHost(database, { id: 44, probeId: "probe-late" });
    const plannedCollectedAtMs = Date.UTC(2024, 7, 12, 10);
    const plannedReceivedAtMs = Date.UTC(2024, 7, 12, 10, 0, 1);

    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-late",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs: plannedReceivedAtMs,
        sequence: 1,
      },
      sample: {
        bootId: "boot-late",
        collectedAtMs: plannedCollectedAtMs,
        hostId: host.id,
        memoryUsedBytes: 1_000,
        probeId: host.probeId,
        receivedAtMs: plannedReceivedAtMs,
        sequence: 1,
      },
    });
    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-late",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs: Date.UTC(2024, 8, 1, 0, 4),
        sequence: 2,
      },
      sample: {
        bootId: "boot-late",
        collectedAtMs: Date.UTC(2024, 7, 12, 11),
        hostId: host.id,
        memoryUsedBytes: 2_000,
        probeId: host.probeId,
        receivedAtMs: Date.UTC(2024, 8, 1, 0, 4),
        sequence: 2,
      },
    });

    writeMetricsArchiveFile({
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
        rangeEndMs: Date.UTC(2024, 8, 1),
        rangeStartMs: Date.UTC(2024, 7, 1),
        samples: [
          {
            bootId: "boot-late",
            collectedAtMs: plannedCollectedAtMs,
            probeId: host.probeId,
            receivedAtMs: plannedReceivedAtMs,
            sequence: 1,
          },
        ],
      },
    });
    database.close();

    const archive = new DatabaseSync(archivePath, { readOnly: true });
    try {
      expect(
        archive.prepare("select sequence from metric_samples").all(),
      ).toEqual([{ sequence: 1 }]);
    } finally {
      archive.close();
    }
  });

  it("archives only observations matching archived sample identities", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-archive-writer-"));
    tempRoots.push(root);
    const archivePath = path.join(root, "metrics-archive-2024-08.sqlite.tmp");
    const database = initializeHubDatabase({
      dataRoot: root,
      sqlitePath: path.join(root, "enoki.db"),
    });
    const host = createHost(database, {
      id: 45,
      probeId: "probe-observations",
    });
    const collectedAtMs = Date.UTC(2024, 7, 31, 23, 59);
    const receivedAtMs = Date.UTC(2024, 8, 1, 0, 1);

    database.metrics.recordObservation({
      bootId: "boot-observations",
      hostId: host.id,
      probeId: host.probeId,
      receivedAtMs: Date.UTC(2024, 7, 15),
      sequence: 4,
    });
    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-observations",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 5,
      },
      sample: {
        bootId: "boot-observations",
        collectedAtMs,
        hostId: host.id,
        memoryUsedBytes: 5_000,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 5,
      },
    });

    writeMetricsArchiveFile({
      archivePath,
      database: database.sqlite,
      nowMs: Date.UTC(2024, 8, 2),
      plan: {
        identity: {
          fileName: path.basename(archivePath),
          path: archivePath,
          sequence: 1,
        },
        period: "monthly",
        rangeEndMs: Date.UTC(2024, 8, 1),
        rangeStartMs: Date.UTC(2024, 7, 1),
        samples: [
          {
            bootId: "boot-observations",
            collectedAtMs,
            probeId: host.probeId,
            receivedAtMs,
            sequence: 5,
          },
        ],
      },
    });
    database.close();

    const archive = new DatabaseSync(archivePath, { readOnly: true });
    try {
      expect(
        archive
          .prepare(
            "select sequence, received_at_ms from report_observations order by sequence",
          )
          .all(),
      ).toEqual([{ received_at_ms: receivedAtMs, sequence: 5 }]);
    } finally {
      archive.close();
    }
  });

  it("uses inclusive range_start and exclusive range_end boundaries", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-archive-writer-"));
    tempRoots.push(root);
    const archivePath = path.join(root, "metrics-archive-2024-08.sqlite.tmp");
    const database = initializeHubDatabase({
      dataRoot: root,
      sqlitePath: path.join(root, "enoki.db"),
    });
    const host = createHost(database, { id: 46, probeId: "probe-boundary" });
    const rangeStartMs = Date.UTC(2024, 7, 1);
    const rangeEndMs = Date.UTC(2024, 8, 1);

    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-boundary",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs: rangeStartMs + 1,
        sequence: 1,
      },
      sample: {
        bootId: "boot-boundary",
        collectedAtMs: rangeStartMs,
        hostId: host.id,
        memoryUsedBytes: 1,
        probeId: host.probeId,
        receivedAtMs: rangeStartMs + 1,
        sequence: 1,
      },
    });
    database.metrics.recordObservationSample({
      observation: {
        bootId: "boot-boundary",
        hostId: host.id,
        probeId: host.probeId,
        receivedAtMs: rangeEndMs + 1,
        sequence: 2,
      },
      sample: {
        bootId: "boot-boundary",
        collectedAtMs: rangeEndMs,
        hostId: host.id,
        memoryUsedBytes: 2,
        probeId: host.probeId,
        receivedAtMs: rangeEndMs + 1,
        sequence: 2,
      },
    });

    writeMetricsArchiveFile({
      archivePath,
      database: database.sqlite,
      nowMs: rangeEndMs,
      plan: {
        identity: {
          fileName: path.basename(archivePath),
          path: archivePath,
          sequence: 1,
        },
        period: "monthly",
        rangeEndMs,
        rangeStartMs,
        samples: [
          {
            bootId: "boot-boundary",
            collectedAtMs: rangeStartMs,
            probeId: host.probeId,
            receivedAtMs: rangeStartMs + 1,
            sequence: 1,
          },
          {
            bootId: "boot-boundary",
            collectedAtMs: rangeEndMs,
            probeId: host.probeId,
            receivedAtMs: rangeEndMs + 1,
            sequence: 2,
          },
        ],
      },
    });
    database.close();

    const archive = new DatabaseSync(archivePath, { readOnly: true });
    try {
      expect(
        archive
          .prepare("select sequence, collected_at_ms from metric_samples")
          .all(),
      ).toEqual([{ collected_at_ms: rangeStartMs, sequence: 1 }]);
    } finally {
      archive.close();
    }
  });
});

function createHost(
  database: HubDatabase,
  input: {
    displayName?: string;
    hostname?: string | null;
    id: number;
    observedIp?: string | null;
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
    displayName: input.displayName ?? `Host ${input.id}`,
    displayNameEdited: false,
    hostname: input.hostname ?? `host-${input.id}`,
    kernel: "6.1",
    lastClockSkewMs: null,
    lastReportAtMs: Date.UTC(2024, 7, 12),
    memoryTotalBytes: 16_000,
    observedIp: input.observedIp ?? "192.0.2.10",
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

function indexNames(database: DatabaseSync) {
  return database
    .prepare("select name from sqlite_master where type = 'index'")
    .all()
    .map((row) => (row as { name: string }).name);
}

function tableColumns(database: DatabaseSync, table: string) {
  return database
    .prepare(`pragma table_info(${table})`)
    .all()
    .map((row) => (row as { name: string }).name);
}
