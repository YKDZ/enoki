import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

describe("Hub database", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("applies migrations to a real SQLite file before audit events are stored", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });

    const event = database.audit.record({
      action: "owner.login",
      actor: "owner",
      occurredAtMs: 1_725_000_000_000,
      outcome: "success",
    });

    expect(event.id).toBeGreaterThan(0);
    expect(database.audit.recent()).toEqual([
      expect.objectContaining({
        action: "owner.login",
        actor: "owner",
        outcome: "success",
      }),
    ]);

    database.close();
  });

  it("applies ordered Migration Layers with independent history tables", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const coreMigrations = path.join(dataRoot, "core-migrations");
    const metricsMigrations = path.join(dataRoot, "metrics-migrations");
    await writeMigration(coreMigrations, "0001_core", [
      "create table core_layer_order (position integer not null)",
      "insert into core_layer_order (position) values (1)",
    ]);
    await writeMigration(metricsMigrations, "0001_metrics", [
      "create table metrics_layer_order (position integer not null)",
      "insert into metrics_layer_order (position) select position + 1 from core_layer_order",
    ]);

    const database = initializeHubDatabase(
      {
        dataRoot,
        sqlitePath: path.join(dataRoot, "enoki.db"),
      },
      {
        migrationLayers: [
          {
            historyTable: "__core_migrations",
            migrationsFolder: coreMigrations,
            name: "core",
          },
          {
            historyTable: "__official_metrics_migrations",
            migrationsFolder: metricsMigrations,
            name: "official_metrics",
          },
        ],
      },
    );

    expect(
      database.sqlite.prepare("select position from metrics_layer_order").get(),
    ).toEqual({ position: 2 });
    expect(migrationHistoryTables(database.sqlite).sort()).toEqual([
      "__core_migrations",
      "__official_metrics_migrations",
    ]);

    database.close();
  });

  it("keeps detailed official Metrics tables out of core-only migrations", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase(
      {
        dataRoot,
        sqlitePath: path.join(dataRoot, "enoki.db"),
      },
      {
        migrationsFolder: path.resolve("drizzle"),
      },
    );

    expect(tables(database.sqlite)).not.toEqual(
      expect.arrayContaining([
        "metric_cpu_cores",
        "metric_disks",
        "metric_network_interfaces",
      ]),
    );

    database.close();
  });

  it("keeps Metrics child rows attached when a sparse official domain row has a different id than its sample", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 77, probeId: "probe-sparse" });

    database.metrics.recordSample({
      bootId: "boot-sparse",
      collectedAtMs: 1_725_000_001_000,
      hostId: 77,
      memoryTotalBytes: 16_000,
      memoryUsedBytes: 8_000,
      probeId: "probe-sparse",
      receivedAtMs: 1_725_000_001_500,
      sequence: 1,
    });
    database.metrics.recordSample({
      bootId: "boot-sparse",
      collectedAtMs: 1_725_000_002_000,
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
      hostId: 77,
      networkInterfaces: [
        {
          name: "eth0",
          rxBytes: 20_000,
          rxBytesDelta: 2_000,
          txBytes: 10_000,
          txBytesDelta: 1_000,
        },
      ],
      probeId: "probe-sparse",
      receivedAtMs: 1_725_000_002_500,
      sequence: 2,
    });

    const history = database.metrics.findSamplesForHost({
      fromCollectedAtMs: 1_725_000_000_000,
      hostId: 77,
      toCollectedAtMs: 1_725_000_003_000,
    });

    expect(history).toEqual([
      expect.objectContaining({
        cpuCores: [],
        disks: [],
        memoryTotalBytes: 16_000,
        memoryUsedBytes: 8_000,
        networkInterfaces: [],
        sequence: 1,
      }),
      expect.objectContaining({
        cpuCores: [{ name: "cpu0", usagePercent: 20 }],
        cpuPercent: 20,
        disks: [
          expect.objectContaining({
            mountPoint: "/",
            readBytesDelta: 300,
            writeBytesDelta: 700,
          }),
        ],
        networkInterfaces: [
          {
            name: "eth0",
            rxBytesDelta: 2_000,
            txBytesDelta: 1_000,
          },
        ],
        sequence: 2,
      }),
    ]);

    database.close();
  });

  it("creates sample indexes for official Metrics domain tables", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });

    expect(uniqueIndexedColumns(database.sqlite)).toEqual(
      expect.arrayContaining([
        "official_metric_cpu.metric_sample_id",
        "official_metric_disk_summary.metric_sample_id",
        "official_metric_load.metric_sample_id",
        "official_metric_memory.metric_sample_id",
        "official_metric_network_summary.metric_sample_id",
        "official_metric_thermal_power.metric_sample_id",
        "official_metric_uptime.metric_sample_id",
      ]),
    );
    expect(indexedColumns(database.sqlite)).toEqual(
      expect.arrayContaining([
        "metric_cpu_cores.metric_sample_id",
        "metric_disks.metric_sample_id",
        "metric_network_interfaces.metric_sample_id",
      ]),
    );

    database.close();
  });

  it("enforces foreign keys and cascades Metrics child rows", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 66, probeId: "probe-cascade" });

    expect(database.sqlite.prepare("PRAGMA foreign_keys").get()).toEqual({
      foreign_keys: 1,
    });
    expect(() =>
      database.metrics.recordSample({
        bootId: "boot-missing-host",
        collectedAtMs: 1_725_000_000_000,
        hostId: 999,
        probeId: "probe-missing-host",
        receivedAtMs: 1_725_000_000_500,
        sequence: 1,
      }),
    ).toThrow();

    database.metrics.recordSample({
      bootId: "boot-cascade",
      collectedAtMs: 1_725_000_001_000,
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
      hostId: 66,
      memoryTotalBytes: 16_000,
      memoryUsedBytes: 8_000,
      probeId: "probe-cascade",
      receivedAtMs: 1_725_000_001_500,
      sequence: 1,
    });
    const sample = database.sqlite
      .prepare("select id from metric_samples where probe_id = ?")
      .get("probe-cascade") as { id: number };

    database.sqlite
      .prepare("delete from metric_samples where id = ?")
      .run(sample.id);

    expect(
      database.sqlite
        .prepare(
          `
          select
            (select count(*) from official_metric_cpu) as cpu,
            (select count(*) from official_metric_memory) as memory,
            (select count(*) from metric_cpu_cores) as cores
          `,
        )
        .get(),
    ).toEqual({
      cores: 0,
      cpu: 0,
      memory: 0,
    });

    database.close();
  });

  it("stores detailed CPU, disk, and network Metrics when only the official Metrics layer creates their tables", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const coreMigrations = path.join(dataRoot, "core-envelope-migrations");
    await writeMigration(coreMigrations, "0001_core_envelope", [
      `create table metric_samples (
        id integer primary key autoincrement not null,
        managed_host_id integer not null,
        probe_id text not null,
        boot_id text not null,
        sequence integer not null,
        collected_at_ms integer not null,
        received_at_ms integer not null,
        cpu_percent real,
        cpu_user_percent real,
        cpu_system_percent real,
        cpu_iowait_percent real,
        cpu_steal_percent real,
        cpu_idle_percent real,
        memory_used_bytes integer,
        memory_total_bytes integer,
        memory_cache_bytes integer,
        swap_total_bytes integer,
        swap_used_bytes integer,
        load_1 real,
        load_5 real,
        load_15 real,
        uptime_seconds integer,
        temperature_celsius real,
        battery_percent integer,
        battery_state text,
        disk_used_bytes integer,
        disk_total_bytes integer,
        network_rx_bytes_delta integer,
        network_tx_bytes_delta integer
      )`,
      "create unique index metric_samples_probe_boot_sequence_idx on metric_samples (probe_id, boot_id, sequence)",
    ]);

    const database = initializeHubDatabase(
      {
        dataRoot,
        sqlitePath: path.join(dataRoot, "enoki.db"),
      },
      {
        migrationLayers: [
          {
            historyTable: "__core_migrations",
            migrationsFolder: coreMigrations,
            name: "core",
          },
          {
            historyTable: "__official_metrics_migrations",
            migrationsFolder: path.resolve("drizzle-official-metrics"),
            name: "official_metrics",
          },
        ],
      },
    );

    database.metrics.recordSample({
      bootId: "boot-official-detail",
      collectedAtMs: 1_725_000_020_000,
      cpuCores: [
        {
          idle: 60,
          iowait: 2,
          irq: 0,
          name: "cpu0",
          nice: 0,
          softirq: 1,
          steal: 0,
          system: 12,
          usagePercent: 40,
          user: 25,
        },
      ],
      disks: [
        {
          availableBytes: 8_000,
          filesystemType: "xfs",
          ioUtilizationPercent: 9.5,
          mountPoint: "/data",
          readAwaitMs: 1.2,
          readBytesDelta: 900,
          totalBytes: 20_000,
          usedBytes: 12_000,
          weightedIoPercent: 10.5,
          writeAwaitMs: 2.3,
          writeBytesDelta: 1_100,
        },
      ],
      hostId: 88,
      networkInterfaces: [
        {
          name: "ens3",
          rxBytes: 50_000,
          rxBytesDelta: 5_000,
          txBytes: 40_000,
          txBytesDelta: 4_000,
        },
      ],
      probeId: "probe-official-detail",
      receivedAtMs: 1_725_000_020_500,
      sequence: 1,
    });

    expect(
      database.metrics.findSamplesForHost({
        fromCollectedAtMs: 1_725_000_019_000,
        hostId: 88,
        toCollectedAtMs: 1_725_000_021_000,
      }),
    ).toEqual([
      expect.objectContaining({
        cpuCores: [{ name: "cpu0", usagePercent: 40 }],
        disks: [
          expect.objectContaining({
            ioUtilizationPercent: 9.5,
            mountPoint: "/data",
            readAwaitMs: 1.2,
            weightedIoPercent: 10.5,
            writeAwaitMs: 2.3,
          }),
        ],
        networkInterfaces: [
          {
            name: "ens3",
            rxBytesDelta: 5_000,
            txBytesDelta: 4_000,
          },
        ],
      }),
    ]);

    database.close();
  });

  it("returns latest-known low-frequency Disk Health when the latest high-frequency sample is sparse", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 99, probeId: "probe-disk-health" });

    database.metrics.recordSample({
      bootId: "boot-disk-health",
      collectedAtMs: 1_725_000_000_000,
      diskHealth: [
        {
          deviceName: "/dev/sda",
          model: "Samsung SSD 870 EVO 1TB",
          passed: true,
          powerOnHours: 12_345,
          serialNumber: "S6PTEST",
          temperatureCelsius: 31,
        },
      ],
      hostId: 99,
      probeId: "probe-disk-health",
      receivedAtMs: 1_725_000_000_500,
      sequence: 1,
    });
    database.metrics.recordSample({
      bootId: "boot-disk-health",
      collectedAtMs: 1_725_000_005_000,
      cpuPercent: 25,
      hostId: 99,
      probeId: "probe-disk-health",
      receivedAtMs: 1_725_000_005_500,
      sequence: 2,
    });

    expect(database.metrics.findLatestSample(99)).toEqual(
      expect.objectContaining({
        cpuPercent: 25,
        diskHealth: [
          expect.objectContaining({
            deviceName: "/dev/sda",
            model: "Samsung SSD 870 EVO 1TB",
            passed: true,
            powerOnHours: 12_345,
            serialNumber: "S6PTEST",
            temperatureCelsius: 31,
          }),
        ],
        sequence: 2,
      }),
    );
    expect(
      database.metrics.findSamplesForHost({
        fromCollectedAtMs: 1_725_000_000_000,
        hostId: 99,
        toCollectedAtMs: 1_725_000_006_000,
      }),
    ).toEqual([
      expect.objectContaining({
        diskHealth: [
          expect.objectContaining({
            deviceName: "/dev/sda",
            passed: true,
          }),
        ],
        sequence: 1,
      }),
      expect.objectContaining({
        diskHealth: [],
        sequence: 2,
      }),
    ]);

    database.close();
  });

  it("enforces one active Probe Operation per Host and creates lookup indexes", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 7, probeId: "probe-operation" });

    const indexes = database.sqlite
      .prepare(
        "select name from sqlite_master where type = 'index' and tbl_name = 'probe_operations'",
      )
      .all()
      .map((row) => (row as { name: string }).name);
    expect(indexes).toEqual(
      expect.arrayContaining([
        "probe_operations_active_for_host_idx",
        "probe_operations_latest_for_host_idx",
        "probe_operations_one_active_per_host_idx",
      ]),
    );

    database.probeOperations.createProbeUpgradeRequest({
      acceptedAtMs: null,
      canceledAtMs: null,
      completedAtMs: null,
      createdAtMs: 1_725_000_000_000,
      currentProbeVersion: "0.1.0",
      failureCode: null,
      failureMessage: null,
      hostId: 7,
      id: null,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "pending",
      supersededAtMs: null,
      targetProbeVersion: "0.2.0",
      updatedAtMs: 1_725_000_000_000,
    });

    expect(() =>
      database.probeOperations.createProbeUpgradeRequest({
        acceptedAtMs: null,
        canceledAtMs: null,
        completedAtMs: null,
        createdAtMs: 1_725_000_001_000,
        currentProbeVersion: "0.1.0",
        failureCode: null,
        failureMessage: null,
        hostId: 7,
        id: null,
        kind: "probe_upgrade",
        runningAtMs: null,
        state: "pending",
        supersededAtMs: null,
        targetProbeVersion: "0.3.0",
        updatedAtMs: 1_725_000_001_000,
      }),
    ).toThrow();

    database.probeOperations.createProbeUpgradeRequest({
      acceptedAtMs: null,
      canceledAtMs: null,
      completedAtMs: 1_725_000_002_000,
      createdAtMs: 1_725_000_001_000,
      currentProbeVersion: "0.1.0",
      failureCode: "manual_failure",
      failureMessage: "Failed for test setup.",
      hostId: 7,
      id: null,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "failed",
      supersededAtMs: null,
      targetProbeVersion: "0.3.0",
      updatedAtMs: 1_725_000_002_000,
    });

    expect(database.probeOperations.findActiveForHost(7)).toEqual(
      expect.objectContaining({
        state: "pending",
        targetProbeVersion: "0.2.0",
      }),
    );
    expect(database.probeOperations.findLatestForHost(7)).toEqual(
      expect.objectContaining({
        state: "failed",
        targetProbeVersion: "0.3.0",
      }),
    );

    database.close();
  });
});

async function writeMigration(
  migrationsFolder: string,
  name: string,
  statements: string[],
) {
  const migrationFolder = path.join(migrationsFolder, name);
  await mkdir(migrationFolder, { recursive: true });
  await writeFile(
    path.join(migrationFolder, "migration.sql"),
    statements.join(";--> statement-breakpoint\n"),
  );
}

function createHost(
  database: ReturnType<typeof initializeHubDatabase>,
  input: { id: number; probeId: string },
) {
  return database.hosts.create({
    clockSkewDetected: false,
    connectAddress: "10.0.0.20",
    createdAtMs: 1_725_000_000_000,
    displayName: `Host ${input.id}`,
    displayNameEdited: false,
    id: input.id,
    lastClockSkewMs: null,
    probeConfigurationVersion: "default-v1",
    probeId: input.probeId,
    probeSecretHash: `secret-hash-${input.id}`,
  });
}

function migrationHistoryTables(sqlite: {
  prepare: (sql: string) => { all: () => unknown[] };
}) {
  return sqlite
    .prepare(
      "select name from sqlite_master where type = 'table' and name like '__%migrations'",
    )
    .all()
    .map((row) => (row as { name: string }).name);
}

function tables(sqlite: {
  prepare: (sql: string) => {
    all: () => unknown[];
  };
}) {
  return sqlite
    .prepare("select name from sqlite_master where type = 'table'")
    .all()
    .map((row) => (row as { name: string }).name);
}

function uniqueIndexedColumns(sqlite: {
  prepare: (sql: string) => {
    all: () => unknown[];
  };
}) {
  return sqlite
    .prepare(
      `
      select m.name || '.' || ii.name as column_name
      from sqlite_master m
      join pragma_index_list(m.name) il
      join pragma_index_info(il.name) ii
      where m.type = 'table' and il."unique" = 1
      order by column_name
      `,
    )
    .all()
    .map((row) => (row as { column_name: string }).column_name);
}

function indexedColumns(sqlite: {
  prepare: (sql: string) => {
    all: () => unknown[];
  };
}) {
  return sqlite
    .prepare(
      `
      select m.name || '.' || ii.name as column_name
      from sqlite_master m
      join pragma_index_list(m.name) il
      join pragma_index_info(il.name) ii
      where m.type = 'table'
      order by column_name
      `,
    )
    .all()
    .map((row) => (row as { column_name: string }).column_name);
}
