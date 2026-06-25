import { rmSync, mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import type { MetricsArchivePeriodPlan } from "./planner.js";

export type MetricsArchivePlannedSample = {
  bootId: string;
  collectedAtMs: number;
  probeId: string;
  receivedAtMs: number;
  sequence: number;
};

export type MetricsArchiveFileRowCounts = Record<string, number>;

export type WriteMetricsArchiveFileInput = {
  archivePath: string;
  database: DatabaseSync;
  hostSnapshotCapturedAtMs?: number;
  nowMs: number;
  plan: MetricsArchivePeriodPlan<MetricsArchivePlannedSample>;
};

export type WriteMetricsArchiveFileResult = {
  archivePath: string;
  rowCounts: MetricsArchiveFileRowCounts;
};

const archiveSchemaVersion = 1;

const archiveTables = [
  "archive_metadata",
  "archive_host_snapshots",
  "metric_samples",
  "official_metric_cpu",
  "official_metric_memory",
  "official_metric_load",
  "official_metric_uptime",
  "official_metric_thermal_power",
  "official_metric_disk_summary",
  "official_metric_network_summary",
  "metric_cpu_cores",
  "metric_disks",
  "metric_network_interfaces",
  "official_metric_disk_health",
  "report_observations",
] as const;

const metricsChildTables = [
  "official_metric_cpu",
  "official_metric_memory",
  "official_metric_load",
  "official_metric_uptime",
  "official_metric_thermal_power",
  "official_metric_disk_summary",
  "official_metric_network_summary",
  "metric_cpu_cores",
  "metric_disks",
  "metric_network_interfaces",
  "official_metric_disk_health",
] as const;

type SqlValue = string | number | null;
type SqlRow = Record<string, SqlValue>;

export function writeMetricsArchiveFile(
  input: WriteMetricsArchiveFileInput,
): WriteMetricsArchiveFileResult {
  mkdirSync(path.dirname(input.archivePath), { recursive: true });
  rmSync(input.archivePath, { force: true });

  const archive = new DatabaseSync(input.archivePath);
  try {
    archive.exec("PRAGMA foreign_keys = ON");
    archive.exec("BEGIN");
    createArchiveSchema(archive);
    copyMetricsClosure(input.database, archive, input.plan);
    const rowCounts = countArchiveRows(archive);
    rowCounts.archive_metadata = 1;
    writeArchiveMetadata(input, archive, rowCounts);
    archive.exec("COMMIT");
    archive.exec("PRAGMA optimize");
    archive.close();
    return {
      archivePath: input.archivePath,
      rowCounts,
    };
  } catch (error) {
    try {
      archive.exec("ROLLBACK");
    } catch {
      // Ignore rollback errors after SQLite has already aborted the transaction.
    }
    archive.close();
    rmSync(input.archivePath, { force: true });
    throw error;
  }
}

function createArchiveSchema(database: DatabaseSync) {
  database.exec(`
    create table archive_metadata (
      id integer primary key check (id = 1),
      archive_schema_version integer not null,
      created_at_ms integer not null,
      enoki_version text,
      period text not null,
      range_start_ms integer not null,
      range_end_ms integer not null,
      sequence integer not null,
      row_counts_json text not null,
      host_snapshot_captured_at_ms integer not null
    );

    create table archive_host_snapshots (
      id integer primary key,
      managed_host_id integer not null,
      probe_id text not null,
      display_name text not null,
      description text not null,
      hostname text,
      os text,
      kernel text,
      architecture text,
      cpu_count integer,
      cpu_model text,
      memory_total_bytes integer,
      probe_version text,
      connect_address text not null,
      observed_ip text,
      deleted_at_ms integer,
      last_report_at_ms integer
    );

    create table metric_samples (
      id integer primary key,
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
    );

    create table official_metric_cpu (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      cpu_percent real,
      cpu_user_percent real,
      cpu_system_percent real,
      cpu_iowait_percent real,
      cpu_steal_percent real,
      cpu_idle_percent real
    );

    create table official_metric_memory (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      memory_used_bytes integer,
      memory_total_bytes integer,
      memory_cache_bytes integer,
      swap_total_bytes integer,
      swap_used_bytes integer
    );

    create table official_metric_load (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      load_1 real,
      load_5 real,
      load_15 real
    );

    create table official_metric_uptime (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      uptime_seconds integer
    );

    create table official_metric_thermal_power (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      temperature_celsius real,
      battery_percent integer,
      battery_state text
    );

    create table official_metric_disk_summary (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      disk_used_bytes integer,
      disk_total_bytes integer
    );

    create table official_metric_network_summary (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      network_rx_bytes_delta integer,
      network_tx_bytes_delta integer
    );

    create table metric_cpu_cores (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      name text not null,
      user integer not null,
      nice integer not null,
      system integer not null,
      idle integer not null,
      iowait integer not null,
      irq integer not null,
      softirq integer not null,
      steal integer not null,
      usage_percent real not null
    );

    create table metric_disks (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      mount_point text not null,
      filesystem_type text not null,
      total_bytes integer not null,
      used_bytes integer not null,
      available_bytes integer not null,
      read_bytes_delta integer not null,
      write_bytes_delta integer not null,
      io_utilization_percent real,
      read_await_ms real,
      write_await_ms real,
      weighted_io_percent real
    );

    create table metric_network_interfaces (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      name text not null,
      rx_bytes integer not null,
      tx_bytes integer not null,
      rx_bytes_delta integer not null,
      tx_bytes_delta integer not null
    );

    create table official_metric_disk_health (
      id integer primary key,
      metric_sample_id integer not null references metric_samples(id) on delete cascade,
      device_name text not null,
      model text,
      serial_number text,
      passed integer not null,
      temperature_celsius real,
      power_on_hours integer,
      total_bytes integer,
      used_bytes integer,
      usage_mount_point text,
      role text
    );

    create table report_observations (
      id integer primary key,
      managed_host_id integer not null,
      probe_id text not null,
      boot_id text not null,
      sequence integer not null,
      received_at_ms integer not null
    );

    create index archive_host_snapshots_host_lookup_idx
      on archive_host_snapshots (managed_host_id, probe_id);
    create index metric_samples_host_time_idx
      on metric_samples (managed_host_id, collected_at_ms);
    create unique index metric_samples_probe_boot_sequence_idx
      on metric_samples (probe_id, boot_id, sequence);
    create unique index official_metric_cpu_sample_idx
      on official_metric_cpu (metric_sample_id);
    create unique index official_metric_memory_sample_idx
      on official_metric_memory (metric_sample_id);
    create unique index official_metric_load_sample_idx
      on official_metric_load (metric_sample_id);
    create unique index official_metric_uptime_sample_idx
      on official_metric_uptime (metric_sample_id);
    create unique index official_metric_thermal_power_sample_idx
      on official_metric_thermal_power (metric_sample_id);
    create unique index official_metric_disk_summary_sample_idx
      on official_metric_disk_summary (metric_sample_id);
    create unique index official_metric_network_summary_sample_idx
      on official_metric_network_summary (metric_sample_id);
    create index metric_cpu_cores_sample_idx on metric_cpu_cores (metric_sample_id);
    create index metric_disks_sample_idx on metric_disks (metric_sample_id);
    create index metric_network_interfaces_sample_idx
      on metric_network_interfaces (metric_sample_id);
    create index official_metric_disk_health_sample_idx
      on official_metric_disk_health (metric_sample_id);
    create unique index report_observations_probe_boot_sequence_idx
      on report_observations (probe_id, boot_id, sequence);
  `);
}

function copyMetricsClosure(
  hot: DatabaseSync,
  archive: DatabaseSync,
  plan: MetricsArchivePeriodPlan<MetricsArchivePlannedSample>,
) {
  if (plan.samples.length === 0) {
    return;
  }

  const plannedSampleFilter = sampleIdentityFilter(plan.samples);
  const samples = hot
    .prepare(
      `
        select *
        from metric_samples
        where collected_at_ms >= ? and collected_at_ms < ?
          and (${plannedSampleFilter.sql})
        order by collected_at_ms, id
      `,
    )
    .all(
      plan.rangeStartMs,
      plan.rangeEndMs,
      ...plannedSampleFilter.parameters,
    ) as SqlRow[];

  insertRows(archive, "metric_samples", samples);
  if (samples.length === 0) {
    return;
  }

  const sampleIds = samples.map((sample) => Number(sample.id));
  const hostIds = [
    ...new Set(samples.map((sample) => Number(sample.managed_host_id))),
  ];
  const hostSnapshots = selectRowsByIds(
    hot,
    "managed_hosts",
    "id",
    hostIds,
  ).map((host) => ({
    architecture: host.architecture ?? null,
    connect_address: host.connect_address ?? null,
    cpu_count: host.cpu_count ?? null,
    cpu_model: host.cpu_model ?? null,
    deleted_at_ms: host.deleted_at_ms ?? null,
    description: host.description ?? null,
    display_name: host.display_name ?? null,
    hostname: host.hostname ?? null,
    id: host.id ?? null,
    kernel: host.kernel ?? null,
    last_report_at_ms: host.last_report_at_ms ?? null,
    managed_host_id: host.id ?? null,
    memory_total_bytes: host.memory_total_bytes ?? null,
    observed_ip: host.observed_ip ?? null,
    os: host.os ?? null,
    probe_id: host.probe_id ?? null,
    probe_version: host.probe_version ?? null,
  }));
  insertRows(archive, "archive_host_snapshots", hostSnapshots);

  for (const table of metricsChildTables) {
    insertRows(
      archive,
      table,
      selectRowsByIds(hot, table, "metric_sample_id", sampleIds),
    );
  }

  const archivedSampleFilter = sampleRowsIdentityFilter("ro", samples);
  const observations = hot
    .prepare(
      `
        select ro.*
        from report_observations ro
        where ${archivedSampleFilter.sql}
        order by ro.received_at_ms, ro.id
      `,
    )
    .all(...archivedSampleFilter.parameters) as SqlRow[];
  insertRows(archive, "report_observations", observations);
}

function sampleIdentityFilter(samples: MetricsArchivePlannedSample[]) {
  return {
    parameters: samples.flatMap((sample) => [
      sample.probeId,
      sample.bootId,
      sample.sequence,
    ]),
    sql: samples
      .map(() => "(probe_id = ? and boot_id = ? and sequence = ?)")
      .join(" or "),
  };
}

function sampleRowsIdentityFilter(tableAlias: string, samples: SqlRow[]) {
  return {
    parameters: samples.flatMap((sample) => [
      sample.probe_id ?? null,
      sample.boot_id ?? null,
      sample.sequence ?? null,
    ]),
    sql: samples
      .map(
        () =>
          `(${tableAlias}.probe_id = ? and ${tableAlias}.boot_id = ? and ${tableAlias}.sequence = ?)`,
      )
      .join(" or "),
  };
}

function selectRowsByIds(
  database: DatabaseSync,
  table: string,
  column: string,
  ids: number[],
): SqlRow[] {
  if (ids.length === 0) {
    return [];
  }

  const placeholders = ids.map(() => "?").join(", ");
  return database
    .prepare(
      `
        select *
        from ${table}
        where ${column} in (${placeholders})
        order by id
      `,
    )
    .all(...ids) as SqlRow[];
}

function insertRows(database: DatabaseSync, table: string, rows: SqlRow[]) {
  if (rows.length === 0) {
    return;
  }

  const columns = Object.keys(rows[0] ?? {});
  const placeholders = columns.map(() => "?").join(", ");
  const statement = database.prepare(
    `
      insert into ${table} (${columns.join(", ")})
      values (${placeholders})
    `,
  );

  for (const row of rows) {
    statement.run(...columns.map((column) => row[column] ?? null));
  }
}

function countArchiveRows(database: DatabaseSync): MetricsArchiveFileRowCounts {
  return Object.fromEntries(
    archiveTables.map((table) => [
      table,
      (
        database.prepare(`select count(*) as count from ${table}`).get() as {
          count: number;
        }
      ).count,
    ]),
  );
}

function writeArchiveMetadata(
  input: WriteMetricsArchiveFileInput,
  database: DatabaseSync,
  rowCounts: MetricsArchiveFileRowCounts,
) {
  database
    .prepare(
      `
        insert into archive_metadata (
          id,
          archive_schema_version,
          created_at_ms,
          enoki_version,
          period,
          range_start_ms,
          range_end_ms,
          sequence,
          row_counts_json,
          host_snapshot_captured_at_ms
        )
        values (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
    )
    .run(
      archiveSchemaVersion,
      input.nowMs,
      null,
      input.plan.period,
      input.plan.rangeStartMs,
      input.plan.rangeEndMs,
      input.plan.identity.sequence,
      JSON.stringify(rowCounts),
      input.hostSnapshotCapturedAtMs ?? input.nowMs,
    );
}
