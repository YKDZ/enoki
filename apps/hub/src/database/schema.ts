import {
  integer,
  sqliteTable,
  text,
  uniqueIndex,
  real,
} from "drizzle-orm/sqlite-core";

export const auditLog = sqliteTable("audit_log", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  occurredAtMs: integer("occurred_at_ms").notNull(),
  actor: text("actor").notNull(),
  action: text("action").notNull(),
  outcome: text("outcome").notNull(),
  subjectType: text("subject_type"),
  subjectId: text("subject_id"),
  remoteAddress: text("remote_address"),
  userAgent: text("user_agent"),
  detailsJson: text("details_json"),
});

export type AuditLogRow = typeof auditLog.$inferSelect;
export type NewAuditLogRow = typeof auditLog.$inferInsert;

export const enrollmentTokens = sqliteTable(
  "enrollment_tokens",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    tokenHash: text("token_hash").notNull(),
    createdAtMs: integer("created_at_ms").notNull(),
    expiresAtMs: integer("expires_at_ms").notNull(),
    usedAtMs: integer("used_at_ms"),
  },
  (table) => [
    uniqueIndex("enrollment_tokens_token_hash_idx").on(table.tokenHash),
  ],
);

export type EnrollmentTokenRow = typeof enrollmentTokens.$inferSelect;
export type NewEnrollmentTokenRow = typeof enrollmentTokens.$inferInsert;

export const managedHosts = sqliteTable(
  "managed_hosts",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    probeId: text("probe_id").notNull(),
    probeSecretHash: text("probe_secret_hash").notNull(),
    displayName: text("display_name").notNull(),
    displayNameEdited: integer("display_name_edited", {
      mode: "boolean",
    }).notNull(),
    hostname: text("hostname"),
    os: text("os"),
    kernel: text("kernel"),
    architecture: text("architecture"),
    cpuCount: integer("cpu_count"),
    cpuModel: text("cpu_model"),
    memoryTotalBytes: integer("memory_total_bytes"),
    inventoryHash: text("inventory_hash"),
    inventoryJson: text("inventory_json"),
    probeVersion: text("probe_version"),
    connectAddress: text("connect_address").notNull(),
    connectAddressEdited: integer("connect_address_edited", {
      mode: "boolean",
    })
      .notNull()
      .default(false),
    observedIp: text("observed_ip"),
    probeConfigurationVersion: text("probe_configuration_version").notNull(),
    probeConfigurationErrorFailedVersion: text(
      "probe_configuration_error_failed_version",
    ),
    probeConfigurationErrorCode: text("probe_configuration_error_code"),
    probeConfigurationErrorMessage: text("probe_configuration_error_message"),
    probeConfigurationErrorReportedAtMs: integer(
      "probe_configuration_error_reported_at_ms",
    ),
    createdAtMs: integer("created_at_ms").notNull(),
    deletedAtMs: integer("deleted_at_ms"),
    lastReportAtMs: integer("last_report_at_ms"),
    clockSkewDetected: integer("clock_skew_detected", {
      mode: "boolean",
    })
      .notNull()
      .default(false),
    lastClockSkewMs: integer("last_clock_skew_ms"),
  },
  (table) => [
    uniqueIndex("managed_hosts_probe_id_idx").on(table.probeId),
    uniqueIndex("managed_hosts_probe_secret_hash_idx").on(
      table.probeSecretHash,
    ),
  ],
);

export type ManagedHostRow = typeof managedHosts.$inferSelect;
export type NewManagedHostRow = typeof managedHosts.$inferInsert;

export const reportObservations = sqliteTable(
  "report_observations",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    managedHostId: integer("managed_host_id").notNull(),
    probeId: text("probe_id").notNull(),
    bootId: text("boot_id").notNull(),
    sequence: integer("sequence").notNull(),
    receivedAtMs: integer("received_at_ms").notNull(),
  },
  (table) => [
    uniqueIndex("report_observations_probe_boot_sequence_idx").on(
      table.probeId,
      table.bootId,
      table.sequence,
    ),
  ],
);

export type ReportObservationRow = typeof reportObservations.$inferSelect;
export type NewReportObservationRow = typeof reportObservations.$inferInsert;

export const metricSamples = sqliteTable(
  "metric_samples",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    managedHostId: integer("managed_host_id").notNull(),
    probeId: text("probe_id").notNull(),
    bootId: text("boot_id").notNull(),
    sequence: integer("sequence").notNull(),
    collectedAtMs: integer("collected_at_ms").notNull(),
    receivedAtMs: integer("received_at_ms").notNull(),
    cpuPercent: real("cpu_percent"),
    memoryUsedBytes: integer("memory_used_bytes"),
    memoryTotalBytes: integer("memory_total_bytes"),
    load1: real("load_1"),
    load5: real("load_5"),
    load15: real("load_15"),
    uptimeSeconds: integer("uptime_seconds"),
    diskUsedBytes: integer("disk_used_bytes"),
    diskTotalBytes: integer("disk_total_bytes"),
    networkRxBytesDelta: integer("network_rx_bytes_delta"),
    networkTxBytesDelta: integer("network_tx_bytes_delta"),
  },
  (table) => [
    uniqueIndex("metric_samples_probe_boot_sequence_idx").on(
      table.probeId,
      table.bootId,
      table.sequence,
    ),
  ],
);

export type MetricSampleRow = typeof metricSamples.$inferSelect;
export type NewMetricSampleRow = typeof metricSamples.$inferInsert;

export const metricCpuCores = sqliteTable("metric_cpu_cores", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  metricSampleId: integer("metric_sample_id").notNull(),
  name: text("name").notNull(),
  user: integer("user").notNull(),
  nice: integer("nice").notNull(),
  system: integer("system").notNull(),
  idle: integer("idle").notNull(),
  iowait: integer("iowait").notNull(),
  irq: integer("irq").notNull(),
  softirq: integer("softirq").notNull(),
  steal: integer("steal").notNull(),
  usagePercent: real("usage_percent").notNull(),
});

export type MetricCpuCoreRow = typeof metricCpuCores.$inferSelect;
export type NewMetricCpuCoreRow = typeof metricCpuCores.$inferInsert;

export const metricDisks = sqliteTable("metric_disks", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  metricSampleId: integer("metric_sample_id").notNull(),
  mountPoint: text("mount_point").notNull(),
  filesystemType: text("filesystem_type").notNull(),
  totalBytes: integer("total_bytes").notNull(),
  usedBytes: integer("used_bytes").notNull(),
  availableBytes: integer("available_bytes").notNull(),
});

export type MetricDiskRow = typeof metricDisks.$inferSelect;
export type NewMetricDiskRow = typeof metricDisks.$inferInsert;

export const metricNetworkInterfaces = sqliteTable(
  "metric_network_interfaces",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    metricSampleId: integer("metric_sample_id").notNull(),
    name: text("name").notNull(),
    rxBytes: integer("rx_bytes").notNull(),
    txBytes: integer("tx_bytes").notNull(),
    rxBytesDelta: integer("rx_bytes_delta").notNull(),
    txBytesDelta: integer("tx_bytes_delta").notNull(),
  },
);

export type MetricNetworkInterfaceRow =
  typeof metricNetworkInterfaces.$inferSelect;
export type NewMetricNetworkInterfaceRow =
  typeof metricNetworkInterfaces.$inferInsert;

export const probeConfigurationGlobalDefaults = sqliteTable(
  "probe_configuration_global_defaults",
  {
    id: integer("id").primaryKey(),
    version: text("version").notNull(),
    updatedAtMs: integer("updated_at_ms").notNull(),
    metricsCollectionIntervalSeconds: integer(
      "metrics_collection_interval_seconds",
    ).notNull(),
    reportingBatchIntervalSeconds: integer(
      "reporting_batch_interval_seconds",
    ).notNull(),
    collectCpu: integer("collect_cpu", { mode: "boolean" }).notNull(),
    collectMemory: integer("collect_memory", { mode: "boolean" }).notNull(),
    collectDisk: integer("collect_disk", { mode: "boolean" }).notNull(),
    collectNetwork: integer("collect_network", { mode: "boolean" }).notNull(),
    collectLoad: integer("collect_load", { mode: "boolean" }).notNull(),
    collectUptime: integer("collect_uptime", { mode: "boolean" }).notNull(),
  },
);

export type ProbeConfigurationGlobalDefaultRow =
  typeof probeConfigurationGlobalDefaults.$inferSelect;
export type NewProbeConfigurationGlobalDefaultRow =
  typeof probeConfigurationGlobalDefaults.$inferInsert;

export const probeConfigurationHostOverrides = sqliteTable(
  "probe_configuration_host_overrides",
  {
    managedHostId: integer("managed_host_id").primaryKey(),
    version: text("version").notNull(),
    updatedAtMs: integer("updated_at_ms").notNull(),
    metricsCollectionIntervalSeconds: integer(
      "metrics_collection_interval_seconds",
    ).notNull(),
    reportingBatchIntervalSeconds: integer(
      "reporting_batch_interval_seconds",
    ).notNull(),
    collectCpu: integer("collect_cpu", { mode: "boolean" }).notNull(),
    collectMemory: integer("collect_memory", { mode: "boolean" }).notNull(),
    collectDisk: integer("collect_disk", { mode: "boolean" }).notNull(),
    collectNetwork: integer("collect_network", { mode: "boolean" }).notNull(),
    collectLoad: integer("collect_load", { mode: "boolean" }).notNull(),
    collectUptime: integer("collect_uptime", { mode: "boolean" }).notNull(),
  },
);

export type ProbeConfigurationHostOverrideRow =
  typeof probeConfigurationHostOverrides.$inferSelect;
export type NewProbeConfigurationHostOverrideRow =
  typeof probeConfigurationHostOverrides.$inferInsert;
