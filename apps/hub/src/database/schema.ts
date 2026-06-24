import { sql } from "drizzle-orm";
import {
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
  real,
} from "drizzle-orm/sqlite-core";

export const auditLog = sqliteTable("audit_log", {
  id: integer().primaryKey({ autoIncrement: true }),
  occurredAtMs: integer().notNull(),
  actor: text().notNull(),
  action: text().notNull(),
  outcome: text().notNull(),
  subjectType: text(),
  subjectId: text(),
  remoteAddress: text(),
  userAgent: text(),
  detailsJson: text(),
});

export type AuditLogRow = typeof auditLog.$inferSelect;
export type NewAuditLogRow = typeof auditLog.$inferInsert;

export const enrollmentTokens = sqliteTable(
  "enrollment_tokens",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    tokenHash: text().notNull(),
    createdAtMs: integer().notNull(),
    expiresAtMs: integer().notNull(),
    usedAtMs: integer(),
  },
  (table) => [
    uniqueIndex("enrollment_tokens_token_hash_idx").on(table.tokenHash),
  ],
);

export type EnrollmentTokenRow = typeof enrollmentTokens.$inferSelect;
export type NewEnrollmentTokenRow = typeof enrollmentTokens.$inferInsert;

export const hosts = sqliteTable(
  "managed_hosts",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    probeId: text().notNull(),
    probeSecretHash: text().notNull(),
    probePublicKeyPem: text(),
    displayName: text().notNull(),
    displayNameEdited: integer({
      mode: "boolean",
    }).notNull(),
    description: text().notNull().default(""),
    hostname: text(),
    os: text(),
    kernel: text(),
    architecture: text(),
    cpuCount: integer(),
    cpuModel: text(),
    memoryTotalBytes: integer(),
    inventoryHash: text(),
    inventoryJson: text(),
    probeVersion: text(),
    connectAddress: text().notNull(),
    connectAddressEdited: integer({
      mode: "boolean",
    })
      .notNull()
      .default(false),
    observedIp: text(),
    probeConfigurationVersion: text().notNull(),
    probeConfigurationErrorFailedVersion: text(),
    probeConfigurationErrorCode: text(),
    probeConfigurationErrorMessage: text(),
    probeConfigurationErrorReportedAtMs: integer(),
    createdAtMs: integer().notNull(),
    deletedAtMs: integer(),
    lastReportAtMs: integer(),
    clockSkewDetected: integer({
      mode: "boolean",
    })
      .notNull()
      .default(false),
    lastClockSkewMs: integer(),
  },
  (table) => [
    uniqueIndex("managed_hosts_probe_id_idx").on(table.probeId),
    uniqueIndex("managed_hosts_probe_secret_hash_idx").on(
      table.probeSecretHash,
    ),
  ],
);

export type HostRow = typeof hosts.$inferSelect;
export type NewHostRow = typeof hosts.$inferInsert;

export const officialHostProfiles = sqliteTable(
  "official_host_profiles",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    hostId: integer("managed_host_id").notNull(),
    snapshotHash: text().notNull(),
    payloadJson: text().notNull(),
    hostname: text().notNull(),
    os: text().notNull(),
    kernel: text().notNull(),
    architecture: text().notNull(),
    cpuCount: integer().notNull(),
    cpuModel: text(),
    memoryTotalBytes: integer().notNull(),
    probeVersion: text().notNull(),
    collectorCapabilitiesJson: text(),
    filesystemsJson: text().notNull(),
    networkInterfacesJson: text().notNull(),
    updatedAtMs: integer().notNull(),
  },
  (table) => [
    uniqueIndex("official_host_profiles_host_idx").on(table.hostId),
    index("official_host_profiles_snapshot_hash_idx").on(table.snapshotHash),
  ],
);

export type OfficialHostProfileRow = typeof officialHostProfiles.$inferSelect;
export type NewOfficialHostProfileRow =
  typeof officialHostProfiles.$inferInsert;

export const probeRequestNonces = sqliteTable(
  "probe_request_nonces",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    probeId: text().notNull(),
    nonce: text().notNull(),
    expiresAtMs: integer().notNull(),
  },
  (table) => [
    uniqueIndex("probe_request_nonces_probe_nonce_idx").on(
      table.probeId,
      table.nonce,
    ),
    index("probe_request_nonces_expires_at_idx").on(table.expiresAtMs),
  ],
);

export type ProbeRequestNonceRow = typeof probeRequestNonces.$inferSelect;
export type NewProbeRequestNonceRow = typeof probeRequestNonces.$inferInsert;

export const probeOperations = sqliteTable(
  "probe_operations",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    managedHostId: integer("managed_host_id").notNull(),
    kind: text().notNull(),
    state: text().notNull(),
    currentProbeVersion: text(),
    targetProbeVersion: text().notNull(),
    failureCode: text(),
    failureMessage: text(),
    createdAtMs: integer().notNull(),
    updatedAtMs: integer().notNull(),
    acceptedAtMs: integer(),
    runningAtMs: integer(),
    completedAtMs: integer(),
    supersededAtMs: integer(),
    canceledAtMs: integer(),
  },
  (table) => [
    uniqueIndex("probe_operations_one_active_per_host_idx")
      .on(table.managedHostId)
      .where(sql`state in ('pending', 'accepted', 'running')`),
    index("probe_operations_active_for_host_idx")
      .on(table.managedHostId, table.updatedAtMs, table.id)
      .where(sql`state in ('pending', 'accepted', 'running')`),
    index("probe_operations_latest_for_host_idx").on(
      table.managedHostId,
      table.updatedAtMs,
      table.id,
    ),
  ],
);

export type ProbeOperationRow = typeof probeOperations.$inferSelect;
export type NewProbeOperationRow = typeof probeOperations.$inferInsert;

export const reportObservations = sqliteTable(
  "report_observations",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    hostId: integer("managed_host_id").notNull(),
    probeId: text().notNull(),
    bootId: text().notNull(),
    sequence: integer().notNull(),
    receivedAtMs: integer().notNull(),
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
    id: integer().primaryKey({ autoIncrement: true }),
    hostId: integer("managed_host_id").notNull(),
    probeId: text().notNull(),
    bootId: text().notNull(),
    sequence: integer().notNull(),
    collectedAtMs: integer().notNull(),
    receivedAtMs: integer().notNull(),
    cpuPercent: real(),
    cpuUserPercent: real(),
    cpuSystemPercent: real(),
    cpuIowaitPercent: real(),
    cpuStealPercent: real(),
    cpuIdlePercent: real(),
    memoryUsedBytes: integer(),
    memoryTotalBytes: integer(),
    memoryCacheBytes: integer(),
    swapTotalBytes: integer(),
    swapUsedBytes: integer(),
    load1: real("load_1"),
    load5: real("load_5"),
    load15: real("load_15"),
    uptimeSeconds: integer(),
    temperatureCelsius: real(),
    batteryPercent: integer(),
    batteryState: text(),
    diskUsedBytes: integer(),
    diskTotalBytes: integer(),
    networkRxBytesDelta: integer(),
    networkTxBytesDelta: integer(),
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

export const officialMetricCpu = sqliteTable(
  "official_metric_cpu",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    cpuPercent: real(),
    cpuUserPercent: real(),
    cpuSystemPercent: real(),
    cpuIowaitPercent: real(),
    cpuStealPercent: real(),
    cpuIdlePercent: real(),
  },
  (table) => [
    uniqueIndex("official_metric_cpu_sample_idx").on(table.metricSampleId),
  ],
);

export type OfficialMetricCpuRow = typeof officialMetricCpu.$inferSelect;
export type NewOfficialMetricCpuRow = typeof officialMetricCpu.$inferInsert;

export const officialMetricMemory = sqliteTable(
  "official_metric_memory",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    memoryUsedBytes: integer(),
    memoryTotalBytes: integer(),
    memoryCacheBytes: integer(),
    swapTotalBytes: integer(),
    swapUsedBytes: integer(),
  },
  (table) => [
    uniqueIndex("official_metric_memory_sample_idx").on(table.metricSampleId),
  ],
);

export type OfficialMetricMemoryRow = typeof officialMetricMemory.$inferSelect;
export type NewOfficialMetricMemoryRow =
  typeof officialMetricMemory.$inferInsert;

export const officialMetricLoad = sqliteTable(
  "official_metric_load",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    load1: real("load_1"),
    load5: real("load_5"),
    load15: real("load_15"),
  },
  (table) => [
    uniqueIndex("official_metric_load_sample_idx").on(table.metricSampleId),
  ],
);

export type OfficialMetricLoadRow = typeof officialMetricLoad.$inferSelect;
export type NewOfficialMetricLoadRow = typeof officialMetricLoad.$inferInsert;

export const officialMetricUptime = sqliteTable(
  "official_metric_uptime",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    uptimeSeconds: integer(),
  },
  (table) => [
    uniqueIndex("official_metric_uptime_sample_idx").on(table.metricSampleId),
  ],
);

export type OfficialMetricUptimeRow = typeof officialMetricUptime.$inferSelect;
export type NewOfficialMetricUptimeRow =
  typeof officialMetricUptime.$inferInsert;

export const officialMetricThermalPower = sqliteTable(
  "official_metric_thermal_power",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    temperatureCelsius: real(),
    batteryPercent: integer(),
    batteryState: text(),
  },
  (table) => [
    uniqueIndex("official_metric_thermal_power_sample_idx").on(
      table.metricSampleId,
    ),
  ],
);

export type OfficialMetricThermalPowerRow =
  typeof officialMetricThermalPower.$inferSelect;
export type NewOfficialMetricThermalPowerRow =
  typeof officialMetricThermalPower.$inferInsert;

export const officialMetricDiskSummary = sqliteTable(
  "official_metric_disk_summary",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    diskUsedBytes: integer(),
    diskTotalBytes: integer(),
  },
  (table) => [
    uniqueIndex("official_metric_disk_summary_sample_idx").on(
      table.metricSampleId,
    ),
  ],
);

export type OfficialMetricDiskSummaryRow =
  typeof officialMetricDiskSummary.$inferSelect;
export type NewOfficialMetricDiskSummaryRow =
  typeof officialMetricDiskSummary.$inferInsert;

export const officialMetricNetworkSummary = sqliteTable(
  "official_metric_network_summary",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    networkRxBytesDelta: integer(),
    networkTxBytesDelta: integer(),
  },
  (table) => [
    uniqueIndex("official_metric_network_summary_sample_idx").on(
      table.metricSampleId,
    ),
  ],
);

export type OfficialMetricNetworkSummaryRow =
  typeof officialMetricNetworkSummary.$inferSelect;
export type NewOfficialMetricNetworkSummaryRow =
  typeof officialMetricNetworkSummary.$inferInsert;

export const metricCpuCores = sqliteTable(
  "metric_cpu_cores",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    name: text().notNull(),
    user: integer().notNull(),
    nice: integer().notNull(),
    system: integer().notNull(),
    idle: integer().notNull(),
    iowait: integer().notNull(),
    irq: integer().notNull(),
    softirq: integer().notNull(),
    steal: integer().notNull(),
    usagePercent: real().notNull(),
  },
  (table) => [index("metric_cpu_cores_sample_idx").on(table.metricSampleId)],
);

export type MetricCpuCoreRow = typeof metricCpuCores.$inferSelect;
export type NewMetricCpuCoreRow = typeof metricCpuCores.$inferInsert;

export const metricDisks = sqliteTable(
  "metric_disks",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    mountPoint: text().notNull(),
    filesystemType: text().notNull(),
    totalBytes: integer().notNull(),
    usedBytes: integer().notNull(),
    availableBytes: integer().notNull(),
    readBytesDelta: integer().notNull().default(0),
    writeBytesDelta: integer().notNull().default(0),
    ioUtilizationPercent: real(),
    readAwaitMs: real(),
    writeAwaitMs: real(),
    weightedIoPercent: real(),
  },
  (table) => [index("metric_disks_sample_idx").on(table.metricSampleId)],
);

export type MetricDiskRow = typeof metricDisks.$inferSelect;
export type NewMetricDiskRow = typeof metricDisks.$inferInsert;

export const metricNetworkInterfaces = sqliteTable(
  "metric_network_interfaces",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    name: text().notNull(),
    rxBytes: integer().notNull(),
    txBytes: integer().notNull(),
    rxBytesDelta: integer().notNull(),
    txBytesDelta: integer().notNull(),
  },
  (table) => [
    index("metric_network_interfaces_sample_idx").on(table.metricSampleId),
  ],
);

export type MetricNetworkInterfaceRow =
  typeof metricNetworkInterfaces.$inferSelect;
export type NewMetricNetworkInterfaceRow =
  typeof metricNetworkInterfaces.$inferInsert;

export const officialMetricDiskHealth = sqliteTable(
  "official_metric_disk_health",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer().notNull(),
    deviceName: text().notNull(),
    model: text(),
    serialNumber: text(),
    passed: integer({ mode: "boolean" }).notNull(),
    temperatureCelsius: real(),
    powerOnHours: integer(),
    totalBytes: integer(),
    usedBytes: integer(),
    usageMountPoint: text(),
    role: text(),
  },
  (table) => [
    index("official_metric_disk_health_sample_idx").on(table.metricSampleId),
  ],
);

export type OfficialMetricDiskHealthRow =
  typeof officialMetricDiskHealth.$inferSelect;
export type NewOfficialMetricDiskHealthRow =
  typeof officialMetricDiskHealth.$inferInsert;

export const probeConfigurationGlobalDefaults = sqliteTable(
  "probe_configuration_global_defaults",
  {
    id: integer().primaryKey(),
    version: text().notNull(),
    updatedAtMs: integer().notNull(),
    metricsCollectionIntervalSeconds: integer().notNull(),
    enabledCollectorIdsJson: text().notNull(),
  },
);

export type ProbeConfigurationGlobalDefaultRow =
  typeof probeConfigurationGlobalDefaults.$inferSelect;
export type NewProbeConfigurationGlobalDefaultRow =
  typeof probeConfigurationGlobalDefaults.$inferInsert;

export const probeConfigurationHostOverrides = sqliteTable(
  "probe_configuration_host_overrides",
  {
    hostId: integer("managed_host_id").primaryKey(),
    version: text().notNull(),
    updatedAtMs: integer().notNull(),
    metricsCollectionIntervalSeconds: integer().notNull(),
    enabledCollectorIdsJson: text().notNull(),
  },
);

export type ProbeConfigurationHostOverrideRow =
  typeof probeConfigurationHostOverrides.$inferSelect;
export type NewProbeConfigurationHostOverrideRow =
  typeof probeConfigurationHostOverrides.$inferInsert;
