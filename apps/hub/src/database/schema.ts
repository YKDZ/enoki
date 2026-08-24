import { sql } from "drizzle-orm";
import {
  check,
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
  real,
} from "drizzle-orm/sqlite-core";

import {
  enrollmentStatusValues,
  enrollmentTargetKindValues,
  maxEnrollmentRejectionCodeLength,
  maxEnrollmentRejectionMessageLength,
} from "../enrollment/lifecycle.js";

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
    enrollmentId: text(),
    tokenHash: text().notNull(),
    createdAtMs: integer().notNull(),
    expiresAtMs: integer().notNull(),
    usedAtMs: integer(),
    targetKind: text({ enum: enrollmentTargetKindValues }),
    targetHostId: integer("target_host_id"),
    expectedHubOrigin: text("expected_hub_origin"),
    expectedProbeId: text("expected_probe_id"),
    expectedProbeVersion: text("expected_probe_version"),
    sourceProbeSha256Json: text("source_probe_sha256_json"),
    targetAssetSetDigest: text("target_asset_set_digest"),
    targetProbeVersion: text("target_probe_version"),
    status: text({ enum: enrollmentStatusValues }).notNull().default("expired"),
    hostId: integer("managed_host_id"),
    verificationDeadlineAtMs: integer(),
    readyAtMs: integer(),
    rejectedAtMs: integer(),
    expiredAtMs: integer(),
    rejectionCode: text(),
    rejectionMessage: text(),
  },
  (table) => [
    uniqueIndex("enrollment_tokens_token_hash_idx").on(table.tokenHash),
    uniqueIndex("enrollment_tokens_enrollment_id_idx").on(table.enrollmentId),
    uniqueIndex("enrollment_tokens_one_active_existing_host_idx")
      .on(table.targetHostId)
      .where(
        sql`${table.targetKind} in ('existing_host', 'manual_reinstall') and ${table.status} in ('pending', 'verifying')`,
      ),
    index("enrollment_tokens_status_expiry_idx").on(
      table.status,
      table.expiresAtMs,
    ),
    check(
      "enrollment_tokens_status_check",
      sql`${table.status} in ('pending', 'verifying', 'ready', 'rejected', 'expired')`,
    ),
    check(
      "enrollment_tokens_target_check",
      sql`(${table.targetKind} = 'new_host' and ${table.targetHostId} is null and ${table.expectedHubOrigin} is null and ${table.expectedProbeId} is null and ${table.expectedProbeVersion} is null and ${table.sourceProbeSha256Json} is null and ${table.targetAssetSetDigest} is null and ${table.targetProbeVersion} is null) or (${table.targetKind} = 'existing_host' and ${table.targetHostId} > 0 and ${table.expectedHubOrigin} is null and ${table.expectedProbeId} is null and ${table.expectedProbeVersion} is null and ${table.sourceProbeSha256Json} is null and ${table.targetAssetSetDigest} is null and ${table.targetProbeVersion} is null) or (${table.targetKind} = 'manual_reinstall' and ${table.targetHostId} > 0 and length(${table.expectedHubOrigin}) > 0 and length(${table.expectedProbeId}) > 0 and length(${table.expectedProbeVersion}) > 0 and length(${table.sourceProbeSha256Json}) > 0 and length(${table.targetAssetSetDigest}) = 71 and length(${table.targetProbeVersion}) > 0) or (${table.targetKind} is null and ${table.targetHostId} is null and ${table.status} = 'expired')`,
    ),
    check(
      "enrollment_tokens_rejection_check",
      sql`(${table.rejectionCode} is null and ${table.rejectionMessage} is null) or (${table.rejectionCode} is not null and length(${table.rejectionCode}) between 1 and ${sql.raw(String(maxEnrollmentRejectionCodeLength))} and (${table.rejectionMessage} is null or length(${table.rejectionMessage}) between 1 and ${sql.raw(String(maxEnrollmentRejectionMessageLength))}))`,
    ),
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
    probeVersion: text(),
    probeAssetBundleVersion: text(),
    probeAssetBundleBootId: text(),
    probeAssetBundleProbeId: text(),
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
    hostId: integer("managed_host_id")
      .notNull()
      .references(() => hosts.id, { onDelete: "cascade" }),
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
    reportBootId: text(),
    reportProbeId: text(),
    reportProfileBundleVersion: text(),
    forwardOperationId: integer(),
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

export const snapshotReplayRequests = sqliteTable(
  "snapshot_replay_requests",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    hostId: integer("managed_host_id")
      .notNull()
      .references(() => hosts.id, { onDelete: "cascade" }),
    collectorId: text().notNull(),
    bootId: text("boot_id").notNull().default(""),
    sequence: integer().notNull().default(0),
    snapshotHash: text("snapshot_hash").notNull().default(""),
    requestedAtMs: integer().notNull(),
    fulfilledAtMs: integer("fulfilled_at_ms"),
  },
  (table) => [
    uniqueIndex("snapshot_replay_requests_host_collector_idx").on(
      table.hostId,
      table.collectorId,
    ),
  ],
);

export type SnapshotReplayRequestRow =
  typeof snapshotReplayRequests.$inferSelect;
export type NewSnapshotReplayRequestRow =
  typeof snapshotReplayRequests.$inferInsert;

export const probeRequestNonces = sqliteTable(
  "probe_request_nonces",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    probeId: text()
      .notNull()
      .references(() => hosts.probeId, { onDelete: "cascade" }),
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
    managedHostId: integer("managed_host_id")
      .notNull()
      .references(() => hosts.id, { onDelete: "cascade" }),
    kind: text().notNull(),
    state: text().notNull(),
    currentProbeVersion: text(),
    targetAssetSetDigest: text("target_asset_set_digest"),
    targetManifestSha256: text("target_manifest_sha256"),
    targetProbeVersion: text().notNull(),
    failureCode: text(),
    failureMessage: text(),
    repairAuthorityExpiresAtMs: integer("repair_authority_expires_at_ms"),
    repairEligibilityEvidenceJson: text("repair_eligibility_evidence_json"),
    repairEligibilityEvidenceSha256: text("repair_eligibility_evidence_sha256"),
    repairEvidenceSha256: text("repair_evidence_sha256"),
    repairFailedOperationId: integer("repair_failed_operation_id"),
    repairNonce: text("repair_nonce"),
    upgradeAuthoritySha256: text("upgrade_authority_sha256"),
    verifiedStageSha256: text("verified_stage_sha256"),
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
    uniqueIndex("probe_operations_repair_evidence_idx")
      .on(table.repairEvidenceSha256)
      .where(sql`repair_evidence_sha256 is not null`),
  ],
);

export type ProbeOperationRow = typeof probeOperations.$inferSelect;
export type NewProbeOperationRow = typeof probeOperations.$inferInsert;

export const metricsArchiveRuns = sqliteTable(
  "metrics_archive_runs",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    period: text().notNull(),
    rangeStartMs: integer().notNull(),
    rangeEndMs: integer().notNull(),
    status: text().notNull(),
    archivePath: text(),
    checksumSha256: text(),
    rowCountsJson: text(),
    cleanupStatus: text(),
    cleanupCompletedAtMs: integer(),
    cleanupErrorMessage: text(),
    startedAtMs: integer().notNull(),
    updatedAtMs: integer().notNull(),
    completedAtMs: integer(),
    errorMessage: text(),
  },
  (table) => [
    index("metrics_archive_runs_status_range_idx").on(
      table.status,
      table.rangeStartMs,
      table.rangeEndMs,
    ),
    index("metrics_archive_runs_period_range_idx").on(
      table.period,
      table.rangeStartMs,
      table.rangeEndMs,
    ),
  ],
);

export type MetricsArchiveRunRow = typeof metricsArchiveRuns.$inferSelect;
export type NewMetricsArchiveRunRow = typeof metricsArchiveRuns.$inferInsert;

export const reportObservations = sqliteTable(
  "report_observations",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    hostId: integer("managed_host_id")
      .notNull()
      .references(() => hosts.id, { onDelete: "cascade" }),
    probeId: text().notNull(),
    bootId: text().notNull(),
    sequence: integer().notNull(),
    receivedAtMs: integer().notNull(),
    observationWindowFailureReason: integer(
      "observation_window_failure_reason",
    ),
    cpuResourceCollectionOutcomeReason: integer(
      "cpu_resource_collection_outcome_reason",
    ),
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
    hostId: integer("managed_host_id")
      .notNull()
      .references(() => hosts.id, { onDelete: "cascade" }),
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

export const metricCollectorOutcomes = sqliteTable(
  "metric_collector_outcomes",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer("metric_sample_id")
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
    collectorId: text("collector_id").notNull(),
    state: integer().notNull(),
    failurePhase: integer("failure_phase"),
    failureCode: text("failure_code"),
  },
  (table) => [
    uniqueIndex("metric_collector_outcomes_sample_collector_idx").on(
      table.metricSampleId,
      table.collectorId,
    ),
  ],
);

export const officialMetricCpu = sqliteTable(
  "official_metric_cpu",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    metricSampleId: integer()
      .notNull()
      .references(() => metricSamples.id, { onDelete: "cascade" }),
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
    hostId: integer("managed_host_id")
      .primaryKey()
      .references(() => hosts.id, { onDelete: "cascade" }),
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
