import type {
  CollectorAvailability as ProtocolCollectorAvailability,
  CollectorCapabilities as ProtocolCollectorCapabilities,
  CpuCoreMetric as ProtocolCpuCoreMetric,
  DiskHealthMetric as ProtocolDiskHealthMetric,
  DiskUsageMetric as ProtocolDiskUsageMetric,
  HostProfileSnapshot as ProtocolHostProfileSnapshot,
  NetworkInterfaceDeltaMetric as ProtocolNetworkInterfaceDeltaMetric,
} from "@enoki/api-client";

export type SessionResponse = {
  authenticated: boolean;
};

export type HostSummary = {
  clockSkew: {
    detected: boolean;
    lastDeltaMs: number | null;
  };
  collectorCapabilities: CollectorCapabilities | null;
  connectAddress: string;
  cpu: string;
  cpuModel: string | null;
  description: string;
  displayName: string;
  id: number;
  lastReportAtMs: number | null;
  latestMetrics: {
    batteryPercent?: number | null;
    batteryState?: string | null;
    collectedAtMs: number;
    cpuIdlePercent?: number | null;
    cpuIowaitPercent?: number | null;
    cpuPercent: number | null;
    cpuStealPercent?: number | null;
    cpuSystemPercent?: number | null;
    cpuUserPercent?: number | null;
    diskHealth?: DiskHealthMetric[];
    diskTotalBytes?: number | null;
    diskUsedBytes?: number | null;
    memoryCacheBytes?: number | null;
    memoryTotalBytes?: number | null;
    memoryUsedBytes: number | null;
    networkRxBitsPerSecond?: number | null;
    networkRxBytesDelta?: number | null;
    networkTxBitsPerSecond?: number | null;
    networkTxBytesDelta?: number | null;
    receivedAtMs: number;
    swapTotalBytes?: number | null;
    swapUsedBytes?: number | null;
    temperatureCelsius?: number | null;
    uptimeSeconds: number | null;
  } | null;
  memory: string;
  probeConfiguration: {
    mode: "inherit" | "override";
    version: string;
  };
  probeVersion: string;
  status: string;
  system: string;
};

export type CollectorCapabilities = ProtocolCollectorCapabilities;

export type CollectorAvailability = ProtocolCollectorAvailability;

export type HostProfileSnapshot = ProtocolHostProfileSnapshot;

export type HostsResponse = {
  hosts: HostSummary[];
};

export type EnrollmentResponse = {
  enrollmentToken: string;
  expiresAtMs: number;
  hubUrl: string;
  installCommand: string;
  installPath: string;
};

export type ProbeConfiguration = {
  enabledCollectorIds: string[];
  metricsCollectionIntervalSeconds: number;
  version: string;
};

export type HostProbeConfigurationResponse = {
  configuration: ProbeConfiguration;
  mode: "inherit" | "override";
};

export type HostMetadataDraft = {
  connectAddress: string;
  description: string;
  displayName: string;
};

export type HostMetricSample = {
  batteryPercent?: number | null;
  batteryState?: string | null;
  collectedAtMs: number;
  cpuCores: ProtocolCpuCoreMetric[];
  cpuIdlePercent?: number | null;
  cpuIowaitPercent?: number | null;
  cpuPercent: number | null;
  cpuStealPercent?: number | null;
  cpuSystemPercent?: number | null;
  cpuUserPercent?: number | null;
  diskHealth?: DiskHealthMetric[];
  diskTotalBytes: number | null;
  diskUsedBytes: number | null;
  disks: ProtocolDiskUsageMetric[];
  memoryCacheBytes?: number | null;
  memoryTotalBytes: number | null;
  memoryUsedBytes: number | null;
  networkInterfaces: Array<
    ProtocolNetworkInterfaceDeltaMetric & {
      rxBitsPerSecond: number | null;
      txBitsPerSecond: number | null;
    }
  >;
  networkRxBitsPerSecond: number | null;
  networkRxBytesDelta: number | null;
  networkTxBitsPerSecond: number | null;
  networkTxBytesDelta: number | null;
  receivedAtMs: number;
  sequence: number;
  swapTotalBytes?: number | null;
  swapUsedBytes?: number | null;
  temperatureCelsius?: number | null;
  uptimeSeconds: number | null;
};

export type DiskHealthMetric = ProtocolDiskHealthMetric;

export type MetricsWindow = "1m" | "1h" | "6h" | "24h" | "7d";

export type HostDetail = HostSummary & {
  hostMetadata: {
    connectAddress: string;
    description: string;
    displayName: string;
    observedIp: string | null;
  };
  hostProfile: HostProfileSnapshot | null;
  inventory: Record<string, unknown> | null;
  probeConfiguration: HostProbeConfigurationResponse;
  probeUpgradeEligibility: {
    currentProbeAssetSetVersion: string | null;
    currentProbeVersion: string | null;
    isUpgradeable: boolean;
    nonUpgradeableReason:
      | "probe_asset_set_version_missing"
      | "probe_asset_set_version_malformed"
      | "probe_version_missing"
      | "probe_version_malformed"
      | "probe_version_development"
      | "probe_version_current"
      | "probe_version_newer"
      | null;
  };
  probeUpgradeStatus: {
    createdAtMs: number;
    failure: {
      code: string;
      message: string;
    } | null;
    id: number;
    state:
      | "pending"
      | "accepted"
      | "running"
      | "succeeded"
      | "failed"
      | "superseded"
      | "canceled";
    targetProbeVersion: string;
    updatedAtMs: number;
  } | null;
  warnings: Array<{
    code: string;
    message: string;
    occurredAtMs?: number;
    technicalDetail?: string;
  }>;
};

export type HostDetailResponse = {
  host: HostDetail;
};

export type HostMetricsResponse = {
  metrics: {
    samples: HostMetricSample[];
    window: MetricsWindow;
  };
};
