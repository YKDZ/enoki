export type SessionResponse = {
  authenticated: boolean;
};

export type HostSummary = {
  clockSkew: {
    detected: boolean;
    lastDeltaMs: number | null;
  };
  connectAddress: string;
  cpu: string;
  cpuModel: string | null;
  description: string;
  displayName: string;
  id: number;
  lastReportAtMs: number | null;
  latestMetrics: {
    collectedAtMs: number;
    cpuPercent: number | null;
    diskTotalBytes?: number | null;
    diskUsedBytes?: number | null;
    memoryTotalBytes?: number | null;
    memoryUsedBytes: number | null;
    networkRxBitsPerSecond?: number | null;
    networkRxBytesDelta?: number | null;
    networkTxBitsPerSecond?: number | null;
    networkTxBytesDelta?: number | null;
    receivedAtMs: number;
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
  collectCpu: boolean;
  collectDisk: boolean;
  collectLoad: boolean;
  collectMemory: boolean;
  collectNetwork: boolean;
  collectUptime: boolean;
  metricsCollectionIntervalSeconds: number;
  reportingBatchIntervalSeconds: number;
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
  collectedAtMs: number;
  cpuCores: Array<{
    name: string;
    usagePercent: number;
  }>;
  cpuPercent: number | null;
  diskTotalBytes: number | null;
  diskUsedBytes: number | null;
  disks: Array<{
    availableBytes: number;
    filesystemType: string;
    mountPoint: string;
    totalBytes: number;
    usedBytes: number;
  }>;
  memoryTotalBytes: number | null;
  memoryUsedBytes: number | null;
  networkInterfaces: Array<{
    name: string;
    rxBitsPerSecond: number | null;
    rxBytesDelta: number;
    txBitsPerSecond: number | null;
    txBytesDelta: number;
  }>;
  networkRxBitsPerSecond: number | null;
  networkRxBytesDelta: number | null;
  networkTxBitsPerSecond: number | null;
  networkTxBytesDelta: number | null;
  receivedAtMs: number;
  sequence: number;
  uptimeSeconds: number | null;
};

export type MetricsWindow = "1m" | "1h" | "6h" | "24h" | "7d";

export type HostDetail = HostSummary & {
  hostMetadata: {
    connectAddress: string;
    description: string;
    displayName: string;
    observedIp: string | null;
  };
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
