export type SessionResponse = {
  authenticated: boolean;
};

export type ManagedHostSummary = {
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

export type ManagedHostsResponse = {
  hosts: ManagedHostSummary[];
};

export type EnrollmentResponse = {
  enrollmentToken: string;
  expiresAtMs: number;
  hubUrl: string;
  installCommand: string;
  installPath: string;
  probeDownloadUrl?: string;
  probeReleaseVersion?: string;
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

export type ManagedHostMetricSample = {
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

export type MetricsWindow = "1h" | "6h" | "24h" | "7d";

export type ManagedHostDetail = ManagedHostSummary & {
  hostMetadata: {
    connectAddress: string;
    description: string;
    displayName: string;
    observedIp: string | null;
  };
  inventory: Record<string, unknown> | null;
  probeConfiguration: HostProbeConfigurationResponse;
  warnings: Array<{
    code: string;
    message: string;
    occurredAtMs?: number;
    technicalDetail?: string;
  }>;
};

export type ManagedHostDetailResponse = {
  host: ManagedHostDetail;
};

export type ManagedHostMetricsResponse = {
  metrics: {
    samples: ManagedHostMetricSample[];
    window: MetricsWindow;
  };
};
