export type ProbeConfigurationValues = {
  collectCpu: boolean;
  collectDisk: boolean;
  collectLoad: boolean;
  collectMemory: boolean;
  collectNetwork: boolean;
  collectUptime: boolean;
  metricsCollectionIntervalSeconds: number;
  reportingBatchIntervalSeconds: number;
};

export type ProbeConfigurationRecord = ProbeConfigurationValues & {
  version: string;
};

export const defaultProbeConfiguration: ProbeConfigurationRecord = {
  collectCpu: true,
  collectDisk: true,
  collectLoad: true,
  collectMemory: true,
  collectNetwork: true,
  collectUptime: true,
  metricsCollectionIntervalSeconds: 5,
  reportingBatchIntervalSeconds: 15,
  version: "default-v1",
};

export function parseProbeConfigurationValues(
  input: unknown,
): ProbeConfigurationValues | null {
  if (!input || typeof input !== "object") {
    return null;
  }

  const candidate = input as Record<string, unknown>;
  const values = {
    collectCpu: candidate.collectCpu,
    collectDisk: candidate.collectDisk,
    collectLoad: candidate.collectLoad,
    collectMemory: candidate.collectMemory,
    collectNetwork: candidate.collectNetwork,
    collectUptime: candidate.collectUptime,
    metricsCollectionIntervalSeconds:
      candidate.metricsCollectionIntervalSeconds,
    reportingBatchIntervalSeconds: candidate.reportingBatchIntervalSeconds,
  };

  if (
    typeof values.collectCpu !== "boolean" ||
    typeof values.collectDisk !== "boolean" ||
    typeof values.collectLoad !== "boolean" ||
    typeof values.collectMemory !== "boolean" ||
    typeof values.collectNetwork !== "boolean" ||
    typeof values.collectUptime !== "boolean" ||
    !Number.isInteger(values.metricsCollectionIntervalSeconds) ||
    !Number.isInteger(values.reportingBatchIntervalSeconds)
  ) {
    return null;
  }

  return values as ProbeConfigurationValues;
}

export function validateProbeConfigurationValues(
  values: ProbeConfigurationValues,
) {
  if (
    values.metricsCollectionIntervalSeconds < 1 ||
    values.metricsCollectionIntervalSeconds > 300
  ) {
    return "metrics_collection_interval_out_of_range";
  }

  if (
    values.reportingBatchIntervalSeconds < 1 ||
    values.reportingBatchIntervalSeconds > 600
  ) {
    return "reporting_batch_interval_out_of_range";
  }

  if (
    values.reportingBatchIntervalSeconds <
    values.metricsCollectionIntervalSeconds
  ) {
    return "reporting_batch_interval_shorter_than_collection_interval";
  }

  return null;
}

export function nextProbeConfigurationVersion(
  scope: string,
  nowMs: number,
  previousVersion?: string,
) {
  const previous = previousVersion
    ? parseProbeConfigurationVersion(scope, previousVersion)
    : null;
  const versionMs = Math.max(nowMs, previous?.versionMs ?? nowMs);
  const sequence =
    previous && previous.versionMs === versionMs ? previous.sequence + 1 : 1;

  return `${scope}-${versionMs}-${sequence}`;
}

function parseProbeConfigurationVersion(scope: string, version: string) {
  const prefix = `${scope}-`;

  if (!version.startsWith(prefix)) {
    return null;
  }

  const parts = version.slice(prefix.length).split("-");
  const versionMs = Number(parts[0]);
  const sequence = parts[1] === undefined ? 1 : Number(parts[1]);

  if (
    !Number.isSafeInteger(versionMs) ||
    versionMs < 0 ||
    !Number.isSafeInteger(sequence) ||
    sequence < 1
  ) {
    return null;
  }

  return { sequence, versionMs };
}
