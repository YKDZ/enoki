import {
  defaultEnabledCollectorIds,
  isProbeCollectorId,
  normalizeEnabledCollectorIds as normalizeKnownEnabledCollectorIds,
  probeCollectorIds,
  type ProbeCollectorId,
} from "@enoki/api-client";

export type { ProbeCollectorId };

export const probeCollectorCatalog = probeCollectorIds.map((id) => ({ id }));
export { defaultEnabledCollectorIds };

export type ProbeConfigurationValues = {
  enabledCollectorIds: string[];
  metricsCollectionIntervalSeconds: number;
};

export type ProbeConfigurationRecord = ProbeConfigurationValues & {
  version: string;
};

export const defaultProbeConfiguration: ProbeConfigurationRecord = {
  enabledCollectorIds: [...defaultEnabledCollectorIds],
  metricsCollectionIntervalSeconds: 5,
  version: "default-v1",
};

export function parseProbeConfigurationValues(
  input: unknown,
): ProbeConfigurationValues | null {
  if (!input || typeof input !== "object") {
    return null;
  }

  const candidate = input as Record<string, unknown>;
  const enabledCollectorIds = candidate.enabledCollectorIds;
  const metricsCollectionIntervalSeconds =
    candidate.metricsCollectionIntervalSeconds;

  if (
    !Array.isArray(enabledCollectorIds) ||
    !enabledCollectorIds.every((collectorId) => {
      return typeof collectorId === "string";
    }) ||
    typeof metricsCollectionIntervalSeconds !== "number" ||
    !Number.isInteger(metricsCollectionIntervalSeconds)
  ) {
    return null;
  }

  return {
    enabledCollectorIds: [...new Set(enabledCollectorIds)],
    metricsCollectionIntervalSeconds,
  };
}

export function validateProbeConfigurationValues(
  values: ProbeConfigurationValues,
) {
  if (
    values.metricsCollectionIntervalSeconds < 1 ||
    values.metricsCollectionIntervalSeconds > 200
  ) {
    return "metrics_collection_interval_out_of_range";
  }

  if (
    values.enabledCollectorIds.some((collectorId) => {
      return !isProbeCollectorId(collectorId);
    })
  ) {
    return "unknown_collector_id";
  }

  return null;
}

export function normalizeProbeConfigurationValues(
  values: ProbeConfigurationValues,
): ProbeConfigurationValues {
  return {
    enabledCollectorIds: normalizeEnabledCollectorIds(
      values.enabledCollectorIds,
    ),
    metricsCollectionIntervalSeconds: values.metricsCollectionIntervalSeconds,
  };
}

export function normalizeEnabledCollectorIds(enabledCollectorIds: string[]) {
  return normalizeKnownEnabledCollectorIds(enabledCollectorIds);
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
