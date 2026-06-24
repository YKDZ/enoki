import type { HostSummary as ApiHostSummary } from "@enoki/api-client";

import type { HostSummary as DatabaseHostSummary } from "../database/hosts.js";

export function hostSummaryResponse(
  host: DatabaseHostSummary,
  options: { metricsCollectionIntervalSeconds?: number } = {},
): ApiHostSummary {
  return {
    clockSkew: {
      detected: host.clockSkew.detected,
      lastDeltaMs: host.clockSkew.lastDeltaMs,
    },
    collectorCapabilities: host.collectorCapabilities,
    connectAddress: host.connectAddress,
    cpu: host.cpu,
    cpuModel: host.cpuModel,
    description: host.description,
    displayName: host.displayName,
    id: host.id,
    lastReportAtMs: host.lastReportAtMs,
    latestMetrics: host.latestMetrics
      ? {
          batteryPercent: host.latestMetrics.batteryPercent,
          batteryState: host.latestMetrics.batteryState,
          collectedAtMs: host.latestMetrics.collectedAtMs,
          cpuIdlePercent: host.latestMetrics.cpuIdlePercent,
          cpuIowaitPercent: host.latestMetrics.cpuIowaitPercent,
          cpuPercent: host.latestMetrics.cpuPercent,
          cpuStealPercent: host.latestMetrics.cpuStealPercent,
          cpuSystemPercent: host.latestMetrics.cpuSystemPercent,
          cpuUserPercent: host.latestMetrics.cpuUserPercent,
          ...(host.latestMetrics.diskHealth?.length
            ? { diskHealth: host.latestMetrics.diskHealth }
            : {}),
          diskTotalBytes: host.latestMetrics.diskTotalBytes,
          diskUsedBytes: host.latestMetrics.diskUsedBytes,
          memoryCacheBytes: host.latestMetrics.memoryCacheBytes,
          memoryTotalBytes: host.latestMetrics.memoryTotalBytes,
          memoryUsedBytes: host.latestMetrics.memoryUsedBytes,
          ...(options.metricsCollectionIntervalSeconds !== undefined
            ? {
                networkRxBitsPerSecond: bitsPerSecond(
                  host.latestMetrics.networkRxBytesDelta,
                  options.metricsCollectionIntervalSeconds,
                ),
                networkTxBitsPerSecond: bitsPerSecond(
                  host.latestMetrics.networkTxBytesDelta,
                  options.metricsCollectionIntervalSeconds,
                ),
              }
            : {}),
          networkRxBytesDelta: host.latestMetrics.networkRxBytesDelta,
          networkTxBytesDelta: host.latestMetrics.networkTxBytesDelta,
          receivedAtMs: host.latestMetrics.receivedAtMs,
          swapTotalBytes: host.latestMetrics.swapTotalBytes,
          swapUsedBytes: host.latestMetrics.swapUsedBytes,
          temperatureCelsius: host.latestMetrics.temperatureCelsius,
          uptimeSeconds: host.latestMetrics.uptimeSeconds,
        }
      : null,
    memory: host.memory,
    probeConfiguration: {
      mode: host.probeConfiguration.mode,
      version: host.probeConfiguration.version,
    },
    probeVersion: host.probeVersion,
    status: host.status,
    system: host.system,
  };
}

function bitsPerSecond(bytes: number | null, intervalSeconds: number) {
  if (bytes === null || intervalSeconds <= 0) {
    return null;
  }

  return (bytes * 8) / intervalSeconds;
}
