import type { HostMetricSample, HostSummary } from "../types";

export type LatestHostMetrics = NonNullable<HostSummary["latestMetrics"]>;

export function latestMetricsFromSample(
  sample: HostMetricSample,
  previous: LatestHostMetrics | null | undefined,
): LatestHostMetrics {
  return mergeLatestMetrics(previous, {
    batteryPercent: sample.batteryPercent,
    batteryState: sample.batteryState,
    collectedAtMs: sample.collectedAtMs,
    cpuIdlePercent: sample.cpuIdlePercent,
    cpuIowaitPercent: sample.cpuIowaitPercent,
    cpuPercent: sample.cpuPercent,
    cpuStealPercent: sample.cpuStealPercent,
    cpuSystemPercent: sample.cpuSystemPercent,
    cpuUserPercent: sample.cpuUserPercent,
    diskHealth: sample.diskHealth,
    diskTotalBytes: sample.diskTotalBytes,
    diskUsedBytes: sample.diskUsedBytes,
    memoryCacheBytes: sample.memoryCacheBytes,
    memoryTotalBytes: sample.memoryTotalBytes,
    memoryUsedBytes: sample.memoryUsedBytes,
    networkRxBitsPerSecond: sample.networkRxBitsPerSecond,
    networkRxBytesDelta: sample.networkRxBytesDelta,
    networkTxBitsPerSecond: sample.networkTxBitsPerSecond,
    networkTxBytesDelta: sample.networkTxBytesDelta,
    receivedAtMs: sample.receivedAtMs,
    swapTotalBytes: sample.swapTotalBytes,
    swapUsedBytes: sample.swapUsedBytes,
    temperatureCelsius: sample.temperatureCelsius,
    uptimeSeconds: sample.uptimeSeconds,
  });
}

export function latestMetricsFromSamples(
  samples: HostMetricSample[],
  previous: LatestHostMetrics | null | undefined,
): LatestHostMetrics | null {
  let latestFromSamples: LatestHostMetrics | null = null;

  for (const sample of samples) {
    latestFromSamples = latestMetricsFromSample(sample, latestFromSamples);
  }

  if (!latestFromSamples) {
    return previous ?? null;
  }

  if (!previous) {
    return latestFromSamples;
  }

  return previous.collectedAtMs > latestFromSamples.collectedAtMs
    ? mergeLatestMetrics(latestFromSamples, previous)
    : mergeLatestMetrics(previous, latestFromSamples);
}

export function mergeLatestMetrics(
  previous: LatestHostMetrics | null | undefined,
  next: LatestHostMetrics,
): LatestHostMetrics {
  const merged = { ...(previous ?? {}) } as Record<
    keyof LatestHostMetrics,
    LatestHostMetrics[keyof LatestHostMetrics]
  >;

  for (const [key, value] of Object.entries(next) as Array<
    [keyof LatestHostMetrics, LatestHostMetrics[keyof LatestHostMetrics]]
  >) {
    if (value === undefined) {
      continue;
    }

    const previousValue = previous?.[key];
    if (
      Array.isArray(value) &&
      value.length === 0 &&
      Array.isArray(previousValue) &&
      previousValue.length > 0
    ) {
      continue;
    }

    merged[key] = value;
  }

  return merged as LatestHostMetrics;
}
