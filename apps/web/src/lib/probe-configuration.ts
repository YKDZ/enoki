export const probeCollectorCatalog = [
  { id: "official.cpu", label: "CPU" },
  { id: "official.memory", label: "内存" },
  { id: "official.disk", label: "磁盘" },
  { id: "official.network", label: "网络" },
  { id: "official.load", label: "负载" },
  { id: "official.uptime", label: "运行时间" },
  { id: "official.temperature", label: "温度" },
  { id: "official.battery", label: "电池" },
  { id: "official.disk-health", label: "磁盘健康" },
] as const;

export type ProbeCollectorId = (typeof probeCollectorCatalog)[number]["id"];

export const defaultEnabledCollectorIds = probeCollectorCatalog.map(
  (collector) => collector.id,
);

export function collectorEnabled(
  enabledCollectorIds: readonly string[],
  collectorId: ProbeCollectorId,
) {
  return enabledCollectorIds.includes(collectorId);
}

export function updateEnabledCollectorIds(
  enabledCollectorIds: readonly string[],
  collectorId: ProbeCollectorId,
  enabled: boolean,
) {
  const next = new Set(enabledCollectorIds);

  if (enabled) {
    next.add(collectorId);
  } else {
    next.delete(collectorId);
  }

  return probeCollectorCatalog
    .filter((collector) => next.has(collector.id))
    .map((collector) => collector.id);
}

export const probeConfigurationTiming = {
  lowFrequencyMultiplier: 12,
  reportingWindowMultiplier: 3,
} as const;

export function derivedReportingBatchIntervalSeconds(
  metricsCollectionIntervalSeconds: number,
) {
  return (
    metricsCollectionIntervalSeconds *
    probeConfigurationTiming.reportingWindowMultiplier
  );
}

export function derivedLowFrequencyIntervalSeconds(
  metricsCollectionIntervalSeconds: number,
) {
  return (
    metricsCollectionIntervalSeconds *
    probeConfigurationTiming.lowFrequencyMultiplier
  );
}

export function configurationErrorText(error: unknown) {
  const code = error instanceof Error ? error.message : "";

  if (code === "metrics_collection_interval_out_of_range") {
    return "基础采样间隔必须在 1 到 200 秒之间。";
  }

  if (code === "unknown_collector_id") {
    return "包含未知采集项，请刷新页面后重试。";
  }

  return "无法保存探针配置，请检查输入后重试。";
}
