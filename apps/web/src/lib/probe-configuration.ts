import {
  defaultEnabledCollectorIds,
  normalizeEnabledCollectorIds as normalizeKnownEnabledCollectorIds,
  probeCollectorIds,
  type ProbeCollectorId,
} from "@enoki/api-client";

export type { ProbeCollectorId };
export { defaultEnabledCollectorIds };

const probeCollectorLabels = {
  "official.battery": "电池",
  "official.cpu": "CPU",
  "official.disk": "磁盘",
  "official.disk-health": "磁盘健康",
  "official.load": "负载",
  "official.memory": "内存",
  "official.network": "网络",
  "official.temperature": "温度",
  "official.uptime": "运行时间",
} satisfies Record<ProbeCollectorId, string>;

export const probeCollectorCatalog = probeCollectorIds.map((id) => ({
  id,
  label: probeCollectorLabels[id],
}));

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

  return normalizeKnownEnabledCollectorIds([...next]);
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
