export const metricToggleFields = [
  ["collectCpu", "CPU"],
  ["collectLoad", "负载"],
  ["collectMemory", "内存"],
  ["collectDisk", "磁盘"],
  ["collectNetwork", "网络"],
  ["collectUptime", "运行时间"],
] as const;

export type MetricToggleKey = (typeof metricToggleFields)[number][0];

export function configurationErrorText(error: unknown) {
  const code = error instanceof Error ? error.message : "";

  if (code === "metrics_collection_interval_out_of_range") {
    return "采集间隔必须在 1 到 300 秒之间。";
  }

  if (code === "reporting_batch_interval_out_of_range") {
    return "上报批次间隔必须在 1 到 600 秒之间。";
  }

  if (code === "reporting_batch_interval_shorter_than_collection_interval") {
    return "上报批次间隔不能小于采集间隔。";
  }

  return "无法保存探针配置，请检查输入后重试。";
}
