export function hostStatusText(status: string) {
  if (status === "online") {
    return "在线";
  }

  if (status === "stale") {
    return "上报延迟";
  }

  if (status === "offline") {
    return "离线";
  }

  return status;
}

export function warningTitle(code: string) {
  if (code === "clock_skew") {
    return "时间偏移警告";
  }

  if (code === "probe_configuration_error") {
    return "探针配置警告";
  }

  return "主机警告";
}
