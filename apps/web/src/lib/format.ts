export function formatTimestamp(timestampMs: number | null) {
  if (timestampMs === null) {
    return "暂无";
  }

  return new Date(timestampMs).toLocaleString();
}

export function formatPercent(value: number | null) {
  if (value === null) {
    return "n/a";
  }

  return `${value.toFixed(1)}%`;
}

export function formatBytes(bytes: number | null) {
  if (!bytes) {
    return "n/a";
  }

  const gibibytes = bytes / 1024 ** 3;
  if (gibibytes >= 1) {
    return `${formatNumber(gibibytes)} GiB`;
  }

  const mebibytes = bytes / 1024 ** 2;
  return `${formatNumber(mebibytes)} MiB`;
}

export function formatByteUsage(
  usedBytes: number | null,
  totalBytes: number | null,
) {
  if (totalBytes === null) {
    return formatBytes(usedBytes);
  }

  return `${formatBytes(usedBytes)} / ${formatBytes(totalBytes)}`;
}

export function formatBitsPerSecond(bitsPerSecond: number | null) {
  if (bitsPerSecond === null) {
    return "n/a";
  }

  if (bitsPerSecond >= 1_000_000) {
    return `${formatNumber(bitsPerSecond / 1_000_000)} Mb/s`;
  }

  if (bitsPerSecond >= 1_000) {
    return `${formatNumber(bitsPerSecond / 1_000)} Kb/s`;
  }

  return `${formatNumber(bitsPerSecond)} b/s`;
}

export function formatClockSkew(deltaMs: number | null) {
  if (deltaMs === null) {
    return "时钟偏移";
  }

  const seconds = Math.round(deltaMs / 1000);
  return `时钟偏移 ${seconds}s`;
}

export function formatDuration(seconds: number | null | undefined) {
  if (seconds === null || seconds === undefined || seconds < 0) {
    return "n/a";
  }

  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);

  if (days > 0) {
    return `${days} 天 ${hours} 小时`;
  }

  if (hours > 0) {
    return `${hours} 小时 ${minutes} 分钟`;
  }

  return `${minutes} 分钟`;
}

function formatNumber(value: number) {
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}
