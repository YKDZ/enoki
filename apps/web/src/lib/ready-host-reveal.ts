import type {
  HostListSortDirection,
  HostListSortKey,
} from "../components/HostListView.vue";
import type { HostSummary } from "../types";

export function locateReadyHost(input: {
  cardBatchSize: number;
  currentCardVisibleCount: number;
  hosts: HostSummary[];
  hostId: number;
  listPageSize: number;
  listSortDirection: HostListSortDirection;
  listSortKey: HostListSortKey | null;
  overviewView: "cards" | "list";
}): { cardVisibleCount: number | null; listPage: number | null } | null {
  const matchingHosts = input.hosts.filter((host) => host.id === input.hostId);
  if (matchingHosts.length !== 1) {
    return null;
  }

  if (input.overviewView === "cards") {
    const index = input.hosts.findIndex((host) => host.id === input.hostId);
    return {
      cardVisibleCount: Math.max(
        input.currentCardVisibleCount,
        input.cardBatchSize,
        index + 1,
      ),
      listPage: null,
    };
  }

  const index = sortHostsForOverview(
    input.hosts,
    input.listSortKey,
    input.listSortDirection,
  ).findIndex((host) => host.id === input.hostId);
  return {
    cardVisibleCount: null,
    listPage: Math.floor(index / Math.max(1, input.listPageSize)) + 1,
  };
}

export function sortHostsForOverview(
  hosts: HostSummary[],
  sortKey: HostListSortKey | null,
  sortDirection: HostListSortDirection,
) {
  if (!sortKey) {
    return hosts;
  }

  return [...hosts].sort((left, right) => {
    const leftValue = sortValue(left, sortKey);
    const rightValue = sortValue(right, sortKey);
    const result =
      typeof leftValue === "string" && typeof rightValue === "string"
        ? leftValue.localeCompare(rightValue, "zh-Hans-CN")
        : Number(leftValue) - Number(rightValue);

    return sortDirection === "asc" ? result : -result;
  });
}

function sortValue(host: HostSummary, key: HostListSortKey) {
  const metrics = host.latestMetrics;
  if (key === "name") return host.displayName;
  if (key === "cpu") return metrics?.cpuPercent ?? -1;
  if (key === "memory") return memoryPercent(host) ?? -1;
  if (key === "disk") return diskPercent(host) ?? -1;
  if (key === "rx") return metrics?.networkRxBitsPerSecond ?? -1;
  if (key === "tx") return metrics?.networkTxBitsPerSecond ?? -1;
  return metrics?.uptimeSeconds ?? -1;
}

function memoryPercent(host: HostSummary) {
  const metrics = host.latestMetrics;
  if (!metrics?.memoryTotalBytes || !metrics.memoryUsedBytes) return null;
  return (metrics.memoryUsedBytes / metrics.memoryTotalBytes) * 100;
}

function diskPercent(host: HostSummary) {
  const metrics = host.latestMetrics;
  if (!metrics?.diskTotalBytes || !metrics.diskUsedBytes) return null;
  return (metrics.diskUsedBytes / metrics.diskTotalBytes) * 100;
}
