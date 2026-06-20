import type {
  ManagedHostDetailSample,
  ManagedHostLiveSummary,
} from "@enoki/api-client/websocket";
import { computed, ref, unref, type MaybeRef } from "vue";

import { apiGet } from "@/lib/api";

import type {
  ManagedHostDetail,
  ManagedHostDetailResponse,
  ManagedHostMetricSample,
  ManagedHostMetricsResponse,
  MetricsWindow,
} from "../types";

type FetchJson = <T>(path: string) => Promise<T>;

const defaultWindow: MetricsWindow = "1h";
const metricsWindowDurationsMs: Record<MetricsWindow, number> = {
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
};

export function useManagedHostDetail(
  managedHostId: MaybeRef<number>,
  options: {
    fetchJson?: FetchJson;
  } = {},
) {
  const fetchJson = options.fetchJson ?? apiGet;
  const host = ref<ManagedHostDetail | null>(null);
  const samples = ref<ManagedHostMetricSample[]>([]);
  const selectedWindow = ref<MetricsWindow>(defaultWindow);
  const isLoading = ref(false);
  const error = ref("");
  const isEmpty = computed(() => samples.value.length === 0);
  const chartRange = computed(() => {
    const endMs =
      samples.value.at(-1)?.collectedAtMs ??
      host.value?.lastReportAtMs ??
      Date.now();
    const durationMs = metricsWindowDurationsMs[selectedWindow.value];

    return {
      maxMs: endMs,
      minMs: endMs - durationMs,
    };
  });
  let livePlaybackTimer: ReturnType<typeof setTimeout> | null = null;
  let pendingLiveSamples: ManagedHostDetailSample[] = [];

  async function load() {
    if (!currentManagedHostId()) {
      return;
    }

    error.value = "";
    isLoading.value = true;

    try {
      const detailResponse = await fetchJson<ManagedHostDetailResponse>(
        `/api/web/managed-hosts/${currentManagedHostId()}`,
      );
      host.value = detailResponse.host;
      await loadMetrics(selectedWindow.value);
    } catch {
      error.value = "无法读取主机详情。";
    } finally {
      isLoading.value = false;
    }
  }

  async function loadMetrics(window: MetricsWindow) {
    const response = await fetchJson<ManagedHostMetricsResponse>(
      `/api/web/managed-hosts/${currentManagedHostId()}/metrics?window=${window}`,
    );
    selectedWindow.value = response.metrics.window;
    samples.value = response.metrics.samples;
    clearLivePlayback();
  }

  async function switchWindow(window: MetricsWindow) {
    error.value = "";
    isLoading.value = true;
    const previousWindow = selectedWindow.value;
    selectedWindow.value = window;

    try {
      await loadMetrics(window);
    } catch {
      selectedWindow.value = previousWindow;
      error.value = "无法读取历史指标。";
    } finally {
      isLoading.value = false;
    }
  }

  function appendLiveSample(sample: ManagedHostDetailSample) {
    if (sample.managedHostId !== currentManagedHostId()) {
      return;
    }

    pendingLiveSamples = dedupeAndSortLiveSamples([
      ...pendingLiveSamples,
      sample,
    ]);
    if (livePlaybackTimer === null) {
      playNextLiveSample();
    }
  }

  function playNextLiveSample() {
    livePlaybackTimer = null;
    const [nextSample, ...remainingSamples] = pendingLiveSamples;
    pendingLiveSamples = remainingSamples;

    if (!nextSample) {
      return;
    }

    commitLiveSample(nextSample);

    livePlaybackTimer = setTimeout(
      playNextLiveSample,
      livePlaybackIntervalMs(),
    );
  }

  function commitLiveSample(sample: ManagedHostDetailSample) {
    if (sample.managedHostId !== currentManagedHostId()) {
      return;
    }

    const intervalSeconds =
      host.value?.probeConfiguration.configuration
        .metricsCollectionIntervalSeconds ?? 5;
    const nextSample = detailSampleToMetricSample(sample, intervalSeconds);
    const existing = samples.value.filter(
      (item) =>
        item.receivedAtMs !== nextSample.receivedAtMs ||
        item.sequence !== nextSample.sequence,
    );

    samples.value = [...existing, nextSample].sort(
      (left, right) =>
        left.collectedAtMs - right.collectedAtMs ||
        left.sequence - right.sequence,
    );
  }

  function livePlaybackIntervalMs() {
    const intervalSeconds =
      host.value?.probeConfiguration.configuration
        .metricsCollectionIntervalSeconds ?? 5;

    return Math.max(1, intervalSeconds) * 1000;
  }

  function clearLivePlayback() {
    pendingLiveSamples = [];
    if (livePlaybackTimer !== null) {
      clearTimeout(livePlaybackTimer);
      livePlaybackTimer = null;
    }
  }

  function applyLiveSummary(summary: ManagedHostLiveSummary) {
    if (!host.value || summary.id !== currentManagedHostId()) {
      return;
    }

    host.value = {
      ...host.value,
      clockSkew: {
        ...host.value.clockSkew,
        detected: summary.warningFlags.clockSkew,
      },
      lastReportAtMs: summary.lastSeenAtMs,
      latestMetrics: summary.latestMetrics
        ? {
            collectedAtMs: summary.latestMetrics.collectedAtMs,
            cpuPercent: summary.latestMetrics.cpuPercent,
            diskTotalBytes: summary.latestMetrics.diskTotalBytes,
            diskUsedBytes: summary.latestMetrics.diskUsedBytes,
            memoryTotalBytes: summary.latestMetrics.memoryTotalBytes,
            memoryUsedBytes: summary.latestMetrics.memoryUsedBytes,
            networkRxBitsPerSecond:
              summary.latestMetrics.networkRxBitsPerSecond,
            networkRxBytesDelta: summary.latestMetrics.networkRxBytesDelta,
            networkTxBitsPerSecond:
              summary.latestMetrics.networkTxBitsPerSecond,
            networkTxBytesDelta: summary.latestMetrics.networkTxBytesDelta,
            receivedAtMs: summary.latestMetrics.receivedAtMs,
            uptimeSeconds: summary.latestMetrics.uptimeSeconds,
          }
        : null,
      status: summary.status,
      warnings: liveSummaryWarnings(host.value.warnings, summary),
    };
  }

  function currentManagedHostId() {
    return unref(managedHostId);
  }

  return {
    appendLiveSample,
    applyLiveSummary,
    chartRange,
    error,
    host,
    isEmpty,
    isLoading,
    load,
    samples,
    selectedWindow,
    switchWindow,
  };
}

function dedupeAndSortLiveSamples(samples: ManagedHostDetailSample[]) {
  const samplesByKey = new Map<string, ManagedHostDetailSample>();

  for (const sample of samples) {
    samplesByKey.set(`${sample.receivedAtMs}:${sample.sequence}`, sample);
  }

  return [...samplesByKey.values()].sort(
    (left, right) =>
      left.collectedAtMs - right.collectedAtMs ||
      left.sequence - right.sequence,
  );
}

function liveSummaryWarnings(
  currentWarnings: ManagedHostDetail["warnings"],
  summary: ManagedHostLiveSummary,
): ManagedHostDetail["warnings"] {
  const warnings = currentWarnings.filter(
    (warning) =>
      warning.code !== "clock_skew" &&
      warning.code !== "probe_configuration_error",
  );

  if (summary.warningFlags.clockSkew) {
    warnings.push({
      code: "clock_skew",
      message: "探针时间与 Hub 时间存在偏移。",
    });
  }

  if (summary.warningFlags.probeConfigurationError) {
    warnings.push({
      code: "probe_configuration_error",
      message: "探针未能应用最新配置，请检查探针连通性或配置下发状态。",
    });
  }

  return warnings;
}

function detailSampleToMetricSample(
  sample: ManagedHostDetailSample,
  intervalSeconds: number,
): ManagedHostMetricSample {
  const networkRxBytesDelta = sumNumbers(
    sample.networkInterfaces.map((networkInterface) =>
      Number(networkInterface.rxBytesDelta),
    ),
  );
  const networkTxBytesDelta = sumNumbers(
    sample.networkInterfaces.map((networkInterface) =>
      Number(networkInterface.txBytesDelta),
    ),
  );
  const diskUsedBytes = sumNumbers(sample.disks.map((disk) => disk.usedBytes));
  const diskTotalBytes = sumNumbers(
    sample.disks.map((disk) => disk.totalBytes),
  );

  return {
    collectedAtMs: sample.collectedAtMs,
    cpuCores: sample.cpuCores,
    cpuPercent: sample.cpuPercent,
    diskTotalBytes,
    diskUsedBytes,
    disks: sample.disks,
    memoryTotalBytes: sample.memoryTotalBytes,
    memoryUsedBytes: sample.memoryUsedBytes,
    networkInterfaces: sample.networkInterfaces.map((networkInterface) => ({
      name: networkInterface.name,
      rxBitsPerSecond: bitsPerSecond(
        networkInterface.rxBytesDelta,
        intervalSeconds,
      ),
      rxBytesDelta: networkInterface.rxBytesDelta,
      txBitsPerSecond: bitsPerSecond(
        networkInterface.txBytesDelta,
        intervalSeconds,
      ),
      txBytesDelta: networkInterface.txBytesDelta,
    })),
    networkRxBitsPerSecond: bitsPerSecond(networkRxBytesDelta, intervalSeconds),
    networkRxBytesDelta,
    networkTxBitsPerSecond: bitsPerSecond(networkTxBytesDelta, intervalSeconds),
    networkTxBytesDelta,
    receivedAtMs: sample.receivedAtMs,
    sequence: sample.sequence,
    uptimeSeconds: sample.uptimeSeconds,
  };
}

function sumNumbers(values: number[]) {
  return values.length
    ? values.reduce((total, value) => total + value, 0)
    : null;
}

function bitsPerSecond(bytes: number | null, intervalSeconds: number) {
  if (bytes === null || intervalSeconds <= 0) {
    return null;
  }

  return (bytes * 8) / intervalSeconds;
}
