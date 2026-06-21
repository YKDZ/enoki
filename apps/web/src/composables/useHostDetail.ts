import type {
  HostDetailSample,
  HostLiveSummary,
} from "@enoki/api-client/websocket";
import { computed, onScopeDispose, ref, unref, type MaybeRef } from "vue";

import { apiGet } from "@/lib/api";
import {
  useHostMetricsWindowStore,
  type HostMetricsWindowPreferences,
} from "@/stores/host-metrics-window";

import type {
  HostDetail,
  HostDetailResponse,
  HostMetricSample,
  HostMetricsResponse,
  MetricsWindow,
} from "../types";

type FetchJson = <T>(path: string) => Promise<T>;

const metricsWindowDurationsMs: Record<MetricsWindow, number> = {
  "1m": 60 * 1000,
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
};

export function useHostDetail(
  hostId: MaybeRef<number>,
  options: {
    fetchJson?: FetchJson;
    windowPreferences?: HostMetricsWindowPreferences;
  } = {},
) {
  const fetchJson = options.fetchJson ?? apiGet;
  const windowPreferences =
    options.windowPreferences ?? useHostMetricsWindowStore();
  const host = ref<HostDetail | null>(null);
  const samples = ref<HostMetricSample[]>([]);
  const selectedWindow = computed<MetricsWindow, MetricsWindow>({
    get: () => windowPreferences.selectedWindowForHost(currentHostId()),
    set: (window: MetricsWindow) =>
      windowPreferences.setSelectedWindowForHost(currentHostId(), window),
  });
  const isLoading = ref(false);
  const error = ref("");
  const metricsError = ref("");
  const isEmpty = computed(() => samples.value.length === 0);
  const chartRange = computed(() => {
    const endMs =
      samples.value.at(-1)?.collectedAtMs ??
      host.value?.lastReportAtMs ??
      Date.now();
    const durationMs = metricsWindowDurationsMs[selectedWindow.value];
    const windowMinMs = endMs - durationMs;
    const firstSampleMs = samples.value[0]?.collectedAtMs;
    const minMs =
      firstSampleMs && firstSampleMs < endMs
        ? Math.max(windowMinMs, firstSampleMs)
        : windowMinMs;

    return {
      maxMs: endMs,
      minMs,
    };
  });
  let livePlaybackTimer: ReturnType<typeof setTimeout> | null = null;
  let metricsRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  let isRefreshingMetrics = false;
  let activeLoad: Promise<void> | null = null;
  let pendingMetricSamples: HostMetricSample[] = [];

  onScopeDispose(() => {
    clearLivePlayback();
    clearMetricsRefreshTimer();
  }, true);

  async function load() {
    if (activeLoad) {
      return activeLoad;
    }

    activeLoad = loadHostDetail().finally(() => {
      activeLoad = null;
    });

    return activeLoad;
  }

  async function loadHostDetail() {
    if (!currentHostId()) {
      return;
    }

    error.value = "";
    isLoading.value = true;

    try {
      const detailResponse = await fetchJson<HostDetailResponse>(
        `/api/web/hosts/${currentHostId()}`,
      );
      host.value = detailResponse.host;
    } catch {
      error.value = "无法读取主机详情。";
      return;
    }

    try {
      await loadMetrics(selectedWindow.value, { mode: "replace" });
    } catch {
      metricsError.value = "无法读取历史指标，稍后会自动重试。";
      samples.value = [];
      clearLivePlayback();
    } finally {
      startMetricsRefreshLoop();
      isLoading.value = false;
    }
  }

  async function loadMetrics(
    window: MetricsWindow,
    options: { mode: "enqueue-new" | "replace" },
  ) {
    const response = await fetchMetrics(window);
    selectedWindow.value = response.metrics.window;
    metricsError.value = "";
    if (options.mode === "replace") {
      samples.value = response.metrics.samples;
      clearLivePlayback();
      updateHostLatestMetric(samples.value.at(-1) ?? null);
      return;
    }

    enqueueMetricSamples(newMetricSamples(response.metrics.samples));
  }

  async function switchWindow(window: MetricsWindow) {
    error.value = "";
    isLoading.value = true;
    const previousWindow = selectedWindow.value;
    selectedWindow.value = window;
    clearMetricsRefreshTimer();

    try {
      await loadMetrics(window, { mode: "replace" });
      startMetricsRefreshLoop();
    } catch {
      selectedWindow.value = previousWindow;
      metricsError.value = "无法读取历史指标，稍后会自动重试。";
      startMetricsRefreshLoop();
    } finally {
      isLoading.value = false;
    }
  }

  function appendLiveSample(sample: HostDetailSample) {
    if (sample.hostId !== currentHostId()) {
      return;
    }

    enqueueMetricSamples([
      detailSampleToMetricSample(sample, metricsCollectionIntervalSeconds()),
    ]);
  }

  function enqueueMetricSamples(nextSamples: HostMetricSample[]) {
    pendingMetricSamples = dedupeAndSortMetricSamples([
      ...pendingMetricSamples,
      ...nextSamples,
    ]);
    if (livePlaybackTimer === null) {
      playNextLiveSample();
    }
  }

  function playNextLiveSample() {
    livePlaybackTimer = null;
    const [nextSample, ...remainingSamples] = pendingMetricSamples;
    pendingMetricSamples = remainingSamples;

    if (!nextSample) {
      return;
    }

    commitMetricSample(nextSample);

    livePlaybackTimer = setTimeout(
      playNextLiveSample,
      livePlaybackIntervalMs(),
    );
  }

  function commitMetricSample(nextSample: HostMetricSample) {
    const existing = samples.value.filter(
      (item) =>
        item.receivedAtMs !== nextSample.receivedAtMs ||
        item.sequence !== nextSample.sequence,
    );
    const windowStartMs =
      nextSample.collectedAtMs - metricsWindowDurationsMs[selectedWindow.value];

    samples.value = [...existing, nextSample]
      .filter((item) => item.collectedAtMs >= windowStartMs)
      .sort(
        (left, right) =>
          left.collectedAtMs - right.collectedAtMs ||
          left.sequence - right.sequence,
      );
    updateHostLatestMetric(nextSample);
  }

  function startMetricsRefreshLoop() {
    clearMetricsRefreshTimer();
    scheduleMetricsRefresh();
  }

  function scheduleMetricsRefresh() {
    if (!currentHostId()) {
      return;
    }

    metricsRefreshTimer = setTimeout(() => {
      void refreshMetrics();
    }, livePlaybackIntervalMs());
  }

  async function refreshMetrics() {
    if (isRefreshingMetrics || !currentHostId()) {
      scheduleMetricsRefresh();
      return;
    }

    isRefreshingMetrics = true;
    try {
      await loadMetrics(selectedWindow.value, { mode: "enqueue-new" });
    } catch {
      metricsError.value = "无法刷新历史指标，稍后会自动重试。";
      // The live socket can still recover state; keep the observation loop alive.
    } finally {
      isRefreshingMetrics = false;
      scheduleMetricsRefresh();
    }
  }

  function livePlaybackIntervalMs() {
    return metricsCollectionIntervalSeconds() * 1000;
  }

  function metricsCollectionIntervalSeconds() {
    const intervalSeconds =
      host.value?.probeConfiguration.configuration
        .metricsCollectionIntervalSeconds ?? 5;

    return Math.max(1, intervalSeconds);
  }

  function clearLivePlayback() {
    pendingMetricSamples = [];
    if (livePlaybackTimer !== null) {
      clearTimeout(livePlaybackTimer);
      livePlaybackTimer = null;
    }
  }

  function clearMetricsRefreshTimer() {
    if (metricsRefreshTimer !== null) {
      clearTimeout(metricsRefreshTimer);
      metricsRefreshTimer = null;
    }
  }

  async function fetchMetrics(window: MetricsWindow) {
    const path = `/api/web/hosts/${currentHostId()}/metrics?window=${window}`;

    try {
      return await fetchJson<HostMetricsResponse>(path);
    } catch (error) {
      if (!isTransientFetchError(error)) {
        throw error;
      }

      await sleep(150);
      return await fetchJson<HostMetricsResponse>(path);
    }
  }

  function applyLiveSummary(summary: HostLiveSummary) {
    if (!host.value || summary.id !== currentHostId()) {
      return;
    }

    host.value = {
      ...host.value,
      clockSkew: {
        ...host.value.clockSkew,
        detected: summary.warningFlags.clockSkew,
      },
      lastReportAtMs: summary.lastSeenAtMs,
      status: summary.status,
      warnings: liveSummaryWarnings(host.value.warnings, summary),
    };
  }

  function updateHostLatestMetric(sample: HostMetricSample | null) {
    if (!host.value || !sample) {
      return;
    }

    host.value = {
      ...host.value,
      lastReportAtMs: Math.max(
        host.value.lastReportAtMs ?? 0,
        sample.receivedAtMs,
      ),
      latestMetrics: {
        collectedAtMs: sample.collectedAtMs,
        cpuPercent: sample.cpuPercent,
        diskTotalBytes: sample.diskTotalBytes,
        diskUsedBytes: sample.diskUsedBytes,
        memoryTotalBytes: sample.memoryTotalBytes,
        memoryUsedBytes: sample.memoryUsedBytes,
        networkRxBitsPerSecond: sample.networkRxBitsPerSecond,
        networkRxBytesDelta: sample.networkRxBytesDelta,
        networkTxBitsPerSecond: sample.networkTxBitsPerSecond,
        networkTxBytesDelta: sample.networkTxBytesDelta,
        receivedAtMs: sample.receivedAtMs,
        uptimeSeconds: sample.uptimeSeconds,
      },
      status: "online",
    };
  }

  function newMetricSamples(nextSamples: HostMetricSample[]) {
    const knownKeys = new Set([
      ...samples.value.map(metricSampleKey),
      ...pendingMetricSamples.map(metricSampleKey),
    ]);

    return nextSamples.filter(
      (sample) => !knownKeys.has(metricSampleKey(sample)),
    );
  }

  function currentHostId() {
    return unref(hostId);
  }

  return {
    appendLiveSample,
    applyLiveSummary,
    chartRange,
    error,
    host,
    isEmpty,
    isLoading,
    metricsError,
    load,
    samples,
    selectedWindow,
    switchWindow,
  };
}

function dedupeAndSortMetricSamples(samples: HostMetricSample[]) {
  const samplesByKey = new Map<string, HostMetricSample>();

  for (const sample of samples) {
    samplesByKey.set(metricSampleKey(sample), sample);
  }

  return [...samplesByKey.values()].sort(
    (left, right) =>
      left.collectedAtMs - right.collectedAtMs ||
      left.sequence - right.sequence,
  );
}

function metricSampleKey(sample: HostMetricSample) {
  return `${sample.receivedAtMs}:${sample.sequence}`;
}

function liveSummaryWarnings(
  currentWarnings: HostDetail["warnings"],
  summary: HostLiveSummary,
): HostDetail["warnings"] {
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
  sample: HostDetailSample,
  intervalSeconds: number,
): HostMetricSample {
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

function isTransientFetchError(error: unknown) {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    error instanceof TypeError ||
    error.message.includes("Failed to fetch") ||
    error.message.includes("ERR_CONTENT_LENGTH_MISMATCH") ||
    error.message.includes("Load failed")
  );
}

function sleep(ms: number) {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

function bitsPerSecond(bytes: number | null, intervalSeconds: number) {
  if (bytes === null || intervalSeconds <= 0) {
    return null;
  }

  return (bytes * 8) / intervalSeconds;
}
