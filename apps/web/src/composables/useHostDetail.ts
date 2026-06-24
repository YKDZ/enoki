import type {
  HostDetailSample,
  HostLiveSummary,
} from "@enoki/api-client/websocket";
import { computed, onScopeDispose, ref, unref, type MaybeRef } from "vue";

import { apiGet, apiMutate, isUnauthorizedError } from "@/lib/api";
import {
  latestMetricsFromSample,
  latestMetricsFromSamples,
  mergeLatestMetrics,
} from "@/lib/latest-metrics";
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
type MutateJson = <T>(
  path: string,
  options: { body?: unknown; method: "DELETE" | "POST" | "PUT" },
) => Promise<T>;

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
    mutateJson?: MutateJson;
    onUnauthorized?: () => void;
    windowPreferences?: HostMetricsWindowPreferences;
  } = {},
) {
  const fetchJson = options.fetchJson ?? apiGet;
  const mutateJson = options.mutateJson ?? apiMutate;
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
  const isCreatingProbeUpgradeRequest = ref(false);
  const error = ref("");
  const metricsError = ref("");
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
  let metricsRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  let isRefreshingMetrics = false;
  let activeLoad: Promise<void> | null = null;
  let activeLoadHostId: number | null = null;
  let pendingMetricSamples: HostMetricSample[] = [];

  onScopeDispose(() => {
    clearLivePlayback();
    clearMetricsRefreshTimer();
  }, true);

  async function load() {
    const targetHostId = currentHostId();
    if (!targetHostId) {
      resetDetailState();
      return;
    }

    if (host.value?.id !== targetHostId) {
      resetDetailState();
    }

    if (activeLoad && activeLoadHostId === targetHostId) {
      return activeLoad;
    }

    const loadPromise = loadHostDetail(targetHostId).finally(() => {
      if (activeLoad === loadPromise) {
        activeLoad = null;
        activeLoadHostId = null;
      }
    });
    activeLoad = loadPromise;
    activeLoadHostId = targetHostId;

    return activeLoad;
  }

  async function loadHostDetail(targetHostId: number) {
    if (!targetHostId || currentHostId() !== targetHostId) {
      return;
    }

    error.value = "";
    isLoading.value = true;

    const detailRequest = refreshHostDetail(targetHostId);
    const metricsRequest = loadMetrics(
      selectedWindow.value,
      { mode: "replace" },
      targetHostId,
    );
    const [detailResult, metricsResult] = await Promise.allSettled([
      detailRequest,
      metricsRequest,
    ]);

    if (detailResult.status === "rejected") {
      if (currentHostId() !== targetHostId) {
        return;
      }

      if (handleUnauthorized(detailResult.reason)) {
        isLoading.value = false;
        return;
      }

      error.value = "无法读取主机详情。";
      isLoading.value = false;
      return;
    }

    let shouldRefreshMetrics = true;

    if (metricsResult.status === "rejected") {
      if (currentHostId() !== targetHostId) {
        return;
      }

      if (handleUnauthorized(metricsResult.reason)) {
        shouldRefreshMetrics = false;
        isLoading.value = false;
        return;
      }

      metricsError.value = "无法读取历史指标，稍后会自动重试。";
      samples.value = [];
      clearLivePlayback();
    }

    if (shouldRefreshMetrics) {
      startMetricsRefreshLoop();
    }
    if (currentHostId() === targetHostId) {
      isLoading.value = false;
    }
  }

  async function loadMetrics(
    window: MetricsWindow,
    options: { mode: "enqueue-new" | "replace" },
    targetHostId = currentHostId(),
  ) {
    const response = await fetchMetrics(window, targetHostId);
    if (currentHostId() !== targetHostId) {
      return;
    }

    selectedWindow.value = response.metrics.window;
    metricsError.value = "";
    if (options.mode === "replace") {
      samples.value = response.metrics.samples;
      clearLivePlayback();
      updateHostLatestMetricsFromSamples(samples.value);
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
    } catch (caught) {
      if (handleUnauthorized(caught)) {
        return;
      }

      selectedWindow.value = previousWindow;
      metricsError.value = "无法读取历史指标，稍后会自动重试。";
      startMetricsRefreshLoop();
    } finally {
      isLoading.value = false;
    }
  }

  async function createProbeUpgradeRequest() {
    if (!currentHostId() || isCreatingProbeUpgradeRequest.value) {
      return;
    }

    isCreatingProbeUpgradeRequest.value = true;

    try {
      const response = await mutateJson<{
        probeUpgradeRequest: NonNullable<HostDetail["probeUpgradeStatus"]>;
      }>(`/api/web/hosts/${currentHostId()}/probe-upgrade-requests`, {
        method: "POST",
      });

      if (host.value) {
        host.value = {
          ...host.value,
          probeUpgradeStatus: response.probeUpgradeRequest,
        };
      }

      return response.probeUpgradeRequest;
    } catch (caught) {
      if (handleUnauthorized(caught)) {
        return;
      }

      throw caught;
    } finally {
      isCreatingProbeUpgradeRequest.value = false;
    }
  }

  function applyHostDetail(nextHost: HostDetail) {
    if (currentHostId() !== nextHost.id) {
      return;
    }

    host.value = nextHost;
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
    let shouldScheduleNextRefresh = true;
    try {
      await loadMetrics(selectedWindow.value, { mode: "enqueue-new" });
      await refreshHostDetailIfProbeUpgradeActive();
    } catch (caught) {
      if (handleUnauthorized(caught)) {
        shouldScheduleNextRefresh = false;
        return;
      }

      metricsError.value = "无法刷新历史指标，稍后会自动重试。";
      // The live socket can still recover state; keep the observation loop alive.
    } finally {
      isRefreshingMetrics = false;
      if (shouldScheduleNextRefresh) {
        scheduleMetricsRefresh();
      }
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

  async function fetchMetrics(window: MetricsWindow, targetHostId: number) {
    const path = `/api/web/hosts/${targetHostId}/metrics?window=${window}`;

    try {
      return await fetchJson<HostMetricsResponse>(path);
    } catch (caught) {
      if (!isTransientFetchError(caught)) {
        throw caught;
      }

      await sleep(150);
      return await fetchJson<HostMetricsResponse>(path);
    }
  }

  async function refreshHostDetail(targetHostId = currentHostId()) {
    const detailResponse = await fetchJson<HostDetailResponse>(
      `/api/web/hosts/${targetHostId}`,
    );
    if (currentHostId() !== targetHostId) {
      return;
    }

    host.value = detailResponse.host;
  }

  async function refreshHostDetailIfProbeUpgradeActive() {
    if (!isProbeUpgradeActive(host.value?.probeUpgradeStatus ?? null)) {
      return;
    }

    await refreshHostDetail();
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
      collectorCapabilities:
        summary.collectorCapabilities === undefined
          ? host.value.collectorCapabilities
          : summary.collectorCapabilities,
      lastReportAtMs: summary.lastSeenAtMs,
      latestMetrics: summary.latestMetrics
        ? mergeLatestMetrics(host.value.latestMetrics, summary.latestMetrics)
        : host.value.latestMetrics,
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
      latestMetrics: latestMetricsFromSample(sample, host.value.latestMetrics),
      status: "online",
    };
  }

  function updateHostLatestMetricsFromSamples(nextSamples: HostMetricSample[]) {
    if (!host.value || nextSamples.length === 0) {
      return;
    }

    const latestSample = nextSamples.at(-1);
    const latestMetrics = latestMetricsFromSamples(
      nextSamples,
      host.value.latestMetrics,
    );

    if (!latestSample || !latestMetrics) {
      return;
    }

    host.value = {
      ...host.value,
      lastReportAtMs: Math.max(
        host.value.lastReportAtMs ?? 0,
        latestSample.receivedAtMs,
      ),
      latestMetrics,
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

  function resetDetailState() {
    host.value = null;
    samples.value = [];
    error.value = "";
    metricsError.value = "";
    isRefreshingMetrics = false;
    clearLivePlayback();
    clearMetricsRefreshTimer();
  }

  function handleUnauthorized(error: unknown) {
    if (!isUnauthorizedError(error)) {
      return false;
    }

    clearLivePlayback();
    clearMetricsRefreshTimer();
    options.onUnauthorized?.();
    return true;
  }

  return {
    appendLiveSample,
    applyHostDetail,
    applyLiveSummary,
    chartRange,
    createProbeUpgradeRequest,
    error,
    host,
    isCreatingProbeUpgradeRequest,
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

function isProbeUpgradeActive(status: HostDetail["probeUpgradeStatus"]) {
  return ["pending", "accepted", "running"].includes(status?.state ?? "");
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
    batteryPercent: sample.batteryPercent,
    batteryState: sample.batteryState,
    collectedAtMs: sample.collectedAtMs,
    cpuCores: sample.cpuCores,
    cpuIdlePercent: sample.cpuIdlePercent,
    cpuIowaitPercent: sample.cpuIowaitPercent,
    cpuPercent: sample.cpuPercent,
    cpuStealPercent: sample.cpuStealPercent,
    cpuSystemPercent: sample.cpuSystemPercent,
    cpuUserPercent: sample.cpuUserPercent,
    diskTotalBytes,
    diskUsedBytes,
    disks: sample.disks.map((disk) => ({
      ...disk,
      readBytesDelta: disk.readBytesDelta ?? 0,
      writeBytesDelta: disk.writeBytesDelta ?? 0,
    })),
    memoryCacheBytes: sample.memoryCacheBytes,
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
    swapTotalBytes: sample.swapTotalBytes,
    swapUsedBytes: sample.swapUsedBytes,
    temperatureCelsius: sample.temperatureCelsius,
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
