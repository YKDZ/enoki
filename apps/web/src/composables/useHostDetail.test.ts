import { afterEach, describe, expect, it, vi } from "vitest";
import { reactive } from "vue";

import { ApiError } from "@/lib/api";

import type { MetricsWindow } from "../types";
import { useHostDetail } from "./useHostDetail";

describe("Host detail data", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("loads detail and fixed-window history over HTTP and supports empty windows", async () => {
    const requestedPaths: string[] = [];
    vi.setSystemTime(new Date(1_725_000_100_000));
    const detail = useHostDetail(1, {
      async fetchJson<T>(path: string) {
        requestedPaths.push(path);

        if (path === "/api/web/hosts/1") {
          return {
            host: {
              id: 1,
              lastReportAtMs: 1_725_000_050_000,
              probeConfiguration: {
                configuration: {
                  metricsCollectionIntervalSeconds: 5,
                  version: "default-v1",
                },
                mode: "inherit",
              },
            },
          } as T;
        }

        return {
          metrics: {
            samples:
              path === "/api/web/hosts/1/metrics?window=6h"
                ? []
                : [
                    {
                      collectedAtMs: 1_725_000_000_000,
                      cpuCores: [],
                      cpuPercent: 25,
                      diskTotalBytes: null,
                      diskUsedBytes: null,
                      disks: [],
                      memoryTotalBytes: null,
                      memoryUsedBytes: null,
                      networkInterfaces: [],
                      networkRxBitsPerSecond: null,
                      networkRxBytesDelta: null,
                      networkTxBitsPerSecond: null,
                      networkTxBytesDelta: null,
                      receivedAtMs: 1_725_000_000_500,
                      sequence: 1,
                      uptimeSeconds: null,
                    },
                  ],
            window: path.endsWith("window=6h")
              ? "6h"
              : path.endsWith("window=1m")
                ? "1m"
                : "1h",
          },
        } as T;
      },
      windowPreferences: createWindowPreferences(),
    });

    await detail.load();

    expect(requestedPaths).toEqual([
      "/api/web/hosts/1",
      "/api/web/hosts/1/metrics?window=1h",
    ]);
    expect(detail.samples.value).toHaveLength(1);
    expect(detail.isEmpty.value).toBe(false);
    expect(detail.chartRange.value).toEqual({
      maxMs: 1_725_000_000_000,
      minMs: 1_725_000_000_000 - 60 * 60 * 1000,
    });

    await detail.switchWindow("6h");

    expect(requestedPaths.at(-1)).toBe("/api/web/hosts/1/metrics?window=6h");
    expect(detail.selectedWindow.value).toBe("6h");
    expect(detail.samples.value).toEqual([]);
    expect(detail.isEmpty.value).toBe(true);
    expect(detail.chartRange.value).toEqual({
      maxMs: 1_725_000_050_000,
      minMs: 1_725_000_050_000 - 6 * 60 * 60 * 1000,
    });

    await detail.switchWindow("1m");

    expect(requestedPaths.at(-1)).toBe("/api/web/hosts/1/metrics?window=1m");
    expect(detail.selectedWindow.value).toBe("1m");
    expect(detail.samples.value).toHaveLength(1);
    expect(detail.isEmpty.value).toBe(false);
    expect(detail.chartRange.value).toEqual({
      maxMs: 1_725_000_000_000,
      minMs: 1_725_000_000_000 - 60 * 1000,
    });
  });

  it("delegates unauthorized detail loads without showing a detail error", async () => {
    const onUnauthorized = vi.fn();
    const detail = useHostDetail(1, {
      async fetchJson<T>(_path: string): Promise<T> {
        throw new ApiError("Request failed: 401", 401);
      },
      onUnauthorized,
      windowPreferences: createWindowPreferences(),
    });

    await detail.load();

    expect(onUnauthorized).toHaveBeenCalledOnce();
    expect(detail.error.value).toBe("");
    expect(detail.host.value).toBeNull();
    expect(detail.isLoading.value).toBe(false);
  });

  it("appends WebSocket samples for the visible host and computes aggregate tail values", async () => {
    const detail = useHostDetail(1, {
      async fetchJson<T>(path: string) {
        if (path === "/api/web/hosts/1") {
          return {
            host: {
              id: 1,
              probeConfiguration: {
                configuration: {
                  metricsCollectionIntervalSeconds: 10,
                  version: "host-1-1",
                },
                mode: "override",
              },
            },
          } as T;
        }

        return {
          metrics: {
            samples: [],
            window: "1h",
          },
        } as T;
      },
      windowPreferences: createWindowPreferences(),
    });

    await detail.load();
    detail.appendLiveSample({
      collectedAtMs: 1_725_000_010_000,
      cpuCores: [
        {
          name: "cpu0",
          usagePercent: 21,
        },
      ],
      cpuPercent: 22,
      disks: [
        {
          availableBytes: 4_000,
          filesystemType: "ext4",
          mountPoint: "/",
          totalBytes: 10_000,
          usedBytes: 6_000,
        },
      ],
      hostId: 2,
      memoryTotalBytes: 10_000,
      memoryUsedBytes: 5_000,
      networkInterfaces: [
        {
          name: "eth0",
          rxBytesDelta: 2_000,
          txBytesDelta: 1_000,
        },
      ],
      receivedAtMs: 1_725_000_010_100,
      sequence: 1,
      uptimeSeconds: 3_600,
    });

    expect(detail.samples.value).toEqual([]);

    detail.appendLiveSample({
      collectedAtMs: 1_725_000_010_000,
      cpuCores: [
        {
          name: "cpu0",
          usagePercent: 21,
        },
      ],
      cpuPercent: 22,
      disks: [
        {
          availableBytes: 4_000,
          filesystemType: "ext4",
          mountPoint: "/",
          totalBytes: 10_000,
          usedBytes: 6_000,
        },
      ],
      hostId: 1,
      memoryTotalBytes: 10_000,
      memoryUsedBytes: 5_000,
      networkInterfaces: [
        {
          name: "eth0",
          rxBytesDelta: 2_000,
          txBytesDelta: 1_000,
        },
      ],
      receivedAtMs: 1_725_000_010_100,
      sequence: 1,
      uptimeSeconds: 3_600,
    });

    expect(detail.samples.value).toEqual([
      expect.objectContaining({
        diskTotalBytes: 10_000,
        diskUsedBytes: 6_000,
        networkInterfaces: [
          {
            name: "eth0",
            rxBitsPerSecond: 1_600,
            rxBytesDelta: 2_000,
            txBitsPerSecond: 800,
            txBytesDelta: 1_000,
          },
        ],
        networkRxBitsPerSecond: 1_600,
        networkRxBytesDelta: 2_000,
        networkTxBitsPerSecond: 800,
        networkTxBytesDelta: 1_000,
      }),
    ]);
    expect(detail.host.value?.latestMetrics).toEqual(
      expect.objectContaining({
        cpuPercent: 22,
        memoryUsedBytes: 5_000,
        networkRxBitsPerSecond: 1_600,
      }),
    );
  });

  it("keeps the host detail visible when the metrics request fails", async () => {
    const detail = useHostDetail(1, {
      async fetchJson<T>(path: string) {
        if (path === "/api/web/hosts/1") {
          return {
            host: {
              id: 1,
              probeConfiguration: {
                configuration: {
                  metricsCollectionIntervalSeconds: 5,
                  version: "default-v1",
                },
                mode: "inherit",
              },
            },
          } as T;
        }

        throw new Error(`Request failed: ${path}`);
      },
      windowPreferences: createWindowPreferences(),
    });

    await detail.load();

    expect(detail.host.value).toEqual(
      expect.objectContaining({
        id: 1,
      }),
    );
    expect(detail.error.value).toBe("");
    expect(detail.metricsError.value).toBe(
      "无法读取历史指标，稍后会自动重试。",
    );
    expect(detail.samples.value).toEqual([]);
  });

  it("plays live samples from the same report batch at the collection cadence", async () => {
    vi.useFakeTimers();
    const detail = useHostDetail(1, {
      async fetchJson<T>(path: string) {
        if (path === "/api/web/hosts/1") {
          return {
            host: {
              id: 1,
              probeConfiguration: {
                configuration: {
                  metricsCollectionIntervalSeconds: 1,
                  version: "host-1-1",
                },
                mode: "override",
              },
            },
          } as T;
        }

        return {
          metrics: {
            samples: [],
            window: "1h",
          },
        } as T;
      },
      windowPreferences: createWindowPreferences(),
    });

    await detail.load();

    detail.appendLiveSample(liveSample(1, 1_725_000_001_000));
    detail.appendLiveSample(liveSample(2, 1_725_000_002_000));
    detail.appendLiveSample(liveSample(3, 1_725_000_003_000));

    expect(detail.samples.value.map((sample) => sample.sequence)).toEqual([1]);

    await vi.advanceTimersByTimeAsync(999);
    expect(detail.samples.value.map((sample) => sample.sequence)).toEqual([1]);

    await vi.advanceTimersByTimeAsync(1);
    expect(detail.samples.value.map((sample) => sample.sequence)).toEqual([
      1, 2,
    ]);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(detail.samples.value.map((sample) => sample.sequence)).toEqual([
      1, 2, 3,
    ]);
  });

  it("polls history and plays newly observed samples at the collection cadence", async () => {
    vi.useFakeTimers();
    let metricsRequestCount = 0;
    const detail = useHostDetail(1, {
      async fetchJson<T>(path: string) {
        if (path === "/api/web/hosts/1") {
          return {
            host: {
              id: 1,
              probeConfiguration: {
                configuration: {
                  metricsCollectionIntervalSeconds: 1,
                  version: "host-1-1",
                },
                mode: "override",
              },
            },
          } as T;
        }

        metricsRequestCount += 1;
        return {
          metrics: {
            samples:
              metricsRequestCount === 1
                ? [metricSample(1, 1_725_000_001_000)]
                : [
                    metricSample(1, 1_725_000_001_000),
                    metricSample(2, 1_725_000_002_000),
                    metricSample(3, 1_725_000_003_000),
                  ],
            window: "1h",
          },
        } as T;
      },
      windowPreferences: createWindowPreferences(),
    });

    await detail.load();

    expect(detail.samples.value.map((sample) => sample.sequence)).toEqual([1]);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(detail.samples.value.map((sample) => sample.sequence)).toEqual([
      1, 2,
    ]);
    expect(detail.host.value?.latestMetrics?.cpuPercent).toBe(2);

    await vi.advanceTimersByTimeAsync(999);
    expect(detail.samples.value.map((sample) => sample.sequence)).toEqual([
      1, 2,
    ]);

    await vi.advanceTimersByTimeAsync(1);
    expect(detail.samples.value.map((sample) => sample.sequence)).toEqual([
      1, 2, 3,
    ]);
  });

  it("keeps the visible chart range equal to the selected window when the window has a leading gap", async () => {
    const detail = useHostDetail(1, {
      async fetchJson<T>(path: string) {
        if (path === "/api/web/hosts/1") {
          return {
            host: {
              id: 1,
              probeConfiguration: {
                configuration: {
                  metricsCollectionIntervalSeconds: 5,
                  version: "host-1-1",
                },
                mode: "override",
              },
            },
          } as T;
        }

        return {
          metrics: {
            samples: [
              metricSample(1, 1_725_000_003_000),
              metricSample(2, 1_725_000_060_000),
            ],
            window: "1m",
          },
        } as T;
      },
      windowPreferences: createWindowPreferences({
        1: "1m",
      }),
    });

    await detail.load();

    expect(detail.chartRange.value).toEqual({
      maxMs: 1_725_000_060_000,
      minMs: 1_725_000_060_000 - 60 * 1000,
    });
  });

  it("updates the current detail summary from live WebSocket summaries", async () => {
    const detail = useHostDetail(1, {
      async fetchJson<T>(path: string) {
        if (path === "/api/web/hosts/1") {
          return {
            host: {
              clockSkew: {
                detected: false,
                lastDeltaMs: null,
              },
              id: 1,
              lastReportAtMs: null,
              latestMetrics: null,
              probeConfiguration: {
                configuration: {
                  metricsCollectionIntervalSeconds: 5,
                  version: "default-v1",
                },
                mode: "inherit",
              },
              status: "offline",
              warnings: [],
            },
          } as T;
        }

        return {
          metrics: {
            samples: [],
            window: "1h",
          },
        } as T;
      },
      windowPreferences: createWindowPreferences(),
    });

    await detail.load();

    detail.applyLiveSummary({
      id: 1,
      lastSeenAtMs: 1_725_000_020_000,
      latestMetrics: {
        collectedAtMs: 1_725_000_019_500,
        cpuPercent: 44,
        diskTotalBytes: 10_000,
        diskUsedBytes: 6_000,
        memoryTotalBytes: 20_000,
        memoryUsedBytes: 12_000,
        networkRxBitsPerSecond: 1_200,
        networkRxBytesDelta: 750,
        networkTxBitsPerSecond: 800,
        networkTxBytesDelta: 500,
        receivedAtMs: 1_725_000_020_000,
        uptimeSeconds: 86_400,
      },
      status: "online",
      warningFlags: {
        clockSkew: true,
        probeConfigurationError: true,
      },
    });

    expect(detail.host.value).toEqual(
      expect.objectContaining({
        clockSkew: expect.objectContaining({
          detected: true,
        }),
        lastReportAtMs: 1_725_000_020_000,
        latestMetrics: null,
        status: "online",
        warnings: expect.arrayContaining([
          expect.objectContaining({
            code: "clock_skew",
          }),
          expect.objectContaining({
            code: "probe_configuration_error",
            message: "探针未能应用最新配置，请检查探针连通性或配置下发状态。",
          }),
        ]),
      }),
    );
    expect(detail.samples.value).toEqual([]);
  });
});

function createWindowPreferences(
  initialWindows: Record<string, MetricsWindow> = {},
) {
  const windowsByHostId = reactive({ ...initialWindows });

  return {
    selectedWindowForHost(hostId: number) {
      return windowsByHostId[String(hostId)] ?? "1h";
    },
    setSelectedWindowForHost(hostId: number, window: MetricsWindow) {
      windowsByHostId[String(hostId)] = window;
    },
  };
}

function liveSample(sequence: number, collectedAtMs: number) {
  return {
    collectedAtMs,
    cpuCores: [],
    cpuPercent: sequence,
    disks: [],
    hostId: 1,
    memoryTotalBytes: 10_000,
    memoryUsedBytes: sequence * 1_000,
    networkInterfaces: [],
    receivedAtMs: 1_725_000_004_000,
    sequence,
    uptimeSeconds: sequence * 60,
  };
}

function metricSample(sequence: number, collectedAtMs: number) {
  return {
    collectedAtMs,
    cpuCores: [],
    cpuPercent: sequence,
    diskTotalBytes: null,
    diskUsedBytes: null,
    disks: [],
    memoryTotalBytes: 10_000,
    memoryUsedBytes: sequence * 1_000,
    networkInterfaces: [],
    networkRxBitsPerSecond: null,
    networkRxBytesDelta: null,
    networkTxBitsPerSecond: null,
    networkTxBytesDelta: null,
    receivedAtMs: collectedAtMs + 100,
    sequence,
    uptimeSeconds: sequence * 60,
  };
}
