import { afterEach, describe, expect, it, vi } from "vitest";

import { useManagedHostDetail } from "./useManagedHostDetail";

describe("Managed Host detail data", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("loads detail and fixed-window history over HTTP and supports empty windows", async () => {
    const requestedPaths: string[] = [];
    vi.setSystemTime(new Date(1_725_000_100_000));
    const detail = useManagedHostDetail(1, {
      async fetchJson<T>(path: string) {
        requestedPaths.push(path);

        if (path === "/api/web/managed-hosts/1") {
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
              path === "/api/web/managed-hosts/1/metrics?window=6h"
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
            window: path.endsWith("window=6h") ? "6h" : "1h",
          },
        } as T;
      },
    });

    await detail.load();

    expect(requestedPaths).toEqual([
      "/api/web/managed-hosts/1",
      "/api/web/managed-hosts/1/metrics?window=1h",
    ]);
    expect(detail.samples.value).toHaveLength(1);
    expect(detail.isEmpty.value).toBe(false);
    expect(detail.chartRange.value).toEqual({
      maxMs: 1_725_000_000_000,
      minMs: 1_725_000_000_000 - 60 * 60 * 1000,
    });

    await detail.switchWindow("6h");

    expect(requestedPaths.at(-1)).toBe(
      "/api/web/managed-hosts/1/metrics?window=6h",
    );
    expect(detail.selectedWindow.value).toBe("6h");
    expect(detail.samples.value).toEqual([]);
    expect(detail.isEmpty.value).toBe(true);
    expect(detail.chartRange.value).toEqual({
      maxMs: 1_725_000_050_000,
      minMs: 1_725_000_050_000 - 6 * 60 * 60 * 1000,
    });
  });

  it("appends WebSocket samples for the visible host and computes aggregate tail values", async () => {
    const detail = useManagedHostDetail(1, {
      async fetchJson<T>(path: string) {
        if (path === "/api/web/managed-hosts/1") {
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
      managedHostId: 2,
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
      managedHostId: 1,
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
  });

  it("plays samples from the same report batch at the collection cadence", async () => {
    vi.useFakeTimers();
    const detail = useManagedHostDetail(1, {
      async fetchJson<T>(path: string) {
        if (path === "/api/web/managed-hosts/1") {
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

  it("updates the current detail summary from live WebSocket summaries", async () => {
    const detail = useManagedHostDetail(1, {
      async fetchJson<T>(path: string) {
        if (path === "/api/web/managed-hosts/1") {
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
        latestMetrics: expect.objectContaining({
          cpuPercent: 44,
          memoryUsedBytes: 12_000,
          uptimeSeconds: 86_400,
        }),
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

function liveSample(sequence: number, collectedAtMs: number) {
  return {
    collectedAtMs,
    cpuCores: [],
    cpuPercent: sequence,
    disks: [],
    managedHostId: 1,
    memoryTotalBytes: 10_000,
    memoryUsedBytes: sequence * 1_000,
    networkInterfaces: [],
    receivedAtMs: 1_725_000_004_000,
    sequence,
    uptimeSeconds: sequence * 60,
  };
}
