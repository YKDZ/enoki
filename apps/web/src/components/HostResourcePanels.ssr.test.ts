import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import type { HostMetricSample } from "../types";
import HostResourcePanels from "./HostResourcePanels.vue";

const cpuSample: HostMetricSample = {
  collectedAtMs: 1_725_000_000_000,
  cpuCores: [
    {
      name: "cpu0",
      usagePercent: 42,
    },
  ],
  cpuPercent: 42,
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
  receivedAtMs: 1_725_000_000_000,
  sequence: 1,
  uptimeSeconds: null,
};

describe("Host resource panels", () => {
  it("renders CPU inventory details below the core charts", async () => {
    const html = await renderToString(
      createSSRApp(HostResourcePanels, {
        aggregateDiskIoSeries: [],
        aggregateDiskSeries: {
          name: "磁盘",
          points: [],
        },
        aggregateNetworkSeries: [],
        cpuCoreSeries: [
          {
            name: "cpu0",
            points: [[1_725_000_000_000, 42]],
          },
        ],
        cpuModel: "AMD Ryzen 7 4800H with Radeon Graphics",
        inventory: {
          cpuBaseFrequencyMhz: 2_900,
          cpuCacheL3Bytes: 8 * 1024 * 1024,
          cpuPhysicalCount: 8,
          cpuSocketCount: 1,
          processCount: 286,
          threadCount: 4255,
        },
        latestSample: cpuSample,
        panel: "cpu",
        samples: [cpuSample],
        xAxisMaxMs: 1_725_000_000_000,
        xAxisMinMs: 1_725_000_000_000 - 60_000,
        xAxisStartContinuityGapMs: 4_000,
      }),
    );

    expect(html).toContain("AMD Ryzen 7 4800H with Radeon Graphics");
    expect(html).toContain("进程");
    expect(html).toContain("286");
    expect(html).toContain("线程");
    expect(html).toContain("4255");
    expect(html).toContain("8 MB");
    expect(html).toContain("2900 MHz");
    expect(html).toContain("物理 CPU");
    expect(html).toContain("插槽");
  });

  it("renders per-interface network traffic totals from window sample deltas", async () => {
    const sample: HostMetricSample = {
      ...cpuSample,
      networkInterfaces: [
        {
          name: "eth0",
          rxBitsPerSecond: 1_600,
          rxBytesDelta: 1024 ** 2,
          txBitsPerSecond: 800,
          txBytesDelta: 512 * 1024,
        },
      ],
      networkRxBitsPerSecond: 1_600,
      networkRxBytesDelta: 1024 ** 2,
      networkTxBitsPerSecond: 800,
      networkTxBytesDelta: 512 * 1024,
    };
    const nextSample: HostMetricSample = {
      ...sample,
      collectedAtMs: 1_725_000_030_000,
      networkInterfaces: [
        {
          name: "eth0",
          rxBitsPerSecond: 3_200,
          rxBytesDelta: 2 * 1024 ** 2,
          txBitsPerSecond: 1_600,
          txBytesDelta: 512 * 1024,
        },
      ],
      networkRxBitsPerSecond: 3_200,
      networkRxBytesDelta: 2 * 1024 ** 2,
      networkTxBitsPerSecond: 1_600,
      networkTxBytesDelta: 512 * 1024,
    };

    const html = await renderToString(
      createSSRApp(HostResourcePanels, {
        aggregateDiskIoSeries: [],
        aggregateDiskSeries: {
          name: "磁盘",
          points: [],
        },
        aggregateNetworkSeries: [],
        cpuCoreSeries: [],
        cpuModel: null,
        inventory: null,
        latestSample: nextSample,
        panel: "network",
        samples: [sample, nextSample],
        xAxisMaxMs: 1_725_000_000_000,
        xAxisMinMs: 1_725_000_000_000 - 60_000,
        xAxisStartContinuityGapMs: 4_000,
      }),
    );

    expect(html).not.toContain("当前总吞吐量");
    expect(html).toContain("接收");
    expect(html).toContain("3.2 Kb/s");
    expect(html).toContain("发送");
    expect(html).toContain("1.6 Kb/s");
    expect(html).toContain("总接收");
    expect(html).toContain("3 MB");
    expect(html).toContain("总发送");
    expect(html).toContain("1 MB");
  });
});
