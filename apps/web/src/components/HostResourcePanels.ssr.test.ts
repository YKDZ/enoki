import { renderToString } from "@vue/server-renderer";
import { createSSRApp } from "vue";
import { describe, expect, it } from "vitest";

import HostResourcePanels from "./HostResourcePanels.vue";

describe("Host resource panels", () => {
  it("renders CPU inventory details below the core charts", async () => {
    const html = await renderToString(
      createSSRApp(HostResourcePanels, {
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
        latestSample: {
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
        },
        panel: "cpu",
        xAxisMaxMs: 1_725_000_000_000,
        xAxisMinMs: 1_725_000_000_000 - 60_000,
      }),
    );

    expect(html).toContain("AMD Ryzen 7 4800H with Radeon Graphics");
    expect(html).toContain("进程");
    expect(html).toContain("286");
    expect(html).toContain("线程");
    expect(html).toContain("4255");
    expect(html).toContain("8 MiB");
    expect(html).toContain("2900 MHz");
    expect(html).toContain("物理 CPU");
    expect(html).toContain("插槽");
  });
});
