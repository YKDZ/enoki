import { renderToString } from "@vue/server-renderer";
import { createSSRApp } from "vue";
import { describe, expect, it } from "vitest";

import ManagedHostCard from "./ManagedHostCard.vue";
import type { ManagedHostSummary } from "../types";

const host: ManagedHostSummary = {
  clockSkew: {
    detected: true,
    lastDeltaMs: 60_000,
  },
  connectAddress: "10.0.0.10",
  cpu: "2 cores",
  cpuModel: null,
  displayName: "managed-host-01",
  id: 1,
  lastReportAtMs: 1_725_000_000_000,
  latestMetrics: {
    collectedAtMs: 1_725_000_000_000,
    cpuPercent: 24,
    diskTotalBytes: 100,
    diskUsedBytes: 58,
    memoryTotalBytes: 100 * 1024 ** 2,
    memoryUsedBytes: 41 * 1024 ** 2,
    networkRxBitsPerSecond: 18_400_000,
    networkTxBitsPerSecond: 6_100_000,
    receivedAtMs: 1_725_000_000_000,
    uptimeSeconds: 3_600,
  },
  memory: "2 GiB",
  probeConfiguration: {
    mode: "inherit",
    version: "default-v1",
  },
  probeVersion: "0.1.0",
  status: "online",
  system: "linux",
};

describe("Managed Host overview card", () => {
  it("renders a clickable summary card with translated status and metric bars", async () => {
    const html = await renderToString(
      createSSRApp(ManagedHostCard, {
        host,
      }),
    );

    expect(html).toContain('role="button"');
    expect(html).toContain("CPU");
    expect(html).toContain("内存");
    expect(html).toContain("41 MiB / 100 MiB");
    expect(html).toContain("磁盘");
    expect(html).toContain("18.4 Mb/s");
    expect(html).toContain("在线");
    expect(html).toContain("时钟偏移 60s");
    expect(html).not.toContain("最新 CPU");
    expect(html).not.toContain("最新上报");
    expect(html).not.toContain(">online<");
  });
});
