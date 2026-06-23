import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import type { MetricsChartData } from "@/lib/metrics-chart-data";

import type { HostDetail } from "../types";
import HostMetricSlotGrid from "./HostMetricSlotGrid.vue";

const chartData: MetricsChartData = {
  cpu: {
    aggregate: { name: "使用率", points: [] },
    cores: [],
  },
  disk: {
    aggregateIoBytes: [],
    aggregateUsedPercent: { name: "使用率", points: [] },
    mounts: [],
  },
  memory: {
    usedPercent: { name: "使用率", points: [] },
  },
  network: {
    aggregate: [],
    interfaces: [],
  },
};

const host: HostDetail = {
  clockSkew: {
    detected: false,
    lastDeltaMs: null,
  },
  collectorCapabilities: {
    official: {
      cpu: { available: true },
      disk: { available: false },
      memory: { available: true },
      network: { available: true },
    },
  },
  connectAddress: "10.0.0.10",
  cpu: "2 cores",
  cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
  description: "",
  displayName: "managed-host-01",
  hostMetadata: {
    connectAddress: "10.0.0.10",
    description: "",
    displayName: "managed-host-01",
    observedIp: null,
  },
  id: 1,
  inventory: {
    cpuCount: 2,
  },
  lastReportAtMs: 1_725_000_000_000,
  latestMetrics: null,
  memory: "8 GB",
  probeConfiguration: {
    configuration: {
      collectCpu: true,
      collectDisk: true,
      collectLoad: true,
      collectMemory: true,
      collectNetwork: true,
      collectUptime: true,
      metricsCollectionIntervalSeconds: 5,
      reportingBatchIntervalSeconds: 15,
      version: "default-v1",
    },
    mode: "inherit",
    version: "default-v1",
  },
  probeUpgradeEligibility: {
    currentProbeAssetSetVersion: null,
    currentProbeVersion: "0.1.0",
    isUpgradeable: false,
    nonUpgradeableReason: "probe_asset_set_version_missing",
  },
  probeUpgradeStatus: null,
  probeVersion: "0.1.0",
  status: "online",
  system: "linux 6.8.0 x86_64",
  warnings: [],
};

describe("Host metric slot grid", () => {
  it("hides unavailable metric domains from the first render", async () => {
    const html = await renderToString(
      createSSRApp(HostMetricSlotGrid, {
        chartData,
        chartStartContinuityGapMs: 4_000,
        host,
        latestMetric: null,
        latestSample: null,
        samples: [],
        xAxisMaxMs: 1_725_000_000_000,
        xAxisMinMs: 1_725_000_000_000 - 60_000,
      }),
    );

    expect(html).toContain("CPU");
    expect(html).toContain("内存");
    expect(html).toContain("网络");
    expect(html).not.toContain("磁盘与 I/O");
    expect(html).not.toContain("暂无磁盘数据");
  });
});
