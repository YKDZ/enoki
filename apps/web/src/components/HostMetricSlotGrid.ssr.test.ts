import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import type { MetricsChartData } from "@/lib/metrics-chart-data";
import { defaultEnabledCollectorIds } from "@/lib/probe-configuration";

import type { HostDetail, HostMetricSample } from "../types";
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
      enabledCollectorIds: [...defaultEnabledCollectorIds],
      metricsCollectionIntervalSeconds: 5,
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
  async function renderHostMetricSlotGrid(
    inputHost: HostDetail,
    options: {
      chartData?: MetricsChartData;
      latestMetric?: HostMetricSample | HostDetail["latestMetrics"] | null;
      latestSample?: HostMetricSample | null;
      samples?: HostMetricSample[];
    } = {},
  ) {
    return await renderToString(
      createSSRApp(HostMetricSlotGrid, {
        chartData: options.chartData ?? chartData,
        chartStartContinuityGapMs: 4_000,
        host: inputHost,
        latestMetric: options.latestMetric ?? null,
        latestSample: options.latestSample ?? null,
        samples: options.samples ?? [],
        xAxisMaxMs: 1_725_000_000_000,
        xAxisMinMs: 1_725_000_000_000 - 60_000,
      }),
    );
  }

  it("hides unavailable metric domains from the first render", async () => {
    const html = await renderHostMetricSlotGrid(host);

    expect(html).toContain("CPU");
    expect(html).toContain("内存");
    expect(html).toContain("网络");
    expect(html).not.toContain("磁盘与 I/O");
    expect(html).not.toContain("暂无磁盘数据");
  });

  it("keeps metric card slots stable with first-frame skeletons", async () => {
    const html = await renderHostMetricSlotGrid({
      ...host,
      collectorCapabilities: {
        official: {
          cpu: { available: true },
          disk: { available: true },
          memory: { available: true },
          network: { available: true },
        },
      },
    });

    expect(html).toContain("data-layout-grid");
    expect(html).toContain('data-panel-id="cpu"');
    expect(html).toContain('data-panel-id="network"');
    expect(html).toContain('data-panel-id="memory"');
    expect(html).toContain('data-panel-id="disk"');
    expect(html).toContain("正在加载指标");
    expect(html).toContain("xl:grid-cols-[minmax(0,1fr)_320px]");
    expect(html).not.toContain("n/a");
  });

  it("renders supported metric cards with chart smoke markers and details", async () => {
    const sample: HostMetricSample = {
      collectedAtMs: 1_725_000_000_000,
      cpuCores: [{ name: "cpu0", usagePercent: 24 }],
      cpuIdlePercent: 76,
      cpuIowaitPercent: 1,
      cpuPercent: 24,
      cpuStealPercent: 0,
      cpuSystemPercent: 8,
      cpuUserPercent: 15,
      diskTotalBytes: 100,
      diskUsedBytes: 50,
      disks: [
        {
          availableBytes: 50,
          filesystemType: "ext4",
          mountPoint: "/",
          readBytesDelta: 128,
          totalBytes: 100,
          usedBytes: 50,
          writeBytesDelta: 256,
        },
      ],
      memoryCacheBytes: 20,
      memoryTotalBytes: 100,
      memoryUsedBytes: 40,
      networkInterfaces: [
        {
          name: "eth0",
          rxBitsPerSecond: 1_600,
          rxBytesDelta: 200,
          txBitsPerSecond: 800,
          txBytesDelta: 100,
        },
      ],
      networkRxBitsPerSecond: 1_600,
      networkRxBytesDelta: 200,
      networkTxBitsPerSecond: 800,
      networkTxBytesDelta: 100,
      receivedAtMs: 1_725_000_000_000,
      sequence: 1,
      uptimeSeconds: 60,
    };
    const html = await renderHostMetricSlotGrid(
      {
        ...host,
        collectorCapabilities: {
          official: {
            cpu: { available: true },
            disk: { available: true },
            memory: { available: true },
            network: { available: true },
          },
        },
        inventory: {
          cpuCount: 2,
          memoryTotalBytes: 100,
        },
      },
      {
        chartData: {
          cpu: {
            aggregate: { name: "使用率", points: [[1_725_000_000_000, 24]] },
            cores: [{ name: "cpu0", points: [[1_725_000_000_000, 24]] }],
          },
          disk: {
            aggregateIoBytes: [
              { name: "读取", points: [[1_725_000_000_000, 128]] },
              { name: "写入", points: [[1_725_000_000_000, 256]] },
            ],
            aggregateUsedPercent: {
              name: "使用率",
              points: [[1_725_000_000_000, 50]],
            },
            mounts: [],
          },
          memory: {
            usedPercent: {
              name: "使用率",
              points: [[1_725_000_000_000, 40]],
            },
          },
          network: {
            aggregate: [
              { name: "接收", points: [[1_725_000_000_000, 1_600]] },
              { name: "发送", points: [[1_725_000_000_000, 800]] },
            ],
            interfaces: [],
          },
        },
        latestMetric: sample,
        latestSample: sample,
        samples: [sample],
      },
    );

    expect(html.match(/data-layout-card/g)).toHaveLength(4);
    expect(html).toContain('data-smoke-chart-title="吞吐量"');
    expect(html).toContain('data-smoke-chart-title="内存"');
    expect(html).toContain('data-smoke-chart-title="占用率"');
    expect(html).toContain('data-smoke-point-count="1"');
    expect(html).toContain("eth0");
    expect(html).toContain("挂载点");
    expect(html).not.toContain("正在加载指标");
  });

  it("uses latest-known Disk Health in disk details unless capability is unavailable", async () => {
    const sample: HostMetricSample = {
      collectedAtMs: 1_725_000_005_000,
      cpuCores: [],
      cpuPercent: 30,
      diskHealth: [],
      diskTotalBytes: 100,
      diskUsedBytes: 60,
      disks: [
        {
          availableBytes: 40,
          filesystemType: "ext4",
          mountPoint: "/",
          totalBytes: 100,
          usedBytes: 60,
        },
      ],
      memoryTotalBytes: 100,
      memoryUsedBytes: 50,
      networkInterfaces: [],
      networkRxBitsPerSecond: null,
      networkRxBytesDelta: null,
      networkTxBitsPerSecond: null,
      networkTxBytesDelta: null,
      receivedAtMs: 1_725_000_005_500,
      sequence: 2,
      uptimeSeconds: 120,
    };
    const latestMetric = {
      ...sample,
      diskHealth: [
        {
          deviceName: "/dev/sda",
          model: "Samsung SSD 870 EVO 1TB",
          passed: true,
          powerOnHours: 12_345,
          serialNumber: "S6PTEST",
          temperatureCelsius: 31,
        },
      ],
    };
    const supportedHost = {
      ...host,
      collectorCapabilities: {
        official: {
          cpu: { available: true },
          disk: { available: true },
          diskHealth: { available: true },
          memory: { available: true },
          network: { available: true },
        },
      },
    };

    const supportedHtml = await renderHostMetricSlotGrid(supportedHost, {
      latestMetric,
      latestSample: sample,
      samples: [sample],
    });
    expect(supportedHtml).toContain("硬盘健康");
    expect(supportedHtml).toContain("Samsung SSD 870 EVO 1TB");

    const unavailableHtml = await renderHostMetricSlotGrid(
      {
        ...supportedHost,
        collectorCapabilities: {
          official: {
            cpu: { available: true },
            disk: { available: true },
            diskHealth: { available: false },
            memory: { available: true },
            network: { available: true },
          },
        },
      },
      {
        latestMetric,
        latestSample: sample,
        samples: [sample],
      },
    );
    expect(unavailableHtml).not.toContain("硬盘健康");
    expect(unavailableHtml).not.toContain("Samsung SSD 870 EVO 1TB");
    expect(unavailableHtml).toContain("挂载点");
  });

  it("hides Disk Health latest-known data when the capability is absent", async () => {
    const sample: HostMetricSample = {
      collectedAtMs: 1_725_000_005_000,
      cpuCores: [],
      cpuPercent: 30,
      diskTotalBytes: 100,
      diskUsedBytes: 60,
      disks: [
        {
          availableBytes: 40,
          filesystemType: "ext4",
          mountPoint: "/",
          totalBytes: 100,
          usedBytes: 60,
        },
      ],
      memoryTotalBytes: 100,
      memoryUsedBytes: 50,
      networkInterfaces: [],
      networkRxBitsPerSecond: null,
      networkRxBytesDelta: null,
      networkTxBitsPerSecond: null,
      networkTxBytesDelta: null,
      receivedAtMs: 1_725_000_005_500,
      sequence: 2,
      uptimeSeconds: 120,
    };
    const html = await renderHostMetricSlotGrid(
      {
        ...host,
        collectorCapabilities: {
          official: {
            cpu: { available: true },
            disk: { available: true },
            memory: { available: true },
            network: { available: true },
          },
        },
      },
      {
        latestMetric: {
          ...sample,
          diskHealth: [
            {
              deviceName: "/dev/sda",
              model: "Samsung SSD 870 EVO 1TB",
              passed: true,
              powerOnHours: 12_345,
              serialNumber: "S6PTEST",
              temperatureCelsius: 31,
            },
          ],
        },
        latestSample: sample,
        samples: [sample],
      },
    );

    expect(html).not.toContain("硬盘健康");
    expect(html).not.toContain("Samsung SSD 870 EVO 1TB");
    expect(html).toContain("挂载点");
  });

  it("hides Disk Health current-sample data when the capability is absent", async () => {
    const sample: HostMetricSample = {
      collectedAtMs: 1_725_000_005_000,
      cpuCores: [],
      cpuPercent: 30,
      diskHealth: [
        {
          deviceName: "/dev/sda",
          model: "Samsung SSD 870 EVO 1TB",
          passed: true,
          powerOnHours: 12_345,
          serialNumber: "S6PTEST",
          temperatureCelsius: 31,
        },
      ],
      diskTotalBytes: 100,
      diskUsedBytes: 60,
      disks: [
        {
          availableBytes: 40,
          filesystemType: "ext4",
          mountPoint: "/",
          totalBytes: 100,
          usedBytes: 60,
        },
      ],
      memoryTotalBytes: 100,
      memoryUsedBytes: 50,
      networkInterfaces: [],
      networkRxBitsPerSecond: null,
      networkRxBytesDelta: null,
      networkTxBitsPerSecond: null,
      networkTxBytesDelta: null,
      receivedAtMs: 1_725_000_005_500,
      sequence: 2,
      uptimeSeconds: 120,
    };
    const html = await renderHostMetricSlotGrid(
      {
        ...host,
        collectorCapabilities: {
          official: {
            cpu: { available: true },
            disk: { available: true },
            memory: { available: true },
            network: { available: true },
          },
        },
      },
      {
        latestMetric: sample,
        latestSample: sample,
        samples: [sample],
      },
    );

    expect(html).not.toContain("硬盘健康");
    expect(html).not.toContain("Samsung SSD 870 EVO 1TB");
    expect(html).toContain("挂载点");
  });
});
