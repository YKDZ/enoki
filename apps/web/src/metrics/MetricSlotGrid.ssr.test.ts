import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import { defaultEnabledCollectorIds } from "@/lib/probe-configuration";
import type { MetricsChartData } from "@/metrics/chart-data";

import type { HostDetail, HostMetricSample } from "../types";
import HostMetricSlotGrid from "./MetricSlotGrid.vue";

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
  collectorCapabilities: null,
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
  hostProfile: {
    architecture: "x86_64",
    cpuCount: 2,
    cpuBaseFrequencyMhz: 2_900,
    cpuCacheL3Bytes: 8 * 1024 * 1024,
    cpuPhysicalCount: 8,
    cpuSocketCount: 1,
    filesystems: [],
    hostname: "managed-host-01",
    kernel: "6.8.0",
    memoryTotalBytes: 8_589_934_592,
    networkInterfaces: [],
    os: "linux",
    processCount: 286,
    probeVersion: "0.1.0",
    threadCount: 4255,
  },
  id: 1,
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
  const hostProfile = host.hostProfile;
  if (!hostProfile) {
    throw new Error("Host fixture is missing a Host Profile.");
  }

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

  it("renders common metric domains without collector capability objects", async () => {
    const html = await renderHostMetricSlotGrid(host);

    expect(html).toContain("CPU");
    expect(html).toContain("内存");
    expect(html).toContain("网络");
    expect(html).toContain("磁盘与 I/O");
  });

  it("keeps metric card slots stable with first-frame skeletons", async () => {
    const html = await renderHostMetricSlotGrid({
      ...host,
      collectorCapabilities: null,
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
        collectorCapabilities: null,
        hostProfile: {
          ...hostProfile,
          cpuCount: 4,
          memoryTotalBytes: 200 * 1024 * 1024,
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
    expect(html).toContain("Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz / 4 核心");
    expect(html).toContain("RAM 总量");
    expect(html).toContain("200 MB");
    expect(html).toContain("eth0");
    expect(html).toContain("挂载点");
    expect(html).not.toContain("正在加载指标");
  });

  it("uses latest-known Disk Health data even when current data is absent", async () => {
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
          role: null,
          serialNumber: "S6PTEST",
          temperatureCelsius: 31,
          totalBytes: null,
          usageMountPoint: null,
          usedBytes: null,
        },
      ],
    };
    const supportedHost = {
      ...host,
      collectorCapabilities: {
        official: {
          diskHealth: { diagnostic: "", status: 1 },
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

    const latestKnownHtml = await renderHostMetricSlotGrid(supportedHost, {
      latestMetric: sample,
      latestSample: sample,
      samples: [latestMetric, sample],
    });
    expect(latestKnownHtml).toContain("硬盘健康");
    expect(latestKnownHtml).toContain("Samsung SSD 870 EVO 1TB");
  });

  it("explains missing Disk Health tool and insufficient local privilege", async () => {
    const missingToolHtml = await renderHostMetricSlotGrid(
      {
        ...host,
        collectorCapabilities: {
          official: {
            diskHealth: { diagnostic: "smartctl is not installed", status: 2 },
          },
        },
      },
      {},
    );
    expect(missingToolHtml).toContain("硬盘健康");
    expect(missingToolHtml).toContain("未安装 smartctl");

    const insufficientPrivilegeHtml = await renderHostMetricSlotGrid(
      {
        ...host,
        collectorCapabilities: {
          official: {
            diskHealth: {
              diagnostic: "sudo rejected privileged helper execution",
              status: 3,
            },
          },
        },
      },
      {},
    );
    expect(insufficientPrivilegeHtml).toContain("本地权限不足");
    expect(insufficientPrivilegeHtml).toContain(
      "sudo rejected privileged helper execution",
    );
  });

  it("shows Disk Health latest-known data when capability is absent", async () => {
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
        collectorCapabilities: null,
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
              role: null,
              serialNumber: "S6PTEST",
              temperatureCelsius: 31,
              totalBytes: null,
              usageMountPoint: null,
              usedBytes: null,
            },
          ],
        },
        latestSample: sample,
        samples: [sample],
      },
    );

    expect(html).toContain("硬盘健康");
    expect(html).toContain("Samsung SSD 870 EVO 1TB");
    expect(html).toContain("挂载点");
  });

  it("shows Disk Health current-sample data when capability is absent", async () => {
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
          role: null,
          serialNumber: "S6PTEST",
          temperatureCelsius: 31,
          totalBytes: null,
          usageMountPoint: null,
          usedBytes: null,
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
        collectorCapabilities: null,
      },
      {
        latestMetric: sample,
        latestSample: sample,
        samples: [sample],
      },
    );

    expect(html).toContain("硬盘健康");
    expect(html).toContain("Samsung SSD 870 EVO 1TB");
    expect(html).toContain("挂载点");
  });

  it("uses latest non-empty Disk Health sample when the latest metric is sparse", async () => {
    const sparseSample: HostMetricSample = {
      collectedAtMs: 1_725_000_005_000,
      cpuCores: [],
      cpuPercent: 30,
      diskHealth: [],
      diskTotalBytes: 100,
      diskUsedBytes: 60,
      disks: [],
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
    const diskHealthSample: HostMetricSample = {
      ...sparseSample,
      collectedAtMs: 1_725_000_000_000,
      diskHealth: [
        {
          deviceName: "/dev/sda",
          model: "Samsung SSD 870 EVO 1TB",
          passed: true,
          powerOnHours: 12_345,
          role: "Data",
          serialNumber: "S6PTEST",
          temperatureCelsius: 31,
          totalBytes: 100 * 1024 ** 3,
          usageMountPoint: "/mnt/disk1",
          usedBytes: 40 * 1024 ** 3,
        },
      ],
      sequence: 1,
    };
    const html = await renderHostMetricSlotGrid(
      {
        ...host,
        collectorCapabilities: {
          official: {
            diskHealth: { diagnostic: "", status: 1 },
          },
        },
      },
      {
        latestMetric: sparseSample,
        latestSample: sparseSample,
        samples: [diskHealthSample, sparseSample],
      },
    );

    expect(html).toContain("硬盘健康");
    expect(html).toContain("Samsung SSD 870 EVO 1TB");
    expect(html).toContain("Data / /mnt/disk1");
    expect(html).toContain("40 GB / 100 GB");
    expect(html).toContain("col-span-12");
    expect(html).not.toContain("等待硬盘健康数据");
  });
});
