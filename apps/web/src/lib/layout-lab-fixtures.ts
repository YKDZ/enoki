import { buildMetricsChartData } from "@/lib/metrics-chart-data";

import type { HostDetail, HostMetricSample } from "../types";

const nowMs = 1_725_000_000_000;

export function createLayoutLabFixture(kind: "dense" | "sparse" = "dense") {
  const host: HostDetail = {
    clockSkew: {
      detected: false,
      lastDeltaMs: null,
    },
    collectorCapabilities: null,
    connectAddress:
      kind === "dense"
        ? "203.0.113.10 / 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
        : "10.0.0.10",
    cpu: "24 cores",
    cpuModel:
      kind === "dense"
        ? "AMD Ryzen 9 7900X 12-Core Processor with a deliberately long suffix"
        : "AMD Ryzen 9 7900X",
    description:
      kind === "dense"
        ? "这是一段较长的主机描述，用于验证标题区域在窄屏和宽屏下都能自然换行，不会挤压工具栏，也不会制造水平滚动。"
        : "",
    displayName:
      kind === "dense"
        ? "生产数据库主机 - 极长显示名称用于验证标题换行能力"
        : "测试主机",
    hostMetadata: {
      connectAddress: "203.0.113.10",
      description: "",
      displayName: "测试主机",
      observedIp: null,
    },
    id: kind === "dense" ? 9_001 : 9_002,
    inventory: {
      architecture: "x86_64",
      cpuBaseFrequencyMhz: 4_700,
      cpuCacheL3Bytes: 67_108_864,
      cpuCount: kind === "dense" ? 24 : 4,
      cpuModel:
        kind === "dense"
          ? "AMD Ryzen 9 7900X 12-Core Processor with a deliberately long suffix"
          : "AMD Ryzen 9 7900X",
      cpuPhysicalCount: 1,
      cpuSocketCount: 1,
      hostname:
        kind === "dense"
          ? "enoki-production-database-primary-long-hostname"
          : "enoki-test",
      kernel: "6.8.0-124-generic",
      memoryTotalBytes: "66437775360",
      os: "Debian GNU/Linux 12 (bookworm)",
      processCount: 286,
      threadCount: 4255,
    },
    lastReportAtMs: nowMs,
    latestMetrics: null,
    memory: "61.9 GiB",
    probeConfiguration: {
      configuration: {
        collectCpu: true,
        collectDisk: true,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: true,
        collectUptime: true,
        metricsCollectionIntervalSeconds: 1,
        reportingBatchIntervalSeconds: 3,
        version: "fixture-v1",
      },
      mode: "inherit",
      version: "fixture-v1",
    },
    probeUpgradeEligibility: {
      currentProbeAssetSetVersion: null,
      currentProbeVersion: "0.1.33",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_version_current",
    },
    probeUpgradeStatus: null,
    probeVersion: "0.1.33",
    status: "online",
    system: "Debian GNU/Linux 12",
    warnings: [],
  };
  const samples = createSamples(kind);

  return {
    chartData: buildMetricsChartData(samples),
    chartStartContinuityGapMs: 4_000,
    host,
    latestMetric: samples.at(-1) ?? null,
    latestSample: samples.at(-1) ?? null,
    samples,
    xAxisMaxMs: nowMs,
    xAxisMinMs: nowMs - 60_000,
  };
}

function createSamples(kind: "dense" | "sparse") {
  const coreCount = kind === "dense" ? 24 : 4;
  const diskCount = kind === "dense" ? 10 : 2;
  const networkCount = kind === "dense" ? 8 : 2;

  return Array.from({ length: kind === "dense" ? 60 : 12 }, (_, index) => {
    const timestampMs = nowMs - (59 - index) * 1_000;
    const cpuCores = Array.from(
      { length: coreCount },
      (_unused, coreIndex) => ({
        name: `cpu${coreIndex}`,
        usagePercent: boundedPercent(
          30 + Math.sin((index + coreIndex) / 5) * 25 + (coreIndex % 4) * 5,
        ),
      }),
    );
    const disks = Array.from({ length: diskCount }, (_unused, diskIndex) => ({
      availableBytes: 1_000_000_000 * (diskIndex + 1),
      filesystemType: diskIndex % 2 === 0 ? "ext4" : "xfs",
      ioUtilizationPercent: boundedPercent(10 + diskIndex * 6),
      mountPoint:
        diskIndex === 0
          ? "/"
          : `/mnt/data/${diskIndex}/very-long-mount-name-for-layout-check`,
      readAwaitMs: 0.5 + diskIndex,
      readBytesDelta: 1_024 * 1024 * (diskIndex + 1),
      totalBytes: 20_000_000_000 * (diskIndex + 1),
      usedBytes: 8_000_000_000 * (diskIndex + 1),
      weightedIoPercent: boundedPercent(8 + diskIndex * 4),
      writeAwaitMs: 0.8 + diskIndex,
      writeBytesDelta: 2_048 * 1024 * (diskIndex + 1),
    }));
    const networkInterfaces = Array.from(
      { length: networkCount },
      (_unused, networkIndex) => ({
        name:
          networkIndex === 0
            ? "eth0"
            : `enp${networkIndex}s0-very-long-interface-name`,
        rxBitsPerSecond: 50_000 * (networkIndex + 1) + index * 300,
        rxBytesDelta: 7_000 * (networkIndex + 1),
        txBitsPerSecond: 30_000 * (networkIndex + 1) + index * 200,
        txBytesDelta: 4_000 * (networkIndex + 1),
      }),
    );
    const networkRxBitsPerSecond = networkInterfaces.reduce(
      (total, networkInterface) =>
        total + (networkInterface.rxBitsPerSecond ?? 0),
      0,
    );
    const networkTxBitsPerSecond = networkInterfaces.reduce(
      (total, networkInterface) =>
        total + (networkInterface.txBitsPerSecond ?? 0),
      0,
    );

    return {
      batteryPercent: null,
      batteryState: null,
      collectedAtMs: timestampMs,
      cpuCores,
      cpuIdlePercent: 40,
      cpuIowaitPercent: 2,
      cpuPercent: boundedPercent(45 + Math.sin(index / 4) * 20),
      cpuStealPercent: 0,
      cpuSystemPercent: 12,
      cpuUserPercent: 46,
      diskTotalBytes: disks.reduce((total, disk) => total + disk.totalBytes, 0),
      diskUsedBytes: disks.reduce((total, disk) => total + disk.usedBytes, 0),
      disks,
      memoryCacheBytes: 6_000_000_000,
      memoryTotalBytes: 66_437_775_360,
      memoryUsedBytes: 28_000_000_000 + index * 10_000_000,
      networkInterfaces,
      networkRxBitsPerSecond,
      networkRxBytesDelta: networkInterfaces.reduce(
        (total, networkInterface) => total + networkInterface.rxBytesDelta,
        0,
      ),
      networkTxBitsPerSecond,
      networkTxBytesDelta: networkInterfaces.reduce(
        (total, networkInterface) => total + networkInterface.txBytesDelta,
        0,
      ),
      receivedAtMs: timestampMs + 100,
      sequence: index + 1,
      swapTotalBytes: 8_000_000_000,
      swapUsedBytes: 1_500_000_000,
      temperatureCelsius: 47.5,
      uptimeSeconds: 360_000 + index,
    } satisfies HostMetricSample;
  });
}

function boundedPercent(value: number) {
  return Math.max(0, Math.min(100, value));
}
