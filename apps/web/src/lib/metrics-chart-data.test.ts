import { describe, expect, it } from "vitest";

import type { HostMetricSample } from "../types";
import {
  buildMetricsChartData,
  extendSeriesToWindowStart,
  type MetricSeries,
} from "./metrics-chart-data";

const samples: HostMetricSample[] = [
  {
    collectedAtMs: 1_725_000_000_000,
    cpuCores: [
      {
        name: "cpu0",
        usagePercent: 20,
      },
      {
        name: "cpu1",
        usagePercent: 40,
      },
    ],
    cpuPercent: 30,
    diskTotalBytes: 100,
    diskUsedBytes: 50,
    disks: [
      {
        availableBytes: 50,
        filesystemType: "ext4",
        mountPoint: "/",
        totalBytes: 100,
        usedBytes: 50,
      },
    ],
    memoryTotalBytes: 200,
    memoryUsedBytes: 100,
    networkInterfaces: [
      {
        name: "eth0",
        rxBitsPerSecond: 800,
        rxBytesDelta: 500,
        txBitsPerSecond: 400,
        txBytesDelta: 250,
      },
    ],
    networkRxBitsPerSecond: 800,
    networkRxBytesDelta: 500,
    networkTxBitsPerSecond: 400,
    networkTxBytesDelta: 250,
    receivedAtMs: 1_725_000_000_500,
    sequence: 1,
    uptimeSeconds: 100,
  },
];

describe("Metrics chart data", () => {
  it("builds aggregate defaults and per-entity detail series from Unix-ms samples", () => {
    const chartData = buildMetricsChartData(samples);

    expect(chartData.cpu.aggregate).toEqual({
      name: "使用率",
      points: [[1_725_000_000_000, 30]],
    });
    expect(chartData.cpu.cores).toEqual([
      {
        name: "cpu0",
        points: [[1_725_000_000_000, 20]],
      },
      {
        name: "cpu1",
        points: [[1_725_000_000_000, 40]],
      },
    ]);
    expect(chartData.memory.usedPercent).toEqual({
      name: "使用率",
      points: [[1_725_000_000_000, 50]],
    });
    expect(chartData.disk.aggregateUsedPercent).toEqual({
      name: "使用率",
      points: [[1_725_000_000_000, 50]],
    });
    expect(chartData.disk.mounts).toEqual([
      {
        name: "/",
        points: [[1_725_000_000_000, 50]],
      },
    ]);
    expect(chartData.network.aggregate).toEqual([
      {
        name: "接收",
        points: [[1_725_000_000_000, 800]],
      },
      {
        name: "发送",
        points: [[1_725_000_000_000, 400]],
      },
    ]);
    expect(chartData.network.interfaces).toEqual([
      {
        name: "eth0 接收",
        points: [[1_725_000_000_000, 800]],
      },
      {
        name: "eth0 发送",
        points: [[1_725_000_000_000, 400]],
      },
    ]);
  });

  it("extends display series to the chart window start using the first known value", () => {
    expect(
      extendSeriesToWindowStart(
        {
          name: "使用率",
          points: [
            [1_725_000_030_000, 40],
            [1_725_000_035_000, 45],
          ],
        },
        1_725_000_000_000,
      ),
    ).toEqual({
      name: "使用率",
      points: [
        [1_725_000_000_000, 40],
        [1_725_000_030_000, 40],
        [1_725_000_035_000, 45],
      ],
    });
  });

  it("keeps display series unchanged when they already reach the window start", () => {
    const series: MetricSeries = {
      name: "使用率",
      points: [
        [1_725_000_000_000, 40],
        [1_725_000_035_000, 45],
      ],
    };

    expect(extendSeriesToWindowStart(series, 1_725_000_000_000)).toBe(series);
  });
});
