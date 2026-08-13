import { describe, expect, it } from "vitest";

import type { HostMetricSample } from "../types";
import {
  buildMetricsChartData,
  extendSeriesToWindowStart,
  linePointsForWindow,
  type MetricSeries,
} from "./chart-data";

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

  it("extends display series only across a continuous start gap", () => {
    expect(
      extendSeriesToWindowStart(
        {
          name: "使用率",
          points: [
            [1_725_000_005_000, 40],
            [1_725_000_010_000, 45],
          ],
        },
        1_725_000_000_000,
        6_000,
      ),
    ).toEqual({
      name: "使用率",
      points: [
        [1_725_000_000_000, 40],
        [1_725_000_005_000, 40],
        [1_725_000_010_000, 45],
      ],
    });
  });

  it("leaves the chart start empty when the first point is after a missing-data gap", () => {
    const series: MetricSeries = {
      name: "使用率",
      points: [
        [1_725_000_030_000, 0],
        [1_725_000_035_000, 45],
      ],
    };

    expect(extendSeriesToWindowStart(series, 1_725_000_000_000, 10_000)).toBe(
      series,
    );
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

  it("returns windowed line points without filling missing-data gaps", () => {
    expect(
      linePointsForWindow(
        [
          [1_725_000_000_000, 10],
          [1_725_000_030_000, 20],
          [1_725_000_035_000, 30],
        ],
        {
          maxStartGapMs: 9_000,
          windowEndMs: 1_725_000_040_000,
          windowStartMs: 1_725_000_020_000,
        },
      ),
    ).toEqual([
      [1_725_000_030_000, 20],
      [1_725_000_035_000, 30],
    ]);
  });

  it("fills the line window start across a continuous sampling gap", () => {
    expect(
      linePointsForWindow(
        [
          [1_725_000_022_000, 20],
          [1_725_000_025_000, 30],
        ],
        {
          maxStartGapMs: 3_000,
          windowEndMs: 1_725_000_030_000,
          windowStartMs: 1_725_000_020_000,
        },
      ),
    ).toEqual([
      [1_725_000_020_000, 20],
      [1_725_000_022_000, 20],
      [1_725_000_025_000, 30],
    ]);
  });

  it("clips a sparkline to its inclusive window boundaries without changing in-window values", () => {
    expect(
      linePointsForWindow(
        [
          [0, 11],
          [10, 22],
          [20, 33],
          [30, 44],
          [40, 55],
        ],
        { windowEndMs: 30, windowStartMs: 10 },
      ),
    ).toEqual([
      [10, 22],
      [20, 33],
      [30, 44],
    ]);
  });

  it("keeps repeated sample times and their values in a sparkline window", () => {
    expect(
      linePointsForWindow(
        [
          [10, 10],
          [20, 95],
          [20, 5],
          [30, 50],
        ],
        { windowEndMs: 30, windowStartMs: 10 },
      ),
    ).toEqual([
      [10, 10],
      [20, 95],
      [20, 5],
      [30, 50],
    ]);
  });

  it("keeps sparse sparkline data sparse when its start gap is not continuous", () => {
    expect(
      linePointsForWindow(
        [
          [10, 20],
          [50, 80],
        ],
        { maxStartGapMs: 5, windowEndMs: 60, windowStartMs: 0 },
      ),
    ).toEqual([
      [10, 20],
      [50, 80],
    ]);
  });
});
