import type { HostMetricSample } from "../types";

export type ChartPoint = [number, number];

export type MetricSeries = {
  name: string;
  points: ChartPoint[];
};

export type MetricsChartData = {
  cpu: {
    aggregate: MetricSeries;
    cores: MetricSeries[];
  };
  disk: {
    aggregateUsedPercent: MetricSeries;
    mounts: MetricSeries[];
  };
  memory: {
    usedPercent: MetricSeries;
  };
  network: {
    aggregate: MetricSeries[];
    interfaces: MetricSeries[];
  };
};

export function buildMetricsChartData(
  samples: HostMetricSample[],
): MetricsChartData {
  return {
    cpu: {
      aggregate: {
        name: "使用率",
        points: valuePoints(samples, (sample) => sample.cpuPercent),
      },
      cores: entityPercentSeries(
        samples,
        (sample) => sample.cpuCores,
        (core) => core.name,
        (core) => core.usagePercent,
      ),
    },
    disk: {
      aggregateUsedPercent: {
        name: "使用率",
        points: valuePoints(samples, (sample) =>
          percent(sample.diskUsedBytes, sample.diskTotalBytes),
        ),
      },
      mounts: entityPercentSeries(
        samples,
        (sample) => sample.disks,
        (disk) => disk.mountPoint,
        (disk) => percent(disk.usedBytes, disk.totalBytes),
      ),
    },
    memory: {
      usedPercent: {
        name: "使用率",
        points: valuePoints(samples, (sample) =>
          percent(sample.memoryUsedBytes, sample.memoryTotalBytes),
        ),
      },
    },
    network: {
      aggregate: [
        {
          name: "接收",
          points: valuePoints(
            samples,
            (sample) => sample.networkRxBitsPerSecond,
          ),
        },
        {
          name: "发送",
          points: valuePoints(
            samples,
            (sample) => sample.networkTxBitsPerSecond,
          ),
        },
      ],
      interfaces: [
        ...entityPercentSeries(
          samples,
          (sample) => sample.networkInterfaces,
          (networkInterface) => `${networkInterface.name} 接收`,
          (networkInterface) => networkInterface.rxBitsPerSecond,
        ),
        ...entityPercentSeries(
          samples,
          (sample) => sample.networkInterfaces,
          (networkInterface) => `${networkInterface.name} 发送`,
          (networkInterface) => networkInterface.txBitsPerSecond,
        ),
      ],
    },
  };
}

export function extendSeriesToWindowStart(
  series: MetricSeries,
  windowStartMs: number | null | undefined,
  maxGapMs = Number.POSITIVE_INFINITY,
): MetricSeries {
  const hasValidMaxGap =
    maxGapMs === Number.POSITIVE_INFINITY || Number.isFinite(maxGapMs);

  if (
    typeof windowStartMs !== "number" ||
    !Number.isFinite(windowStartMs) ||
    !hasValidMaxGap ||
    series.points.length === 0
  ) {
    return series;
  }

  const [firstTime, firstValue] = series.points[0] as ChartPoint;
  if (firstTime <= windowStartMs || firstTime - windowStartMs > maxGapMs) {
    return series;
  }

  return {
    ...series,
    points: [[windowStartMs, firstValue], ...series.points],
  };
}

export function extendSeriesListToWindowStart(
  series: MetricSeries[],
  windowStartMs: number | null | undefined,
  maxGapMs?: number,
): MetricSeries[] {
  return series.map((item) =>
    extendSeriesToWindowStart(item, windowStartMs, maxGapMs),
  );
}

export function linePointsForWindow(
  points: ChartPoint[],
  options: {
    maxStartGapMs?: number;
    maxVisiblePoints?: number;
    windowEndMs: number;
    windowStartMs: number;
  },
): ChartPoint[] {
  const visiblePoints = points.filter(
    ([time]) => time >= options.windowStartMs && time <= options.windowEndMs,
  );
  const firstPoint = visiblePoints[0];
  const maxStartGapMs = options.maxStartGapMs ?? Number.POSITIVE_INFINITY;
  const continuousPoints =
    firstPoint &&
    firstPoint[0] > options.windowStartMs &&
    firstPoint[0] - options.windowStartMs <= maxStartGapMs
      ? [[options.windowStartMs, firstPoint[1]] as ChartPoint, ...visiblePoints]
      : visiblePoints;

  return sampled(continuousPoints, options.maxVisiblePoints ?? 240);
}

function valuePoints(
  samples: HostMetricSample[],
  valueForSample: (sample: HostMetricSample) => number | null,
): ChartPoint[] {
  return samples.flatMap((sample) => {
    const value = valueForSample(sample);

    return value === null ? [] : [[sample.collectedAtMs, value] as ChartPoint];
  });
}

function entityPercentSeries<TEntity>(
  samples: HostMetricSample[],
  entitiesForSample: (sample: HostMetricSample) => TEntity[],
  nameForEntity: (entity: TEntity) => string,
  valueForEntity: (entity: TEntity) => number | null,
): MetricSeries[] {
  const seriesByName = new Map<string, ChartPoint[]>();

  for (const sample of samples) {
    for (const entity of entitiesForSample(sample)) {
      const value = valueForEntity(entity);

      if (value === null) {
        continue;
      }

      const name = nameForEntity(entity);
      const points = seriesByName.get(name) ?? [];
      points.push([sample.collectedAtMs, value]);
      seriesByName.set(name, points);
    }
  }

  return [...seriesByName.entries()].map(([name, points]) => ({
    name,
    points,
  }));
}

function percent(used: number | null, total: number | null) {
  if (used === null || total === null || total <= 0) {
    return null;
  }

  return (used / total) * 100;
}

function sampled<T>(items: T[], maxItems: number) {
  if (items.length <= maxItems) {
    return items;
  }

  const step = (items.length - 1) / (maxItems - 1);

  return Array.from(
    { length: maxItems },
    (_, index) => items[Math.round(index * step)] as T,
  );
}
