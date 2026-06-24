import type { MetricsChartData } from "@/lib/metrics-chart-data";

import type {
  CollectorAvailability,
  HostDetail,
  HostMetricSample,
} from "../../types";

export type OfficialMetricDomain =
  | "cpu"
  | "disk"
  | "diskHealth"
  | "memory"
  | "network";

export type MetricCardHostFacts = {
  cpuModel: string | null;
  id: number;
  inventory: Record<string, unknown> | null;
};

export type OfficialMetricCardSourceData = {
  chartData: MetricsChartData;
  chartStartContinuityGapMs: number;
  hostFacts: MetricCardHostFacts;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  latestSample: HostMetricSample | null;
  samples: HostMetricSample[];
  xAxisMaxMs: number;
  xAxisMinMs: number;
};

export type CpuMetricCardData = {
  chartData: MetricsChartData["cpu"];
  chartStartContinuityGapMs: number;
  hostFacts: MetricCardHostFacts;
  latestSample: HostMetricSample | null;
};

export type MemoryMetricCardData = {
  chartData: MetricsChartData["memory"];
  chartStartContinuityGapMs: number;
  hostId: number;
  inventory: Record<string, unknown> | null;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  xAxisMaxMs: number;
  xAxisMinMs: number;
};

export type NetworkMetricCardData = {
  chartData: MetricsChartData["network"];
  chartStartContinuityGapMs: number;
  hostId: number;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  latestSample: HostMetricSample | null;
  samples: HostMetricSample[];
  xAxisMaxMs: number;
  xAxisMinMs: number;
};

export type DiskMetricCardData = {
  chartData: MetricsChartData["disk"];
  chartStartContinuityGapMs: number;
  hostId: number;
  latestSample: HostMetricSample | null;
  xAxisMaxMs: number;
  xAxisMinMs: number;
};

export type DiskHealthMetricCardData = {
  hostId: number;
  latestDiskHealth: NonNullable<HostMetricSample["diskHealth"]> | null;
};

export type MetricCardProps<TData> = {
  capability: CollectorAvailability;
  data: TData;
};

export type CpuMetricCardProps = MetricCardProps<CpuMetricCardData>;
export type MemoryMetricCardProps = MetricCardProps<MemoryMetricCardData>;
export type NetworkMetricCardProps = MetricCardProps<NetworkMetricCardData>;
export type DiskMetricCardProps = MetricCardProps<DiskMetricCardData>;
export type DiskHealthMetricCardProps =
  MetricCardProps<DiskHealthMetricCardData>;

export type OfficialMetricCardProps =
  | CpuMetricCardProps
  | DiskHealthMetricCardProps
  | MemoryMetricCardProps
  | NetworkMetricCardProps
  | DiskMetricCardProps;
