import type { MetricsChartData } from "@/metrics/chart-data";

import type {
  CollectorAvailability,
  CollectorCapabilities,
  HostDetail,
  HostMetricSample,
  HostProfileSnapshot,
} from "../types";

export const officialMetricCardDomains = [
  "cpu",
  "network",
  "memory",
  "disk",
  "diskHealth",
] as const satisfies readonly (keyof NonNullable<
  CollectorCapabilities["official"]
>)[];

export type OfficialMetricCardDomain =
  (typeof officialMetricCardDomains)[number];

export type MetricCardHostViewModel = {
  cpuModel: string | null;
  hostProfile: HostProfileSnapshot | null;
  id: number;
};

export type OfficialMetricCardSourceViewModel = {
  chartData: MetricsChartData;
  chartStartContinuityGapMs: number;
  hostFacts: MetricCardHostViewModel;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  latestSample: HostMetricSample | null;
  samples: HostMetricSample[];
  xAxisMaxMs: number;
  xAxisMinMs: number;
};

export type CpuMetricCardViewModel = {
  chartData: MetricsChartData["cpu"];
  chartStartContinuityGapMs: number;
  hostFacts: MetricCardHostViewModel;
  latestSample: HostMetricSample | null;
};

export type MemoryMetricCardViewModel = {
  chartData: MetricsChartData["memory"];
  chartStartContinuityGapMs: number;
  hostId: number;
  hostProfile: HostProfileSnapshot | null;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  xAxisMaxMs: number;
  xAxisMinMs: number;
};

export type NetworkMetricCardViewModel = {
  chartData: MetricsChartData["network"];
  chartStartContinuityGapMs: number;
  hostId: number;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  latestSample: HostMetricSample | null;
  samples: HostMetricSample[];
  xAxisMaxMs: number;
  xAxisMinMs: number;
};

export type DiskMetricCardViewModel = {
  chartData: MetricsChartData["disk"];
  chartStartContinuityGapMs: number;
  hostId: number;
  latestSample: HostMetricSample | null;
  xAxisMaxMs: number;
  xAxisMinMs: number;
};

export type DiskHealthMetricCardViewModel = {
  hostId: number;
  latestDiskHealth: NonNullable<HostMetricSample["diskHealth"]> | null;
};

export type MetricCardProps<TViewModel> = {
  capability: CollectorAvailability;
  data: TViewModel;
};

export type CpuMetricCardProps = MetricCardProps<CpuMetricCardViewModel>;
export type MemoryMetricCardProps = MetricCardProps<MemoryMetricCardViewModel>;
export type NetworkMetricCardProps =
  MetricCardProps<NetworkMetricCardViewModel>;
export type DiskMetricCardProps = MetricCardProps<DiskMetricCardViewModel>;
export type DiskHealthMetricCardProps =
  MetricCardProps<DiskHealthMetricCardViewModel>;

export type OfficialMetricCardProps =
  | CpuMetricCardProps
  | DiskHealthMetricCardProps
  | MemoryMetricCardProps
  | NetworkMetricCardProps
  | DiskMetricCardProps;
