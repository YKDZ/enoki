import type { Component } from "vue";

import type {
  CollectorAvailability,
  CollectorCapabilities,
  HostMetricSample,
} from "../../types";
import CpuMetricsCard from "./CpuMetricsCard.vue";
import DiskMetricsCard from "./DiskMetricsCard.vue";
import MemoryMetricsCard from "./MemoryMetricsCard.vue";
import NetworkMetricsCard from "./NetworkMetricsCard.vue";
import type {
  CpuMetricCardData,
  CpuMetricCardProps,
  DiskMetricCardData,
  DiskMetricCardProps,
  MemoryMetricCardData,
  MemoryMetricCardProps,
  NetworkMetricCardData,
  NetworkMetricCardProps,
  OfficialMetricCardProps,
  OfficialMetricCardSourceData,
  OfficialMetricDomain,
} from "./types";

type OfficialMetricsCardDefinition = {
  component: Component;
  domain: OfficialMetricDomain;
};

export const officialMetricsCards: OfficialMetricsCardDefinition[] = [
  { component: CpuMetricsCard, domain: "cpu" },
  { component: NetworkMetricsCard, domain: "network" },
  { component: MemoryMetricsCard, domain: "memory" },
  { component: DiskMetricsCard, domain: "disk" },
];

export function officialMetricCardProps(
  domain: OfficialMetricDomain,
  capabilities: CollectorCapabilities | null,
  data: OfficialMetricCardSourceData,
): OfficialMetricCardProps | null {
  const capability = officialMetricCapability(capabilities, domain);

  switch (domain) {
    case "cpu":
      return cpuMetricCardProps(capability, {
        chartData: data.chartData.cpu,
        chartStartContinuityGapMs: data.chartStartContinuityGapMs,
        hostFacts: data.hostFacts,
        latestSample: data.latestSample,
      });
    case "disk":
      return diskMetricCardProps(capability, {
        chartData: data.chartData.disk,
        chartStartContinuityGapMs: data.chartStartContinuityGapMs,
        diskHealthCapability: capabilities?.official?.diskHealth,
        hostId: data.hostFacts.id,
        latestSample: diskLatestSampleWithLatestKnownHealth(
          data.latestSample,
          data.latestMetric,
          capabilities?.official?.diskHealth,
        ),
        xAxisMaxMs: data.xAxisMaxMs,
        xAxisMinMs: data.xAxisMinMs,
      });
    case "memory":
      return memoryMetricCardProps(capability, {
        chartData: data.chartData.memory,
        chartStartContinuityGapMs: data.chartStartContinuityGapMs,
        hostId: data.hostFacts.id,
        inventory: data.hostFacts.inventory,
        latestMetric: data.latestMetric,
        xAxisMaxMs: data.xAxisMaxMs,
        xAxisMinMs: data.xAxisMinMs,
      });
    case "network":
      return networkMetricCardProps(capability, {
        chartData: data.chartData.network,
        chartStartContinuityGapMs: data.chartStartContinuityGapMs,
        hostId: data.hostFacts.id,
        latestMetric: data.latestMetric,
        latestSample: data.latestSample,
        samples: data.samples,
        xAxisMaxMs: data.xAxisMaxMs,
        xAxisMinMs: data.xAxisMinMs,
      });
  }
}

export function cpuMetricCardProps(
  capability: CollectorAvailability | undefined,
  data: CpuMetricCardData,
): CpuMetricCardProps | null {
  if (capability?.available === false) {
    return null;
  }
  return {
    capability: capability ?? { available: true },
    data,
  };
}

export function diskMetricCardProps(
  capability: CollectorAvailability | undefined,
  data: DiskMetricCardData,
): DiskMetricCardProps | null {
  if (capability?.available === false) {
    return null;
  }
  return {
    capability: capability ?? { available: true },
    data,
  };
}

export function memoryMetricCardProps(
  capability: CollectorAvailability | undefined,
  data: MemoryMetricCardData,
): MemoryMetricCardProps | null {
  if (capability?.available === false) {
    return null;
  }
  return {
    capability: capability ?? { available: true },
    data,
  };
}

export function networkMetricCardProps(
  capability: CollectorAvailability | undefined,
  data: NetworkMetricCardData,
): NetworkMetricCardProps | null {
  if (capability?.available === false) {
    return null;
  }
  return {
    capability: capability ?? { available: true },
    data,
  };
}

function officialMetricCapability(
  capabilities: CollectorCapabilities | null,
  domain: OfficialMetricDomain,
): CollectorAvailability | undefined {
  return capabilities?.official?.[domain];
}

function diskLatestSampleWithLatestKnownHealth(
  latestSample: HostMetricSample | null,
  latestMetric: OfficialMetricCardSourceData["latestMetric"],
  diskHealthCapability: CollectorAvailability | undefined,
): HostMetricSample | null {
  if (
    !latestSample ||
    diskHealthCapability?.available !== true ||
    latestSample.diskHealth !== undefined ||
    !latestMetric?.diskHealth
  ) {
    return latestSample;
  }

  return {
    ...latestSample,
    diskHealth: latestMetric.diskHealth,
  };
}
