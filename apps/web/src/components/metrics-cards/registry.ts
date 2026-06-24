import type { Component } from "vue";

import type { HostMetricSample } from "@/types";

import type { CollectorAvailability, CollectorCapabilities } from "../../types";
import CpuMetricsCard from "./CpuMetricsCard.vue";
import DiskHealthMetricsCard from "./DiskHealthMetricsCard.vue";
import DiskMetricsCard from "./DiskMetricsCard.vue";
import MemoryMetricsCard from "./MemoryMetricsCard.vue";
import NetworkMetricsCard from "./NetworkMetricsCard.vue";
import type {
  CpuMetricCardData,
  CpuMetricCardProps,
  DiskHealthMetricCardData,
  DiskHealthMetricCardProps,
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
  { component: DiskHealthMetricsCard, domain: "diskHealth" },
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
        hostId: data.hostFacts.id,
        latestSample: data.latestSample,
        xAxisMaxMs: data.xAxisMaxMs,
        xAxisMinMs: data.xAxisMinMs,
      });
    case "diskHealth":
      return diskHealthMetricCardProps(capability, {
        hostId: data.hostFacts.id,
        latestDiskHealth: latestKnownDiskHealth(data),
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

export function diskHealthMetricCardProps(
  capability: CollectorAvailability | undefined,
  data: DiskHealthMetricCardData,
): DiskHealthMetricCardProps | null {
  if (capability?.available !== true) {
    return null;
  }
  return {
    capability,
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

function latestKnownDiskHealth(
  data: OfficialMetricCardSourceData,
): NonNullable<HostMetricSample["diskHealth"]> | null {
  if (data.latestMetric?.diskHealth?.length) {
    return data.latestMetric.diskHealth;
  }

  return latestNonEmptyMetricArray(data.samples, "diskHealth");
}

function latestNonEmptyMetricArray<Key extends keyof HostMetricSample>(
  samples: HostMetricSample[],
  key: Key,
): Extract<NonNullable<HostMetricSample[Key]>, unknown[]> | null {
  for (const sample of [...samples].reverse()) {
    const value = sample[key];

    if (Array.isArray(value) && value.length > 0) {
      return value as Extract<NonNullable<HostMetricSample[Key]>, unknown[]>;
    }
  }

  return null;
}
