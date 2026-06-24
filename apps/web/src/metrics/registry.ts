import type { Component } from "vue";

import type { HostMetricSample } from "@/types";

import type { CollectorAvailability, CollectorCapabilities } from "../types";
import CpuMetricsCard from "./cpu/Card.vue";
import DiskHealthMetricsCard from "./disk-health/Card.vue";
import DiskMetricsCard from "./disk/Card.vue";
import MemoryMetricsCard from "./memory/Card.vue";
import NetworkMetricsCard from "./network/Card.vue";
import { officialMetricCardDomains } from "./view-model";
import type {
  CpuMetricCardProps,
  CpuMetricCardViewModel,
  DiskHealthMetricCardProps,
  DiskHealthMetricCardViewModel,
  DiskMetricCardProps,
  DiskMetricCardViewModel,
  MemoryMetricCardProps,
  MemoryMetricCardViewModel,
  NetworkMetricCardProps,
  NetworkMetricCardViewModel,
  OfficialMetricCardProps,
  OfficialMetricCardDomain,
  OfficialMetricCardSourceViewModel,
} from "./view-model";

type OfficialMetricsCardDefinition = {
  component: Component;
  domain: OfficialMetricCardDomain;
};

const officialMetricCardComponents = {
  cpu: CpuMetricsCard,
  disk: DiskMetricsCard,
  diskHealth: DiskHealthMetricsCard,
  memory: MemoryMetricsCard,
  network: NetworkMetricsCard,
} satisfies Record<OfficialMetricCardDomain, Component>;

export const officialMetricsCards: OfficialMetricsCardDefinition[] =
  officialMetricCardDomains.map((domain) => ({
    component: officialMetricCardComponents[domain],
    domain,
  }));

export function officialMetricCardProps(
  domain: OfficialMetricCardDomain,
  capabilities: CollectorCapabilities | null,
  data: OfficialMetricCardSourceViewModel,
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
        hostProfile: data.hostFacts.hostProfile,
        hostId: data.hostFacts.id,
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
  data: CpuMetricCardViewModel,
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
  data: DiskMetricCardViewModel,
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
  data: DiskHealthMetricCardViewModel,
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
  data: MemoryMetricCardViewModel,
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
  data: NetworkMetricCardViewModel,
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
  domain: OfficialMetricCardDomain,
): CollectorAvailability | undefined {
  return capabilities?.official?.[domain];
}

function latestKnownDiskHealth(
  data: OfficialMetricCardSourceViewModel,
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
