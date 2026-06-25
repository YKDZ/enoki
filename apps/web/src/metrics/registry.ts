import type { Component } from "vue";

import type { HostMetricSample } from "@/types";

import type {
  CollectorCapabilities,
  DiskHealthCollectorCapability,
} from "../types";
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
  capability: OfficialMetricCardCapability,
  data: OfficialMetricCardSourceViewModel,
): OfficialMetricCardProps {
  switch (domain) {
    case "cpu":
      return cpuMetricCardProps({
        chartData: data.chartData.cpu,
        chartStartContinuityGapMs: data.chartStartContinuityGapMs,
        hostFacts: data.hostFacts,
        latestSample: data.latestSample,
      });
    case "disk":
      return diskMetricCardProps({
        chartData: data.chartData.disk,
        chartStartContinuityGapMs: data.chartStartContinuityGapMs,
        hostId: data.hostFacts.id,
        latestSample: data.latestSample,
        xAxisMaxMs: data.xAxisMaxMs,
        xAxisMinMs: data.xAxisMinMs,
      });
    case "diskHealth":
      return diskHealthMetricCardProps(capability.diskHealth, {
        hostId: data.hostFacts.id,
        latestDiskHealth: latestKnownDiskHealth(data),
      });
    case "memory":
      return memoryMetricCardProps({
        chartData: data.chartData.memory,
        chartStartContinuityGapMs: data.chartStartContinuityGapMs,
        hostProfile: data.hostFacts.hostProfile,
        hostId: data.hostFacts.id,
        latestMetric: data.latestMetric,
        xAxisMaxMs: data.xAxisMaxMs,
        xAxisMinMs: data.xAxisMinMs,
      });
    case "network":
      return networkMetricCardProps({
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

type OfficialMetricCardCapability = {
  diskHealth?: DiskHealthCollectorCapability;
};

export function officialMetricCardCapability(
  domain: OfficialMetricCardDomain,
  capabilities: CollectorCapabilities | null,
): OfficialMetricCardCapability {
  switch (domain) {
    case "diskHealth":
      return { diskHealth: capabilities?.official?.diskHealth };
    case "cpu":
    case "disk":
    case "memory":
    case "network":
      return {};
  }
}

export function cpuMetricCardProps(
  data: CpuMetricCardViewModel,
): CpuMetricCardProps {
  return {
    data,
  };
}

export function diskMetricCardProps(
  data: DiskMetricCardViewModel,
): DiskMetricCardProps {
  return {
    data,
  };
}

export function diskHealthMetricCardProps(
  capability: DiskHealthCollectorCapability | undefined,
  data: DiskHealthMetricCardViewModel,
): DiskHealthMetricCardProps {
  return {
    capability: capability ?? { diagnostic: "", status: 0 },
    data,
  };
}

export function memoryMetricCardProps(
  data: MemoryMetricCardViewModel,
): MemoryMetricCardProps {
  return {
    data,
  };
}

export function networkMetricCardProps(
  data: NetworkMetricCardViewModel,
): NetworkMetricCardProps {
  return {
    data,
  };
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
