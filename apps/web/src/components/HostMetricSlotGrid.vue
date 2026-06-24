<script setup lang="ts">
import { computed } from "vue";

import type { MetricsChartData } from "@/lib/metrics-chart-data";

import type { HostDetail, HostMetricSample } from "../types";
import {
  officialMetricCardProps,
  officialMetricsCards,
} from "./metrics-cards/registry";

const props = defineProps<{
  chartData: MetricsChartData;
  chartStartContinuityGapMs: number;
  host: HostDetail;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  latestSample: HostMetricSample | null;
  samples: HostMetricSample[];
  xAxisMaxMs: number;
  xAxisMinMs: number;
}>();

const metricsData = computed(() => ({
  chartData: props.chartData,
  chartStartContinuityGapMs: props.chartStartContinuityGapMs,
  hostFacts: {
    cpuModel: props.host.cpuModel,
    hostProfile: props.host.hostProfile,
    id: props.host.id,
  },
  latestMetric: props.latestMetric,
  latestSample: props.latestSample,
  samples: props.samples,
  xAxisMaxMs: props.xAxisMaxMs,
  xAxisMinMs: props.xAxisMinMs,
}));

const visibleMetricCards = computed(() =>
  officialMetricsCards.flatMap((card) => {
    const cardProps = officialMetricCardProps(
      card.domain,
      props.host.collectorCapabilities,
      metricsData.value,
    );

    return cardProps ? [{ ...card, props: cardProps }] : [];
  }),
);
</script>

<template>
  <div class="grid grid-cols-12 gap-4" data-layout-grid>
    <component
      :is="card.component"
      v-for="card in visibleMetricCards"
      :key="card.domain"
      v-bind="card.props"
      data-layout-card
      :data-panel-id="card.domain"
    />
  </div>
</template>
