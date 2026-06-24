<script setup lang="ts">
import { formatPercent } from "@/lib/format";

import MemoryDetails from "../MemoryDetails.vue";
import MetricPanel from "../MetricPanel.vue";
import MetricsChart from "../MetricsChart.vue";
import { panelStorageKey } from "./card-utils";
import MetricCardLoading from "./MetricCardLoading.vue";
import type { MemoryMetricCardProps } from "./types";

defineProps<MemoryMetricCardProps>();
</script>

<template>
  <MetricPanel
    title="内存"
    description="使用量、缓存与交换"
    size="lg"
    height="normal"
    :storage-key="panelStorageKey(data.hostId, 'memory')"
    collapsible
  >
    <template v-if="data.latestMetric" #chart>
      <MetricsChart
        :series="[data.chartData.usedPercent]"
        title="内存"
        :x-axis-max-ms="data.xAxisMaxMs"
        :x-axis-min-ms="data.xAxisMinMs"
        :x-axis-start-continuity-gap-ms="data.chartStartContinuityGapMs"
        :y-axis-max="100"
        :y-axis-min="0"
        y-axis-name="%"
        :value-formatter="formatPercent"
      />
    </template>
    <MemoryDetails
      v-if="data.latestMetric"
      :host-profile="data.hostProfile"
      :latest-metric="data.latestMetric"
    />
    <MetricCardLoading v-else />
  </MetricPanel>
</template>
