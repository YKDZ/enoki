<script setup lang="ts">
import { formatBitsPerSecond } from "@/lib/format";

import MetricPanel from "../MetricPanel.vue";
import MetricsChart from "../MetricsChart.vue";
import NetworkDetails from "../NetworkDetails.vue";
import { panelStorageKey } from "./card-utils";
import MetricCardLoading from "./MetricCardLoading.vue";
import type { NetworkMetricCardProps } from "./types";

defineProps<NetworkMetricCardProps>();
</script>

<template>
  <MetricPanel
    title="网络"
    description="公网接口吞吐"
    size="lg"
    height="normal"
    :storage-key="panelStorageKey(data.hostId, 'network')"
    collapsible
  >
    <template v-if="data.latestSample" #chart>
      <MetricsChart
        :series="data.chartData.aggregate"
        title="吞吐量"
        :x-axis-max-ms="data.xAxisMaxMs"
        :x-axis-min-ms="data.xAxisMinMs"
        :x-axis-start-continuity-gap-ms="data.chartStartContinuityGapMs"
        y-axis-name="b/s"
        :value-formatter="formatBitsPerSecond"
      />
    </template>
    <NetworkDetails
      v-if="data.latestSample"
      :latest-metric="data.latestMetric"
      :latest-sample="data.latestSample"
      :samples="data.samples"
    />
    <MetricCardLoading v-else />
  </MetricPanel>
</template>
