<script setup lang="ts">
import { formatBitsPerSecond } from "@/lib/format";

import MetricCardLoading from "../shared/MetricCardLoading.vue";
import MetricPanel from "../shared/MetricPanel.vue";
import MetricsChart from "../shared/MetricsChart.vue";
import { panelStorageKey } from "../shared/panel-storage";
import type { NetworkMetricCardProps } from "../view-model";
import NetworkDetails from "./Details.vue";

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
