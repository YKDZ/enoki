<script setup lang="ts">
import { Skeleton } from "@/components/ui/skeleton";
import { formatPercent, formatTrafficBytes } from "@/lib/format";

import MetricPanel from "../shared/MetricPanel.vue";
import MetricsChart from "../shared/MetricsChart.vue";
import { panelStorageKey } from "../shared/panel-storage";
import type { DiskMetricCardProps } from "../view-model";
import DiskDetails from "./Details.vue";

defineProps<DiskMetricCardProps>();
</script>

<template>
  <MetricPanel
    title="磁盘与 I/O"
    size="xl"
    layout="side"
    :storage-key="panelStorageKey(data.hostId, 'disk')"
    collapsible
  >
    <template v-if="data.latestSample" #chart>
      <div class="grid gap-4">
        <MetricsChart
          :series="[data.chartData.aggregateUsedPercent]"
          title="占用率"
          :x-axis-max-ms="data.xAxisMaxMs"
          :x-axis-min-ms="data.xAxisMinMs"
          :x-axis-start-continuity-gap-ms="data.chartStartContinuityGapMs"
          :y-axis-max="100"
          :y-axis-min="0"
          y-axis-name="%"
          :value-formatter="formatPercent"
        />
        <MetricsChart
          :series="data.chartData.aggregateIoBytes"
          title="I/O"
          :x-axis-max-ms="data.xAxisMaxMs"
          :x-axis-min-ms="data.xAxisMinMs"
          :x-axis-start-continuity-gap-ms="data.chartStartContinuityGapMs"
          y-axis-name="B"
          :value-formatter="formatTrafficBytes"
        />
      </div>
    </template>
    <template v-else #chart>
      <div aria-label="正在加载指标" class="grid gap-4" role="status">
        <span class="sr-only">正在加载指标</span>
        <Skeleton class="h-40 w-full" />
        <Skeleton class="h-40 w-full" />
      </div>
    </template>
    <template v-if="data.latestSample" #details>
      <DiskDetails :latest-sample="data.latestSample" variant="stack" />
    </template>
    <template v-else #details>
      <div aria-hidden="true" class="grid gap-3">
        <Skeleton class="h-14 w-full" />
        <Skeleton class="h-14 w-full" />
        <Skeleton class="h-14 w-full" />
        <Skeleton class="h-14 w-full" />
      </div>
    </template>
  </MetricPanel>
</template>
