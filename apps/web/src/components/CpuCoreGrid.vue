<script setup lang="ts">
import { computed } from "vue";

import { formatPercent } from "@/lib/format";
import type { MetricSeries } from "@/lib/metrics-chart-data";

import type { HostMetricSample } from "../types";
import SparklineChart from "./SparklineChart.vue";

const cpuSparklineWindowMs = 60_000;

const props = defineProps<{
  cpuCoreSeries: MetricSeries[];
  latestSample: HostMetricSample | null;
  xAxisStartContinuityGapMs: number;
}>();

const cpuCoreRows = computed(() => {
  const latestByName = new Map(
    (props.latestSample?.cpuCores ?? []).map((core) => [
      core.name,
      core.usagePercent,
    ]),
  );

  return props.cpuCoreSeries
    .map((series) => ({
      latestPercent: latestByName.get(series.name) ?? latestPointValue(series),
      name: series.name,
      points: series.points,
      windowEndMs: series.points.at(-1)?.[0] ?? 0,
    }))
    .sort((left, right) =>
      left.name.localeCompare(right.name, undefined, {
        numeric: true,
        sensitivity: "base",
      }),
    );
});

function latestPointValue(series: MetricSeries) {
  return series.points.at(-1)?.[1] ?? 0;
}
</script>

<template>
  <div
    v-if="cpuCoreRows.length"
    class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4"
  >
    <div
      v-for="core in cpuCoreRows"
      :key="core.name"
      class="grid gap-1"
      :title="`${core.name} ${formatPercent(core.latestPercent)}`"
    >
      <div
        class="flex items-center justify-between gap-2 text-[11px] leading-none"
      >
        <span class="text-foreground font-medium">
          {{ core.name.replace("cpu", "CPU ") }}
        </span>
        <span class="text-foreground font-medium">
          {{ formatPercent(core.latestPercent) }}
        </span>
      </div>
      <SparklineChart
        :points="core.points"
        :window-end-ms="core.windowEndMs"
        :window-start-ms="core.windowEndMs - cpuSparklineWindowMs"
        :max-start-gap-ms="xAxisStartContinuityGapMs"
      />
    </div>
  </div>
  <p v-else class="text-muted-foreground text-sm">暂无核心数据</p>
</template>
