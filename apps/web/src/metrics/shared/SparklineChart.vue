<script setup lang="ts">
import { computed } from "vue";

import { linePointsForWindow, type ChartPoint } from "@/metrics/chart-data";

const chartHeight = 72;
const chartWidth = 100;

const props = withDefaults(
  defineProps<{
    maxStartGapMs?: number;
    maxValue?: number;
    minValue?: number;
    points: ChartPoint[];
    windowEndMs: number;
    windowStartMs: number;
  }>(),
  {
    maxStartGapMs: Number.POSITIVE_INFINITY,
    maxValue: 100,
    minValue: 0,
  },
);

const polylinePoints = computed(() => {
  const visiblePoints = linePointsForWindow(props.points, {
    maxStartGapMs: props.maxStartGapMs,
    maxVisiblePoints: 72,
    windowEndMs: props.windowEndMs,
    windowStartMs: props.windowStartMs,
  });

  return visiblePoints
    .map(([time, value]) => {
      const x =
        ((time - props.windowStartMs) /
          (props.windowEndMs - props.windowStartMs)) *
        chartWidth;

      return `${boundedCoordinate(x)},${valueY(value)}`;
    })
    .join(" ");
});

function valueY(value: number) {
  const range = props.maxValue - props.minValue;
  const percent =
    range <= 0 ? 0 : (boundedValue(value) - props.minValue) / range;

  return (chartHeight - percent * (chartHeight - 3) - 2).toFixed(1);
}

function boundedValue(value: number) {
  return Math.min(props.maxValue, Math.max(props.minValue, value));
}

function boundedCoordinate(value: number) {
  return Math.min(chartWidth, Math.max(0, value)).toFixed(1);
}
</script>

<template>
  <svg
    class="bg-background h-24 w-full border"
    viewBox="0 0 100 72"
    preserveAspectRatio="none"
  >
    <path
      d="M 0 70 H 100"
      fill="none"
      stroke="currentColor"
      class="text-muted"
      stroke-width="1"
      shape-rendering="crispEdges"
    />
    <polyline
      v-if="polylinePoints"
      :points="polylinePoints"
      fill="none"
      stroke="currentColor"
      class="text-[var(--metric-good)]"
      stroke-linecap="round"
      stroke-linejoin="round"
      stroke-width="1.8"
    />
  </svg>
</template>
