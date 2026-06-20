<script setup lang="ts">
import * as echarts from "echarts";
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";

import type { MetricSeries } from "@/lib/metrics-chart-data";

type TooltipParam = {
  axisValue?: number | string;
  data?: number | [number, number];
  marker?: string;
  seriesName?: string;
  value?: number | [number, number];
};

type LegendSelectChangedEvent = {
  selected?: Record<string, boolean>;
};

const props = defineProps<{
  emptyText?: string;
  series: MetricSeries[];
  title: string;
  valueFormatter?: (value: number) => string;
  xAxisMaxMs?: number;
  xAxisMinMs?: number;
  yAxisName?: string;
}>();

const chartElement = ref<HTMLElement | null>(null);
const pointCount = computed(() =>
  props.series.reduce((total, item) => total + item.points.length, 0),
);
let chart: echarts.ECharts | null = null;
let legendSelected: Record<string, boolean> = {};

onMounted(async () => {
  await nextTick();

  if (!chartElement.value) {
    return;
  }

  chart = echarts.init(chartElement.value);
  chart.on("legendselectchanged", (event: unknown) => {
    const selected = legendSelectionFromEvent(event);

    if (selected) {
      legendSelected = selected;
    }
  });
  renderChart();
  window.addEventListener("resize", resizeChart);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", resizeChart);
  chart?.dispose();
  chart = null;
});

watch(
  () => [
    props.series,
    props.title,
    props.xAxisMaxMs,
    props.xAxisMinMs,
    props.yAxisName,
  ],
  () => {
    renderChart();
  },
  {
    deep: true,
  },
);

function renderChart() {
  if (!chart) {
    return;
  }

  const formatter = props.valueFormatter ?? ((value: number) => String(value));
  const hasData = props.series.some((item) => item.points.length > 0);
  const theme = chartTheme();
  const titleText = props.yAxisName ? `${props.title} ${props.yAxisName}` : props.title;

  chart.clear();
  chart.setOption({
    animation: false,
    color: ["#34d399", "#60a5fa", "#f59e0b", "#f472b6", "#a78bfa", "#22d3ee"],
    grid: {
      bottom: 20,
      left: 48,
      right: 18,
      top: 50,
    },
    legend: {
      inactiveColor: theme.mutedForeground,
      left: "center",
      pageIconColor: theme.foreground,
      pageTextStyle: {
        color: theme.mutedForeground,
      },
      textStyle: {
        color: theme.label,
        fontSize: 12,
      },
      selected: legendSelected,
      type: "scroll",
      top: 0,
    },
    series: props.series.map((item) => ({
      data: chartSeriesPoints(item.points),
      name: item.name,
      showSymbol: false,
      smooth: true,
      type: "line",
    })),
    title: {
      left: 0,
      text: titleText,
      textStyle: {
        color: theme.label,
        fontSize: 14,
        fontWeight: 600,
      },
    },
    tooltip: {
      backgroundColor: theme.card,
      borderColor: theme.border,
      borderWidth: 1,
      extraCssText:
        "box-shadow: 0 12px 30px rgb(15 23 42 / 0.12); border-radius: 8px;",
      formatter(params: TooltipParam | TooltipParam[]) {
        return tooltipText(params, formatter);
      },
      textStyle: {
        color: theme.foreground,
        fontSize: 12,
      },
      trigger: "axis",
    },
    xAxis: {
      axisLabel: {
        show: false,
      },
      axisTick: {
        show: false,
      },
      max: props.xAxisMaxMs,
      min: props.xAxisMinMs,
      type: "time",
    },
    yAxis: {
      axisLabel: {
        color: theme.mutedForeground,
        formatter,
      },
      nameTextStyle: {
        color: theme.mutedForeground,
      },
      splitLine: {
        lineStyle: {
          color: theme.border,
        },
      },
      type: "value",
    },
    ...emptyGraphicOption(hasData, theme),
  });
}

function resizeChart() {
  chart?.resize();
}

function legendSelectionFromEvent(
  event: unknown,
): Record<string, boolean> | null {
  if (typeof event !== "object" || event === null || !("selected" in event)) {
    return null;
  }

  const selected = (event as LegendSelectChangedEvent).selected;

  if (
    typeof selected !== "object" ||
    selected === null ||
    !Object.values(selected).every((item) => typeof item === "boolean")
  ) {
    return null;
  }

  return selected;
}

function emptyGraphicOption(
  hasData: boolean,
  theme: ReturnType<typeof chartTheme>,
) {
  if (hasData) {
    return {};
  }

  return {
    graphic: {
      left: "center",
      style: {
        fill: theme.mutedForeground,
        text: props.emptyText ?? "暂无历史指标",
      },
      top: "middle",
      type: "text",
    },
  };
}

function chartSeriesPoints(points: MetricSeries["points"]) {
  const firstPoint = points[0];

  if (
    props.xAxisMinMs === undefined ||
    props.xAxisMaxMs === undefined ||
    !firstPoint ||
    firstPoint[0] <= props.xAxisMinMs ||
    firstPoint[0] - props.xAxisMinMs <= missingDataThresholdMs()
  ) {
    return points;
  }

  return [
    [firstPoint[0], 0],
    ...points,
  ];
}

function missingDataThresholdMs() {
  if (props.xAxisMinMs === undefined || props.xAxisMaxMs === undefined) {
    return 0;
  }

  const rangeMs = Math.max(0, props.xAxisMaxMs - props.xAxisMinMs);

  return Math.min(
    5 * 60 * 1000,
    Math.max(60 * 1000, rangeMs * 0.02),
  );
}

function chartTheme() {
  const style = getComputedStyle(document.documentElement);

  return {
    border: cssColor(style, "--border", "#e5e7eb"),
    card: cssColor(style, "--card", "#ffffff"),
    foreground: cssColor(style, "--foreground", "#111827"),
    label: cssColor(style, "--chart-label", "#374151"),
    mutedForeground: cssColor(style, "--muted-foreground", "#6b7280"),
  };
}

function cssColor(
  style: CSSStyleDeclaration,
  variableName: string,
  fallback: string,
) {
  return style.getPropertyValue(variableName).trim() || fallback;
}

function tooltipText(
  params: TooltipParam | TooltipParam[],
  valueFormatter: (value: number) => string,
) {
  const items = Array.isArray(params) ? params : [params];
  const timestamp = tooltipTimestamp(items[0]);
  const lines = items
    .map((item) => {
      const value = tooltipValue(item);

      if (value === null) {
        return "";
      }

      return `<div>${item.marker ?? ""}${escapeHtml(item.seriesName ?? "")}: ${escapeHtml(valueFormatter(value))}</div>`;
    })
    .filter(Boolean);

  return [
    `<div class="font-medium">${escapeHtml(timestamp)}</div>`,
    ...lines,
  ].join("");
}

function tooltipTimestamp(param: TooltipParam | undefined) {
  const rawValue = Array.isArray(param?.data)
    ? param.data[0]
    : Array.isArray(param?.value)
      ? param.value[0]
      : param?.axisValue;
  const value = Number(rawValue);

  if (!Number.isFinite(value)) {
    return "";
  }

  return new Date(value).toLocaleString([], {
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    month: "numeric",
    second: "2-digit",
  });
}

function tooltipValue(param: TooltipParam) {
  const rawValue = Array.isArray(param.data)
    ? param.data[1]
    : Array.isArray(param.value)
      ? param.value[1]
      : param.value;
  const value = Number(rawValue);

  return Number.isFinite(value) ? value : null;
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
</script>

<template>
  <div
    ref="chartElement"
    class="h-72 min-h-72 w-full"
    role="img"
    :aria-label="title"
    :data-smoke-chart-title="title"
    :data-smoke-point-count="pointCount"
  />
</template>
