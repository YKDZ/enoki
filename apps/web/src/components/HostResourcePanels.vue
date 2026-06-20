<script setup lang="ts">
import { Cpu, Download, HardDrive, Upload } from "@lucide/vue";
import { computed } from "vue";

import { Progress } from "@/components/ui/progress";
import { formatBitsPerSecond, formatBytes, formatPercent } from "@/lib/format";
import type { MetricSeries } from "@/lib/metrics-chart-data";
import type { ManagedHostMetricSample } from "../types";
import MetricsChart from "./MetricsChart.vue";

const cpuSparklineWindowMs = 60_000;
const cpuSparklineHeight = 70;

const props = defineProps<{
  aggregateDiskSeries: MetricSeries;
  aggregateNetworkSeries: MetricSeries[];
  cpuCoreSeries: MetricSeries[];
  cpuModel: string | null;
  inventory: Record<string, unknown> | null;
  latestSample: ManagedHostMetricSample | null;
  panel: "cpu" | "disk" | "network";
  xAxisMaxMs: number;
  xAxisMinMs: number;
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
      points: sparklinePoints(series.points),
    }))
    .sort((left, right) =>
      left.name.localeCompare(right.name, undefined, {
        numeric: true,
        sensitivity: "base",
      }),
    );
});

const diskRows = computed(() =>
  [...(props.latestSample?.disks ?? [])].sort(
    (left, right) =>
      diskPercent(right.usedBytes, right.totalBytes) -
      diskPercent(left.usedBytes, left.totalBytes),
  ),
);

const networkRows = computed(() =>
  [...(props.latestSample?.networkInterfaces ?? [])].sort((left, right) =>
    left.name.localeCompare(right.name, undefined, {
      numeric: true,
      sensitivity: "base",
    }),
  ),
);

function diskPercent(usedBytes: number, totalBytes: number) {
  if (totalBytes <= 0) {
    return 0;
  }

  return (usedBytes / totalBytes) * 100;
}

function boundedPercent(value: number | null | undefined) {
  return Math.min(100, Math.max(0, value ?? 0));
}

function latestPointValue(series: MetricSeries) {
  return series.points.at(-1)?.[1] ?? 0;
}

function sparklinePoints(points: MetricSeries["points"]) {
  const latestTime = points.at(-1)?.[0] ?? 0;
  const windowStart = latestTime - cpuSparklineWindowMs;
  const sampledPoints = sampled(
    points.filter(([time]) => time >= windowStart),
    72,
  );

  if (sampledPoints.length === 0) {
    return "";
  }

  return sampledPoints
    .map(([time, value]) => {
      const x = ((time - windowStart) / cpuSparklineWindowMs) * 100;

      return `${x.toFixed(1)},${pointY(value)}`;
    })
    .join(" ");
}

function pointY(value: number) {
  return (cpuSparklineHeight - boundedPercent(value) * 0.68).toFixed(1);
}

function sampled<T>(items: T[], maxItems: number) {
  if (items.length <= maxItems) {
    return items;
  }

  const step = (items.length - 1) / (maxItems - 1);

  return Array.from(
    { length: maxItems },
    (_, index) => items[Math.round(index * step)] as T,
  );
}

function inventoryNumber(key: string) {
  const value = Number(props.inventory?.[key] ?? 0);

  return Number.isFinite(value) && value > 0 ? value : null;
}

function inventoryText(key: string, formatter?: (value: number) => string) {
  const value = inventoryNumber(key);

  if (value === null) {
    return "暂无";
  }

  return formatter ? formatter(value) : String(value);
}

function frequencyText(value: number) {
  return `${value} MHz`;
}
</script>

<template>
  <div v-if="panel === 'cpu'" class="grid gap-5">
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
        <div class="flex items-center justify-between gap-2 text-[11px] leading-none">
          <span class="font-medium text-foreground">
            {{ core.name.replace("cpu", "CPU ") }}
          </span>
          <span class="font-medium text-foreground">
            {{ formatPercent(core.latestPercent) }}
          </span>
        </div>
        <svg
          class="h-24 w-full border bg-background"
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
            v-if="core.points"
            :points="core.points"
            fill="none"
            stroke="currentColor"
            class="text-emerald-500"
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="1.8"
          />
        </svg>
      </div>
    </div>
    <p v-else class="text-sm text-muted-foreground">暂无核心数据</p>
    <div class="grid gap-3 text-sm text-muted-foreground md:grid-cols-2 xl:grid-cols-3">
      <div>
        <p>CPU 型号</p>
        <p class="mt-1 truncate font-medium text-foreground" :title="cpuModel ?? undefined">
          {{ cpuModel || "暂无" }}
        </p>
      </div>
      <div>
        <p>进程</p>
        <p class="mt-1 font-medium text-foreground">
          {{ inventoryText("processCount") }}
        </p>
      </div>
      <div>
        <p>线程</p>
        <p class="mt-1 font-medium text-foreground">
          {{ inventoryText("threadCount") }}
        </p>
      </div>
      <div>
        <p>L3 缓存</p>
        <p class="mt-1 font-medium text-foreground">
          {{ inventoryText("cpuCacheL3Bytes", formatBytes) }}
        </p>
      </div>
      <div>
        <p>基准频率</p>
        <p class="mt-1 font-medium text-foreground">
          {{ inventoryText("cpuBaseFrequencyMhz", frequencyText) }}
        </p>
      </div>
      <div>
        <p>物理 CPU</p>
        <p class="mt-1 font-medium text-foreground">
          {{ inventoryText("cpuPhysicalCount") }}
        </p>
      </div>
      <div>
        <p>插槽</p>
        <p class="mt-1 font-medium text-foreground">
          {{ inventoryText("cpuSocketCount") }}
        </p>
      </div>
    </div>
  </div>

  <div
    v-else-if="panel === 'disk'"
    class="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]"
  >
    <MetricsChart
      :series="[aggregateDiskSeries]"
      title="磁盘趋势"
      :x-axis-max-ms="xAxisMaxMs"
      :x-axis-min-ms="xAxisMinMs"
      y-axis-name="%"
      :value-formatter="formatPercent"
    />

    <div class="rounded-md border p-4">
      <div class="mb-3 flex items-center gap-2 text-sm font-medium">
        <HardDrive class="size-4 text-muted-foreground" />
        挂载点
      </div>
      <div v-if="diskRows.length" class="grid gap-4">
        <div v-for="disk in diskRows" :key="disk.mountPoint" class="grid gap-2">
          <div class="flex items-center justify-between gap-3 text-sm">
            <span class="truncate font-medium">{{ disk.mountPoint }}</span>
            <span class="shrink-0 text-muted-foreground">
              {{ formatBytes(disk.usedBytes) }} /
              {{ formatBytes(disk.totalBytes) }}
            </span>
          </div>
          <Progress
            :model-value="
              boundedPercent(diskPercent(disk.usedBytes, disk.totalBytes))
            "
          />
        </div>
      </div>
      <p v-else class="text-sm text-muted-foreground">暂无磁盘数据</p>
    </div>
  </div>

  <div v-else class="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
    <MetricsChart
      :series="aggregateNetworkSeries"
      title="吞吐量"
      :x-axis-max-ms="xAxisMaxMs"
      :x-axis-min-ms="xAxisMinMs"
      y-axis-name="b/s"
      :value-formatter="formatBitsPerSecond"
    />

    <div class="rounded-md border p-4">
      <div class="mb-3 flex items-center gap-2 text-sm font-medium">
        <Download class="size-4 text-muted-foreground" />
        接口
      </div>
      <div v-if="networkRows.length" class="grid gap-4">
        <div
          v-for="networkInterface in networkRows"
          :key="networkInterface.name"
          class="grid gap-2"
        >
          <div class="flex items-center justify-between gap-3 text-sm">
            <span class="font-medium">{{ networkInterface.name }}</span>
          </div>
          <div class="grid gap-2 rounded-md bg-muted/40 p-3 text-sm">
            <div class="flex items-center justify-between gap-3">
              <span class="flex items-center gap-2 text-muted-foreground">
                <Download class="size-3.5 text-sky-600" />
                接收
              </span>
              <span class="font-medium">
                {{ formatBitsPerSecond(networkInterface.rxBitsPerSecond) }}
              </span>
            </div>
            <div class="flex items-center justify-between gap-3">
              <span class="flex items-center gap-2 text-muted-foreground">
                <Upload class="size-3.5 text-amber-600" />
                发送
              </span>
              <span class="font-medium">
                {{ formatBitsPerSecond(networkInterface.txBitsPerSecond) }}
              </span>
            </div>
          </div>
        </div>
      </div>
      <p v-else class="text-sm text-muted-foreground">暂无网络数据</p>
    </div>
  </div>
</template>
