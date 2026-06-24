<script setup lang="ts">
import { Download, HardDrive, Upload, EthernetPort } from "@lucide/vue";
import { computed } from "vue";

import { Progress } from "@/components/ui/progress";
import {
  formatBitsPerSecond,
  formatBytes,
  formatPercent,
  formatTrafficBytes,
} from "@/lib/format";
import type { MetricSeries } from "@/metrics/chart-data";

import type { HostMetricSample, HostProfileSnapshot } from "../../types";
import MetricsChart from "../shared/MetricsChart.vue";
import SparklineChart from "../shared/SparklineChart.vue";

const cpuSparklineWindowMs = 60_000;

const props = defineProps<{
  aggregateDiskSeries: MetricSeries;
  aggregateDiskIoSeries: MetricSeries[];
  aggregateNetworkSeries: MetricSeries[];
  cpuCoreSeries: MetricSeries[];
  cpuModel: string | null;
  hostProfile: HostProfileSnapshot | null;
  latestSample: HostMetricSample | null;
  panel: "cpu" | "disk" | "network";
  samples: HostMetricSample[];
  xAxisMaxMs: number;
  xAxisMinMs: number;
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

const diskRows = computed(() =>
  [...(props.latestSample?.disks ?? [])].sort(
    (left, right) =>
      diskPercent(right.usedBytes, right.totalBytes) -
      diskPercent(left.usedBytes, left.totalBytes),
  ),
);

const cpuBreakdownRows = computed<Array<[string, number | null]>>(() => [
  ["用户", props.latestSample?.cpuUserPercent ?? null],
  ["系统", props.latestSample?.cpuSystemPercent ?? null],
  ["等待", props.latestSample?.cpuIowaitPercent ?? null],
  ["抢占", props.latestSample?.cpuStealPercent ?? null],
  ["空闲", props.latestSample?.cpuIdlePercent ?? null],
]);

const networkRows = computed(() => {
  const latestByName = new Map(
    (props.latestSample?.networkInterfaces ?? []).map((networkInterface) => [
      networkInterface.name,
      networkInterface,
    ]),
  );
  const totalsByName = new Map<
    string,
    {
      name: string;
      rxBitsPerSecond: number | null;
      rxWindowBytes: number;
      txBitsPerSecond: number | null;
      txWindowBytes: number;
    }
  >();
  const sourceSamples = props.samples.length
    ? props.samples
    : props.latestSample
      ? [props.latestSample]
      : [];

  for (const sample of sourceSamples) {
    for (const networkInterface of sample.networkInterfaces) {
      const totals = totalsByName.get(networkInterface.name) ?? {
        name: networkInterface.name,
        rxBitsPerSecond:
          latestByName.get(networkInterface.name)?.rxBitsPerSecond ?? null,
        rxWindowBytes: 0,
        txBitsPerSecond:
          latestByName.get(networkInterface.name)?.txBitsPerSecond ?? null,
        txWindowBytes: 0,
      };
      totals.rxWindowBytes += networkInterface.rxBytesDelta;
      totals.txWindowBytes += networkInterface.txBytesDelta;
      totalsByName.set(networkInterface.name, totals);
    }
  }

  return [...totalsByName.values()].sort((left, right) =>
    left.name.localeCompare(right.name, undefined, {
      numeric: true,
      sensitivity: "base",
    }),
  );
});

function diskPercent(usedBytes: number, totalBytes: number) {
  if (totalBytes <= 0) {
    return 0;
  }

  return (usedBytes / totalBytes) * 100;
}

function latestPointValue(series: MetricSeries) {
  return series.points.at(-1)?.[1] ?? 0;
}

function boundedPercent(value: number | null | undefined) {
  return Math.min(100, Math.max(0, value ?? 0));
}

function positiveNumber(value: number | null | undefined) {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? value
    : null;
}

function hostProfileText(
  value: number | null | undefined,
  formatter?: (value: number) => string,
) {
  const normalized = positiveNumber(value);

  if (normalized === null) {
    return "暂无";
  }

  return formatter ? formatter(normalized) : String(normalized);
}

function frequencyText(value: number) {
  return `${value} MHz`;
}

function formatMilliseconds(value: number | null) {
  return value === null ? "n/a" : `${value.toFixed(1)} ms`;
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
    <div
      class="grid gap-2 rounded-md border p-3 text-sm sm:grid-cols-2 lg:grid-cols-5"
    >
      <div
        v-for="[label, value] in cpuBreakdownRows"
        :key="label"
        class="min-w-0"
      >
        <p class="text-muted-foreground text-xs">{{ label }}</p>
        <p class="font-medium">{{ formatPercent(value) }}</p>
      </div>
    </div>
    <div
      class="text-muted-foreground grid min-w-0 gap-3 text-sm md:grid-cols-2 xl:grid-cols-3"
    >
      <div class="min-w-0">
        <p>CPU 型号</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium wrap-break-word whitespace-normal"
          :title="cpuModel ?? undefined"
        >
          {{ cpuModel || "暂无" }}
        </p>
      </div>
      <div class="min-w-0">
        <p>进程</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium wrap-break-word whitespace-normal"
        >
          {{ hostProfileText(hostProfile?.processCount) }}
        </p>
      </div>
      <div class="min-w-0">
        <p>线程</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium wrap-break-word whitespace-normal"
        >
          {{ hostProfileText(hostProfile?.threadCount) }}
        </p>
      </div>
      <div class="min-w-0">
        <p>L3 缓存</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium wrap-break-word whitespace-normal"
        >
          {{ hostProfileText(hostProfile?.cpuCacheL3Bytes, formatBytes) }}
        </p>
      </div>
      <div class="min-w-0">
        <p>基准频率</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium wrap-break-word whitespace-normal"
        >
          {{ hostProfileText(hostProfile?.cpuBaseFrequencyMhz, frequencyText) }}
        </p>
      </div>
      <div class="min-w-0">
        <p>物理 CPU</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium wrap-break-word whitespace-normal"
        >
          {{ hostProfileText(hostProfile?.cpuPhysicalCount) }}
        </p>
      </div>
      <div class="min-w-0">
        <p>插槽</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium wrap-break-word whitespace-normal"
        >
          {{ hostProfileText(hostProfile?.cpuSocketCount) }}
        </p>
      </div>
    </div>
  </div>

  <div
    v-else-if="panel === 'disk'"
    class="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]"
  >
    <div class="grid gap-4">
      <MetricsChart
        :series="[aggregateDiskSeries]"
        title="磁盘使用率"
        :x-axis-max-ms="xAxisMaxMs"
        :x-axis-min-ms="xAxisMinMs"
        :x-axis-start-continuity-gap-ms="xAxisStartContinuityGapMs"
        :y-axis-max="100"
        :y-axis-min="0"
        y-axis-name="%"
        :value-formatter="formatPercent"
      />
      <MetricsChart
        :series="aggregateDiskIoSeries"
        title="磁盘 I/O"
        :x-axis-max-ms="xAxisMaxMs"
        :x-axis-min-ms="xAxisMinMs"
        :x-axis-start-continuity-gap-ms="xAxisStartContinuityGapMs"
        y-axis-name="B"
        :value-formatter="formatTrafficBytes"
      />
    </div>

    <div class="rounded-md border p-4">
      <div class="mb-3 flex items-center gap-2 text-sm font-medium">
        <HardDrive class="text-muted-foreground size-4" />
        挂载点
      </div>
      <div v-if="diskRows.length" class="grid gap-4">
        <div v-for="disk in diskRows" :key="disk.mountPoint" class="grid gap-2">
          <div class="flex items-center justify-between gap-3 text-sm">
            <span class="truncate font-medium">{{ disk.mountPoint }}</span>
            <span class="text-muted-foreground shrink-0">
              {{ formatBytes(disk.usedBytes) }} /
              {{ formatBytes(disk.totalBytes) }}
            </span>
          </div>
          <Progress
            :model-value="
              boundedPercent(diskPercent(disk.usedBytes, disk.totalBytes))
            "
          />
          <div class="bg-muted/40 grid gap-2 rounded-md p-3 text-xs">
            <div class="flex items-center justify-between gap-3">
              <span class="text-muted-foreground">读取</span>
              <span class="font-medium">
                {{ formatTrafficBytes(disk.readBytesDelta ?? null) }}
              </span>
            </div>
            <div class="flex items-center justify-between gap-3">
              <span class="text-muted-foreground">写入</span>
              <span class="font-medium">
                {{ formatTrafficBytes(disk.writeBytesDelta ?? null) }}
              </span>
            </div>
            <div class="flex items-center justify-between gap-3">
              <span class="text-muted-foreground">等待</span>
              <span class="font-medium">
                {{ formatMilliseconds(disk.readAwaitMs ?? null) }} /
                {{ formatMilliseconds(disk.writeAwaitMs ?? null) }}
              </span>
            </div>
            <div class="flex items-center justify-between gap-3">
              <span class="text-muted-foreground">I/O</span>
              <span class="font-medium">
                {{ formatPercent(disk.ioUtilizationPercent ?? null) }}
              </span>
            </div>
          </div>
        </div>
      </div>
      <p v-else class="text-muted-foreground text-sm">暂无磁盘数据</p>
    </div>
  </div>

  <div v-else class="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
    <MetricsChart
      :series="aggregateNetworkSeries"
      title="吞吐量"
      :x-axis-max-ms="xAxisMaxMs"
      :x-axis-min-ms="xAxisMinMs"
      :x-axis-start-continuity-gap-ms="xAxisStartContinuityGapMs"
      y-axis-name="b/s"
      :value-formatter="formatBitsPerSecond"
    />

    <div class="rounded-md border p-4">
      <div class="mb-3 flex items-center gap-2 text-sm font-medium">
        <EthernetPort class="text-muted-foreground size-4" />
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
          <div class="bg-muted/40 grid gap-2 rounded-md p-3 text-sm">
            <div class="flex items-center justify-between gap-3">
              <span class="text-muted-foreground flex items-center gap-2">
                <Download class="size-3.5 text-sky-600" />
                接收
              </span>
              <span class="font-medium">
                {{ formatBitsPerSecond(networkInterface.rxBitsPerSecond) }}
              </span>
            </div>
            <div class="flex items-center justify-between gap-3">
              <span class="text-muted-foreground flex items-center gap-2">
                <Download class="size-3.5 text-sky-600" />
                总接收
              </span>
              <span class="font-medium">
                {{ formatTrafficBytes(networkInterface.rxWindowBytes) }}
              </span>
            </div>
            <div class="flex items-center justify-between gap-3">
              <span class="text-muted-foreground flex items-center gap-2">
                <Upload class="size-3.5 text-amber-600" />
                发送
              </span>
              <span class="font-medium">
                {{ formatBitsPerSecond(networkInterface.txBitsPerSecond) }}
              </span>
            </div>
            <div class="flex items-center justify-between gap-3">
              <span class="text-muted-foreground flex items-center gap-2">
                <Upload class="size-3.5 text-amber-600" />
                总发送
              </span>
              <span class="font-medium">
                {{ formatTrafficBytes(networkInterface.txWindowBytes) }}
              </span>
            </div>
          </div>
        </div>
      </div>
      <p v-else class="text-muted-foreground text-sm">暂无网络数据</p>
    </div>
  </div>
</template>
