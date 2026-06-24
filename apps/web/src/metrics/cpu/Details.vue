<script setup lang="ts">
import { computed } from "vue";

import { formatBytes, formatPercent } from "@/lib/format";

import type { HostMetricSample, HostProfileSnapshot } from "../../types";

const props = defineProps<{
  cpuModel: string | null;
  hostProfile: HostProfileSnapshot | null;
  latestSample: HostMetricSample | null;
}>();

const cpuBreakdownRows = computed<Array<[string, number | null]>>(() => [
  ["用户", props.latestSample?.cpuUserPercent ?? null],
  ["系统", props.latestSample?.cpuSystemPercent ?? null],
  ["等待", props.latestSample?.cpuIowaitPercent ?? null],
  ["抢占", props.latestSample?.cpuStealPercent ?? null],
  ["空闲", props.latestSample?.cpuIdlePercent ?? null],
]);

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
</script>

<template>
  <div class="grid gap-4">
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
</template>
