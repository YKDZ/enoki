<script setup lang="ts">
import { computed } from "vue";

import { formatBytes, formatPercent } from "@/lib/format";

import type { HostMetricSample } from "../types";

const props = defineProps<{
  cpuModel: string | null;
  inventory: Record<string, unknown> | null;
  latestSample: HostMetricSample | null;
}>();

const cpuBreakdownRows = computed<Array<[string, number | null]>>(() => [
  ["用户", props.latestSample?.cpuUserPercent ?? null],
  ["系统", props.latestSample?.cpuSystemPercent ?? null],
  ["等待", props.latestSample?.cpuIowaitPercent ?? null],
  ["抢占", props.latestSample?.cpuStealPercent ?? null],
  ["空闲", props.latestSample?.cpuIdlePercent ?? null],
]);

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
          {{ inventoryText("processCount") }}
        </p>
      </div>
      <div class="min-w-0">
        <p>线程</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium break-words whitespace-normal"
        >
          {{ inventoryText("threadCount") }}
        </p>
      </div>
      <div class="min-w-0">
        <p>L3 缓存</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium break-words whitespace-normal"
        >
          {{ inventoryText("cpuCacheL3Bytes", formatBytes) }}
        </p>
      </div>
      <div class="min-w-0">
        <p>基准频率</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium break-words whitespace-normal"
        >
          {{ inventoryText("cpuBaseFrequencyMhz", frequencyText) }}
        </p>
      </div>
      <div class="min-w-0">
        <p>物理 CPU</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium break-words whitespace-normal"
        >
          {{ inventoryText("cpuPhysicalCount") }}
        </p>
      </div>
      <div class="min-w-0">
        <p>插槽</p>
        <p
          class="text-foreground mt-1 min-w-0 font-medium break-words whitespace-normal"
        >
          {{ inventoryText("cpuSocketCount") }}
        </p>
      </div>
    </div>
  </div>
</template>
