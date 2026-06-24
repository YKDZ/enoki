<script setup lang="ts">
import { HardDrive } from "@lucide/vue";
import { computed } from "vue";

import { Progress } from "@/components/ui/progress";
import { formatBytes, formatPercent, formatTrafficBytes } from "@/lib/format";

import type { HostMetricSample } from "../../types";

const props = defineProps<{
  latestSample: HostMetricSample | null;
  variant?: "grid" | "stack";
}>();

const diskRows = computed(() =>
  [...(props.latestSample?.disks ?? [])].sort(
    (left, right) =>
      diskPercent(right.usedBytes, right.totalBytes) -
      diskPercent(left.usedBytes, left.totalBytes),
  ),
);

function diskPercent(usedBytes: number, totalBytes: number) {
  if (totalBytes <= 0) {
    return 0;
  }

  return (usedBytes / totalBytes) * 100;
}

function boundedPercent(value: number) {
  return Math.min(100, Math.max(0, value));
}
</script>

<template>
  <div v-if="diskRows.length" class="grid gap-5">
    <div v-if="diskRows.length" class="grid gap-3">
      <div class="text-muted-foreground flex items-center gap-2 text-sm">
        <HardDrive class="size-4" aria-hidden="true" />
        挂载点
      </div>
      <div :class="['grid gap-3', variant === 'stack' ? '' : 'xl:grid-cols-2']">
        <div v-for="disk in diskRows" :key="disk.mountPoint" class="grid gap-2">
          <div class="flex items-center justify-between gap-3 text-sm">
            <span class="min-w-0 font-medium wrap-break-word">
              {{ disk.mountPoint }}
            </span>
            <span class="text-muted-foreground shrink-0">
              {{ formatPercent(diskPercent(disk.usedBytes, disk.totalBytes)) }}
            </span>
          </div>
          <Progress
            :model-value="
              boundedPercent(diskPercent(disk.usedBytes, disk.totalBytes))
            "
          />
          <div
            class="text-muted-foreground flex flex-wrap gap-x-4 gap-y-1 text-xs"
          >
            <span>
              {{ formatBytes(disk.usedBytes) }} /
              {{ formatBytes(disk.totalBytes) }}
            </span>
            <span
              >读取 {{ formatTrafficBytes(disk.readBytesDelta ?? null) }}</span
            >
            <span
              >写入 {{ formatTrafficBytes(disk.writeBytesDelta ?? null) }}</span
            >
          </div>
        </div>
      </div>
    </div>
  </div>
  <p v-else class="text-muted-foreground text-sm">暂无磁盘数据</p>
</template>
