<script setup lang="ts">
import { Activity, HardDrive } from "@lucide/vue";
import { computed } from "vue";

import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { formatBytes, formatPercent, formatTrafficBytes } from "@/lib/format";

import type { CollectorAvailability, HostMetricSample } from "../types";

const props = defineProps<{
  diskHealthCapability?: CollectorAvailability;
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
const diskHealthRows = computed(() =>
  props.diskHealthCapability?.available === false
    ? []
    : (props.latestSample?.diskHealth ?? []),
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
  <div v-if="diskRows.length || diskHealthRows.length" class="grid gap-5">
    <div v-if="diskHealthRows.length" class="grid gap-3">
      <div class="text-muted-foreground flex items-center gap-2 text-sm">
        <Activity class="size-4" aria-hidden="true" />
        硬盘健康
      </div>
      <div :class="['grid gap-3', variant === 'stack' ? '' : 'xl:grid-cols-2']">
        <div
          v-for="disk in diskHealthRows"
          :key="disk.deviceName"
          class="border-border/70 bg-background/40 grid gap-2 rounded-md border p-3"
        >
          <div class="flex items-center justify-between gap-3 text-sm">
            <span class="min-w-0 font-medium break-words">
              {{ disk.model || disk.deviceName }}
            </span>
            <Badge :variant="disk.passed ? 'secondary' : 'destructive'">
              {{ disk.passed ? "健康" : "需关注" }}
            </Badge>
          </div>
          <div
            class="text-muted-foreground flex flex-wrap gap-x-4 gap-y-1 text-xs"
          >
            <span>{{ disk.deviceName }}</span>
            <span v-if="disk.temperatureCelsius !== null">
              {{ disk.temperatureCelsius }} °C
            </span>
            <span v-if="disk.powerOnHours !== null">
              通电 {{ disk.powerOnHours }} 小时
            </span>
            <span v-if="disk.serialNumber">序列号 {{ disk.serialNumber }}</span>
          </div>
        </div>
      </div>
    </div>

    <div v-if="diskRows.length" class="grid gap-3">
      <div class="text-muted-foreground flex items-center gap-2 text-sm">
        <HardDrive class="size-4" aria-hidden="true" />
        挂载点
      </div>
      <div :class="['grid gap-3', variant === 'stack' ? '' : 'xl:grid-cols-2']">
        <div v-for="disk in diskRows" :key="disk.mountPoint" class="grid gap-2">
          <div class="flex items-center justify-between gap-3 text-sm">
            <span class="min-w-0 font-medium break-words">
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
