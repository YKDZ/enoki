<script setup lang="ts">
import {
  Activity,
  Clock3,
  HardDrive,
  ShieldAlert,
  Thermometer,
} from "@lucide/vue";
import { computed } from "vue";

import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { formatBytes, formatDuration, formatTemperature } from "@/lib/format";

import MetricPanel from "../shared/MetricPanel.vue";
import { panelStorageKey } from "../shared/panel-storage";
import type { DiskHealthMetricCardProps } from "../view-model";

const props = defineProps<DiskHealthMetricCardProps>();

const disks = computed(() =>
  [...(props.data.latestDiskHealth ?? [])].sort((left, right) =>
    left.deviceName.localeCompare(right.deviceName),
  ),
);

const statusMessage = computed(() => {
  switch (props.capability.status) {
    case 2:
      return "未安装 smartctl，硬盘健康数据暂不可用";
    case 3:
      return "本地权限不足，无法运行硬盘健康辅助程序";
    case 4:
      return "硬盘健康辅助程序执行失败";
    case 5:
      return "smartctl 扫描失败";
    case 6:
      return "当前硬盘不支持 SMART 数据";
    case 7:
      return "smartctl 输出格式异常";
    default:
      return "等待硬盘健康数据";
  }
});

const showUnavailableState = computed(
  () => disks.value.length === 0 && props.capability.status !== 1,
);

function powerOnDuration(hours: number | null) {
  return hours === null ? null : formatDuration(hours * 60 * 60);
}

function usagePercent(usedBytes: number | null, totalBytes: number | null) {
  if (usedBytes === null || totalBytes === null || totalBytes <= 0) {
    return null;
  }

  return Math.max(0, Math.min(100, (usedBytes / totalBytes) * 100));
}

function usageText(usedBytes: number | null, totalBytes: number | null) {
  if (usedBytes === null || totalBytes === null || totalBytes <= 0) {
    return null;
  }

  return `${formatBytes(usedBytes)} / ${formatBytes(totalBytes)}`;
}
</script>

<template>
  <MetricPanel
    title="硬盘健康"
    description="硬盘自检状态"
    size="xl"
    :storage-key="panelStorageKey(data.hostId, 'disk-health')"
    collapsible
  >
    <div
      v-if="showUnavailableState"
      class="border-border/70 bg-background/40 grid gap-2 rounded-md border p-3"
      role="status"
    >
      <div class="text-muted-foreground flex items-center gap-2 text-sm">
        <ShieldAlert class="size-4" aria-hidden="true" />
        <span>{{ statusMessage }}</span>
      </div>
      <p
        v-if="capability.diagnostic"
        class="text-muted-foreground text-xs wrap-break-word"
      >
        {{ capability.diagnostic }}
      </p>
    </div>
    <div
      v-else-if="disks.length"
      class="grid gap-3 md:grid-cols-2 xl:grid-cols-3"
    >
      <div
        v-for="disk in disks"
        :key="disk.deviceName"
        class="border-border/70 bg-background/40 grid gap-3 rounded-md border p-3"
      >
        <div class="flex min-w-0 items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex min-w-0 items-center gap-2">
              <HardDrive
                class="text-muted-foreground size-4 shrink-0"
                aria-hidden="true"
              />
              <span class="min-w-0 text-sm font-medium wrap-break-word">
                {{ disk.model || disk.deviceName }}
              </span>
            </div>
            <p class="text-muted-foreground mt-1 text-xs wrap-break-word">
              {{ disk.deviceName }}
            </p>
          </div>
          <Badge :variant="disk.passed ? 'secondary' : 'destructive'">
            {{ disk.passed ? "健康" : "需关注" }}
          </Badge>
        </div>

        <div class="grid gap-2 text-sm sm:grid-cols-2">
          <div
            v-if="disk.role || disk.usageMountPoint"
            class="text-muted-foreground flex items-center gap-2"
          >
            <HardDrive class="size-4" aria-hidden="true" />
            <span class="min-w-0 wrap-break-word">
              {{
                [disk.role, disk.usageMountPoint].filter(Boolean).join(" / ")
              }}
            </span>
          </div>
          <div
            v-if="disk.temperatureCelsius !== null"
            class="text-muted-foreground flex items-center gap-2"
          >
            <Thermometer class="size-4" aria-hidden="true" />
            <span>{{ formatTemperature(disk.temperatureCelsius) }}</span>
          </div>
          <div
            v-if="powerOnDuration(disk.powerOnHours)"
            class="text-muted-foreground flex items-center gap-2"
          >
            <Clock3 class="size-4" aria-hidden="true" />
            <span>通电 {{ powerOnDuration(disk.powerOnHours) }}</span>
          </div>
        </div>

        <div
          v-if="usageText(disk.usedBytes, disk.totalBytes)"
          class="grid gap-2"
        >
          <div class="flex items-center justify-between gap-3 text-xs">
            <span class="text-muted-foreground">占用</span>
            <span class="text-foreground font-medium">
              {{ usageText(disk.usedBytes, disk.totalBytes) }}
            </span>
          </div>
          <Progress
            :model-value="usagePercent(disk.usedBytes, disk.totalBytes) ?? 0"
          />
        </div>

        <p
          v-if="disk.serialNumber"
          class="text-muted-foreground text-xs wrap-break-word"
        >
          序列号 {{ disk.serialNumber }}
        </p>
      </div>
    </div>
    <div v-else aria-label="正在加载指标" class="grid gap-3" role="status">
      <span class="sr-only">正在加载指标</span>
      <Skeleton class="h-24 w-full" />
      <div class="text-muted-foreground flex items-center gap-2 text-sm">
        <Activity class="size-4" aria-hidden="true" />
        等待硬盘健康数据
      </div>
    </div>
  </MetricPanel>
</template>
