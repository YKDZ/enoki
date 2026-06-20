<script setup lang="ts">
import { AlertTriangle, Download, Upload } from "@lucide/vue";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  formatBitsPerSecond,
  formatByteUsage,
  formatClockSkew,
} from "@/lib/format";
import { hostStatusText } from "@/lib/managed-host-display";
import type { ManagedHostSummary } from "../types";

const props = defineProps<{
  host: ManagedHostSummary;
}>();

defineEmits<{
  openHostDetail: [hostId: number];
}>();

function statusClass(status: string) {
  if (status === "online") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }

  if (status === "stale") {
    return "border-amber-200 bg-amber-50 text-amber-700";
  }

  return "border-slate-200 bg-slate-100 text-slate-500";
}

function progressClass(value: number | null | undefined) {
  const normalized = value ?? 0;

  if (normalized >= 75) {
    return "[&_[data-slot=progress-indicator]]:bg-red-500";
  }

  if (normalized >= 55) {
    return "[&_[data-slot=progress-indicator]]:bg-amber-500";
  }

  return "[&_[data-slot=progress-indicator]]:bg-emerald-500";
}

function metricPercent(value: number | null | undefined) {
  return value ?? 0;
}

function metricText(value: number | null | undefined) {
  return value === null || value === undefined ? "n/a" : `${value.toFixed(1)}%`;
}

function diskPercent() {
  const metrics = props.host.latestMetrics;
  if (!metrics?.diskTotalBytes || !metrics.diskUsedBytes) {
    return null;
  }

  return (metrics.diskUsedBytes / metrics.diskTotalBytes) * 100;
}

function memoryPercent() {
  const metrics = props.host.latestMetrics;
  if (!metrics?.memoryTotalBytes || !metrics.memoryUsedBytes) {
    return null;
  }

  return (metrics.memoryUsedBytes / metrics.memoryTotalBytes) * 100;
}
</script>

<template>
  <Card
    class="cursor-pointer border-slate-200 bg-card text-card-foreground transition hover:-translate-y-0.5 hover:shadow-md"
    role="button"
    tabindex="0"
    @click="$emit('openHostDetail', host.id)"
    @keydown.enter="$emit('openHostDetail', host.id)"
  >
    <CardHeader class="pb-3">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <h3 class="truncate text-base font-semibold">{{ host.displayName }}</h3>
          <p class="mt-1 truncate text-sm text-muted-foreground">
            {{ host.connectAddress }}
          </p>
        </div>
        <div class="flex flex-col items-end gap-2">
          <Badge :class="statusClass(host.status)" variant="outline">
            {{ hostStatusText(host.status) }}
          </Badge>
          <Badge
            v-if="host.clockSkew.detected"
            class="gap-1 border-amber-200 bg-amber-50 text-amber-700"
            variant="outline"
          >
            <AlertTriangle class="size-3.5" aria-hidden="true" />
            {{ formatClockSkew(host.clockSkew.lastDeltaMs) }}
          </Badge>
        </div>
      </div>
    </CardHeader>

    <CardContent class="grid gap-4">
      <div class="grid gap-3">
        <div class="grid grid-cols-[48px_1fr_112px] items-center gap-3 text-sm">
          <span class="text-muted-foreground">CPU</span>
          <Progress
            :model-value="metricPercent(host.latestMetrics?.cpuPercent)"
            :class="progressClass(host.latestMetrics?.cpuPercent)"
          />
          <span class="text-right font-medium">
            {{ metricText(host.latestMetrics?.cpuPercent) }}
          </span>
        </div>
        <div class="grid grid-cols-[48px_1fr_112px] items-center gap-3 text-sm">
          <span class="text-muted-foreground">内存</span>
          <Progress
            :model-value="metricPercent(memoryPercent())"
            :class="progressClass(memoryPercent())"
          />
          <span class="text-right text-xs font-medium leading-tight">
            {{
              formatByteUsage(
                host.latestMetrics?.memoryUsedBytes ?? null,
                host.latestMetrics?.memoryTotalBytes ?? null,
              )
            }}
          </span>
        </div>
        <div class="grid grid-cols-[48px_1fr_112px] items-center gap-3 text-sm">
          <span class="text-muted-foreground">磁盘</span>
          <Progress
            :model-value="metricPercent(diskPercent())"
            :class="progressClass(diskPercent())"
          />
          <span class="text-right font-medium">{{ metricText(diskPercent()) }}</span>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-3 text-sm">
        <div class="flex items-center gap-2 rounded-md bg-muted/50 px-3 py-2">
          <Download class="size-4 text-muted-foreground" aria-hidden="true" />
          <span class="font-medium">
            {{
              formatBitsPerSecond(
                host.latestMetrics?.networkRxBitsPerSecond ?? null,
              )
            }}
          </span>
        </div>
        <div class="flex items-center gap-2 rounded-md bg-muted/50 px-3 py-2">
          <Upload class="size-4 text-muted-foreground" aria-hidden="true" />
          <span class="font-medium">
            {{
              formatBitsPerSecond(
                host.latestMetrics?.networkTxBitsPerSecond ?? null,
              )
            }}
          </span>
        </div>
      </div>
    </CardContent>
  </Card>
</template>
