<script setup lang="ts">
import {
  AlertTriangle,
  Cpu,
  Download,
  HardDrive,
  MemoryStick,
  Server,
  Upload,
} from "@lucide/vue";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  formatBitsPerSecond,
  formatByteUsage,
  formatClockSkew,
} from "@/lib/format";
import { hostStatusText } from "@/lib/host-display";

import type { HostSummary } from "../types";

const props = defineProps<{
  host: HostSummary;
}>();

defineEmits<{
  openHostDetail: [hostId: number];
}>();

function statusClass(status: string) {
  if (status === "online") {
    return "border-[var(--status-online-border)] bg-[var(--status-online-bg)] text-[var(--status-online-fg)]";
  }

  if (status === "stale") {
    return "border-[var(--status-stale-border)] bg-[var(--status-stale-bg)] text-[var(--status-stale-fg)]";
  }

  return "border-[var(--status-offline-border)] bg-[var(--status-offline-bg)] text-[var(--status-offline-fg)]";
}

function progressClass(value: number | null | undefined) {
  const normalized = value ?? 0;

  if (normalized >= 75) {
    return "[&_[data-slot=progress-indicator]]:bg-[var(--metric-bad)]";
  }

  if (normalized >= 55) {
    return "[&_[data-slot=progress-indicator]]:bg-[var(--metric-warn)]";
  }

  return "[&_[data-slot=progress-indicator]]:bg-[var(--metric-good)]";
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
    class="border-border bg-card text-card-foreground cursor-pointer transition hover:-translate-y-0.5 hover:shadow-md"
    role="button"
    tabindex="0"
    @click="$emit('openHostDetail', host.id)"
    @keydown.enter="$emit('openHostDetail', host.id)"
  >
    <CardHeader class="pb-3">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <div class="flex min-w-0 items-center gap-2">
            <Server
              class="text-muted-foreground size-4 shrink-0"
              aria-hidden="true"
            />
            <h3 class="text-base font-semibold break-words whitespace-normal">
              {{ host.displayName }}
            </h3>
          </div>
          <p
            v-if="host.description"
            class="text-muted-foreground mt-1 text-sm break-words whitespace-normal"
          >
            {{ host.description }}
          </p>
        </div>
        <div class="flex flex-col items-end gap-2">
          <Badge :class="statusClass(host.status)" variant="outline">
            {{ hostStatusText(host.status) }}
          </Badge>
          <Badge
            v-if="host.clockSkew.detected"
            class="gap-1 border-[var(--status-stale-border)] bg-[var(--status-stale-bg)] text-[var(--status-stale-fg)]"
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
        <div
          class="grid grid-cols-[72px_minmax(0,1fr)_max-content] items-center gap-3 text-sm"
        >
          <span class="text-muted-foreground flex items-center gap-1.5">
            <Cpu class="size-4" aria-hidden="true" />
            CPU
          </span>
          <Progress
            :model-value="metricPercent(host.latestMetrics?.cpuPercent)"
            :class="progressClass(host.latestMetrics?.cpuPercent)"
          />
          <span class="min-w-16 text-right font-medium whitespace-nowrap">
            {{ metricText(host.latestMetrics?.cpuPercent) }}
          </span>
        </div>
        <div
          class="grid grid-cols-[72px_minmax(0,1fr)_max-content] items-center gap-3 text-sm"
        >
          <span class="text-muted-foreground flex items-center gap-1.5">
            <MemoryStick class="size-4" aria-hidden="true" />
            内存
          </span>
          <Progress
            :model-value="metricPercent(memoryPercent())"
            :class="progressClass(memoryPercent())"
          />
          <span
            class="min-w-[8.75rem] text-right text-xs leading-tight font-medium whitespace-nowrap tabular-nums"
          >
            {{
              formatByteUsage(
                host.latestMetrics?.memoryUsedBytes ?? null,
                host.latestMetrics?.memoryTotalBytes ?? null,
              )
            }}
          </span>
        </div>
        <div
          class="grid grid-cols-[72px_minmax(0,1fr)_max-content] items-center gap-3 text-sm"
        >
          <span class="text-muted-foreground flex items-center gap-1.5">
            <HardDrive class="size-4" aria-hidden="true" />
            磁盘
          </span>
          <Progress
            :model-value="metricPercent(diskPercent())"
            :class="progressClass(diskPercent())"
          />
          <span class="min-w-16 text-right font-medium whitespace-nowrap">{{
            metricText(diskPercent())
          }}</span>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-3 text-sm">
        <div class="bg-muted/50 flex items-center gap-2 rounded-md px-3 py-2">
          <Download class="text-muted-foreground size-4" aria-hidden="true" />
          <span class="font-medium">
            {{
              formatBitsPerSecond(
                host.latestMetrics?.networkRxBitsPerSecond ?? null,
              )
            }}
          </span>
        </div>
        <div class="bg-muted/50 flex items-center gap-2 rounded-md px-3 py-2">
          <Upload class="text-muted-foreground size-4" aria-hidden="true" />
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
