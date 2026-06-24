<script setup lang="ts">
import {
  BatteryMedium,
  Clock3,
  Cpu,
  Download,
  MemoryStick,
  Thermometer,
  Upload,
} from "@lucide/vue";

import { Card, CardContent } from "@/components/ui/card";
import {
  formatBitsPerSecond,
  formatBytes,
  formatByteUsage,
  formatDuration,
  formatPercent,
  formatTemperature,
} from "@/lib/format";

import type { HostMetricSample, HostSummary } from "../../types";

defineProps<{
  latestMetric: HostMetricSample | HostSummary["latestMetrics"] | null;
}>();
</script>

<template>
  <Card>
    <CardContent
      class="grid grid-cols-2 gap-3 p-4 md:grid-cols-4 xl:grid-cols-7"
    >
      <div class="flex items-center gap-3">
        <div
          class="rounded-md bg-[var(--metric-cpu-bg)] p-2 text-[var(--metric-cpu-fg)]"
        >
          <Cpu class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-muted-foreground text-xs">CPU</p>
          <p class="text-lg font-semibold">
            {{ formatPercent(latestMetric?.cpuPercent ?? null) }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div
          class="rounded-md bg-[var(--metric-memory-bg)] p-2 text-[var(--metric-memory-fg)]"
        >
          <MemoryStick class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-muted-foreground text-xs">内存</p>
          <p class="text-sm font-semibold">
            {{
              formatByteUsage(
                latestMetric?.memoryUsedBytes ?? null,
                latestMetric?.memoryTotalBytes ?? null,
              )
            }}
          </p>
          <p class="text-muted-foreground text-xs">
            缓存 {{ formatBytes(latestMetric?.memoryCacheBytes ?? null) }} /
            交换
            {{
              formatByteUsage(
                latestMetric?.swapUsedBytes ?? null,
                latestMetric?.swapTotalBytes ?? null,
              )
            }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div
          class="rounded-md bg-[var(--metric-network-rx-bg)] p-2 text-[var(--metric-network-rx-fg)]"
        >
          <Download class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-muted-foreground text-xs">接收</p>
          <p class="text-lg font-semibold">
            {{
              formatBitsPerSecond(latestMetric?.networkRxBitsPerSecond ?? null)
            }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div
          class="rounded-md bg-[var(--metric-network-tx-bg)] p-2 text-[var(--metric-network-tx-fg)]"
        >
          <Upload class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-muted-foreground text-xs">发送</p>
          <p class="text-lg font-semibold">
            {{
              formatBitsPerSecond(latestMetric?.networkTxBitsPerSecond ?? null)
            }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div
          class="rounded-md bg-[var(--metric-neutral-bg)] p-2 text-[var(--metric-neutral-fg)]"
        >
          <Clock3 class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-muted-foreground text-xs">运行时间</p>
          <p class="text-sm font-semibold">
            {{ formatDuration(latestMetric?.uptimeSeconds) }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div
          class="rounded-md bg-[var(--metric-neutral-bg)] p-2 text-[var(--metric-neutral-fg)]"
        >
          <Thermometer class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-muted-foreground text-xs">温度</p>
          <p class="text-sm font-semibold">
            {{ formatTemperature(latestMetric?.temperatureCelsius ?? null) }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div
          class="rounded-md bg-[var(--metric-neutral-bg)] p-2 text-[var(--metric-neutral-fg)]"
        >
          <BatteryMedium class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-muted-foreground text-xs">电池</p>
          <p class="text-sm font-semibold">
            {{
              latestMetric?.batteryPercent === null ||
              latestMetric?.batteryPercent === undefined
                ? "n/a"
                : `${latestMetric.batteryPercent}%`
            }}
          </p>
        </div>
      </div>
    </CardContent>
  </Card>
</template>
