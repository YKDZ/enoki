<script setup lang="ts">
import { Clock3, Cpu, Download, MemoryStick, Upload } from "@lucide/vue";

import { Card, CardContent } from "@/components/ui/card";
import {
  formatBitsPerSecond,
  formatByteUsage,
  formatDuration,
  formatPercent,
} from "@/lib/format";
import type { ManagedHostMetricSample, ManagedHostSummary } from "../types";

defineProps<{
  latestMetric:
    | ManagedHostMetricSample
    | ManagedHostSummary["latestMetrics"]
    | null;
}>();
</script>

<template>
  <Card>
    <CardContent class="grid gap-4 p-4 md:grid-cols-5">
      <div class="flex items-center gap-3">
        <div class="rounded-md bg-emerald-50 p-2 text-emerald-700">
          <Cpu class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-xs text-muted-foreground">CPU</p>
          <p class="text-lg font-semibold">
            {{ formatPercent(latestMetric?.cpuPercent ?? null) }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div class="rounded-md bg-sky-50 p-2 text-sky-700">
          <MemoryStick class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-xs text-muted-foreground">内存</p>
          <p class="text-sm font-semibold">
            {{
              formatByteUsage(
                latestMetric?.memoryUsedBytes ?? null,
                latestMetric?.memoryTotalBytes ?? null,
              )
            }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div class="rounded-md bg-violet-50 p-2 text-violet-700">
          <Download class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-xs text-muted-foreground">接收</p>
          <p class="text-lg font-semibold">
            {{
              formatBitsPerSecond(
                latestMetric?.networkRxBitsPerSecond ?? null,
              )
            }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div class="rounded-md bg-amber-50 p-2 text-amber-700">
          <Upload class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-xs text-muted-foreground">发送</p>
          <p class="text-lg font-semibold">
            {{
              formatBitsPerSecond(
                latestMetric?.networkTxBitsPerSecond ?? null,
              )
            }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div class="rounded-md bg-slate-100 p-2 text-slate-700">
          <Clock3 class="size-4" aria-hidden="true" />
        </div>
        <div>
          <p class="text-xs text-muted-foreground">运行时间</p>
          <p class="text-sm font-semibold">
            {{ formatDuration(latestMetric?.uptimeSeconds) }}
          </p>
        </div>
      </div>
    </CardContent>
  </Card>
</template>
