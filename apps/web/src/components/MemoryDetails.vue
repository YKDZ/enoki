<script setup lang="ts">
import { formatBytes, formatByteUsage } from "@/lib/format";

import type { HostDetail, HostMetricSample } from "../types";

defineProps<{
  host: HostDetail;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
}>();
</script>

<template>
  <div class="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
    <div class="min-w-0">
      <p class="text-muted-foreground text-xs">已用 / 总量</p>
      <p class="font-semibold break-words">
        {{
          formatByteUsage(
            latestMetric?.memoryUsedBytes ?? null,
            latestMetric?.memoryTotalBytes ?? null,
          )
        }}
      </p>
    </div>
    <div class="min-w-0">
      <p class="text-muted-foreground text-xs">RAM 总量</p>
      <p class="font-semibold break-words">
        {{ formatBytes(Number(host.inventory?.memoryTotalBytes ?? 0) || null) }}
      </p>
    </div>
    <div
      v-if="
        latestMetric?.memoryCacheBytes !== null &&
        latestMetric?.memoryCacheBytes !== undefined
      "
      class="min-w-0"
    >
      <p class="text-muted-foreground text-xs">缓存</p>
      <p class="font-semibold break-words">
        {{ formatBytes(latestMetric.memoryCacheBytes) }}
      </p>
    </div>
    <div
      v-if="
        latestMetric?.swapTotalBytes !== null &&
        latestMetric?.swapTotalBytes !== undefined
      "
      class="min-w-0"
    >
      <p class="text-muted-foreground text-xs">Swap</p>
      <p class="font-semibold break-words">
        {{
          formatByteUsage(
            latestMetric?.swapUsedBytes ?? null,
            latestMetric.swapTotalBytes,
          )
        }}
      </p>
    </div>
  </div>
</template>
