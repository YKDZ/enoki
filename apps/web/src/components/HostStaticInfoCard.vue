<script setup lang="ts">
import { Cpu, MemoryStick } from "@lucide/vue";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatBytes, formatTimestamp } from "@/lib/format";
import type { ManagedHostDetail } from "../types";

defineProps<{
  host: ManagedHostDetail;
}>();

defineEmits<{
  openHostMetadata: [host: ManagedHostDetail];
}>();

function inventoryText(host: ManagedHostDetail, key: string) {
  const value = host.inventory?.[key];

  if (value === null || value === undefined || value === "") {
    return "暂无";
  }

  return String(value);
}

function memoryTotal(host: ManagedHostDetail) {
  return Number(host.inventory?.memoryTotalBytes ?? 0) || null;
}

function cpuModel(host: ManagedHostDetail) {
  return host.cpuModel || "暂无型号";
}

function cpuCoreCount(host: ManagedHostDetail) {
  const value = Number(host.inventory?.cpuCount ?? 0);

  return value > 0 ? `${value} 核心` : "核心数暂无";
}
</script>

<template>
  <Card>
    <CardHeader class="flex flex-row items-center justify-between gap-3 pb-2">
      <CardTitle class="text-base">主机资料</CardTitle>
      <Button
        variant="outline"
        size="sm"
        type="button"
        @click="$emit('openHostMetadata', host)"
      >
        编辑
      </Button>
    </CardHeader>
    <CardContent class="grid min-w-0 gap-3 text-sm">
      <div
        class="flex min-w-0 items-start justify-between gap-3 rounded-md border px-3 py-2"
      >
        <span class="shrink-0 text-muted-foreground">显示名称</span>
        <span class="min-w-0 break-words text-right font-medium whitespace-normal">
          {{ host.hostMetadata.displayName }}
        </span>
      </div>
      <div class="grid gap-2">
        <div class="min-w-0 rounded-md bg-muted/50 p-3">
          <Cpu class="mb-2 size-4 text-muted-foreground" aria-hidden="true" />
          <p class="text-xs text-muted-foreground">CPU</p>
          <p
            class="min-w-0 break-words font-semibold whitespace-normal"
            :title="cpuModel(host)"
          >
            {{ cpuModel(host) }}
          </p>
          <p class="mt-1 min-w-0 break-words text-xs text-muted-foreground">
            {{ cpuCoreCount(host) }}
          </p>
        </div>
        <div class="min-w-0 rounded-md bg-muted/50 p-3">
          <MemoryStick
            class="mb-2 size-4 text-muted-foreground"
            aria-hidden="true"
          />
          <p class="text-xs text-muted-foreground">RAM</p>
          <p class="min-w-0 break-words font-semibold whitespace-normal">
            {{ formatBytes(memoryTotal(host)) }}
          </p>
        </div>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-xs text-muted-foreground">IP 地址</p>
        <p class="mt-1 min-w-0 break-words font-medium whitespace-normal">
          {{ host.connectAddress }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-xs text-muted-foreground">操作系统</p>
        <p class="mt-1 min-w-0 break-words font-medium whitespace-normal">
          {{ host.system }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-xs text-muted-foreground">主机名</p>
        <p class="mt-1 min-w-0 break-words font-medium whitespace-normal">
          {{ inventoryText(host, "hostname") }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-xs text-muted-foreground">架构</p>
        <p class="mt-1 min-w-0 break-words font-medium whitespace-normal">
          {{ inventoryText(host, "architecture") }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-xs text-muted-foreground">最近上报</p>
        <p class="mt-1 min-w-0 break-words font-medium whitespace-normal">
          {{ formatTimestamp(host.lastReportAtMs) }}
        </p>
      </div>
    </CardContent>
  </Card>
</template>
