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
    <CardContent class="grid gap-3 text-sm">
      <div class="flex items-center justify-between rounded-md border px-3 py-2">
        <span class="text-muted-foreground">显示名称</span>
        <span class="font-medium">{{ host.hostMetadata.displayName }}</span>
      </div>
      <div class="grid gap-2">
        <div class="rounded-md bg-muted/50 p-3">
          <Cpu class="mb-2 size-4 text-muted-foreground" aria-hidden="true" />
          <p class="text-xs text-muted-foreground">CPU</p>
          <p class="truncate font-semibold" :title="cpuModel(host)">
            {{ cpuModel(host) }}
          </p>
          <p class="mt-1 text-xs text-muted-foreground">
            {{ cpuCoreCount(host) }}
          </p>
        </div>
        <div class="rounded-md bg-muted/50 p-3">
          <MemoryStick
            class="mb-2 size-4 text-muted-foreground"
            aria-hidden="true"
          />
          <p class="text-xs text-muted-foreground">RAM</p>
          <p class="font-semibold">{{ formatBytes(memoryTotal(host)) }}</p>
        </div>
      </div>
      <div class="rounded-md border p-3">
        <p class="text-xs text-muted-foreground">主机名</p>
        <p class="mt-1 font-medium">{{ inventoryText(host, "hostname") }}</p>
      </div>
      <div class="rounded-md border p-3">
        <p class="text-xs text-muted-foreground">架构</p>
        <p class="mt-1 font-medium">{{ inventoryText(host, "architecture") }}</p>
      </div>
      <div class="rounded-md border p-3">
        <p class="text-xs text-muted-foreground">最近上报</p>
        <p class="mt-1 font-medium">{{ formatTimestamp(host.lastReportAtMs) }}</p>
      </div>
    </CardContent>
  </Card>
</template>
