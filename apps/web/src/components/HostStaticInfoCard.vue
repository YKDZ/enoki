<script setup lang="ts">
import { Cpu, MemoryStick } from "@lucide/vue";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatBytes, formatTimestamp } from "@/lib/format";

import type { HostDetail } from "../types";

defineProps<{
  host: HostDetail;
}>();

defineEmits<{
  openHostMetadata: [host: HostDetail];
}>();

function inventoryText(host: HostDetail, key: string) {
  const value = host.inventory?.[key];

  if (value === null || value === undefined || value === "") {
    return "暂无";
  }

  return String(value);
}

function memoryTotal(host: HostDetail) {
  return Number(host.inventory?.memoryTotalBytes ?? 0) || null;
}

function cpuModel(host: HostDetail) {
  return host.cpuModel || "暂无型号";
}

function cpuCoreCount(host: HostDetail) {
  const value = Number(host.inventory?.cpuCount ?? 0);

  return value > 0 ? `${value} 核心` : "核心数暂无";
}

function probeVersionText(value: string | null) {
  return value?.trim() || "暂无";
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
        <span class="text-muted-foreground shrink-0">显示名称</span>
        <span
          class="min-w-0 text-right font-medium break-words whitespace-normal"
        >
          {{ host.hostMetadata.displayName }}
        </span>
      </div>
      <div class="grid gap-2">
        <div class="bg-muted/50 min-w-0 rounded-md p-3">
          <Cpu class="text-muted-foreground mb-2 size-4" aria-hidden="true" />
          <p class="text-muted-foreground text-xs">CPU</p>
          <p
            class="min-w-0 font-semibold break-words whitespace-normal"
            :title="cpuModel(host)"
          >
            {{ cpuModel(host) }}
          </p>
          <p class="text-muted-foreground mt-1 min-w-0 text-xs break-words">
            {{ cpuCoreCount(host) }}
          </p>
        </div>
        <div class="bg-muted/50 min-w-0 rounded-md p-3">
          <MemoryStick
            class="text-muted-foreground mb-2 size-4"
            aria-hidden="true"
          />
          <p class="text-muted-foreground text-xs">RAM</p>
          <p class="min-w-0 font-semibold break-words whitespace-normal">
            {{ formatBytes(memoryTotal(host)) }}
          </p>
        </div>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-muted-foreground text-xs">IP 地址</p>
        <p class="mt-1 min-w-0 font-medium break-words whitespace-normal">
          {{ host.connectAddress }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-muted-foreground text-xs">操作系统</p>
        <p class="mt-1 min-w-0 font-medium break-words whitespace-normal">
          {{ host.system }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-muted-foreground text-xs">主机名</p>
        <p class="mt-1 min-w-0 font-medium break-words whitespace-normal">
          {{ inventoryText(host, "hostname") }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-muted-foreground text-xs">架构</p>
        <p class="mt-1 min-w-0 font-medium break-words whitespace-normal">
          {{ inventoryText(host, "architecture") }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-muted-foreground text-xs">当前探针版本</p>
        <p class="mt-1 min-w-0 font-medium break-words whitespace-normal">
          {{
            probeVersionText(host.probeUpgradeEligibility.currentProbeVersion)
          }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-muted-foreground text-xs">Hub 当前探针资产版本</p>
        <p class="mt-1 min-w-0 font-medium break-words whitespace-normal">
          {{
            probeVersionText(
              host.probeUpgradeEligibility.currentProbeAssetSetVersion,
            )
          }}
        </p>
      </div>
      <div class="min-w-0 rounded-md border p-3">
        <p class="text-muted-foreground text-xs">最近上报</p>
        <p class="mt-1 min-w-0 font-medium break-words whitespace-normal">
          {{ formatTimestamp(host.lastReportAtMs) }}
        </p>
      </div>
    </CardContent>
  </Card>
</template>
