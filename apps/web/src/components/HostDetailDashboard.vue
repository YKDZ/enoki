<script setup lang="ts">
import {
  Activity,
  BatteryMedium,
  Clock3,
  Info,
  Monitor,
  Network,
  Settings,
  Server,
  Thermometer,
} from "@lucide/vue";
import type { AcceptableValue } from "reka-ui";
import { computed } from "vue";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { formatDuration, formatTemperature } from "@/lib/format";
import { hostStatusText } from "@/lib/host-display";
import type { MetricsChartData } from "@/lib/metrics-chart-data";

import type { HostDetail, HostMetricSample, MetricsWindow } from "../types";
import DeleteHostAlertDialog, {
  type DeleteHostMode,
} from "./DeleteHostAlertDialog.vue";
import HostMetricSlotGrid from "./HostMetricSlotGrid.vue";

const props = defineProps<{
  chartData: MetricsChartData;
  chartStartContinuityGapMs: number;
  deletingHostId: number | null;
  host: HostDetail;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  latestSample: HostMetricSample | null;
  samples: HostMetricSample[];
  selectedWindow: MetricsWindow;
  windowOptions: ReadonlyArray<{ label: string; value: MetricsWindow }>;
  xAxisMaxMs: number;
  xAxisMinMs: number;
}>();

const emit = defineEmits<{
  deleteHost: [host: HostDetail, mode: DeleteHostMode];
  openHostSettings: [host: HostDetail];
  switchMetricsWindow: [value: AcceptableValue];
}>();

const metadataCapabilityMetric = computed(
  () => props.host.latestMetrics ?? props.latestMetric,
);
const metadataDisplayMetric = computed(
  () => props.latestMetric ?? props.host.latestMetrics,
);
const metadataItems = computed(() =>
  [
    metadataItem(Network, "IP", props.host.connectAddress),
    metadataItem(Server, "主机名", inventoryOptionalText("hostname")),
    metadataItem(Monitor, "系统", inventoryOptionalText("os")),
    metadataItem(Info, "内核", inventoryOptionalText("kernel")),
    metadataItem(Activity, "架构", inventoryOptionalText("architecture")),
    metadataCapabilityMetric.value?.uptimeSeconds === null ||
    metadataCapabilityMetric.value?.uptimeSeconds === undefined
      ? null
      : metadataItem(
          Clock3,
          "运行时间",
          formatDuration(
            metadataDisplayMetric.value?.uptimeSeconds ??
              metadataCapabilityMetric.value.uptimeSeconds,
          ),
        ),
    metadataCapabilityMetric.value?.temperatureCelsius === null ||
    metadataCapabilityMetric.value?.temperatureCelsius === undefined
      ? null
      : metadataItem(
          Thermometer,
          "温度",
          formatTemperature(
            metadataDisplayMetric.value?.temperatureCelsius ??
              metadataCapabilityMetric.value.temperatureCelsius,
          ),
        ),
    metadataCapabilityMetric.value?.batteryPercent === null ||
    metadataCapabilityMetric.value?.batteryPercent === undefined
      ? null
      : metadataItem(
          BatteryMedium,
          "电池",
          `${metadataDisplayMetric.value?.batteryPercent ?? metadataCapabilityMetric.value.batteryPercent}%`,
        ),
    metadataItem(Activity, "探针", props.host.probeVersion),
  ].filter((item) => item !== null),
);

function metadataItem(
  icon: typeof Activity,
  label: string,
  value: string | null | undefined,
) {
  const normalized = optionalText(value);

  return normalized === null
    ? null
    : {
        icon,
        label,
        value: normalized,
      };
}

function optionalText(value: string | null | undefined) {
  if (value === null || value === undefined) {
    return null;
  }

  const normalized = value.trim();
  return normalized && normalized !== "n/a" ? normalized : null;
}

function inventoryOptionalText(key: string) {
  const value = props.host.inventory?.[key];
  return value === null || value === undefined || value === ""
    ? null
    : String(value);
}

function statusClass(status: string) {
  if (status === "online") {
    return "border-[var(--status-online-border)] bg-[var(--status-online-bg)] text-[var(--status-online-fg)]";
  }

  if (status === "stale") {
    return "border-[var(--status-stale-border)] bg-[var(--status-stale-bg)] text-[var(--status-stale-fg)]";
  }

  return "border-[var(--status-offline-border)] bg-[var(--status-offline-bg)] text-[var(--status-offline-fg)]";
}
</script>

<template>
  <section class="grid gap-4 pb-24">
    <div class="flex items-start gap-3 border-b pb-4">
      <div class="flex h-7 shrink-0 items-center">
        <Server class="size-5" aria-hidden="true" />
      </div>
      <div class="grid min-w-0 flex-1 gap-3">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <h2 class="text-xl leading-7 font-semibold wrap-break-word">
                {{ host.displayName }}
              </h2>
              <Badge :class="statusClass(host.status)" variant="outline">
                {{ hostStatusText(host.status) }}
              </Badge>
            </div>
          </div>

          <div class="flex shrink-0 items-center gap-2">
            <slot name="actions" />
            <Select
              :model-value="selectedWindow"
              @update:model-value="emit('switchMetricsWindow', $event)"
            >
              <SelectTrigger class="h-8 w-28">
                <SelectValue placeholder="时间范围" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem
                  v-for="option in windowOptions"
                  :key="option.value"
                  :value="option.value"
                >
                  {{ option.label }}
                </SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              size="sm"
              type="button"
              aria-label="设置"
              title="配置"
              @click="emit('openHostSettings', host)"
            >
              <Settings class="size-4" aria-hidden="true" />
              设置
            </Button>
            <DeleteHostAlertDialog
              :deleting-host-id="deletingHostId"
              :host="host"
              @delete-host="
                (targetHost, mode) => emit('deleteHost', targetHost, mode)
              "
            />
          </div>
        </div>

        <div
          v-if="host.description"
          class="bg-muted/35 text-muted-foreground rounded-md border px-3 py-2 text-sm wrap-break-word whitespace-normal"
        >
          {{ host.description }}
        </div>
        <div
          v-if="metadataItems.length"
          class="text-muted-foreground flex min-w-0 flex-wrap gap-x-6 gap-y-3 text-xs"
        >
          <div
            v-for="item in metadataItems"
            :key="item.label"
            class="flex min-w-0 items-center gap-2"
          >
            <component
              :is="item.icon"
              class="size-3.5 shrink-0"
              aria-hidden="true"
            />
            <span class="shrink-0">{{ item.label }}</span>
            <span class="text-foreground min-w-0 font-medium wrap-break-word">
              {{ item.value }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <HostMetricSlotGrid
      :chart-data="chartData"
      :chart-start-continuity-gap-ms="chartStartContinuityGapMs"
      :host="host"
      :latest-metric="latestMetric"
      :latest-sample="latestSample"
      :samples="samples"
      :x-axis-max-ms="xAxisMaxMs"
      :x-axis-min-ms="xAxisMinMs"
    />
  </section>
</template>
