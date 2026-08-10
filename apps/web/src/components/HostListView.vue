<script setup lang="ts">
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Cpu,
  Download,
  HardDrive,
  MemoryStick,
  Server,
  Upload,
} from "@lucide/vue";
import {
  computed,
  defineComponent,
  h,
  type Component,
  type PropType,
} from "vue";

import { Badge } from "@/components/ui/badge";
import {
  formatBitsPerSecond,
  formatByteUsage,
  formatDuration,
} from "@/lib/format";
import { hostStatusText } from "@/lib/host-display";
import { sortHostsForOverview } from "@/lib/ready-host-reveal";

import type { HostSummary } from "../types";

export type HostListSortKey =
  | "cpu"
  | "disk"
  | "memory"
  | "name"
  | "rx"
  | "tx"
  | "uptime";
export type HostListSortDirection = "asc" | "desc";

const props = defineProps<{
  hosts: HostSummary[];
  highlightedHostId?: number | null;
  page: number;
  pageSize: number;
}>();

defineEmits<{
  openHostDetail: [hostId: number];
}>();

const sortKey = defineModel<HostListSortKey | null>("sortKey", {
  required: true,
});
const sortDirection = defineModel<HostListSortDirection>("sortDirection", {
  required: true,
});

const columns: Array<{ key: HostListSortKey; label: string }> = [
  { key: "name", label: "主机" },
  { key: "cpu", label: "CPU" },
  { key: "memory", label: "内存" },
  { key: "disk", label: "磁盘" },
  { key: "rx", label: "接收" },
  { key: "tx", label: "发送" },
  { key: "uptime", label: "运行时间" },
];

const MetricInline = defineComponent({
  props: {
    icon: {
      required: true,
      type: [Object, Function] as PropType<Component>,
    },
    text: {
      required: true,
      type: String,
    },
  },
  setup(metricProps) {
    return () =>
      h("span", { class: "flex min-w-0 items-center gap-1.5 text-sm" }, [
        h(metricProps.icon, {
          "aria-hidden": "true",
          class: "text-muted-foreground size-4 shrink-0",
        }),
        h(
          "span",
          { class: "min-w-0 truncate font-medium tabular-nums" },
          metricProps.text,
        ),
      ]);
  },
});

const sortedHosts = computed(() => {
  return sortHostsForOverview(props.hosts, sortKey.value, sortDirection.value);
});
const visibleHosts = computed(() => {
  const start = (props.page - 1) * props.pageSize;

  return sortedHosts.value.slice(start, start + props.pageSize);
});

function setSort(nextKey: HostListSortKey) {
  if (sortKey.value !== nextKey) {
    sortKey.value = nextKey;
    sortDirection.value = "asc";
    return;
  }

  if (sortDirection.value === "asc") {
    sortDirection.value = "desc";
    return;
  }

  sortKey.value = null;
  sortDirection.value = "asc";
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

function diskPercent(host: HostSummary) {
  const metrics = host.latestMetrics;
  if (!metrics?.diskTotalBytes || !metrics.diskUsedBytes) {
    return null;
  }

  return (metrics.diskUsedBytes / metrics.diskTotalBytes) * 100;
}

function memoryPercent(host: HostSummary) {
  const metrics = host.latestMetrics;
  if (!metrics?.memoryTotalBytes || !metrics.memoryUsedBytes) {
    return null;
  }

  return (metrics.memoryUsedBytes / metrics.memoryTotalBytes) * 100;
}

function percentText(value: number | null | undefined) {
  return value === null || value === undefined ? "n/a" : `${value.toFixed(1)}%`;
}

function SortIcon(key: HostListSortKey) {
  if (sortKey.value !== key) {
    return ArrowUpDown;
  }

  return sortDirection.value === "asc" ? ArrowUp : ArrowDown;
}
</script>

<template>
  <div class="overflow-x-auto">
    <div class="grid min-w-[980px] gap-2">
      <div
        class="text-muted-foreground grid grid-cols-[minmax(250px,1.25fr)_minmax(72px,.55fr)_minmax(180px,1.25fr)_minmax(72px,.55fr)_repeat(2,minmax(100px,.75fr))_minmax(92px,.7fr)] gap-3 px-3 text-xs font-medium"
      >
        <button
          v-for="column in columns"
          :key="column.key"
          type="button"
          class="hover:text-foreground flex items-center gap-1 text-left"
          @click="setSort(column.key)"
        >
          {{ column.label }}
          <component :is="SortIcon(column.key)" class="size-3" />
        </button>
      </div>
      <button
        v-for="host in visibleHosts"
        :key="host.id"
        type="button"
        :data-enoki-host-id="host.id"
        :class="[
          'bg-card text-card-foreground hover:bg-accent/40 grid grid-cols-[minmax(250px,1.25fr)_minmax(72px,.55fr)_minmax(180px,1.25fr)_minmax(72px,.55fr)_repeat(2,minmax(100px,.75fr))_minmax(92px,.7fr)] items-center gap-3 rounded-md border px-3 py-3 text-left transition',
          host.id === highlightedHostId && 'ring-primary ring-2 ring-offset-2',
        ]"
        @click="$emit('openHostDetail', host.id)"
      >
        <div class="min-w-0">
          <div class="flex items-center gap-2 font-medium">
            <Server
              class="text-muted-foreground size-4 shrink-0"
              aria-hidden="true"
            />
            <span class="wrap-break-word whitespace-normal">{{
              host.displayName
            }}</span>
            <Badge :class="statusClass(host.status)" variant="outline">
              {{ hostStatusText(host.status) }}
            </Badge>
          </div>
          <p
            v-if="host.description"
            class="text-muted-foreground mt-1 text-xs wrap-break-word whitespace-normal"
          >
            {{ host.description }}
          </p>
        </div>
        <MetricInline
          :icon="Cpu"
          :text="percentText(host.latestMetrics?.cpuPercent)"
        />
        <MetricInline
          :icon="MemoryStick"
          :text="
            formatByteUsage(
              host.latestMetrics?.memoryUsedBytes ?? null,
              host.latestMetrics?.memoryTotalBytes ?? null,
            )
          "
        />
        <MetricInline
          :icon="HardDrive"
          :text="percentText(diskPercent(host))"
        />
        <MetricInline
          :icon="Download"
          :text="
            formatBitsPerSecond(
              host.latestMetrics?.networkRxBitsPerSecond ?? null,
            )
          "
        />
        <MetricInline
          :icon="Upload"
          :text="
            formatBitsPerSecond(
              host.latestMetrics?.networkTxBitsPerSecond ?? null,
            )
          "
        />
        <span class="text-sm font-medium">{{
          formatDuration(host.latestMetrics?.uptimeSeconds)
        }}</span>
      </button>
    </div>
  </div>
</template>
