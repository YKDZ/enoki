<script setup lang="ts">
import { AlertTriangle, ArrowLeft, LoaderCircle, Settings } from "@lucide/vue";
import { computed, onMounted } from "vue";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { useManagedHostDetail } from "@/composables/useManagedHostDetail";
import { formatBitsPerSecond, formatPercent } from "@/lib/format";
import { hostStatusText, warningTitle } from "@/lib/managed-host-display";
import { buildMetricsChartData } from "@/lib/metrics-chart-data";
import type {
  HostMetadataDraft,
  HostProbeConfigurationResponse,
  ManagedHostDetail,
} from "../types";
import DeleteHostAlertDialog from "./DeleteHostAlertDialog.vue";
import HostMetadataDialog from "./HostMetadataDialog.vue";
import HostMetricsSummary from "./HostMetricsSummary.vue";
import HostProbeConfigurationDialog from "./HostProbeConfigurationDialog.vue";
import HostResourcePanels from "./HostResourcePanels.vue";
import HostStaticInfoCard from "./HostStaticInfoCard.vue";
import MetricsChart from "./MetricsChart.vue";

const props = defineProps<{
  activeHostConfigurationId: number | null;
  activeHostMetadataId: number | null;
  deletingHostId: number | null;
  detail: ReturnType<typeof useManagedHostDetail>;
  hostConfigurationDraft: HostProbeConfigurationResponse | null;
  hostConfigurationError: string;
  hostMetadataDraft: HostMetadataDraft | null;
  hostMetadataError: string;
  isSavingHostConfiguration: boolean;
  isSavingHostMetadata: boolean;
}>();

const emit = defineEmits<{
  back: [];
  deleteHost: [host: ManagedHostDetail];
  openHostConfiguration: [hostId: number];
  openHostMetadata: [host: ManagedHostDetail];
  saveHostConfiguration: [];
  saveHostMetadata: [];
}>();

const windowOptions = [
  {
    label: "1 小时",
    value: "1h",
  },
  {
    label: "6 小时",
    value: "6h",
  },
  {
    label: "24 小时",
    value: "24h",
  },
  {
    label: "7 天",
    value: "7d",
  },
] as const;

const chartData = computed(() =>
  buildMetricsChartData(props.detail.samples.value),
);
const host = computed(() => props.detail.host.value);
const latestSample = computed(() => props.detail.samples.value.at(-1) ?? null);
const latestMetric = computed(
  () => latestSample.value ?? host.value?.latestMetrics ?? null,
);

onMounted(() => {
  void props.detail.load();
});

function statusClass(status: string) {
  if (status === "online") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }

  if (status === "stale") {
    return "border-amber-200 bg-amber-50 text-amber-700";
  }

  return "border-slate-200 bg-slate-100 text-slate-500";
}
</script>

<template>
  <section class="mx-auto max-w-7xl px-5 py-5">
    <div
      v-if="detail.isLoading.value && !host"
      class="grid place-items-center py-24"
      aria-live="polite"
    >
      <LoaderCircle class="text-primary size-8 animate-spin" />
    </div>

    <Alert v-else-if="detail.error.value" class="border-red-200 bg-red-50">
      <AlertTriangle class="size-4" aria-hidden="true" />
      <AlertTitle>无法加载</AlertTitle>
      <AlertDescription>{{ detail.error.value }}</AlertDescription>
    </Alert>

    <div v-else-if="host" class="grid gap-4">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b pb-4">
        <div class="flex min-w-0 items-center gap-3">
          <Button
            variant="ghost"
            size="icon"
            type="button"
            aria-label="返回"
            title="返回"
            @click="emit('back')"
          >
            <ArrowLeft class="size-4" aria-hidden="true" />
          </Button>
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <h2 class="truncate text-xl font-semibold">{{ host.displayName }}</h2>
              <Badge :class="statusClass(host.status)" variant="outline">
                {{ hostStatusText(host.status) }}
              </Badge>
            </div>
            <p
              v-if="host.description"
              class="mt-1 max-w-3xl break-words text-sm text-muted-foreground whitespace-normal"
            >
              {{ host.description }}
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <Select
            :model-value="detail.selectedWindow.value"
            @update:model-value="
              (value) =>
                detail.switchWindow(value as typeof detail.selectedWindow.value)
            "
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
            size="icon-sm"
            type="button"
            aria-label="配置"
            title="配置"
            @click="emit('openHostConfiguration', host.id)"
          >
            <Settings class="size-4" aria-hidden="true" />
          </Button>
          <DeleteHostAlertDialog
            :deleting-host-id="deletingHostId"
            :host="host"
            @delete-host="emit('deleteHost', $event)"
          />
        </div>
      </div>

      <Alert
        v-for="warning in host.warnings"
        :key="`${warning.code}-${warning.occurredAtMs ?? 0}`"
        class="border-amber-200 bg-amber-50"
      >
        <AlertTriangle class="size-4" aria-hidden="true" />
        <AlertTitle>{{ warningTitle(warning.code) }}</AlertTitle>
        <AlertDescription>{{ warning.message }}</AlertDescription>
      </Alert>

      <HostMetricsSummary :latest-metric="latestMetric" />

      <div class="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div class="grid gap-4">
          <Card>
            <CardContent class="p-4">
              <Tabs default-value="overview">
                <TabsList class="h-8 bg-muted">
                  <TabsTrigger value="overview" class="h-7">概览</TabsTrigger>
                  <TabsTrigger value="cpu" class="h-7">CPU</TabsTrigger>
                  <TabsTrigger value="disk" class="h-7">磁盘</TabsTrigger>
                  <TabsTrigger value="network" class="h-7">网络</TabsTrigger>
                </TabsList>
                <TabsContent value="overview" class="mt-4 grid gap-4 lg:grid-cols-2">
                  <MetricsChart
                    :series="[chartData.cpu.aggregate]"
                    title="CPU"
                    :x-axis-max-ms="detail.chartRange.value.maxMs"
                    :x-axis-min-ms="detail.chartRange.value.minMs"
                    y-axis-name="%"
                    :value-formatter="formatPercent"
                  />
                  <MetricsChart
                    :series="[chartData.memory.usedPercent]"
                    title="内存"
                    :x-axis-max-ms="detail.chartRange.value.maxMs"
                    :x-axis-min-ms="detail.chartRange.value.minMs"
                    y-axis-name="%"
                    :value-formatter="formatPercent"
                  />
                  <MetricsChart
                    :series="[chartData.disk.aggregateUsedPercent]"
                    title="磁盘"
                    :x-axis-max-ms="detail.chartRange.value.maxMs"
                    :x-axis-min-ms="detail.chartRange.value.minMs"
                    y-axis-name="%"
                    :value-formatter="formatPercent"
                  />
                  <MetricsChart
                    :series="chartData.network.aggregate"
                    title="网络吞吐量"
                    :x-axis-max-ms="detail.chartRange.value.maxMs"
                    :x-axis-min-ms="detail.chartRange.value.minMs"
                    y-axis-name="b/s"
                    :value-formatter="formatBitsPerSecond"
                  />
                </TabsContent>
                <TabsContent value="cpu" class="mt-4">
                  <HostResourcePanels
                    panel="cpu"
                    :aggregate-disk-series="chartData.disk.aggregateUsedPercent"
                    :aggregate-network-series="chartData.network.aggregate"
                    :cpu-core-series="chartData.cpu.cores"
                    :cpu-model="host.cpuModel"
                    :inventory="host.inventory"
                    :latest-sample="latestSample"
                    :x-axis-max-ms="detail.chartRange.value.maxMs"
                    :x-axis-min-ms="detail.chartRange.value.minMs"
                  />
                </TabsContent>
                <TabsContent value="disk" class="mt-4">
                  <HostResourcePanels
                    panel="disk"
                    :aggregate-disk-series="chartData.disk.aggregateUsedPercent"
                    :aggregate-network-series="chartData.network.aggregate"
                    :cpu-core-series="chartData.cpu.cores"
                    :cpu-model="host.cpuModel"
                    :inventory="host.inventory"
                    :latest-sample="latestSample"
                    :x-axis-max-ms="detail.chartRange.value.maxMs"
                    :x-axis-min-ms="detail.chartRange.value.minMs"
                  />
                </TabsContent>
                <TabsContent value="network" class="mt-4">
                  <HostResourcePanels
                    panel="network"
                    :aggregate-disk-series="chartData.disk.aggregateUsedPercent"
                    :aggregate-network-series="chartData.network.aggregate"
                    :cpu-core-series="chartData.cpu.cores"
                    :cpu-model="host.cpuModel"
                    :inventory="host.inventory"
                    :latest-sample="latestSample"
                    :x-axis-max-ms="detail.chartRange.value.maxMs"
                    :x-axis-min-ms="detail.chartRange.value.minMs"
                  />
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>

        <HostStaticInfoCard
          :host="host"
          @open-host-metadata="emit('openHostMetadata', $event)"
        />
      </div>

      <HostMetadataDialog
        :active-host-metadata-id="activeHostMetadataId"
        :host="host"
        :host-metadata-draft="hostMetadataDraft"
        :host-metadata-error="hostMetadataError"
        :is-saving-host-metadata="isSavingHostMetadata"
        @close-host-metadata="emit('openHostMetadata', $event)"
        @save-host-metadata="emit('saveHostMetadata')"
      />
      <HostProbeConfigurationDialog
        :active-host-configuration-id="activeHostConfigurationId"
        :host="host"
        :host-configuration-draft="hostConfigurationDraft"
        :host-configuration-error="hostConfigurationError"
        :is-saving-host-configuration="isSavingHostConfiguration"
        @close-host-configuration="emit('openHostConfiguration', $event)"
        @save-host-configuration="emit('saveHostConfiguration')"
      />
    </div>
  </section>
</template>
