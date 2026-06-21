<script setup lang="ts">
import { AlertTriangle, ArrowLeft, LoaderCircle, Settings } from "@lucide/vue";
import type { AcceptableValue } from "reka-ui";
import { computed, onMounted, ref, watch } from "vue";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "@/components/ui/sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { useHostDetail } from "@/composables/useHostDetail";
import { formatBitsPerSecond, formatPercent } from "@/lib/format";
import { hostStatusText, warningTitle } from "@/lib/host-display";
import { buildMetricsChartData } from "@/lib/metrics-chart-data";

import type {
  HostMetadataDraft,
  HostProbeConfigurationResponse,
  HostDetail,
  MetricsWindow,
} from "../types";
import DeleteHostAlertDialog from "./DeleteHostAlertDialog.vue";
import HostDetailSkeleton from "./HostDetailSkeleton.vue";
import HostMetadataDialog from "./HostMetadataDialog.vue";
import HostMetricsSummary from "./HostMetricsSummary.vue";
import HostProbeConfigurationDialog from "./HostProbeConfigurationDialog.vue";
import HostResourcePanels from "./HostResourcePanels.vue";
import HostStaticInfoCard from "./HostStaticInfoCard.vue";
import MetricsChart from "./MetricsChart.vue";
import StateHero from "./StateHero.vue";

const props = defineProps<{
  activeHostConfigurationId: number | null;
  activeHostMetadataId: number | null;
  deletingHostId: number | null;
  detail: ReturnType<typeof useHostDetail>;
  hostConfigurationDraft: HostProbeConfigurationResponse | null;
  hostConfigurationError: string;
  hostMetadataDraft: HostMetadataDraft | null;
  hostMetadataError: string;
  isSavingHostConfiguration: boolean;
  isSavingHostMetadata: boolean;
}>();

const emit = defineEmits<{
  back: [];
  deleteHost: [host: HostDetail];
  openHostConfiguration: [hostId: number];
  openHostMetadata: [host: HostDetail];
  saveHostConfiguration: [];
  saveHostMetadata: [];
}>();

const windowOptions = [
  {
    label: "1 分钟",
    value: "1m",
  },
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
const windowValues = new Set<MetricsWindow>(
  windowOptions.map((option) => option.value),
);
const isProbeUpgradeDialogOpen = ref(false);

const chartData = computed(() =>
  buildMetricsChartData(props.detail.samples.value),
);
const host = computed(() => props.detail.host.value);
const latestSample = computed(() => props.detail.samples.value.at(-1) ?? null);
const latestMetric = computed(
  () => latestSample.value ?? host.value?.latestMetrics ?? null,
);
const probeUpgradeEligibility = computed(
  () => host.value?.probeUpgradeEligibility ?? null,
);
const probeUpgradeStatus = computed(
  () => host.value?.probeUpgradeStatus ?? null,
);
const isProbeUpgradeActive = computed(() =>
  ["pending", "accepted", "running"].includes(
    probeUpgradeStatus.value?.state ?? "",
  ),
);
const probeUpgradeTargetVersion = computed(
  () =>
    probeUpgradeStatus.value?.targetProbeVersion ??
    probeUpgradeEligibility.value?.currentProbeAssetSetVersion ??
    "",
);
const canCreateProbeUpgradeRequest = computed(
  () =>
    Boolean(probeUpgradeEligibility.value?.isUpgradeable) &&
    !isProbeUpgradeActive.value &&
    !props.detail.isCreatingProbeUpgradeRequest.value,
);

onMounted(() => {
  void props.detail.load();
});

watch(
  () => probeUpgradeStatus.value,
  (status, previousStatus) => {
    if (
      status?.state !== "failed" ||
      status.id === previousStatus?.id ||
      !status.failure
    ) {
      return;
    }

    toast.error("Probe 升级失败", {
      description: status.failure.message || status.failure.code,
    });
  },
);

function statusClass(status: string) {
  if (status === "online") {
    return "border-[var(--status-online-border)] bg-[var(--status-online-bg)] text-[var(--status-online-fg)]";
  }

  if (status === "stale") {
    return "border-[var(--status-stale-border)] bg-[var(--status-stale-bg)] text-[var(--status-stale-fg)]";
  }

  return "border-[var(--status-offline-border)] bg-[var(--status-offline-bg)] text-[var(--status-offline-fg)]";
}

function switchMetricsWindow(value: AcceptableValue) {
  if (!isMetricsWindow(value)) {
    return;
  }

  void props.detail.switchWindow(value);
}

function isMetricsWindow(value: AcceptableValue): value is MetricsWindow {
  return typeof value === "string" && windowValues.has(value as MetricsWindow);
}

async function createProbeUpgradeRequest() {
  try {
    await props.detail.createProbeUpgradeRequest();
    isProbeUpgradeDialogOpen.value = false;
  } catch {
    toast.error("无法创建 Probe Upgrade Request", {
      description: "请稍后重试。",
    });
  }
}
</script>

<template>
  <section class="mx-auto max-w-7xl px-5 py-5">
    <HostDetailSkeleton v-if="detail.isLoading.value && !host" />

    <StateHero
      v-else-if="detail.error.value"
      :icon="AlertTriangle"
      tone="destructive"
      title="无法加载"
      :description="detail.error.value"
    >
      <template #action>
        <Button type="button" variant="outline" @click="emit('back')">
          <ArrowLeft class="size-4" aria-hidden="true" />
          返回首页
        </Button>
        <Button type="button" @click="detail.load()">
          <LoaderCircle
            v-if="detail.isLoading.value"
            class="size-4 animate-spin"
            aria-hidden="true"
          />
          重试
        </Button>
      </template>
    </StateHero>

    <div v-else-if="host" class="grid gap-4">
      <div
        class="flex flex-wrap items-center justify-between gap-3 border-b pb-4"
      >
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
              <h2 class="truncate text-xl font-semibold">
                {{ host.displayName }}
              </h2>
              <Badge :class="statusClass(host.status)" variant="outline">
                {{ hostStatusText(host.status) }}
              </Badge>
            </div>
            <p
              v-if="host.description"
              class="text-muted-foreground mt-1 max-w-3xl text-sm wrap-break-word whitespace-normal"
            >
              {{ host.description }}
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <Dialog
            v-if="probeUpgradeEligibility"
            v-model:open="isProbeUpgradeDialogOpen"
          >
            <DialogTrigger as-child>
              <Button
                variant="outline"
                size="sm"
                type="button"
                class="relative"
                :disabled="!canCreateProbeUpgradeRequest"
                title="Probe 升级"
              >
                <LoaderCircle
                  v-if="
                    isProbeUpgradeActive ||
                    detail.isCreatingProbeUpgradeRequest.value
                  "
                  class="text-muted-foreground size-4 animate-spin"
                  aria-hidden="true"
                />
                <span
                  v-if="
                    probeUpgradeEligibility.isUpgradeable &&
                    !isProbeUpgradeActive
                  "
                  class="absolute -top-1 -right-1 size-2.5 rounded-full bg-red-500"
                  aria-hidden="true"
                />
                <span
                  v-if="
                    probeUpgradeEligibility.isUpgradeable &&
                    !isProbeUpgradeActive
                  "
                  class="sr-only"
                >
                  Probe 可升级，确认 Probe 升级，将此 Host 的 Probe 升级到
                  {{ probeUpgradeTargetVersion }}
                </span>
                {{
                  isProbeUpgradeActive ||
                  detail.isCreatingProbeUpgradeRequest.value
                    ? "Probe 升级中"
                    : "Probe 升级"
                }}
              </Button>
            </DialogTrigger>
            <DialogContent force-mount>
              <DialogHeader>
                <DialogTitle>确认 Probe 升级</DialogTitle>
                <DialogDescription>
                  将此 Host 的 Probe 升级到 {{ probeUpgradeTargetVersion }}。
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  @click="isProbeUpgradeDialogOpen = false"
                >
                  返回
                </Button>
                <Button
                  type="button"
                  :disabled="detail.isCreatingProbeUpgradeRequest.value"
                  @click="createProbeUpgradeRequest"
                >
                  <LoaderCircle
                    v-if="detail.isCreatingProbeUpgradeRequest.value"
                    class="size-4 animate-spin"
                    aria-hidden="true"
                  />
                  确认升级
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
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
        <div class="order-2 min-w-0 xl:order-1">
          <Tabs default-value="overview">
            <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
              <TabsList class="bg-muted h-8">
                <TabsTrigger value="overview" class="h-7">概览</TabsTrigger>
                <TabsTrigger value="cpu" class="h-7">CPU</TabsTrigger>
                <TabsTrigger value="disk" class="h-7">磁盘</TabsTrigger>
                <TabsTrigger value="network" class="h-7">网络</TabsTrigger>
              </TabsList>
              <Select
                :model-value="detail.selectedWindow.value"
                @update:model-value="switchMetricsWindow"
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
            </div>

            <Alert v-if="detail.metricsError?.value" class="mb-4">
              <AlertTriangle class="size-4" aria-hidden="true" />
              <AlertTitle>历史指标暂时不可用</AlertTitle>
              <AlertDescription class="flex flex-wrap items-center gap-3">
                <span>{{ detail.metricsError?.value }}</span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  @click="detail.switchWindow(detail.selectedWindow.value)"
                >
                  重试
                </Button>
              </AlertDescription>
            </Alert>

            <TabsContent
              value="overview"
              class="mt-0 grid gap-4 lg:grid-cols-2"
            >
              <MetricsChart
                :series="[chartData.cpu.aggregate]"
                title="CPU"
                :x-axis-max-ms="detail.chartRange.value.maxMs"
                :x-axis-min-ms="detail.chartRange.value.minMs"
                :y-axis-max="100"
                :y-axis-min="0"
                y-axis-name="%"
                :value-formatter="formatPercent"
              />
              <MetricsChart
                :series="[chartData.memory.usedPercent]"
                title="内存"
                :x-axis-max-ms="detail.chartRange.value.maxMs"
                :x-axis-min-ms="detail.chartRange.value.minMs"
                :y-axis-max="100"
                :y-axis-min="0"
                y-axis-name="%"
                :value-formatter="formatPercent"
              />
              <MetricsChart
                :series="[chartData.disk.aggregateUsedPercent]"
                title="磁盘"
                :x-axis-max-ms="detail.chartRange.value.maxMs"
                :x-axis-min-ms="detail.chartRange.value.minMs"
                :y-axis-max="100"
                :y-axis-min="0"
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
            <TabsContent value="cpu" class="mt-0">
              <HostResourcePanels
                panel="cpu"
                :aggregate-disk-series="chartData.disk.aggregateUsedPercent"
                :aggregate-network-series="chartData.network.aggregate"
                :cpu-core-series="chartData.cpu.cores"
                :cpu-model="host.cpuModel"
                :inventory="host.inventory"
                :latest-sample="latestSample"
                :samples="detail.samples.value"
                :x-axis-max-ms="detail.chartRange.value.maxMs"
                :x-axis-min-ms="detail.chartRange.value.minMs"
              />
            </TabsContent>
            <TabsContent value="disk" class="mt-0">
              <HostResourcePanels
                panel="disk"
                :aggregate-disk-series="chartData.disk.aggregateUsedPercent"
                :aggregate-network-series="chartData.network.aggregate"
                :cpu-core-series="chartData.cpu.cores"
                :cpu-model="host.cpuModel"
                :inventory="host.inventory"
                :latest-sample="latestSample"
                :samples="detail.samples.value"
                :x-axis-max-ms="detail.chartRange.value.maxMs"
                :x-axis-min-ms="detail.chartRange.value.minMs"
              />
            </TabsContent>
            <TabsContent value="network" class="mt-0">
              <HostResourcePanels
                panel="network"
                :aggregate-disk-series="chartData.disk.aggregateUsedPercent"
                :aggregate-network-series="chartData.network.aggregate"
                :cpu-core-series="chartData.cpu.cores"
                :cpu-model="host.cpuModel"
                :inventory="host.inventory"
                :latest-sample="latestSample"
                :samples="detail.samples.value"
                :x-axis-max-ms="detail.chartRange.value.maxMs"
                :x-axis-min-ms="detail.chartRange.value.minMs"
              />
            </TabsContent>
          </Tabs>
        </div>

        <HostStaticInfoCard
          class="order-1 xl:order-2"
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
