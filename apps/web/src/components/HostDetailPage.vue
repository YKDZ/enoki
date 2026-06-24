<script setup lang="ts">
import {
  AlertTriangle,
  ArrowLeft,
  LoaderCircle,
  CircleArrowUp,
} from "@lucide/vue";
import type { AcceptableValue } from "reka-ui";
import { computed, onMounted, ref, watch } from "vue";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "@/components/ui/sonner";
import type { useHostDetail } from "@/composables/useHostDetail";
import { warningTitle } from "@/lib/host-display";
import { buildMetricsChartData } from "@/metrics/chart-data";
import { latestMetricsFromSample } from "@/metrics/latest-metrics";

import type {
  HostMetadataDraft,
  HostProbeConfigurationResponse,
  HostDetail,
  MetricsWindow,
} from "../types";
import type { DeleteHostMode } from "./DeleteHostAlertDialog.vue";
import HostDetailDashboard from "./HostDetailDashboard.vue";
import HostDetailSkeleton from "./HostDetailSkeleton.vue";
import HostSettingsDialog from "./HostSettingsDialog.vue";
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
  deleteHost: [host: HostDetail, mode: DeleteHostMode];
  openHostConfiguration: [hostId: number];
  openHostMetadata: [host: HostDetail];
  probeUpgradeRequested: [
    hostId: number,
    status: NonNullable<HostDetail["probeUpgradeStatus"]>,
  ];
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
const visibleWarnings = computed(
  () =>
    host.value?.warnings.filter((warning) => warning.code !== "clock_skew") ??
    [],
);
const latestSample = computed(() => props.detail.samples.value.at(-1) ?? null);
const latestMetric = computed(() => {
  if (!latestSample.value) {
    return host.value?.latestMetrics ?? null;
  }

  return latestMetricsFromSample(latestSample.value, host.value?.latestMetrics);
});
const chartStartContinuityGapMs = computed(() => {
  const intervalSeconds =
    host.value?.probeConfiguration.configuration
      .metricsCollectionIntervalSeconds ?? 5;

  return Math.max(3_000, intervalSeconds * 3_000 + 1_000);
});
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
    (isProbeUpgradeActive.value
      ? probeUpgradeStatus.value?.targetProbeVersion
      : null) ??
    probeUpgradeEligibility.value?.currentProbeAssetSetVersion ??
    "",
);
const canCreateProbeUpgradeRequest = computed(
  () =>
    Boolean(probeUpgradeEligibility.value?.isUpgradeable) &&
    !isProbeUpgradeActive.value &&
    !props.detail.isCreatingProbeUpgradeRequest.value,
);
const showProbeUpgradeButton = computed(
  () =>
    Boolean(probeUpgradeEligibility.value?.isUpgradeable) ||
    isProbeUpgradeActive.value ||
    props.detail.isCreatingProbeUpgradeRequest.value,
);
const lastClockSkewToastHostId = ref<number | null>(null);

onMounted(() => {
  void props.detail.load();
  watch(
    host,
    (currentHost) => {
      if (!currentHost) {
        lastClockSkewToastHostId.value = null;
        return;
      }

      if (!currentHost.clockSkew.detected) {
        if (lastClockSkewToastHostId.value === currentHost.id) {
          lastClockSkewToastHostId.value = null;
        }
        return;
      }

      if (lastClockSkewToastHostId.value === currentHost.id) {
        return;
      }

      lastClockSkewToastHostId.value = currentHost.id;
      toast.warning("时间不同步", {
        description: clockSkewToastDescription(
          currentHost.clockSkew.lastDeltaMs,
        ),
      });
    },
    {
      immediate: true,
    },
  );
});

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
    const status = await props.detail.createProbeUpgradeRequest();
    isProbeUpgradeDialogOpen.value = false;
    if (host.value && status) {
      emit("probeUpgradeRequested", host.value.id, status);
    }
  } catch {
    toast.error("无法创建探针升级请求", {
      description: "请稍后重试。",
    });
  }
}

function clockSkewToastDescription(deltaMs: number | null) {
  if (deltaMs === null) {
    return "探针时间与中心端时间存在偏移。";
  }

  return `探针时间与中心端时间相差约 ${Math.round(deltaMs / 1000)} 秒。`;
}

function openHostSettings(currentHost: HostDetail) {
  if (props.activeHostMetadataId !== currentHost.id) {
    emit("openHostMetadata", currentHost);
  }

  if (props.activeHostConfigurationId !== currentHost.id) {
    emit("openHostConfiguration", currentHost.id);
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
      <Alert
        v-for="warning in visibleWarnings"
        :key="`${warning.code}-${warning.occurredAtMs ?? 0}`"
        class="border-amber-200 bg-amber-50"
      >
        <AlertTriangle class="size-4" aria-hidden="true" />
        <AlertTitle>{{ warningTitle(warning.code) }}</AlertTitle>
        <AlertDescription>{{ warning.message }}</AlertDescription>
      </Alert>

      <Alert v-if="detail.metricsError?.value">
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

      <HostDetailDashboard
        :chart-data="chartData"
        :chart-start-continuity-gap-ms="chartStartContinuityGapMs"
        :deleting-host-id="deletingHostId"
        :host="host"
        :latest-metric="latestMetric"
        :latest-sample="latestSample"
        :samples="detail.samples.value"
        :selected-window="detail.selectedWindow.value"
        :window-options="windowOptions"
        :x-axis-max-ms="detail.chartRange.value.maxMs"
        :x-axis-min-ms="detail.chartRange.value.minMs"
        @delete-host="
          (targetHost, mode) => emit('deleteHost', targetHost, mode)
        "
        @open-host-settings="openHostSettings"
        @switch-metrics-window="switchMetricsWindow"
      >
        <template #actions>
          <Button
            v-if="showProbeUpgradeButton"
            variant="outline"
            size="icon-sm"
            type="button"
            class="relative"
            :disabled="!canCreateProbeUpgradeRequest"
            :aria-label="
              isProbeUpgradeActive || detail.isCreatingProbeUpgradeRequest.value
                ? '探针升级中'
                : probeUpgradeEligibility?.isUpgradeable
                  ? `探针可升级到 ${probeUpgradeTargetVersion}`
                  : '探针升级'
            "
            :title="
              isProbeUpgradeActive || detail.isCreatingProbeUpgradeRequest.value
                ? '探针升级中'
                : '探针升级'
            "
            @click="isProbeUpgradeDialogOpen = true"
          >
            <LoaderCircle
              v-if="
                isProbeUpgradeActive ||
                detail.isCreatingProbeUpgradeRequest.value
              "
              class="text-muted-foreground size-4 animate-spin"
              aria-hidden="true"
            />
            <CircleArrowUp v-else class="size-4" aria-hidden="true" />
            <span
              v-if="
                probeUpgradeEligibility?.isUpgradeable && !isProbeUpgradeActive
              "
              class="absolute -top-1 -right-1 size-2.5 rounded-full bg-red-500"
              aria-hidden="true"
            />
          </Button>
        </template>
      </HostDetailDashboard>

      <Dialog
        v-if="isProbeUpgradeDialogOpen"
        :open="isProbeUpgradeDialogOpen"
        @update:open="isProbeUpgradeDialogOpen = $event"
      >
        <DialogContent class="pointer-events-auto! z-60 opacity-100!">
          <DialogHeader>
            <DialogTitle>确认升级探针</DialogTitle>
            <DialogDescription>
              将此主机的探针升级到 {{ probeUpgradeTargetVersion }}。
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

      <HostSettingsDialog
        :active-host-configuration-id="activeHostConfigurationId"
        :active-host-metadata-id="activeHostMetadataId"
        :host="host"
        :host-configuration-draft="hostConfigurationDraft"
        :host-configuration-error="hostConfigurationError"
        :host-metadata-draft="hostMetadataDraft"
        :host-metadata-error="hostMetadataError"
        :is-saving-host-configuration="isSavingHostConfiguration"
        :is-saving-host-metadata="isSavingHostMetadata"
        @close-host-configuration="emit('openHostConfiguration', $event)"
        @close-host-metadata="emit('openHostMetadata', $event)"
        @save-host-configuration="emit('saveHostConfiguration')"
        @save-host-metadata="emit('saveHostMetadata')"
      />
    </div>
  </section>
</template>
