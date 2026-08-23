<script setup lang="ts">
import {
  AlertTriangle,
  ArrowLeft,
  LoaderCircle,
  CircleArrowUp,
} from "@lucide/vue";
import type { AcceptableValue } from "reka-ui";
import { computed, inject, onMounted, ref, watch } from "vue";

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
import type { useHostDetail } from "@/composables/useHostDetail";
import { webFeedbackKey } from "@/feedback/web-feedback-port";
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
import ProbeUpgradeStatusAlert from "./ProbeUpgradeStatusAlert.vue";
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
  replacementMigrationRequested: [hostId: number];
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
    label: "10 分钟",
    value: "10m",
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
    label: "3 天",
    value: "3d",
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
const webFeedback = inject(webFeedbackKey);

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
const replacementMigration = computed(
  () => probeUpgradeEligibility.value?.manualReinstall ?? null,
);
const isProbeUpgradeActive = computed(() =>
  ["pending", "accepted", "running"].includes(
    probeUpgradeStatus.value?.state ?? "",
  ),
);
const isProbeUpgradeFailed = computed(
  () => probeUpgradeStatus.value?.state === "failed",
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
    !isProbeUpgradeFailed.value &&
    !props.detail.isCreatingProbeUpgradeRequest.value,
);
const showProbeUpgradeButton = computed(
  () =>
    !isProbeUpgradeFailed.value &&
    (Boolean(probeUpgradeEligibility.value?.isUpgradeable) ||
      isProbeUpgradeActive.value ||
      props.detail.isCreatingProbeUpgradeRequest.value),
);
onMounted(() => {
  void props.detail.load();
  watch(
    host,
    (currentHost) => {
      if (currentHost?.clockSkew.detected) {
        webFeedback?.submit({
          hostId: currentHost.id,
          kind: "clock-skew-detected",
          roundedDeltaSeconds:
            currentHost.clockSkew.lastDeltaMs === null
              ? null
              : Math.round(currentHost.clockSkew.lastDeltaMs / 1000),
        });
      }
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
    webFeedback?.submit({
      hostId: host.value?.id ?? 0,
      kind: "probe-upgrade-request-failed",
    });
  }
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
        <template #current-problem>
          <Alert
            v-if="replacementMigration"
            data-testid="manual-probe-reinstall"
            class="border-amber-200 bg-amber-50"
          >
            <AlertTriangle class="size-4" aria-hidden="true" />
            <AlertTitle>需要手动重新安装探针</AlertTitle>
            <AlertDescription class="grid gap-3">
              <p>
                当前探针安装包无法安全原地升级。Hub
                已将此转换封闭为手动重装；主机、主机元数据和指标历史会保留，探针身份会替换。
              </p>
              <p>目标探针版本：{{ replacementMigration.targetProbeVersion }}</p>
              <div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  @click="emit('replacementMigrationRequested', host.id)"
                >
                  生成手动重装命令
                </Button>
              </div>
            </AlertDescription>
          </Alert>
          <ProbeUpgradeStatusAlert
            v-if="probeUpgradeStatus"
            :status="probeUpgradeStatus"
            @retry-probe-upgrade="isProbeUpgradeDialogOpen = true"
          />
        </template>

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
