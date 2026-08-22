<script setup lang="ts">
import { CircleX, LoaderCircle } from "@lucide/vue";
import { computed } from "vue";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import type { HostDetail } from "@/types";

const props = withDefaults(
  defineProps<{
    manualReinstallAvailable?: boolean;
    status: NonNullable<HostDetail["probeUpgradeStatus"]>;
  }>(),
  { manualReinstallAvailable: false },
);

const emit = defineEmits<{
  manualReinstall: [];
  retryProbeUpgrade: [];
}>();

const presentation = computed(() => {
  switch (props.status.state) {
    case "pending":
      return {
        action: null,
        description: "Hub 正在等待探针接收升级请求。",
        icon: LoaderCircle,
        iconClass: "animate-spin",
        title: "探针升级等待中",
        variant: "default" as const,
      };
    case "accepted":
      return {
        action: null,
        description: "探针已接收请求，正在等待升级开始。",
        icon: LoaderCircle,
        iconClass: "animate-spin",
        title: "探针已接收升级请求",
        variant: "default" as const,
      };
    case "running":
      return {
        action: null,
        description: "探针正在安装并切换到目标版本。",
        icon: LoaderCircle,
        iconClass: "animate-spin",
        title: "探针升级进行中",
        variant: "default" as const,
      };
    case "failed":
      return failedPresentation(
        props.status.failure?.recoveryDisposition ?? "unclassified",
      );
    case "succeeded":
    case "canceled":
    case "superseded":
      return null;
    default:
      return null;
  }
});

type RecoveryDisposition = NonNullable<
  NonNullable<HostDetail["probeUpgradeStatus"]>["failure"]
>["recoveryDisposition"];

function failedPresentation(disposition: RecoveryDisposition) {
  const base = {
    icon: CircleX,
    iconClass: "",
    variant: "destructive" as const,
  };

  switch (disposition) {
    case "retry_probe_upgrade":
      return {
        ...base,
        action: "retry" as const,
        description:
          "上次探针升级未完成。请再次确认升级后，由 Hub 创建新的升级请求。",
        title: "探针升级失败：请再次确认升级",
      };
    case "probe_repair":
      return {
        ...base,
        action: "repair" as const,
        description:
          "升级已进入激活阶段，请在受影响主机上以 root 权限修复探针。",
        title: "探针升级失败：需要修复探针",
      };
    case "manual_reinstall_required":
      return {
        ...base,
        action: props.manualReinstallAvailable
          ? ("manual-reinstall" as const)
          : null,
        description: props.manualReinstallAvailable
          ? "当前安装无法安全原地恢复。请生成绑定此主机的一次性命令，手动重新安装探针。"
          : "当前安装无法安全原地恢复。现有恢复流程只支持离线主机，请待主机状态变为离线后再继续。",
        title: "探针升级失败：需要手动重新安装探针",
      };
    case "unclassified":
    default:
      return {
        ...base,
        action: null,
        description:
          "Hub 无法安全判断恢复方式。请检查 Hub 与探针状态后再决定下一步。",
        title: "探针升级失败：未知问题",
      };
  }
}
</script>

<template>
  <Alert
    v-if="presentation"
    data-testid="probe-upgrade-status"
    :variant="presentation.variant"
  >
    <component
      :is="presentation.icon"
      class="size-4"
      :class="presentation.iconClass"
      aria-hidden="true"
    />
    <AlertTitle>{{ presentation.title }}</AlertTitle>
    <AlertDescription class="grid gap-3">
      <p>{{ presentation.description }}</p>
      <p>目标探针版本：{{ status.targetProbeVersion }}</p>
      <p v-if="presentation.action === 'repair'">
        运行
        <code>sudo enoki-probe repair</code>，然后返回此页确认探针恢复上报。
      </p>
      <div
        v-if="
          presentation.action === 'retry' ||
          presentation.action === 'manual-reinstall'
        "
      >
        <Button
          type="button"
          variant="outline"
          size="sm"
          @click="
            presentation.action === 'retry'
              ? emit('retryProbeUpgrade')
              : emit('manualReinstall')
          "
        >
          {{
            presentation.action === "retry"
              ? "再次确认升级"
              : "生成手动重装命令"
          }}
        </Button>
      </div>
    </AlertDescription>
  </Alert>
</template>
