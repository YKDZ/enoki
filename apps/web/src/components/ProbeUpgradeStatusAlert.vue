<script setup lang="ts">
import { CheckCircle2, CircleAlert, CircleX, LoaderCircle } from "@lucide/vue";
import { computed } from "vue";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { HostDetail } from "@/types";

const props = defineProps<{
  status: NonNullable<HostDetail["probeUpgradeStatus"]>;
}>();

const presentation = computed(() => {
  switch (props.status.state) {
    case "pending":
      return {
        icon: LoaderCircle,
        iconClass: "animate-spin",
        title: "探针升级等待中",
        variant: "default" as const,
      };
    case "accepted":
      return {
        icon: LoaderCircle,
        iconClass: "animate-spin",
        title: "探针已接收升级请求",
        variant: "default" as const,
      };
    case "running":
      return {
        icon: LoaderCircle,
        iconClass: "animate-spin",
        title: "探针升级进行中",
        variant: "default" as const,
      };
    case "succeeded":
      return {
        icon: CheckCircle2,
        iconClass: "text-emerald-600",
        title: "探针升级完成",
        variant: "default" as const,
      };
    case "failed":
      return {
        icon: CircleX,
        iconClass: "",
        title: "探针升级失败",
        variant: "destructive" as const,
      };
    case "canceled":
      return {
        icon: CircleAlert,
        iconClass: "",
        title: "探针升级已取消",
        variant: "default" as const,
      };
    case "superseded":
      return {
        icon: CircleAlert,
        iconClass: "",
        title: "探针升级请求已被替代",
        variant: "default" as const,
      };
    default:
      throw new Error(`不支持的探针升级状态：${props.status.state}`);
  }
});
</script>

<template>
  <Alert data-testid="probe-upgrade-status" :variant="presentation.variant">
    <component
      :is="presentation.icon"
      class="size-4"
      :class="presentation.iconClass"
      aria-hidden="true"
    />
    <AlertTitle>{{ presentation.title }}</AlertTitle>
    <AlertDescription class="grid gap-2">
      <p>目标探针版本：{{ status.targetProbeVersion }}</p>
      <p v-if="status.failure">
        {{ status.failure.message || status.failure.code }}
        <span v-if="status.failure.message">（{{ status.failure.code }}）</span>
      </p>
      <p v-if="status.state === 'failed'">
        请在受影响主机上以 root 权限运行 Probe
        Repair，然后返回此页确认探针恢复上报。
      </p>
    </AlertDescription>
  </Alert>
</template>
