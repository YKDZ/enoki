<script setup lang="ts">
import { Check, Copy, LoaderCircle, X } from "@lucide/vue";
import { useClipboard, useTimeoutFn } from "@vueuse/core";
import { computed, ref, watch } from "vue";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import type { EnrollmentResponse } from "../types";

const props = defineProps<{
  enrollment: EnrollmentResponse | null;
  enrollmentError: string;
  isCreatingEnrollment: boolean;
  open: boolean;
}>();

defineEmits<{
  createEnrollment: [];
  "update:open": [open: boolean];
}>();

const installCommand = computed(() => props.enrollment?.installCommand ?? "");
const copyStatus = ref<"idle" | "success" | "error">("idle");
const { copied, copy, isSupported } = useClipboard({
  copiedDuring: 2_000,
  source: installCommand,
});
const { start: clearCopyError } = useTimeoutFn(
  () => {
    if (copyStatus.value === "error") {
      copyStatus.value = "idle";
    }
  },
  2_000,
  { immediate: false },
);
const copyButtonClass = computed(() => {
  if (copyStatus.value === "success") {
    return "border-green-200 text-green-700 hover:bg-green-50 hover:text-green-800";
  }

  if (copyStatus.value === "error") {
    return "border-red-200 text-red-700 hover:bg-red-50 hover:text-red-800";
  }

  return "";
});
const copyButtonLabel = computed(() => {
  if (copyStatus.value === "success") {
    return "已复制";
  }

  if (copyStatus.value === "error") {
    return "复制失败";
  }

  return "复制";
});

watch(copied, (value) => {
  if (!value && copyStatus.value === "success") {
    copyStatus.value = "idle";
  }
});

watch(installCommand, () => {
  copyStatus.value = "idle";
});

async function copyInstallCommand() {
  if (!installCommand.value) {
    return;
  }

  try {
    if (!isSupported.value) {
      throw new Error("clipboard_not_supported");
    }

    await copy();
    copyStatus.value = "success";
  } catch {
    copyStatus.value = "error";
    clearCopyError();
  }
}
</script>

<template>
  <Dialog :open="open" @update:open="$emit('update:open', $event)">
    <DialogContent class="sm:max-w-3xl">
      <DialogHeader>
        <DialogTitle>添加主机</DialogTitle>
        <DialogDescription class="sr-only">
          生成并复制用于部署探针的一次性安装命令。
        </DialogDescription>
      </DialogHeader>

      <div class="grid gap-4">
        <p
          v-if="enrollmentError"
          class="text-sm leading-6 text-red-600"
          role="alert"
        >
          {{ enrollmentError }}
        </p>

        <div
          v-if="isCreatingEnrollment"
          class="text-muted-foreground flex items-center gap-2 text-sm"
          aria-live="polite"
        >
          <LoaderCircle class="size-4 animate-spin" aria-hidden="true" />
          <span>正在生成安装命令</span>
        </div>

        <template v-else-if="enrollment">
          <div class="flex items-center justify-between gap-3">
            <p class="text-muted-foreground text-sm">
              {{ new Date(enrollment.expiresAtMs).toLocaleString() }} 过期
            </p>
            <Button
              variant="outline"
              size="sm"
              type="button"
              :class="copyButtonClass"
              @click="copyInstallCommand"
            >
              <Check
                v-if="copyStatus === 'success'"
                class="size-4"
                aria-hidden="true"
              />
              <X
                v-else-if="copyStatus === 'error'"
                class="size-4"
                aria-hidden="true"
              />
              <Copy v-else class="size-4" aria-hidden="true" />
              {{ copyButtonLabel }}
            </Button>
          </div>

          <dl class="grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <dt class="text-muted-foreground">Hub API URL</dt>
              <dd class="mt-1 break-all">
                {{ enrollment.hubUrl }}
              </dd>
            </div>
            <div>
              <dt class="text-muted-foreground">探针版本</dt>
              <dd class="mt-1">由 Hub 分发</dd>
            </div>
            <div>
              <dt class="text-muted-foreground">安装路径</dt>
              <dd class="mt-1 break-all">
                {{ enrollment.installPath }}
              </dd>
            </div>
          </dl>

          <code
            class="bg-muted block max-h-56 overflow-auto rounded-md border px-3 py-2 text-sm leading-6 whitespace-pre-wrap"
          >
            {{ enrollment.installCommand }}
          </code>
        </template>

        <div v-else class="text-muted-foreground text-sm">暂无安装命令。</div>
      </div>

      <DialogFooter>
        <Button
          v-if="!enrollment || enrollmentError"
          type="button"
          :disabled="isCreatingEnrollment"
          @click="$emit('createEnrollment')"
        >
          <LoaderCircle
            v-if="isCreatingEnrollment"
            class="size-4 animate-spin"
            aria-hidden="true"
          />
          生成命令
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
