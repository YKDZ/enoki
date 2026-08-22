<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import { nextTick, ref, watch } from "vue";

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

const installCommandControl = ref<HTMLTextAreaElement | null>(null);
let focusedInstallCommand: string | null = null;

watch(
  [
    () => props.enrollment?.installCommand,
    () => props.isCreatingEnrollment,
    () => props.open,
  ],
  async ([installCommand, isCreatingEnrollment, isOpen]) => {
    if (
      !installCommand ||
      isCreatingEnrollment ||
      !isOpen ||
      installCommand === focusedInstallCommand
    ) {
      return;
    }

    focusedInstallCommand = installCommand;
    await nextTick();
    if (
      !props.open ||
      props.isCreatingEnrollment ||
      props.enrollment?.installCommand !== installCommand
    ) {
      return;
    }

    const control = installCommandControl.value;
    if (!control) {
      return;
    }

    control.focus();
  },
  { flush: "post" },
);
</script>

<template>
  <Dialog :open="open" @update:open="$emit('update:open', $event)">
    <DialogContent class="sm:max-w-3xl">
      <DialogHeader>
        <DialogTitle>添加主机</DialogTitle>
        <DialogDescription class="sr-only">
          生成用于部署探针的一次性安装命令。
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
          <p class="text-muted-foreground text-sm">
            状态：{{
              enrollment.status === "pending" ? "等待安装" : "正在验证"
            }}
          </p>

          <dl class="grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <dt class="text-muted-foreground">Hub API URL</dt>
              <dd class="mt-1 break-all">
                {{ enrollment.hubUrl }}
              </dd>
            </div>
            <div>
              <dt class="text-muted-foreground">安装配方版本</dt>
              <dd class="mt-1">
                {{ enrollment.bootstrapRecipe.recipe.version }}
              </dd>
            </div>
            <div>
              <dt class="text-muted-foreground">探针安装包版本</dt>
              <dd class="mt-1">
                {{ enrollment.bootstrapRecipe.bundleVersion }}
              </dd>
            </div>
          </dl>

          <div class="text-sm">
            <p class="text-muted-foreground">支持的目标平台</p>
            <ul
              aria-label="支持的目标平台"
              class="mt-1 list-inside list-disc font-mono text-xs leading-5"
            >
              <li
                v-for="target in enrollment.bootstrapRecipe.targets"
                :key="target"
              >
                {{ target }}
              </li>
            </ul>
          </div>

          <p class="text-muted-foreground text-sm leading-6">
            请先从 GitHub Release 获取配方与公开记录，核对配方 SHA-256
            <code>{{ enrollment.bootstrapRecipe.recipe.sha256 }}</code>
            及分发信任根指纹
            <code>{{ enrollment.bootstrapRecipe.rootFingerprint }}</code
            >，再执行此命令。
          </p>

          <textarea
            v-if="enrollment.status === 'pending'"
            ref="installCommandControl"
            aria-label="安装命令"
            autocomplete="off"
            class="h-44 max-h-72 w-full resize-y overflow-auto bg-black p-4 font-mono text-xs leading-5 text-white"
            :value="enrollment.installCommand"
            readonly
            rows="6"
            spellcheck="false"
            wrap="off"
          />

          <p v-else class="text-muted-foreground text-sm" aria-live="polite">
            正在验证探针是否已连接到 Hub。
          </p>
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
