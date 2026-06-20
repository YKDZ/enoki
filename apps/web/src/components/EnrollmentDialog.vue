<script setup lang="ts">
import { Copy, LoaderCircle } from "@lucide/vue";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { EnrollmentResponse } from "../types";

defineProps<{
  enrollment: EnrollmentResponse | null;
  enrollmentError: string;
  isCreatingEnrollment: boolean;
  open: boolean;
}>();

defineEmits<{
  copyInstallCommand: [];
  createEnrollment: [];
  "update:open": [open: boolean];
}>();
</script>

<template>
  <Dialog :open="open" @update:open="$emit('update:open', $event)">
    <DialogContent class="sm:max-w-3xl">
      <DialogHeader>
        <DialogTitle>添加主机</DialogTitle>
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
          class="flex items-center gap-2 text-sm text-muted-foreground"
          aria-live="polite"
        >
          <LoaderCircle class="size-4 animate-spin" aria-hidden="true" />
          <span>正在生成安装命令</span>
        </div>

        <template v-else-if="enrollment">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm text-muted-foreground">
              {{ new Date(enrollment.expiresAtMs).toLocaleString() }} 过期
            </p>
            <Button
              variant="outline"
              size="sm"
              type="button"
              @click="$emit('copyInstallCommand')"
            >
              <Copy class="size-4" aria-hidden="true" />
              复制
            </Button>
          </div>

          <dl class="grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <dt class="text-muted-foreground">Hub</dt>
              <dd class="mt-1 break-all">
                {{ enrollment.hubUrl }}
              </dd>
            </div>
            <div>
              <dt class="text-muted-foreground">探针版本</dt>
              <dd class="mt-1">
                {{ enrollment.probeReleaseVersion ?? "自定义下载地址" }}
              </dd>
            </div>
            <div>
              <dt class="text-muted-foreground">安装路径</dt>
              <dd class="mt-1 break-all">
                {{ enrollment.installPath }}
              </dd>
            </div>
          </dl>

          <code
            class="block max-h-56 overflow-auto rounded-md border bg-muted px-3 py-2 text-sm leading-6 whitespace-pre-wrap"
          >
            {{ enrollment.installCommand }}
          </code>
        </template>

        <div v-else class="text-sm text-muted-foreground">暂无安装命令。</div>
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
