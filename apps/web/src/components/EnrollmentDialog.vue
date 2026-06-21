<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";

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
            {{ new Date(enrollment.expiresAtMs).toLocaleString() }} 过期
          </p>

          <dl class="grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <dt class="text-muted-foreground">Hub API URL</dt>
              <dd class="mt-1 break-all">
                {{ enrollment.hubUrl }}
              </dd>
            </div>
            <div>
              <dt class="text-muted-foreground">安装路径</dt>
              <dd class="mt-1 break-all">
                {{ enrollment.installPath }}
              </dd>
            </div>
          </dl>

          <pre
            class="max-h-72 overflow-auto bg-black p-4 font-mono text-xs leading-5 whitespace-pre-wrap text-white"
          ><code>{{ enrollment.installCommand }}</code></pre>
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
