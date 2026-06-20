<script setup lang="ts">
import { Copy } from "@lucide/vue";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { EnrollmentResponse } from "../types";

defineProps<{
  enrollment: EnrollmentResponse | null;
  enrollmentError: string;
}>();

defineEmits<{
  copyInstallCommand: [];
}>();
</script>

<template>
  <Card v-if="enrollment || enrollmentError" class="mb-5">
    <CardContent class="pt-4">
      <p
        v-if="enrollmentError"
        class="text-sm leading-6 text-red-600"
        role="alert"
      >
        {{ enrollmentError }}
      </p>

      <div v-if="enrollment" class="grid gap-3">
        <div class="flex items-center justify-between gap-3">
          <div>
            <h3 class="text-sm font-semibold">添加主机</h3>
            <p class="mt-1 text-sm text-muted-foreground">
              {{ new Date(enrollment.expiresAtMs).toLocaleString() }} 过期
            </p>
          </div>
          <Button
            variant="outline"
            size="icon"
            type="button"
            aria-label="复制安装命令"
            title="复制安装命令"
            @click="$emit('copyInstallCommand')"
          >
            <Copy class="size-4" aria-hidden="true" />
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
          class="block overflow-x-auto rounded-md border bg-muted px-3 py-2 text-sm"
        >
          {{ enrollment.installCommand }}
        </code>
      </div>
    </CardContent>
  </Card>
</template>
