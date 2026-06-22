<script setup lang="ts">
import { LoaderCircle, Save } from "@lucide/vue";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  metricToggleFields,
  type MetricToggleKey,
} from "@/lib/probe-configuration";

import type { ProbeConfiguration } from "../types";

const props = defineProps<{
  draft: ProbeConfiguration | null;
  error: string;
  isSaving: boolean;
  message: string;
  open: boolean;
}>();

const emit = defineEmits<{
  "update:open": [value: boolean];
  saveProbeConfiguration: [];
}>();

function setMetricToggle(
  key: MetricToggleKey,
  value: boolean | "indeterminate",
) {
  if (!props.draft) {
    return;
  }

  props.draft[key] = value === true;
}
</script>

<template>
  <Dialog :open="open" @update:open="emit('update:open', $event)">
    <DialogContent class="sm:max-w-3xl">
      <DialogHeader>
        <DialogTitle>全局设置</DialogTitle>
        <DialogDescription>
          保存后会自动同步给继承全局配置的探针。
        </DialogDescription>
      </DialogHeader>

      <div v-if="!draft && !error" class="grid gap-4">
        <div class="flex justify-between gap-4">
          <Skeleton class="h-5 w-28" />
        </div>
        <div class="grid gap-4 sm:grid-cols-2">
          <div class="grid gap-2">
            <Skeleton class="h-4 w-24" />
            <Skeleton class="h-9 w-full" />
          </div>
          <div class="grid gap-2">
            <Skeleton class="h-4 w-24" />
            <Skeleton class="h-9 w-full" />
          </div>
        </div>
        <div class="grid gap-3 sm:grid-cols-3">
          <Skeleton v-for="index in 8" :key="index" class="h-5 w-full" />
        </div>
        <div class="flex justify-end">
          <Skeleton class="h-9 w-28" />
        </div>
      </div>

      <form
        v-else-if="draft"
        class="grid gap-4"
        @submit.prevent="emit('saveProbeConfiguration')"
      >
        <h3 class="text-base font-semibold">全局探针配置</h3>

        <div class="grid gap-4 sm:grid-cols-2">
          <Label class="grid gap-2 text-sm font-medium">
            指标采集间隔（秒）
            <Input
              v-model.number="draft.metricsCollectionIntervalSeconds"
              type="number"
              min="1"
              max="300"
            />
          </Label>
          <Label class="grid gap-2 text-sm font-medium">
            上报批次间隔（秒）
            <Input
              v-model.number="draft.reportingBatchIntervalSeconds"
              type="number"
              min="1"
              max="600"
            />
          </Label>
        </div>

        <fieldset class="grid gap-3 sm:grid-cols-3">
          <legend class="sr-only">指标采集项</legend>
          <Label
            v-for="[key, label] in metricToggleFields"
            :key="key"
            class="flex items-center gap-2 text-sm"
          >
            <Checkbox
              :model-value="draft[key]"
              @update:model-value="setMetricToggle(key, $event)"
            />
            {{ label }}
          </Label>
        </fieldset>

        <p v-if="error" class="text-sm text-red-600" role="alert">
          {{ error }}
        </p>
        <p v-if="message" class="text-sm text-emerald-600" role="status">
          {{ message }}
        </p>

        <div class="flex justify-end">
          <Button type="submit" :disabled="isSaving">
            <LoaderCircle v-if="isSaving" class="size-4 animate-spin" />
            <Save v-else class="size-4" aria-hidden="true" />
            保存探针配置
          </Button>
        </div>
      </form>

      <p v-else class="text-sm text-red-600" role="alert">
        {{ error }}
      </p>
    </DialogContent>
  </Dialog>
</template>
