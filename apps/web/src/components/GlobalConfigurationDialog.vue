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
  derivedLowFrequencyIntervalSeconds,
  derivedReportingBatchIntervalSeconds,
  collectorEnabled,
  probeCollectorCatalog,
  updateEnabledCollectorIds,
  type ProbeCollectorId,
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

function setCollectorToggle(
  collectorId: ProbeCollectorId,
  value: boolean | "indeterminate",
) {
  if (!props.draft) {
    return;
  }

  props.draft.enabledCollectorIds = updateEnabledCollectorIds(
    props.draft.enabledCollectorIds,
    collectorId,
    value === true,
  );
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

        <div class="grid gap-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
          <Label class="grid gap-2 text-sm font-medium">
            基础采样间隔（秒）
            <Input
              v-model.number="draft.metricsCollectionIntervalSeconds"
              type="number"
              min="1"
              max="200"
            />
          </Label>
          <div class="grid gap-2 text-sm">
            <span class="font-medium">节拍映射</span>
            <div class="text-muted-foreground grid gap-1">
              <span>
                高频采集：{{ draft.metricsCollectionIntervalSeconds }} 秒
              </span>
              <span>
                低频采集：{{
                  derivedLowFrequencyIntervalSeconds(
                    draft.metricsCollectionIntervalSeconds,
                  )
                }}
                秒
              </span>
              <span>
                上报窗口：{{
                  derivedReportingBatchIntervalSeconds(
                    draft.metricsCollectionIntervalSeconds,
                  )
                }}
                秒
              </span>
            </div>
          </div>
        </div>

        <fieldset class="grid gap-3 sm:grid-cols-3">
          <legend class="sr-only">指标采集项</legend>
          <Label
            v-for="collector in probeCollectorCatalog"
            :key="collector.id"
            class="flex items-center gap-2 text-sm"
          >
            <Checkbox
              :model-value="
                collectorEnabled(draft.enabledCollectorIds, collector.id)
              "
              @update:model-value="setCollectorToggle(collector.id, $event)"
            />
            {{ collector.label }}
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
