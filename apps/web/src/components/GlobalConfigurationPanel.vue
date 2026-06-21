<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
}>();

defineEmits<{
  save: [];
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
  <section class="mb-6 border-b pb-6">
    <div class="flex items-start justify-between gap-4">
      <div>
        <h3 class="text-base font-semibold">全局探针配置</h3>
      </div>
      <span class="text-muted-foreground text-xs">
        版本 {{ draft?.version ?? "读取中" }}
      </span>
    </div>

    <form v-if="draft" class="mt-4 grid gap-4" @submit.prevent="$emit('save')">
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

      <Button class="h-10 w-fit" type="submit" :disabled="isSaving">
        <LoaderCircle v-if="isSaving" class="size-4 animate-spin" />
        保存全局配置
      </Button>
    </form>

    <p v-else-if="error" class="mt-4 text-sm text-red-600" role="alert">
      {{ error }}
    </p>
  </section>
</template>
