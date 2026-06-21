<script setup lang="ts">
import { LoaderCircle, Save } from "@lucide/vue";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  metricToggleFields,
  type MetricToggleKey,
} from "@/lib/probe-configuration";

import type { HostProbeConfigurationResponse, HostDetail } from "../types";

const props = defineProps<{
  activeHostConfigurationId: number | null;
  host: HostDetail;
  hostConfigurationDraft: HostProbeConfigurationResponse | null;
  hostConfigurationError: string;
  isSavingHostConfiguration: boolean;
}>();

const emit = defineEmits<{
  closeHostConfiguration: [hostId: number];
  saveHostConfiguration: [];
}>();

function setMetricToggle(
  key: MetricToggleKey,
  value: boolean | "indeterminate",
) {
  if (!props.hostConfigurationDraft) {
    return;
  }

  props.hostConfigurationDraft.configuration[key] = value === true;
}

function updateOpen(open: boolean) {
  if (!open && props.activeHostConfigurationId === props.host.id) {
    emit("closeHostConfiguration", props.host.id);
  }
}
</script>

<template>
  <Dialog
    :open="activeHostConfigurationId === host.id"
    @update:open="updateOpen"
  >
    <DialogContent class="sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>探针配置</DialogTitle>
        <DialogDescription class="sr-only">
          调整此主机的探针采集配置。
        </DialogDescription>
      </DialogHeader>

      <form
        v-if="hostConfigurationDraft"
        class="grid gap-4"
        @submit.prevent="$emit('saveHostConfiguration')"
      >
        <RadioGroup
          v-model="hostConfigurationDraft.mode"
          class="flex flex-wrap gap-3 text-sm"
        >
          <Label class="flex items-center gap-2">
            <RadioGroupItem value="inherit" />
            继承
          </Label>
          <Label class="flex items-center gap-2">
            <RadioGroupItem value="override" />
            覆盖
          </Label>
        </RadioGroup>

        <div
          v-if="hostConfigurationDraft.mode === 'override'"
          class="grid gap-4"
        >
          <div class="grid gap-4 sm:grid-cols-2">
            <Label class="grid gap-2 text-sm font-medium">
              采集间隔
              <Input
                v-model.number="
                  hostConfigurationDraft.configuration
                    .metricsCollectionIntervalSeconds
                "
                type="number"
                min="1"
                max="300"
              />
            </Label>
            <Label class="grid gap-2 text-sm font-medium">
              上报间隔
              <Input
                v-model.number="
                  hostConfigurationDraft.configuration
                    .reportingBatchIntervalSeconds
                "
                type="number"
                min="1"
                max="600"
              />
            </Label>
          </div>

          <fieldset class="grid gap-3 sm:grid-cols-2">
            <legend class="sr-only">指标采集项</legend>
            <Label
              v-for="[key, label] in metricToggleFields"
              :key="key"
              class="flex items-center gap-2 text-sm"
            >
              <Checkbox
                :model-value="hostConfigurationDraft.configuration[key]"
                @update:model-value="setMetricToggle(key, $event)"
              />
              {{ label }}
            </Label>
          </fieldset>
        </div>

        <p
          v-if="hostConfigurationError"
          class="text-sm text-red-600"
          role="alert"
        >
          {{ hostConfigurationError }}
        </p>

        <DialogFooter>
          <Button type="submit" :disabled="isSavingHostConfiguration">
            <LoaderCircle
              v-if="isSavingHostConfiguration"
              class="size-4 animate-spin"
            />
            <Save v-else class="size-4" aria-hidden="true" />
            保存
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
