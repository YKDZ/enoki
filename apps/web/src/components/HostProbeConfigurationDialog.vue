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
  derivedLowFrequencyIntervalSeconds,
  derivedReportingBatchIntervalSeconds,
  collectorEnabled,
  probeCollectorCatalog,
  updateEnabledCollectorIds,
  type ProbeCollectorId,
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

function setCollectorToggle(
  collectorId: ProbeCollectorId,
  value: boolean | "indeterminate",
) {
  if (!props.hostConfigurationDraft) {
    return;
  }

  props.hostConfigurationDraft.configuration.enabledCollectorIds =
    updateEnabledCollectorIds(
      props.hostConfigurationDraft.configuration.enabledCollectorIds,
      collectorId,
      value === true,
    );
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
          <div class="grid gap-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
            <Label class="grid gap-2 text-sm font-medium">
              基础采样间隔
              <Input
                v-model.number="
                  hostConfigurationDraft.configuration
                    .metricsCollectionIntervalSeconds
                "
                type="number"
                min="1"
                max="200"
              />
            </Label>
            <div class="grid gap-2 text-sm">
              <span class="font-medium">节拍映射</span>
              <div class="text-muted-foreground grid gap-1">
                <span>
                  高频采集：{{
                    hostConfigurationDraft.configuration
                      .metricsCollectionIntervalSeconds
                  }}
                  秒
                </span>
                <span>
                  低频采集：{{
                    derivedLowFrequencyIntervalSeconds(
                      hostConfigurationDraft.configuration
                        .metricsCollectionIntervalSeconds,
                    )
                  }}
                  秒
                </span>
                <span>
                  上报窗口：{{
                    derivedReportingBatchIntervalSeconds(
                      hostConfigurationDraft.configuration
                        .metricsCollectionIntervalSeconds,
                    )
                  }}
                  秒
                </span>
              </div>
            </div>
          </div>

          <fieldset class="grid gap-3 sm:grid-cols-2">
            <legend class="sr-only">指标采集项</legend>
            <Label
              v-for="collector in probeCollectorCatalog"
              :key="collector.id"
              class="flex items-center gap-2 text-sm"
            >
              <Checkbox
                :model-value="
                  collectorEnabled(
                    hostConfigurationDraft.configuration.enabledCollectorIds,
                    collector.id,
                  )
                "
                @update:model-value="setCollectorToggle(collector.id, $event)"
              />
              {{ collector.label }}
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
