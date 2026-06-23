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
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  metricToggleFields,
  type MetricToggleKey,
} from "@/lib/probe-configuration";

import type {
  HostDetail,
  HostMetadataDraft,
  HostProbeConfigurationResponse,
} from "../types";

const props = defineProps<{
  activeHostConfigurationId: number | null;
  activeHostMetadataId: number | null;
  host: HostDetail;
  hostConfigurationDraft: HostProbeConfigurationResponse | null;
  hostConfigurationError: string;
  hostMetadataDraft: HostMetadataDraft | null;
  hostMetadataError: string;
  isSavingHostConfiguration: boolean;
  isSavingHostMetadata: boolean;
}>();

const emit = defineEmits<{
  closeHostConfiguration: [hostId: number];
  closeHostMetadata: [host: HostDetail];
  saveHostConfiguration: [];
  saveHostMetadata: [];
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
  if (open) {
    return;
  }

  if (props.activeHostMetadataId === props.host.id) {
    emit("closeHostMetadata", props.host);
  }

  if (props.activeHostConfigurationId === props.host.id) {
    emit("closeHostConfiguration", props.host.id);
  }
}
</script>

<template>
  <Dialog
    :open="
      activeHostMetadataId === host.id || activeHostConfigurationId === host.id
    "
    @update:open="updateOpen"
  >
    <DialogContent class="sm:max-w-3xl">
      <DialogHeader>
        <DialogTitle>主机设置</DialogTitle>
        <DialogDescription class="sr-only">
          编辑主机资料和探针配置。
        </DialogDescription>
      </DialogHeader>

      <Tabs
        :default-value="activeHostMetadataId === host.id ? 'metadata' : 'probe'"
        class="grid gap-4"
      >
        <TabsList class="grid w-full grid-cols-2">
          <TabsTrigger value="metadata">主机资料</TabsTrigger>
          <TabsTrigger value="probe">探针配置</TabsTrigger>
        </TabsList>

        <TabsContent value="metadata">
          <div
            v-if="
              activeHostMetadataId === host.id &&
              !hostMetadataDraft &&
              !isSavingHostMetadata
            "
            class="grid gap-4"
          >
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="grid gap-2">
                <Skeleton class="h-4 w-20" />
                <Skeleton class="h-9 w-full" />
              </div>
              <div class="grid gap-2">
                <Skeleton class="h-4 w-16" />
                <Skeleton class="h-9 w-full" />
              </div>
            </div>
            <div class="grid gap-2">
              <Skeleton class="h-4 w-12" />
              <Skeleton class="h-24 w-full" />
            </div>
            <div class="flex justify-end">
              <Skeleton class="h-9 w-28" />
            </div>
          </div>
          <form
            v-else-if="hostMetadataDraft"
            class="grid gap-4"
            @submit.prevent="$emit('saveHostMetadata')"
          >
            <div class="grid gap-4 sm:grid-cols-2">
              <Label class="grid gap-2 text-sm font-medium">
                显示名称
                <Input
                  v-model="hostMetadataDraft.displayName"
                  type="text"
                  required
                />
              </Label>
              <Label class="grid gap-2 text-sm font-medium">
                IP 地址
                <Input
                  v-model="hostMetadataDraft.connectAddress"
                  type="text"
                  required
                />
              </Label>
            </div>
            <Label class="grid gap-2 text-sm font-medium">
              描述
              <Textarea
                v-model="hostMetadataDraft.description"
                class="min-h-24 resize-none"
                maxlength="500"
              />
            </Label>

            <p
              v-if="hostMetadataError"
              class="text-sm text-red-600"
              role="alert"
            >
              {{ hostMetadataError }}
            </p>

            <DialogFooter>
              <Button type="submit" :disabled="isSavingHostMetadata">
                <LoaderCircle
                  v-if="isSavingHostMetadata"
                  class="size-4 animate-spin"
                />
                <Save v-else class="size-4" aria-hidden="true" />
                保存主机资料
              </Button>
            </DialogFooter>
          </form>
        </TabsContent>

        <TabsContent value="probe">
          <div
            v-if="
              activeHostConfigurationId === host.id &&
              !hostConfigurationDraft &&
              !isSavingHostConfiguration
            "
            class="grid min-h-72 gap-4"
          >
            <div class="flex gap-3">
              <Skeleton class="h-5 w-20" />
              <Skeleton class="h-5 w-20" />
            </div>
            <Separator />
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="grid gap-2">
                <Skeleton class="h-4 w-20" />
                <Skeleton class="h-9 w-full" />
              </div>
              <div class="grid gap-2">
                <Skeleton class="h-4 w-20" />
                <Skeleton class="h-9 w-full" />
              </div>
            </div>
            <div class="grid gap-3 sm:grid-cols-2">
              <Skeleton v-for="index in 8" :key="index" class="h-5 w-full" />
            </div>
            <div class="flex justify-end">
              <Skeleton class="h-9 w-28" />
            </div>
          </div>
          <form
            v-else-if="hostConfigurationDraft"
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

            <Separator />

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
                保存探针配置
              </Button>
            </DialogFooter>
          </form>
        </TabsContent>
      </Tabs>
    </DialogContent>
  </Dialog>
</template>
