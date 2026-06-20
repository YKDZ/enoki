<script setup lang="ts">
import { LoaderCircle, Pencil, Save, X } from "@lucide/vue";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { HostMetadataDraft, ManagedHostDetail } from "../types";

defineProps<{
  activeHostMetadataId: number | null;
  host: ManagedHostDetail;
  hostMetadataDraft: HostMetadataDraft | null;
  hostMetadataError: string;
  isSavingHostMetadata: boolean;
}>();

defineEmits<{
  openHostMetadata: [host: ManagedHostDetail];
  saveHostMetadata: [];
}>();
</script>

<template>
  <Card>
    <CardHeader class="flex flex-row items-center justify-between gap-3 pb-3">
      <CardTitle>主机信息</CardTitle>
      <Button
        variant="outline"
        size="icon-sm"
        type="button"
        :aria-label="
          activeHostMetadataId === host.id ? '关闭主机信息编辑' : '编辑主机信息'
        "
        :title="
          activeHostMetadataId === host.id ? '关闭主机信息编辑' : '编辑主机信息'
        "
        @click="$emit('openHostMetadata', host)"
      >
        <X
          v-if="activeHostMetadataId === host.id"
          class="size-4"
          aria-hidden="true"
        />
        <Pencil v-else class="size-4" aria-hidden="true" />
      </Button>
    </CardHeader>
    <CardContent>
      <form
        v-if="activeHostMetadataId === host.id && hostMetadataDraft"
        class="grid gap-4"
        @submit.prevent="$emit('saveHostMetadata')"
      >
        <div class="grid gap-4 sm:grid-cols-2">
          <Label class="grid gap-2 text-sm font-medium">
            显示名称
            <Input v-model="hostMetadataDraft.displayName" type="text" required />
          </Label>
          <Label class="grid gap-2 text-sm font-medium">
            IP 地址
            <Input v-model="hostMetadataDraft.connectAddress" type="text" required />
          </Label>
        </div>

        <p v-if="hostMetadataError" class="text-sm text-red-600" role="alert">
          {{ hostMetadataError }}
        </p>

        <Button type="submit" class="w-fit" :disabled="isSavingHostMetadata">
          <LoaderCircle
            v-if="isSavingHostMetadata"
            class="size-4 animate-spin"
          />
          <Save v-else class="size-4" aria-hidden="true" />
          保存
        </Button>
      </form>

      <dl v-else class="grid gap-3 text-sm">
        <div class="flex justify-between gap-4">
          <dt class="text-muted-foreground">显示名称</dt>
          <dd class="text-right font-medium">{{ host.hostMetadata.displayName }}</dd>
        </div>
        <div class="flex justify-between gap-4">
          <dt class="text-muted-foreground">IP 地址</dt>
          <dd class="text-right font-medium">{{ host.hostMetadata.connectAddress }}</dd>
        </div>
      </dl>
    </CardContent>
  </Card>
</template>
