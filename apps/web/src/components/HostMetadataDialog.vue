<script setup lang="ts">
import { LoaderCircle, Save } from "@lucide/vue";

import { Button } from "@/components/ui/button";
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
import { Textarea } from "@/components/ui/textarea";

import type { HostMetadataDraft, HostDetail } from "../types";

const props = defineProps<{
  activeHostMetadataId: number | null;
  host: HostDetail;
  hostMetadataDraft: HostMetadataDraft | null;
  hostMetadataError: string;
  isSavingHostMetadata: boolean;
}>();

const emit = defineEmits<{
  closeHostMetadata: [host: HostDetail];
  saveHostMetadata: [];
}>();

function updateOpen(open: boolean) {
  if (!open && props.activeHostMetadataId === props.host.id) {
    emit("closeHostMetadata", props.host);
  }
}
</script>

<template>
  <Dialog :open="activeHostMetadataId === host.id" @update:open="updateOpen">
    <DialogContent>
      <DialogHeader>
        <DialogTitle>主机信息</DialogTitle>
        <DialogDescription class="sr-only">
          编辑主机显示名称、描述和连接地址。
        </DialogDescription>
      </DialogHeader>

      <form
        v-if="hostMetadataDraft"
        class="grid gap-4"
        @submit.prevent="$emit('saveHostMetadata')"
      >
        <Label class="grid gap-2 text-sm font-medium">
          显示名称
          <Input v-model="hostMetadataDraft.displayName" type="text" required />
        </Label>
        <Label class="grid gap-2 text-sm font-medium">
          描述
          <Textarea
            v-model="hostMetadataDraft.description"
            class="min-h-24 resize-none"
            maxlength="500"
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

        <p v-if="hostMetadataError" class="text-sm text-red-600" role="alert">
          {{ hostMetadataError }}
        </p>

        <DialogFooter>
          <Button type="submit" :disabled="isSavingHostMetadata">
            <LoaderCircle
              v-if="isSavingHostMetadata"
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
