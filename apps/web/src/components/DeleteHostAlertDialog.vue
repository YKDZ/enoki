<script setup lang="ts">
import { LoaderCircle, Trash2 } from "@lucide/vue";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import type { HostDetail } from "@/types";

export type DeleteHostMode = "hub-only" | "uninstall";

defineProps<{
  deletingHostId: number | null;
  host: HostDetail;
}>();

defineEmits<{
  deleteHost: [host: HostDetail, mode: DeleteHostMode];
}>();
</script>

<template>
  <AlertDialog>
    <AlertDialogTrigger as-child>
      <Button
        variant="destructive"
        size="icon"
        type="button"
        aria-label="删除"
        title="删除"
        :disabled="deletingHostId === host.id"
      >
        <LoaderCircle
          v-if="deletingHostId === host.id"
          class="size-4 animate-spin"
          aria-hidden="true"
        />
        <Trash2 v-else class="size-4" aria-hidden="true" />
      </Button>
    </AlertDialogTrigger>
    <AlertDialogContent class="pointer-events-auto! z-60 opacity-100!">
      <AlertDialogHeader>
        <AlertDialogTitle>删除主机</AlertDialogTitle>
        <AlertDialogDescription>
          删除主机只会删除 Hub 中的主机，不会卸载本机探针。若要同时清理本机和
          Hub，请选择 “卸载探针并删除主机”。
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel>取消</AlertDialogCancel>
        <AlertDialogAction
          variant="outline"
          @click="$emit('deleteHost', host, 'hub-only')"
        >
          删除主机
        </AlertDialogAction>
        <AlertDialogAction
          variant="destructive"
          @click="$emit('deleteHost', host, 'uninstall')"
        >
          卸载探针并删除主机
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
