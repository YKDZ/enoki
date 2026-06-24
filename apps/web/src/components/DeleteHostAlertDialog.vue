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
          如果探针仍在运行，先卸载探针再删除记录。若探针已经手动卸载或长期离线，可以只删除
          服务端记录。
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel>取消</AlertDialogCancel>
        <AlertDialogAction
          variant="outline"
          @click="$emit('deleteHost', host, 'hub-only')"
        >
          仅删除记录
        </AlertDialogAction>
        <AlertDialogAction
          variant="destructive"
          @click="$emit('deleteHost', host, 'uninstall')"
        >
          卸载并删除
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
