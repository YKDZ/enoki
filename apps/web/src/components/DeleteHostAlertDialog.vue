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
import type { ManagedHostDetail } from "../types";

defineProps<{
  deletingHostId: number | null;
  host: ManagedHostDetail;
}>();

defineEmits<{
  deleteHost: [host: ManagedHostDetail];
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
    <AlertDialogContent>
      <AlertDialogHeader>
        <AlertDialogTitle>删除主机</AlertDialogTitle>
        <AlertDialogDescription>
          删除后，Hub 会隐藏此主机的记录、历史指标和详情页，并使当前 Probe
          身份失效。目标主机上的 enoki-probe systemd 服务和二进制文件不会被远程卸载；
          如不再需要采集，请在目标主机上停止并卸载探针。
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel>取消</AlertDialogCancel>
        <AlertDialogAction
          variant="destructive"
          @click="$emit('deleteHost', host)"
        >
          删除
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
