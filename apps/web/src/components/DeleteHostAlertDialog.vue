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

defineProps<{
  deletingHostId: number | null;
  host: HostDetail;
}>();

defineEmits<{
  deleteHost: [host: HostDetail];
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
          Hub
          会向此主机下发探针卸载请求。探针确认卸载完成后，主机记录、历史指标和详情页会从
          Hub 中移除。
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel>取消</AlertDialogCancel>
        <AlertDialogAction
          class="bg-destructive hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:bg-destructive/60 dark:focus-visible:ring-destructive/40 text-white"
          @click="$emit('deleteHost', host)"
        >
          卸载并删除
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
