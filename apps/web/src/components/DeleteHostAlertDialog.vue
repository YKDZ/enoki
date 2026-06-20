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
        variant="outline"
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
          删除后，此主机的记录和历史指标将不再显示。
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel>取消</AlertDialogCancel>
        <AlertDialogAction
          class="bg-destructive text-white hover:bg-destructive/90"
          @click="$emit('deleteHost', host)"
        >
          删除
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
