<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";

defineProps<{
  isSubmitting: boolean;
  open: boolean;
}>();

const emit = defineEmits<{
  confirm: [];
  "update:open": [open: boolean];
}>();
</script>

<template>
  <Button type="button" variant="outline" @click="emit('update:open', true)">
    升级全部探针
  </Button>
  <AlertDialog :open="open" @update:open="emit('update:open', $event)">
    <AlertDialogContent data-testid="probe-upgrade-all-dialog">
      <AlertDialogHeader>
        <AlertDialogTitle>升级全部探针</AlertDialogTitle>
        <AlertDialogDescription>
          Hub
          将在提交时检查全部活动主机，不受当前分页、排序或过滤影响，并只为当时合格的主机创建普通探针升级请求。
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel :disabled="isSubmitting">取消</AlertDialogCancel>
        <AlertDialogAction :disabled="isSubmitting" @click="emit('confirm')">
          <LoaderCircle
            v-if="isSubmitting"
            class="size-4 animate-spin"
            aria-hidden="true"
          />
          确认升级全部探针
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
