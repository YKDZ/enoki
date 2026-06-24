<script setup lang="ts">
import { Skeleton } from "@/components/ui/skeleton";
</script>

<template>
  <div aria-label="正在加载指标" class="grid gap-4" role="status">
    <span class="sr-only">正在加载指标</span>
    <Skeleton class="h-40 w-full" />
    <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Skeleton class="h-14 w-full" />
      <Skeleton class="h-14 w-full" />
      <Skeleton class="h-14 w-full" />
      <Skeleton class="h-14 w-full" />
    </div>
  </div>
</template>
