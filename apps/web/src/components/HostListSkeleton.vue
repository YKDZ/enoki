<script setup lang="ts">
import { Skeleton } from "@/components/ui/skeleton";
</script>

<template>
  <div class="overflow-x-auto" aria-label="正在加载主机列表" aria-live="polite">
    <div class="grid min-w-[980px] gap-2">
      <div
        class="text-muted-foreground grid grid-cols-[minmax(220px,1.3fr)_76px_repeat(6,minmax(92px,1fr))] gap-3 px-3 text-xs font-medium"
      >
        <Skeleton class="h-4 w-12" />
        <Skeleton class="h-4 w-10" />
        <Skeleton class="h-4 w-10" />
        <Skeleton class="h-4 w-10" />
        <Skeleton class="h-4 w-10" />
        <Skeleton class="h-4 w-10" />
        <Skeleton class="h-4 w-10" />
        <Skeleton class="h-4 w-16" />
      </div>

      <div
        v-for="index in 8"
        :key="index"
        class="bg-card grid grid-cols-[minmax(220px,1.3fr)_76px_repeat(6,minmax(92px,1fr))] items-center gap-3 rounded-md border px-3 py-3"
      >
        <div class="grid gap-2">
          <Skeleton class="h-4 w-36" />
          <Skeleton class="h-3 w-52" />
        </div>
        <Skeleton class="h-5 w-14 rounded-full" />
        <Skeleton v-for="metric in 6" :key="metric" class="h-4 w-20" />
      </div>
    </div>
  </div>
</template>
