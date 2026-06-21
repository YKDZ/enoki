<script setup lang="ts">
import { Skeleton } from "@/components/ui/skeleton";
</script>

<template>
  <div
    class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3"
    aria-label="正在加载主机列表"
    aria-live="polite"
  >
    <div
      v-for="index in 6"
      :key="index"
      class="border-border bg-card text-card-foreground rounded-lg border p-5"
    >
      <div class="flex items-start justify-between gap-4">
        <div class="grid min-w-0 flex-1 gap-2">
          <Skeleton class="h-5 w-40" />
          <Skeleton class="h-4 w-28" />
        </div>
        <Skeleton class="h-6 w-14 rounded-full" />
      </div>

      <div class="mt-6 grid gap-4">
        <div
          v-for="metric in 3"
          :key="metric"
          class="grid grid-cols-[72px_1fr_64px] items-center gap-3"
        >
          <Skeleton class="h-4 w-12" />
          <Skeleton class="h-2 w-full" />
          <Skeleton class="h-4 w-16" />
        </div>
      </div>

      <div class="mt-5 grid grid-cols-2 gap-3">
        <Skeleton class="h-10 w-full" />
        <Skeleton class="h-10 w-full" />
      </div>
    </div>
  </div>
</template>
