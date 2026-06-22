<script setup lang="ts">
import { Skeleton } from "@/components/ui/skeleton";
</script>

<template>
  <div
    class="grid gap-4 pb-24"
    aria-label="正在加载主机详情"
    aria-live="polite"
  >
    <div class="flex items-start gap-3 border-b pb-4">
      <Skeleton class="size-5 rounded-sm" />
      <div class="grid min-w-0 flex-1 gap-3">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="grid min-w-0 gap-2">
            <div class="flex items-center gap-2">
              <Skeleton class="h-7 w-44" />
              <Skeleton class="h-6 w-14 rounded-full" />
            </div>
          </div>

          <div class="flex shrink-0 items-center gap-2">
            <Skeleton class="h-8 w-24" />
            <Skeleton class="h-8 w-28" />
            <Skeleton class="h-8 w-20" />
            <Skeleton class="size-8 rounded-md" />
          </div>
        </div>

        <Skeleton class="h-10 w-full max-w-3xl rounded-md" />

        <div class="flex min-w-0 flex-wrap gap-x-6 gap-y-3">
          <div
            v-for="index in 8"
            :key="index"
            class="flex min-w-0 items-center gap-2"
          >
            <Skeleton class="size-3.5 rounded-sm" />
            <Skeleton class="h-3 w-12" />
            <Skeleton class="h-3 w-28" />
          </div>
        </div>
      </div>
    </div>

    <div class="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <div class="rounded-md border p-4 xl:col-span-2">
        <div class="mb-4 flex items-start justify-between gap-3">
          <div class="grid gap-2">
            <Skeleton class="h-5 w-16" />
            <Skeleton class="h-4 w-64 max-w-[70vw]" />
          </div>
          <Skeleton class="h-7 w-24" />
        </div>
        <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <Skeleton v-for="index in 16" :key="index" class="h-24 w-full" />
        </div>
        <div class="mt-5 grid gap-2 sm:grid-cols-3">
          <Skeleton v-for="index in 6" :key="index" class="h-4 w-full" />
        </div>
      </div>

      <div v-for="panel in 4" :key="panel" class="rounded-md border p-4">
        <div class="mb-4 flex items-start justify-between gap-3">
          <div class="grid gap-2">
            <Skeleton class="h-5 w-20" />
            <Skeleton class="h-4 w-48 max-w-[60vw]" />
          </div>
          <Skeleton class="size-8 rounded-md" />
        </div>
        <Skeleton class="h-56 w-full" />
        <div class="mt-4 grid gap-2">
          <Skeleton class="h-4 w-full" />
          <Skeleton class="h-4 w-4/5" />
        </div>
      </div>
    </div>
  </div>
</template>
