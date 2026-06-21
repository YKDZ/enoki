<script setup lang="ts">
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
</script>

<template>
  <div class="grid gap-4" aria-label="正在加载主机详情" aria-live="polite">
    <div
      class="flex flex-wrap items-center justify-between gap-3 border-b pb-4"
    >
      <div class="flex min-w-0 items-center gap-3">
        <Skeleton class="size-9 rounded-md" />
        <div class="grid gap-2">
          <div class="flex items-center gap-2">
            <Skeleton class="h-6 w-44" />
            <Skeleton class="h-6 w-14 rounded-full" />
          </div>
          <Skeleton class="h-4 w-72 max-w-[72vw]" />
        </div>
      </div>
      <div class="flex items-center gap-2">
        <Skeleton class="h-8 w-28" />
        <Skeleton class="size-8 rounded-md" />
        <Skeleton class="size-8 rounded-md" />
      </div>
    </div>

    <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <Card v-for="index in 4" :key="index">
        <CardContent class="grid gap-3 p-4">
          <Skeleton class="h-4 w-20" />
          <Skeleton class="h-6 w-28" />
          <Skeleton class="h-2 w-full" />
        </CardContent>
      </Card>
    </div>

    <div class="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <Card>
        <CardHeader class="border-b px-4 py-3">
          <div class="flex items-center justify-between gap-3">
            <Skeleton class="h-5 w-20" />
            <Skeleton class="h-8 w-28" />
          </div>
        </CardHeader>
        <CardContent class="p-4">
          <div class="mb-4 flex gap-2">
            <Skeleton v-for="index in 4" :key="index" class="h-8 w-16" />
          </div>
          <div class="grid gap-4 lg:grid-cols-2">
            <Skeleton v-for="index in 4" :key="index" class="h-64 w-full" />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <Skeleton class="h-5 w-24" />
        </CardHeader>
        <CardContent class="grid gap-4">
          <div v-for="index in 6" :key="index" class="grid gap-2">
            <Skeleton class="h-3 w-16" />
            <Skeleton class="h-4 w-full" />
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
