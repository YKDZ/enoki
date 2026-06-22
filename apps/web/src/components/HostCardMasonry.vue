<script setup lang="ts">
import { useIntersectionObserver } from "@vueuse/core";
import { computed, ref } from "vue";

import HostCard from "@/components/HostCard.vue";
import { Skeleton } from "@/components/ui/skeleton";

import type { HostSummary } from "../types";

const props = defineProps<{
  hosts: HostSummary[];
  isLoadingMore: boolean;
  skeletonCount: number;
  visibleCount: number;
}>();

const emit = defineEmits<{
  "load-more": [];
  "open-host-detail": [hostId: number];
}>();

const visibleHosts = computed(() => props.hosts.slice(0, props.visibleCount));
const hasMore = computed(() => props.visibleCount < props.hosts.length);
const loadMoreSentinel = ref<HTMLElement | null>(null);

useIntersectionObserver(
  loadMoreSentinel,
  ([entry]) => {
    if (entry?.isIntersecting && hasMore.value && !props.isLoadingMore) {
      emit("load-more");
    }
  },
  {
    rootMargin: "240px",
  },
);
</script>

<template>
  <div class="grid gap-4">
    <div class="columns-1 gap-4 sm:columns-2 xl:columns-3">
      <div
        v-for="host in visibleHosts"
        :key="host.id"
        class="mb-4 break-inside-avoid"
      >
        <HostCard
          :host="host"
          @open-host-detail="emit('open-host-detail', $event)"
        />
      </div>

      <div
        v-for="index in isLoadingMore ? skeletonCount : 0"
        :key="`skeleton-${index}`"
        data-testid="host-card-lazy-skeleton"
        class="mb-4 break-inside-avoid rounded-lg border p-5"
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
      </div>
    </div>

    <span
      v-if="hasMore"
      ref="loadMoreSentinel"
      class="h-px"
      aria-hidden="true"
    />
  </div>
</template>
