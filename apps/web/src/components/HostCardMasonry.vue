<script setup lang="ts">
import { useIntersectionObserver } from "@vueuse/core";
import { computed, ref } from "vue";

import HostCard from "@/components/HostCard.vue";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import type { HostSummary } from "../types";

const props = defineProps<{
  batchSize: number;
  batchSizeOptions: number[];
  hosts: HostSummary[];
  visibleCount: number;
}>();

const emit = defineEmits<{
  "load-more": [];
  "open-host-detail": [hostId: number];
  "update:batchSize": [batchSize: number];
}>();

const batchSizeValue = computed({
  get: () => String(props.batchSize),
  set(value) {
    const nextBatchSize = Number(value);

    if (Number.isFinite(nextBatchSize) && nextBatchSize > 0) {
      emit("update:batchSize", nextBatchSize);
    }
  },
});

const visibleHosts = computed(() => props.hosts.slice(0, props.visibleCount));
const hasMore = computed(() => props.visibleCount < props.hosts.length);
const loadMoreSentinel = ref<HTMLElement | null>(null);

useIntersectionObserver(
  loadMoreSentinel,
  ([entry]) => {
    if (entry?.isIntersecting && hasMore.value) {
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
    </div>

    <div
      class="flex flex-col gap-3 border-t pt-4 sm:flex-row sm:items-center sm:justify-between"
    >
      <div class="text-muted-foreground flex items-center gap-2 text-sm">
        <span>每次加载</span>
        <Select v-model="batchSizeValue">
          <SelectTrigger size="sm" class="w-20">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem
              v-for="option in batchSizeOptions"
              :key="option"
              :value="String(option)"
            >
              {{ option }}
            </SelectItem>
          </SelectContent>
        </Select>
        <span
          >{{ Math.min(visibleCount, hosts.length) }} / {{ hosts.length }}</span
        >
      </div>

      <Button
        v-if="hasMore"
        type="button"
        variant="outline"
        @click="emit('load-more')"
      >
        加载更多
      </Button>
      <span ref="loadMoreSentinel" class="h-px" aria-hidden="true" />
    </div>
  </div>
</template>
