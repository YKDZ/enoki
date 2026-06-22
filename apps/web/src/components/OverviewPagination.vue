<script setup lang="ts">
import { ChevronLeft, ChevronRight } from "@lucide/vue";
import { computed } from "vue";

import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const props = defineProps<{
  page: number;
  pageSize: number;
  pageSizeOptions: number[];
  total: number;
}>();

const emit = defineEmits<{
  "update:page": [page: number];
  "update:pageSize": [pageSize: number];
}>();

const pageSizeValue = computed({
  get: () => String(props.pageSize),
  set(value) {
    const nextPageSize = Number(value);

    if (Number.isFinite(nextPageSize) && nextPageSize > 0) {
      emit("update:pageSize", nextPageSize);
    }
  },
});

const rangeText = computed(() => {
  if (props.total === 0) {
    return "0 / 0";
  }

  const start = (props.page - 1) * props.pageSize + 1;
  const end = Math.min(props.page * props.pageSize, props.total);

  return `${start}-${end} / ${props.total}`;
});
const pageCount = computed(() =>
  Math.max(1, Math.ceil(props.total / props.pageSize)),
);
const minimumPageSize = computed(() => Math.min(...props.pageSizeOptions));
const shouldShowPagination = computed(() => pageCount.value > 1);
const shouldShowPageSize = computed(() => props.total > minimumPageSize.value);
const shouldShowControls = computed(
  () => shouldShowPagination.value || shouldShowPageSize.value,
);
</script>

<template>
  <div
    v-if="shouldShowControls"
    class="grid gap-3 sm:grid-cols-[1fr_auto_1fr] sm:items-center"
  >
    <div class="text-muted-foreground text-sm">
      {{ rangeText }}
    </div>

    <Pagination
      v-if="shouldShowPagination"
      :items-per-page="pageSize"
      :page="page"
      :sibling-count="1"
      :total="total"
      class="mx-0 w-auto justify-start sm:justify-center"
      @update:page="emit('update:page', $event)"
    >
      <PaginationContent v-slot="{ items }">
        <PaginationPrevious size="icon" aria-label="上一页">
          <ChevronLeft class="size-4" aria-hidden="true" />
          <span class="sr-only">上一页</span>
        </PaginationPrevious>
        <template v-for="(item, index) in items" :key="index">
          <PaginationItem
            v-if="item.type === 'page'"
            :is-active="item.value === page"
            :value="item.value"
          >
            {{ item.value }}
          </PaginationItem>
          <PaginationEllipsis v-else :index="index" />
        </template>
        <PaginationNext size="icon" aria-label="下一页">
          <ChevronRight class="size-4" aria-hidden="true" />
          <span class="sr-only">下一页</span>
        </PaginationNext>
      </PaginationContent>
    </Pagination>
    <div v-else aria-hidden="true" />

    <div
      v-if="shouldShowPageSize"
      class="text-muted-foreground flex items-center gap-2 text-sm sm:justify-end"
    >
      <span>每页</span>
      <Select v-model="pageSizeValue">
        <SelectTrigger size="sm" class="w-20">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem
            v-for="option in pageSizeOptions"
            :key="option"
            :value="String(option)"
          >
            {{ option }}
          </SelectItem>
        </SelectContent>
      </Select>
    </div>
    <div v-else aria-hidden="true" />
  </div>
</template>
