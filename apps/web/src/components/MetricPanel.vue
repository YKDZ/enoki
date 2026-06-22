<script setup lang="ts">
import { ChevronDown, ChevronUp } from "@lucide/vue";
import { ref, watch } from "vue";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const props = defineProps<{
  collapsible?: boolean;
  defaultCollapsed?: boolean;
  description?: string;
  height?: "normal" | "tall";
  layout?: "side" | "stack";
  size?: "sm" | "md" | "lg" | "xl";
  storageKey?: string;
  title: string;
  width?: "half" | "full";
}>();

const isCollapsed = ref(initialCollapsed());
const sizeClass = {
  lg: "col-span-12 xl:col-span-6",
  md: "col-span-12 md:col-span-6 xl:col-span-4",
  sm: "col-span-12 md:col-span-6 xl:col-span-3",
  xl: "col-span-12",
};

watch(isCollapsed, (value) => {
  if (!props.storageKey || typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(props.storageKey, value ? "1" : "0");
});

function initialCollapsed() {
  if (!props.storageKey || typeof window === "undefined") {
    return Boolean(props.defaultCollapsed);
  }

  const stored = window.localStorage.getItem(props.storageKey);

  if (stored === "1") {
    return true;
  }

  if (stored === "0") {
    return false;
  }

  return Boolean(props.defaultCollapsed);
}
</script>

<template>
  <Card
    :class="[
      'min-w-0 overflow-hidden',
      size ? sizeClass[size] : width === 'full' ? 'lg:col-span-2' : '',
      height === 'normal' ? 'min-h-[280px]' : '',
      height === 'tall' && !isCollapsed ? 'min-h-[520px] lg:row-span-2' : '',
    ]"
  >
    <CardHeader class="pb-2">
      <div class="flex min-w-0 items-start justify-between gap-3">
        <div class="min-w-0">
          <CardTitle class="text-base">{{ title }}</CardTitle>
          <p v-if="description" class="text-muted-foreground mt-1 text-xs">
            {{ description }}
          </p>
        </div>
        <div class="flex items-center gap-2">
          <slot name="action" />
          <Button
            v-if="collapsible"
            type="button"
            variant="outline"
            size="sm"
            @click="isCollapsed = !isCollapsed"
          >
            <ChevronDown v-if="isCollapsed" class="size-4" aria-hidden="true" />
            <ChevronUp v-else class="size-4" aria-hidden="true" />
            {{ isCollapsed ? "展开" : "收起" }}
          </Button>
        </div>
      </div>
    </CardHeader>
    <CardContent
      v-if="!isCollapsed || $slots.default || $slots.footer"
      class="grid gap-4"
    >
      <div
        v-if="$slots.details"
        :class="[
          'grid min-w-0 gap-4',
          layout === 'side'
            ? 'xl:grid-cols-[minmax(0,1fr)_320px]'
            : 'xl:grid-cols-1',
        ]"
      >
        <div v-if="!isCollapsed" class="grid min-w-0 gap-4">
          <div
            v-if="$slots.chart || $slots.right"
            :class="[
              'grid min-w-0 gap-4',
              $slots.right
                ? 'xl:grid-cols-[minmax(0,1fr)_220px]'
                : 'xl:grid-cols-1',
            ]"
          >
            <div v-if="$slots.chart" class="min-w-0">
              <slot name="chart" />
            </div>
            <aside v-if="$slots.right" class="min-w-0">
              <slot name="right" />
            </aside>
          </div>
        </div>
        <aside v-if="$slots.details" class="min-w-0">
          <slot name="details" />
        </aside>
      </div>
      <div
        v-else-if="!isCollapsed && ($slots.chart || $slots.right)"
        :class="[
          'grid min-w-0 gap-4',
          $slots.right
            ? 'xl:grid-cols-[minmax(0,1fr)_220px]'
            : 'xl:grid-cols-1',
        ]"
      >
        <div v-if="$slots.chart" class="min-w-0">
          <slot name="chart" />
        </div>
        <aside v-if="$slots.right" class="min-w-0">
          <slot name="right" />
        </aside>
      </div>
      <slot />
      <footer v-if="$slots.footer" class="text-muted-foreground text-sm">
        <slot name="footer" />
      </footer>
    </CardContent>
  </Card>
</template>
