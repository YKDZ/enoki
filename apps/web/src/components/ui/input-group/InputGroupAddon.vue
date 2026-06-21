<script setup lang="ts">
import type { HTMLAttributes } from "vue";

import { cn } from "@/lib/utils";

const props = withDefaults(
  defineProps<{
    align?: "inline-start" | "inline-end";
    class?: HTMLAttributes["class"];
  }>(),
  {
    align: "inline-start",
  },
);
</script>

<template>
  <div
    data-slot="input-group-addon"
    :data-align="align"
    :class="
      cn(
        'text-muted-foreground flex h-full shrink-0 items-center gap-1.5 px-2',
        align === 'inline-end' && 'ml-auto',
        props.class,
      )
    "
  >
    <slot />
  </div>
</template>
