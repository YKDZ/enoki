<script setup lang="ts">
import type { HTMLAttributes } from "vue";

import { cn } from "@/lib/utils";

const props = defineProps<{
  class?: HTMLAttributes["class"];
}>();
</script>

<template>
  <div
    data-slot="input-group"
    :class="
      cn(
        'border-input bg-background focus-within:border-ring focus-within:ring-ring/50 flex h-9 w-full min-w-0 items-center rounded-md border shadow-xs transition-[color,box-shadow] focus-within:ring-3',
        props.class,
      )
    "
  >
    <slot />
  </div>
</template>
