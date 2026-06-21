<script setup lang="ts">
import type { HTMLAttributes } from "vue";

import { cn } from "@/lib/utils";

const props = withDefaults(
  defineProps<{
    class?: HTMLAttributes["class"];
    size?: "sm" | "icon-xs";
    type?: "button" | "submit" | "reset";
    variant?: "ghost" | "default";
  }>(),
  {
    size: "sm",
    type: "button",
    variant: "ghost",
  },
);
</script>

<template>
  <button
    data-slot="input-group-button"
    :type="type"
    :class="
      cn(
        'inline-flex shrink-0 items-center justify-center gap-1.5 rounded-md text-sm font-medium transition-colors outline-none disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0',
        variant === 'ghost' && 'hover:bg-accent hover:text-accent-foreground',
        variant === 'default' &&
          'bg-primary text-primary-foreground hover:bg-primary/90',
        size === 'sm' && 'h-7 px-2',
        size === 'icon-xs' && 'size-7',
        props.class,
      )
    "
  >
    <slot />
  </button>
</template>
