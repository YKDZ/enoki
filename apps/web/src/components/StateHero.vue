<script setup lang="ts">
import type { Component } from "vue";

const props = withDefaults(
  defineProps<{
    description?: string;
    icon: Component;
    tone?: "default" | "destructive";
    title: string;
  }>(),
  {
    description: "",
    tone: "default",
  },
);
</script>

<template>
  <section
    class="grid min-h-[24rem] place-items-center px-5 py-16 text-center"
    aria-live="polite"
  >
    <div class="mx-auto grid w-full max-w-xl justify-items-center gap-5">
      <div
        :class="[
          'grid size-16 place-items-center rounded-full border',
          props.tone === 'destructive'
            ? 'border-destructive/25 bg-destructive/10 text-destructive'
            : 'border-border bg-muted text-muted-foreground',
        ]"
        aria-hidden="true"
      >
        <component :is="props.icon" class="size-8" />
      </div>

      <div class="grid gap-2">
        <h2 class="text-2xl font-semibold tracking-normal">
          {{ props.title }}
        </h2>
        <p
          v-if="props.description"
          class="text-muted-foreground mx-auto max-w-md text-sm leading-6"
        >
          {{ props.description }}
        </p>
      </div>

      <div v-if="$slots.action" class="flex flex-wrap justify-center gap-2">
        <slot name="action" />
      </div>
    </div>
  </section>
</template>
