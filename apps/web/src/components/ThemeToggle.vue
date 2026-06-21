<script setup lang="ts">
import { Monitor, Moon, Sun } from "@lucide/vue";
import { useColorMode } from "@vueuse/core";
import { computed } from "vue";

import { Button } from "@/components/ui/button";

type ThemeMode = "auto" | "light" | "dark";

const mode = useColorMode({
  initialValue: "auto",
  modes: {
    auto: "",
    dark: "dark",
    light: "",
  },
  storageKey: "enoki-theme-mode",
});

const storedMode = computed(() => mode.store.value as ThemeMode);
const modeText = computed(() => {
  if (storedMode.value === "light") {
    return "浅色";
  }

  if (storedMode.value === "dark") {
    return "深色";
  }

  return "自动";
});
const nextModeText = computed(() => {
  if (storedMode.value === "auto") {
    return "浅色";
  }

  if (storedMode.value === "light") {
    return "深色";
  }

  return "自动";
});
const buttonLabel = computed(
  () => `主题：${modeText.value}，点击切换到${nextModeText.value}`,
);

function cycleThemeMode() {
  if (storedMode.value === "auto") {
    mode.store.value = "light";
    return;
  }

  if (storedMode.value === "light") {
    mode.store.value = "dark";
    return;
  }

  mode.store.value = "auto";
}
</script>

<template>
  <Button
    variant="outline"
    size="icon"
    type="button"
    :aria-label="buttonLabel"
    :title="buttonLabel"
    @click="cycleThemeMode"
  >
    <Monitor v-if="storedMode === 'auto'" class="size-4" aria-hidden="true" />
    <Sun v-else-if="storedMode === 'light'" class="size-4" aria-hidden="true" />
    <Moon v-else class="size-4" aria-hidden="true" />
  </Button>
</template>
