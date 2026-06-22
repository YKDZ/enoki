<script setup lang="ts">
import { LoaderCircle, LogOut, Plus, Settings } from "@lucide/vue";

import { Button } from "@/components/ui/button";

import ThemeToggle from "./ThemeToggle.vue";

defineProps<{
  isAuthenticated: boolean;
  isCreatingEnrollment: boolean;
}>();

defineEmits<{
  goHome: [];
  openEnrollment: [];
  logout: [];
  toggleGlobalConfiguration: [];
}>();
</script>

<template>
  <header class="bg-background/95 border-b backdrop-blur">
    <div class="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
      <button
        type="button"
        class="focus-visible:ring-ring flex cursor-pointer items-center gap-3 rounded-md pr-2 transition outline-none focus-visible:ring-2 focus-visible:ring-offset-2"
        aria-label="返回首页"
        @click="$emit('goHome')"
      >
        <span
          class="size-8 shrink-0 bg-current"
          style="
            mask: url(&quot;/logo.svg&quot;) center / contain no-repeat;
            -webkit-mask: url(&quot;/logo.svg&quot;) center / contain no-repeat;
          "
          aria-hidden="true"
        />
        <h1 class="text-lg leading-6 font-semibold">Enoki</h1>
      </button>

      <div class="flex items-center gap-2">
        <ThemeToggle />
        <nav
          v-if="isAuthenticated"
          class="flex items-center gap-2"
          aria-label="主要操作"
        >
          <Button
            variant="outline"
            size="icon"
            type="button"
            aria-label="添加探针"
            title="添加探针"
            :disabled="isCreatingEnrollment"
            @click="$emit('openEnrollment')"
          >
            <LoaderCircle
              v-if="isCreatingEnrollment"
              class="size-4 animate-spin"
              aria-hidden="true"
            />
            <Plus v-else class="size-4" aria-hidden="true" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            type="button"
            aria-label="设置"
            title="设置"
            @click="$emit('toggleGlobalConfiguration')"
          >
            <Settings class="size-4" aria-hidden="true" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            type="button"
            aria-label="退出登录"
            title="退出登录"
            @click="$emit('logout')"
          >
            <LogOut class="size-4" aria-hidden="true" />
          </Button>
        </nav>
      </div>
    </div>
  </header>
</template>
