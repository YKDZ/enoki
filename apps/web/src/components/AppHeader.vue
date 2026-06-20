<script setup lang="ts">
import { Activity, LoaderCircle, LogOut, Plus, Settings } from "@lucide/vue";

import { Button } from "@/components/ui/button";

defineProps<{
  isAuthenticated: boolean;
  isCreatingEnrollment: boolean;
}>();

defineEmits<{
  createEnrollment: [];
  logout: [];
  toggleGlobalConfiguration: [];
}>();
</script>

<template>
  <header class="border-b bg-background/95 backdrop-blur">
    <div class="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
      <div class="flex items-center gap-3">
        <div
          class="grid size-9 place-items-center rounded-md bg-primary text-primary-foreground"
        >
          <Activity class="size-5" aria-hidden="true" />
        </div>
        <h1 class="text-lg leading-6 font-semibold">Enoki</h1>
      </div>

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
          @click="$emit('createEnrollment')"
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
  </header>
</template>
