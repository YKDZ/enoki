<script setup lang="ts">
import { Eye, EyeOff, LoaderCircle, LogIn, ServerCrash } from "@lucide/vue";
import { ref } from "vue";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group";
import { Label } from "@/components/ui/label";
import type { LoginErrorKind } from "@/lib/login-errors";

import StateHero from "./StateHero.vue";

defineProps<{
  isSubmitting: boolean;
  loginError: string;
  loginErrorKind: LoginErrorKind;
}>();

const password = defineModel<string>("password", { required: true });
const isPasswordVisible = ref(false);

defineEmits<{
  login: [];
}>();
</script>

<template>
  <StateHero
    v-if="loginError && loginErrorKind === 'hub_unavailable'"
    :icon="ServerCrash"
    tone="destructive"
    title="Hub 暂不可用"
    :description="loginError"
  >
    <template #action>
      <Button type="button" :disabled="isSubmitting" @click="$emit('login')">
        <LoaderCircle
          v-if="isSubmitting"
          class="size-4 animate-spin"
          aria-hidden="true"
        />
        <ServerCrash v-else class="size-4" aria-hidden="true" />
        重试连接
      </Button>
    </template>
  </StateHero>

  <section v-else class="mx-auto grid max-w-md px-5 py-16">
    <Card>
      <CardHeader>
        <CardTitle>登录</CardTitle>
      </CardHeader>

      <CardContent>
        <form @submit.prevent="$emit('login')">
          <Label class="grid gap-2 text-sm font-medium" for="owner-password">
            密码
            <InputGroup>
              <InputGroupInput
                id="owner-password"
                v-model="password"
                :type="isPasswordVisible ? 'text' : 'password'"
                autocomplete="current-password"
                required
              />
              <InputGroupAddon align="inline-end" class="pr-1">
                <InputGroupButton
                  :aria-label="isPasswordVisible ? '隐藏密码' : '显示密码'"
                  :title="isPasswordVisible ? '隐藏密码' : '显示密码'"
                  size="icon-xs"
                  @click="isPasswordVisible = !isPasswordVisible"
                >
                  <EyeOff
                    v-if="isPasswordVisible"
                    class="size-4"
                    aria-hidden="true"
                  />
                  <Eye v-else class="size-4" aria-hidden="true" />
                </InputGroupButton>
              </InputGroupAddon>
            </InputGroup>
          </Label>

          <p
            v-if="loginError"
            class="mt-3 text-sm leading-6 text-red-600"
            role="alert"
          >
            {{ loginError }}
          </p>

          <Button
            class="mt-6 h-10 w-full"
            type="submit"
            :disabled="isSubmitting"
          >
            <LoaderCircle
              v-if="isSubmitting"
              class="size-4 animate-spin"
              aria-hidden="true"
            />
            <LogIn v-else class="size-4" aria-hidden="true" />
            登录
          </Button>
        </form>
      </CardContent>
    </Card>
  </section>
</template>
