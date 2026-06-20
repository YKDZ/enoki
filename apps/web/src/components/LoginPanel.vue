<script setup lang="ts">
import { LoaderCircle, LogIn } from "@lucide/vue";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

defineProps<{
  isSubmitting: boolean;
  loginError: string;
}>();

const password = defineModel<string>("password", { required: true });

defineEmits<{
  login: [];
}>();
</script>

<template>
  <section class="mx-auto grid max-w-md px-5 py-16">
    <Card>
      <CardHeader>
        <CardTitle>管理员登录</CardTitle>
      </CardHeader>

      <CardContent>
        <form @submit.prevent="$emit('login')">
          <Label class="grid gap-2 text-sm font-medium" for="owner-password">
            管理员密码
            <Input
              id="owner-password"
              v-model="password"
              type="password"
              autocomplete="current-password"
              required
            />
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
