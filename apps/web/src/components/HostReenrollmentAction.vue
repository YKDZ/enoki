<script setup lang="ts">
import { Button } from "@/components/ui/button";
import { canReenrollHost } from "@/lib/host-reenrollment";

import type { HostSummary } from "../types";

const props = defineProps<{
  host: Pick<HostSummary, "id" | "status">;
}>();

defineEmits<{
  createExistingHostEnrollment: [hostId: number];
}>();
</script>

<template>
  <Button
    v-if="canReenrollHost(props.host)"
    type="button"
    size="sm"
    variant="outline"
    @click.stop="$emit('createExistingHostEnrollment', host.id)"
    @keydown.stop
  >
    重新注册探针
  </Button>
</template>
