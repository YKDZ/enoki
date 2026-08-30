<script setup lang="ts">
import type { ProbeUpgradeOverviewProblem } from "@enoki/api-client";
import { AlertTriangle, LoaderCircle } from "@lucide/vue";

import { Badge } from "@/components/ui/badge";

defineProps<{
  problem: ProbeUpgradeOverviewProblem;
}>();
</script>

<template>
  <Badge
    v-if="problem"
    :class="
      problem.status === 'failed'
        ? 'gap-1 border-[var(--metric-bad)]/40 bg-[var(--metric-bad)]/10 text-[var(--metric-bad)]'
        : 'gap-1 border-[var(--status-stale-border)] bg-[var(--status-stale-bg)] text-[var(--status-stale-fg)]'
    "
    variant="outline"
  >
    <AlertTriangle
      v-if="problem.status === 'failed'"
      class="size-3.5"
      aria-hidden="true"
    />
    <LoaderCircle v-else class="size-3.5" aria-hidden="true" />
    {{ problem.status === "failed" ? "探针升级失败" : "探针升级中" }}
  </Badge>
</template>
