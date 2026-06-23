<script setup lang="ts">
import CpuCoreGrid from "../CpuCoreGrid.vue";
import CpuDetails from "../CpuDetails.vue";
import MetricPanel from "../MetricPanel.vue";
import { inventoryText, panelStorageKey } from "./card-utils";
import MetricCardLoading from "./MetricCardLoading.vue";
import type { CpuMetricCardProps } from "./types";

defineProps<CpuMetricCardProps>();
</script>

<template>
  <MetricPanel
    title="CPU"
    :description="`${data.hostFacts.cpuModel || '暂无型号'} / ${inventoryText(data.hostFacts.inventory, 'cpuCount')} 核心`"
    size="xl"
    height="tall"
    :storage-key="panelStorageKey(data.hostFacts.id, 'cpu')"
    collapsible
  >
    <template v-if="data.latestSample" #chart>
      <CpuCoreGrid
        :cpu-core-series="data.chartData.cores"
        :latest-sample="data.latestSample"
        :x-axis-start-continuity-gap-ms="data.chartStartContinuityGapMs"
      />
    </template>
    <CpuDetails
      v-if="data.latestSample"
      :cpu-model="data.hostFacts.cpuModel"
      :inventory="data.hostFacts.inventory"
      :latest-sample="data.latestSample"
    />
    <MetricCardLoading v-else />
  </MetricPanel>
</template>
