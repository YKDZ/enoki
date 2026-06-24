<script setup lang="ts">
import MetricCardLoading from "../shared/MetricCardLoading.vue";
import MetricPanel from "../shared/MetricPanel.vue";
import { panelStorageKey } from "../shared/panel-storage";
import type { CpuMetricCardProps } from "../view-model";
import CpuCoreGrid from "./CoreGrid.vue";
import CpuDetails from "./Details.vue";

defineProps<CpuMetricCardProps>();

function optionalProfileText(value: string | number | null | undefined) {
  return value === null || value === undefined || value === ""
    ? "暂无"
    : String(value);
}
</script>

<template>
  <MetricPanel
    title="CPU"
    :description="`${data.hostFacts.cpuModel || '暂无型号'} / ${optionalProfileText(data.hostFacts.hostProfile?.cpuCount)} 核心`"
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
      :host-profile="data.hostFacts.hostProfile"
      :latest-sample="data.latestSample"
    />
    <MetricCardLoading v-else />
  </MetricPanel>
</template>
