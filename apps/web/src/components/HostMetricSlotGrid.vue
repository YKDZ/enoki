<script setup lang="ts">
import {
  formatBitsPerSecond,
  formatPercent,
  formatTrafficBytes,
} from "@/lib/format";
import type { MetricsChartData } from "@/lib/metrics-chart-data";

import type { HostDetail, HostMetricSample } from "../types";
import CpuCoreGrid from "./CpuCoreGrid.vue";
import CpuDetails from "./CpuDetails.vue";
import DiskDetails from "./DiskDetails.vue";
import MemoryDetails from "./MemoryDetails.vue";
import MetricPanel from "./MetricPanel.vue";
import MetricsChart from "./MetricsChart.vue";
import NetworkDetails from "./NetworkDetails.vue";

defineProps<{
  chartData: MetricsChartData;
  chartStartContinuityGapMs: number;
  host: HostDetail;
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  latestSample: HostMetricSample | null;
  samples: HostMetricSample[];
  xAxisMaxMs: number;
  xAxisMinMs: number;
}>();

function collectorAvailable(
  host: HostDetail,
  domain: "cpu" | "disk" | "memory" | "network",
) {
  return host.collectorCapabilities?.official?.[domain]?.available !== false;
}

function inventoryText(host: HostDetail, key: string) {
  const value = host.inventory?.[key];
  return value === null || value === undefined || value === ""
    ? "暂无"
    : String(value);
}

function panelStorageKey(host: HostDetail, panel: string) {
  return `enoki:host:${host.id}:panel:${panel}:collapsed`;
}
</script>

<template>
  <div class="grid grid-cols-12 gap-4" data-layout-grid>
    <MetricPanel
      v-if="collectorAvailable(host, 'cpu')"
      title="CPU"
      :description="`${host.cpuModel || '暂无型号'} / ${inventoryText(host, 'cpuCount')} 核心`"
      size="xl"
      height="tall"
      :storage-key="panelStorageKey(host, 'cpu')"
      data-layout-card
      data-panel-id="cpu"
      collapsible
    >
      <template #chart>
        <CpuCoreGrid
          :cpu-core-series="chartData.cpu.cores"
          :latest-sample="latestSample"
          :x-axis-start-continuity-gap-ms="chartStartContinuityGapMs"
        />
      </template>
      <CpuDetails
        :cpu-model="host.cpuModel"
        :inventory="host.inventory"
        :latest-sample="latestSample"
      />
    </MetricPanel>

    <MetricPanel
      v-if="collectorAvailable(host, 'network')"
      title="网络"
      description="公网接口吞吐"
      size="lg"
      height="normal"
      :storage-key="panelStorageKey(host, 'network')"
      data-layout-card
      data-panel-id="network"
      collapsible
    >
      <template #chart>
        <MetricsChart
          :series="chartData.network.aggregate"
          title="吞吐量"
          :x-axis-max-ms="xAxisMaxMs"
          :x-axis-min-ms="xAxisMinMs"
          :x-axis-start-continuity-gap-ms="chartStartContinuityGapMs"
          y-axis-name="b/s"
          :value-formatter="formatBitsPerSecond"
        />
      </template>
      <NetworkDetails
        :latest-metric="latestMetric"
        :latest-sample="latestSample"
        :samples="samples"
      />
    </MetricPanel>

    <MetricPanel
      v-if="collectorAvailable(host, 'memory')"
      title="内存"
      description="使用量、缓存与交换"
      size="lg"
      height="normal"
      :storage-key="panelStorageKey(host, 'memory')"
      data-layout-card
      data-panel-id="memory"
      collapsible
    >
      <template #chart>
        <MetricsChart
          :series="[chartData.memory.usedPercent]"
          title="内存"
          :x-axis-max-ms="xAxisMaxMs"
          :x-axis-min-ms="xAxisMinMs"
          :x-axis-start-continuity-gap-ms="chartStartContinuityGapMs"
          :y-axis-max="100"
          :y-axis-min="0"
          y-axis-name="%"
          :value-formatter="formatPercent"
        />
      </template>
      <MemoryDetails :host="host" :latest-metric="latestMetric" />
    </MetricPanel>

    <MetricPanel
      v-if="collectorAvailable(host, 'disk')"
      title="磁盘与 I/O"
      size="xl"
      layout="side"
      :storage-key="panelStorageKey(host, 'disk')"
      data-layout-card
      data-panel-id="disk"
      collapsible
    >
      <template #chart>
        <div class="grid gap-4">
          <MetricsChart
            :series="[chartData.disk.aggregateUsedPercent]"
            title="占用率"
            :x-axis-max-ms="xAxisMaxMs"
            :x-axis-min-ms="xAxisMinMs"
            :x-axis-start-continuity-gap-ms="chartStartContinuityGapMs"
            :y-axis-max="100"
            :y-axis-min="0"
            y-axis-name="%"
            :value-formatter="formatPercent"
          />
          <MetricsChart
            :series="chartData.disk.aggregateIoBytes"
            title="I/O"
            :x-axis-max-ms="xAxisMaxMs"
            :x-axis-min-ms="xAxisMinMs"
            :x-axis-start-continuity-gap-ms="chartStartContinuityGapMs"
            y-axis-name="B"
            :value-formatter="formatTrafficBytes"
          />
        </div>
      </template>
      <template #details>
        <DiskDetails :latest-sample="latestSample" variant="stack" />
      </template>
    </MetricPanel>
  </div>
</template>
