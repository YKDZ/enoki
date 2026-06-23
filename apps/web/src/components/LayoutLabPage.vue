<script setup lang="ts">
import { computed, ref } from "vue";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { createLayoutLabFixture } from "@/lib/layout-lab-fixtures";

import HostMetricSlotGrid from "./HostMetricSlotGrid.vue";
import MetricPanel from "./MetricPanel.vue";

const isDialogOpen = ref(false);
const scenario = computed(() =>
  typeof window !== "undefined" &&
  new URLSearchParams(window.location.search).get("scenario") === "sparse"
    ? "sparse"
    : "dense",
);
const fixture = computed(() => createLayoutLabFixture(scenario.value));
const sizes = ["sm", "md", "lg", "xl"] as const;
const heights = ["normal", "tall"] as const;
</script>

<template>
  <main class="mx-auto grid max-w-7xl gap-6 px-5 py-5" data-layout-root>
    <header class="flex flex-wrap items-start justify-between gap-3">
      <div class="grid gap-1">
        <h1 class="text-xl font-semibold">卡槽布局实验室</h1>
        <p class="text-muted-foreground text-sm">
          使用生产卡槽渲染器和固定极端数据验证响应式布局。
        </p>
      </div>
      <Button type="button" variant="outline" @click="isDialogOpen = true">
        打开测试弹窗
      </Button>
    </header>

    <Dialog v-model:open="isDialogOpen">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>测试弹窗</DialogTitle>
          <DialogDescription>
            用于验证滚动锁定不会改变页面横向布局。
          </DialogDescription>
        </DialogHeader>
      </DialogContent>
    </Dialog>

    <section class="grid gap-3" data-layout-section="production-slots">
      <h2 class="text-base font-semibold">生产卡槽</h2>
      <HostMetricSlotGrid
        :chart-data="fixture.chartData"
        :chart-start-continuity-gap-ms="fixture.chartStartContinuityGapMs"
        :host="fixture.host"
        :latest-metric="fixture.latestMetric"
        :latest-sample="fixture.latestSample"
        :samples="fixture.samples"
        :x-axis-max-ms="fixture.xAxisMaxMs"
        :x-axis-min-ms="fixture.xAxisMinMs"
      />
    </section>

    <section class="grid gap-3" data-layout-section="panel-matrix">
      <h2 class="text-base font-semibold">卡片配置矩阵</h2>
      <div class="grid grid-cols-12 gap-4" data-layout-grid>
        <MetricPanel
          v-for="size in sizes"
          :key="`body-${size}`"
          :title="`正文 ${size}`"
          :size="size"
          data-layout-card
        >
          <p class="text-muted-foreground text-sm break-words">
            长文本内容用于验证换行行为：abcdefghijklmnopqrstuvwxyz0123456789 /
            very-long-token-without-natural-breakpoints
          </p>
        </MetricPanel>

        <MetricPanel
          v-for="height in heights"
          :key="`chart-${height}`"
          title="图表卡片"
          size="lg"
          :height="height"
          data-layout-card
          collapsible
        >
          <template #chart>
            <div
              class="bg-muted/35 grid h-72 min-h-72 place-items-center rounded-md border text-sm"
              data-layout-chart
            >
              chart
            </div>
          </template>
          <p class="text-muted-foreground text-sm">
            折叠后这段正文仍然需要保留。
          </p>
        </MetricPanel>

        <MetricPanel
          title="右侧明细"
          size="xl"
          layout="side"
          data-layout-card
          collapsible
        >
          <template #chart>
            <div
              class="bg-muted/35 grid h-72 min-h-72 place-items-center rounded-md border text-sm"
              data-layout-chart
            >
              chart
            </div>
          </template>
          <template #details>
            <div class="grid gap-2 text-sm">
              <div
                v-for="index in 8"
                :key="index"
                class="rounded-md border p-3"
              >
                明细 {{ index }} / very-long-detail-label-for-layout-check
              </div>
            </div>
          </template>
        </MetricPanel>
      </div>
    </section>
  </main>
</template>
