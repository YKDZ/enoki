<script setup lang="ts">
import { Download, Upload, EthernetPort } from "@lucide/vue";
import { computed } from "vue";

import { formatBitsPerSecond, formatTrafficBytes } from "@/lib/format";

import type { HostDetail, HostMetricSample } from "../types";

const props = defineProps<{
  latestMetric: HostMetricSample | HostDetail["latestMetrics"] | null;
  latestSample: HostMetricSample | null;
  samples: HostMetricSample[];
}>();

type NetworkRow = {
  key: string;
  name: string;
  rxBitsPerSecond: number | null;
  rxWindowBytes: number;
  txBitsPerSecond: number | null;
  txWindowBytes: number;
};

const networkRows = computed<NetworkRow[]>(() => {
  const latestByName = new Map(
    (props.latestSample?.networkInterfaces ?? []).map((networkInterface) => [
      networkInterface.name,
      networkInterface,
    ]),
  );
  const totalsByName = new Map<string, NetworkRow>();
  const sourceSamples = props.samples.length
    ? props.samples
    : props.latestSample
      ? [props.latestSample]
      : [];

  for (const sample of sourceSamples) {
    for (const networkInterface of sample.networkInterfaces) {
      const latest = latestByName.get(networkInterface.name);
      const totals = totalsByName.get(networkInterface.name) ?? {
        key: `interface:${networkInterface.name}`,
        name: networkInterface.name,
        rxBitsPerSecond: latest?.rxBitsPerSecond ?? null,
        rxWindowBytes: 0,
        txBitsPerSecond: latest?.txBitsPerSecond ?? null,
        txWindowBytes: 0,
      };
      totals.rxWindowBytes += networkInterface.rxBytesDelta;
      totals.txWindowBytes += networkInterface.txBytesDelta;
      totalsByName.set(networkInterface.name, totals);
    }
  }

  const interfaceRows = [...totalsByName.values()].sort((left, right) =>
    left.name.localeCompare(right.name, undefined, {
      numeric: true,
      sensitivity: "base",
    }),
  );

  if (interfaceRows.length <= 1) {
    return interfaceRows;
  }

  return [
    {
      key: "aggregate",
      name: "总计",
      rxBitsPerSecond: props.latestMetric?.networkRxBitsPerSecond ?? null,
      rxWindowBytes: interfaceRows.reduce(
        (total, networkInterface) => total + networkInterface.rxWindowBytes,
        0,
      ),
      txBitsPerSecond: props.latestMetric?.networkTxBitsPerSecond ?? null,
      txWindowBytes: interfaceRows.reduce(
        (total, networkInterface) => total + networkInterface.txWindowBytes,
        0,
      ),
    },
    ...interfaceRows,
  ];
});
</script>

<template>
  <div class="grid gap-4">
    <div v-if="networkRows.length" class="grid gap-2">
      <div class="text-muted-foreground flex items-center gap-2 text-sm">
        <EthernetPort class="size-4" aria-hidden="true" />
        网卡
      </div>
      <div class="grid gap-2 lg:grid-cols-2">
        <div
          v-for="networkInterface in networkRows"
          :key="networkInterface.key"
          class="bg-muted/35 grid gap-2 rounded-md border p-3 text-sm"
        >
          <div class="font-medium wrap-break-word">
            {{ networkInterface.name }}
          </div>
          <div class="grid gap-2 sm:grid-cols-2">
            <div>
              <p class="text-muted-foreground text-xs">接收</p>
              <p class="font-medium">
                {{ formatBitsPerSecond(networkInterface.rxBitsPerSecond) }}
              </p>
              <p class="text-muted-foreground text-xs">
                {{ formatTrafficBytes(networkInterface.rxWindowBytes) }}
              </p>
            </div>
            <div>
              <p class="text-muted-foreground text-xs">发送</p>
              <p class="font-medium">
                {{ formatBitsPerSecond(networkInterface.txBitsPerSecond) }}
              </p>
              <p class="text-muted-foreground text-xs">
                {{ formatTrafficBytes(networkInterface.txWindowBytes) }}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
