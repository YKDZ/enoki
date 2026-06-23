import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import type { HostMetricSample } from "../types";
import NetworkDetails from "./NetworkDetails.vue";

const baseSample: HostMetricSample = {
  collectedAtMs: 1_725_000_000_000,
  cpuCores: [],
  cpuPercent: null,
  diskTotalBytes: null,
  diskUsedBytes: null,
  disks: [],
  memoryTotalBytes: null,
  memoryUsedBytes: null,
  networkInterfaces: [],
  networkRxBitsPerSecond: null,
  networkRxBytesDelta: null,
  networkTxBitsPerSecond: null,
  networkTxBytesDelta: null,
  receivedAtMs: 1_725_000_000_000,
  sequence: 1,
  uptimeSeconds: null,
};

function renderNetworkDetails(sample: HostMetricSample, samples = [sample]) {
  return renderToString(
    createSSRApp(NetworkDetails, {
      latestMetric: sample,
      latestSample: sample,
      samples,
    }),
  );
}

describe("Network details", () => {
  it("does not render an aggregate card when only one interface is monitored", async () => {
    const sample: HostMetricSample = {
      ...baseSample,
      networkInterfaces: [
        {
          name: "eth0",
          rxBitsPerSecond: 1_600,
          rxBytesDelta: 1_024,
          txBitsPerSecond: 800,
          txBytesDelta: 512,
        },
      ],
      networkRxBitsPerSecond: 1_600,
      networkRxBytesDelta: 1_024,
      networkTxBitsPerSecond: 800,
      networkTxBytesDelta: 512,
    };

    const html = await renderNetworkDetails(sample);

    expect(html).toContain("eth0");
    expect(html).not.toContain("总计");
  });

  it("renders aggregate traffic as the first card when multiple interfaces are monitored", async () => {
    const firstSample: HostMetricSample = {
      ...baseSample,
      networkInterfaces: [
        {
          name: "eth1",
          rxBitsPerSecond: 3_200,
          rxBytesDelta: 2_048,
          txBitsPerSecond: 1_600,
          txBytesDelta: 1_024,
        },
        {
          name: "eth0",
          rxBitsPerSecond: 1_600,
          rxBytesDelta: 1_024,
          txBitsPerSecond: 800,
          txBytesDelta: 512,
        },
      ],
      networkRxBitsPerSecond: 4_800,
      networkRxBytesDelta: 3_072,
      networkTxBitsPerSecond: 2_400,
      networkTxBytesDelta: 1_536,
    };
    const latestSample: HostMetricSample = {
      ...firstSample,
      collectedAtMs: 1_725_000_030_000,
      networkInterfaces: [
        {
          name: "eth1",
          rxBitsPerSecond: 6_400,
          rxBytesDelta: 4_096,
          txBitsPerSecond: 3_200,
          txBytesDelta: 2_048,
        },
        {
          name: "eth0",
          rxBitsPerSecond: 3_200,
          rxBytesDelta: 2_048,
          txBitsPerSecond: 1_600,
          txBytesDelta: 1_024,
        },
      ],
      networkRxBitsPerSecond: 9_600,
      networkRxBytesDelta: 6_144,
      networkTxBitsPerSecond: 4_800,
      networkTxBytesDelta: 3_072,
    };

    const html = await renderNetworkDetails(latestSample, [
      firstSample,
      latestSample,
    ]);

    expect(html.indexOf("总计")).toBeLessThan(html.indexOf("eth0"));
    expect(html.indexOf("总计")).toBeLessThan(html.indexOf("eth1"));
    expect(html).toContain("9.6 Kb/s");
    expect(html).toContain("4.8 Kb/s");
    expect(html).toContain("9 KB");
    expect(html).toContain("4.5 KB");
  });
});
