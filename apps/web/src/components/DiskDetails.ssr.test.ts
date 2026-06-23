import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import type { HostMetricSample } from "../types";
import DiskDetails from "./DiskDetails.vue";

const baseSample: HostMetricSample = {
  collectedAtMs: 1_725_000_000_000,
  cpuCores: [],
  cpuPercent: null,
  diskTotalBytes: 20_000,
  diskUsedBytes: 16_000,
  disks: [
    {
      availableBytes: 4_000,
      filesystemType: "ext4",
      mountPoint: "/",
      readBytesDelta: 300,
      totalBytes: 20_000,
      usedBytes: 16_000,
      writeBytesDelta: 700,
    },
  ],
  memoryTotalBytes: null,
  memoryUsedBytes: null,
  networkInterfaces: [],
  networkRxBitsPerSecond: null,
  networkRxBytesDelta: null,
  networkTxBitsPerSecond: null,
  networkTxBytesDelta: null,
  receivedAtMs: 1_725_000_000_500,
  sequence: 1,
  uptimeSeconds: null,
};

describe("Disk details", () => {
  it("renders only filesystem usage facts", async () => {
    const html = await renderToString(
      createSSRApp(DiskDetails, {
        latestSample: {
          ...baseSample,
          diskHealth: [
            {
              deviceName: "/dev/sda",
              model: "Samsung SSD 870 EVO 1TB",
              passed: true,
              powerOnHours: 12_345,
              serialNumber: "S6PTEST",
              temperatureCelsius: 31,
            },
          ],
        },
      }),
    );

    expect(html).toContain("挂载点");
    expect(html).toContain("/");
    expect(html).toContain("读取");
    expect(html).not.toContain("硬盘健康");
    expect(html).not.toContain("Samsung SSD 870 EVO 1TB");
  });

  it("does not render an empty Disk Health block", async () => {
    const html = await renderToString(
      createSSRApp(DiskDetails, {
        latestSample: baseSample,
      }),
    );

    expect(html).not.toContain("硬盘健康");
    expect(html.toLowerCase()).not.toContain("n/a");
  });

  it("renders an empty state when disk metrics are absent", async () => {
    const html = await renderToString(
      createSSRApp(DiskDetails, {
        latestSample: {
          ...baseSample,
          disks: [],
        },
      }),
    );

    expect(html).toContain("暂无磁盘数据");
  });
});
