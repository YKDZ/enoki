import { describe, expect, it } from "vitest";

import {
  cpuMetricCardProps,
  officialMetricCardCapability,
  officialMetricCardProps,
} from "./registry";
import type {
  CpuMetricCardViewModel,
  OfficialMetricCardSourceViewModel,
} from "./view-model";

describe("official metrics card props", () => {
  it("builds CPU card props from CPU-only data", () => {
    const data: CpuMetricCardViewModel = {
      chartData: {
        aggregate: { name: "使用率", points: [[1_725_000_000_000, 24]] },
        cores: [{ name: "cpu0", points: [[1_725_000_000_000, 24]] }],
      },
      chartStartContinuityGapMs: 4_000,
      hostFacts: {
        cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
        hostProfile: {
          architecture: "x86_64",
          cpuCount: 2,
          filesystems: [],
          hostname: "managed-host-01",
          kernel: "6.8.0",
          memoryTotalBytes: 8_589_934_592,
          networkInterfaces: [],
          os: "linux",
          probeVersion: "0.1.0",
        },
        id: 1,
      },
      latestSample: null,
    };

    expect(cpuMetricCardProps(data)).toEqual({
      data,
    });
  });

  it("renders common card domains without collector capability payloads", () => {
    const data = createSourceViewModel();

    expect(officialMetricCardProps("cpu", {}, data)).not.toBeNull();
    expect(officialMetricCardProps("memory", {}, data)).not.toBeNull();
    expect(officialMetricCardProps("disk", {}, data)).not.toBeNull();
    expect(officialMetricCardProps("network", {}, data)).not.toBeNull();
  });

  it("lets Disk Health own its typed capability rendering decision", () => {
    const data = createSourceViewModel({
      latestMetric: {
        collectedAtMs: 1_725_000_000_000,
        cpuCores: [],
        cpuPercent: 24,
        diskHealth: [
          {
            deviceName: "/dev/sda",
            model: "Samsung SSD 870 EVO 1TB",
            passed: true,
            powerOnHours: 12_345,
            role: null,
            serialNumber: "S6PTEST",
            temperatureCelsius: 31,
            totalBytes: null,
            usageMountPoint: null,
            usedBytes: null,
          },
        ],
        diskTotalBytes: 100,
        diskUsedBytes: 50,
        disks: [],
        memoryTotalBytes: 100,
        memoryUsedBytes: 40,
        networkInterfaces: [],
        networkRxBitsPerSecond: null,
        networkRxBytesDelta: null,
        networkTxBitsPerSecond: null,
        networkTxBytesDelta: null,
        receivedAtMs: 1_725_000_000_000,
        sequence: 1,
        uptimeSeconds: 60,
      },
    });

    expect(officialMetricCardProps("diskHealth", {}, data)).toEqual({
      capability: { diagnostic: "", status: 0 },
      data: {
        hostId: 1,
        latestDiskHealth: data.latestMetric?.diskHealth,
      },
    });

    const capability = officialMetricCardCapability("diskHealth", {
      official: {
        diskHealth: { diagnostic: "", status: 1 },
      },
    });

    expect(officialMetricCardProps("diskHealth", capability, data)).toEqual({
      capability: { diagnostic: "", status: 1 },
      data: {
        hostId: 1,
        latestDiskHealth: data.latestMetric?.diskHealth,
      },
    });

    const missingToolCapability = officialMetricCardCapability("diskHealth", {
      official: {
        diskHealth: { diagnostic: "smartctl is not installed", status: 2 },
      },
    });

    expect(
      officialMetricCardProps("diskHealth", missingToolCapability, {
        ...data,
        latestMetric: { ...data.latestMetric!, diskHealth: [] },
      }),
    ).toEqual({
      capability: { diagnostic: "smartctl is not installed", status: 2 },
      data: {
        hostId: 1,
        latestDiskHealth: null,
      },
    });
  });
});

function createSourceViewModel(
  overrides: Partial<OfficialMetricCardSourceViewModel> = {},
): OfficialMetricCardSourceViewModel {
  return {
    chartData: {
      cpu: {
        aggregate: { name: "使用率", points: [] },
        cores: [],
      },
      disk: {
        aggregateIoBytes: [],
        aggregateUsedPercent: { name: "使用率", points: [] },
        mounts: [],
      },
      memory: {
        usedPercent: { name: "使用率", points: [] },
      },
      network: {
        aggregate: [],
        interfaces: [],
      },
    },
    chartStartContinuityGapMs: 4_000,
    hostFacts: {
      cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
      hostProfile: {
        architecture: "x86_64",
        cpuCount: 2,
        filesystems: [],
        hostname: "managed-host-01",
        kernel: "6.8.0",
        memoryTotalBytes: 8_589_934_592,
        networkInterfaces: [],
        os: "linux",
        probeVersion: "0.1.0",
      },
      id: 1,
    },
    latestMetric: null,
    latestSample: null,
    samples: [],
    xAxisMaxMs: 1_725_000_000_000,
    xAxisMinMs: 1_725_000_000_000 - 60_000,
    ...overrides,
  };
}
