import { describe, expect, it } from "vitest";

import type {
  CollectorCapabilities,
  CpuCoreMetric,
  DiskHealthMetric,
  DiskUsageMetric,
  NetworkInterfaceDeltaMetric,
} from "../src/protocol.js";
import {
  parseWebSocketServerMessage,
  parseWebSocketClientMessage,
  webSocketClientMessageSchema,
} from "../src/websocket.js";

describe("WebSocket contracts", () => {
  it("validates browser detail subscription messages", () => {
    expect(
      parseWebSocketClientMessage({
        hostId: 42,
        type: "subscribe_host_detail",
      }),
    ).toEqual({
      hostId: 42,
      type: "subscribe_host_detail",
    });

    expect(
      parseWebSocketClientMessage({
        hostId: 42,
        type: "unsubscribe_host_detail",
      }),
    ).toEqual({
      hostId: 42,
      type: "unsubscribe_host_detail",
    });
  });

  it("rejects invalid browser WebSocket messages", () => {
    expect(parseWebSocketClientMessage("not an object")).toBeNull();
    expect(
      parseWebSocketClientMessage({
        hostId: "42",
        type: "subscribe_host_detail",
      }),
    ).toBeNull();
    expect(
      parseWebSocketClientMessage({
        type: "subscribe_everything",
      }),
    ).toBeNull();
  });

  it("exports the Valibot schema for shared runtime validation", () => {
    expect(webSocketClientMessageSchema).toBeDefined();
  });

  it("exports JSON metric types derived from the Probe protocol", () => {
    const capabilities = {
      official: {
        diskHealth: {
          available: true,
        },
        inventory: {
          available: true,
        },
      },
    } satisfies CollectorCapabilities;
    const cpuCore = {
      name: "cpu0",
      usagePercent: 12.5,
    } satisfies CpuCoreMetric;
    const disk = {
      availableBytes: 512,
      filesystemType: "ext4",
      mountPoint: "/",
      readBytesDelta: 128,
      totalBytes: 1024,
      usedBytes: 512,
      writeBytesDelta: 64,
    } satisfies DiskUsageMetric;
    const diskHealth = {
      deviceName: "/dev/sda",
      model: "Example SSD",
      passed: true,
      powerOnHours: 100,
      role: "data",
      serialNumber: "serial",
      temperatureCelsius: 32,
      totalBytes: 1024,
      usageMountPoint: "/",
      usedBytes: 512,
    } satisfies DiskHealthMetric;
    const networkInterface = {
      name: "eth0",
      rxBytesDelta: 1024,
      txBytesDelta: 2048,
    } satisfies NetworkInterfaceDeltaMetric;

    expect({
      capabilities,
      cpuCore,
      disk,
      diskHealth,
      networkInterface,
    }).toBeDefined();
  });

  it("validates server Host summary messages", () => {
    expect(
      parseWebSocketServerMessage({
        host: {
          collectorCapabilities: {
            official: {
              disk: {
                available: false,
              },
            },
          },
          id: 1,
          lastSeenAtMs: 1_725_000_010_000,
          latestMetrics: null,
          status: "online",
          warningFlags: {
            clockSkew: false,
            probeConfigurationError: false,
          },
        },
        type: "host_summary",
      }),
    ).toEqual({
      host: {
        collectorCapabilities: {
          official: {
            disk: {
              available: false,
            },
          },
        },
        id: 1,
        lastSeenAtMs: 1_725_000_010_000,
        latestMetrics: null,
        status: "online",
        warningFlags: {
          clockSkew: false,
          probeConfigurationError: false,
        },
      },
      type: "host_summary",
    });
  });

  it("validates precomputed network throughput in summary metrics", () => {
    expect(
      parseWebSocketServerMessage({
        host: {
          id: 1,
          lastSeenAtMs: 1_725_000_010_000,
          latestMetrics: {
            collectedAtMs: 1_725_000_009_500,
            cpuPercent: 42.5,
            diskTotalBytes: 2_048,
            diskUsedBytes: 1_536,
            memoryTotalBytes: 2_147_483_648,
            memoryUsedBytes: 1_073_741_824,
            networkRxBitsPerSecond: 6_400,
            networkRxBytesDelta: 4_000,
            networkTxBitsPerSecond: 3_200,
            networkTxBytesDelta: 2_000,
            receivedAtMs: 1_725_000_010_000,
            uptimeSeconds: 86_400,
          },
          status: "online",
          warningFlags: {
            clockSkew: false,
            probeConfigurationError: false,
          },
        },
        type: "host_summary",
      }),
    ).toEqual({
      host: {
        id: 1,
        lastSeenAtMs: 1_725_000_010_000,
        latestMetrics: {
          collectedAtMs: 1_725_000_009_500,
          cpuPercent: 42.5,
          diskTotalBytes: 2_048,
          diskUsedBytes: 1_536,
          memoryTotalBytes: 2_147_483_648,
          memoryUsedBytes: 1_073_741_824,
          networkRxBitsPerSecond: 6_400,
          networkRxBytesDelta: 4_000,
          networkTxBitsPerSecond: 3_200,
          networkTxBytesDelta: 2_000,
          receivedAtMs: 1_725_000_010_000,
          uptimeSeconds: 86_400,
        },
        status: "online",
        warningFlags: {
          clockSkew: false,
          probeConfigurationError: false,
        },
      },
      type: "host_summary",
    });
  });

  it("validates server Host Profile live update messages", () => {
    expect(
      parseWebSocketServerMessage({
        hostId: 1,
        hostProfile: {
          architecture: "x86_64",
          collectorCapabilities: {
            official: {
              cpu: {
                available: true,
              },
            },
          },
          cpuBaseFrequencyMhz: null,
          cpuCacheL3Bytes: null,
          cpuCount: 4,
          cpuModel: "AMD EPYC",
          cpuPhysicalCount: null,
          cpuSocketCount: null,
          filesystems: [
            {
              availableBytes: 10,
              filesystemType: "xfs",
              mountPoint: "/data",
              totalBytes: 20,
            },
          ],
          hostname: "profile-host",
          kernel: "6.9.0",
          memoryTotalBytes: 34_359_738_368,
          networkInterfaces: [
            {
              addresses: ["10.0.0.20"],
              name: "eth0",
            },
          ],
          os: "linux",
          probeVersion: "0.3.0",
          processCount: 120,
          threadCount: null,
        },
        type: "host_profile",
      }),
    ).toEqual({
      hostId: 1,
      hostProfile: expect.objectContaining({
        cpuCount: 4,
        hostname: "profile-host",
        probeVersion: "0.3.0",
      }),
      type: "host_profile",
    });
  });

  it("validates uptime in live detail samples", () => {
    expect(
      parseWebSocketServerMessage({
        hostId: 1,
        sample: {
          collectedAtMs: 1_725_000_009_500,
          cpuCores: [],
          cpuPercent: 12,
          disks: [],
          hostId: 1,
          memoryTotalBytes: 2_147_483_648,
          memoryUsedBytes: 1_073_741_824,
          networkInterfaces: [],
          receivedAtMs: 1_725_000_010_000,
          sequence: 1,
          uptimeSeconds: 86_400,
        },
        type: "host_detail_sample",
      }),
    ).toEqual({
      hostId: 1,
      sample: {
        collectedAtMs: 1_725_000_009_500,
        cpuCores: [],
        cpuPercent: 12,
        disks: [],
        hostId: 1,
        memoryTotalBytes: 2_147_483_648,
        memoryUsedBytes: 1_073_741_824,
        networkInterfaces: [],
        receivedAtMs: 1_725_000_010_000,
        sequence: 1,
        uptimeSeconds: 86_400,
      },
      type: "host_detail_sample",
    });
  });
});
