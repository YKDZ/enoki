import { describe, expect, it } from "vitest";

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
