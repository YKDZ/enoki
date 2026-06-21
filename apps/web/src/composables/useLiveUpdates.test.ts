import { afterEach, describe, expect, it, vi } from "vitest";
import { ref } from "vue";

import type { HostSummary } from "../types";
import { applyHostLiveSummary, useLiveUpdates } from "./useLiveUpdates";

const existingHost: HostSummary = {
  clockSkew: {
    detected: false,
    lastDeltaMs: null,
  },
  connectAddress: "10.0.0.10",
  cpu: "2 cores",
  cpuModel: null,
  description: "生产数据库",
  displayName: "managed-host-01",
  id: 1,
  lastReportAtMs: null,
  latestMetrics: null,
  memory: "2 GB",
  probeConfiguration: {
    mode: "inherit",
    version: "default-v1",
  },
  probeVersion: "0.1.0",
  status: "offline",
  system: "linux",
};

class FakeWebSocket {
  static readonly CLOSED = 3;
  static readonly CLOSING = 2;
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;

  readonly listeners = new Map<
    string,
    Array<(event: { data?: string }) => void>
  >();
  readonly sent: string[] = [];
  readyState = FakeWebSocket.OPEN;

  constructor(readonly url: string) {
    fakeSockets.push(this);
  }

  addEventListener(type: string, listener: (event: { data?: string }) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }

  close() {
    this.readyState = FakeWebSocket.CLOSED;
    this.emit("close");
  }

  emit(type: string, event: { data?: string } = {}) {
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event);
    }
  }

  send(message: string) {
    this.sent.push(message);
  }
}

const originalWebSocket = globalThis.WebSocket;
const originalWindow = globalThis.window;
let fakeSockets: FakeWebSocket[] = [];

describe("live Host summaries", () => {
  afterEach(() => {
    vi.useRealTimers();
    globalThis.WebSocket = originalWebSocket;
    globalThis.window = originalWindow;
    fakeSockets = [];
  });

  it("requests a typed host list reload when a live summary arrives for an unknown host", () => {
    const result = applyHostLiveSummary([existingHost], {
      id: 2,
      lastSeenAtMs: 1_725_000_010_000,
      latestMetrics: null,
      status: "online",
      warningFlags: {
        clockSkew: false,
        probeConfigurationError: false,
      },
    });

    expect(result).toEqual({
      hosts: [existingHost],
      needsReload: true,
    });
  });

  it("reloads the typed host list when a WebSocket summary references an unknown host", async () => {
    const hosts = ref<HostSummary[]>([existingHost]);
    let reloadCount = 0;
    const liveUpdates = useLiveUpdates({
      hosts,
      isAuthenticated: ref(true),
      async loadHosts() {
        reloadCount += 1;
        hosts.value = [
          existingHost,
          {
            ...existingHost,
            connectAddress: "10.0.0.11",
            description: "备用节点",
            displayName: "managed-host-02",
            id: 2,
            status: "online",
          },
        ];
      },
    });

    await liveUpdates.handleLiveUpdate(
      JSON.stringify({
        host: {
          id: 2,
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
    );

    expect(reloadCount).toBe(1);
    expect(hosts.value.map((host) => host.id)).toEqual([1, 2]);
  });

  it("passes subscribed detail samples to the detail handler", async () => {
    const hosts = ref<HostSummary[]>([existingHost]);
    const detailSamples: unknown[] = [];
    const liveUpdates = useLiveUpdates({
      hosts,
      isAuthenticated: ref(true),
      async loadHosts() {},
      onDetailSample(sample) {
        detailSamples.push(sample);
      },
    });

    await liveUpdates.handleLiveUpdate(
      JSON.stringify({
        hostId: 1,
        sample: {
          collectedAtMs: 1_725_000_009_500,
          cpuCores: [],
          cpuPercent: 42,
          disks: [],
          hostId: 1,
          memoryTotalBytes: null,
          memoryUsedBytes: null,
          networkInterfaces: [],
          receivedAtMs: 1_725_000_010_000,
          sequence: 1,
          uptimeSeconds: null,
        },
        type: "host_detail_sample",
      }),
    );

    expect(detailSamples).toEqual([
      expect.objectContaining({
        cpuPercent: 42,
        hostId: 1,
        sequence: 1,
      }),
    ]);
  });

  it("reconnects and refreshes HTTP state when the live socket closes", async () => {
    vi.useFakeTimers();
    globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
    globalThis.window = {
      location: {
        host: "hub.example.test",
        protocol: "https:",
      },
    } as Window & typeof globalThis;

    const hosts = ref<HostSummary[]>([existingHost]);
    let hostReloadCount = 0;
    let detailRecoveryCount = 0;
    const liveUpdates = useLiveUpdates({
      hosts,
      isAuthenticated: ref(true),
      async loadHosts() {
        hostReloadCount += 1;
      },
      reconnectDelayMs: 25,
      async recoverDetail() {
        detailRecoveryCount += 1;
      },
    });

    liveUpdates.connectLiveUpdates();
    liveUpdates.subscribeHostDetail(1);
    fakeSockets[0]?.emit("open");

    expect(fakeSockets).toHaveLength(1);
    expect(fakeSockets[0]?.url).toBe("wss://hub.example.test/api/web/ws");
    expect(fakeSockets[0]?.sent).toContain(
      JSON.stringify({
        hostId: 1,
        type: "subscribe_host_detail",
      }),
    );

    fakeSockets[0]?.emit("close");
    await Promise.resolve();

    expect(hostReloadCount).toBe(1);
    expect(detailRecoveryCount).toBe(1);

    await vi.advanceTimersByTimeAsync(25);
    fakeSockets[1]?.emit("open");

    expect(fakeSockets).toHaveLength(2);
    expect(fakeSockets[1]?.sent).toContain(
      JSON.stringify({
        hostId: 1,
        type: "subscribe_host_detail",
      }),
    );

    liveUpdates.disconnectLiveUpdates();
  });
});
