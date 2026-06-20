import {
  type ManagedHostDetailSample,
  type ManagedHostLiveSummary,
  parseWebSocketServerMessage,
  type WebSocketClientMessage,
} from "@enoki/api-client/websocket";
import type { Ref } from "vue";

import type { ManagedHostSummary } from "../types";

export type LiveSummaryApplyResult = {
  hosts: ManagedHostSummary[];
  needsReload: boolean;
};

export function applyManagedHostLiveSummary(
  hosts: ManagedHostSummary[],
  summary: ManagedHostLiveSummary,
): LiveSummaryApplyResult {
  let matched = false;
  const updatedHosts = hosts.map((host) => {
    if (host.id !== summary.id) {
      return host;
    }

    matched = true;
    return {
      ...host,
      clockSkew: {
        ...host.clockSkew,
        detected: summary.warningFlags.clockSkew,
      },
      lastReportAtMs: summary.lastSeenAtMs,
      latestMetrics: summary.latestMetrics
        ? {
            collectedAtMs: summary.latestMetrics.collectedAtMs,
            cpuPercent: summary.latestMetrics.cpuPercent,
            diskTotalBytes: summary.latestMetrics.diskTotalBytes,
            diskUsedBytes: summary.latestMetrics.diskUsedBytes,
            memoryTotalBytes: summary.latestMetrics.memoryTotalBytes,
            memoryUsedBytes: summary.latestMetrics.memoryUsedBytes,
            networkRxBitsPerSecond:
              summary.latestMetrics.networkRxBitsPerSecond,
            networkRxBytesDelta: summary.latestMetrics.networkRxBytesDelta,
            networkTxBitsPerSecond:
              summary.latestMetrics.networkTxBitsPerSecond,
            networkTxBytesDelta: summary.latestMetrics.networkTxBytesDelta,
            receivedAtMs: summary.latestMetrics.receivedAtMs,
            uptimeSeconds: summary.latestMetrics.uptimeSeconds,
          }
        : null,
      status: summary.status,
    };
  });

  return {
    hosts: updatedHosts,
    needsReload: !matched,
  };
}

export function useLiveUpdates(options: {
  hosts: Ref<ManagedHostSummary[]>;
  isAuthenticated: Ref<boolean>;
  loadHosts: () => Promise<void>;
  onDetailSample?: (sample: ManagedHostDetailSample) => void;
  onSummary?: (summary: ManagedHostLiveSummary) => void;
  reconnectDelayMs?: number;
  recoverDetail?: () => Promise<void>;
}) {
  let liveUpdatesSocket: WebSocket | null = null;
  let detailManagedHostId: number | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  const reconnectDelayMs = options.reconnectDelayMs ?? 1_000;

  function connectLiveUpdates() {
    disconnectLiveUpdates();
    openLiveUpdatesSocket();
  }

  function openLiveUpdatesSocket() {
    if (!options.isAuthenticated.value) {
      return;
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(
      `${protocol}//${window.location.host}/api/web/ws`,
    );
    liveUpdatesSocket = socket;

    socket.addEventListener("message", (event) => {
      void handleLiveUpdate(event.data);
    });
    socket.addEventListener("open", () => {
      if (detailManagedHostId !== null) {
        sendClientMessage({
          managedHostId: detailManagedHostId,
          type: "subscribe_managed_host_detail",
        });
      }
    });
    socket.addEventListener("close", () => {
      if (liveUpdatesSocket === socket) {
        liveUpdatesSocket = null;
        scheduleReconnect();
      }
    });
    socket.addEventListener("error", () => {
      socket.close();
    });
  }

  function disconnectLiveUpdates() {
    clearReconnectTimer();
    const socket = liveUpdatesSocket;
    liveUpdatesSocket = null;

    if (
      socket &&
      (socket.readyState === WebSocket.CONNECTING ||
        socket.readyState === WebSocket.OPEN)
    ) {
      socket.close();
    }
  }

  function clearReconnectTimer() {
    if (reconnectTimer === null) {
      return;
    }

    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  function scheduleReconnect() {
    if (!options.isAuthenticated.value || reconnectTimer !== null) {
      return;
    }

    void recoverCurrentHttpState();
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      openLiveUpdatesSocket();
    }, reconnectDelayMs);
  }

  async function recoverCurrentHttpState() {
    try {
      await options.loadHosts();
      if (detailManagedHostId !== null) {
        await options.recoverDetail?.();
      }
    } catch {
      // The reconnect attempt still proceeds; the next close can retry recovery.
    }
  }

  async function handleLiveUpdate(data: unknown) {
    if (typeof data !== "string") {
      return;
    }

    let payload: unknown;
    try {
      payload = JSON.parse(data);
    } catch {
      return;
    }

    const message = parseWebSocketServerMessage(payload);

    if (message?.type !== "managed_host_summary") {
      if (message?.type === "managed_host_detail_sample") {
        options.onDetailSample?.(message.sample);
      }
      return;
    }

    const result = applyManagedHostLiveSummary(
      options.hosts.value,
      message.host,
    );
    options.hosts.value = result.hosts;
    options.onSummary?.(message.host);

    if (result.needsReload) {
      await options.loadHosts();
    }
  }

  function subscribeManagedHostDetail(managedHostId: number) {
    detailManagedHostId = managedHostId;
    sendClientMessage({
      managedHostId,
      type: "subscribe_managed_host_detail",
    });
  }

  function unsubscribeManagedHostDetail(managedHostId: number) {
    if (detailManagedHostId === managedHostId) {
      detailManagedHostId = null;
    }
    sendClientMessage({
      managedHostId,
      type: "unsubscribe_managed_host_detail",
    });
  }

  function sendClientMessage(message: WebSocketClientMessage) {
    if (liveUpdatesSocket?.readyState !== WebSocket.OPEN) {
      return;
    }

    liveUpdatesSocket.send(JSON.stringify(message));
  }

  return {
    connectLiveUpdates,
    disconnectLiveUpdates,
    handleLiveUpdate,
    subscribeManagedHostDetail,
    unsubscribeManagedHostDetail,
  };
}
