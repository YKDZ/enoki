import {
  type HostDetailSample,
  type HostLiveSummary,
  parseWebSocketServerMessage,
  type WebSocketClientMessage,
} from "@enoki/api-client/websocket";
import type { Ref } from "vue";

import type { HostSummary } from "../types";

export type LiveSummaryApplyResult = {
  hosts: HostSummary[];
  needsReload: boolean;
};

export function applyHostLiveSummary(
  hosts: HostSummary[],
  summary: HostLiveSummary,
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
            batteryPercent: summary.latestMetrics.batteryPercent,
            batteryState: summary.latestMetrics.batteryState,
            collectedAtMs: summary.latestMetrics.collectedAtMs,
            cpuIdlePercent: summary.latestMetrics.cpuIdlePercent,
            cpuIowaitPercent: summary.latestMetrics.cpuIowaitPercent,
            cpuPercent: summary.latestMetrics.cpuPercent,
            cpuStealPercent: summary.latestMetrics.cpuStealPercent,
            cpuSystemPercent: summary.latestMetrics.cpuSystemPercent,
            cpuUserPercent: summary.latestMetrics.cpuUserPercent,
            diskTotalBytes: summary.latestMetrics.diskTotalBytes,
            diskUsedBytes: summary.latestMetrics.diskUsedBytes,
            memoryCacheBytes: summary.latestMetrics.memoryCacheBytes,
            memoryTotalBytes: summary.latestMetrics.memoryTotalBytes,
            memoryUsedBytes: summary.latestMetrics.memoryUsedBytes,
            networkRxBitsPerSecond:
              summary.latestMetrics.networkRxBitsPerSecond,
            networkRxBytesDelta: summary.latestMetrics.networkRxBytesDelta,
            networkTxBitsPerSecond:
              summary.latestMetrics.networkTxBitsPerSecond,
            networkTxBytesDelta: summary.latestMetrics.networkTxBytesDelta,
            receivedAtMs: summary.latestMetrics.receivedAtMs,
            swapTotalBytes: summary.latestMetrics.swapTotalBytes,
            swapUsedBytes: summary.latestMetrics.swapUsedBytes,
            temperatureCelsius: summary.latestMetrics.temperatureCelsius,
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
  hosts: Ref<HostSummary[]>;
  isAuthenticated: Ref<boolean>;
  loadHosts: () => Promise<void>;
  onDetailSample?: (sample: HostDetailSample) => void;
  onSummary?: (summary: HostLiveSummary) => void;
  reconnectDelayMs?: number;
  recoverDetail?: () => Promise<void>;
}) {
  let liveUpdatesSocket: WebSocket | null = null;
  let detailHostId: number | null = null;
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
      if (detailHostId !== null) {
        sendClientMessage({
          hostId: detailHostId,
          type: "subscribe_host_detail",
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
      if (detailHostId !== null) {
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

    if (message?.type !== "host_summary") {
      if (message?.type === "host_detail_sample") {
        options.onDetailSample?.(message.sample);
      }
      return;
    }

    const result = applyHostLiveSummary(options.hosts.value, message.host);
    options.hosts.value = result.hosts;
    options.onSummary?.(message.host);

    if (result.needsReload) {
      await options.loadHosts();
    }
  }

  function subscribeHostDetail(hostId: number) {
    detailHostId = hostId;
    sendClientMessage({
      hostId,
      type: "subscribe_host_detail",
    });
  }

  function unsubscribeHostDetail(hostId: number) {
    if (detailHostId === hostId) {
      detailHostId = null;
    }
    sendClientMessage({
      hostId,
      type: "unsubscribe_host_detail",
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
    subscribeHostDetail,
    unsubscribeHostDetail,
  };
}
