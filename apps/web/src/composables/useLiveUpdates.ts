import {
  type HostDetailSample,
  type HostLiveSummary,
  parseWebSocketServerMessage,
  type WebSocketClientMessage,
} from "@enoki/api-client/websocket";
import type { Ref } from "vue";

import { hostProfileBackedFields } from "@/lib/host-profile-live";
import { mergeLatestMetrics } from "@/metrics/latest-metrics";

import type { HostProfileSnapshot, HostSummary } from "../types";

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
      collectorCapabilities:
        summary.collectorCapabilities === undefined
          ? host.collectorCapabilities
          : summary.collectorCapabilities,
      lastReportAtMs: summary.lastSeenAtMs,
      latestMetrics: summary.latestMetrics
        ? mergeLatestMetrics(host.latestMetrics, summary.latestMetrics)
        : null,
      probeUpgradeProblem: summary.probeUpgradeProblem,
      status: summary.status,
    };
  });

  return {
    hosts: updatedHosts,
    needsReload: !matched,
  };
}

export function applyHostProfileLiveUpdate(
  hosts: HostSummary[],
  hostId: number,
  hostProfile: HostProfileSnapshot,
): LiveSummaryApplyResult {
  let matched = false;
  const updatedHosts = hosts.map((host) => {
    if (host.id !== hostId) {
      return host;
    }

    matched = true;
    return {
      ...host,
      ...hostProfileBackedFields(hostProfile),
    };
  });

  return {
    hosts: updatedHosts,
    needsReload: !matched,
  };
}

export function applyHostRemoved(hosts: HostSummary[], hostId: number) {
  return hosts.filter((host) => host.id !== hostId);
}

export function useLiveUpdates(options: {
  hosts: Ref<HostSummary[]>;
  isAuthenticated: Ref<boolean>;
  loadHosts: () => Promise<void>;
  onDetailSample?: (sample: HostDetailSample) => void;
  onHostProfile?: (hostId: number, hostProfile: HostProfileSnapshot) => void;
  onHostReady?: (hint: {
    enrollmentId: string;
    hostId: number;
    type: "host_ready";
  }) => void;
  onHostRemoved?: (hostId: number) => void;
  onSummary?: (summary: HostLiveSummary) => void;
  reconnectDelayMs?: number;
  recoverDetail?: () => Promise<void>;
  recoverEnrollment?: () => Promise<void>;
}) {
  let liveUpdatesSocket: WebSocket | null = null;
  let detailHostId: number | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let reconnectGeneration = 0;
  const reconnectDelayMs = options.reconnectDelayMs ?? 1_000;

  function connectLiveUpdates() {
    disconnectLiveUpdates();
    openLiveUpdatesSocket(null);
  }

  function openLiveUpdatesSocket(recoveryGeneration: number | null) {
    if (!options.isAuthenticated.value) {
      return;
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(
      `${protocol}//${window.location.host}/api/web/ws`,
    );
    liveUpdatesSocket = socket;
    let recoveredAfterOpen = false;

    socket.addEventListener("message", (event) => {
      void handleLiveUpdate(event.data);
    });
    socket.addEventListener("open", () => {
      if (liveUpdatesSocket !== socket) {
        return;
      }

      if (detailHostId !== null) {
        sendClientMessage({
          hostId: detailHostId,
          type: "subscribe_host_detail",
        });
      }

      if (
        recoveryGeneration !== null &&
        recoveryGeneration === reconnectGeneration &&
        !recoveredAfterOpen
      ) {
        recoveredAfterOpen = true;
        void recoverCurrentHttpState();
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

    const recoveryGeneration = ++reconnectGeneration;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      openLiveUpdatesSocket(recoveryGeneration);
    }, reconnectDelayMs);
  }

  async function recoverCurrentHttpState() {
    try {
      await options.loadHosts();
      await Promise.all([
        detailHostId === null ? undefined : options.recoverDetail?.(),
        options.recoverEnrollment?.(),
      ]);
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

    if (message?.type === "host_removed") {
      options.hosts.value = applyHostRemoved(
        options.hosts.value,
        message.hostId,
      );
      options.onHostRemoved?.(message.hostId);
      return;
    }

    if (message?.type === "host_ready") {
      options.onHostReady?.({
        enrollmentId: message.enrollmentId,
        hostId: message.hostId,
        type: "host_ready",
      });
      return;
    }

    if (message?.type === "host_detail_sample") {
      options.onDetailSample?.(message.sample);
      return;
    }

    if (message?.type === "host_profile") {
      const result = applyHostProfileLiveUpdate(
        options.hosts.value,
        message.hostId,
        message.hostProfile,
      );
      options.hosts.value = result.hosts;
      options.onHostProfile?.(message.hostId, message.hostProfile);

      if (result.needsReload) {
        await options.loadHosts();
      }
      return;
    }

    if (message?.type !== "host_summary") {
      return;
    }

    const recoversOpenProbeUpgradeProblem =
      detailHostId === message.host.id &&
      options.hosts.value.some(
        (host) =>
          host.id === message.host.id &&
          host.probeUpgradeProblem?.status === "failed",
      ) &&
      message.host.probeUpgradeProblem === null;
    const result = applyHostLiveSummary(options.hosts.value, message.host);
    options.hosts.value = result.hosts;
    options.onSummary?.(message.host);

    if (result.needsReload) {
      await options.loadHosts();
    } else if (recoversOpenProbeUpgradeProblem) {
      await options.recoverDetail?.();
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
