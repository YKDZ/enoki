import {
  type ManagedHostDetailSample,
  type ManagedHostLiveSummary,
  parseWebSocketClientMessage,
  type WebSocketServerMessage,
} from "@enoki/api-client/websocket";
import type { WSContext, WSMessageReceive } from "hono/ws";

import type { ManagedHostSummary } from "./database/managed-hosts.js";

type LiveClient = {
  detailManagedHostId: number | null;
  sessionId: string;
  socket: WSContext;
};

export type LiveUpdateBroadcaster = {
  addClient: (socket: WSContext, options: { sessionId: string }) => void;
  broadcastDetailSample: (sample: ManagedHostDetailSample) => void;
  broadcastManagedHostSummary: (summary: ManagedHostLiveSummary) => void;
  closeSession: (sessionId: string) => void;
  handleClientMessage: (socket: WSContext, message: WSMessageReceive) => void;
  removeClient: (socket: WSContext) => void;
};

export function createLiveUpdateBroadcaster(): LiveUpdateBroadcaster {
  const clients = new Map<WSContext, LiveClient>();

  return {
    addClient(socket, options) {
      clients.set(socket, {
        detailManagedHostId: null,
        sessionId: options.sessionId,
        socket,
      });
    },
    broadcastDetailSample(sample) {
      const message: WebSocketServerMessage = {
        managedHostId: sample.managedHostId,
        sample,
        type: "managed_host_detail_sample",
      };

      for (const client of clients.values()) {
        if (client.detailManagedHostId === sample.managedHostId) {
          sendJson(client.socket, message);
        }
      }
    },
    broadcastManagedHostSummary(summary) {
      const message: WebSocketServerMessage = {
        host: summary,
        type: "managed_host_summary",
      };

      for (const client of clients.values()) {
        sendJson(client.socket, message);
      }
    },
    closeSession(sessionId) {
      for (const [socket, client] of clients.entries()) {
        if (client.sessionId !== sessionId) {
          continue;
        }

        clients.delete(socket);
        closeSocket(socket);
      }
    },
    handleClientMessage(socket, message) {
      const client = clients.get(socket);

      if (!client) {
        return;
      }

      const payload = parseWebSocketPayload(message);

      if (!payload) {
        return;
      }

      const parsed = parseWebSocketClientMessage(payload);

      if (!parsed) {
        return;
      }

      if (parsed.type === "subscribe_managed_host_detail") {
        client.detailManagedHostId = parsed.managedHostId;
        return;
      }

      if (client.detailManagedHostId === parsed.managedHostId) {
        client.detailManagedHostId = null;
      }
    },
    removeClient(socket) {
      clients.delete(socket);
    },
  };
}

export function liveSummaryFromManagedHost(
  host: ManagedHostSummary,
  options: {
    metricsCollectionIntervalSeconds: number;
  },
): ManagedHostLiveSummary {
  return {
    id: host.id,
    lastSeenAtMs: host.lastReportAtMs,
    latestMetrics: host.latestMetrics
      ? {
          collectedAtMs: host.latestMetrics.collectedAtMs,
          cpuPercent: host.latestMetrics.cpuPercent,
          diskTotalBytes: host.latestMetrics.diskTotalBytes,
          diskUsedBytes: host.latestMetrics.diskUsedBytes,
          memoryTotalBytes: host.latestMetrics.memoryTotalBytes,
          memoryUsedBytes: host.latestMetrics.memoryUsedBytes,
          networkRxBitsPerSecond: bitsPerSecond(
            host.latestMetrics.networkRxBytesDelta,
            options.metricsCollectionIntervalSeconds,
          ),
          networkRxBytesDelta: host.latestMetrics.networkRxBytesDelta,
          networkTxBitsPerSecond: bitsPerSecond(
            host.latestMetrics.networkTxBytesDelta,
            options.metricsCollectionIntervalSeconds,
          ),
          networkTxBytesDelta: host.latestMetrics.networkTxBytesDelta,
          receivedAtMs: host.latestMetrics.receivedAtMs,
          uptimeSeconds: host.latestMetrics.uptimeSeconds,
        }
      : null,
    status: host.status,
    warningFlags: {
      clockSkew: host.clockSkew.detected,
      probeConfigurationError: host.probeConfigurationError !== null,
    },
  };
}

function bitsPerSecond(bytes: number | null, intervalSeconds: number) {
  if (bytes === null || intervalSeconds <= 0) {
    return null;
  }

  return (bytes * 8) / intervalSeconds;
}

function parseWebSocketPayload(message: WSMessageReceive) {
  const text = webSocketMessageText(message);

  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function webSocketMessageText(message: WSMessageReceive) {
  if (typeof message === "string") {
    return message;
  }

  if (message instanceof ArrayBuffer) {
    return new TextDecoder().decode(message);
  }

  return null;
}

function sendJson(socket: WSContext, message: WebSocketServerMessage) {
  if (socket.readyState !== 1) {
    return;
  }

  try {
    socket.send(JSON.stringify(message));
  } catch {
    // A broken socket should not interrupt Probe report handling.
  }
}

function closeSocket(socket: WSContext) {
  try {
    socket.close();
  } catch {
    // A broken socket should not interrupt session invalidation.
  }
}
