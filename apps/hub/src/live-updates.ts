import {
  type HostDetailSample,
  type HostLiveSummary,
  parseWebSocketClientMessage,
  type WebSocketServerMessage,
} from "@enoki/api-client/websocket";
import type { WSContext, WSMessageReceive } from "hono/ws";

import type { HostSummary } from "./database/hosts.js";

type LiveClient = {
  detailHostId: number | null;
  sessionId: string;
  socket: WSContext;
};

export type LiveUpdateBroadcaster = {
  addClient: (socket: WSContext, options: { sessionId: string }) => void;
  broadcastDetailSample: (sample: HostDetailSample) => void;
  broadcastHostSummary: (summary: HostLiveSummary) => void;
  closeSession: (sessionId: string) => void;
  handleClientMessage: (socket: WSContext, message: WSMessageReceive) => void;
  removeClient: (socket: WSContext) => void;
};

export function createLiveUpdateBroadcaster(): LiveUpdateBroadcaster {
  const clients = new Map<WSContext, LiveClient>();

  return {
    addClient(socket, options) {
      clients.set(socket, {
        detailHostId: null,
        sessionId: options.sessionId,
        socket,
      });
    },
    broadcastDetailSample(sample) {
      const message: WebSocketServerMessage = {
        hostId: sample.hostId,
        sample,
        type: "host_detail_sample",
      };

      for (const client of clients.values()) {
        if (client.detailHostId === sample.hostId) {
          sendJson(client.socket, message);
        }
      }
    },
    broadcastHostSummary(summary) {
      const message: WebSocketServerMessage = {
        host: summary,
        type: "host_summary",
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

      if (parsed.type === "subscribe_host_detail") {
        client.detailHostId = parsed.hostId;
        return;
      }

      if (client.detailHostId === parsed.hostId) {
        client.detailHostId = null;
      }
    },
    removeClient(socket) {
      clients.delete(socket);
    },
  };
}

export function liveSummaryFromHost(
  host: HostSummary,
  options: {
    metricsCollectionIntervalSeconds: number;
  },
): HostLiveSummary {
  return {
    id: host.id,
    lastSeenAtMs: host.lastReportAtMs,
    latestMetrics: host.latestMetrics
      ? {
          batteryPercent: host.latestMetrics.batteryPercent,
          batteryState: host.latestMetrics.batteryState,
          collectedAtMs: host.latestMetrics.collectedAtMs,
          cpuIdlePercent: host.latestMetrics.cpuIdlePercent,
          cpuIowaitPercent: host.latestMetrics.cpuIowaitPercent,
          cpuPercent: host.latestMetrics.cpuPercent,
          cpuStealPercent: host.latestMetrics.cpuStealPercent,
          cpuSystemPercent: host.latestMetrics.cpuSystemPercent,
          cpuUserPercent: host.latestMetrics.cpuUserPercent,
          diskTotalBytes: host.latestMetrics.diskTotalBytes,
          diskUsedBytes: host.latestMetrics.diskUsedBytes,
          memoryCacheBytes: host.latestMetrics.memoryCacheBytes,
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
          swapTotalBytes: host.latestMetrics.swapTotalBytes,
          swapUsedBytes: host.latestMetrics.swapUsedBytes,
          temperatureCelsius: host.latestMetrics.temperatureCelsius,
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

  if (ArrayBuffer.isView(message)) {
    const view = message as ArrayBufferView<ArrayBuffer>;
    return new TextDecoder().decode(
      new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
    );
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
