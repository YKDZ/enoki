import { Hono } from "hono";

import type { AuditRepository } from "../database/audit.js";
import type {
  HostStatusThresholds,
  HostRepository,
} from "../database/hosts.js";
import type { MetricsRepository } from "../database/metrics.js";
import type { ProbeConfigurationRepository } from "../database/probe-configuration.js";

export type HostRouteServices = {
  audit?: AuditRepository;
  hostStatus?: HostStatusThresholds;
  hosts: HostRepository;
  metrics?: MetricsRepository;
  now?: () => number;
  probeConfigurations?: ProbeConfigurationRepository;
};

const metricsWindows = {
  "1m": 60 * 1000,
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
} as const;

type MetricsWindow = keyof typeof metricsWindows;

export function createHostRoutes(services: HostRouteServices) {
  const routes = new Hono();
  const now = services.now ?? Date.now;

  routes.get("/:hostId", (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    if (!hostId) {
      return hostMetadataError("host_not_found", 404);
    }

    const host = services.hosts.findActiveById(hostId);
    if (!host) {
      return hostMetadataError("host_not_found", 404);
    }

    const hostSummary = services.hosts
      .listSummaries({
        latestMetricForHost: (hostId) =>
          services.metrics?.findLatestSample(hostId) ?? null,
        nowMs: now(),
        probeConfigurationForHost: (hostId) => {
          const effective =
            services.probeConfigurations?.getEffectiveForHost(hostId);

          return {
            mode: effective?.mode ?? "inherit",
            version: effective?.configuration.version ?? "default-v1",
          };
        },
        thresholds: services.hostStatus,
      })
      .find((summary) => summary.id === hostId);

    if (!hostSummary) {
      return hostMetadataError("host_not_found", 404);
    }

    return context.json({
      host: {
        ...hostSummary,
        hostMetadata: {
          connectAddress: host.connectAddress,
          description: host.description,
          displayName: host.displayName,
          observedIp: host.observedIp,
        },
        inventory: parseInventory(host.inventoryJson),
        probeConfiguration: services.probeConfigurations?.getEffectiveForHost(
          hostId,
        ) ?? {
          configuration: null,
          mode: "inherit",
        },
        warnings: warningList(host),
      },
    });
  });

  routes.get("/:hostId/metrics", (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    if (!hostId || !services.hosts.exists(hostId)) {
      return hostMetadataError("host_not_found", 404);
    }

    const window = metricsWindow(context.req.query("window"));
    if (!window) {
      return hostMetadataError("invalid_metrics_window");
    }

    const toCollectedAtMs = now();
    const fromCollectedAtMs = toCollectedAtMs - metricsWindows[window];
    const effectiveConfiguration =
      services.probeConfigurations?.getEffectiveForHost(hostId).configuration;
    const intervalSeconds =
      effectiveConfiguration?.metricsCollectionIntervalSeconds ?? 5;

    return context.json({
      metrics: {
        samples:
          services.metrics
            ?.findSamplesForHost({
              fromCollectedAtMs,
              hostId,
              toCollectedAtMs,
            })
            .map((sample) => ({
              collectedAtMs: sample.collectedAtMs,
              cpuCores: sample.cpuCores,
              cpuPercent: sample.cpuPercent,
              diskTotalBytes: sample.diskTotalBytes,
              diskUsedBytes: sample.diskUsedBytes,
              disks: sample.disks,
              memoryTotalBytes: sample.memoryTotalBytes,
              memoryUsedBytes: sample.memoryUsedBytes,
              networkInterfaces: sample.networkInterfaces.map(
                (networkInterface) => ({
                  ...networkInterface,
                  rxBitsPerSecond: bitsPerSecond(
                    networkInterface.rxBytesDelta,
                    intervalSeconds,
                  ),
                  txBitsPerSecond: bitsPerSecond(
                    networkInterface.txBytesDelta,
                    intervalSeconds,
                  ),
                }),
              ),
              networkRxBitsPerSecond: bitsPerSecond(
                sample.networkRxBytesDelta,
                intervalSeconds,
              ),
              networkRxBytesDelta: sample.networkRxBytesDelta,
              networkTxBitsPerSecond: bitsPerSecond(
                sample.networkTxBytesDelta,
                intervalSeconds,
              ),
              networkTxBytesDelta: sample.networkTxBytesDelta,
              receivedAtMs: sample.receivedAtMs,
              sequence: sample.sequence,
              uptimeSeconds: sample.uptimeSeconds,
            })) ?? [],
        window,
      },
    });
  });

  routes.put("/:hostId/metadata", async (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    if (!hostId) {
      return hostMetadataError("host_not_found", 404);
    }

    const input = parseHostMetadata(await context.req.json());
    if (!input) {
      return hostMetadataError("invalid_host_metadata");
    }

    const host = services.hosts.updateMetadata(hostId, input);
    if (!host) {
      return hostMetadataError("host_not_found", 404);
    }

    services.audit?.record({
      action: "host.metadata.update",
      actor: "owner",
      occurredAtMs: now(),
      outcome: "success",
      subjectId: String(host.id),
      subjectType: "host",
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });

    return context.json({
      connectAddress: host.connectAddress,
      description: host.description,
      displayName: host.displayName,
      id: host.id,
    });
  });

  routes.delete("/:hostId", (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    if (!hostId) {
      return hostMetadataError("host_not_found", 404);
    }

    const host = services.hosts.softDelete(hostId, now());
    if (!host) {
      return hostMetadataError("host_not_found", 404);
    }

    services.audit?.record({
      action: "host.delete",
      actor: "owner",
      occurredAtMs: now(),
      outcome: "success",
      subjectId: String(host.id),
      subjectType: "host",
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });

    return new Response(null, { status: 204 });
  });

  return routes;
}

function parseHostMetadata(input: unknown) {
  if (!input || typeof input !== "object") {
    return null;
  }

  const candidate = input as {
    connectAddress?: unknown;
    description?: unknown;
    displayName?: unknown;
  };
  const output: {
    connectAddress?: string;
    description?: string;
    displayName?: string;
  } = {};

  if (Object.hasOwn(candidate, "displayName")) {
    const displayName = stringValue(candidate.displayName);
    if (!displayName) {
      return null;
    }
    output.displayName = displayName;
  }

  if (Object.hasOwn(candidate, "connectAddress")) {
    const connectAddress = stringValue(candidate.connectAddress);
    if (!connectAddress) {
      return null;
    }
    output.connectAddress = connectAddress;
  }

  if (Object.hasOwn(candidate, "description")) {
    const description = stringValue(candidate.description);
    if (description.length > 500) {
      return null;
    }
    output.description = description;
  }

  if (Object.keys(output).length === 0) {
    return null;
  }

  return output;
}

function stringValue(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function hostMetadataError(error: string, status: 400 | 404 = 400) {
  return new Response(JSON.stringify({ error }), {
    headers: {
      "content-type": "application/json",
    },
    status,
  });
}

function numericHostId(value: string | undefined) {
  const hostId = Number(value);

  return Number.isInteger(hostId) && hostId > 0 ? hostId : null;
}

function metricsWindow(value: string | undefined): MetricsWindow | null {
  return value && Object.hasOwn(metricsWindows, value)
    ? (value as MetricsWindow)
    : null;
}

function parseInventory(inventoryJson: string | null) {
  if (!inventoryJson) {
    return null;
  }

  try {
    return JSON.parse(inventoryJson) as unknown;
  } catch {
    return null;
  }
}

function warningList(host: {
  clockSkewDetected: boolean;
  lastClockSkewMs: number | null;
  probeConfigurationErrorCode: string | null;
  probeConfigurationErrorFailedVersion: string | null;
  probeConfigurationErrorMessage: string | null;
  probeConfigurationErrorReportedAtMs: number | null;
}) {
  const warnings: Array<{
    code: string;
    message: string;
    occurredAtMs?: number;
    technicalDetail?: string;
  }> = [];

  if (host.clockSkewDetected) {
    warnings.push({
      code: "clock_skew",
      message:
        host.lastClockSkewMs === null
          ? "探针时间与 Hub 时间存在偏移。"
          : `探针时间与 Hub 时间偏移 ${Math.round(
              host.lastClockSkewMs / 1000,
            )} 秒。`,
    });
  }

  if (
    host.probeConfigurationErrorCode &&
    host.probeConfigurationErrorFailedVersion &&
    host.probeConfigurationErrorMessage &&
    host.probeConfigurationErrorReportedAtMs !== null
  ) {
    warnings.push({
      code: "probe_configuration_error",
      message: "探针未能应用最新配置，请检查探针连通性或配置下发状态。",
      occurredAtMs: host.probeConfigurationErrorReportedAtMs,
      technicalDetail: `配置版本 ${host.probeConfigurationErrorFailedVersion}，错误代码 ${host.probeConfigurationErrorCode}，Probe 原始信息：${host.probeConfigurationErrorMessage}`,
    });
  }

  return warnings;
}

function bitsPerSecond(bytes: number | null, intervalSeconds: number) {
  if (bytes === null || intervalSeconds <= 0) {
    return null;
  }

  return (bytes * 8) / intervalSeconds;
}
