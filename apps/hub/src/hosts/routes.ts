import type {
  HostDetailResponse,
  HostMetadataResponse,
  HostMetricSample,
  HostMetricsResponse,
  ProbeUpgradeAllResponse,
  ProbeUpgradeRequestResponse,
  ProbeUpgradeStatus,
} from "@enoki/api-client";
import { Hono } from "hono";

import type { ProbeOperationConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { SnapshotCollectorStorageRegistry } from "../database/host-profiles.js";
import type {
  HostStatusThresholds,
  HostRepository,
} from "../database/hosts.js";
import type { MetricsRepository } from "../database/metrics.js";
import type { ProbeConfigurationRepository } from "../database/probe-configuration.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import { readJsonBody } from "../http/json.js";
import {
  broadcastHostRemovedHint,
  type LiveUpdateBroadcaster,
} from "../live-updates.js";
import { defaultProbeConfiguration } from "../probe-configuration/model.js";
import { evaluateProbeUpgradeEligibility } from "../probe/asset-set.js";
import { manualProbeReinstallPolicy } from "../probe/manual-reinstall-policy.js";
import {
  cancelProbeUpgradeRequest,
  createProbeUninstallRequest,
  createProbeUpgradeRequest,
  isActiveProbeOperation,
  type ProbeUpgradeRequest,
} from "../probe/operation.js";
import {
  readProbeReleaseContextFromDirectory,
  unavailableProbeReleaseContext,
} from "../probe/release-context.js";
import {
  currentProbeUpgradeProblem,
  probeUpgradeRecoveryDisposition,
} from "../probe/upgrade-recovery.js";
import {
  hostSummaryResponse,
  probeUpgradeOverviewProblem,
} from "./api-response.js";
import { broadcastHostSummaryHint } from "./live-summary.js";
import {
  defaultProbeOperationTimeouts,
  persistTimedOutProbeUpgradeRequest,
} from "./probe-upgrade-timeout.js";

export type HostRouteServices = {
  audit?: AuditRepository;
  hostStatus?: HostStatusThresholds;
  hosts: HostRepository;
  liveUpdates?: LiveUpdateBroadcaster | null;
  metrics?: MetricsRepository;
  now?: () => number;
  probeAssetDir?: string;
  probeDistributionRootPublicKeyPem?: Buffer | string;
  probeOperationTimeouts?: ProbeOperationConfig;
  probeConfigurations?: ProbeConfigurationRepository;
  probeOperations?: ProbeOperationRepository;
  snapshotCollectors?: SnapshotCollectorStorageRegistry;
};

const metricsWindows = {
  "1m": 60 * 1000,
  "10m": 10 * 60 * 1000,
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "3d": 3 * 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
} as const;

type MetricsWindow = keyof typeof metricsWindows;

export function createHostRoutes(services: HostRouteServices) {
  const routes = new Hono();
  const now = services.now ?? Date.now;
  const probeOperationTimeouts =
    services.probeOperationTimeouts ?? defaultProbeOperationTimeouts;

  routes.post("/probe-upgrade-requests", async (context) => {
    const body = await readJsonBody(context.req);
    if (!body.ok || !isEmptyJsonObject(body.value)) {
      return hostMetadataError("invalid_request");
    }

    if (!services.probeOperations) {
      return hostMetadataError("probe_operations_unavailable", 503);
    }

    const { assetSet, releaseTransition } =
      await readProbeUpgradeReleaseContext(services);
    const activeHosts = services.hosts.listActive();
    const latestOperations = services.probeOperations.findLatestForHosts(
      activeHosts.map((host) => host.id),
    );
    const response: ProbeUpgradeAllResponse = {
      failed: 0,
      skipped: 0,
      submitted: 0,
    };

    for (const host of activeHosts) {
      const eligibility = evaluateProbeUpgradeEligibility({
        probeAssetSetVersion: assetSet.version,
        probeAssetSetVersionNonUpgradeableReason: assetSet.nonUpgradeableReason,
        probeVersion: host.probeVersion,
        releaseTransition,
      });
      const latestOperation = latestOperations.get(host.id) ?? null;
      const hostProfileObservation =
        services.snapshotCollectors?.hostProfile.readObservation(host.id) ??
        null;
      const currentProblem = currentProbeUpgradeProblem({
        operation: latestOperation,
        reportedProbeVersion: hostProfileObservation?.view.probeVersion,
        reportedProbeVersionObservedAtMs: hostProfileObservation?.observedAtMs,
      });

      if (
        !eligibility.isUpgradeable ||
        !eligibility.currentProbeAssetSetVersion ||
        !assetSet.targetAssetSetDigest ||
        (latestOperation && isActiveProbeOperation(latestOperation)) ||
        currentProblem
      ) {
        response.skipped += 1;
        continue;
      }

      const result = createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: eligibility.currentProbeVersion,
        hostId: host.id,
        nowMs: now(),
        target: {
          assetSetDigest: assetSet.targetAssetSetDigest,
          version: eligibility.currentProbeAssetSetVersion,
        },
      });

      let created: ProbeUpgradeRequest;
      try {
        created = services.probeOperations.createProbeUpgradeRequest(
          result.operation,
        );
      } catch {
        response.failed += 1;
        continue;
      }

      response.submitted += 1;
      services.audit?.record({
        action: "probe_upgrade_request.create",
        actor: "owner",
        details: {
          hostId: host.id,
          targetProbeVersion: created.targetProbeVersion,
        },
        occurredAtMs: now(),
        outcome: "success",
        subjectId: String(created.id),
        subjectType: "probe_upgrade_request",
        userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
      });
      broadcastHostSummaryHint(services, {
        hostId: host.id,
        nowMs: now(),
        timeouts: probeOperationTimeouts,
        userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
      });
    }

    return context.json(response);
  });

  routes.get("/:hostId", async (context) => {
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
        hostProfileForHost: (hostId) =>
          services.snapshotCollectors?.hostProfile.read(hostId) ?? null,
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

    const { assetSet: currentProbeAssetSetVersion, releaseTransition } =
      await readProbeUpgradeReleaseContext(services);

    const hostProfileObservation =
      services.snapshotCollectors?.hostProfile.readObservation(hostId) ?? null;
    const hostProfile = hostProfileObservation?.view ?? null;
    const timedOutOperation = failTimedOutActiveProbeUpgradeRequest({
      hostId,
      nowMs: now(),
      probeOperationTimeouts,
      services,
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });

    const currentOperation = currentProbeUpgradeProblem({
      operation:
        timedOutOperation ??
        services.probeOperations?.findLatestForHost(hostId) ??
        null,
      reportedProbeVersion: hostProfile?.probeVersion,
      reportedProbeVersionObservedAtMs: hostProfileObservation?.observedAtMs,
    });
    const probeUpgradeEligibility = evaluateProbeUpgradeEligibility({
      probeAssetSetVersion: currentProbeAssetSetVersion.version,
      probeAssetSetVersionNonUpgradeableReason:
        currentProbeAssetSetVersion.nonUpgradeableReason,
      probeVersion: host.probeVersion,
      releaseTransition,
    });
    const manualReinstall = manualProbeReinstallPolicy({
      eligibility: probeUpgradeEligibility,
      hostLastReportAtMs: host.lastReportAtMs,
      hostProbeVersion: host.probeVersion,
      latestOperation: currentOperation,
      nowMs: now(),
      offlineAfterMs: services.hostStatus?.offlineAfterMs ?? 90_000,
      sourceProbeSha256: releaseTransition?.sourceProbeSha256 ?? [],
      targetAssetSetDigest: currentProbeAssetSetVersion.targetAssetSetDigest,
      targetProbeVersion: currentProbeAssetSetVersion.version,
    });
    const response = {
      host: {
        ...hostSummaryResponse(hostSummary, {
          probeUpgradeProblem: probeUpgradeOverviewProblem({
            operation: currentOperation,
            reportedProbeVersion: hostProfile?.probeVersion,
            reportedProbeVersionObservedAtMs:
              hostProfileObservation?.observedAtMs,
          }),
        }),
        hostMetadata: {
          connectAddress: host.connectAddress,
          description: host.description,
          displayName: host.displayName,
          observedIp: host.observedIp,
        },
        hostProfile,
        probeConfiguration: services.probeConfigurations?.getEffectiveForHost(
          hostId,
        ) ?? {
          configuration: defaultProbeConfiguration,
          mode: "inherit",
        },
        reportedProbeConfigurationVersion: host.probeConfigurationVersion,
        probeUpgradeEligibility: {
          ...probeUpgradeEligibility,
          ...(manualReinstall ? { manualReinstall } : {}),
        },
        probeUpgradeStatus: probeUpgradeStatus(currentOperation),
        warnings: warningList(host),
      },
    } satisfies HostDetailResponse;

    return context.json(response);
  });

  routes.post("/:hostId/probe-upgrade-requests", async (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    if (!hostId) {
      return hostMetadataError("host_not_found", 404);
    }

    if (!services.probeOperations) {
      return hostMetadataError("probe_operations_unavailable", 503);
    }

    const host = services.hosts.findActiveById(hostId);
    if (!host) {
      return hostMetadataError("host_not_found", 404);
    }

    const { assetSet: currentProbeAssetSetVersion, releaseTransition } =
      await readProbeUpgradeReleaseContext(services);
    const eligibility = evaluateProbeUpgradeEligibility({
      probeAssetSetVersion: currentProbeAssetSetVersion.version,
      probeAssetSetVersionNonUpgradeableReason:
        currentProbeAssetSetVersion.nonUpgradeableReason,
      probeVersion: host.probeVersion,
      releaseTransition,
    });

    if (
      !eligibility.isUpgradeable ||
      !eligibility.currentProbeAssetSetVersion ||
      !currentProbeAssetSetVersion.targetAssetSetDigest
    ) {
      return context.json(
        {
          error: "host_not_upgradeable",
          reason: eligibility.nonUpgradeableReason,
        },
        409,
      );
    }

    const activeOperation =
      failTimedOutActiveProbeUpgradeRequest({
        hostId,
        nowMs: now(),
        probeOperationTimeouts,
        services,
        userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
      }) ?? services.probeOperations.findActiveForHost(hostId);
    const result = createProbeUpgradeRequest({
      activeOperation,
      currentProbeVersion: eligibility.currentProbeVersion,
      hostId,
      nowMs: now(),
      target: {
        assetSetDigest: currentProbeAssetSetVersion.targetAssetSetDigest,
        version: eligibility.currentProbeAssetSetVersion,
      },
    });
    if (result.error) {
      return context.json(
        {
          error: result.error,
        },
        409,
      );
    }

    const isDuplicate = result.events.length === 0 && result.operation.id;
    let operation = result.operation;

    for (const event of result.events) {
      if (event.action === "superseded") {
        const superseded = services.probeOperations.updateProbeUpgradeRequest(
          event.operation,
        );
        services.audit?.record({
          action: "probe_upgrade_request.supersede",
          actor: "owner",
          details: {
            hostId,
            targetProbeVersion: superseded.targetProbeVersion,
          },
          occurredAtMs: now(),
          outcome: "success",
          subjectId: String(superseded.id),
          subjectType: "probe_upgrade_request",
          userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
        });
      }

      if (event.action === "created") {
        operation = services.probeOperations.createProbeUpgradeRequest(
          event.operation,
        );
        services.audit?.record({
          action: "probe_upgrade_request.create",
          actor: "owner",
          details: {
            hostId,
            targetProbeVersion: operation.targetProbeVersion,
          },
          occurredAtMs: now(),
          outcome: "success",
          subjectId: String(operation.id),
          subjectType: "probe_upgrade_request",
          userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
        });
      }
    }

    const response = {
      probeUpgradeRequest: probeUpgradeStatus(operation),
    } satisfies ProbeUpgradeRequestResponse;

    if (!isDuplicate) {
      broadcastHostSummaryHint(services, {
        hostId,
        nowMs: now(),
        timeouts: probeOperationTimeouts,
        userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
      });
    }

    return context.json(response, isDuplicate ? 200 : 201);
  });

  routes.delete("/:hostId/probe-upgrade-requests/:operationId", (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    const operationId = numericHostId(context.req.param("operationId"));
    if (!hostId || !operationId) {
      return hostMetadataError("probe_upgrade_request_not_found", 404);
    }

    const operation = services.probeOperations?.findById(operationId) ?? null;
    if (!operation || operation.hostId !== hostId) {
      return hostMetadataError("probe_upgrade_request_not_found", 404);
    }

    const result = cancelProbeUpgradeRequest({
      nowMs: now(),
      operation,
    });

    if (result.error || !result.canceled) {
      return context.json(
        {
          error: result.error,
        },
        409,
      );
    }

    const canceled =
      services.probeOperations?.updateProbeUpgradeRequest(result.canceled) ??
      result.canceled;
    services.audit?.record({
      action: "probe_upgrade_request.cancel",
      actor: "owner",
      details: {
        hostId,
        targetProbeVersion: canceled.targetProbeVersion,
      },
      occurredAtMs: now(),
      outcome: "success",
      subjectId: String(canceled.id),
      subjectType: "probe_upgrade_request",
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });

    const response = {
      probeUpgradeRequest: probeUpgradeStatus(canceled),
    } satisfies ProbeUpgradeRequestResponse;

    broadcastHostSummaryHint(services, {
      hostId,
      nowMs: now(),
      timeouts: probeOperationTimeouts,
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });

    return context.json(response);
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

    const response = {
      metrics: {
        samples:
          services.metrics
            ?.findSamplesForHost({
              fromCollectedAtMs,
              hostId,
              toCollectedAtMs,
            })
            .map(
              (sample): HostMetricSample => ({
                batteryPercent: sample.batteryPercent,
                batteryState: sample.batteryState,
                collectedAtMs: sample.collectedAtMs,
                cpuCores: sample.cpuCores,
                cpuIdlePercent: sample.cpuIdlePercent,
                cpuIowaitPercent: sample.cpuIowaitPercent,
                cpuPercent: sample.cpuPercent,
                cpuStealPercent: sample.cpuStealPercent,
                cpuSystemPercent: sample.cpuSystemPercent,
                cpuUserPercent: sample.cpuUserPercent,
                diskTotalBytes: sample.diskTotalBytes,
                ...(sample.diskHealth.length
                  ? { diskHealth: sample.diskHealth }
                  : {}),
                diskUsedBytes: sample.diskUsedBytes,
                disks: sample.disks,
                memoryCacheBytes: sample.memoryCacheBytes,
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
                swapTotalBytes: sample.swapTotalBytes,
                swapUsedBytes: sample.swapUsedBytes,
                temperatureCelsius: sample.temperatureCelsius,
                uptimeSeconds: sample.uptimeSeconds,
              }),
            ) ?? [],
        window,
      },
    } satisfies HostMetricsResponse;

    return context.json(response);
  });

  routes.put("/:hostId/metadata", async (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    if (!hostId) {
      return hostMetadataError("host_not_found", 404);
    }

    const body = await readJsonBody(context.req);
    if (!body.ok) {
      return hostMetadataError("malformed_json");
    }

    const input = parseHostMetadata(body.value);
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

    const response = {
      connectAddress: host.connectAddress,
      description: host.description,
      displayName: host.displayName,
      id: host.id,
    } satisfies HostMetadataResponse;

    return context.json(response);
  });

  routes.delete("/:hostId", (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    if (!hostId) {
      return hostMetadataError("host_not_found", 404);
    }

    const mode = context.req.query("mode") ?? "uninstall";
    if (mode !== "uninstall" && mode !== "hub-only") {
      return hostMetadataError("host_delete_mode_invalid", 400);
    }

    const host = services.hosts.findActiveById(hostId);
    if (!host) {
      return hostMetadataError("host_not_found", 404);
    }

    if (mode === "hub-only") {
      const nowMs = now();
      const deleted = services.hosts.softDelete(hostId, nowMs);
      if (!deleted) {
        return hostMetadataError("host_not_found", 404);
      }

      broadcastHostRemovedHint(services.liveUpdates, deleted.id);

      services.audit?.record({
        action: "host.delete",
        actor: "owner",
        details: {
          hostId,
          mode,
        },
        occurredAtMs: nowMs,
        outcome: "success",
        subjectId: String(host.id),
        subjectType: "host",
        userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
      });

      return context.json({
        deletedHost: {
          deletedAtMs: deleted.deletedAtMs,
          id: deleted.id,
        },
      });
    }

    if (!services.probeOperations) {
      return hostMetadataError("probe_operations_unavailable", 503);
    }

    const activeOperation =
      failTimedOutActiveProbeUpgradeRequest({
        hostId,
        nowMs: now(),
        probeOperationTimeouts,
        services,
        userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
      }) ?? services.probeOperations.findActiveForHost(hostId);
    const result = createProbeUninstallRequest({
      activeOperation,
      hostId,
      nowMs: now(),
    });

    if (result.error) {
      return context.json(
        {
          error: result.error,
        },
        409,
      );
    }

    const isDuplicate = result.events.length === 0 && result.operation.id;
    let operation = result.operation;

    for (const event of result.events) {
      if (event.action === "superseded") {
        services.probeOperations.updateProbeUpgradeRequest(event.operation);
      }

      if (event.action === "created") {
        operation = services.probeOperations.createProbeUpgradeRequest(
          event.operation,
        );
      }
    }

    services.audit?.record({
      action: "host.delete",
      actor: "owner",
      details: {
        hostId,
        probeOperationId: operation.id,
      },
      occurredAtMs: now(),
      outcome: "success",
      subjectId: String(host.id),
      subjectType: "host",
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });

    return context.json(
      {
        probeUninstallRequest: {
          acceptedAtMs: operation.acceptedAtMs,
          completedAtMs: operation.completedAtMs,
          createdAtMs: operation.createdAtMs,
          failure: operation.failureCode
            ? {
                code: operation.failureCode,
                message: operation.failureMessage ?? "",
              }
            : null,
          id: operation.id,
          runningAtMs: operation.runningAtMs,
          state: operation.state,
          updatedAtMs: operation.updatedAtMs,
        },
      },
      isDuplicate ? 200 : 202,
    );
  });

  return routes;
}

function isEmptyJsonObject(value: unknown): value is Record<string, never> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === 0
  );
}

export function createProbeOperationRoutes(
  services: Pick<HostRouteServices, "probeOperations">,
) {
  const routes = new Hono();

  routes.get("/:operationId", (context) => {
    const operationId = numericHostId(context.req.param("operationId"));
    const operation = operationId
      ? services.probeOperations?.findById(operationId)
      : null;
    if (!operation) {
      return hostMetadataError("probe_operation_not_found", 404);
    }

    return context.json({
      probeOperation: {
        ...probeUpgradeStatus(operation),
        hostId: operation.hostId,
        kind: operation.kind,
      },
    });
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

function hostMetadataError(error: string, status: 400 | 404 | 503 = 400) {
  return new Response(JSON.stringify({ error }), {
    headers: {
      "content-type": "application/json",
    },
    status,
  });
}

function failTimedOutActiveProbeUpgradeRequest(input: {
  hostId: number;
  nowMs: number;
  probeOperationTimeouts: ProbeOperationConfig;
  services: HostRouteServices;
  userAgent?: string;
}) {
  const activeOperation =
    input.services.probeOperations?.findActiveForHost(input.hostId) ?? null;
  if (!activeOperation) {
    return null;
  }

  return persistTimedOutProbeUpgradeRequest({
    audit: input.services.audit,
    nowMs: input.nowMs,
    operation: activeOperation,
    probeOperations: input.services.probeOperations,
    timeouts: input.probeOperationTimeouts,
    userAgent: input.userAgent,
  });
}

function readProbeUpgradeReleaseContext(services: HostRouteServices) {
  return services.probeAssetDir
    ? readProbeReleaseContextFromDirectory({
        assetDir: services.probeAssetDir,
        trustedRootPublicKeyPem: services.probeDistributionRootPublicKeyPem,
      })
    : Promise.resolve(unavailableProbeReleaseContext());
}

function probeUpgradeStatus(operation: ProbeUpgradeRequest): ProbeUpgradeStatus;
function probeUpgradeStatus(operation: null): null;
function probeUpgradeStatus(
  operation: ProbeUpgradeRequest | null,
): ProbeUpgradeStatus | null;
function probeUpgradeStatus(
  operation: ProbeUpgradeRequest | null,
): ProbeUpgradeStatus | null {
  if (!operation) {
    return null;
  }

  return {
    acceptedAtMs: operation.acceptedAtMs,
    completedAtMs: operation.completedAtMs,
    createdAtMs: operation.createdAtMs,
    failure: operation.failureCode
      ? {
          recoveryDisposition: probeUpgradeRecoveryDisposition(operation),
        }
      : null,
    id: requiredOperationId(operation),
    runningAtMs: operation.runningAtMs,
    state: operation.state,
    targetProbeVersion: operation.targetProbeVersion,
    updatedAtMs: operation.updatedAtMs,
  };
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

function requiredOperationId(operation: ProbeUpgradeRequest) {
  if (operation.id === null) {
    throw new Error("Probe operation must be persisted before formatting.");
  }

  return operation.id;
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
