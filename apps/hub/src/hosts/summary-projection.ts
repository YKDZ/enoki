import type { HostSummary as ApiHostSummary } from "@enoki/api-client";

import type { ProbeOperationConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { SnapshotCollectorStorageRegistry } from "../database/host-profiles.js";
import type {
  HostRepository,
  HostStatusThresholds,
  HostSummary as DatabaseHostSummary,
} from "../database/hosts.js";
import type { MetricsRepository } from "../database/metrics.js";
import type { ProbeConfigurationRepository } from "../database/probe-configuration.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import { hostSummaryResponse } from "./api-response.js";
import { probeUpgradeOverviewProblems } from "./probe-upgrade-overview.js";

export type HostSummaryProjection = {
  databaseHost: DatabaseHostSummary;
  response: ApiHostSummary;
  metricsCollectionIntervalSeconds: number;
};

export function projectHostSummaries(
  services: {
    audit?: AuditRepository;
    hosts: HostRepository;
    hostStatus?: HostStatusThresholds;
    metrics?: MetricsRepository;
    probeConfigurations?: ProbeConfigurationRepository;
    probeOperations?: ProbeOperationRepository;
    snapshotCollectors?: SnapshotCollectorStorageRegistry;
  },
  input: {
    hostIds?: number[];
    nowMs: number;
    timeouts: Pick<
      ProbeOperationConfig,
      "acceptedTimeoutMs" | "runningTimeoutMs"
    >;
    userAgent?: string;
  },
): HostSummaryProjection[] {
  const hostProfileObservations = new Map<
    number,
    ReturnType<
      SnapshotCollectorStorageRegistry["hostProfile"]["readObservation"]
    >
  >();
  const metricsCollectionIntervals = new Map<number, number>();
  const selectedHostIds = input.hostIds ? new Set(input.hostIds) : null;
  const databaseHosts = services.hosts
    .listSummaries({
      hostProfileForHost: (hostId) => {
        const observation =
          services.snapshotCollectors?.hostProfile.readObservation(hostId) ??
          null;
        hostProfileObservations.set(hostId, observation);
        return observation?.view ?? null;
      },
      latestMetricForHost: (hostId) =>
        services.metrics?.findLatestSample(hostId) ?? null,
      nowMs: input.nowMs,
      probeConfigurationForHost: (hostId) => {
        const effective =
          services.probeConfigurations?.getEffectiveForHost(hostId);
        metricsCollectionIntervals.set(
          hostId,
          effective?.configuration.metricsCollectionIntervalSeconds ?? 5,
        );

        return {
          mode: effective?.mode ?? "inherit",
          version: effective?.configuration.version ?? "default-v1",
        };
      },
      thresholds: services.hostStatus,
    })
    .filter((host) => selectedHostIds?.has(host.id) ?? true);
  const problems = probeUpgradeOverviewProblems({
    audit: services.audit,
    hostIds: databaseHosts.map((host) => host.id),
    nowMs: input.nowMs,
    probeOperations: services.probeOperations,
    reportedHostProfileObservationForHost: (hostId) =>
      hostProfileObservations.get(hostId) ?? null,
    timeouts: input.timeouts,
    userAgent: input.userAgent,
  });

  return databaseHosts.map((databaseHost) => {
    const metricsCollectionIntervalSeconds =
      metricsCollectionIntervals.get(databaseHost.id) ?? 5;

    return {
      databaseHost,
      metricsCollectionIntervalSeconds,
      response: hostSummaryResponse(databaseHost, {
        metricsCollectionIntervalSeconds,
        probeUpgradeProblem: problems.get(databaseHost.id) ?? null,
      }),
    };
  });
}
