import type { ProbeOperationConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { SnapshotCollectorStorageRegistry } from "../database/host-profiles.js";
import type {
  HostRepository,
  HostStatusThresholds,
} from "../database/hosts.js";
import type { MetricsRepository } from "../database/metrics.js";
import type { ProbeConfigurationRepository } from "../database/probe-configuration.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import {
  liveSummaryFromHost,
  type LiveUpdateBroadcaster,
} from "../live-updates.js";
import { probeUpgradeOverviewProblems } from "./probe-upgrade-overview.js";

export function broadcastHostSummaryHint(
  services: {
    audit?: AuditRepository;
    hosts: HostRepository;
    hostStatus?: HostStatusThresholds;
    liveUpdates?: LiveUpdateBroadcaster | null;
    metrics?: MetricsRepository;
    probeConfigurations?: ProbeConfigurationRepository;
    probeOperations?: ProbeOperationRepository;
    snapshotCollectors?: SnapshotCollectorStorageRegistry;
  },
  input: {
    hostId: number;
    nowMs: number;
    timeouts: Pick<
      ProbeOperationConfig,
      "acceptedTimeoutMs" | "runningTimeoutMs"
    >;
    userAgent?: string;
  },
) {
  if (!services.liveUpdates) {
    return;
  }

  try {
    const reportedProbeVersions = new Map<number, string | null | undefined>();
    const hostSummary = services.hosts
      .listSummaries({
        hostProfileForHost: (hostId) => {
          const hostProfile =
            services.snapshotCollectors?.hostProfile.read(hostId) ?? null;
          reportedProbeVersions.set(hostId, hostProfile?.probeVersion);
          return hostProfile;
        },
        latestMetricForHost: (hostId) =>
          services.metrics?.findLatestSample(hostId) ?? null,
        nowMs: input.nowMs,
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
      .find((summary) => summary.id === input.hostId);

    if (!hostSummary) {
      return;
    }

    const effectiveConfiguration =
      services.probeConfigurations?.getEffectiveForHost(input.hostId);
    const problems = probeUpgradeOverviewProblems({
      audit: services.audit,
      hostIds: [input.hostId],
      nowMs: input.nowMs,
      probeOperations: services.probeOperations,
      reportedProbeVersionForHost: (hostId) =>
        reportedProbeVersions.get(hostId),
      timeouts: input.timeouts,
      userAgent: input.userAgent,
    });

    services.liveUpdates.broadcastHostSummary(
      liveSummaryFromHost(hostSummary, {
        metricsCollectionIntervalSeconds:
          effectiveConfiguration?.configuration
            .metricsCollectionIntervalSeconds ?? 5,
        probeUpgradeProblem: problems.get(input.hostId) ?? null,
      }),
    );
  } catch {
    // The committed Host or Probe operation state remains authoritative.
  }
}
