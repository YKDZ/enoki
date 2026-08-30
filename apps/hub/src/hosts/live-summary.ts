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
import { projectHostSummaries } from "./summary-projection.js";

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
    const projection = projectHostSummaries(services, {
      hostIds: [input.hostId],
      nowMs: input.nowMs,
      timeouts: input.timeouts,
      userAgent: input.userAgent,
    })[0];

    if (!projection) {
      return;
    }

    services.liveUpdates.broadcastHostSummary(
      liveSummaryFromHost(projection.databaseHost, {
        metricsCollectionIntervalSeconds:
          projection.metricsCollectionIntervalSeconds,
        probeUpgradeProblem: projection.response.probeUpgradeProblem,
      }),
    );
  } catch {
    // 已提交的 Host 或 Probe Operation 状态仍是权威事实。
  }
}
