import type { ProbeUpgradeOverviewProblem } from "@enoki/api-client";
import type { HostProfileSnapshot } from "@enoki/api-client/protocol";

import type { ProbeOperationConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import { probeUpgradeOverviewProblem } from "./api-response.js";
import { persistTimedOutProbeUpgradeRequest } from "./probe-upgrade-timeout.js";

export function probeUpgradeOverviewProblems(input: {
  audit?: AuditRepository;
  hostIds: number[];
  nowMs: number;
  probeOperations?: ProbeOperationRepository;
  reportedHostProfileObservationForHost: (
    hostId: number,
  ) => { observedAtMs: number; view: HostProfileSnapshot } | null;
  timeouts: Pick<
    ProbeOperationConfig,
    "acceptedTimeoutMs" | "runningTimeoutMs"
  >;
  userAgent?: string;
}) {
  const latestOperations =
    input.probeOperations?.findLatestForHosts(input.hostIds) ?? new Map();
  const problems = new Map<number, ProbeUpgradeOverviewProblem>();

  for (const hostId of input.hostIds) {
    const hostProfileObservation =
      input.reportedHostProfileObservationForHost(hostId);
    const latestOperation = latestOperations.get(hostId) ?? null;
    const timedOutOperation = latestOperation
      ? persistTimedOutProbeUpgradeRequest({
          audit: input.audit,
          nowMs: input.nowMs,
          operation: latestOperation,
          probeOperations: input.probeOperations,
          timeouts: input.timeouts,
          userAgent: input.userAgent,
        })
      : null;

    problems.set(
      hostId,
      probeUpgradeOverviewProblem({
        operation: timedOutOperation ?? latestOperation,
        reportedProbeVersion: hostProfileObservation?.view.probeVersion,
        reportedProbeVersionObservedAtMs: hostProfileObservation?.observedAtMs,
      }),
    );
  }

  return problems;
}
