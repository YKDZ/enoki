import type { ProbeUpgradeOverviewProblem } from "@enoki/api-client";
import type { HostProfileSnapshot } from "@enoki/api-client/protocol";

import type { ProbeOperationConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import { createForwardTransitions } from "../probe/forward-transitions.js";
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
  const forwardTransitions = input.probeOperations
    ? createForwardTransitions({
        audit: input.audit,
        probeOperations: input.probeOperations,
      })
    : null;

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
      forwardTransitions?.view({
        acceptedHostProfile: hostProfileObservation
          ? {
              kind: "authenticated_host_profile",
              observedAtMs: hostProfileObservation.observedAtMs,
              probeVersion: hostProfileObservation.view.probeVersion,
            }
          : null,
        latestOperation: timedOutOperation ?? latestOperation,
      }).overviewProblem ?? null,
    );
  }

  return problems;
}
