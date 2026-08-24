import type { ProbeUpgradeOverviewProblem } from "@enoki/api-client";
import type { HostProfileSnapshot } from "@enoki/api-client/protocol";

import type { ProbeOperationConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { HostProfileForwardEvidence } from "../database/host-profiles.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import type { HostRow } from "../database/schema.js";
import {
  createForwardTransitions,
  type AuthenticatedHostProfileEvidence,
} from "../probe/forward-transitions.js";
import { persistTimedOutProbeUpgradeRequest } from "./probe-upgrade-timeout.js";

export function probeUpgradeOverviewProblems(input: {
  audit?: AuditRepository;
  hostIds: number[];
  nowMs: number;
  probeOperations?: ProbeOperationRepository;
  acceptedHostProfileEvidenceForHost: (
    hostId: number,
  ) => AuthenticatedHostProfileEvidence | null;
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
    const acceptedHostProfile =
      input.acceptedHostProfileEvidenceForHost(hostId);
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
        acceptedHostProfile,
        latestOperation: timedOutOperation ?? latestOperation,
      }).overviewProblem ?? null,
    );
  }

  return problems;
}

export function acceptedForwardHostProfileEvidence(input: {
  host: Pick<
    HostRow,
    | "probeAssetBundleBootId"
    | "probeAssetBundleProbeId"
    | "probeAssetBundleVersion"
  >;
  observation: {
    forwardEvidence: HostProfileForwardEvidence | null;
    observedAtMs: number;
    view: HostProfileSnapshot;
  } | null;
}): AuthenticatedHostProfileEvidence | null {
  if (!input.observation?.forwardEvidence) return null;

  return {
    authenticatedProbeId: input.observation.forwardEvidence.reportProbeId,
    bootEvidenceBootId: input.host.probeAssetBundleBootId,
    bootEvidenceProbeId: input.host.probeAssetBundleProbeId,
    bootProbeAssetBundleVersion: input.host.probeAssetBundleVersion,
    kind: "authenticated_host_profile",
    observedAtMs: input.observation.observedAtMs,
    operationId: input.observation.forwardEvidence.operationId,
    probeAssetBundleVersion:
      input.observation.forwardEvidence.profileProbeAssetBundleVersion,
    probeVersion: input.observation.view.probeVersion,
    profileReportBootId: input.observation.forwardEvidence.reportBootId,
  };
}
