import type { ProbeOperationConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import {
  acceptedTimedOutProbeUpgradeRequest,
  runningTimedOutProbeUpgradeRequest,
  type ProbeUpgradeRequest,
} from "../probe/operation.js";

export const defaultProbeOperationTimeouts = {
  acceptedTimeoutMs: 5 * 60 * 1_000,
  runningTimeoutMs: 15 * 60 * 1_000,
} satisfies Pick<
  ProbeOperationConfig,
  "acceptedTimeoutMs" | "runningTimeoutMs"
>;

export function persistTimedOutProbeUpgradeRequest(input: {
  audit?: AuditRepository;
  nowMs: number;
  operation: ProbeUpgradeRequest;
  probeOperations?: ProbeOperationRepository;
  timeouts: Pick<
    ProbeOperationConfig,
    "acceptedTimeoutMs" | "runningTimeoutMs"
  >;
  userAgent?: string;
}) {
  const failed =
    acceptedTimedOutProbeUpgradeRequest({
      acceptedTimeoutMs: input.timeouts.acceptedTimeoutMs,
      nowMs: input.nowMs,
      operation: input.operation,
    }) ??
    runningTimedOutProbeUpgradeRequest({
      nowMs: input.nowMs,
      operation: input.operation,
      runningTimeoutMs: input.timeouts.runningTimeoutMs,
    });

  if (!failed) {
    return null;
  }

  const persisted =
    input.probeOperations?.updateProbeUpgradeRequest(failed) ?? failed;
  input.audit?.record({
    action: "probe_upgrade_request.fail",
    actor: "system",
    details: {
      failureCode: persisted.failureCode,
      hostId: persisted.hostId,
      targetProbeVersion: persisted.targetProbeVersion,
    },
    occurredAtMs: input.nowMs,
    outcome: "success",
    subjectId: String(persisted.id),
    subjectType: "probe_upgrade_request",
    userAgent: input.userAgent,
  });

  return persisted;
}
