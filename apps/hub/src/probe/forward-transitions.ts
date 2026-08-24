import type {
  ProbeUpgradeOverviewProblem,
  ProbeUpgradeStatus,
} from "@enoki/api-client";

import type { AuditRepository } from "../database/audit.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import {
  evaluateProbeUpgradeEligibility,
  type ProbeUpgradeNonUpgradeableReason,
} from "./asset-set.js";
import {
  acknowledgeProbeUpgradeRequest,
  createProbeUpgradeRequest,
  failReportedProbeUpgradeRequest,
  startProbeUpgradeRequest,
  succeedProbeUpgradeRequestFromHostProfile,
  type ProbeUpgradeRequest,
} from "./operation.js";
import type { ProbeReleaseContext } from "./release-context.js";
import { probeUpgradeRecoveryDisposition } from "./upgrade-recovery.js";

export type AuthenticatedHostProfileEvidence = {
  authenticatedProbeId: string;
  bootEvidenceBootId: string | null;
  bootEvidenceProbeId: string | null;
  bootProbeAssetBundleVersion: string | null;
  kind: "authenticated_host_profile";
  observedAtMs: number;
  operationId: number;
  probeAssetBundleVersion: string | null;
  probeVersion: string;
  profileReportBootId: string;
};

export type ForwardTransitionView = {
  currentOperation: ProbeUpgradeRequest | null;
  overviewProblem: ProbeUpgradeOverviewProblem;
  status: ProbeUpgradeStatus | null;
};

type OperationEvidenceBase = {
  hostId: number;
  observedAtMs: number;
  operationId: number;
};

export type AuthenticatedForwardEvidence =
  | (OperationEvidenceBase & { kind: "operation_accepted" })
  | (OperationEvidenceBase & { kind: "operation_running" })
  | (OperationEvidenceBase & {
      code: string;
      kind: "operation_failed";
      message: string;
      repairEligibility?: {
        evidenceJson: string;
        evidenceSha256: string;
      } | null;
    })
  | (OperationEvidenceBase & {
      authenticatedProbeId: string;
      bootEvidenceBootId: string | null;
      bootEvidenceProbeId: string | null;
      bootProbeAssetBundleVersion: string | null;
      hostProfile: {
        probeAssetBundleVersion?: string | null;
        probeVersion?: string | null;
      };
      kind: "host_profile_terminal";
      profileReportBootId: string;
    });

export type CompatibleUpgradeIntent = {
  hostId: number;
  kind: "compatible_upgrade";
  sourceProbeVersion: string | null;
};

export type ForwardTransitions = {
  authorize(input: {
    intent: CompatibleUpgradeIntent;
    nowMs: number;
    releaseContext: ProbeReleaseContext;
    userAgent?: string;
  }):
    | {
        kind: "authorized";
        operation: ProbeUpgradeRequest;
        reused: boolean;
      }
    | {
        kind: "refused";
        reason:
          | ProbeUpgradeNonUpgradeableReason
          | "probe_upgrade_request_active";
      };
  reconcileAuthenticatedEvidence(input: {
    evidence: AuthenticatedForwardEvidence[];
  }):
    | { kind: "reconciled"; operations: ProbeUpgradeRequest[] }
    | {
        kind: "refused";
        reason: "probe_operation_not_found" | "probe_operation_status_invalid";
      };
  view(input: {
    acceptedHostProfile: AuthenticatedHostProfileEvidence | null;
    latestOperation: ProbeUpgradeRequest | null;
  }): ForwardTransitionView;
};

export function createForwardTransitions(input: {
  audit?: AuditRepository;
  probeOperations: ProbeOperationRepository;
}): ForwardTransitions {
  return {
    authorize({ intent, nowMs, releaseContext, userAgent }) {
      const authorization = compatibleUpgradeAuthorization(
        intent,
        releaseContext,
      );
      if (authorization.kind === "refused") {
        return authorization;
      }

      const result = createProbeUpgradeRequest({
        activeOperation: input.probeOperations.findActiveForHost(intent.hostId),
        currentProbeVersion: intent.sourceProbeVersion,
        hostId: intent.hostId,
        nowMs,
        target: {
          assetSetDigest: authorization.targetAssetSetDigest,
          version: authorization.targetProbeVersion,
        },
      });
      if (result.error) {
        return { kind: "refused", reason: result.error };
      }

      const operation = result.events.length
        ? input.probeOperations.commitProbeUpgradeAuthorization(result.events)
        : result.operation;
      for (const event of result.events) {
        const persisted =
          event.action === "created" ? operation : event.operation;
        input.audit?.record({
          action:
            event.action === "created"
              ? "probe_upgrade_request.create"
              : "probe_upgrade_request.supersede",
          actor: "owner",
          details: {
            hostId: intent.hostId,
            targetProbeVersion: persisted.targetProbeVersion,
          },
          occurredAtMs: nowMs,
          outcome: "success",
          subjectId: String(persisted.id),
          subjectType: "probe_upgrade_request",
          userAgent,
        });
      }

      return {
        kind: "authorized",
        operation,
        reused: result.events.length === 0,
      };
    },
    reconcileAuthenticatedEvidence({ evidence }) {
      const staged = new Map<number, ProbeUpgradeRequest>();
      const changed = new Map<number, ProbeUpgradeRequest>();

      for (const fact of evidence) {
        const operation =
          staged.get(fact.operationId) ??
          input.probeOperations.findById(fact.operationId);
        if (
          !operation ||
          operation.hostId !== fact.hostId ||
          !["probe_upgrade", "probe_repair"].includes(operation.kind)
        ) {
          return { kind: "refused", reason: "probe_operation_not_found" };
        }

        const result = reconcileOneEvidence(operation, fact);
        if (result.kind === "refused") return result;
        if (result.operation !== operation) {
          staged.set(fact.operationId, result.operation);
          changed.set(fact.operationId, result.operation);
        }
      }

      const persisted = [...changed.values()].map((operation) =>
        input.probeOperations.updateProbeUpgradeRequest(operation),
      );
      return { kind: "reconciled", operations: persisted };
    },
    view({ acceptedHostProfile, latestOperation }) {
      const currentOperation = currentForwardOperation({
        acceptedHostProfile,
        latestOperation,
      });
      if (!currentOperation) {
        return {
          currentOperation: null,
          overviewProblem: null,
          status: null,
        };
      }

      const failedUpgrade =
        currentOperation.kind === "probe_repair"
          ? input.probeOperations.findBoundFailedUpgradeForRepair(
              currentOperation,
            )
          : null;
      return {
        currentOperation,
        overviewProblem: {
          status:
            currentOperation.state === "failed" ? "failed" : "in_progress",
        },
        status: probeUpgradeStatus(currentOperation, failedUpgrade),
      };
    },
  };
}

function reconcileOneEvidence(
  operation: ProbeUpgradeRequest,
  evidence: AuthenticatedForwardEvidence,
):
  | { kind: "reconciled"; operation: ProbeUpgradeRequest }
  | { kind: "refused"; reason: "probe_operation_status_invalid" } {
  if (evidence.kind === "operation_accepted") {
    if (isClosed(operation)) {
      return { kind: "reconciled", operation };
    }
    const result = acknowledgeProbeUpgradeRequest({
      nowMs: evidence.observedAtMs,
      operation,
    });
    return result.error
      ? { kind: "refused", reason: "probe_operation_status_invalid" }
      : { kind: "reconciled", operation: result.acknowledged };
  }

  if (evidence.kind === "operation_running") {
    if (isClosed(operation)) {
      return { kind: "reconciled", operation };
    }
    const result = startProbeUpgradeRequest({
      nowMs: evidence.observedAtMs,
      operation,
    });
    return result.error
      ? { kind: "refused", reason: "probe_operation_status_invalid" }
      : { kind: "reconciled", operation: result.operation };
  }

  if (evidence.kind === "operation_failed") {
    if (isClosed(operation) && !evidence.repairEligibility) {
      return { kind: "reconciled", operation };
    }
    const result = failReportedProbeUpgradeRequest({
      code: evidence.code,
      message: evidence.message,
      nowMs: evidence.observedAtMs,
      operation,
      repairEligibility: evidence.repairEligibility,
    });
    return result.error
      ? { kind: "refused", reason: "probe_operation_status_invalid" }
      : { kind: "reconciled", operation: result.operation };
  }

  const succeeded = succeedProbeUpgradeRequestFromHostProfile({
    authenticatedProbeId: evidence.authenticatedProbeId,
    bootEvidenceBootId: evidence.bootEvidenceBootId,
    bootEvidenceProbeId: evidence.bootEvidenceProbeId,
    bootProbeAssetBundleVersion: evidence.bootProbeAssetBundleVersion,
    hostProfile: evidence.hostProfile,
    nowMs: evidence.observedAtMs,
    operation,
    profileReportBootId: evidence.profileReportBootId,
  });
  return {
    kind: "reconciled",
    operation: succeeded ?? operation,
  };
}

function isClosed(operation: ProbeUpgradeRequest) {
  return ["canceled", "failed", "succeeded", "superseded"].includes(
    operation.state,
  );
}

function currentForwardOperation(input: {
  acceptedHostProfile: AuthenticatedHostProfileEvidence | null;
  latestOperation: ProbeUpgradeRequest | null;
}) {
  const operation = input.latestOperation;
  if (
    !operation ||
    !["probe_upgrade", "probe_repair"].includes(operation.kind) ||
    ["succeeded", "canceled", "superseded"].includes(operation.state)
  ) {
    return null;
  }

  if (
    operation.kind === "probe_upgrade" &&
    operation.state === "failed" &&
    operation.completedAtMs !== null &&
    input.acceptedHostProfile !== null &&
    acceptedHostProfileProvesFailedUpgradeRecovery(
      input.acceptedHostProfile,
      operation,
    ) &&
    probeUpgradeRecoveryDisposition(operation) !== "probe_repair"
  ) {
    return null;
  }

  return operation;
}

function acceptedHostProfileProvesFailedUpgradeRecovery(
  evidence: AuthenticatedHostProfileEvidence,
  operation: ProbeUpgradeRequest,
) {
  return (
    operation.id !== null &&
    operation.completedAtMs !== null &&
    evidence.operationId === operation.id &&
    evidence.observedAtMs > operation.completedAtMs &&
    Boolean(evidence.authenticatedProbeId) &&
    Boolean(evidence.profileReportBootId) &&
    evidence.bootEvidenceBootId === evidence.profileReportBootId &&
    evidence.bootEvidenceProbeId === evidence.authenticatedProbeId &&
    normalizeProbeVersion(evidence.bootProbeAssetBundleVersion) ===
      normalizeProbeVersion(operation.targetProbeVersion) &&
    normalizeProbeVersion(evidence.probeAssetBundleVersion) ===
      normalizeProbeVersion(operation.targetProbeVersion) &&
    normalizeProbeVersion(evidence.probeVersion) ===
      normalizeProbeVersion(operation.targetProbeVersion)
  );
}

function probeUpgradeStatus(
  operation: ProbeUpgradeRequest,
  failedUpgrade: ProbeUpgradeRequest | null,
): ProbeUpgradeStatus {
  if (operation.id === null) {
    throw new Error("Probe Operation view requires a persisted record.");
  }
  return {
    acceptedAtMs: operation.acceptedAtMs,
    completedAtMs: operation.completedAtMs,
    createdAtMs: operation.createdAtMs,
    failure: operation.failureCode
      ? {
          recoveryDisposition: probeUpgradeRecoveryDisposition(
            operation,
            failedUpgrade,
          ),
        }
      : null,
    id: operation.id,
    kind: operation.kind,
    runningAtMs: operation.runningAtMs,
    state: operation.state,
    targetProbeVersion: operation.targetProbeVersion,
    updatedAtMs: operation.updatedAtMs,
  };
}

function normalizeProbeVersion(value: string | null | undefined) {
  return value?.trim().replace(/^v/, "") ?? "";
}

function compatibleUpgradeAuthorization(
  intent: CompatibleUpgradeIntent,
  releaseContext: ProbeReleaseContext,
):
  | {
      kind: "authorized";
      targetAssetSetDigest: string;
      targetProbeVersion: string;
    }
  | { kind: "refused"; reason: ProbeUpgradeNonUpgradeableReason } {
  const eligibility = evaluateProbeUpgradeEligibility({
    probeAssetSetVersion: releaseContext.assetSet.version,
    probeAssetSetVersionNonUpgradeableReason:
      releaseContext.assetSet.nonUpgradeableReason,
    probeVersion: intent.sourceProbeVersion,
    releaseTransition: releaseContext.releaseTransition,
  });
  if (!eligibility.isUpgradeable) {
    return { kind: "refused", reason: eligibility.nonUpgradeableReason! };
  }
  if (
    !eligibility.currentProbeAssetSetVersion ||
    !releaseContext.assetSet.targetAssetSetDigest ||
    releaseContext.releaseTransition?.targetAssetSetDigest !==
      releaseContext.assetSet.targetAssetSetDigest
  ) {
    return { kind: "refused", reason: "probe_release_transition_mismatch" };
  }
  return {
    kind: "authorized",
    targetAssetSetDigest: releaseContext.assetSet.targetAssetSetDigest,
    targetProbeVersion: eligibility.currentProbeAssetSetVersion,
  };
}
