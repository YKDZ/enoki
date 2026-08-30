import { Buffer } from "node:buffer";

import {
  createForwardTransitions,
  type AuthenticatedForwardEvidence,
} from "./forward-transitions.js";
import { deriveLifecycleAuthorityKey } from "./lifecycle-authority.js";
import {
  defaultProbeOperationTokenTtlMs,
  issueProbeOperationToken,
} from "./operation-token.js";
import {
  acknowledgeProbeUpgradeRequest,
  failReportedProbeUpgradeRequest,
  hasUnavailableProbeUpgradeTarget,
  isClosedProbeOperation,
  succeedReportedProbeOperation,
  startProbeUpgradeRequest,
  type ProbeUpgradeRequest,
} from "./operation.js";
import { verifyProbeRepairEligibility } from "./repair-authority.js";
import type { ProtoMessage } from "./report-validation.js";
import { parseProbeOperationId } from "./route-http.js";
import {
  defaultProbeOperationTokenSecret,
  type ProbeRouteServices,
} from "./route-services.js";

export function pendingProbeOperationForHost(
  services: ProbeRouteServices,
  hostId: number,
  probeId: string,
  nowMs: number,
): ProtoMessage | null {
  const operation = services.probeOperations?.findActiveForHost(hostId);

  if (!operation || operation.state !== "pending") {
    return null;
  }
  if (operation.kind === "probe_upgrade" && !operation.targetAssetSetDigest) {
    return null;
  }

  return probeUpgradeOperationMessage(operation, {
    expiresAtMs: nowMs + defaultProbeOperationTokenTtlMs,
    probeId,
    secret: probeOperationTokenSecret(services),
  });
}

function probeUpgradeOperationMessage(
  operation: ProbeUpgradeRequest,
  tokenInput: {
    expiresAtMs: number;
    probeId: string;
    secret: string;
  },
): ProtoMessage {
  if (operation.kind === "probe_uninstall") {
    return {
      id: String(operation.id),
      probeUninstall: {
        operationToken: issueProbeOperationToken({
          expiresAtMs: tokenInput.expiresAtMs,
          operation,
          probeId: tokenInput.probeId,
          secret: tokenInput.secret,
        }),
      },
    };
  }

  return {
    id: String(operation.id),
    probeUpgrade: {
      currentProbeVersion: operation.currentProbeVersion ?? "",
      hostId: String(operation.hostId),
      operationToken: issueProbeOperationToken({
        expiresAtMs: tokenInput.expiresAtMs,
        operation,
        probeId: tokenInput.probeId,
        secret: tokenInput.secret,
      }),
      targetAssetSetDigest: operation.targetAssetSetDigest ?? "",
      targetManifestSha256: "",
      targetProbeVersion: operation.targetProbeVersion,
    },
  };
}

function probeOperationTokenSecret(services: ProbeRouteServices) {
  return services.probeOperationTokenSecret ?? defaultProbeOperationTokenSecret;
}

function applyProbeOperationReports(input: {
  hostId: number;
  nowMs: number;
  operations: ProbeUpgradeRequest[];
  services: ProbeRouteServices;
}): { error: string | null; hostRemovedIds: number[] } {
  const hostRemovedIds: number[] = [];
  for (const operation of input.operations) {
    const updated =
      input.services.probeOperations?.updateProbeUpgradeRequest(operation) ??
      operation;
    const removed = completeProbeUninstallIfSucceeded({
      nowMs: input.nowMs,
      operation: updated,
      services: input.services,
    });
    if (removed !== null) {
      hostRemovedIds.push(removed);
    }
  }

  return { error: null, hostRemovedIds };
}

function planProbeOperationReportApplication(input: {
  acknowledgements: ProtoMessage[];
  hostId: number;
  nowMs: number;
  probeId: string;
  services: ProbeRouteServices;
  statuses: ProtoMessage[];
}):
  | { error: string; operations: [] }
  | {
      error: null;
      operations: ProbeUpgradeRequest[];
    } {
  if (
    !input.services.probeOperations &&
    (input.acknowledgements.length > 0 || input.statuses.length > 0)
  ) {
    return {
      error: "malformed_probe_operation_acknowledgement",
      operations: [],
    };
  }

  const stagedOperations = new Map<number, ProbeUpgradeRequest>();
  const operationsToUpdate = new Map<number, ProbeUpgradeRequest>();
  const forwardEvidence: AuthenticatedForwardEvidence[] = [];

  for (const acknowledgement of input.acknowledgements) {
    const operation = findReportableProbeOperation(
      input.services,
      input.hostId,
      acknowledgement.operationId,
      stagedOperations,
    );

    if (!operation) {
      return {
        error: "malformed_probe_operation_acknowledgement",
        operations: [],
      };
    }

    if (isClosedProbeOperation(operation)) {
      continue;
    }

    if (operation.kind !== "probe_uninstall") {
      forwardEvidence.push({
        hostId: input.hostId,
        kind: "operation_accepted",
        observedAtMs: input.nowMs,
        operationId: operation.id!,
      });
      continue;
    }

    const result = acknowledgeProbeUpgradeRequest({
      nowMs: input.nowMs,
      operation,
    });

    if (result.error) {
      return {
        error: "malformed_probe_operation_acknowledgement",
        operations: [],
      };
    }

    if (result.acknowledged !== operation) {
      stageProbeOperationUpdate(
        result.acknowledged,
        stagedOperations,
        operationsToUpdate,
      );
    }
  }

  for (const status of input.statuses) {
    const operation = findReportableProbeOperation(
      input.services,
      input.hostId,
      status.operationId,
      stagedOperations,
    );

    if (!operation) {
      return {
        error: "malformed_probe_operation_status",
        operations: [],
      };
    }

    const repairEligibility = verifiedRepairEligibilityForStatus({
      operation,
      probeId: input.probeId,
      services: input.services,
      status,
    });

    if (operation.kind !== "probe_uninstall") {
      const evidence = forwardEvidenceFromStatus({
        hostId: input.hostId,
        nowMs: input.nowMs,
        operation,
        repairEligibility,
        status,
      });
      if (!evidence) {
        return {
          error: "malformed_probe_operation_status",
          operations: [],
        };
      }
      forwardEvidence.push(evidence);
      continue;
    }

    if (isClosedProbeOperation(operation) && !repairEligibility) {
      continue;
    }

    const result = applyProbeOperationStatus(
      status,
      operation,
      input.nowMs,
      repairEligibility,
    );

    if (result.error) {
      return {
        error: "malformed_probe_operation_status",
        operations: [],
      };
    }

    if (result.operation !== operation) {
      stageProbeOperationUpdate(
        result.operation,
        stagedOperations,
        operationsToUpdate,
      );
    }
  }

  if (forwardEvidence.length > 0) {
    const reconciled = forwardTransitionsFor(
      input.services,
    ).reconcileAuthenticatedEvidence({ evidence: forwardEvidence });
    if (reconciled.kind === "refused") {
      return {
        error: "malformed_probe_operation_status",
        operations: [],
      };
    }
  }

  return {
    error: null,
    operations: [...operationsToUpdate.values()],
  };
}

export function reconcileAuthenticatedOperationEvidence(input: {
  acknowledgements: ProtoMessage[];
  hostId: number;
  nowMs: number;
  probeId: string;
  services: ProbeRouteServices;
  statuses: ProtoMessage[];
}): { error: string | null; hostRemovedIds: number[] } {
  const plan = planProbeOperationReportApplication(input);
  if (plan.error) {
    return { error: plan.error, hostRemovedIds: [] };
  }
  return applyProbeOperationReports({
    hostId: input.hostId,
    nowMs: input.nowMs,
    operations: plan.operations,
    services: input.services,
  });
}

function forwardEvidenceFromStatus(input: {
  hostId: number;
  nowMs: number;
  operation: ProbeUpgradeRequest;
  repairEligibility?: {
    evidenceJson: string;
    evidenceSha256: string;
  } | null;
  status: ProtoMessage;
}): AuthenticatedForwardEvidence | null {
  const status = decodeProbeOperationStatus(input.status);
  if (status?.kind === "running") {
    return {
      hostId: input.hostId,
      kind: "operation_running",
      observedAtMs: input.nowMs,
      operationId: input.operation.id!,
    };
  }
  if (status?.kind === "failed") {
    return {
      code: status.code,
      hostId: input.hostId,
      kind: "operation_failed",
      message: status.message,
      observedAtMs: input.nowMs,
      operationId: input.operation.id!,
      repairEligibility: input.repairEligibility,
    };
  }
  return null;
}

function stageProbeOperationUpdate(
  operation: ProbeUpgradeRequest,
  stagedOperations: Map<number, ProbeUpgradeRequest>,
  operationsToUpdate: Map<number, ProbeUpgradeRequest>,
) {
  if (operation.id === null) {
    return;
  }

  stagedOperations.set(operation.id, operation);
  operationsToUpdate.set(operation.id, operation);
}

function findReportableProbeOperation(
  services: ProbeRouteServices,
  hostId: number,
  operationId: string | null | undefined,
  stagedOperations?: Map<number, ProbeUpgradeRequest>,
) {
  const id = parseProbeOperationId(operationId);

  if (id === null) {
    return null;
  }

  const stagedOperation = stagedOperations?.get(id);
  if (stagedOperation && !hasUnavailableProbeUpgradeTarget(stagedOperation)) {
    return stagedOperation;
  }

  const active = services.probeOperations?.findActiveForHost(hostId);
  if (active?.id === id && !hasUnavailableProbeUpgradeTarget(active)) {
    return active;
  }

  const operation = services.probeOperations?.findById(id);
  if (
    operation?.hostId === hostId &&
    !hasUnavailableProbeUpgradeTarget(operation) &&
    ["failed", "superseded", "canceled", "succeeded"].includes(operation.state)
  ) {
    return operation;
  }

  return null;
}

function applyProbeOperationStatus(
  status: ProtoMessage,
  operation: ProbeUpgradeRequest,
  nowMs: number,
  repairEligibility?: {
    evidenceJson: string;
    evidenceSha256: string;
  } | null,
) {
  const decoded = decodeProbeOperationStatus(status);
  if (decoded?.kind === "running") {
    return startProbeUpgradeRequest({
      nowMs,
      operation,
    });
  }

  if (decoded?.kind === "failed") {
    return failReportedProbeUpgradeRequest({
      code: decoded.code,
      message: decoded.message,
      nowMs,
      operation,
      repairEligibility,
    });
  }

  if (decoded?.kind === "succeeded") {
    return succeedReportedProbeOperation({
      nowMs,
      operation,
    });
  }

  return {
    error: "probe_operation_status_invalid" as const,
    operation,
  };
}

function decodeProbeOperationStatus(
  status: ProtoMessage,
):
  | { kind: "running" }
  | { code: string; kind: "failed"; message: string }
  | { kind: "succeeded" }
  | null {
  const branches = [
    Boolean(status.running),
    Boolean(status.failed),
    Boolean(status.succeeded),
  ];
  if (branches.filter(Boolean).length !== 1) return null;

  if (status.running) return { kind: "running" };
  if (status.failed?.errorCode) {
    return {
      code: status.failed.errorCode,
      kind: "failed",
      message: status.failed.message ?? "",
    };
  }
  return status.succeeded ? { kind: "succeeded" } : null;
}

function verifiedRepairEligibilityForStatus(input: {
  operation: ProbeUpgradeRequest;
  probeId: string;
  services: ProbeRouteServices;
  status: ProtoMessage;
}) {
  if (
    input.status.failed?.errorCode !== "lifecycle.upgrade_repair_required" ||
    typeof input.status.failed.repairEligibilityEvidence !== "string" ||
    !input.status.failed.repairEligibilityEvidence ||
    typeof input.status.failed.repairEligibilitySignature !== "string" ||
    !input.status.failed.repairEligibilitySignature
  ) {
    return null;
  }
  const tokenHash =
    input.services.enrollments.lifecycleAuthorityTokenHashForHost(
      input.operation.hostId,
    );
  const hubOrigin = input.services.probeApiOrigin ?? "";
  if (!tokenHash || !/^[0-9a-f]{64}$/.test(tokenHash) || !hubOrigin) {
    return null;
  }
  return verifyProbeRepairEligibility({
    canonicalEvidence: input.status.failed.repairEligibilityEvidence,
    evidenceSignature: input.status.failed.repairEligibilitySignature,
    expectedHubOrigin: hubOrigin,
    expectedProbeId: input.probeId,
    failedUpgrade: input.operation,
    installKey: deriveLifecycleAuthorityKey(
      Buffer.from(tokenHash, "hex"),
      hubOrigin,
    ),
  });
}

function completeProbeUninstallIfSucceeded(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
  services: ProbeRouteServices;
}) {
  if (
    input.operation.kind !== "probe_uninstall" ||
    input.operation.state !== "succeeded"
  ) {
    return null;
  }

  const deleted = input.services.hosts.softDelete(
    input.operation.hostId,
    input.nowMs,
  );
  if (deleted) {
    return deleted.id;
  }
  return null;
}

export function markProbeUpgradeSucceededFromHostProfile(input: {
  authenticatedProbeId: string;
  bootEvidenceBootId: string | null;
  bootEvidenceProbeId: string | null;
  bootProbeAssetBundleVersion: string | null;
  hostId: number;
  hostProfile: {
    probeAssetBundleVersion?: string | null;
    probeVersion?: string | null;
  } | null;
  nowMs: number;
  profileReportBootId: string;
  services: ProbeRouteServices;
}) {
  if (!input.hostProfile?.probeVersion) {
    return;
  }

  const active = input.services.probeOperations?.findActiveForHost(
    input.hostId,
  );
  if (!active) {
    return;
  }

  if (active.id === null) return;
  forwardTransitionsFor(input.services).reconcileAuthenticatedEvidence({
    evidence: [
      {
        authenticatedProbeId: input.authenticatedProbeId,
        bootEvidenceBootId: input.bootEvidenceBootId,
        bootEvidenceProbeId: input.bootEvidenceProbeId,
        bootProbeAssetBundleVersion: input.bootProbeAssetBundleVersion,
        hostId: input.hostId,
        hostProfile: input.hostProfile,
        kind: "host_profile_terminal",
        observedAtMs: input.nowMs,
        operationId: active.id,
        profileReportBootId: input.profileReportBootId,
      },
    ],
  });
}

function forwardTransitionsFor(services: ProbeRouteServices) {
  return (
    services.forwardTransitions ??
    createForwardTransitions({
      audit: services.audit,
      probeOperations: services.probeOperations!,
    })
  );
}
