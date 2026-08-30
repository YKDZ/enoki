export type ProbeOperationState =
  | "pending"
  | "accepted"
  | "running"
  | "succeeded"
  | "failed"
  | "superseded"
  | "canceled";

export type ProbeOperationKind =
  | "probe_upgrade"
  | "probe_repair"
  | "probe_uninstall";

export type ProbeUpgradeRequest = {
  acceptedAtMs: number | null;
  canceledAtMs: number | null;
  completedAtMs: number | null;
  createdAtMs: number;
  currentProbeVersion: string | null;
  failureCode: string | null;
  failureMessage: string | null;
  hostId: number;
  id: number | null;
  kind: ProbeOperationKind;
  repairAuthorityExpiresAtMs?: number | null;
  repairEligibilityEvidenceJson?: string | null;
  repairEligibilityEvidenceSha256?: string | null;
  repairEvidenceSha256?: string | null;
  repairEligibilityKind?: "failed_upgrade" | "installed_bundle_failure" | null;
  repairFailureGeneration?: string | null;
  repairFailedOperationId?: number | null;
  repairNonce?: string | null;
  runningAtMs: number | null;
  state: ProbeOperationState;
  supersededAtMs: number | null;
  targetAssetSetDigest?: string | null;
  targetManifestSha256?: string | null;
  targetProbeVersion: string;
  updatedAtMs: number;
  upgradeAuthoritySha256?: string | null;
  verifiedStageSha256?: string | null;
};

export type ProbeUpgradeTarget = {
  assetSetDigest: string;
  version: string;
};

export type ProbeUpgradeRequestLifecycleEvent = {
  action: "created" | "superseded";
  operation: ProbeUpgradeRequest;
};

export type CreateProbeUpgradeRequestResult =
  | {
      error: null;
      events: ProbeUpgradeRequestLifecycleEvent[];
      operation: ProbeUpgradeRequest;
    }
  | {
      error: "probe_upgrade_request_active";
      events: [];
      operation: null;
    };

export type CreateProbeUninstallRequestResult =
  | {
      error: null;
      events: ProbeUpgradeRequestLifecycleEvent[];
      operation: ProbeUpgradeRequest;
    }
  | {
      error: "probe_operation_active";
      events: [];
      operation: null;
    };

export function createProbeRepairRequest(input: {
  authorityExpiresAtMs: number;
  evidenceSha256: string;
  failedOperation: ProbeUpgradeRequest;
  nonce: string;
  nowMs: number;
  targetManifestSha256: string;
  verifiedStageSha256: string;
}): ProbeUpgradeRequest | null {
  if (
    input.failedOperation.kind !== "probe_upgrade" ||
    input.failedOperation.state !== "failed" ||
    input.failedOperation.id === null ||
    !input.failedOperation.targetAssetSetDigest
  ) {
    return null;
  }
  return {
    acceptedAtMs: input.nowMs,
    canceledAtMs: null,
    completedAtMs: null,
    createdAtMs: input.nowMs,
    currentProbeVersion: input.failedOperation.targetProbeVersion,
    failureCode: null,
    failureMessage: null,
    hostId: input.failedOperation.hostId,
    id: null,
    kind: "probe_repair",
    repairAuthorityExpiresAtMs: input.authorityExpiresAtMs,
    repairEvidenceSha256: input.evidenceSha256,
    repairEligibilityKind: "failed_upgrade",
    repairFailureGeneration: null,
    repairFailedOperationId: input.failedOperation.id,
    repairNonce: input.nonce,
    runningAtMs: null,
    state: "accepted",
    supersededAtMs: null,
    targetAssetSetDigest: input.failedOperation.targetAssetSetDigest,
    targetManifestSha256: input.targetManifestSha256,
    targetProbeVersion: input.failedOperation.targetProbeVersion,
    updatedAtMs: input.nowMs,
    upgradeAuthoritySha256: input.failedOperation.upgradeAuthoritySha256,
    verifiedStageSha256: input.verifiedStageSha256,
  };
}

export function createInstalledBundleRepairRequest(input: {
  authorityExpiresAtMs: number;
  bundleVersion: string;
  evidenceSha256: string;
  failureGeneration: string;
  hostId: number;
  manifestSha256: string;
  targetAssetSetDigest: string;
  nonce: string;
  nowMs: number;
}): ProbeUpgradeRequest | null {
  if (
    !/^[0-9a-f]{64}$/.test(input.failureGeneration) ||
    !/^[0-9a-f]{64}$/.test(input.evidenceSha256) ||
    !/^[0-9a-f]{64}$/.test(input.manifestSha256) ||
    !/^sha256:[0-9a-f]{64}$/.test(input.targetAssetSetDigest) ||
    !input.bundleVersion
  ) {
    return null;
  }
  return {
    acceptedAtMs: input.nowMs,
    canceledAtMs: null,
    completedAtMs: null,
    createdAtMs: input.nowMs,
    currentProbeVersion: input.bundleVersion,
    failureCode: null,
    failureMessage: null,
    hostId: input.hostId,
    id: null,
    kind: "probe_repair",
    repairAuthorityExpiresAtMs: input.authorityExpiresAtMs,
    repairEligibilityKind: "installed_bundle_failure",
    repairEvidenceSha256: input.evidenceSha256,
    repairFailedOperationId: null,
    repairFailureGeneration: input.failureGeneration,
    repairNonce: input.nonce,
    runningAtMs: null,
    state: "accepted",
    supersededAtMs: null,
    targetAssetSetDigest: input.targetAssetSetDigest,
    targetManifestSha256: input.manifestSha256,
    targetProbeVersion: input.bundleVersion,
    updatedAtMs: input.nowMs,
  };
}

export function createProbeUpgradeRequest(input: {
  activeOperation: null;
  currentProbeVersion: string | null;
  hostId: number;
  nowMs: number;
  target: ProbeUpgradeTarget;
}): Extract<CreateProbeUpgradeRequestResult, { error: null }>;
export function createProbeUpgradeRequest(input: {
  activeOperation: ProbeUpgradeRequest | null;
  currentProbeVersion: string | null;
  hostId: number;
  nowMs: number;
  target: ProbeUpgradeTarget;
}): CreateProbeUpgradeRequestResult;
export function createProbeUpgradeRequest(input: {
  activeOperation: ProbeUpgradeRequest | null;
  currentProbeVersion: string | null;
  hostId: number;
  nowMs: number;
  target: ProbeUpgradeTarget;
}): CreateProbeUpgradeRequestResult {
  if (
    input.activeOperation?.targetProbeVersion === input.target.version &&
    input.activeOperation.targetAssetSetDigest ===
      input.target.assetSetDigest &&
    isActiveProbeOperation(input.activeOperation)
  ) {
    return {
      error: null,
      events: [],
      operation: input.activeOperation,
    };
  }

  const operation = newPendingProbeUpgradeRequest(input);

  if (
    input.activeOperation &&
    isSafeToSupersedeProbeOperation(input.activeOperation)
  ) {
    const superseded = {
      ...input.activeOperation,
      state: "superseded" as const,
      supersededAtMs: input.nowMs,
      updatedAtMs: input.nowMs,
    };

    return {
      error: null,
      events: [
        {
          action: "superseded",
          operation: superseded,
        },
        {
          action: "created",
          operation,
        },
      ],
      operation,
    };
  }

  if (input.activeOperation && isActiveProbeOperation(input.activeOperation)) {
    return {
      error: "probe_upgrade_request_active",
      events: [],
      operation: null,
    };
  }

  return {
    error: null,
    events: [
      {
        action: "created",
        operation,
      },
    ],
    operation,
  };
}

export function createProbeUninstallRequest(input: {
  activeOperation: null;
  hostId: number;
  nowMs: number;
}): Extract<CreateProbeUninstallRequestResult, { error: null }>;
export function createProbeUninstallRequest(input: {
  activeOperation: ProbeUpgradeRequest | null;
  hostId: number;
  nowMs: number;
}): CreateProbeUninstallRequestResult;
export function createProbeUninstallRequest(input: {
  activeOperation: ProbeUpgradeRequest | null;
  hostId: number;
  nowMs: number;
}): CreateProbeUninstallRequestResult {
  if (input.activeOperation?.kind === "probe_uninstall") {
    return {
      error: null,
      events: [],
      operation: input.activeOperation,
    };
  }

  const operation = newPendingProbeUninstallRequest(input);

  if (
    input.activeOperation &&
    isSafeToSupersedeProbeOperation(input.activeOperation)
  ) {
    const superseded = {
      ...input.activeOperation,
      state: "superseded" as const,
      supersededAtMs: input.nowMs,
      updatedAtMs: input.nowMs,
    };

    return {
      error: null,
      events: [
        {
          action: "superseded",
          operation: superseded,
        },
        {
          action: "created",
          operation,
        },
      ],
      operation,
    };
  }

  if (input.activeOperation && isActiveProbeOperation(input.activeOperation)) {
    return {
      error: "probe_operation_active",
      events: [],
      operation: null,
    };
  }

  return {
    error: null,
    events: [
      {
        action: "created",
        operation,
      },
    ],
    operation,
  };
}

export function cancelProbeUpgradeRequest(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): {
  canceled: ProbeUpgradeRequest | null;
  error: "probe_upgrade_request_not_cancelable" | null;
} {
  if (input.operation.state !== "pending") {
    return {
      canceled: null,
      error: "probe_upgrade_request_not_cancelable",
    };
  }

  return {
    canceled: {
      ...input.operation,
      canceledAtMs: input.nowMs,
      state: "canceled",
      updatedAtMs: input.nowMs,
    },
    error: null,
  };
}

export function acknowledgeProbeUpgradeRequest(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): {
  acknowledged: ProbeUpgradeRequest;
  error: "probe_operation_not_acknowledgeable" | null;
} {
  if (hasUnavailableProbeUpgradeTarget(input.operation)) {
    return {
      acknowledged: input.operation,
      error: "probe_operation_not_acknowledgeable",
    };
  }

  if (input.operation.state === "pending") {
    return {
      acknowledged: {
        ...input.operation,
        acceptedAtMs: input.operation.acceptedAtMs ?? input.nowMs,
        state: "accepted",
        updatedAtMs: input.nowMs,
      },
      error: null,
    };
  }

  if (
    input.operation.state === "accepted" ||
    input.operation.state === "running"
  ) {
    return {
      acknowledged: input.operation,
      error: null,
    };
  }

  return {
    acknowledged: input.operation,
    error: "probe_operation_not_acknowledgeable",
  };
}

export function startProbeUpgradeRequest(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): {
  error: "probe_operation_status_invalid" | null;
  operation: ProbeUpgradeRequest;
} {
  if (hasUnavailableProbeUpgradeTarget(input.operation)) {
    return {
      error: "probe_operation_status_invalid",
      operation: input.operation,
    };
  }

  if (input.operation.state === "accepted") {
    return {
      error: null,
      operation: {
        ...input.operation,
        runningAtMs: input.operation.runningAtMs ?? input.nowMs,
        state: "running",
        updatedAtMs: input.nowMs,
      },
    };
  }

  if (input.operation.state === "running") {
    return {
      error: null,
      operation: input.operation,
    };
  }

  if (input.operation.state === "succeeded") {
    // root-owned 激活交接在目标 Boot/Profile 证据关闭 Hub operation 前保持
    // `running`。后续 Probe 重启可以重放这份不可变交接，但不得回退或拒绝
    // 已成为权威事实的成功终态。
    return {
      error: null,
      operation: input.operation,
    };
  }

  return {
    error: "probe_operation_status_invalid",
    operation: input.operation,
  };
}

export function failReportedProbeUpgradeRequest(input: {
  code: string;
  message: string;
  nowMs: number;
  operation: ProbeUpgradeRequest;
  repairEligibility?: {
    evidenceJson: string;
    evidenceSha256: string;
  } | null;
}): {
  error: "probe_operation_status_invalid" | null;
  operation: ProbeUpgradeRequest;
} {
  if (hasUnavailableProbeUpgradeTarget(input.operation)) {
    return {
      error: "probe_operation_status_invalid",
      operation: input.operation,
    };
  }

  if (
    input.operation.state === "accepted" ||
    input.operation.state === "running"
  ) {
    const failed = failProbeUpgradeRequest({
      code: input.code,
      message: input.message,
      nowMs: input.nowMs,
      operation: input.operation,
    });
    return {
      error: null,
      operation: withRepairEligibility(failed, input.repairEligibility),
    };
  }

  if (input.operation.state === "failed") {
    return {
      error: null,
      operation: withRepairEligibility(
        input.operation,
        input.repairEligibility,
      ),
    };
  }

  return {
    error: "probe_operation_status_invalid",
    operation: input.operation,
  };
}

function withRepairEligibility(
  operation: ProbeUpgradeRequest,
  repairEligibility:
    | { evidenceJson: string; evidenceSha256: string }
    | null
    | undefined,
) {
  return repairEligibility
    ? {
        ...operation,
        repairEligibilityEvidenceJson: repairEligibility.evidenceJson,
        repairEligibilityEvidenceSha256: repairEligibility.evidenceSha256,
      }
    : operation;
}

export function succeedReportedProbeOperation(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): {
  error: "probe_operation_status_invalid" | null;
  operation: ProbeUpgradeRequest;
} {
  if (
    input.operation.kind === "probe_uninstall" &&
    (input.operation.state === "accepted" ||
      input.operation.state === "running")
  ) {
    return {
      error: null,
      operation: {
        ...input.operation,
        completedAtMs: input.nowMs,
        failureCode: null,
        failureMessage: null,
        state: "succeeded",
        updatedAtMs: input.nowMs,
      },
    };
  }

  if (input.operation.state === "succeeded") {
    return {
      error: null,
      operation: input.operation,
    };
  }

  return {
    error: "probe_operation_status_invalid",
    operation: input.operation,
  };
}

export function succeedProbeUpgradeRequestFromHostProfile(input: {
  authenticatedProbeId: string;
  bootEvidenceBootId: string | null | undefined;
  bootEvidenceProbeId: string | null | undefined;
  bootProbeAssetBundleVersion: string | null | undefined;
  hostProfile:
    | {
        probeAssetBundleVersion?: string | null;
        probeVersion?: string | null;
      }
    | null
    | undefined;
  nowMs: number;
  operation: ProbeUpgradeRequest;
  profileReportBootId: string;
}): ProbeUpgradeRequest | null {
  if (
    !["probe_upgrade", "probe_repair"].includes(input.operation.kind) ||
    (input.operation.kind === "probe_repair" &&
      input.operation.state !== "running") ||
    hasUnavailableProbeUpgradeTarget(input.operation) ||
    !isActiveProbeOperation(input.operation) ||
    !input.profileReportBootId ||
    input.bootEvidenceBootId !== input.profileReportBootId ||
    input.bootEvidenceProbeId !== input.authenticatedProbeId ||
    normalizeProbeVersion(input.bootProbeAssetBundleVersion) !==
      normalizeProbeVersion(input.operation.targetProbeVersion) ||
    normalizeProbeVersion(input.hostProfile?.probeAssetBundleVersion) !==
      normalizeProbeVersion(input.operation.targetProbeVersion) ||
    normalizeProbeVersion(input.hostProfile?.probeVersion) !==
      normalizeProbeVersion(input.operation.targetProbeVersion)
  ) {
    return null;
  }

  return {
    ...input.operation,
    completedAtMs: input.nowMs,
    failureCode: null,
    failureMessage: null,
    state: "succeeded",
    updatedAtMs: input.nowMs,
  };
}

export function acceptedTimedOutProbeUpgradeRequest(input: {
  acceptedTimeoutMs: number;
  nowMs: number;
  operation: ProbeUpgradeRequest;
}) {
  if (
    input.operation.state !== "accepted" ||
    input.operation.acceptedAtMs === null ||
    input.nowMs - input.operation.acceptedAtMs < input.acceptedTimeoutMs
  ) {
    return null;
  }

  return failProbeUpgradeRequest({
    code: "accepted_timeout",
    message: "Probe accepted the upgrade request but did not start it in time.",
    nowMs: input.nowMs,
    operation: input.operation,
  });
}

export function runningTimedOutProbeUpgradeRequest(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
  runningTimeoutMs: number;
}) {
  if (
    input.operation.state !== "running" ||
    input.operation.runningAtMs === null ||
    input.nowMs - input.operation.runningAtMs < input.runningTimeoutMs
  ) {
    return null;
  }

  return failProbeUpgradeRequest({
    code: "running_timeout",
    message:
      input.operation.kind === "probe_uninstall"
        ? "Probe started the uninstall but did not report completion in time."
        : "Probe started the upgrade but did not report the target version in time.",
    nowMs: input.nowMs,
    operation: input.operation,
  });
}

export function isActiveProbeOperation(operation: ProbeUpgradeRequest) {
  return ["pending", "accepted", "running"].includes(operation.state);
}

export function isClosedProbeOperation(operation: ProbeUpgradeRequest) {
  return ["canceled", "failed", "succeeded", "superseded"].includes(
    operation.state,
  );
}

function isSafeToSupersedeProbeOperation(operation: ProbeUpgradeRequest) {
  return operation.state === "pending" || operation.state === "accepted";
}

export function hasUnavailableProbeUpgradeTarget(
  operation: ProbeUpgradeRequest,
) {
  return operation.kind === "probe_upgrade" && !operation.targetAssetSetDigest;
}

function normalizeProbeVersion(value: string | null | undefined) {
  return typeof value === "string" ? value.trim().replace(/^v/, "") : "";
}

function newPendingProbeUpgradeRequest(input: {
  currentProbeVersion: string | null;
  hostId: number;
  nowMs: number;
  target: ProbeUpgradeTarget;
}): ProbeUpgradeRequest {
  return {
    acceptedAtMs: null,
    canceledAtMs: null,
    completedAtMs: null,
    createdAtMs: input.nowMs,
    currentProbeVersion: input.currentProbeVersion,
    failureCode: null,
    failureMessage: null,
    hostId: input.hostId,
    id: null,
    kind: "probe_upgrade",
    runningAtMs: null,
    state: "pending",
    supersededAtMs: null,
    targetAssetSetDigest: input.target.assetSetDigest,
    targetProbeVersion: input.target.version,
    updatedAtMs: input.nowMs,
  };
}

function newPendingProbeUninstallRequest(input: {
  hostId: number;
  nowMs: number;
}): ProbeUpgradeRequest {
  return {
    acceptedAtMs: null,
    canceledAtMs: null,
    completedAtMs: null,
    createdAtMs: input.nowMs,
    currentProbeVersion: null,
    failureCode: null,
    failureMessage: null,
    hostId: input.hostId,
    id: null,
    kind: "probe_uninstall",
    runningAtMs: null,
    state: "pending",
    supersededAtMs: null,
    targetProbeVersion: "",
    updatedAtMs: input.nowMs,
  };
}

function failProbeUpgradeRequest(input: {
  code: string;
  message: string;
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): ProbeUpgradeRequest {
  return {
    ...input.operation,
    completedAtMs: input.nowMs,
    failureCode: input.code,
    failureMessage: input.message,
    state: "failed",
    updatedAtMs: input.nowMs,
  };
}
