import type { ProbeUpgradeRecoveryDisposition } from "@enoki/api-client";

import type { ProbeUpgradeRequest } from "./operation.js";

const manualReinstallFailureCodes = new Set([
  "insufficient_privilege",
  "manual_probe_reinstall_required",
  "post_replacement_restart_failure",
  "post_replacement_status_write_failure",
  "running_timeout",
  "probe_manual_reinstall_required",
  "unsupported_installation",
]);

const retryProbeUpgradeFailureCodes = new Set([
  "accepted_timeout",
  "architecture_missing",
  "asset_missing",
  "checksum_failure",
  "downgrade_rejected",
  "lifecycle.upgrade_acquisition_failed",
  "lifecycle.upgrade_candidate_invalid",
  "lifecycle.upgrade_failed_before_activation",
  "signature_failure",
  "signing_key_untrusted",
  "target_mismatch",
  "unsafe_archive",
  "unsupported_architecture",
]);

export function probeUpgradeRecoveryDisposition(
  operation: Pick<
    ProbeUpgradeRequest,
    | "failureCode"
    | "kind"
    | "repairAuthorityExpiresAtMs"
    | "repairEvidenceSha256"
    | "repairFailedOperationId"
    | "repairNonce"
    | "state"
    | "targetManifestSha256"
    | "upgradeAuthoritySha256"
    | "verifiedStageSha256"
  >,
): ProbeUpgradeRecoveryDisposition | null {
  const { failureCode } = operation;
  if (!failureCode || operation.state !== "failed") return null;

  if (failureCode === "lifecycle.upgrade_repair_required") {
    return trustedPostactivationUpgradeFailure(operation)
      ? "probe_repair"
      : "manual_reinstall_required";
  }

  if (failureCode === "lifecycle.repair_unresolved") {
    return trustedUnresolvedRepair(operation)
      ? "probe_repair"
      : "manual_reinstall_required";
  }

  if (manualReinstallFailureCodes.has(failureCode)) {
    return "manual_reinstall_required";
  }

  if (
    operation.kind === "probe_upgrade" &&
    retryProbeUpgradeFailureCodes.has(failureCode)
  ) {
    return "retry_probe_upgrade";
  }

  return null;
}

function trustedPostactivationUpgradeFailure(
  operation: Pick<
    ProbeUpgradeRequest,
    | "kind"
    | "targetManifestSha256"
    | "upgradeAuthoritySha256"
    | "verifiedStageSha256"
  >,
) {
  return (
    operation.kind === "probe_upgrade" &&
    isSha256(operation.targetManifestSha256) &&
    isSha256(operation.upgradeAuthoritySha256) &&
    isSha256(operation.verifiedStageSha256)
  );
}

function trustedUnresolvedRepair(
  operation: Pick<
    ProbeUpgradeRequest,
    | "kind"
    | "repairAuthorityExpiresAtMs"
    | "repairEvidenceSha256"
    | "repairFailedOperationId"
    | "repairNonce"
    | "targetManifestSha256"
    | "verifiedStageSha256"
  >,
) {
  return (
    operation.kind === "probe_repair" &&
    Number.isSafeInteger(operation.repairFailedOperationId) &&
    (operation.repairFailedOperationId ?? 0) > 0 &&
    Number.isSafeInteger(operation.repairAuthorityExpiresAtMs) &&
    (operation.repairAuthorityExpiresAtMs ?? 0) > 0 &&
    isSha256(operation.repairEvidenceSha256) &&
    typeof operation.repairNonce === "string" &&
    /^[0-9a-f]{32}$/.test(operation.repairNonce) &&
    isSha256(operation.targetManifestSha256) &&
    isSha256(operation.verifiedStageSha256)
  );
}

function isSha256(value: string | null | undefined) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

export function currentProbeUpgradeProblem(input: {
  operation: ProbeUpgradeRequest | null;
  reportedProbeVersion?: string | null;
  reportedProbeVersionObservedAtMs: number | null | undefined;
}) {
  const { operation } = input;
  if (
    !operation ||
    !["probe_upgrade", "probe_repair"].includes(operation.kind) ||
    ["succeeded", "canceled", "superseded"].includes(operation.state) ||
    (operation.state === "failed" &&
      recoveryEvidenceIsFresh(input, operation) &&
      normalizeProbeVersion(input.reportedProbeVersion) ===
        normalizeProbeVersion(operation.targetProbeVersion))
  ) {
    return null;
  }

  return operation;
}

function recoveryEvidenceIsFresh(
  input: { reportedProbeVersionObservedAtMs: number | null | undefined },
  operation: ProbeUpgradeRequest,
) {
  return (
    operation.completedAtMs !== null &&
    input.reportedProbeVersionObservedAtMs !== null &&
    input.reportedProbeVersionObservedAtMs !== undefined &&
    input.reportedProbeVersionObservedAtMs > operation.completedAtMs
  );
}

function normalizeProbeVersion(value: string | null | undefined) {
  return typeof value === "string" ? value.trim().replace(/^v/, "") : "";
}
