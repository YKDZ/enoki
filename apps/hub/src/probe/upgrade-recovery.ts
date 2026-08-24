import { createHash } from "node:crypto";

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
    | "hostId"
    | "id"
    | "kind"
    | "repairAuthorityExpiresAtMs"
    | "repairEvidenceSha256"
    | "repairEligibilityEvidenceJson"
    | "repairEligibilityEvidenceSha256"
    | "repairFailedOperationId"
    | "repairNonce"
    | "state"
    | "targetAssetSetDigest"
    | "targetManifestSha256"
    | "targetProbeVersion"
    | "upgradeAuthoritySha256"
    | "verifiedStageSha256"
  >,
  failedUpgrade: ProbeUpgradeRequest | null = null,
): ProbeUpgradeRecoveryDisposition | null {
  const { failureCode } = operation;
  if (!failureCode || operation.state !== "failed") return null;

  if (failureCode === "lifecycle.upgrade_repair_required") {
    return trustedPostactivationUpgradeFailure(operation)
      ? "probe_repair"
      : "manual_reinstall_required";
  }

  if (failureCode === "lifecycle.repair_unresolved") {
    return trustedUnresolvedRepair(operation, failedUpgrade)
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
    | "failureCode"
    | "hostId"
    | "id"
    | "kind"
    | "repairEligibilityEvidenceJson"
    | "repairEligibilityEvidenceSha256"
    | "state"
    | "targetAssetSetDigest"
    | "targetManifestSha256"
    | "targetProbeVersion"
    | "upgradeAuthoritySha256"
    | "verifiedStageSha256"
  >,
) {
  const eligibility = parsedEligibility(operation);
  return (
    operation.kind === "probe_upgrade" &&
    operation.state === "failed" &&
    operation.failureCode === "lifecycle.upgrade_repair_required" &&
    eligibility !== null &&
    eligibility.failedOperationId === String(operation.id) &&
    eligibility.hostId === String(operation.hostId) &&
    eligibility.targetBundleVersion === operation.targetProbeVersion &&
    eligibility.failedAuthoritySha256 === operation.upgradeAuthoritySha256 &&
    eligibility.targetAssetSetDigest === operation.targetAssetSetDigest &&
    eligibility.targetManifestSha256 === operation.targetManifestSha256 &&
    eligibility.verifiedStageSha256 === operation.verifiedStageSha256
  );
}

function trustedUnresolvedRepair(
  operation: Pick<
    ProbeUpgradeRequest,
    | "hostId"
    | "id"
    | "kind"
    | "repairAuthorityExpiresAtMs"
    | "repairEvidenceSha256"
    | "repairFailedOperationId"
    | "repairNonce"
    | "targetAssetSetDigest"
    | "targetManifestSha256"
    | "targetProbeVersion"
    | "upgradeAuthoritySha256"
    | "verifiedStageSha256"
  >,
  failedUpgrade: ProbeUpgradeRequest | null,
) {
  return (
    operation.kind === "probe_repair" &&
    Number.isSafeInteger(operation.repairFailedOperationId) &&
    (operation.repairFailedOperationId ?? 0) > 0 &&
    operation.repairFailedOperationId !== operation.id &&
    Number.isSafeInteger(operation.repairAuthorityExpiresAtMs) &&
    (operation.repairAuthorityExpiresAtMs ?? 0) > 0 &&
    isSha256(operation.repairEvidenceSha256) &&
    typeof operation.repairNonce === "string" &&
    /^[0-9a-f]{32}$/.test(operation.repairNonce) &&
    isAssetSetDigest(operation.targetAssetSetDigest) &&
    isSha256(operation.targetManifestSha256) &&
    isSha256(operation.upgradeAuthoritySha256) &&
    isSha256(operation.verifiedStageSha256) &&
    failedUpgrade !== null &&
    trustedPostactivationUpgradeFailure(failedUpgrade) &&
    failedUpgrade.id === operation.repairFailedOperationId &&
    failedUpgrade.hostId === operation.hostId &&
    failedUpgrade.targetProbeVersion === operation.targetProbeVersion &&
    failedUpgrade.targetAssetSetDigest === operation.targetAssetSetDigest &&
    failedUpgrade.targetManifestSha256 === operation.targetManifestSha256 &&
    failedUpgrade.verifiedStageSha256 === operation.verifiedStageSha256 &&
    failedUpgrade.upgradeAuthoritySha256 === operation.upgradeAuthoritySha256
  );
}

function parsedEligibility(
  operation: Pick<
    ProbeUpgradeRequest,
    "repairEligibilityEvidenceJson" | "repairEligibilityEvidenceSha256"
  >,
) {
  const json = operation.repairEligibilityEvidenceJson;
  if (
    typeof json !== "string" ||
    !isSha256(operation.repairEligibilityEvidenceSha256) ||
    createHash("sha256").update(json).digest("hex") !==
      operation.repairEligibilityEvidenceSha256
  ) {
    return null;
  }
  try {
    const value = JSON.parse(json) as Record<string, unknown>;
    return value.schemaVersion === 1 &&
      typeof value.hubOrigin === "string" &&
      typeof value.hostId === "string" &&
      typeof value.probeId === "string" &&
      typeof value.failedOperationId === "string" &&
      isSha256Value(value.failedAuthoritySha256) &&
      isSha256Value(value.journalSha256) &&
      [
        "activation-started",
        "repair-required",
        "finalizing",
        "stage-cleanup-required",
      ].includes(String(value.journalPhase)) &&
      Number.isSafeInteger(value.activatedTargets) &&
      Number.isSafeInteger(value.finalizedTargets) &&
      typeof value.targetBundleVersion === "string" &&
      isAssetSetDigest(value.targetAssetSetDigest) &&
      isSha256Value(value.targetManifestSha256) &&
      isSha256Value(value.verifiedStageSha256)
      ? value
      : null;
  } catch {
    return null;
  }
}

function isSha256(value: string | null | undefined) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isSha256Value(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isAssetSetDigest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
}
