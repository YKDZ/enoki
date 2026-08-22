import type { ProbeUpgradeRecoveryDisposition } from "@enoki/api-client";

import type { ProbeUpgradeRequest } from "./operation.js";

const manualReinstallFailureCodes = new Set([
  "insufficient_privilege",
  "manual_probe_reinstall_required",
  "probe_manual_reinstall_required",
  "unsupported_installation",
]);

const probeRepairFailureCodes = new Set([
  "post_replacement_restart_failure",
  "post_replacement_status_write_failure",
  "running_timeout",
]);

const retryProbeUpgradeFailureCodes = new Set([
  "accepted_timeout",
  "architecture_missing",
  "asset_missing",
  "checksum_failure",
  "downgrade_rejected",
  "signature_failure",
  "signing_key_untrusted",
  "target_mismatch",
  "unsafe_archive",
  "unsupported_architecture",
]);

export function probeUpgradeRecoveryDisposition(
  failureCode: string,
): ProbeUpgradeRecoveryDisposition {
  if (manualReinstallFailureCodes.has(failureCode)) {
    return "manual_reinstall_required";
  }

  if (probeRepairFailureCodes.has(failureCode)) {
    return "probe_repair";
  }

  if (retryProbeUpgradeFailureCodes.has(failureCode)) {
    return "retry_probe_upgrade";
  }

  return "unclassified";
}

export function currentProbeUpgradeProblem(input: {
  operation: ProbeUpgradeRequest | null;
  reportedProbeVersion?: string | null;
}) {
  const { operation } = input;
  if (
    !operation ||
    operation.kind !== "probe_upgrade" ||
    ["succeeded", "canceled", "superseded"].includes(operation.state) ||
    (operation.state === "failed" &&
      normalizeProbeVersion(input.reportedProbeVersion) ===
        normalizeProbeVersion(operation.targetProbeVersion))
  ) {
    return null;
  }

  return operation;
}

function normalizeProbeVersion(value: string | null | undefined) {
  return typeof value === "string" ? value.trim().replace(/^v/, "") : "";
}
