import type { ProbeUpgradeEligibility } from "./asset-set.js";
import type { ProbeUpgradeRequest } from "./operation.js";
import { probeUpgradeRecoveryDisposition } from "./upgrade-recovery.js";

export type ManualProbeReinstallPolicy = NonNullable<
  ProbeUpgradeEligibility["manualReinstall"]
> & {
  reason: "closed_recovery" | "signed_transition";
};

export function manualProbeReinstallPolicy(input: {
  eligibility: ProbeUpgradeEligibility;
  hostLastReportAtMs: number | null;
  hostProbeVersion: string | null;
  latestOperation: ProbeUpgradeRequest | null;
  nowMs: number;
  offlineAfterMs: number;
  sourceProbeSha256: string[];
  targetAssetSetDigest: string | null;
  targetProbeVersion: string | null;
}): ManualProbeReinstallPolicy | null {
  if (input.eligibility.manualReinstall) {
    return {
      ...input.eligibility.manualReinstall,
      reason: "signed_transition",
    };
  }

  const operation = input.latestOperation;
  const hostIsOffline =
    input.hostLastReportAtMs !== null &&
    input.nowMs - input.hostLastReportAtMs >= input.offlineAfterMs;
  if (
    !hostIsOffline ||
    !operation ||
    operation.kind !== "probe_upgrade" ||
    operation.state !== "failed" ||
    !operation.failureCode ||
    probeUpgradeRecoveryDisposition(operation.failureCode) !==
      "manual_reinstall_required" ||
    !input.hostProbeVersion ||
    input.sourceProbeSha256.length === 0 ||
    operation.currentProbeVersion !== input.hostProbeVersion ||
    !input.targetProbeVersion ||
    operation.targetProbeVersion !== input.targetProbeVersion ||
    !input.targetAssetSetDigest ||
    operation.targetAssetSetDigest !== input.targetAssetSetDigest
  ) {
    return null;
  }

  return {
    reason: "closed_recovery",
    sourceProbeVersion: input.hostProbeVersion,
    sourceProbeSha256: input.sourceProbeSha256,
    targetAssetSetDigest: input.targetAssetSetDigest,
    targetProbeVersion: input.targetProbeVersion,
  };
}
