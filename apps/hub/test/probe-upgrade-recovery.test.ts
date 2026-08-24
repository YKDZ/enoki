import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import type { ProbeUpgradeRequest } from "../src/probe/operation";
import { probeUpgradeRecoveryDisposition } from "../src/probe/upgrade-recovery";

const hashes = {
  asset: `sha256:${"1".repeat(64)}`,
  authority: "2".repeat(64),
  journal: "3".repeat(64),
  manifest: "4".repeat(64),
  stage: "5".repeat(64),
};

describe("Probe Upgrade recovery classification", () => {
  it("requires a persisted verified postactivation eligibility fact", () => {
    const upgrade = failedUpgrade();
    expect(probeUpgradeRecoveryDisposition(upgrade)).toBe(
      "manual_reinstall_required",
    );

    const trusted = withEligibility(upgrade);
    expect(probeUpgradeRecoveryDisposition(trusted)).toBe("probe_repair");
    expect(
      probeUpgradeRecoveryDisposition({
        ...trusted,
        repairEligibilityEvidenceSha256: "6".repeat(64),
      }),
    ).toBe("manual_reinstall_required");
  });

  it("requires an unresolved Repair to cross-bind a distinct failed Upgrade", () => {
    const upgrade = withEligibility(failedUpgrade());
    const repair: ProbeUpgradeRequest = {
      ...upgrade,
      id: 12,
      kind: "probe_repair",
      repairAuthorityExpiresAtMs: 1_725_000_120_000,
      repairEvidenceSha256: "6".repeat(64),
      repairFailedOperationId: 11,
      repairNonce: "7".repeat(32),
      failureCode: "lifecycle.repair_unresolved",
    };
    expect(probeUpgradeRecoveryDisposition(repair, upgrade)).toBe(
      "probe_repair",
    );
    expect(
      probeUpgradeRecoveryDisposition(
        { ...repair, repairFailedOperationId: repair.id },
        upgrade,
      ),
    ).toBe("manual_reinstall_required");
    expect(
      probeUpgradeRecoveryDisposition(repair, {
        ...upgrade,
        targetAssetSetDigest: `sha256:${"8".repeat(64)}`,
      }),
    ).toBe("manual_reinstall_required");
  });
});

function failedUpgrade(): ProbeUpgradeRequest {
  return {
    acceptedAtMs: 1_725_000_001_000,
    canceledAtMs: null,
    completedAtMs: 1_725_000_010_000,
    createdAtMs: 1_725_000_000_000,
    currentProbeVersion: "0.1.0",
    failureCode: "lifecycle.upgrade_repair_required",
    failureMessage: "private",
    hostId: 7,
    id: 11,
    kind: "probe_upgrade",
    runningAtMs: 1_725_000_002_000,
    state: "failed",
    supersededAtMs: null,
    targetAssetSetDigest: hashes.asset,
    targetManifestSha256: hashes.manifest,
    targetProbeVersion: "0.2.0",
    updatedAtMs: 1_725_000_010_000,
    upgradeAuthoritySha256: hashes.authority,
    verifiedStageSha256: hashes.stage,
  };
}

function withEligibility(operation: ProbeUpgradeRequest): ProbeUpgradeRequest {
  const json = JSON.stringify({
    schemaVersion: 1,
    hubOrigin: "https://probe.example.test",
    hostId: String(operation.hostId),
    probeId: "probe_01",
    failedOperationId: String(operation.id),
    failedAuthoritySha256: hashes.authority,
    journalSha256: hashes.journal,
    journalPhase: "repair-required",
    activatedTargets: 1,
    finalizedTargets: 0,
    targetBundleVersion: operation.targetProbeVersion,
    targetAssetSetDigest: hashes.asset,
    targetManifestSha256: hashes.manifest,
    verifiedStageSha256: hashes.stage,
  });
  return {
    ...operation,
    repairEligibilityEvidenceJson: json,
    repairEligibilityEvidenceSha256: createHash("sha256")
      .update(json)
      .digest("hex"),
  };
}
