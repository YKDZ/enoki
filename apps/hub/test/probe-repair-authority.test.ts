import { describe, expect, it } from "vitest";

import type { ProbeUpgradeRequest } from "../src/probe/operation.js";
import {
  authorizeInstalledBundleRepair,
  canonicalInstalledBundleFailureEvidence,
  authorizeProbeRepair,
  canonicalProbeRepairEvidence,
  signInstalledBundleFailureEvidence,
  signProbeRepairEvidence,
} from "../src/probe/repair-authority.js";

describe("Probe Repair authority", () => {
  it("keeps installed-bundle failure eligibility disjoint from failed Upgrade", () => {
    const installKey = Buffer.alloc(32, 0x11);
    const evidence = {
      kind: "installed_bundle_failure" as const,
      schemaVersion: 1 as const,
      hubOrigin: "https://hub.example",
      probeId: "probe_01",
      generation: "a".repeat(64),
      bootId: "4f7d3e15-63cc-4d61-8fe4-f5d42773dd51",
      unit: "enoki-observation-runtime.service" as const,
      unitSha256: "b".repeat(64),
      identityReceiptSha256: "c".repeat(64),
      installStateSha256: "d".repeat(64),
      manifestSha256: "e".repeat(64),
      bundleVersion: "1.2.3",
      issuedAtMs: 1_725_000_001_000,
      expiresAtMs: 1_725_000_061_000,
      requestNonce: "request_nonce_01",
    };
    const evidenceSignature = signInstalledBundleFailureEvidence(
      canonicalInstalledBundleFailureEvidence(evidence),
      installKey,
    );
    const decision = authorizeInstalledBundleRepair({
      authorityExpiresAtMs: 1_725_000_061_000,
      evidence,
      evidenceSignature,
      expectedBundleVersion: "1.2.3",
      expectedHubOrigin: "https://hub.example",
      expectedProbeId: "probe_01",
      hostId: 7,
      installKey,
      nowMs: 1_725_000_001_000,
      repairNonce: "repair_nonce_01",
      repairOperationId: "42",
      targetAssetSetDigest: `sha256:${"f".repeat(64)}`,
    });

    expect(decision).toEqual({
      disposition: "probe_repair",
      authority: expect.objectContaining({
        kind: "installed_bundle_failure",
        generation: "a".repeat(64),
        hostId: "7",
        probeId: "probe_01",
        repairOperationId: "42",
        targetAssetSetDigest: `sha256:${"f".repeat(64)}`,
      }),
      signature: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(decision.authority).not.toHaveProperty("failedOperationId");
    expect(
      authorizeInstalledBundleRepair({
        authorityExpiresAtMs: 1_725_000_061_000,
        evidence: { ...evidence, generation: "f".repeat(64) },
        evidenceSignature,
        expectedBundleVersion: "1.2.3",
        expectedHubOrigin: "https://hub.example",
        expectedProbeId: "probe_01",
        hostId: 7,
        installKey,
        nowMs: 1_725_000_001_000,
        repairNonce: "repair_nonce_02",
        repairOperationId: "43",
        targetAssetSetDigest: `sha256:${"f".repeat(64)}`,
      }).disposition,
    ).toBe("manual_reinstall_required");
  });

  it("issues a domain-separated authority only for signed postactivation evidence bound to the failed Upgrade", () => {
    const installKey = Buffer.alloc(32, 0x11);
    const failedUpgrade: ProbeUpgradeRequest = {
      acceptedAtMs: 1_725_000_000_100,
      canceledAtMs: null,
      completedAtMs: 1_725_000_001_000,
      createdAtMs: 1_725_000_000_000,
      currentProbeVersion: "1.2.3",
      failureCode: "lifecycle.upgrade_repair_required",
      failureMessage: "private diagnostic",
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      runningAtMs: 1_725_000_000_200,
      state: "failed",
      supersededAtMs: null,
      targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
      targetProbeVersion: "1.2.4",
      updatedAtMs: 1_725_000_001_000,
      upgradeAuthoritySha256: "b".repeat(64),
      verifiedStageSha256: "e".repeat(64),
    };
    const evidence = {
      schemaVersion: 1 as const,
      hubOrigin: "https://hub.example",
      hostId: "7",
      probeId: "probe_01",
      failedOperationId: "41",
      failedAuthoritySha256: "b".repeat(64),
      journalSha256: "c".repeat(64),
      journalPhase: "repair-required" as const,
      activatedTargets: 3,
      finalizedTargets: 0,
      targetBundleVersion: "1.2.4",
      targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
      targetManifestSha256: "d".repeat(64),
      verifiedStageSha256: "e".repeat(64),
      issuedAtMs: 1_725_000_001_000,
      expiresAtMs: 1_725_000_061_000,
      requestNonce: "request_nonce_01",
    };
    const evidenceSignature = signProbeRepairEvidence(
      canonicalProbeRepairEvidence(evidence),
      installKey,
    );
    expect(evidenceSignature).toBe(
      "2010c4ef8f227628ce5c3ba568e3ddbe33d9e582bed425d46f7095d2d0147d82",
    );

    const decision = authorizeProbeRepair({
      authorityExpiresAtMs: 1_725_000_061_000,
      evidence,
      evidenceSignature,
      expectedHubOrigin: "https://hub.example",
      expectedProbeId: "probe_01",
      failedUpgrade,
      installKey,
      nowMs: 1_725_000_001_000,
      repairNonce: "repair_nonce_01",
      repairOperationId: "42",
      targetManifestSha256: "d".repeat(64),
    });

    expect(decision).toEqual({
      disposition: "probe_repair",
      authority: {
        schemaVersion: 1,
        hubOrigin: "https://hub.example",
        hostId: "7",
        probeId: "probe_01",
        failedOperationId: "41",
        repairOperationId: "42",
        repairNonce: "repair_nonce_01",
        repairEvidenceSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        targetBundleVersion: "1.2.4",
        targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
        targetManifestSha256: "d".repeat(64),
        verifiedStageSha256: "e".repeat(64),
        expiresAtMs: 1_725_000_061_000,
      },
      signature: expect.stringMatching(/^[0-9a-f]{64}$/),
    });

    const partialFinalization = {
      ...evidence,
      activatedTargets: 20,
      finalizedTargets: 7,
      requestNonce: "request_nonce_partial",
    };
    expect(
      authorizeProbeRepair({
        authorityExpiresAtMs: 1_725_000_061_000,
        evidence: partialFinalization,
        evidenceSignature: signProbeRepairEvidence(
          canonicalProbeRepairEvidence(partialFinalization),
          installKey,
        ),
        expectedHubOrigin: "https://hub.example",
        expectedProbeId: "probe_01",
        failedUpgrade,
        installKey,
        nowMs: 1_725_000_001_000,
        repairNonce: "repair_nonce_partial",
        repairOperationId: "44",
        targetManifestSha256: "d".repeat(64),
      }).disposition,
    ).toBe("probe_repair");

    expect(
      authorizeProbeRepair({
        authorityExpiresAtMs: 1_725_000_061_000,
        evidence: { ...evidence, journalPhase: "prepared" as never },
        evidenceSignature,
        expectedHubOrigin: "https://hub.example",
        expectedProbeId: "probe_01",
        failedUpgrade,
        installKey,
        nowMs: 1_725_000_001_000,
        repairNonce: "repair_nonce_02",
        repairOperationId: "43",
        targetManifestSha256: "d".repeat(64),
      }),
    ).toEqual({ disposition: "manual_reinstall_required" });
  });
});
