import { describe, expect, it } from "vitest";

import type { ProbeUpgradeRequest } from "../src/probe/operation.js";
import {
  authorizeProbeRepair,
  canonicalProbeRepairEvidence,
  signProbeRepairEvidence,
} from "../src/probe/repair-authority.js";

describe("Probe Repair authority", () => {
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
