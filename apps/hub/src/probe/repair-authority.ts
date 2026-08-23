import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import type { ProbeUpgradeRequest } from "./operation.js";

const repairEvidenceSigningDomain = Buffer.from(
  "enoki/lifecycle-repair-evidence/hmac-sha256/v1\0",
);
const repairAuthoritySigningDomain = Buffer.from(
  "enoki/lifecycle-repair-authority/hmac-sha256/v1\0",
);
const maxRepairAuthorityTtlMs = 2 * 60 * 1000;
const postactivationPhases = new Set<ProbeRepairEvidence["journalPhase"]>([
  "activation-started",
  "repair-required",
  "finalizing",
  "stage-cleanup-required",
]);

export type ProbeRepairEvidence = {
  schemaVersion: 1;
  hubOrigin: string;
  hostId: string;
  probeId: string;
  failedOperationId: string;
  failedAuthoritySha256: string;
  journalSha256: string;
  journalPhase:
    | "activation-started"
    | "repair-required"
    | "finalizing"
    | "stage-cleanup-required";
  activatedTargets: number;
  finalizedTargets: number;
  targetBundleVersion: string;
  targetAssetSetDigest: string;
  targetManifestSha256: string;
  verifiedStageSha256: string;
  issuedAtMs: number;
  expiresAtMs: number;
  requestNonce: string;
};

export type ProbeRepairAuthority = {
  schemaVersion: 1;
  hubOrigin: string;
  hostId: string;
  probeId: string;
  failedOperationId: string;
  repairOperationId: string;
  repairNonce: string;
  repairEvidenceSha256: string;
  targetBundleVersion: string;
  targetAssetSetDigest: string;
  targetManifestSha256: string;
  verifiedStageSha256: string;
  expiresAtMs: number;
};

export type ProbeRepairAuthorizationDecision =
  | {
      disposition: "probe_repair";
      authority: ProbeRepairAuthority;
      signature: string;
    }
  | { disposition: "manual_reinstall_required" };

export type VerifiedProbeRepairEvidence = {
  evidence: ProbeRepairEvidence;
  repairEvidenceSha256: string;
};

export function canonicalProbeRepairEvidence(evidence: ProbeRepairEvidence) {
  return Buffer.from(JSON.stringify(evidence), "utf8");
}

export function canonicalProbeRepairAuthority(authority: ProbeRepairAuthority) {
  return Buffer.from(JSON.stringify(authority), "utf8");
}

export function signProbeRepairEvidence(
  canonicalEvidence: Uint8Array,
  installKey: Uint8Array,
) {
  return signRepairFacts(
    repairEvidenceSigningDomain,
    canonicalEvidence,
    installKey,
  );
}

export function signProbeRepairAuthority(
  canonicalAuthority: Uint8Array,
  installKey: Uint8Array,
) {
  return signRepairFacts(
    repairAuthoritySigningDomain,
    canonicalAuthority,
    installKey,
  );
}

export function authorizeProbeRepair(input: {
  authorityExpiresAtMs: number;
  evidence: ProbeRepairEvidence;
  evidenceSignature: string;
  expectedHubOrigin: string;
  expectedProbeId: string;
  failedUpgrade: ProbeUpgradeRequest;
  installKey: Uint8Array;
  nowMs: number;
  repairNonce: string;
  repairOperationId: string;
  targetManifestSha256: string;
}): ProbeRepairAuthorizationDecision {
  const verified = verifyProbeRepairEvidence(input);
  if (
    !verified ||
    !validIdentifier(input.repairOperationId) ||
    !validIdentifier(input.repairNonce) ||
    input.authorityExpiresAtMs <= input.nowMs ||
    input.authorityExpiresAtMs - input.nowMs > maxRepairAuthorityTtlMs
  ) {
    return { disposition: "manual_reinstall_required" };
  }

  const authority: ProbeRepairAuthority = {
    schemaVersion: 1,
    hubOrigin: input.expectedHubOrigin,
    hostId: String(input.failedUpgrade.hostId),
    probeId: input.expectedProbeId,
    failedOperationId: String(input.failedUpgrade.id),
    repairOperationId: input.repairOperationId,
    repairNonce: input.repairNonce,
    repairEvidenceSha256: verified.repairEvidenceSha256,
    targetBundleVersion: input.evidence.targetBundleVersion,
    targetAssetSetDigest: input.evidence.targetAssetSetDigest,
    targetManifestSha256: input.evidence.targetManifestSha256,
    verifiedStageSha256: input.evidence.verifiedStageSha256,
    expiresAtMs: input.authorityExpiresAtMs,
  };
  return {
    disposition: "probe_repair",
    authority,
    signature: signProbeRepairAuthority(
      canonicalProbeRepairAuthority(authority),
      input.installKey,
    ),
  };
}

export function verifyProbeRepairEvidence(input: {
  evidence: ProbeRepairEvidence;
  evidenceSignature: string;
  expectedHubOrigin: string;
  expectedProbeId: string;
  failedUpgrade: ProbeUpgradeRequest;
  installKey: Uint8Array;
  nowMs: number;
  targetManifestSha256: string;
}): VerifiedProbeRepairEvidence | null {
  const evidenceBytes = canonicalProbeRepairEvidence(input.evidence);
  if (
    !verifyRepairFacts(
      repairEvidenceSigningDomain,
      evidenceBytes,
      input.evidenceSignature,
      input.installKey,
    ) ||
    !postactivationPhases.has(input.evidence.journalPhase) ||
    input.failedUpgrade.kind !== "probe_upgrade" ||
    input.failedUpgrade.state !== "failed" ||
    input.failedUpgrade.id === null ||
    input.failedUpgrade.completedAtMs === null ||
    input.evidence.hubOrigin !== input.expectedHubOrigin ||
    input.evidence.hostId !== String(input.failedUpgrade.hostId) ||
    input.evidence.probeId !== input.expectedProbeId ||
    input.evidence.failedOperationId !== String(input.failedUpgrade.id) ||
    input.evidence.failedAuthoritySha256 !==
      input.failedUpgrade.upgradeAuthoritySha256 ||
    input.evidence.targetBundleVersion !==
      input.failedUpgrade.targetProbeVersion ||
    input.evidence.targetAssetSetDigest !==
      input.failedUpgrade.targetAssetSetDigest ||
    input.evidence.targetManifestSha256 !== input.targetManifestSha256 ||
    input.evidence.verifiedStageSha256 !==
      input.failedUpgrade.verifiedStageSha256 ||
    input.evidence.issuedAtMs > input.nowMs ||
    input.evidence.expiresAtMs <= input.nowMs ||
    input.evidence.expiresAtMs - input.evidence.issuedAtMs >
      maxRepairAuthorityTtlMs ||
    !validRepairEvidence(input.evidence)
  ) {
    return null;
  }
  return {
    evidence: input.evidence,
    repairEvidenceSha256: createHash("sha256")
      .update(evidenceBytes)
      .digest("hex"),
  };
}

function signRepairFacts(
  domain: Uint8Array,
  facts: Uint8Array,
  installKey: Uint8Array,
) {
  if (installKey.byteLength !== 32) {
    throw new Error("Lifecycle authority key must be 32 bytes.");
  }
  return createHmac("sha256", installKey)
    .update(domain)
    .update(facts)
    .digest("hex");
}

function verifyRepairFacts(
  domain: Uint8Array,
  facts: Uint8Array,
  signatureHex: string,
  installKey: Uint8Array,
) {
  if (!isSha256(signatureHex) || installKey.byteLength !== 32) return false;
  const expected = Buffer.from(
    signRepairFacts(domain, facts, installKey),
    "hex",
  );
  return timingSafeEqual(expected, Buffer.from(signatureHex, "hex"));
}

function validRepairEvidence(evidence: ProbeRepairEvidence) {
  return (
    evidence.schemaVersion === 1 &&
    validIdentifier(evidence.hostId) &&
    validIdentifier(evidence.probeId) &&
    validIdentifier(evidence.failedOperationId) &&
    isSha256(evidence.failedAuthoritySha256) &&
    isSha256(evidence.journalSha256) &&
    Number.isSafeInteger(evidence.activatedTargets) &&
    evidence.activatedTargets >= 0 &&
    Number.isSafeInteger(evidence.finalizedTargets) &&
    evidence.finalizedTargets >= 0 &&
    validVersion(evidence.targetBundleVersion) &&
    evidence.targetAssetSetDigest.startsWith("sha256:") &&
    isSha256(evidence.targetAssetSetDigest.slice("sha256:".length)) &&
    isSha256(evidence.targetManifestSha256) &&
    isSha256(evidence.verifiedStageSha256) &&
    Number.isSafeInteger(evidence.issuedAtMs) &&
    Number.isSafeInteger(evidence.expiresAtMs) &&
    validIdentifier(evidence.requestNonce) &&
    validPostactivationProgress(evidence)
  );
}

function validPostactivationProgress(evidence: ProbeRepairEvidence) {
  const targetCount = 20;
  if (
    evidence.activatedTargets > targetCount ||
    evidence.finalizedTargets > targetCount
  ) {
    return false;
  }
  switch (evidence.journalPhase) {
    case "activation-started":
    case "repair-required":
      return evidence.finalizedTargets === 0;
    case "finalizing":
      return evidence.activatedTargets === targetCount;
    case "stage-cleanup-required":
      return (
        evidence.activatedTargets === targetCount &&
        evidence.finalizedTargets === targetCount
      );
  }
}

function validIdentifier(value: string) {
  return /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

function validVersion(value: string) {
  return /^[A-Za-z0-9.+-]{1,64}$/.test(value);
}

function isSha256(value: string) {
  return /^[0-9a-f]{64}$/.test(value);
}
