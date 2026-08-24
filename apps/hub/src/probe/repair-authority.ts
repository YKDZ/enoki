import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import type { ProbeUpgradeRequest } from "./operation.js";

const repairEvidenceSigningDomain = Buffer.from(
  "enoki/lifecycle-repair-evidence/hmac-sha256/v1\0",
);
const repairEligibilitySigningDomain = Buffer.from(
  "enoki/lifecycle-repair-eligibility/hmac-sha256/v1\0",
);
const repairAuthoritySigningDomain = Buffer.from(
  "enoki/lifecycle-repair-authority/hmac-sha256/v1\0",
);
const installedBundleFailureEvidenceSigningDomain = Buffer.from(
  "enoki/installed-bundle-failure-evidence/hmac-sha256/v1\0",
);
const installedBundleRepairAuthoritySigningDomain = Buffer.from(
  "enoki/installed-bundle-repair-authority/hmac-sha256/v1\0",
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

export type ProbeRepairEligibility = Omit<
  ProbeRepairEvidence,
  "expiresAtMs" | "issuedAtMs" | "requestNonce"
>;

export type VerifiedProbeRepairEligibility = {
  evidence: ProbeRepairEligibility;
  evidenceJson: string;
  evidenceSha256: string;
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

export type InstalledBundleFailureEvidence = {
  kind: "installed_bundle_failure";
  schemaVersion: 1;
  hubOrigin: string;
  probeId: string;
  generation: string;
  bootId: string;
  unit: "enoki-observation-runtime.service";
  unitSha256: string;
  identityReceiptSha256: string;
  installStateSha256: string;
  manifestSha256: string;
  bundleVersion: string;
  issuedAtMs: number;
  expiresAtMs: number;
  requestNonce: string;
};

export type InstalledBundleRepairAuthority = {
  kind: "installed_bundle_failure";
  schemaVersion: 1;
  hubOrigin: string;
  hostId: string;
  probeId: string;
  generation: string;
  bootId: string;
  unit: "enoki-observation-runtime.service";
  unitSha256: string;
  identityReceiptSha256: string;
  installStateSha256: string;
  manifestSha256: string;
  bundleVersion: string;
  repairOperationId: string;
  repairNonce: string;
  repairEvidenceSha256: string;
  expiresAtMs: number;
};

export type InstalledBundleRepairAuthorizationDecision =
  | {
      disposition: "probe_repair";
      authority: InstalledBundleRepairAuthority;
      signature: string;
    }
  | { disposition: "manual_reinstall_required"; authority?: never };

export function canonicalInstalledBundleFailureEvidence(
  evidence: InstalledBundleFailureEvidence,
) {
  return Buffer.from(JSON.stringify(evidence), "utf8");
}

export function signInstalledBundleFailureEvidence(
  canonicalEvidence: Uint8Array,
  installKey: Uint8Array,
) {
  return signRepairFacts(
    installedBundleFailureEvidenceSigningDomain,
    canonicalEvidence,
    installKey,
  );
}

export function canonicalInstalledBundleRepairAuthority(
  authority: InstalledBundleRepairAuthority,
) {
  return Buffer.from(JSON.stringify(authority), "utf8");
}

export function verifyInstalledBundleFailureEvidence(input: {
  evidence: InstalledBundleFailureEvidence;
  evidenceSignature: string;
  expectedBundleVersion: string;
  expectedHubOrigin: string;
  expectedProbeId: string;
  installKey: Uint8Array;
  nowMs: number;
}): { repairEvidenceSha256: string } | null {
  const canonicalEvidence = canonicalInstalledBundleFailureEvidence(
    input.evidence,
  );
  const validSha256 = (value: string) => /^[0-9a-f]{64}$/.test(value);
  if (
    input.evidence.kind !== "installed_bundle_failure" ||
    input.evidence.schemaVersion !== 1 ||
    input.evidence.unit !== "enoki-observation-runtime.service" ||
    input.evidence.hubOrigin !== input.expectedHubOrigin ||
    input.evidence.probeId !== input.expectedProbeId ||
    input.evidence.bundleVersion !== input.expectedBundleVersion ||
    !validSha256(input.evidence.generation) ||
    !validSha256(input.evidence.unitSha256) ||
    !validSha256(input.evidence.identityReceiptSha256) ||
    !validSha256(input.evidence.installStateSha256) ||
    !validSha256(input.evidence.manifestSha256) ||
    !validIdentifier(input.evidence.bootId) ||
    !validIdentifier(input.evidence.requestNonce) ||
    !Number.isSafeInteger(input.evidence.issuedAtMs) ||
    !Number.isSafeInteger(input.evidence.expiresAtMs) ||
    input.evidence.issuedAtMs > input.nowMs ||
    input.evidence.expiresAtMs <= input.nowMs ||
    input.evidence.expiresAtMs - input.evidence.issuedAtMs >
      maxRepairAuthorityTtlMs ||
    !verifyRepairFacts(
      installedBundleFailureEvidenceSigningDomain,
      canonicalEvidence,
      input.evidenceSignature,
      input.installKey,
    )
  )
    return null;
  return {
    repairEvidenceSha256: createHash("sha256")
      .update(canonicalEvidence)
      .digest("hex"),
  };
}

export function authorizeInstalledBundleRepair(input: {
  authorityExpiresAtMs: number;
  evidence: InstalledBundleFailureEvidence;
  evidenceSignature: string;
  expectedBundleVersion: string;
  expectedHubOrigin: string;
  expectedProbeId: string;
  hostId: number;
  installKey: Uint8Array;
  nowMs: number;
  repairNonce: string;
  repairOperationId: string;
}): InstalledBundleRepairAuthorizationDecision {
  const verified = verifyInstalledBundleFailureEvidence(input);
  if (
    !verified ||
    !validIdentifier(input.repairOperationId) ||
    !validIdentifier(input.repairNonce) ||
    input.authorityExpiresAtMs <= input.nowMs ||
    input.authorityExpiresAtMs - input.nowMs > maxRepairAuthorityTtlMs
  ) {
    return { disposition: "manual_reinstall_required" };
  }
  const authority: InstalledBundleRepairAuthority = {
    kind: "installed_bundle_failure",
    schemaVersion: 1,
    hubOrigin: input.expectedHubOrigin,
    hostId: String(input.hostId),
    probeId: input.expectedProbeId,
    generation: input.evidence.generation,
    bootId: input.evidence.bootId,
    unit: input.evidence.unit,
    unitSha256: input.evidence.unitSha256,
    identityReceiptSha256: input.evidence.identityReceiptSha256,
    installStateSha256: input.evidence.installStateSha256,
    manifestSha256: input.evidence.manifestSha256,
    bundleVersion: input.evidence.bundleVersion,
    repairOperationId: input.repairOperationId,
    repairNonce: input.repairNonce,
    repairEvidenceSha256: verified.repairEvidenceSha256,
    expiresAtMs: input.authorityExpiresAtMs,
  };
  return {
    disposition: "probe_repair",
    authority,
    signature: signRepairFacts(
      installedBundleRepairAuthoritySigningDomain,
      canonicalInstalledBundleRepairAuthority(authority),
      input.installKey,
    ),
  };
}

export function canonicalProbeRepairEvidence(evidence: ProbeRepairEvidence) {
  return Buffer.from(JSON.stringify(evidence), "utf8");
}

export function canonicalProbeRepairEligibility(
  evidence: ProbeRepairEligibility,
) {
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

export function signProbeRepairEligibility(
  canonicalEvidence: Uint8Array,
  installKey: Uint8Array,
) {
  return signRepairFacts(
    repairEligibilitySigningDomain,
    canonicalEvidence,
    installKey,
  );
}

export function verifyProbeRepairEligibility(input: {
  canonicalEvidence: string;
  evidenceSignature: string;
  expectedHubOrigin: string;
  expectedProbeId: string;
  failedUpgrade: ProbeUpgradeRequest;
  installKey: Uint8Array;
}): VerifiedProbeRepairEligibility | null {
  let evidence: ProbeRepairEligibility;
  try {
    evidence = JSON.parse(input.canonicalEvidence) as ProbeRepairEligibility;
  } catch {
    return null;
  }
  const canonical = canonicalProbeRepairEligibility(evidence);
  if (
    canonical.toString("utf8") !== input.canonicalEvidence ||
    !verifyRepairFacts(
      repairEligibilitySigningDomain,
      canonical,
      input.evidenceSignature,
      input.installKey,
    ) ||
    !validRepairEligibility(evidence) ||
    input.failedUpgrade.kind !== "probe_upgrade" ||
    input.failedUpgrade.id === null ||
    evidence.hubOrigin !== input.expectedHubOrigin ||
    evidence.hostId !== String(input.failedUpgrade.hostId) ||
    evidence.probeId !== input.expectedProbeId ||
    evidence.failedOperationId !== String(input.failedUpgrade.id) ||
    evidence.failedAuthoritySha256 !==
      input.failedUpgrade.upgradeAuthoritySha256 ||
    evidence.targetBundleVersion !== input.failedUpgrade.targetProbeVersion ||
    evidence.targetAssetSetDigest !==
      input.failedUpgrade.targetAssetSetDigest ||
    evidence.targetManifestSha256 !==
      input.failedUpgrade.targetManifestSha256 ||
    evidence.verifiedStageSha256 !== input.failedUpgrade.verifiedStageSha256
  ) {
    return null;
  }
  return {
    evidence,
    evidenceJson: input.canonicalEvidence,
    evidenceSha256: createHash("sha256").update(canonical).digest("hex"),
  };
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
    validRepairEligibility(evidence) &&
    Number.isSafeInteger(evidence.issuedAtMs) &&
    Number.isSafeInteger(evidence.expiresAtMs) &&
    validIdentifier(evidence.requestNonce)
  );
}

function validRepairEligibility(evidence: ProbeRepairEligibility) {
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
    validPostactivationProgress(evidence)
  );
}

function validPostactivationProgress(evidence: ProbeRepairEligibility) {
  const targetCount = 21;
  if (
    evidence.activatedTargets > targetCount ||
    evidence.finalizedTargets > targetCount
  ) {
    return false;
  }
  switch (evidence.journalPhase) {
    case "activation-started":
      return evidence.finalizedTargets === 0;
    case "repair-required":
      return evidence.finalizedTargets <= evidence.activatedTargets;
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
