import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";

import type { EnrollmentRepository } from "../database/enrollments.js";
import { validEnrollmentId } from "../enrollment/lifecycle.js";
import {
  validProbePublicKeyPem,
  verifyProbeRequestSignature,
} from "./probe-identity.js";
import { readProbeReleaseContextFromDirectory } from "./release-context.js";

const RegistrationAttempt = enoki.v1.ProbeRegistrationAttempt as any;

type ProtoMessage = Record<string, any>;

export type ValidatedRegistrationAttempt = {
  candidatePublicKeyPem: string;
  committedSourceProbeSha256: string;
  enrollmentId: string;
  hostId: number;
  hubOrigin: string;
  oldProbeId: string;
  replacementCommitSha256: string;
  signedAttemptSha256: string;
  sourceProbeVersion: string;
  targetAssetSetDigest: string;
  targetManifestSha256: string;
  targetBundleTarget: string;
  targetProbeVersion: string;
};

export type RegistrationAttemptResolution =
  | { kind: "accepted"; attempt: ValidatedRegistrationAttempt }
  | { kind: "invalid" }
  | { kind: "ordinary" }
  | { kind: "replay"; outcome: Buffer };

export async function resolveRegistrationAttempt(input: {
  enrollments: Pick<EnrollmentRepository, "replayRegistrationOutcome">;
  probeAssetDir?: string;
  probeDistributionRootPublicKeyPem?: Buffer | string;
  request: ProtoMessage;
  tokenHash: string;
}): Promise<RegistrationAttemptResolution> {
  const attempt = decodeSignedRegistrationAttempt(input.request);
  if (attempt === "invalid") {
    return { kind: "invalid" };
  }
  if (!attempt) {
    return { kind: "ordinary" };
  }

  const replay = input.enrollments.replayRegistrationOutcome({
    signedAttemptSha256: attempt.signedAttemptSha256,
    tokenHash: input.tokenHash,
  });
  if (replay) {
    return { kind: "replay", outcome: replay };
  }
  if (
    !(await attemptMatchesCurrentRelease(attempt, {
      probeAssetDir: input.probeAssetDir,
      probeDistributionRootPublicKeyPem:
        input.probeDistributionRootPublicKeyPem,
    }))
  ) {
    return { kind: "invalid" };
  }
  return { attempt, kind: "accepted" };
}

function decodeSignedRegistrationAttempt(
  request: ProtoMessage,
): ValidatedRegistrationAttempt | "invalid" | null {
  const canonicalBytes = Buffer.from(request.canonicalAttempt ?? []);
  const signature = Buffer.from(request.candidateSignature ?? []);
  if (canonicalBytes.length === 0 && signature.length === 0) {
    return null;
  }
  if (
    canonicalBytes.length === 0 ||
    canonicalBytes.length > 32 * 1024 ||
    signature.length === 0 ||
    signature.length > 1024 ||
    request.installationInspection ||
    request.installationRejection ||
    (request.snapshots ?? []).length > 0
  ) {
    return "invalid";
  }

  let attempt: ProtoMessage;
  try {
    attempt = RegistrationAttempt.decode(canonicalBytes) as ProtoMessage;
    if (
      !Buffer.from(
        RegistrationAttempt.encode(
          RegistrationAttempt.create(attempt),
        ).finish(),
      ).equals(canonicalBytes)
    ) {
      return "invalid";
    }
  } catch {
    return "invalid";
  }

  const hostId = Number(attempt.hostId);
  const candidatePublicKeyPem = String(attempt.candidatePublicKeyPem ?? "");
  const hubOrigin = String(attempt.hubOrigin ?? "");
  if (
    attempt.schemaVersion !== 1 ||
    !validEnrollmentId(String(attempt.enrollmentId ?? "")) ||
    !Number.isSafeInteger(hostId) ||
    hostId <= 0 ||
    !validPublicProbeId(attempt.oldProbeId) ||
    !validProbeVersion(attempt.sourceProbeVersion) ||
    !validProbeVersion(attempt.targetProbeVersion) ||
    !validSha256Digest(attempt.committedSourceProbeSha256) ||
    !/^(aarch64|x86_64)-unknown-linux-(gnu|musl)$/.test(
      String(attempt.targetBundleTarget ?? ""),
    ) ||
    !validSha256Digest(attempt.targetManifestSha256) ||
    !validSha256Digest(attempt.replacementCommitSha256) ||
    !/^[0-9a-f]{64}$/.test(String(attempt.nonce ?? "")) ||
    !/^sha256:[0-9a-f]{64}$/.test(String(attempt.targetAssetSetDigest ?? "")) ||
    request.probePublicKeyPem !== candidatePublicKeyPem ||
    !validProbePublicKeyPem(candidatePublicKeyPem) ||
    normalizedHubOrigin(hubOrigin) !== hubOrigin
  ) {
    return "invalid";
  }

  if (
    !verifyProbeRequestSignature(
      candidatePublicKeyPem,
      registrationAttemptSignaturePayload(canonicalBytes),
      signature.toString("hex"),
    )
  ) {
    return "invalid";
  }

  return {
    candidatePublicKeyPem,
    committedSourceProbeSha256: String(attempt.committedSourceProbeSha256),
    enrollmentId: String(attempt.enrollmentId),
    hostId,
    hubOrigin,
    oldProbeId: String(attempt.oldProbeId),
    replacementCommitSha256: String(attempt.replacementCommitSha256),
    signedAttemptSha256: createHash("sha256")
      .update("enoki.probe-registration-attempt.signed.v1\n")
      .update(canonicalBytes)
      .update(signature)
      .digest("hex"),
    sourceProbeVersion: String(attempt.sourceProbeVersion),
    targetAssetSetDigest: String(attempt.targetAssetSetDigest),
    targetManifestSha256: String(attempt.targetManifestSha256),
    targetBundleTarget: String(attempt.targetBundleTarget),
    targetProbeVersion: String(attempt.targetProbeVersion),
  };
}

async function attemptMatchesCurrentRelease(
  attempt: ValidatedRegistrationAttempt,
  releaseSource: {
    probeAssetDir?: string;
    probeDistributionRootPublicKeyPem?: Buffer | string;
  },
) {
  if (
    !releaseSource.probeAssetDir ||
    !releaseSource.probeDistributionRootPublicKeyPem
  ) {
    return false;
  }
  const release = await readProbeReleaseContextFromDirectory({
    assetDir: releaseSource.probeAssetDir,
    trustedRootPublicKeyPem: releaseSource.probeDistributionRootPublicKeyPem,
  });
  const transition = release.releaseTransition;
  return Boolean(
    transition &&
    release.assetSet.targetAssetSetDigest === attempt.targetAssetSetDigest &&
    transition.targetAssetSetDigest === attempt.targetAssetSetDigest &&
    transition.targetProbeVersion === attempt.targetProbeVersion &&
    transition.targetBundles?.some(
      (bundle) =>
        bundle.target === attempt.targetBundleTarget &&
        bundle.bundleManifestSha256 === attempt.targetManifestSha256,
    ),
  );
}

function registrationAttemptSignaturePayload(canonicalBytes: Uint8Array) {
  return `enoki.probe-registration-attempt.v1\n${createHash("sha256")
    .update(canonicalBytes)
    .digest("hex")}`;
}

function validSha256Digest(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function validProbeVersion(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(value)
  );
}

function normalizedHubOrigin(value: string) {
  try {
    const url = new URL(value);
    if (
      (url.protocol !== "https:" && url.protocol !== "http:") ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

function validPublicProbeId(value: unknown): value is string {
  return typeof value === "string" && /^probe_[A-Za-z0-9_-]{1,90}$/.test(value);
}
