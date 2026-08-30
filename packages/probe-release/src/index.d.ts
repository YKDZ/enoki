import type { KeyObject } from "node:crypto";

export type ProbeBundleComponentProfile = Readonly<{
  path: string;
  permissionProfile: string;
  resourceContract: string;
}>;

export type ProbeBundledBootstrapAsset = Readonly<{
  archivePath: string;
  bootstrapBuildRole: "acquirer" | "activator";
  key: "acquirer" | "activator";
  permissionProfile: string;
  role: string;
}>;

export type ProbeTrustDelegation = {
  distribution: string;
  generation: number;
  kind: "enoki-probe-trust-delegation";
  purpose: "probe-asset-signing";
  rootKeyId: string;
  schemaVersion: 1;
  signingIdentity: {
    algorithm: "rsa-sha256";
    keyId: string;
    publicKeyPem: string;
  };
};

export type SignedDocument<T> = {
  bytes: Buffer;
  signature: Buffer;
} & T;

export const probeBundleComponentProfiles: Readonly<
  Record<string, ProbeBundleComponentProfile>
>;
export const probeBundledBootstrapAssets: readonly ProbeBundledBootstrapAsset[];
export const probeTargets: readonly string[];
export function inspectProbeBundleArchiveBytes(
  archive: Buffer,
  input: {
    bundledBootstrap: { distribution: string; rootKeyId: string };
    requireEmbeddedProbeIdentity?: boolean;
    target: string;
    version: string;
  },
): Promise<{ bundleManifestSha256: string; probeSha256: string }>;
export function inspectHistoricalProbeBundleArchiveBytes(
  archive: Buffer,
  input: {
    bundledBootstrap?: { distribution: string; rootKeyId: string };
    requireEmbeddedProbeIdentity?: boolean;
    target: string;
    version: string;
  },
): Promise<{ bundleManifestSha256: string; probeSha256: string }>;
export function inspectRuntimeProbeBundleArchiveBytes(
  archive: Buffer,
  input: {
    requireEmbeddedProbeIdentity?: boolean;
    target: string;
    version: string;
  },
): Promise<{ bundleManifestSha256: string; probeSha256: string }>;
export function readRegularFileSnapshot(
  filePath: string,
  label: string,
  bounds: { expectedSize: number; maximumSize: number },
): Promise<{ bytes: Buffer; size: number }>;

export function canonicalPublicKeyPem(value: string | Buffer): Buffer;
export function createProbeTrustDelegation(input: {
  distribution: string;
  generation: number;
  purpose?: "probe-asset-signing";
  releasePublicKeyPem: string | Buffer;
  rootPrivateKey?: KeyObject;
  rootPrivateKeyPem?: string | Buffer;
}): SignedDocument<{ delegation: ProbeTrustDelegation }>;
export function verifyProbeTrustDelegation(input: {
  bytes: Uint8Array;
  expectedDistribution: string;
  expectedPurpose?: "probe-asset-signing";
  highestAcceptedGeneration?: number;
  rootPublicKeyPem: string | Buffer;
  signature: Uint8Array;
}): ProbeTrustDelegation;

export function createReleaseTransitionContract(
  input: Record<string, unknown>,
): Promise<SignedDocument<{ contract: Record<string, unknown> }>>;
export function verifyReleaseTransitionContract(
  input: Record<string, unknown>,
): Record<string, unknown>;
export function releaseTransitionContractSigningInput(
  bytes: Uint8Array,
): Buffer;
export function preflightReleaseMigrationConfiguration(
  input: Record<string, unknown>,
): unknown;

export function createTrustEpochMigrationAuthorization(input: {
  candidateVersion: string;
  distribution: string;
  legacyRelease: Record<string, unknown>;
  rootPrivateKeyPem: string | Buffer;
}): SignedDocument<{
  authorization: Record<string, unknown>;
}>;
export function verifyTrustEpochMigrationAuthorization(
  input: Record<string, unknown>,
): Record<string, unknown>;
export function trustEpochMigrationAuthorizationSigningInput(
  bytes: Uint8Array,
): Buffer;
export function trustEpochLegacyReleaseSha256(
  legacyRelease: Record<string, unknown>,
): string;
