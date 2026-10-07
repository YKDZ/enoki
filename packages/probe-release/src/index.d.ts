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

export type ReleaseTransitionClassification =
  | "compatible"
  | "replacement-required";

export type ReleaseTransitionProbeComponent = Readonly<{
  file: "enoki-probe";
  role: "probe";
  sha256: string;
  target: string;
}>;

export type ReleaseTransitionTargetBundle = Readonly<{
  bundleManifestSha256: string;
  file: string;
  sha256: string;
  size: number;
  target: string;
}>;

export type ReleaseTransitionContractTarget = Readonly<{
  assetClosure: readonly ReleaseTransitionTargetBundle[];
  assetSetManifestSha256: string;
  delegationGeneration: number;
  signingKeyId: string;
  version: string;
}>;

export type ReleaseTransitionLegacyAsset = Readonly<{
  name: string;
  sha256: string;
  size: number;
}>;

export type GenericReleaseTransitionContract = Readonly<{
  candidateCommit: string;
  distribution: string;
  kind: "enoki-release-transition-contract";
  rootKeyId: string;
  schemaVersion: 1;
  source: Readonly<{
    probeComponents: readonly ReleaseTransitionProbeComponent[];
    version: string;
  }>;
  target: ReleaseTransitionContractTarget;
  transition: ReleaseTransitionClassification;
}>;

export type TrustEpochMigrationReleaseTransitionContract = Readonly<{
  candidateCommit: string;
  distribution: string;
  kind: "enoki-release-transition-contract";
  migrationAuthorizationSha256: string;
  migrationGeneration: 1;
  rootKeyId: string;
  schemaVersion: 1;
  source: Readonly<{
    assets: readonly ReleaseTransitionLegacyAsset[];
    commit: string;
    hubDigest: string;
    hubImage: string;
    legacySigningKeySha256: string;
    probeComponents: readonly ReleaseTransitionProbeComponent[];
    releaseId: number;
    repository: string;
    tag: string;
    tagRefSha: string;
    targetCommitish: string;
  }>;
  target: ReleaseTransitionContractTarget;
  transition: "replacement-required";
}>;

export type ReleaseTransitionContract =
  | GenericReleaseTransitionContract
  | TrustEpochMigrationReleaseTransitionContract;

export type ReleaseTransitionContractExpectation = Readonly<{
  candidateCommit?: string;
  classification?: string;
  delegationGeneration?: number;
  sourceCommit?: string;
  sourceTag?: string;
  sourceVersion?: string;
  targetAssetClosure?: readonly unknown[];
  targetAssetSetManifestSha256?: string;
  targetVersion?: string;
}>;

export type SignedDocument<T> = {
  bytes: Buffer;
  signature: Buffer;
} & T;

export const probeBundleComponentProfiles: Readonly<
  Record<string, ProbeBundleComponentProfile>
>;
export const probeBundledBootstrapAssets: readonly ProbeBundledBootstrapAsset[];
export const probeTargets: readonly string[];

export function inspectProbeElf(
  binary: Buffer,
  options: {
    requireEmbeddedProbeIdentity?: boolean;
    target: string;
    version: string;
  },
): void;
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
export function verifyReleaseTransitionContract(input: {
  authorizationBytes?: Uint8Array;
  authorizationSignature?: Uint8Array;
  contractBytes: Uint8Array;
  contractSignature: Uint8Array;
  expected?: ReleaseTransitionContractExpectation;
  rootPublicKeyPem: string | Buffer;
}): ReleaseTransitionContract;
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
