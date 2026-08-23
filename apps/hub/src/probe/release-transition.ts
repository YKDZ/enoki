import { createHash, createPublicKey, verify } from "node:crypto";
import { open } from "node:fs/promises";

import type { VerifiedReleaseTransition } from "./asset-set.js";
import { readBoundedMetadataSnapshotFromDirectory } from "./assets.js";

const contractDomain = Buffer.from(
  "enoki/release-transition-contract/v1\0",
  "utf8",
);
const delegationDomain = Buffer.from(
  "enoki/probe-trust-delegation/v1\0",
  "utf8",
);
const trustEpochAuthorizationDomain = Buffer.from(
  "enoki/trust-epoch-migration-authorization/v1\0",
  "utf8",
);
const digestPattern = /^[0-9a-f]{64}$/;
const semverPattern = /^(?:0|[1-9]\d*)[.](?:0|[1-9]\d*)[.](?:0|[1-9]\d*)$/;
const probeTargets = [
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
] as const;
export const releaseTransitionMetadataFileNames = [
  "release-transition-contract.json",
  "release-transition-contract.json.sig",
  "trust-delegation.json",
  "trust-delegation.json.sig",
  "manifest.json",
  "manifest.json.sig",
  "root-key.pem",
  "signing-key.pem",
  "trust-epoch-migration-authorization.json",
  "trust-epoch-migration-authorization.json.sig",
] as const;

const requiredReleaseTransitionMetadataFileNames = [
  "release-transition-contract.json",
  "release-transition-contract.json.sig",
  "trust-delegation.json",
  "trust-delegation.json.sig",
  "manifest.json",
  "manifest.json.sig",
  "root-key.pem",
  "signing-key.pem",
] as const;

export async function readVerifiedReleaseTransitionFromDirectory(input: {
  assetDir: string;
  maxMetadataBytes?: number;
  maxTotalMetadataBytes?: number;
  openFile?: typeof open;
  trustedRootPublicKeyPem: string | Buffer;
}): Promise<VerifiedReleaseTransition | null> {
  const files = await readTransitionFiles(input);
  if (!files) return null;
  return verifiedReleaseTransitionFromMetadata({
    files,
    trustedRootPublicKeyPem: input.trustedRootPublicKeyPem,
  });
}

export function verifiedReleaseTransitionFromMetadata(input: {
  files: Partial<
    Record<(typeof releaseTransitionMetadataFileNames)[number], Buffer | null>
  >;
  trustedRootPublicKeyPem: string | Buffer;
}): VerifiedReleaseTransition | null {
  const files = transitionFilesFromMetadata(input.files);
  if (!files) return null;
  const trustedRoot = canonicalPublicKey(input.trustedRootPublicKeyPem);
  const rootKey = canonicalPublicKeyOrNull(files.rootKey);
  const signingKey = canonicalPublicKeyOrNull(files.signingKey);
  if (!rootKey || !signingKey || !rootKey.equals(trustedRoot)) return null;

  const delegation = parseCanonicalObject(files.delegation);
  const contract = parseCanonicalObject(files.contract);
  const manifest = parseObject(files.manifest);
  if (!delegation || !contract || !manifest) return null;
  if (
    !verifySigned(
      delegationDomain,
      files.delegation,
      files.delegationSignature,
      trustedRoot,
    ) ||
    !verifySigned(
      contractDomain,
      files.contract,
      files.contractSignature,
      trustedRoot,
    ) ||
    !verify("RSA-SHA256", files.manifest, signingKey, files.manifestSignature)
  ) {
    return null;
  }

  const rootKeyId = sha256(trustedRoot);
  const signingKeyId = sha256(signingKey);
  const assets = assetClosure(manifest.assets);
  const contractAssets = assetClosure(
    valueAt(contract, "target", "assetClosure"),
  );
  const sourceVersion = stringAt(contract, "source", "version");
  const sourceProbeSha256 = sourceProbeComponentDigests(contract);
  const targetVersion = stringAt(contract, "target", "version");
  const transition = stringAt(contract, "transition");
  const targetAssetSetDigest = `sha256:${sha256(files.manifest)}`;
  const delegationGeneration = numberAt(delegation, "generation");

  if (
    !hasVerifiedAssetSetMetadata({
      assets,
      delegation,
      delegationGeneration,
      manifest,
      rootKeyId,
      signingKey,
      signingKeyId,
    })
  ) {
    return null;
  }

  const trustEpochTransition = verifiedTrustEpochMigrationTransition({
    authorization: files.authorization,
    authorizationSignature: files.authorizationSignature,
    contract,
    manifest,
    manifestBytes: files.manifest,
    rootKeyId,
    signingKeyId,
    targetAssetSetDigest,
    trustedRoot,
  });
  if (trustEpochTransition) return trustEpochTransition;
  if (files.authorization || files.authorizationSignature) return null;

  if (
    !hasExactKeys(delegation, [
      "distribution",
      "generation",
      "kind",
      "purpose",
      "rootKeyId",
      "schemaVersion",
      "signingIdentity",
    ]) ||
    !hasExactKeys(valueAt(delegation, "signingIdentity"), [
      "algorithm",
      "keyId",
      "publicKeyPem",
    ]) ||
    !hasExactKeys(contract, [
      "distribution",
      "kind",
      "rootKeyId",
      "schemaVersion",
      "source",
      "target",
      "transition",
    ]) ||
    !hasExactKeys(valueAt(contract, "source"), [
      "probeComponents",
      "version",
    ]) ||
    !hasExactKeys(valueAt(contract, "target"), [
      "assetClosure",
      "assetSetManifestSha256",
      "delegationGeneration",
      "signingKeyId",
      "version",
    ]) ||
    !hasExactKeys(manifest, ["assets", "kind", "signature", "version"]) ||
    !hasExactKeys(valueAt(manifest, "signature"), [
      "algorithm",
      "delegationGeneration",
      "delegationKeyId",
      "file",
      "publicKey",
    ]) ||
    stringAt(delegation, "kind") !== "enoki-probe-trust-delegation" ||
    numberAt(delegation, "schemaVersion") !== 1 ||
    stringAt(delegation, "distribution") !== "enoki" ||
    stringAt(delegation, "purpose") !== "probe-asset-signing" ||
    stringAt(delegation, "rootKeyId") !== rootKeyId ||
    !Number.isSafeInteger(delegationGeneration) ||
    (delegationGeneration ?? 0) < 1 ||
    stringAt(delegation, "signingIdentity", "algorithm") !== "rsa-sha256" ||
    stringAt(delegation, "signingIdentity", "keyId") !== signingKeyId ||
    canonicalPublicKeyOrNull(
      stringAt(delegation, "signingIdentity", "publicKeyPem") ?? "",
    )?.compare(signingKey) !== 0 ||
    stringAt(contract, "kind") !== "enoki-release-transition-contract" ||
    numberAt(contract, "schemaVersion") !== 1 ||
    stringAt(contract, "distribution") !== "enoki" ||
    stringAt(contract, "rootKeyId") !== rootKeyId ||
    !semverPattern.test(sourceVersion ?? "") ||
    !sourceProbeSha256 ||
    !semverPattern.test(targetVersion ?? "") ||
    !["compatible", "replacement-required"].includes(transition ?? "") ||
    stringAt(manifest, "kind") !== "enoki-probe-assets" ||
    stringAt(manifest, "version") !== targetVersion ||
    stringAt(manifest, "signature", "algorithm") !== "rsa-sha256" ||
    stringAt(manifest, "signature", "file") !== "manifest.json.sig" ||
    stringAt(manifest, "signature", "publicKey") !== "signing-key.pem" ||
    numberAt(manifest, "signature", "delegationGeneration") !==
      delegationGeneration ||
    stringAt(manifest, "signature", "delegationKeyId") !== signingKeyId ||
    numberAt(contract, "target", "delegationGeneration") !==
      delegationGeneration ||
    stringAt(contract, "target", "signingKeyId") !== signingKeyId ||
    stringAt(contract, "target", "assetSetManifestSha256") !==
      sha256(files.manifest) ||
    !assets ||
    !contractAssets ||
    JSON.stringify(contractAssets) !== JSON.stringify(assets)
  ) {
    return null;
  }

  return {
    classification: transition as VerifiedReleaseTransition["classification"],
    sourceProbeVersion: sourceVersion!,
    sourceProbeSha256,
    targetAssetSetDigest,
    targetProbeVersion: targetVersion!,
  };
}

async function readTransitionFiles(input: {
  assetDir: string;
  maxMetadataBytes?: number;
  maxTotalMetadataBytes?: number;
  openFile?: typeof open;
}) {
  const files = await readBoundedMetadataSnapshotFromDirectory({
    assetDir: input.assetDir,
    optionalFileNames: [
      "trust-epoch-migration-authorization.json",
      "trust-epoch-migration-authorization.json.sig",
    ],
    requiredFileNames: requiredReleaseTransitionMetadataFileNames,
    maxFileBytes: input.maxMetadataBytes,
    maxTotalBytes: input.maxTotalMetadataBytes,
    openFile: input.openFile,
  });
  if (!files) return null;
  return files;
}

function transitionFilesFromMetadata(
  files: Partial<
    Record<(typeof releaseTransitionMetadataFileNames)[number], Buffer | null>
  >,
) {
  if (
    requiredReleaseTransitionMetadataFileNames.some(
      (fileName) => !files[fileName],
    )
  ) {
    return null;
  }
  return {
    contract: files["release-transition-contract.json"]!,
    contractSignature: files["release-transition-contract.json.sig"]!,
    delegation: files["trust-delegation.json"]!,
    delegationSignature: files["trust-delegation.json.sig"]!,
    manifest: files["manifest.json"]!,
    manifestSignature: files["manifest.json.sig"]!,
    rootKey: files["root-key.pem"]!,
    signingKey: files["signing-key.pem"]!,
    authorization: files["trust-epoch-migration-authorization.json"] ?? null,
    authorizationSignature:
      files["trust-epoch-migration-authorization.json.sig"] ?? null,
  };
}

function hasVerifiedAssetSetMetadata(input: {
  assets: ReturnType<typeof assetClosure>;
  delegation: Record<string, unknown>;
  delegationGeneration: number | null;
  manifest: Record<string, unknown>;
  rootKeyId: string;
  signingKey: Buffer;
  signingKeyId: string;
}) {
  return !(
    !hasExactKeys(input.delegation, [
      "distribution",
      "generation",
      "kind",
      "purpose",
      "rootKeyId",
      "schemaVersion",
      "signingIdentity",
    ]) ||
    !hasExactKeys(valueAt(input.delegation, "signingIdentity"), [
      "algorithm",
      "keyId",
      "publicKeyPem",
    ]) ||
    !hasExactKeys(input.manifest, ["assets", "kind", "signature", "version"]) ||
    !hasExactKeys(valueAt(input.manifest, "signature"), [
      "algorithm",
      "delegationGeneration",
      "delegationKeyId",
      "file",
      "publicKey",
    ]) ||
    stringAt(input.delegation, "kind") !== "enoki-probe-trust-delegation" ||
    numberAt(input.delegation, "schemaVersion") !== 1 ||
    stringAt(input.delegation, "distribution") !== "enoki" ||
    stringAt(input.delegation, "purpose") !== "probe-asset-signing" ||
    stringAt(input.delegation, "rootKeyId") !== input.rootKeyId ||
    !Number.isSafeInteger(input.delegationGeneration) ||
    (input.delegationGeneration ?? 0) < 1 ||
    stringAt(input.delegation, "signingIdentity", "algorithm") !==
      "rsa-sha256" ||
    stringAt(input.delegation, "signingIdentity", "keyId") !==
      input.signingKeyId ||
    canonicalPublicKeyOrNull(
      stringAt(input.delegation, "signingIdentity", "publicKeyPem") ?? "",
    )?.compare(input.signingKey) !== 0 ||
    stringAt(input.manifest, "kind") !== "enoki-probe-assets" ||
    !semverPattern.test(stringAt(input.manifest, "version") ?? "") ||
    stringAt(input.manifest, "signature", "algorithm") !== "rsa-sha256" ||
    stringAt(input.manifest, "signature", "file") !== "manifest.json.sig" ||
    stringAt(input.manifest, "signature", "publicKey") !== "signing-key.pem" ||
    numberAt(input.manifest, "signature", "delegationGeneration") !==
      input.delegationGeneration ||
    stringAt(input.manifest, "signature", "delegationKeyId") !==
      input.signingKeyId ||
    !input.assets
  );
}

function verifiedTrustEpochMigrationTransition(input: {
  authorization: Buffer | null;
  authorizationSignature: Buffer | null;
  contract: Record<string, unknown>;
  manifest: Record<string, unknown>;
  manifestBytes: Buffer;
  rootKeyId: string;
  signingKeyId: string;
  targetAssetSetDigest: string;
  trustedRoot: Buffer;
}): VerifiedReleaseTransition | null {
  const hasAuthorization = Boolean(
    input.authorization || input.authorizationSignature,
  );
  if (!hasAuthorization) return null;
  if (!input.authorization || !input.authorizationSignature) return null;
  const authorization = parseCanonicalObject(input.authorization);
  const sourceProbeSha256 = sourceProbeComponentDigests(input.contract);
  if (
    !authorization ||
    !verifySigned(
      trustEpochAuthorizationDomain,
      input.authorization,
      input.authorizationSignature,
      input.trustedRoot,
    ) ||
    !hasExactKeys(input.contract, [
      "candidateCommit",
      "distribution",
      "kind",
      "migrationAuthorizationSha256",
      "migrationGeneration",
      "rootKeyId",
      "schemaVersion",
      "source",
      "target",
      "transition",
    ]) ||
    !hasExactKeys(authorization, [
      "candidateVersion",
      "distribution",
      "kind",
      "legacyRelease",
      "migrationGeneration",
      "purpose",
      "rootKeyId",
      "schemaVersion",
      "targetRootKeyId",
    ]) ||
    input.contract.kind !== "enoki-release-transition-contract" ||
    input.contract.schemaVersion !== 1 ||
    input.contract.transition !== "replacement-required" ||
    !/^[0-9a-f]{40}$/.test(String(input.contract.candidateCommit ?? "")) ||
    input.contract.distribution !== "enoki" ||
    input.contract.migrationGeneration !== 1 ||
    input.contract.rootKeyId !== input.rootKeyId ||
    input.contract.migrationAuthorizationSha256 !==
      sha256(input.authorization) ||
    authorization.kind !== "enoki-trust-epoch-migration-authorization" ||
    authorization.schemaVersion !== 1 ||
    authorization.distribution !== "enoki" ||
    authorization.purpose !== "release-baseline-migration" ||
    authorization.migrationGeneration !== 1 ||
    authorization.rootKeyId !== input.rootKeyId ||
    authorization.targetRootKeyId !== input.rootKeyId ||
    authorization.candidateVersion !==
      `v${stringAt(input.contract, "target", "version")}` ||
    !exactTrustEpochLegacyReleaseMatches(authorization, input.contract) ||
    !sourceProbeSha256 ||
    !exactTrustEpochTargetMatches(
      input.contract,
      input.manifest,
      input.manifestBytes,
      input.signingKeyId,
    )
  ) {
    return null;
  }

  return {
    classification: "replacement-required",
    sourceProbeVersion: "0.1.74",
    sourceProbeSha256,
    targetAssetSetDigest: input.targetAssetSetDigest,
    targetProbeVersion: stringAt(input.contract, "target", "version")!,
  };
}

function sourceProbeComponentDigests(contract: Record<string, unknown>) {
  const components = valueAt(contract, "source", "probeComponents");
  if (!Array.isArray(components) || components.length !== probeTargets.length) {
    return null;
  }
  const digests = components.map((component, index) => {
    if (
      !component ||
      typeof component !== "object" ||
      Array.isArray(component) ||
      !hasExactKeys(component as Record<string, unknown>, [
        "file",
        "role",
        "sha256",
        "target",
      ]) ||
      stringAt(component as Record<string, unknown>, "role") !== "probe" ||
      stringAt(component as Record<string, unknown>, "file") !==
        "enoki-probe" ||
      stringAt(component as Record<string, unknown>, "target") !==
        probeTargets[index] ||
      !/^[0-9a-f]{64}$/.test(
        stringAt(component as Record<string, unknown>, "sha256") ?? "",
      )
    ) {
      return null;
    }
    return stringAt(component as Record<string, unknown>, "sha256")!;
  });
  return digests.every((digest): digest is string => digest !== null)
    ? digests
    : null;
}

function exactTrustEpochLegacyReleaseMatches(
  authorization: Record<string, unknown>,
  contract: Record<string, unknown>,
) {
  const source = valueAt(contract, "source");
  if (
    !hasExactKeys(source, [
      "assets",
      "commit",
      "hubDigest",
      "hubImage",
      "legacySigningKeySha256",
      "probeComponents",
      "releaseId",
      "repository",
      "tag",
      "tagRefSha",
      "targetCommitish",
    ]) ||
    stringAt(contract, "source", "tag") !== "v0.1.74"
  ) {
    return false;
  }
  return (
    JSON.stringify(valueAt(authorization, "legacyRelease")) ===
    JSON.stringify({
      assets: valueAt(contract, "source", "assets"),
      githubRelease: {
        id: valueAt(contract, "source", "releaseId"),
        peeledCommitSha: valueAt(contract, "source", "commit"),
        repository: valueAt(contract, "source", "repository"),
        tag: valueAt(contract, "source", "tag"),
        tagRefSha: valueAt(contract, "source", "tagRefSha"),
        targetCommitish: valueAt(contract, "source", "targetCommitish"),
      },
      hub: {
        digest: valueAt(contract, "source", "hubDigest"),
        image: valueAt(contract, "source", "hubImage"),
      },
      legacySigningKeySha256: valueAt(
        contract,
        "source",
        "legacySigningKeySha256",
      ),
    })
  );
}

function exactTrustEpochTargetMatches(
  contract: Record<string, unknown>,
  manifest: Record<string, unknown>,
  manifestBytes: Buffer,
  signingKeyId: string,
) {
  const assets = assetClosure(manifest.assets);
  const contractAssets = assetClosure(
    valueAt(contract, "target", "assetClosure"),
  );
  return (
    hasExactKeys(valueAt(contract, "target"), [
      "assetClosure",
      "assetSetManifestSha256",
      "delegationGeneration",
      "signingKeyId",
      "version",
    ]) &&
    Boolean(assets) &&
    Boolean(contractAssets) &&
    stringAt(contract, "target", "version") === manifest.version &&
    stringAt(contract, "target", "signingKeyId") === signingKeyId &&
    numberAt(contract, "target", "delegationGeneration") ===
      numberAt(manifest, "signature", "delegationGeneration") &&
    stringAt(contract, "target", "assetSetManifestSha256") ===
      sha256(manifestBytes) &&
    JSON.stringify(contractAssets) === JSON.stringify(assets)
  );
}

function parseCanonicalObject(bytes: Buffer) {
  const value = parseObject(bytes);
  return value && bytes.equals(Buffer.from(`${JSON.stringify(value)}\n`))
    ? value
    : null;
}

function parseObject(bytes: Buffer): Record<string, unknown> | null {
  try {
    const value = JSON.parse(bytes.toString("utf8")) as unknown;
    return value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function assetClosure(value: unknown) {
  if (!Array.isArray(value) || value.length !== probeTargets.length)
    return null;
  const assets = [];
  for (const [index, asset] of value.entries()) {
    if (!asset || typeof asset !== "object" || Array.isArray(asset))
      return null;
    const entry = asset as Record<string, unknown>;
    if (
      !digestPattern.test(String(entry.bundleManifestSha256 ?? "")) ||
      typeof entry.file !== "string" ||
      !entry.file ||
      !digestPattern.test(String(entry.sha256 ?? "")) ||
      !Number.isSafeInteger(entry.size) ||
      (entry.size as number) < 0 ||
      typeof entry.target !== "string" ||
      entry.target !== probeTargets[index] ||
      entry.file !== `enoki-probe-${probeTargets[index]}.tar.gz`
    )
      return null;
    assets.push({
      bundleManifestSha256: entry.bundleManifestSha256,
      file: entry.file,
      sha256: entry.sha256,
      size: entry.size,
      target: entry.target,
    });
  }
  return assets;
}

function verifySigned(
  domain: Buffer,
  bytes: Buffer,
  signature: Buffer,
  key: Buffer,
) {
  return verify("RSA-SHA256", Buffer.concat([domain, bytes]), key, signature);
}

function canonicalPublicKey(value: string | Buffer) {
  return Buffer.from(
    createPublicKey(value).export({ format: "pem", type: "spki" }),
  );
}

function canonicalPublicKeyOrNull(value: string | Buffer) {
  try {
    return canonicalPublicKey(value);
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      String((error as NodeJS.ErrnoException).code).startsWith("ERR_OSSL_")
    ) {
      return null;
    }
    throw error;
  }
}

function valueAt(
  value: Record<string, unknown>,
  ...segments: string[]
): unknown {
  let current: unknown = value;
  for (const segment of segments) {
    if (!current || typeof current !== "object" || Array.isArray(current))
      return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function stringAt(value: Record<string, unknown>, ...segments: string[]) {
  const result = valueAt(value, ...segments);
  return typeof result === "string" ? result : null;
}

function numberAt(value: Record<string, unknown>, ...segments: string[]) {
  const result = valueAt(value, ...segments);
  return typeof result === "number" ? result : null;
}

function hasExactKeys(value: unknown, expected: string[]) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return (
    JSON.stringify(Object.keys(value).sort()) ===
    JSON.stringify([...expected].sort())
  );
}

function sha256(value: Buffer) {
  return createHash("sha256").update(value).digest("hex");
}
