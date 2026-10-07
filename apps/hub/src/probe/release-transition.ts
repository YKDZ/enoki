import { createHash, createPublicKey, verify } from "node:crypto";
import { open } from "node:fs/promises";

import {
  type ReleaseTransitionContract,
  verifyReleaseTransitionContract,
} from "@enoki/probe-release";

import type { VerifiedReleaseTransition } from "./asset-set.js";
import { readBoundedMetadataSnapshotFromDirectory } from "./assets.js";

const delegationDomain = Buffer.from(
  "enoki/probe-trust-delegation/v1\0",
  "utf8",
);
const digestPattern = /^[0-9a-f]{64}$/;
const semverPattern = /^(?:0|[1-9]\d*)[.](?:0|[1-9]\d*)[.](?:0|[1-9]\d*)$/;
const enokiDistribution = "enoki";
const trustEpochSourceVersion = "0.1.74";
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

type VerifiedAssetSetMetadata = {
  assets: NonNullable<ReturnType<typeof assetClosure>>;
  delegationGeneration: number;
  targetVersion: string;
};

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
  const manifest = parseObject(files.manifest);
  if (!delegation || !manifest) return null;
  if (
    !verifySigned(
      delegationDomain,
      files.delegation,
      files.delegationSignature,
      trustedRoot,
    ) ||
    !verify("RSA-SHA256", files.manifest, signingKey, files.manifestSignature)
  ) {
    return null;
  }

  const signingKeyId = sha256(signingKey);
  const assetSet = verifiedAssetSetMetadata({
    delegation,
    manifest,
    rootKeyId: sha256(trustedRoot),
    signingKey,
    signingKeyId,
  });
  if (!assetSet) return null;

  const contract = verifiedReleaseTransitionContract({
    assetSet,
    authorization: files.authorization,
    authorizationSignature: files.authorizationSignature,
    contractBytes: files.contract,
    contractSignature: files.contractSignature,
    manifestBytes: files.manifest,
    signingKeyId,
    trustedRoot,
  });
  if (!contract) return null;

  const targetAssetSetDigest = `sha256:${sha256(files.manifest)}`;
  const sourceProbeSha256 = contract.source.probeComponents.map(
    (component) => component.sha256,
  );
  const targetBundles = assetSet.assets.map(
    ({ bundleManifestSha256, target }) => ({
      bundleManifestSha256: String(bundleManifestSha256),
      target: String(target),
    }),
  );
  if ("migrationAuthorizationSha256" in contract) {
    return {
      classification: contract.transition,
      sourceProbeSha256,
      sourceProbeVersion: trustEpochSourceVersion,
      targetAssetSetDigest,
      targetBundles,
      targetProbeVersion: contract.target.version,
    };
  }
  return {
    classification: contract.transition,
    sourceProbeSha256,
    sourceProbeVersion: contract.source.version,
    targetAssetSetDigest,
    targetBundles,
    targetProbeVersion: contract.target.version,
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

function verifiedAssetSetMetadata(input: {
  delegation: Record<string, unknown>;
  manifest: Record<string, unknown>;
  rootKeyId: string;
  signingKey: Buffer;
  signingKeyId: string;
}): VerifiedAssetSetMetadata | null {
  const assets = assetClosure(input.manifest.assets);
  const delegationGeneration = numberAt(input.delegation, "generation");
  const targetVersion = stringAt(input.manifest, "version");
  if (
    !assets ||
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
    stringAt(input.delegation, "distribution") !== enokiDistribution ||
    stringAt(input.delegation, "purpose") !== "probe-asset-signing" ||
    stringAt(input.delegation, "rootKeyId") !== input.rootKeyId ||
    !Number.isSafeInteger(delegationGeneration) ||
    (delegationGeneration ?? 0) < 1 ||
    stringAt(input.delegation, "signingIdentity", "algorithm") !==
      "rsa-sha256" ||
    stringAt(input.delegation, "signingIdentity", "keyId") !==
      input.signingKeyId ||
    canonicalPublicKeyOrNull(
      stringAt(input.delegation, "signingIdentity", "publicKeyPem") ?? "",
    )?.compare(input.signingKey) !== 0 ||
    stringAt(input.manifest, "kind") !== "enoki-probe-assets" ||
    !semverPattern.test(targetVersion ?? "") ||
    stringAt(input.manifest, "signature", "algorithm") !== "rsa-sha256" ||
    stringAt(input.manifest, "signature", "file") !== "manifest.json.sig" ||
    stringAt(input.manifest, "signature", "publicKey") !== "signing-key.pem" ||
    numberAt(input.manifest, "signature", "delegationGeneration") !==
      delegationGeneration ||
    stringAt(input.manifest, "signature", "delegationKeyId") !==
      input.signingKeyId
  ) {
    return null;
  }
  return {
    assets: assets!,
    delegationGeneration: delegationGeneration!,
    targetVersion: targetVersion!,
  };
}

function verifiedReleaseTransitionContract(input: {
  assetSet: VerifiedAssetSetMetadata;
  authorization: Buffer | null;
  authorizationSignature: Buffer | null;
  contractBytes: Buffer;
  contractSignature: Buffer;
  manifestBytes: Buffer;
  signingKeyId: string;
  trustedRoot: Buffer;
}): ReleaseTransitionContract | null {
  let contract: ReleaseTransitionContract;
  try {
    contract = verifyReleaseTransitionContract({
      ...(input.authorization
        ? { authorizationBytes: input.authorization }
        : {}),
      ...(input.authorizationSignature
        ? { authorizationSignature: input.authorizationSignature }
        : {}),
      contractBytes: input.contractBytes,
      contractSignature: input.contractSignature,
      expected: {
        delegationGeneration: input.assetSet.delegationGeneration,
        targetAssetClosure: input.assetSet.assets,
        targetAssetSetManifestSha256: sha256(input.manifestBytes),
        targetVersion: input.assetSet.targetVersion,
      },
      rootPublicKeyPem: input.trustedRoot,
    });
  } catch {
    return null;
  }
  if (
    contract.distribution !== enokiDistribution ||
    contract.target.signingKeyId !== input.signingKeyId ||
    "migrationAuthorizationSha256" in contract !==
      Boolean(input.authorization || input.authorizationSignature)
  ) {
    return null;
  }
  return contract;
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
