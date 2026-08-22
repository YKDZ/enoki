import { createHash, createPublicKey, verify } from "node:crypto";
import { open } from "node:fs/promises";

import type { VerifiedReleaseTransition } from "./asset-set.js";
import { readBoundedMetadataFilesFromDirectory } from "./assets.js";

const contractDomain = Buffer.from(
  "enoki/release-transition-contract/v1\0",
  "utf8",
);
const delegationDomain = Buffer.from(
  "enoki/probe-trust-delegation/v1\0",
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
  const targetVersion = stringAt(contract, "target", "version");
  const transition = stringAt(contract, "transition");
  const targetAssetSetDigest = `sha256:${sha256(files.manifest)}`;
  const delegationGeneration = numberAt(delegation, "generation");

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
    !hasExactKeys(valueAt(contract, "source"), ["version"]) ||
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
  const files = await readBoundedMetadataFilesFromDirectory({
    assetDir: input.assetDir,
    fileNames: releaseTransitionMetadataFileNames,
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
  if (releaseTransitionMetadataFileNames.some((fileName) => !files[fileName])) {
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
  };
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
