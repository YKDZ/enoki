import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

import type { VerifiedReleaseTransition } from "./asset-set.js";

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

export async function readVerifiedReleaseTransitionFromDirectory(input: {
  assetDir: string;
  trustedRootPublicKeyPem: string | Buffer;
}): Promise<VerifiedReleaseTransition | null> {
  try {
    const files = await readTransitionFiles(input.assetDir);
    const trustedRoot = canonicalPublicKey(input.trustedRootPublicKeyPem);
    if (!files.rootKey.equals(trustedRoot)) return null;

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
      !verify(
        "RSA-SHA256",
        files.manifest,
        files.signingKey,
        files.manifestSignature,
      )
    ) {
      return null;
    }

    const rootKeyId = sha256(trustedRoot);
    const signingKey = canonicalPublicKey(files.signingKey);
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
      canonicalPublicKey(
        stringAt(delegation, "signingIdentity", "publicKeyPem") ?? "",
      ).compare(signingKey) !== 0 ||
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
  } catch {
    return null;
  }
}

async function readTransitionFiles(assetDir: string) {
  const [
    contract,
    contractSignature,
    delegation,
    delegationSignature,
    manifest,
    manifestSignature,
    rootKey,
    signingKey,
  ] = await Promise.all([
    readFile(path.join(assetDir, "release-transition-contract.json")),
    readFile(path.join(assetDir, "release-transition-contract.json.sig")),
    readFile(path.join(assetDir, "trust-delegation.json")),
    readFile(path.join(assetDir, "trust-delegation.json.sig")),
    readFile(path.join(assetDir, "manifest.json")),
    readFile(path.join(assetDir, "manifest.json.sig")),
    readFile(path.join(assetDir, "root-key.pem")),
    readFile(path.join(assetDir, "signing-key.pem")),
  ]);
  return {
    contract,
    contractSignature,
    delegation,
    delegationSignature,
    manifest,
    manifestSignature,
    rootKey: canonicalPublicKey(rootKey),
    signingKey,
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
