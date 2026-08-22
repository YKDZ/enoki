import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";

const contractDomain = Buffer.from(
  "enoki/release-transition-contract/v1\0",
  "utf8",
);
const digestPattern = /^[0-9a-f]{64}$/;
const semverPattern = /^(?:0|[1-9]\d*)[.](?:0|[1-9]\d*)[.](?:0|[1-9]\d*)$/;
const probeTargets = Object.freeze([
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
]);

export function createReleaseTransitionContract(input) {
  const rootPrivateKey = createPrivateKey(input.rootPrivateKeyPem);
  const rootPublicKey = canonicalPublicKey(createPublicKey(rootPrivateKey));
  const manifest = parseManifest(input.targetManifestBytes);
  const contract = validateContract({
    distribution: input.distribution,
    kind: "enoki-release-transition-contract",
    rootKeyId: sha256(rootPublicKey),
    schemaVersion: 1,
    source: { version: input.sourceVersion },
    target: {
      assetClosure: manifest.assets,
      assetSetManifestSha256: sha256(input.targetManifestBytes),
      delegationGeneration: manifest.signature.delegationGeneration,
      signingKeyId: manifest.signature.delegationKeyId,
      version: manifest.version,
    },
    transition: input.transition,
  });
  const bytes = canonicalBytes(contract);

  return {
    bytes,
    contract,
    signature: sign(
      "RSA-SHA256",
      Buffer.concat([contractDomain, bytes]),
      rootPrivateKey,
    ),
  };
}

function validateContract(value) {
  assertPlainObject(value, "Release Transition Contract");
  assertExactKeys(value, [
    "distribution",
    "kind",
    "rootKeyId",
    "schemaVersion",
    "source",
    "target",
    "transition",
  ]);
  assertPlainObject(value.source, "Release Transition Contract source");
  assertExactKeys(value.source, ["version"]);
  assertPlainObject(value.target, "Release Transition Contract target");
  assertExactKeys(value.target, [
    "assetClosure",
    "assetSetManifestSha256",
    "delegationGeneration",
    "signingKeyId",
    "version",
  ]);
  if (
    value.kind !== "enoki-release-transition-contract" ||
    value.schemaVersion !== 1 ||
    !/^[a-z][a-z0-9-]{0,63}$/.test(value.distribution ?? "") ||
    !digestPattern.test(value.rootKeyId ?? "") ||
    !semverPattern.test(value.source.version ?? "") ||
    !semverPattern.test(value.target.version ?? "") ||
    !digestPattern.test(value.target.assetSetManifestSha256 ?? "") ||
    !Number.isSafeInteger(value.target.delegationGeneration) ||
    value.target.delegationGeneration < 1 ||
    !digestPattern.test(value.target.signingKeyId ?? "") ||
    !["compatible", "replacement-required"].includes(value.transition)
  ) {
    throw new Error("Release Transition Contract fields are invalid");
  }

  return {
    distribution: value.distribution,
    kind: value.kind,
    rootKeyId: value.rootKeyId,
    schemaVersion: value.schemaVersion,
    source: { version: value.source.version },
    target: {
      assetClosure: validateAssetClosure(value.target.assetClosure),
      assetSetManifestSha256: value.target.assetSetManifestSha256,
      delegationGeneration: value.target.delegationGeneration,
      signingKeyId: value.target.signingKeyId,
      version: value.target.version,
    },
    transition: value.transition,
  };
}

function parseManifest(bytes) {
  let value;
  try {
    value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error("Probe Asset Set manifest is malformed");
  }
  assertPlainObject(value, "Probe Asset Set manifest");
  assertExactKeys(value, ["assets", "kind", "signature", "version"]);
  assertPlainObject(value.signature, "Probe Asset Set manifest signature");
  assertExactKeys(value.signature, [
    "algorithm",
    "delegationGeneration",
    "delegationKeyId",
    "file",
    "publicKey",
  ]);
  if (
    value.kind !== "enoki-probe-assets" ||
    !semverPattern.test(value.version ?? "") ||
    value.signature.algorithm !== "rsa-sha256" ||
    !Number.isSafeInteger(value.signature.delegationGeneration) ||
    value.signature.delegationGeneration < 1 ||
    !digestPattern.test(value.signature.delegationKeyId ?? "") ||
    value.signature.file !== "manifest.json.sig" ||
    value.signature.publicKey !== "signing-key.pem"
  ) {
    throw new Error("Probe Asset Set manifest transition fields are invalid");
  }
  return {
    assets: validateAssetClosure(value.assets),
    signature: {
      delegationGeneration: value.signature.delegationGeneration,
      delegationKeyId: value.signature.delegationKeyId,
    },
    version: value.version,
  };
}

function validateAssetClosure(value) {
  if (!Array.isArray(value) || value.length !== probeTargets.length) {
    throw new Error("Probe Asset Set asset closure is invalid");
  }
  return value.map((asset, index) => {
    assertPlainObject(asset, "Probe Asset Set asset");
    assertExactKeys(asset, [
      "bundleManifestSha256",
      "file",
      "sha256",
      "size",
      "target",
    ]);
    if (
      !digestPattern.test(asset.bundleManifestSha256 ?? "") ||
      typeof asset.file !== "string" ||
      !asset.file ||
      !digestPattern.test(asset.sha256 ?? "") ||
      !Number.isSafeInteger(asset.size) ||
      asset.size < 0 ||
      asset.target !== probeTargets[index] ||
      asset.file !== `enoki-probe-${probeTargets[index]}.tar.gz`
    ) {
      throw new Error("Probe Asset Set asset closure is invalid");
    }
    return {
      bundleManifestSha256: asset.bundleManifestSha256,
      file: asset.file,
      sha256: asset.sha256,
      size: asset.size,
      target: asset.target,
    };
  });
}

function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function canonicalPublicKey(value) {
  try {
    const publicKey = value?.type === "public" ? value : createPublicKey(value);
    return Buffer.from(publicKey.export({ format: "pem", type: "spki" }));
  } catch {
    throw new Error("Release Transition Contract root key is malformed");
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertPlainObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} is malformed`);
  }
}

function assertExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error("Release Transition Contract fields are invalid");
  }
}
