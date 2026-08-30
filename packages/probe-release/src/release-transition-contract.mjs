import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

import { inspectLegacyProbeAssetSet } from "./legacy-probe-asset-set.mjs";
import {
  inspectProbeBundleArchiveBytes,
  probeTargets,
} from "./probe-asset-bundle.mjs";
import { verifyProbeTrustDelegation } from "./probe-trust-delegation.mjs";
import { readRegularFileSnapshot } from "./regular-file-snapshot.mjs";
import { verifyTrustEpochMigrationAuthorization } from "./trust-epoch-migration-lib.mjs";

const signingDomain = Buffer.from(
  "enoki/release-transition-contract/v1\0",
  "utf8",
);
const digestPattern = /^[0-9a-f]{64}$/;
const semverPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const MAX_CONTRACT_BYTES = 64 * 1024;
const MAX_SIGNATURE_BYTES = 1024;
const MAX_TARGET_BUNDLE_BYTES = 1024 * 1024 * 1024;
const MAX_TARGET_CLOSURE_BYTES = 4 * 1024 * 1024 * 1024;

export async function createReleaseTransitionContract(input) {
  const authorization = verifyTrustEpochMigrationAuthorization({
    bytes: input.authorizationBytes,
    expectedCandidateVersion: `v${input.targetVersion}`,
    expectedLegacyRelease: input.legacyRelease,
    rootPublicKeyPem: input.rootPublicKeyPem,
    signature: input.authorizationSignature,
  });
  const delegation = verifyProbeTrustDelegation({
    bytes: input.delegationBytes,
    expectedDistribution: authorization.distribution,
    rootPublicKeyPem: input.rootPublicKeyPem,
    signature: input.delegationSignature,
  });
  const target = await inspectTargetProbeAssetSet(input.targetAssetDir, {
    delegationBytes: input.delegationBytes,
    delegationSignature: input.delegationSignature,
    delegationSigningKeyId: delegation.signingIdentity.keyId,
    delegationSigningPublicKeyPem: delegation.signingIdentity.publicKeyPem,
    bundledBootstrap: {
      distribution: authorization.distribution,
      rootKeyId: authorization.rootKeyId,
    },
    rootPublicKeyPem: input.rootPublicKeyPem,
    targetVersion: input.targetVersion,
  });
  if (
    target.delegationGeneration !== delegation.generation ||
    target.signingKeyId !== delegation.signingIdentity.keyId
  ) {
    throw new Error("Release Transition Contract target does not match");
  }
  const rootPrivateKey = createPrivateKey(input.rootPrivateKeyPem);
  if (
    sha256(canonicalPublicKey(createPublicKey(rootPrivateKey))) !==
    authorization.rootKeyId
  ) {
    throw new Error("Release Transition Contract root identity does not match");
  }
  if (typeof input.sourceAssetDir !== "string" || !input.sourceAssetDir) {
    throw new Error(
      "Release Transition Contract source Probe asset closure is required",
    );
  }
  const sourceAssetSet = await inspectLegacyProbeAssetSet(
    input.sourceAssetDir,
    {
      expectedAssets: authorization.legacyRelease.assets,
      expectedSigningKeySha256:
        authorization.legacyRelease.legacySigningKeySha256,
      expectedVersion: authorization.legacyRelease.githubRelease.tag.slice(1),
    },
  );
  const contract = validateContract({
    candidateCommit: input.candidateCommit,
    distribution: authorization.distribution,
    kind: "enoki-release-transition-contract",
    migrationAuthorizationSha256: sha256(input.authorizationBytes),
    migrationGeneration: authorization.migrationGeneration,
    rootKeyId: authorization.rootKeyId,
    schemaVersion: 1,
    source: {
      assetSetManifestSha256: sourceAssetSet.assetSetManifestSha256,
      assets: authorization.legacyRelease.assets,
      commit: authorization.legacyRelease.githubRelease.peeledCommitSha,
      hubDigest: authorization.legacyRelease.hub.digest,
      hubImage: authorization.legacyRelease.hub.image,
      legacySigningKeySha256:
        authorization.legacyRelease.legacySigningKeySha256,
      probeComponents: sourceAssetSet.probeComponents,
      releaseId: authorization.legacyRelease.githubRelease.id,
      repository: authorization.legacyRelease.githubRelease.repository,
      tag: authorization.legacyRelease.githubRelease.tag,
      tagRefSha: authorization.legacyRelease.githubRelease.tagRefSha,
      targetCommitish:
        authorization.legacyRelease.githubRelease.targetCommitish,
    },
    target: {
      assetClosure: target.assets,
      assetSetManifestSha256: target.assetSetManifestSha256,
      delegationGeneration: delegation.generation,
      probeComponents: target.probeComponents,
      signingKeyId: delegation.signingIdentity.keyId,
      version: input.targetVersion,
    },
    transition: "replacement-required",
  });
  const bytes = canonicalBytes(contract);
  assertBoundedBytes(bytes, MAX_CONTRACT_BYTES, "contract");
  return {
    bytes,
    contract,
    signature: sign(
      "RSA-SHA256",
      releaseTransitionContractSigningInput(bytes),
      rootPrivateKey,
    ),
  };
}

async function inspectTargetProbeAssetSet(assetDir, input) {
  if (typeof assetDir !== "string" || !assetDir) {
    throw new Error(
      "Release Transition Contract target Probe asset closure is required",
    );
  }
  const expectedFiles = [
    ...probeTargets.flatMap((target) => {
      const archive = `enoki-probe-${target}.tar.gz`;
      return [archive, `${archive}.sha256`];
    }),
    "manifest.json",
    "manifest.json.sig",
    "root-key.pem",
    "signing-key.pem",
    "trust-delegation.json",
    "trust-delegation.json.sig",
  ].sort();
  const actualFiles = (await readdir(assetDir)).sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(
      "Release Transition Contract target Probe asset closure is invalid",
    );
  }
  const [
    manifestBytes,
    manifestSignature,
    rootKey,
    signingKey,
    delegationBytes,
    delegationSignature,
  ] = await Promise.all([
    readFile(path.join(assetDir, "manifest.json")),
    readFile(path.join(assetDir, "manifest.json.sig")),
    readFile(path.join(assetDir, "root-key.pem")),
    readFile(path.join(assetDir, "signing-key.pem")),
    readFile(path.join(assetDir, "trust-delegation.json")),
    readFile(path.join(assetDir, "trust-delegation.json.sig")),
  ]);
  const root = canonicalPublicKey(createPublicKey(input.rootPublicKeyPem));
  const expectedSigningKey = canonicalPublicKey(
    createPublicKey(input.delegationSigningPublicKeyPem),
  );
  const actualSigningKey = canonicalPublicKey(createPublicKey(signingKey));
  if (
    !canonicalPublicKey(createPublicKey(rootKey)).equals(root) ||
    !actualSigningKey.equals(expectedSigningKey) ||
    sha256(actualSigningKey) !== input.delegationSigningKeyId ||
    !delegationBytes.equals(Buffer.from(input.delegationBytes)) ||
    !delegationSignature.equals(Buffer.from(input.delegationSignature)) ||
    !verify("RSA-SHA256", manifestBytes, actualSigningKey, manifestSignature)
  ) {
    throw new Error(
      "Release Transition Contract target Probe asset closure is invalid",
    );
  }
  const target = parseTargetManifest(manifestBytes);
  if (
    target.version !== input.targetVersion ||
    target.signingKeyId !== input.delegationSigningKeyId
  ) {
    throw new Error("Release Transition Contract target does not match");
  }
  const probeComponents = [];
  for (let index = 0; index < probeTargets.length; index += 1) {
    const targetName = probeTargets[index];
    const asset = target.assets[index];
    const file = `enoki-probe-${targetName}.tar.gz`;
    if (asset.file !== file || asset.target !== targetName) {
      throw new Error(
        "Release Transition Contract target Probe asset closure is invalid",
      );
    }
    const archivePath = path.join(assetDir, file);
    const archive = await readRegularFileSnapshot(
      archivePath,
      "Release Transition Contract target Probe archive",
    ).catch(() => {
      throw new Error(
        "Release Transition Contract target Probe asset closure is invalid",
      );
    });
    if (
      archive.size !== asset.size ||
      sha256(archive.bytes) !== asset.sha256 ||
      (await readFile(`${archivePath}.sha256`, "utf8")) !==
        `${asset.sha256}  ${file}\n`
    ) {
      throw new Error(
        "Release Transition Contract target Probe asset closure is invalid",
      );
    }
    const inspectedBundle = await inspectProbeBundleArchiveBytes(
      archive.bytes,
      {
        bundledBootstrap: input.bundledBootstrap,
        target: targetName,
        version: `v${target.version}`,
      },
    );
    if (inspectedBundle.bundleManifestSha256 !== asset.bundleManifestSha256) {
      throw new Error(
        "Release Transition Contract target Probe asset closure is invalid",
      );
    }
    probeComponents.push({
      file: "enoki-probe",
      role: "probe",
      sha256: inspectedBundle.probeSha256,
      target: targetName,
    });
  }
  return {
    ...target,
    assetSetManifestSha256: sha256(manifestBytes),
    probeComponents,
  };
}

export function verifyReleaseTransitionContract({
  authorizationBytes,
  authorizationSignature,
  contractBytes,
  contractSignature,
  expected,
  rootPublicKeyPem,
}) {
  assertBoundedBytes(contractBytes, MAX_CONTRACT_BYTES, "contract");
  assertBoundedBytes(contractSignature, MAX_SIGNATURE_BYTES, "signature");
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(contractBytes).toString("utf8"));
  } catch {
    throw new Error("Release Transition Contract is malformed");
  }
  const contract = validateContract(parsed);
  const canonical = canonicalBytes(contract);
  if (!Buffer.from(contractBytes).equals(canonical)) {
    throw new Error("Release Transition Contract encoding does not match");
  }
  if (
    !verify(
      "RSA-SHA256",
      releaseTransitionContractSigningInput(canonical),
      createPublicKey(rootPublicKeyPem),
      contractSignature,
    )
  ) {
    throw new Error(
      "Release Transition Contract root signature does not match",
    );
  }
  if (!isMigrationContract(contract)) {
    if (
      contract.rootKeyId !==
      sha256(canonicalPublicKey(createPublicKey(rootPublicKeyPem)))
    ) {
      throw new Error(
        "Release Transition Contract root identity does not match",
      );
    }
    if (expected && !matchesExpectedContract(contract, expected)) {
      throw new Error("Release Transition Contract candidate does not match");
    }
    return contract;
  }
  const authorization = verifyTrustEpochMigrationAuthorization({
    bytes: authorizationBytes,
    expectedCandidateVersion: `v${contract.target.version}`,
    expectedLegacyRelease: {
      assets: contract.source.assets,
      githubRelease: {
        id: contract.source.releaseId,
        peeledCommitSha: contract.source.commit,
        repository: contract.source.repository,
        tag: contract.source.tag,
        tagRefSha: contract.source.tagRefSha,
        targetCommitish: contract.source.targetCommitish,
      },
      hub: {
        digest: contract.source.hubDigest,
        image: contract.source.hubImage,
      },
      legacySigningKeySha256: contract.source.legacySigningKeySha256,
    },
    rootPublicKeyPem,
    signature: authorizationSignature,
  });
  if (
    contract.migrationAuthorizationSha256 !== sha256(authorizationBytes) ||
    contract.migrationGeneration !== authorization.migrationGeneration ||
    contract.distribution !== authorization.distribution ||
    contract.rootKeyId !== authorization.rootKeyId
  ) {
    throw new Error("Release Transition Contract authorization does not match");
  }
  if (expected && !matchesExpectedContract(contract, expected)) {
    throw new Error("Release Transition Contract candidate does not match");
  }
  return contract;
}

function matchesExpectedContract(contract, expected) {
  const comparisons = [
    ["candidateCommit", contract.candidateCommit],
    ["classification", contract.transition],
    ["delegationGeneration", contract.target.delegationGeneration],
    ["sourceCommit", contract.source.commit],
    ["sourceTag", contract.source.tag],
    ["sourceVersion", contract.source.version],
    ["targetAssetSetManifestSha256", contract.target.assetSetManifestSha256],
    ["targetAssetClosure", contract.target.assetClosure],
    ["targetVersion", contract.target.version],
  ];
  return comparisons.every(([name, actual]) => {
    if (expected[name] === undefined) return true;
    if (actual === undefined) return false;
    return typeof actual === "object"
      ? JSON.stringify(expected[name]) === JSON.stringify(actual)
      : expected[name] === actual;
  });
}

export function releaseTransitionContractSigningInput(bytes) {
  return Buffer.concat([signingDomain, Buffer.from(bytes)]);
}

export function preflightReleaseMigrationConfiguration({
  authorization,
  authorizationSignatureBase64,
  candidateCommit,
  candidateVersion,
  contract,
  contractSignatureBase64,
  rootPublicKeyPem,
}) {
  const contractValues = [contract, contractSignatureBase64];
  const contractConfigured = contractValues.filter(
    (value) => typeof value === "string" && value.length > 0,
  ).length;
  if (contractConfigured !== contractValues.length) {
    throw new Error(
      "Release Transition Contract must be provided as one complete closure",
    );
  }
  const authorizationValues = [authorization, authorizationSignatureBase64];
  const authorizationConfigured = authorizationValues.filter(
    (value) => typeof value === "string" && value.length > 0,
  ).length;
  if (authorizationConfigured !== 0 && authorizationConfigured !== 2) {
    throw new Error(
      "Release migration authorization must be provided as one complete closure",
    );
  }
  if (
    (authorizationConfigured === 2 &&
      Buffer.byteLength(authorization) > MAX_CONTRACT_BYTES) ||
    Buffer.byteLength(contract) > MAX_CONTRACT_BYTES
  ) {
    throw new Error("Release migration public configuration is invalid");
  }
  const contractBytes = Buffer.from(contract);
  const migrationContract =
    parsedContractUsesMigrationAuthorization(contractBytes);
  return verifyReleaseTransitionContract({
    ...(authorizationConfigured === 2
      ? {
          authorizationBytes: Buffer.from(authorization),
          authorizationSignature: decodeBoundedBase64(
            authorizationSignatureBase64,
            "authorization signature",
          ),
        }
      : {}),
    contractBytes,
    contractSignature: decodeBoundedBase64(
      contractSignatureBase64,
      "contract signature",
    ),
    expected: {
      candidateCommit,
      ...(migrationContract ? { sourceTag: "v0.1.74" } : {}),
      targetVersion: candidateVersion.replace(/^v/, ""),
    },
    rootPublicKeyPem,
  });
}

function parsedContractUsesMigrationAuthorization(contractBytes) {
  try {
    return isMigrationContract(
      JSON.parse(Buffer.from(contractBytes).toString("utf8")),
    );
  } catch {
    return false;
  }
}

function decodeBoundedBase64(value, description) {
  if (
    typeof value !== "string" ||
    value.length < 4 ||
    value.length > 2048 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new Error(`Release migration ${description} is invalid`);
  }
  const bytes = Buffer.from(value, "base64");
  assertBoundedBytes(bytes, MAX_SIGNATURE_BYTES, description);
  if (bytes.toString("base64") !== value) {
    throw new Error(`Release migration ${description} is invalid`);
  }
  return bytes;
}

function validateContract(value) {
  if (!isMigrationContract(value)) {
    return validateGenericContract(value);
  }
  assertPlainObject(value, "Release Transition Contract");
  assertExactKeys(value, [
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
  ]);
  assertPlainObject(value.source, "Release Transition Contract source");
  assertExactKeys(value.source, [
    "assetSetManifestSha256",
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
  ]);
  assertPlainObject(value.target, "Release Transition Contract target");
  assertExactKeys(value.target, [
    "assetClosure",
    "assetSetManifestSha256",
    "delegationGeneration",
    "probeComponents",
    "signingKeyId",
    "version",
  ]);
  if (
    value.kind !== "enoki-release-transition-contract" ||
    value.schemaVersion !== 1 ||
    value.transition !== "replacement-required" ||
    !/^[0-9a-f]{40}$/.test(value.candidateCommit ?? "") ||
    !/^[a-z][a-z0-9-]{0,63}$/.test(value.distribution ?? "") ||
    !digestPattern.test(value.migrationAuthorizationSha256 ?? "") ||
    !digestPattern.test(value.rootKeyId ?? "") ||
    value.migrationGeneration !== 1 ||
    value.source.tag !== "v0.1.74" ||
    !digestPattern.test(value.source.assetSetManifestSha256 ?? "") ||
    !/^[0-9a-f]{40}$/.test(value.source.commit ?? "") ||
    !/^sha256:[0-9a-f]{64}$/.test(value.source.hubDigest ?? "") ||
    !Array.isArray(value.source.assets) ||
    !Array.isArray(value.source.probeComponents) ||
    !Array.isArray(value.target.probeComponents) ||
    !semverPattern.test(value.target.version ?? "") ||
    !digestPattern.test(value.target.assetSetManifestSha256 ?? "") ||
    !Number.isSafeInteger(value.target.delegationGeneration) ||
    value.target.delegationGeneration < 1 ||
    !digestPattern.test(value.target.signingKeyId ?? "") ||
    !Array.isArray(value.target.assetClosure)
  ) {
    throw new Error("Release Transition Contract fields are invalid");
  }
  validateAssetClosure(value.target.assetClosure);
  validateProbeComponents(value.source.probeComponents, "source");
  validateProbeComponents(value.target.probeComponents, "target");
  return JSON.parse(JSON.stringify(value));
}

function validateGenericContract(value) {
  assertPlainObject(value, "Release Transition Contract");
  assertExactKeys(value, [
    "candidateCommit",
    "distribution",
    "kind",
    "rootKeyId",
    "schemaVersion",
    "source",
    "target",
    "transition",
  ]);
  assertPlainObject(value.source, "Release Transition Contract source");
  assertExactKeys(value.source, [
    "assetSetManifestSha256",
    "probeComponents",
    "version",
  ]);
  assertPlainObject(value.target, "Release Transition Contract target");
  assertExactKeys(value.target, [
    "assetClosure",
    "assetSetManifestSha256",
    "delegationGeneration",
    "probeComponents",
    "signingKeyId",
    "version",
  ]);
  if (
    value.kind !== "enoki-release-transition-contract" ||
    value.schemaVersion !== 1 ||
    !["compatible", "replacement-required"].includes(value.transition) ||
    !/^[0-9a-f]{40}$/.test(value.candidateCommit ?? "") ||
    !/^[a-z][a-z0-9-]{0,63}$/.test(value.distribution ?? "") ||
    !digestPattern.test(value.rootKeyId ?? "") ||
    !digestPattern.test(value.source.assetSetManifestSha256 ?? "") ||
    !semverPattern.test(value.source.version ?? "") ||
    !semverPattern.test(value.target.version ?? "") ||
    !digestPattern.test(value.target.assetSetManifestSha256 ?? "") ||
    !Number.isSafeInteger(value.target.delegationGeneration) ||
    value.target.delegationGeneration < 1 ||
    !digestPattern.test(value.target.signingKeyId ?? "")
  ) {
    throw new Error("Release Transition Contract fields are invalid");
  }
  validateProbeComponents(value.source.probeComponents, "source");
  validateProbeComponents(value.target.probeComponents, "target");
  validateAssetClosure(value.target.assetClosure);
  return JSON.parse(JSON.stringify(value));
}

function isMigrationContract(value) {
  return Object.hasOwn(value ?? {}, "migrationAuthorizationSha256");
}

function validateProbeComponents(value, side) {
  if (!Array.isArray(value) || value.length !== probeTargets.length) {
    throw new Error(
      `Release Transition Contract ${side} Probe closure is invalid`,
    );
  }
  return value.map((component, index) => {
    const target = probeTargets[index];
    assertPlainObject(component, `Release Transition Contract ${side} Probe`);
    assertExactKeys(component, ["file", "role", "sha256", "target"]);
    if (
      component.file !== "enoki-probe" ||
      component.role !== "probe" ||
      !digestPattern.test(component.sha256 ?? "") ||
      component.target !== target
    ) {
      throw new Error(
        `Release Transition Contract ${side} Probe closure is invalid`,
      );
    }
    return {
      file: "enoki-probe",
      role: "probe",
      sha256: component.sha256,
      target,
    };
  });
}

function parseTargetManifest(bytes) {
  let value;
  try {
    value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error("Release Transition Contract target manifest is malformed");
  }
  assertPlainObject(value, "Release Transition Contract target manifest");
  assertPlainObject(
    value.signature,
    "Release Transition Contract target signature",
  );
  if (
    value.kind !== "enoki-probe-assets" ||
    !semverPattern.test(value.version ?? "") ||
    !Number.isSafeInteger(value.signature.delegationGeneration) ||
    value.signature.delegationGeneration < 1 ||
    !digestPattern.test(value.signature.delegationKeyId ?? "") ||
    !Array.isArray(value.assets)
  ) {
    throw new Error("Release Transition Contract target does not match");
  }
  return {
    assets: validateAssetClosure(value.assets),
    delegationGeneration: value.signature.delegationGeneration,
    signingKeyId: value.signature.delegationKeyId,
    version: value.version,
  };
}

function validateAssetClosure(value) {
  if (!Array.isArray(value) || value.length !== probeTargets.length) {
    throw new Error("Release Transition Contract Bundle closure is invalid");
  }
  let closureBytes = 0;
  return value.map((asset, index) => {
    assertPlainObject(asset, "Release Transition Contract Bundle");
    assertExactKeys(asset, [
      "bundleManifestSha256",
      "file",
      "sha256",
      "size",
      "target",
    ]);
    const target = probeTargets[index];
    if (
      !digestPattern.test(asset.bundleManifestSha256 ?? "") ||
      asset.file !== `enoki-probe-${target}.tar.gz` ||
      !digestPattern.test(asset.sha256 ?? "") ||
      !Number.isSafeInteger(asset.size) ||
      asset.size < 0 ||
      asset.size > MAX_TARGET_BUNDLE_BYTES ||
      asset.target !== target
    ) {
      throw new Error("Release Transition Contract Bundle closure is invalid");
    }
    closureBytes += asset.size;
    if (closureBytes > MAX_TARGET_CLOSURE_BYTES) {
      throw new Error("Release Transition Contract Bundle closure is invalid");
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

function assertBoundedBytes(value, maximum, description) {
  const length = Buffer.isBuffer(value)
    ? value.byteLength
    : value instanceof Uint8Array
      ? value.byteLength
      : -1;
  if (length < 1 || length > maximum) {
    throw new Error(`Release Transition Contract ${description} is invalid`);
  }
}

function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function canonicalPublicKey(key) {
  return Buffer.from(key.export({ format: "pem", type: "spki" }));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertPlainObject(value, description) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} is malformed`);
  }
}

function assertExactKeys(value, expected) {
  if (
    JSON.stringify(Object.keys(value).sort()) !==
    JSON.stringify([...expected].sort())
  ) {
    throw new Error("Release Transition Contract fields are invalid");
  }
}
