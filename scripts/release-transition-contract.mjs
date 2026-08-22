import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";

import { verifyProbeTrustDelegation } from "./release-candidate-lib.mjs";
import { verifyTrustEpochMigrationAuthorization } from "./trust-epoch-migration-lib.mjs";

const signingDomain = Buffer.from(
  "enoki/release-transition-contract/v1\0",
  "utf8",
);
const digestPattern = /^[0-9a-f]{64}$/;
const semverPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const probeTargets = Object.freeze([
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
]);

export function createReleaseTransitionContract(input) {
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
  const target = parseTargetManifest(input.targetManifestBytes);
  if (
    target.version !== input.targetVersion ||
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
  const contract = validateContract({
    candidateCommit: input.candidateCommit,
    distribution: authorization.distribution,
    kind: "enoki-release-transition-contract",
    migrationAuthorizationSha256: sha256(input.authorizationBytes),
    migrationGeneration: authorization.migrationGeneration,
    rootKeyId: authorization.rootKeyId,
    schemaVersion: 1,
    source: {
      assets: authorization.legacyRelease.assets,
      commit: authorization.legacyRelease.githubRelease.peeledCommitSha,
      hubDigest: authorization.legacyRelease.hub.digest,
      hubImage: authorization.legacyRelease.hub.image,
      legacySigningKeySha256:
        authorization.legacyRelease.legacySigningKeySha256,
      releaseId: authorization.legacyRelease.githubRelease.id,
      repository: authorization.legacyRelease.githubRelease.repository,
      tag: authorization.legacyRelease.githubRelease.tag,
      tagRefSha: authorization.legacyRelease.githubRelease.tagRefSha,
      targetCommitish:
        authorization.legacyRelease.githubRelease.targetCommitish,
    },
    target: {
      assetClosure: target.assets,
      assetSetManifestSha256: sha256(input.targetManifestBytes),
      delegationGeneration: delegation.generation,
      signingKeyId: delegation.signingIdentity.keyId,
      version: input.targetVersion,
    },
    transition: "replacement-required",
  });
  const bytes = canonicalBytes(contract);
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

export function verifyReleaseTransitionContract({
  authorizationBytes,
  authorizationSignature,
  contractBytes,
  contractSignature,
  expected,
  rootPublicKeyPem,
}) {
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
  if (
    expected &&
    (contract.candidateCommit !== expected.candidateCommit ||
      contract.target.delegationGeneration !== expected.delegationGeneration ||
      contract.source.commit !== expected.sourceCommit ||
      contract.source.tag !== expected.sourceTag ||
      contract.target.assetSetManifestSha256 !==
        expected.targetAssetSetManifestSha256 ||
      contract.target.version !== expected.targetVersion)
  ) {
    throw new Error("Release Transition Contract candidate does not match");
  }
  return contract;
}

export function releaseTransitionContractSigningInput(bytes) {
  return Buffer.concat([signingDomain, Buffer.from(bytes)]);
}

function validateContract(value) {
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
    "assets",
    "commit",
    "hubDigest",
    "hubImage",
    "legacySigningKeySha256",
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
    !/^[0-9a-f]{40}$/.test(value.source.commit ?? "") ||
    !/^sha256:[0-9a-f]{64}$/.test(value.source.hubDigest ?? "") ||
    !Array.isArray(value.source.assets) ||
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
  return JSON.parse(JSON.stringify(value));
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
      asset.target !== target
    ) {
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
