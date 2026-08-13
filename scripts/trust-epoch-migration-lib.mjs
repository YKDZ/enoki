import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";

const domain = Buffer.from(
  "enoki/trust-epoch-migration-authorization/v1\0",
  "utf8",
);
const sha256Pattern = /^[0-9a-f]{64}$/;
const tagPattern = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const gitObjectPattern = /^[0-9a-f]{40}$/;

export function createTrustEpochMigrationAuthorization({
  candidateVersion,
  distribution,
  legacyRelease,
  rootPrivateKeyPem,
}) {
  const root = createPrivateKey(rootPrivateKeyPem);
  assertRsa4096(root, "Trust Epoch Migration Authorization root private key");
  const rootKeyId = sha256(canonicalPublicKeyPem(createPublicKey(root)));
  const authorization = validateDocument({
    candidateVersion,
    distribution,
    kind: "enoki-trust-epoch-migration-authorization",
    legacyRelease,
    migrationGeneration: 1,
    purpose: "release-baseline-migration",
    rootKeyId,
    schemaVersion: 1,
    targetRootKeyId: rootKeyId,
  });
  const bytes = canonicalBytes(authorization);
  return {
    authorization,
    bytes,
    signature: sign("RSA-SHA256", signingInput(bytes), root),
  };
}

export function verifyTrustEpochMigrationAuthorization({
  bytes,
  expectedCandidateVersion,
  expectedDistribution = "enoki",
  expectedLegacyRelease,
  rootPublicKeyPem,
  signature,
}) {
  const root = canonicalRsa4096PublicKey(rootPublicKeyPem);
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error("Trust Epoch Migration Authorization is malformed");
  }
  const authorization = validateDocument(parsed);
  const canonical = canonicalBytes(authorization);
  if (!Buffer.from(bytes).equals(canonical)) {
    throw new Error(
      "Trust Epoch Migration Authorization must use canonical encoding",
    );
  }
  const rootKeyId = sha256(root);
  if (authorization.candidateVersion !== expectedCandidateVersion) {
    throw new Error(
      "Trust Epoch Migration Authorization candidate version is invalid",
    );
  }
  if (
    authorization.distribution !== expectedDistribution ||
    authorization.rootKeyId !== rootKeyId ||
    authorization.targetRootKeyId !== rootKeyId
  ) {
    throw new Error("Trust Epoch Migration Authorization binding is invalid");
  }
  if (!sameLegacyRelease(authorization.legacyRelease, expectedLegacyRelease)) {
    throw new Error(
      "Trust Epoch Migration Authorization does not bind this Release Baseline",
    );
  }
  let valid = false;
  try {
    valid = verify("RSA-SHA256", signingInput(canonical), root, signature);
  } catch {
    valid = false;
  }
  if (!valid)
    throw new Error(
      "Trust Epoch Migration Authorization root signature is invalid",
    );
  return authorization;
}

export function trustEpochMigrationAuthorizationSigningInput(bytes) {
  return signingInput(bytes);
}

function validateDocument(value) {
  assertPlainObject(value, "Trust Epoch Migration Authorization");
  assertExactKeys(value, [
    "candidateVersion",
    "distribution",
    "kind",
    "legacyRelease",
    "migrationGeneration",
    "purpose",
    "rootKeyId",
    "schemaVersion",
    "targetRootKeyId",
  ]);
  if (
    !tagPattern.test(value.candidateVersion ?? "") ||
    !/^[a-z][a-z0-9-]{0,63}$/.test(value.distribution ?? "") ||
    value.kind !== "enoki-trust-epoch-migration-authorization" ||
    value.migrationGeneration !== 1 ||
    value.purpose !== "release-baseline-migration" ||
    value.schemaVersion !== 1 ||
    !sha256Pattern.test(value.rootKeyId ?? "") ||
    !sha256Pattern.test(value.targetRootKeyId ?? "")
  ) {
    throw new Error("Trust Epoch Migration Authorization fields are invalid");
  }
  return {
    candidateVersion: value.candidateVersion,
    distribution: value.distribution,
    kind: value.kind,
    legacyRelease: validateLegacyRelease(value.legacyRelease),
    migrationGeneration: value.migrationGeneration,
    purpose: value.purpose,
    rootKeyId: value.rootKeyId,
    schemaVersion: value.schemaVersion,
    targetRootKeyId: value.targetRootKeyId,
  };
}

function validateLegacyRelease(value) {
  assertPlainObject(
    value,
    "Trust Epoch Migration Authorization legacy release",
  );
  assertExactKeys(value, [
    "assets",
    "githubRelease",
    "hub",
    "legacySigningKeySha256",
  ]);
  if (!sha256Pattern.test(value.legacySigningKeySha256 ?? "")) {
    throw new Error(
      "Trust Epoch Migration Authorization legacy signing key is invalid",
    );
  }
  assertPlainObject(
    value.githubRelease,
    "Trust Epoch Migration Authorization GitHub Release",
  );
  assertExactKeys(value.githubRelease, [
    "id",
    "peeledCommitSha",
    "repository",
    "tag",
    "tagRefSha",
    "targetCommitish",
  ]);
  if (
    !Number.isSafeInteger(value.githubRelease.id) ||
    value.githubRelease.id < 1 ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(
      value.githubRelease.repository ?? "",
    ) ||
    value.githubRelease.tag !== "v0.1.74" ||
    !gitObjectPattern.test(value.githubRelease.tagRefSha ?? "") ||
    !gitObjectPattern.test(value.githubRelease.peeledCommitSha ?? "") ||
    typeof value.githubRelease.targetCommitish !== "string" ||
    !value.githubRelease.targetCommitish
  )
    throw new Error(
      "Trust Epoch Migration Authorization GitHub Release is invalid",
    );
  assertPlainObject(value.hub, "Trust Epoch Migration Authorization Hub");
  assertExactKeys(value.hub, ["digest", "image"]);
  if (
    !/^ghcr[.]io\/[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(value.hub.image ?? "") ||
    !/^sha256:[0-9a-f]{64}$/.test(value.hub.digest ?? "")
  ) {
    throw new Error("Trust Epoch Migration Authorization Hub is invalid");
  }
  if (!Array.isArray(value.assets) || value.assets.length === 0) {
    throw new Error("Trust Epoch Migration Authorization assets are invalid");
  }
  const names = new Set();
  const assets = value.assets
    .map((asset) => {
      assertPlainObject(asset, "Trust Epoch Migration Authorization asset");
      assertExactKeys(asset, ["name", "sha256", "size"]);
      if (
        typeof asset.name !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(asset.name) ||
        !sha256Pattern.test(asset.sha256 ?? "") ||
        !Number.isSafeInteger(asset.size) ||
        asset.size < 0 ||
        names.has(asset.name)
      )
        throw new Error("Trust Epoch Migration Authorization asset is invalid");
      names.add(asset.name);
      return { name: asset.name, sha256: asset.sha256, size: asset.size };
    })
    .sort((left, right) => compareAscii(left.name, right.name));
  return {
    assets,
    githubRelease: {
      id: value.githubRelease.id,
      peeledCommitSha: value.githubRelease.peeledCommitSha,
      repository: value.githubRelease.repository,
      tag: value.githubRelease.tag,
      tagRefSha: value.githubRelease.tagRefSha,
      targetCommitish: value.githubRelease.targetCommitish,
    },
    hub: {
      digest: value.hub.digest,
      image: value.hub.image,
    },
    legacySigningKeySha256: value.legacySigningKeySha256,
  };
}

function sameLegacyRelease(left, right) {
  try {
    return (
      JSON.stringify(left) === JSON.stringify(validateLegacyRelease(right))
    );
  } catch {
    return false;
  }
}

function canonicalBytes(authorization) {
  return Buffer.from(`${JSON.stringify(authorization)}\n`, "utf8");
}

function compareAscii(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function signingInput(bytes) {
  return Buffer.concat([domain, Buffer.from(bytes)]);
}

function canonicalRsa4096PublicKey(value) {
  let key;
  try {
    key = createPublicKey(value);
  } catch {
    throw new Error(
      "Trust Epoch Migration Authorization root public key is malformed",
    );
  }
  assertRsa4096(key, "Trust Epoch Migration Authorization root public key");
  return canonicalPublicKeyPem(key);
}

function canonicalPublicKeyPem(key) {
  return Buffer.from(key.export({ format: "pem", type: "spki" }), "utf8");
}

function assertRsa4096(key, description) {
  if (
    key.asymmetricKeyType !== "rsa" ||
    key.asymmetricKeyDetails?.modulusLength !== 4096
  ) {
    throw new Error(`${description} must be RSA-4096`);
  }
}

function assertPlainObject(value, description) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error(`${description} is malformed`);
}

function assertExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort()))
    throw new Error(
      "Trust Epoch Migration Authorization contains unexpected fields",
    );
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
