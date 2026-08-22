import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";

const signingDomain = Buffer.from(
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
  const rootPrivateKey = createPrivateKey(rootPrivateKeyPem);
  const rootPublicKey = canonicalPublicKey(createPublicKey(rootPrivateKey));
  const authorization = validateAuthorization({
    candidateVersion,
    distribution,
    kind: "enoki-trust-epoch-migration-authorization",
    legacyRelease,
    migrationGeneration: 1,
    purpose: "release-baseline-migration",
    rootKeyId: sha256(rootPublicKey),
    schemaVersion: 1,
    targetRootKeyId: sha256(rootPublicKey),
  });
  const bytes = canonicalBytes(authorization);
  return {
    authorization,
    bytes,
    signature: sign(
      "RSA-SHA256",
      trustEpochMigrationAuthorizationSigningInput(bytes),
      rootPrivateKey,
    ),
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
  const rootPublicKey = canonicalPublicKey(rootPublicKeyPem);
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error("Trust Epoch Migration Authorization is malformed");
  }
  const authorization = validateAuthorization(parsed);
  const canonical = canonicalBytes(authorization);
  if (!Buffer.from(bytes).equals(canonical)) {
    throw new Error(
      "Trust Epoch Migration Authorization must use canonical encoding",
    );
  }
  const rootKeyId = sha256(rootPublicKey);
  if (authorization.candidateVersion !== expectedCandidateVersion) {
    throw new Error(
      "Trust Epoch Migration Authorization candidate version does not match",
    );
  }
  if (
    authorization.distribution !== expectedDistribution ||
    authorization.rootKeyId !== rootKeyId ||
    authorization.targetRootKeyId !== rootKeyId
  ) {
    throw new Error(
      "Trust Epoch Migration Authorization trust binding does not match",
    );
  }
  if (!sameLegacyRelease(authorization.legacyRelease, expectedLegacyRelease)) {
    throw new Error(
      "Trust Epoch Migration Authorization Release Baseline does not match",
    );
  }
  let valid = false;
  try {
    valid = verify(
      "RSA-SHA256",
      trustEpochMigrationAuthorizationSigningInput(canonical),
      rootPublicKey,
      signature,
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new Error(
      "Trust Epoch Migration Authorization root signature does not match",
    );
  }
  return authorization;
}

export function trustEpochMigrationAuthorizationSigningInput(bytes) {
  return Buffer.concat([signingDomain, Buffer.from(bytes)]);
}

function validateAuthorization(value) {
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
  const githubRelease = value.githubRelease;
  assertPlainObject(
    githubRelease,
    "Trust Epoch Migration Authorization GitHub Release",
  );
  assertExactKeys(githubRelease, [
    "id",
    "peeledCommitSha",
    "repository",
    "tag",
    "tagRefSha",
    "targetCommitish",
  ]);
  if (
    !Number.isSafeInteger(githubRelease.id) ||
    githubRelease.id < 1 ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(
      githubRelease.repository ?? "",
    ) ||
    githubRelease.tag !== "v0.1.74" ||
    !tagPattern.test(githubRelease.tag) ||
    !gitObjectPattern.test(githubRelease.tagRefSha ?? "") ||
    !gitObjectPattern.test(githubRelease.peeledCommitSha ?? "") ||
    typeof githubRelease.targetCommitish !== "string" ||
    githubRelease.targetCommitish.length === 0
  ) {
    throw new Error(
      "Trust Epoch Migration Authorization GitHub Release is invalid",
    );
  }
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
      ) {
        throw new Error("Trust Epoch Migration Authorization asset is invalid");
      }
      names.add(asset.name);
      return { name: asset.name, sha256: asset.sha256, size: asset.size };
    })
    .sort((left, right) => compareAscii(left.name, right.name));
  return {
    assets,
    githubRelease: {
      id: githubRelease.id,
      peeledCommitSha: githubRelease.peeledCommitSha,
      repository: githubRelease.repository,
      tag: githubRelease.tag,
      tagRefSha: githubRelease.tagRefSha,
      targetCommitish: githubRelease.targetCommitish,
    },
    hub: { digest: value.hub.digest, image: value.hub.image },
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

function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function canonicalPublicKey(value) {
  try {
    const publicKey = value?.type === "public" ? value : createPublicKey(value);
    return Buffer.from(publicKey.export({ format: "pem", type: "spki" }));
  } catch {
    throw new Error(
      "Trust Epoch Migration Authorization root public key is malformed",
    );
  }
}

function compareAscii(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertPlainObject(value, description) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} is malformed`);
  }
}

function assertExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) {
    throw new Error(
      "Trust Epoch Migration Authorization contains unexpected fields",
    );
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
