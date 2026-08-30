import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";

const probeTrustDelegationDomain = Buffer.from(
  "enoki/probe-trust-delegation/v1\0",
  "utf8",
);

export function createProbeTrustDelegation({
  distribution,
  generation,
  purpose = "probe-asset-signing",
  releasePublicKeyPem,
  rootPrivateKey,
  rootPrivateKeyPem,
}) {
  const hasKeyObject = rootPrivateKey !== undefined;
  const hasPem = rootPrivateKeyPem !== undefined;
  if (hasKeyObject === hasPem) {
    throw new Error("exactly one root private key representation is required");
  }
  if (hasKeyObject && rootPrivateKey?.type !== "private") {
    throw new Error("root private key must be a KeyObject");
  }
  const signingKey = hasKeyObject
    ? rootPrivateKey
    : createPrivateKey(rootPrivateKeyPem);
  assertRsa4096PrivateKey(signingKey, "Probe Distribution Trust Root");
  const rootPublicKeyPem = canonicalRsa4096PublicKeyPem(
    createPublicKey(signingKey).export({ format: "pem", type: "spki" }),
    "Probe Distribution Trust Root public key",
  );
  const releasePublicKey = canonicalRsa4096PublicKeyPem(
    releasePublicKeyPem,
    "Probe asset signing public key",
  );
  const delegation = validateProbeTrustDelegationDocument({
    distribution,
    generation,
    kind: "enoki-probe-trust-delegation",
    purpose,
    rootKeyId: sha256(rootPublicKeyPem),
    schemaVersion: 1,
    signingIdentity: {
      algorithm: "rsa-sha256",
      keyId: sha256(releasePublicKey),
      publicKeyPem: releasePublicKey.toString("utf8"),
    },
  });
  const bytes = canonicalProbeTrustDelegationBytes(delegation);
  return {
    bytes,
    delegation,
    signature: sign(
      "RSA-SHA256",
      trustDelegationSigningInput(bytes),
      signingKey,
    ),
  };
}

export function verifyProbeTrustDelegation({
  bytes,
  expectedDistribution,
  expectedPurpose = "probe-asset-signing",
  highestAcceptedGeneration = 0,
  rootPublicKeyPem,
  signature,
}) {
  if (
    !Number.isSafeInteger(highestAcceptedGeneration) ||
    highestAcceptedGeneration < 0
  ) {
    throw new Error(
      "highest accepted Probe Trust Delegation generation is invalid",
    );
  }
  const rootPublicKey = canonicalRsa4096PublicKeyPem(
    rootPublicKeyPem,
    "Probe Distribution Trust Root public key",
  );
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error("Probe Trust Delegation is malformed");
  }
  const delegation = validateProbeTrustDelegationDocument(parsed);
  const canonicalBytes = canonicalProbeTrustDelegationBytes(delegation);
  if (!Buffer.from(bytes).equals(canonicalBytes)) {
    throw new Error("Probe Trust Delegation must use canonical encoding");
  }
  if (
    delegation.distribution !== expectedDistribution ||
    delegation.purpose !== expectedPurpose ||
    delegation.rootKeyId !== sha256(rootPublicKey)
  ) {
    throw new Error("Probe Trust Delegation binding is invalid");
  }
  if (delegation.generation < highestAcceptedGeneration) {
    throw new Error(
      "Probe Trust Delegation generation is not newer than installed trust",
    );
  }
  let valid = false;
  try {
    valid = verify(
      "RSA-SHA256",
      trustDelegationSigningInput(canonicalBytes),
      rootPublicKey,
      signature,
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new Error("Probe Trust Delegation root signature is invalid");
  }
  return delegation;
}

export function canonicalPublicKeyPem(publicKeyPem) {
  try {
    return Buffer.from(
      createPublicKey(publicKeyPem).export({ format: "pem", type: "spki" }),
      "utf8",
    );
  } catch {
    throw new Error("Probe Trust Delegation public key is malformed");
  }
}

function canonicalRsa4096PublicKeyPem(publicKeyPem, description) {
  const key = rsa4096PublicKey(publicKeyPem, description);
  return Buffer.from(key.export({ format: "pem", type: "spki" }), "utf8");
}

function rsa4096PublicKey(publicKeyPem, description) {
  let key;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    throw new Error(`${description} is malformed`);
  }
  if (
    key.asymmetricKeyType !== "rsa" ||
    key.asymmetricKeyDetails?.modulusLength !== 4096
  ) {
    throw new Error(`${description} must be RSA-4096`);
  }
  return key;
}

function assertRsa4096PrivateKey(privateKey, description) {
  if (
    privateKey?.type !== "private" ||
    privateKey.asymmetricKeyType !== "rsa" ||
    privateKey.asymmetricKeyDetails?.modulusLength !== 4096
  ) {
    throw new Error(`${description} must be an RSA-4096 private key`);
  }
}

function validateProbeTrustDelegationDocument(value) {
  assertPlainObject(value, "Probe Trust Delegation");
  assertExactKeys(value, [
    "distribution",
    "generation",
    "kind",
    "purpose",
    "rootKeyId",
    "schemaVersion",
    "signingIdentity",
  ]);
  if (
    value.kind !== "enoki-probe-trust-delegation" ||
    value.schemaVersion !== 1 ||
    typeof value.distribution !== "string" ||
    !/^[a-z][a-z0-9-]{0,63}$/.test(value.distribution) ||
    value.purpose !== "probe-asset-signing" ||
    !Number.isSafeInteger(value.generation) ||
    value.generation < 1 ||
    !/^[0-9a-f]{64}$/.test(value.rootKeyId)
  ) {
    throw new Error("Probe Trust Delegation fields are invalid");
  }
  assertPlainObject(
    value.signingIdentity,
    "Probe Trust Delegation signing identity",
  );
  assertExactKeys(value.signingIdentity, [
    "algorithm",
    "keyId",
    "publicKeyPem",
  ]);
  const publicKey = canonicalRsa4096PublicKeyPem(
    value.signingIdentity.publicKeyPem,
    "Probe Trust Delegation signing identity",
  );
  if (
    value.signingIdentity.algorithm !== "rsa-sha256" ||
    !/^[0-9a-f]{64}$/.test(value.signingIdentity.keyId) ||
    value.signingIdentity.keyId !== sha256(publicKey)
  ) {
    throw new Error("Probe Trust Delegation signing identity is invalid");
  }
  return {
    distribution: value.distribution,
    generation: value.generation,
    kind: value.kind,
    purpose: value.purpose,
    rootKeyId: value.rootKeyId,
    schemaVersion: value.schemaVersion,
    signingIdentity: {
      algorithm: value.signingIdentity.algorithm,
      keyId: value.signingIdentity.keyId,
      publicKeyPem: publicKey.toString("utf8"),
    },
  };
}

function canonicalProbeTrustDelegationBytes(delegation) {
  return Buffer.from(`${JSON.stringify(delegation)}\n`, "utf8");
}

function trustDelegationSigningInput(bytes) {
  return Buffer.concat([probeTrustDelegationDomain, bytes]);
}

function assertPlainObject(value, description) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
}

function assertExactKeys(value, expectedKeys) {
  const actualKeys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expected)) {
    throw new Error(`manifest fields must be exactly: ${expected.join(", ")}`);
  }
}

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}
