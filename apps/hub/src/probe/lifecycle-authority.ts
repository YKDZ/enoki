import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from "node:crypto";

const signingDomain = Buffer.from("enoki/lifecycle-upgrade-authority/v1\0");

export type LifecycleAuthorityKeyPair = {
  privateKeyPem: string;
  publicKeyPem: string;
  publicKeySha256: string;
};

export type LifecycleUpgradeAuthority = {
  schemaVersion: 1;
  hubOrigin: string;
  hostId: string;
  probeId: string;
  operationId: string;
  sourceBundleVersion: string;
  sourceInstallStateSha256: string;
  sourceManifestSha256: string;
  targetBundleVersion: string;
  targetAssetSetDigest: string;
  targetManifestSha256: string;
  verifiedStageSha256: string;
  expiresAtMs: number;
};

export function canonicalLifecycleUpgradeAuthority(
  authority: LifecycleUpgradeAuthority,
) {
  return Buffer.from(JSON.stringify(authority), "utf8");
}

export function generateLifecycleAuthorityKeyPair(): LifecycleAuthorityKeyPair {
  const pair = generateKeyPairSync("rsa", {
    modulusLength: 3072,
    publicExponent: 0x10001,
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  return lifecycleAuthorityKeyPair(pair.privateKey, pair.publicKey);
}

export function lifecycleAuthorityKeyPair(
  privateKeyPem: string,
  publicKeyPem: string,
): LifecycleAuthorityKeyPair {
  const canonicalPublic = createPublicKey(publicKeyPem).export({
    format: "pem",
    type: "spki",
  }) as string;
  if (
    !createPublicKey(createPrivateKey(privateKeyPem)).equals(
      createPublicKey(canonicalPublic),
    )
  ) {
    throw new Error("Lifecycle authority keypair does not match.");
  }
  return {
    privateKeyPem,
    publicKeyPem: canonicalPublic,
    publicKeySha256: createHash("sha256").update(canonicalPublic).digest("hex"),
  };
}

export function lifecycleAuthorityKeyPairFromPrivate(
  privateKeyPem: string,
): LifecycleAuthorityKeyPair {
  const publicKeyPem = createPublicKey(createPrivateKey(privateKeyPem)).export({
    format: "pem",
    type: "spki",
  }) as string;
  return lifecycleAuthorityKeyPair(privateKeyPem, publicKeyPem);
}

export function signLifecycleUpgradeAuthority(
  canonicalAuthority: Uint8Array,
  key: LifecycleAuthorityKeyPair,
) {
  return sign(
    "RSA-SHA256",
    Buffer.concat([signingDomain, Buffer.from(canonicalAuthority)]),
    key.privateKeyPem,
  ).toString("hex");
}
