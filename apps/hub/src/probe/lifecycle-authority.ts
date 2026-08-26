import { createHmac } from "node:crypto";

const installKeySalt = Buffer.from(
  "enoki/lifecycle-authority/install-key/hkdf-sha256/v1\0",
);
const installKeyInfoDomain = Buffer.from(
  "enoki/lifecycle-authority/hub-origin/hkdf-sha256/v1\0",
);
const signingDomain = Buffer.from(
  "enoki/lifecycle-upgrade-authority/hmac-sha256/v1\0",
);

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

export function deriveLifecycleAuthorityKey(
  enrollmentTokenSha256: Uint8Array,
  normalizedHubOrigin: string,
) {
  if (enrollmentTokenSha256.byteLength !== 32) {
    throw new Error("Lifecycle authority IKM must be one SHA-256 digest.");
  }
  const prk = createHmac("sha256", installKeySalt)
    .update(enrollmentTokenSha256)
    .digest();
  return createHmac("sha256", prk)
    .update(installKeyInfoDomain)
    .update(normalizedHubOrigin, "utf8")
    .update(Buffer.from([1]))
    .digest();
}

export function signLifecycleUpgradeAuthority(
  canonicalAuthority: Uint8Array,
  installKey: Uint8Array,
) {
  if (installKey.byteLength !== 32) {
    throw new Error("Lifecycle authority key must be 32 bytes.");
  }
  return createHmac("sha256", installKey)
    .update(signingDomain)
    .update(canonicalAuthority)
    .digest("hex");
}
