import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createProbeTrustDelegation,
  probeBundleComponentProfiles,
  probeBundledBootstrapAssets,
  verifyProbeTrustDelegation,
} from "./index.mjs";

const rsa4096TestIdentities = new Map();

function rsa4096TestKeyPair(slot) {
  let identity = rsa4096TestIdentities.get(slot);
  if (!identity) {
    identity = Object.freeze(
      generateKeyPairSync("rsa", {
        modulusLength: 4096,
        privateKeyEncoding: { format: "pem", type: "pkcs8" },
        publicKeyEncoding: { format: "pem", type: "spki" },
      }),
    );
    rsa4096TestIdentities.set(slot, identity);
  }
  return identity;
}

describe("Probe release primitives", () => {
  it("keeps the fixed Probe Asset Bundle roles in one package", () => {
    expect(Object.keys(probeBundleComponentProfiles)).toEqual([
      "probe",
      "observation-runtime",
      "system-state-provider",
      "disk-health-provider",
      "lifecycle-companion",
    ]);
    expect(probeBundledBootstrapAssets.map(({ role }) => role)).toEqual([
      "bootstrap-acquirer",
      "bootstrap-activator",
    ]);
  });

  it("creates canonical delegation bytes accepted by the same verifier", () => {
    const root = rsa4096TestKeyPair("probe-release-root");
    const release = rsa4096TestKeyPair("probe-release-signer");
    const signed = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 3,
      releasePublicKeyPem: release.publicKey,
      rootPrivateKeyPem: root.privateKey,
    });

    expect(signed.bytes).toEqual(
      Buffer.from(`${JSON.stringify(signed.delegation)}\n`, "utf8"),
    );
    expect(
      verifyProbeTrustDelegation({
        bytes: signed.bytes,
        expectedDistribution: "enoki",
        rootPublicKeyPem: root.publicKey,
        signature: signed.signature,
      }),
    ).toEqual(signed.delegation);
  });

  it("rejects explicitly weak RSA-2048 production trust identities", () => {
    const root = rsa4096TestKeyPair("probe-release-root");
    const release = rsa4096TestKeyPair("probe-release-signer");
    const weakRejectionOnlyIdentity = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const signed = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 3,
      releasePublicKeyPem: release.publicKey,
      rootPrivateKeyPem: root.privateKey,
    });

    expect(() =>
      createProbeTrustDelegation({
        distribution: "enoki",
        generation: 3,
        releasePublicKeyPem: release.publicKey,
        rootPrivateKeyPem: weakRejectionOnlyIdentity.privateKey,
      }),
    ).toThrow(/Trust Root must be an RSA-4096 private key/);
    expect(() =>
      createProbeTrustDelegation({
        distribution: "enoki",
        generation: 3,
        releasePublicKeyPem: weakRejectionOnlyIdentity.publicKey,
        rootPrivateKeyPem: root.privateKey,
      }),
    ).toThrow(/signing public key must be RSA-4096/);
    expect(() =>
      verifyProbeTrustDelegation({
        bytes: signed.bytes,
        expectedDistribution: "enoki",
        rootPublicKeyPem: weakRejectionOnlyIdentity.publicKey,
        signature: signed.signature,
      }),
    ).toThrow(/Trust Root public key must be RSA-4096/);
  });
});
