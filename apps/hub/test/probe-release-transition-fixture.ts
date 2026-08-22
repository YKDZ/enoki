import { generateKeyPairSync, sign } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";

// @ts-expect-error JavaScript release tool has no declaration file.
import { createProbeTrustDelegation } from "../../../scripts/release-candidate-lib.mjs";
// @ts-expect-error JavaScript release transition issuer has no declaration file.
import { createReleaseTransitionContract } from "../../../scripts/release-transition-contract.mjs";

export type TestProbeReleaseAuthority = ReturnType<typeof testKeyPair>;

export async function writeSignedProbeAssetSet(
  assetDir: string,
  input: {
    authority?: TestProbeReleaseAuthority;
    sourceVersion: string;
    targetVersion: string;
    transition: "compatible" | "replacement-required";
  },
) {
  const authority = input.authority ?? testKeyPair();
  const release = testKeyPair();
  const delegation = createProbeTrustDelegation({
    distribution: "enoki",
    generation: 3,
    releasePublicKeyPem: release.publicKey,
    rootPrivateKeyPem: authority.privateKey,
  });
  const manifest = Buffer.from(
    `${JSON.stringify({
      assets: [
        "aarch64-unknown-linux-gnu",
        "aarch64-unknown-linux-musl",
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
      ].map((target, index) => ({
        bundleManifestSha256: String(index + 1).repeat(64),
        file: `enoki-probe-${target}.tar.gz`,
        sha256: String(index + 5).repeat(64),
        size: 123 + index,
        target,
      })),
      kind: "enoki-probe-assets",
      signature: {
        algorithm: "rsa-sha256",
        delegationGeneration: 3,
        delegationKeyId: delegation.delegation.signingIdentity.keyId,
        file: "manifest.json.sig",
        publicKey: "signing-key.pem",
      },
      version: input.targetVersion,
    })}\n`,
  );
  const contract = createReleaseTransitionContract({
    distribution: "enoki",
    rootPrivateKeyPem: authority.privateKey,
    sourceVersion: input.sourceVersion,
    targetManifestBytes: manifest,
    transition: input.transition,
  });

  await Promise.all([
    writeFile(path.join(assetDir, "manifest.json"), manifest),
    writeFile(
      path.join(assetDir, "manifest.json.sig"),
      sign("RSA-SHA256", manifest, release.privateKey),
    ),
    writeFile(path.join(assetDir, "signing-key.pem"), release.publicKey),
    writeFile(path.join(assetDir, "root-key.pem"), authority.publicKey),
    writeFile(path.join(assetDir, "trust-delegation.json"), delegation.bytes),
    writeFile(
      path.join(assetDir, "trust-delegation.json.sig"),
      delegation.signature,
    ),
    writeFile(
      path.join(assetDir, "release-transition-contract.json"),
      contract.bytes,
    ),
    writeFile(
      path.join(assetDir, "release-transition-contract.json.sig"),
      contract.signature,
    ),
  ]);

  return {
    authority,
    rootPublicKeyPem: authority.publicKey,
  };
}

function testKeyPair() {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privateKey: pair.privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKey: pair.publicKey.export({ format: "pem", type: "spki" }),
  };
}
