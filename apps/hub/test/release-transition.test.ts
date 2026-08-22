import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

// @ts-expect-error JavaScript release tool has no declaration file.
import { createProbeTrustDelegation } from "../../../scripts/release-candidate-lib.mjs";
// @ts-expect-error JavaScript release transition issuer has no declaration file.
import { createReleaseTransitionContract } from "../../../scripts/release-transition-contract.mjs";
import { readVerifiedReleaseTransitionFromDirectory } from "../src/probe/release-transition.js";

describe("verified Probe release transition", () => {
  it("returns no transition when the release does not declare one", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const root = testKeyPair();

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: root.publicKey,
      }),
    ).resolves.toBeNull();
  });

  it("reads a root-authorized compatible source-to-target transition", async () => {
    const fixture = await writeTransitionFixture({ transition: "compatible" });

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir: fixture.assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toEqual({
      classification: "compatible",
      sourceProbeVersion: "1.3.0",
      targetAssetSetDigest: fixture.targetAssetSetDigest,
      targetProbeVersion: "1.4.0",
    });
  });

  it("preserves an explicit replacement-required classification", async () => {
    const fixture = await writeTransitionFixture({
      transition: "replacement-required",
    });

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir: fixture.assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toMatchObject({
      classification: "replacement-required",
      sourceProbeVersion: "1.3.0",
      targetProbeVersion: "1.4.0",
    });
  });
});

async function writeTransitionFixture(input: {
  transition: "compatible" | "replacement-required";
}) {
  const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
  const root = testKeyPair();
  const release = testKeyPair();
  const delegation = createProbeTrustDelegation({
    distribution: "enoki",
    generation: 3,
    releasePublicKeyPem: release.publicKey,
    rootPrivateKeyPem: root.privateKey,
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
      version: "1.4.0",
    })}\n`,
  );
  const contract = createReleaseTransitionContract({
    distribution: "enoki",
    rootPrivateKeyPem: root.privateKey,
    sourceVersion: "1.3.0",
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
    writeFile(path.join(assetDir, "root-key.pem"), root.publicKey),
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
    assetDir,
    rootPublicKeyPem: root.publicKey,
    targetAssetSetDigest: `sha256:${createHash("sha256").update(manifest).digest("hex")}`,
  };
}

function testKeyPair() {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privateKey: pair.privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKey: pair.publicKey.export({ format: "pem", type: "spki" }),
  };
}
