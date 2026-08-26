import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";

import {
  createProbeTrustDelegation,
  createReleaseTransitionContract,
  createTrustEpochMigrationAuthorization,
  probeTargets,
} from "@enoki/probe-release";
import {
  createGenericReleaseTransitionContractFixture,
  createSignedLegacyProbeAssetSetFixture,
} from "@enoki/probe-release/test-fixture";

export type TestProbeReleaseAuthority = ReturnType<typeof testKeyPair>;

export async function writeSignedProbeAssetSet(
  assetDir: string,
  input: {
    authority?: TestProbeReleaseAuthority;
    sourceVersion: string;
    targetVersion: string;
    transition: "compatible" | "replacement-required";
    trustEpoch?: boolean;
    x86_64GnuBundle?: {
      archive: Buffer;
      bundleManifest: Buffer;
    };
    x86_64GnuSourceProbeSha256?: string;
  },
) {
  const sourceProbeComponents = sourceProbeComponentFixture().map((component) =>
    component.target === "x86_64-unknown-linux-gnu" &&
    input.x86_64GnuSourceProbeSha256
      ? { ...component, sha256: input.x86_64GnuSourceProbeSha256 }
      : component,
  );
  const authority = input.authority ?? testKeyPair();
  const release = testKeyPair();
  const delegation = createProbeTrustDelegation({
    distribution: "enoki",
    generation: 3,
    releasePublicKeyPem: release.publicKey,
    rootPrivateKeyPem: authority.privateKey,
  });
  const assets = probeTargets.map((target, index) => {
    if (target === "x86_64-unknown-linux-gnu" && input.x86_64GnuBundle) {
      return {
        bundleManifestSha256: sha256(input.x86_64GnuBundle.bundleManifest),
        file: `enoki-probe-${target}.tar.gz`,
        sha256: sha256(input.x86_64GnuBundle.archive),
        size: input.x86_64GnuBundle.archive.byteLength,
        target,
      };
    }
    return {
      bundleManifestSha256: String(index + 1).repeat(64),
      file: `enoki-probe-${target}.tar.gz`,
      sha256: String(index + 5).repeat(64),
      size: 123 + index,
      target,
    };
  });
  const manifest = Buffer.from(
    `${JSON.stringify({
      assets,
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
  const trustEpoch = input.trustEpoch
    ? await createTrustEpochMigrationFixture({
        authority,
        delegation,
        manifest,
        targetVersion: input.targetVersion,
      })
    : null;
  const contract =
    trustEpoch?.contract ??
    createGenericReleaseTransitionContractFixture({
      authority,
      manifest,
      sourceVersion: input.sourceVersion,
      transition: input.transition,
      sourceProbeComponents,
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
    ...(input.x86_64GnuBundle
      ? [
          writeFile(
            path.join(assetDir, "enoki-probe-x86_64-unknown-linux-gnu.tar.gz"),
            input.x86_64GnuBundle.archive,
          ),
        ]
      : []),
    ...(trustEpoch
      ? [
          writeFile(
            path.join(assetDir, "trust-epoch-migration-authorization.json"),
            trustEpoch.authorization.bytes,
          ),
          writeFile(
            path.join(assetDir, "trust-epoch-migration-authorization.json.sig"),
            trustEpoch.authorization.signature,
          ),
        ]
      : []),
  ]);

  return {
    authority,
    rootPublicKeyPem: authority.publicKey,
    targetAssetSetDigest: `sha256:${createHash("sha256").update(manifest).digest("hex")}`,
    targetBundles: assets.map(({ bundleManifestSha256, target }) => ({
      bundleManifestSha256,
      target,
    })),
    sourceProbeSha256: (
      trustEpoch?.sourceProbeComponents ?? sourceProbeComponents
    ).map(({ sha256 }: { sha256: string }) => sha256),
  };
}

async function createTrustEpochMigrationFixture({
  authority,
  delegation,
  manifest,
  targetVersion,
}: {
  authority: TestProbeReleaseAuthority;
  delegation: ReturnType<typeof createProbeTrustDelegation>;
  manifest: Buffer;
  targetVersion: string;
}) {
  const sourceRelease = testKeyPair();
  const source = await createSignedLegacyProbeAssetSetFixture({
    privateKeyPem: sourceRelease.privateKey,
    publicKeyPem: sourceRelease.publicKey,
  });
  const legacyRelease = {
    assets: source.assets,
    githubRelease: {
      id: 368250351,
      peeledCommitSha: "6f639fe757785c085be31c3d92c7b1c128db3cb0",
      repository: "YKDZ/enoki",
      tag: "v0.1.74",
      tagRefSha: "4".repeat(40),
      targetCommitish: "main",
    },
    hub: {
      digest: `sha256:${"5".repeat(64)}`,
      image: "ghcr.io/ykdz/enoki-hub",
    },
    legacySigningKeySha256: sha256(Buffer.from(sourceRelease.publicKey)),
  };
  const authorization = createTrustEpochMigrationAuthorization({
    candidateVersion: `v${targetVersion}`,
    distribution: "enoki",
    legacyRelease,
    rootPrivateKeyPem: authority.privateKey,
  });
  try {
    return {
      authorization,
      contract: await createReleaseTransitionContract({
        authorizationBytes: authorization.bytes,
        authorizationSignature: authorization.signature,
        candidateCommit: "a".repeat(40),
        delegationBytes: delegation.bytes,
        delegationSignature: delegation.signature,
        legacyRelease,
        rootPrivateKeyPem: authority.privateKey,
        rootPublicKeyPem: authority.publicKey,
        sourceAssetDir: source.assetDir,
        targetManifestBytes: manifest,
        targetVersion,
      }),
      sourceProbeComponents: source.probeComponents,
    };
  } finally {
    await source.cleanup();
  }
}

function sourceProbeComponentFixture() {
  return probeTargets.map((target, index) => ({
    file: "enoki-probe",
    role: "probe",
    sha256: String(index + 5).repeat(64),
    target,
  }));
}

function sha256(value: Buffer) {
  return createHash("sha256").update(value).digest("hex");
}

function testKeyPair() {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privateKey: pair.privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKey: pair.publicKey.export({ format: "pem", type: "spki" }),
  };
}
