import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";

// @ts-expect-error JavaScript release tool has no declaration file.
import { createProbeTrustDelegation } from "../../../scripts/release-candidate-lib.mjs";
// @ts-expect-error JavaScript release transition issuer has no declaration file.
import { createReleaseTransitionContract } from "../../../scripts/release-transition-contract.mjs";
// @ts-expect-error JavaScript Trust Epoch authorization issuer has no declaration file.
import { createTrustEpochMigrationAuthorization } from "../../../scripts/trust-epoch-migration-lib.mjs";

export type TestProbeReleaseAuthority = ReturnType<typeof testKeyPair>;

export async function writeSignedProbeAssetSet(
  assetDir: string,
  input: {
    authority?: TestProbeReleaseAuthority;
    sourceVersion: string;
    targetVersion: string;
    transition: "compatible" | "replacement-required";
    trustEpoch?: boolean;
  },
) {
  const sourceProbeComponents = sourceProbeComponentFixture();
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
  const trustEpoch = input.trustEpoch
    ? createTrustEpochMigrationFixture({
        authority,
        delegation,
        manifest,
        targetVersion: input.targetVersion,
        sourceProbeComponents,
      })
    : null;
  const contract =
    trustEpoch?.contract ??
    createGenericReleaseTransitionContract({
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
    sourceProbeSha256: sourceProbeComponents.map(({ sha256 }) => sha256),
  };
}

function createTrustEpochMigrationFixture({
  authority,
  delegation,
  manifest,
  targetVersion,
  sourceProbeComponents,
}: {
  authority: TestProbeReleaseAuthority;
  delegation: ReturnType<typeof createProbeTrustDelegation>;
  manifest: Buffer;
  targetVersion: string;
  sourceProbeComponents: ReturnType<typeof sourceProbeComponentFixture>;
}) {
  const legacyRelease = {
    assets: [
      { name: "manifest.json", sha256: "1".repeat(64), size: 100 },
      { name: "manifest.json.sig", sha256: "2".repeat(64), size: 256 },
      { name: "signing-key.pem", sha256: "3".repeat(64), size: 451 },
    ],
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
    legacySigningKeySha256: "3".repeat(64),
  };
  const authorization = createTrustEpochMigrationAuthorization({
    candidateVersion: `v${targetVersion}`,
    distribution: "enoki",
    legacyRelease,
    rootPrivateKeyPem: authority.privateKey,
  });
  return {
    authorization,
    contract: createReleaseTransitionContract({
      authorizationBytes: authorization.bytes,
      authorizationSignature: authorization.signature,
      candidateCommit: "a".repeat(40),
      delegationBytes: delegation.bytes,
      delegationSignature: delegation.signature,
      legacyRelease,
      rootPrivateKeyPem: authority.privateKey,
      rootPublicKeyPem: authority.publicKey,
      targetManifestBytes: manifest,
      targetVersion,
      sourceProbeComponents,
    }),
  };
}

function createGenericReleaseTransitionContract({
  authority,
  manifest,
  sourceVersion,
  transition,
  sourceProbeComponents,
}: {
  authority: TestProbeReleaseAuthority;
  manifest: Buffer;
  sourceVersion: string;
  transition: "compatible" | "replacement-required";
  sourceProbeComponents: ReturnType<typeof sourceProbeComponentFixture>;
}) {
  const value = JSON.parse(manifest.toString("utf8")) as {
    assets: unknown;
    signature: {
      delegationGeneration: number;
      delegationKeyId: string;
    };
    version: string;
  };
  const rootPublicKey = Buffer.from(
    createPublicKey(authority.publicKey).export({
      format: "pem",
      type: "spki",
    }),
  );
  const bytes = Buffer.from(
    `${JSON.stringify({
      distribution: "enoki",
      kind: "enoki-release-transition-contract",
      rootKeyId: sha256(rootPublicKey),
      schemaVersion: 1,
      source: {
        probeComponents: sourceProbeComponents,
        version: sourceVersion,
      },
      target: {
        assetClosure: value.assets,
        assetSetManifestSha256: sha256(manifest),
        delegationGeneration: value.signature.delegationGeneration,
        signingKeyId: value.signature.delegationKeyId,
        version: value.version,
      },
      transition,
    })}\n`,
  );
  return {
    bytes,
    signature: sign(
      "RSA-SHA256",
      Buffer.concat([
        Buffer.from("enoki/release-transition-contract/v1\0", "utf8"),
        bytes,
      ]),
      authority.privateKey,
    ),
  };
}

function sourceProbeComponentFixture() {
  return [
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
  ].map((target, index) => ({
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
