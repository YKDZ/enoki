import { createHash, generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import { assertMigrationCandidateJoin } from "./release-baseline-migration-lib.mjs";
import { createProbeTrustDelegation } from "./release-candidate-lib.mjs";
import {
  createReleaseTransitionContract,
  preflightReleaseMigrationConfiguration,
  verifyReleaseTransitionContract,
} from "./release-transition-contract.mjs";
import { createTrustEpochMigrationAuthorization } from "./trust-epoch-migration-lib.mjs";

describe("Trust Epoch release transition", () => {
  it("requires one signed source Probe component digest for every fixed target", () => {
    const fixture = transitionFixture();
    expect(() =>
      createReleaseTransitionContract({
        ...fixture.createInput,
        sourceProbeComponents: undefined,
      }),
    ).toThrow("source Probe closure is invalid");
  });

  it("binds the authorized legacy baseline to one replacement-required candidate", () => {
    const fixture = transitionFixture();
    const signed = createReleaseTransitionContract(fixture.createInput);

    expect(signed.contract).toMatchObject({
      candidateCommit: fixture.expected.candidateCommit,
      migrationGeneration: 1,
      source: {
        commit: fixture.expected.sourceCommit,
        tag: "v0.1.74",
      },
      target: {
        assetSetManifestSha256: fixture.expected.targetAssetSetManifestSha256,
        version: "1.2.3",
      },
      transition: "replacement-required",
    });
    expect(
      verifyReleaseTransitionContract({
        authorizationBytes: fixture.createInput.authorizationBytes,
        authorizationSignature: fixture.createInput.authorizationSignature,
        contractBytes: signed.bytes,
        contractSignature: signed.signature,
        expected: fixture.expected,
        rootPublicKeyPem: fixture.root.publicKey,
      }),
    ).toEqual(signed.contract);
  });

  it("reports that a different ordinary candidate does not match", () => {
    const fixture = transitionFixture();
    const signed = createReleaseTransitionContract(fixture.createInput);

    expect(() =>
      verifyReleaseTransitionContract({
        authorizationBytes: fixture.createInput.authorizationBytes,
        authorizationSignature: fixture.createInput.authorizationSignature,
        contractBytes: signed.bytes,
        contractSignature: signed.signature,
        expected: { ...fixture.expected, candidateCommit: "f".repeat(40) },
        rootPublicKeyPem: fixture.root.publicKey,
      }),
    ).toThrow("does not match");
  });

  it.each([
    [
      "authorization",
      (baseline) => (baseline.authorization.sha256 = "f".repeat(64)),
    ],
    [
      "release id",
      (_baseline, transition) => (transition.source.releaseId += 1),
    ],
    [
      "asset closure",
      (_baseline, transition) => (transition.source.assets[0].size += 1),
    ],
    [
      "Hub digest",
      (_baseline, transition) =>
        (transition.source.hubDigest = `sha256:${"f".repeat(64)}`),
    ],
  ])("rejects an ordinary A/B mismatch in %s", (_name, mutate) => {
    const fixture = transitionFixture();
    const signed = createReleaseTransitionContract(fixture.createInput);
    const baseline = {
      authorization: {
        legacyReleaseSha256: sha256(
          Buffer.from(JSON.stringify(fixture.createInput.legacyRelease)),
        ),
        sha256: sha256(fixture.createInput.authorizationBytes),
      },
      githubRelease: {
        peeledCommitSha:
          fixture.createInput.legacyRelease.githubRelease.peeledCommitSha,
      },
      kind: "enoki-trust-epoch-migration-baseline",
      tag: "v0.1.74",
    };
    const transition = structuredClone(signed.contract);
    mutate(baseline, transition);
    expect(() =>
      assertMigrationCandidateJoin({
        identity: {
          commit: fixture.expected.candidateCommit,
          version: "v1.2.3",
        },
        releaseBaseline: baseline,
        releaseTransition: transition,
      }),
    ).toThrow("candidate does not match");
  });

  it("preflights the four public values before candidate signing", () => {
    const fixture = transitionFixture();
    const signed = createReleaseTransitionContract(fixture.createInput);
    expect(
      preflightReleaseMigrationConfiguration({
        authorization: fixture.createInput.authorizationBytes.toString(),
        authorizationSignatureBase64:
          fixture.createInput.authorizationSignature.toString("base64"),
        candidateCommit: fixture.expected.candidateCommit,
        candidateVersion: "v1.2.3",
        contract: signed.bytes.toString(),
        contractSignatureBase64: signed.signature.toString("base64"),
        rootPublicKeyPem: fixture.root.publicKey,
      }),
    ).toEqual(signed.contract);
  });

  it("requires the four public values to be configured together", () => {
    const fixture = transitionFixture();
    expect(() =>
      preflightReleaseMigrationConfiguration({
        authorization: fixture.createInput.authorizationBytes.toString(),
        authorizationSignatureBase64: "",
        candidateCommit: fixture.expected.candidateCommit,
        candidateVersion: "v1.2.3",
        contract: "",
        contractSignatureBase64: "",
        rootPublicKeyPem: fixture.root.publicKey,
      }),
    ).toThrow("one complete closure");
  });

  it("rejects bounded transition metadata before parsing", () => {
    const fixture = transitionFixture();
    expect(() =>
      verifyReleaseTransitionContract({
        authorizationBytes: fixture.createInput.authorizationBytes,
        authorizationSignature: fixture.createInput.authorizationSignature,
        contractBytes: Buffer.alloc(64 * 1024 + 1, 32),
        contractSignature: Buffer.alloc(256),
        rootPublicKeyPem: fixture.root.publicKey,
      }),
    ).toThrow("contract is invalid");
  });

  it("rejects an authorization asset cardinality above the fixed bound", () => {
    const fixture = transitionFixture();
    expect(() =>
      createTrustEpochMigrationAuthorization({
        candidateVersion: "v1.2.3",
        distribution: "enoki",
        legacyRelease: {
          ...fixture.createInput.legacyRelease,
          assets: Array.from({ length: 65 }, (_, index) => ({
            name: `asset-${index}`,
            sha256: "1".repeat(64),
            size: 1,
          })),
        },
        rootPrivateKeyPem: fixture.root.privateKey,
      }),
    ).toThrow("assets are invalid");
  });
});

function transitionFixture() {
  const root = keyPair();
  const release = keyPair();
  const delegation = createProbeTrustDelegation({
    distribution: "enoki",
    generation: 1,
    releasePublicKeyPem: release.publicKey,
    rootPrivateKeyPem: root.privateKey,
  });
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
    candidateVersion: "v1.2.3",
    distribution: "enoki",
    legacyRelease,
    rootPrivateKeyPem: root.privateKey,
  });
  const assets = [
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
  ].map((target, index) => ({
    bundleManifestSha256: String(index + 1).repeat(64),
    file: `enoki-probe-${target}.tar.gz`,
    sha256: String(index + 5).repeat(64),
    size: index + 1000,
    target,
  }));
  const targetManifestBytes = Buffer.from(
    `${JSON.stringify({
      assets,
      kind: "enoki-probe-assets",
      signature: {
        algorithm: "rsa-sha256",
        delegationGeneration: 1,
        delegationKeyId: delegation.delegation.signingIdentity.keyId,
        file: "manifest.json.sig",
        publicKey: "signing-key.pem",
      },
      version: "1.2.3",
    })}\n`,
  );
  const candidateCommit = "a".repeat(40);
  return {
    createInput: {
      authorizationBytes: authorization.bytes,
      authorizationSignature: authorization.signature,
      candidateCommit,
      delegationBytes: delegation.bytes,
      delegationSignature: delegation.signature,
      legacyRelease,
      rootPrivateKeyPem: root.privateKey,
      rootPublicKeyPem: root.publicKey,
      sourceProbeComponents: [
        "aarch64-unknown-linux-gnu",
        "aarch64-unknown-linux-musl",
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
      ].map((target, index) => ({
        file: "enoki-probe",
        role: "probe",
        sha256: String(index + 5).repeat(64),
        target,
      })),
      targetManifestBytes,
      targetVersion: "1.2.3",
    },
    expected: {
      candidateCommit,
      delegationGeneration: 1,
      sourceCommit: legacyRelease.githubRelease.peeledCommitSha,
      sourceTag: "v0.1.74",
      targetAssetSetManifestSha256: sha256(targetManifestBytes),
      targetVersion: "1.2.3",
    },
    root,
  };
}

function keyPair() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
