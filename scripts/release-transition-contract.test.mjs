import { createHash, generateKeyPairSync, sign } from "node:crypto";

import {
  createProbeTrustDelegation,
  createReleaseTransitionContract,
  createTrustEpochMigrationAuthorization,
  releaseTransitionContractSigningInput,
  verifyReleaseTransitionContract,
} from "@enoki/probe-release";
import { createSignedLegacyProbeAssetSetFixture } from "@enoki/probe-release/test-fixture";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { assertMigrationCandidateJoin } from "./release-baseline-migration-lib.ts";
import { declareReleaseTransition } from "./release-transition-declaration.ts";

describe("Trust Epoch release transition", () => {
  let fixture;

  beforeAll(async () => {
    fixture = await transitionFixture();
  });

  afterAll(async () => {
    await fixture.cleanup();
  });

  it("derives every source Probe digest from the signed release asset closure", async () => {
    const signed = await createReleaseTransitionContract(fixture.createInput);

    expect(signed.contract.source.probeComponents).toEqual(
      fixture.sourceProbeComponents,
    );
  });

  it("requires the complete migration closure", async () => {
    await expect(
      createReleaseTransitionContract({
        ...fixture.createInput,
        sourceAssetDir: undefined,
      }),
    ).rejects.toThrow("migration closure is incomplete");
  });

  it("refuses a release identity the Probe Trust Delegation does not authorize", async () => {
    await expect(
      createReleaseTransitionContract({
        ...fixture.createInput,
        releasePrivateKeyPem: fixture.unauthorizedRelease.privateKey,
      }),
    ).rejects.toThrow("not authorized by the Probe Trust Delegation");
  });

  it("binds the authorized legacy baseline to one replacement-required candidate", async () => {
    const signed = await createReleaseTransitionContract(fixture.createInput);

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
        ...fixture.trust,
        authorizationBytes: fixture.createInput.authorizationBytes,
        authorizationSignature: fixture.createInput.authorizationSignature,
        contractBytes: signed.bytes,
        contractSignature: signed.signature,
        expected: fixture.expected,
      }),
    ).toEqual(signed.contract);
  });

  it("reports that a different ordinary candidate does not match", async () => {
    const signed = await createReleaseTransitionContract(fixture.createInput);

    expect(() =>
      verifyReleaseTransitionContract({
        ...fixture.trust,
        authorizationBytes: fixture.createInput.authorizationBytes,
        authorizationSignature: fixture.createInput.authorizationSignature,
        contractBytes: signed.bytes,
        contractSignature: signed.signature,
        expected: { ...fixture.expected, candidateCommit: "f".repeat(40) },
      }),
    ).toThrow("does not match");
  });

  it.each(["compatible", "replacement-required"])(
    "binds an ordinary signed %s contract to one candidate commit before planning",
    async (transition) => {
      const signed = await createReleaseTransitionContract(
        fixture.genericInput(transition),
      );
      const expected = {
        candidateCommit: fixture.expected.candidateCommit,
        classification: transition,
        delegationGeneration: 1,
        sourceVersion: "1.2.2",
        targetAssetClosure: fixture.assets,
        targetAssetSetManifestSha256:
          fixture.expected.targetAssetSetManifestSha256,
        targetVersion: "1.2.3",
      };

      expect(
        verifyReleaseTransitionContract({
          ...fixture.trust,
          contractBytes: signed.bytes,
          contractSignature: signed.signature,
          expected,
        }),
      ).toEqual(signed.contract);
      expect(() =>
        verifyReleaseTransitionContract({
          ...fixture.trust,
          contractBytes: signed.bytes,
          contractSignature: sign(
            "RSA-SHA256",
            releaseTransitionContractSigningInput(signed.bytes),
            fixture.root.privateKey,
          ),
          expected,
        }),
      ).toThrow(
        "signature does not match the authorized Probe signing identity",
      );
      expect(() =>
        verifyReleaseTransitionContract({
          ...fixture.trust,
          contractBytes: signed.bytes,
          contractSignature: signed.signature,
          expected: { ...expected, candidateCommit: "f".repeat(40) },
        }),
      ).toThrow("candidate does not match");
      const unboundContract = structuredClone(signed.contract);
      delete unboundContract.candidateCommit;
      expect(() =>
        verifyReleaseTransitionContract({
          ...fixture.trust,
          contractBytes: Buffer.from(`${JSON.stringify(unboundContract)}\n`),
          contractSignature: signed.signature,
        }),
      ).toThrow("fields are invalid");
    },
  );

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
  ])("rejects an ordinary A/B mismatch in %s", async (_name, mutate) => {
    const signed = await createReleaseTransitionContract(fixture.createInput);
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

  it("rejects bounded transition metadata before parsing", () => {
    expect(() =>
      verifyReleaseTransitionContract({
        ...fixture.trust,
        authorizationBytes: fixture.createInput.authorizationBytes,
        authorizationSignature: fixture.createInput.authorizationSignature,
        contractBytes: Buffer.alloc(64 * 1024 + 1, 32),
        contractSignature: Buffer.alloc(256),
      }),
    ).toThrow("contract is invalid");
  });

  it("rejects an authorization asset cardinality above the fixed bound", () => {
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

async function transitionFixture() {
  const root = keyPair();
  const release = keyPair();
  const unauthorizedRelease = keyPair();
  const delegation = createProbeTrustDelegation({
    distribution: "enoki",
    generation: 1,
    releasePublicKeyPem: release.publicKey,
    rootPrivateKeyPem: root.privateKey,
  });
  const source = await createSignedLegacyProbeAssetSetFixture({
    privateKeyPem: release.privateKey,
    publicKeyPem: release.publicKey,
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
    legacySigningKeySha256: sha256(Buffer.from(release.publicKey)),
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
  const createInput = {
    authorizationBytes: authorization.bytes,
    authorizationSignature: authorization.signature,
    candidateCommit,
    delegationBytes: delegation.bytes,
    delegationSignature: delegation.signature,
    distribution: "enoki",
    legacyRelease,
    releasePrivateKeyPem: release.privateKey,
    rootPublicKeyPem: root.publicKey,
    sourceAssetDir: source.assetDir,
    targetManifestBytes,
    targetVersion: "1.2.3",
  };
  return {
    assets,
    cleanup: source.cleanup,
    createInput,
    expected: {
      candidateCommit,
      delegationGeneration: 1,
      sourceCommit: legacyRelease.githubRelease.peeledCommitSha,
      sourceTag: "v0.1.74",
      targetAssetSetManifestSha256: sha256(targetManifestBytes),
      targetVersion: "1.2.3",
    },
    genericInput: (transition) => ({
      ...createInput,
      authorizationBytes: undefined,
      authorizationSignature: undefined,
      legacyRelease: undefined,
      sourceAssetDir: undefined,
      sourceProbeComponents: source.probeComponents,
      sourceVersion: "1.2.2",
      transition,
    }),
    root,
    sourceProbeComponents: source.probeComponents,
    trust: {
      delegationBytes: delegation.bytes,
      delegationSignature: delegation.signature,
      expectedDistribution: "enoki",
      rootPublicKeyPem: root.publicKey,
    },
    unauthorizedRelease,
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

describe("Release Transition declaration", () => {
  it("returns the approved classification for a declared pair", () => {
    expect(
      declareReleaseTransition({
        baselineIsTrustEpochMigration: false,
        sourceVersion: "0.1.75",
        targetVersion: "0.1.76",
      }),
    ).toEqual({
      baselineIsTrustEpochMigration: false,
      classification: "compatible",
      sourceVersion: "0.1.75",
      targetVersion: "0.1.76",
    });
    expect(
      declareReleaseTransition({
        baselineIsTrustEpochMigration: true,
        sourceVersion: "0.1.74",
        targetVersion: "0.1.75",
      }).classification,
    ).toBe("replacement-required");
  });

  it("fails closed for an undeclared pair or a disagreeing baseline", () => {
    expect(() =>
      declareReleaseTransition({
        baselineIsTrustEpochMigration: false,
        sourceVersion: "1.2.2",
        targetVersion: "1.2.3",
      }),
    ).toThrow(
      "Release Transition classification is not declared for 1.2.2 -> 1.2.3",
    );
    expect(() =>
      declareReleaseTransition({
        baselineIsTrustEpochMigration: false,
        sourceVersion: "0.1.74",
        targetVersion: "0.1.75",
      }),
    ).toThrow(
      "Release Transition declaration does not match the verified Release Baseline",
    );
  });
});
