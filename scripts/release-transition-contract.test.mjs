import { createHash, sign } from "node:crypto";

import {
  createReleaseTransitionContract,
  createProbeTrustDelegation,
  preflightReleaseMigrationConfiguration,
  releaseTransitionContractSigningInput,
  verifyReleaseTransitionContract,
} from "@enoki/probe-release";
import { createTrustEpochMigrationAuthorization } from "@enoki/probe-release";
import { createSignedLegacyProbeAssetSetFixture } from "@enoki/probe-release/test-fixture";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { assertMigrationCandidateJoin } from "./release-baseline-migration-lib.mjs";
import { rsa4096TestKeyPair } from "./test-rsa-key-pool.mjs";

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

  it("requires the authenticated source release asset closure", async () => {
    await expect(
      createReleaseTransitionContract({
        ...fixture.createInput,
        sourceAssetDir: undefined,
      }),
    ).rejects.toThrow("source Probe asset closure is required");
  });

  it.each([
    ["missing", (source) => delete source.assetSetManifestSha256],
    ["malformed", (source) => (source.assetSetManifestSha256 = "not-a-digest")],
  ])(
    "rejects a root-signed contract with a %s source asset-set closure",
    async (_name, mutate) => {
      const signed = await createReleaseTransitionContract(fixture.createInput);
      const contract = structuredClone(signed.contract);
      mutate(contract.source);
      const bytes = Buffer.from(`${JSON.stringify(contract)}\n`);

      expect(() =>
        verifyReleaseTransitionContract({
          authorizationBytes: fixture.createInput.authorizationBytes,
          authorizationSignature: fixture.createInput.authorizationSignature,
          contractBytes: bytes,
          contractSignature: sign(
            "RSA-SHA256",
            releaseTransitionContractSigningInput(bytes),
            fixture.root.privateKey,
          ),
          expected: fixture.expected,
          rootPublicKeyPem: fixture.root.publicKey,
        }),
      ).toThrow("fields are invalid");
    },
  );

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
        authorizationBytes: fixture.createInput.authorizationBytes,
        authorizationSignature: fixture.createInput.authorizationSignature,
        contractBytes: signed.bytes,
        contractSignature: signed.signature,
        expected: fixture.expected,
        rootPublicKeyPem: fixture.root.publicKey,
      }),
    ).toEqual(signed.contract);
  });

  it("reports that a different ordinary candidate does not match", async () => {
    const signed = await createReleaseTransitionContract(fixture.createInput);

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

  it.each(["compatible", "replacement-required"])(
    "binds an ordinary signed %s contract to one candidate commit before planning",
    (transition) => {
      const targetManifest = JSON.parse(
        fixture.createInput.targetManifestBytes,
      );
      const contract = {
        candidateCommit: fixture.expected.candidateCommit,
        distribution: "enoki",
        kind: "enoki-release-transition-contract",
        rootKeyId: sha256(Buffer.from(fixture.root.publicKey)),
        schemaVersion: 1,
        source: {
          assetSetManifestSha256: "f".repeat(64),
          probeComponents: fixture.sourceProbeComponents,
          version: "1.2.2",
        },
        target: {
          assetClosure: targetManifest.assets,
          assetSetManifestSha256: sha256(
            fixture.createInput.targetManifestBytes,
          ),
          delegationGeneration: 1,
          probeComponents: fixture.targetProbeComponents,
          signingKeyId: targetManifest.signature.delegationKeyId,
          version: "1.2.3",
        },
        transition,
      };
      const bytes = Buffer.from(`${JSON.stringify(contract)}\n`);
      const signature = sign(
        "RSA-SHA256",
        releaseTransitionContractSigningInput(bytes),
        fixture.root.privateKey,
      );
      const input = {
        contractBytes: bytes,
        contractSignature: signature,
        expected: {
          candidateCommit: fixture.expected.candidateCommit,
          sourceVersion: "1.2.2",
          targetAssetSetManifestSha256: contract.target.assetSetManifestSha256,
          targetVersion: "1.2.3",
          classification: transition,
        },
        rootPublicKeyPem: fixture.root.publicKey,
      };

      expect(verifyReleaseTransitionContract(input)).toEqual(contract);
      expect(
        preflightReleaseMigrationConfiguration({
          authorization: "",
          authorizationSignatureBase64: "",
          candidateCommit: fixture.expected.candidateCommit,
          candidateVersion: "v1.2.3",
          contract: bytes.toString(),
          contractSignatureBase64: signature.toString("base64"),
          rootPublicKeyPem: fixture.root.publicKey,
        }),
      ).toEqual(contract);
      expect(
        preflightReleaseMigrationConfiguration({
          authorization: fixture.createInput.authorizationBytes.toString(),
          authorizationSignatureBase64:
            fixture.createInput.authorizationSignature.toString("base64"),
          candidateCommit: fixture.expected.candidateCommit,
          candidateVersion: "v1.2.3",
          contract: bytes.toString(),
          contractSignatureBase64: signature.toString("base64"),
          rootPublicKeyPem: fixture.root.publicKey,
        }),
      ).toEqual(contract);
      const unboundContract = structuredClone(contract);
      delete unboundContract.candidateCommit;
      const unboundBytes = Buffer.from(`${JSON.stringify(unboundContract)}\n`);
      expect(() =>
        verifyReleaseTransitionContract({
          contractBytes: unboundBytes,
          contractSignature: sign(
            "RSA-SHA256",
            releaseTransitionContractSigningInput(unboundBytes),
            fixture.root.privateKey,
          ),
          rootPublicKeyPem: fixture.root.publicKey,
        }),
      ).toThrow("fields are invalid");
      expect(() =>
        verifyReleaseTransitionContract({
          ...input,
          expected: {
            ...input.expected,
            candidateCommit: "f".repeat(40),
          },
        }),
      ).toThrow("candidate does not match");
      expect(() =>
        preflightReleaseMigrationConfiguration({
          authorization: "",
          authorizationSignatureBase64: "",
          candidateCommit: "f".repeat(40),
          candidateVersion: "v1.2.3",
          contract: bytes.toString(),
          contractSignatureBase64: signature.toString("base64"),
          rootPublicKeyPem: fixture.root.publicKey,
        }),
      ).toThrow("candidate does not match");
      expect(() =>
        verifyReleaseTransitionContract({
          ...input,
          contractSignature: Buffer.from(signature).fill(0),
        }),
      ).toThrow("root signature does not match");
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

  it("preflights the four public values before candidate signing", async () => {
    const signed = await createReleaseTransitionContract(fixture.createInput);
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

  it("keeps Trust Epoch migration preflight bound to the fixed legacy source tag", async () => {
    const signed = await createReleaseTransitionContract(fixture.createInput);
    const wrongSourceTag = structuredClone(signed.contract);
    wrongSourceTag.source.tag = "v0.1.75";
    const contractBytes = Buffer.from(`${JSON.stringify(wrongSourceTag)}\n`);

    expect(() =>
      preflightReleaseMigrationConfiguration({
        authorization: fixture.createInput.authorizationBytes.toString(),
        authorizationSignatureBase64:
          fixture.createInput.authorizationSignature.toString("base64"),
        candidateCommit: fixture.expected.candidateCommit,
        candidateVersion: "v1.2.3",
        contract: contractBytes.toString(),
        contractSignatureBase64: sign(
          "RSA-SHA256",
          releaseTransitionContractSigningInput(contractBytes),
          fixture.root.privateKey,
        ).toString("base64"),
        rootPublicKeyPem: fixture.root.publicKey,
      }),
    ).toThrow(/fields are invalid|candidate does not match/);
  });

  it("requires the four public values to be configured together", () => {
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
  const root = rsa4096TestKeyPair("transition-root");
  const release = rsa4096TestKeyPair("transition-release");
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
  const targetProbeComponents = assets.map((asset, index) => ({
    file: "enoki-probe",
    role: "probe",
    sha256: ["a", "b", "c", "d"][index].repeat(64),
    target: asset.target,
  }));
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
      sourceAssetDir: source.assetDir,
      targetProbeComponents,
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
    cleanup: source.cleanup,
    sourceProbeComponents: source.probeComponents,
    targetProbeComponents,
  };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
