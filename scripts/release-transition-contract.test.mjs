import { execFile } from "node:child_process";
import { createHash, sign } from "node:crypto";
import { renameSync } from "node:fs";
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import {
  createReleaseTransitionContract,
  createProbeTrustDelegation,
  probeBundledBootstrapAssets,
  preflightReleaseMigrationConfiguration,
  probeBundleComponentProfiles,
  releaseTransitionContractSigningInput,
  verifyReleaseTransitionContract,
} from "@enoki/probe-release";
import { createTrustEpochMigrationAuthorization } from "@enoki/probe-release";
import { createSignedLegacyProbeAssetSetFixture } from "@enoki/probe-release/test-fixture";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { assertMigrationCandidateJoin } from "./release-baseline-migration-lib.mjs";
import { rsa4096TestKeyPair } from "./test-rsa-key-pool.mjs";

const execFileAsync = promisify(execFile);
const archiveSwap = vi.hoisted(() => ({ replace: null }));
const sourceArchiveSwap = vi.hoisted(() => ({ replace: null }));

vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    async open(...args) {
      const handle = await original.open(...args);
      sourceArchiveSwap.replace?.(String(args[0]));
      sourceArchiveSwap.replace = null;
      return handle;
    },
  };
});

vi.mock("node:child_process", async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    spawn(...args) {
      archiveSwap.replace?.();
      archiveSwap.replace = null;
      return original.spawn(...args);
    },
  };
});

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

  it("does not sign caller-supplied target component digests", async () => {
    const signed = await createReleaseTransitionContract({
      ...fixture.createInput,
      targetProbeComponents: fixture.targetProbeComponents.map((component) => ({
        ...component,
        sha256: "f".repeat(64),
      })),
    });

    expect(signed.contract.target.probeComponents).toEqual(
      fixture.targetProbeComponents,
    );
  });

  it("rejects an arbitrary target signer that re-signs a manifest claiming the delegated key id", async () => {
    const local = await transitionFixture();
    const attacker = rsa4096TestKeyPair("transition-attacker");
    try {
      const manifestPath = path.join(
        local.createInput.targetAssetDir,
        "manifest.json",
      );
      const manifest = await readFile(manifestPath);
      await Promise.all([
        writeFile(
          path.join(local.createInput.targetAssetDir, "signing-key.pem"),
          attacker.publicKey,
        ),
        writeFile(
          path.join(local.createInput.targetAssetDir, "manifest.json.sig"),
          sign("RSA-SHA256", manifest, attacker.privateKey),
        ),
      ]);

      await expect(
        createReleaseTransitionContract(local.createInput),
      ).rejects.toThrow("target Probe asset closure is invalid");
    } finally {
      await local.cleanup();
    }
  });

  it("keeps target receipts bound to verified archive bytes when the archive path is atomically replaced", async () => {
    const local = await transitionFixture();
    const archiveName = "enoki-probe-aarch64-unknown-linux-gnu.tar.gz";
    const archivePath = path.join(
      local.createInput.targetAssetDir,
      archiveName,
    );
    const contents = await mkdtemp(
      path.join(tmpdir(), "enoki-release-transition-toctou-"),
    );
    const replacementPath = path.join(contents, "replacement.tar.gz");
    try {
      await execFileAsync("tar", [
        "--extract",
        "--gzip",
        "--file",
        archivePath,
        "--directory",
        contents,
      ]);
      const replacementProbe = Buffer.concat([
        await readFile(path.join(contents, "enoki-probe")),
        Buffer.from("replacement payload"),
      ]);
      const replacementManifest = JSON.parse(
        await readFile(path.join(contents, "bundle-manifest.json")),
      );
      replacementManifest.components[0].sha256 = sha256(replacementProbe);
      await Promise.all([
        writeFile(path.join(contents, "enoki-probe"), replacementProbe),
        writeFile(
          path.join(contents, "bundle-manifest.json"),
          `${JSON.stringify(replacementManifest)}\n`,
        ),
      ]);
      await execFileAsync("tar", [
        "--create",
        "--gzip",
        "--file",
        replacementPath,
        "--directory",
        contents,
        "bundle-manifest.json",
        "enoki-probe",
      ]);
      archiveSwap.replace = () => renameSync(replacementPath, archivePath);

      const signed = await createReleaseTransitionContract(local.createInput);
      expect(signed.contract.target.probeComponents).toEqual(
        local.targetProbeComponents,
      );
    } finally {
      archiveSwap.replace = null;
      await rm(contents, { force: true, recursive: true });
      await local.cleanup();
    }
  });

  it("requires the authenticated source release asset closure", async () => {
    await expect(
      createReleaseTransitionContract({
        ...fixture.createInput,
        sourceAssetDir: undefined,
      }),
    ).rejects.toThrow("source Probe asset closure is required");
  });

  it("rejects a symlinked legacy source archive before deriving its receipt", async () => {
    const local = await transitionFixture();
    const sourceArchive = path.join(
      local.createInput.sourceAssetDir,
      "enoki-probe-aarch64-unknown-linux-gnu.tar.gz",
    );
    const replacementDir = await mkdtemp(
      path.join(tmpdir(), "enoki-legacy-source-symlink-"),
    );
    const replacement = path.join(replacementDir, "authorized.tar.gz");
    try {
      await writeFile(replacement, await readFile(sourceArchive));
      await rm(sourceArchive);
      await symlink(replacement, sourceArchive);

      await expect(
        createReleaseTransitionContract(local.createInput),
      ).rejects.toThrow("legacy Probe Asset Set archive does not match");
    } finally {
      await rm(replacementDir, { force: true, recursive: true });
      await local.cleanup();
    }
  });

  it("rejects a non-regular legacy source archive before deriving its receipt", async () => {
    const local = await transitionFixture();
    const sourceArchive = path.join(
      local.createInput.sourceAssetDir,
      "enoki-probe-aarch64-unknown-linux-gnu.tar.gz",
    );
    try {
      await rm(sourceArchive);
      await mkdir(sourceArchive);

      await expect(
        createReleaseTransitionContract(local.createInput),
      ).rejects.toThrow("legacy Probe Asset Set archive does not match");
    } finally {
      await local.cleanup();
    }
  });

  it("keeps source receipts bound to the opened regular-file snapshot when its path is replaced", async () => {
    const local = await transitionFixture();
    const archivePath = path.join(
      local.createInput.sourceAssetDir,
      "enoki-probe-aarch64-unknown-linux-gnu.tar.gz",
    );
    const replacementDir = await mkdtemp(
      path.join(tmpdir(), "enoki-legacy-source-snapshot-"),
    );
    const replacement = path.join(replacementDir, "replacement.tar.gz");
    try {
      await writeFile(replacement, Buffer.from("untrusted replacement"));
      sourceArchiveSwap.replace = (openedPath) => {
        if (openedPath === archivePath) renameSync(replacement, archivePath);
      };

      const signed = await createReleaseTransitionContract(local.createInput);
      expect(signed.contract.source.probeComponents).toEqual(
        local.sourceProbeComponents,
      );
    } finally {
      sourceArchiveSwap.replace = null;
      await rm(replacementDir, { force: true, recursive: true });
      await local.cleanup();
    }
  });

  it("rejects a re-signed outer target whose archive payload disagrees with its inner receipt before signing", async () => {
    const local = await transitionFixture();
    const archiveName = "enoki-probe-aarch64-unknown-linux-gnu.tar.gz";
    const archivePath = path.join(
      local.createInput.targetAssetDir,
      archiveName,
    );
    const contents = await mkdtemp(
      path.join(tmpdir(), "enoki-release-transition-mismatch-"),
    );
    try {
      await execFileAsync("tar", [
        "--extract",
        "--gzip",
        "--file",
        archivePath,
        "--directory",
        contents,
      ]);
      await writeFile(
        path.join(contents, "enoki-probe"),
        Buffer.concat([
          await readFile(path.join(contents, "enoki-probe")),
          Buffer.from("different but still an ELF payload"),
        ]),
      );
      await execFileAsync("tar", [
        "--create",
        "--gzip",
        "--file",
        archivePath,
        "--directory",
        contents,
        "bundle-manifest.json",
        "enoki-probe",
      ]);
      const archive = await readFile(archivePath);
      const manifestPath = path.join(
        local.createInput.targetAssetDir,
        "manifest.json",
      );
      const manifest = JSON.parse(await readFile(manifestPath));
      const asset = manifest.assets.find((entry) => entry.file === archiveName);
      asset.sha256 = sha256(archive);
      asset.size = archive.byteLength;
      const manifestBytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
      await Promise.all([
        writeFile(manifestPath, manifestBytes),
        writeFile(
          path.join(local.createInput.targetAssetDir, "manifest.json.sig"),
          sign("RSA-SHA256", manifestBytes, local.release.privateKey),
        ),
        writeFile(`${archivePath}.sha256`, `${asset.sha256}  ${archiveName}\n`),
      ]);

      await expect(
        createReleaseTransitionContract(local.createInput),
      ).rejects.toThrow("Probe bundle archive closure is invalid");
    } finally {
      await rm(contents, { force: true, recursive: true });
      await local.cleanup();
    }
  });

  it("rejects a self-consistent target archive whose bundled Bootstrap identity has the wrong trust root before signing", async () => {
    const local = await transitionFixture();
    try {
      await replaceTargetArchiveWithBootstrap(local, {
        rootKeyId: "f".repeat(64),
      });

      await expect(
        createReleaseTransitionContract(local.createInput),
      ).rejects.toThrow(
        "Probe Bootstrap embedded build identity does not match",
      );
    } finally {
      await local.cleanup();
    }
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
  const target = await createVerifiedTargetAssetSet({
    delegation,
    release,
    root,
    version: "1.2.3",
  });
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
      targetAssetDir: target.assetDir,
      targetManifestBytes: target.manifestBytes,
      targetVersion: "1.2.3",
    },
    expected: {
      candidateCommit,
      delegationGeneration: 1,
      sourceCommit: legacyRelease.githubRelease.peeledCommitSha,
      sourceTag: "v0.1.74",
      targetAssetSetManifestSha256: sha256(target.manifestBytes),
      targetVersion: "1.2.3",
    },
    root,
    release,
    cleanup: async () => {
      await source.cleanup();
      await target.cleanup();
    },
    sourceProbeComponents: source.probeComponents,
    targetProbeComponents: target.probeComponents,
  };
}

async function createVerifiedTargetAssetSet({
  delegation,
  release,
  root,
  version,
}) {
  const assetDir = await mkdtemp(
    path.join(tmpdir(), "enoki-release-transition-target-"),
  );
  const assets = [];
  const probeComponents = [];
  const targets = [
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
  ];
  for (const target of targets) {
    const contents = path.join(assetDir, `${target}.contents`);
    const archiveName = `enoki-probe-${target}.tar.gz`;
    const archivePath = path.join(assetDir, archiveName);
    const probe = createProbeElf({ target, version: `v${version}` });
    const components = Object.entries(probeBundleComponentProfiles).map(
      ([role, profile]) => ({
        ...profile,
        role,
        sha256: sha256(probe),
        size: probe.byteLength,
        version,
      }),
    );
    const bundleManifest = Buffer.from(
      `${JSON.stringify({
        components,
        kind: "enoki-probe-bundle",
        target,
        version,
      })}\n`,
    );
    await mkdir(contents);
    for (const { path: componentPath } of Object.values(
      probeBundleComponentProfiles,
    )) {
      await writeFile(path.join(contents, componentPath), probe);
      await chmod(path.join(contents, componentPath), 0o755);
    }
    await writeFile(
      path.join(contents, "bundle-manifest.json"),
      bundleManifest,
    );
    await execFileAsync("tar", [
      "--create",
      "--gzip",
      "--file",
      archivePath,
      "--directory",
      contents,
      "bundle-manifest.json",
      ...Object.values(probeBundleComponentProfiles).map(
        ({ path: componentPath }) => componentPath,
      ),
    ]);
    await rm(contents, { force: true, recursive: true });
    const archive = await readFile(archivePath);
    const archiveSha256 = sha256(archive);
    await writeFile(
      `${archivePath}.sha256`,
      `${archiveSha256}  ${archiveName}\n`,
    );
    assets.push({
      bundleManifestSha256: sha256(bundleManifest),
      file: archiveName,
      sha256: archiveSha256,
      size: archive.byteLength,
      target,
    });
    probeComponents.push({
      file: "enoki-probe",
      role: "probe",
      sha256: sha256(probe),
      target,
    });
  }
  const manifestBytes = Buffer.from(
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
      version,
    })}\n`,
  );
  await Promise.all([
    writeFile(path.join(assetDir, "manifest.json"), manifestBytes),
    writeFile(
      path.join(assetDir, "manifest.json.sig"),
      sign("RSA-SHA256", manifestBytes, release.privateKey),
    ),
    writeFile(path.join(assetDir, "root-key.pem"), root.publicKey),
    writeFile(path.join(assetDir, "signing-key.pem"), release.publicKey),
    writeFile(path.join(assetDir, "trust-delegation.json"), delegation.bytes),
    writeFile(
      path.join(assetDir, "trust-delegation.json.sig"),
      delegation.signature,
    ),
  ]);
  return {
    assetDir,
    cleanup: () => rm(assetDir, { force: true, recursive: true }),
    manifestBytes,
    probeComponents,
  };
}

async function replaceTargetArchiveWithBootstrap(local, { rootKeyId }) {
  const target = "aarch64-unknown-linux-gnu";
  const archiveName = `enoki-probe-${target}.tar.gz`;
  const archivePath = path.join(local.createInput.targetAssetDir, archiveName);
  const contents = await mkdtemp(
    path.join(tmpdir(), "enoki-transition-bootstrap-"),
  );
  try {
    await execFileAsync("tar", [
      "--extract",
      "--gzip",
      "--file",
      archivePath,
      "--directory",
      contents,
    ]);
    const bundleManifestPath = path.join(contents, "bundle-manifest.json");
    const bundleManifest = JSON.parse(await readFile(bundleManifestPath));
    bundleManifest.bootstrapAssets = probeBundledBootstrapAssets.map(
      (asset) => {
        const bytes = createBootstrapElf({
          identity: {
            distribution: "enoki",
            role: asset.bootstrapBuildRole,
            rootFingerprint: rootKeyId,
            rootKeyId,
            target,
            version: "v1.2.3",
          },
          target,
        });
        const destination = path.join(contents, asset.archivePath);
        return { asset, bytes, destination };
      },
    );
    for (const { bytes, destination } of bundleManifest.bootstrapAssets) {
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, bytes, { mode: 0o755 });
      await chmod(destination, 0o755);
    }
    bundleManifest.bootstrapAssets = bundleManifest.bootstrapAssets.map(
      ({ asset, bytes }) => ({
        path: asset.archivePath,
        permissionProfile: asset.permissionProfile,
        role: asset.role,
        sha256: sha256(bytes),
        size: bytes.byteLength,
        version: "1.2.3",
      }),
    );
    const bundleManifestBytes = Buffer.from(
      `${JSON.stringify(bundleManifest)}\n`,
    );
    await writeFile(bundleManifestPath, bundleManifestBytes);
    await execFileAsync("tar", [
      "--create",
      "--gzip",
      "--file",
      archivePath,
      "--directory",
      contents,
      "bundle-manifest.json",
      ...Object.values(probeBundleComponentProfiles).map(
        ({ path: componentPath }) => componentPath,
      ),
      ...probeBundledBootstrapAssets.map(({ archivePath: member }) => member),
    ]);
    const archive = await readFile(archivePath);
    const manifestPath = path.join(
      local.createInput.targetAssetDir,
      "manifest.json",
    );
    const manifest = JSON.parse(await readFile(manifestPath));
    const asset = manifest.assets.find((entry) => entry.file === archiveName);
    asset.bundleManifestSha256 = sha256(bundleManifestBytes);
    asset.sha256 = sha256(archive);
    asset.size = archive.byteLength;
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
    await Promise.all([
      writeFile(manifestPath, manifestBytes),
      writeFile(
        path.join(local.createInput.targetAssetDir, "manifest.json.sig"),
        sign("RSA-SHA256", manifestBytes, local.release.privateKey),
      ),
      writeFile(`${archivePath}.sha256`, `${asset.sha256}  ${archiveName}\n`),
    ]);
  } finally {
    await rm(contents, { force: true, recursive: true });
  }
}

function createProbeElf({ target, version }) {
  const architecture = target.startsWith("x86_64-") ? 62 : 183;
  const interpreter = target.endsWith("-gnu")
    ? target.startsWith("x86_64-")
      ? "/lib64/ld-linux-x86-64.so.2\0"
      : "/lib/ld-linux-aarch64.so.1\0"
    : "";
  const headerSize = 64;
  const programHeaderSize = interpreter ? 56 : 0;
  const interpreterBytes = Buffer.from(interpreter);
  const markers = Buffer.from(
    `ENOKI_PROBE_TARGET=${target}\0ENOKI_PROBE_VERSION=${version}\0`,
  );
  const binary = Buffer.alloc(
    headerSize + programHeaderSize + interpreterBytes.length + markers.length,
  );
  binary.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  binary.writeUInt16LE(2, 16);
  binary.writeUInt16LE(architecture, 18);
  binary.writeUInt32LE(1, 20);
  binary.writeUInt16LE(headerSize, 52);
  binary.writeUInt16LE(56, 54);
  binary.writeUInt16LE(interpreter ? 1 : 0, 56);
  if (interpreter) {
    binary.writeBigUInt64LE(BigInt(headerSize), 32);
    binary.writeUInt32LE(3, headerSize);
    binary.writeUInt32LE(4, headerSize + 4);
    binary.writeBigUInt64LE(
      BigInt(headerSize + programHeaderSize),
      headerSize + 8,
    );
    binary.writeBigUInt64LE(BigInt(interpreterBytes.length), headerSize + 32);
    binary.writeBigUInt64LE(BigInt(interpreterBytes.length), headerSize + 40);
    binary.set(interpreterBytes, headerSize + programHeaderSize);
  }
  binary.set(markers, headerSize + programHeaderSize + interpreterBytes.length);
  return binary;
}

function createBootstrapElf({ identity, target }) {
  const machine = target.startsWith("aarch64-") ? 183 : 62;
  const names = Buffer.from("\0.shstrtab\0.enoki_bootstrap\0", "utf8");
  const payload = Buffer.from(JSON.stringify(identity), "utf8");
  const section = Buffer.concat([
    Buffer.from("ENOKI_BOOTSTRAP_BUILD_IDENTITY_V1\0", "utf8"),
    Buffer.from([
      (payload.byteLength >>> 24) & 0xff,
      (payload.byteLength >>> 16) & 0xff,
      (payload.byteLength >>> 8) & 0xff,
      payload.byteLength & 0xff,
    ]),
    payload,
  ]);
  const sectionTableOffset = 64;
  const identityOffset = sectionTableOffset + 3 * 64;
  const namesOffset = identityOffset + section.byteLength;
  const binary = Buffer.alloc(namesOffset + names.byteLength);
  binary.write("\x7fELF", 0, "binary");
  binary[4] = 2;
  binary[5] = 1;
  binary[6] = 1;
  binary.writeUInt16LE(machine, 18);
  binary.writeBigUInt64LE(BigInt(sectionTableOffset), 40);
  binary.writeUInt16LE(64, 58);
  binary.writeUInt16LE(3, 60);
  binary.writeUInt16LE(1, 62);
  writeElfSection(binary, sectionTableOffset + 64, {
    nameOffset: 1,
    offset: namesOffset,
    size: names.byteLength,
  });
  writeElfSection(binary, sectionTableOffset + 128, {
    nameOffset: 11,
    offset: identityOffset,
    size: section.byteLength,
  });
  section.copy(binary, identityOffset);
  names.copy(binary, namesOffset);
  return binary;
}

function writeElfSection(
  binary,
  offset,
  { nameOffset, offset: contents, size },
) {
  binary.writeUInt32LE(nameOffset, offset);
  binary.writeBigUInt64LE(BigInt(contents), offset + 24);
  binary.writeBigUInt64LE(BigInt(size), offset + 32);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
