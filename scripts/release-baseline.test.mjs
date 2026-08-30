import { execFile } from "node:child_process";
import { createHash, createPublicKey, sign as signContents } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import {
  createProbeTrustDelegation,
  createReleaseTransitionContract,
  createTrustEpochMigrationAuthorization,
  probeTargets,
} from "@enoki/probe-release";
import { createSignedLegacyProbeAssetSetFixture } from "@enoki/probe-release/test-fixture";
import { describe, expect, it } from "vitest";

import { packageProbeBootstrapArtifact } from "./probe-bootstrap-artifact.mjs";
import {
  createGhcrRegistryClient,
  createGitHubReleaseClient,
  recheckReleaseBaseline,
  resolveReleaseBaseline,
  selectReleaseBaseline,
  validateReleaseBaselineBundle,
  validateResolvedReleaseBaseline,
} from "./release-baseline-lib.mjs";
import { prepareProbeAssetSet } from "./release-candidate-lib.mjs";
import { rsa4096TestKeyPair } from "./test-rsa-key-pool.mjs";

const execFileAsync = promisify(execFile);
const indexMediaType = "application/vnd.oci.image.index.v1+json";
const manifestMediaType = "application/vnd.oci.image.manifest.v1+json";
const configMediaType = "application/vnd.oci.image.config.v1+json";
const layerMediaType = "application/vnd.oci.image.layer.v1.tar";
const commitSha = "1".repeat(40);
const tagSha = "2".repeat(40);
// Keep real RSA-4096 fixture setup bounded on shared CI while reusing named
// identities instead of regenerating an expensive key for each test.
const rsa4096FixtureTimeoutMs = 15_000;

describe("Release Baseline resolution", () => {
  it("selects the highest published stable SemVer below the candidate", () => {
    const selected = selectReleaseBaseline({
      candidateVersion: "v2.0.0",
      releases: [
        release("v0.9.8"),
        release("v1.7.2"),
        release("v1.2.0"),
        release("v0.10.0"),
      ],
    });
    expect(selected.tagName).toBe("v1.7.2");
  });

  it("orders arbitrarily large SemVer components without Number precision loss", () => {
    const selected = selectReleaseBaseline({
      candidateVersion: "v90071992547409931234567891.0.0",
      releases: [
        release("v90071992547409931234567889.999999999999999999999.0"),
        release("v90071992547409931234567890.0.0"),
      ],
    });
    expect(selected.tagName).toBe("v90071992547409931234567890.0.0");
  });

  it("rejects a candidate that is not newer than every stable release", () => {
    expect(() =>
      selectReleaseBaseline({
        candidateVersion: "v1.7.2",
        releases: [release("v1.6.9"), release("v1.7.2")],
      }),
    ).toThrow("must be newer than published stable release v1.7.2");
  });

  it("excludes prereleases, drafts, malformed tags, and convenience refs", () => {
    const selected = selectReleaseBaseline({
      candidateVersion: "v2.0.0",
      releases: [
        release("v1.8.0", { prerelease: true }),
        release("v1.7.0", { draft: true }),
        release("v1.6.0-rc.1"),
        release("latest"),
        release("1.5.0"),
        release("v1.4.0"),
      ],
    });
    expect(selected.tagName).toBe("v1.4.0");
  });

  it("requires a published Release Baseline", () => {
    expect(() =>
      selectReleaseBaseline({
        candidateVersion: "v0.1.0",
        releases: [release("v0.1.0-rc.1", { prerelease: true })],
      }),
    ).toThrow("no published Release Baseline exists");
  });

  it("hard-deletes the historical empty-baseline branch", async () => {
    const files = await Promise.all(
      [
        ".github/workflows/release.yml",
        ".github/workflows/reusable-build-release-candidate.yml",
        "scripts/release-baseline.mjs",
        "scripts/release-baseline-lib.mjs",
        "scripts/release-candidate-lib.mjs",
        "scripts/release-e2e-lib.mjs",
        "scripts/release-verification-lib.mjs",
      ].map((file) => readFile(file, "utf8")),
    );
    expect(files.join("\n")).not.toContain(
      ["first", "formal", "release"].join("-"),
    );
  });

  it(
    "rejects a self-signed baseline outside the canonical production trust root",
    async () => {
      const fixture = await createResolverFixture();
      const { publicKey: unrelatedPublicKey } =
        rsa4096TestKeyPair("baseline-unrelated");
      try {
        fixture.arguments_.trustedRootPublicKeyPem = unrelatedPublicKey;
        await expect(
          resolveReleaseBaseline(fixture.arguments_),
        ).rejects.toThrow(
          "root key does not match the trusted Probe Distribution Trust Root",
        );
      } finally {
        await fixture.cleanup();
      }
    },
    rsa4096FixtureTimeoutMs,
  );

  it("accepts legacy Probe binaries without identity markers only after trust-root and signature verification", async () => {
    const fixture = await createResolverFixture({ legacyProbe: true });
    try {
      await expect(
        resolveReleaseBaseline(fixture.arguments_),
      ).resolves.toMatchObject({ tag: "v1.7.2" });
    } finally {
      await fixture.cleanup();
    }
  });

  it("normalizes the root-authorized migration identity for the strict E2E baseline schema", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      const descriptor = await resolveReleaseBaseline(fixture.arguments_);
      expect(descriptor).toMatchObject({
        kind: "enoki-trust-epoch-migration-baseline",
        schemaVersion: 1,
        tag: "v0.1.74",
        transition: "replacement-required",
      });
      expect(Object.keys(descriptor.githubRelease).sort()).toEqual([
        "id",
        "peeledCommitSha",
        "repository",
        "tagRefSha",
        "targetCommitish",
      ]);
      await expect(
        recheckReleaseBaseline({
          bundleDir: fixture.outputDir,
          candidateVersion: "v0.1.75",
          githubRepository: "YKDZ/enoki",
          releaseCatalog: fixture.arguments_.releaseCatalog,
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).resolves.toMatchObject({ transition: "replacement-required" });

      const descriptorPath = path.join(
        fixture.outputDir,
        "release-baseline.json",
      );
      const persisted = JSON.parse(await readFile(descriptorPath, "utf8"));
      persisted.githubRelease.tag = persisted.tag;
      await writeFile(descriptorPath, `${JSON.stringify(persisted)}\n`);
      await expect(
        validateResolvedReleaseBaseline(fixture.outputDir, {
          candidateVersion: "v0.1.75",
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow("fields are invalid");
    } finally {
      await fixture.cleanup();
    }
  });

  it("keeps the first rooted release publication closure as an ordinary v0.1.76 baseline", async () => {
    const fixture = await createResolverFixture({
      candidateVersion: "v0.1.76",
      historicalTransition: true,
      version: "v0.1.75",
    });
    try {
      const descriptor = await resolveReleaseBaseline(fixture.arguments_);
      expect(descriptor).toMatchObject({
        kind: "enoki-release-baseline",
        tag: "v0.1.75",
      });
      expect(descriptor.probeAssetSet).not.toHaveProperty("releaseTransition");
      expect(descriptor.probeAssetSet.files.map(({ file }) => file)).toEqual(
        expect.arrayContaining([
          "release-transition-contract.json",
          "release-transition-contract.json.sig",
          "trust-epoch-migration-authorization.json",
          "trust-epoch-migration-authorization.json.sig",
        ]),
      );
    } finally {
      await fixture.cleanup();
    }
  });

  it("keeps the ordinary rooted failure when migration material is unavailable", async () => {
    const fixture = await createResolverFixture({ legacyTrustEpoch: true });
    try {
      fixture.release.tagName = "v0.1.74";
      fixture.releaseIdentity.tagName = "v0.1.74";
      fixture.releaseIdentity.assets = fixture.release.assets;
      fixture.arguments_.candidateVersion = "v0.1.75";
      const error = await resolveReleaseBaseline(fixture.arguments_).catch(
        (caught) => caught,
      );
      expect(error).toMatchObject({
        classification: "rooted-baseline-metadata-closure-missing",
        code: "RELEASE_BASELINE_ROOT_METADATA_CLOSURE_MISSING",
      });
      expect(error.message).toContain("must contain exactly");
    } finally {
      await fixture.cleanup();
    }
  });

  it("rejects an extra migration baseline Hub directory member", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      await resolveReleaseBaseline(fixture.arguments_);
      await writeFile(path.join(fixture.outputDir, "hub", "extra"), "extra");
      await expect(
        validateResolvedReleaseBaseline(fixture.outputDir, {
          candidateVersion: "v0.1.75",
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow("Hub directory must contain exactly");
    } finally {
      await fixture.cleanup();
    }
  });

  it("does not classify another legacy tag as the trust epoch migration", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      fixture.release.tagName = "v0.1.73";
      fixture.releaseIdentity.tagName = "v0.1.73";
      fixture.arguments_.candidateVersion = "v0.1.75";
      await expect(resolveReleaseBaseline(fixture.arguments_)).rejects.toThrow(
        "must contain exactly",
      );
    } finally {
      await fixture.cleanup();
    }
  });

  it("materializes and offline-validates one complete linux/amd64 OCI archive", async () => {
    const fixture = await createResolverFixture();
    try {
      const descriptor = await resolveReleaseBaseline(fixture.arguments_);
      expect(descriptor).toMatchObject({
        githubRelease: {
          id: 172,
          peeledCommitSha: commitSha,
          tagRefSha: tagSha,
          targetCommitish: "main",
        },
        hub: {
          imageDigest: fixture.hub.imageManifest.descriptor.digest,
          platform: { architecture: "amd64", os: "linux" },
        },
        kind: "enoki-release-baseline",
        schemaVersion: 2,
        tag: "v1.7.2",
      });
      expect(await readdir(path.join(fixture.outputDir, "hub"))).toEqual([
        "enoki-hub-v1.7.2.oci.tar",
      ]);
      const archivePath = path.join(
        fixture.outputDir,
        "hub",
        "enoki-hub-v1.7.2.oci.tar",
      );
      const { stdout: archiveMembers } = await execFileAsync("tar", [
        "--list",
        "--file",
        archivePath,
      ]);
      expect(archiveMembers.split("\n")).toContain("index.json");
      expect(archiveMembers.split("\n")).not.toContain("./index.json");
      await expect(
        validateReleaseBaselineBundle(fixture.outputDir, {
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).resolves.toEqual(descriptor);
    } finally {
      await fixture.cleanup();
    }
  });

  it("accepts the historical Hub asset layout only when it differs by checksum sidecars", async () => {
    const fixture = await createResolverFixture({ legacyHubAssets: true });
    try {
      await expect(
        resolveReleaseBaseline(fixture.arguments_),
      ).resolves.toMatchObject({ tag: "v1.7.2" });
    } finally {
      await fixture.cleanup();
    }
  });

  it("rejects a Hub index with the wrong runnable platform", async () => {
    const fixture = await createResolverFixture({ architecture: "arm64" });
    try {
      await expect(resolveReleaseBaseline(fixture.arguments_)).rejects.toThrow(
        "exactly one runnable linux/amd64 image",
      );
    } finally {
      await fixture.cleanup();
    }
  });

  it("rejects an attestation-only Hub index", async () => {
    const fixture = await createResolverFixture({ attestationOnly: true });
    try {
      await expect(resolveReleaseBaseline(fixture.arguments_)).rejects.toThrow(
        "exactly one runnable linux/amd64 image",
      );
    } finally {
      await fixture.cleanup();
    }
  });

  it("rejects a missing Hub layer before materializing the bundle", async () => {
    const fixture = await createResolverFixture();
    try {
      fixture.hub.layers = [];
      await expect(resolveReleaseBaseline(fixture.arguments_)).rejects.toThrow(
        "missing image layers",
      );
    } finally {
      await fixture.cleanup();
    }
  });

  it("rejects tampered Hub layer bytes before materializing the bundle", async () => {
    const fixture = await createResolverFixture();
    try {
      fixture.hub.layers[0].bytes[0] ^= 0xff;
      await expect(resolveReleaseBaseline(fixture.arguments_)).rejects.toThrow(
        "digest or size does not match",
      );
    } finally {
      await fixture.cleanup();
    }
  });

  it("fails offline validation when a materialized OCI archive is tampered", async () => {
    const fixture = await createResolverFixture();
    try {
      await resolveReleaseBaseline(fixture.arguments_);
      const archivePath = path.join(
        fixture.outputDir,
        "hub",
        "enoki-hub-v1.7.2.oci.tar",
      );
      const archive = await readFile(archivePath);
      archive[archive.length - 1] ^= 0xff;
      await writeFile(archivePath, archive);
      await expect(
        validateReleaseBaselineBundle(fixture.outputDir, {
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow("OCI archive does not match its descriptor");
    } finally {
      await fixture.cleanup();
    }
  });

  it("supports a registry Bearer challenge while recursively fetching manifests, config, and layers", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-registry-"));
    try {
      const probe = await createProbeAssetSetFixture(workDir, "v1.7.2");
      const hub = await createHubClosureFixture(workDir, probe.outputDir);
      const requests = [];
      const registry = createGhcrRegistryClient({
        fetchImpl: registryFetchFixture({ hub, requests }),
      });
      await expect(
        registry.downloadImage({
          image: "ghcr.io/ykdz/enoki-hub",
          reference: "v1.7.2",
        }),
      ).resolves.toMatchObject({
        platform: { architecture: "amd64", os: "linux" },
      });
      expect(requests.some((request) => request.includes("/token?"))).toBe(
        true,
      );
      expect(
        requests.filter((request) => request.includes("/blobs/")),
      ).toHaveLength(2);
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("fails registry resolution when a recursively referenced blob is missing", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-registry-"));
    try {
      const probe = await createProbeAssetSetFixture(workDir, "v1.7.2");
      const hub = await createHubClosureFixture(workDir, probe.outputDir);
      const registry = createGhcrRegistryClient({
        fetchImpl: registryFetchFixture({ hub, missingLayer: true }),
      });
      await expect(
        registry.downloadImage({
          image: "ghcr.io/ykdz/enoki-hub",
          reference: "v1.7.2",
        }),
      ).rejects.toThrow("HTTP 404");
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("pins the GitHub release association, annotated tag ref, and peeled commit", async () => {
    const requests = [];
    const client = createGitHubReleaseClient({
      apiBaseUrl: "https://api.github.test",
      fetchImpl: githubFetchFixture(requests),
      repository: "YKDZ/enoki",
      token: "test-token",
    });
    const releases = await client.listReleases();
    await expect(
      client.resolveReleaseIdentity({ tagName: "v1.7.2" }),
    ).resolves.toMatchObject({
      id: 172,
      peeledCommitSha: commitSha,
      tagRefSha: tagSha,
      targetCommitish: "main",
    });
    expect(releases[0].targetCommitish).toBe("main");
    expect(requests).toContain(
      `https://api.github.test/repos/YKDZ/enoki/git/tags/${tagSha}`,
    );
  });

  it("final recheck fails if the stable catalog changes after resolution", async () => {
    const fixture = await createResolverFixture();
    try {
      await resolveReleaseBaseline(fixture.arguments_);
      fixture.releases.push(release("v1.8.0"));
      await expect(
        recheckReleaseBaseline({
          bundleDir: fixture.outputDir,
          candidateVersion: "v2.0.0",
          githubRepository: "YKDZ/enoki",
          releaseCatalog: fixture.arguments_.releaseCatalog,
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow("catalog changed");
    } finally {
      await fixture.cleanup();
    }
  });

  it("final recheck fails if the tag is retargeted with an unchanged release catalog", async () => {
    const fixture = await createResolverFixture();
    try {
      await resolveReleaseBaseline(fixture.arguments_);
      fixture.releaseIdentity.peeledCommitSha = "3".repeat(40);
      await expect(
        recheckReleaseBaseline({
          bundleDir: fixture.outputDir,
          candidateVersion: "v2.0.0",
          githubRepository: "YKDZ/enoki",
          releaseCatalog: fixture.arguments_.releaseCatalog,
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow("tag identity changed");
    } finally {
      await fixture.cleanup();
    }
  });

  it("fails closed on incomplete or digest-mismatched Probe assets", async () => {
    const incomplete = await createResolverFixture();
    try {
      incomplete.release.assets = incomplete.release.assets.filter(
        ({ name }) => name !== "manifest.json",
      );
      incomplete.releaseIdentity.assets = incomplete.release.assets;
      await expect(
        resolveReleaseBaseline(incomplete.arguments_),
      ).rejects.toThrow("Probe Asset Set must contain exactly");
    } finally {
      await incomplete.cleanup();
    }

    const tampered = await createResolverFixture();
    try {
      tampered.contents.set("manifest.json", Buffer.from("tampered"));
      await expect(resolveReleaseBaseline(tampered.arguments_)).rejects.toThrow(
        "published digest or size",
      );
    } finally {
      await tampered.cleanup();
    }
  });

  it("exposes resolve, validate, and final recheck through the shared CLI path", async () => {
    const workflow = await readFile(
      ".github/workflows/reusable-build-release-candidate.yml",
      "utf8",
    );
    const releaseWorkflow = await readFile(
      ".github/workflows/release.yml",
      "utf8",
    );
    expect(workflow).toContain(
      "PRODUCTION_PROBE_PUBLIC_KEY: ${{ vars.ENOKI_PROBE_ASSET_SIGNING_PUBLIC_KEY_PEM }}",
    );
    expect(workflow).toContain("release-baseline.mjs recheck");
    expect(workflow).toContain("--trusted-root-public-key-env");
    expect(workflow).toContain(
      "TRUST_EPOCH_MIGRATION_AUTHORIZATION: ${{ vars.ENOKI_TRUST_EPOCH_MIGRATION_AUTHORIZATION_JSON }}",
    );
    expect(workflow).toContain(
      "RELEASE_TRANSITION_CONTRACT: ${{ vars.ENOKI_RELEASE_TRANSITION_CONTRACT_JSON }}",
    );
    expect(workflow).toContain(
      'if [ "$RELEASE_BASELINE_KIND" = "enoki-trust-epoch-migration-baseline" ]; then',
    );
    expect(releaseWorkflow).not.toMatch(
      /trust[_-]epoch|skip[_-]baseline|legacy[_-]signing/i,
    );
    expect(releaseWorkflow).toContain("group: enoki-release-global");
  });
});

function release(tagName, overrides = {}) {
  return {
    assets: [],
    draft: false,
    id: 172,
    prerelease: false,
    tagName,
    targetCommitish: "main",
    ...overrides,
  };
}

async function createResolverFixture(options = {}) {
  const workDir = await mkdtemp(path.join(tmpdir(), "enoki-baseline-"));
  const version = options.version ?? "v1.7.2";
  const probe = await createProbeAssetSetFixture(workDir, version, {
    legacyProbe: options.legacyProbe,
  });
  if (options.historicalTransition) {
    const sourceRelease = rsa4096TestKeyPair("baseline-legacy-release");
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
      candidateVersion: version,
      distribution: "enoki",
      legacyRelease,
      rootPrivateKeyPem: probe.root.privateKey,
    });
    const transition = await createReleaseTransitionContract({
      authorizationBytes: authorization.bytes,
      authorizationSignature: authorization.signature,
      candidateCommit: commitSha,
      delegationBytes: await readFile(
        path.join(probe.outputDir, "trust-delegation.json"),
      ),
      delegationSignature: await readFile(
        path.join(probe.outputDir, "trust-delegation.json.sig"),
      ),
      legacyRelease,
      rootPrivateKeyPem: probe.root.privateKey,
      rootPublicKeyPem: probe.root.publicKey,
      sourceAssetDir: source.assetDir,
      targetAssetDir: probe.outputDir,
      targetVersion: version.slice(1),
    });
    await source.cleanup();
    await Promise.all([
      writeFile(
        path.join(probe.outputDir, "release-transition-contract.json"),
        transition.bytes,
      ),
      writeFile(
        path.join(probe.outputDir, "release-transition-contract.json.sig"),
        transition.signature,
      ),
      writeFile(
        path.join(probe.outputDir, "trust-epoch-migration-authorization.json"),
        authorization.bytes,
      ),
      writeFile(
        path.join(
          probe.outputDir,
          "trust-epoch-migration-authorization.json.sig",
        ),
        authorization.signature,
      ),
    ]);
  }
  if (options.legacyTrustEpoch) {
    await Promise.all(
      [
        "root-key.pem",
        "trust-delegation.json",
        "trust-delegation.json.sig",
      ].map((file) => rm(path.join(probe.outputDir, file))),
    );
  }
  const hub = await createHubClosureFixture(workDir, probe.outputDir, options);
  const contents = new Map();
  for (const name of await readdir(probe.outputDir)) {
    contents.set(name, await readFile(path.join(probe.outputDir, name)));
  }
  const assets = [...contents]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, bytes], index) => ({
      digest: `sha256:${sha256(bytes)}`,
      id: index + 1,
      name,
      size: bytes.byteLength,
    }));
  const release_ = release(version, { assets });
  const releases = [release_];
  const releaseIdentity = {
    assets,
    id: release_.id,
    peeledCommitSha: commitSha,
    tagName: release_.tagName,
    tagRefSha: tagSha,
    targetCommitish: release_.targetCommitish,
  };
  const outputDir = path.join(workDir, "release-baseline");
  return {
    arguments_: {
      assetDownloader: {
        downloadAsset: async ({ asset }) => contents.get(asset.name),
      },
      candidateVersion: options.candidateVersion ?? "v2.0.0",
      githubRepository: "YKDZ/enoki",
      hubImage: "ghcr.io/ykdz/enoki-hub",
      outputDir,
      registry: { downloadImage: async () => hub },
      releaseCatalog: {
        listReleases: async () => releases,
        resolveReleaseIdentity: async () => releaseIdentity,
      },
      trustedRootPublicKeyPem: probe.root.publicKey,
    },
    cleanup: () => rm(workDir, { force: true, recursive: true }),
    contents,
    hub,
    outputDir,
    probe,
    release: release_,
    releaseIdentity,
    releases,
  };
}

async function createLegacyTrustEpochFixture() {
  const fixture = await createResolverFixture({ legacyTrustEpoch: true });
  fixture.release.tagName = "v0.1.74";
  fixture.releaseIdentity.tagName = "v0.1.74";
  fixture.releaseIdentity.assets = fixture.release.assets;
  fixture.arguments_.candidateVersion = "v0.1.75";
  const expectedLegacyRelease = {
    assets: fixture.release.assets.map((asset) => ({
      name: asset.name,
      sha256: asset.digest.slice("sha256:".length),
      size: asset.size,
    })),
    githubRelease: {
      id: fixture.releaseIdentity.id,
      peeledCommitSha: fixture.releaseIdentity.peeledCommitSha,
      repository: "YKDZ/enoki",
      tag: "v0.1.74",
      tagRefSha: fixture.releaseIdentity.tagRefSha,
      targetCommitish: fixture.releaseIdentity.targetCommitish,
    },
    hub: {
      digest: fixture.hub.sourceManifest.descriptor.digest,
      image: "ghcr.io/ykdz/enoki-hub",
    },
    legacySigningKeySha256: sha256(Buffer.from(fixture.probe.publicKey)),
  };
  const authorization = createTrustEpochMigrationAuthorization({
    candidateVersion: "v0.1.75",
    distribution: "enoki",
    legacyRelease: expectedLegacyRelease,
    rootPrivateKeyPem: fixture.probe.root.privateKey,
  });
  fixture.arguments_.trustEpochMigrationAuthorizationBytes =
    authorization.bytes;
  fixture.arguments_.trustEpochMigrationAuthorizationSignature =
    authorization.signature;
  return fixture;
}

async function createProbeAssetSetFixture(
  workDir,
  version,
  { legacyProbe = false } = {},
) {
  const archivesDir = path.join(workDir, "archives");
  const outputDir = path.join(workDir, "probe-assets-source");
  const { privateKey, publicKey } = rsa4096TestKeyPair("baseline-release");
  const root = rsa4096TestKeyPair("baseline-root");
  const delegation = createProbeTrustDelegation({
    distribution: "enoki",
    generation: 1,
    releasePublicKeyPem: publicKey,
    rootPrivateKeyPem: root.privateKey,
  });
  const delegationPath = path.join(workDir, "trust-delegation.json");
  const delegationSignaturePath = path.join(
    workDir,
    "trust-delegation.json.sig",
  );
  await writeFile(delegationPath, delegation.bytes);
  await writeFile(delegationSignaturePath, delegation.signature);
  await mkdir(archivesDir, { recursive: true });
  for (const target of probeTargets) {
    const file = `enoki-probe-${target}.tar.gz`;
    await writeProbeArchive(path.join(archivesDir, file), {
      legacyProbe: false,
      target,
      version,
    });
    const contents = await readFile(path.join(archivesDir, file));
    await writeFile(
      path.join(archivesDir, `${file}.sha256`),
      `${sha256(contents)}  ${file}\n`,
    );
  }
  const bootstrapArchivesDir = await createBootstrapArchives(
    workDir,
    root,
    version,
  );
  await prepareProbeAssetSet({
    archivesDir,
    bootstrapArchivesDir,
    outputDir,
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
    rootPublicKeyPem: root.publicKey,
    delegationBytes: delegation.bytes,
    delegationSignature: delegation.signature,
    distribution: "enoki",
    version,
  });
  if (legacyProbe) {
    const manifestPath = path.join(outputDir, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    for (const asset of manifest.assets) {
      const replacement = await writeProbeArchive(
        path.join(outputDir, asset.file),
        {
          legacyProbe: true,
          target: asset.target,
          version,
        },
      );
      const archive = await readFile(path.join(outputDir, asset.file));
      asset.bundleManifestSha256 = replacement.bundleManifestSha256;
      asset.sha256 = sha256(archive);
      asset.size = archive.byteLength;
      await writeFile(
        path.join(outputDir, `${asset.file}.sha256`),
        `${asset.sha256}  ${asset.file}\n`,
      );
    }
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
    await writeFile(manifestPath, manifestBytes);
    await writeFile(
      path.join(outputDir, "manifest.json.sig"),
      signContents("RSA-SHA256", manifestBytes, privateKey),
    );
  }
  return { outputDir, privateKey, publicKey, root };
}

async function createBootstrapArchives(workDir, root, version) {
  const outputDir = path.join(workDir, `probe-bootstrap-${version}`);
  const rootKeyId = sha256(
    createPublicKey(root.publicKey).export({ format: "pem", type: "spki" }),
  );
  for (const target of probeTargets) {
    const binariesDir = path.join(workDir, `bootstrap-${target}`);
    await mkdir(binariesDir, { recursive: true });
    const identity = {
      distribution: "enoki",
      rootFingerprint: rootKeyId,
      rootKeyId,
      target,
      version,
    };
    const acquirerPath = path.join(
      binariesDir,
      "enoki-probe-bootstrap-acquire",
    );
    const activatorPath = path.join(
      binariesDir,
      "enoki-probe-bootstrap-activate",
    );
    await writeFile(
      acquirerPath,
      createBootstrapElf({ ...identity, role: "acquirer" }),
      { mode: 0o755 },
    );
    await writeFile(
      activatorPath,
      createBootstrapElf({ ...identity, role: "activator" }),
      { mode: 0o755 },
    );
    await packageProbeBootstrapArtifact({
      binaries: { acquirerPath, activatorPath },
      distribution: "enoki",
      outputDir,
      rootKeyId,
      sourceDateEpoch: "0",
      target,
      version,
    });
  }
  return outputDir;
}

function createBootstrapElf(identity) {
  const machine = identity.target.startsWith("aarch64") ? 183 : 62;
  const names = Buffer.from("\0.shstrtab\0.enoki_bootstrap\0");
  const payload = Buffer.from(JSON.stringify(identity));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.byteLength);
  const marker = Buffer.concat([
    Buffer.from("ENOKI_BOOTSTRAP_BUILD_IDENTITY_V1\0"),
    length,
    payload,
  ]);
  const sectionOffset = 64;
  const identityOffset = sectionOffset + 3 * 64;
  const namesOffset = identityOffset + marker.byteLength;
  const binary = Buffer.alloc(namesOffset + names.byteLength);
  binary.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  binary.writeUInt16LE(machine, 18);
  binary.writeBigUInt64LE(BigInt(sectionOffset), 40);
  binary.writeUInt16LE(64, 58);
  binary.writeUInt16LE(3, 60);
  binary.writeUInt16LE(1, 62);
  writeBootstrapSection(
    binary,
    sectionOffset + 64,
    1,
    namesOffset,
    names.length,
  );
  writeBootstrapSection(
    binary,
    sectionOffset + 128,
    11,
    identityOffset,
    marker.length,
  );
  marker.copy(binary, identityOffset);
  names.copy(binary, namesOffset);
  return binary;
}

function writeBootstrapSection(binary, at, name, contents, size) {
  binary.writeUInt32LE(name, at);
  binary.writeBigUInt64LE(BigInt(contents), at + 24);
  binary.writeBigUInt64LE(BigInt(size), at + 32);
}

async function writeProbeArchive(
  archivePath,
  { legacyProbe, target, version },
) {
  const bootstrapAssets = [];
  for (const [member, permissionProfile, role] of [
    [
      "bootstrap/enoki-probe-bootstrap-acquire",
      "bootstrap-acquirer-v1",
      "bootstrap-acquirer",
    ],
    [
      "bootstrap/enoki-probe-bootstrap-activate",
      "bootstrap-activator-v1",
      "bootstrap-activator",
    ],
  ]) {
    try {
      const { stdout } = await execFileAsync(
        "tar",
        ["-xOzf", archivePath, member],
        { encoding: "buffer" },
      );
      bootstrapAssets.push({ bytes: stdout, member, permissionProfile, role });
    } catch {
      bootstrapAssets.length = 0;
      break;
    }
  }
  const binaryDir = `${archivePath}.contents`;
  await mkdir(binaryDir, { recursive: true });
  const binaryPath = path.join(binaryDir, "enoki-probe");
  await writeFile(
    binaryPath,
    createProbeElf({ includeIdentity: !legacyProbe, target, version }),
  );
  await chmod(binaryPath, 0o755);
  const binary = await readFile(binaryPath);
  for (const rolePath of [
    "enoki-observation-runtime",
    "enoki-cpu-resource-provider",
    "enoki-disk-health-resource-provider",
    "enoki-probe-lifecycle-companion",
  ]) {
    await writeFile(path.join(binaryDir, rolePath), binary, { mode: 0o755 });
  }
  const bundleManifest = Buffer.from(
    `${JSON.stringify({
      ...(bootstrapAssets.length
        ? {
            bootstrapAssets: bootstrapAssets.map(
              ({ bytes, member, permissionProfile, role }) => ({
                path: member,
                permissionProfile,
                role,
                sha256: sha256(bytes),
                size: bytes.byteLength,
                version: version.slice(1),
              }),
            ),
          }
        : {}),
      components: [
        {
          path: "enoki-probe",
          permissionProfile: "probe-v5",
          resourceContract: "hub-reporting-v1",
          role: "probe",
          sha256: sha256(binary),
          size: binary.byteLength,
          version: version.slice(1),
        },
        {
          path: "enoki-observation-runtime",
          permissionProfile: "observation-runtime-v4",
          resourceContract: "official-observation-v2",
          role: "observation-runtime",
          sha256: sha256(binary),
          size: binary.byteLength,
          version: version.slice(1),
        },
        {
          path: "enoki-cpu-resource-provider",
          permissionProfile: "system-state-provider-v5",
          resourceContract: "system-state-v3",
          role: "system-state-provider",
          sha256: sha256(binary),
          size: binary.byteLength,
          version: version.slice(1),
        },
        {
          path: "enoki-disk-health-resource-provider",
          permissionProfile: "disk-health-provider-v3",
          resourceContract: "disk-health-v1",
          role: "disk-health-provider",
          sha256: sha256(binary),
          size: binary.byteLength,
          version: version.slice(1),
        },
        {
          path: "enoki-probe-lifecycle-companion",
          permissionProfile: "lifecycle-companion-v3",
          resourceContract: "local-lifecycle-v1",
          role: "lifecycle-companion",
          sha256: sha256(binary),
          size: binary.byteLength,
          version: version.slice(1),
        },
      ],
      kind: "enoki-probe-bundle",
      target,
      version: version.slice(1),
    })}\n`,
  );
  await writeFile(path.join(binaryDir, "bundle-manifest.json"), bundleManifest);
  for (const { bytes, member } of bootstrapAssets) {
    const destination = path.join(binaryDir, member);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, bytes, { mode: 0o755 });
  }
  await execFileAsync("tar", [
    "--create",
    "--gzip",
    "--file",
    archivePath,
    "--directory",
    binaryDir,
    "bundle-manifest.json",
    "enoki-probe",
    "enoki-observation-runtime",
    "enoki-cpu-resource-provider",
    "enoki-disk-health-resource-provider",
    "enoki-probe-lifecycle-companion",
    ...bootstrapAssets.map(({ member }) => member),
  ]);
  await rm(binaryDir, { force: true, recursive: true });
  return { bundleManifestSha256: sha256(bundleManifest) };
}

function createProbeElf({ includeIdentity, target, version }) {
  const architecture = target.startsWith("x86_64-") ? 62 : 183;
  const interpreter = target.endsWith("-gnu")
    ? target.startsWith("x86_64-")
      ? "/lib64/ld-linux-x86-64.so.2\0"
      : "/lib/ld-linux-aarch64.so.1\0"
    : "";
  const headerSize = 64;
  const programHeaderSize = interpreter ? 56 : 0;
  const marker = includeIdentity
    ? Buffer.from(
        `ENOKI_PROBE_TARGET=${target}\0ENOKI_PROBE_VERSION=${version}\0`,
      )
    : Buffer.alloc(0);
  const interpreterBytes = Buffer.from(interpreter);
  const result = Buffer.alloc(
    headerSize + programHeaderSize + interpreterBytes.length + marker.length,
  );
  result.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  result.writeUInt16LE(2, 16);
  result.writeUInt16LE(architecture, 18);
  result.writeUInt32LE(1, 20);
  result.writeUInt16LE(headerSize, 52);
  result.writeUInt16LE(56, 54);
  result.writeUInt16LE(interpreter ? 1 : 0, 56);
  if (interpreter) {
    result.writeBigUInt64LE(BigInt(headerSize), 32);
    result.writeUInt32LE(3, headerSize);
    result.writeUInt32LE(4, headerSize + 4);
    result.writeBigUInt64LE(
      BigInt(headerSize + programHeaderSize),
      headerSize + 8,
    );
    result.writeBigUInt64LE(BigInt(interpreterBytes.length), headerSize + 32);
    result.writeBigUInt64LE(BigInt(interpreterBytes.length), headerSize + 40);
    result.set(interpreterBytes, headerSize + programHeaderSize);
  }
  result.set(marker, headerSize + programHeaderSize + interpreterBytes.length);
  return result;
}

async function createHubClosureFixture(
  workDir,
  probeAssetSetDir,
  {
    architecture = "amd64",
    attestationOnly = false,
    legacyHubAssets = false,
  } = {},
) {
  const rootfsDir = path.join(workDir, `hub-rootfs-${architecture}`);
  const embeddedAssetsDir = path.join(rootfsDir, "app", "probe-assets");
  await mkdir(embeddedAssetsDir, { recursive: true });
  if (legacyHubAssets) {
    for (const file of await readdir(probeAssetSetDir)) {
      if (!file.endsWith(".tar.gz.sha256")) {
        await cp(
          path.join(probeAssetSetDir, file),
          path.join(embeddedAssetsDir, file),
        );
      }
    }
  } else {
    await cp(probeAssetSetDir, embeddedAssetsDir, { recursive: true });
  }
  const layerPath = path.join(workDir, `hub-layer-${architecture}.tar`);
  await execFileAsync("tar", ["-cf", layerPath, "-C", rootfsDir, "."]);
  const layerBytes = await readFile(layerPath);
  const layer = content(layerBytes, layerMediaType);
  const config = content(
    Buffer.from(
      `${JSON.stringify({
        architecture,
        os: "linux",
        rootfs: {
          diff_ids: [layer.descriptor.digest],
          type: "layers",
        },
      })}\n`,
    ),
    configMediaType,
  );
  const imageManifest = content(
    Buffer.from(
      `${JSON.stringify({
        config: config.descriptor,
        layers: [layer.descriptor],
        mediaType: manifestMediaType,
        schemaVersion: 2,
      })}\n`,
    ),
    manifestMediaType,
  );
  const attestationBytes = Buffer.from(
    `${JSON.stringify({
      config: config.descriptor,
      layers: [],
      mediaType: manifestMediaType,
      schemaVersion: 2,
    })}\n`,
  );
  const attestation = content(attestationBytes, manifestMediaType);
  const manifests = attestationOnly
    ? [
        {
          ...attestation.descriptor,
          annotations: {
            "vnd.docker.reference.type": "attestation-manifest",
          },
          platform: { architecture: "unknown", os: "unknown" },
        },
      ]
    : [
        {
          ...imageManifest.descriptor,
          platform: { architecture, os: "linux" },
        },
        {
          ...attestation.descriptor,
          annotations: {
            "vnd.docker.reference.type": "attestation-manifest",
          },
          platform: { architecture: "unknown", os: "unknown" },
        },
      ];
  const sourceManifest = content(
    Buffer.from(`${JSON.stringify({ manifests, schemaVersion: 2 })}\n`),
    indexMediaType,
  );
  return {
    config,
    imageManifest,
    layers: [layer],
    platform: { architecture: "amd64", os: "linux" },
    sourceManifest,
  };
}

function content(bytes, mediaType) {
  return {
    bytes: Buffer.from(bytes),
    descriptor: {
      digest: `sha256:${sha256(bytes)}`,
      mediaType,
      size: bytes.byteLength,
    },
  };
}

function registryFetchFixture({ hub, missingLayer = false, requests = [] }) {
  let challenged = false;
  const contents = new Map([
    ["v1.7.2", hub.sourceManifest],
    [hub.sourceManifest.descriptor.digest, hub.sourceManifest],
    [hub.imageManifest.descriptor.digest, hub.imageManifest],
    [hub.config.descriptor.digest, hub.config],
    ...hub.layers.map((layer) => [layer.descriptor.digest, layer]),
  ]);
  return async (url, options = {}) => {
    requests.push(url);
    if (url.startsWith("https://ghcr.io/token?")) {
      return jsonResponse({ token: "registry-token" });
    }
    if (!challenged && !options.headers?.Authorization) {
      challenged = true;
      return new Response("unauthorized", {
        headers: {
          "www-authenticate":
            'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:ykdz/enoki-hub:pull"',
        },
        status: 401,
      });
    }
    const reference = decodeURIComponent(url.split("/").at(-1));
    const item = contents.get(reference);
    if (
      !item ||
      (missingLayer && reference === hub.layers[0].descriptor.digest)
    ) {
      return new Response("missing", { status: 404 });
    }
    const isManifest = url.includes("/manifests/");
    return new Response(item.bytes, {
      headers: isManifest
        ? {
            "content-type": item.descriptor.mediaType,
            "docker-content-digest": item.descriptor.digest,
          }
        : { "content-type": "application/octet-stream" },
      status: 200,
    });
  };
}

function githubFetchFixture(requests) {
  const releasePayload = {
    assets: [],
    draft: false,
    id: 172,
    prerelease: false,
    tag_name: "v1.7.2",
    target_commitish: "main",
  };
  return async (url) => {
    requests.push(url);
    if (url.endsWith("/releases?per_page=100&page=1")) {
      return jsonResponse([releasePayload]);
    }
    if (url.endsWith("/releases/tags/v1.7.2")) {
      return jsonResponse(releasePayload);
    }
    if (url.endsWith("/git/ref/tags/v1.7.2")) {
      return jsonResponse({
        object: { sha: tagSha, type: "tag" },
        ref: "refs/tags/v1.7.2",
      });
    }
    if (url.endsWith(`/git/tags/${tagSha}`)) {
      return jsonResponse({ object: { sha: commitSha, type: "commit" } });
    }
    throw new Error(`unexpected GitHub request: ${url}`);
  };
}

function jsonResponse(value, headers = {}) {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json", ...headers },
    status: 200,
  });
}

async function targetProbeComponentsFromAssetSet(assetDir) {
  return Promise.all(
    probeTargets.map(async (target) => {
      const { stdout } = await execFileAsync(
        "tar",
        [
          "--extract",
          "--gzip",
          "--file",
          path.join(assetDir, `enoki-probe-${target}.tar.gz`),
          "--to-stdout",
          "enoki-probe",
        ],
        { encoding: "buffer" },
      );
      return {
        file: "enoki-probe",
        role: "probe",
        sha256: sha256(stdout),
        target,
      };
    }),
  );
}

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}
