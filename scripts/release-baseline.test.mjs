import { execFile } from "node:child_process";
import { createHash, sign as signContents } from "node:crypto";
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

import { describe, expect, it } from "vitest";

import {
  createGhcrRegistryClient,
  createGitHubReleaseClient,
  recheckReleaseBaseline,
  resolveReleaseBaseline,
  selectReleaseBaseline,
  validateReleaseBaselineBundle,
  validateResolvedReleaseBaseline,
} from "./release-baseline-lib.mjs";
import {
  createProbeTrustDelegation,
  prepareProbeAssetSet,
  probeTargets,
  validateReleaseCandidate,
} from "./release-candidate-lib.mjs";
import { rsa4096TestKeyPair } from "./test-rsa-key-pool.mjs";
import {
  createTrustEpochMigrationAuthorization,
  trustEpochMigrationAuthorizationSigningInput,
  verifyTrustEpochMigrationAuthorization,
} from "./trust-epoch-migration-lib.mjs";

const execFileAsync = promisify(execFile);
const indexMediaType = "application/vnd.oci.image.index.v1+json";
const manifestMediaType = "application/vnd.oci.image.manifest.v1+json";
const configMediaType = "application/vnd.oci.image.config.v1+json";
const layerMediaType = "application/vnd.oci.image.layer.v1.tar";
const commitSha = "1".repeat(40);
const tagSha = "2".repeat(40);
// This fixture generates three distinct RSA-4096 identities. On a shared CI
// worker that legitimate cryptographic setup can outlast Vitest's 5s default;
// keep the allowance local and bounded so an actual hang still fails quickly.
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

  it("admits the one root-authorized legacy baseline only as manual reinstall", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      await expect(
        resolveReleaseBaseline(fixture.arguments_),
      ).resolves.toMatchObject({
        kind: "enoki-trust-epoch-migration-baseline",
        tag: "v0.1.74",
        transition: "manual-reinstall-required",
      });
      await expect(
        recheckReleaseBaseline({
          bundleDir: fixture.outputDir,
          candidateVersion: "v0.1.75",
          githubRepository: "YKDZ/enoki",
          releaseCatalog: fixture.arguments_.releaseCatalog,
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).resolves.toMatchObject({ transition: "manual-reinstall-required" });
    } finally {
      await fixture.cleanup();
    }
  });

  it("rejects replaying a pinned migration bundle for another candidate", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      await resolveReleaseBaseline(fixture.arguments_);
      await expect(
        validateResolvedReleaseBaseline(fixture.outputDir, {
          candidateVersion: "v0.1.76",
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow("candidate");
      await expect(
        recheckReleaseBaseline({
          bundleDir: fixture.outputDir,
          candidateVersion: "v0.1.76",
          githubRepository: "YKDZ/enoki",
          releaseCatalog: fixture.arguments_.releaseCatalog,
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow("candidate");
    } finally {
      await fixture.cleanup();
    }
  });

  it("candidate validation rejects a migration authorization issued for another candidate", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      const descriptor = await resolveReleaseBaseline(fixture.arguments_);
      const candidateDir = path.join(
        path.dirname(fixture.outputDir),
        "candidate-replay",
      );
      await mkdir(candidateDir);
      await cp(fixture.outputDir, path.join(candidateDir, "release-baseline"), {
        recursive: true,
      });
      await writeFile(
        path.join(candidateDir, "candidate-manifest.json"),
        `${JSON.stringify({
          bootstrap: {},
          candidate: { commit: "4".repeat(40), version: "v0.1.76" },
          hub: {},
          kind: "enoki-release-candidate",
          probeAssetSet: {},
          releaseBaseline: descriptor,
          schemaVersion: 3,
        })}\n`,
      );
      await expect(
        validateReleaseCandidate(candidateDir, {
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow("candidate version");
    } finally {
      await fixture.cleanup();
    }
  });

  it("migration recheck rejects a changed published catalog", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      await resolveReleaseBaseline(fixture.arguments_);
      fixture.releases.push(release("v0.1.73", { id: 171 }));
      await expect(
        recheckReleaseBaseline({
          bundleDir: fixture.outputDir,
          candidateVersion: "v0.1.75",
          githubRepository: "YKDZ/enoki",
          releaseCatalog: fixture.arguments_.releaseCatalog,
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow("catalog changed");
    } finally {
      await fixture.cleanup();
    }
  });

  it.each(["missing", "added", "replaced"])(
    "pinned migration bundle rejects %s assets",
    async (mutation) => {
      const fixture = await createLegacyTrustEpochFixture();
      try {
        await resolveReleaseBaseline(fixture.arguments_);
        const assetDir = path.join(fixture.outputDir, "probe-assets");
        const first = fixture.expectedLegacyRelease.assets[0].name;
        if (mutation === "missing") await rm(path.join(assetDir, first));
        if (mutation === "added")
          await writeFile(path.join(assetDir, "unexpected-asset"), "extra");
        if (mutation === "replaced")
          await writeFile(path.join(assetDir, first), "replacement");
        await expect(
          validateResolvedReleaseBaseline(fixture.outputDir, {
            candidateVersion: "v0.1.75",
            trustedRootPublicKeyPem: fixture.probe.root.publicKey,
          }),
        ).rejects.toThrow();
      } finally {
        await fixture.cleanup();
      }
    },
  );

  it.each([
    "releaseId",
    "tagRefSha",
    "peeledCommitSha",
    "targetCommitish",
    "hubDigest",
    "descriptorSchema",
    "authorizationSignature",
  ])("pinned migration bundle rejects changed %s", async (field) => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      await resolveReleaseBaseline(fixture.arguments_);
      const descriptorPath = path.join(
        fixture.outputDir,
        "release-baseline.json",
      );
      const descriptor = JSON.parse(await readFile(descriptorPath, "utf8"));
      if (field === "releaseId") descriptor.githubRelease.id += 1;
      if (field === "tagRefSha")
        descriptor.githubRelease.tagRefSha = "3".repeat(40);
      if (field === "peeledCommitSha")
        descriptor.githubRelease.peeledCommitSha = "3".repeat(40);
      if (field === "targetCommitish")
        descriptor.githubRelease.targetCommitish = "other";
      if (field === "hubDigest")
        descriptor.hub.digest = `sha256:${"0".repeat(64)}`;
      if (field === "descriptorSchema") descriptor.schemaVersion = 2;
      if (field === "authorizationSignature") {
        const signaturePath = path.join(
          fixture.outputDir,
          "trust-epoch-migration-authorization.json.sig",
        );
        await writeFile(signaturePath, Buffer.alloc(512));
      } else {
        await writeFile(
          descriptorPath,
          `${JSON.stringify(descriptor, null, 2)}\n`,
        );
      }
      await expect(
        validateResolvedReleaseBaseline(fixture.outputDir, {
          candidateVersion: "v0.1.75",
          trustedRootPublicKeyPem: fixture.probe.root.publicKey,
        }),
      ).rejects.toThrow();
    } finally {
      await fixture.cleanup();
    }
  });

  it("canonicalizes nested migration release identity independent of input key order", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      const canonical = createTrustEpochMigrationAuthorization({
        candidateVersion: "v0.1.75",
        distribution: "enoki",
        legacyRelease: fixture.expectedLegacyRelease,
        rootPrivateKeyPem: fixture.probe.root.privateKey,
      });
      const release = fixture.expectedLegacyRelease;
      const reordered = createTrustEpochMigrationAuthorization({
        candidateVersion: "v0.1.75",
        distribution: "enoki",
        legacyRelease: {
          legacySigningKeySha256: release.legacySigningKeySha256,
          hub: { image: release.hub.image, digest: release.hub.digest },
          githubRelease: {
            targetCommitish: release.githubRelease.targetCommitish,
            tagRefSha: release.githubRelease.tagRefSha,
            tag: release.githubRelease.tag,
            repository: release.githubRelease.repository,
            peeledCommitSha: release.githubRelease.peeledCommitSha,
            id: release.githubRelease.id,
          },
          assets: release.assets.map(({ name, sha256, size }) => ({
            size,
            name,
            sha256,
          })),
        },
        rootPrivateKeyPem: fixture.probe.root.privateKey,
      });
      expect(reordered.bytes).toEqual(canonical.bytes);
    } finally {
      await fixture.cleanup();
    }
  });

  it.each(["探针.tar.gz", "line\nbreak", "tab\tasset"])(
    "rejects non-protocol migration asset name %j",
    async (name) => {
      const fixture = await createLegacyTrustEpochFixture();
      try {
        const legacyRelease = structuredClone(fixture.expectedLegacyRelease);
        legacyRelease.assets[0].name = name;
        expect(() =>
          createTrustEpochMigrationAuthorization({
            candidateVersion: "v0.1.75",
            distribution: "enoki",
            legacyRelease,
            rootPrivateKeyPem: fixture.probe.root.privateKey,
          }),
        ).toThrow("asset");
      } finally {
        await fixture.cleanup();
      }
    },
  );

  it("uses one locale-independent asset order for canonical authorization bytes", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      const first = structuredClone(fixture.expectedLegacyRelease);
      first.assets = [
        { name: "z_asset", sha256: "1".repeat(64), size: 1 },
        { name: "A.asset", sha256: "2".repeat(64), size: 2 },
        { name: "a-asset", sha256: "3".repeat(64), size: 3 },
      ];
      const second = structuredClone(first);
      second.assets.reverse();
      const canonical = (legacyRelease) =>
        createTrustEpochMigrationAuthorization({
          candidateVersion: "v0.1.75",
          distribution: "enoki",
          legacyRelease,
          rootPrivateKeyPem: fixture.probe.root.privateKey,
        }).bytes;
      expect(canonical(second)).toEqual(canonical(first));
      expect(
        JSON.parse(canonical(first)).legacyRelease.assets.map(
          ({ name }) => name,
        ),
      ).toEqual(["A.asset", "a-asset", "z_asset"]);
    } finally {
      await fixture.cleanup();
    }
  });

  it.each([
    "assets",
    "candidateVersion",
    "distribution",
    "legacySigningKeySha256",
    "migrationGeneration",
    "purpose",
    "releaseId",
    "peeledCommit",
    "tagRef",
    "targetCommitish",
    "hubDigest",
    "root",
    "schemaVersion",
    "tag",
    "targetRootKeyId",
    "addedAsset",
    "replacedAsset",
  ])(
    "rejects a Trust Epoch Migration Authorization with wrong %s",
    async (field) => {
      const fixture = await createLegacyTrustEpochFixture();
      try {
        const parsed = JSON.parse(
          fixture.arguments_.trustEpochMigrationAuthorizationBytes.toString(
            "utf8",
          ),
        );
        if (field === "assets") parsed.legacyRelease.assets.pop();
        if (field === "candidateVersion") parsed.candidateVersion = "v0.1.76";
        if (field === "distribution") parsed.distribution = "other";
        if (field === "legacySigningKeySha256") {
          parsed.legacyRelease.legacySigningKeySha256 = "0".repeat(64);
        }
        if (field === "migrationGeneration") parsed.migrationGeneration = 2;
        if (field === "purpose") parsed.purpose = "probe-asset-signing";
        if (field === "releaseId") parsed.legacyRelease.githubRelease.id += 1;
        if (field === "peeledCommit")
          parsed.legacyRelease.githubRelease.peeledCommitSha = "3".repeat(40);
        if (field === "tagRef")
          parsed.legacyRelease.githubRelease.tagRefSha = "3".repeat(40);
        if (field === "targetCommitish")
          parsed.legacyRelease.githubRelease.targetCommitish = "other";
        if (field === "hubDigest")
          parsed.legacyRelease.hub.digest = `sha256:${"0".repeat(64)}`;
        if (field === "root") parsed.rootKeyId = "0".repeat(64);
        if (field === "schemaVersion") parsed.schemaVersion = 2;
        if (field === "tag") parsed.legacyRelease.githubRelease.tag = "v0.1.73";
        if (field === "targetRootKeyId")
          parsed.targetRootKeyId = "0".repeat(64);
        if (field === "addedAsset")
          parsed.legacyRelease.assets.push({
            name: "extra",
            sha256: "0".repeat(64),
            size: 1,
          });
        if (field === "replacedAsset")
          parsed.legacyRelease.assets[0].sha256 = "0".repeat(64);
        const bytes = Buffer.from(`${JSON.stringify(parsed)}\n`);
        expect(() =>
          verifyTrustEpochMigrationAuthorization({
            bytes,
            expectedCandidateVersion: "v0.1.75",
            expectedDistribution: "enoki",
            expectedLegacyRelease: fixture.expectedLegacyRelease,
            rootPublicKeyPem: fixture.probe.root.publicKey,
            signature: signContents(
              "RSA-SHA256",
              trustEpochMigrationAuthorizationSigningInput(bytes),
              fixture.probe.root.privateKey,
            ),
          }),
        ).toThrow();
      } finally {
        await fixture.cleanup();
      }
    },
  );

  it("rejects an invalid migration root signature", async () => {
    const fixture = await createLegacyTrustEpochFixture();
    try {
      expect(() =>
        verifyTrustEpochMigrationAuthorization({
          bytes: fixture.arguments_.trustEpochMigrationAuthorizationBytes,
          expectedCandidateVersion: "v0.1.75",
          expectedDistribution: "enoki",
          expectedLegacyRelease: fixture.expectedLegacyRelease,
          rootPublicKeyPem: fixture.probe.root.publicKey,
          signature: Buffer.alloc(512),
        }),
      ).toThrow("signature");
    } finally {
      await fixture.cleanup();
    }
  });

  it.each(["releaseId", "tagRefSha", "peeledCommitSha", "targetCommitish"])(
    "resolver rejects changed published migration %s",
    async (field) => {
      const fixture = await createLegacyTrustEpochFixture();
      try {
        if (field === "releaseId") fixture.releaseIdentity.id += 1;
        if (field === "tagRefSha")
          fixture.releaseIdentity.tagRefSha = "3".repeat(40);
        if (field === "peeledCommitSha")
          fixture.releaseIdentity.peeledCommitSha = "3".repeat(40);
        if (field === "targetCommitish")
          fixture.releaseIdentity.targetCommitish = "other";
        await expect(
          resolveReleaseBaseline(fixture.arguments_),
        ).rejects.toThrow();
      } finally {
        await fixture.cleanup();
      }
    },
  );

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
  fixture.expectedLegacyRelease = expectedLegacyRelease;
  return fixture;
}

async function createResolverFixture(options = {}) {
  const workDir = await mkdtemp(path.join(tmpdir(), "enoki-baseline-"));
  const probe = await createProbeAssetSetFixture(workDir, "v1.7.2", {
    legacyProbe: options.legacyProbe,
  });
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
  const release_ = release("v1.7.2", { assets });
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
      candidateVersion: "v2.0.0",
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
  await prepareProbeAssetSet({
    archivesDir,
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

async function writeProbeArchive(
  archivePath,
  { legacyProbe, target, version },
) {
  const binaryDir = `${archivePath}.contents`;
  await mkdir(binaryDir, { recursive: true });
  const binaryPath = path.join(binaryDir, "enoki-probe");
  await writeFile(
    binaryPath,
    createProbeElf({ includeIdentity: !legacyProbe, target, version }),
  );
  await chmod(binaryPath, 0o755);
  const binary = await readFile(binaryPath);
  const bundleManifest = Buffer.from(
    `${JSON.stringify({
      components: [
        {
          path: "enoki-probe",
          permissionProfile: "probe-v1",
          role: "probe",
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
  await execFileAsync("tar", [
    "--create",
    "--gzip",
    "--file",
    archivePath,
    "--directory",
    binaryDir,
    "bundle-manifest.json",
    "enoki-probe",
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

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}
