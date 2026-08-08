import { execFile } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign as signContents,
} from "node:crypto";
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
  prepareProbeAssetSet,
  probeTargets,
} from "./release-candidate-lib.mjs";

const execFileAsync = promisify(execFile);
const indexMediaType = "application/vnd.oci.image.index.v1+json";
const manifestMediaType = "application/vnd.oci.image.manifest.v1+json";
const configMediaType = "application/vnd.oci.image.config.v1+json";
const layerMediaType = "application/vnd.oci.image.layer.v1.tar";
const commitSha = "1".repeat(40);
const tagSha = "2".repeat(40);

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

  it("rejects a self-signed baseline outside the canonical production trust root", async () => {
    const fixture = await createResolverFixture();
    const { publicKey: unrelatedPublicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    try {
      fixture.arguments_.trustedProbePublicKeyPem = unrelatedPublicKey;
      await expect(resolveReleaseBaseline(fixture.arguments_)).rejects.toThrow(
        "canonical production Probe public key",
      );
    } finally {
      await fixture.cleanup();
    }
  });

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
      await expect(
        validateReleaseBaselineBundle(fixture.outputDir, {
          trustedProbePublicKeyPem: fixture.probe.publicKey,
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
        validateReleaseBaselineBundle(fixture.outputDir),
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
          trustedProbePublicKeyPem: fixture.probe.publicKey,
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
          trustedProbePublicKeyPem: fixture.probe.publicKey,
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
        ({ name }) => name !== "install-probe.sh",
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
      tampered.contents.set("install-probe.sh", Buffer.from("tampered"));
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
    expect(workflow).toContain("--trusted-probe-public-key-env");
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
  const probe = await createProbeAssetSetFixture(workDir, "v1.7.2", {
    legacyProbe: options.legacyProbe,
  });
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
      trustedProbePublicKeyPem: probe.publicKey,
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
  const installerPath = path.join(workDir, "install-probe.sh");
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
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
  await writeFile(
    installerPath,
    "#!/bin/sh\nreadonly TRUST='__ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256__'\n",
  );
  await prepareProbeAssetSet({
    archivesDir,
    installerPath,
    outputDir,
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
    version,
  });
  if (legacyProbe) {
    const manifestPath = path.join(outputDir, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    for (const asset of manifest.assets) {
      await writeProbeArchive(path.join(outputDir, asset.file), {
        legacyProbe: true,
        target: asset.target,
        version,
      });
      const archive = await readFile(path.join(outputDir, asset.file));
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
  return { outputDir, privateKey, publicKey };
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
  await execFileAsync("tar", [
    "--create",
    "--gzip",
    "--file",
    archivePath,
    "--directory",
    binaryDir,
    "enoki-probe",
  ]);
  await rm(binaryDir, { force: true, recursive: true });
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
