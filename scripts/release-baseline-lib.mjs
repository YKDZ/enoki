import { execFile } from "node:child_process";
import { createHash, createPublicKey, randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import {
  inspectProbeAssetSet,
  probeTargets,
} from "./release-candidate-lib.mjs";
import { inspectHubOciArchive } from "./release-candidate-oci.mjs";

const execFileAsync = promisify(execFile);
const stableSemVerTagPattern = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const sha256DigestPattern = /^sha256:([0-9a-f]{64})$/;
const gitObjectIdPattern = /^[0-9a-f]{40}$/;
const baselineDescriptorFile = "release-baseline.json";
const hubSourceManifestFile = "hub-source-manifest.json";
const ociIndexMediaTypes = new Set([
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.index.v1+json",
]);
const imageManifestMediaTypes = new Set([
  "application/vnd.docker.distribution.manifest.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
]);
const imageConfigMediaTypes = new Set([
  "application/vnd.docker.container.image.v1+json",
  "application/vnd.oci.image.config.v1+json",
]);
const imageLayerMediaTypes = new Set([
  "application/vnd.docker.image.rootfs.diff.tar.gzip",
  "application/vnd.oci.image.layer.v1.tar",
  "application/vnd.oci.image.layer.v1.tar+gzip",
]);
const registryManifestMediaTypes = new Set([
  ...ociIndexMediaTypes,
  ...imageManifestMediaTypes,
]);

export function createGitHubReleaseClient({
  apiBaseUrl = "https://api.github.com",
  fetchImpl = globalThis.fetch,
  repository,
  token,
}) {
  assertImmutableRepository(repository);
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const api = (suffix) => `${apiBaseUrl}/repos/${repository}${suffix}`;

  return Object.freeze({
    async downloadAsset({ asset }) {
      if (!Number.isSafeInteger(asset?.id) || asset.id <= 0) {
        throw new Error("GitHub Release asset ID is invalid");
      }
      const response = await fetchImpl(api(`/releases/assets/${asset.id}`), {
        headers: { ...headers, Accept: "application/octet-stream" },
      });
      await assertFetchSucceeded(response, "download GitHub Release asset");
      return new Uint8Array(await response.arrayBuffer());
    },

    async listReleases() {
      const releases = [];
      for (let page = 1; ; page += 1) {
        const response = await fetchImpl(
          api(`/releases?per_page=100&page=${page}`),
          { headers },
        );
        await assertFetchSucceeded(response, "list GitHub Releases");
        const pageReleases = await response.json();
        if (!Array.isArray(pageReleases)) {
          throw new Error("GitHub Releases API returned malformed content");
        }
        releases.push(...pageReleases.map(normalizeGitHubRelease));
        if (!/rel="next"/.test(response.headers.get("link") ?? "")) {
          return releases;
        }
      }
    },

    async resolveReleaseIdentity({ tagName }) {
      if (!stableSemVerTagPattern.test(tagName ?? "")) {
        throw new Error("GitHub Release identity requires a stable tag");
      }
      const encodedTag = encodeURIComponent(tagName);
      const releaseResponse = await fetchImpl(
        api(`/releases/tags/${encodedTag}`),
        { headers },
      );
      await assertFetchSucceeded(
        releaseResponse,
        "resolve GitHub Release by tag",
      );
      const release = normalizeGitHubRelease(await releaseResponse.json());
      if (release.tagName !== tagName) {
        throw new Error("GitHub Release is associated with a different tag");
      }

      const referenceResponse = await fetchImpl(
        api(`/git/ref/tags/${encodedTag}`),
        { headers },
      );
      await assertFetchSucceeded(referenceResponse, "resolve GitHub tag ref");
      const reference = await referenceResponse.json();
      if (reference?.ref !== `refs/tags/${tagName}`) {
        throw new Error("GitHub tag ref resolved an unexpected reference");
      }
      const tagRefSha = assertGitObject(reference.object, "GitHub tag ref").sha;
      const peeledCommitSha = await peelGitObject({
        api,
        fetchImpl,
        headers,
        initialObject: reference.object,
      });
      return {
        assets: release.assets,
        id: release.id,
        peeledCommitSha,
        tagName: release.tagName,
        tagRefSha,
        targetCommitish: release.targetCommitish,
      };
    },
  });
}

export function createGhcrRegistryClient({
  fetchImpl = globalThis.fetch,
  token: configuredToken,
} = {}) {
  return Object.freeze({
    async downloadImage({ image, reference }) {
      assertImmutableImageName(image);
      if (!stableSemVerTagPattern.test(reference ?? "")) {
        throw new Error(
          "GHCR Release Baseline lookup reference must be a stable version tag",
        );
      }
      const repository = image.slice("ghcr.io/".length);
      let token = configuredToken;
      const fetchRegistry = async ({ kind, reference: contentReference }) => {
        const url = `https://ghcr.io/v2/${repository}/${kind}/${contentReference}`;
        const accept =
          kind === "manifests"
            ? [...registryManifestMediaTypes].join(", ")
            : "application/octet-stream";
        let response = await fetchImpl(url, {
          headers: {
            Accept: accept,
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
        });
        if (response.status === 401) {
          token = await requestRegistryToken({
            challenge: response.headers.get("www-authenticate"),
            fetchImpl,
            repository,
          });
          response = await fetchImpl(url, {
            headers: { Accept: accept, Authorization: `Bearer ${token}` },
          });
        }
        await assertFetchSucceeded(response, `download GHCR ${kind}`);
        const bytes = Buffer.from(await response.arrayBuffer());
        if (kind === "manifests") {
          return registryManifestIdentity(response, bytes);
        }
        return bytes;
      };

      const tagged = await fetchRegistry({
        kind: "manifests",
        reference,
      });
      const pinned = await fetchRegistry({
        kind: "manifests",
        reference: tagged.descriptor.digest,
      });
      if (
        !descriptorsEqual(tagged.descriptor, pinned.descriptor) ||
        !tagged.bytes.equals(pinned.bytes)
      ) {
        throw new Error(
          "GHCR Hub tag and immutable digest returned different manifests",
        );
      }

      const sourceManifest = pinned;
      const source = parseJsonBytes(
        sourceManifest.bytes,
        "Release Baseline Hub source manifest",
      );
      let imageManifest;
      let platform;
      if (ociIndexMediaTypes.has(sourceManifest.descriptor.mediaType)) {
        const selectedDescriptor = selectRunnableImageDescriptor(source);
        imageManifest = await fetchRegistry({
          kind: "manifests",
          reference: selectedDescriptor.digest,
        });
        assertContentMatchesDescriptor(
          imageManifest,
          selectedDescriptor,
          "Release Baseline Hub image manifest",
        );
        platform = selectedDescriptor.platform;
      } else if (
        imageManifestMediaTypes.has(sourceManifest.descriptor.mediaType)
      ) {
        imageManifest = sourceManifest;
      } else {
        throw new Error("Release Baseline Hub tag has no runnable image");
      }

      const manifest = validateImageManifest(imageManifest);
      const configBytes = await fetchRegistry({
        kind: "blobs",
        reference: manifest.config.digest,
      });
      const config = {
        bytes: configBytes,
        descriptor: { ...manifest.config },
      };
      assertContentMatchesDescriptor(
        config,
        manifest.config,
        "Release Baseline Hub image config",
      );
      const parsedConfig = validateImageConfig(config);
      if (
        parsedConfig.os !== "linux" ||
        parsedConfig.architecture !== "amd64"
      ) {
        throw new Error("Release Baseline Hub image must target linux/amd64");
      }
      if (
        platform &&
        (platform.os !== parsedConfig.os ||
          platform.architecture !== parsedConfig.architecture)
      ) {
        throw new Error(
          "Release Baseline Hub image descriptor platform disagrees with its config",
        );
      }
      platform = { architecture: "amd64", os: "linux" };

      const layers = [];
      for (const layerDescriptor of manifest.layers) {
        const bytes = await fetchRegistry({
          kind: "blobs",
          reference: layerDescriptor.digest,
        });
        const layer = { bytes, descriptor: { ...layerDescriptor } };
        assertContentMatchesDescriptor(
          layer,
          layerDescriptor,
          "Release Baseline Hub image layer",
        );
        layers.push(layer);
      }
      const closure = {
        config,
        imageManifest,
        layers,
        platform,
        sourceManifest,
      };
      validateImageClosure(closure);
      return closure;
    },
  });
}

export async function resolveReleaseBaseline({
  assetDownloader,
  candidateVersion,
  githubRepository,
  hubImage,
  outputDir,
  registry,
  releaseCatalog,
  trustedProbePublicKeyPem,
}) {
  const trustedPublicKey = canonicalTrustedProbePublicKey(
    trustedProbePublicKeyPem,
  );
  const releases = await releaseCatalog.listReleases();
  const catalogSnapshot = createReleaseCatalogSnapshot(releases);
  const selected = selectReleaseBaseline({
    candidateVersion,
    releases,
  });

  assertImmutableRepository(githubRepository);
  assertImmutableImageName(hubImage);
  const releaseIdentity = await resolveAndAssertReleaseIdentity({
    releaseCatalog,
    selected,
  });
  const expectedAssetNames = expectedProbeAssetNames();
  const assetsByName = collectRequiredReleaseAssets(
    selected.assets,
    expectedAssetNames,
  );
  const stagingDir = `${outputDir}.tmp-${randomUUID()}`;
  const probeAssetDir = path.join(stagingDir, "probe-assets");
  try {
    await mkdir(probeAssetDir, { recursive: true });
    for (const name of expectedAssetNames) {
      const asset = assetsByName.get(name);
      const bytes = Buffer.from(
        await assetDownloader.downloadAsset({
          asset,
          release: selected,
          repository: githubRepository,
        }),
      );
      assertDownloadedAsset(bytes, asset);
      await writeFile(path.join(probeAssetDir, name), bytes);
    }

    const publishedPublicKey = await readFile(
      path.join(probeAssetDir, "signing-key.pem"),
    );
    if (!publishedPublicKey.equals(trustedPublicKey)) {
      throw new Error(
        "Release Baseline signing-key.pem does not match the canonical production Probe public key",
      );
    }
    const inspectedProbe = await inspectProbeAssetSet(probeAssetDir, {
      expectedVersion: selected.tagName.slice(1),
      requireEmbeddedProbeIdentity: false,
    });

    const resolvedHub = await registry.downloadImage({
      image: hubImage,
      reference: selected.tagName,
    });
    validateImageClosure(resolvedHub);
    await writeFile(
      path.join(stagingDir, hubSourceManifestFile),
      resolvedHub.sourceManifest.bytes,
    );
    const hubDirectory = path.join(stagingDir, "hub");
    await mkdir(hubDirectory, { recursive: true });
    const hubArchiveFile = `enoki-hub-${selected.tagName}.oci.tar`;
    const hubArchivePath = path.join(hubDirectory, hubArchiveFile);
    await materializeOciArchive(resolvedHub, hubArchivePath);
    const offlineHub = await inspectBaselineHubArchive(
      hubArchivePath,
      inspectedProbe.files,
    );
    if (offlineHub.digest !== resolvedHub.imageManifest.descriptor.digest) {
      throw new Error(
        "materialized Release Baseline Hub OCI archive changed the image digest",
      );
    }

    const installer = inspectedProbe.files.find(
      ({ file }) => file === "install-probe.sh",
    );
    const descriptor = {
      catalogSnapshot,
      githubRelease: {
        id: releaseIdentity.id,
        peeledCommitSha: releaseIdentity.peeledCommitSha,
        repository: githubRepository,
        tagRefSha: releaseIdentity.tagRefSha,
        targetCommitish: releaseIdentity.targetCommitish,
      },
      hub: {
        archive: `hub/${hubArchiveFile}`,
        archiveSha256: await fileSha256(hubArchivePath),
        digest: resolvedHub.sourceManifest.descriptor.digest,
        image: hubImage,
        imageDigest: resolvedHub.imageManifest.descriptor.digest,
        mediaType: resolvedHub.sourceManifest.descriptor.mediaType,
        platform: resolvedHub.platform,
        sourceManifest: hubSourceManifestFile,
        sourceManifestSha256: sha256(resolvedHub.sourceManifest.bytes),
        sourceManifestSize: resolvedHub.sourceManifest.bytes.byteLength,
        size: (await stat(hubArchivePath)).size,
      },
      installer,
      kind: "enoki-release-baseline",
      probeAssetSet: {
        directory: "probe-assets",
        files: inspectedProbe.files,
        signingIdentity: inspectedProbe.signingIdentity,
        trustRoot: {
          publicKeySha256: sha256(trustedPublicKey),
        },
        version: inspectedProbe.version,
      },
      schemaVersion: 2,
      tag: selected.tagName,
    };
    await writeFile(
      path.join(stagingDir, baselineDescriptorFile),
      `${JSON.stringify(descriptor, null, 2)}\n`,
    );
    await validateReleaseBaselineBundle(stagingDir, {
      trustedProbePublicKeyPem: trustedPublicKey.toString("utf8"),
    });
    await rename(stagingDir, outputDir);
    return descriptor;
  } catch (error) {
    await rm(stagingDir, { force: true, recursive: true });
    throw error;
  }
}

export async function recheckReleaseBaseline({
  bundleDir,
  candidateVersion,
  githubRepository,
  releaseCatalog,
  trustedProbePublicKeyPem,
}) {
  const descriptor = await validateResolvedReleaseBaseline(bundleDir, {
    trustedProbePublicKeyPem,
  });
  const releases = await releaseCatalog.listReleases();
  const freshSnapshot = createReleaseCatalogSnapshot(releases);
  if (!objectsEqual(freshSnapshot, descriptor.catalogSnapshot)) {
    throw new Error(
      "published Release catalog changed after Release Baseline resolution",
    );
  }
  const selected = selectReleaseBaseline({
    candidateVersion,
    releases,
  });
  if (selected.tagName !== descriptor.tag) {
    throw new Error("Release Baseline selection changed after resolution");
  }
  if (descriptor.githubRelease.repository !== githubRepository) {
    throw new Error("Release Baseline GitHub repository changed");
  }
  const identity = await resolveAndAssertReleaseIdentity({
    releaseCatalog,
    selected,
  });
  const expectedIdentity = {
    id: descriptor.githubRelease.id,
    peeledCommitSha: descriptor.githubRelease.peeledCommitSha,
    tagRefSha: descriptor.githubRelease.tagRefSha,
    targetCommitish: descriptor.githubRelease.targetCommitish,
  };
  const actualIdentity = {
    id: identity.id,
    peeledCommitSha: identity.peeledCommitSha,
    tagRefSha: identity.tagRefSha,
    targetCommitish: identity.targetCommitish,
  };
  if (!objectsEqual(actualIdentity, expectedIdentity)) {
    throw new Error(
      "Release Baseline GitHub Release or tag identity changed after resolution",
    );
  }
  return descriptor;
}

export async function validateResolvedReleaseBaseline(bundleDir, options = {}) {
  return validateReleaseBaselineBundle(bundleDir, options);
}

export async function validateReleaseBaselineBundle(
  bundleDir,
  { trustedProbePublicKeyPem } = {},
) {
  assertSameFileNames(
    (await readdir(bundleDir)).sort(),
    [
      baselineDescriptorFile,
      "hub",
      hubSourceManifestFile,
      "probe-assets",
    ].sort(),
    "Release Baseline bundle",
  );
  const descriptor = await readJson(
    path.join(bundleDir, baselineDescriptorFile),
    "Release Baseline descriptor",
  );
  assertPlainObject(descriptor, "Release Baseline descriptor");
  assertExactKeys(descriptor, [
    "catalogSnapshot",
    "githubRelease",
    "hub",
    "installer",
    "kind",
    "probeAssetSet",
    "schemaVersion",
    "tag",
  ]);
  if (
    descriptor.kind !== "enoki-release-baseline" ||
    descriptor.schemaVersion !== 2 ||
    !stableSemVerTagPattern.test(descriptor.tag ?? "")
  ) {
    throw new Error(
      "Release Baseline descriptor schema, kind, or tag is invalid",
    );
  }
  validateReleaseCatalogSnapshot(descriptor.catalogSnapshot);

  const githubRelease = descriptor.githubRelease;
  assertPlainObject(githubRelease, "Release Baseline GitHub Release");
  assertExactKeys(githubRelease, [
    "id",
    "peeledCommitSha",
    "repository",
    "tagRefSha",
    "targetCommitish",
  ]);
  assertImmutableRepository(githubRelease.repository);
  if (
    !Number.isSafeInteger(githubRelease.id) ||
    githubRelease.id <= 0 ||
    !gitObjectIdPattern.test(githubRelease.tagRefSha ?? "") ||
    !gitObjectIdPattern.test(githubRelease.peeledCommitSha ?? "") ||
    typeof githubRelease.targetCommitish !== "string" ||
    githubRelease.targetCommitish.length === 0
  ) {
    throw new Error("Release Baseline descriptor release identity is invalid");
  }
  const snapshotRelease = descriptor.catalogSnapshot.entries.find(
    ({ id, tag }) => id === githubRelease.id && tag === descriptor.tag,
  );
  if (
    !snapshotRelease ||
    snapshotRelease.targetCommitish !== githubRelease.targetCommitish
  ) {
    throw new Error(
      "Release Baseline descriptor disagrees with its catalog snapshot",
    );
  }

  const probe = descriptor.probeAssetSet;
  assertPlainObject(probe, "Release Baseline Probe Asset Set");
  assertExactKeys(probe, [
    "directory",
    "files",
    "signingIdentity",
    "trustRoot",
    "version",
  ]);
  if (
    probe.directory !== "probe-assets" ||
    probe.version !== descriptor.tag.slice(1)
  ) {
    throw new Error("Release Baseline Probe version disagrees with its tag");
  }
  assertPlainObject(probe.trustRoot, "Release Baseline Probe trust root");
  assertExactKeys(probe.trustRoot, ["publicKeySha256"]);
  if (!/^[0-9a-f]{64}$/.test(probe.trustRoot.publicKeySha256 ?? "")) {
    throw new Error("Release Baseline Probe trust root is invalid");
  }
  const publishedPublicKey = await readFile(
    path.join(bundleDir, "probe-assets", "signing-key.pem"),
  );
  if (sha256(publishedPublicKey) !== probe.trustRoot.publicKeySha256) {
    throw new Error("Release Baseline Probe trust root does not match content");
  }
  if (trustedProbePublicKeyPem !== undefined) {
    const trusted = canonicalTrustedProbePublicKey(trustedProbePublicKeyPem);
    if (!publishedPublicKey.equals(trusted)) {
      throw new Error(
        "Release Baseline signing-key.pem does not match the canonical production Probe public key",
      );
    }
  }
  const inspectedProbe = await inspectProbeAssetSet(
    path.join(bundleDir, "probe-assets"),
    {
      expectedVersion: probe.version,
      requireEmbeddedProbeIdentity: false,
    },
  );
  if (
    !objectsEqual(inspectedProbe.files, probe.files) ||
    !objectsEqual(inspectedProbe.signingIdentity, probe.signingIdentity) ||
    inspectedProbe.signingIdentity.publicKeySha256 !==
      probe.trustRoot.publicKeySha256
  ) {
    throw new Error(
      "Release Baseline Probe Asset Set descriptor does not match content",
    );
  }
  const expectedInstaller = inspectedProbe.files.find(
    ({ file }) => file === "install-probe.sh",
  );
  if (!objectsEqual(descriptor.installer, expectedInstaller)) {
    throw new Error(
      "Release Baseline installer descriptor does not match content",
    );
  }

  const hub = descriptor.hub;
  assertPlainObject(hub, "Release Baseline Hub");
  assertExactKeys(hub, [
    "archive",
    "archiveSha256",
    "digest",
    "image",
    "imageDigest",
    "mediaType",
    "platform",
    "size",
    "sourceManifest",
    "sourceManifestSha256",
    "sourceManifestSize",
  ]);
  assertImmutableImageName(hub.image);
  const expectedArchive = `hub/enoki-hub-${descriptor.tag}.oci.tar`;
  if (
    hub.archive !== expectedArchive ||
    hub.sourceManifest !== hubSourceManifestFile ||
    !sha256DigestPattern.test(hub.digest ?? "") ||
    !sha256DigestPattern.test(hub.imageDigest ?? "") ||
    !registryManifestMediaTypes.has(hub.mediaType) ||
    !/^[0-9a-f]{64}$/.test(hub.archiveSha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(hub.sourceManifestSha256 ?? "") ||
    !Number.isSafeInteger(hub.size) ||
    hub.size < 1 ||
    !Number.isSafeInteger(hub.sourceManifestSize) ||
    hub.sourceManifestSize < 1 ||
    !objectsEqual(hub.platform, { architecture: "amd64", os: "linux" })
  ) {
    throw new Error("Release Baseline Hub descriptor is invalid");
  }
  assertSameFileNames(
    await readdir(path.join(bundleDir, "hub")),
    [path.basename(expectedArchive)],
    "Release Baseline Hub directory",
  );
  const sourceBytes = await readFile(
    path.join(bundleDir, hubSourceManifestFile),
  );
  if (
    sourceBytes.byteLength !== hub.sourceManifestSize ||
    sha256(sourceBytes) !== hub.sourceManifestSha256 ||
    hub.digest !== `sha256:${hub.sourceManifestSha256}`
  ) {
    throw new Error(
      "Release Baseline Hub source manifest does not match its descriptor",
    );
  }
  const sourceDescriptor = {
    digest: hub.digest,
    mediaType: hub.mediaType,
    size: hub.sourceManifestSize,
  };
  const source = parseJsonBytes(
    sourceBytes,
    "Release Baseline Hub source manifest",
  );
  const selected = selectedImageDescriptorFromSource(source, sourceDescriptor);
  if (selected.digest !== hub.imageDigest) {
    throw new Error(
      "Release Baseline Hub source manifest selects a different image digest",
    );
  }
  const archivePath = path.join(bundleDir, hub.archive);
  const archiveDetails = await stat(archivePath);
  if (
    archiveDetails.size !== hub.size ||
    (await fileSha256(archivePath)) !== hub.archiveSha256
  ) {
    throw new Error(
      "Release Baseline Hub OCI archive does not match its descriptor",
    );
  }
  const offlineHub = await inspectBaselineHubArchive(
    archivePath,
    inspectedProbe.files,
  );
  if (offlineHub.digest !== hub.imageDigest) {
    throw new Error(
      "Release Baseline Hub OCI archive contains a different image digest",
    );
  }
  return descriptor;
}

export function selectReleaseBaseline({ candidateVersion, releases }) {
  const candidate = parseStableSemVer(candidateVersion, "candidate version");
  const publishedStableReleases = releases
    .filter(isPublishedStableRelease)
    .map((release) => ({
      release,
      version: parseStableSemVer(release.tagName, "release tag"),
    }))
    .sort((left, right) => compareSemVer(right.version, left.version));
  const newest = publishedStableReleases[0];
  if (newest && compareSemVer(candidate, newest.version) <= 0) {
    throw new Error(
      `candidate ${candidateVersion} must be newer than published stable release ${newest.release.tagName}`,
    );
  }
  const baseline = publishedStableReleases.find(
    ({ version }) => compareSemVer(version, candidate) < 0,
  );
  if (!baseline) {
    throw new Error("no published Release Baseline exists");
  }
  return baseline.release;
}

export function assertReleaseBaselinePrecedesCandidate({
  baselineTag,
  candidateVersion,
}) {
  const baseline = parseStableSemVer(baselineTag, "Release Baseline tag");
  const candidate = parseStableSemVer(candidateVersion, "candidate version");
  if (compareSemVer(baseline, candidate) >= 0) {
    throw new Error(
      `Release Baseline ${baselineTag} must be lower than candidate ${candidateVersion}`,
    );
  }
}

export function createReleaseCatalogSnapshot(releases) {
  const entries = releases
    .filter(isPublishedStableRelease)
    .map((release) => ({
      assets: (release.assets ?? [])
        .map((asset) => ({
          digest: asset.digest ?? null,
          id: asset.id,
          name: asset.name,
          size: asset.size,
        }))
        .sort((left, right) =>
          `${left.name}:${left.id}`.localeCompare(`${right.name}:${right.id}`),
        ),
      id: release.id,
      tag: release.tagName,
      targetCommitish: release.targetCommitish,
    }))
    .sort((left, right) => left.tag.localeCompare(right.tag));
  const serialized = JSON.stringify(entries);
  return { entries, sha256: sha256(Buffer.from(serialized)) };
}

export function validateReleaseCatalogSnapshot(snapshot) {
  assertPlainObject(snapshot, "Release catalog snapshot");
  assertExactKeys(snapshot, ["entries", "sha256"]);
  if (!Array.isArray(snapshot.entries)) {
    throw new Error("Release catalog snapshot entries are invalid");
  }
  const expected = createReleaseCatalogSnapshot(
    snapshot.entries.map((entry) => ({
      assets: entry.assets,
      draft: false,
      id: entry.id,
      prerelease: false,
      tagName: entry.tag,
      targetCommitish: entry.targetCommitish,
    })),
  );
  if (!objectsEqual(expected, snapshot)) {
    throw new Error("Release catalog snapshot checksum is invalid");
  }
}

async function resolveAndAssertReleaseIdentity({ releaseCatalog, selected }) {
  if (typeof releaseCatalog.resolveReleaseIdentity !== "function") {
    throw new Error("Release catalog cannot pin Git tag provenance");
  }
  const identity = await releaseCatalog.resolveReleaseIdentity({
    tagName: selected.tagName,
  });
  if (
    identity.id !== selected.id ||
    identity.tagName !== selected.tagName ||
    identity.targetCommitish !== selected.targetCommitish ||
    !gitObjectIdPattern.test(identity.tagRefSha ?? "") ||
    !gitObjectIdPattern.test(identity.peeledCommitSha ?? "") ||
    !objectsEqual(identity.assets, selected.assets)
  ) {
    throw new Error(
      "GitHub Release association, target, assets, or tag provenance changed during resolution",
    );
  }
  return identity;
}

async function peelGitObject({ api, fetchImpl, headers, initialObject }) {
  let object = assertGitObject(initialObject, "GitHub tag ref");
  const seen = new Set();
  for (let depth = 0; depth < 8; depth += 1) {
    if (object.type === "commit") {
      return object.sha;
    }
    if (object.type !== "tag" || seen.has(object.sha)) {
      throw new Error("GitHub tag ref does not peel to one commit");
    }
    seen.add(object.sha);
    const response = await fetchImpl(api(`/git/tags/${object.sha}`), {
      headers,
    });
    await assertFetchSucceeded(response, "peel annotated GitHub tag");
    object = assertGitObject(
      (await response.json())?.object,
      "annotated GitHub tag",
    );
  }
  throw new Error("GitHub tag ref nesting is too deep");
}

function assertGitObject(object, description) {
  if (
    !object ||
    typeof object !== "object" ||
    !gitObjectIdPattern.test(object.sha ?? "") ||
    !["commit", "tag"].includes(object.type)
  ) {
    throw new Error(`${description} object is invalid`);
  }
  return object;
}

function normalizeGitHubRelease(release) {
  assertPlainObject(release, "GitHub Release");
  return {
    assets: Array.isArray(release.assets)
      ? release.assets.map((asset) => ({
          digest: asset.digest,
          id: asset.id,
          name: asset.name,
          size: asset.size,
        }))
      : [],
    draft: release.draft,
    id: release.id,
    prerelease: release.prerelease,
    tagName: release.tag_name,
    targetCommitish: release.target_commitish,
  };
}

function isPublishedStableRelease(release) {
  return (
    release?.draft === false &&
    release?.prerelease === false &&
    stableSemVerTagPattern.test(release?.tagName ?? "")
  );
}

function parseStableSemVer(value, description) {
  const match = stableSemVerTagPattern.exec(value ?? "");
  if (!match) {
    throw new Error(`${description} must be a stable SemVer tag like v1.2.3`);
  }
  return match.slice(1).map((component) => BigInt(component));
}

function compareSemVer(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] < right[index]) return -1;
    if (left[index] > right[index]) return 1;
  }
  return 0;
}

function expectedProbeAssetNames() {
  return [
    ...probeTargets.flatMap((target) => {
      const archive = `enoki-probe-${target}.tar.gz`;
      return [archive, `${archive}.sha256`];
    }),
    "install-probe.sh",
    "manifest.json",
    "manifest.json.sig",
    "signing-key.pem",
  ].sort();
}

function collectRequiredReleaseAssets(assets, expectedNames) {
  const assetsByName = new Map();
  for (const asset of assets ?? []) {
    if (!expectedNames.includes(asset?.name)) continue;
    if (assetsByName.has(asset.name)) {
      throw new Error(`Release Baseline asset ${asset.name} is duplicated`);
    }
    assertRemoteAssetIdentity(asset);
    assetsByName.set(asset.name, asset);
  }
  if (
    !objectsEqual([...assetsByName.keys()].sort(), [...expectedNames].sort())
  ) {
    throw new Error(
      `Release Baseline Probe Asset Set must contain exactly: ${expectedNames.join(", ")}`,
    );
  }
  return assetsByName;
}

function assertDownloadedAsset(bytes, asset) {
  const expectedDigest = asset.digest.slice("sha256:".length);
  if (bytes.byteLength !== asset.size || sha256(bytes) !== expectedDigest) {
    throw new Error(
      `downloaded Release Baseline asset ${asset.name} does not match its published digest or size`,
    );
  }
}

function assertRemoteAssetIdentity(asset) {
  if (
    !Number.isSafeInteger(asset.id) ||
    asset.id <= 0 ||
    !Number.isSafeInteger(asset.size) ||
    asset.size < 0 ||
    !sha256DigestPattern.test(asset.digest ?? "")
  ) {
    throw new Error(
      `Release Baseline asset ${asset.name ?? "<unnamed>"} has no immutable published identity`,
    );
  }
}

function canonicalTrustedProbePublicKey(publicKeyPem) {
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    throw new Error("canonical production Probe public key is required");
  }
  const canonicalPem = publicKeyPem.endsWith("\n")
    ? publicKeyPem
    : `${publicKeyPem}\n`;
  try {
    createPublicKey(canonicalPem);
  } catch {
    throw new Error("canonical production Probe public key is malformed");
  }
  return Buffer.from(canonicalPem);
}

function selectRunnableImageDescriptor(index) {
  if (
    index.schemaVersion !== 2 ||
    !Array.isArray(index.manifests) ||
    index.manifests.length === 0
  ) {
    throw new Error("Release Baseline Hub image index is malformed");
  }
  const runnable = [];
  for (const descriptor of index.manifests) {
    assertRegistryDescriptor(
      descriptor,
      registryManifestMediaTypes,
      "Release Baseline Hub image index entry",
    );
    const platform = descriptor.platform;
    assertDescriptorPlatform(platform);
    const isAttestation =
      descriptor.annotations?.["vnd.docker.reference.type"] ===
        "attestation-manifest" ||
      (platform?.os === "unknown" && platform?.architecture === "unknown");
    if (
      !isAttestation &&
      imageManifestMediaTypes.has(descriptor.mediaType) &&
      platform?.os === "linux" &&
      platform?.architecture === "amd64"
    ) {
      assertExactPlatform(platform);
      runnable.push(descriptor);
    }
  }
  if (runnable.length !== 1) {
    throw new Error(
      "Release Baseline Hub tag must select exactly one runnable linux/amd64 image",
    );
  }
  return runnable[0];
}

function assertDescriptorPlatform(platform) {
  if (
    !platform ||
    typeof platform !== "object" ||
    typeof platform.os !== "string" ||
    platform.os.length === 0 ||
    typeof platform.architecture !== "string" ||
    platform.architecture.length === 0 ||
    (platform.variant !== undefined && typeof platform.variant !== "string")
  ) {
    throw new Error("Release Baseline Hub image platform is malformed");
  }
}

function selectedImageDescriptorFromSource(source, sourceDescriptor) {
  if (
    source.schemaVersion !== 2 ||
    (source.mediaType !== undefined &&
      source.mediaType !== sourceDescriptor.mediaType)
  ) {
    throw new Error(
      "Release Baseline Hub source manifest media type is invalid",
    );
  }
  if (ociIndexMediaTypes.has(sourceDescriptor.mediaType)) {
    return selectRunnableImageDescriptor(source);
  }
  if (imageManifestMediaTypes.has(sourceDescriptor.mediaType)) {
    validateImageManifest({
      bytes: Buffer.from(JSON.stringify(source)),
      descriptor: sourceDescriptor,
    });
    return sourceDescriptor;
  }
  throw new Error("Release Baseline Hub source manifest is unsupported");
}

function validateImageManifest(content) {
  assertRegistryDescriptor(
    content.descriptor,
    imageManifestMediaTypes,
    "Release Baseline Hub image manifest",
  );
  const manifest = parseJsonBytes(
    content.bytes,
    "Release Baseline Hub image manifest",
  );
  if (
    manifest.schemaVersion !== 2 ||
    manifest.mediaType !== content.descriptor.mediaType ||
    !manifest.config ||
    !Array.isArray(manifest.layers)
  ) {
    throw new Error("Release Baseline Hub image manifest is malformed");
  }
  assertRegistryDescriptor(
    manifest.config,
    imageConfigMediaTypes,
    "Release Baseline Hub image config descriptor",
  );
  for (const layer of manifest.layers) {
    assertRegistryDescriptor(
      layer,
      imageLayerMediaTypes,
      "Release Baseline Hub image layer descriptor",
    );
  }
  return manifest;
}

function validateImageConfig(content) {
  const config = parseJsonBytes(
    content.bytes,
    "Release Baseline Hub image config",
  );
  if (
    !config.rootfs ||
    config.rootfs.type !== "layers" ||
    !Array.isArray(config.rootfs.diff_ids)
  ) {
    throw new Error("Release Baseline Hub image config is malformed");
  }
  return config;
}

function validateImageClosure(closure) {
  assertContentIdentity(
    closure.sourceManifest,
    registryManifestMediaTypes,
    "Release Baseline Hub source manifest",
  );
  const source = parseJsonBytes(
    closure.sourceManifest.bytes,
    "Release Baseline Hub source manifest",
  );
  const selected = selectedImageDescriptorFromSource(
    source,
    closure.sourceManifest.descriptor,
  );
  assertContentIdentity(
    closure.imageManifest,
    imageManifestMediaTypes,
    "Release Baseline Hub image manifest",
  );
  assertContentMatchesDescriptor(
    closure.imageManifest,
    selected,
    "Release Baseline Hub selected image manifest",
  );
  const manifest = validateImageManifest(closure.imageManifest);
  assertContentIdentity(
    closure.config,
    imageConfigMediaTypes,
    "Release Baseline Hub image config",
  );
  assertContentMatchesDescriptor(
    closure.config,
    manifest.config,
    "Release Baseline Hub image config",
  );
  const config = validateImageConfig(closure.config);
  if (
    config.os !== "linux" ||
    config.architecture !== "amd64" ||
    !objectsEqual(closure.platform, { architecture: "amd64", os: "linux" }) ||
    config.rootfs.diff_ids.length !== manifest.layers.length
  ) {
    throw new Error(
      "Release Baseline Hub closure must be one complete linux/amd64 image",
    );
  }
  if (
    !Array.isArray(closure.layers) ||
    closure.layers.length !== manifest.layers.length
  ) {
    throw new Error("Release Baseline Hub closure is missing image layers");
  }
  for (let index = 0; index < closure.layers.length; index += 1) {
    assertContentIdentity(
      closure.layers[index],
      imageLayerMediaTypes,
      `Release Baseline Hub image layer ${index}`,
    );
    assertContentMatchesDescriptor(
      closure.layers[index],
      manifest.layers[index],
      `Release Baseline Hub image layer ${index}`,
    );
  }
}

async function materializeOciArchive(closure, archivePath) {
  validateImageClosure(closure);
  const layoutDir = await mkdtemp(path.join(tmpdir(), "enoki-baseline-oci-"));
  try {
    const blobsDir = path.join(layoutDir, "blobs", "sha256");
    await mkdir(blobsDir, { recursive: true });
    for (const content of [
      closure.imageManifest,
      closure.config,
      ...closure.layers,
    ]) {
      await writeFile(
        path.join(blobsDir, content.descriptor.digest.slice("sha256:".length)),
        content.bytes,
      );
    }
    await writeFile(
      path.join(layoutDir, "oci-layout"),
      `${JSON.stringify({ imageLayoutVersion: "1.0.0" })}\n`,
    );
    await writeFile(
      path.join(layoutDir, "index.json"),
      `${JSON.stringify({
        manifests: [
          {
            ...closure.imageManifest.descriptor,
            platform: closure.platform,
          },
        ],
        schemaVersion: 2,
      })}\n`,
    );
    await execFileAsync("tar", [
      "--sort=name",
      "--mtime=@0",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      "--format=gnu",
      "--create",
      "--file",
      archivePath,
      "--directory",
      layoutDir,
      ".",
    ]);
  } finally {
    await rm(layoutDir, { force: true, recursive: true });
  }
}

async function inspectBaselineHubArchive(archivePath, probeFiles) {
  try {
    return await inspectHubOciArchive({ archivePath, probeFiles });
  } catch (error) {
    // Published Hub images through v0.1.70 embedded every runtime-verifiable
    // Probe asset but did not copy the optional GitHub checksum sidecars.
    // Preserve that one exact historical shape; all other missing/extra files
    // still fail the shared rootfs verifier.
    if (
      !(error instanceof Error) ||
      !error.message.startsWith(
        "Hub OCI embedded Probe Asset Set must contain exactly:",
      )
    ) {
      throw error;
    }
    return inspectHubOciArchive({
      archivePath,
      probeFiles: probeFiles.filter(
        ({ file }) => !file.endsWith(".tar.gz.sha256"),
      ),
    });
  }
}

function assertContentMatchesDescriptor(content, expected, description) {
  if (!descriptorsEqual(content.descriptor, expected)) {
    throw new Error(`${description} descriptor changed while downloading`);
  }
  assertContentIdentity(content, new Set([expected.mediaType]), description);
}

function assertContentIdentity(content, allowedMediaTypes, description) {
  assertRegistryDescriptor(content?.descriptor, allowedMediaTypes, description);
  if (!Buffer.isBuffer(content?.bytes)) {
    throw new Error(`${description} bytes are missing`);
  }
  if (
    content.bytes.byteLength !== content.descriptor.size ||
    `sha256:${sha256(content.bytes)}` !== content.descriptor.digest
  ) {
    throw new Error(`${description} digest or size does not match`);
  }
}

function assertRegistryDescriptor(descriptor, allowedMediaTypes, description) {
  if (
    !descriptor ||
    typeof descriptor !== "object" ||
    !sha256DigestPattern.test(descriptor.digest ?? "") ||
    !Number.isSafeInteger(descriptor.size) ||
    descriptor.size < 0 ||
    !allowedMediaTypes.has(descriptor.mediaType)
  ) {
    throw new Error(`${description} descriptor is invalid`);
  }
}

function descriptorsEqual(left, right) {
  return (
    left?.digest === right?.digest &&
    left?.mediaType === right?.mediaType &&
    left?.size === right?.size
  );
}

function assertExactPlatform(platform) {
  if (
    !platform ||
    typeof platform !== "object" ||
    platform.os !== "linux" ||
    platform.architecture !== "amd64" ||
    (platform.variant !== undefined && platform.variant !== "")
  ) {
    throw new Error("Release Baseline Hub platform is not linux/amd64");
  }
}

function registryManifestIdentity(response, bytes) {
  const digest = response.headers.get("docker-content-digest");
  const mediaType = (response.headers.get("content-type") ?? "")
    .split(";", 1)[0]
    .trim();
  const descriptor = { digest, mediaType, size: bytes.byteLength };
  assertContentIdentity(
    { bytes, descriptor },
    registryManifestMediaTypes,
    "GHCR Hub manifest",
  );
  return { bytes, descriptor };
}

async function requestRegistryToken({ challenge, fetchImpl, repository }) {
  const parsed = parseBearerChallenge(challenge);
  if (
    parsed.realm !== "https://ghcr.io/token" ||
    parsed.service !== "ghcr.io" ||
    parsed.scope !== `repository:${repository}:pull`
  ) {
    throw new Error("GHCR authentication challenge is invalid");
  }
  const query = new URLSearchParams({
    scope: parsed.scope,
    service: parsed.service,
  });
  const response = await fetchImpl(`${parsed.realm}?${query}`, {
    headers: { Accept: "application/json" },
  });
  await assertFetchSucceeded(response, "request GHCR pull token");
  const body = await response.json();
  const token = body?.token ?? body?.access_token;
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("GHCR token response is malformed");
  }
  return token;
}

function parseBearerChallenge(challenge) {
  if (typeof challenge !== "string" || !/^Bearer\s/i.test(challenge)) {
    throw new Error("GHCR did not return a Bearer authentication challenge");
  }
  const result = {};
  for (const match of challenge
    .replace(/^Bearer\s+/i, "")
    .matchAll(/(?:^|,)\s*([a-z]+)="([^"]+)"/g)) {
    result[match[1]] = match[2];
  }
  return result;
}

async function assertFetchSucceeded(response, action) {
  if (!response?.ok) {
    throw new Error(
      `${action} failed with HTTP ${response?.status ?? "unknown"}`,
    );
  }
}

function assertImmutableRepository(repository) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? "")) {
    throw new Error("GitHub repository must be an owner/name pair");
  }
}

function assertImmutableImageName(image) {
  if (
    !/^ghcr[.]io\/[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(image ?? "") ||
    image.includes("@") ||
    image.split("/").at(-1).includes(":")
  ) {
    throw new Error(
      "Hub image must be a GHCR repository without a mutable tag or digest reference",
    );
  }
}

function assertSameFileNames(actual, expected, description) {
  if (!objectsEqual(actual, expected)) {
    throw new Error(
      `${description} must contain exactly: ${expected.join(", ")}`,
    );
  }
}

function assertPlainObject(value, description) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
}

function assertExactKeys(value, expectedKeys) {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (!objectsEqual(actual, expected)) {
    throw new Error(`${expectedKeys.join(", ")} must be the exact fields`);
  }
}

async function readJson(filePath, description) {
  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch {
    throw new Error(`${description} is missing or malformed`);
  }
}

function parseJsonBytes(bytes, description) {
  try {
    const value = JSON.parse(bytes.toString("utf8"));
    assertPlainObject(value, description);
    return value;
  } catch {
    throw new Error(`${description} is malformed`);
  }
}

async function fileSha256(filePath) {
  return sha256(await readFile(filePath));
}

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function objectsEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}
