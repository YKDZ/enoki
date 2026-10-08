import { execFile } from "node:child_process";
import { createPublicKey, randomUUID } from "node:crypto";
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
  probeTargets,
  trustEpochLegacyReleaseSha256,
} from "@enoki/probe-release";

import {
  resolveMigrationAuthorization,
  validateMigrationBaselineContents,
  verifyLegacyProbeAssetSet,
} from "./release-baseline-migration-lib.ts";
import {
  assertContentIdentity,
  assertContentMatchesDescriptor,
  assertImmutableImageName,
  assertImmutableRepository,
  assertReleaseBaselinePrecedesCandidate,
  baselineDescriptorFile,
  canonicalTrustedProbePublicKey,
  compareSemVer,
  createReleaseCatalogSnapshot,
  descriptorsEqual,
  fileSha256,
  gitObjectIdPattern,
  hubSourceManifestFile,
  imageManifestMediaTypes,
  inspectBaselineHubArchive,
  isPublishedStableRelease,
  ociIndexMediaTypes,
  objectsEqual,
  parseJsonBytes,
  parseStableSemVer,
  registryManifestMediaTypes,
  selectRunnableImageDescriptor,
  sha256,
  sha256DigestPattern,
  stableSemVerTagPattern,
  validateImageClosure,
  validateImageConfig,
  validateImageManifest,
  validateReleaseBaselineBundle,
  validateReleaseCatalogSnapshot,
  validateResolvedReleaseBaseline,
  validateTrustEpochMigrationBaselineBundle,
} from "./release-baseline-verification.ts";
import { inspectProbeAssetSet } from "./release-candidate-verification.ts";
import { assertPlainObject } from "./release-json-guards.ts";

export {
  assertReleaseBaselinePrecedesCandidate,
  createReleaseCatalogSnapshot,
  validateReleaseBaselineBundle,
  validateReleaseCatalogSnapshot,
  validateResolvedReleaseBaseline,
  validateTrustEpochMigrationBaselineBundle,
};

const execFileAsync = promisify(execFile);
const transitionMetadataFileNames = Object.freeze([
  "release-transition-contract.json",
  "release-transition-contract.json.sig",
  "trust-epoch-migration-authorization.json",
  "trust-epoch-migration-authorization.json.sig",
]);

class RootedBaselineMetadataClosureError extends Error {
  constructor(message) {
    super(message);
    this.code = "RELEASE_BASELINE_ROOT_METADATA_CLOSURE_MISSING";
    this.classification = "rooted-baseline-metadata-closure-missing";
  }
}

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
  trustedRootPublicKeyPem,
  trustEpochMigrationAuthorizationBytes,
  trustEpochMigrationAuthorizationSignature,
}) {
  try {
    return await resolveRootedReleaseBaseline({
      assetDownloader,
      candidateVersion,
      githubRepository,
      hubImage,
      outputDir,
      registry,
      releaseCatalog,
      trustedRootPublicKeyPem,
    });
  } catch (rootedError) {
    if (
      !isExactLegacyRootMetadataGap(rootedError) ||
      trustEpochMigrationAuthorizationBytes === undefined ||
      trustEpochMigrationAuthorizationSignature === undefined
    ) {
      throw rootedError;
    }
    return resolveTrustEpochMigrationBaseline({
      assetDownloader,
      candidateVersion,
      githubRepository,
      hubImage,
      outputDir,
      registry,
      releaseCatalog,
      trustedRootPublicKeyPem,
      trustEpochMigrationAuthorizationBytes,
      trustEpochMigrationAuthorizationSignature,
    });
  }
}

async function resolveRootedReleaseBaseline({
  assetDownloader,
  candidateVersion,
  githubRepository,
  hubImage,
  outputDir,
  registry,
  releaseCatalog,
  trustedRootPublicKeyPem,
}) {
  const trustedRootPublicKey = canonicalTrustedProbePublicKey(
    trustedRootPublicKeyPem,
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
  const expectedAssetNames = expectedRootedProbeAssetNames(selected.assets);
  const assetsByName = collectRequiredReleaseAssets(
    selected.assets,
    expectedAssetNames,
    selected.tagName,
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

    const inspectedProbe = await inspectProbeAssetSet(probeAssetDir, {
      expectedVersion: selected.tagName.slice(1),
      requireEmbeddedProbeIdentity: false,
      trustedRootPublicKeyPem: trustedRootPublicKey,
    });
    if (
      inspectedProbe.releaseTransition &&
      inspectedProbe.releaseTransition.candidateCommit !==
        releaseIdentity.peeledCommitSha
    ) {
      throw new Error(
        "published Release Baseline transition does not match its release commit",
      );
    }

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
      kind: "enoki-release-baseline",
      probeAssetSet: {
        directory: "probe-assets",
        files: inspectedProbe.files,
        signingIdentity: inspectedProbe.signingIdentity,
        trustRoot: {
          publicKeySha256: sha256(trustedRootPublicKey),
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
      trustedRootPublicKeyPem: trustedRootPublicKey.toString("utf8"),
    });
    await rename(stagingDir, outputDir);
    return descriptor;
  } catch (error) {
    await rm(stagingDir, { force: true, recursive: true });
    throw error;
  }
}

function isExactLegacyRootMetadataGap(error) {
  return (
    error instanceof RootedBaselineMetadataClosureError &&
    error.code === "RELEASE_BASELINE_ROOT_METADATA_CLOSURE_MISSING" &&
    error.releaseBaselineTag === "v0.1.74"
  );
}

async function resolveTrustEpochMigrationBaseline({
  assetDownloader,
  candidateVersion,
  githubRepository,
  hubImage,
  outputDir,
  registry,
  releaseCatalog,
  trustedRootPublicKeyPem,
  trustEpochMigrationAuthorizationBytes,
  trustEpochMigrationAuthorizationSignature,
}) {
  const trustedRoot = canonicalTrustedProbePublicKey(trustedRootPublicKeyPem);
  const releases = await releaseCatalog.listReleases();
  const catalogSnapshot = createReleaseCatalogSnapshot(releases);
  const selected = selectReleaseBaseline({ candidateVersion, releases });
  const identity = await resolveAndAssertReleaseIdentity({
    releaseCatalog,
    selected,
  });
  const resolvedHub = await registry.downloadImage({
    image: hubImage,
    reference: selected.tagName,
  });
  validateImageClosure(resolvedHub);
  const { authorization, expectedLegacyRelease } =
    resolveMigrationAuthorization({
      authorizationBytes: trustEpochMigrationAuthorizationBytes,
      authorizationSignature: trustEpochMigrationAuthorizationSignature,
      candidateVersion,
      githubRelease: {
        id: identity.id,
        peeledCommitSha: identity.peeledCommitSha,
        repository: githubRepository,
        tag: selected.tagName,
        tagRefSha: identity.tagRefSha,
        targetCommitish: identity.targetCommitish,
      },
      hub: {
        digest: resolvedHub.sourceManifest.descriptor.digest,
        image: hubImage,
      },
      publishedAssets: selected.assets,
      trustedRootPublicKeyPem: trustedRoot,
    });
  const stagingDir = `${outputDir}.tmp-${randomUUID()}`;
  const probeAssetDir = path.join(stagingDir, "probe-assets");
  try {
    await mkdir(probeAssetDir, { recursive: true });
    for (const asset of authorization.legacyRelease.assets) {
      const published = (selected.assets ?? []).find(
        ({ name }) => name === asset.name,
      );
      if (
        !published ||
        published.size !== asset.size ||
        published.digest !== `sha256:${asset.sha256}`
      ) {
        throw new Error(
          "Trust Epoch Migration Authorization asset closure does not match",
        );
      }
      const bytes = Buffer.from(
        await assetDownloader.downloadAsset({
          asset: published,
          release: selected,
          repository: githubRepository,
        }),
      );
      assertDownloadedAsset(bytes, published);
      await writeFile(path.join(probeAssetDir, asset.name), bytes);
    }
    await verifyLegacyProbeAssetSet(
      probeAssetDir,
      authorization.legacyRelease.legacySigningKeySha256,
    );
    await writeFile(
      path.join(stagingDir, "trust-epoch-migration-authorization.json"),
      trustEpochMigrationAuthorizationBytes,
    );
    await writeFile(
      path.join(stagingDir, "trust-epoch-migration-authorization.json.sig"),
      trustEpochMigrationAuthorizationSignature,
    );
    await writeFile(
      path.join(stagingDir, hubSourceManifestFile),
      resolvedHub.sourceManifest.bytes,
    );
    const hubDirectory = path.join(stagingDir, "hub");
    await mkdir(hubDirectory, { recursive: true });
    const hubArchiveFile = `enoki-hub-${selected.tagName}.oci.tar`;
    const hubArchivePath = path.join(hubDirectory, hubArchiveFile);
    await materializeOciArchive(resolvedHub, hubArchivePath);
    const legacyFiles = authorization.legacyRelease.assets.map((asset) => ({
      file: asset.name,
      sha256: asset.sha256,
      size: asset.size,
    }));
    const offlineHub = await inspectBaselineHubArchive(
      hubArchivePath,
      legacyFiles,
    );
    if (offlineHub.digest !== resolvedHub.imageManifest.descriptor.digest) {
      throw new Error(
        "materialized Trust Epoch Migration Hub OCI archive does not match",
      );
    }
    const descriptor = {
      authorization: {
        file: "trust-epoch-migration-authorization.json",
        legacyReleaseSha256: trustEpochLegacyReleaseSha256(
          authorization.legacyRelease,
        ),
        sha256: sha256(trustEpochMigrationAuthorizationBytes),
        signatureFile: "trust-epoch-migration-authorization.json.sig",
        signatureSha256: sha256(trustEpochMigrationAuthorizationSignature),
      },
      catalogSnapshot,
      githubRelease: expectedLegacyRelease.githubRelease,
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
      kind: "enoki-trust-epoch-migration-baseline",
      legacyProbeAssets: {
        directory: "probe-assets",
        files: authorization.legacyRelease.assets,
      },
      schemaVersion: 1,
      tag: selected.tagName,
      transition: "replacement-required",
    };
    await writeFile(
      path.join(stagingDir, baselineDescriptorFile),
      `${JSON.stringify(descriptor, null, 2)}\n`,
    );
    await validateTrustEpochMigrationBaselineBundle(stagingDir, {
      candidateVersion,
      trustedRootPublicKeyPem: trustedRoot,
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
  trustedRootPublicKeyPem,
}) {
  const descriptor = await validateResolvedReleaseBaseline(bundleDir, {
    candidateVersion,
    trustedRootPublicKeyPem,
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

function expectedProbeAssetNames() {
  return [
    ...probeTargets.flatMap((target) => {
      const archive = `enoki-probe-${target}.tar.gz`;
      return [archive, `${archive}.sha256`];
    }),
    "manifest.json",
    "manifest.json.sig",
    "root-key.pem",
    "signing-key.pem",
    "trust-delegation.json",
    "trust-delegation.json.sig",
  ].sort();
}

function expectedRootedProbeAssetNames(assets) {
  const ordinary = expectedProbeAssetNames();
  const publishedNames = new Set((assets ?? []).map(({ name }) => name));
  const historicalTransitionCount = transitionMetadataFileNames.filter((name) =>
    publishedNames.has(name),
  ).length;
  if (historicalTransitionCount === 0) return ordinary;
  if (historicalTransitionCount === transitionMetadataFileNames.length) {
    return [...ordinary, ...transitionMetadataFileNames].sort();
  }
  throw new Error(
    "Release Baseline Probe Asset Set transition closure is incomplete",
  );
}

function collectRequiredReleaseAssets(assets, expectedNames, baselineTag) {
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
    const actualNames = [...assetsByName.keys()].sort();
    const legacyNames = expectedNames
      .filter(
        (name) =>
          ![
            "root-key.pem",
            "trust-delegation.json",
            "trust-delegation.json.sig",
          ].includes(name),
      )
      .sort();
    const error = objectsEqual(actualNames, legacyNames)
      ? new RootedBaselineMetadataClosureError(
          `Release Baseline Probe Asset Set must contain exactly: ${expectedNames.join(", ")}`,
        )
      : new Error(
          `Release Baseline Probe Asset Set must contain exactly: ${expectedNames.join(", ")}`,
        );
    if (error instanceof RootedBaselineMetadataClosureError) {
      error.releaseBaselineTag = baselineTag;
    }
    throw error;
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
      "blobs",
      "index.json",
      "oci-layout",
    ]);
  } finally {
    await rm(layoutDir, { force: true, recursive: true });
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
