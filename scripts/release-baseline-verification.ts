// Release Baseline 验收证据的离线检验实现：只读校验 baseline bundle、catalog snapshot 与
// Hub OCI 制品；远端解析、下载与生产者职责仍由 release-baseline-lib.mjs 承担。
import { createHash, createPublicKey } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

import { validateMigrationBaselineContents } from "./release-baseline-migration-lib.ts";
import {
  inspectHubOciArchive,
  type ProbeAssetFileIdentity,
} from "./release-candidate-oci.ts";
import { inspectProbeAssetSet } from "./release-candidate-verification.ts";
import {
  assertPlainObject,
  isSafeInteger,
  isUnknownArray,
  isUnknownRecord,
  objectView,
  stringValue,
  type UnknownRecord,
} from "./release-json-guards.ts";

type BaselineBundleOptions = {
  candidateVersion?: string;
  trustedRootPublicKeyPem?: Buffer | string;
};

type CatalogRelease = {
  assets?: unknown;
  draft?: unknown;
  id?: unknown;
  prerelease?: unknown;
  tagName?: unknown;
  targetCommitish?: unknown;
};

type ImagePlatform = {
  architecture: string;
  os: string;
  variant?: string;
};

type RegistryDescriptor = {
  annotations?: unknown;
  digest: string;
  mediaType: string;
  platform?: unknown;
  size: number;
};

type HubContent = {
  bytes: Buffer;
  descriptor: RegistryDescriptor;
};

type HubClosure = {
  config: HubContent;
  imageManifest: HubContent;
  layers: HubContent[];
  platform: unknown;
  sourceManifest: HubContent;
};

export type ReleaseCatalogEntry = {
  assets: { digest: unknown; id: unknown; name: unknown; size: unknown }[];
  id?: unknown;
  tag?: unknown;
  targetCommitish?: unknown;
};

export type ReleaseCatalogSnapshot = {
  entries: ReleaseCatalogEntry[];
  sha256: string;
};

export const stableSemVerTagPattern =
  /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
export const sha256DigestPattern = /^sha256:([0-9a-f]{64})$/;
export const gitObjectIdPattern = /^[0-9a-f]{40}$/;
export const baselineDescriptorFile = "release-baseline.json";
export const hubSourceManifestFile = "hub-source-manifest.json";
export const ociIndexMediaTypes = new Set([
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.index.v1+json",
]);
export const imageManifestMediaTypes = new Set([
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
export const registryManifestMediaTypes = new Set([
  ...ociIndexMediaTypes,
  ...imageManifestMediaTypes,
]);
export async function validateResolvedReleaseBaseline(
  bundleDir: string,
  options: BaselineBundleOptions = {},
) {
  const descriptor: unknown = await readJson(
    path.join(bundleDir, baselineDescriptorFile),
    "Release Baseline descriptor",
  );
  if (
    isUnknownRecord(descriptor) &&
    descriptor.kind === "enoki-trust-epoch-migration-baseline"
  ) {
    return validateTrustEpochMigrationBaselineBundle(bundleDir, options);
  }
  return validateReleaseBaselineBundle(bundleDir, options);
}

export async function validateTrustEpochMigrationBaselineBundle(
  bundleDir: string,
  { candidateVersion, trustedRootPublicKeyPem }: BaselineBundleOptions = {},
) {
  assertSameFileNames(
    (await readdir(bundleDir)).sort(),
    [
      baselineDescriptorFile,
      "hub",
      hubSourceManifestFile,
      "probe-assets",
      "trust-epoch-migration-authorization.json",
      "trust-epoch-migration-authorization.json.sig",
    ].sort(),
    "Trust Epoch Migration Release Baseline bundle",
  );
  const descriptor = await readJson(
    path.join(bundleDir, baselineDescriptorFile),
    "Trust Epoch Migration Release Baseline descriptor",
  );
  assertPlainObject(
    descriptor,
    "Trust Epoch Migration Release Baseline descriptor",
  );
  assertExactKeys(descriptor, [
    "authorization",
    "catalogSnapshot",
    "githubRelease",
    "hub",
    "kind",
    "legacyProbeAssets",
    "schemaVersion",
    "tag",
    "transition",
  ]);
  if (
    descriptor.kind !== "enoki-trust-epoch-migration-baseline" ||
    descriptor.schemaVersion !== 1 ||
    descriptor.transition !== "replacement-required" ||
    descriptor.tag !== "v0.1.74"
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline descriptor does not match",
    );
  }
  validateReleaseCatalogSnapshot(descriptor.catalogSnapshot);
  return validateMigrationBaselineContents({
    bundleDir,
    candidateVersion,
    descriptor,
    trustedRootPublicKeyPem,
  });
}

export async function validateReleaseBaselineBundle(
  bundleDir: string,
  { trustedRootPublicKeyPem }: BaselineBundleOptions = {},
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
    "kind",
    "probeAssetSet",
    "schemaVersion",
    "tag",
  ]);
  if (
    descriptor.kind !== "enoki-release-baseline" ||
    descriptor.schemaVersion !== 2 ||
    !stableSemVerTagPattern.test(stringValue(descriptor.tag))
  ) {
    throw new Error(
      "Release Baseline descriptor schema, kind, or tag is invalid",
    );
  }
  const catalogSnapshot: unknown = descriptor.catalogSnapshot;
  validateReleaseCatalogSnapshot(catalogSnapshot);

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
    !isSafeInteger(githubRelease.id) ||
    githubRelease.id <= 0 ||
    !gitObjectIdPattern.test(stringValue(githubRelease.tagRefSha)) ||
    !gitObjectIdPattern.test(stringValue(githubRelease.peeledCommitSha)) ||
    typeof githubRelease.targetCommitish !== "string" ||
    githubRelease.targetCommitish.length === 0
  ) {
    throw new Error("Release Baseline descriptor release identity is invalid");
  }
  const snapshotRelease = catalogSnapshot.entries.find(
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
    probe.version !== stringValue(descriptor.tag).slice(1)
  ) {
    throw new Error("Release Baseline Probe version disagrees with its tag");
  }
  const trustRoot: unknown = probe.trustRoot;
  assertPlainObject(trustRoot, "Release Baseline Probe trust root");
  assertExactKeys(trustRoot, ["publicKeySha256"]);
  if (!/^[0-9a-f]{64}$/.test(stringValue(trustRoot.publicKeySha256))) {
    throw new Error("Release Baseline Probe trust root is invalid");
  }
  const publishedRootPublicKey = await readFile(
    path.join(bundleDir, "probe-assets", "root-key.pem"),
  );
  if (sha256(publishedRootPublicKey) !== trustRoot.publicKeySha256) {
    throw new Error("Release Baseline Probe trust root does not match content");
  }
  if (trustedRootPublicKeyPem !== undefined) {
    const trusted = canonicalTrustedProbePublicKey(trustedRootPublicKeyPem);
    if (!publishedRootPublicKey.equals(trusted)) {
      throw new Error(
        "Release Baseline root-key.pem does not match the external Probe Distribution Trust Root",
      );
    }
  }
  const inspectedProbe = await inspectProbeAssetSet(
    path.join(bundleDir, "probe-assets"),
    {
      expectedVersion: stringValue(probe.version),
      requireEmbeddedProbeIdentity: false,
      trustedRootPublicKeyPem,
    },
  );
  if (
    !objectsEqual(inspectedProbe.files, probe.files) ||
    !objectsEqual(inspectedProbe.signingIdentity, probe.signingIdentity)
  ) {
    throw new Error(
      "Release Baseline Probe Asset Set descriptor does not match content",
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
  const expectedArchive = `hub/enoki-hub-${stringValue(descriptor.tag)}.oci.tar`;
  if (
    hub.archive !== expectedArchive ||
    hub.sourceManifest !== hubSourceManifestFile ||
    !sha256DigestPattern.test(stringValue(hub.digest)) ||
    !sha256DigestPattern.test(stringValue(hub.imageDigest)) ||
    !registryManifestMediaTypes.has(stringValue(hub.mediaType)) ||
    !/^[0-9a-f]{64}$/.test(stringValue(hub.archiveSha256)) ||
    !/^[0-9a-f]{64}$/.test(stringValue(hub.sourceManifestSha256)) ||
    !isSafeInteger(hub.size) ||
    hub.size < 1 ||
    !isSafeInteger(hub.sourceManifestSize) ||
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
    hub.digest !== `sha256:${stringValue(hub.sourceManifestSha256)}`
  ) {
    throw new Error(
      "Release Baseline Hub source manifest does not match its descriptor",
    );
  }
  const sourceDescriptor = {
    digest: stringValue(hub.digest),
    mediaType: stringValue(hub.mediaType),
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

export function assertReleaseBaselinePrecedesCandidate({
  baselineTag,
  candidateVersion,
}: {
  baselineTag: unknown;
  candidateVersion: unknown;
}) {
  const baseline = parseStableSemVer(baselineTag, "Release Baseline tag");
  const candidate = parseStableSemVer(candidateVersion, "candidate version");
  if (compareSemVer(baseline, candidate) >= 0) {
    throw new Error(
      `Release Baseline ${String(baselineTag)} must be lower than candidate ${String(candidateVersion)}`,
    );
  }
}

export function createReleaseCatalogSnapshot(
  releases: readonly CatalogRelease[],
) {
  const entries = releases
    .filter(isPublishedStableRelease)
    .map((release) => {
      const assetSource = isUnknownArray(release.assets) ? release.assets : [];
      return {
        assets: assetSource
          .map((asset) => {
            const view = objectView(asset);
            return {
              digest: view.digest ?? null,
              id: view.id,
              name: view.name,
              size: view.size,
            };
          })
          .sort((left, right) =>
            `${stringValue(left.name)}:${String(left.id)}`.localeCompare(
              `${stringValue(right.name)}:${String(right.id)}`,
            ),
          ),
        id: release.id,
        tag: release.tagName,
        targetCommitish: release.targetCommitish,
      };
    })
    .sort((left, right) =>
      stringValue(left.tag).localeCompare(stringValue(right.tag)),
    );
  const serialized = JSON.stringify(entries);
  return { entries, sha256: sha256(Buffer.from(serialized)) };
}

export function validateReleaseCatalogSnapshot(
  snapshot: unknown,
): asserts snapshot is ReleaseCatalogSnapshot {
  assertPlainObject(snapshot, "Release catalog snapshot");
  assertExactKeys(snapshot, ["entries", "sha256"]);
  if (!isUnknownArray(snapshot.entries)) {
    throw new Error("Release catalog snapshot entries are invalid");
  }
  const expected = createReleaseCatalogSnapshot(
    snapshot.entries.map((entry) => {
      const view = objectView(entry);
      return {
        assets: view.assets,
        draft: false,
        id: view.id,
        prerelease: false,
        tagName: view.tag,
        targetCommitish: view.targetCommitish,
      };
    }),
  );
  if (!objectsEqual(expected, snapshot)) {
    throw new Error("Release catalog snapshot checksum is invalid");
  }
}

export function isPublishedStableRelease(
  release: unknown,
): release is CatalogRelease {
  const view = objectView(release);
  return (
    view.draft === false &&
    view.prerelease === false &&
    stableSemVerTagPattern.test(stringValue(view.tagName))
  );
}

export function parseStableSemVer(
  value: unknown,
  description: string,
): readonly bigint[] {
  const match = stableSemVerTagPattern.exec(stringValue(value));
  if (!match) {
    throw new Error(`${description} must be a stable SemVer tag like v1.2.3`);
  }
  return match.slice(1).map((component) => BigInt(component));
}

export function compareSemVer(
  left: readonly bigint[],
  right: readonly bigint[],
): number {
  for (let index = 0; index < 3; index += 1) {
    const leftComponent = left[index] ?? 0n;
    const rightComponent = right[index] ?? 0n;
    if (leftComponent < rightComponent) return -1;
    if (leftComponent > rightComponent) return 1;
  }
  return 0;
}

export function canonicalTrustedProbePublicKey(publicKeyPem: unknown): Buffer {
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

export function selectRunnableImageDescriptor(
  index: unknown,
): RegistryDescriptor {
  const manifests = isUnknownRecord(index) ? index.manifests : null;
  if (
    !isUnknownRecord(index) ||
    index.schemaVersion !== 2 ||
    !isUnknownArray(manifests) ||
    manifests.length === 0
  ) {
    throw new Error("Release Baseline Hub image index is malformed");
  }
  const runnable: RegistryDescriptor[] = [];
  for (const descriptor of manifests) {
    assertRegistryDescriptor(
      descriptor,
      registryManifestMediaTypes,
      "Release Baseline Hub image index entry",
    );
    const platform: unknown = descriptor.platform;
    assertDescriptorPlatform(platform);
    const annotations = objectView(descriptor.annotations);
    const isAttestation =
      annotations["vnd.docker.reference.type"] === "attestation-manifest" ||
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
  const runnableDescriptor = runnable[0];
  if (!runnableDescriptor) {
    throw new Error(
      "Release Baseline Hub tag must select exactly one runnable linux/amd64 image",
    );
  }
  return runnableDescriptor;
}

function assertDescriptorPlatform(
  platform: unknown,
): asserts platform is ImagePlatform {
  if (
    !isUnknownRecord(platform) ||
    typeof platform.os !== "string" ||
    platform.os.length === 0 ||
    typeof platform.architecture !== "string" ||
    platform.architecture.length === 0 ||
    (platform.variant !== undefined && typeof platform.variant !== "string")
  ) {
    throw new Error("Release Baseline Hub image platform is malformed");
  }
}

function selectedImageDescriptorFromSource(
  source: UnknownRecord,
  sourceDescriptor: RegistryDescriptor,
): RegistryDescriptor {
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

export function validateImageManifest(content: HubContent): UnknownRecord {
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

export function validateImageConfig(content: HubContent): UnknownRecord {
  const config = parseJsonBytes(
    content.bytes,
    "Release Baseline Hub image config",
  );
  const rootfs: unknown = config.rootfs;
  if (
    !isUnknownRecord(rootfs) ||
    rootfs.type !== "layers" ||
    !isUnknownArray(rootfs.diff_ids)
  ) {
    throw new Error("Release Baseline Hub image config is malformed");
  }
  return config;
}

export function validateImageClosure(closure: HubClosure): void {
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
  const configDiffIds = objectView(config.rootfs).diff_ids;
  const manifestLayers = manifest.layers;
  if (
    config.os !== "linux" ||
    config.architecture !== "amd64" ||
    !objectsEqual(closure.platform, { architecture: "amd64", os: "linux" }) ||
    !isUnknownArray(configDiffIds) ||
    !isUnknownArray(manifestLayers) ||
    configDiffIds.length !== manifestLayers.length
  ) {
    throw new Error(
      "Release Baseline Hub closure must be one complete linux/amd64 image",
    );
  }
  if (
    !Array.isArray(closure.layers) ||
    closure.layers.length !== manifestLayers.length
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
      manifestLayers[index],
      `Release Baseline Hub image layer ${index}`,
    );
  }
}

export async function inspectBaselineHubArchive(
  archivePath: string,
  probeFiles: readonly ProbeAssetFileIdentity[],
) {
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

export function assertContentMatchesDescriptor(
  content: unknown,
  expected: unknown,
  description: string,
): void {
  if (!descriptorsEqual(objectView(content).descriptor, expected)) {
    throw new Error(`${description} descriptor changed while downloading`);
  }
  const expectedMediaType = objectView(expected).mediaType;
  assertContentIdentity(
    content,
    new Set([stringValue(expectedMediaType)]),
    description,
  );
}

export function assertContentIdentity(
  content: unknown,
  allowedMediaTypes: ReadonlySet<string>,
  description: string,
): asserts content is HubContent {
  const view = objectView(content);
  assertRegistryDescriptor(view.descriptor, allowedMediaTypes, description);
  const bytes = view.bytes;
  if (!Buffer.isBuffer(bytes)) {
    throw new Error(`${description} bytes are missing`);
  }
  if (
    bytes.byteLength !== view.descriptor.size ||
    `sha256:${sha256(bytes)}` !== view.descriptor.digest
  ) {
    throw new Error(`${description} digest or size does not match`);
  }
}

function assertRegistryDescriptor(
  descriptor: unknown,
  allowedMediaTypes: ReadonlySet<string>,
  description: string,
): asserts descriptor is RegistryDescriptor {
  const view = objectView(descriptor);
  const digest = view.digest;
  const size = view.size;
  const mediaType = view.mediaType;
  if (
    !isUnknownRecord(descriptor) ||
    !sha256DigestPattern.test(stringValue(digest)) ||
    !isSafeInteger(size) ||
    size < 0 ||
    !allowedMediaTypes.has(stringValue(mediaType))
  ) {
    throw new Error(`${description} descriptor is invalid`);
  }
}

export function descriptorsEqual(left: unknown, right: unknown): boolean {
  const actual = objectView(left);
  const expected = objectView(right);
  return (
    actual.digest === expected.digest &&
    actual.mediaType === expected.mediaType &&
    actual.size === expected.size
  );
}

function assertExactPlatform(platform: ImagePlatform): void {
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

export function assertImmutableRepository(repository: unknown): void {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(stringValue(repository))) {
    throw new Error("GitHub repository must be an owner/name pair");
  }
}

export function assertImmutableImageName(image: unknown): void {
  const name = stringValue(image);
  if (
    !/^ghcr[.]io\/[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(name) ||
    name.includes("@") ||
    name.split("/").at(-1)?.includes(":")
  ) {
    throw new Error(
      "Hub image must be a GHCR repository without a mutable tag or digest reference",
    );
  }
}

function assertSameFileNames(
  actual: readonly unknown[],
  expected: readonly string[],
  description: string,
): void {
  if (!objectsEqual(actual, expected)) {
    throw new Error(
      `${description} must contain exactly: ${expected.join(", ")}`,
    );
  }
}

function assertExactKeys(
  value: UnknownRecord,
  expectedKeys: readonly string[],
): void {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (!objectsEqual(actual, expected)) {
    throw new Error(`${expectedKeys.join(", ")} must be the exact fields`);
  }
}

async function readJson(
  filePath: string,
  description: string,
): Promise<unknown> {
  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch {
    throw new Error(`${description} is missing or malformed`);
  }
}

export function parseJsonBytes(
  bytes: Buffer,
  description: string,
): UnknownRecord {
  try {
    const value = JSON.parse(bytes.toString("utf8"));
    assertPlainObject(value, description);
    return value;
  } catch {
    throw new Error(`${description} is malformed`);
  }
}

export async function fileSha256(filePath: string): Promise<string> {
  return sha256(await readFile(filePath));
}

export function sha256(contents: Buffer | Uint8Array | string): string {
  return createHash("sha256").update(contents).digest("hex");
}

export function objectsEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}
