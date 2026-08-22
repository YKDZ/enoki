import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

import { inspectHubOciArchive } from "./release-candidate-oci.mjs";
import {
  trustEpochLegacyReleaseSha256,
  verifyTrustEpochMigrationAuthorization,
} from "./trust-epoch-migration-lib.mjs";

const sourceManifestFile = "hub-source-manifest.json";
const authorizationFile = "trust-epoch-migration-authorization.json";
const authorizationSignatureFile =
  "trust-epoch-migration-authorization.json.sig";
const digestPattern = /^[0-9a-f]{64}$/;
const sha256DigestPattern = /^sha256:[0-9a-f]{64}$/;
const manifestMediaTypes = new Set([
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
]);

export function resolveMigrationAuthorization({
  authorizationBytes,
  authorizationSignature,
  candidateVersion,
  githubRelease,
  hub,
  publishedAssets,
  trustedRootPublicKeyPem,
}) {
  const expectedLegacyRelease = {
    assets: (publishedAssets ?? []).map((asset) => ({
      name: asset.name,
      sha256:
        typeof asset.digest === "string" && asset.digest.startsWith("sha256:")
          ? asset.digest.slice("sha256:".length)
          : "",
      size: asset.size,
    })),
    githubRelease,
    hub,
    legacySigningKeySha256: readLegacySigningKeyFingerprint(authorizationBytes),
  };
  const authorization = verifyTrustEpochMigrationAuthorization({
    bytes: authorizationBytes,
    expectedCandidateVersion: candidateVersion,
    expectedDistribution: "enoki",
    expectedLegacyRelease,
    rootPublicKeyPem: trustedRootPublicKeyPem,
    signature: authorizationSignature,
  });
  return { authorization, expectedLegacyRelease };
}

export async function validateMigrationBaselineContents({
  bundleDir,
  candidateVersion,
  descriptor,
  trustedRootPublicKeyPem,
}) {
  const authorizationBytes = await readFile(
    path.join(bundleDir, authorizationFile),
  );
  const authorizationSignature = await readFile(
    path.join(bundleDir, authorizationSignatureFile),
  );
  assertExactKeys(descriptor.authorization, [
    "file",
    "legacyReleaseSha256",
    "sha256",
    "signatureFile",
    "signatureSha256",
  ]);
  if (
    descriptor.authorization.file !== authorizationFile ||
    descriptor.authorization.signatureFile !== authorizationSignatureFile ||
    descriptor.authorization.sha256 !== sha256(authorizationBytes) ||
    descriptor.authorization.signatureSha256 !== sha256(authorizationSignature)
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline authorization does not match",
    );
  }

  const assets = descriptor.legacyProbeAssets;
  assertExactKeys(assets, ["directory", "files"]);
  if (assets.directory !== "probe-assets" || !Array.isArray(assets.files)) {
    throw new Error(
      "Trust Epoch Migration Release Baseline assets do not match",
    );
  }
  const expectedLegacyRelease = {
    assets: assets.files,
    githubRelease: descriptor.githubRelease,
    hub: { digest: descriptor.hub?.digest, image: descriptor.hub?.image },
    legacySigningKeySha256: readLegacySigningKeyFingerprint(authorizationBytes),
  };
  const authorization = verifyTrustEpochMigrationAuthorization({
    bytes: authorizationBytes,
    expectedCandidateVersion: candidateVersion,
    expectedDistribution: "enoki",
    expectedLegacyRelease,
    rootPublicKeyPem: trustedRootPublicKeyPem,
    signature: authorizationSignature,
  });
  if (
    descriptor.authorization.legacyReleaseSha256 !==
    trustEpochLegacyReleaseSha256(authorization.legacyRelease)
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline authorization does not match",
    );
  }

  assertSameFileNames(
    await readdir(path.join(bundleDir, "probe-assets")),
    assets.files.map(({ name }) => name),
    "Trust Epoch Migration Release Baseline Probe assets",
  );
  for (const asset of assets.files) {
    const bytes = await readFile(
      path.join(bundleDir, "probe-assets", asset.name),
    );
    if (bytes.byteLength !== asset.size || sha256(bytes) !== asset.sha256) {
      throw new Error(
        `Trust Epoch Migration Release Baseline asset ${asset.name} does not match`,
      );
    }
  }
  await verifyLegacyProbeAssetSet(
    path.join(bundleDir, "probe-assets"),
    authorization.legacyRelease.legacySigningKeySha256,
  );
  await validateMigrationHubBundle(bundleDir, descriptor);
  return descriptor;
}

export function assertMigrationCandidateJoin({
  identity,
  releaseBaseline,
  releaseTransition,
}) {
  if (releaseBaseline.kind !== "enoki-trust-epoch-migration-baseline") {
    if (releaseTransition !== null) {
      throw new Error("Ordinary Release Candidate transition does not match");
    }
    return;
  }
  const source = releaseTransition?.source;
  const legacyRelease = source && {
    assets: source.assets,
    githubRelease: {
      id: source.releaseId,
      peeledCommitSha: source.commit,
      repository: source.repository,
      tag: source.tag,
      tagRefSha: source.tagRefSha,
      targetCommitish: source.targetCommitish,
    },
    hub: { digest: source.hubDigest, image: source.hubImage },
    legacySigningKeySha256: source.legacySigningKeySha256,
  };
  if (
    releaseTransition === null ||
    releaseTransition.transition !== "replacement-required" ||
    releaseTransition.candidateCommit !== identity.commit ||
    source.tag !== releaseBaseline.tag ||
    source.commit !== releaseBaseline.githubRelease?.peeledCommitSha ||
    releaseTransition.migrationAuthorizationSha256 !==
      releaseBaseline.authorization?.sha256 ||
    trustEpochLegacyReleaseSha256(legacyRelease) !==
      releaseBaseline.authorization?.legacyReleaseSha256 ||
    `v${releaseTransition.target.version}` !== identity.version
  ) {
    throw new Error("Trust Epoch Migration candidate does not match");
  }
}

export async function verifyLegacyProbeAssetSet(assetDir, expectedFingerprint) {
  const signingKey = await readFile(path.join(assetDir, "signing-key.pem"));
  if (sha256(signingKey) !== expectedFingerprint) {
    throw new Error(
      "Trust Epoch Migration Authorization legacy signing key does not match",
    );
  }
  const [manifest, signature] = await Promise.all([
    readFile(path.join(assetDir, "manifest.json")),
    readFile(path.join(assetDir, "manifest.json.sig")),
  ]);
  let valid = false;
  try {
    valid = verify(
      "RSA-SHA256",
      manifest,
      createPublicKey(signingKey),
      signature,
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new Error("legacy Probe Asset Set manifest signature does not match");
  }
}

async function validateMigrationHubBundle(bundleDir, descriptor) {
  const hub = descriptor.hub;
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
  if (
    hub.archive !== `hub/enoki-hub-${descriptor.tag}.oci.tar` ||
    hub.sourceManifest !== sourceManifestFile ||
    !sha256DigestPattern.test(hub.digest ?? "") ||
    !sha256DigestPattern.test(hub.imageDigest ?? "") ||
    !manifestMediaTypes.has(hub.mediaType) ||
    !digestPattern.test(hub.archiveSha256 ?? "") ||
    !digestPattern.test(hub.sourceManifestSha256 ?? "") ||
    !Number.isSafeInteger(hub.size) ||
    hub.size < 1 ||
    !Number.isSafeInteger(hub.sourceManifestSize) ||
    hub.sourceManifestSize < 1 ||
    JSON.stringify(hub.platform) !==
      JSON.stringify({ architecture: "amd64", os: "linux" })
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub descriptor does not match",
    );
  }
  assertSameFileNames(
    await readdir(path.join(bundleDir, "hub")),
    [path.basename(hub.archive)],
    "Trust Epoch Migration Release Baseline Hub directory",
  );
  const sourceBytes = await readFile(path.join(bundleDir, sourceManifestFile));
  if (
    sourceBytes.byteLength !== hub.sourceManifestSize ||
    sha256(sourceBytes) !== hub.sourceManifestSha256 ||
    hub.digest !== `sha256:${hub.sourceManifestSha256}`
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub source manifest does not match",
    );
  }
  const source = parseJson(sourceBytes);
  const selectedDigest = Array.isArray(source.manifests)
    ? source.manifests.find(
        ({ mediaType, platform }) =>
          /(?:image[.]manifest|distribution[.]manifest)[.]v[12][+]json$/.test(
            mediaType ?? "",
          ) &&
          platform?.os === "linux" &&
          platform?.architecture === "amd64",
      )?.digest
    : hub.digest;
  if (selectedDigest !== hub.imageDigest) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub image does not match",
    );
  }
  const archivePath = path.join(bundleDir, hub.archive);
  if (
    (await stat(archivePath)).size !== hub.size ||
    sha256(await readFile(archivePath)) !== hub.archiveSha256
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub OCI archive does not match",
    );
  }
  const probeFiles = descriptor.legacyProbeAssets.files.map((asset) => ({
    file: asset.name,
    sha256: asset.sha256,
    size: asset.size,
  }));
  const offlineHub = await inspectHubOciArchive({ archivePath, probeFiles });
  if (offlineHub.digest !== hub.imageDigest) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub OCI image does not match",
    );
  }
}

function readLegacySigningKeyFingerprint(bytes) {
  if (bytes.byteLength > 64 * 1024) return "";
  try {
    return JSON.parse(bytes.toString("utf8"))?.legacyRelease
      ?.legacySigningKeySha256;
  } catch {
    return "";
  }
}

function parseJson(bytes) {
  try {
    const value = JSON.parse(bytes.toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw 0;
    return value;
  } catch {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub source manifest is malformed",
    );
  }
}

function assertExactKeys(value, expected) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    JSON.stringify(Object.keys(value).sort()) !==
      JSON.stringify([...expected].sort())
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline fields are invalid",
    );
  }
}

function assertSameFileNames(actual, expected, description) {
  if (
    JSON.stringify([...actual].sort()) !== JSON.stringify([...expected].sort())
  ) {
    throw new Error(
      `${description} must contain exactly: ${expected.join(", ")}`,
    );
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
