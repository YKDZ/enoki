// Trust Epoch Migration Release Baseline 的离线内容校验与候选衔接判定。
// 这些函数只读取本地 Bundle 与已签名 Authorization 字节，不做远端下载或选择。

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

import {
  trustEpochLegacyReleaseSha256,
  verifyTrustEpochMigrationAuthorization,
} from "@enoki/probe-release";

import {
  inspectHubOciArchive,
  type ProbeAssetFileIdentity,
} from "./release-candidate-oci.ts";
import {
  isUnknownArray,
  isPositiveSafeInteger,
  objectView,
  stringValue,
  type UnknownRecord,
} from "./release-json-guards.ts";

const sourceManifestFile = "hub-source-manifest.json";
const authorizationFile = "trust-epoch-migration-authorization.json";
const authorizationSignatureFile =
  "trust-epoch-migration-authorization.json.sig";
const digestPattern = /^[0-9a-f]{64}$/;
const sha256DigestPattern = /^sha256:[0-9a-f]{64}$/;
const manifestMediaTypes = new Set<unknown>([
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
}: {
  authorizationBytes: Buffer;
  authorizationSignature: Buffer;
  candidateVersion: unknown;
  githubRelease: unknown;
  hub: unknown;
  publishedAssets: readonly unknown[];
  trustedRootPublicKeyPem: unknown;
}): {
  authorization: UnknownRecord;
  expectedLegacyRelease: UnknownRecord;
} {
  const expectedLegacyRelease = {
    assets: publishedAssets.map((asset) => {
      const view = objectView(asset);
      const digest = view.digest;
      return {
        name: view.name,
        sha256:
          typeof digest === "string" && digest.startsWith("sha256:")
            ? digest.slice("sha256:".length)
            : "",
        size: view.size,
      };
    }),
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
}: {
  bundleDir: string;
  candidateVersion: unknown;
  descriptor: unknown;
  trustedRootPublicKeyPem: unknown;
}): Promise<unknown> {
  const authorizationBytes = await readFile(
    path.join(bundleDir, authorizationFile),
  );
  const authorizationSignature = await readFile(
    path.join(bundleDir, authorizationSignatureFile),
  );
  const descriptorView = objectView(descriptor);
  const authorizationDescriptor = descriptorView.authorization;
  assertExactKeys(authorizationDescriptor, [
    "file",
    "legacyReleaseSha256",
    "sha256",
    "signatureFile",
    "signatureSha256",
  ]);
  if (
    authorizationDescriptor.file !== authorizationFile ||
    authorizationDescriptor.signatureFile !== authorizationSignatureFile ||
    authorizationDescriptor.sha256 !== sha256(authorizationBytes) ||
    authorizationDescriptor.signatureSha256 !== sha256(authorizationSignature)
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline authorization does not match",
    );
  }

  const assets = descriptorView.legacyProbeAssets;
  assertExactKeys(assets, ["directory", "files"]);
  const files = assets.files;
  if (assets.directory !== "probe-assets" || !isUnknownArray(files)) {
    throw new Error(
      "Trust Epoch Migration Release Baseline assets do not match",
    );
  }
  const hub = objectView(descriptorView.hub);
  const expectedLegacyRelease = {
    assets: files,
    githubRelease: descriptorView.githubRelease,
    hub: { digest: hub.digest, image: hub.image },
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
    authorizationDescriptor.legacyReleaseSha256 !==
    trustEpochLegacyReleaseSha256(objectView(authorization.legacyRelease))
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline authorization does not match",
    );
  }

  assertSameFileNames(
    await readdir(path.join(bundleDir, "probe-assets")),
    files.map((asset) => objectView(asset).name),
    "Trust Epoch Migration Release Baseline Probe assets",
  );
  for (const asset of files) {
    const view = objectView(asset);
    const bytes = await readFile(
      path.join(bundleDir, "probe-assets", stringValue(view.name)),
    );
    if (bytes.byteLength !== view.size || sha256(bytes) !== view.sha256) {
      throw new Error(
        `Trust Epoch Migration Release Baseline asset ${String(view.name)} does not match`,
      );
    }
  }
  await verifyLegacyProbeAssetSet(
    path.join(bundleDir, "probe-assets"),
    objectView(authorization.legacyRelease).legacySigningKeySha256,
  );
  await validateMigrationHubBundle(bundleDir, descriptorView);
  return descriptor;
}

export function assertMigrationCandidateJoin({
  identity,
  releaseBaseline,
  releaseTransition,
}: {
  identity: unknown;
  releaseBaseline: unknown;
  releaseTransition: UnknownRecord | null;
}): void {
  const identityView = objectView(identity);
  const baseline = objectView(releaseBaseline);
  if (
    releaseTransition !== null &&
    releaseTransition.candidateCommit !== identityView.commit
  ) {
    throw new Error("Release Transition Contract candidate does not match");
  }
  if (baseline.kind !== "enoki-trust-epoch-migration-baseline") {
    if (
      releaseTransition !== null &&
      (!new Set(["compatible", "replacement-required"]).has(
        stringValue(releaseTransition.transition),
      ) ||
        objectView(releaseTransition.source).version !==
          objectView(baseline.probeAssetSet).version ||
        `v${String(objectView(releaseTransition.target).version)}` !==
          identityView.version)
    ) {
      throw new Error("Ordinary Release Candidate transition does not match");
    }
    return;
  }
  const sourceView = objectView(releaseTransition?.source);
  const legacyRelease = {
    assets: sourceView.assets,
    githubRelease: {
      id: sourceView.releaseId,
      peeledCommitSha: sourceView.commit,
      repository: sourceView.repository,
      tag: sourceView.tag,
      tagRefSha: sourceView.tagRefSha,
      targetCommitish: sourceView.targetCommitish,
    },
    hub: { digest: sourceView.hubDigest, image: sourceView.hubImage },
    legacySigningKeySha256: sourceView.legacySigningKeySha256,
  };
  if (
    releaseTransition === null ||
    releaseTransition.transition !== "replacement-required" ||
    sourceView.tag !== baseline.tag ||
    sourceView.commit !== objectView(baseline.githubRelease).peeledCommitSha ||
    releaseTransition.migrationAuthorizationSha256 !==
      objectView(baseline.authorization).sha256 ||
    trustEpochLegacyReleaseSha256(objectView(legacyRelease)) !==
      objectView(baseline.authorization).legacyReleaseSha256 ||
    `v${String(objectView(releaseTransition.target).version)}` !==
      identityView.version
  ) {
    throw new Error("Trust Epoch Migration candidate does not match");
  }
}

export async function verifyLegacyProbeAssetSet(
  assetDir: string,
  expectedFingerprint: unknown,
): Promise<void> {
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

async function validateMigrationHubBundle(
  bundleDir: string,
  descriptor: UnknownRecord,
): Promise<void> {
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
    hub.archive !== `hub/enoki-hub-${String(descriptor.tag)}.oci.tar` ||
    hub.sourceManifest !== sourceManifestFile ||
    !sha256DigestPattern.test(stringValue(hub.digest)) ||
    !sha256DigestPattern.test(stringValue(hub.imageDigest)) ||
    !manifestMediaTypes.has(hub.mediaType) ||
    !digestPattern.test(stringValue(hub.archiveSha256)) ||
    !digestPattern.test(stringValue(hub.sourceManifestSha256)) ||
    !isPositiveSafeInteger(hub.size) ||
    !isPositiveSafeInteger(hub.sourceManifestSize) ||
    JSON.stringify(hub.platform) !==
      JSON.stringify({ architecture: "amd64", os: "linux" })
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub descriptor does not match",
    );
  }
  assertSameFileNames(
    await readdir(path.join(bundleDir, "hub")),
    [path.basename(stringValue(hub.archive))],
    "Trust Epoch Migration Release Baseline Hub directory",
  );
  const sourceBytes = await readFile(path.join(bundleDir, sourceManifestFile));
  if (
    sourceBytes.byteLength !== hub.sourceManifestSize ||
    sha256(sourceBytes) !== hub.sourceManifestSha256 ||
    hub.digest !== `sha256:${String(hub.sourceManifestSha256)}`
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub source manifest does not match",
    );
  }
  const source = parseJson(sourceBytes);
  const manifests = source.manifests;
  const selectedDigest = isUnknownArray(manifests)
    ? manifests
        .map(objectView)
        .find(
          (entry) =>
            /(?:image[.]manifest|distribution[.]manifest)[.]v[12][+]json$/.test(
              stringValue(entry.mediaType),
            ) &&
            objectView(entry.platform).os === "linux" &&
            objectView(entry.platform).architecture === "amd64",
        )?.digest
    : hub.digest;
  if (selectedDigest !== hub.imageDigest) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub image does not match",
    );
  }
  const archivePath = path.join(bundleDir, stringValue(hub.archive));
  if (
    (await stat(archivePath)).size !== hub.size ||
    sha256(await readFile(archivePath)) !== hub.archiveSha256
  ) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub OCI archive does not match",
    );
  }
  const legacyAssets = objectView(descriptor.legacyProbeAssets).files;
  const probeFiles: readonly ProbeAssetFileIdentity[] = isUnknownArray(
    legacyAssets,
  )
    ? legacyAssets.map((asset) => {
        const view = objectView(asset);
        return {
          file: stringValue(view.name),
          sha256: stringValue(view.sha256),
          size: typeof view.size === "number" ? view.size : Number.NaN,
        };
      })
    : [];
  const offlineHub = await inspectHubOciArchive({ archivePath, probeFiles });
  if (offlineHub.digest !== hub.imageDigest) {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub OCI image does not match",
    );
  }
}

function readLegacySigningKeyFingerprint(bytes: Buffer): unknown {
  if (bytes.byteLength > 64 * 1024) return "";
  try {
    const parsed: unknown = JSON.parse(bytes.toString("utf8"));
    return objectView(objectView(parsed).legacyRelease).legacySigningKeySha256;
  } catch {
    return "";
  }
}

function parseJson(bytes: Buffer): UnknownRecord {
  try {
    const value: unknown = JSON.parse(bytes.toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw 0;
    return objectView(value);
  } catch {
    throw new Error(
      "Trust Epoch Migration Release Baseline Hub source manifest is malformed",
    );
  }
}

function assertExactKeys(
  value: unknown,
  expected: readonly string[],
): asserts value is UnknownRecord {
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

function assertSameFileNames(
  actual: readonly string[],
  expected: readonly unknown[],
  description: string,
): void {
  if (
    JSON.stringify([...actual].sort()) !== JSON.stringify([...expected].sort())
  ) {
    throw new Error(
      `${description} must contain exactly: ${expected.join(", ")}`,
    );
  }
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
