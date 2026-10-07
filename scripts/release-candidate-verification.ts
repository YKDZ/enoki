// 候选验收与离线制品检验的唯一实现：只读校验已发布的 Probe 资产、压缩包与
// candidate manifest，不做构建、签名、打包或发布；WeakMap 身份由此模块独占。
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import {
  canonicalPublicKeyPem,
  inspectProbeElf,
  probeBundleComponentProfiles,
  probeBundledBootstrapAssets,
  probeTargets,
  verifyReleaseTransitionContract,
  verifyProbeTrustDelegation,
} from "@enoki/probe-release";

import { inspectProbeBootstrapBinary } from "./probe-bootstrap-inspection.ts";
import { assertMigrationCandidateJoin } from "./release-baseline-migration-lib.ts";
import { inspectHubOciArchive } from "./release-candidate-oci.ts";
import type { ProbeAssetFileIdentity } from "./release-candidate-oci.ts";
import {
  assertPlainObject,
  isNonEmptyString,
  isSafeInteger,
  isUnknownArray,
  objectView,
  stringValue,
  type UnknownRecord,
} from "./release-json-guards.ts";

const execFileAsync = promisify(execFile);
const commitPattern = /^[0-9a-f]{40}$/;
const stableSemVerTagPattern = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
export const bootstrapRecipeFile = "enoki-probe-bootstrap.py";
export const bootstrapRecipeRecordFile = "enoki-probe-bootstrap-recipe.json";
const verifiedCandidateReleaseTransitions = new WeakMap<object, unknown>();

export type ReleaseCandidateManifest = {
  bootstrapRecipe: unknown;
  candidate: UnknownRecord;
  hub: UnknownRecord;
  kind: string;
  probeAssetSet: UnknownRecord;
  releaseBaseline: unknown;
  schemaVersion: number;
};

type ProbeAssetSetInspectionOptions = {
  expectedDelegationBytes?: Buffer;
  expectedDelegationSignature?: Buffer;
  expectedVersion?: string;
  highestAcceptedDelegationGeneration?: number;
  requireEmbeddedProbeIdentity?: boolean;
  trustedRootPublicKeyPem?: Buffer | string;
  trustedRootPublicKeySha256?: string;
  unsigned?: boolean;
};

export function releaseTransitionForValidatedCandidate(
  manifest: object,
): unknown {
  const transition = verifiedCandidateReleaseTransitions.get(manifest);
  if (transition === undefined) {
    throw new Error("Candidate Manifest has not passed release verification");
  }
  return transition;
}

export function validateCandidateIdentity(identity: unknown): {
  commit: string;
  version: string;
} {
  const view = objectView(identity);
  const commit = view.commit;
  const version = view.version;
  if (!isNonEmptyString(commit) || !commitPattern.test(commit)) {
    throw new Error("commit must be a full lowercase 40-character object ID");
  }

  if (!isNonEmptyString(version) || !stableSemVerTagPattern.test(version)) {
    throw new Error("version must be a stable SemVer tag like v1.2.3");
  }

  return { commit, version };
}

export async function validateReleaseCandidate(
  candidateDir: string,
  { trustedRootPublicKeyPem }: { trustedRootPublicKeyPem: Buffer | string },
) {
  const manifest = await readCandidateManifest(
    path.join(candidateDir, "candidate-manifest.json"),
  );
  const identity = validateCandidateIdentity(manifest.candidate);
  assertExactKeys(manifest, [
    "bootstrapRecipe",
    "candidate",
    "hub",
    "kind",
    "probeAssetSet",
    "releaseBaseline",
    "schemaVersion",
  ]);
  assertExactKeys(manifest.candidate, ["commit", "version"]);
  if (
    manifest.schemaVersion !== 4 ||
    manifest.kind !== "enoki-release-candidate"
  ) {
    throw new Error("Candidate Manifest schema or kind is unsupported");
  }
  const releaseBaseline = manifest.releaseBaseline;
  assertPlainObject(releaseBaseline, "Candidate Manifest Release Baseline");
  const expectedCandidateFiles = [
    "candidate-manifest.json",
    "hub",
    "probe-assets",
    "recipe",
    "release-baseline",
  ];
  if (
    releaseBaseline.kind === "enoki-release-baseline" ||
    releaseBaseline.kind === "enoki-trust-epoch-migration-baseline"
  ) {
    const {
      assertReleaseBaselinePrecedesCandidate,
      validateResolvedReleaseBaseline,
    } = await import("./release-baseline-verification.ts");
    assertReleaseBaselinePrecedesCandidate({
      baselineTag: releaseBaseline.tag,
      candidateVersion: identity.version,
    });
    const inspectedBaseline = await validateResolvedReleaseBaseline(
      path.join(candidateDir, "release-baseline"),
      { candidateVersion: identity.version, trustedRootPublicKeyPem },
    );
    if (JSON.stringify(inspectedBaseline) !== JSON.stringify(releaseBaseline)) {
      throw new Error(
        "Candidate Manifest Release Baseline descriptor does not match content",
      );
    }
  } else {
    throw new Error(
      "Candidate Manifest requires one Release Baseline descriptor",
    );
  }
  assertSameFileNames(
    (await readdir(candidateDir)).sort(),
    expectedCandidateFiles.sort(),
    "Enoki Release Candidate directory",
  );

  const bootstrapRecipe = manifest.bootstrapRecipe;
  assertPlainObject(
    bootstrapRecipe,
    "Candidate Manifest Probe Bootstrap recipe",
  );
  assertExactKeys(bootstrapRecipe, [
    "bundleVersion",
    "distribution",
    "file",
    "kind",
    "recordFile",
    "recordSha256",
    "recordSize",
    "rootFingerprint",
    "schemaVersion",
    "sha256",
    "size",
    "targets",
    "version",
  ]);
  if (
    bootstrapRecipe.bundleVersion !== identity.version.slice(1) ||
    bootstrapRecipe.distribution !== "enoki" ||
    bootstrapRecipe.file !== bootstrapRecipeFile ||
    bootstrapRecipe.kind !== "enoki-probe-bootstrap-recipe-record" ||
    bootstrapRecipe.recordFile !== bootstrapRecipeRecordFile ||
    !/^[0-9a-f]{64}$/.test(stringValue(bootstrapRecipe.recordSha256)) ||
    !isSafeInteger(bootstrapRecipe.recordSize) ||
    bootstrapRecipe.recordSize < 1 ||
    bootstrapRecipe.schemaVersion !== 1 ||
    JSON.stringify(bootstrapRecipe.targets) !== JSON.stringify(probeTargets) ||
    bootstrapRecipe.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(stringValue(bootstrapRecipe.rootFingerprint)) ||
    !/^[0-9a-f]{64}$/.test(stringValue(bootstrapRecipe.sha256)) ||
    !isSafeInteger(bootstrapRecipe.size) ||
    bootstrapRecipe.size < 1
  ) {
    throw new Error("Candidate Manifest Probe Bootstrap recipe is invalid");
  }
  const expectedRootFingerprint = sha256(
    canonicalPublicKeyPem(trustedRootPublicKeyPem),
  );
  if (bootstrapRecipe.rootFingerprint !== expectedRootFingerprint) {
    throw new Error("Probe Bootstrap recipe root does not match trusted root");
  }
  assertSameFileNames(
    (await readdir(path.join(candidateDir, "recipe"))).sort(),
    [bootstrapRecipeRecordFile, bootstrapRecipeFile].sort(),
    "Candidate Probe Bootstrap recipe directory",
  );
  const recipePath = path.join(candidateDir, "recipe", bootstrapRecipe.file);
  const recipeDetails = await stat(recipePath);
  const recipeBytes = await readFile(recipePath);
  const recordPath = path.join(
    candidateDir,
    "recipe",
    bootstrapRecipe.recordFile,
  );
  const recordDetails = await stat(recordPath);
  const recordBytes = await readFile(recordPath);
  const expectedRecord = {
    bundleVersion: bootstrapRecipe.bundleVersion,
    distribution: bootstrapRecipe.distribution,
    kind: bootstrapRecipe.kind,
    recipe: {
      file: bootstrapRecipe.file,
      sha256: bootstrapRecipe.sha256,
      size: bootstrapRecipe.size,
      version: bootstrapRecipe.version,
    },
    rootFingerprint: bootstrapRecipe.rootFingerprint,
    schemaVersion: bootstrapRecipe.schemaVersion,
    targets: bootstrapRecipe.targets,
  };
  if (
    !recipeDetails.isFile() ||
    recipeDetails.size !== bootstrapRecipe.size ||
    sha256(recipeBytes) !== bootstrapRecipe.sha256 ||
    !recipeBytes.includes(
      `ROOT_FINGERPRINT = "${bootstrapRecipe.rootFingerprint}"`,
    ) ||
    !recipeBytes.includes(
      `BUNDLE_VERSION = "${bootstrapRecipe.bundleVersion}"`,
    ) ||
    !recipeBytes.includes(`DISTRIBUTION = "${bootstrapRecipe.distribution}"`) ||
    !recipeBytes.includes(`RECIPE_VERSION = "${bootstrapRecipe.version}"`) ||
    !recordDetails.isFile() ||
    recordDetails.size !== bootstrapRecipe.recordSize ||
    sha256(recordBytes) !== bootstrapRecipe.recordSha256 ||
    !recordBytes.equals(
      Buffer.from(`${JSON.stringify(expectedRecord, null, 2)}\n`),
    )
  ) {
    throw new Error(
      "Candidate Probe Bootstrap recipe does not match its record",
    );
  }

  const probe = manifest.probeAssetSet;
  assertPlainObject(probe, "Candidate Manifest Probe Asset Set");
  assertExactKeys(probe, ["directory", "files", "signingIdentity", "version"]);
  if (
    probe.directory !== "probe-assets" ||
    probe.version !== identity.version.slice(1)
  ) {
    throw new Error(
      "Candidate Manifest Probe version disagrees with candidate version",
    );
  }
  const inspectedProbe = await inspectProbeAssetSet(
    path.join(candidateDir, "probe-assets"),
    {
      expectedVersion: stringValue(probe.version),
      trustedRootPublicKeyPem,
    },
  );
  assertMigrationCandidateJoin({
    identity,
    releaseBaseline,
    releaseTransition: inspectedProbe.releaseTransition ?? null,
  });
  if (JSON.stringify(inspectedProbe.files) !== JSON.stringify(probe.files)) {
    throw new Error(
      "Candidate Manifest Probe file identities do not match content",
    );
  }
  if (
    JSON.stringify(inspectedProbe.signingIdentity) !==
    JSON.stringify(probe.signingIdentity)
  ) {
    throw new Error(
      "Candidate Manifest signing identity does not match content",
    );
  }

  const hub = manifest.hub;
  assertPlainObject(hub, "Candidate Manifest Hub");
  assertExactKeys(hub, [
    "archive",
    "archiveSha256",
    "digest",
    "embeddedProbeVersion",
    "size",
  ]);
  const expectedArchive = `hub/enoki-hub-${identity.version}.oci.tar`;
  if (hub.archive !== expectedArchive) {
    throw new Error(
      `Candidate Manifest Hub archive must be ${expectedArchive}`,
    );
  }
  if (hub.embeddedProbeVersion !== probe.version) {
    throw new Error("Candidate Manifest Hub and Probe versions disagree");
  }
  const hubDir = path.join(candidateDir, "hub");
  assertSameFileNames(
    await readdir(hubDir),
    [path.basename(expectedArchive)],
    "Candidate Hub directory",
  );
  const hubPath = path.join(candidateDir, expectedArchive);
  const hubDetails = await stat(hubPath);
  if (
    hubDetails.size !== hub.size ||
    (await fileSha256(hubPath)) !== hub.archiveSha256
  ) {
    throw new Error(
      "Candidate Hub OCI archive checksum or size does not match",
    );
  }
  const inspectedHub = await inspectHubOciArchive({
    archivePath: hubPath,
    probeFiles: inspectedProbe.files,
  });
  if (inspectedHub.digest !== hub.digest) {
    throw new Error("Candidate Hub OCI digest does not match");
  }

  verifiedCandidateReleaseTransitions.set(
    manifest,
    inspectedProbe.releaseTransition ?? null,
  );
  return manifest;
}

export async function inspectProbeAssetSet(
  assetDir: string,
  {
    expectedDelegationBytes,
    expectedDelegationSignature,
    expectedVersion,
    highestAcceptedDelegationGeneration = 0,
    requireEmbeddedProbeIdentity = true,
    trustedRootPublicKeyPem,
    trustedRootPublicKeySha256,
    unsigned = false,
  }: ProbeAssetSetInspectionOptions = {},
) {
  const transitionFileNames = [
    "release-transition-contract.json",
    "release-transition-contract.json.sig",
  ];
  const migrationAuthorizationFileNames = [
    "trust-epoch-migration-authorization.json",
    "trust-epoch-migration-authorization.json.sig",
  ];
  const actualFiles = (await readdir(assetDir)).sort();
  const transitionFileCount = transitionFileNames.filter((file) =>
    actualFiles.includes(file),
  ).length;
  const migrationAuthorizationFileCount =
    migrationAuthorizationFileNames.filter((file) =>
      actualFiles.includes(file),
    ).length;
  if (
    (transitionFileCount !== 0 && transitionFileCount !== 2) ||
    (migrationAuthorizationFileCount !== 0 &&
      migrationAuthorizationFileCount !== 2) ||
    (migrationAuthorizationFileCount === 2 && transitionFileCount !== 2)
  ) {
    throw new Error("Probe Asset Set transition closure is incomplete");
  }
  if (
    unsigned &&
    (transitionFileCount !== 0 || migrationAuthorizationFileCount !== 0)
  ) {
    throw new Error("Unsigned Probe Asset Set cannot declare a transition");
  }
  const expectedFiles = [
    ...probeTargets.flatMap((target) => {
      const archive = `enoki-probe-${target}.tar.gz`;
      return [archive, `${archive}.sha256`];
    }),
    "manifest.json",
    ...(unsigned ? [] : ["manifest.json.sig"]),
    "root-key.pem",
    "signing-key.pem",
    "trust-delegation.json",
    "trust-delegation.json.sig",
    ...(transitionFileCount === 2 ? transitionFileNames : []),
    ...(migrationAuthorizationFileCount === 2
      ? migrationAuthorizationFileNames
      : []),
  ].sort();
  assertSameFileNames(actualFiles, expectedFiles, "Probe Asset Set");

  const manifestBytes = await readFile(path.join(assetDir, "manifest.json"));
  let manifest: unknown;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error("Probe Asset Set manifest is malformed");
  }
  assertPlainObject(manifest, "Probe Asset Set manifest");
  assertExactKeys(manifest, ["assets", "kind", "signature", "version"]);
  if (
    manifest.kind !== "enoki-probe-assets" ||
    !stableSemVerTagPattern.test(`v${manifest.version}`) ||
    (expectedVersion && manifest.version !== expectedVersion)
  ) {
    throw new Error("Probe Asset Set version or kind is invalid");
  }
  assertPlainObject(manifest.signature, "Probe Asset Set signature descriptor");
  assertExactKeys(manifest.signature, [
    "algorithm",
    "delegationGeneration",
    "delegationKeyId",
    "file",
    "publicKey",
  ]);
  if (
    manifest.signature.algorithm !== "rsa-sha256" ||
    !isSafeInteger(manifest.signature.delegationGeneration) ||
    manifest.signature.delegationGeneration < 1 ||
    !/^[0-9a-f]{64}$/.test(stringValue(manifest.signature.delegationKeyId)) ||
    manifest.signature.file !== "manifest.json.sig" ||
    manifest.signature.publicKey !== "signing-key.pem"
  ) {
    throw new Error("Probe Asset Set signature descriptor is unsupported");
  }
  if (
    !isUnknownArray(manifest.assets) ||
    manifest.assets.length !== probeTargets.length
  ) {
    throw new Error("Probe Asset Set does not contain every supported target");
  }

  const packagedRootPublicKey = canonicalPublicKeyPem(
    await readFile(path.join(assetDir, "root-key.pem")),
  );
  if (
    trustedRootPublicKeyPem !== undefined &&
    !packagedRootPublicKey.equals(
      canonicalPublicKeyPem(trustedRootPublicKeyPem),
    )
  ) {
    throw new Error(
      "Probe Asset Set root key does not match the trusted Probe Distribution Trust Root",
    );
  }
  if (
    trustedRootPublicKeySha256 !== undefined &&
    sha256(packagedRootPublicKey) !== trustedRootPublicKeySha256
  ) {
    throw new Error(
      "Probe Asset Set root key does not match the trusted Probe Distribution Trust Root",
    );
  }
  const bundledBootstrap = {
    distribution: "enoki",
    rootKeyId: sha256(packagedRootPublicKey),
  };

  for (const [index, target] of probeTargets.entries()) {
    const asset = manifest.assets[index];
    assertPlainObject(asset, `Probe Asset Set target ${target}`);
    assertExactKeys(asset, [
      "bundleManifestSha256",
      "file",
      "sha256",
      "size",
      "target",
    ]);
    const expectedFile = `enoki-probe-${target}.tar.gz`;
    if (
      asset.target !== target ||
      asset.file !== expectedFile ||
      !/^[0-9a-f]{64}$/.test(stringValue(asset.bundleManifestSha256)) ||
      !/^[0-9a-f]{64}$/.test(stringValue(asset.sha256)) ||
      !isSafeInteger(asset.size) ||
      asset.size < 0
    ) {
      throw new Error(`Probe Asset Set target ${target} is malformed`);
    }
    const archivePath = path.join(assetDir, asset.file);
    const archiveDetails = await stat(archivePath);
    if (
      archiveDetails.size !== asset.size ||
      (await fileSha256(archivePath)) !== asset.sha256
    ) {
      throw new Error(`Probe Asset Set checksum does not match ${asset.file}`);
    }
    const sidecar = await readFile(`${archivePath}.sha256`, "utf8");
    if (sidecar !== `${asset.sha256}  ${asset.file}\n`) {
      throw new Error(
        `Probe Asset Set checksum sidecar does not match ${asset.file}`,
      );
    }
    const inspectedArchive = await inspectProbeArchive(archivePath, {
      bundledBootstrap,
      requireEmbeddedProbeIdentity,
      target,
      version: `v${manifest.version}`,
    });
    if (inspectedArchive.bundleManifestSha256 !== asset.bundleManifestSha256) {
      throw new Error(
        `Probe Asset Set bundle manifest does not match ${asset.file}`,
      );
    }
  }

  const publicKey = await readFile(path.join(assetDir, "signing-key.pem"));
  const canonicalRootPublicKey = packagedRootPublicKey;
  if (
    trustedRootPublicKeyPem === undefined &&
    trustedRootPublicKeySha256 === undefined
  ) {
    throw new Error(
      "Probe Asset Set verification requires an external Probe Distribution Trust Root",
    );
  }
  const trustedRootPublicKey = trustedRootPublicKeyPem
    ? canonicalPublicKeyPem(trustedRootPublicKeyPem)
    : undefined;
  if (
    trustedRootPublicKey !== undefined &&
    !canonicalRootPublicKey.equals(trustedRootPublicKey)
  ) {
    throw new Error(
      "Probe Asset Set root key does not match the trusted Probe Distribution Trust Root",
    );
  }
  if (
    trustedRootPublicKeySha256 !== undefined &&
    sha256(canonicalRootPublicKey) !== trustedRootPublicKeySha256
  ) {
    throw new Error(
      "Probe Asset Set root key does not match the trusted Probe Distribution Trust Root",
    );
  }
  if (
    trustedRootPublicKey !== undefined &&
    trustedRootPublicKeySha256 !== undefined &&
    sha256(trustedRootPublicKey) !== trustedRootPublicKeySha256
  ) {
    throw new Error(
      "external Probe Distribution Trust Root PEM and fingerprint disagree",
    );
  }
  const delegationBytes = await readFile(
    path.join(assetDir, "trust-delegation.json"),
  );
  const delegationSignature = await readFile(
    path.join(assetDir, "trust-delegation.json.sig"),
  );
  if (
    expectedDelegationBytes !== undefined &&
    !Buffer.from(delegationBytes).equals(Buffer.from(expectedDelegationBytes))
  ) {
    throw new Error(
      "Probe Asset Set delegation does not match the trusted delegation",
    );
  }
  if (
    expectedDelegationSignature !== undefined &&
    !Buffer.from(delegationSignature).equals(
      Buffer.from(expectedDelegationSignature),
    )
  ) {
    throw new Error(
      "Probe Asset Set delegation signature does not match the trusted delegation",
    );
  }
  const delegation = verifyProbeTrustDelegation({
    bytes: delegationBytes,
    expectedDistribution: "enoki",
    highestAcceptedGeneration: highestAcceptedDelegationGeneration,
    rootPublicKeyPem: trustedRootPublicKey ?? canonicalRootPublicKey,
    signature: delegationSignature,
  });
  if (
    delegation.generation !== manifest.signature.delegationGeneration ||
    delegation.signingIdentity.keyId !== manifest.signature.delegationKeyId ||
    delegation.signingIdentity.keyId !== sha256(publicKey)
  ) {
    throw new Error(
      "Probe Asset Set delegation does not match manifest signing identity",
    );
  }
  if (!unsigned) {
    const signature = await readFile(path.join(assetDir, "manifest.json.sig"));
    let signatureValid = false;
    try {
      const crypto = await import("node:crypto");
      signatureValid = crypto.verify(
        "RSA-SHA256",
        manifestBytes,
        publicKey,
        signature,
      );
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) {
      throw new Error("Probe Asset Set manifest signature is invalid");
    }
  }
  let releaseTransition: Record<string, unknown> | null = null;
  if (transitionFileCount === 2) {
    const contractBytes = await readFile(
      path.join(assetDir, "release-transition-contract.json"),
    );
    let contract: unknown;
    try {
      contract = JSON.parse(contractBytes.toString("utf8"));
    } catch {
      throw new Error("Release Transition Contract is malformed");
    }
    const contractView = objectView(contract);
    const contractSource = objectView(contractView.source);
    releaseTransition = verifyReleaseTransitionContract({
      ...(migrationAuthorizationFileCount === 2
        ? {
            authorizationBytes: await readFile(
              path.join(assetDir, "trust-epoch-migration-authorization.json"),
            ),
            authorizationSignature: await readFile(
              path.join(
                assetDir,
                "trust-epoch-migration-authorization.json.sig",
              ),
            ),
          }
        : {}),
      contractBytes,
      contractSignature: await readFile(
        path.join(assetDir, "release-transition-contract.json.sig"),
      ),
      expected: {
        classification: contractView.transition,
        delegationGeneration: manifest.signature.delegationGeneration,
        sourceCommit: contractSource.commit,
        sourceTag: contractSource.tag,
        sourceVersion: contractSource.version,
        targetAssetClosure: manifest.assets,
        targetAssetSetManifestSha256: sha256(manifestBytes),
        targetVersion: manifest.version,
      },
      rootPublicKeyPem: trustedRootPublicKey ?? canonicalRootPublicKey,
    });
  }
  const publicKeySha256 = sha256(publicKey);
  const files: ProbeAssetFileIdentity[] = [];
  for (const file of expectedFiles) {
    const filePath = path.join(assetDir, file);
    const details = await stat(filePath);
    files.push({
      file,
      sha256: await fileSha256(filePath),
      size: details.size,
    });
  }
  return {
    files,
    ...(releaseTransition ? { releaseTransition } : {}),
    signingIdentity: {
      algorithm: "rsa-sha256",
      publicKeyFile: "signing-key.pem",
      publicKeySha256,
    },
    version: manifest.version,
  };
}

export async function inspectProbeArchive(
  archivePath: string,
  {
    bundledBootstrap,
    requireEmbeddedProbeIdentity = true,
    target,
    version,
  }: {
    bundledBootstrap?: { distribution: string; rootKeyId: string };
    requireEmbeddedProbeIdentity?: boolean;
    target: string;
    version: string;
  },
) {
  const extractionDir = await mkdtemp(
    path.join(tmpdir(), "enoki-probe-archive-"),
  );

  try {
    let listing;
    try {
      ({ stdout: listing } = await execFileAsync(
        "tar",
        ["--list", "--gzip", "--file", archivePath],
        { env: untrustedToolEnvironment(), maxBuffer: 1024 * 1024 },
      ));
    } catch {
      throw new Error(
        `Probe archive ${path.basename(archivePath)} is not a valid gzip/tar archive`,
      );
    }
    const expectedListing = [
      "bundle-manifest.json",
      ...Object.values(probeBundleComponentProfiles).map(
        ({ path: componentPath }) => componentPath,
      ),
      ...(bundledBootstrap
        ? probeBundledBootstrapAssets.map(({ archivePath }) => archivePath)
        : []),
    ].join("\n");
    if (listing !== `${expectedListing}\n`) {
      throw new Error(
        `Probe archive ${path.basename(archivePath)} must contain exactly its bundle manifest and enoki-probe payload`,
      );
    }

    try {
      await execFileAsync(
        "tar",
        [
          "--extract",
          "--gzip",
          "--file",
          archivePath,
          "--directory",
          extractionDir,
          "--no-same-owner",
        ],
        { env: untrustedToolEnvironment(), maxBuffer: 1024 * 1024 },
      );
    } catch {
      throw new Error(
        `Probe archive ${path.basename(archivePath)} is not a valid gzip/tar archive`,
      );
    }

    const binaryPath = path.join(extractionDir, "enoki-probe");
    const details = await lstat(binaryPath);
    if (!details.isFile()) {
      throw new Error(
        `Probe archive ${path.basename(archivePath)} payload must be a regular file`,
      );
    }
    if ((details.mode & 0o111) === 0) {
      throw new Error(
        `Probe archive ${path.basename(archivePath)} payload must be executable`,
      );
    }

    const manifestPath = path.join(extractionDir, "bundle-manifest.json");
    const manifestDetails = await lstat(manifestPath);
    if (!manifestDetails.isFile()) {
      throw new Error(
        `Probe archive ${path.basename(archivePath)} bundle manifest must be a regular file`,
      );
    }
    inspectProbeElf(await readFile(binaryPath), {
      requireEmbeddedProbeIdentity,
      target,
      version,
    });
    if (bundledBootstrap) {
      for (const asset of probeBundledBootstrapAssets) {
        const bootstrapPath = path.join(extractionDir, asset.archivePath);
        const bootstrapDetails = await lstat(bootstrapPath);
        if (
          !bootstrapDetails.isFile() ||
          (bootstrapDetails.mode & 0o111) === 0
        ) {
          throw new Error(
            `Probe archive ${path.basename(archivePath)} bundled Bootstrap asset must be a regular executable file`,
          );
        }
        await inspectProbeBootstrapBinary({
          binaryPath: bootstrapPath,
          distribution: bundledBootstrap.distribution,
          role: asset.bootstrapBuildRole,
          rootKeyId: bundledBootstrap.rootKeyId,
          target,
          version,
        });
      }
    }
    const componentDetails = await readProbeBundleComponentDetails(
      extractionDir,
      probeBundleComponentProfiles,
    );
    const bootstrapDetails = bundledBootstrap
      ? await readProbeBundleComponentDetails(
          extractionDir,
          Object.fromEntries(
            probeBundledBootstrapAssets.map((asset) => [
              asset.role,
              { path: asset.archivePath },
            ]),
          ),
        )
      : undefined;
    const bundleManifest = await readFile(manifestPath);
    validateProbeBundleManifest(bundleManifest, {
      bootstrapDetails,
      componentDetails,
      target,
      version: version.slice(1),
    });
    return { bundleManifestSha256: sha256(bundleManifest) };
  } finally {
    await rm(extractionDir, { force: true, recursive: true });
  }
}

type ProbeBundleComponentDetail = {
  sha256: string;
  size: number;
};

export async function readProbeBundleComponentDetails(
  extractionDir: string,
  profiles: Readonly<Record<string, { path: string }>>,
): Promise<Map<string, ProbeBundleComponentDetail>> {
  const detailsByPath = new Map<string, ProbeBundleComponentDetail>();
  for (const profile of Object.values(profiles)) {
    const componentPath = path.join(extractionDir, profile.path);
    const details = await lstat(componentPath);
    if (!details.isFile()) {
      throw new Error("Probe bundle component must be a regular file");
    }
    detailsByPath.set(profile.path, {
      sha256: await fileSha256(componentPath),
      size: details.size,
    });
  }
  return detailsByPath;
}

function validateProbeBundleManifest(
  bytes: Buffer,
  {
    bootstrapDetails,
    componentDetails,
    target,
    version,
  }: {
    bootstrapDetails?: Map<string, ProbeBundleComponentDetail>;
    componentDetails: Map<string, ProbeBundleComponentDetail>;
    target: string;
    version: string;
  },
): void {
  let manifest: unknown;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("Probe bundle manifest is malformed");
  }
  assertPlainObject(manifest, "Probe bundle manifest");
  assertExactKeys(
    manifest,
    bootstrapDetails
      ? ["bootstrapAssets", "components", "kind", "target", "version"]
      : ["components", "kind", "target", "version"],
  );
  if (
    manifest.kind !== "enoki-probe-bundle" ||
    manifest.target !== target ||
    manifest.version !== version ||
    !isUnknownArray(manifest.components) ||
    manifest.components.length !==
      Object.keys(probeBundleComponentProfiles).length
  ) {
    throw new Error("Probe bundle manifest is incoherent");
  }
  const expectedRoles = Object.keys(probeBundleComponentProfiles);
  const byRole = new Map<string, UnknownRecord>();
  for (const component of manifest.components) {
    assertPlainObject(component, "Probe bundle component");
    assertExactKeys(component, [
      "path",
      "permissionProfile",
      "resourceContract",
      "role",
      "sha256",
      "size",
      "version",
    ]);
    if (typeof component.role !== "string" || byRole.has(component.role)) {
      throw new Error("Probe bundle component is incoherent");
    }
    byRole.set(component.role, component);
  }
  for (const role of expectedRoles) {
    const component = byRole.get(role);
    const profile = probeBundleComponentProfiles[role];
    if (
      !component ||
      !profile ||
      component.path !== profile.path ||
      component.permissionProfile !== profile.permissionProfile ||
      component.resourceContract !== profile.resourceContract ||
      component.sha256 !== componentDetails.get(profile.path)?.sha256 ||
      !isSafeInteger(component.size) ||
      component.size <= 0 ||
      component.size !== componentDetails.get(profile.path)?.size ||
      component.version !== version
    ) {
      throw new Error("Probe bundle component is incoherent");
    }
  }
  if (bootstrapDetails) {
    if (
      !isUnknownArray(manifest.bootstrapAssets) ||
      manifest.bootstrapAssets.length !== probeBundledBootstrapAssets.length
    ) {
      throw new Error("Probe bundle Bootstrap asset is incoherent");
    }
    const byRole = new Map<string, UnknownRecord>();
    for (const asset of manifest.bootstrapAssets) {
      assertPlainObject(asset, "Probe bundle Bootstrap asset");
      assertExactKeys(asset, [
        "path",
        "permissionProfile",
        "role",
        "sha256",
        "size",
        "version",
      ]);
      if (typeof asset.role !== "string" || byRole.has(asset.role)) {
        throw new Error("Probe bundle Bootstrap asset is incoherent");
      }
      byRole.set(asset.role, asset);
    }
    for (const expected of probeBundledBootstrapAssets) {
      const asset = byRole.get(expected.role);
      const details = bootstrapDetails.get(expected.archivePath);
      if (
        !asset ||
        asset.path !== expected.archivePath ||
        asset.permissionProfile !== expected.permissionProfile ||
        asset.sha256 !== details?.sha256 ||
        !isSafeInteger(asset.size) ||
        asset.size <= 0 ||
        asset.size !== details?.size ||
        asset.version !== version
      ) {
        throw new Error("Probe bundle Bootstrap asset is incoherent");
      }
    }
  }
}

export function untrustedToolEnvironment() {
  return {
    LANG: "C",
    PATH: process.env.PATH ?? "/usr/bin:/bin",
  };
}

export function assertSameFileNames(
  actual: readonly string[],
  expected: readonly string[],
  description: string,
): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `${description} must contain exactly: ${expected.join(", ")}`,
    );
  }
}

function assertExactKeys(
  value: unknown,
  expectedKeys: readonly string[],
): void {
  const actualKeys = Object.keys(objectView(value)).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expected)) {
    throw new Error(`manifest fields must be exactly: ${expected.join(", ")}`);
  }
}

async function readCandidateManifest(
  manifestPath: string,
): Promise<UnknownRecord> {
  let manifest: unknown;
  try {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  } catch {
    throw new Error("Candidate Manifest is missing or malformed");
  }
  assertPlainObject(manifest, "Candidate Manifest");
  return manifest;
}

export async function fileSha256(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  const file = await import("node:fs");
  for await (const chunk of file.createReadStream(filePath)) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

export function sha256(contents: Uint8Array | string): string {
  return createHash("sha256").update(contents).digest("hex");
}
