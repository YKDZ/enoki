import { execFile } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
} from "node:crypto";
import {
  chmod,
  copyFile,
  cp,
  lstat,
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
  canonicalPublicKeyPem,
  createProbeTrustDelegation,
  inspectLegacyProbeAssetSet,
  inspectProbeElf,
  probeBundleComponentProfiles,
  probeBundledBootstrapAssets,
  probeTargets,
  verifyReleaseTransitionContract,
  verifyProbeTrustDelegation,
} from "@enoki/probe-release";

import {
  inspectProbeBootstrapBinary,
  probeBootstrapTargets,
  withVerifiedProbeBootstrapArtifact,
} from "./probe-bootstrap-artifact.mjs";
import { assertMigrationCandidateJoin } from "./release-baseline-migration-lib.mjs";
import { inspectHubOciArchive } from "./release-candidate-oci.mjs";

const execFileAsync = promisify(execFile);
const commitPattern = /^[0-9a-f]{40}$/;
const stableSemVerTagPattern = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const bootstrapRecipeFile = "enoki-probe-bootstrap.py";
const bootstrapRecipeRecordFile = "enoki-probe-bootstrap-recipe.json";
const verifiedCandidateReleaseTransitions = new WeakMap();
export function releaseTransitionForValidatedCandidate(manifest) {
  if (!verifiedCandidateReleaseTransitions.has(manifest)) {
    throw new Error("Candidate Manifest has not passed release verification");
  }
  return verifiedCandidateReleaseTransitions.get(manifest);
}

export function createReleaseCandidateManifest({
  bootstrapRecipe,
  candidate,
  hub,
  probeAssetSet,
  releaseBaseline,
}) {
  return {
    bootstrapRecipe,
    candidate,
    hub,
    kind: "enoki-release-candidate",
    probeAssetSet,
    releaseBaseline,
    schemaVersion: 4,
  };
}

export async function createProbeBootstrapPublication({
  bundleVersion,
  sourceDir,
  trustedRootPublicKeyPem,
}) {
  const rootFingerprint = sha256(
    canonicalPublicKeyPem(trustedRootPublicKeyPem),
  );
  const recipeTemplate = await readFile(
    path.join(sourceDir, "scripts/probe-bootstrap-recipe.py"),
    "utf8",
  );
  const recipeRoles = {
    components: Object.fromEntries(
      Object.entries(probeBundleComponentProfiles).map(([role, profile]) => [
        role,
        {
          path: profile.path,
          permissionProfile: profile.permissionProfile,
          resourceContract: profile.resourceContract,
        },
      ]),
    ),
    bootstrapAssets: Object.fromEntries(
      probeBundledBootstrapAssets.map((asset) => [
        asset.role,
        {
          path: asset.archivePath,
          permissionProfile: asset.permissionProfile,
        },
      ]),
    ),
  };
  const recipeBytes = Buffer.from(
    recipeTemplate
      .replaceAll("__ENOKI_DISTRIBUTION__", "enoki")
      .replaceAll("__ENOKI_ROOT_FINGERPRINT__", rootFingerprint)
      .replaceAll("__ENOKI_BUNDLE_VERSION__", bundleVersion)
      .replaceAll("__ENOKI_BUNDLE_ROLES__", JSON.stringify(recipeRoles)),
  );
  if (recipeBytes.includes("__ENOKI_")) {
    throw new Error("Probe Bootstrap recipe record is incomplete");
  }
  const record = {
    bundleVersion,
    distribution: "enoki",
    kind: "enoki-probe-bootstrap-recipe-record",
    recipe: {
      file: bootstrapRecipeFile,
      sha256: sha256(recipeBytes),
      size: recipeBytes.byteLength,
      version: "v1",
    },
    rootFingerprint,
    schemaVersion: 1,
    targets: [...probeTargets],
  };
  const recordBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`);
  return { recipeBytes, record, recordBytes };
}

export async function writeProbeBootstrapPublication({
  bundleVersion,
  outputDir,
  sourceDir,
  trustedRootPublicKeyPem,
}) {
  const publication = await createProbeBootstrapPublication({
    bundleVersion,
    sourceDir,
    trustedRootPublicKeyPem,
  });
  await mkdir(outputDir, { recursive: true });
  await Promise.all([
    writeFile(
      path.join(outputDir, bootstrapRecipeFile),
      publication.recipeBytes,
      {
        mode: 0o755,
      },
    ),
    writeFile(
      path.join(outputDir, bootstrapRecipeRecordFile),
      publication.recordBytes,
    ),
  ]);
  return publication.record;
}

export function validateCandidateIdentity({ commit, version }) {
  if (!commitPattern.test(commit ?? "")) {
    throw new Error("commit must be a full lowercase 40-character object ID");
  }

  if (!stableSemVerTagPattern.test(version ?? "")) {
    throw new Error("version must be a stable SemVer tag like v1.2.3");
  }

  return { commit, version };
}

export function validateProbeSigningIdentity({ privateKeyPem, publicKeyPem }) {
  if (!privateKeyPem) {
    throw new Error("Probe asset signing private key is required");
  }
  if (!publicKeyPem) {
    throw new Error("Probe asset signing public key is required");
  }

  assertSigningKeyPair(privateKeyPem, publicKeyPem);
  const publicKeyText = Buffer.from(publicKeyPem).toString("utf8");
  const normalizedPublicKey = Buffer.from(
    publicKeyText.endsWith("\n") ? publicKeyText : `${publicKeyText}\n`,
  );

  return { publicKeySha256: sha256(normalizedPublicKey) };
}

export function validateDelegatedProbeSigningIdentity({
  delegationBytes,
  delegationSignature,
  distribution,
  highestAcceptedGeneration,
  privateKeyPem,
  publicKeyPem,
  rootPublicKeyPem,
}) {
  const delegation = verifyProbeTrustDelegation({
    bytes: delegationBytes,
    expectedDistribution: distribution,
    highestAcceptedGeneration,
    rootPublicKeyPem,
    signature: delegationSignature,
  });
  const identity = validateProbeSigningIdentity({
    privateKeyPem,
    publicKeyPem,
  });
  if (delegation.signingIdentity.keyId !== identity.publicKeySha256) {
    throw new Error(
      "Probe asset signing identity is not authorized by the Probe Trust Delegation",
    );
  }
  return { ...identity, delegation };
}

export function parseCommandLine(arguments_) {
  const [command, ...tokens] = arguments_;
  const options = new Map();

  for (let index = 0; index < tokens.length; index += 2) {
    const name = tokens[index];
    const value = tokens[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`invalid command-line argument: ${name ?? "<missing>"}`);
    }
    if (options.has(name)) {
      throw new Error(`duplicate command-line argument: ${name}`);
    }
    options.set(name, value);
  }

  return { command, options };
}

export function requiredOption(options, name) {
  const value = options.get(name);
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

export function assertAllowedOptions(command, options, allowedNames) {
  const allowed = new Set(allowedNames);
  for (const name of options.keys()) {
    if (!allowed.has(name)) {
      throw new Error(`unknown option for ${command}: ${name}`);
    }
  }
}

export async function packageProbeArchive({
  binaryPath,
  outputDir,
  sourceDateEpoch,
  target,
  version,
}) {
  const { version: stableVersion } = validateCandidateIdentity({
    commit: "0".repeat(40),
    version,
  });
  if (!probeTargets.includes(target)) {
    throw new Error(`unsupported Probe target: ${target}`);
  }
  if (!/^(?:0|[1-9]\d*)$/.test(sourceDateEpoch ?? "")) {
    throw new Error("source date epoch must be a non-negative integer");
  }
  const binary = await readFile(binaryPath);
  inspectProbeElf(binary, { target, version: stableVersion });

  const stagingDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-package-"));
  const file = `enoki-probe-${target}.tar.gz`;
  const archivePath = path.join(outputDir, file);
  try {
    await mkdir(outputDir, { recursive: true });
    for (const profile of Object.values(probeBundleComponentProfiles)) {
      const source =
        profile.path === "enoki-probe"
          ? binaryPath
          : path.join(path.dirname(binaryPath), profile.path);
      const component = await readFile(source);
      inspectProbeElf(component, { target, version: stableVersion });
      const staged = path.join(stagingDir, profile.path);
      await copyFile(source, staged);
      await chmod(staged, 0o755);
    }
    const componentDetails = await readProbeBundleComponentDetails(
      stagingDir,
      probeBundleComponentProfiles,
    );
    await writeFile(
      path.join(stagingDir, "bundle-manifest.json"),
      `${JSON.stringify(
        {
          components: renderProbeBundleComponentsFromDetails({
            componentDetails,
            version: stableVersion.slice(1),
          }),
          kind: "enoki-probe-bundle",
          target,
          version: stableVersion.slice(1),
        },
        null,
        2,
      )}\n`,
    );
    await execFileAsync(
      "tar",
      [
        "--create",
        "--gzip",
        "--sort=name",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "--blocking-factor=1",
        `--mtime=@${sourceDateEpoch}`,
        "--format=gnu",
        "--file",
        archivePath,
        "--directory",
        stagingDir,
        "bundle-manifest.json",
        ...Object.values(probeBundleComponentProfiles).map(({ path }) => path),
      ],
      { env: untrustedToolEnvironment(), maxBuffer: 1024 * 1024 },
    );
    await inspectProbeArchive(archivePath, {
      target,
      version: stableVersion,
    });
    const archiveSha256 = await fileSha256(archivePath);
    await writeFile(`${archivePath}.sha256`, `${archiveSha256}  ${file}\n`);
    return { archivePath, archiveSha256, file };
  } finally {
    await rm(stagingDir, { force: true, recursive: true });
  }
}

// Bootstrap 的受限 producer 与普通 Probe producer 在此合成唯一公开归档。
// Bootstrap 输入先绑定精确 size+sha256 快照，再从该私有快照提取固定角色；
// compose 之后不存在第二个可发布 Bootstrap archive。
async function composeProbeArchive({
  bootstrapArchivePath,
  bootstrapExpectedArchive,
  distribution,
  outputPath,
  rootKeyId,
  runtimeArchivePath,
  sourceDateEpoch,
  target,
  version,
}) {
  await inspectProbeArchive(runtimeArchivePath, { target, version });
  const stagingDir = await mkdtemp(
    path.join(tmpdir(), "enoki-probe-bundle-compose-"),
  );
  try {
    await execFileAsync(
      "tar",
      [
        "--extract",
        "--gzip",
        "--file",
        runtimeArchivePath,
        "--directory",
        stagingDir,
        "--no-same-owner",
      ],
      { env: untrustedToolEnvironment(), maxBuffer: 1024 * 1024 },
    );
    await mkdir(path.join(stagingDir, "bootstrap"), { recursive: true });
    await withVerifiedProbeBootstrapArtifact(
      {
        archivePath: bootstrapArchivePath,
        distribution,
        expectedArchive: bootstrapExpectedArchive,
        rootKeyId,
        target,
        version,
      },
      async ({ extractedRoles }) => {
        for (const asset of probeBundledBootstrapAssets) {
          const destination = path.join(stagingDir, asset.archivePath);
          await copyFile(extractedRoles[asset.key].binaryPath, destination);
          await chmod(destination, 0o755);
        }
      },
    );
    const componentDetails = await readProbeBundleComponentDetails(
      stagingDir,
      probeBundleComponentProfiles,
    );
    const bootstrapDetails = await readProbeBundleComponentDetails(
      stagingDir,
      Object.fromEntries(
        probeBundledBootstrapAssets.map((asset) => [
          asset.role,
          { path: asset.archivePath },
        ]),
      ),
    );
    await writeFile(
      path.join(stagingDir, "bundle-manifest.json"),
      `${JSON.stringify(
        {
          bootstrapAssets: renderBundledBootstrapAssets({
            componentDetails: bootstrapDetails,
            version: version.slice(1),
          }),
          components: renderProbeBundleComponentsFromDetails({
            componentDetails,
            version: version.slice(1),
          }),
          kind: "enoki-probe-bundle",
          target,
          version: version.slice(1),
        },
        null,
        2,
      )}\n`,
    );
    await mkdir(path.dirname(outputPath), { recursive: true });
    await execFileAsync(
      "tar",
      [
        "--create",
        "--gzip",
        "--sort=name",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "--blocking-factor=1",
        `--mtime=@${sourceDateEpoch}`,
        "--format=gnu",
        "--file",
        outputPath,
        "--directory",
        stagingDir,
        "bundle-manifest.json",
        ...Object.values(probeBundleComponentProfiles).map(({ path }) => path),
        ...probeBundledBootstrapAssets.map(({ archivePath }) => archivePath),
      ],
      { env: untrustedToolEnvironment(), maxBuffer: 1024 * 1024 },
    );
  } finally {
    await rm(stagingDir, { force: true, recursive: true });
  }
}

export async function packageReleaseCandidate({
  candidateDir,
  outputPath,
  sourceDateEpoch,
  trustedRootPublicKeyPem,
}) {
  if (!/^(?:0|[1-9]\d*)$/.test(sourceDateEpoch ?? "")) {
    throw new Error("source date epoch must be a non-negative integer");
  }
  await validateReleaseCandidate(candidateDir, { trustedRootPublicKeyPem });
  await mkdir(path.dirname(outputPath), { recursive: true });
  await execFileAsync(
    "tar",
    [
      "--create",
      "--gzip",
      "--sort=name",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      `--mtime=@${sourceDateEpoch}`,
      "--format=gnu",
      "--file",
      outputPath,
      "--directory",
      candidateDir,
      ".",
    ],
    { env: untrustedToolEnvironment(), maxBuffer: 1024 * 1024 },
  );
  return { outputPath, sha256: await fileSha256(outputPath) };
}

export async function assertCheckedOutCommit(sourceDir, expectedCommit) {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], {
    cwd: sourceDir,
  });
  const actualCommit = stdout.trim();

  if (actualCommit !== expectedCommit) {
    throw new Error(
      `candidate commit ${expectedCommit} does not match checked-out source ${actualCommit}`,
    );
  }
}

export async function prepareProbeAssetSet({
  archivesDir,
  bootstrapArchivesDir,
  delegationSignature,
  delegationBytes,
  distribution,
  outputDir,
  privateKeyPem,
  publicKeyPem,
  rootPublicKeyPem,
  version,
}) {
  const unsignedDir = `${outputDir}.unsigned-${randomUUID()}`;
  try {
    await prepareUnsignedProbeAssetSet({
      archivesDir,
      bootstrapArchivesDir,
      delegationSignature,
      delegationBytes,
      distribution,
      outputDir: unsignedDir,
      publicKeyPem,
      rootPublicKeyPem,
      version,
    });
    return await signProbeAssetSet({
      expectedDelegationBytes: delegationBytes,
      expectedDelegationSignature: delegationSignature,
      outputDir,
      privateKeyPem,
      trustedRootPublicKeyPem: rootPublicKeyPem,
      unsignedAssetDir: unsignedDir,
    });
  } finally {
    await rm(unsignedDir, { force: true, recursive: true });
  }
}

export async function prepareUnsignedProbeAssetSet({
  archivesDir,
  bootstrapArchivesDir,
  delegationSignature,
  delegationBytes,
  distribution,
  outputDir,
  publicKeyPem,
  rootPublicKeyPem,
  version,
}) {
  const { version: stableVersion } = validateCandidateIdentity({
    commit: "0".repeat(40),
    version,
  });
  if (!publicKeyPem) {
    throw new Error("Probe asset signing public key is required");
  }
  assertSigningPublicKey(publicKeyPem);
  const delegation = verifyProbeTrustDelegation({
    bytes: delegationBytes,
    expectedDistribution: distribution,
    rootPublicKeyPem,
    signature: delegationSignature,
  });

  const expectedInputs = probeTargets
    .flatMap((target) => {
      const archive = `enoki-probe-${target}.tar.gz`;
      return [archive, `${archive}.sha256`];
    })
    .sort();
  const actualInputs = (await readdir(archivesDir)).sort();
  assertSameFileNames(
    actualInputs,
    expectedInputs,
    "Probe build artifact directory",
  );

  if (!bootstrapArchivesDir) {
    throw new Error("Probe Bootstrap build artifact directory is required");
  }
  const expectedBootstrapInputs = probeBootstrapTargets
    .flatMap((target) => {
      const archive = `enoki-probe-bootstrap-${target}.tar.gz`;
      return [archive, `${archive}.sha256`];
    })
    .sort();
  assertSameFileNames(
    (await readdir(bootstrapArchivesDir)).sort(),
    expectedBootstrapInputs,
    "Probe Bootstrap build artifact directory",
  );

  const rootPublicKey = canonicalPublicKeyPem(rootPublicKeyPem);
  const rootKeyId = sha256(rootPublicKey);
  const bundledArchivesDir = await mkdtemp(
    path.join(tmpdir(), "enoki-probe-bundled-archives-"),
  );

  const assets = [];
  for (const target of probeTargets) {
    const file = `enoki-probe-${target}.tar.gz`;
    const archive = await readFile(path.join(archivesDir, file));
    const archiveSha256 = sha256(archive);
    const checksum = await readFile(
      path.join(archivesDir, `${file}.sha256`),
      "utf8",
    );
    if (checksum !== `${archiveSha256}  ${file}\n`) {
      throw new Error(`Probe checksum sidecar does not match ${file}`);
    }
    const bootstrapFile = `enoki-probe-bootstrap-${target}.tar.gz`;
    const bootstrapArchivePath = path.join(bootstrapArchivesDir, bootstrapFile);
    const bootstrapArchive = await readFile(bootstrapArchivePath);
    const bootstrapChecksum = await readFile(
      `${bootstrapArchivePath}.sha256`,
      "utf8",
    );
    const bootstrapSha256 = sha256(bootstrapArchive);
    if (bootstrapChecksum !== `${bootstrapSha256}  ${bootstrapFile}\n`) {
      throw new Error(
        `Probe Bootstrap checksum sidecar does not match ${bootstrapFile}`,
      );
    }
    const bundledArchivePath = path.join(bundledArchivesDir, file);
    await composeProbeArchive({
      bootstrapArchivePath,
      bootstrapExpectedArchive: {
        sha256: bootstrapSha256,
        size: bootstrapArchive.byteLength,
      },
      distribution,
      outputPath: bundledArchivePath,
      rootKeyId,
      runtimeArchivePath: path.join(archivesDir, file),
      sourceDateEpoch: "0",
      target,
      version: stableVersion,
    });
    const bundledArchive = await readFile(bundledArchivePath);
    const bundledArchiveSha256 = sha256(bundledArchive);
    await writeFile(
      `${bundledArchivePath}.sha256`,
      `${bundledArchiveSha256}  ${file}\n`,
    );
    const inspectedArchive = await inspectProbeArchive(bundledArchivePath, {
      bundledBootstrap: { distribution, rootKeyId },
      target,
      version: stableVersion,
    });
    assets.push({
      bundleManifestSha256: inspectedArchive.bundleManifestSha256,
      file,
      sha256: bundledArchiveSha256,
      size: bundledArchive.byteLength,
      target,
    });
  }

  const publicKeyText = Buffer.from(publicKeyPem).toString("utf8");
  const publicKey = Buffer.from(
    publicKeyText.endsWith("\n") ? publicKeyText : `${publicKeyText}\n`,
  );
  const publicKeySha256 = sha256(publicKey);
  if (delegation.signingIdentity.keyId !== publicKeySha256) {
    throw new Error(
      "Probe asset signing identity is not authorized by the Probe Trust Delegation",
    );
  }
  const manifest = `${JSON.stringify(
    {
      assets,
      kind: "enoki-probe-assets",
      signature: {
        algorithm: "rsa-sha256",
        delegationGeneration: delegation.generation,
        delegationKeyId: delegation.signingIdentity.keyId,
        file: "manifest.json.sig",
        publicKey: "signing-key.pem",
      },
      version: stableVersion.slice(1),
    },
    null,
    2,
  )}\n`;
  const manifestBytes = Buffer.from(manifest);
  const stagingDir = `${outputDir}.tmp-${randomUUID()}`;

  try {
    await mkdir(stagingDir, { recursive: false });
    for (const file of expectedInputs) {
      await copyFile(
        path.join(bundledArchivesDir, file),
        path.join(stagingDir, file),
      );
    }
    await writeFile(path.join(stagingDir, "manifest.json"), manifestBytes);
    await writeFile(path.join(stagingDir, "root-key.pem"), rootPublicKey);
    await writeFile(path.join(stagingDir, "signing-key.pem"), publicKey);
    await writeFile(
      path.join(stagingDir, "trust-delegation.json"),
      delegationBytes,
    );
    await writeFile(
      path.join(stagingDir, "trust-delegation.json.sig"),
      delegationSignature,
    );
    await rename(stagingDir, outputDir);
  } catch (error) {
    await rm(stagingDir, { force: true, recursive: true });
    throw error;
  } finally {
    await rm(bundledArchivesDir, { force: true, recursive: true });
  }

  return { outputDir, publicKeySha256, version: stableVersion };
}

export async function signProbeAssetSet({
  expectedDelegationBytes,
  expectedDelegationSignature,
  outputDir,
  privateKeyPem,
  trustedRootPublicKeyPem,
  unsignedAssetDir,
}) {
  if (!privateKeyPem) {
    throw new Error("Probe asset signing private key is required");
  }
  if (
    !trustedRootPublicKeyPem ||
    !expectedDelegationBytes ||
    !expectedDelegationSignature
  ) {
    throw new Error(
      "Probe Asset Set signing requires an external Probe Distribution Trust Root and exact Probe Trust Delegation",
    );
  }
  const inspected = await inspectProbeAssetSet(unsignedAssetDir, {
    expectedDelegationBytes,
    expectedDelegationSignature,
    trustedRootPublicKeyPem,
    unsigned: true,
  });
  const publicKey = await readFile(
    path.join(unsignedAssetDir, "signing-key.pem"),
    "utf8",
  );
  assertSigningKeyPair(privateKeyPem, publicKey);
  const manifestBytes = await readFile(
    path.join(unsignedAssetDir, "manifest.json"),
  );
  const signature = sign("RSA-SHA256", manifestBytes, privateKeyPem);
  const stagingDir = `${outputDir}.tmp-${randomUUID()}`;

  try {
    await cp(unsignedAssetDir, stagingDir, { recursive: true });
    await writeFile(path.join(stagingDir, "manifest.json.sig"), signature);
    await inspectProbeAssetSet(stagingDir, {
      expectedDelegationBytes,
      expectedDelegationSignature,
      expectedVersion: inspected.version,
      trustedRootPublicKeyPem,
    });
    await rename(stagingDir, outputDir);
  } catch (error) {
    await rm(stagingDir, { force: true, recursive: true });
    throw error;
  }

  return {
    outputDir,
    publicKeySha256: inspected.signingIdentity.publicKeySha256,
    version: `v${inspected.version}`,
  };
}

export async function assembleReleaseCandidate({
  commit,
  hubOciPath,
  outputDir,
  probeAssetSetDir,
  releaseBaselineDir,
  sourceDir,
  trustedRootPublicKeyPem,
  version,
}) {
  const identity = validateCandidateIdentity({ commit, version });
  await assertCheckedOutCommit(sourceDir, identity.commit);
  const probeAssetSet = await inspectProbeAssetSet(probeAssetSetDir, {
    expectedVersion: version.slice(1),
    trustedRootPublicKeyPem,
  });
  const hubOci = await inspectHubOciArchive({
    archivePath: hubOciPath,
    probeFiles: probeAssetSet.files,
  });
  const { validateResolvedReleaseBaseline } =
    await import("./release-baseline-lib.mjs");
  const releaseBaseline = await validateResolvedReleaseBaseline(
    releaseBaselineDir,
    {
      candidateVersion: version,
      trustedRootPublicKeyPem,
    },
  );
  assertMigrationCandidateJoin({
    identity,
    releaseBaseline,
    releaseTransition: probeAssetSet.releaseTransition ?? null,
  });
  const hubArchiveFile = `enoki-hub-${version}.oci.tar`;
  const hubArchive = {
    archive: `hub/${hubArchiveFile}`,
    archiveSha256: await fileSha256(hubOciPath),
    digest: hubOci.digest,
    embeddedProbeVersion: probeAssetSet.version,
    size: (await stat(hubOciPath)).size,
  };
  const { recipeBytes, record, recordBytes } =
    await createProbeBootstrapPublication({
      bundleVersion: version.slice(1),
      sourceDir,
      trustedRootPublicKeyPem,
    });
  const bootstrapRecipe = {
    bundleVersion: record.bundleVersion,
    distribution: record.distribution,
    file: bootstrapRecipeFile,
    kind: record.kind,
    recordFile: bootstrapRecipeRecordFile,
    recordSha256: sha256(recordBytes),
    recordSize: recordBytes.byteLength,
    rootFingerprint: record.rootFingerprint,
    schemaVersion: record.schemaVersion,
    sha256: sha256(recipeBytes),
    size: recipeBytes.byteLength,
    targets: record.targets,
    version: "v1",
  };
  const manifest = createReleaseCandidateManifest({
    bootstrapRecipe,
    candidate: identity,
    hub: hubArchive,
    probeAssetSet: {
      directory: "probe-assets",
      files: probeAssetSet.files,
      signingIdentity: probeAssetSet.signingIdentity,
      version: probeAssetSet.version,
    },
    releaseBaseline,
  });
  const stagingDir = `${outputDir}.tmp-${randomUUID()}`;

  try {
    await mkdir(path.join(stagingDir, "hub"), { recursive: true });
    await mkdir(path.join(stagingDir, "recipe"), { recursive: true });
    await cp(probeAssetSetDir, path.join(stagingDir, "probe-assets"), {
      recursive: true,
    });
    await cp(releaseBaselineDir, path.join(stagingDir, "release-baseline"), {
      recursive: true,
    });
    await copyFile(hubOciPath, path.join(stagingDir, "hub", hubArchiveFile));
    await writeFile(
      path.join(stagingDir, "recipe", bootstrapRecipeFile),
      recipeBytes,
      { mode: 0o755 },
    );
    await writeFile(
      path.join(stagingDir, "recipe", bootstrapRecipeRecordFile),
      recordBytes,
    );
    await writeFile(
      path.join(stagingDir, "candidate-manifest.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
    await rename(stagingDir, outputDir);
  } catch (error) {
    await rm(stagingDir, { force: true, recursive: true });
    throw error;
  }

  await validateReleaseCandidate(outputDir, { trustedRootPublicKeyPem });
  return manifest;
}

export async function compareHubOciBuilds({
  firstPath,
  probeAssetSetDir,
  secondPath,
  trustedRootPublicKeyPem,
}) {
  const probeAssetSet = await inspectProbeAssetSet(probeAssetSetDir, {
    trustedRootPublicKeyPem,
  });
  const [first, second] = await Promise.all([
    inspectHubOciArchive({
      archivePath: firstPath,
      probeFiles: probeAssetSet.files,
    }),
    inspectHubOciArchive({
      archivePath: secondPath,
      probeFiles: probeAssetSet.files,
    }),
  ]);
  if (first.digest !== second.digest) {
    throw new Error(
      `Hub OCI builds are not reproducible: ${first.digest} != ${second.digest}`,
    );
  }
  return { digest: first.digest };
}

export async function validateReleaseCandidate(
  candidateDir,
  { trustedRootPublicKeyPem } = {},
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
    } = await import("./release-baseline-lib.mjs");
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
    !/^[0-9a-f]{64}$/.test(bootstrapRecipe.recordSha256 ?? "") ||
    !Number.isSafeInteger(bootstrapRecipe.recordSize) ||
    bootstrapRecipe.recordSize < 1 ||
    bootstrapRecipe.schemaVersion !== 1 ||
    JSON.stringify(bootstrapRecipe.targets) !== JSON.stringify(probeTargets) ||
    bootstrapRecipe.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(bootstrapRecipe.rootFingerprint ?? "") ||
    !/^[0-9a-f]{64}$/.test(bootstrapRecipe.sha256 ?? "") ||
    !Number.isSafeInteger(bootstrapRecipe.size) ||
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
    { expectedVersion: probe.version, trustedRootPublicKeyPem },
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
  assetDir,
  {
    expectedDelegationBytes,
    expectedDelegationSignature,
    expectedVersion,
    highestAcceptedDelegationGeneration = 0,
    requireEmbeddedProbeIdentity = true,
    trustedRootPublicKeyPem,
    trustedRootPublicKeySha256,
    unsigned = false,
  } = {},
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
  let manifest;
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
    !Number.isSafeInteger(manifest.signature.delegationGeneration) ||
    manifest.signature.delegationGeneration < 1 ||
    !/^[0-9a-f]{64}$/.test(manifest.signature.delegationKeyId) ||
    manifest.signature.file !== "manifest.json.sig" ||
    manifest.signature.publicKey !== "signing-key.pem"
  ) {
    throw new Error("Probe Asset Set signature descriptor is unsupported");
  }
  if (
    !Array.isArray(manifest.assets) ||
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
  const targetProbeComponents = [];

  for (let index = 0; index < probeTargets.length; index += 1) {
    const target = probeTargets[index];
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
      !/^[0-9a-f]{64}$/.test(asset.bundleManifestSha256) ||
      !/^[0-9a-f]{64}$/.test(asset.sha256) ||
      !Number.isSafeInteger(asset.size) ||
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
    targetProbeComponents.push({
      sha256: inspectedArchive.probeSha256,
      target,
    });
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
  let releaseTransition = null;
  if (transitionFileCount === 2) {
    const contractBytes = await readFile(
      path.join(assetDir, "release-transition-contract.json"),
    );
    let contract;
    try {
      contract = JSON.parse(contractBytes.toString("utf8"));
    } catch {
      throw new Error("Release Transition Contract is malformed");
    }
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
        classification: contract.transition,
        delegationGeneration: manifest.signature.delegationGeneration,
        sourceCommit: contract.source?.commit,
        sourceTag: contract.source?.tag,
        sourceVersion: contract.source?.version,
        targetAssetClosure: manifest.assets,
        targetAssetSetManifestSha256: sha256(manifestBytes),
        targetVersion: manifest.version,
      },
      rootPublicKeyPem: trustedRootPublicKey ?? canonicalRootPublicKey,
    });
    if (
      !Array.isArray(releaseTransition.target?.probeComponents) ||
      releaseTransition.target.probeComponents.length !==
        targetProbeComponents.length ||
      releaseTransition.target.probeComponents.some(
        (component, index) =>
          component?.file !== "enoki-probe" ||
          component?.role !== "probe" ||
          component?.target !== targetProbeComponents[index]?.target ||
          component?.sha256 !== targetProbeComponents[index]?.sha256,
      )
    ) {
      throw new Error(
        "Release Transition Contract target Probe closure does not match verified bundles",
      );
    }
  }
  const publicKeySha256 = sha256(publicKey);
  const files = [];
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

function assertSigningPublicKey(publicKeyPem) {
  try {
    createPublicKey(publicKeyPem);
  } catch {
    throw new Error("Probe asset signing public key is malformed");
  }
}

async function inspectProbeArchive(
  archivePath,
  { bundledBootstrap, requireEmbeddedProbeIdentity = true, target, version },
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
    return {
      bundleManifestSha256: sha256(bundleManifest),
      probeSha256: componentDetails.get("enoki-probe")?.sha256,
    };
  } finally {
    await rm(extractionDir, { force: true, recursive: true });
  }
}

async function readProbeBundleComponentDetails(extractionDir, profiles) {
  const detailsByPath = new Map();
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
  bytes,
  { bootstrapDetails, componentDetails, target, version },
) {
  let manifest;
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
    !Array.isArray(manifest.components) ||
    manifest.components.length !==
      Object.keys(probeBundleComponentProfiles).length
  ) {
    throw new Error("Probe bundle manifest is incoherent");
  }
  const expectedRoles = Object.keys(probeBundleComponentProfiles);
  const byRole = new Map();
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
      component.path !== profile.path ||
      component.permissionProfile !== profile.permissionProfile ||
      component.resourceContract !== profile.resourceContract ||
      component.sha256 !== componentDetails.get(profile.path)?.sha256 ||
      !Number.isSafeInteger(component.size) ||
      component.size <= 0 ||
      component.size !== componentDetails.get(profile.path)?.size ||
      component.version !== version
    ) {
      throw new Error("Probe bundle component is incoherent");
    }
  }
  if (bootstrapDetails) {
    if (
      !Array.isArray(manifest.bootstrapAssets) ||
      manifest.bootstrapAssets.length !== probeBundledBootstrapAssets.length
    ) {
      throw new Error("Probe bundle Bootstrap asset is incoherent");
    }
    const byRole = new Map();
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
        !Number.isSafeInteger(asset.size) ||
        asset.size <= 0 ||
        asset.size !== details?.size ||
        asset.version !== version
      ) {
        throw new Error("Probe bundle Bootstrap asset is incoherent");
      }
    }
  }
}

function renderProbeBundleComponentsFromDetails({ componentDetails, version }) {
  return Object.entries(probeBundleComponentProfiles).map(
    ([role, profile]) => ({
      ...profile,
      role,
      sha256: componentDetails.get(profile.path).sha256,
      size: componentDetails.get(profile.path).size,
      version,
    }),
  );
}

function renderBundledBootstrapAssets({ componentDetails, version }) {
  return probeBundledBootstrapAssets.map(
    ({ archivePath, permissionProfile, role }) => ({
      path: archivePath,
      permissionProfile,
      role,
      sha256: componentDetails.get(archivePath).sha256,
      size: componentDetails.get(archivePath).size,
      version,
    }),
  );
}

function untrustedToolEnvironment() {
  return {
    LANG: "C",
    PATH: process.env.PATH ?? "/usr/bin:/bin",
  };
}

function assertSigningKeyPair(privateKeyPem, publicKeyPem) {
  let privateKey;
  let derivedPublicKey;
  let declaredPublicKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
    derivedPublicKey = createPublicKey(privateKey).export({
      format: "der",
      type: "spki",
    });
    declaredPublicKey = createPublicKey(publicKeyPem).export({
      format: "der",
      type: "spki",
    });
  } catch {
    throw new Error("Probe asset signing key material is malformed");
  }
  if (
    privateKey.asymmetricKeyType !== "rsa" ||
    privateKey.asymmetricKeyDetails?.modulusLength !== 4096
  ) {
    throw new Error("Probe asset signing key must be an RSA-4096 private key");
  }

  if (!derivedPublicKey.equals(declaredPublicKey)) {
    throw new Error(
      "Probe asset signing public key does not match private key",
    );
  }
}

function assertSameFileNames(actual, expected, description) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
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
  const actualKeys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expected)) {
    throw new Error(`manifest fields must be exactly: ${expected.join(", ")}`);
  }
}

async function readCandidateManifest(manifestPath) {
  let manifest;
  try {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  } catch {
    throw new Error("Candidate Manifest is missing or malformed");
  }
  assertPlainObject(manifest, "Candidate Manifest");
  return manifest;
}

async function fileSha256(filePath) {
  const hash = createHash("sha256");
  const file = await import("node:fs");
  for await (const chunk of file.createReadStream(filePath)) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}
