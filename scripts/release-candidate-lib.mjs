import { execFile } from "node:child_process";
import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
} from "node:crypto";
import {
  chmod,
  copyFile,
  cp,
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
  verifyProbeTrustDelegation,
} from "@enoki/probe-release";

import {
  probeBootstrapTargets,
  withVerifiedProbeBootstrapArtifact,
} from "./probe-bootstrap-inspection.ts";
import { assertMigrationCandidateJoin } from "./release-baseline-migration-lib.ts";
import { inspectHubOciArchive } from "./release-candidate-oci.ts";
import {
  assertSameFileNames,
  bootstrapRecipeFile,
  bootstrapRecipeRecordFile,
  fileSha256,
  inspectProbeArchive,
  inspectProbeAssetSet,
  readProbeBundleComponentDetails,
  releaseTransitionForValidatedCandidate,
  sha256,
  untrustedToolEnvironment,
  validateCandidateIdentity,
  validateReleaseCandidate,
} from "./release-candidate-verification.ts";

export {
  inspectProbeAssetSet,
  releaseTransitionForValidatedCandidate,
  validateCandidateIdentity,
  validateReleaseCandidate,
};

const execFileAsync = promisify(execFile);
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

function assertSigningPublicKey(publicKeyPem) {
  try {
    createPublicKey(publicKeyPem);
  } catch {
    throw new Error("Probe asset signing public key is malformed");
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

function assertSigningKeyPair(privateKeyPem, publicKeyPem) {
  let derivedPublicKey;
  let declaredPublicKey;
  try {
    derivedPublicKey = createPublicKey(createPrivateKey(privateKeyPem)).export({
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

  if (!derivedPublicKey.equals(declaredPublicKey)) {
    throw new Error(
      "Probe asset signing public key does not match private key",
    );
  }
}
