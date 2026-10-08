import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmod,
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
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
} from "@enoki/probe-release";

import { assertMigrationCandidateJoin } from "./release-baseline-migration-lib.ts";
import { inspectHubOciArchive } from "./release-candidate-oci.ts";
import {
  prepareUnsignedProbeAssetSet,
  renderProbeBundleComponentsFromDetails,
  signProbeAssetSet,
} from "./release-candidate-signing.ts";
import {
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

export {
  assertAllowedOptions,
  parseCommandLine,
  requiredOption,
} from "./release-json-guards.ts";

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
