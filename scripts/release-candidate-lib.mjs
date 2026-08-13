import { execFile } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
  verify,
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
  inspectProbeBootstrapArtifact,
  probeBootstrapTargets,
} from "./probe-bootstrap-artifact.mjs";
import { inspectHubOciArchive } from "./release-candidate-oci.mjs";

const execFileAsync = promisify(execFile);
const commitPattern = /^[0-9a-f]{40}$/;
const stableSemVerTagPattern = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const probeTrustDelegationDomain = Buffer.from(
  "enoki/probe-trust-delegation/v1\0",
  "utf8",
);
const dynamicLoaderByProbeTarget = Object.freeze({
  "aarch64-unknown-linux-gnu": "/lib/ld-linux-aarch64.so.1",
  "aarch64-unknown-linux-musl": "/lib/ld-musl-aarch64.so.1",
  "x86_64-unknown-linux-gnu": "/lib64/ld-linux-x86-64.so.2",
  "x86_64-unknown-linux-musl": "/lib/ld-musl-x86_64.so.1",
});
const probeBundleComponentProfiles = Object.freeze({
  probe: Object.freeze({
    path: "enoki-probe",
    permissionProfile: "probe-v1",
  }),
});

export const probeTargets = Object.freeze([
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
]);

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
  assertRsa4096PublicKey(publicKeyPem, "Probe asset signing public key");
  const publicKeyText = Buffer.from(publicKeyPem).toString("utf8");
  const normalizedPublicKey = Buffer.from(
    publicKeyText.endsWith("\n") ? publicKeyText : `${publicKeyText}\n`,
  );

  return { publicKeySha256: sha256(normalizedPublicKey) };
}

export function createProbeTrustDelegation({
  distribution,
  generation,
  purpose = "probe-asset-signing",
  releasePublicKeyPem,
  rootPrivateKey,
  rootPrivateKeyPem,
}) {
  const hasKeyObject = rootPrivateKey !== undefined;
  const hasPem = rootPrivateKeyPem !== undefined;
  if (hasKeyObject === hasPem) {
    throw new Error("exactly one root private key representation is required");
  }
  if (hasKeyObject && rootPrivateKey?.type !== "private") {
    throw new Error("root private key must be a KeyObject");
  }
  const signingKey = hasKeyObject
    ? rootPrivateKey
    : createPrivateKey(rootPrivateKeyPem);
  assertRsa4096PrivateKey(signingKey, "Probe Distribution Trust Root");
  const rootPublicKeyPem = canonicalPublicKeyPem(
    createPublicKey(signingKey).export({ format: "pem", type: "spki" }),
  );
  const releasePublicKey = canonicalRsa4096PublicKeyPem(
    releasePublicKeyPem,
    "Probe asset signing public key",
  );
  const delegation = validateProbeTrustDelegationDocument({
    distribution,
    generation,
    kind: "enoki-probe-trust-delegation",
    purpose,
    rootKeyId: sha256(rootPublicKeyPem),
    schemaVersion: 1,
    signingIdentity: {
      algorithm: "rsa-sha256",
      keyId: sha256(releasePublicKey),
      publicKeyPem: releasePublicKey.toString("utf8"),
    },
  });
  const bytes = canonicalProbeTrustDelegationBytes(delegation);
  return {
    bytes,
    delegation,
    signature: sign(
      "RSA-SHA256",
      trustDelegationSigningInput(bytes),
      signingKey,
    ),
  };
}

export function verifyProbeTrustDelegation({
  bytes,
  expectedDistribution,
  expectedPurpose = "probe-asset-signing",
  highestAcceptedGeneration = 0,
  rootPublicKeyPem,
  signature,
}) {
  if (
    !Number.isSafeInteger(highestAcceptedGeneration) ||
    highestAcceptedGeneration < 0
  ) {
    throw new Error(
      "highest accepted Probe Trust Delegation generation is invalid",
    );
  }
  const rootPublicKey = canonicalRsa4096PublicKeyPem(
    rootPublicKeyPem,
    "Probe Distribution Trust Root public key",
  );
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error("Probe Trust Delegation is malformed");
  }
  const delegation = validateProbeTrustDelegationDocument(parsed);
  const canonicalBytes = canonicalProbeTrustDelegationBytes(delegation);
  if (!Buffer.from(bytes).equals(canonicalBytes)) {
    throw new Error("Probe Trust Delegation must use canonical encoding");
  }
  if (
    delegation.distribution !== expectedDistribution ||
    delegation.purpose !== expectedPurpose ||
    delegation.rootKeyId !== sha256(rootPublicKey)
  ) {
    throw new Error("Probe Trust Delegation binding is invalid");
  }
  if (delegation.generation < highestAcceptedGeneration) {
    throw new Error(
      "Probe Trust Delegation generation is not newer than installed trust",
    );
  }
  let valid = false;
  try {
    valid = verify(
      "RSA-SHA256",
      trustDelegationSigningInput(canonicalBytes),
      rootPublicKey,
      signature,
    );
  } catch {
    valid = false;
  }
  if (!valid)
    throw new Error("Probe Trust Delegation root signature is invalid");
  return delegation;
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

function validateProbeTrustDelegationDocument(value) {
  assertPlainObject(value, "Probe Trust Delegation");
  assertExactKeys(value, [
    "distribution",
    "generation",
    "kind",
    "purpose",
    "rootKeyId",
    "schemaVersion",
    "signingIdentity",
  ]);
  if (
    value.kind !== "enoki-probe-trust-delegation" ||
    value.schemaVersion !== 1 ||
    typeof value.distribution !== "string" ||
    !/^[a-z][a-z0-9-]{0,63}$/.test(value.distribution) ||
    value.purpose !== "probe-asset-signing" ||
    !Number.isSafeInteger(value.generation) ||
    value.generation < 1 ||
    !/^[0-9a-f]{64}$/.test(value.rootKeyId)
  ) {
    throw new Error("Probe Trust Delegation fields are invalid");
  }
  assertPlainObject(
    value.signingIdentity,
    "Probe Trust Delegation signing identity",
  );
  assertExactKeys(value.signingIdentity, [
    "algorithm",
    "keyId",
    "publicKeyPem",
  ]);
  const publicKey = canonicalRsa4096PublicKeyPem(
    value.signingIdentity.publicKeyPem,
    "Probe Trust Delegation signing identity",
  );
  if (
    value.signingIdentity.algorithm !== "rsa-sha256" ||
    !/^[0-9a-f]{64}$/.test(value.signingIdentity.keyId) ||
    value.signingIdentity.keyId !== sha256(publicKey)
  ) {
    throw new Error("Probe Trust Delegation signing identity is invalid");
  }
  return {
    distribution: value.distribution,
    generation: value.generation,
    kind: value.kind,
    purpose: value.purpose,
    rootKeyId: value.rootKeyId,
    schemaVersion: value.schemaVersion,
    signingIdentity: {
      algorithm: value.signingIdentity.algorithm,
      keyId: value.signingIdentity.keyId,
      publicKeyPem: publicKey.toString("utf8"),
    },
  };
}

function canonicalProbeTrustDelegationBytes(delegation) {
  return Buffer.from(`${JSON.stringify(delegation)}\n`, "utf8");
}

function trustDelegationSigningInput(bytes) {
  return Buffer.concat([probeTrustDelegationDomain, bytes]);
}

function canonicalPublicKeyPem(publicKeyPem) {
  try {
    return Buffer.from(
      createPublicKey(publicKeyPem).export({ format: "pem", type: "spki" }),
      "utf8",
    );
  } catch {
    throw new Error("Probe Trust Delegation public key is malformed");
  }
}

function canonicalRsa4096PublicKeyPem(publicKeyPem, description) {
  assertRsa4096PublicKey(publicKeyPem, description);
  return canonicalPublicKeyPem(publicKeyPem);
}

function assertRsa4096PublicKey(publicKeyPem, description) {
  let key;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    throw new Error(`${description} is malformed`);
  }
  if (
    key.asymmetricKeyType !== "rsa" ||
    key.asymmetricKeyDetails?.modulusLength !== 4096
  ) {
    throw new Error(`${description} must be RSA-4096`);
  }
}

function assertRsa4096PrivateKey(privateKey, description) {
  if (
    privateKey?.type !== "private" ||
    privateKey.asymmetricKeyType !== "rsa" ||
    privateKey.asymmetricKeyDetails?.modulusLength !== 4096
  ) {
    throw new Error(`${description} must be an RSA-4096 private key`);
  }
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
    const stagedBinary = path.join(stagingDir, "enoki-probe");
    await copyFile(binaryPath, stagedBinary);
    await chmod(stagedBinary, 0o755);
    const binarySha256 = sha256(binary);
    await writeFile(
      path.join(stagingDir, "bundle-manifest.json"),
      `${JSON.stringify(
        {
          components: renderProbeBundleComponents({
            binarySha256,
            binarySize: binary.byteLength,
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
        "enoki-probe",
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
    const inspectedArchive = await inspectProbeArchive(
      path.join(archivesDir, file),
      {
        target,
        version: stableVersion,
      },
    );
    assets.push({
      bundleManifestSha256: inspectedArchive.bundleManifestSha256,
      file,
      sha256: archiveSha256,
      size: archive.byteLength,
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
  const rootPublicKey = canonicalRsa4096PublicKeyPem(
    rootPublicKeyPem,
    "Probe Distribution Trust Root public key",
  );
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
      await copyFile(path.join(archivesDir, file), path.join(stagingDir, file));
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
  bootstrapArtifactDir,
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
  const rootKeyId = sha256(
    canonicalRsa4096PublicKeyPem(
      trustedRootPublicKeyPem,
      "Probe Distribution Trust Root public key",
    ),
  );
  const bootstrap = await inspectProbeBootstrapArtifacts(bootstrapArtifactDir, {
    distribution: "enoki",
    rootKeyId,
    version,
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
      trustedRootPublicKeyPem,
    },
  );
  const hubArchiveFile = `enoki-hub-${version}.oci.tar`;
  const hubArchive = {
    archive: `hub/${hubArchiveFile}`,
    archiveSha256: await fileSha256(hubOciPath),
    digest: hubOci.digest,
    embeddedProbeVersion: probeAssetSet.version,
    size: (await stat(hubOciPath)).size,
  };
  const manifest = {
    bootstrap: {
      directory: "probe-bootstrap",
      distribution: "enoki",
      files: bootstrap.files,
      rootKeyId,
      version: version.slice(1),
    },
    candidate: identity,
    hub: hubArchive,
    kind: "enoki-release-candidate",
    probeAssetSet: {
      directory: "probe-assets",
      files: probeAssetSet.files,
      signingIdentity: probeAssetSet.signingIdentity,
      version: probeAssetSet.version,
    },
    releaseBaseline,
    schemaVersion: 3,
  };
  const stagingDir = `${outputDir}.tmp-${randomUUID()}`;

  try {
    await mkdir(path.join(stagingDir, "hub"), { recursive: true });
    await mkdir(path.join(stagingDir, "probe-bootstrap"), { recursive: true });
    await cp(probeAssetSetDir, path.join(stagingDir, "probe-assets"), {
      recursive: true,
    });
    for (const { file } of bootstrap.files) {
      await copyFile(
        path.join(bootstrapArtifactDir, file),
        path.join(stagingDir, "probe-bootstrap", file),
      );
    }
    if (releaseBaseline.kind === "enoki-release-baseline") {
      await cp(releaseBaselineDir, path.join(stagingDir, "release-baseline"), {
        recursive: true,
      });
    }
    await copyFile(hubOciPath, path.join(stagingDir, "hub", hubArchiveFile));
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
    "bootstrap",
    "candidate",
    "hub",
    "kind",
    "probeAssetSet",
    "releaseBaseline",
    "schemaVersion",
  ]);
  assertExactKeys(manifest.candidate, ["commit", "version"]);
  if (
    manifest.schemaVersion !== 3 ||
    manifest.kind !== "enoki-release-candidate"
  ) {
    throw new Error("Candidate Manifest schema or kind is unsupported");
  }
  const releaseBaseline = manifest.releaseBaseline;
  assertPlainObject(releaseBaseline, "Candidate Manifest Release Baseline");
  const expectedCandidateFiles = [
    "candidate-manifest.json",
    "hub",
    "probe-bootstrap",
    "probe-assets",
    "release-baseline",
  ];
  if (releaseBaseline.kind === "enoki-release-baseline") {
    const {
      assertReleaseBaselinePrecedesCandidate,
      validateReleaseBaselineBundle,
    } = await import("./release-baseline-lib.mjs");
    assertReleaseBaselinePrecedesCandidate({
      baselineTag: releaseBaseline.tag,
      candidateVersion: identity.version,
    });
    const inspectedBaseline = await validateReleaseBaselineBundle(
      path.join(candidateDir, "release-baseline"),
      { trustedRootPublicKeyPem },
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

  const bootstrap = manifest.bootstrap;
  assertPlainObject(bootstrap, "Candidate Manifest Probe Bootstrap");
  assertExactKeys(bootstrap, [
    "directory",
    "distribution",
    "files",
    "rootKeyId",
    "version",
  ]);
  if (
    bootstrap.directory !== "probe-bootstrap" ||
    bootstrap.distribution !== "enoki" ||
    bootstrap.version !== identity.version.slice(1) ||
    !/^[0-9a-f]{64}$/.test(bootstrap.rootKeyId)
  ) {
    throw new Error("Candidate Manifest Probe Bootstrap is malformed");
  }
  const expectedRootKeyId = sha256(
    canonicalRsa4096PublicKeyPem(
      trustedRootPublicKeyPem,
      "Probe Distribution Trust Root public key",
    ),
  );
  if (bootstrap.rootKeyId !== expectedRootKeyId) {
    throw new Error(
      "Candidate Manifest Probe Bootstrap root key does not match trusted root",
    );
  }
  const inspectedBootstrap = await inspectProbeBootstrapCandidateDirectory(
    path.join(candidateDir, bootstrap.directory),
    {
      distribution: bootstrap.distribution,
      rootKeyId: bootstrap.rootKeyId,
      version: identity.version,
    },
  );
  if (
    JSON.stringify(inspectedBootstrap.files) !== JSON.stringify(bootstrap.files)
  ) {
    throw new Error(
      "Candidate Manifest Probe Bootstrap file identities do not match content",
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

  return manifest;
}

async function inspectProbeBootstrapArtifacts(
  artifactDir,
  { distribution, rootKeyId, version },
) {
  if (typeof artifactDir !== "string") {
    throw new Error("Probe Bootstrap artifact directory is required");
  }
  const expectedInputs = probeBootstrapTargets
    .flatMap((target) => {
      const archive = `enoki-probe-bootstrap-${target}.tar.gz`;
      return [archive, `${archive}.sha256`];
    })
    .sort();
  assertSameFileNames(
    (await readdir(artifactDir)).sort(),
    expectedInputs,
    "Probe Bootstrap build artifact directory",
  );
  const files = [];
  for (const target of probeBootstrapTargets) {
    const file = `enoki-probe-bootstrap-${target}.tar.gz`;
    const archivePath = path.join(artifactDir, file);
    const archive = await readFile(archivePath);
    const checksum = await readFile(`${archivePath}.sha256`, "utf8");
    const digest = sha256(archive);
    if (checksum !== `${digest}  ${file}\n`) {
      throw new Error(
        `Probe Bootstrap checksum sidecar does not match ${file}`,
      );
    }
    await inspectProbeBootstrapArtifact({
      archivePath,
      distribution,
      rootKeyId,
      target,
      version,
    });
    files.push({ file, sha256: digest, size: archive.byteLength, target });
  }
  return { files };
}

async function inspectProbeBootstrapCandidateDirectory(
  candidateDir,
  { distribution, rootKeyId, version },
) {
  const expectedFiles = probeBootstrapTargets
    .map((target) => `enoki-probe-bootstrap-${target}.tar.gz`)
    .sort();
  assertSameFileNames(
    (await readdir(candidateDir)).sort(),
    expectedFiles,
    "Candidate Probe Bootstrap directory",
  );
  const files = [];
  for (const target of probeBootstrapTargets) {
    const file = `enoki-probe-bootstrap-${target}.tar.gz`;
    const archivePath = path.join(candidateDir, file);
    const archive = await readFile(archivePath);
    await inspectProbeBootstrapArtifact({
      archivePath,
      distribution,
      rootKeyId,
      target,
      version,
    });
    files.push({
      file,
      sha256: sha256(archive),
      size: archive.byteLength,
      target,
    });
  }
  return { files };
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
  ].sort();
  assertSameFileNames(
    (await readdir(assetDir)).sort(),
    expectedFiles,
    "Probe Asset Set",
  );

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
  const rootPublicKey = await readFile(path.join(assetDir, "root-key.pem"));
  const canonicalRootPublicKey = canonicalRsa4096PublicKeyPem(
    rootPublicKey,
    "Probe Asset Set root public key",
  );
  if (
    trustedRootPublicKeyPem === undefined &&
    trustedRootPublicKeySha256 === undefined
  ) {
    throw new Error(
      "Probe Asset Set verification requires an external Probe Distribution Trust Root",
    );
  }
  const trustedRootPublicKey = trustedRootPublicKeyPem
    ? canonicalRsa4096PublicKeyPem(
        trustedRootPublicKeyPem,
        "Probe Distribution Trust Root public key",
      )
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
    signingIdentity: {
      algorithm: "rsa-sha256",
      publicKeyFile: "signing-key.pem",
      publicKeySha256,
    },
    version: manifest.version,
  };
}

function assertSigningPublicKey(publicKeyPem) {
  assertRsa4096PublicKey(publicKeyPem, "Probe asset signing public key");
}

async function inspectProbeArchive(
  archivePath,
  { requireEmbeddedProbeIdentity = true, target, version },
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
    ]
      .sort()
      .join("\n");
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
    const componentDetails = await readProbeBundleComponentDetails(
      extractionDir,
      probeBundleComponentProfiles,
    );
    const bundleManifest = await readFile(manifestPath);
    validateProbeBundleManifest(bundleManifest, {
      componentDetails,
      target,
      version: version.slice(1),
    });
    return { bundleManifestSha256: sha256(bundleManifest) };
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
  { componentDetails, target, version },
) {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("Probe bundle manifest is malformed");
  }
  assertPlainObject(manifest, "Probe bundle manifest");
  assertExactKeys(manifest, ["components", "kind", "target", "version"]);
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
      component.sha256 !== componentDetails.get(profile.path)?.sha256 ||
      !Number.isSafeInteger(component.size) ||
      component.size <= 0 ||
      component.size !== componentDetails.get(profile.path)?.size ||
      component.version !== version
    ) {
      throw new Error("Probe bundle component is incoherent");
    }
  }
}

function renderProbeBundleComponents({ binarySha256, binarySize, version }) {
  return Object.entries(probeBundleComponentProfiles).map(
    ([role, profile]) => ({
      ...profile,
      role,
      sha256: binarySha256,
      size: binarySize,
      version,
    }),
  );
}

function inspectProbeElf(
  binary,
  { requireEmbeddedProbeIdentity = true, target, version },
) {
  const archiveTarget = `enoki-probe-${target}.tar.gz`;
  if (
    binary.length < 64 ||
    !binary.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||
    binary[4] !== 2 ||
    binary[5] !== 1
  ) {
    throw new Error(
      `${archiveTarget} payload must be a 64-bit little-endian ELF`,
    );
  }

  const expectedMachine = target.startsWith("x86_64-") ? 62 : 183;
  if (binary.readUInt16LE(18) !== expectedMachine) {
    throw new Error(
      `${archiveTarget} ELF architecture does not match ${target}`,
    );
  }

  const contents = binary.toString("latin1");
  if (
    requireEmbeddedProbeIdentity &&
    !contents.includes(`ENOKI_PROBE_TARGET=${target}\0`)
  ) {
    throw new Error(
      `${archiveTarget} embedded target does not match ${target}`,
    );
  }
  if (
    requireEmbeddedProbeIdentity &&
    !contents.includes(`ENOKI_PROBE_VERSION=${version}\0`)
  ) {
    throw new Error(
      `${archiveTarget} embedded Probe version does not match ${version}`,
    );
  }

  const interpreter = elfInterpreter(binary);
  const expectedLoader = dynamicLoaderByProbeTarget[target];
  const staticMuslBinary = target.endsWith("-musl") && !interpreter;
  if (!staticMuslBinary && interpreter !== expectedLoader) {
    throw new Error(`${archiveTarget} ELF ABI does not match ${target}`);
  }
}

function elfInterpreter(binary) {
  const programHeaderOffset = Number(binary.readBigUInt64LE(32));
  const programHeaderSize = binary.readUInt16LE(54);
  const programHeaderCount = binary.readUInt16LE(56);
  if (
    !Number.isSafeInteger(programHeaderOffset) ||
    programHeaderSize < 56 ||
    programHeaderOffset + programHeaderSize * programHeaderCount > binary.length
  ) {
    throw new Error("Probe ELF program headers are malformed");
  }

  for (let index = 0; index < programHeaderCount; index += 1) {
    const offset = programHeaderOffset + index * programHeaderSize;
    if (binary.readUInt32LE(offset) !== 3) {
      continue;
    }
    const stringOffset = Number(binary.readBigUInt64LE(offset + 8));
    const stringSize = Number(binary.readBigUInt64LE(offset + 32));
    if (
      !Number.isSafeInteger(stringOffset) ||
      !Number.isSafeInteger(stringSize) ||
      stringSize < 2 ||
      stringOffset + stringSize > binary.length
    ) {
      throw new Error("Probe ELF interpreter is malformed");
    }
    const interpreter = binary
      .subarray(stringOffset, stringOffset + stringSize)
      .toString("utf8");
    if (
      !interpreter.endsWith("\0") ||
      interpreter.slice(0, -1).includes("\0")
    ) {
      throw new Error("Probe ELF interpreter is malformed");
    }
    return interpreter.slice(0, -1);
  }
  return undefined;
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
  assertRsa4096PrivateKey(privateKey, "Probe asset signing key");

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
