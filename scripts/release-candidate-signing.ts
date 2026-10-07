// 候选签名 producer 与四个正式签名动作 CLI 入口的唯一实现：校验签名身份、合成并
// 准备未签名 Probe Asset Set、对其签名。离线验收检验复用 verification.ts，不在此重复。
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
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import {
  canonicalPublicKeyPem,
  probeBundleComponentProfiles,
  probeBundledBootstrapAssets,
  probeTargets,
  verifyProbeTrustDelegation,
} from "@enoki/probe-release";

import {
  probeBootstrapTargets,
  withVerifiedProbeBootstrapArtifact,
  type ProbeBootstrapArchiveExpectation,
  type VerifiedProbeBootstrapArtifact,
} from "./probe-bootstrap-inspection.ts";
import {
  assertSameFileNames,
  inspectProbeArchive,
  inspectProbeAssetSet,
  readProbeBundleComponentDetails,
  sha256,
  untrustedToolEnvironment,
  validateCandidateIdentity,
} from "./release-candidate-verification.ts";
import {
  assertAllowedOptions,
  parseCommandLine,
  regexInput,
  requiredOption,
  type CommandLineOptions,
} from "./release-json-guards.ts";

const execFileAsync = promisify(execFile);

type ProbeBundleComponentDetails = Map<
  string,
  { sha256: string; size: number }
>;

export function validateProbeSigningIdentity({
  privateKeyPem,
  publicKeyPem,
}: {
  privateKeyPem: Buffer | string | undefined;
  publicKeyPem: Buffer | string | undefined;
}) {
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
}: {
  delegationBytes: Buffer;
  delegationSignature: Buffer;
  distribution: string;
  highestAcceptedGeneration?: number;
  privateKeyPem: Buffer | string | undefined;
  publicKeyPem: Buffer | string | undefined;
  rootPublicKeyPem: Buffer | string;
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

export function renderProbeBundleComponentsFromDetails({
  componentDetails,
  version,
}: {
  componentDetails: ProbeBundleComponentDetails;
  version: string;
}) {
  return Object.entries(probeBundleComponentProfiles).map(
    ([role, profile]) => ({
      ...profile,
      role,
      sha256: componentDetail(componentDetails, profile.path).sha256,
      size: componentDetail(componentDetails, profile.path).size,
      version,
    }),
  );
}

function renderBundledBootstrapAssets({
  componentDetails,
  version,
}: {
  componentDetails: ProbeBundleComponentDetails;
  version: string;
}) {
  return probeBundledBootstrapAssets.map(
    ({ archivePath, permissionProfile, role }) => ({
      path: archivePath,
      permissionProfile,
      role,
      sha256: componentDetail(componentDetails, archivePath).sha256,
      size: componentDetail(componentDetails, archivePath).size,
      version,
    }),
  );
}

function componentDetail(
  componentDetails: ProbeBundleComponentDetails,
  componentPath: string,
): { sha256: string; size: number } {
  const details = componentDetails.get(componentPath);
  if (details === undefined) {
    throw new Error("Probe bundle component details are incomplete");
  }
  return details;
}

function assertSigningPublicKey(publicKeyPem: Buffer | string): void {
  try {
    createPublicKey(publicKeyPem);
  } catch {
    throw new Error("Probe asset signing public key is malformed");
  }
}

function assertSigningKeyPair(
  privateKeyPem: Buffer | string,
  publicKeyPem: Buffer | string,
): void {
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
}: {
  bootstrapArchivePath: string;
  bootstrapExpectedArchive: ProbeBootstrapArchiveExpectation;
  distribution: string;
  outputPath: string;
  rootKeyId: string;
  runtimeArchivePath: string;
  sourceDateEpoch: string;
  target: string;
  version: string;
}): Promise<void> {
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
      async ({ extractedRoles }: VerifiedProbeBootstrapArtifact) => {
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
}: {
  archivesDir: string;
  bootstrapArchivesDir: string | undefined;
  delegationBytes: Buffer;
  delegationSignature: Buffer;
  distribution: string;
  outputDir: string;
  publicKeyPem: Buffer | string | undefined;
  rootPublicKeyPem: Buffer | string;
  version: string;
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

  const assets: {
    bundleManifestSha256: string;
    file: string;
    sha256: string;
    size: number;
    target: string;
  }[] = [];
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
}: {
  expectedDelegationBytes: Buffer | undefined;
  expectedDelegationSignature: Buffer | undefined;
  outputDir: string;
  privateKeyPem: Buffer | string | undefined;
  trustedRootPublicKeyPem: Buffer | string | undefined;
  unsignedAssetDir: string;
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
      // inspected.version 只有已通过 stable SemVer 校验的字符串才会返回，
      // regexInput 仅满足 unknown 的静态收窄，不改变任何取值。
      expectedVersion: regexInput(inspected.version),
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
    version: `v${regexInput(inspected.version)}`,
  };
}

type SigningCommandInput = {
  argv: readonly string[];
  environment: NodeJS.ProcessEnv;
};

export async function runValidateSigningIdentityCommand({
  argv,
  environment,
}: SigningCommandInput): Promise<string> {
  const { command, options } = parseCommandLine(argv);
  assertAllowedOptions(command, options, [
    "--private-key-env",
    "--public-key-env",
    "--root-public-key-env",
    "--distribution",
    "--trust-delegation",
    "--trust-delegation-signature",
  ]);
  const privateKeyEnvironment = requiredOption(options, "--private-key-env");
  const publicKeyEnvironment = requiredOption(options, "--public-key-env");
  const identity = validateDelegatedProbeSigningIdentity({
    delegationBytes: await readFile(
      requiredOption(options, "--trust-delegation"),
    ),
    delegationSignature: await readFile(
      requiredOption(options, "--trust-delegation-signature"),
    ),
    distribution: requiredOption(options, "--distribution"),
    privateKeyPem: environment[privateKeyEnvironment],
    publicKeyPem: environment[publicKeyEnvironment],
    rootPublicKeyPem: trustedRootPem(options, environment),
  });

  return `Probe asset signing identity is valid: ${identity.publicKeySha256}`;
}

export async function runPrepareUnsignedProbeAssetsCommand({
  argv,
  environment,
}: SigningCommandInput): Promise<string> {
  const { command, options } = parseCommandLine(argv);
  assertAllowedOptions(command, options, [
    "--archives-dir",
    "--bootstrap-archives-dir",
    "--output",
    "--public-key-env",
    "--root-public-key-env",
    "--distribution",
    "--trust-delegation",
    "--trust-delegation-signature",
    "--version",
  ]);
  const publicKeyEnvironment = requiredOption(options, "--public-key-env");
  const result = await prepareUnsignedProbeAssetSet({
    archivesDir: requiredOption(options, "--archives-dir"),
    bootstrapArchivesDir: requiredOption(options, "--bootstrap-archives-dir"),
    delegationBytes: await readFile(
      requiredOption(options, "--trust-delegation"),
    ),
    delegationSignature: await readFile(
      requiredOption(options, "--trust-delegation-signature"),
    ),
    distribution: requiredOption(options, "--distribution"),
    outputDir: requiredOption(options, "--output"),
    publicKeyPem: environment[publicKeyEnvironment],
    rootPublicKeyPem: trustedRootPem(options, environment),
    version: requiredOption(options, "--version"),
  });

  return `prepared unsigned Probe Asset Set ${result.version} at ${result.outputDir}`;
}

export async function runSignProbeAssetsCommand({
  argv,
  environment,
}: SigningCommandInput): Promise<string> {
  const { command, options } = parseCommandLine(argv);
  assertAllowedOptions(command, options, [
    "--input",
    "--output",
    "--private-key-env",
    "--root-public-key-env",
    "--trust-delegation",
    "--trust-delegation-signature",
  ]);
  const privateKeyEnvironment = requiredOption(options, "--private-key-env");
  const result = await signProbeAssetSet({
    expectedDelegationBytes: await readFile(
      requiredOption(options, "--trust-delegation"),
    ),
    expectedDelegationSignature: await readFile(
      requiredOption(options, "--trust-delegation-signature"),
    ),
    outputDir: requiredOption(options, "--output"),
    privateKeyPem: environment[privateKeyEnvironment],
    trustedRootPublicKeyPem:
      environment[requiredOption(options, "--root-public-key-env")],
    unsignedAssetDir: requiredOption(options, "--input"),
  });

  return `signed Probe Asset Set ${result.version} at ${result.outputDir}`;
}

export async function runValidateProbeAssetsCommand({
  argv,
  environment,
}: SigningCommandInput): Promise<string> {
  const assetDir = argv[1];
  const rootPublicKeyEnvironment = argv[3];
  if (
    argv.length !== 4 ||
    argv[2] !== "--root-public-key-env" ||
    assetDir === undefined ||
    rootPublicKeyEnvironment === undefined
  ) {
    throw new Error(
      "validate-probe-assets requires an Asset Set directory and --root-public-key-env",
    );
  }
  const probe = await inspectProbeAssetSet(assetDir, {
    trustedRootPublicKeyPem: environment[rootPublicKeyEnvironment],
  });

  return `Probe Asset Set is valid: ${probe.version} ${probe.signingIdentity.publicKeySha256}`;
}

// --root-public-key-env 未设置时原行为是把缺失值交给共享包的 PEM 守卫报错；该
// 守卫对 undefined 与空串走同一 catch，共享包声明只接受 string|Buffer，故取空串。
function trustedRootPem(
  options: CommandLineOptions,
  environment: NodeJS.ProcessEnv,
): string {
  return environment[requiredOption(options, "--root-public-key-env")] ?? "";
}
