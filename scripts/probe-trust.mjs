#!/usr/bin/env node

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPair,
} from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import {
  createProbeTrustDelegation,
  verifyProbeTrustDelegation,
} from "@enoki/probe-release";

import {
  assertAllowedOptions,
  parseCommandLine,
  requiredOption,
} from "./release-candidate-lib.mjs";

const generateKeyPairAsync = promisify(generateKeyPair);

process.umask(0o077);

try {
  const { command, options } = parseCommandLine(process.argv.slice(2));

  if (command === "init-root") {
    assertAllowedOptions(command, options, [
      "--output-dir",
      "--passphrase-file",
    ]);
    const result = await initializeRoot({
      outputDir: requiredOption(options, "--output-dir"),
      passphrase: await readPassphraseFile(
        requiredOption(options, "--passphrase-file"),
      ),
    });
    process.stdout.write(
      `initialized Probe Distribution Trust Root: ${result.keyId}\n`,
    );
  } else if (command === "init-release-key") {
    assertAllowedOptions(command, options, ["--output-dir"]);
    const result = await initializeReleaseKey({
      outputDir: requiredOption(options, "--output-dir"),
    });
    process.stdout.write(
      `initialized Probe Asset Signing Identity: ${result.keyId}\n`,
    );
  } else if (command === "authorize-release-key") {
    assertAllowedOptions(command, options, [
      "--generation",
      "--output-dir",
      "--release-public-key",
      "--root-passphrase-file",
      "--root-private-key",
    ]);
    const generation = parseGeneration(requiredOption(options, "--generation"));
    const rootPassphrase = await readPassphraseFile(
      requiredOption(options, "--root-passphrase-file"),
    );
    let rootPrivateKeyPem;
    try {
      rootPrivateKeyPem = await readPrivateKeyFile(
        requiredOption(options, "--root-private-key"),
      );
      const result = await authorizeReleaseKey({
        generation,
        outputDir: requiredOption(options, "--output-dir"),
        releasePublicKeyPem: await readRegularFile(
          requiredOption(options, "--release-public-key"),
        ),
        rootPassphrase,
        rootPrivateKeyPem,
      });
      process.stdout.write(
        `authorized Probe Asset Signing Identity: ${result.keyId} generation ${result.generation}\n`,
      );
    } finally {
      rootPassphrase.fill(0);
      rootPrivateKeyPem?.fill(0);
    }
  } else if (command === "verify") {
    assertAllowedOptions(command, options, [
      "--delegation",
      "--highest-accepted-generation",
      "--root-public-key",
      "--signature",
    ]);
    const rootPublicKeyPem = await readRegularFile(
      requiredOption(options, "--root-public-key"),
    );
    assertRsa4096(createPublicKey(rootPublicKeyPem), "root signing identity");
    const delegation = verifyProbeTrustDelegation({
      bytes: await readRegularFile(requiredOption(options, "--delegation")),
      highestAcceptedGeneration: parseHighestAcceptedGeneration(
        requiredOption(options, "--highest-accepted-generation"),
      ),
      expectedDistribution: "enoki",
      expectedPurpose: "probe-asset-signing",
      rootPublicKeyPem,
      signature: await readRegularFile(requiredOption(options, "--signature")),
    });
    assertRsa4096(
      createPublicKey(delegation.signingIdentity.publicKeyPem),
      "release signing identity",
    );
    process.stdout.write(
      `verified Probe Trust Delegation: ${delegation.signingIdentity.keyId} generation ${delegation.generation}\n`,
    );
  } else {
    throw new Error(`unknown command: ${command ?? "<missing>"}`);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "command failed";
  process.stderr.write(`probe-trust: ${message}\n`);
  process.exitCode = 1;
}

async function initializeRoot({ outputDir, passphrase }) {
  let target;
  try {
    target = await createPrivateOutputDirectory(outputDir);
    const keyPair = await generateKeyPairAsync("rsa", {
      modulusLength: 4096,
      privateKeyEncoding: {
        cipher: "aes-256-cbc",
        format: "pem",
        passphrase,
        type: "pkcs8",
      },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    await writeFile(
      path.join(target.stagingDir, "root-private-key.pem"),
      keyPair.privateKey,
      {
        mode: 0o600,
      },
    );
    await writeFile(
      path.join(target.stagingDir, "root-public-key.pem"),
      keyPair.publicKey,
      {
        mode: 0o644,
      },
    );
    await chmod(path.join(target.stagingDir, "root-public-key.pem"), 0o644);
    await publishOutputDirectory(target, [
      "root-private-key.pem",
      "root-public-key.pem",
    ]);
    return { keyId: sha256(keyPair.publicKey) };
  } catch (error) {
    if (target) await rm(target.stagingDir, { force: true, recursive: true });
    throw error;
  } finally {
    passphrase.fill(0);
  }
}

async function initializeReleaseKey({ outputDir }) {
  const target = await createPrivateOutputDirectory(outputDir);
  try {
    const keyPair = await generateKeyPairAsync("rsa", {
      modulusLength: 4096,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    await writeFile(
      path.join(target.stagingDir, "release-private-key.pem"),
      keyPair.privateKey,
      { mode: 0o600 },
    );
    await writeFile(
      path.join(target.stagingDir, "release-public-key.pem"),
      keyPair.publicKey,
      { mode: 0o644 },
    );
    await chmod(path.join(target.stagingDir, "release-public-key.pem"), 0o644);
    await publishOutputDirectory(target, [
      "release-private-key.pem",
      "release-public-key.pem",
    ]);
    return { keyId: sha256(keyPair.publicKey) };
  } catch (error) {
    await rm(target.stagingDir, { force: true, recursive: true });
    throw error;
  }
}

async function authorizeReleaseKey({
  generation,
  outputDir,
  releasePublicKeyPem,
  rootPassphrase,
  rootPrivateKeyPem,
}) {
  try {
    const rootPrivateKey = decryptRootPrivateKey({
      privateKeyPem: rootPrivateKeyPem,
      passphrase: rootPassphrase,
    });
    assertRsa4096(rootPrivateKey, "root signing identity");
    const releasePublicKey = createPublicKey(releasePublicKeyPem);
    assertRsa4096(releasePublicKey, "release signing identity");
    const rootPublicKeyPem = Buffer.from(
      createPublicKey(rootPrivateKey).export({ format: "pem", type: "spki" }),
      "utf8",
    );
    const delegation = createProbeTrustDelegation({
      distribution: "enoki",
      generation,
      releasePublicKeyPem,
      rootPrivateKey,
    });
    const target = await createPrivateOutputDirectory(outputDir);
    try {
      const delegationPath = path.join(
        target.stagingDir,
        "trust-delegation.json",
      );
      const signaturePath = path.join(
        target.stagingDir,
        "trust-delegation.json.sig",
      );
      await writeFile(delegationPath, delegation.bytes, { mode: 0o644 });
      await writeFile(signaturePath, delegation.signature, { mode: 0o644 });
      await chmod(delegationPath, 0o644);
      await chmod(signaturePath, 0o644);
      verifyProbeTrustDelegation({
        bytes: await readRegularFile(delegationPath),
        expectedDistribution: "enoki",
        expectedPurpose: "probe-asset-signing",
        highestAcceptedGeneration: generation,
        rootPublicKeyPem,
        signature: await readRegularFile(signaturePath),
      });
      await publishOutputDirectory(target, [
        "trust-delegation.json",
        "trust-delegation.json.sig",
      ]);
      return {
        generation: delegation.delegation.generation,
        keyId: delegation.delegation.signingIdentity.keyId,
      };
    } catch (error) {
      await rm(target.stagingDir, { force: true, recursive: true });
      throw error;
    }
  } finally {
    rootPassphrase.fill(0);
    rootPrivateKeyPem.fill(0);
  }
}

async function readPassphraseFile(filePath) {
  const { bytes: passphrase, status } = await readRegularFileWithStatus(
    filePath,
    "passphrase file",
  );
  try {
    if ((status.mode & 0o077) !== 0) {
      throw new Error(
        "passphrase file permissions must not be wider than 0600",
      );
    }
    if (status.nlink !== 1) {
      throw new Error("passphrase file must have exactly one hard link");
    }
    const length =
      passphrase.byteLength > 1 &&
      passphrase.at(-2) === 13 &&
      passphrase.at(-1) === 10
        ? passphrase.byteLength - 2
        : passphrase.byteLength > 0 && passphrase.at(-1) === 10
          ? passphrase.byteLength - 1
          : passphrase.byteLength;
    const normalized = Buffer.from(passphrase.subarray(0, length));
    if (normalized.byteLength < 32) {
      normalized.fill(0);
      throw new Error(
        "passphrase file must contain at least 32 CSPRNG-random bytes after its optional line ending",
      );
    }
    return normalized;
  } finally {
    passphrase.fill(0);
  }
}

async function readPrivateKeyFile(filePath) {
  const { bytes, status } = await readRegularFileWithStatus(
    filePath,
    "private key file",
  );
  try {
    if ((status.mode & 0o077) !== 0) {
      throw new Error(
        "private key file permissions must not be wider than 0600",
      );
    }
    if (status.nlink !== 1) {
      throw new Error("private key file must have exactly one hard link");
    }
    return bytes;
  } catch (error) {
    bytes.fill(0);
    throw error;
  }
}

function assertRsa4096(key, label) {
  if (
    key.asymmetricKeyType !== "rsa" ||
    key.asymmetricKeyDetails?.modulusLength !== 4096
  ) {
    throw new Error(`${label} must be RSA-4096`);
  }
}

async function readRegularFile(filePath) {
  return (await readRegularFileWithStatus(filePath, "input file")).bytes;
}

async function readRegularFileWithStatus(filePath, label) {
  const handle = await open(
    filePath,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  ).catch((error) => {
    if (error?.code === "ENOENT") throw new Error(`${label} does not exist`);
    if (error?.code === "ELOOP") {
      throw new Error(`${label} must be a regular non-symbolic-link file`);
    }
    throw error;
  });
  try {
    const status = await handle.stat();
    if (!status.isFile()) {
      throw new Error(`${label} must be a regular non-symbolic-link file`);
    }
    return { bytes: await handle.readFile(), status };
  } finally {
    await handle.close();
  }
}

function decryptRootPrivateKey({ privateKeyPem, passphrase }) {
  if (
    !privateKeyPem
      .toString("utf8")
      .startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
  ) {
    throw new Error("root private key must be an encrypted PKCS#8 PEM file");
  }
  try {
    return createPrivateKey({
      format: "pem",
      key: privateKeyPem,
      passphrase,
      type: "pkcs8",
    });
  } catch {
    throw new Error("root private key could not be unlocked");
  }
}

function parseGeneration(value) {
  if (!/^[1-9]\d*$/.test(value)) {
    throw new Error(
      "generation must be a safe integer greater than or equal to 1",
    );
  }
  const generation = Number(value);
  if (!Number.isSafeInteger(generation)) {
    throw new Error(
      "generation must be a safe integer greater than or equal to 1",
    );
  }
  return generation;
}

function parseHighestAcceptedGeneration(value) {
  if (!/^(?:0|[1-9]\d*)$/.test(value)) {
    throw new Error(
      "highest accepted generation must be a safe non-negative integer",
    );
  }
  const generation = Number(value);
  if (!Number.isSafeInteger(generation)) {
    throw new Error(
      "highest accepted generation must be a safe non-negative integer",
    );
  }
  return generation;
}

async function createPrivateOutputDirectory(outputDir) {
  const absoluteOutputDir = path.resolve(outputDir);
  await assertSafeDirectoryPath(path.dirname(absoluteOutputDir));
  const targetStatus = await lstat(absoluteOutputDir).catch((error) => {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  });
  if (targetStatus) throw new Error("output directory already exists");
  const stagingDir = await mkdtemp(
    path.join(
      path.dirname(absoluteOutputDir),
      `.${path.basename(absoluteOutputDir)}.staging-`,
    ),
  );
  await chmod(stagingDir, 0o700);
  return { outputDir: absoluteOutputDir, stagingDir };
}

async function publishOutputDirectory(target, fileNames) {
  let published = false;
  try {
    for (const fileName of fileNames) {
      await syncPath(path.join(target.stagingDir, fileName));
    }
    await syncPath(target.stagingDir);
    await rename(target.stagingDir, target.outputDir);
    published = true;
    try {
      await syncPath(path.dirname(target.outputDir));
    } catch (error) {
      throw new Error(
        "output was fully published but parent directory fsync failed; inspect the output instead of rerunning the ceremony",
        { cause: error },
      );
    }
  } catch (error) {
    if (!published) {
      await rm(target.stagingDir, { force: true, recursive: true });
    }
    throw error;
  }
}

async function syncPath(filePath) {
  const handle = await open(filePath, constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function assertSafeDirectoryPath(directoryPath) {
  const parsed = path.parse(directoryPath);
  if (directoryPath === parsed.root) {
    throw new Error(
      "ceremony output must use a dedicated private parent rather than the filesystem root",
    );
  }
  let current = parsed.root;
  for (const segment of directoryPath
    .slice(parsed.root.length)
    .split(path.sep)) {
    if (!segment) continue;
    current = path.join(current, segment);
    const status = await lstat(current);
    if (status.isSymbolicLink() || !status.isDirectory()) {
      throw new Error(
        "output directory parent must not contain symbolic links or non-directories",
      );
    }
    const ownedByCurrentProcessOrRoot =
      status.uid === process.getuid?.() || status.uid === 0;
    const isTrustedStickySystemDirectory =
      status.uid === 0 && (status.mode & 0o1000) !== 0;
    if (
      !ownedByCurrentProcessOrRoot ||
      ((status.mode & 0o022) !== 0 && !isTrustedStickySystemDirectory)
    ) {
      throw new Error(
        "output directory parent must be owned by the current user or root and not shared writable",
      );
    }
    if (
      current === directoryPath &&
      (status.uid !== process.getuid?.() || (status.mode & 0o777) !== 0o700)
    ) {
      throw new Error(
        "ceremony output parent must be current-user-owned mode 0700 for no-replace publication",
      );
    }
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
