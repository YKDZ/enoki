import { execFile } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { probeTargets } from "./probe-asset-bundle.mjs";
import { readRegularFileSnapshot } from "./regular-file-snapshot.mjs";

const execFileAsync = promisify(execFile);
const MAX_LEGACY_PROBE_ARCHIVE_BYTES = 1024 * 1024 * 1024;
const dynamicLoaderByProbeTarget = Object.freeze({
  "aarch64-unknown-linux-gnu": "/lib/ld-linux-aarch64.so.1",
  "aarch64-unknown-linux-musl": "/lib/ld-musl-aarch64.so.1",
  "x86_64-unknown-linux-gnu": "/lib64/ld-linux-x86-64.so.2",
  "x86_64-unknown-linux-musl": "/lib/ld-musl-x86_64.so.1",
});

export async function inspectLegacyProbeAssetSet(
  assetDir,
  { expectedAssets, expectedSigningKeySha256, expectedVersion },
) {
  if (!Array.isArray(expectedAssets) || expectedAssets.length === 0) {
    throw new Error("legacy Probe Asset Set authorization is incomplete");
  }
  const expectedFiles = expectedAssets
    .map((asset) => {
      assertPlainObject(asset, "legacy Probe Asset Set authorized asset");
      assertExactKeys(asset, ["name", "sha256", "size"]);
      if (
        typeof asset.name !== "string" ||
        path.basename(asset.name) !== asset.name ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(asset.name) ||
        !/^[0-9a-f]{64}$/.test(asset.sha256) ||
        !Number.isSafeInteger(asset.size) ||
        asset.size < 1 ||
        asset.size > MAX_LEGACY_PROBE_ARCHIVE_BYTES
      ) {
        throw new Error("legacy Probe Asset Set authorization is invalid");
      }
      return asset.name;
    })
    .sort();
  if (new Set(expectedFiles).size !== expectedFiles.length) {
    throw new Error("legacy Probe Asset Set authorization is invalid");
  }
  assertSameFileNames(
    (await readdir(assetDir)).sort(),
    expectedFiles,
    "legacy Probe Asset Set",
  );
  for (const asset of expectedAssets) {
    if (
      probeTargets.some(
        (target) => asset.name === `enoki-probe-${target}.tar.gz`,
      )
    ) {
      // 每个 archive 在签名 manifest 已经通过之后由下面同一段受控
      // bytes 路径验证。这里若提前按路径哈希，之后再打开 archive 会重新
      // 引入 pathname TOCTOU。
      continue;
    }
    const assetPath = path.join(assetDir, asset.name);
    const details = await stat(assetPath);
    if (
      !details.isFile() ||
      details.size !== asset.size ||
      (await fileSha256(assetPath)) !== asset.sha256
    ) {
      throw new Error(
        `legacy Probe Asset Set authorized asset does not match ${asset.name}`,
      );
    }
  }

  const manifestBytes = await readFile(path.join(assetDir, "manifest.json"));
  const signingKey = await readFile(path.join(assetDir, "signing-key.pem"));
  if (sha256(signingKey) !== expectedSigningKeySha256) {
    throw new Error("legacy Probe Asset Set signing identity does not match");
  }
  let signatureValid = false;
  try {
    signatureValid = verify(
      "RSA-SHA256",
      manifestBytes,
      createPublicKey(signingKey),
      await readFile(path.join(assetDir, "manifest.json.sig")),
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    throw new Error("legacy Probe Asset Set manifest signature is invalid");
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error("legacy Probe Asset Set manifest is malformed");
  }
  assertPlainObject(manifest, "legacy Probe Asset Set manifest");
  assertExactKeys(manifest, ["assets", "kind", "signature", "version"]);
  assertPlainObject(
    manifest.signature,
    "legacy Probe Asset Set signature descriptor",
  );
  assertExactKeys(manifest.signature, ["algorithm", "file", "publicKey"]);
  if (
    manifest.kind !== "enoki-probe-assets" ||
    manifest.version !== expectedVersion ||
    manifest.signature.algorithm !== "rsa-sha256" ||
    manifest.signature.file !== "manifest.json.sig" ||
    manifest.signature.publicKey !== "signing-key.pem" ||
    !Array.isArray(manifest.assets) ||
    manifest.assets.length !== probeTargets.length
  ) {
    throw new Error("legacy Probe Asset Set manifest is invalid");
  }

  const probeComponents = [];
  for (let index = 0; index < probeTargets.length; index += 1) {
    const target = probeTargets[index];
    const asset = manifest.assets[index];
    assertPlainObject(asset, `legacy Probe Asset Set target ${target}`);
    assertExactKeys(asset, ["file", "sha256", "size", "target"]);
    const file = `enoki-probe-${target}.tar.gz`;
    if (
      asset.file !== file ||
      asset.target !== target ||
      !/^[0-9a-f]{64}$/.test(asset.sha256) ||
      !Number.isSafeInteger(asset.size) ||
      asset.size < 1 ||
      asset.size > MAX_LEGACY_PROBE_ARCHIVE_BYTES
    ) {
      throw new Error(`legacy Probe Asset Set target ${target} is invalid`);
    }
    const archivePath = path.join(assetDir, file);
    const authorizedAsset = expectedAssets.find(
      (expected) => expected.name === file,
    );
    if (!authorizedAsset || asset.size !== authorizedAsset.size) {
      throw new Error(`legacy Probe Asset Set archive does not match ${file}`);
    }
    const archive = await readRegularFileSnapshot(
      archivePath,
      "legacy Probe Asset Set archive",
      {
        expectedSize: asset.size,
        maximumSize: MAX_LEGACY_PROBE_ARCHIVE_BYTES,
      },
    ).catch(() => {
      throw new Error("legacy Probe Asset Set archive does not match");
    });
    if (
      sha256(archive.bytes) !== asset.sha256 ||
      sha256(archive.bytes) !== authorizedAsset.sha256
    ) {
      throw new Error(`legacy Probe Asset Set archive does not match ${file}`);
    }
    if (
      (await readFile(`${archivePath}.sha256`, "utf8")) !==
      `${asset.sha256}  ${file}\n`
    ) {
      throw new Error(`legacy Probe Asset Set sidecar does not match ${file}`);
    }
    probeComponents.push({
      file: "enoki-probe",
      role: "probe",
      sha256: await inspectLegacyProbeArchive(archive.bytes, {
        archiveName: file,
        target,
        version: `v${manifest.version}`,
      }),
      target,
    });
  }
  const installer = await readFile(
    path.join(assetDir, "install-probe.sh"),
    "utf8",
  );
  if (!installer.includes(expectedSigningKeySha256)) {
    throw new Error("legacy Probe installer does not pin its signing identity");
  }
  return {
    assetSetManifestSha256: sha256(manifestBytes),
    probeComponents,
    version: manifest.version,
  };
}

async function inspectLegacyProbeArchive(
  archive,
  { archiveName, target, version },
) {
  const extractionDir = await mkdtemp(
    path.join(tmpdir(), "enoki-legacy-probe-archive-"),
  );
  try {
    const archivePath = path.join(extractionDir, "archive.tar.gz");
    await writeFile(archivePath, archive, { mode: 0o600 });
    let listing;
    try {
      ({ stdout: listing } = await execFileAsync(
        "tar",
        ["--list", "--gzip", "--file", archivePath],
        { env: untrustedToolEnvironment(), maxBuffer: 1024 * 1024 },
      ));
    } catch {
      throw new Error(`legacy Probe archive ${archiveName} is invalid`);
    }
    if (listing !== "enoki-probe\n") {
      throw new Error(`legacy Probe archive ${archiveName} closure is invalid`);
    }
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
    const binaryPath = path.join(extractionDir, "enoki-probe");
    const details = await lstat(binaryPath);
    if (!details.isFile() || (details.mode & 0o111) === 0) {
      throw new Error(`legacy Probe archive ${archiveName} payload is invalid`);
    }
    const binary = await readFile(binaryPath);
    inspectProbeElf(binary, { target, version });
    return sha256(binary);
  } finally {
    await rm(extractionDir, { force: true, recursive: true });
  }
}

export function inspectProbeElf(
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
