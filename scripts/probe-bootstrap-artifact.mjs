import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { inflateRawSync } from "node:zlib";

const execFileAsync = promisify(execFile);
const identityMagic = Buffer.from("ENOKI_BOOTSTRAP_BUILD_IDENTITY_V1\0");
const maxProbeBootstrapArchiveBytes = 64 * 1024 * 1024;
const expectedProbeBootstrapRoles = Object.freeze([
  { name: "enoki-probe-bootstrap-acquire", role: "acquirer" },
  { name: "enoki-probe-bootstrap-activate", role: "activator" },
]);

export const probeBootstrapTargets = Object.freeze([
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
]);

const elfMachineByTarget = Object.freeze({
  "aarch64-unknown-linux-gnu": 183,
  "aarch64-unknown-linux-musl": 183,
  "x86_64-unknown-linux-gnu": 62,
  "x86_64-unknown-linux-musl": 62,
});

export async function inspectProbeBootstrapBinary({
  binaryPath,
  distribution,
  role,
  rootKeyId,
  target,
  version,
}) {
  assertBuildIdentity({ distribution, role, rootKeyId, target, version });
  const binary = await readFile(binaryPath);
  return inspectProbeBootstrapBytes({
    binary,
    distribution,
    role,
    rootKeyId,
    target,
    version,
  });
}

/// Inspects the final compressed release artifact without extracting it to the
/// filesystem. This proves its two role binaries, modes and build-fixed trust
/// identities survived packaging.
export async function inspectProbeBootstrapArtifact({
  archivePath,
  distribution,
  rootKeyId,
  target,
  version,
}) {
  const inspected = await inspectProbeBootstrapArchiveInput({
    archivePath,
    distribution,
    rootKeyId,
    target,
    version,
  });
  return inspected.public;
}

async function inspectProbeBootstrapArchiveInput({
  archivePath,
  distribution,
  expectedArchive,
  rootKeyId,
  target,
  version,
}) {
  assertBuildTrust({ distribution, rootKeyId, target, version });
  if (typeof archivePath !== "string") {
    throw new Error("Probe Bootstrap archive path is invalid");
  }
  const archive = await readBoundedArchive(archivePath);
  assertExpectedArchive(archive, expectedArchive);
  const archiveRoles = parseExactProbeBootstrapArchive(archive);
  const [acquirer, activator] = await Promise.all(
    expectedProbeBootstrapRoles.map(async ({ name, role }) => {
      const binary = archiveRoles.get(name);
      return {
        binary,
        inspection: inspectProbeBootstrapBytes({
          binary,
          distribution,
          role,
          rootKeyId,
          target,
          version,
        }),
      };
    }),
  );
  return {
    public: {
      roles: {
        acquirer: acquirer.inspection,
        activator: activator.inspection,
      },
      sha256: sha256(archive),
    },
    roleBytes: { acquirer: acquirer.binary, activator: activator.binary },
  };
}

function assertExpectedArchive(archive, expectedArchive) {
  if (expectedArchive === undefined) return;
  if (
    !isPlainObject(expectedArchive) ||
    Object.keys(expectedArchive).sort().join(",") !== "sha256,size" ||
    !/^[0-9a-f]{64}$/.test(expectedArchive.sha256 ?? "") ||
    !Number.isSafeInteger(expectedArchive.size) ||
    expectedArchive.size <= 0 ||
    archive.byteLength !== expectedArchive.size ||
    sha256(archive) !== expectedArchive.sha256
  ) {
    throw new Error(
      "Candidate Probe Bootstrap archive no longer matches validated Candidate",
    );
  }
}

// Keeps archive parsing outside elevated authority. The callback receives only
// two digest-checked, regular role binaries in a private controller-owned
// directory; the directory is removed even when transfer or installation
// fails.
export async function withExtractedProbeBootstrapArtifact(input, callback) {
  if (typeof callback !== "function") {
    throw new Error("Probe Bootstrap extraction requires a callback");
  }
  const inspected = await inspectProbeBootstrapArchiveInput(input);
  const inspection = inspected.public;
  const temporaryDirectory = await mkdtemp(
    path.join(tmpdir(), "enoki-probe-bootstrap-inspected-"),
  );
  try {
    await chmod(temporaryDirectory, 0o700);
    const extractedRoles = {};
    for (const { name, role } of expectedProbeBootstrapRoles) {
      const binaryPath = path.join(temporaryDirectory, name);
      await writeFile(binaryPath, inspected.roleBytes[role], {
        flag: "wx",
        mode: 0o755,
      });
      const details = await lstat(binaryPath);
      if (
        !details.isFile() ||
        details.isSymbolicLink() ||
        (details.mode & 0o777) !== 0o755
      ) {
        throw new Error("Probe Bootstrap extracted role binary is unsafe");
      }
      const binary = await readFile(binaryPath);
      const expected = inspection.roles[role];
      if (
        binary.byteLength !== expected.size ||
        sha256(binary) !== expected.sha256
      ) {
        throw new Error(
          "Probe Bootstrap archive changed while extracting inspected roles",
        );
      }
      extractedRoles[role] = { ...expected, binaryPath };
    }
    return await callback({
      ...inspection,
      extractedRoles: Object.freeze(extractedRoles),
      temporaryDirectory,
    });
  } finally {
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
}

async function readBoundedArchive(archivePath) {
  const handle = await open(archivePath, "r");
  try {
    const details = await handle.stat();
    if (
      !details.isFile() ||
      details.size <= 0 ||
      details.size > maxProbeBootstrapArchiveBytes
    ) {
      throw new Error("Probe Bootstrap archive size is invalid");
    }
    const archive = await handle.readFile();
    if (archive.byteLength !== details.size) {
      throw new Error("Probe Bootstrap archive changed while being read");
    }
    return archive;
  } finally {
    await handle.close();
  }
}

function parseExactProbeBootstrapArchive(archive) {
  const tar = decompressOneExactGzipMember(archive);
  const roles = new Map();
  let offset = 0;
  for (const { name } of expectedProbeBootstrapRoles) {
    if (offset + 512 > tar.byteLength) throw unsafeBootstrapArchive();
    const header = tar.subarray(offset, offset + 512);
    assertTarHeaderChecksum(header);
    if (
      (header[156] !== 0 && header[156] !== "0".charCodeAt(0)) ||
      readTarString(header, 0, 100) !== name ||
      readTarString(header, 157, 100) !== "" ||
      readTarString(header, 257, 6) !== "ustar" ||
      readTarString(header, 263, 2) !== "00" ||
      readTarString(header, 345, 155) !== "" ||
      readTarOctal(header, 100, 8) !== 0o755 ||
      readTarOctal(header, 108, 8) !== 0 ||
      readTarOctal(header, 116, 8) !== 0 ||
      readTarOctalOrEmptyZero(header, 329, 8) !== 0 ||
      readTarOctalOrEmptyZero(header, 337, 8) !== 0
    ) {
      throw unsafeBootstrapArchive();
    }
    const size = readTarOctal(header, 124, 12);
    if (
      !Number.isSafeInteger(size) ||
      size <= 0 ||
      size > maxProbeBootstrapArchiveBytes
    ) {
      throw unsafeBootstrapArchive();
    }
    const contentsStart = offset + 512;
    const paddedSize = Math.ceil(size / 512) * 512;
    if (contentsStart + paddedSize > tar.byteLength)
      throw unsafeBootstrapArchive();
    if (
      tar
        .subarray(contentsStart + size, contentsStart + paddedSize)
        .some((byte) => byte !== 0)
    ) {
      throw unsafeBootstrapArchive();
    }
    roles.set(name, tar.subarray(contentsStart, contentsStart + size));
    offset = contentsStart + paddedSize;
  }
  if (
    offset + 1024 !== tar.byteLength ||
    tar.subarray(offset).some((byte) => byte !== 0)
  ) {
    throw unsafeBootstrapArchive();
  }
  return roles;
}

function decompressOneExactGzipMember(archive) {
  if (
    archive.byteLength < 18 ||
    archive[0] !== 0x1f ||
    archive[1] !== 0x8b ||
    archive[2] !== 8 ||
    archive[3] !== 0
  ) {
    throw unsafeBootstrapArchive();
  }
  const offset = 10;
  if (offset >= archive.byteLength - 8) throw unsafeBootstrapArchive();
  let result;
  try {
    result = inflateRawSync(archive.subarray(offset), {
      info: true,
      maxOutputLength: maxProbeBootstrapArchiveBytes,
    });
  } catch {
    throw unsafeBootstrapArchive();
  }
  const compressedLength = result.engine.bytesWritten;
  const trailerOffset = offset + compressedLength;
  if (
    !Number.isSafeInteger(compressedLength) ||
    trailerOffset + 8 !== archive.byteLength ||
    result.buffer.byteLength > maxProbeBootstrapArchiveBytes ||
    archive.readUInt32LE(trailerOffset) !== crc32(result.buffer) ||
    archive.readUInt32LE(trailerOffset + 4) !== result.buffer.byteLength >>> 0
  ) {
    throw unsafeBootstrapArchive();
  }
  return result.buffer;
}

function assertTarHeaderChecksum(header) {
  const stored = readTarOctal(header, 148, 8);
  let actual = 0;
  for (let index = 0; index < 512; index += 1) {
    actual += index >= 148 && index < 156 ? 32 : header[index];
  }
  if (stored !== actual) throw unsafeBootstrapArchive();
}

function readTarString(header, offset, length) {
  const value = header.subarray(offset, offset + length);
  const terminator = value.indexOf(0);
  const bytes = terminator === -1 ? value : value.subarray(0, terminator);
  if (bytes.some((byte) => byte < 0x20 || byte > 0x7e))
    throw unsafeBootstrapArchive();
  if (
    terminator !== -1 &&
    value.subarray(terminator).some((byte) => byte !== 0)
  ) {
    throw unsafeBootstrapArchive();
  }
  return bytes.toString("utf8");
}

function readTarOctal(header, offset, length) {
  const value = header.subarray(offset, offset + length);
  const text = value
    .toString("ascii")
    .replace(/[\0 ]+$/, "")
    .trim();
  if (!/^[0-7]+$/.test(text)) throw unsafeBootstrapArchive();
  const parsed = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(parsed)) throw unsafeBootstrapArchive();
  return parsed;
}

function readTarOctalOrEmptyZero(header, offset, length) {
  const value = header.subarray(offset, offset + length);
  if (value.every((byte) => byte === 0 || byte === 0x20)) return 0;
  return readTarOctal(header, offset, length);
}

function unsafeBootstrapArchive() {
  return new Error("Probe Bootstrap archive structure is unsafe");
}

function crc32(value) {
  let crc = 0xffffffff;
  for (const byte of value) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function inspectProbeBootstrapBytes({
  binary,
  distribution,
  role,
  rootKeyId,
  target,
  version,
}) {
  const section = elfSection(binary, ".enoki_bootstrap", target);
  const identity = parseIdentitySection(section);
  if (
    identity.distribution !== distribution ||
    identity.role !== role ||
    identity.rootFingerprint !== rootKeyId ||
    identity.rootKeyId !== rootKeyId ||
    identity.target !== target ||
    identity.version !== version
  ) {
    throw new Error("Probe Bootstrap embedded build identity does not match");
  }
  return { identity, sha256: sha256(binary), size: binary.byteLength };
}

export async function packageProbeBootstrapArtifact({
  binaries,
  distribution,
  outputDir,
  rootKeyId,
  sourceDateEpoch,
  target,
  version,
}) {
  if (!/^(?:0|[1-9]\d*)$/.test(sourceDateEpoch ?? "")) {
    throw new Error("source date epoch must be a non-negative integer");
  }
  const roleBinaries = exactRoleBinaries(binaries);
  const inspections = await Promise.all(
    roleBinaries.map(({ binaryPath, role }) =>
      inspectProbeBootstrapBinary({
        binaryPath,
        distribution,
        role,
        rootKeyId,
        target,
        version,
      }),
    ),
  );
  if (!sameBuildTrust(inspections[0].identity, inspections[1].identity)) {
    throw new Error("Probe Bootstrap role identities must match");
  }
  const file = `enoki-probe-bootstrap-${target}.tar.gz`;
  const archivePath = path.join(outputDir, file);
  // GNU tar applies each later --directory relative to the previous one.
  // Resolve role paths before invoking it so packaging cannot depend on that
  // mutable process directory state.
  const archiveRoleBinaries = roleBinaries.map(({ binaryPath, role }) => ({
    binaryPath: path.resolve(binaryPath),
    role,
  }));
  await mkdir(outputDir, { recursive: true });
  await execFileAsync(
    "tar",
    [
      "--create",
      "--gzip",
      "--blocking-factor=1",
      "--format=ustar",
      "--sort=name",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      `--mtime=@${sourceDateEpoch}`,
      "--mode=0755",
      "--file",
      archivePath,
      ...archiveRoleBinaries.flatMap(({ binaryPath }) => [
        "--directory",
        path.dirname(binaryPath),
        path.basename(binaryPath),
      ]),
    ],
    { env: untrustedToolEnvironment(), maxBuffer: 1024 * 1024 },
  );
  const archive = await readFile(archivePath);
  await writeFile(`${archivePath}.sha256`, `${sha256(archive)}  ${file}\n`);
  return {
    archivePath,
    file,
    sha256: sha256(archive),
    size: archive.byteLength,
  };
}

function exactRoleBinaries(binaries) {
  if (
    !isPlainObject(binaries) ||
    Object.keys(binaries).join(",") !== "acquirerPath,activatorPath" ||
    typeof binaries.acquirerPath !== "string" ||
    typeof binaries.activatorPath !== "string" ||
    path.basename(binaries.acquirerPath) !== "enoki-probe-bootstrap-acquire" ||
    path.basename(binaries.activatorPath) !==
      "enoki-probe-bootstrap-activate" ||
    binaries.acquirerPath === binaries.activatorPath
  ) {
    throw new Error(
      "Probe Bootstrap artifact requires exactly its two role binaries",
    );
  }
  return [
    { binaryPath: binaries.acquirerPath, role: "acquirer" },
    { binaryPath: binaries.activatorPath, role: "activator" },
  ];
}

function elfSection(binary, expectedName, target) {
  if (
    binary.byteLength < 64 ||
    !binary.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||
    binary[4] !== 2 ||
    binary[5] !== 1 ||
    binary[6] !== 1 ||
    binary.readUInt16LE(18) !== elfMachineByTarget[target]
  ) {
    throw new Error("Probe Bootstrap binary is not the expected ELF target");
  }
  const sectionOffset = safeOffset(
    binary.readBigUInt64LE(40),
    binary.byteLength,
  );
  const sectionEntrySize = binary.readUInt16LE(58);
  const sectionCount = binary.readUInt16LE(60);
  const namesIndex = binary.readUInt16LE(62);
  if (
    sectionEntrySize < 64 ||
    sectionCount === 0 ||
    namesIndex >= sectionCount ||
    !isInBounds(
      sectionOffset,
      sectionEntrySize * sectionCount,
      binary.byteLength,
    )
  ) {
    throw new Error("Probe Bootstrap ELF section table is invalid");
  }
  const sectionAt = (index) => sectionOffset + index * sectionEntrySize;
  const namesHeader = sectionAt(namesIndex);
  const namesOffset = safeOffset(
    binary.readBigUInt64LE(namesHeader + 24),
    binary.byteLength,
  );
  const namesSize = safeOffset(
    binary.readBigUInt64LE(namesHeader + 32),
    binary.byteLength,
  );
  if (!isInBounds(namesOffset, namesSize, binary.byteLength)) {
    throw new Error("Probe Bootstrap ELF string table is invalid");
  }
  const names = binary.subarray(namesOffset, namesOffset + namesSize);
  const matches = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const header = sectionAt(index);
    const nameOffset = binary.readUInt32LE(header);
    const name = elfString(names, nameOffset);
    if (name === expectedName) {
      const offset = safeOffset(
        binary.readBigUInt64LE(header + 24),
        binary.byteLength,
      );
      const size = safeOffset(
        binary.readBigUInt64LE(header + 32),
        binary.byteLength,
      );
      if (!isInBounds(offset, size, binary.byteLength)) {
        throw new Error("Probe Bootstrap ELF identity section is invalid");
      }
      matches.push(binary.subarray(offset, offset + size));
    }
  }
  if (matches.length !== 1) {
    throw new Error(
      "Probe Bootstrap ELF must contain exactly one identity section",
    );
  }
  return matches[0];
}

function parseIdentitySection(section) {
  if (section.byteLength < identityMagic.byteLength + 4) {
    throw new Error("Probe Bootstrap identity section is invalid");
  }
  if (!section.subarray(0, identityMagic.byteLength).equals(identityMagic)) {
    throw new Error("Probe Bootstrap identity section is invalid");
  }
  const payloadLength = section.readUInt32BE(identityMagic.byteLength);
  const payloadOffset = identityMagic.byteLength + 4;
  if (payloadLength !== section.byteLength - payloadOffset) {
    throw new Error("Probe Bootstrap identity section is invalid");
  }
  const payload = section.subarray(payloadOffset);
  let identity;
  try {
    identity = JSON.parse(payload.toString("utf8"));
  } catch {
    throw new Error("Probe Bootstrap identity section is invalid");
  }
  if (
    !isPlainObject(identity) ||
    Object.keys(identity).join(",") !==
      "distribution,rootFingerprint,rootKeyId,target,version,role" ||
    Buffer.from(`${JSON.stringify(identity)}`).compare(payload) !== 0
  ) {
    throw new Error("Probe Bootstrap identity section is invalid");
  }
  assertBuildIdentity(identity);
  if (identity.rootFingerprint !== identity.rootKeyId) {
    throw new Error("Probe Bootstrap identity section is invalid");
  }
  return identity;
}

function assertBuildIdentity({
  distribution,
  role,
  rootKeyId,
  target,
  version,
}) {
  assertBuildTrust({ distribution, rootKeyId, target, version });
  if (!["acquirer", "activator"].includes(role)) {
    throw new Error("Probe Bootstrap build identity is invalid");
  }
}

function assertBuildTrust({ distribution, rootKeyId, target, version }) {
  if (
    !/^[a-z][a-z0-9-]{0,63}$/.test(distribution) ||
    !/^[0-9a-f]{64}$/.test(rootKeyId) ||
    !probeBootstrapTargets.includes(target) ||
    !/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)
  ) {
    throw new Error("Probe Bootstrap build identity is invalid");
  }
}

function sameBuildTrust(left, right) {
  return (
    left.distribution === right.distribution &&
    left.rootFingerprint === right.rootFingerprint &&
    left.rootKeyId === right.rootKeyId &&
    left.target === right.target &&
    left.version === right.version
  );
}

function elfString(table, offset) {
  if (offset >= table.byteLength) return undefined;
  const end = table.indexOf(0, offset);
  if (end === -1) return undefined;
  return table.subarray(offset, end).toString("utf8");
}

function safeOffset(value, total) {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("Probe Bootstrap ELF offsets are invalid");
  }
  const offset = Number(value);
  if (offset > total)
    throw new Error("Probe Bootstrap ELF offsets are invalid");
  return offset;
}

function isInBounds(offset, size, total) {
  return (
    Number.isSafeInteger(offset) &&
    Number.isSafeInteger(size) &&
    offset + size <= total
  );
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function untrustedToolEnvironment() {
  return { LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" };
}

async function main(arguments_) {
  const [command, ...tokens] = arguments_;
  const options = new Map();
  for (let index = 0; index < tokens.length; index += 2) {
    if (!tokens[index]?.startsWith("--") || tokens[index + 1] === undefined) {
      throw new Error("invalid Probe Bootstrap artifact command");
    }
    options.set(tokens[index].slice(2), tokens[index + 1]);
  }
  const buildIdentity = {
    distribution: options.get("distribution"),
    rootKeyId: options.get("root-key-id"),
    target: options.get("target"),
    version: options.get("version"),
  };
  if (command === "inspect") {
    await inspectProbeBootstrapBinary({
      binaryPath: options.get("binary"),
      role: options.get("role"),
      ...buildIdentity,
    });
    return;
  }
  if (command === "package") {
    await packageProbeBootstrapArtifact({
      ...buildIdentity,
      binaries: {
        acquirerPath: options.get("acquirer-binary"),
        activatorPath: options.get("activator-binary"),
      },
      outputDir: options.get("output-dir"),
      sourceDateEpoch: options.get("source-date-epoch"),
    });
    return;
  }
  throw new Error("unknown Probe Bootstrap artifact command");
}

if (import.meta.main) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
    process.exitCode = 1;
  });
}
