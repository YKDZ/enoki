// Probe Bootstrap 发布制品的本地检验闭包：读取有界压缩包、解析 USTAR/gzip 成员并
// 校验两个 role 二进制的 ELF 与内嵌 build identity。打包与 CLI 保持在原入口。

import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { inflateRawSync } from "node:zlib";

import {
  isUnknownRecord,
  isSafeInteger,
  objectView,
  stringValue,
  type UnknownRecord,
} from "./release-json-guards.ts";

const identityMagic = Buffer.from("ENOKI_BOOTSTRAP_BUILD_IDENTITY_V1\0");
const maxProbeBootstrapArchiveBytes = 64 * 1024 * 1024;
const expectedProbeBootstrapRoles = Object.freeze([
  { name: "enoki-probe-bootstrap-acquire", role: "acquirer" },
  { name: "enoki-probe-bootstrap-activate", role: "activator" },
] as const);

type ProbeBootstrapExpectedRole = (typeof expectedProbeBootstrapRoles)[number];

export const probeBootstrapTargets = Object.freeze([
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
]);

const elfMachineByTarget: Readonly<Record<string, number>> = Object.freeze({
  "aarch64-unknown-linux-gnu": 183,
  "aarch64-unknown-linux-musl": 183,
  "x86_64-unknown-linux-gnu": 62,
  "x86_64-unknown-linux-musl": 62,
});

export type ProbeBootstrapRole = "acquirer" | "activator";

export type ProbeBootstrapInspection = {
  identity: UnknownRecord;
  sha256: string;
  size: number;
};

export type ProbeBootstrapBuildTrust = {
  distribution: string;
  rootKeyId: string;
  target: string;
  version: string;
};

export type ProbeBootstrapArchiveExpectation = {
  sha256: string;
  size: number;
};

export type ProbeBootstrapBinaryInput = ProbeBootstrapBuildTrust & {
  binaryPath: string;
  role: unknown;
};

export type ProbeBootstrapArchiveInput = Partial<ProbeBootstrapBuildTrust> & {
  archivePath: unknown;
  expectedArchive?: unknown;
};

export type VerifiedProbeBootstrapSnapshot = {
  archivePath: string;
  sha256: string;
  size: number;
  temporaryDirectory: string;
};

export type ExtractedProbeBootstrapRole = ProbeBootstrapInspection & {
  binaryPath: string;
};

export type ProbeBootstrapArchiveCallback = (
  snapshot: VerifiedProbeBootstrapSnapshot,
) => Promise<unknown>;

export type ProbeBootstrapArtifactCallback = (
  artifact: VerifiedProbeBootstrapArtifact,
) => Promise<unknown>;

export type VerifiedProbeBootstrapArtifact = {
  archivePath: string;
  extractedRoles: Readonly<
    Record<ProbeBootstrapRole, ExtractedProbeBootstrapRole>
  >;
  roles: Record<ProbeBootstrapRole, ProbeBootstrapInspection>;
  sha256: string;
  temporaryDirectory: string;
};

export async function inspectProbeBootstrapBinary(
  input: ProbeBootstrapBinaryInput,
): Promise<ProbeBootstrapInspection> {
  const { binaryPath, distribution, role, rootKeyId, target, version } = input;
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

/// 直接检验最终压缩发布制品，不解压到文件系统；证明两个 role 二进制、权限与
/// build-fixed trust identity 在打包后仍然成立。
export async function inspectProbeBootstrapArtifact(
  input: ProbeBootstrapArchiveInput,
): Promise<{
  roles: Record<ProbeBootstrapRole, ProbeBootstrapInspection>;
  sha256: string;
}> {
  const inspected = await inspectProbeBootstrapArchiveInput(input);
  return inspected.public;
}

async function inspectProbeBootstrapArchiveInput(input: {
  archivePath: unknown;
  distribution?: string;
  expectedArchive?: unknown;
  rootKeyId?: string;
  target?: string;
  version?: string;
}): Promise<{
  archive: Buffer;
  public: {
    roles: Record<ProbeBootstrapRole, ProbeBootstrapInspection>;
    sha256: string;
  };
  roleBytes: Record<ProbeBootstrapRole, Buffer | undefined>;
}> {
  const archivePath = input.archivePath;
  assertBuildTrust({
    distribution: input.distribution,
    rootKeyId: input.rootKeyId,
    target: input.target,
    version: input.version,
  });
  if (typeof archivePath !== "string") {
    throw new Error("Probe Bootstrap archive path is invalid");
  }
  const archive = await readBoundedArchive(archivePath);
  assertExpectedArchive(archive, input.expectedArchive);
  const archiveRoles = parseExactProbeBootstrapArchive(archive);
  const inspectedRoles = new Map<
    ProbeBootstrapRole,
    { binary: Buffer; inspection: ProbeBootstrapInspection }
  >();
  await Promise.all(
    expectedProbeBootstrapRoles.map(async ({ name, role }) => {
      const binary = archiveRoles.get(name);
      if (binary === undefined) {
        throw unsafeBootstrapArchive();
      }
      const inspection = inspectProbeBootstrapBytes({
        binary,
        distribution: input.distribution,
        role,
        rootKeyId: input.rootKeyId,
        target: input.target,
        version: input.version,
      });
      inspectedRoles.set(role, { binary, inspection });
    }),
  );
  const acquirer = inspectedRoles.get("acquirer");
  const activator = inspectedRoles.get("activator");
  if (acquirer === undefined || activator === undefined) {
    throw unsafeBootstrapArchive();
  }
  const roles: Record<ProbeBootstrapRole, ProbeBootstrapInspection> = {
    acquirer: acquirer.inspection,
    activator: activator.inspection,
  };
  return {
    public: { roles, sha256: sha256(archive) },
    archive,
    roleBytes: { acquirer: acquirer.binary, activator: activator.binary },
  };
}

function assertExpectedArchive(
  archive: Buffer,
  expectedArchive: unknown,
): void {
  if (expectedArchive === undefined) return;
  if (
    !isUnknownRecord(expectedArchive) ||
    Object.keys(expectedArchive).sort().join(",") !== "sha256,size" ||
    !/^[0-9a-f]{64}$/.test(stringValue(expectedArchive.sha256))
  ) {
    throw new Error(
      "Probe Bootstrap archive does not match the expected release bytes",
    );
  }
  const size = expectedArchive.size;
  if (
    !isSafeInteger(size) ||
    !(size > 0) ||
    archive.byteLength !== size ||
    sha256(archive) !== expectedArchive.sha256
  ) {
    throw new Error(
      "Probe Bootstrap archive does not match the expected release bytes",
    );
  }
}

export async function withVerifiedProbeBootstrapArchive(
  input: ProbeBootstrapArchiveInput,
  callback: ProbeBootstrapArchiveCallback,
): Promise<unknown> {
  if (typeof callback !== "function") {
    throw new Error("Probe Bootstrap archive snapshot requires a callback");
  }
  const archivePath = input?.archivePath;
  if (typeof archivePath !== "string") {
    throw new Error("Probe Bootstrap archive path is invalid");
  }
  if (input.expectedArchive === undefined) {
    throw new Error(
      "Probe Bootstrap archive snapshot requires expected release bytes",
    );
  }
  const archive = await readBoundedArchive(archivePath);
  assertExpectedArchive(archive, input.expectedArchive);
  return withPrivateProbeBootstrapArchive(archive, callback);
}

async function withPrivateProbeBootstrapArchive(
  archive: Buffer,
  callback: ProbeBootstrapArchiveCallback,
): Promise<unknown> {
  const temporaryDirectory = await mkdtemp(
    path.join(tmpdir(), "enoki-probe-bootstrap-verified-"),
  );
  try {
    await chmod(temporaryDirectory, 0o700);
    const archivePath = path.join(temporaryDirectory, "probe-bootstrap.tar.gz");
    await writeFile(archivePath, archive, { flag: "wx", mode: 0o600 });
    return await callback({
      archivePath,
      sha256: sha256(archive),
      size: archive.byteLength,
      temporaryDirectory,
    });
  } finally {
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
}

// 压缩包解析保持在提权权限之外。回调只拿到两个已通过摘要校验的普通 role 二进制，
// 位于私有、由 controller 持有的目录；即使传输或安装失败也会删除该目录。
export async function withVerifiedProbeBootstrapArtifact(
  input: ProbeBootstrapArchiveInput,
  callback: ProbeBootstrapArtifactCallback,
): Promise<unknown> {
  if (typeof callback !== "function") {
    throw new Error("Probe Bootstrap extraction requires a callback");
  }
  const inspected = await inspectProbeBootstrapArchiveInput(input);
  const inspection = inspected.public;
  return withPrivateProbeBootstrapArchive(
    inspected.archive,
    async (snapshot: VerifiedProbeBootstrapSnapshot) => {
      const { archivePath, temporaryDirectory } = snapshot;
      const extractRole = async (entry: ProbeBootstrapExpectedRole) => {
        const binaryPath = path.join(temporaryDirectory, entry.name);
        const roleBytes = inspected.roleBytes[entry.role];
        if (roleBytes === undefined) {
          throw unsafeBootstrapArchive();
        }
        await writeFile(binaryPath, roleBytes, { flag: "wx", mode: 0o755 });
        const details = await lstat(binaryPath);
        if (
          !details.isFile() ||
          details.isSymbolicLink() ||
          (details.mode & 0o777) !== 0o755
        ) {
          throw new Error("Probe Bootstrap extracted role binary is unsafe");
        }
        const binary = await readFile(binaryPath);
        const expected = inspection.roles[entry.role];
        if (
          binary.byteLength !== expected.size ||
          sha256(binary) !== expected.sha256
        ) {
          throw new Error(
            "Probe Bootstrap archive changed while extracting inspected roles",
          );
        }
        return { ...expected, binaryPath };
      };
      const extractedRoles = Object.freeze({
        acquirer: await extractRole(expectedProbeBootstrapRoles[0]),
        activator: await extractRole(expectedProbeBootstrapRoles[1]),
      });
      return await callback({
        ...inspection,
        archivePath,
        extractedRoles,
        temporaryDirectory,
      });
    },
  );
}

async function readBoundedArchive(archivePath: string): Promise<Buffer> {
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

function parseExactProbeBootstrapArchive(archive: Buffer): Map<string, Buffer> {
  const tar = decompressOneExactGzipMember(archive);
  const roles = new Map<string, Buffer>();
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
    if (contentsStart + paddedSize > tar.byteLength) {
      throw unsafeBootstrapArchive();
    }
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

function decompressOneExactGzipMember(archive: Buffer): Buffer {
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
  let inflated: unknown;
  try {
    inflated = inflateRawSync(archive.subarray(offset), {
      info: true,
      maxOutputLength: maxProbeBootstrapArchiveBytes,
    });
  } catch {
    throw unsafeBootstrapArchive();
  }
  const info = objectView(inflated);
  const buffer = info.buffer;
  if (!Buffer.isBuffer(buffer)) throw unsafeBootstrapArchive();
  const compressedLength = objectView(info.engine).bytesWritten;
  if (!isSafeInteger(compressedLength)) throw unsafeBootstrapArchive();
  const trailerOffset = offset + compressedLength;
  if (
    trailerOffset + 8 !== archive.byteLength ||
    buffer.byteLength > maxProbeBootstrapArchiveBytes ||
    archive.readUInt32LE(trailerOffset) !== crc32(buffer) ||
    archive.readUInt32LE(trailerOffset + 4) !== buffer.byteLength >>> 0
  ) {
    throw unsafeBootstrapArchive();
  }
  return buffer;
}

function assertTarHeaderChecksum(header: Buffer): void {
  const stored = readTarOctal(header, 148, 8);
  let actual = 0;
  for (const [index, byte] of header.entries()) {
    actual += index >= 148 && index < 156 ? 32 : byte;
  }
  if (stored !== actual) throw unsafeBootstrapArchive();
}

function readTarString(header: Buffer, offset: number, length: number): string {
  const value = header.subarray(offset, offset + length);
  const terminator = value.indexOf(0);
  const bytes = terminator === -1 ? value : value.subarray(0, terminator);
  if (bytes.some((byte) => byte < 0x20 || byte > 0x7e)) {
    throw unsafeBootstrapArchive();
  }
  if (
    terminator !== -1 &&
    value.subarray(terminator).some((byte) => byte !== 0)
  ) {
    throw unsafeBootstrapArchive();
  }
  return bytes.toString("utf8");
}

function readTarOctal(header: Buffer, offset: number, length: number): number {
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

function readTarOctalOrEmptyZero(
  header: Buffer,
  offset: number,
  length: number,
): number {
  const value = header.subarray(offset, offset + length);
  if (value.every((byte) => byte === 0 || byte === 0x20)) return 0;
  return readTarOctal(header, offset, length);
}

function unsafeBootstrapArchive(): Error {
  return new Error("Probe Bootstrap archive structure is unsafe");
}

function crc32(value: Uint8Array): number {
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
}: {
  binary: Buffer;
  distribution: unknown;
  role: unknown;
  rootKeyId: unknown;
  target: unknown;
  version: unknown;
}): ProbeBootstrapInspection {
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

function elfSection(
  binary: Buffer,
  expectedName: string,
  target: unknown,
): Buffer {
  if (
    binary.byteLength < 64 ||
    !binary.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||
    binary[4] !== 2 ||
    binary[5] !== 1 ||
    binary[6] !== 1 ||
    binary.readUInt16LE(18) !== elfMachineByTarget[stringValue(target)]
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
  const sectionAt = (index: number): number =>
    sectionOffset + index * sectionEntrySize;
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
  const matches: Buffer[] = [];
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
  const [only] = matches;
  if (matches.length !== 1 || only === undefined) {
    throw new Error(
      "Probe Bootstrap ELF must contain exactly one identity section",
    );
  }
  return only;
}

function parseIdentitySection(section: Buffer): UnknownRecord {
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
  let identity: unknown;
  try {
    identity = JSON.parse(payload.toString("utf8"));
  } catch {
    throw new Error("Probe Bootstrap identity section is invalid");
  }
  if (
    !isUnknownRecord(identity) ||
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

function assertBuildIdentity(identity: UnknownRecord): void {
  assertBuildTrust({
    distribution: identity.distribution,
    rootKeyId: identity.rootKeyId,
    target: identity.target,
    version: identity.version,
  });
  if (!["acquirer", "activator"].includes(stringValue(identity.role))) {
    throw new Error("Probe Bootstrap build identity is invalid");
  }
}

function assertBuildTrust({
  distribution,
  rootKeyId,
  target,
  version,
}: {
  distribution: unknown;
  rootKeyId: unknown;
  target: unknown;
  version: unknown;
}): void {
  if (
    !/^[a-z][a-z0-9-]{0,63}$/.test(stringValue(distribution)) ||
    !/^[0-9a-f]{64}$/.test(stringValue(rootKeyId)) ||
    !probeBootstrapTargets.includes(stringValue(target)) ||
    !/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(stringValue(version))
  ) {
    throw new Error("Probe Bootstrap build identity is invalid");
  }
}

export function sameBuildTrust(left: unknown, right: unknown): boolean {
  const actual = objectView(left);
  const expected = objectView(right);
  return (
    actual.distribution === expected.distribution &&
    actual.rootFingerprint === expected.rootFingerprint &&
    actual.rootKeyId === expected.rootKeyId &&
    actual.target === expected.target &&
    actual.version === expected.version
  );
}

function elfString(table: Buffer, offset: number): string | undefined {
  if (offset >= table.byteLength) return undefined;
  const end = table.indexOf(0, offset);
  if (end === -1) return undefined;
  return table.subarray(offset, end).toString("utf8");
}

function safeOffset(value: bigint, total: number): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("Probe Bootstrap ELF offsets are invalid");
  }
  const offset = Number(value);
  if (offset > total) {
    throw new Error("Probe Bootstrap ELF offsets are invalid");
  }
  return offset;
}

function isInBounds(offset: number, size: number, total: number): boolean {
  return (
    Number.isSafeInteger(offset) &&
    Number.isSafeInteger(size) &&
    offset + size <= total
  );
}

export function sha256(contents: Uint8Array): string {
  return createHash("sha256").update(contents).digest("hex");
}
