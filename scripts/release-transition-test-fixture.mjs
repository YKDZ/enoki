import { execFile } from "node:child_process";
import { createHash, sign } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const sourceTargets = [
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
];

export async function createSignedLegacyProbeAssetSetFixture({
  privateKeyPem,
  publicKeyPem,
}) {
  const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-source-assets-"));
  const assets = [];
  const probeComponents = [];
  for (const target of sourceTargets) {
    const contentsDir = path.join(assetDir, `${target}-contents`);
    await mkdir(contentsDir);
    const probe = createSourceProbeElf(target);
    const probePath = path.join(contentsDir, "enoki-probe");
    await writeFile(probePath, probe);
    await chmod(probePath, 0o755);
    const file = `enoki-probe-${target}.tar.gz`;
    await execFileAsync("tar", [
      "--create",
      "--gzip",
      "--file",
      path.join(assetDir, file),
      "--directory",
      contentsDir,
      "enoki-probe",
    ]);
    await rm(contentsDir, { recursive: true });
    const archive = await readFile(path.join(assetDir, file));
    const archiveSha256 = sha256(archive);
    await writeFile(
      path.join(assetDir, `${file}.sha256`),
      `${archiveSha256}  ${file}\n`,
    );
    assets.push({ file, sha256: archiveSha256, size: archive.length, target });
    probeComponents.push({
      file: "enoki-probe",
      role: "probe",
      sha256: sha256(probe),
      target,
    });
  }
  const manifest = Buffer.from(
    `${JSON.stringify({
      assets,
      kind: "enoki-probe-assets",
      signature: {
        algorithm: "rsa-sha256",
        file: "manifest.json.sig",
        publicKey: "signing-key.pem",
      },
      version: "0.1.74",
    })}\n`,
  );
  await writeFile(path.join(assetDir, "manifest.json"), manifest);
  await writeFile(
    path.join(assetDir, "manifest.json.sig"),
    sign("RSA-SHA256", manifest, privateKeyPem),
  );
  await writeFile(path.join(assetDir, "signing-key.pem"), publicKeyPem);
  await writeFile(
    path.join(assetDir, "install-probe.sh"),
    `#!/bin/sh\n# ${sha256(Buffer.from(publicKeyPem))}\n`,
  );
  const authorizedAssets = [];
  for (const name of await readdir(assetDir)) {
    const bytes = await readFile(path.join(assetDir, name));
    authorizedAssets.push({ name, sha256: sha256(bytes), size: bytes.length });
  }
  authorizedAssets.sort((left, right) => left.name.localeCompare(right.name));
  return {
    assetDir,
    assets: authorizedAssets,
    cleanup: () => rm(assetDir, { force: true, recursive: true }),
    probeComponents,
  };
}

function createSourceProbeElf(target) {
  const interpreter = target.endsWith("-gnu")
    ? target.startsWith("x86_64-")
      ? "/lib64/ld-linux-x86-64.so.2\0"
      : "/lib/ld-linux-aarch64.so.1\0"
    : "";
  const headerSize = 64;
  const programHeaderSize = interpreter ? 56 : 0;
  const marker = Buffer.from(
    `ENOKI_PROBE_TARGET=${target}\0ENOKI_PROBE_VERSION=v0.1.74\0`,
  );
  const interpreterBytes = Buffer.from(interpreter);
  const binary = Buffer.alloc(
    headerSize + programHeaderSize + interpreterBytes.length + marker.length,
  );
  binary.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  binary.writeUInt16LE(2, 16);
  binary.writeUInt16LE(target.startsWith("x86_64-") ? 62 : 183, 18);
  binary.writeUInt32LE(1, 20);
  binary.writeBigUInt64LE(BigInt(headerSize), 32);
  binary.writeUInt16LE(headerSize, 52);
  binary.writeUInt16LE(56, 54);
  binary.writeUInt16LE(interpreter ? 1 : 0, 56);
  if (interpreter) {
    binary.writeUInt32LE(3, headerSize);
    binary.writeBigUInt64LE(BigInt(headerSize + 56), headerSize + 8);
    binary.writeBigUInt64LE(BigInt(interpreterBytes.length), headerSize + 32);
    interpreterBytes.copy(binary, headerSize + 56);
  }
  marker.copy(binary, headerSize + programHeaderSize + interpreterBytes.length);
  return binary;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
