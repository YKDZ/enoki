// Probe Bootstrap 发布制品的打包与命令行入口；本地压缩包与 ELF 检验闭包见
// ./probe-bootstrap-inspection.ts。

import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import {
  inspectProbeBootstrapBinary,
  sameBuildTrust,
  sha256,
} from "./probe-bootstrap-inspection.ts";
import { isUnknownRecord } from "./release-json-guards.ts";

const execFileAsync = promisify(execFile);

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
      ...roleBinaries.flatMap(({ binaryPath }) => [
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
    !isUnknownRecord(binaries) ||
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
