// Probe Bootstrap 发布制品的打包与命令行入口；本地压缩包与 ELF 检验闭包见
// ./probe-bootstrap-inspection.ts。GNU tar 的第二个相对 --directory 会承接前一个
// 目录，因此打包前把每个角色目录规范化为绝对路径，归档成员名保持 basename。

import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import {
  inspectProbeBootstrapBinary,
  sameBuildTrust,
  sha256,
  type ProbeBootstrapBuildTrust,
  type ProbeBootstrapRole,
} from "./probe-bootstrap-inspection.ts";
import {
  isUnknownRecord,
  regexInput,
  assertAllowedOptions,
  parseCommandLine,
  requiredOption,
} from "./release-json-guards.ts";

const execFileAsync = promisify(execFile);

const inspectOptions = [
  "--binary",
  "--distribution",
  "--role",
  "--root-key-id",
  "--target",
  "--version",
] as const;
const packageOptions = [
  "--acquirer-binary",
  "--activator-binary",
  "--distribution",
  "--output-dir",
  "--root-key-id",
  "--source-date-epoch",
  "--target",
  "--version",
] as const;

type RoleBinary = {
  binaryPath: string;
  role: ProbeBootstrapRole;
};

export type PackageProbeBootstrapArtifactInput = ProbeBootstrapBuildTrust & {
  binaries: unknown;
  outputDir: string;
  sourceDateEpoch: unknown;
};

export type PackagedProbeBootstrapArtifact = {
  archivePath: string;
  file: string;
  sha256: string;
  size: number;
};

export async function packageProbeBootstrapArtifact(
  input: PackageProbeBootstrapArtifactInput,
): Promise<PackagedProbeBootstrapArtifact> {
  const {
    binaries,
    distribution,
    outputDir,
    rootKeyId,
    sourceDateEpoch,
    target,
    version,
  } = input;
  if (!/^(?:0|[1-9]\d*)$/.test(regexInput(sourceDateEpoch))) {
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
  const [acquirerInspection, activatorInspection] = inspections;
  if (
    acquirerInspection === undefined ||
    activatorInspection === undefined ||
    !sameBuildTrust(acquirerInspection.identity, activatorInspection.identity)
  ) {
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
        path.dirname(path.resolve(binaryPath)),
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

function exactRoleBinaries(binaries: unknown): RoleBinary[] {
  if (
    !isUnknownRecord(binaries) ||
    Object.keys(binaries).join(",") !== "acquirerPath,activatorPath" ||
    !isNonEmptyStringPath(binaries.acquirerPath) ||
    !isNonEmptyStringPath(binaries.activatorPath) ||
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

function isNonEmptyStringPath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function untrustedToolEnvironment(): NodeJS.ProcessEnv {
  return { LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" };
}

async function main(arguments_: readonly string[]): Promise<void> {
  const { command, options } = parseCommandLine(arguments_);
  const buildIdentity = {
    distribution: requiredOption(options, "--distribution"),
    rootKeyId: requiredOption(options, "--root-key-id"),
    target: requiredOption(options, "--target"),
    version: requiredOption(options, "--version"),
  };
  if (command === "inspect") {
    assertAllowedOptions(command, options, inspectOptions);
    await inspectProbeBootstrapBinary({
      binaryPath: requiredOption(options, "--binary"),
      role: requiredOption(options, "--role"),
      ...buildIdentity,
    });
    return;
  }
  if (command === "package") {
    assertAllowedOptions(command, options, packageOptions);
    await packageProbeBootstrapArtifact({
      ...buildIdentity,
      binaries: {
        acquirerPath: requiredOption(options, "--acquirer-binary"),
        activatorPath: requiredOption(options, "--activator-binary"),
      },
      outputDir: requiredOption(options, "--output-dir"),
      sourceDateEpoch: options.get("--source-date-epoch"),
    });
    return;
  }
  throw new Error("unknown Probe Bootstrap artifact command");
}

if (import.meta.main) {
  main(process.argv.slice(2)).catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
    process.exitCode = 1;
  });
}
