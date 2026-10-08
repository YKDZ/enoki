// Probe Asset Bundle 的正式打包实现：把一次 release 构建产出的五个角色二进制收成
// 同一版本匹配的压缩包，并在写盘前后逐角色校验身份与最终归档闭包。

import { execFile } from "node:child_process";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import {
  inspectProbeElf,
  probeBundleComponentProfiles,
  probeTargets,
} from "@enoki/probe-release";

import { renderProbeBundleComponentsFromDetails } from "./release-candidate-signing.ts";
import {
  fileSha256,
  inspectProbeArchive,
  readProbeBundleComponentDetails,
  untrustedToolEnvironment,
  validateCandidateIdentity,
} from "./release-candidate-verification.ts";

const execFileAsync = promisify(execFile);

// ADR-0079：短生命周期 Resource Provider 只带固定 Host 访问合同，不要求旧普通 Probe 标记，
// 其 ELF 架构与 ABI 校验保持；其余角色维持既有标记要求（Companion 属保持项，非 ADR 要求）。
const rolesWithoutEmbeddedProbeIdentity: readonly string[] = Object.freeze([
  "disk-health-provider",
  "system-state-provider",
]);

export async function packageProbeArchive({
  binaryPath,
  outputDir,
  sourceDateEpoch,
  target,
  version,
}: {
  binaryPath: string;
  outputDir: string;
  sourceDateEpoch: string | undefined;
  target: string;
  version: string;
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
    for (const [role, profile] of Object.entries(
      probeBundleComponentProfiles,
    )) {
      const source =
        profile.path === "enoki-probe"
          ? binaryPath
          : path.join(path.dirname(binaryPath), profile.path);
      const component = await readFile(source);
      inspectProbeElf(component, {
        requireEmbeddedProbeIdentity:
          !rolesWithoutEmbeddedProbeIdentity.includes(role),
        target,
        version: stableVersion,
      });
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
