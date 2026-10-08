import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

type PackageManifest = {
  readonly engines?: { readonly node?: unknown };
  readonly packageManager?: unknown;
};

type DevcontainerManifest = {
  readonly build?: { readonly args?: Record<string, unknown> };
};

const repositoryRoot = process.cwd();
const diagnostics: string[] = [];
const packageManifest = JSON.parse(
  readFileSync(path.join(repositoryRoot, "package.json"), "utf8"),
) as PackageManifest;
const devcontainer = JSON.parse(
  readFileSync(
    path.join(repositoryRoot, ".devcontainer/devcontainer.json"),
    "utf8",
  ),
) as DevcontainerManifest;
const dockerfile = readFileSync(
  path.join(repositoryRoot, ".devcontainer/Dockerfile"),
  "utf8",
);
const rustToolchain = readFileSync(
  path.join(repositoryRoot, "rust-toolchain.toml"),
  "utf8",
);

const nodeVersionDeclaration = packageManifest.engines?.node;
const nodeVersion =
  typeof nodeVersionDeclaration === "string" &&
  /^\d+\.\d+\.\d+$/u.test(nodeVersionDeclaration)
    ? nodeVersionDeclaration
    : undefined;
if (nodeVersion === undefined) {
  diagnostics.push(
    `根 package.json 的 engines.node 必须是精确三段版本，当前为 ${JSON.stringify(nodeVersionDeclaration ?? null)}`,
  );
}

const packageManagerDeclaration = packageManifest.packageManager;
const pnpmMatch =
  typeof packageManagerDeclaration === "string"
    ? /^pnpm@(\d+\.\d+\.\d+)(?:\+[^+]+)?$/u.exec(packageManagerDeclaration)
    : null;
const pnpmVersion = pnpmMatch?.[1];
if (pnpmVersion === undefined) {
  diagnostics.push(
    `根 package.json 的 packageManager 必须是精确 pnpm pin，当前为 ${JSON.stringify(packageManagerDeclaration ?? null)}`,
  );
}

function readRustChannel(): string | undefined {
  let inToolchainTable = false;
  for (const line of rustToolchain.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (/^\[[^\]]+\](?:\s+#.*)?$/u.test(trimmed)) {
      inToolchainTable = /^\[toolchain\](?:\s+#.*)?$/u.test(trimmed);
      continue;
    }
    if (!inToolchainTable) continue;

    const match =
      /^channel\s*=\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)')\s*(?:#.*)?$/u.exec(
        trimmed,
      );
    const channel = match?.[1] ?? match?.[2];
    if (channel !== undefined) return channel;
  }

  return undefined;
}

function readDockerBuildArg(name: string): string | undefined {
  const match = new RegExp(`^ARG\\s+${name}=(\\S+)\\s*$`, "mu").exec(
    dockerfile,
  );

  return match?.[1];
}

function checkMirror(
  label: string,
  actual: unknown,
  expected: string | undefined,
  source: string,
): void {
  if (actual === expected && expected !== undefined) return;

  diagnostics.push(
    `${label} 为 ${JSON.stringify(actual ?? null)}，应与 ${source} ${JSON.stringify(expected ?? null)} 一致`,
  );
}

const buildArgs = devcontainer.build?.args ?? {};
checkMirror(
  ".devcontainer/devcontainer.json 的 NODE_VERSION",
  buildArgs.NODE_VERSION,
  nodeVersion,
  "根 package.json 的 engines.node",
);
checkMirror(
  ".devcontainer/Dockerfile 的 NODE_VERSION",
  readDockerBuildArg("NODE_VERSION"),
  nodeVersion,
  "根 package.json 的 engines.node",
);

const rustChannel = readRustChannel();
if (rustChannel === undefined) {
  diagnostics.push(
    "rust-toolchain.toml 的 [toolchain].channel 缺失或不是字符串",
  );
}
checkMirror(
  ".devcontainer/devcontainer.json 的 RUST_TOOLCHAIN",
  buildArgs.RUST_TOOLCHAIN,
  rustChannel,
  "rust-toolchain.toml 的 [toolchain].channel",
);
checkMirror(
  ".devcontainer/Dockerfile 的 RUST_TOOLCHAIN",
  readDockerBuildArg("RUST_TOOLCHAIN"),
  rustChannel,
  "rust-toolchain.toml 的 [toolchain].channel",
);

if (/^(?:1|true)$/iu.test(process.env.CI ?? "")) {
  if (nodeVersion !== undefined && process.version !== `v${nodeVersion}`) {
    diagnostics.push(
      `CI Node 运行版本为 ${JSON.stringify(process.version)}，应与根 package.json 的 engines.node ${JSON.stringify(nodeVersion)} 一致`,
    );
  }

  if (pnpmVersion !== undefined) {
    const result = spawnSync("pnpm", ["--version"], { encoding: "utf8" });
    if (result.error !== undefined) {
      diagnostics.push(`CI 无法读取 pnpm 版本：${result.error.message}`);
    } else if (result.status !== 0) {
      diagnostics.push(
        `CI 执行 pnpm --version 失败，退出码为 ${String(result.status)}`,
      );
    } else if (result.stdout.trim() !== pnpmVersion) {
      diagnostics.push(
        `CI pnpm 运行版本为 ${JSON.stringify(result.stdout.trim())}，应与根 package.json 的 packageManager ${JSON.stringify(pnpmVersion)} 一致`,
      );
    }
  }
}

if (diagnostics.length > 0) {
  process.stderr.write(`${diagnostics.join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(
    `工具链声明一致：Node ${nodeVersion}、pnpm ${pnpmVersion}、Rust ${rustChannel}\n`,
  );
}
