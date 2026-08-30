import { spawn, spawnSync } from "node:child_process";
import {
  accessSync,
  chmodSync,
  copyFileSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const generateScript = resolve(packageRoot, "scripts/generate.mjs");
const fixtures: string[] = [];

afterEach(() => {
  for (const fixture of fixtures.splice(0)) {
    rmSync(fixture, { force: true, recursive: true });
  }
});

describe("protobuf generation", () => {
  it("keeps installed consumers able to import while generation is in progress", async () => {
    const fixture = createFixture();
    const generated = startGenerate(fixture);

    await waitForFile(fixture.readyFile);

    expect(importInstalledProto(fixture.repoRoot).status).toBe(0);
    expect(await waitForExit(generated)).toBe(0);
  });

  it("leaves installed consumers on the previous output when generation fails", async () => {
    const fixture = createFixture({ failFirstPbjs: true });
    const generated = startGenerate(fixture);

    expect(await waitForExit(generated)).not.toBe(0);
    expect(importInstalledProto(fixture.repoRoot).status).toBe(0);
    expect(stagingDirectories(fixture.sourceRoot)).toEqual([]);
  });
});

function createFixture(options: { failFirstPbjs?: boolean } = {}) {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "enoki-proto-generate-"));
  fixtures.push(fixtureRoot);

  const repoRoot = join(fixtureRoot, "repo");
  const sourceRoot = join(repoRoot, "packages/proto");
  const sourceTsOut = join(sourceRoot, "src/generated/ts");
  const sourceRustOut = join(sourceRoot, "src/generated/rust");
  const installedRoot = join(repoRoot, "node_modules/@enoki/proto");
  const installedTsOut = join(installedRoot, "src/generated/ts");
  const binRoot = join(fixtureRoot, "bin");
  const readyFile = join(fixtureRoot, "first-pbjs-written");

  mkdirSync(join(sourceRoot, "scripts"), { recursive: true });
  mkdirSync(sourceTsOut, { recursive: true });
  mkdirSync(sourceRustOut, { recursive: true });
  mkdirSync(join(sourceRoot, "proto/enoki/v1"), { recursive: true });
  mkdirSync(installedTsOut, { recursive: true });
  mkdirSync(join(repoRoot, "node_modules/protobufjs"), { recursive: true });
  mkdirSync(binRoot, { recursive: true });

  copyFileSync(generateScript, join(sourceRoot, "scripts/generate.mjs"));
  writeFileSync(join(sourceRoot, "proto/enoki/v1/probe.proto"), "");
  writeFileSync(
    join(sourceTsOut, "enoki_pb.js"),
    'import $protobuf from "protobufjs/minimal.js";\nexport default $protobuf;\n',
  );
  writeFileSync(
    join(sourceTsOut, "enoki_pb.d.ts"),
    "declare const root: {};\n",
  );
  writeFileSync(join(sourceRustOut, "enoki.v1.rs"), "pub struct Previous;\n");
  linkSync(
    join(sourceTsOut, "enoki_pb.js"),
    join(installedTsOut, "enoki_pb.js"),
  );
  writeFileSync(
    join(installedRoot, "package.json"),
    JSON.stringify({
      exports: {
        "./generated/ts/enoki_pb.js": "./src/generated/ts/enoki_pb.js",
      },
      name: "@enoki/proto",
      type: "module",
    }),
  );
  writeFileSync(
    join(repoRoot, "node_modules/protobufjs/package.json"),
    JSON.stringify({
      exports: { "./minimal.js": "./minimal.js" },
      name: "protobufjs",
      type: "module",
    }),
  );
  writeFileSync(
    join(repoRoot, "node_modules/protobufjs/minimal.js"),
    "export default {};\n",
  );
  writeFileSync(join(repoRoot, "package.json"), '{"type":"module"}\n');
  writeMockCommands(binRoot);

  return {
    binRoot,
    failFirstPbjs: options.failFirstPbjs,
    readyFile,
    repoRoot,
    sourceRoot,
  };
}

function writeMockCommands(binRoot: string) {
  const pnpm = join(binRoot, "pnpm");
  const cargo = join(binRoot, "cargo");

  writeFileSync(
    pnpm,
    `#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const args = process.argv.slice(2);
const output = args[args.indexOf("--out") + 1];
const wrap = args[args.indexOf("--wrap") + 1];

mkdirSync(dirname(output), { recursive: true });
if (args.includes("pbjs") && wrap === "es6") {
  writeFileSync(output, 'import * as $protobuf from "protobufjs/minimal";\\nexport default $protobuf;\\n');
  writeFileSync(process.env.ATOMIC_GENERATE_READY_FILE, "ready");
  if (process.env.ATOMIC_GENERATE_FAIL_FIRST_PBJS === "true") {
    process.exit(1);
  }
  await new Promise((resolve) => setTimeout(resolve, 400));
} else if (args.includes("pbjs")) {
  writeFileSync(output, "export default {};\\n");
} else {
  writeFileSync(output, "declare const root: {};\\n");
}
`,
  );
  writeFileSync(
    cargo,
    `#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";

const output = process.argv.at(-1);
mkdirSync(output, { recursive: true });
writeFileSync(output + "/enoki.v1.rs", "pub struct Current;\\n");
`,
  );
  chmodSync(pnpm, 0o755);
  chmodSync(cargo, 0o755);
}

function startGenerate(fixture: ReturnType<typeof createFixture>) {
  return spawn(
    process.execPath,
    [join(fixture.sourceRoot, "scripts/generate.mjs")],
    {
      env: {
        ...process.env,
        ATOMIC_GENERATE_FAIL_FIRST_PBJS: String(Boolean(fixture.failFirstPbjs)),
        ATOMIC_GENERATE_READY_FILE: fixture.readyFile,
        PATH: `${fixture.binRoot}:${process.env.PATH}`,
      },
    },
  );
}

function importInstalledProto(repoRoot: string) {
  return spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      'await import("@enoki/proto/generated/ts/enoki_pb.js");',
    ],
    { cwd: repoRoot },
  );
}

function stagingDirectories(sourceRoot: string) {
  return readdirSync(join(sourceRoot, "src")).filter((entry) =>
    entry.startsWith(".generated-"),
  );
}

async function waitForFile(file: string) {
  const deadline = Date.now() + 5_000;

  while (Date.now() < deadline) {
    try {
      accessSync(file);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  throw new Error(`Timed out waiting for ${file}`);
}

function waitForExit(child: ReturnType<typeof spawn>) {
  return new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code));
  });
}
