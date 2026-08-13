import { execFile } from "node:child_process";
import {
  access,
  cp,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("Hub package test entrypoint", () => {
  it("tests the current source with clean or stale build output", async () => {
    const fixtureRoot = await createFixture();
    const serverOutput = join(fixtureRoot, "apps/hub/dist/src/server.js");
    const serverSource = join(fixtureRoot, "apps/hub/src/server.ts");

    await runPublicHubTest(fixtureRoot);
    await expect(access(serverOutput)).resolves.toBeUndefined();

    const currentSourceMarker = "current-source-after-stale-output";
    await writeFile(
      serverSource,
      `void "${currentSourceMarker}";\n${await readFile(serverSource, "utf8")}`,
    );
    const staleOutput = 'throw new Error("stale Hub build");\n';
    await writeFile(serverOutput, staleOutput);
    await runPublicHubTest(fixtureRoot);
    expect(await readFile(serverOutput, "utf8")).toContain(currentSourceMarker);
  }, 60_000);
});

async function createFixture() {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "enoki-hub-test-entry-"));
  temporaryDirectories.push(fixtureRoot);

  await Promise.all([
    ...[
      "package.json",
      "pnpm-lock.yaml",
      "pnpm-workspace.yaml",
      "tsconfig.base.json",
      "turbo.json",
    ].map((path) => cp(path, join(fixtureRoot, path))),
    copySourceDirectory("apps/hub", fixtureRoot),
    copySourceDirectory("packages/api-client", fixtureRoot),
    copySourceDirectory("packages/proto", fixtureRoot),
  ]);

  await execFileAsync("pnpm", ["install", "--frozen-lockfile", "--offline"], {
    cwd: fixtureRoot,
    env: { ...process.env, CI: "true" },
  });
  return fixtureRoot;
}

async function copySourceDirectory(source, fixtureRoot) {
  const destination = join(fixtureRoot, source);
  await mkdir(destination, { recursive: true });
  await cp(source, destination, {
    filter: (path) => !/\/(?:dist|node_modules)(?:\/|$)/.test(path),
    recursive: true,
  });
}

async function runPublicHubTest(fixtureRoot) {
  await execFileAsync(
    "pnpm",
    ["--filter", "@enoki/hub", "test", "test/server-startup.test.ts"],
    {
      cwd: fixtureRoot,
      env: { ...process.env, CI: "true" },
    },
  );
}
