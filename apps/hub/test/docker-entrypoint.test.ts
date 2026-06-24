import { spawn } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const entrypointScript = path.join(
  repositoryRoot,
  "apps/hub/docker-entrypoint.sh",
);
const tempRoots: string[] = [];

describe("Hub Docker entrypoint", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it.each(["/", "/app", "/usr", "relative/data", "/data/../usr"])(
    "rejects unsafe ENOKI_DATA_ROOT=%s before chowning",
    async (dataRoot) => {
      const result = await runEntrypoint({
        ENOKI_DATA_ROOT: dataRoot,
      });

      expect(result.code).toBe(1);
      expect(result.stderr).toContain("ENOKI_DATA_ROOT");
    },
  );

  it("rejects a symlink ENOKI_DATA_ROOT below /data before chowning", async () => {
    const root = await createTempRoot();
    const mockBin = path.join(root, "bin");
    const linkPath = `/data/enoki-entrypoint-link-${process.pid}-${Date.now()}`;
    await mkdir(mockBin, { recursive: true });
    await writeFile(
      path.join(mockBin, "id"),
      '#!/bin/sh\n[ "$1" = "-u" ] && { echo 1000; exit 0; }\nexit 1\n',
    );
    await chmod(path.join(mockBin, "id"), 0o755);
    await symlink("/app", linkPath);
    tempRoots.push(linkPath);

    const result = await runEntrypoint({
      ENOKI_DATA_ROOT: linkPath,
      PATH: `${mockBin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("ENOKI_DATA_ROOT");
  });
});

async function createTempRoot() {
  const root = await mkdtemp(path.join(os.tmpdir(), "enoki-entrypoint-"));
  tempRoots.push(root);

  return root;
}

async function runEntrypoint(environment: NodeJS.ProcessEnv) {
  const child = spawn("sh", [entrypointScript, "true"], {
    env: {
      ...process.env,
      ...environment,
    },
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });

  const code = await new Promise<number | null>((resolve) => {
    child.on("close", resolve);
  });

  return { code, stderr, stdout };
}
