import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

describe("create-probe-asset-manifest", () => {
  it("stores the asset set version without the release tag prefix", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-manifest-"));

    try {
      await writeFile(
        path.join(workDir, "enoki-probe-x86_64-unknown-linux-gnu.tar.gz"),
        "probe archive",
      );

      await execFileAsync(
        "node",
        ["scripts/create-probe-asset-manifest.mjs", workDir],
        {
          env: {
            ...process.env,
            ENOKI_PROBE_VERSION: "v0.1.18",
          },
        },
      );

      const manifest = JSON.parse(
        await readFile(path.join(workDir, "manifest.json"), "utf8"),
      );

      expect(manifest.version).toBe("0.1.18");
    } finally {
      await rm(workDir, {
        force: true,
        recursive: true,
      });
    }
  });
});
