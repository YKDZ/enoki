import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { build } from "vite";
import { afterEach, describe, expect, it } from "vitest";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("production Web security boundary", () => {
  it("emits only external scripts and same-origin static resources", async () => {
    const outDir = await mkdtemp(join(tmpdir(), "enoki-web-security-"));
    temporaryDirectories.push(outDir);
    await build({
      build: { outDir },
      configFile: "vite.config.ts",
      logLevel: "silent",
    });

    const index = await readFile(join(outDir, "index.html"), "utf8");
    const scriptTags = [
      ...index.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi),
    ];
    expect(scriptTags.length).toBeGreaterThan(0);
    expect(scriptTags.every(([tag]) => /\bsrc=["'][^"']+["']/.test(tag))).toBe(
      true,
    );
    expect(scriptTags.some(([tag]) => /theme-init\.js/.test(tag))).toBe(true);

    for (const assetPath of await textAssets(outDir)) {
      const content = await readFile(assetPath, "utf8");
      expect(content).not.toMatch(
        /(?:\b(?:href|src)=["']https?:|@import\s+(?:url\()?['"]?https?:|url\(\s*['"]?https?:)/i,
      );
    }
  }, 30_000);
});

async function textAssets(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        return textAssets(path);
      }
      return /\.(?:css|html|js)$/.test(entry.name) ? [path] : [];
    }),
  );

  return paths.flat();
}
