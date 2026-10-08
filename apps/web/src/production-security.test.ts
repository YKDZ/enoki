import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const productionDist = join(
  resolve(dirname(fileURLToPath(import.meta.url)), ".."),
  "dist",
);

describe("production Web security boundary", () => {
  it("emits only external scripts and same-origin static resources", async () => {
    const index = await readFile(join(productionDist, "index.html"), "utf8");
    const scriptTags = [
      ...index.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi),
    ];
    expect(scriptTags.length).toBeGreaterThan(0);
    expect(scriptTags.every(([tag]) => /\bsrc=["'][^"']+["']/.test(tag))).toBe(
      true,
    );
    expect(scriptTags.some(([tag]) => /theme-init\.js/.test(tag))).toBe(true);

    for (const assetPath of await textAssets(productionDist)) {
      const content = await readFile(assetPath, "utf8");
      expect(content).not.toMatch(
        /(?:\b(?:href|src)=["']https?:|@import\s+(?:url\()?['"]?https?:|url\(\s*['"]?https?:)/i,
      );
    }
  });
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
