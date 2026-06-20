import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";

describe("Hub Web asset serving", () => {
  it("serves built Web assets with history fallback", async () => {
    const webDistPath = await mkdtemp(join(tmpdir(), "enoki-web-dist-"));
    await writeFile(join(webDistPath, "index.html"), "<main>Enoki Web</main>");

    const app = createHubApp({ webDistPath });
    const response = await app.request("/hosts/managed-host-01");

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    await expect(response.text()).resolves.toBe("<main>Enoki Web</main>");
  });
});
