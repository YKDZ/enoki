import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createProbeApiApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-probe-api-"));
  tempRoots.push(dataRoot);

  return initializeHubDatabase({
    dataRoot,
    sqlitePath: path.join(dataRoot, "enoki.db"),
  });
}

describe("Probe-only API surface", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("does not expose Web UI, Web API, or WebSocket routes", async () => {
    const database = await createTemporaryDatabase();
    const app = createProbeApiApp({ database });

    const healthResponse = await app.request("/api/health");
    expect(healthResponse.status).toBe(200);
    await expect(healthResponse.json()).resolves.toEqual({
      service: "enoki-hub",
      status: "ok",
    });

    const probeResponse = await app.request("/api/probe/config", {
      method: "POST",
    });
    expect(probeResponse.status).not.toBe(404);

    await expect(app.request("/api/web/auth/login")).resolves.toMatchObject({
      status: 404,
    });
    await expect(app.request("/api/web/ws")).resolves.toMatchObject({
      status: 404,
    });
    await expect(app.request("/hosts/1")).resolves.toMatchObject({
      status: 404,
    });

    database.close();
  });

  it("serves Probe installer assets from the probe-only API surface", async () => {
    const database = await createTemporaryDatabase();
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-probe-assets-"));
    tempRoots.push(root);
    const assetDir = path.join(root, "assets");
    const installScriptPath = path.join(assetDir, "install-probe.sh");
    await mkdir(assetDir, { recursive: true });
    await writeFile(installScriptPath, "#!/usr/bin/env bash\necho install\n");
    await writeFile(path.join(assetDir, "manifest.json"), '{"assets":[]}');

    const app = createProbeApiApp({
      database,
      probeAssets: {
        assetDir,
        installScriptPath,
      },
    });

    const installResponse = await app.request("/api/probe/install.sh");
    expect(installResponse.status).toBe(200);
    await expect(installResponse.text()).resolves.toContain("echo install");

    const manifestResponse = await app.request(
      "/api/probe/assets/manifest.json",
    );
    expect(manifestResponse.status).toBe(200);
    await expect(manifestResponse.text()).resolves.toContain('{"assets":[]}');

    database.close();
  });
});
