import { mkdtemp, rm } from "node:fs/promises";
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
});
