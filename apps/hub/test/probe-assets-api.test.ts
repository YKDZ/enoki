import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";

const tempRoots: string[] = [];

describe("Probe asset API", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("serves the installer and signed Probe assets without owner auth", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    const installScriptPath = path.join(root, "install-probe.sh");
    await mkdir(assetDir, { recursive: true });
    await writeFile(installScriptPath, "#!/usr/bin/env bash\necho install\n");
    await writeFile(path.join(assetDir, "manifest.json"), '{"assets":[]}');
    await writeFile(path.join(assetDir, "manifest.json.sig"), "signature");
    await writeFile(path.join(assetDir, "signing-key.pem"), "public key");
    await writeFile(path.join(assetDir, "enoki-probe-test.tar.gz"), "archive");

    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      probeAssets: {
        assetDir,
        installScriptPath,
      },
    });

    await expectText(app, "/api/probe/install.sh", "echo install");
    await expectText(app, "/api/probe/assets/manifest.json", '{"assets":[]}');
    await expectText(app, "/api/probe/assets/manifest.json.sig", "signature");
    await expectText(app, "/api/probe/assets/signing-key.pem", "public key");
    await expectText(
      app,
      "/api/probe/assets/enoki-probe-test.tar.gz",
      "archive",
    );
  });

  it("rejects invalid asset filenames", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(path.join(root, "secret"), "secret");

    const app = createHubApp({
      probeAssets: {
        assetDir,
        installScriptPath: path.join(root, "install-probe.sh"),
      },
    });

    const response = await app.request("/api/probe/assets/..%2Fsecret");

    expect(response.status).toBe(404);
  });
});

async function createTempRoot() {
  const root = await mkdtemp(path.join(os.tmpdir(), "enoki-probe-assets-"));
  tempRoots.push(root);

  return root;
}

async function expectText(
  app: ReturnType<typeof createHubApp>,
  route: string,
  expected: string,
) {
  const response = await app.request(route);

  expect(response.status).toBe(200);
  await expect(response.text()).resolves.toContain(expected);
}
