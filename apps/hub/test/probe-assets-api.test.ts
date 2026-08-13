import {
  appendFile,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
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

  it("serves signed Probe assets without owner auth and has no installer endpoint", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    await mkdir(assetDir, { recursive: true });
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
      },
    });

    expect((await app.request("/api/probe/install.sh")).status).toBe(404);
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
      },
    });

    const response = await app.request("/api/probe/assets/..%2Fsecret");

    expect(response.status).toBe(404);
  });

  it("does not follow asset symlinks outside the Probe asset directory", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(path.join(root, "secret.pem"), "secret");
    await symlink(
      path.join(root, "secret.pem"),
      path.join(assetDir, "signing-key.pem"),
    );

    const app = createHubApp({
      probeAssets: {
        assetDir,
      },
    });

    const response = await app.request("/api/probe/assets/signing-key.pem");

    expect(response.status).toBe(404);
    await expect(response.text()).resolves.not.toContain("secret");
  });

  it("rejects final symlinks for Probe metadata", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(path.join(assetDir, "actual-manifest"), '{"assets":[]}');
    await symlink(
      path.join(assetDir, "actual-manifest"),
      path.join(assetDir, "manifest.json"),
    );

    const app = createHubApp({
      probeAssets: {
        assetDir,
      },
    });

    expect((await app.request("/api/probe/assets/manifest.json")).status).toBe(
      404,
    );
  });

  it("does not follow a Probe installation package symlink outside the asset directory", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    const packageName = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";
    await mkdir(assetDir, { recursive: true });
    await writeFile(path.join(root, "secret-package"), "secret");
    await symlink(
      path.join(root, "secret-package"),
      path.join(assetDir, packageName),
    );

    const app = createHubApp({
      probeAssets: {
        assetDir,
      },
    });

    const response = await app.request(`/api/probe/assets/${packageName}`);
    expect(response.status).toBe(404);
  });

  it("streams bounded Probe installation packages and rejects excess live streams with retry guidance", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    const packageName = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";
    await mkdir(assetDir, { recursive: true });
    await writeFile(
      path.join(assetDir, packageName),
      Buffer.alloc(2 * 1024 * 1024, 7),
    );

    const app = createHubApp({
      probeAssets: {
        assetDir,
        maxConcurrentPackageStreams: 1,
        packageStreamHighWaterMark: 1,
      },
    });

    const first = await app.request(`/api/probe/assets/${packageName}`);
    expect(first.status).toBe(200);
    expect(first.headers.get("content-length")).toBe(String(2 * 1024 * 1024));
    expect(first.headers.get("accept-ranges")).toBe("none");
    expect(first.body).not.toBeNull();

    const congested = await app.request(`/api/probe/assets/${packageName}`);
    expect(congested.status).toBe(503);
    expect(congested.headers.get("retry-after")).toBe("1");

    await first.body!.cancel();
    const retried = await app.request(`/api/probe/assets/${packageName}`);
    expect(retried.status).toBe(200);
    await retried.body!.cancel();
  });

  it("keeps a package response within its initial signed length when the inode grows", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    const packageName = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";
    const packagePath = path.join(assetDir, packageName);
    const initial = Buffer.from("signed package");
    await mkdir(assetDir, { recursive: true });
    await writeFile(packagePath, initial);

    const app = createHubApp({
      probeAssets: {
        assetDir,
        packageStreamHighWaterMark: 1,
      },
    });

    const response = await app.request(`/api/probe/assets/${packageName}`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-length")).toBe(
      String(initial.byteLength),
    );

    await appendFile(packagePath, " attacker-controlled suffix");

    expect(Buffer.from(await response.arrayBuffer())).toEqual(initial);
  });

  it("releases a stalled package stream after its duration limit", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    const packageName = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";
    await mkdir(assetDir, { recursive: true });
    await writeFile(path.join(assetDir, packageName), "archive");

    const app = createHubApp({
      probeAssets: {
        assetDir,
        maxConcurrentPackageStreams: 1,
        maxPackageStreamDurationMs: 1,
      },
    });

    const stalled = await app.request(`/api/probe/assets/${packageName}`);
    expect(stalled.status).toBe(200);

    await new Promise((resolve) => setTimeout(resolve, 20));

    const retried = await app.request(`/api/probe/assets/${packageName}`);
    expect(retried.status).toBe(200);
    await retried.body!.cancel();
  });

  it("bounds metadata reads and rejects Range requests instead of creating a resume path", async () => {
    const root = await createTempRoot();
    const assetDir = path.join(root, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(path.join(assetDir, "manifest.json"), "x".repeat(17));

    const app = createHubApp({
      probeAssets: {
        assetDir,
        maxMetadataBytes: 16,
      },
    });

    expect((await app.request("/api/probe/assets/manifest.json")).status).toBe(
      404,
    );
    expect(
      (
        await app.request("/api/probe/assets/manifest.json", {
          headers: { range: "bytes=0-1" },
        })
      ).status,
    ).toBe(416);
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
