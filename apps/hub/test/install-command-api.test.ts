import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-install-db-"));
  tempRoots.push(dataRoot);

  return initializeHubDatabase({
    dataRoot,
    sqlitePath: path.join(dataRoot, "enoki.db"),
  });
}

async function loginOwner(app: ReturnType<typeof createHubApp>) {
  const response = await app.request("/api/web/auth/login", {
    body: JSON.stringify({
      password: "correct horse battery staple",
    }),
    headers: {
      "content-type": "application/json",
    },
    method: "POST",
  });

  expect(response.status).toBe(200);
  return response.headers.get("set-cookie") ?? "";
}

describe("Owner add-host install command", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("creates a pending Enrollment Token with a copyable Probe install command", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      installation: {
        installPath: "/opt/enoki/bin/enoki-probe",
        installScriptUrl:
          "https://github.com/example/enoki/releases/download/v0.1.0/install-probe.sh",
        probeReleaseVersion: "v0.1.0",
        publicHubUrl: "https://hub.example",
      },
    });
    const ownerSession = await loginOwner(app);

    const response = await app.request("/api/web/enrollments", {
      headers: {
        cookie: ownerSession,
      },
      method: "POST",
    });

    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      enrollmentToken: string;
      installCommand: string;
      installPath: string;
      probeReleaseVersion: string;
    };

    expect(body.installPath).toBe("/opt/enoki/bin/enoki-probe");
    expect(body.probeReleaseVersion).toBe("v0.1.0");
    expect(body.installCommand).toContain(
      "https://github.com/example/enoki/releases/download/v0.1.0/install-probe.sh",
    );
    expect(body.installCommand).toContain(
      "ENOKI_HUB_URL='https://hub.example'",
    );
    expect(body.installCommand).toContain(
      `ENOKI_ENROLLMENT_TOKEN='${body.enrollmentToken}'`,
    );
    expect(body.installCommand).toContain("ENOKI_PROBE_VERSION='v0.1.0'");
    expect(body.installCommand).toContain(
      "ENOKI_INSTALL_PATH='/opt/enoki/bin/enoki-probe'",
    );

    database.close();
  });
});
