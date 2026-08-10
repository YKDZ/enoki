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

  it("creates a pending NewHost Enrollment with a copyable Probe install command", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      installation: {
        installPath: "/usr/local/bin/enoki-probe",
        installScriptPath: "/api/probe/install.sh",
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
      enrollmentId: string;
      enrollmentToken: string;
      expiresAtMs: number;
      installCommand: string;
      installPath: string;
      status: string;
    };

    expect(body.enrollmentId).toMatch(/^enr_/);
    expect(body.status).toBe("pending");
    expect(body.expiresAtMs).toBeGreaterThan(Date.now() - 1_000);
    expect(body.installPath).toBe("/usr/local/bin/enoki-probe");
    expect(body.installCommand).toContain(
      "https://hub.example/api/probe/install.sh",
    );
    expect(body.installCommand).toContain(
      "ENOKI_HUB_URL='https://hub.example'",
    );
    expect(body.installCommand).toContain(
      `ENOKI_ENROLLMENT_TOKEN='${body.enrollmentToken}'`,
    );
    expect(body.installCommand).not.toContain("ENOKI_PROBE_VERSION=");
    expect(body.installCommand).not.toContain("ENOKI_PROBE_DOWNLOAD_URL=");
    expect(body.installCommand).not.toContain("ENOKI_INSTALL_PATH=");
    expect(
      database.sqlite
        .prepare("select count(*) as count from managed_hosts")
        .get(),
    ).toEqual({ count: 0 });

    database.close();
  });

  it("keeps explicit install path overrides in the generated command", async () => {
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
        installScriptPath: "/api/probe/install.sh",
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
      installCommand: string;
      installPath: string;
    };

    expect(body.installPath).toBe("/opt/enoki/bin/enoki-probe");
    expect(body.installCommand).toContain(
      "ENOKI_INSTALL_PATH='/opt/enoki/bin/enoki-probe'",
    );

    database.close();
  });

  it("keeps NewHost and ExistingHost install command shapes identical apart from their tokens", async () => {
    const database = await createTemporaryDatabase();
    database.hosts.create({
      clockSkewDetected: false,
      connectAddress: "203.0.113.10",
      createdAtMs: 1_725_000_000_000,
      displayName: "Offline Host",
      displayNameEdited: false,
      id: 7,
      lastClockSkewMs: null,
      probeConfigurationVersion: "default-v1",
      probeId: "probe-offline-host",
      probeSecretHash: "secret-hash-offline-host",
    });
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      installation: {
        installPath: "/usr/local/bin/enoki-probe",
        installScriptPath: "/api/probe/install.sh",
        publicHubUrl: "https://hub.example",
      },
    });
    const ownerSession = await loginOwner(app);
    const newHost = await app.request("/api/web/enrollments", {
      headers: { cookie: ownerSession },
      method: "POST",
    });
    const existingHost = await app.request("/api/web/enrollments", {
      body: JSON.stringify({
        target: { hostId: 7, kind: "existing_host" },
      }),
      headers: { "content-type": "application/json", cookie: ownerSession },
      method: "POST",
    });
    expect(newHost.status).toBe(201);
    expect(existingHost.status).toBe(201);
    const newCommand = (await newHost.json()) as {
      enrollmentToken: string;
      installCommand: string;
    };
    const existingCommand = (await existingHost.json()) as {
      enrollmentToken: string;
      installCommand: string;
    };

    expect(
      newCommand.installCommand.replace(newCommand.enrollmentToken, "<token>"),
    ).toBe(
      existingCommand.installCommand.replace(
        existingCommand.enrollmentToken,
        "<token>",
      ),
    );
    expect(newCommand.installCommand).not.toContain("ENOKI_ENROLLMENT_TARGET");
    expect(existingCommand.installCommand).not.toContain(
      "ENOKI_ENROLLMENT_TARGET",
    );

    database.close();
  });

  it("persists an overdue pending Enrollment as expired when the Owner reads its status", async () => {
    const database = await createTemporaryDatabase();
    let nowMs = 1_725_000_000_000;
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => nowMs,
    });
    const ownerSession = await loginOwner(app);
    const created = await app.request("/api/web/enrollments", {
      headers: { cookie: ownerSession },
      method: "POST",
    });
    const enrollment = (await created.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
      expiresAtMs: number;
    };

    nowMs = enrollment.expiresAtMs;
    const statusResponse = await app.request(
      `/api/web/enrollments/${enrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );

    expect(statusResponse.status).toBe(200);
    await expect(statusResponse.json()).resolves.toEqual({
      createdAtMs: 1_725_000_000_000,
      enrollmentId: enrollment.enrollmentId,
      expiresAtMs: enrollment.expiresAtMs,
      expiredAtMs: enrollment.expiresAtMs,
      hostId: null,
      readyAtMs: null,
      rejectedAtMs: null,
      rejection: null,
      status: "expired",
      target: { kind: "new_host" },
      verificationDeadlineAtMs: null,
    });
    expect(
      database.sqlite
        .prepare(
          "select status, expired_at_ms as expiredAtMs from enrollment_tokens where enrollment_id = ?",
        )
        .get(enrollment.enrollmentId),
    ).toEqual({
      expiredAtMs: enrollment.expiresAtMs,
      status: "expired",
    });

    database.close();
  });
});
