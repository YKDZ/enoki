import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-auth-db-"));
  tempRoots.push(dataRoot);

  return initializeHubDatabase({
    dataRoot,
    sqlitePath: path.join(dataRoot, "enoki.db"),
  });
}

describe("Owner authentication API", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("rejects unauthenticated browser data requests", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });

    const response = await app.request("/api/web/hosts");

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "owner_session_required",
    });
  });

  it("rejects unauthenticated browser data namespace requests by default", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });

    const response = await app.request("/api/web/future-data-route");

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "owner_session_required",
    });
  });

  it("creates an HTTP-only SameSite=Lax Owner session after login", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });

    const response = await app.request(
      "https://enoki.example/api/web/auth/login",
      {
        body: JSON.stringify({
          password: "correct horse battery staple",
        }),
        headers: {
          "content-type": "application/json",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      authenticated: true,
    });

    const cookie = response.headers.get("set-cookie");
    expect(cookie).toContain("enoki_owner_session=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Secure");
  });

  it("sets Secure session cookies when HTTPS is terminated by a reverse proxy", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
        trustProxyHeaders: true,
      },
    });

    const response = await app.request(
      "http://hub.internal/api/web/auth/login",
      {
        body: JSON.stringify({
          password: "correct horse battery staple",
        }),
        headers: {
          "content-type": "application/json",
          "x-forwarded-proto": "https",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toContain("Secure");
  });

  it("does not trust forwarded HTTPS headers by default when setting session cookies", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });

    const response = await app.request(
      "http://hub.internal/api/web/auth/login",
      {
        body: JSON.stringify({
          password: "correct horse battery staple",
        }),
        headers: {
          "content-type": "application/json",
          "x-forwarded-proto": "https",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).not.toContain("Secure");
  });

  it("sets Secure session cookies when the public Hub URL is HTTPS", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        publicHttps: true,
        sessionCookieName: "enoki_owner_session",
      },
    });

    const response = await app.request(
      "http://hub.internal/api/web/auth/login",
      {
        body: JSON.stringify({
          password: "correct horse battery staple",
        }),
        headers: {
          "content-type": "application/json",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toContain("Secure");
  });

  it("allows browser data requests with a valid Owner session", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });

    const loginResponse = await app.request("/api/web/auth/login", {
      body: JSON.stringify({
        password: "correct horse battery staple",
      }),
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
    });
    const sessionCookie = loginResponse.headers.get("set-cookie");

    const response = await app.request("/api/web/hosts", {
      headers: {
        cookie: sessionCookie ?? "",
      },
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      hosts: [],
    });
  });

  it("does not expose command-like browser or Probe API endpoints", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    });
    const loginResponse = await app.request("/api/web/auth/login", {
      body: JSON.stringify({
        password: "correct horse battery staple",
      }),
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
    });
    const ownerSession = loginResponse.headers.get("set-cookie") ?? "";
    const forbiddenWebApiPaths = [
      "/api/web/commands",
      "/api/web/shell",
      "/api/web/scripts",
      "/api/web/service-restarts",
      "/api/web/file-read",
      "/api/web/log-tail",
      "/api/web/external-checks",
      "/api/web/hosts/1/commands",
      "/api/web/hosts/1/shell",
      "/api/web/hosts/1/scripts",
      "/api/web/hosts/1/service-restarts",
      "/api/web/hosts/1/file-read",
      "/api/web/hosts/1/log-tail",
      "/api/web/hosts/1/external-checks",
    ];

    for (const path of forbiddenWebApiPaths) {
      const response = await app.request(path, {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      });

      expect(response.status, path).toBe(404);
    }

    for (const path of [
      "/api/probe/command",
      "/api/probe/shell",
      "/api/probe/script",
      "/api/probe/service-restart",
      "/api/probe/file-read",
      "/api/probe/log-tail",
      "/api/probe/external-check",
    ]) {
      const response = await app.request(path, {
        headers: {
          authorization: "Bearer enk_probe_placeholder",
        },
        method: "POST",
      });

      expect(response.status, path).toBe(404);
    }

    database.close();
  });

  it("delays failed login attempts without creating an Owner session", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 25,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });
    const startedAt = performance.now();

    const response = await app.request("/api/web/auth/login", {
      body: JSON.stringify({
        password: "wrong password",
      }),
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
    });

    expect(response.status).toBe(401);
    expect(performance.now() - startedAt).toBeGreaterThanOrEqual(20);
    expect(response.headers.get("set-cookie")).toBeNull();
    await expect(response.json()).resolves.toEqual({
      error: "invalid_credentials",
    });
  });

  it("records minimal audit events for Owner login attempts", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    });

    await app.request("/api/web/auth/login", {
      body: JSON.stringify({
        password: "wrong password",
      }),
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
    });
    await app.request("/api/web/auth/login", {
      body: JSON.stringify({
        password: "correct horse battery staple",
      }),
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
    });

    expect(database.audit.recent(2)).toEqual([
      expect.objectContaining({
        action: "owner.login",
        actor: "owner",
        outcome: "success",
      }),
      expect.objectContaining({
        action: "owner.login",
        actor: "owner",
        outcome: "failure",
      }),
    ]);
    database.close();
  });

  it("clears the Owner session on logout", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });
    const loginResponse = await app.request("/api/web/auth/login", {
      body: JSON.stringify({
        password: "correct horse battery staple",
      }),
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
    });
    const sessionCookie = loginResponse.headers.get("set-cookie") ?? "";

    const logoutResponse = await app.request("/api/web/auth/logout", {
      headers: {
        cookie: sessionCookie,
      },
      method: "POST",
    });

    expect(logoutResponse.status).toBe(200);
    expect(logoutResponse.headers.get("set-cookie")).toContain(
      "enoki_owner_session=",
    );
    await expect(logoutResponse.json()).resolves.toEqual({
      authenticated: false,
    });

    const protectedResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: sessionCookie,
      },
    });
    expect(protectedResponse.status).toBe(401);
  });
});
