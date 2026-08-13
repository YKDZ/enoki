import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { createMemoryOwnerSessionRepository } from "../src/auth/memory-owner-session-repository";
import { createMemoryPasswordVerificationBudget } from "../src/auth/password-verification-budget";
import { createOwnerAuth } from "../src/auth/routes";
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

  it("stores only a digest of each opaque Owner session token", async () => {
    const ownerSessions = createMemoryOwnerSessionRepository();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      ownerSessions,
    });

    const response = await app.request("/api/web/auth/login", {
      body: JSON.stringify({
        password: "correct horse battery staple",
      }),
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
    });
    const token = response.headers
      .get("set-cookie")
      ?.match(/enoki_owner_session=([^;]+)/)?.[1];

    expect(token).toBeTruthy();
    expect(ownerSessions.list()).toEqual([
      expect.objectContaining({
        tokenDigest: createHash("sha256")
          .update(token ?? "")
          .digest("hex"),
      }),
    ]);
    expect(JSON.stringify(ownerSessions.list())).not.toContain(token);
  });

  it("clears expired sessions before issuing a replacement", async () => {
    let nowMs = 1_725_000_000_000;
    const invalidated: string[] = [];
    const ownerSessions = createMemoryOwnerSessionRepository();
    const auth = createOwnerAuth(
      {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      {
        now: () => nowMs,
        onSessionInvalidated: (sessionId) => invalidated.push(sessionId),
        ownerSessions,
      },
    );
    const login = () =>
      auth.routes.request("/login", {
        body: JSON.stringify({ password: "correct horse battery staple" }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });

    await login();
    const expiredDigest = ownerSessions.list()[0]?.tokenDigest;
    nowMs += 7 * 24 * 60 * 60 * 1000 + 1;
    await login();

    expect(ownerSessions.list()).toHaveLength(1);
    expect(invalidated).toEqual([expiredDigest]);
  });

  it("keeps at most eight sessions and deterministically evicts the oldest created", async () => {
    const invalidated: string[] = [];
    const ownerSessions = createMemoryOwnerSessionRepository();
    const auth = createOwnerAuth(
      {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      {
        now: () => 1_725_000_000_000,
        onSessionInvalidated: (sessionId) => invalidated.push(sessionId),
        ownerSessions,
        passwordVerificationBudget: createMemoryPasswordVerificationBudget({
          capacity: 20,
        }),
      },
    );
    const login = async () => {
      const response = await auth.routes.request("/login", {
        body: JSON.stringify({ password: "correct horse battery staple" }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      return response.headers.get("set-cookie") ?? "";
    };

    const cookies = await Promise.all(
      Array.from({ length: 20 }, async () => login()),
    );

    expect(ownerSessions.list()).toHaveLength(8);
    expect(invalidated).toHaveLength(12);
    for (const [index, cookie] of cookies.entries()) {
      const response = await auth.routes.request("/session", {
        headers: { cookie },
      });
      await expect(response.json(), String(index)).resolves.toEqual({
        authenticated: index >= 12,
      });
    }
  });

  it("does not preserve Owner sessions across restart, password replacement, or Hub Restore", async () => {
    const config = {
      failureDelayMs: 0,
      ownerPassword: "correct horse battery staple",
      sessionCookieName: "enoki_owner_session",
    };
    const originalAuth = createOwnerAuth(config);
    const loginResponse = await originalAuth.routes.request("/login", {
      body: JSON.stringify({ password: config.ownerPassword }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    const cookie = loginResponse.headers.get("set-cookie") ?? "";
    const replacementInstances = [
      createOwnerAuth(config),
      createOwnerAuth({ ...config, ownerPassword: "replacement password" }),
      createOwnerAuth(config),
    ];

    for (const auth of replacementInstances) {
      const response = await auth.routes.request("/session", {
        headers: { cookie },
      });
      await expect(response.json()).resolves.toEqual({ authenticated: false });
    }
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

  it("sets Secure based only on the configured HTTPS Management Origin", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        managementOrigin: "https://manage.example",
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
    expect(cookie).toContain("Path=/api/web");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Secure");
    expect(cookie).not.toContain("Domain=");
    expect(cookie).not.toContain("__Host-");
  });

  it("ignores forwarded protocol when setting session cookies", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        managementOrigin: "https://manage.example",
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
    expect(response.headers.get("set-cookie")).toContain("Secure");
  });

  it("does not let forwarded protocol make an HTTP Management Origin Secure", async () => {
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
    const cookie = response.headers.get("set-cookie");
    expect(cookie).toContain("enoki_owner_session=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Path=/api/web");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).not.toContain("Domain=");
    expect(cookie).not.toContain("Secure");
    expect(cookie).not.toContain("__Host-");
  });

  it("sets Secure session cookies when the Management Origin is HTTPS", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        managementOrigin: "https://manage.example",
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

  it("allows browser data requests without a session when no-password Web UI mode is enabled", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        noPasswordWebUi: true,
        sessionCookieName: "enoki_owner_session",
      },
    });

    const sessionResponse = await app.request("/api/web/auth/session");
    expect(sessionResponse.status).toBe(200);
    await expect(sessionResponse.json()).resolves.toEqual({
      authenticated: true,
    });

    const hostsResponse = await app.request("/api/web/hosts");
    expect(hostsResponse.status).toBe(200);
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [],
    });

    const loginResponse = await app.request("/api/web/auth/login", {
      method: "POST",
    });
    expect(loginResponse.status).toBe(200);
    expect(loginResponse.headers.get("set-cookie")).toBeNull();
    await expect(loginResponse.json()).resolves.toEqual({
      authenticated: true,
    });

    const logoutResponse = await app.request("/api/web/auth/logout", {
      method: "POST",
    });
    expect(logoutResponse.status).toBe(200);
    await expect(logoutResponse.json()).resolves.toEqual({
      authenticated: true,
    });
  });

  it("throttles a correct password before verification when the global budget is exhausted", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      now: () => 1_725_000_000_000,
    });
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await app.request("/api/web/auth/login", {
        body: JSON.stringify({ password: "wrong password" }),
        headers: {
          "content-type": "application/json",
          "user-agent": `owner-login-test-${attempt}`,
          "x-forwarded-for": `203.0.113.${attempt + 1}`,
        },
        method: "POST",
      });
      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toEqual({
        error: "invalid_credentials",
      });
    }

    const limitedResponse = await app.request("/api/web/auth/login", {
      body: JSON.stringify({ password: "correct horse battery staple" }),
      headers: {
        "content-type": "application/json",
        "user-agent": "correct-owner-login",
        "x-forwarded-for": "198.51.100.200",
      },
      method: "POST",
    });

    expect(limitedResponse.status).toBe(429);
    expect(limitedResponse.headers.get("retry-after")).toBe("180");
    expect(limitedResponse.headers.get("set-cookie")).toBeNull();
    await expect(limitedResponse.json()).resolves.toEqual({
      error: "too_many_login_attempts",
    });
  });

  it("charges successful and failed password verifications to the same global budget", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });
    const loginRequest = (password: string) => ({
      body: JSON.stringify({ password }),
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "203.0.113.8",
      },
      method: "POST",
    });

    for (const password of [
      "wrong password",
      "correct horse battery staple",
      "wrong password",
      "correct horse battery staple",
      "wrong password",
    ]) {
      const response = await app.request(
        "/api/web/auth/login",
        loginRequest(password),
      );
      expect(response.status).toBe(
        password === "correct horse battery staple" ? 200 : 401,
      );
    }

    const limitedResponse = await app.request(
      "/api/web/auth/login",
      loginRequest("correct horse battery staple"),
    );
    expect(limitedResponse.status).toBe(429);
  });

  it("returns the same exhausted-budget response for correct and incorrect passwords", async () => {
    const throttledResponse = async (password: string) => {
      const auth = createOwnerAuth({
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      });
      const request = (candidate: string) =>
        auth.routes.request("/login", {
          body: JSON.stringify({ password: candidate }),
          headers: { "content-type": "application/json" },
          method: "POST",
        });

      for (let attempt = 0; attempt < 5; attempt += 1) {
        await request("wrong password");
      }

      const response = await request(password);
      return {
        body: await response.json(),
        retryAfter: response.headers.get("retry-after"),
        status: response.status,
      };
    };

    await expect(
      throttledResponse("correct horse battery staple"),
    ).resolves.toEqual(await throttledResponse("wrong password"));
  });

  it("accepts another verification after one token continuously refills", async () => {
    let monotonicNowMs = 100;
    const auth = createOwnerAuth(
      {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      {
        delay: async () => {},
        passwordVerificationBudget: createMemoryPasswordVerificationBudget({
          monotonicNow: () => monotonicNowMs,
        }),
      },
    );
    const loginRequest = {
      body: JSON.stringify({ password: "wrong password" }),
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "203.0.113.9",
      },
      method: "POST",
    };

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await auth.routes.request("/login", loginRequest);
      expect(response.status).toBe(401);
    }

    monotonicNowMs += 180_000;
    const response = await auth.routes.request("/login", loginRequest);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_credentials",
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

  it("caps the bounded delay applied after a failed password verification", async () => {
    const delays: number[] = [];
    const auth = createOwnerAuth(
      {
        failureDelayMs: 60_000,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      {
        delay: async (milliseconds) => {
          delays.push(milliseconds);
        },
      },
    );

    const response = await auth.routes.request("/login", {
      body: JSON.stringify({ password: "wrong password" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });

    expect(response.status).toBe(401);
    expect(delays).toEqual([1_000]);
  });

  it("bounds concurrent failed-verification delays by the global budget capacity", async () => {
    const delayedRequests: Array<() => void> = [];
    const auth = createOwnerAuth(
      {
        failureDelayMs: 1_000,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      {
        delay: () =>
          new Promise<void>((resolve) => {
            delayedRequests.push(resolve);
          }),
      },
    );
    const request = {
      body: JSON.stringify({ password: "wrong password" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    };

    const responses = Array.from({ length: 100 }, async () =>
      auth.routes.request("/login", request),
    );
    await new Promise<void>((resolve) => setImmediate(resolve));

    expect(delayedRequests).toHaveLength(5);
    for (const resolve of delayedRequests) resolve();
    const statuses = (await Promise.all(responses)).map(
      (response) => response.status,
    );
    expect(statuses.filter((status) => status === 401)).toHaveLength(5);
    expect(statuses.filter((status) => status === 429)).toHaveLength(95);
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
    expect(logoutResponse.headers.get("set-cookie")).toContain("Path=/api/web");
    expect(logoutResponse.headers.get("set-cookie")).toContain(
      "SameSite=Strict",
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
