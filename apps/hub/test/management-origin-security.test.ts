import type { UpgradeWebSocket } from "hono/ws";
import { describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";

const managementOrigin = "https://manage.example";

describe("management same-origin boundary", () => {
  it("rejects a cross-site form login before authentication state changes", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        managementOrigin,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });

    const response = await app.request(
      "https://attacker.example/api/web/auth/login",
      {
        body: "password=correct+horse+battery+staple",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          forwarded: "host=manage.example;proto=https",
          host: "manage.example",
          origin: "https://attacker.example",
          "sec-fetch-site": "cross-site",
          "x-forwarded-host": "manage.example",
          "x-forwarded-proto": "https",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(403);
    expect(response.headers.get("set-cookie")).toBeNull();
  });

  it("rejects same-site cross-origin logout even when the session cookie is present", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        managementOrigin,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });
    const login = await app.request(`${managementOrigin}/api/web/auth/login`, {
      body: JSON.stringify({ password: "correct horse battery staple" }),
      headers: { "content-type": "application/json", origin: managementOrigin },
      method: "POST",
    });
    const cookie = login.headers.get("set-cookie") ?? "";

    const response = await app.request(
      `${managementOrigin}/api/web/auth/logout`,
      {
        headers: {
          cookie,
          origin: "https://sibling.example",
          "sec-fetch-site": "same-site",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(403);
    const session = await app.request(
      `${managementOrigin}/api/web/auth/session`,
      {
        headers: { cookie },
      },
    );
    await expect(session.json()).resolves.toEqual({ authenticated: true });
  });

  it("rejects content-type confusion on no-password management writes", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        managementOrigin,
        noPasswordWebUi: true,
        sessionCookieName: "enoki_owner_session",
      },
    });

    const response = await app.request(
      `${managementOrigin}/api/web/auth/login`,
      {
        body: JSON.stringify({}),
        headers: { "content-type": "text/plain", origin: managementOrigin },
        method: "POST",
      },
    );

    expect(response.status).toBe(415);
  });

  it("rejects malformed JSON before a no-password management write", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        managementOrigin,
        noPasswordWebUi: true,
        sessionCookieName: "enoki_owner_session",
      },
    });

    const response = await app.request(
      `${managementOrigin}/api/web/auth/login`,
      {
        body: "{",
        headers: {
          "content-type": "application/json",
          origin: managementOrigin,
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(400);
  });

  it("rejects a cross-origin authenticated WebSocket before upgrade", async () => {
    let upgradeInvoked = false;
    const upgradeWebSocket = (() =>
      async (context: { text: (body: string) => Response }) => {
        upgradeInvoked = true;
        return context.text("upgraded");
      }) as unknown as UpgradeWebSocket;
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        managementOrigin,
        noPasswordWebUi: true,
        sessionCookieName: "enoki_owner_session",
      },
      webSocket: { upgradeWebSocket },
    });

    const response = await app.request(`${managementOrigin}/api/web/ws`, {
      headers: {
        connection: "upgrade",
        forwarded: "host=manage.example;proto=https",
        host: "manage.example",
        origin: "https://attacker.example",
        upgrade: "websocket",
        "x-forwarded-host": "manage.example",
        "x-forwarded-proto": "https",
      },
    });

    expect(response.status).toBe(403);
    expect(upgradeInvoked).toBe(false);
  });

  it("does not authorize a cross-origin JSON preflight", async () => {
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        managementOrigin,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
    });

    const response = await app.request(
      `${managementOrigin}/api/web/auth/login`,
      {
        headers: {
          "access-control-request-headers": "content-type",
          "access-control-request-method": "POST",
          origin: "https://attacker.example",
          "sec-fetch-site": "cross-site",
        },
        method: "OPTIONS",
      },
    );

    expect(response.status).toBe(403);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(response.headers.get("access-control-allow-credentials")).toBeNull();
  });

  it.each(["http://manage.example:8080", "https://manage.example"])(
    "allows normal same-origin login and WebSocket upgrade at %s",
    async (explicitOrigin) => {
      let upgradeInvoked = false;
      const upgradeWebSocket = (() =>
        async (context: { text: (body: string) => Response }) => {
          upgradeInvoked = true;
          return context.text("upgraded");
        }) as unknown as UpgradeWebSocket;
      const app = createHubApp({
        auth: {
          failureDelayMs: 0,
          managementOrigin: explicitOrigin,
          ownerPassword: "correct horse battery staple",
          sessionCookieName: "enoki_owner_session",
        },
        webSocket: { upgradeWebSocket },
      });
      const login = await app.request(`${explicitOrigin}/api/web/auth/login`, {
        body: JSON.stringify({ password: "correct horse battery staple" }),
        headers: {
          "content-type": "application/json",
          origin: explicitOrigin,
          "sec-fetch-site": "same-origin",
        },
        method: "POST",
      });
      const cookie = login.headers.get("set-cookie") ?? "";

      expect(login.status).toBe(200);
      const webSocket = await app.request(`${explicitOrigin}/api/web/ws`, {
        headers: {
          connection: "upgrade",
          cookie,
          origin: explicitOrigin,
          upgrade: "websocket",
        },
      });
      expect(webSocket.status).toBe(200);
      expect(upgradeInvoked).toBe(true);
    },
  );
});
