import { EventEmitter } from "node:events";
import type { AddressInfo } from "node:net";

import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { describe, expect, it, vi } from "vitest";

import { createHubApp, createProbeApiApp } from "../src/app";
import {
  createJsonLineHubLogger,
  createMemoryHubLogger,
  hubRouteId,
  readHubLogLevel,
} from "../src/hub-logger";
import {
  createHubNodeServer,
  createProbeApiNodeServer,
} from "../src/node-server";
import {
  createBoundedHubShutdown,
  installHubFatalHandlers,
} from "../src/process-lifecycle";

describe("Hub structured logging", () => {
  it("writes one bounded JSON line per production event and keeps sensitive input out", () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const logger = createJsonLineHubLogger({
      level: "debug",
      stderr: (line) => stderr.push(line),
      stdout: (line) => stdout.push(line),
    });

    logger.log({
      component: "hub",
      durationMs: 12,
      event: "request.completed",
      level: "info",
      method: "POST",
      outcome: "ok",
      requestId: "hub_request_id_1234567890",
      routeId: "web_auth_login",
      status: 200,
    });
    logger.log({
      component: "hub",
      event: "process.fatal",
      level: "error",
      outcome: "unhandled_rejection",
    });

    expect(stdout).toHaveLength(1);
    expect(stderr).toHaveLength(1);
    expect(JSON.parse(stdout[0] ?? "")).toEqual({
      component: "hub",
      durationMs: 12,
      event: "request.completed",
      level: "info",
      method: "POST",
      outcome: "ok",
      requestId: "hub_request_id_1234567890",
      routeId: "web_auth_login",
      status: 200,
    });
    expect(JSON.parse(stderr[0] ?? "")).toMatchObject({
      event: "process.fatal",
      level: "error",
      outcome: "unhandled_rejection",
    });
  });

  it("validates the startup-only Hub log level", () => {
    expect(readHubLogLevel(undefined)).toBe("info");
    expect(readHubLogLevel("debug")).toBe("debug");
    expect(() => readHubLogLevel("verbose")).toThrow("ENOKI_HUB_LOG_LEVEL");
  });

  it("uses Hub request IDs and logs recognized routes without request secrets", async () => {
    const memory = createMemoryHubLogger({ level: "debug" });
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      logger: memory.logger,
      requestId: () => "hub_request_id_1234567890",
    });
    const secret = "enrollment-secret-cookie-token-password";
    const response = await app.request(`/api/web/auth/login?token=${secret}`, {
      body: JSON.stringify({ password: secret }),
      headers: {
        authorization: `Bearer ${secret}`,
        cookie: `session=${secret}`,
        "content-type": "application/json",
        "user-agent": secret,
        "x-request-id": "client-controlled-id",
      },
      method: "POST",
    });

    expect(response.status).toBe(401);
    expect(response.headers.get("x-request-id")).toBe(
      "hub_request_id_1234567890",
    );
    expect(memory.events).toContainEqual(
      expect.objectContaining({
        event: "request.completed",
        level: "debug",
        method: "POST",
        outcome: "invalid_credentials",
        requestId: "hub_request_id_1234567890",
        routeId: "web_auth_login",
        status: 401,
      }),
    );
    expect(JSON.stringify(memory.events)).not.toContain(secret);
    expect(JSON.stringify(memory.events)).not.toContain("client-controlled-id");
  });

  it("keeps successful health requests out of the default info log", async () => {
    const memory = createMemoryHubLogger();
    const response = await createHubApp({ logger: memory.logger }).request(
      "/api/health",
    );

    expect(response.status).toBe(200);
    expect(memory.events).toEqual([]);
  });

  it("maps only supported methods to recognized route IDs", () => {
    const routes = [
      ["GET", "/api/health", "health"],
      ["POST", "/api/web/auth/login", "web_auth_login"],
      ["POST", "/api/web/auth/logout", "web_auth_logout"],
      ["GET", "/api/web/auth/session", "web_auth_session"],
      ["GET", "/api/web/audit-log", "web_audit_log"],
      ["POST", "/api/web/enrollments", "web_enrollments"],
      ["POST", "/api/web/enrollments/existing-host/42", "web_enrollments"],
      ["GET", "/api/web/enrollments/42", "web_enrollment"],
      ["GET", "/api/web/hosts", "web_hosts"],
      ["GET", "/api/web/hosts/42", "web_host"],
      ["DELETE", "/api/web/hosts/42", "web_host"],
      ["GET", "/api/web/hosts/42/metrics", "web_host_metrics"],
      ["PUT", "/api/web/hosts/42/metadata", "web_host_metadata"],
      [
        "GET",
        "/api/web/hosts/42/probe-configuration",
        "web_probe_configuration",
      ],
      [
        "PUT",
        "/api/web/hosts/42/probe-configuration",
        "web_probe_configuration",
      ],
      ["GET", "/api/web/probe-configuration", "web_probe_configuration"],
      ["PUT", "/api/web/probe-configuration", "web_probe_configuration"],
      ["GET", "/api/web/probe-operations/42", "web_probe_operation"],
      ["POST", "/api/probe/register", "probe_registration"],
      ["POST", "/api/probe/report", "probe_report"],
      ["POST", "/api/probe/config", "probe_configuration"],
      [
        "POST",
        "/api/probe/operations/42/token/validate",
        "probe_operation_token_validation",
      ],
      ["POST", "/api/probe/operations/42/status", "probe_operation_status"],
      ["GET", "/api/probe/assets/probe.tar.gz", "probe_asset"],
      [
        "POST",
        "/api/web/hosts/42/probe-upgrade-requests",
        "web_probe_upgrade_request",
      ],
      [
        "DELETE",
        "/api/web/hosts/42/probe-upgrade-requests/7",
        "web_probe_upgrade_request",
      ],
    ] as const;

    for (const [method, path, routeId] of routes) {
      expect(hubRouteId(method, path)).toBe(routeId);
      expect(hubRouteId("OPTIONS", path)).toBe("unknown");
    }

    expect(hubRouteId("GET", "/attacker-controlled-path")).toBe("unknown");
    expect(hubRouteId("GET", "/api/probe/config")).toBe("unknown");
    expect(hubRouteId("GET", "/api/web/hosts/42/probe-upgrade-requests")).toBe(
      "unknown",
    );
  });

  it("keeps routine Probe Configuration requests out of the default info log", async () => {
    const memory = createMemoryHubLogger();
    const raw = new Hono();
    const app = createProbeApiApp({ app: raw, logger: memory.logger });
    app.post("/api/probe/config", (context) => context.json({ ok: true }));

    const response = await app.request("/api/probe/config", { method: "POST" });

    expect(response.status).toBe(200);
    expect(memory.events).toEqual([]);
  });

  it("marks only successfully served non-API content as a Web static asset", async () => {
    const memory = createMemoryHubLogger({ level: "debug" });
    const raw = new Hono();
    const app = createHubApp({ app: raw, logger: memory.logger });
    app.get("/assets/app.js", (context) =>
      context.body("export {};", 200, { "content-type": "text/javascript" }),
    );

    await app.request("/assets/app.js");
    await app.request("/not-served");

    expect(memory.events).toEqual([
      expect.objectContaining({ routeId: "web_static_asset", status: 200 }),
      expect.objectContaining({ routeId: "unknown", status: 404 }),
    ]);
  });

  it("records a state-changing management request once at the default info level", async () => {
    const memory = createMemoryHubLogger();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      logger: memory.logger,
      requestId: () => "hub_request_id_1234567890",
    });

    const response = await app.request("/api/web/auth/login", {
      body: JSON.stringify({ password: "correct horse battery staple" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });

    expect(response.status).toBe(200);
    expect(memory.events).toEqual([
      expect.objectContaining({
        event: "request.completed",
        level: "info",
        outcome: "ok",
        routeId: "web_auth_login",
      }),
    ]);
  });

  it("keeps enrollment, identity, token, and header seeds out of rejected Probe logs", async () => {
    const memory = createMemoryHubLogger({ level: "debug" });
    const secret = "seeded-enrollment-probe-identity-operation-token";
    const response = await createProbeApiApp({ logger: memory.logger }).request(
      `/api/probe/register?enrollmentToken=${secret}`,
      {
        body: secret,
        headers: {
          authorization: `Bearer ${secret}`,
          cookie: `probe=${secret}`,
          "user-agent": secret,
          "x-enoki-probe-id": secret,
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(404);
    expect(JSON.stringify(memory.events)).not.toContain(secret);
    expect(memory.events).toContainEqual(
      expect.objectContaining({
        outcome: "http_404",
        routeId: "probe_registration",
      }),
    );
  });

  it("uses only allowlisted response error codes as outcomes", async () => {
    const memory = createMemoryHubLogger({ level: "debug" });
    const secret = "attacker_selected_secret_outcome";
    const raw = new Hono();
    const app = createHubApp({ app: raw, logger: memory.logger });
    app.post("/rejected", (context) => context.json({ error: secret }, 400));

    await app.request("/rejected", { method: "POST" });

    expect(memory.events).toContainEqual(
      expect.objectContaining({ outcome: "http_400" }),
    );
    expect(JSON.stringify(memory.events)).not.toContain(secret);
  });

  for (const [listener, createApp] of [
    [
      "management",
      (raw: Hono, logger: ReturnType<typeof createMemoryHubLogger>["logger"]) =>
        createHubApp({ app: raw, logger }),
    ],
    [
      "probe",
      (raw: Hono, logger: ReturnType<typeof createMemoryHubLogger>["logger"]) =>
        createProbeApiApp({ app: raw, logger }),
    ],
  ] as const) {
    it(`redacts an ordinary ${listener} error and logs one safe failure`, async () => {
      const memory = createMemoryHubLogger({ level: "debug" });
      const secret = `${listener}-seeded-enrollment-secret`;
      const consoleError = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const raw = new Hono();
      const app = createApp(raw, memory.logger);
      app.get("/explode", () => {
        throw new Error(secret);
      });

      try {
        const response = await app.request("/explode");

        expect(response.status).toBe(500);
        expect(response.headers.get("content-type")).toBe(
          "text/plain; charset=UTF-8",
        );
        await expect(response.text()).resolves.toBe("Internal Server Error");
        expect(memory.events).toEqual([
          expect.objectContaining({
            event: "request.completed",
            level: "error",
            outcome: "internal_error",
            routeId: "unknown",
            status: 500,
          }),
        ]);
        expect(JSON.stringify(memory.events)).not.toContain(secret);
        expect(consoleError).not.toHaveBeenCalled();
      } finally {
        consoleError.mockRestore();
      }
    });

    for (const [exceptionStatus, createException] of [
      [500, (secret: string) => new HTTPException(500, { message: secret })],
      [
        503,
        (secret: string) =>
          new HTTPException(503, {
            message: `${secret}-message`,
            res: new Response(`${secret}-body`, {
              headers: {
                "content-type": "application/json",
                "x-seeded-secret": secret,
              },
            }),
          }),
      ],
    ] as const) {
      it(`redacts a ${listener} HTTPException ${exceptionStatus} response and logs one safe failure`, async () => {
        const memory = createMemoryHubLogger({ level: "debug" });
        const secret = `${listener}-http-exception-${exceptionStatus}-secret`;
        const raw = new Hono();
        const app = createApp(raw, memory.logger);
        app.get("/explode-http", () => {
          throw createException(secret);
        });

        const response = await app.request("/explode-http");

        expect(response.status).toBe(500);
        expect(response.headers.get("content-type")).toBe(
          "text/plain; charset=UTF-8",
        );
        expect(response.headers.get("x-seeded-secret")).toBeNull();
        await expect(response.text()).resolves.toBe("Internal Server Error");
        expect(memory.events).toEqual([
          expect.objectContaining({
            event: "request.completed",
            level: "error",
            outcome: "internal_error",
            routeId: "unknown",
            status: 500,
          }),
        ]);
        expect(JSON.stringify(memory.events)).not.toContain(secret);
      });
    }
  }

  it("emits completion events from both running listener roles", async () => {
    const memory = createMemoryHubLogger({ level: "debug" });
    const hub = await createHubNodeServer({
      hostname: "127.0.0.1",
      logger: memory.logger,
      port: 0,
    });
    const probe = await createProbeApiNodeServer({
      hostname: "127.0.0.1",
      logger: memory.logger,
      port: 0,
    });

    try {
      const managementAddress = hub.address() as AddressInfo;
      const probeAddress = probe.address() as AddressInfo;
      await fetch(`http://127.0.0.1:${managementAddress.port}/api/health`);
      await fetch(`http://127.0.0.1:${probeAddress.port}/api/health`);

      expect(memory.events).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            component: "management-listener",
            event: "request.completed",
            routeId: "health",
          }),
          expect.objectContaining({
            component: "probe-listener",
            event: "request.completed",
            routeId: "health",
          }),
        ]),
      );
    } finally {
      await Promise.all([hub.close(), probe.close()]);
    }
  });

  it("records only one fatal event and performs a bounded shutdown", async () => {
    const memory = createMemoryHubLogger();
    const processEvents = new EventEmitter();
    const stopBackground = vi.fn().mockResolvedValue(undefined);
    const closeListeners = vi.fn().mockResolvedValue(undefined);
    const closeDatabase = vi.fn();
    const exit = vi.fn();
    const shutdown = createBoundedHubShutdown({
      closeDatabase,
      closeListeners,
      exit,
      logger: memory.logger,
      stopBackground,
      timeoutMs: 100,
    });
    installHubFatalHandlers({
      logger: memory.logger,
      process: processEvents,
      shutdown,
    });

    processEvents.emit("uncaughtException", new Error("secret error text"));
    processEvents.emit("unhandledRejection", new Error("another secret"));
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1));

    expect(
      memory.events.filter((event) => event.event === "process.fatal"),
    ).toHaveLength(1);
    expect(stopBackground).toHaveBeenCalledTimes(1);
    expect(closeListeners).toHaveBeenCalledTimes(1);
    expect(closeDatabase).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(memory.events)).not.toContain("secret error text");
  });

  it("handles an explicit startup failure through the same fatal shutdown path", async () => {
    const memory = createMemoryHubLogger();
    const processEvents = new EventEmitter();
    const closeStartedListeners = vi.fn().mockResolvedValue(undefined);
    const closeOpenedDatabase = vi.fn();
    const exit = vi.fn();
    const shutdown = createBoundedHubShutdown({
      closeDatabase: closeOpenedDatabase,
      closeListeners: closeStartedListeners,
      exit,
      logger: memory.logger,
      stopBackground: vi.fn().mockResolvedValue(undefined),
      timeoutMs: 100,
    });
    const fatal = installHubFatalHandlers({
      logger: memory.logger,
      process: processEvents,
      shutdown,
    });

    fatal(
      "startup_failure",
      "ENOKI_PUBLIC_HUB_URL has been removed. Set ENOKI_MANAGEMENT_ORIGIN and, when the Probe API differs, ENOKI_PROBE_API_ORIGIN.",
    );
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1));

    expect(memory.events).toContainEqual(
      expect.objectContaining({
        event: "process.fatal",
        outcome: "startup_failure",
        configurationMessage:
          "ENOKI_PUBLIC_HUB_URL has been removed. Set ENOKI_MANAGEMENT_ORIGIN and, when the Probe API differs, ENOKI_PROBE_API_ORIGIN.",
      }),
    );
    expect(closeStartedListeners).toHaveBeenCalledOnce();
    expect(closeOpenedDatabase).toHaveBeenCalledOnce();
  });

  it("exits after the shutdown deadline when a dependency does not stop", async () => {
    const memory = createMemoryHubLogger();
    const stopBackground = vi.fn(() => new Promise<void>(() => {}));
    const exit = vi.fn();
    const shutdown = createBoundedHubShutdown({
      closeDatabase: vi.fn(),
      closeListeners: vi.fn().mockResolvedValue(undefined),
      exit,
      logger: memory.logger,
      stopBackground,
      timeoutMs: 1,
    });

    await shutdown(0);

    expect(exit).toHaveBeenCalledWith(1);
    expect(stopBackground).toHaveBeenCalledOnce();
    expect(memory.events).toContainEqual(
      expect.objectContaining({
        event: "process.shutdown.completed",
        level: "error",
        outcome: "shutdown_timeout",
      }),
    );
  });

  it("records cleanup completion separately from a shutdown deadline", async () => {
    const memory = createMemoryHubLogger();
    const exit = vi.fn();
    const shutdown = createBoundedHubShutdown({
      closeDatabase: vi.fn(),
      closeListeners: vi.fn().mockResolvedValue(undefined),
      exit,
      logger: memory.logger,
      stopBackground: vi.fn().mockResolvedValue(undefined),
      timeoutMs: 100,
    });

    await shutdown(0);

    expect(exit).toHaveBeenCalledWith(0);
    expect(memory.events).toEqual([
      expect.objectContaining({
        event: "process.shutdown.started",
        level: "info",
        outcome: "graceful_shutdown",
      }),
      expect.objectContaining({
        event: "process.shutdown.completed",
        level: "info",
        outcome: "graceful_shutdown",
      }),
    ]);
  });

  it("upgrades an active graceful shutdown to a failing exit after a fatal error", async () => {
    const memory = createMemoryHubLogger();
    let finishBackground!: () => void;
    const stopBackground = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finishBackground = resolve;
        }),
    );
    const exit = vi.fn();
    const shutdown = createBoundedHubShutdown({
      closeDatabase: vi.fn(),
      closeListeners: vi.fn().mockResolvedValue(undefined),
      exit,
      logger: memory.logger,
      stopBackground,
      timeoutMs: 100,
    });

    const graceful = shutdown(0);
    const fatal = shutdown(1);
    finishBackground();
    await Promise.all([graceful, fatal]);

    expect(exit).toHaveBeenCalledOnce();
    expect(exit).toHaveBeenCalledWith(1);
  });
});
