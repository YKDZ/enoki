import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    tempRoots
      .splice(0)
      .map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe("Owner Audit Log API", () => {
  it("exposes persisted lifecycle evidence only through an Owner session", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-audit-api-"));
    tempRoots.push(dataRoot);
    const database = await initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "owner-secret",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1234,
    });

    database.audit.record({
      action: "host.delete",
      actor: "owner",
      details: { hostId: 7, probeOperationId: 42 },
      occurredAtMs: 1234,
      outcome: "success",
      subjectId: "7",
      subjectType: "host",
    });

    expect((await app.request("/api/web/audit-log")).status).toBe(401);
    const login = await app.request("/api/web/auth/login", {
      body: JSON.stringify({ password: "owner-secret" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    const response = await app.request("/api/web/audit-log?limit=20", {
      headers: { cookie: login.headers.get("set-cookie") ?? "" },
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      auditLog: [
        expect.objectContaining({
          action: "owner.login",
          actor: "owner",
          outcome: "success",
        }),
        expect.objectContaining({
          action: "host.delete",
          details: { hostId: 7, probeOperationId: 42 },
          subjectId: "7",
          subjectType: "host",
        }),
      ],
    });
    database.close();
  });
});
