import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import {
  renderInstallCommand,
  resolveProbeBootstrapRecipeRecord,
} from "../src/enrollment/install-command";
import { hashSecret } from "../src/enrollment/routes";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture";

const tempRoots: string[] = [];
const bootstrapRecipe = {
  bundleVersion: "1.2.3",
  distribution: "enoki",
  kind: "enoki-probe-bootstrap-recipe-record" as const,
  recipe: {
    file: "enoki-probe-bootstrap.py",
    sha256: "a".repeat(64),
    size: 123,
    version: "v1",
  },
  rootFingerprint: "b".repeat(64),
  schemaVersion: 1 as const,
  targets: ["x86_64-unknown-linux-gnu"],
};

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

  it("uses the explicit development recipe when a local runtime has no image publication", () => {
    expect(
      resolveProbeBootstrapRecipeRecord({
        deployment: undefined,
        nodeEnvironment: "development",
      }),
    ).toMatchObject({
      bundleVersion: "0.0.0",
      distribution: "enoki-development",
      targets: [],
    });
  });

  it("requires the fixed publication record in production and image runtimes", () => {
    for (const runtime of [
      { deployment: undefined, nodeEnvironment: "production" },
      { deployment: "docker", nodeEnvironment: "development" },
    ]) {
      expect(() =>
        resolveProbeBootstrapRecipeRecord({
          ...runtime,
          filePath: "/definitely/missing/bootstrap-recipe-record.json",
        }),
      ).toThrow();
    }
  });

  it("quotes enrollment material for the authenticated static recipe without passing it through sudo", () => {
    const command = renderInstallCommand(
      { probeApiOrigin: "https://hub.example/' $(whoami)" },
      { enrollmentToken: "token'; touch /tmp/injected #" },
    ).installCommand;

    expect(command).toContain("enoki-probe-bootstrap.py");
    expect(command).toContain("printf '%s\\n'");
    expect(command).not.toContain("/usr/local/bin/enoki-probe-bootstrap");
    expect(command).not.toContain("sudo env");
    expect(command).not.toContain("sudo ENOKI_");
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
        bootstrapRecipe,
        probeApiOrigin: "https://hub.example",
      },
    });
    const ownerSession = await loginOwner(app);

    const response = await app.request(
      "https://attacker.example/api/web/enrollments",
      {
        body: JSON.stringify({}),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
      expiresAtMs: number;
      installCommand: string;
      status: string;
    };

    expect(body.enrollmentId).toMatch(/^enr_/);
    expect(body.status).toBe("pending");
    expect(
      (body as typeof body & { bootstrapRecipe: unknown }).bootstrapRecipe,
    ).toEqual(bootstrapRecipe);
    expect(body.expiresAtMs).toBeGreaterThan(Date.now() - 1_000);
    expect(body).not.toHaveProperty("installPath");
    expect(body).not.toHaveProperty("installScriptUrl");
    expect(body.installCommand).toContain("enoki-probe-bootstrap.py");
    expect(body.installCommand).toContain(body.enrollmentToken);
    expect(body.installCommand).not.toContain(
      "/usr/local/bin/enoki-probe-bootstrap",
    );
    expect(
      database.sqlite
        .prepare("select count(*) as count from managed_hosts")
        .get(),
    ).toEqual({ count: 0 });

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
        probeApiOrigin: "https://hub.example",
      },
    });
    const ownerSession = await loginOwner(app);
    const newHost = await app.request("/api/web/enrollments", {
      body: JSON.stringify({}),
      headers: { "content-type": "application/json", cookie: ownerSession },
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

  it("issues one bounded manual reinstall command from the verified replacement transition", async () => {
    const database = await createTemporaryDatabase();
    const assetDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-reinstall-assets-"),
    );
    tempRoots.push(assetDir);
    const release = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.2.2",
      targetVersion: "1.2.3",
      transition: "replacement-required",
    });
    database.hosts.create({
      clockSkewDetected: false,
      connectAddress: "203.0.113.10",
      createdAtMs: 1_725_000_000_000,
      displayName: "需要迁移的主机",
      displayNameEdited: false,
      id: 7,
      lastClockSkewMs: null,
      lastReportAtMs: 1_725_000_000_000,
      probeConfigurationVersion: "default-v1",
      probeId: "probe-old-identity",
      probeSecretHash: "secret-hash-old-identity",
      probeVersion: "1.2.2",
    });
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      installation: {
        bootstrapRecipe,
        probeApiOrigin: "https://hub.example",
      },
      probeAssets: {
        assetDir,
        trustedRootPublicKeyPem: release.rootPublicKeyPem,
      },
    });
    const ownerSession = await loginOwner(app);

    const response = await app.request(
      "/api/web/enrollments/manual-reinstall/7",
      { headers: { cookie: ownerSession }, method: "POST" },
    );

    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
      installCommand: string;
      target: { hostId: number; kind: string };
    };
    expect(body.target).toEqual({ hostId: 7, kind: "manual_reinstall" });
    expect(body.installCommand).toContain("enoki-probe-bootstrap.py");
    expect(body.installCommand).toContain(body.enrollmentToken);
    expect(body.installCommand).not.toContain("&&");
    expect(body.installCommand).not.toContain(" uninstall");
    expect(
      database.enrollments.inspectPending({
        nowMs: Date.now(),
        tokenHash: hashSecret(body.enrollmentToken),
      }),
    ).toEqual(
      expect.objectContaining({
        sourceProbeSha256: release.sourceProbeSha256,
        sourceProbeVersion: "1.2.2",
        targetKind: "manual_reinstall",
      }),
    );
    expect(
      database.sqlite
        .prepare(
          `select expected_hub_origin as expectedHubOrigin,
                  expected_probe_id as expectedProbeId,
                  expected_probe_version as expectedProbeVersion,
                  target_asset_set_digest as targetAssetSetDigest,
                  target_probe_version as targetProbeVersion
             from enrollment_tokens where enrollment_id = ?`,
        )
        .get(body.enrollmentId),
    ).toEqual({
      expectedHubOrigin: "https://hub.example",
      expectedProbeId: "probe-old-identity",
      expectedProbeVersion: "1.2.2",
      targetAssetSetDigest: release.targetAssetSetDigest,
      targetProbeVersion: "1.2.3",
    });

    database.close();
  });

  it("issues the same bounded command for an offline closed recovery disposition", async () => {
    const database = await createTemporaryDatabase();
    const assetDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-recovery-reinstall-assets-"),
    );
    tempRoots.push(assetDir);
    const release = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.2.2",
      targetVersion: "1.2.3",
      transition: "compatible",
    });
    database.hosts.create({
      clockSkewDetected: false,
      connectAddress: "203.0.113.10",
      createdAtMs: 1_725_000_000_000,
      displayName: "恢复中的主机",
      displayNameEdited: false,
      id: 8,
      lastClockSkewMs: null,
      lastReportAtMs: 1_725_000_000_000,
      probeConfigurationVersion: "default-v1",
      probeId: "probe-recovery-identity",
      probeSecretHash: "secret-hash-recovery-identity",
      probeVersion: "1.2.2",
    });
    database.probeOperations.createProbeUpgradeRequest({
      acceptedAtMs: 1_725_000_001_000,
      canceledAtMs: null,
      completedAtMs: 1_725_000_003_000,
      createdAtMs: 1_725_000_000_500,
      currentProbeVersion: "1.2.2",
      failureCode: "manual_probe_reinstall_required",
      failureMessage: null,
      hostId: 8,
      id: null,
      kind: "probe_upgrade",
      runningAtMs: 1_725_000_002_000,
      state: "failed",
      supersededAtMs: null,
      targetAssetSetDigest: release.targetAssetSetDigest,
      targetProbeVersion: "1.2.3",
      updatedAtMs: 1_725_000_003_000,
    });
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      installation: {
        bootstrapRecipe,
        probeApiOrigin: "https://hub.example",
      },
      now: () => 1_725_000_100_000,
      probeAssets: {
        assetDir,
        trustedRootPublicKeyPem: release.rootPublicKeyPem,
      },
    });
    const ownerSession = await loginOwner(app);

    const response = await app.request(
      "/api/web/enrollments/manual-reinstall/8",
      { headers: { cookie: ownerSession }, method: "POST" },
    );

    expect(response.status).toBe(201);
    await expect(response.json()).resolves.toEqual(
      expect.objectContaining({
        target: { hostId: 8, kind: "manual_reinstall" },
      }),
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
      body: JSON.stringify({}),
      headers: { "content-type": "application/json", cookie: ownerSession },
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
