import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { afterEach, describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase, type HubDatabase } from "../src/database/index";
import { createTestProbeIdentity } from "./probe-test-auth";

const temporaryRoots: string[] = [];

type CreatedEnrollment = {
  enrollmentId: string;
  enrollmentToken: string;
  expiresAtMs: number;
};

type EnrollmentRow = {
  enrollmentId: string;
  expiresAtMs: number;
  hostId: number | null;
  rejectedAtMs: number | null;
  rejectionCode: string | null;
  rejectionMessage: string | null;
  status: string;
  usedAtMs: number | null;
  verificationDeadlineAtMs: number | null;
};

describe("Probe installation rejection API", () => {
  afterEach(async () => {
    await Promise.all(
      temporaryRoots
        .splice(0)
        .map((temporaryRoot) =>
          rm(temporaryRoot, { force: true, recursive: true }),
        ),
    );
  });

  it("does not let an unrelated token alter either pending Enrollment", async () => {
    let nowMs = 1_000;
    const database = await createTemporaryDatabase();
    const app = createApp(database, () => nowMs);
    const ownerSession = await loginOwner(app);
    const first = await createEnrollment(app, ownerSession);
    const second = await createEnrollment(app, ownerSession);
    const before = [
      readEnrollment(database, first.enrollmentId),
      readEnrollment(database, second.enrollmentId),
    ];

    const response = await submitInstallationRejection(
      app,
      "enk_unrelated_token",
      { code: "existing_probe_installation", message: "untrusted input" },
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });
    expect(readEnrollment(database, first.enrollmentId)).toEqual(before[0]);
    expect(readEnrollment(database, second.enrollmentId)).toEqual(before[1]);
    expect(hostCount(database)).toBe(0);

    database.close();
    nowMs += 1;
  });

  it("fails closed at an expired pending deadline without changing that or another Enrollment", async () => {
    let nowMs = 10_000;
    const database = await createTemporaryDatabase();
    const app = createApp(database, () => nowMs);
    const ownerSession = await loginOwner(app);
    const expired = await createEnrollment(app, ownerSession);
    const unaffected = await createEnrollment(app, ownerSession);
    nowMs = expired.expiresAtMs;
    const beforeExpired = readEnrollment(database, expired.enrollmentId);
    const beforeUnaffected = readEnrollment(database, unaffected.enrollmentId);

    const response = await submitInstallationRejection(
      app,
      expired.enrollmentToken,
      { code: "existing_probe_installation", message: "untrusted input" },
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });
    expect(readEnrollment(database, expired.enrollmentId)).toEqual(
      beforeExpired,
    );
    expect(readEnrollment(database, unaffected.enrollmentId)).toEqual(
      beforeUnaffected,
    );
    expect(hostCount(database)).toBe(0);

    database.close();
  });

  it("rejects one verifying Enrollment before its deadline without changing its Host or another Enrollment", async () => {
    let nowMs = 20_000;
    const database = await createTemporaryDatabase();
    const app = createApp(database, () => nowMs);
    const ownerSession = await loginOwner(app);
    const verifying = await createEnrollment(app, ownerSession);
    await registerProbe(app, verifying.enrollmentToken, "verifying-host");
    const unaffected = await createEnrollment(app, ownerSession);
    const beforeVerifying = readEnrollment(database, verifying.enrollmentId);
    const beforeUnaffected = readEnrollment(database, unaffected.enrollmentId);
    nowMs += 1;

    const response = await submitInstallationRejection(
      app,
      verifying.enrollmentToken,
      {
        code: "probe_bound_to_different_hub",
        message: "untrusted input must not persist",
      },
    );

    expect(response.status).toBe(204);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(readEnrollment(database, verifying.enrollmentId)).toEqual({
      ...beforeVerifying,
      rejectedAtMs: nowMs,
      rejectionCode: "probe_bound_to_different_hub",
      rejectionMessage: "local Probe installation is bound to a different Hub",
      status: "rejected",
    });
    expect(readEnrollment(database, unaffected.enrollmentId)).toEqual(
      beforeUnaffected,
    );
    expect(hostCount(database)).toBe(1);

    database.close();
  });

  it.each([0, 1])(
    "fails closed when a verifying deadline is reached or passed (%i ms)",
    async (deadlineOffsetMs) => {
      let nowMs = 30_000;
      const database = await createTemporaryDatabase();
      const app = createApp(database, () => nowMs);
      const ownerSession = await loginOwner(app);
      const verifying = await createEnrollment(app, ownerSession);
      await registerProbe(
        app,
        verifying.enrollmentToken,
        `deadline-${deadlineOffsetMs}`,
      );
      const unaffected = await createEnrollment(app, ownerSession);
      const beforeVerifying = readEnrollment(database, verifying.enrollmentId);
      const beforeUnaffected = readEnrollment(
        database,
        unaffected.enrollmentId,
      );
      const deadline = beforeVerifying.verificationDeadlineAtMs;
      if (deadline === null) {
        throw new Error("fixture Enrollment did not enter verifying");
      }
      nowMs = deadline + deadlineOffsetMs;

      const response = await submitInstallationRejection(
        app,
        verifying.enrollmentToken,
        { code: "existing_probe_installation", message: "untrusted input" },
      );

      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toEqual({
        error: "invalid_enrollment_token",
      });
      expect(readEnrollment(database, verifying.enrollmentId)).toEqual(
        beforeVerifying,
      );
      expect(readEnrollment(database, unaffected.enrollmentId)).toEqual(
        beforeUnaffected,
      );
      expect(hostCount(database)).toBe(1);

      database.close();
    },
  );

  it("rejects invalid and unknown codes without leaking input or changing any Enrollment", async () => {
    let nowMs = 40_000;
    const database = await createTemporaryDatabase();
    const app = createApp(database, () => nowMs);
    const ownerSession = await loginOwner(app);
    const first = await createEnrollment(app, ownerSession);
    const second = await createEnrollment(app, ownerSession);
    const before = [
      readEnrollment(database, first.enrollmentId),
      readEnrollment(database, second.enrollmentId),
    ];
    const attackerCode = "installer_unrecognized";
    const attackerMessage = "private local installation detail";

    const response = await submitInstallationRejection(
      app,
      first.enrollmentToken,
      {
        code: attackerCode,
        message: attackerMessage,
      },
    );

    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body).toEqual({ error: "malformed_probe_registration" });
    expect(JSON.stringify(body)).not.toContain(attackerCode);
    expect(JSON.stringify(body)).not.toContain(attackerMessage);
    expect(readEnrollment(database, first.enrollmentId)).toEqual(before[0]);
    expect(readEnrollment(database, second.enrollmentId)).toEqual(before[1]);
    expect(hostCount(database)).toBe(0);

    database.close();
    nowMs += 1;
  });

  it("confirms a repeated canonical rejection without creating a second audit record", async () => {
    let nowMs = 50_000;
    const database = await createTemporaryDatabase();
    const app = createApp(database, () => nowMs);
    const ownerSession = await loginOwner(app);
    const hostEnrollment = await createEnrollment(app, ownerSession);
    await registerProbe(app, hostEnrollment.enrollmentToken, "context-host");
    const host = database.sqlite
      .prepare("select probe_id as probeId from managed_hosts")
      .get() as { probeId: string };
    const enrollment = await createEnrollment(app, ownerSession);
    const unaffected = await createEnrollment(app, ownerSession);
    const beforeUnaffected = readEnrollment(database, unaffected.enrollmentId);

    const responses = await Promise.all([
      submitInstallationRejection(app, enrollment.enrollmentToken, {
        code: "existing_probe_installation",
        existingProbeId: host.probeId,
        message: "untrusted input",
      }),
      submitInstallationRejection(app, enrollment.enrollmentToken, {
        code: "existing_probe_installation",
        existingProbeId: host.probeId,
        message: "untrusted input",
      }),
    ]);

    expect(responses.map((response) => response.status).sort()).toEqual([
      204, 204,
    ]);
    expect(readEnrollment(database, enrollment.enrollmentId)).toEqual(
      expect.objectContaining({
        rejectedAtMs: nowMs,
        rejectionCode: "existing_probe_installation",
        rejectionMessage: "existing local Probe installation detected",
        status: "rejected",
      }),
    );
    expect(readEnrollment(database, unaffected.enrollmentId)).toEqual(
      beforeUnaffected,
    );
    expect(hostCount(database)).toBe(1);
    expect(
      database.audit
        .recent()
        .filter((entry) => entry.action === "enrollment.installation_rejected"),
    ).toHaveLength(1);

    database.close();
  });

  it("does not treat an unmatched existing-Probe context as an idempotent confirmation", async () => {
    let nowMs = 52_500;
    const database = await createTemporaryDatabase();
    const app = createApp(database, () => nowMs);
    const ownerSession = await loginOwner(app);
    const enrollment = await createEnrollment(app, ownerSession);
    const rejection = {
      code: "existing_probe_installation",
      existingProbeId: "probe_unmatched_context",
      message: "untrusted input",
    };

    const first = await submitInstallationRejection(
      app,
      enrollment.enrollmentToken,
      rejection,
    );
    const retried = await submitInstallationRejection(
      app,
      enrollment.enrollmentToken,
      rejection,
    );

    expect(first.status).toBe(204);
    expect(retried.status).toBe(401);
    await expect(retried.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });
    expect(readEnrollment(database, enrollment.enrollmentId)).toEqual(
      expect.objectContaining({ hostId: null, status: "rejected" }),
    );
    expect(
      database.audit
        .recent()
        .filter((entry) => entry.action === "enrollment.installation_rejected"),
    ).toHaveLength(1);

    database.close();
    nowMs += 1;
  });

  it("confirms a repeated existing-Probe rejection after its associated Host is soft-deleted", async () => {
    let nowMs = 55_000;
    const database = await createTemporaryDatabase();
    const app = createApp(database, () => nowMs);
    const ownerSession = await loginOwner(app);
    const hostEnrollment = await createEnrollment(app, ownerSession);
    await registerProbe(app, hostEnrollment.enrollmentToken, "context-host");
    const host = database.sqlite
      .prepare("select id, probe_id as probeId from managed_hosts")
      .get() as { id: number; probeId: string };
    const enrollment = await createEnrollment(app, ownerSession);

    const first = await submitInstallationRejection(
      app,
      enrollment.enrollmentToken,
      {
        code: "existing_probe_installation",
        existingProbeId: host.probeId,
        message: "untrusted input",
      },
    );
    expect(first.status).toBe(204);
    expect(readEnrollment(database, enrollment.enrollmentId).hostId).toBe(
      host.id,
    );
    expect(database.hosts.softDelete(host.id, nowMs + 1)).not.toBeNull();

    nowMs += 1;
    const retried = await submitInstallationRejection(
      app,
      enrollment.enrollmentToken,
      {
        code: "existing_probe_installation",
        existingProbeId: host.probeId,
        message: "untrusted input",
      },
    );

    expect(retried.status).toBe(204);
    expect(
      database.audit
        .recent()
        .filter((entry) => entry.action === "enrollment.installation_rejected"),
    ).toHaveLength(1);

    database.close();
  });

  it("does not confirm a terminal rejection when its canonical code or Host context changes", async () => {
    let nowMs = 60_000;
    const database = await createTemporaryDatabase();
    const app = createApp(database, () => nowMs);
    const ownerSession = await loginOwner(app);
    const firstHostEnrollment = await createEnrollment(app, ownerSession);
    await registerProbe(app, firstHostEnrollment.enrollmentToken, "first-host");
    const secondHostEnrollment = await createEnrollment(app, ownerSession);
    await registerProbe(
      app,
      secondHostEnrollment.enrollmentToken,
      "second-host",
    );
    const hosts = database.sqlite
      .prepare("select probe_id as probeId from managed_hosts order by id")
      .all() as Array<{ probeId: string }>;
    const enrollment = await createEnrollment(app, ownerSession);

    const first = await submitInstallationRejection(
      app,
      enrollment.enrollmentToken,
      {
        code: "existing_probe_installation",
        existingProbeId: hosts[0]?.probeId,
        message: "untrusted input",
      },
    );
    expect(first.status).toBe(204);
    const terminal = readEnrollment(database, enrollment.enrollmentId);

    const changedContext = await submitInstallationRejection(
      app,
      enrollment.enrollmentToken,
      {
        code: "existing_probe_installation",
        existingProbeId: hosts[1]?.probeId,
        message: "untrusted input",
      },
    );
    const changedCode = await submitInstallationRejection(
      app,
      enrollment.enrollmentToken,
      {
        code: "probe_bound_to_different_hub",
        message: "untrusted input",
      },
    );

    for (const response of [changedContext, changedCode]) {
      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toEqual({
        error: "invalid_enrollment_token",
      });
    }
    expect(readEnrollment(database, enrollment.enrollmentId)).toEqual(terminal);
    expect(
      database.audit
        .recent()
        .filter((entry) => entry.action === "enrollment.installation_rejected"),
    ).toHaveLength(1);

    database.close();
    nowMs += 1;
  });
});

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(
    path.join(os.tmpdir(), "enoki-install-rejection-"),
  );
  temporaryRoots.push(dataRoot);
  return initializeHubDatabase({
    dataRoot,
    sqlitePath: path.join(dataRoot, "enoki.db"),
  });
}

function createApp(database: HubDatabase, now: () => number) {
  return createHubApp({
    auth: {
      failureDelayMs: 0,
      ownerPassword: "correct horse battery staple",
      sessionCookieName: "enoki_owner_session",
    },
    database,
    now,
  });
}

async function loginOwner(app: ReturnType<typeof createHubApp>) {
  const response = await app.request("/api/web/auth/login", {
    body: JSON.stringify({ password: "correct horse battery staple" }),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  expect(response.status).toBe(200);
  return response.headers.get("set-cookie") ?? "";
}

async function createEnrollment(
  app: ReturnType<typeof createHubApp>,
  ownerSession: string,
): Promise<CreatedEnrollment> {
  const response = await app.request("/api/web/enrollments", {
    headers: { cookie: ownerSession },
    method: "POST",
  });
  expect(response.status).toBe(201);
  return (await response.json()) as CreatedEnrollment;
}

async function registerProbe(
  app: ReturnType<typeof createHubApp>,
  enrollmentToken: string,
  hostname: string,
) {
  const identity = createTestProbeIdentity();
  const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
  const response = await app.request("/api/probe/register", {
    body: RegistrationRequest.encode(
      RegistrationRequest.create({
        enrollmentToken,
        probePublicKeyPem: identity.publicKeyPem,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: {
              architecture: "x86_64",
              cpuCount: 2,
              cpuModel: "Test CPU",
              filesystems: [
                {
                  availableBytes: 60_000,
                  filesystemType: "ext4",
                  mountPoint: "/",
                  totalBytes: 100_000,
                },
              ],
              hostname,
              kernel: "6.8.0",
              memoryTotalBytes: 2_147_483_648,
              networkInterfaces: [{ addresses: ["192.0.2.10"], name: "eth0" }],
              os: "linux",
              probeVersion: "0.1.0",
            },
          },
        ],
      }),
    ).finish(),
    headers: { "content-type": "application/x-protobuf" },
    method: "POST",
  });
  expect(response.status).toBe(200);
}

async function submitInstallationRejection(
  app: ReturnType<typeof createHubApp>,
  enrollmentToken: string,
  rejection: { code: string; existingProbeId?: string; message: string },
) {
  const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
  return app.request("/api/probe/register", {
    body: RegistrationRequest.encode(
      RegistrationRequest.create({
        enrollmentToken,
        installationRejection: rejection,
      }),
    ).finish(),
    headers: { "content-type": "application/x-protobuf" },
    method: "POST",
  });
}

function readEnrollment(
  database: HubDatabase,
  enrollmentId: string,
): EnrollmentRow {
  const row = database.sqlite
    .prepare(
      `select
        enrollment_id as enrollmentId,
        expires_at_ms as expiresAtMs,
        managed_host_id as hostId,
        rejected_at_ms as rejectedAtMs,
        rejection_code as rejectionCode,
        rejection_message as rejectionMessage,
        status,
        used_at_ms as usedAtMs,
        verification_deadline_at_ms as verificationDeadlineAtMs
      from enrollment_tokens
      where enrollment_id = ?`,
    )
    .get(enrollmentId) as EnrollmentRow | undefined;
  if (!row) {
    throw new Error(`Enrollment ${enrollmentId} was not persisted`);
  }

  return row;
}

function hostCount(database: HubDatabase) {
  const row = database.sqlite
    .prepare("select count(*) as count from managed_hosts")
    .get() as { count: number };
  return row.count;
}
