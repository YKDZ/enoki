import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import root from "../../../packages/proto/src/generated/ts/enoki_pb.js";
import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import {
  createProbeUninstallRequest,
  createProbeUpgradeRequest,
} from "../src/probe/operation";
import { validateProbeOperationToken } from "../src/probe/operation-token";

const tempRoots: string[] = [];

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-report-db-"));
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

async function createEnrollmentToken(
  app: ReturnType<typeof createHubApp>,
  ownerSession: string,
) {
  const response = await app.request("/api/web/enrollments", {
    headers: {
      cookie: ownerSession,
    },
    method: "POST",
  });

  expect(response.status).toBe(201);
  return ((await response.json()) as { enrollmentToken: string })
    .enrollmentToken;
}

async function registerProbe(
  app: ReturnType<typeof createHubApp>,
  enrollmentToken: string,
) {
  const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
  const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;
  const response = await app.request("/api/probe/register", {
    body: RegistrationRequest.encode(
      RegistrationRequest.create({
        enrollmentToken,
        inventory: {
          architecture: "x86_64",
          cpuCount: 2,
          hostname: "managed-host-01",
          kernel: "6.8.0",
          memoryTotalBytes: 2_147_483_648,
          os: "linux",
          probeVersion: "0.1.0",
        },
      }),
    ).finish(),
    headers: {
      "content-type": "application/x-protobuf",
    },
    method: "POST",
  });

  expect(response.status).toBe(200);
  return RegistrationResponse.decode(
    new Uint8Array(await response.arrayBuffer()),
  );
}

function requestWithStreamBody(
  path: string,
  init: Omit<RequestInit, "body"> & {
    body: ReadableStream<Uint8Array>;
  },
) {
  return new Request(`http://localhost${path}`, {
    ...init,
    duplex: "half",
  } as RequestInit & { duplex: "half" });
}

describe("Probe report API", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("delivers the same pending Probe Operation in report responses until it is acknowledged", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const operation = database.probeOperations.createProbeUpgradeRequest(
      createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: host.id,
        nowMs: 1_725_000_009_000,
        targetProbeVersion: "0.2.0",
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    async function report(sequence: number) {
      const response = await app.request("/api/probe/report", {
        body: ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: sequence,
            sequenceStart: sequence,
          }),
        ).finish(),
        headers: {
          authorization: `Bearer ${registration.probeSecret}`,
          "content-type": "application/x-protobuf",
        },
        method: "POST",
      });

      expect(response.status).toBe(200);
      return ReportResponse.decode(
        new Uint8Array(await response.arrayBuffer()),
      );
    }

    const first = await report(1);
    const retry = await report(1);

    for (const response of [first, retry]) {
      expect(response.pendingOperation?.id).toBe(String(operation.id));
      expect(response.pendingOperation?.probeUpgrade).toEqual(
        expect.objectContaining({
          currentProbeVersion: "0.1.0",
          operationToken: expect.any(String),
          targetProbeVersion: "0.2.0",
        }),
      );
      expect(response.pendingOperation?.probeUpgrade?.operationToken).not.toBe(
        "",
      );
    }
  });

  it("validates Probe Operation Tokens on a probe-only API path", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
      probeOperationTokenSecret: "configured-token-signing-secret",
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const otherEnrollmentToken = await createEnrollmentToken(app, ownerSession);
    const otherRegistration = await registerProbe(app, otherEnrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const operation = database.probeOperations.createProbeUpgradeRequest(
      createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: host.id,
        nowMs: 1_725_000_009_000,
        targetProbeVersion: "0.2.0",
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    const delivery = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(delivery.status).toBe(200);
    const token = ReportResponse.decode(
      new Uint8Array(await delivery.arrayBuffer()),
    ).pendingOperation?.probeUpgrade?.operationToken;
    expect(token).toEqual(expect.any(String));
    expect(
      validateProbeOperationToken({
        nowMs: 1_725_000_010_000,
        operation,
        probeId: registration.probeId,
        secret: "configured-token-signing-secret",
        targetProbeVersion: "0.2.0",
        token: token ?? "",
      }),
    ).toEqual({ error: null });

    const accepted = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      {
        body: JSON.stringify({
          targetProbeVersion: "0.2.0",
          token,
        }),
        headers: {
          authorization: `Bearer ${registration.probeSecret}`,
          "content-type": "application/json",
        },
        method: "POST",
      },
    );
    expect(accepted.status).toBe(200);
    await expect(accepted.json()).resolves.toEqual({ valid: true });

    const wrongProbe = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      {
        body: JSON.stringify({
          targetProbeVersion: "0.2.0",
          token,
        }),
        headers: {
          authorization: `Bearer ${otherRegistration.probeSecret}`,
          "content-type": "application/json",
        },
        method: "POST",
      },
    );
    expect(wrongProbe.status).toBe(403);
    await expect(wrongProbe.json()).resolves.toEqual({
      error: "probe_operation_token_probe_mismatch",
    });

    const wrongTarget = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      {
        body: JSON.stringify({
          targetProbeVersion: "0.3.0",
          token,
        }),
        headers: {
          authorization: `Bearer ${registration.probeSecret}`,
          "content-type": "application/json",
        },
        method: "POST",
      },
    );
    expect(wrongTarget.status).toBe(403);
    await expect(wrongTarget.json()).resolves.toEqual({
      error: "probe_operation_token_target_mismatch",
    });

    database.probeOperations.updateProbeUpgradeRequest({
      ...operation,
      canceledAtMs: 1_725_000_010_000,
      state: "canceled",
      updatedAtMs: 1_725_000_010_000,
    });
    const canceled = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      {
        body: JSON.stringify({
          targetProbeVersion: "0.2.0",
          token,
        }),
        headers: {
          authorization: `Bearer ${registration.probeSecret}`,
          "content-type": "application/json",
        },
        method: "POST",
      },
    );
    expect(canceled.status).toBe(403);
    await expect(canceled.json()).resolves.toEqual({
      error: "probe_operation_token_operation_closed",
    });
  });

  it("accepts Probe Operation acknowledgements and status reports idempotently", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const operation = database.probeOperations.createProbeUpgradeRequest(
      createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: host.id,
        nowMs: 1_725_000_009_000,
        targetProbeVersion: "0.2.0",
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    const acknowledged = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          operationAcknowledgements: [{ operationId: String(operation.id) }],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(acknowledged.status).toBe(200);
    expect(
      ReportResponse.decode(new Uint8Array(await acknowledged.arrayBuffer()))
        .pendingOperation,
    ).toBeNull();
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        acceptedAtMs: 1_725_000_010_000,
        state: "accepted",
      }),
    );

    const running = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          operationStatuses: [
            {
              operationId: String(operation.id),
              running: {},
            },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 2,
          sequenceStart: 2,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(running.status).toBe(200);
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        runningAtMs: 1_725_000_010_000,
        state: "running",
      }),
    );

    for (const sequence of [3, 3]) {
      const failed = await app.request("/api/probe/report", {
        body: ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
            operationStatuses: [
              {
                failed: {
                  errorCode: "unsupported_installation",
                  message: "systemd is unavailable",
                },
                operationId: String(operation.id),
              },
            ],
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: sequence,
            sequenceStart: sequence,
          }),
        ).finish(),
        headers: {
          authorization: `Bearer ${registration.probeSecret}`,
          "content-type": "application/x-protobuf",
        },
        method: "POST",
      });

      expect(failed.status).toBe(200);
    }
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        completedAtMs: 1_725_000_010_000,
        failureCode: "unsupported_installation",
        failureMessage: "systemd is unavailable",
        state: "failed",
      }),
    );
  });

  it("marks a Probe Upgrade Request succeeded only after Inventory reports the target version", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const operation = database.probeOperations.createProbeUpgradeRequest(
      createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: host.id,
        nowMs: 1_725_000_009_000,
        targetProbeVersion: "0.2.0",
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const running = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-after-upgrade",
          operationAcknowledgements: [{ operationId: String(operation.id) }],
          operationStatuses: [
            {
              operationId: String(operation.id),
              running: {},
            },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(running.status).toBe(200);
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        state: "running",
      }),
    );

    const targetInventory = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-after-upgrade",
          inventory: {
            architecture: "x86_64",
            cpuCount: 2,
            hostname: "managed-host-01",
            kernel: "6.8.0",
            memoryTotalBytes: 2_147_483_648,
            os: "linux",
            probeVersion: "0.2.0",
          },
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 2,
          sequenceStart: 2,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(targetInventory.status).toBe(200);
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        completedAtMs: 1_725_000_010_000,
        state: "succeeded",
      }),
    );
  });

  it("rejects malformed Probe Operation acknowledgements and statuses with stable errors", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const badAck = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          operationAcknowledgements: [{ operationId: "operation-missing" }],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(badAck.status).toBe(400);
    await expect(badAck.json()).resolves.toEqual({
      error: "malformed_probe_operation_acknowledgement",
    });

    const badStatus = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          operationStatuses: [{ operationId: "" }],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 2,
          sequenceStart: 2,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(badStatus.status).toBe(400);
    await expect(badStatus.json()).resolves.toEqual({
      error: "malformed_probe_operation_status",
    });
  });

  it("keeps Probe Operation state unchanged when a valid acknowledgement is followed by a malformed status", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const operation = database.probeOperations.createProbeUpgradeRequest(
      createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: host.id,
        nowMs: 1_725_000_009_000,
        targetProbeVersion: "0.2.0",
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          operationAcknowledgements: [{ operationId: String(operation.id) }],
          operationStatuses: [{ operationId: "" }],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_operation_status",
    });
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        acceptedAtMs: null,
        state: "pending",
      }),
    );
  });

  it("keeps Probe Operation state unchanged when a valid status is followed by a malformed status", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const operation = database.probeOperations.createProbeUpgradeRequest({
      ...createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: host.id,
        nowMs: 1_725_000_009_000,
        targetProbeVersion: "0.2.0",
      }).operation,
      acceptedAtMs: 1_725_000_009_500,
      state: "accepted",
      updatedAtMs: 1_725_000_009_500,
    });
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          operationStatuses: [
            {
              operationId: String(operation.id),
              running: {},
            },
            { operationId: "" },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_operation_status",
    });
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        runningAtMs: null,
        state: "accepted",
      }),
    );
  });

  it("ignores stale status reports for superseded Probe Operations without regressing state", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const staleOperation = database.probeOperations.createProbeUpgradeRequest({
      ...createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: host.id,
        nowMs: 1_725_000_009_000,
        targetProbeVersion: "0.2.0",
      }).operation,
      state: "superseded",
      supersededAtMs: 1_725_000_009_500,
      updatedAtMs: 1_725_000_009_500,
    });
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          operationStatuses: [
            {
              failed: {
                errorCode: "unsupported_installation",
                message: "late local status",
              },
              operationId: String(staleOperation.id),
            },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(200);
    expect(database.probeOperations.findById(staleOperation.id ?? 0)).toEqual(
      expect.objectContaining({
        failureCode: null,
        state: "superseded",
      }),
    );
  });

  it("stores raw Metrics samples and exposes current Host Status summaries", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          inventoryHash: "",
          metrics: [
            {
              collectedAtMs: 1_725_000_009_500,
              cpuCores: [
                {
                  idle: 850,
                  name: "cpu0",
                  nice: 10,
                  softirq: 2,
                  steal: 1,
                  system: 40,
                  usagePercent: 15,
                  user: 100,
                },
              ],
              cpuPercent: 42.5,
              disks: [
                {
                  availableBytes: 512,
                  filesystemType: "ext4",
                  mountPoint: "/",
                  totalBytes: 2_048,
                  usedBytes: 1_536,
                },
              ],
              load_1: 0.12,
              load_5: 0.34,
              load_15: 0.56,
              memoryTotalBytes: 2_147_483_648,
              memoryUsedBytes: 1_073_741_824,
              networkInterfaces: [
                {
                  name: "eth0",
                  rxBytes: 9_000,
                  rxBytesDelta: 4_000,
                  txBytes: 11_000,
                  txBytesDelta: 2_000,
                },
              ],
              sequence: 1,
              uptimeSeconds: 86_400,
            },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(200);
    const acknowledgement = ReportResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(acknowledgement.acceptedSequenceEnd.toString()).toBe("1");
    expect(acknowledgement.serverTimeMs.toString()).toBe("1725000010000");
    expect(acknowledgement.currentProbeConfigurationVersion).toBe("default-v1");

    const storedSample = database.sqlite
      .prepare(
        "select id, sequence, boot_id, collected_at_ms, received_at_ms, cpu_percent, memory_used_bytes, memory_total_bytes, load_1, load_5, load_15, uptime_seconds, disk_used_bytes, disk_total_bytes, network_rx_bytes_delta, network_tx_bytes_delta from metric_samples",
      )
      .get() as {
      boot_id: string;
      collected_at_ms: number;
      cpu_percent: number;
      disk_total_bytes: number;
      disk_used_bytes: number;
      id: number;
      load_1: number;
      load_5: number;
      load_15: number;
      memory_total_bytes: number;
      memory_used_bytes: number;
      network_rx_bytes_delta: number;
      network_tx_bytes_delta: number;
      received_at_ms: number;
      sequence: number;
      uptime_seconds: number;
    };
    expect(storedSample).toEqual(
      expect.objectContaining({
        boot_id: "boot-01",
        collected_at_ms: 1_725_000_009_500,
        cpu_percent: 42.5,
        disk_total_bytes: 2_048,
        disk_used_bytes: 1_536,
        load_1: 0.12,
        load_5: 0.34,
        load_15: 0.56,
        memory_total_bytes: 2_147_483_648,
        memory_used_bytes: 1_073_741_824,
        network_rx_bytes_delta: 4_000,
        network_tx_bytes_delta: 2_000,
        received_at_ms: 1_725_000_010_000,
        sequence: 1,
        uptime_seconds: 86_400,
      }),
    );

    expect(
      database.sqlite
        .prepare(
          "select name, user, system, idle, usage_percent from metric_cpu_cores where metric_sample_id = ?",
        )
        .all(storedSample.id),
    ).toEqual([
      {
        idle: 850,
        name: "cpu0",
        system: 40,
        usage_percent: 15,
        user: 100,
      },
    ]);
    expect(
      database.sqlite
        .prepare(
          "select mount_point, filesystem_type, total_bytes, used_bytes, available_bytes from metric_disks where metric_sample_id = ?",
        )
        .all(storedSample.id),
    ).toEqual([
      {
        available_bytes: 512,
        filesystem_type: "ext4",
        mount_point: "/",
        total_bytes: 2_048,
        used_bytes: 1_536,
      },
    ]);
    expect(
      database.sqlite
        .prepare(
          "select name, rx_bytes, tx_bytes, rx_bytes_delta, tx_bytes_delta from metric_network_interfaces where metric_sample_id = ?",
        )
        .all(storedSample.id),
    ).toEqual([
      {
        name: "eth0",
        rx_bytes: 9_000,
        rx_bytes_delta: 4_000,
        tx_bytes: 11_000,
        tx_bytes_delta: 2_000,
      },
    ]);

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          displayName: "managed-host-01",
          lastReportAtMs: 1_725_000_010_000,
          latestMetrics: expect.objectContaining({
            collectedAtMs: 1_725_000_009_500,
            cpuPercent: 42.5,
            diskTotalBytes: 2_048,
            diskUsedBytes: 1_536,
            load1: 0.12,
            load5: 0.34,
            load15: 0.56,
            memoryTotalBytes: 2_147_483_648,
            memoryUsedBytes: 1_073_741_824,
            networkRxBitsPerSecond: 6_400,
            networkRxBytesDelta: 4_000,
            networkTxBitsPerSecond: 3_200,
            networkTxBytesDelta: 2_000,
            receivedAtMs: 1_725_000_010_000,
            uptimeSeconds: 86_400,
          }),
          status: "online",
        }),
      ],
    });

    database.close();
  });

  it("stores disabled individual Metrics as absent fields instead of zero samples", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-partial-metrics",
          metrics: [
            {
              collectedAtMs: 1_725_000_009_500,
              memoryTotalBytes: 2_147_483_648,
              memoryUsedBytes: 1_073_741_824,
              sequence: 1,
            },
          ],
          probeConfigurationVersion: "memory-only-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(200);

    const storedSample = database.sqlite
      .prepare(
        "select cpu_percent, memory_used_bytes, memory_total_bytes, load_1, load_5, load_15, uptime_seconds, disk_used_bytes, disk_total_bytes, network_rx_bytes_delta, network_tx_bytes_delta from metric_samples",
      )
      .get();
    expect(storedSample).toEqual({
      cpu_percent: null,
      disk_total_bytes: null,
      disk_used_bytes: null,
      load_1: null,
      load_5: null,
      load_15: null,
      memory_total_bytes: 2_147_483_648,
      memory_used_bytes: 1_073_741_824,
      network_rx_bytes_delta: null,
      network_tx_bytes_delta: null,
      uptime_seconds: null,
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          latestMetrics: expect.objectContaining({
            cpuPercent: null,
            diskTotalBytes: null,
            diskUsedBytes: null,
            load1: null,
            load5: null,
            load15: null,
            memoryTotalBytes: 2_147_483_648,
            memoryUsedBytes: 1_073_741_824,
            networkRxBytesDelta: null,
            networkTxBytesDelta: null,
            uptimeSeconds: null,
          }),
        }),
      ],
    });

    database.close();
  });

  it("acknowledges duplicate observations without storing duplicate Metrics samples", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const reportBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-duplicate",
        metrics: [
          {
            collectedAtMs: 1_725_000_009_500,
            cpuPercent: 42.5,
            memoryUsedBytes: 1_073_741_824,
            sequence: 7,
          },
        ],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 7,
        sequenceStart: 7,
      }),
    ).finish();

    const sendReport = () =>
      app.request("/api/probe/report", {
        body: reportBody,
        headers: {
          authorization: `Bearer ${registration.probeSecret}`,
          "content-type": "application/x-protobuf",
        },
        method: "POST",
      });

    const firstResponse = await sendReport();
    const duplicateResponse = await sendReport();

    expect(firstResponse.status).toBe(200);
    expect(duplicateResponse.status).toBe(200);
    const duplicateAck = ReportResponse.decode(
      new Uint8Array(await duplicateResponse.arrayBuffer()),
    );
    expect(duplicateAck.acceptedSequenceEnd.toString()).toBe("7");

    const counts = database.sqlite
      .prepare(
        "select (select count(*) from report_observations) as observations, (select count(*) from metric_samples) as samples",
      )
      .get() as { observations: number; samples: number };
    expect(counts).toEqual({
      observations: 1,
      samples: 1,
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          latestMetrics: expect.objectContaining({
            cpuPercent: 42.5,
          }),
          status: "online",
        }),
      ],
    });

    database.close();
  });

  it("derives Host Status from received time and refreshes it for empty batches", async () => {
    const database = await createTemporaryDatabase();
    let now = 1_725_000_000_000;
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => now,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-empty",
          inventoryHash: "",
          metrics: [],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(200);

    const readStatus = async () => {
      const hostsResponse = await app.request("/api/web/hosts", {
        headers: {
          cookie: ownerSession,
        },
      });
      const body = (await hostsResponse.json()) as {
        hosts: Array<{
          lastReportAtMs: number;
          latestMetrics: unknown;
          status: string;
        }>;
      };

      return body.hosts[0];
    };

    await expect(readStatus()).resolves.toEqual(
      expect.objectContaining({
        lastReportAtMs: 1_725_000_000_000,
        latestMetrics: null,
        status: "online",
      }),
    );

    now += 45_000;
    await expect(readStatus()).resolves.toEqual(
      expect.objectContaining({
        status: "stale",
      }),
    );

    now += 50_000;
    await expect(readStatus()).resolves.toEqual(
      expect.objectContaining({
        status: "offline",
      }),
    );

    database.close();
  });

  it("detects Probe clock skew separately from Host Status", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_600_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-skew",
          metrics: [
            {
              collectedAtMs: 1_725_000_000_000,
              cpuPercent: 12.5,
              memoryUsedBytes: 512,
              sequence: 1,
            },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(200);

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          clockSkew: {
            detected: true,
            lastDeltaMs: 600_000,
          },
          status: "online",
        }),
      ],
    });

    database.close();
  });

  it("persists Probe Configuration errors from reports into Host summaries", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_700_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-config-error",
          metrics: [],
          probeConfigurationError: {
            errorCode: "probe_configuration_fetch_failed",
            failedVersion: "global-1725000700000-1",
            message: "report request failed: 503 Service Unavailable",
          },
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(200);

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          probeConfigurationError: {
            errorCode: "probe_configuration_fetch_failed",
            failedVersion: "global-1725000700000-1",
            message: "report request failed: 503 Service Unavailable",
            reportedAtMs: 1_725_000_700_000,
          },
        }),
      ],
    });

    database.close();
  });

  it("clears persisted Probe Configuration errors after a clean report", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_700_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const errorResponse = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-config-error-cleared",
          metrics: [],
          probeConfigurationError: {
            errorCode: "probe_configuration_fetch_failed",
            failedVersion: "global-1725000700000-1",
            message: "report request failed: 503 Service Unavailable",
          },
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(errorResponse.status).toBe(200);

    const cleanResponse = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-config-error-cleared",
          metrics: [],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 2,
          sequenceStart: 2,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(cleanResponse.status).toBe(200);

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          probeConfigurationError: null,
        }),
      ],
    });

    database.close();
  });

  it("rejects unauthorized, malformed, compressed, and oversized report payloads", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const validBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-validation",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
      }),
    ).finish();

    const unauthorized = await app.request("/api/probe/report", {
      body: validBody,
      headers: {
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get("cache-control")).toBe("no-store");

    const malformed = await app.request("/api/probe/report", {
      body: new Uint8Array([0xff, 0xff, 0xff]),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(malformed.status).toBe(400);
    expect(malformed.headers.get("cache-control")).toBe("no-store");
    await expect(malformed.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });

    const compressed = await app.request("/api/probe/report", {
      body: validBody,
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-encoding": "gzip",
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(compressed.status).toBe(415);
    expect(compressed.headers.get("cache-control")).toBe("no-store");
    await expect(compressed.json()).resolves.toEqual({
      error: "payload_compression_not_supported",
    });

    const contentLengthOversized = await app.request("/api/probe/report", {
      body: validBody,
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-length": String(1024 * 1024 + 1),
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(contentLengthOversized.status).toBe(413);
    expect(contentLengthOversized.headers.get("cache-control")).toBe(
      "no-store",
    );
    await expect(contentLengthOversized.json()).resolves.toEqual({
      error: "probe_report_too_large",
    });

    const oversized = await app.request("/api/probe/report", {
      body: new Uint8Array(1024 * 1024 + 1),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(oversized.status).toBe(413);
    expect(oversized.headers.get("cache-control")).toBe("no-store");
    await expect(oversized.json()).resolves.toEqual({
      error: "probe_report_too_large",
    });

    database.close();
  });

  it("stops reading Probe report bodies after the payload limit is exceeded", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    let pullCount = 0;
    let canceled = false;
    const body = new ReadableStream<Uint8Array>({
      cancel() {
        canceled = true;
      },
      pull(controller) {
        pullCount += 1;

        if (pullCount === 1) {
          controller.enqueue(new Uint8Array(1024 * 1024));
          return;
        }

        if (pullCount === 2) {
          controller.enqueue(new Uint8Array(1));
          return;
        }

        throw new Error("Probe report body was read past the capped limit");
      },
    });

    const response = await app.fetch(
      requestWithStreamBody("/api/probe/report", {
        body,
        headers: {
          authorization: `Bearer ${registration.probeSecret}`,
          "content-type": "application/x-protobuf",
        },
        method: "POST",
      }),
    );

    expect(response.status).toBe(413);
    expect(canceled).toBe(true);
    expect(pullCount).toBe(2);
    await expect(response.json()).resolves.toEqual({
      error: "probe_report_too_large",
    });

    database.close();
  });

  it("does not record audit events for routine Probe reports", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_080_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const auditCountBeforeReport = database.sqlite
      .prepare("select count(*) as count from audit_log")
      .get() as { count: number };

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-audit-boundary",
          metrics: [
            {
              collectedAtMs: 1_725_000_079_500,
              cpuPercent: 42.5,
              sequence: 1,
            },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(200);
    expect(
      database.sqlite.prepare("select count(*) as count from audit_log").get(),
    ).toEqual(auditCountBeforeReport);

    database.close();
  });

  it("rejects full Inventory reports when the supplied Inventory hash is not canonical", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-bad-inventory-hash",
          inventory: {
            architecture: "x86_64",
            cpuCount: 4,
            hostname: "managed-host-renamed",
            kernel: "6.8.0",
            memoryTotalBytes: 4_294_967_296,
            os: "linux",
            probeVersion: "0.1.0",
          },
          inventoryHash: "not-the-canonical-inventory-hash",
          metrics: [],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          displayName: "managed-host-01",
          lastReportAtMs: null,
        }),
      ],
    });

    database.close();
  });

  it("rejects Metrics reports that omit a sample from the advertised sequence range", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-missing-sequence",
          metrics: [
            {
              collectedAtMs: 1_725_000_009_500,
              cpuPercent: 20,
              memoryUsedBytes: 1_024,
              sequence: 10,
            },
            {
              collectedAtMs: 1_725_000_009_700,
              cpuPercent: 30,
              memoryUsedBytes: 2_048,
              sequence: 12,
            },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 12,
          sequenceStart: 10,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });

    const counts = database.sqlite
      .prepare(
        "select (select count(*) from report_observations) as observations, (select count(*) from metric_samples) as samples",
      )
      .get() as { observations: number; samples: number };
    expect(counts).toEqual({
      observations: 0,
      samples: 0,
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          lastReportAtMs: null,
        }),
      ],
    });

    database.close();
  });

  it("delivers a pending Probe Uninstall Operation to the matching probe", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
      probeOperationTokenSecret: "configured-token-signing-secret",
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const operation = database.probeOperations.createProbeUpgradeRequest(
      createProbeUninstallRequest({
        activeOperation: null,
        hostId: host.id,
        nowMs: 1_725_000_009_000,
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(200);
    const body = ReportResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(body.pendingOperation?.id).toBe(String(operation.id));
    expect(body.pendingOperation?.probeUninstall).toEqual(
      expect.objectContaining({
        operationToken: expect.any(String),
      }),
    );
    expect(body.pendingOperation?.probeUpgrade).toBeNull();

    database.close();
  });

  it("soft deletes the Host after a Probe Uninstall Operation reports success", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
      probeOperationTokenSecret: "configured-token-signing-secret",
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const operation = database.probeOperations.createProbeUpgradeRequest(
      createProbeUninstallRequest({
        activeOperation: null,
        hostId: host.id,
        nowMs: 1_725_000_009_000,
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    const delivery = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    const token = ReportResponse.decode(
      new Uint8Array(await delivery.arrayBuffer()),
    ).pendingOperation?.probeUninstall?.operationToken;

    const runningReport = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          operationAcknowledgements: [
            {
              operationId: String(operation.id),
            },
          ],
          operationStatuses: [
            {
              operationId: String(operation.id),
              running: {},
            },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 2,
          sequenceStart: 2,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(runningReport.status).toBe(200);

    const status = await app.request(
      `/api/probe/operations/${operation.id}/status`,
      {
        body: JSON.stringify({
          status: "succeeded",
          token,
        }),
        headers: {
          authorization: `Bearer ${registration.probeSecret}`,
          "content-type": "application/json",
        },
        method: "POST",
      },
    );
    expect(status.status).toBe(200);

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(hostsResponse.status).toBe(200);
    await expect(hostsResponse.json()).resolves.toEqual({ hosts: [] });

    database.close();
  });

  it("rejects Metrics reports with duplicate sample sequence entries", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_010_000,
    });
    const enrollmentToken = await createEnrollmentToken(
      app,
      await loginOwner(app),
    );
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-duplicate-sample",
          metrics: [
            {
              collectedAtMs: 1_725_000_009_500,
              cpuPercent: 20,
              memoryUsedBytes: 1_024,
              sequence: 10,
            },
            {
              collectedAtMs: 1_725_000_009_700,
              cpuPercent: 30,
              memoryUsedBytes: 2_048,
              sequence: 10,
            },
          ],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 11,
          sequenceStart: 10,
        }),
      ).finish(),
      headers: {
        authorization: `Bearer ${registration.probeSecret}`,
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });

    const counts = database.sqlite
      .prepare(
        "select (select count(*) from report_observations) as observations, (select count(*) from metric_samples) as samples",
      )
      .get() as { observations: number; samples: number };
    expect(counts).toEqual({
      observations: 0,
      samples: 0,
    });

    database.close();
  });
});
