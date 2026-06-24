import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import * as root from "../../../packages/proto/src/generated/ts/enoki_pb.js";
import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import { createTestProbeIdentity, signedProbeRequest } from "./probe-test-auth";

const tempRoots: string[] = [];

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-metadata-db-"));
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
  const identity = createTestProbeIdentity();
  const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
  const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;
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
              hostname: "managed-host-01",
              kernel: "6.8.0",
              memoryTotalBytes: 2_147_483_648,
              networkInterfaces: [
                {
                  addresses: ["10.0.0.10"],
                  name: "eth0",
                },
              ],
              os: "linux",
              probeVersion: "0.1.0",
            },
          },
        ],
      }),
    ).finish(),
    headers: {
      "content-type": "application/x-protobuf",
    },
    method: "POST",
  });

  expect(response.status).toBe(200);
  const registration = RegistrationResponse.decode(
    new Uint8Array(await response.arrayBuffer()),
  );
  return { ...registration, privateKeyPem: identity.privateKeyPem };
}

async function reportHostProfile(
  app: ReturnType<typeof createHubApp>,
  registration: {
    privateKeyPem: string;
    probeId: string;
  },
  input: {
    address: string;
    bootId: string;
    hostname: string;
    sequence: number;
  },
) {
  const ReportRequest = root.enoki.v1.ProbeReportRequest;
  const body = ReportRequest.encode(
    ReportRequest.create({
      bootId: input.bootId,
      metrics: [],
      probeConfigurationVersion: "default-v1",
      probeId: registration.probeId,
      sequenceEnd: input.sequence,
      sequenceStart: input.sequence,
      snapshots: [
        {
          collectorId: "official.host-profile",
          hostProfile: {
            architecture: "x86_64",
            cpuCount: 2,
            hostname: input.hostname,
            kernel: "6.8.0",
            memoryTotalBytes: 2_147_483_648,
            networkInterfaces: [
              {
                addresses: [input.address],
                name: "eth0",
              },
            ],
            os: "linux",
            probeVersion: "0.1.0",
          },
        },
      ],
    }),
  ).finish();
  const response = await app.request(
    "/api/probe/report",
    signedProbeRequest(registration, "/api/probe/report", body),
  );

  expect(response.status).toBe(200);
}

async function reportMetric(
  app: ReturnType<typeof createHubApp>,
  registration: {
    privateKeyPem: string;
    probeId: string;
  },
  sequence: number,
  observedIp?: string,
) {
  const ReportRequest = root.enoki.v1.ProbeReportRequest;
  const body = ReportRequest.encode(
    ReportRequest.create({
      bootId: "boot-soft-delete",
      metrics: [
        {
          collectedAtMs: 1_725_000_059_500,
          cpuPercent: 12.5,
          sequence,
        },
      ],
      probeConfigurationVersion: "default-v1",
      probeId: registration.probeId,
      sequenceEnd: sequence,
      sequenceStart: sequence,
    }),
  ).finish();
  const response = await app.request("/api/probe/report", {
    ...signedProbeRequest(registration, "/api/probe/report", body),
    headers: {
      ...signedProbeRequest(registration, "/api/probe/report", body).headers,
      ...(observedIp ? { "x-forwarded-for": observedIp } : {}),
    },
  });

  expect(response.status).toBe(200);
}

async function firstHostId(
  app: ReturnType<typeof createHubApp>,
  ownerSession: string,
) {
  const response = await app.request("/api/web/hosts", {
    headers: {
      cookie: ownerSession,
    },
  });

  expect(response.status).toBe(200);
  const body = (await response.json()) as { hosts: { id: number }[] };
  return body.hosts[0]?.id;
}

describe("Host Metadata API", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("lets the Owner edit Display Name, Description, and Connect Address", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_040_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    const updateResponse = await app.request(
      `/api/web/hosts/${hostId}/metadata`,
      {
        body: JSON.stringify({
          connectAddress: "ssh.internal.example",
          description: "华东区主机",
          displayName: "生产探针 01",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );

    expect(updateResponse.status).toBe(200);
    await expect(updateResponse.json()).resolves.toEqual({
      connectAddress: "ssh.internal.example",
      description: "华东区主机",
      displayName: "生产探针 01",
      id: hostId,
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          connectAddress: "ssh.internal.example",
          description: "华东区主机",
          displayName: "生产探针 01",
          id: hostId,
        }),
      ],
    });
    expect(database.audit.recent(10)).toContainEqual(
      expect.objectContaining({
        action: "host.metadata.update",
        actor: "owner",
        outcome: "success",
        subjectId: String(hostId),
        subjectType: "host",
      }),
    );

    database.close();
  });

  it("returns a JSON error for malformed Host Metadata JSON", async () => {
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
    await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    const response = await app.request(`/api/web/hosts/${hostId}/metadata`, {
      body: "{",
      headers: {
        "content-type": "application/json",
        cookie: ownerSession,
      },
      method: "PUT",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_json",
    });

    database.close();
  });

  it("does not send Host Metadata in Probe Configuration", async () => {
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
    const hostId = await firstHostId(app, ownerSession);

    const updateResponse = await app.request(
      `/api/web/hosts/${hostId}/metadata`,
      {
        body: JSON.stringify({
          connectAddress: "ssh.internal.example",
          description: "不下发给探针",
          displayName: "生产探针 01",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );
    expect(updateResponse.status).toBe(200);

    const ConfigurationRequest = root.enoki.v1.ProbeConfigurationRequest;
    const ConfigurationResponse = root.enoki.v1.ProbeConfigurationResponse;
    const configBody = ConfigurationRequest.encode(
      ConfigurationRequest.create({
        currentVersion: "default-v1",
        probeId: registration.probeId,
      }),
    ).finish();
    const configResponse = await app.request(
      "/api/probe/config",
      signedProbeRequest(registration, "/api/probe/config", configBody),
    );

    expect(configResponse.status).toBe(200);
    const configuration = ConfigurationResponse.toObject(
      ConfigurationResponse.decode(
        new Uint8Array(await configResponse.arrayBuffer()),
      ),
      { defaults: true },
    ) as Record<string, unknown>;
    expect(configuration).toEqual(
      expect.objectContaining({
        metricsCollectionIntervalSeconds: 5,
        version: "default-v1",
      }),
    );
    expect(configuration).not.toHaveProperty("displayName");
    expect(configuration).not.toHaveProperty("connectAddress");
    expect(configuration).not.toHaveProperty("description");

    database.close();
  });

  it("keeps an Host Profile-derived Connect Address when hash-only reports only have Observed IP", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_055_000,
      trustForwardedProbeHeaders: true,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    await reportMetric(app, registration, 1, "203.0.113.55");

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          connectAddress: "10.0.0.10",
          id: hostId,
        }),
      ],
    });

    database.close();
  });

  it("lets the Owner edit only Connect Address without freezing Display Name sync", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_056_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    const updateResponse = await app.request(
      `/api/web/hosts/${hostId}/metadata`,
      {
        body: JSON.stringify({
          connectAddress: "ssh.internal.example",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );
    expect(updateResponse.status).toBe(200);
    await expect(updateResponse.json()).resolves.toEqual({
      connectAddress: "ssh.internal.example",
      description: "",
      displayName: "managed-host-01",
      id: hostId,
    });

    await reportHostProfile(app, registration, {
      address: "10.0.0.20",
      bootId: "boot-connect-only-edit",
      hostname: "managed-host-02",
      sequence: 1,
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          connectAddress: "ssh.internal.example",
          displayName: "managed-host-02",
          id: hostId,
        }),
      ],
    });

    database.close();
  });

  it("lets the Owner edit only Display Name without freezing Connect Address derivation", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_057_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    const updateResponse = await app.request(
      `/api/web/hosts/${hostId}/metadata`,
      {
        body: JSON.stringify({
          displayName: "生产探针 01",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );
    expect(updateResponse.status).toBe(200);
    await expect(updateResponse.json()).resolves.toEqual({
      connectAddress: "10.0.0.10",
      description: "",
      displayName: "生产探针 01",
      id: hostId,
    });

    await reportHostProfile(app, registration, {
      address: "10.0.0.20",
      bootId: "boot-display-only-edit",
      hostname: "managed-host-02",
      sequence: 1,
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          connectAddress: "10.0.0.20",
          displayName: "生产探针 01",
          id: hostId,
        }),
      ],
    });

    database.close();
  });

  it("syncs Display Name and Connect Address from Host Profile until the Owner edits them", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_050_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    await reportHostProfile(app, registration, {
      address: "10.0.0.20",
      bootId: "boot-sync-before-edit",
      hostname: "managed-host-02",
      sequence: 1,
    });

    let hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          connectAddress: "10.0.0.20",
          displayName: "managed-host-02",
          id: hostId,
        }),
      ],
    });

    const updateResponse = await app.request(
      `/api/web/hosts/${hostId}/metadata`,
      {
        body: JSON.stringify({
          connectAddress: "ssh.internal.example",
          displayName: "生产探针 01",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );
    expect(updateResponse.status).toBe(200);

    await reportHostProfile(app, registration, {
      address: "10.0.0.30",
      bootId: "boot-sync-after-edit",
      hostname: "managed-host-03",
      sequence: 1,
    });

    hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          connectAddress: "ssh.internal.example",
          displayName: "生产探针 01",
          id: hostId,
        }),
      ],
    });

    database.close();
  });

  it("creates a Probe uninstall request when deleting a Host", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_060_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);
    await reportMetric(app, registration, 1);

    const deleteResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
      method: "DELETE",
    });

    expect(deleteResponse.status).toBe(202);
    const deleteBody = (await deleteResponse.json()) as {
      probeUninstallRequest: { id: number; state: string };
    };
    expect(deleteBody.probeUninstallRequest).toEqual({
      createdAtMs: 1_725_000_060_000,
      failure: null,
      id: expect.any(Number),
      state: "pending",
      updatedAtMs: 1_725_000_060_000,
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          id: hostId,
        }),
      ],
    });

    const metadataResponse = await app.request(
      `/api/web/hosts/${hostId}/metadata`,
      {
        body: JSON.stringify({
          connectAddress: "ssh.internal.example",
          displayName: "已删除主机",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );
    expect(metadataResponse.status).toBe(200);

    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const reportRequestBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-soft-delete",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
      }),
    ).finish();
    const reportResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", reportRequestBody),
    );
    expect(reportResponse.status).toBe(200);
    const reportBody = ReportResponse.decode(
      new Uint8Array(await reportResponse.arrayBuffer()),
    );
    expect(reportBody.pendingOperation?.id).toBe(
      String(deleteBody.probeUninstallRequest.id),
    );
    expect(reportBody.pendingOperation?.probeUninstall?.operationToken).toEqual(
      expect.any(String),
    );
    expect(
      database.sqlite
        .prepare("select count(*) as count from metric_samples")
        .get(),
    ).toEqual({
      count: 1,
    });
    expect(database.audit.recent(10)).toContainEqual(
      expect.objectContaining({
        action: "host.delete",
        actor: "owner",
        outcome: "success",
        subjectId: String(hostId),
        subjectType: "host",
      }),
    );

    database.close();
  });

  it("can delete Hub-side Host data when the Probe is already gone", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_070_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);
    await reportMetric(app, registration, 1);

    const deleteResponse = await app.request(
      `/api/web/hosts/${hostId}?mode=hub-only`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "DELETE",
      },
    );

    expect(deleteResponse.status).toBe(200);
    await expect(deleteResponse.json()).resolves.toEqual({
      deletedHost: {
        deletedAtMs: 1_725_000_070_000,
        id: hostId,
      },
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [],
    });

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(detailResponse.status).toBe(404);
    expect(database.audit.recent(10)).toContainEqual(
      expect.objectContaining({
        action: "host.delete",
        actor: "owner",
        detailsJson: JSON.stringify({ hostId, mode: "hub-only" }),
        outcome: "success",
        subjectId: String(hostId),
        subjectType: "host",
      }),
    );

    database.close();
  });
});
