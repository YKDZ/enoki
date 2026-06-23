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
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-config-db-"));
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
        inventory: {
          architecture: "x86_64",
          cpuCount: 2,
          hostname: "managed-host-01",
          kernel: "6.8.0",
          memoryTotalBytes: 2_147_483_648,
          os: "linux",
          probeVersion: "0.1.0",
        },
        probePublicKeyPem: identity.publicKeyPem,
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

describe("Probe Configuration API", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("updates global defaults and exposes the inherited effective version to Owners and Probes", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_020_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);

    const updateResponse = await app.request("/api/web/probe-configuration", {
      body: JSON.stringify({
        collectCpu: true,
        collectDisk: false,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: false,
        collectUptime: true,
        metricsCollectionIntervalSeconds: 10,
        reportingBatchIntervalSeconds: 30,
      }),
      headers: {
        "content-type": "application/json",
        cookie: ownerSession,
      },
      method: "PUT",
    });

    expect(updateResponse.status).toBe(200);
    const updated = (await updateResponse.json()) as {
      configuration: { version: string };
    };
    expect(updated.configuration.version).not.toBe("default-v1");

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          displayName: "managed-host-01",
          probeConfiguration: {
            mode: "inherit",
            version: updated.configuration.version,
          },
        }),
      ],
    });

    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const reportBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        inventoryHash: "",
        metrics: [],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
      }),
    ).finish();
    const reportResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", reportBody),
    );

    expect(reportResponse.status).toBe(200);
    const acknowledgement = ReportResponse.decode(
      new Uint8Array(await reportResponse.arrayBuffer()),
    );
    expect(acknowledgement.currentProbeConfigurationVersion).toBe(
      updated.configuration.version,
    );

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
    expect(configResponse.headers.get("cache-control")).toBe("no-store");
    const configuration = ConfigurationResponse.decode(
      new Uint8Array(await configResponse.arrayBuffer()),
    );
    expect(configuration).toEqual(
      expect.objectContaining({
        collectCpu: true,
        collectDisk: false,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: false,
        collectUptime: true,
        metricsCollectionIntervalSeconds: 10,
        reportingBatchIntervalSeconds: 30,
        version: updated.configuration.version,
      }),
    );

    database.close();
  });

  it("records minimal audit events for Owner Probe Configuration changes", async () => {
    const database = await createTemporaryDatabase();
    let now = 1_725_000_020_000;
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
    await registerProbe(app, enrollmentToken);
    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    const hostId = ((await hostsResponse.json()) as { hosts: { id: number }[] })
      .hosts[0]?.id;

    now += 1;
    const globalResponse = await app.request("/api/web/probe-configuration", {
      body: JSON.stringify({
        collectCpu: true,
        collectDisk: false,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: false,
        collectUptime: true,
        metricsCollectionIntervalSeconds: 10,
        reportingBatchIntervalSeconds: 30,
      }),
      headers: {
        "content-type": "application/json",
        cookie: ownerSession,
      },
      method: "PUT",
    });
    expect(globalResponse.status).toBe(200);

    now += 1;
    const overrideResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-configuration`,
      {
        body: JSON.stringify({
          configuration: {
            collectCpu: false,
            collectDisk: false,
            collectLoad: false,
            collectMemory: false,
            collectNetwork: false,
            collectUptime: false,
            metricsCollectionIntervalSeconds: 60,
            reportingBatchIntervalSeconds: 120,
          },
          mode: "override",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );
    expect(overrideResponse.status).toBe(200);

    now += 1;
    const inheritResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-configuration`,
      {
        body: JSON.stringify({
          mode: "inherit",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );
    expect(inheritResponse.status).toBe(200);

    expect(database.audit.recent(5)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          action: "probe_configuration.host.inherit",
          actor: "owner",
          outcome: "success",
          subjectId: String(hostId),
          subjectType: "host",
        }),
        expect.objectContaining({
          action: "probe_configuration.host.override",
          actor: "owner",
          outcome: "success",
          subjectId: String(hostId),
          subjectType: "host",
        }),
        expect.objectContaining({
          action: "probe_configuration.global.update",
          actor: "owner",
          outcome: "success",
          subjectType: "probe_configuration",
        }),
      ]),
    );

    database.close();
  });

  it("generates distinct Probe Configuration versions for same-millisecond consecutive edits", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_020_000,
    });
    const ownerSession = await loginOwner(app);

    const updateGlobal = async (metricsCollectionIntervalSeconds: number) => {
      const response = await app.request("/api/web/probe-configuration", {
        body: JSON.stringify({
          collectCpu: true,
          collectDisk: true,
          collectLoad: true,
          collectMemory: true,
          collectNetwork: true,
          collectUptime: true,
          metricsCollectionIntervalSeconds,
          reportingBatchIntervalSeconds: 30,
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      });

      expect(response.status).toBe(200);
      return ((await response.json()) as { configuration: { version: string } })
        .configuration.version;
    };

    const firstVersion = await updateGlobal(10);
    const secondVersion = await updateGlobal(11);

    expect(secondVersion).not.toBe(firstVersion);

    database.close();
  });

  it("lets a Host override Probe Configuration and then inherit global defaults again", async () => {
    const database = await createTemporaryDatabase();
    let now = 1_725_000_030_000;
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
    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    const hostId = ((await hostsResponse.json()) as { hosts: { id: number }[] })
      .hosts[0]?.id;

    now += 1;
    const globalResponse = await app.request("/api/web/probe-configuration", {
      body: JSON.stringify({
        collectCpu: true,
        collectDisk: true,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: true,
        collectUptime: true,
        metricsCollectionIntervalSeconds: 10,
        reportingBatchIntervalSeconds: 30,
      }),
      headers: {
        "content-type": "application/json",
        cookie: ownerSession,
      },
      method: "PUT",
    });
    const globalVersion = (
      (await globalResponse.json()) as {
        configuration: { version: string };
      }
    ).configuration.version;

    now += 1;
    const overrideResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-configuration`,
      {
        body: JSON.stringify({
          configuration: {
            collectCpu: false,
            collectDisk: false,
            collectLoad: false,
            collectMemory: false,
            collectNetwork: false,
            collectUptime: false,
            metricsCollectionIntervalSeconds: 60,
            reportingBatchIntervalSeconds: 120,
          },
          mode: "override",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );

    expect(overrideResponse.status).toBe(200);
    const override = (await overrideResponse.json()) as {
      configuration: {
        collectCpu: boolean;
        collectMemory: boolean;
        metricsCollectionIntervalSeconds: number;
        reportingBatchIntervalSeconds: number;
        version: string;
      };
      mode: "override";
    };
    expect(override.mode).toBe("override");
    expect(override.configuration.version).not.toBe(globalVersion);
    expect(override.configuration).toEqual(
      expect.objectContaining({
        collectCpu: false,
        collectMemory: false,
        metricsCollectionIntervalSeconds: 60,
        reportingBatchIntervalSeconds: 120,
      }),
    );

    const ConfigurationRequest = root.enoki.v1.ProbeConfigurationRequest;
    const ConfigurationResponse = root.enoki.v1.ProbeConfigurationResponse;
    const configBody = ConfigurationRequest.encode(
      ConfigurationRequest.create({
        currentVersion: globalVersion,
        probeId: registration.probeId,
      }),
    ).finish();
    const configResponse = await app.request(
      "/api/probe/config",
      signedProbeRequest(registration, "/api/probe/config", configBody),
    );
    const probeConfiguration = ConfigurationResponse.decode(
      new Uint8Array(await configResponse.arrayBuffer()),
    );
    expect(probeConfiguration.version).toBe(override.configuration.version);
    expect(probeConfiguration.metricsCollectionIntervalSeconds).toBe(60);
    expect(probeConfiguration.reportingBatchIntervalSeconds).toBe(120);
    expect(probeConfiguration.collectCpu).toBe(false);
    expect(probeConfiguration.collectUptime).toBe(false);

    const inheritResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-configuration`,
      {
        body: JSON.stringify({
          mode: "inherit",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );

    expect(inheritResponse.status).toBe(200);
    await expect(inheritResponse.json()).resolves.toEqual({
      configuration: expect.objectContaining({
        version: globalVersion,
      }),
      mode: "inherit",
    });

    database.close();
  });

  it("rejects host Probe Configuration overrides for unknown Hosts", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_030_000,
    });
    const ownerSession = await loginOwner(app);

    const response = await app.request(
      "/api/web/hosts/999/probe-configuration",
      {
        body: JSON.stringify({
          configuration: {
            collectCpu: true,
            collectDisk: true,
            collectLoad: true,
            collectMemory: true,
            collectNetwork: true,
            collectUptime: true,
            metricsCollectionIntervalSeconds: 10,
            reportingBatchIntervalSeconds: 30,
          },
          mode: "override",
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      },
    );

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({
      error: "host_not_found",
    });
    expect(
      database.sqlite
        .prepare(
          "select count(*) as count from probe_configuration_host_overrides",
        )
        .get(),
    ).toEqual({ count: 0 });

    database.close();
  });

  it("rejects invalid Probe Configuration intervals without changing the effective version", async () => {
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
    const invalidInputs = [
      {
        error: "metrics_collection_interval_out_of_range",
        input: {
          metricsCollectionIntervalSeconds: 0,
          reportingBatchIntervalSeconds: 30,
        },
      },
      {
        error: "reporting_batch_interval_out_of_range",
        input: {
          metricsCollectionIntervalSeconds: 10,
          reportingBatchIntervalSeconds: 601,
        },
      },
      {
        error: "reporting_batch_interval_shorter_than_collection_interval",
        input: {
          metricsCollectionIntervalSeconds: 60,
          reportingBatchIntervalSeconds: 30,
        },
      },
    ];

    for (const invalid of invalidInputs) {
      const response = await app.request("/api/web/probe-configuration", {
        body: JSON.stringify({
          collectCpu: true,
          collectDisk: true,
          collectLoad: true,
          collectMemory: true,
          collectNetwork: true,
          collectUptime: true,
          ...invalid.input,
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "PUT",
      });

      expect(response.status).toBe(400);
      await expect(response.json()).resolves.toEqual({
        error: invalid.error,
      });
    }

    const currentResponse = await app.request("/api/web/probe-configuration", {
      headers: {
        cookie: ownerSession,
      },
    });

    await expect(currentResponse.json()).resolves.toEqual({
      configuration: expect.objectContaining({
        metricsCollectionIntervalSeconds: 5,
        reportingBatchIntervalSeconds: 15,
        version: "default-v1",
      }),
    });

    database.close();
  });

  it("accepts one-second collection and reporting intervals", async () => {
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

    const response = await app.request("/api/web/probe-configuration", {
      body: JSON.stringify({
        collectCpu: true,
        collectDisk: true,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: true,
        collectUptime: true,
        metricsCollectionIntervalSeconds: 1,
        reportingBatchIntervalSeconds: 1,
      }),
      headers: {
        "content-type": "application/json",
        cookie: ownerSession,
      },
      method: "PUT",
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      configuration: expect.objectContaining({
        metricsCollectionIntervalSeconds: 1,
        reportingBatchIntervalSeconds: 1,
      }),
    });

    database.close();
  });
});
