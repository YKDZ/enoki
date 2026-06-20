import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import root from "../../../packages/proto/src/generated/ts/enoki_pb.js";
import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-detail-db-"));
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
          cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
          filesystems: [
            {
              filesystemType: "ext4",
              mountPoint: "/",
              totalBytes: 20_000,
            },
          ],
          hostname: "managed-host-01",
          kernel: "6.8.0",
          memoryTotalBytes: 8_589_934_592,
          networkInterfaces: [
            {
              addresses: ["10.0.0.10"],
              name: "eth0",
            },
          ],
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

async function firstHostId(
  app: ReturnType<typeof createHubApp>,
  ownerSession: string,
) {
  const response = await app.request("/api/web/managed-hosts", {
    headers: {
      cookie: ownerSession,
    },
  });

  expect(response.status).toBe(200);
  const body = (await response.json()) as { hosts: { id: number }[] };
  return body.hosts[0]?.id;
}

async function sendReport(
  app: ReturnType<typeof createHubApp>,
  registration: {
    probeId: string;
    probeSecret: string;
  },
  input: {
    collectedAtMs: number;
    cpuPercent: number;
    sequence: number;
  },
) {
  const ReportRequest = root.enoki.v1.ProbeReportRequest;
  const response = await app.request("/api/probe/report", {
    body: ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-detail-history",
        metrics: [
          {
            collectedAtMs: input.collectedAtMs,
            cpuCores: [
              {
                idle: 850,
                name: "cpu0",
                nice: 0,
                softirq: 2,
                steal: 1,
                system: 40,
                usagePercent: input.cpuPercent - 1,
                user: 100,
              },
              {
                idle: 820,
                name: "cpu1",
                nice: 0,
                softirq: 2,
                steal: 1,
                system: 45,
                usagePercent: input.cpuPercent + 1,
                user: 110,
              },
            ],
            cpuPercent: input.cpuPercent,
            disks: [
              {
                availableBytes: 4_000,
                filesystemType: "ext4",
                mountPoint: "/",
                totalBytes: 20_000,
                usedBytes: 16_000,
              },
              {
                availableBytes: 2_000,
                filesystemType: "xfs",
                mountPoint: "/data",
                totalBytes: 10_000,
                usedBytes: 8_000,
              },
            ],
            memoryTotalBytes: 8_589_934_592,
            memoryUsedBytes: 4_294_967_296,
            networkInterfaces: [
              {
                name: "eth0",
                rxBytes: 20_000,
                rxBytesDelta: 3_000,
                txBytes: 30_000,
                txBytesDelta: 1_000,
              },
              {
                name: "eth1",
                rxBytes: 10_000,
                rxBytesDelta: 2_000,
                txBytes: 12_000,
                txBytesDelta: 500,
              },
            ],
            sequence: input.sequence,
            uptimeSeconds: 3600,
          },
        ],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: input.sequence,
        sequenceStart: input.sequence,
      }),
    ).finish(),
    headers: {
      authorization: `Bearer ${registration.probeSecret}`,
      "content-type": "application/x-protobuf",
    },
    method: "POST",
  });

  expect(response.status).toBe(200);
}

describe("Managed Host detail API", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("returns current detail, warnings, and fixed-window metrics history for the Owner", async () => {
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
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    nowMs = 1_725_000_005_000;
    await sendReport(app, registration, {
      collectedAtMs: 1_725_000_004_500,
      cpuPercent: 33.5,
      sequence: 1,
    });

    const overviewResponse = await app.request("/api/web/managed-hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(overviewResponse.status).toBe(200);
    await expect(overviewResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          id: hostId,
          latestMetrics: expect.objectContaining({
            diskTotalBytes: 30_000,
            diskUsedBytes: 24_000,
            networkRxBitsPerSecond: 8_000,
            networkTxBitsPerSecond: 2_400,
          }),
        }),
      ],
    });

    const detailResponse = await app.request(
      `/api/web/managed-hosts/${hostId}`,
      {
        headers: {
          cookie: ownerSession,
        },
      },
    );

    expect(detailResponse.status).toBe(200);
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        hostMetadata: {
          connectAddress: "10.0.0.10",
          displayName: "managed-host-01",
          observedIp: null,
        },
        cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
        id: hostId,
        inventory: expect.objectContaining({
          architecture: "x86_64",
          cpuCount: 2,
          cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
          hostname: "managed-host-01",
          memoryTotalBytes: "8589934592",
          networkInterfaces: [
            {
              addresses: ["10.0.0.10"],
              name: "eth0",
            },
          ],
          os: "linux",
          probeVersion: "0.1.0",
        }),
        probeConfiguration: expect.objectContaining({
          configuration: expect.objectContaining({
            metricsCollectionIntervalSeconds: 5,
            version: "default-v1",
          }),
          mode: "inherit",
        }),
        status: "online",
        warnings: [],
      }),
    });

    const historyResponse = await app.request(
      `/api/web/managed-hosts/${hostId}/metrics?window=1h`,
      {
        headers: {
          cookie: ownerSession,
        },
      },
    );

    expect(historyResponse.status).toBe(200);
    await expect(historyResponse.json()).resolves.toEqual({
      metrics: {
        samples: [
          {
            collectedAtMs: 1_725_000_004_500,
            cpuCores: [
              {
                name: "cpu0",
                usagePercent: 32.5,
              },
              {
                name: "cpu1",
                usagePercent: 34.5,
              },
            ],
            cpuPercent: 33.5,
            diskTotalBytes: 30_000,
            diskUsedBytes: 24_000,
            disks: [
              {
                availableBytes: 4_000,
                filesystemType: "ext4",
                mountPoint: "/",
                totalBytes: 20_000,
                usedBytes: 16_000,
              },
              {
                availableBytes: 2_000,
                filesystemType: "xfs",
                mountPoint: "/data",
                totalBytes: 10_000,
                usedBytes: 8_000,
              },
            ],
            memoryTotalBytes: 8_589_934_592,
            memoryUsedBytes: 4_294_967_296,
            networkInterfaces: [
              {
                name: "eth0",
                rxBitsPerSecond: 4_800,
                rxBytesDelta: 3_000,
                txBitsPerSecond: 1_600,
                txBytesDelta: 1_000,
              },
              {
                name: "eth1",
                rxBitsPerSecond: 3_200,
                rxBytesDelta: 2_000,
                txBitsPerSecond: 800,
                txBytesDelta: 500,
              },
            ],
            networkRxBitsPerSecond: 8_000,
            networkRxBytesDelta: 5_000,
            networkTxBitsPerSecond: 2_400,
            networkTxBytesDelta: 1_500,
            receivedAtMs: 1_725_000_005_000,
            sequence: 1,
            uptimeSeconds: 3600,
          },
        ],
        window: "1h",
      },
    });

    const invalidWindowResponse = await app.request(
      `/api/web/managed-hosts/${hostId}/metrics?window=2h`,
      {
        headers: {
          cookie: ownerSession,
        },
      },
    );

    expect(invalidWindowResponse.status).toBe(400);

    database.close();
  });

  it("keeps raw Probe Configuration errors out of primary detail warning copy", async () => {
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
    const hostId = await firstHostId(app, ownerSession);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const reportResponse = await app.request("/api/probe/report", {
      body: ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-config-error-detail",
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
    expect(reportResponse.status).toBe(200);

    const detailResponse = await app.request(
      `/api/web/managed-hosts/${hostId}`,
      {
        headers: {
          cookie: ownerSession,
        },
      },
    );

    expect(detailResponse.status).toBe(200);
    const body = (await detailResponse.json()) as {
      host: {
        warnings: Array<{
          code: string;
          message: string;
          technicalDetail?: string;
        }>;
      };
    };

    expect(body.host.warnings).toEqual([
      expect.objectContaining({
        code: "probe_configuration_error",
        message: "探针未能应用最新配置，请检查探针连通性或配置下发状态。",
        technicalDetail: expect.stringContaining(
          "report request failed: 503 Service Unavailable",
        ),
      }),
    ]);
    expect(body.host.warnings[0]?.message).not.toContain("503");

    database.close();
  });
});
