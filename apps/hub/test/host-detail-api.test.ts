import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import * as root from "../../../packages/proto/src/generated/ts/enoki_pb.js";
import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import {
  createTestProbeIdentity,
  signedProbeRequest,
  type RegisteredTestProbe,
} from "./probe-test-auth";

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
  input: { probeVersion?: string | null } = {},
) {
  const identity = createTestProbeIdentity();
  const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
  const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;
  const probeVersion = input.probeVersion ?? "0.1.0";
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
              cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
              collectorCapabilities: {
                official: {
                  cpu: { available: true },
                  disk: { available: true },
                  load: { available: true },
                  memory: { available: true },
                  network: { available: true },
                  uptime: { available: true },
                },
              },
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
              ...(input.probeVersion === null ? {} : { probeVersion }),
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
  registration: RegisteredTestProbe,
  input: { diskAvailable: boolean | null; sequence: number },
) {
  const ReportRequest = root.enoki.v1.ProbeReportRequest;
  const body = ReportRequest.encode(
    ReportRequest.create({
      bootId: "boot-capability",
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
            ...(input.diskAvailable === null
              ? {}
              : {
                  collectorCapabilities: {
                    official: {
                      cpu: { available: true },
                      disk: { available: input.diskAvailable },
                      load: { available: true },
                      memory: { available: true },
                      network: { available: true },
                      uptime: { available: true },
                    },
                  },
                }),
            cpuCount: 2,
            cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
            filesystems: input.diskAvailable
              ? [
                  {
                    filesystemType: "ext4",
                    mountPoint: "/",
                    totalBytes: 20_000,
                  },
                ]
              : [],
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

function probeAssetManifest(version?: unknown) {
  return {
    assets: [
      {
        file: "enoki-probe-x86_64-unknown-linux-gnu.tar.gz",
        sha256: "a".repeat(64),
        target: "x86_64-unknown-linux-gnu",
      },
    ],
    kind: "enoki-probe-assets",
    signature: {
      algorithm: "rsa-sha256",
      file: "manifest.json.sig",
    },
    ...(version === undefined ? {} : { version }),
  };
}

async function readHostProbeUpgradeEligibility(input: {
  manifestVersion?: unknown;
  probeVersion?: string | null;
}) {
  const database = await createTemporaryDatabase();
  const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-assets-"));
  tempRoots.push(assetRoot);
  const assetDir = path.join(assetRoot, "assets");
  await mkdir(assetDir, { recursive: true });
  await writeFile(
    path.join(assetDir, "manifest.json"),
    JSON.stringify(probeAssetManifest(input.manifestVersion)),
  );
  const app = createHubApp({
    auth: {
      failureDelayMs: 0,
      ownerPassword: "correct horse battery staple",
      sessionCookieName: "enoki_owner_session",
    },
    database,
    probeAssets: {
      assetDir,
      installScriptPath: path.join(assetRoot, "install-probe.sh"),
    },
  });
  const ownerSession = await loginOwner(app);
  const enrollmentToken = await createEnrollmentToken(app, ownerSession);
  await registerProbe(app, enrollmentToken, {
    probeVersion: input.probeVersion,
  });
  const hostId = await firstHostId(app, ownerSession);

  const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
    headers: {
      cookie: ownerSession,
    },
  });

  expect(detailResponse.status).toBe(200);
  const body = (await detailResponse.json()) as {
    host: {
      probeUpgradeEligibility: unknown;
      probeVersion: string;
    };
  };

  database.close();
  return body.host.probeUpgradeEligibility;
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
  const hostId = body.hosts[0]?.id;
  if (hostId === undefined) {
    throw new Error("expected at least one Host");
  }
  return hostId;
}

async function sendReport(
  app: ReturnType<typeof createHubApp>,
  registration: RegisteredTestProbe,
  input: {
    collectedAtMs: number;
    cpuPercent: number;
    diskHealth?: Array<{
      deviceName: string;
      model?: string;
      passed: boolean;
      powerOnHours?: number;
      serialNumber?: string;
      temperatureCelsius?: number;
    }>;
    sequence: number;
  },
) {
  const ReportRequest = root.enoki.v1.ProbeReportRequest;
  const body = ReportRequest.encode(
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
          diskHealth: input.diskHealth ?? [],
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
  ).finish();
  const response = await app.request(
    "/api/probe/report",
    signedProbeRequest(registration, "/api/probe/report", body),
  );

  expect(response.status).toBe(200);
}

describe("Host detail API", () => {
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

    const overviewResponse = await app.request("/api/web/hosts", {
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

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(detailResponse.status).toBe(200);
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        hostMetadata: {
          connectAddress: "10.0.0.10",
          description: "",
          displayName: "managed-host-01",
          observedIp: null,
        },
        cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
        id: hostId,
        hostProfile: expect.objectContaining({
          architecture: "x86_64",
          cpuCount: 2,
          cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
          hostname: "managed-host-01",
          memoryTotalBytes: 8_589_934_592,
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
      `/api/web/hosts/${hostId}/metrics?window=1h`,
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
            batteryPercent: null,
            batteryState: null,
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
            cpuIdlePercent: null,
            cpuIowaitPercent: null,
            cpuPercent: 33.5,
            cpuStealPercent: null,
            cpuSystemPercent: null,
            cpuUserPercent: null,
            diskTotalBytes: 30_000,
            diskUsedBytes: 24_000,
            disks: [
              {
                availableBytes: 4_000,
                filesystemType: "ext4",
                ioUtilizationPercent: null,
                mountPoint: "/",
                readAwaitMs: null,
                readBytesDelta: 0,
                totalBytes: 20_000,
                usedBytes: 16_000,
                weightedIoPercent: null,
                writeAwaitMs: null,
                writeBytesDelta: 0,
              },
              {
                availableBytes: 2_000,
                filesystemType: "xfs",
                ioUtilizationPercent: null,
                mountPoint: "/data",
                readAwaitMs: null,
                readBytesDelta: 0,
                totalBytes: 10_000,
                usedBytes: 8_000,
                weightedIoPercent: null,
                writeAwaitMs: null,
                writeBytesDelta: 0,
              },
            ],
            memoryCacheBytes: null,
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
            swapTotalBytes: null,
            swapUsedBytes: null,
            temperatureCelsius: null,
            uptimeSeconds: 3600,
          },
        ],
        window: "1h",
      },
    });

    const oneMinuteHistoryResponse = await app.request(
      `/api/web/hosts/${hostId}/metrics?window=1m`,
      {
        headers: {
          cookie: ownerSession,
        },
      },
    );

    expect(oneMinuteHistoryResponse.status).toBe(200);
    await expect(oneMinuteHistoryResponse.json()).resolves.toEqual({
      metrics: {
        samples: [expect.objectContaining({ sequence: 1 })],
        window: "1m",
      },
    });

    const invalidWindowResponse = await app.request(
      `/api/web/hosts/${hostId}/metrics?window=2h`,
      {
        headers: {
          cookie: ownerSession,
        },
      },
    );

    expect(invalidWindowResponse.status).toBe(400);

    database.close();
  });

  it("does not expose database-only Host summary fields in Owner responses", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_005_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);
    await sendReport(app, registration, {
      collectedAtMs: 1_725_000_004_500,
      cpuPercent: 33.5,
      sequence: 1,
    });

    const listResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(listResponse.status).toBe(200);
    const listBody = (await listResponse.json()) as {
      hosts: Array<Record<string, unknown> & { latestMetrics: unknown }>;
    };
    expect(listBody.hosts[0]).toBeDefined();
    expect(listBody.hosts[0]).not.toHaveProperty("probeConfigurationError");
    expect(listBody.hosts[0]?.latestMetrics).not.toHaveProperty("load1");
    expect(listBody.hosts[0]?.latestMetrics).not.toHaveProperty("load5");
    expect(listBody.hosts[0]?.latestMetrics).not.toHaveProperty("load15");

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(detailResponse.status).toBe(200);
    const detailBody = (await detailResponse.json()) as {
      host: Record<string, unknown> & { latestMetrics: unknown };
    };
    expect(detailBody.host).not.toHaveProperty("probeConfigurationError");
    expect(detailBody.host.latestMetrics).not.toHaveProperty("load1");
    expect(detailBody.host.latestMetrics).not.toHaveProperty("load5");
    expect(detailBody.host.latestMetrics).not.toHaveProperty("load15");

    database.close();
  });

  it("returns latest-known Disk Health from sparse low-frequency Probe reports", async () => {
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
      diskHealth: [
        {
          deviceName: "/dev/sda",
          model: "Samsung SSD 870 EVO 1TB",
          passed: true,
          powerOnHours: 12_345,
          serialNumber: "S6PTEST",
          temperatureCelsius: 31,
        },
      ],
      sequence: 1,
    });
    nowMs = 1_725_000_010_000;
    await sendReport(app, registration, {
      collectedAtMs: 1_725_000_009_500,
      cpuPercent: 42.5,
      sequence: 2,
    });

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(detailResponse.status).toBe(200);
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        latestMetrics: expect.objectContaining({
          cpuPercent: 42.5,
          diskHealth: [
            expect.objectContaining({
              deviceName: "/dev/sda",
              model: "Samsung SSD 870 EVO 1TB",
              passed: true,
              powerOnHours: 12_345,
              serialNumber: "S6PTEST",
              temperatureCelsius: 31,
            }),
          ],
        }),
        status: "online",
      }),
    });

    const historyResponse = await app.request(
      `/api/web/hosts/${hostId}/metrics?window=1h`,
      {
        headers: {
          cookie: ownerSession,
        },
      },
    );
    expect(historyResponse.status).toBe(200);
    const history = (await historyResponse.json()) as {
      metrics: { samples: Array<Record<string, unknown>> };
    };
    expect(history).toEqual({
      metrics: expect.objectContaining({
        samples: [
          expect.objectContaining({
            diskHealth: [
              expect.objectContaining({
                deviceName: "/dev/sda",
                passed: true,
              }),
            ],
            sequence: 1,
          }),
          expect.objectContaining({ sequence: 2 }),
        ],
      }),
    });
    expect(history.metrics.samples[1]).not.toHaveProperty("diskHealth");

    database.close();
  });

  it("persists Collector Capability with Host Profile and exposes it on Host summary and detail", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_000_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    const registeredSummaryResponse = await app.request("/api/web/hosts", {
      headers: { cookie: ownerSession },
    });
    expect(registeredSummaryResponse.status).toBe(200);
    await expect(registeredSummaryResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          collectorCapabilities: expect.objectContaining({
            official: expect.objectContaining({
              disk: { available: true },
            }),
          }),
          id: hostId,
        }),
      ],
    });

    await reportHostProfile(app, registration, {
      diskAvailable: false,
      sequence: 1,
    });

    const summaryResponse = await app.request("/api/web/hosts", {
      headers: { cookie: ownerSession },
    });
    expect(summaryResponse.status).toBe(200);
    await expect(summaryResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          collectorCapabilities: expect.objectContaining({
            official: expect.objectContaining({
              disk: { available: false },
            }),
          }),
          id: hostId,
        }),
      ],
    });

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: { cookie: ownerSession },
    });
    expect(detailResponse.status).toBe(200);
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        collectorCapabilities: expect.objectContaining({
          official: expect.objectContaining({
            disk: { available: false },
          }),
        }),
        hostProfile: expect.objectContaining({
          collectorCapabilities: expect.objectContaining({
            official: expect.objectContaining({
              disk: { available: false },
            }),
          }),
        }),
      }),
    });

    const persistedHostProfile = JSON.parse(
      database.sqlite
        .prepare("select inventory_json from managed_hosts where id = ?")
        .get(hostId)!.inventory_json as string,
    ) as {
      collectorCapabilities: {
        official: Record<string, unknown>;
      };
    };
    persistedHostProfile.collectorCapabilities.official.diskHealth = {};
    database.sqlite
      .prepare("update managed_hosts set inventory_json = ? where id = ?")
      .run(JSON.stringify(persistedHostProfile), hostId);

    const protoJsonFalseCapabilityResponse = await app.request(
      `/api/web/hosts/${hostId}`,
      {
        headers: { cookie: ownerSession },
      },
    );
    expect(protoJsonFalseCapabilityResponse.status).toBe(200);
    await expect(protoJsonFalseCapabilityResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        collectorCapabilities: expect.objectContaining({
          official: expect.objectContaining({
            disk: { available: false },
          }),
        }),
      }),
    });

    await reportHostProfile(app, registration, {
      diskAvailable: null,
      sequence: 2,
    });

    const disappearedSummaryResponse = await app.request("/api/web/hosts", {
      headers: { cookie: ownerSession },
    });
    expect(disappearedSummaryResponse.status).toBe(200);
    await expect(disappearedSummaryResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          collectorCapabilities: null,
          id: hostId,
        }),
      ],
    });

    const disappearedDetailResponse = await app.request(
      `/api/web/hosts/${hostId}`,
      {
        headers: { cookie: ownerSession },
      },
    );
    expect(disappearedDetailResponse.status).toBe(200);
    await expect(disappearedDetailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        collectorCapabilities: null,
      }),
    });

    const counts = database.sqlite
      .prepare(
        "select (select count(*) from report_observations) as observations, (select count(*) from metric_samples) as samples",
      )
      .get() as { observations: number; samples: number };
    expect(counts).toEqual({ observations: 2, samples: 0 });

    database.close();
  });

  it("uses stored Host Profile Collector Capability for Host summaries before legacy Host Profile JSON", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_000_000,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    database.snapshotCollectors.write({
      collectorId: "official.host-profile",
      hostId,
      payload: {
        architecture: "x86_64",
        collectorCapabilities: {
          official: {
            disk: { available: true },
          },
        },
        cpuCount: 2,
        filesystems: [],
        hostname: "managed-host-01",
        kernel: "6.8.0",
        memoryTotalBytes: 8_589_934_592,
        networkInterfaces: [],
        os: "linux",
        probeVersion: "0.1.0",
      },
      snapshotHash: "host-profile-summary-hash",
      updatedAtMs: 1_725_000_000_100,
    });
    database.sqlite
      .prepare("update managed_hosts set inventory_json = ? where id = ?")
      .run(
        JSON.stringify({
          collectorCapabilities: {
            official: {
              disk: { available: false },
            },
          },
        }),
        hostId,
      );

    const summaryResponse = await app.request("/api/web/hosts", {
      headers: { cookie: ownerSession },
    });

    expect(summaryResponse.status).toBe(200);
    await expect(summaryResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          collectorCapabilities: expect.objectContaining({
            official: expect.objectContaining({
              disk: { available: true },
            }),
          }),
          id: hostId,
        }),
      ],
    });

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

    const reportBody = ReportRequest.encode(
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
    ).finish();
    const reportResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", reportBody),
    );
    expect(reportResponse.status).toBe(200);

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });

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

  it("exposes Host Probe Upgrade eligibility from the Hub Probe Asset Set manifest", async () => {
    const database = await createTemporaryDatabase();
    const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-assets-"));
    tempRoots.push(assetRoot);
    const assetDir = path.join(assetRoot, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(
      path.join(assetDir, "manifest.json"),
      JSON.stringify(probeAssetManifest("v0.2.0")),
    );
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      probeAssets: {
        assetDir,
        installScriptPath: path.join(assetRoot, "install-probe.sh"),
      },
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken);
    const hostId = await firstHostId(app, ownerSession);

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(detailResponse.status).toBe(200);
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        probeUpgradeEligibility: {
          currentProbeAssetSetVersion: "0.2.0",
          currentProbeVersion: "0.1.0",
          isUpgradeable: true,
          nonUpgradeableReason: null,
        },
      }),
    });

    database.close();
  });

  it("lets the Owner create a Probe Upgrade Request and exposes status on Host detail", async () => {
    const database = await createTemporaryDatabase();
    const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-assets-"));
    tempRoots.push(assetRoot);
    const assetDir = path.join(assetRoot, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(
      path.join(assetDir, "manifest.json"),
      JSON.stringify(probeAssetManifest("v0.2.0")),
    );
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_000_000,
      probeAssets: {
        assetDir,
        installScriptPath: path.join(assetRoot, "install-probe.sh"),
      },
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken, { probeVersion: "0.1.0" });
    const hostId = await firstHostId(app, ownerSession);

    const unauthenticatedResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        method: "POST",
      },
    );
    expect(unauthenticatedResponse.status).toBe(401);

    const createResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );

    expect(createResponse.status).toBe(201);
    const createdBody = (await createResponse.json()) as {
      probeUpgradeRequest: {
        createdAtMs: number;
        failure: null;
        id: number;
        state: string;
        targetProbeVersion: string;
        updatedAtMs: number;
      };
    };
    expect(createdBody).toEqual({
      probeUpgradeRequest: {
        createdAtMs: 1_725_000_000_000,
        failure: null,
        id: expect.any(Number),
        state: "pending",
        targetProbeVersion: "0.2.0",
        updatedAtMs: 1_725_000_000_000,
      },
    });

    const duplicateResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );
    expect(duplicateResponse.status).toBe(200);
    await expect(duplicateResponse.json()).resolves.toEqual({
      probeUpgradeRequest: {
        createdAtMs: 1_725_000_000_000,
        failure: null,
        id: createdBody.probeUpgradeRequest.id,
        state: "pending",
        targetProbeVersion: "0.2.0",
        updatedAtMs: 1_725_000_000_000,
      },
    });

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(detailResponse.status).toBe(200);
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        probeUpgradeStatus: {
          createdAtMs: 1_725_000_000_000,
          failure: null,
          id: expect.any(Number),
          state: "pending",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 1_725_000_000_000,
        },
      }),
    });
    database.sqlite
      .prepare(
        "update probe_operations set state = 'failed', failure_code = ?, failure_message = ?, completed_at_ms = ?, updated_at_ms = ? where id = (select id from probe_operations where managed_host_id = ? order by id desc limit 1)",
      )
      .run(
        "unsupported_installation",
        "当前安装方式不支持 Probe 升级。",
        1_725_000_001_000,
        1_725_000_001_000,
        hostId,
      );

    const failedDetailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(failedDetailResponse.status).toBe(200);
    await expect(failedDetailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        probeUpgradeStatus: {
          createdAtMs: 1_725_000_000_000,
          failure: {
            code: "unsupported_installation",
            message: "当前安装方式不支持 Probe 升级。",
          },
          id: expect.any(Number),
          state: "failed",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 1_725_000_001_000,
        },
      }),
    });
    expect(database.audit.recent(10)).toContainEqual(
      expect.objectContaining({
        action: "probe_upgrade_request.create",
        actor: "owner",
        outcome: "success",
        subjectId: expect.any(String),
        subjectType: "probe_upgrade_request",
      }),
    );

    database.close();
  });

  it("rejects a different target while an active Probe Upgrade Request is running", async () => {
    const database = await createTemporaryDatabase();
    const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-assets-"));
    tempRoots.push(assetRoot);
    const assetDir = path.join(assetRoot, "assets");
    const manifestPath = path.join(assetDir, "manifest.json");
    await mkdir(assetDir, { recursive: true });
    await writeFile(manifestPath, JSON.stringify(probeAssetManifest("v0.2.0")));
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_000_000,
      probeAssets: {
        assetDir,
        installScriptPath: path.join(assetRoot, "install-probe.sh"),
      },
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken, { probeVersion: "0.1.0" });
    const hostId = await firstHostId(app, ownerSession);

    const createResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as {
      probeUpgradeRequest: { id: number };
    };
    database.sqlite
      .prepare(
        "update probe_operations set state = 'running', running_at_ms = ?, updated_at_ms = ? where id = ?",
      )
      .run(
        1_725_000_000_500,
        1_725_000_000_500,
        created.probeUpgradeRequest.id,
      );
    await writeFile(manifestPath, JSON.stringify(probeAssetManifest("v0.3.0")));

    const rejectedResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );

    expect(rejectedResponse.status).toBe(409);
    await expect(rejectedResponse.json()).resolves.toEqual({
      error: "probe_upgrade_request_active",
    });
    const activeRows = database.sqlite
      .prepare(
        "select id, state, target_probe_version from probe_operations where managed_host_id = ? and state in ('pending', 'accepted', 'running')",
      )
      .all(hostId);
    expect(activeRows).toEqual([
      {
        id: created.probeUpgradeRequest.id,
        state: "running",
        target_probe_version: "0.2.0",
      },
    ]);

    database.close();
  });

  it("marks an active Probe Upgrade Request succeeded when Host detail already has the target Probe version", async () => {
    const database = await createTemporaryDatabase();
    const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-assets-"));
    tempRoots.push(assetRoot);
    const assetDir = path.join(assetRoot, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(
      path.join(assetDir, "manifest.json"),
      JSON.stringify(probeAssetManifest("v0.2.0")),
    );
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_001_000,
      probeAssets: {
        assetDir,
        installScriptPath: path.join(assetRoot, "install-probe.sh"),
      },
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken, { probeVersion: "0.1.0" });
    const hostId = await firstHostId(app, ownerSession);

    const createResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );
    const created = (await createResponse.json()) as {
      probeUpgradeRequest: { id: number };
    };
    database.sqlite
      .prepare(
        "update probe_operations set state = 'running', running_at_ms = ?, updated_at_ms = ? where id = ?",
      )
      .run(
        1_725_000_000_500,
        1_725_000_000_500,
        created.probeUpgradeRequest.id,
      );
    database.sqlite
      .prepare("update managed_hosts set probe_version = ? where id = ?")
      .run("v0.2.0", hostId);
    database.snapshotCollectors.write({
      collectorId: "official.host-profile",
      hostId,
      payload: {
        architecture: "x86_64",
        cpuCount: 2,
        cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
        filesystems: [],
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
        probeVersion: "v0.2.0",
      },
      snapshotHash: "host-profile-upgraded-probe-version",
      updatedAtMs: 1_725_000_000_750,
    });

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(detailResponse.status).toBe(200);
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        probeUpgradeStatus: {
          createdAtMs: 1_725_000_001_000,
          failure: null,
          id: created.probeUpgradeRequest.id,
          state: "succeeded",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 1_725_000_001_000,
        },
      }),
    });
    expect(
      database.probeOperations.findById(created.probeUpgradeRequest.id),
    ).toEqual(
      expect.objectContaining({
        completedAtMs: 1_725_000_001_000,
        failureCode: null,
        state: "succeeded",
      }),
    );

    database.close();
  });

  it("keeps an active Probe Upgrade Request running when only the legacy Host row changes", async () => {
    const database = await createTemporaryDatabase();
    const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-assets-"));
    tempRoots.push(assetRoot);
    const assetDir = path.join(assetRoot, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(
      path.join(assetDir, "manifest.json"),
      JSON.stringify(probeAssetManifest("v0.2.0")),
    );
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_001_000,
      probeAssets: {
        assetDir,
        installScriptPath: path.join(assetRoot, "install-probe.sh"),
      },
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken, { probeVersion: "0.1.0" });
    const hostId = await firstHostId(app, ownerSession);

    const createResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );
    const created = (await createResponse.json()) as {
      probeUpgradeRequest: { id: number };
    };
    database.sqlite
      .prepare(
        "update probe_operations set state = 'running', running_at_ms = ?, updated_at_ms = ? where id = ?",
      )
      .run(
        1_725_000_000_500,
        1_725_000_000_500,
        created.probeUpgradeRequest.id,
      );
    database.sqlite
      .prepare(
        "update managed_hosts set probe_version = ?, inventory_json = ? where id = ?",
      )
      .run(
        "v0.2.0",
        JSON.stringify({
          architecture: "x86_64",
          cpuCount: 2,
          cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
          filesystems: [],
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
          probeVersion: "v0.2.0",
        }),
        hostId,
      );

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(detailResponse.status).toBe(200);
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        hostProfile: expect.objectContaining({
          probeVersion: "0.1.0",
        }),
        probeVersion: "v0.2.0",
        probeUpgradeStatus: expect.objectContaining({
          id: created.probeUpgradeRequest.id,
          state: "running",
          targetProbeVersion: "0.2.0",
        }),
      }),
    });
    expect(
      database.probeOperations.findById(created.probeUpgradeRequest.id),
    ).toEqual(
      expect.objectContaining({
        completedAtMs: null,
        state: "running",
      }),
    );

    database.close();
  });

  it("persists accepted and running Probe Upgrade Request timeouts on observable routes", async () => {
    const database = await createTemporaryDatabase();
    const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-assets-"));
    tempRoots.push(assetRoot);
    const assetDir = path.join(assetRoot, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(
      path.join(assetDir, "manifest.json"),
      JSON.stringify(probeAssetManifest("v0.2.0")),
    );
    let nowMs = 1_725_000_000_000;
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => nowMs,
      probeAssets: {
        assetDir,
        installScriptPath: path.join(assetRoot, "install-probe.sh"),
      },
      probeOperations: {
        acceptedTimeoutMs: 1_000,
        runningTimeoutMs: 2_000,
      },
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken, { probeVersion: "0.1.0" });
    const hostId = await firstHostId(app, ownerSession);

    const createResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );
    const created = (await createResponse.json()) as {
      probeUpgradeRequest: { id: number };
    };
    database.sqlite
      .prepare(
        "update probe_operations set state = 'accepted', accepted_at_ms = ?, updated_at_ms = ? where id = ?",
      )
      .run(nowMs, nowMs, created.probeUpgradeRequest.id);
    nowMs += 1_001;

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(detailResponse.status).toBe(200);
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        probeUpgradeStatus: {
          createdAtMs: 1_725_000_000_000,
          failure: {
            code: "accepted_timeout",
            message:
              "Probe accepted the upgrade request but did not start it in time.",
          },
          id: created.probeUpgradeRequest.id,
          state: "failed",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 1_725_000_001_001,
        },
      }),
    });
    expect(
      database.probeOperations.findById(created.probeUpgradeRequest.id),
    ).toEqual(
      expect.objectContaining({
        completedAtMs: 1_725_000_001_001,
        failureCode: "accepted_timeout",
        state: "failed",
      }),
    );

    const secondCreateResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );
    expect(secondCreateResponse.status).toBe(201);
    const secondCreated = (await secondCreateResponse.json()) as {
      probeUpgradeRequest: { id: number };
    };
    database.sqlite
      .prepare(
        "update probe_operations set state = 'running', running_at_ms = ?, updated_at_ms = ? where id = ?",
      )
      .run(nowMs, nowMs, secondCreated.probeUpgradeRequest.id);
    nowMs += 2_001;

    const thirdCreateResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );

    expect(thirdCreateResponse.status).toBe(201);
    expect(
      database.probeOperations.findById(secondCreated.probeUpgradeRequest.id),
    ).toEqual(
      expect.objectContaining({
        completedAtMs: 1_725_000_003_002,
        failureCode: "running_timeout",
        state: "failed",
      }),
    );
    const failureAudits = database.audit
      .recent(10)
      .filter((event) => event.action === "probe_upgrade_request.fail");
    expect(failureAudits).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor: "system",
          detailsJson: expect.stringContaining("accepted_timeout"),
          outcome: "success",
          subjectId: String(created.probeUpgradeRequest.id),
        }),
        expect.objectContaining({
          actor: "system",
          detailsJson: expect.stringContaining("running_timeout"),
          outcome: "success",
          subjectId: String(secondCreated.probeUpgradeRequest.id),
        }),
      ]),
    );

    database.close();
  });

  it("rejects Probe Upgrade Request creation for non-upgradeable Hosts with stable error codes", async () => {
    const database = await createTemporaryDatabase();
    const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-assets-"));
    tempRoots.push(assetRoot);
    const assetDir = path.join(assetRoot, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(
      path.join(assetDir, "manifest.json"),
      JSON.stringify(probeAssetManifest("v0.2.0")),
    );
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      probeAssets: {
        assetDir,
        installScriptPath: path.join(assetRoot, "install-probe.sh"),
      },
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken, { probeVersion: "0.2.0" });
    const hostId = await firstHostId(app, ownerSession);

    const response = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      error: "host_not_upgradeable",
      reason: "probe_version_current",
    });

    database.close();
  });

  it("supports backend cancel for pending Probe Upgrade Requests only", async () => {
    const database = await createTemporaryDatabase();
    const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-assets-"));
    tempRoots.push(assetRoot);
    const assetDir = path.join(assetRoot, "assets");
    await mkdir(assetDir, { recursive: true });
    await writeFile(
      path.join(assetDir, "manifest.json"),
      JSON.stringify(probeAssetManifest("v0.2.0")),
    );
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      now: () => 1_725_000_000_000,
      probeAssets: {
        assetDir,
        installScriptPath: path.join(assetRoot, "install-probe.sh"),
      },
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    await registerProbe(app, enrollmentToken, { probeVersion: "0.1.0" });
    const hostId = await firstHostId(app, ownerSession);

    const createResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );
    const created = (await createResponse.json()) as {
      probeUpgradeRequest: { id: number };
    };

    const cancelResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests/${created.probeUpgradeRequest.id}`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "DELETE",
      },
    );

    expect(cancelResponse.status).toBe(200);
    await expect(cancelResponse.json()).resolves.toEqual({
      probeUpgradeRequest: {
        createdAtMs: 1_725_000_000_000,
        failure: null,
        id: created.probeUpgradeRequest.id,
        state: "canceled",
        targetProbeVersion: "0.2.0",
        updatedAtMs: 1_725_000_000_000,
      },
    });

    const secondCreateResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "POST",
      },
    );
    const secondCreated = (await secondCreateResponse.json()) as {
      probeUpgradeRequest: { id: number };
    };
    database.sqlite
      .prepare(
        "update probe_operations set state = 'accepted', accepted_at_ms = ? where id = ?",
      )
      .run(1_725_000_000_500, secondCreated.probeUpgradeRequest.id);

    const rejectedCancelResponse = await app.request(
      `/api/web/hosts/${hostId}/probe-upgrade-requests/${secondCreated.probeUpgradeRequest.id}`,
      {
        headers: {
          cookie: ownerSession,
        },
        method: "DELETE",
      },
    );

    expect(rejectedCancelResponse.status).toBe(409);
    await expect(rejectedCancelResponse.json()).resolves.toEqual({
      error: "probe_upgrade_request_not_cancelable",
    });
    expect(database.audit.recent(10)).toContainEqual(
      expect.objectContaining({
        action: "probe_upgrade_request.cancel",
        actor: "owner",
        outcome: "success",
        subjectId: String(created.probeUpgradeRequest.id),
        subjectType: "probe_upgrade_request",
      }),
    );

    database.close();
  });

  it("exposes stable non-upgradeable reasons for missing and malformed versions", async () => {
    await expect(
      readHostProbeUpgradeEligibility({
        manifestVersion: "0.2.0",
        probeVersion: null,
      }),
    ).resolves.toEqual({
      currentProbeAssetSetVersion: "0.2.0",
      currentProbeVersion: null,
      isUpgradeable: false,
      nonUpgradeableReason: "probe_version_missing",
    });

    await expect(
      readHostProbeUpgradeEligibility({
        manifestVersion: "0.2.0",
        probeVersion: "01.2.3",
      }),
    ).resolves.toEqual({
      currentProbeAssetSetVersion: "0.2.0",
      currentProbeVersion: "01.2.3",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_version_malformed",
    });

    await expect(
      readHostProbeUpgradeEligibility({
        probeVersion: "0.1.0",
      }),
    ).resolves.toEqual({
      currentProbeAssetSetVersion: null,
      currentProbeVersion: "0.1.0",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_asset_set_version_missing",
    });

    await expect(
      readHostProbeUpgradeEligibility({
        manifestVersion: "01.2.3",
        probeVersion: "0.1.0",
      }),
    ).resolves.toEqual({
      currentProbeAssetSetVersion: null,
      currentProbeVersion: "0.1.0",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_asset_set_version_malformed",
    });
  });
});
