import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { afterEach, describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import {
  createProbeUninstallRequest,
  createProbeUpgradeRequest,
} from "../src/probe/operation";
import {
  issueProbeOperationToken,
  validateProbeOperationToken,
} from "../src/probe/operation-token";
import {
  createTestProbeIdentity,
  signedProbeHeaders,
  signedJsonProbeRequest,
  signedProbeRequest,
} from "./probe-test-auth";

const tempRoots: string[] = [];
const hostProfileCrossRuntimeCanonicalHash =
  "22843eb296c1643cd0a9b40706f3609fecbaec0ae0114a041923c9adaef07da3";

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
    body: JSON.stringify({}),
    headers: {
      "content-type": "application/json",
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

  return {
    ...registration,
    privateKeyPem: identity.privateKeyPem,
  };
}

function sampleHostProfileSnapshot(
  overrides: Partial<root.enoki.v1.IHostProfileSnapshot> = {},
): root.enoki.v1.IHostProfileSnapshot {
  return {
    architecture: "x86_64",
    cpuCount: 2,
    cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
    filesystems: [
      {
        availableBytes: 60_000,
        filesystemType: "ext4",
        mountPoint: "/",
        totalBytes: 100_000,
      },
    ],
    hostname: "managed-host-01",
    kernel: "6.8.0",
    memoryTotalBytes: 2_147_483_648,
    networkInterfaces: [
      {
        addresses: ["10.0.0.10", "2001:db8::10"],
        name: "eth0",
      },
    ],
    os: "linux",
    probeVersion: "0.1.0",
    ...overrides,
  };
}

function hostProfileCrossRuntimeCanonicalFixture(): root.enoki.v1.IHostProfileSnapshot {
  return sampleHostProfileSnapshot({
    collectorCapabilities: {
      official: {
        diskHealth: { status: 1 },
      },
    },
    cpuBaseFrequencyMhz: 2_100,
    cpuCacheL3Bytes: 36 * 1024 * 1024,
    cpuPhysicalCount: 1,
    cpuSocketCount: 1,
    filesystems: [
      {
        availableBytes: 20_000,
        filesystemType: "zfs",
        mountPoint: "/a",
        totalBytes: 70_000,
      },
      {
        availableBytes: 30_000,
        filesystemType: "ext4",
        mountPoint: "/B",
        totalBytes: 80_000,
      },
      {
        availableBytes: 40_000,
        filesystemType: "xfs",
        mountPoint: "/😀",
        totalBytes: 90_000,
      },
      {
        availableBytes: 10_000,
        filesystemType: "apfs",
        mountPoint: "/B",
        totalBytes: 60_000,
      },
    ],
    hostname: "fixture-host",
    networkInterfaces: [
      {
        addresses: ["fd00::2", "10.0.0.2", "10.0.0.2", "2001:db8::2"],
        name: "eth1",
      },
      {
        addresses: ["fe80::1"],
        name: "Éth0",
      },
      {
        addresses: ["192.0.2.10"],
        name: "Eth0",
      },
      {
        addresses: ["203.0.113.10"],
        name: "😀0",
      },
    ],
    processCount: 123,
    threadCount: 456,
  });
}

function hashStableHostProfile(
  hostProfile: root.enoki.v1.IHostProfileSnapshot,
) {
  const HostProfileSnapshot = root.enoki.v1.HostProfileSnapshot;

  return createHash("sha256")
    .update(
      HostProfileSnapshot.encode(
        HostProfileSnapshot.create(stableHostProfile(hostProfile)),
      ).finish(),
    )
    .digest("hex");
}

function stableHostProfile<T extends root.enoki.v1.IHostProfileSnapshot>(
  hostProfile: T,
): T {
  const { probeAssetBundleVersion: _bundleVersion, ...stable } = hostProfile;
  return {
    ...stable,
    filesystems: [...(hostProfile.filesystems ?? [])].sort(
      (left, right) =>
        compareProtoStrings(left.mountPoint, right.mountPoint) ||
        compareProtoStrings(left.filesystemType, right.filesystemType),
    ),
    networkInterfaces: [...(hostProfile.networkInterfaces ?? [])]
      .map((networkInterface) => ({
        ...networkInterface,
        addresses: [...new Set(networkInterface.addresses ?? [])].sort(
          compareProtoStrings,
        ),
      }))
      .sort((left, right) => compareProtoStrings(left.name, right.name)),
  } as T;
}

function compareProtoStrings(left: unknown, right: unknown) {
  return Buffer.compare(
    Buffer.from(String(left ?? ""), "utf8"),
    Buffer.from(String(right ?? ""), "utf8"),
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

  it("persists one idempotent Observation Window Failure without Metrics", async () => {
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
    const registration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-window-failure",
        observationWindowFailure: {
          reason:
            root.enoki.v1.ObservationWindowFailureReason
              .OBSERVATION_RUNTIME_UNAVAILABLE,
        },
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
      }),
    ).finish();

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await app.request(
        "/api/probe/report",
        signedProbeRequest(registration, "/api/probe/report", body),
      );
      expect(response.status).toBe(200);
    }

    expect(
      database.metrics.findObservation({
        bootId: "boot-window-failure",
        probeId: registration.probeId,
        sequence: 2,
      }),
    ).toEqual({
      cpuResourceCollectionOutcomeReason: null,
      observationWindowFailureReason: 1,
    });
    expect(
      database.sqlite
        .prepare(
          "select count(*) as count from metric_samples where boot_id = ?",
        )
        .get("boot-window-failure"),
    ).toEqual({ count: 0 });

    database.close();
  });

  it("rejects unknown Observation Window Failure reasons", async () => {
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
    const registration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-window-failure-invalid",
        observationWindowFailure: {
          reason: 99 as root.enoki.v1.ObservationWindowFailureReason,
        },
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });
    database.close();
  });

  it("persists one idempotent CPU resource acquisition outcome without Metrics", async () => {
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
    const registration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-cpu-acquisition-outcome",
        cpuResourceCollectionOutcomes: [
          {
            sequence: 2,
            reason:
              root.enoki.v1.CpuResourceCollectionOutcomeReason
                .CPU_RESOURCE_UNAVAILABLE,
          },
        ],
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
      }),
    ).finish();

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await app.request(
        "/api/probe/report",
        signedProbeRequest(registration, "/api/probe/report", body),
      );
      expect(response.status).toBe(200);
    }

    expect(
      database.metrics.findObservation({
        bootId: "boot-cpu-acquisition-outcome",
        probeId: registration.probeId,
        sequence: 2,
      }),
    ).toEqual({
      cpuResourceCollectionOutcomeReason: 1,
      observationWindowFailureReason: null,
    });
    database.close();
  });

  it("binds CPU acquisition outcomes to their exact sequence and rejects unknown reasons", async () => {
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
    const registration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const report = (reason: number) =>
      ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-cpu-sequence-outcome",
          cpuResourceCollectionOutcomes: [{ sequence: 2, reason }],
          metrics: [1, 2, 3].map((sequence) => ({
            collectedAtMs: sequence * 1_000,
            memoryUsedBytes: sequence,
            sequence,
          })),
          probeId: registration.probeId,
          sequenceEnd: 3,
          sequenceStart: 1,
        }),
      ).finish();

    for (let retry = 0; retry < 2; retry += 1) {
      const response = await app.request(
        "/api/probe/report",
        signedProbeRequest(
          registration,
          "/api/probe/report",
          report(
            root.enoki.v1.CpuResourceCollectionOutcomeReason
              .CPU_RESOURCE_UNAVAILABLE,
          ),
        ),
      );
      expect(response.status).toBe(200);
    }
    expect(
      database.sqlite
        .prepare(
          "select sequence, cpu_resource_collection_outcome_reason as reason from report_observations order by sequence",
        )
        .all(),
    ).toEqual([
      { reason: null, sequence: 1 },
      { reason: 1, sequence: 2 },
      { reason: null, sequence: 3 },
    ]);

    const unknown = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", report(99)),
    );
    expect(unknown.status).toBe(400);
    database.close();
  });

  it("persists typed collector outcomes idempotently with their exact sample", async () => {
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
    const registration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const runtimeProfile = sampleHostProfileSnapshot({
      probeAssetBundleVersion: "1.2.3",
    });
    const boot = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-collector-outcomes",
        metrics: [],
        probeAssetBundleVersion: "1.2.3",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceStart: 1,
        sequenceEnd: 1,
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", boot),
        )
      ).status,
    ).toBe(200);
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-collector-outcomes",
        metrics: [
          {
            collectedAtMs: 1_725_000_000_000,
            networkInterfaces: [{ name: "eth0", rxBytes: 10, txBytes: 20 }],
            disks: [
              {
                mountPoint: "/",
                filesystemType: "ext4",
                totalBytes: 100,
                usedBytes: 40,
                availableBytes: 50,
              },
            ],
            temperatureCelsius: 42,
            batteryPercent: 80,
            batteryState: "Discharging",
            diskHealth: [
              { deviceName: "/dev/sda", model: "Example", passed: true },
            ],
            collectorOutcomes: [
              {
                collectorId: "official.memory",
                state: 3,
                failure: { phase: 2, code: "official.memory.future-code" },
              },
              { collectorId: "official.network", state: 1 },
              { collectorId: "official.disk", state: 1 },
              { collectorId: "official.temperature", state: 1 },
              { collectorId: "official.battery", state: 1 },
              { collectorId: "official.disk-health", state: 1 },
              { collectorId: "official.host-profile", state: 1 },
            ],
            sequence: 2,
          },
        ],
        probeId: registration.probeId,
        sequenceStart: 2,
        sequenceEnd: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: runtimeProfile,
            snapshotHash: hashStableHostProfile(runtimeProfile),
          },
        ],
      }),
    ).finish();
    for (let retry = 0; retry < 2; retry += 1) {
      const response = await app.request(
        "/api/probe/report",
        signedProbeRequest(registration, "/api/probe/report", body),
      );
      expect(response.status).toBe(200);
    }
    expect(
      database.sqlite
        .prepare(
          "select collector_id, state, failure_phase, failure_code from metric_collector_outcomes order by collector_id",
        )
        .all(),
    ).toEqual([
      {
        collector_id: "official.battery",
        state: 1,
        failure_phase: null,
        failure_code: null,
      },
      {
        collector_id: "official.disk",
        state: 1,
        failure_phase: null,
        failure_code: null,
      },
      {
        collector_id: "official.disk-health",
        state: 1,
        failure_phase: null,
        failure_code: null,
      },
      {
        collector_id: "official.host-profile",
        state: 1,
        failure_phase: null,
        failure_code: null,
      },
      {
        collector_id: "official.memory",
        state: 3,
        failure_phase: 2,
        failure_code: "official.memory.future-code",
      },
      {
        collector_id: "official.network",
        state: 1,
        failure_phase: null,
        failure_code: null,
      },
      {
        collector_id: "official.temperature",
        state: 1,
        failure_phase: null,
        failure_code: null,
      },
    ]);
    expect(
      database.sqlite
        .prepare(
          "select name, rx_bytes, tx_bytes from metric_network_interfaces",
        )
        .get(),
    ).toEqual({ name: "eth0", rx_bytes: 10, tx_bytes: 20 });
    expect(
      database.sqlite
        .prepare(
          "select mount_point, total_bytes, used_bytes from metric_disks",
        )
        .get(),
    ).toEqual({ mount_point: "/", total_bytes: 100, used_bytes: 40 });
    expect(
      database.sqlite
        .prepare(
          "select temperature_celsius, battery_percent, battery_state from official_metric_thermal_power",
        )
        .get(),
    ).toEqual({
      battery_percent: 80,
      battery_state: "Discharging",
      temperature_celsius: 42,
    });
    expect(
      database.sqlite
        .prepare(
          "select device_name, model, passed from official_metric_disk_health",
        )
        .get(),
    ).toEqual({ device_name: "/dev/sda", model: "Example", passed: 1 });
    database.close();
  });

  it("bounds collector-owned failure codes while keeping unknown valid codes inert", async () => {
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
    const registration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    for (const [index, code] of [
      "x",
      "Official.memory.bad",
      "official.cpu.wrong-owner",
      `official.memory.${"x".repeat(81)}`,
    ].entries()) {
      const bootId = `boot-invalid-outcome-${index}`;
      const boot = ReportRequest.encode(
        ReportRequest.create({
          bootId,
          metrics: [],
          probeAssetBundleVersion: "1.2.3",
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceStart: 1,
          sequenceEnd: 1,
        }),
      ).finish();
      expect(
        (
          await app.request(
            "/api/probe/report",
            signedProbeRequest(registration, "/api/probe/report", boot),
          )
        ).status,
      ).toBe(200);
      const malformed = ReportRequest.encode(
        ReportRequest.create({
          bootId,
          metrics: [
            {
              collectedAtMs: 1_725_000_000_000,
              collectorOutcomes: [
                {
                  collectorId: "official.memory",
                  state: 3,
                  failure: { phase: 2, code },
                },
              ],
              sequence: 2,
            },
          ],
          probeId: registration.probeId,
          sequenceStart: 2,
          sequenceEnd: 2,
        }),
      ).finish();
      expect(
        (
          await app.request(
            "/api/probe/report",
            signedProbeRequest(registration, "/api/probe/report", malformed),
          )
        ).status,
      ).toBe(400);
    }
    database.close();
  });

  it("normalizes the frozen N-1 numeric failure slot without extending it", async () => {
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
    const registration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const boot = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-legacy-outcome",
        metrics: [],
        probeAssetBundleVersion: "1.2.3",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceStart: 1,
        sequenceEnd: 1,
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", boot),
        )
      ).status,
    ).toBe(200);
    const legacy = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-legacy-outcome",
        metrics: [
          {
            collectedAtMs: 1_725_000_000_000,
            collectorOutcomes: [
              {
                collectorId: "official.memory",
                state: 3,
                failure: { phase: 2, legacyCode: 6 },
              },
            ],
            sequence: 2,
          },
        ],
        probeId: registration.probeId,
        sequenceStart: 2,
        sequenceEnd: 2,
      }),
    ).finish();

    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", legacy),
        )
      ).status,
    ).toBe(200);
    expect(
      database.sqlite
        .prepare("select failure_code from metric_collector_outcomes")
        .get(),
    ).toEqual({
      failure_code: "official.memory.facts-malformed",
    });
    database.close();
  });

  it("rejects hash-only Host Profile Produced without satisfying readiness", async () => {
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
    const registration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const boot = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-hash-only-readiness",
        metrics: [],
        probeAssetBundleVersion: "1.2.3",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceStart: 1,
        sequenceEnd: 1,
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", boot),
        )
      ).status,
    ).toBe(200);
    const hashOnly = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-hash-only-readiness",
        metrics: [
          {
            collectedAtMs: 1_725_000_000_000,
            collectorOutcomes: [
              { collectorId: "official.host-profile", state: 1 },
            ],
            sequence: 2,
          },
        ],
        probeId: registration.probeId,
        sequenceStart: 2,
        sequenceEnd: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            snapshotHash: hashStableHostProfile(sampleHostProfileSnapshot()),
          },
        ],
      }),
    ).finish();

    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", hashOnly),
        )
      ).status,
    ).toBe(400);
    expect(
      database.sqlite.prepare("select status from enrollment_tokens").get(),
    ).toEqual({ status: "verifying" });
    database.close();
  });

  it("rejects the next authentic Probe report after Hub-only Host deletion", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      probeOperationTokenSecret: "hub-only-delete-token-secret",
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const host = database.hosts.findByProbeId(registration.probeId);
    if (!host) {
      throw new Error("registered Probe Host is missing");
    }
    const uninstall = database.probeOperations.createProbeUpgradeRequest(
      createProbeUninstallRequest({
        activeOperation: null,
        hostId: host.id,
        nowMs: Date.now(),
      }).operation,
    );
    const uninstallToken = issueProbeOperationToken({
      expiresAtMs: Date.now() + 60_000,
      operation: uninstall,
      probeId: registration.probeId,
      secret: "hub-only-delete-token-secret",
    });
    const deletion = await app.request(
      `/api/web/hosts/${host.id}?mode=hub-only`,
      {
        headers: { cookie: ownerSession },
        method: "DELETE",
      },
    );
    expect(deletion.status).toBe(200);
    expect(database.hosts.findActiveById(host.id)).toBeNull();

    const activeUninstallStatus = await app.request(
      `/api/probe/operations/${uninstall.id}/status`,
      signedJsonProbeRequest(
        registration,
        `/api/probe/operations/${uninstall.id}/status`,
        JSON.stringify({ status: "succeeded", token: uninstallToken }),
      ),
    );
    expect(activeUninstallStatus.status).toBe(401);

    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const reportBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-after-hub-only-delete",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: sampleHostProfileSnapshot(),
          },
        ],
      }),
    ).finish();
    const rejected = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", reportBody),
    );

    expect(rejected.status).toBe(401);
    await expect(rejected.json()).resolves.toEqual({
      error: "probe_identity_required",
    });
    expect(
      database.sqlite
        .prepare(
          "select deleted_at_ms as deletedAtMs from managed_hosts where id = ?",
        )
        .get(host.id),
    ).toEqual({ deletedAtMs: expect.any(Number) });

    database.close();
  });

  it("makes a legacy full sequence-one Startup Report without an Enrollment ID ready for the latest verifying Enrollment", async () => {
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
    const enrollmentResponse = await app.request("/api/web/enrollments", {
      headers: { cookie: ownerSession },
      method: "POST",
    });
    expect(enrollmentResponse.status).toBe(201);
    const enrollment = (await enrollmentResponse.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
    };
    const registration = await registerProbe(app, enrollment.enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-startup-readiness",
        metrics: [],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: sampleHostProfileSnapshot(),
          },
        ],
      }),
    ).finish();

    const report = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(report.status).toBe(200);
    const status = await app.request(
      `/api/web/enrollments/${enrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    await expect(status.json()).resolves.toEqual(
      expect.objectContaining({
        hostId: expect.any(Number),
        readyAtMs: expect.any(Number),
        status: "ready",
      }),
    );
    const metricsCount = database.sqlite
      .prepare("select count(*) as count from metric_samples")
      .get() as { count: number };
    expect(metricsCount.count).toBe(0);

    database.close();
  });

  it("rejects a sequence-one Startup Report that creates a Metrics time slice", async () => {
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
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-startup-with-metrics",
        metrics: [
          {
            collectedAtMs: 1_725_000_000_000,
            cpuPercent: 12.5,
            sequence: 1,
          },
        ],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: sampleHostProfileSnapshot(),
            snapshotHash: hashStableHostProfile(sampleHostProfileSnapshot()),
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });
    expect(
      database.sqlite
        .prepare("select count(*) as count from metric_samples")
        .get(),
    ).toEqual({ count: 0 });

    database.close();
  });

  it("rejects an unsolicited full Host Profile outside the Startup Report", async () => {
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
    const startupHostProfile = sampleHostProfileSnapshot();
    const startup = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-unsolicited-snapshot",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: startupHostProfile,
            snapshotHash: hashStableHostProfile(startupHostProfile),
          },
        ],
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", startup),
        )
      ).status,
    ).toBe(200);

    const unsolicitedHostProfile = sampleHostProfileSnapshot({
      hostname: "unsolicited-snapshot-host",
    });
    const unsolicited = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-unsolicited-snapshot",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: unsolicitedHostProfile,
            snapshotHash: hashStableHostProfile(unsolicitedHostProfile),
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", unsolicited),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });
    expect(
      database.snapshotCollectors.hostProfile.read(
        database.hosts.findByProbeId(registration.probeId)?.id ?? -1,
      )?.hostname,
    ).toBe("managed-host-01");

    database.close();
  });

  it("rejects a current full Host Profile at a new sequence without a Hub replay request", async () => {
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
    const hostProfile = sampleHostProfileSnapshot();
    const startup = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-current-unsolicited-snapshot",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile,
            snapshotHash: hashStableHostProfile(hostProfile),
          },
        ],
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", startup),
        )
      ).status,
    ).toBe(200);

    const unsolicited = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-current-unsolicited-snapshot",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile,
            snapshotHash: hashStableHostProfile(hostProfile),
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", unsolicited),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });

    database.close();
  });

  it("keeps the explicit Enrollment ID Startup Report correlation path", async () => {
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
    const enrollment = (await (
      await app.request("/api/web/enrollments", {
        headers: { cookie: ownerSession },
        method: "POST",
      })
    ).json()) as { enrollmentId: string; enrollmentToken: string };
    const registration = await registerProbe(app, enrollment.enrollmentToken);
    const body = root.enoki.v1.ProbeReportRequest.encode(
      root.enoki.v1.ProbeReportRequest.create({
        bootId: "boot-explicit-enrollment-id",
        enrollmentId: registration.enrollmentId,
        metrics: [],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: sampleHostProfileSnapshot(),
          },
        ],
      }),
    ).finish();

    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", body),
        )
      ).status,
    ).toBe(200);
    const status = await app.request(
      `/api/web/enrollments/${enrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    await expect(status.json()).resolves.toEqual(
      expect.objectContaining({ status: "ready" }),
    );

    database.close();
  });

  it("rejects a legacy Startup Report without an Enrollment ID after status-first startup timeout without report effects", async () => {
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
    const enrollmentResponse = await app.request("/api/web/enrollments", {
      headers: { cookie: ownerSession },
      method: "POST",
    });
    const enrollment = (await enrollmentResponse.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
    };
    const registration = await registerProbe(app, enrollment.enrollmentToken);
    nowMs += 60_000;
    const deadlineStatus = await app.request(
      `/api/web/enrollments/${enrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    await expect(deadlineStatus.json()).resolves.toEqual(
      expect.objectContaining({
        readyAtMs: null,
        status: "rejected",
      }),
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-startup-at-deadline",
        metrics: [],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: sampleHostProfileSnapshot(),
          },
        ],
      }),
    ).finish();

    const report = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(report.status).toBe(409);
    await expect(report.json()).resolves.toEqual({
      error: "probe_startup_timeout",
    });
    const status = await app.request(
      `/api/web/enrollments/${enrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    await expect(status.json()).resolves.toEqual(
      expect.objectContaining({
        readyAtMs: null,
        status: "rejected",
      }),
    );
    expect(
      database.sqlite
        .prepare("select last_report_at_ms from managed_hosts")
        .get(),
    ).toEqual({ last_report_at_ms: null });
    expect(
      database.sqlite
        .prepare("select count(*) as count from report_observations")
        .get(),
    ).toEqual({ count: 0 });

    database.close();
  });

  it("allows a legacy normal restart after a historical timeout when a newer Enrollment became ready", async () => {
    const database = await createTemporaryDatabase();
    const nowMs = 1_725_000_000_000;
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
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const startup = (bootId: string, enrollmentId?: string) =>
      ReportRequest.encode(
        ReportRequest.create({
          bootId,
          enrollmentId,
          metrics: [],
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 1,
          sequenceStart: 1,
          snapshots: [
            {
              collectorId: "official.host-profile",
              hostProfile: sampleHostProfileSnapshot(),
            },
          ],
        }),
      ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(
            registration,
            "/api/probe/report",
            startup("boot-current-ready", registration.enrollmentId),
          ),
        )
      ).status,
    ).toBe(200);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    database.sqlite
      .prepare(
        `insert into enrollment_tokens (
          enrollment_id, token_hash, created_at_ms, expires_at_ms, used_at_ms,
          target_kind, managed_host_id, verification_deadline_at_ms,
          rejected_at_ms, rejection_code, status
        ) values (?, ?, ?, ?, ?, 'new_host', ?, ?, ?, 'probe_startup_timeout', 'rejected')`,
      )
      .run(
        "enr_historical_timeout",
        "historical-token-hash",
        nowMs - 120_000,
        nowMs - 60_000,
        nowMs - 120_000,
        host.id,
        nowMs - 90_000,
        nowMs - 90_000,
      );

    const restart = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        startup("boot-normal-restart"),
      ),
    );

    expect(restart.status).toBe(200);
    database.close();
  });

  it("rolls back Enrollment readiness together with every report write when ingestion fails", async () => {
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
    const enrollmentResponse = await app.request("/api/web/enrollments", {
      headers: { cookie: ownerSession },
      method: "POST",
    });
    const enrollment = (await enrollmentResponse.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
    };
    const registration = await registerProbe(app, enrollment.enrollmentToken);
    database.sqlite.exec(`
      create trigger fail_startup_observation
      before insert on report_observations
      begin
        select raise(abort, 'simulated report persistence failure');
      end;
    `);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-startup-rollback",
        metrics: [],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: sampleHostProfileSnapshot(),
          },
        ],
      }),
    ).finish();

    const report = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(report.status).toBe(500);
    const status = await app.request(
      `/api/web/enrollments/${enrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    await expect(status.json()).resolves.toEqual(
      expect.objectContaining({
        readyAtMs: null,
        status: "verifying",
      }),
    );
    expect(
      database.sqlite
        .prepare("select last_report_at_ms from managed_hosts")
        .get(),
    ).toEqual({ last_report_at_ms: null });
    expect(
      database.sqlite
        .prepare("select count(*) as count from report_observations")
        .get(),
    ).toEqual({ count: 0 });

    database.close();
  });

  it("rejects a malformed operation in an otherwise valid Startup Report without consuming readiness or report effects", async () => {
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
    const enrollment = (await (
      await app.request("/api/web/enrollments", {
        headers: { cookie: ownerSession },
        method: "POST",
      })
    ).json()) as { enrollmentId: string; enrollmentToken: string };
    const registration = await registerProbe(app, enrollment.enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-startup-malformed-operation",
        enrollmentId: registration.enrollmentId,
        operationStatuses: [{ operationId: "not-an-operation", running: {} }],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: sampleHostProfileSnapshot(),
          },
        ],
      }),
    ).finish();

    const report = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(report.status).toBe(400);
    await expect(report.json()).resolves.toEqual({
      error: "malformed_probe_operation_status",
    });
    const status = await app.request(
      `/api/web/enrollments/${enrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    await expect(status.json()).resolves.toEqual(
      expect.objectContaining({ readyAtMs: null, status: "verifying" }),
    );
    expect(
      database.sqlite
        .prepare("select last_report_at_ms from managed_hosts")
        .get(),
    ).toEqual({ last_report_at_ms: null });
    expect(
      database.sqlite
        .prepare("select count(*) as count from report_observations")
        .get(),
    ).toEqual({ count: 0 });

    database.close();
  });

  it("does not broadcast Host removal or commit Probe Uninstall when later report ingestion rolls back", async () => {
    const database = await createTemporaryDatabase();
    const removedHostIds: number[] = [];
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      liveUpdates: {
        broadcastDetailSample() {},
        broadcastHostProfile() {},
        broadcastHostReady() {},
        broadcastHostRemoved(hostId: number) {
          removedHostIds.push(hostId);
        },
        broadcastHostSummary() {},
      } as never,
      now: () => 1_725_000_010_000,
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
    const send = (sequence: number, operationPayload: object) =>
      app.request(
        "/api/probe/report",
        signedProbeRequest(
          registration,
          "/api/probe/report",
          ReportRequest.encode(
            ReportRequest.create({
              bootId: "boot-uninstall-rollback",
              probeConfigurationVersion: "default-v1",
              probeId: registration.probeId,
              sequenceEnd: sequence,
              sequenceStart: sequence,
              ...operationPayload,
            }),
          ).finish(),
        ),
      );

    expect(
      (
        await send(1, {
          operationAcknowledgements: [{ operationId: String(operation.id) }],
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await send(2, {
          operationStatuses: [
            { operationId: String(operation.id), running: {} },
          ],
        })
      ).status,
    ).toBe(200);
    database.sqlite.exec(`
      create trigger fail_uninstall_report_ingestion
      before insert on report_observations
      begin
        select raise(abort, 'simulated later ingestion failure');
      end;
    `);

    const failed = await send(3, {
      operationStatuses: [{ operationId: String(operation.id), succeeded: {} }],
    });

    expect(failed.status).toBe(500);
    expect(removedHostIds).toEqual([]);
    expect(
      database.sqlite
        .prepare("select deleted_at_ms from managed_hosts where id = ?")
        .get(host.id),
    ).toEqual({ deleted_at_ms: null });
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({ state: "running" }),
    );

    database.close();
  });

  it("requests the full Host Profile snapshot when a hash-only snapshot report is unknown", async () => {
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
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const startupHostProfile = sampleHostProfileSnapshot();
    const startup = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-snapshot-hash-only",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: startupHostProfile,
            snapshotHash: hashStableHostProfile(startupHostProfile),
          },
        ],
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", startup),
        )
      ).status,
    ).toBe(200);
    const changedHostProfile = sampleHostProfileSnapshot({
      hostname: "snapshot-renamed-host",
    });
    const changedHash = hashStableHostProfile(changedHostProfile);
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-snapshot-hash-only",
        metrics: [
          {
            collectedAtMs: 1_725_000_000_000,
            cpuPercent: 12.5,
            sequence: 2,
          },
        ],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            snapshotHash: changedHash,
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(response.status).toBe(200);
    const acknowledgement = ReportResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(acknowledgement.requestedSnapshotCollectorIds).toEqual([
      "official.host-profile",
    ]);

    const metricsCount = database.sqlite
      .prepare("select count(*) as count from metric_samples")
      .get() as { count: number };
    expect(metricsCount.count).toBe(1);

    database.close();
  });

  it("stores a requested full Host Profile snapshot replay from a Probe report", async () => {
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
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const changedHostProfile = sampleHostProfileSnapshot({
      cpuCount: 4,
      cpuModel: "AMD EPYC 7B13",
      hostname: "snapshot-renamed-host",
      memoryTotalBytes: 4_294_967_296,
      probeVersion: "0.2.0",
    });
    const changedHash = hashStableHostProfile(changedHostProfile);
    const startupHostProfile = sampleHostProfileSnapshot();
    const startup = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-snapshot-full-replay",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: startupHostProfile,
            snapshotHash: hashStableHostProfile(startupHostProfile),
          },
        ],
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", startup),
        )
      ).status,
    ).toBe(200);
    const compact = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-snapshot-full-replay",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
        metrics: [
          {
            collectedAtMs: 1_725_000_000_000,
            cpuPercent: 12.5,
            sequence: 2,
          },
        ],
        snapshots: [
          {
            collectorId: "official.host-profile",
            snapshotHash: changedHash,
          },
        ],
      }),
    ).finish();
    const compactResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", compact),
    );
    expect(compactResponse.status).toBe(200);
    expect(
      ReportResponse.decode(new Uint8Array(await compactResponse.arrayBuffer()))
        .requestedSnapshotCollectorIds,
    ).toEqual(["official.host-profile"]);
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-snapshot-full-replay",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: changedHostProfile,
            snapshotHash: changedHash,
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(response.status).toBe(200);
    const acknowledgement = ReportResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(acknowledgement.requestedSnapshotCollectorIds).toEqual([]);

    const retry = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );
    expect(retry.status).toBe(200);
    expect(
      String(
        ReportResponse.decode(new Uint8Array(await retry.arrayBuffer()))
          .acceptedSequenceEnd,
      ),
    ).toBe("2");
    expect(
      database.sqlite
        .prepare(
          "select (select count(*) from report_observations) as observations, (select count(*) from metric_samples) as samples",
        )
        .get(),
    ).toEqual({ observations: 2, samples: 1 });
    expect(
      database.sqlite
        .prepare(
          "select boot_id, sequence, snapshot_hash, fulfilled_at_ms from snapshot_replay_requests",
        )
        .get(),
    ).toEqual({
      boot_id: "boot-snapshot-full-replay",
      fulfilled_at_ms: 1_725_000_000_000,
      sequence: 2,
      snapshot_hash: changedHash,
    });

    const storedHost = database.sqlite
      .prepare(
        "select h.hostname, h.probe_version, h.cpu_count, h.cpu_model, h.memory_total_bytes, hp.snapshot_hash, hp.payload_json from managed_hosts h join official_host_profiles hp on hp.managed_host_id = h.id",
      )
      .get() as {
      cpu_count: number;
      cpu_model: string;
      hostname: string;
      memory_total_bytes: number;
      payload_json: string;
      probe_version: string;
      snapshot_hash: string;
    };
    expect(storedHost).toEqual(
      expect.objectContaining({
        cpu_count: 4,
        cpu_model: "AMD EPYC 7B13",
        hostname: "snapshot-renamed-host",
        memory_total_bytes: 4_294_967_296,
        probe_version: "0.2.0",
        snapshot_hash: changedHash,
      }),
    );
    expect(JSON.parse(storedHost.payload_json)).toEqual(
      expect.objectContaining({
        cpuModel: "AMD EPYC 7B13",
        hostname: "snapshot-renamed-host",
      }),
    );

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          cpuModel: "AMD EPYC 7B13",
          probeVersion: "0.2.0",
        }),
      ],
    });

    database.close();
  });

  it("processes a Hub-requested Startup sequence Snapshot Replay without a new time slice", async () => {
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
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const startupHostProfile = sampleHostProfileSnapshot();
    const startup = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-startup-snapshot-replay",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: startupHostProfile,
            snapshotHash: hashStableHostProfile(startupHostProfile),
          },
        ],
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(registration, "/api/probe/report", startup),
        )
      ).status,
    ).toBe(200);

    const host = database.hosts.findByProbeId(registration.probeId);
    expect(host).not.toBeNull();
    const replayHostProfile = sampleHostProfileSnapshot({
      hostname: "startup-snapshot-replay-host",
    });
    const replaySnapshotHash = hashStableHostProfile(replayHostProfile);
    database.snapshotCollectors.requestSnapshotReplay({
      bootId: "boot-startup-snapshot-replay",
      collectorId: "official.host-profile",
      hostId: host?.id ?? -1,
      requestedAtMs: 1_725_000_000_000,
      sequence: 1,
      snapshotHash: replaySnapshotHash,
    });
    const replay = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-startup-snapshot-replay",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: replayHostProfile,
            snapshotHash: replaySnapshotHash,
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", replay),
    );
    expect(response.status).toBe(200);
    expect(
      String(
        ReportResponse.decode(new Uint8Array(await response.arrayBuffer()))
          .acceptedSequenceEnd,
      ),
    ).toBe("1");
    expect(
      database.sqlite
        .prepare(
          "select (select count(*) from report_observations) as observations, (select count(*) from metric_samples) as samples",
        )
        .get(),
    ).toEqual({ observations: 1, samples: 0 });
    expect(
      database.snapshotCollectors.hostProfile.read(host?.id ?? -1)?.hostname,
    ).toBe("startup-snapshot-replay-host");

    const unsolicitedNextSequence = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-startup-snapshot-replay",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: replayHostProfile,
            snapshotHash: replaySnapshotHash,
          },
        ],
      }),
    ).finish();
    const unsolicitedResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        unsolicitedNextSequence,
      ),
    );
    expect(unsolicitedResponse.status).toBe(400);

    database.close();
  });

  it("rejects an old Snapshot Replay after the Hub replaces it with a newer request", async () => {
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
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const startupHostProfile = sampleHostProfileSnapshot();
    const oldReplayHostProfile = sampleHostProfileSnapshot({
      hostname: "old-replay-host",
    });
    const newReplayHostProfile = sampleHostProfileSnapshot({
      hostname: "new-replay-host",
    });
    const oldReplayHash = hashStableHostProfile(oldReplayHostProfile);
    const newReplayHash = hashStableHostProfile(newReplayHostProfile);
    const send = (body: Uint8Array) =>
      app.request(
        "/api/probe/report",
        signedProbeRequest(registration, "/api/probe/report", body),
      );

    expect(
      (
        await send(
          ReportRequest.encode(
            ReportRequest.create({
              bootId: "boot-replay-request-replacement",
              probeConfigurationVersion: "default-v1",
              probeId: registration.probeId,
              sequenceEnd: 1,
              sequenceStart: 1,
              snapshots: [
                {
                  collectorId: "official.host-profile",
                  hostProfile: startupHostProfile,
                  snapshotHash: hashStableHostProfile(startupHostProfile),
                },
              ],
            }),
          ).finish(),
        )
      ).status,
    ).toBe(200);

    const requestCompactReplay = async (
      sequence: number,
      snapshotHash: string,
    ) => {
      const compactResponse = await send(
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-replay-request-replacement",
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: sequence,
            sequenceStart: sequence,
            snapshots: [
              {
                collectorId: "official.host-profile",
                snapshotHash,
              },
            ],
          }),
        ).finish(),
      );
      expect(compactResponse.status).toBe(200);
      expect(
        ReportResponse.decode(
          new Uint8Array(await compactResponse.arrayBuffer()),
        ).requestedSnapshotCollectorIds,
      ).toEqual(["official.host-profile"]);
    };

    await requestCompactReplay(2, oldReplayHash);

    const oldReplayBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-replay-request-replacement",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: oldReplayHostProfile,
            snapshotHash: oldReplayHash,
          },
        ],
      }),
    ).finish();
    const firstOldReplay = await send(oldReplayBody);
    expect(firstOldReplay.status).toBe(200);

    await requestCompactReplay(3, newReplayHash);
    expect(
      database.sqlite
        .prepare(
          "select boot_id, sequence, snapshot_hash, fulfilled_at_ms from snapshot_replay_requests",
        )
        .get(),
    ).toEqual({
      boot_id: "boot-replay-request-replacement",
      fulfilled_at_ms: null,
      sequence: 3,
      snapshot_hash: newReplayHash,
    });

    const historicOldReplay = await send(oldReplayBody);
    expect(historicOldReplay.status).toBe(400);

    const wrongHashReplay = await send(
      ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-replay-request-replacement",
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 3,
          sequenceStart: 3,
          snapshots: [
            {
              collectorId: "official.host-profile",
              hostProfile: oldReplayHostProfile,
              snapshotHash: oldReplayHash,
            },
          ],
        }),
      ).finish(),
    );
    expect(wrongHashReplay.status).toBe(400);

    const wrongBootReplay = await send(
      ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-replay-request-replacement-wrong",
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 3,
          sequenceStart: 3,
          snapshots: [
            {
              collectorId: "official.host-profile",
              hostProfile: newReplayHostProfile,
              snapshotHash: newReplayHash,
            },
          ],
        }),
      ).finish(),
    );
    expect(wrongBootReplay.status).toBe(400);

    const newReplay = await send(
      ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-replay-request-replacement",
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: 3,
          sequenceStart: 3,
          snapshots: [
            {
              collectorId: "official.host-profile",
              hostProfile: newReplayHostProfile,
              snapshotHash: newReplayHash,
            },
          ],
        }),
      ).finish(),
    );
    expect(newReplay.status).toBe(200);
    expect(
      String(
        ReportResponse.decode(new Uint8Array(await newReplay.arrayBuffer()))
          .acceptedSequenceEnd,
      ),
    ).toBe("3");
    expect(
      database.snapshotCollectors.hostProfile.read(
        database.hosts.findByProbeId(registration.probeId)?.id ?? -1,
      )?.hostname,
    ).toBe("new-replay-host");
    expect(
      database.sqlite
        .prepare(
          "select (select count(*) from report_observations) as observations, (select count(*) from metric_samples) as samples",
        )
        .get(),
    ).toEqual({ observations: 3, samples: 0 });

    database.close();
  });

  it("marks an active Probe Upgrade Request succeeded from a Host Profile snapshot report", async () => {
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
        nowMs: 1_725_000_010_000,
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
      acceptedAtMs: 1_725_000_015_000,
      runningAtMs: 1_725_000_020_000,
      state: "running",
    });
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const changedHostProfile = sampleHostProfileSnapshot({
      probeVersion: "v0.2.0",
    });
    const changedHash = hashStableHostProfile(changedHostProfile);
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-upgrade-host-profile",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: changedHostProfile,
            snapshotHash: changedHash,
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(response.status).toBe(200);
    expect(operation.id).toEqual(expect.any(Number));
    if (operation.id === null) {
      throw new Error("persisted Probe Upgrade Request is missing an id");
    }
    expect(database.probeOperations.findById(operation.id)).toEqual(
      expect.objectContaining({
        completedAtMs: 1_725_000_030_000,
        failureCode: null,
        state: "succeeded",
        targetProbeVersion: "0.2.0",
      }),
    );

    database.close();
  });

  it("stores a requested full Host Profile snapshot replay with the Rust canonical fixture hash", async () => {
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
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const hostProfile = hostProfileCrossRuntimeCanonicalFixture();
    expect(hashStableHostProfile(hostProfile)).toBe(
      hostProfileCrossRuntimeCanonicalHash,
    );
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-cross-runtime-host-profile",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile,
            snapshotHash: hostProfileCrossRuntimeCanonicalHash,
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(response.status).toBe(200);
    const acknowledgement = ReportResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(acknowledgement.requestedSnapshotCollectorIds).toEqual([]);

    const storedHost = database.sqlite
      .prepare("select hostname from managed_hosts")
      .get() as { hostname: string };
    expect(storedHost).toEqual({
      hostname: "fixture-host",
    });
    const storedHostProfile = database.sqlite
      .prepare("select snapshot_hash from official_host_profiles")
      .get() as { snapshot_hash: string };
    expect(storedHostProfile.snapshot_hash).toBe(
      hostProfileCrossRuntimeCanonicalHash,
    );

    database.close();
  });

  it("rejects full Host Profile snapshot reports when the supplied snapshot hash is not canonical", async () => {
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
    const hostProfile = sampleHostProfileSnapshot({
      hostname: "bad-snapshot-hash-host",
    });
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-bad-host-profile-hash",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile,
            snapshotHash: "not-the-canonical-host-profile-hash",
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

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

  it("rejects a snapshot payload when the collector id does not own the oneof branch", async () => {
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
    const hostProfile = sampleHostProfileSnapshot({
      hostname: "wrong-collector-branch-host",
    });
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-wrong-snapshot-branch",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.disk",
            hostProfile,
            snapshotHash: hashStableHostProfile(hostProfile),
          },
        ],
      }),
    ).finish();

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });

    const storedHostProfile = database.sqlite
      .prepare("select hostname from official_host_profiles")
      .get() as { hostname: string };
    expect(storedHostProfile.hostname).toBe("managed-host-01");

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
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    async function report(sequence: number) {
      const body = ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-01",
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: sequence,
          sequenceStart: sequence,
        }),
      ).finish();
      const response = await app.request(
        "/api/probe/report",
        signedProbeRequest(registration, "/api/probe/report", body),
      );

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
          hostId: String(host.id),
          operationToken: expect.any(String),
          targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
          targetManifestSha256: "",
          targetProbeVersion: "0.2.0",
        }),
      );
      expect(response.pendingOperation?.probeUpgrade?.operationToken).not.toBe(
        "",
      );
    }
  });

  it("keeps legacy Probe Upgrade Requests without an Asset Set target closed to report progress", async () => {
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
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
      targetAssetSetDigest: null,
    });
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const report = (payload: object) =>
      app.request(
        "/api/probe/report",
        signedProbeRequest(
          registration,
          "/api/probe/report",
          ReportRequest.encode(
            ReportRequest.create({
              bootId: "boot-legacy-upgrade-target",
              probeConfigurationVersion: "default-v1",
              probeId: registration.probeId,
              sequenceEnd: 1,
              sequenceStart: 1,
              ...payload,
            }),
          ).finish(),
        ),
      );

    const acknowledgement = await report({
      operationAcknowledgements: [{ operationId: String(operation.id) }],
    });
    expect(acknowledgement.status).toBe(400);
    await expect(acknowledgement.json()).resolves.toEqual({
      error: "malformed_probe_operation_acknowledgement",
    });

    const status = await report({
      operationStatuses: [{ operationId: String(operation.id), running: {} }],
    });
    expect(status.status).toBe(400);
    await expect(status.json()).resolves.toEqual({
      error: "malformed_probe_operation_status",
    });

    const hostProfile = sampleHostProfileSnapshot({ probeVersion: "0.2.0" });
    const observation = await report({
      snapshots: [
        {
          collectorId: "official.host-profile",
          hostProfile,
          snapshotHash: hashStableHostProfile(hostProfile),
        },
      ],
    });
    expect(observation.status).toBe(200);
    expect(
      ReportResponse.decode(new Uint8Array(await observation.arrayBuffer()))
        .pendingOperation,
    ).toBeNull();
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({ state: "pending" }),
    );

    database.close();
  });

  it("authenticates signed Probe report requests and rejects nonce replay", async () => {
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
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
      }),
    ).finish();
    const headers = signedProbeHeaders({
      body,
      method: "POST",
      nonce: "0123456789abcdef0123456789abcdef",
      pathAndQuery: "/api/probe/report",
      privateKeyPem: registration.privateKeyPem,
      probeId: registration.probeId,
      timestampMs: String(Date.now()),
    });

    const response = await app.request("/api/probe/report", {
      body,
      headers,
      method: "POST",
    });
    expect(response.status).toBe(200);
    expect(
      String(
        ReportResponse.decode(new Uint8Array(await response.arrayBuffer()))
          .acceptedSequenceEnd,
      ),
    ).toBe("1");

    const replay = await app.request("/api/probe/report", {
      body,
      headers,
      method: "POST",
    });
    expect(replay.status).toBe(401);

    const replayAfterAppRestart = await createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    }).request("/api/probe/report", {
      body,
      headers,
      method: "POST",
    });
    expect(replayAfterAppRestart.status).toBe(401);

    const downgraded = await app.request("/api/probe/report", {
      body,
      headers: {
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });
    expect(downgraded.status).toBe(401);
  });

  it("binds signed Probe report requests to the configured Probe API Origin", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      probeApiOrigin: "https://probe.example",
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-origin-01",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
      }),
    ).finish();

    const wrongOriginResponse = await app.request(
      "http://hub.example/api/probe/report",
      {
        body,
        headers: signedProbeHeaders({
          body,
          nonce: "11111111111111111111111111111111",
          pathAndQuery: "http://hub.example/api/probe/report",
          privateKeyPem: registration.privateKeyPem,
          probeId: registration.probeId,
          timestampMs: String(Date.now()),
        }),
        method: "POST",
      },
    );
    expect(wrongOriginResponse.status).toBe(401);

    const matchingOriginResponse = await app.request(
      "http://hub.example/api/probe/report",
      {
        body,
        headers: signedProbeHeaders({
          body,
          nonce: "22222222222222222222222222222222",
          pathAndQuery: "https://probe.example/api/probe/report",
          privateKeyPem: registration.privateKeyPem,
          probeId: registration.probeId,
          timestampMs: String(Date.now()),
        }),
        method: "POST",
      },
    );
    expect(matchingOriginResponse.status).toBe(200);
  });

  it("ignores forwarded host and protocol for the Probe report signature origin", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      probeApiOrigin: "https://probe.example",
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-forwarded-origin-01",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
      }),
    ).finish();

    const response = await app.request(
      "http://internal.example/api/probe/report",
      {
        body,
        headers: {
          ...signedProbeHeaders({
            body,
            nonce: "33333333333333333333333333333333",
            pathAndQuery: "https://probe.example/api/probe/report",
            privateKeyPem: registration.privateKeyPem,
            probeId: registration.probeId,
            timestampMs: String(Date.now()),
          }),
          "x-forwarded-host": "public.example",
          "x-forwarded-proto": "https",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(200);
  });

  it("rejects a Probe signature bound to forwarded host and protocol", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      probeApiOrigin: "https://probe.example",
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);
    const registration = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-forwarded-origin-02",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
      }),
    ).finish();

    const response = await app.request(
      "http://internal.example/api/probe/report",
      {
        body,
        headers: {
          ...signedProbeHeaders({
            body,
            nonce: "44444444444444444444444444444444",
            pathAndQuery: "https://public.example/api/probe/report",
            privateKeyPem: registration.privateKeyPem,
            probeId: registration.probeId,
            timestampMs: String(Date.now()),
          }),
          "x-forwarded-host": "public.example",
          "x-forwarded-proto": "https",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(401);
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
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    const delivery = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 1,
            sequenceStart: 1,
          }),
        ).finish(),
      ),
    );
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
        targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
        targetProbeVersion: "0.2.0",
        token: token ?? "",
      }),
    ).toEqual({ error: null });

    const accepted = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      signedJsonProbeRequest(
        registration,
        `/api/probe/operations/${operation.id}/token/validate`,
        JSON.stringify({
          targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
          targetProbeVersion: "0.2.0",
          token,
        }),
      ),
    );
    expect(accepted.status).toBe(200);
    await expect(accepted.json()).resolves.toEqual({ valid: true });

    const legacyBearer = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      {
        body: JSON.stringify({
          targetProbeVersion: "0.2.0",
          token,
        }),
        headers: {
          authorization: "Bearer enk_probe_legacy",
          "content-type": "application/json",
        },
        method: "POST",
      },
    );
    expect(legacyBearer.status).toBe(401);
    await expect(legacyBearer.json()).resolves.toEqual({
      error: "probe_identity_required",
    });

    const unsigned = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      {
        body: JSON.stringify({
          targetProbeVersion: "0.2.0",
          token,
        }),
        headers: {
          "content-type": "application/json",
        },
        method: "POST",
      },
    );
    expect(unsigned.status).toBe(401);
    await expect(unsigned.json()).resolves.toEqual({
      error: "probe_identity_required",
    });

    const wrongProbe = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      signedJsonProbeRequest(
        otherRegistration,
        `/api/probe/operations/${operation.id}/token/validate`,
        JSON.stringify({
          targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
          targetProbeVersion: "0.2.0",
          token,
        }),
      ),
    );
    expect(wrongProbe.status).toBe(403);
    await expect(wrongProbe.json()).resolves.toEqual({
      error: "probe_operation_token_probe_mismatch",
    });

    const wrongTarget = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      signedJsonProbeRequest(
        registration,
        `/api/probe/operations/${operation.id}/token/validate`,
        JSON.stringify({
          targetProbeVersion: "0.3.0",
          token,
        }),
      ),
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
      signedJsonProbeRequest(
        registration,
        `/api/probe/operations/${operation.id}/token/validate`,
        JSON.stringify({
          targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
          targetProbeVersion: "0.2.0",
          token,
        }),
      ),
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
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    const acknowledged = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
            operationAcknowledgements: [{ operationId: String(operation.id) }],
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 1,
            sequenceStart: 1,
          }),
        ).finish(),
      ),
    );

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

    const running = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );

    expect(running.status).toBe(200);
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        runningAtMs: 1_725_000_010_000,
        state: "running",
      }),
    );

    for (const sequence of [3, 3]) {
      const failed = await app.request(
        "/api/probe/report",
        signedProbeRequest(
          registration,
          "/api/probe/report",
          ReportRequest.encode(
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
        ),
      );

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

  it("preserves accepted and running transition evidence when one Probe report acknowledges and starts an operation", async () => {
    const database = await createTemporaryDatabase();
    const nowMs = 1_725_000_010_000;
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
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const operation = database.probeOperations.createProbeUpgradeRequest(
      createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: host.id,
        nowMs: nowMs - 1_000,
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const report = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
            operationAcknowledgements: [{ operationId: String(operation.id) }],
            operationStatuses: [
              { operationId: String(operation.id), running: {} },
            ],
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 1,
            sequenceStart: 1,
          }),
        ).finish(),
      ),
    );

    expect(report.status).toBe(200);
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        acceptedAtMs: nowMs,
        runningAtMs: nowMs,
        state: "running",
        updatedAtMs: nowMs,
      }),
    );

    const ownerOperation = await app.request(
      `/api/web/probe-operations/${operation.id}`,
      { headers: { cookie: ownerSession } },
    );

    expect(ownerOperation.status).toBe(200);
    await expect(ownerOperation.json()).resolves.toEqual({
      probeOperation: expect.objectContaining({
        acceptedAtMs: nowMs,
        completedAtMs: null,
        hostId: host.id,
        id: operation.id,
        kind: "probe_upgrade",
        runningAtMs: nowMs,
        state: "running",
        targetProbeVersion: "0.2.0",
      }),
    });

    database.close();
  });

  it("marks a Probe Upgrade Request succeeded from a Host Profile snapshot", async () => {
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
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const startupHostProfile = sampleHostProfileSnapshot();
    const upgradedHostProfile = sampleHostProfileSnapshot({
      probeVersion: "0.2.0",
    });
    const upgradedHostProfileHash = hashStableHostProfile(upgradedHostProfile);

    const running = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
            snapshots: [
              {
                collectorId: "official.host-profile",
                hostProfile: startupHostProfile,
                snapshotHash: hashStableHostProfile(startupHostProfile),
              },
            ],
          }),
        ).finish(),
      ),
    );
    expect(running.status).toBe(200);
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        state: "running",
      }),
    );

    const compactObservation = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-after-upgrade",
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 2,
            sequenceStart: 2,
            snapshots: [
              {
                collectorId: "official.host-profile",
                snapshotHash: upgradedHostProfileHash,
              },
            ],
          }),
        ).finish(),
      ),
    );
    expect(compactObservation.status).toBe(200);

    const targetHostProfile = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-after-upgrade",
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 2,
            sequenceStart: 2,
            snapshots: [
              {
                collectorId: "official.host-profile",
                hostProfile: upgradedHostProfile,
                snapshotHash: upgradedHostProfileHash,
              },
            ],
          }),
        ).finish(),
      ),
    );
    expect(targetHostProfile.status).toBe(200);
    expect(database.probeOperations.findById(operation.id ?? 0)).toEqual(
      expect.objectContaining({
        completedAtMs: 1_725_000_010_000,
        state: "succeeded",
      }),
    );

    database.close();
  });

  it("advances Host Profile freshness from validated same-hash full and compact reports", async () => {
    const database = await createTemporaryDatabase();
    let nowMs = 1_725_000_001_000;
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
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const hostProfile = {
      architecture: "x86_64",
      cpuCount: 2,
      hostname: "managed-host-01",
      kernel: "6.8.0",
      memoryTotalBytes: 2_147_483_648,
      os: "linux",
      probeVersion: "0.1.0",
    } satisfies root.enoki.v1.IHostProfileSnapshot;
    const snapshotHash = hashStableHostProfile(hostProfile);
    const send = (sequence: number, snapshot: root.enoki.v1.ISnapshot) => {
      const body = ReportRequest.encode(
        ReportRequest.create({
          bootId: "boot-same-hash-observation",
          probeConfigurationVersion: "default-v1",
          probeId: registration.probeId,
          sequenceEnd: sequence,
          sequenceStart: sequence,
          snapshots: [snapshot],
        }),
      ).finish();

      return app.request(
        "/api/probe/report",
        signedProbeRequest(registration, "/api/probe/report", body),
      );
    };

    nowMs = 1_725_000_001_100;
    const full = await send(1, {
      collectorId: "official.host-profile",
      hostProfile,
      snapshotHash,
    });
    expect(full.status).toBe(200);
    expect(
      database.snapshotCollectors.hostProfile.readObservation(host.id)
        ?.observedAtMs,
    ).toBe(nowMs);

    nowMs = 1_725_000_001_200;
    const compact = await send(2, {
      collectorId: "official.host-profile",
      snapshotHash,
    });
    expect(compact.status).toBe(200);
    expect(
      ReportResponse.decode(new Uint8Array(await compact.arrayBuffer()))
        .requestedSnapshotCollectorIds,
    ).toEqual([]);
    expect(
      database.snapshotCollectors.hostProfile.readObservation(host.id)
        ?.observedAtMs,
    ).toBe(nowMs);

    const failed = database.probeOperations.createProbeUpgradeRequest({
      acceptedAtMs: 1_725_000_001_210,
      canceledAtMs: null,
      completedAtMs: 1_725_000_001_250,
      createdAtMs: 1_725_000_001_200,
      currentProbeVersion: "0.0.9",
      failureCode: "post_replacement_restart_failure",
      failureMessage: "local restart failed",
      hostId: host.id,
      id: null,
      kind: "probe_upgrade",
      runningAtMs: 1_725_000_001_220,
      state: "failed",
      supersededAtMs: null,
      targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
      targetProbeVersion: "0.1.0",
      updatedAtMs: 1_725_000_001_250,
    });

    nowMs = 1_725_000_001_300;
    const duplicateCompact = await send(2, {
      collectorId: "official.host-profile",
      snapshotHash,
    });
    expect(duplicateCompact.status).toBe(200);
    expect(
      database.snapshotCollectors.hostProfile.readObservation(host.id)
        ?.observedAtMs,
    ).toBe(1_725_000_001_200);
    const duplicateDetail = await app.request(`/api/web/hosts/${host.id}`, {
      headers: { cookie: ownerSession },
    });
    await expect(duplicateDetail.json()).resolves.toEqual({
      host: expect.objectContaining({
        probeUpgradeStatus: expect.objectContaining({
          id: failed.id,
          state: "failed",
        }),
      }),
    });

    nowMs = 1_725_000_001_350;
    const wrongHash = await send(3, {
      collectorId: "official.host-profile",
      snapshotHash: "unknown-host-profile-hash",
    });
    expect(wrongHash.status).toBe(200);
    expect(
      ReportResponse.decode(new Uint8Array(await wrongHash.arrayBuffer()))
        .requestedSnapshotCollectorIds,
    ).toEqual(["official.host-profile"]);
    expect(
      database.snapshotCollectors.hostProfile.readObservation(host.id)
        ?.observedAtMs,
    ).toBe(1_725_000_001_200);

    nowMs = 1_725_000_001_400;
    const newCompact = await send(4, {
      collectorId: "official.host-profile",
      snapshotHash,
    });
    expect(newCompact.status).toBe(200);
    const recoveredDetail = await app.request(`/api/web/hosts/${host.id}`, {
      headers: { cookie: ownerSession },
    });
    await expect(recoveredDetail.json()).resolves.toEqual({
      host: expect.objectContaining({ probeUpgradeStatus: null }),
    });
    expect(database.probeOperations.findById(failed.id ?? 0)).toEqual(
      expect.objectContaining({ state: "failed" }),
    );

    database.close();
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

    const badAck = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
            operationAcknowledgements: [{ operationId: "operation-missing" }],
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 1,
            sequenceStart: 1,
          }),
        ).finish(),
      ),
    );
    expect(badAck.status).toBe(400);
    await expect(badAck.json()).resolves.toEqual({
      error: "malformed_probe_operation_acknowledgement",
    });

    const badStatus = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
            operationStatuses: [{ operationId: "" }],
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 2,
            sequenceStart: 2,
          }),
        ).finish(),
      ),
    );
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
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
    );
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );

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
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
      acceptedAtMs: 1_725_000_009_500,
      state: "accepted",
      updatedAtMs: 1_725_000_009_500,
    });
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );

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
        target: {
          assetSetDigest: `sha256:${"a".repeat(64)}`,
          version: "0.2.0",
        },
      }).operation,
      state: "superseded",
      supersededAtMs: 1_725_000_009_500,
      updatedAtMs: 1_725_000_009_500,
    });
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );

    expect(response.status).toBe(200);
    expect(database.probeOperations.findById(staleOperation.id ?? 0)).toEqual(
      expect.objectContaining({
        failureCode: null,
        state: "superseded",
      }),
    );
  });

  it("stores official Metrics as sample envelope and domain rows while exposing current Host Status summaries", async () => {
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

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
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
                diskHealth: [
                  {
                    deviceName: "/dev/sda",
                    model: "Example SSD",
                    passed: true,
                    temperatureCelsius: 31,
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
      ),
    );

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
        received_at_ms: 1_725_000_010_000,
        sequence: 1,
      }),
    );
    expect(storedSample).toEqual(
      expect.objectContaining({
        cpu_percent: null,
        disk_total_bytes: null,
        disk_used_bytes: null,
        load_1: null,
        load_5: null,
        load_15: null,
        memory_total_bytes: null,
        memory_used_bytes: null,
        network_rx_bytes_delta: null,
        network_tx_bytes_delta: null,
        uptime_seconds: null,
      }),
    );

    expect(
      database.sqlite
        .prepare(
          "select cpu_percent, cpu_user_percent, cpu_system_percent from official_metric_cpu where metric_sample_id = ?",
        )
        .get(storedSample.id),
    ).toEqual({
      cpu_percent: 42.5,
      cpu_system_percent: null,
      cpu_user_percent: null,
    });
    expect(
      database.sqlite
        .prepare(
          "select memory_used_bytes, memory_total_bytes from official_metric_memory where metric_sample_id = ?",
        )
        .get(storedSample.id),
    ).toEqual({
      memory_total_bytes: 2_147_483_648,
      memory_used_bytes: 1_073_741_824,
    });
    expect(
      database.sqlite
        .prepare(
          "select load_1, load_5, load_15 from official_metric_load where metric_sample_id = ?",
        )
        .get(storedSample.id),
    ).toEqual({
      load_1: 0.12,
      load_5: 0.34,
      load_15: 0.56,
    });
    expect(
      database.sqlite
        .prepare(
          "select uptime_seconds from official_metric_uptime where metric_sample_id = ?",
        )
        .get(storedSample.id),
    ).toEqual({
      uptime_seconds: 86_400,
    });
    expect(
      database.sqlite
        .prepare(
          "select disk_used_bytes, disk_total_bytes from official_metric_disk_summary where metric_sample_id = ?",
        )
        .get(storedSample.id),
    ).toEqual({
      disk_total_bytes: 2_048,
      disk_used_bytes: 1_536,
    });
    expect(
      database.sqlite
        .prepare(
          "select network_rx_bytes_delta, network_tx_bytes_delta from official_metric_network_summary where metric_sample_id = ?",
        )
        .get(storedSample.id),
    ).toEqual({
      network_rx_bytes_delta: 4_000,
      network_tx_bytes_delta: 2_000,
    });
    expect(
      database.sqlite
        .prepare(
          "select device_name, model, passed, temperature_celsius from official_metric_disk_health where metric_sample_id = ?",
        )
        .get(storedSample.id),
    ).toEqual({
      device_name: "/dev/sda",
      model: "Example SSD",
      passed: 1,
      temperature_celsius: 31,
    });

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

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );

    expect(response.status).toBe(200);

    expect(
      database.sqlite
        .prepare(
          "select probe_configuration_version from managed_hosts where probe_id = ?",
        )
        .get(registration.probeId),
    ).toEqual({ probe_configuration_version: "memory-only-v1" });

    const storedSample = database.sqlite
      .prepare(
        "select id, cpu_percent, memory_used_bytes, memory_total_bytes, load_1, load_5, load_15, uptime_seconds, disk_used_bytes, disk_total_bytes, network_rx_bytes_delta, network_tx_bytes_delta from metric_samples",
      )
      .get() as {
      id: number;
      [key: string]: number | null;
    };
    expect(storedSample).toEqual({
      cpu_percent: null,
      disk_total_bytes: null,
      disk_used_bytes: null,
      id: storedSample.id,
      load_1: null,
      load_5: null,
      load_15: null,
      memory_total_bytes: null,
      memory_used_bytes: null,
      network_rx_bytes_delta: null,
      network_tx_bytes_delta: null,
      uptime_seconds: null,
    });
    expect(
      database.sqlite
        .prepare(
          "select memory_used_bytes, memory_total_bytes from official_metric_memory where metric_sample_id = ?",
        )
        .get(storedSample.id),
    ).toEqual({
      memory_total_bytes: 2_147_483_648,
      memory_used_bytes: 1_073_741_824,
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
      app.request(
        "/api/probe/report",
        signedProbeRequest(registration, "/api/probe/report", reportBody),
      );

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

  it("retries a Metrics report after a domain storage failure without losing the sample", async () => {
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
    const reportBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-retry-domain-failure",
        metrics: [
          {
            collectedAtMs: 1_725_000_009_500,
            memoryTotalBytes: 2_147_483_648,
            memoryUsedBytes: 1_073_741_824,
            sequence: 9,
          },
        ],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 9,
        sequenceStart: 9,
      }),
    ).finish();

    const sendReport = () =>
      app.request(
        "/api/probe/report",
        signedProbeRequest(registration, "/api/probe/report", reportBody),
      );

    database.sqlite.exec(`
      create trigger fail_official_metric_memory_insert
      before insert on official_metric_memory
      begin
        select raise(abort, 'injected official metric memory failure');
      end
    `);

    const failedResponse = await sendReport();
    expect(failedResponse.status).toBe(500);

    database.sqlite.exec("drop trigger fail_official_metric_memory_insert");

    const retryResponse = await sendReport();
    expect(retryResponse.status).toBe(200);

    const counts = database.sqlite
      .prepare(
        "select (select count(*) from report_observations) as observations, (select count(*) from metric_samples) as samples, (select count(*) from official_metric_memory) as memory",
      )
      .get() as { memory: number; observations: number; samples: number };
    expect(counts).toEqual({
      memory: 1,
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
            memoryTotalBytes: 2_147_483_648,
            memoryUsedBytes: 1_073_741_824,
          }),
        }),
      ],
    });

    database.close();
  });

  it("does not add Metrics to an already accepted empty observation", async () => {
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
    const emptyBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-empty-then-sample",
        metrics: [],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 3,
        sequenceStart: 3,
      }),
    ).finish();
    const changedBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-empty-then-sample",
        metrics: [
          {
            collectedAtMs: 1_725_000_009_500,
            cpuPercent: 42.5,
            sequence: 3,
          },
        ],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 3,
        sequenceStart: 3,
      }),
    ).finish();

    const emptyResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", emptyBody),
    );
    const changedDuplicateResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", changedBody),
    );

    expect(emptyResponse.status).toBe(200);
    expect(changedDuplicateResponse.status).toBe(200);
    expect(
      database.sqlite
        .prepare(
          "select (select count(*) from report_observations) as observations, (select count(*) from metric_samples) as samples",
        )
        .get(),
    ).toEqual({
      observations: 1,
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
          latestMetrics: null,
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

    const reportBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-empty",
        metrics: [],
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
      }),
    ).finish();
    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", reportBody),
    );

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

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );

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

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );

    expect(response.status).toBe(200);

    expect(database.hosts.listSummaries()).toEqual([
      expect.objectContaining({
        probeConfigurationError: {
          errorCode: "probe_configuration_fetch_failed",
          failedVersion: "global-1725000700000-1",
          message: "report request failed: 503 Service Unavailable",
          reportedAtMs: 1_725_000_700_000,
        },
      }),
    ]);

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(hostsResponse.status).toBe(200);
    const hostsBody = (await hostsResponse.json()) as {
      hosts: Array<Record<string, unknown>>;
    };
    expect(hostsBody.hosts[0]).not.toHaveProperty("probeConfigurationError");

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

    const errorResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );
    expect(errorResponse.status).toBe(200);

    const cleanResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-config-error-cleared",
            metrics: [],
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 2,
            sequenceStart: 2,
          }),
        ).finish(),
      ),
    );
    expect(cleanResponse.status).toBe(200);

    expect(database.hosts.listSummaries()).toEqual([
      expect.objectContaining({
        probeConfigurationError: null,
      }),
    ]);

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

    const malformedBody = new Uint8Array([0xff, 0xff, 0xff]);
    const malformed = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", malformedBody),
    );
    expect(malformed.status).toBe(400);
    expect(malformed.headers.get("cache-control")).toBe("no-store");
    await expect(malformed.json()).resolves.toEqual({
      error: "malformed_probe_report",
    });

    const compressed = await app.request("/api/probe/report", {
      body: validBody,
      headers: {
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
    await registerProbe(app, enrollmentToken);
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

    const body = ReportRequest.encode(
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
    ).finish();
    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", body),
    );

    expect(response.status).toBe(200);
    expect(
      database.sqlite.prepare("select count(*) as count from audit_log").get(),
    ).toEqual(auditCountBeforeReport);

    database.close();
  });

  it("rejects full Host Profile reports when the supplied Host Profile hash is not canonical", async () => {
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

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-bad-host-profile-hash",
            metrics: [],
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 1,
            sequenceStart: 1,
            snapshots: [
              {
                collectorId: "official.host-profile",
                hostProfile: {
                  architecture: "x86_64",
                  cpuCount: 4,
                  hostname: "managed-host-renamed",
                  kernel: "6.8.0",
                  memoryTotalBytes: 4_294_967_296,
                  os: "linux",
                  probeVersion: "0.1.0",
                },
                snapshotHash: "not-the-canonical-host-profile-hash",
              },
            ],
          }),
        ).finish(),
      ),
    );

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

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );

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

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 1,
            sequenceStart: 1,
          }),
        ).finish(),
      ),
    );

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
    const removedHostIds: number[] = [];
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      liveUpdates: {
        broadcastDetailSample() {},
        broadcastHostProfile() {},
        broadcastHostReady() {},
        broadcastHostRemoved(hostId: number) {
          removedHostIds.push(hostId);
        },
        broadcastHostSummary() {},
      } as never,
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

    const delivery = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
          ReportRequest.create({
            bootId: "boot-01",
            probeConfigurationVersion: "default-v1",
            probeId: registration.probeId,
            sequenceEnd: 1,
            sequenceStart: 1,
          }),
        ).finish(),
      ),
    );
    const token = ReportResponse.decode(
      new Uint8Array(await delivery.arrayBuffer()),
    ).pendingOperation?.probeUninstall?.operationToken;

    const validated = await app.request(
      `/api/probe/operations/${operation.id}/token/validate`,
      signedJsonProbeRequest(
        registration,
        `/api/probe/operations/${operation.id}/token/validate`,
        JSON.stringify({ token }),
      ),
    );
    expect(validated.status).toBe(200);
    expect(database.probeOperations.findById(operation.id ?? 0)).toMatchObject({
      acceptedAtMs: 1_725_000_010_000,
      runningAtMs: 1_725_000_010_000,
      state: "running",
    });
    expect(removedHostIds).toEqual([]);

    const legacyBearerStatus = await app.request(
      `/api/probe/operations/${operation.id}/status`,
      {
        body: JSON.stringify({
          status: "succeeded",
          token,
        }),
        headers: {
          authorization: "Bearer enk_probe_legacy",
          "content-type": "application/json",
        },
        method: "POST",
      },
    );
    expect(legacyBearerStatus.status).toBe(401);
    await expect(legacyBearerStatus.json()).resolves.toEqual({
      error: "probe_identity_required",
    });

    const status = await app.request(
      `/api/probe/operations/${operation.id}/status`,
      signedJsonProbeRequest(
        registration,
        `/api/probe/operations/${operation.id}/status`,
        JSON.stringify({
          status: "succeeded",
          token,
        }),
      ),
    );
    expect(status.status).toBe(200);
    expect(removedHostIds).toEqual([host.id]);

    const repeatedStatus = await app.request(
      `/api/probe/operations/${operation.id}/status`,
      signedJsonProbeRequest(
        registration,
        `/api/probe/operations/${operation.id}/status`,
        JSON.stringify({
          status: "succeeded",
          token,
        }),
      ),
    );
    expect(repeatedStatus.status).toBe(200);
    expect(removedHostIds).toEqual([host.id]);

    const failedReplay = await app.request(
      `/api/probe/operations/${operation.id}/status`,
      signedJsonProbeRequest(
        registration,
        `/api/probe/operations/${operation.id}/status`,
        JSON.stringify({
          errorCode: "probe_uninstall_failed",
          message: "",
          status: "failed",
          token,
        }),
      ),
    );
    expect(failedReplay.status).toBe(401);

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

    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        registration,
        "/api/probe/report",
        ReportRequest.encode(
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
      ),
    );

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
