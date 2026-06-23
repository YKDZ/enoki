import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";

import { serve } from "@hono/node-server";
import { afterEach, describe, expect, it } from "vitest";

import * as root from "../../../packages/proto/src/generated/ts/enoki_pb.js";
import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import { hashSecret } from "../src/enrollment/routes";
import { createTestProbeIdentity, signedProbeRequest } from "./probe-test-auth";

const tempRoots: string[] = [];
const Inventory = root.enoki.v1.Inventory;
const testProbePrivateKeys = new WeakMap<Response, string>();

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-probe-db-"));
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
  hostname = "managed-host-01",
  headers: Record<string, string> = {},
  options: { publicKey?: boolean; publicKeyPem?: string } = {},
) {
  const identity = createTestProbeIdentity();
  const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
  const probePublicKeyPem = options.publicKeyPem ?? identity.publicKeyPem;

  const response = await app.request("/api/probe/register", {
    body: RegistrationRequest.encode(
      RegistrationRequest.create({
        enrollmentToken,
        inventory: sampleInventory({ hostname }),
        ...(options.publicKey === false ? {} : { probePublicKeyPem }),
      }),
    ).finish(),
    headers: {
      "content-type": "application/x-protobuf",
      ...headers,
    },
    method: "POST",
  });

  if (options.publicKey !== false) {
    testProbePrivateKeys.set(response, identity.privateKeyPem);
  }

  return response;
}

async function decodeRegisteredProbe(response: Response) {
  const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;
  const privateKeyPem = testProbePrivateKeys.get(response);
  const registration = RegistrationResponse.decode(
    new Uint8Array(await response.arrayBuffer()),
  );

  if (!privateKeyPem) {
    throw new Error("missing test Probe private key");
  }

  return { ...registration, privateKeyPem };
}

function sampleInventory(
  overrides: Partial<root.enoki.v1.IInventory> = {},
): root.enoki.v1.IInventory {
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

function hashStableInventory(inventory: root.enoki.v1.IInventory) {
  return createHash("sha256")
    .update(
      Inventory.encode(Inventory.create(stableInventory(inventory))).finish(),
    )
    .digest("hex");
}

function stableInventory(
  inventory: root.enoki.v1.IInventory,
): root.enoki.v1.IInventory {
  return {
    ...inventory,
    filesystems: [...(inventory.filesystems ?? [])].sort(
      (left, right) =>
        String(left.mountPoint ?? "").localeCompare(
          String(right.mountPoint ?? ""),
        ) ||
        String(left.filesystemType ?? "").localeCompare(
          String(right.filesystemType ?? ""),
        ),
    ),
    networkInterfaces: [...(inventory.networkInterfaces ?? [])]
      .map((networkInterface) => ({
        ...networkInterface,
        addresses: [...new Set(networkInterface.addresses ?? [])].sort(),
      }))
      .sort((left, right) =>
        String(left.name ?? "").localeCompare(String(right.name ?? "")),
      ),
  };
}

async function withHubServer(
  app: ReturnType<typeof createHubApp>,
  callback: (origin: string) => Promise<void>,
) {
  const server = serve({
    fetch: app.fetch,
    hostname: "127.0.0.1",
    port: 0,
  });

  await new Promise<void>((resolve) => {
    server.once("listening", resolve);
  });

  const address = server.address() as AddressInfo;

  try {
    await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  }
}

describe("Probe registration API", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("creates a pending Enrollment Token without creating a Host card", async () => {
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

    const createResponse = await app.request("/api/web/enrollments", {
      headers: {
        cookie: ownerSession,
      },
      method: "POST",
    });

    expect(createResponse.status).toBe(201);
    const enrollment = (await createResponse.json()) as {
      enrollmentToken: string;
      expiresAtMs: number;
    };
    expect(enrollment.enrollmentToken).toMatch(/^enk_enroll_/);
    expect(enrollment.expiresAtMs).toBeGreaterThan(Date.now());

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(hostsResponse.status).toBe(200);
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [],
    });
    expect(database.audit.recent(1)).toEqual([
      expect.objectContaining({
        action: "enrollment_token.create",
        actor: "owner",
        outcome: "success",
      }),
    ]);

    database.close();
  });

  it("registers a Probe with an Enrollment Token and creates a Host", async () => {
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
    const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;

    const response = await registerProbe(app, enrollmentToken);

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const decoded = RegistrationResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(decoded.probeId).toMatch(/^probe_/);
    expect(decoded.probeSecret).toBe("");
    expect(decoded.initialConfiguration?.version).toBe("default-v1");
    expect(decoded.initialConfiguration?.metricsCollectionIntervalSeconds).toBe(
      5,
    );
    expect(decoded.initialConfiguration?.reportingBatchIntervalSeconds).toBe(
      15,
    );
    expect(decoded.initialConfiguration).toEqual(
      expect.objectContaining({
        collectCpu: true,
        collectDisk: true,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: true,
        collectUptime: true,
      }),
    );

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(hostsResponse.status).toBe(200);
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          cpu: "2 cores",
          displayName: "managed-host-01",
          memory: "2 GB",
          probeVersion: "0.1.0",
          status: "offline",
          system: "linux 6.8.0 x86_64",
        }),
      ],
    });

    database.close();
  });

  it("rejects reuse of an Enrollment Token after successful registration", async () => {
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

    const firstResponse = await registerProbe(
      app,
      enrollmentToken,
      "managed-host-01",
    );
    expect(firstResponse.status).toBe(200);

    const secondResponse = await registerProbe(
      app,
      enrollmentToken,
      "managed-host-02",
    );

    expect(secondResponse.status).toBe(401);
    await expect(secondResponse.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
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
        }),
      ],
    });

    database.close();
  });

  it("rejects Probe registration when the Enrollment Token is missing", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    });
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;

    const response = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          inventory: {
            architecture: "x86_64",
            hostname: "managed-host-01",
            kernel: "6.8.0",
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

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });

    database.close();
  });

  it("rejects Probe registration with an invalid Enrollment Token", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    });

    const response = await registerProbe(app, "enk_enroll_not-real");

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });

    database.close();
  });

  it("rejects Probe registration without consuming the Enrollment Token when the public key is invalid", async () => {
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

    const missingKey = await registerProbe(
      app,
      enrollmentToken,
      "managed-host-01",
      {},
      { publicKey: false },
    );
    expect(missingKey.status).toBe(400);
    await expect(missingKey.json()).resolves.toEqual({
      error: "probe_public_key_required",
    });

    const invalidKey = await registerProbe(
      app,
      enrollmentToken,
      "managed-host-01",
      {},
      { publicKeyPem: "not-a-public-key" },
    );
    expect(invalidKey.status).toBe(400);
    await expect(invalidKey.json()).resolves.toEqual({
      error: "probe_public_key_required",
    });

    const response = await registerProbe(app, enrollmentToken);
    expect(response.status).toBe(200);

    database.close();
  });

  it("rejects Probe registration with an expired Enrollment Token", async () => {
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
    now += 1000 * 60 * 16;

    const response = await registerProbe(app, enrollmentToken);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [],
    });

    database.close();
  });

  it("authenticates registered Probe requests with the Probe Identity bearer secret", async () => {
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
    const registrationResponse = await registerProbe(app, enrollmentToken);
    const ConfigurationRequest = root.enoki.v1.ProbeConfigurationRequest;
    const ConfigurationResponse = root.enoki.v1.ProbeConfigurationResponse;
    const registration = await decodeRegisteredProbe(registrationResponse);

    const configBody = ConfigurationRequest.encode(
      ConfigurationRequest.create({
        currentVersion: "",
        probeId: registration.probeId,
      }),
    ).finish();
    const response = await app.request(
      "/api/probe/config",
      signedProbeRequest(registration, "/api/probe/config", configBody),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const configuration = ConfigurationResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(configuration.version).toBe("default-v1");
    expect(configuration.metricsCollectionIntervalSeconds).toBe(5);
    expect(configuration.reportingBatchIntervalSeconds).toBe(15);
    expect(configuration).toEqual(
      expect.objectContaining({
        collectCpu: true,
        collectDisk: true,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: true,
        collectUptime: true,
      }),
    );

    database.close();
  });

  it("asks a Probe for full Inventory when a report hash is unknown", async () => {
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
    const registrationResponse = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const registration = await decodeRegisteredProbe(registrationResponse);

    const reportBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        inventoryHash:
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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
    expect(response.headers.get("cache-control")).toBe("no-store");
    const acknowledgement = ReportResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(acknowledgement.inventoryNeeded).toBe(true);
    expect(acknowledgement.acceptedSequenceEnd.toString()).toBe("1");
    expect(acknowledgement.currentProbeConfigurationVersion).toBe("default-v1");
    expect(acknowledgement.serverTimeMs.toString()).toBe("1725000000000");

    database.close();
  });

  it("stores a changed full Inventory snapshot from a Probe report", async () => {
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
    const registrationResponse = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const Inventory = root.enoki.v1.Inventory;
    const changedInventory = Inventory.create({
      architecture: "x86_64",
      cpuCount: 4,
      cpuModel: "AMD EPYC 7B13",
      filesystems: [
        {
          availableBytes: 500_000,
          filesystemType: "ext4",
          mountPoint: "/",
          totalBytes: 1_000_000,
        },
      ],
      hostname: "renamed-host",
      kernel: "6.9.0",
      memoryTotalBytes: 4_294_967_296,
      networkInterfaces: [
        {
          addresses: ["10.0.0.20"],
          name: "eth0",
        },
      ],
      os: "linux",
      probeVersion: "0.2.0",
    });
    const changedInventoryHash = createHash("sha256")
      .update(Inventory.encode(changedInventory).finish())
      .digest("hex");
    const registration = await decodeRegisteredProbe(registrationResponse);

    const reportBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        inventory: changedInventory,
        inventoryHash: changedInventoryHash,
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
      }),
    ).finish();
    const response = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", reportBody),
    );

    expect(response.status).toBe(200);
    const acknowledgement = ReportResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(acknowledgement.inventoryNeeded).toBe(false);

    const storedHost = database.sqlite
      .prepare(
        "select hostname, probe_version, cpu_count, cpu_model, memory_total_bytes, inventory_hash, inventory_json from managed_hosts",
      )
      .get() as {
      cpu_count: number;
      cpu_model: string;
      hostname: string;
      inventory_hash: string;
      inventory_json: string;
      memory_total_bytes: number;
      probe_version: string;
    };
    expect(storedHost).toEqual(
      expect.objectContaining({
        cpu_count: 4,
        cpu_model: "AMD EPYC 7B13",
        hostname: "renamed-host",
        inventory_hash: changedInventoryHash,
        memory_total_bytes: 4_294_967_296,
        probe_version: "0.2.0",
      }),
    );
    expect(JSON.parse(storedHost.inventory_json)).toEqual(
      expect.objectContaining({
        cpuModel: "AMD EPYC 7B13",
        hostname: "renamed-host",
        networkInterfaces: [
          {
            addresses: ["10.0.0.20"],
            name: "eth0",
          },
        ],
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

  it("accepts hash-only reports after shuffled Inventory repeated fields are canonicalized", async () => {
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
    const registrationResponse = await registerProbe(app, enrollmentToken);
    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const ReportResponse = root.enoki.v1.ProbeReportResponse;
    const shuffledInventory = sampleInventory({
      filesystems: [
        {
          availableBytes: 30_000,
          filesystemType: "ext4",
          mountPoint: "/var",
          totalBytes: 80_000,
        },
        {
          availableBytes: 60_000,
          filesystemType: "ext4",
          mountPoint: "/",
          totalBytes: 100_000,
        },
      ],
      networkInterfaces: [
        {
          addresses: ["2001:db8::10", "10.0.0.10", "10.0.0.10"],
          name: "eth0",
        },
      ],
    });
    const canonicalHash = hashStableInventory(shuffledInventory);
    expect(canonicalHash).toBe(
      "81b44963b7d5790b078d36ad59ac8ffa3da60b6684b58ca152252dfb5574c013",
    );
    const registration = await decodeRegisteredProbe(registrationResponse);

    const fullSnapshotBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        inventory: shuffledInventory,
        inventoryHash: canonicalHash,
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
      }),
    ).finish();
    const fullSnapshotResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", fullSnapshotBody),
    );

    expect(fullSnapshotResponse.status).toBe(200);
    const fullSnapshotAck = ReportResponse.decode(
      new Uint8Array(await fullSnapshotResponse.arrayBuffer()),
    );
    expect(fullSnapshotAck.inventoryNeeded).toBe(false);

    const hashOnlyBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        inventoryHash: canonicalHash,
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 3,
        sequenceStart: 3,
      }),
    ).finish();
    const hashOnlyResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(registration, "/api/probe/report", hashOnlyBody),
    );

    expect(hashOnlyResponse.status).toBe(200);
    const hashOnlyAck = ReportResponse.decode(
      new Uint8Array(await hashOnlyResponse.arrayBuffer()),
    );
    expect(hashOnlyAck.inventoryNeeded).toBe(false);

    const storedHost = database.sqlite
      .prepare("select inventory_hash from managed_hosts")
      .get() as { inventory_hash: string };
    expect(storedHost.inventory_hash).toBe(canonicalHash);

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(hostsResponse.status).toBe(200);

    database.close();
  });

  it("records Observed IP from trusted forwarding headers without using it as Host Metadata", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      trustForwardedProbeHeaders: true,
    });
    const ownerSession = await loginOwner(app);
    const enrollmentToken = await createEnrollmentToken(app, ownerSession);

    const response = await registerProbe(
      app,
      enrollmentToken,
      "managed-host-01",
      {
        "x-forwarded-for": "203.0.113.10, 10.0.0.1",
      },
    );

    expect(response.status).toBe(200);
    const storedHost = database.sqlite
      .prepare("select connect_address, observed_ip from managed_hosts")
      .get() as {
      connect_address: string;
      observed_ip: string;
    };
    expect(storedHost).toEqual({
      connect_address: "10.0.0.10",
      observed_ip: "203.0.113.10",
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          connectAddress: "10.0.0.10",
        }),
      ],
    });

    database.close();
  });

  it("records direct Observed IP and ignores forwarding headers unless they are trusted", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      database,
    });
    const enrollmentToken = "enk_enroll_direct";
    const createdAtMs = Date.now();
    database.enrollments.createPending({
      createdAtMs,
      expiresAtMs: createdAtMs + 60_000,
      tokenHash: hashSecret(enrollmentToken),
    });
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const identity = createTestProbeIdentity();

    await withHubServer(app, async (origin) => {
      const response = await fetch(`${origin}/api/probe/register`, {
        body: RegistrationRequest.encode(
          RegistrationRequest.create({
            enrollmentToken,
            inventory: sampleInventory(),
            probePublicKeyPem: identity.publicKeyPem,
          }),
        ).finish(),
        headers: {
          "content-type": "application/x-protobuf",
          "x-forwarded-for": "203.0.113.10",
        },
        method: "POST",
      });

      expect(response.status).toBe(200);
    });

    const storedHost = database.sqlite
      .prepare("select connect_address, observed_ip from managed_hosts")
      .get() as {
      connect_address: string;
      observed_ip: string;
    };
    expect(storedHost).toEqual({
      connect_address: "10.0.0.10",
      observed_ip: "127.0.0.1",
    });

    database.close();
  });

  it("initializes Display Name from a short Probe-derived fallback when hostname is blank", async () => {
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

    const response = await registerProbe(app, enrollmentToken, "");

    expect(response.status).toBe(200);
    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    const body = (await hostsResponse.json()) as {
      hosts: Array<{ displayName: string }>;
    };
    expect(body.hosts[0]?.displayName).toMatch(/^probe_[A-Za-z0-9_-]+$/);
    expect(body.hosts[0]?.displayName.length).toBeLessThanOrEqual(14);

    database.close();
  });

  it("rejects compressed Probe registration requests", async () => {
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

    const response = await registerProbe(
      app,
      enrollmentToken,
      "managed-host-01",
      {
        "content-encoding": "gzip",
      },
    );

    expect(response.status).toBe(415);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual({
      error: "payload_compression_not_supported",
    });

    database.close();
  });

  it("rejects Probe Configuration fetches when the Probe bearer is missing", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    });
    const ConfigurationRequest = root.enoki.v1.ProbeConfigurationRequest;

    const response = await app.request("/api/probe/config", {
      body: ConfigurationRequest.encode(
        ConfigurationRequest.create({
          currentVersion: "",
          probeId: "probe_01",
        }),
      ).finish(),
      headers: {
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual({
      error: "probe_identity_required",
    });

    database.close();
  });

  it("rejects compressed Probe Configuration fetch requests", async () => {
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
    const registrationResponse = await registerProbe(app, enrollmentToken);
    const ConfigurationRequest = root.enoki.v1.ProbeConfigurationRequest;
    const registration = await decodeRegisteredProbe(registrationResponse);

    const response = await app.request("/api/probe/config", {
      body: ConfigurationRequest.encode(
        ConfigurationRequest.create({
          currentVersion: "",
          probeId: registration.probeId,
        }),
      ).finish(),
      headers: {
        authorization: "Bearer enk_probe_legacy",
        "content-encoding": "gzip",
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(415);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual({
      error: "payload_compression_not_supported",
    });

    database.close();
  });

  it("rejects Probe Configuration fetches when the Probe bearer is invalid", async () => {
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
    const registrationResponse = await registerProbe(app, enrollmentToken);
    const ConfigurationRequest = root.enoki.v1.ProbeConfigurationRequest;
    const registration = await decodeRegisteredProbe(registrationResponse);

    const response = await app.request("/api/probe/config", {
      body: ConfigurationRequest.encode(
        ConfigurationRequest.create({
          currentVersion: "",
          probeId: registration.probeId,
        }),
      ).finish(),
      headers: {
        authorization: "Bearer enk_probe_not-real",
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "probe_identity_required",
    });

    database.close();
  });

  it("does not issue legacy Probe Identity secrets", async () => {
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
    const registrationResponse = await registerProbe(app, enrollmentToken);
    const registration = await decodeRegisteredProbe(registrationResponse);

    const storedHost = database.sqlite
      .prepare("select probe_secret_hash from managed_hosts")
      .get() as { probe_secret_hash: string };

    expect(registration.probeSecret).toBeUndefined();
    expect(storedHost.probe_secret_hash).toMatch(/^[0-9a-f]{64}$/);

    database.close();
  });

  it("does not accept Enrollment Tokens from registration URLs", async () => {
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

    const response = await app.request(
      `/api/probe/register?enrollment_token=${enrollmentToken}`,
      {
        body: new Uint8Array(),
        headers: {
          "content-type": "application/x-protobuf",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    await expect(hostsResponse.json()).resolves.toEqual({
      hosts: [],
    });

    database.close();
  });

  it("rejects unauthenticated Enrollment Token creation", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
    });

    const response = await app.request("/api/web/enrollments", {
      method: "POST",
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "owner_session_required",
    });

    database.close();
  });
});
