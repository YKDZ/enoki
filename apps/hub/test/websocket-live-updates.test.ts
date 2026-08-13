import { mkdtemp, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { afterEach, describe, expect, it } from "vitest";
import WebSocket from "ws";

import { createHubApp } from "../src/app";
import { createMemoryPasswordVerificationBudget } from "../src/auth/password-verification-budget";
import { initializeHubDatabase } from "../src/database/index";
import { createLiveUpdateBroadcaster } from "../src/live-updates";
import { createHubNodeServer } from "../src/node-server";
import { hashStableHostProfile } from "./host-profile-hash";
import {
  createTestProbeIdentity,
  signedJsonProbeHeaders,
  signedProbeHeaders,
} from "./probe-test-auth";

const tempRoots: string[] = [];
const openServers: Array<{ close: () => Promise<void> }> = [];
const diskHealthCapabilityStatus =
  root.enoki.v1.DiskHealthCollectorCapabilityStatus;

function diskHealthCapability(available: boolean | undefined) {
  return {
    diagnostic: available ? "" : "SMART data is unsupported",
    status: available
      ? diskHealthCapabilityStatus.DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_AVAILABLE
      : diskHealthCapabilityStatus.DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_UNSUPPORTED_SMART_DATA,
  };
}

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-ws-db-"));
  tempRoots.push(dataRoot);

  return initializeHubDatabase({
    dataRoot,
    sqlitePath: path.join(dataRoot, "enoki.db"),
  });
}

async function startHubServer(options: {
  database: Awaited<ReturnType<typeof createTemporaryDatabase>>;
  now?: () => number;
}) {
  const server = await createHubNodeServer({
    auth: {
      failureDelayMs: 0,
      ownerPassword: "correct horse battery staple",
      sessionCookieName: "enoki_owner_session",
    },
    database: options.database,
    hostname: "127.0.0.1",
    now: options.now,
    passwordVerificationBudget: createMemoryPasswordVerificationBudget({
      capacity: 20,
    }),
    port: 0,
  });
  openServers.push(server);

  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const webSocketUrl = `ws://127.0.0.1:${address.port}/api/web/ws`;

  return {
    baseUrl,
    server,
    webSocketUrl,
  };
}

async function loginOwner(baseUrl: string) {
  const response = await fetch(`${baseUrl}/api/web/auth/login`, {
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

async function createEnrollmentToken(baseUrl: string, ownerSession: string) {
  const response = await fetch(`${baseUrl}/api/web/enrollments`, {
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

async function registerProbe(baseUrl: string, enrollmentToken: string) {
  const identity = createTestProbeIdentity();
  const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
  const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;
  const response = await fetch(`${baseUrl}/api/probe/register`, {
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
  return { ...registration, privateKeyPem: identity.privateKeyPem };
}

async function sendReport(
  baseUrl: string,
  registration: {
    privateKeyPem: string;
    probeId: string;
  },
  options: {
    bootId?: string;
    cpuPercent?: number;
    diskAvailable?: boolean;
    hostProfile?: root.enoki.v1.IHostProfileSnapshot;
    sequence?: number;
  } = {},
) {
  const ReportRequest = root.enoki.v1.ProbeReportRequest;
  const ReportResponse = root.enoki.v1.ProbeReportResponse;
  const sequence = options.sequence ?? 1;
  const metrics = [
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
      cpuPercent: options.cpuPercent ?? 42.5,
      disks: [
        {
          availableBytes: 512,
          filesystemType: "ext4",
          mountPoint: "/",
          totalBytes: 2_048,
          usedBytes: 1_536,
        },
      ],
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
      sequence,
      uptimeSeconds: 86_400,
    },
  ];
  const hostProfile = hostProfileForReport(options);
  const postReport = async (input: {
    metrics: typeof metrics;
    snapshots: root.enoki.v1.ISnapshot[];
  }) => {
    const body = ReportRequest.encode(
      ReportRequest.create({
        bootId: options.bootId ?? "boot-live-summary",
        metrics: input.metrics,
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: sequence,
        sequenceStart: sequence,
        snapshots: input.snapshots,
      }),
    ).finish();
    const reportUrl = `${baseUrl}/api/probe/report`;
    const response = await fetch(reportUrl, {
      body,
      headers: signedProbeHeaders({
        body,
        pathAndQuery: "/api/probe/report",
        privateKeyPem: registration.privateKeyPem,
        probeId: registration.probeId,
      }),
      method: "POST",
    });

    expect(response.status).toBe(200);
    return response;
  };

  if (!hostProfile) {
    await postReport({ metrics, snapshots: [] });
    return;
  }

  const snapshotHash = hashStableHostProfile(hostProfile);
  const compactResponse = await postReport({
    metrics,
    snapshots: [
      {
        collectorId: "official.host-profile",
        snapshotHash,
      },
    ],
  });
  expect(
    ReportResponse.decode(new Uint8Array(await compactResponse.arrayBuffer()))
      .requestedSnapshotCollectorIds,
  ).toEqual(["official.host-profile"]);
  await postReport({
    metrics: [],
    snapshots: [
      {
        collectorId: "official.host-profile",
        hostProfile,
        snapshotHash,
      },
    ],
  });
}

async function sendStartupReport(
  baseUrl: string,
  registration: {
    privateKeyPem: string;
    probeId: string;
  },
  input: {
    bootId: string;
    hostProfile?: root.enoki.v1.IHostProfileSnapshot;
  },
) {
  const ReportRequest = root.enoki.v1.ProbeReportRequest;
  const hostProfile = input.hostProfile ?? baselineHostProfile();
  const body = ReportRequest.encode(
    ReportRequest.create({
      bootId: input.bootId,
      metrics: [],
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
  const reportUrl = `${baseUrl}/api/probe/report`;
  const response = await fetch(reportUrl, {
    body,
    headers: signedProbeHeaders({
      body,
      pathAndQuery: "/api/probe/report",
      privateKeyPem: registration.privateKeyPem,
      probeId: registration.probeId,
    }),
    method: "POST",
  });

  expect(response.status).toBe(200);
}

function hostProfileForReport(input: {
  diskAvailable?: boolean;
  hostProfile?: root.enoki.v1.IHostProfileSnapshot;
}) {
  if (input.hostProfile) {
    return input.hostProfile;
  }
  if (input.diskAvailable === undefined) {
    return null;
  }

  return {
    ...baselineHostProfile(),
    collectorCapabilities: {
      official: {
        diskHealth: diskHealthCapability(input.diskAvailable),
      },
    },
  } satisfies root.enoki.v1.IHostProfileSnapshot;
}

function baselineHostProfile(): root.enoki.v1.IHostProfileSnapshot {
  return {
    architecture: "x86_64",
    cpuCount: 2,
    hostname: "managed-host-01",
    kernel: "6.8.0",
    memoryTotalBytes: 2_147_483_648,
    os: "linux",
    probeVersion: "0.1.0",
  };
}

async function completeProbeUninstall(
  baseUrl: string,
  registration: {
    privateKeyPem: string;
    probeId: string;
  },
  operationId: number,
) {
  const ReportRequest = root.enoki.v1.ProbeReportRequest;
  const ReportResponse = root.enoki.v1.ProbeReportResponse;
  const reportBody = ReportRequest.encode(
    ReportRequest.create({
      bootId: "boot-probe-uninstall",
      probeConfigurationVersion: "default-v1",
      probeId: registration.probeId,
      sequenceEnd: 1,
      sequenceStart: 1,
    }),
  ).finish();
  const reportUrl = `${baseUrl}/api/probe/report`;
  const report = await fetch(reportUrl, {
    body: reportBody,
    headers: signedProbeHeaders({
      body: reportBody,
      pathAndQuery: "/api/probe/report",
      privateKeyPem: registration.privateKeyPem,
      probeId: registration.probeId,
    }),
    method: "POST",
  });
  expect(report.status).toBe(200);
  const token = ReportResponse.decode(
    new Uint8Array(await report.arrayBuffer()),
  ).pendingOperation?.probeUninstall?.operationToken;
  if (!token) {
    throw new Error("Expected a Probe Uninstall operation token.");
  }

  const tokenPath = `/api/probe/operations/${operationId}/token/validate`;
  const tokenBody = JSON.stringify({ token });
  const tokenValidation = await fetch(`${baseUrl}${tokenPath}`, {
    body: tokenBody,
    headers: signedJsonProbeHeaders({
      body: tokenBody,
      pathAndQuery: tokenPath,
      privateKeyPem: registration.privateKeyPem,
      probeId: registration.probeId,
    }),
    method: "POST",
  });
  expect(tokenValidation.status).toBe(200);

  const statusPath = `/api/probe/operations/${operationId}/status`;
  const statusBody = JSON.stringify({ status: "succeeded", token });
  const status = await fetch(`${baseUrl}${statusPath}`, {
    body: statusBody,
    headers: signedJsonProbeHeaders({
      body: statusBody,
      pathAndQuery: statusPath,
      privateKeyPem: registration.privateKeyPem,
      probeId: registration.probeId,
    }),
    method: "POST",
  });
  expect(status.status).toBe(200);
}

function openWebSocket(
  url: string,
  options: {
    cookie?: string;
  } = {},
) {
  return new Promise<WebSocket>((resolve, reject) => {
    const socket = new WebSocket(url, {
      headers: options.cookie
        ? {
            cookie: options.cookie,
          }
        : undefined,
    });

    socket.once("open", () => {
      resolve(socket);
    });
    socket.once("error", reject);
    socket.once("unexpected-response", (_request, response) => {
      reject(new Error(`unexpected response ${response.statusCode}`));
    });
  });
}

function readWebSocketJson(socket: WebSocket) {
  return new Promise<unknown>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("Timed out waiting for WebSocket message."));
    }, 500);
    const onMessage = (data: WebSocket.RawData) => {
      cleanup();
      resolve(JSON.parse(data.toString()));
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      socket.off("message", onMessage);
      socket.off("error", onError);
    };

    socket.on("message", onMessage);
    socket.on("error", onError);
  });
}

function readHostRemoved(socket: WebSocket) {
  return new Promise<unknown>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("Timed out waiting for a Host removal message."));
    }, 500);
    const onMessage = (data: WebSocket.RawData) => {
      const message = JSON.parse(data.toString()) as { type?: string };
      if (message.type !== "host_removed") {
        return;
      }

      cleanup();
      resolve(message);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      socket.off("message", onMessage);
      socket.off("error", onError);
    };

    socket.on("message", onMessage);
    socket.on("error", onError);
  });
}

function collectWebSocketJson(
  socket: WebSocket,
  options: {
    quietMs?: number;
    timeoutMs?: number;
  } = {},
) {
  const quietMs = options.quietMs ?? 50;
  const timeoutMs = options.timeoutMs ?? 500;

  return new Promise<unknown[]>((resolve, reject) => {
    const messages: unknown[] = [];
    let quietTimer: NodeJS.Timeout | null = null;
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("Timed out waiting for WebSocket messages."));
    }, timeoutMs);
    const finishAfterQuiet = () => {
      if (quietTimer) {
        clearTimeout(quietTimer);
      }

      quietTimer = setTimeout(() => {
        cleanup();
        resolve(messages);
      }, quietMs);
    };
    const onMessage = (data: WebSocket.RawData) => {
      messages.push(JSON.parse(data.toString()));
      finishAfterQuiet();
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      if (quietTimer) {
        clearTimeout(quietTimer);
      }

      socket.off("message", onMessage);
      socket.off("error", onError);
    };

    socket.on("message", onMessage);
    socket.on("error", onError);
  });
}

async function closeSocket(socket: WebSocket) {
  if (
    socket.readyState === WebSocket.CLOSED ||
    socket.readyState === WebSocket.CLOSING
  ) {
    return;
  }

  await new Promise<void>((resolve) => {
    socket.once("close", () => {
      resolve();
    });
    socket.close();
  });
}

function waitForSocketClose(socket: WebSocket) {
  return new Promise<void>((resolve) => {
    if (
      socket.readyState === WebSocket.CLOSED ||
      socket.readyState === WebSocket.CLOSING
    ) {
      resolve();
      return;
    }

    socket.once("close", () => {
      resolve();
    });
  });
}

describe("WebSocket live updates", () => {
  afterEach(async () => {
    await Promise.all(openServers.splice(0).map((server) => server.close()));
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("accepts Node Buffer client messages when subscribing to detail samples", () => {
    const liveUpdates = createLiveUpdateBroadcaster();
    const sentMessages: unknown[] = [];
    const socket = {
      close() {},
      readyState: 1,
      send(message: string) {
        sentMessages.push(JSON.parse(message) as unknown);
      },
    };

    liveUpdates.addClient(socket as never, {
      sessionId: "owner-session",
    });
    liveUpdates.handleClientMessage(
      socket as never,
      Buffer.from(
        JSON.stringify({
          hostId: 1,
          type: "subscribe_host_detail",
        }),
      ) as never,
    );
    liveUpdates.broadcastDetailSample({
      collectedAtMs: 1_725_000_009_500,
      cpuCores: [],
      cpuPercent: 42,
      disks: [],
      hostId: 1,
      memoryTotalBytes: null,
      memoryUsedBytes: null,
      networkInterfaces: [],
      receivedAtMs: 1_725_000_010_000,
      sequence: 1,
      uptimeSeconds: null,
    });

    expect(sentMessages).toEqual([
      {
        hostId: 1,
        sample: expect.objectContaining({
          cpuPercent: 42,
          hostId: 1,
          sequence: 1,
        }),
        type: "host_detail_sample",
      },
    ]);
  });

  it("broadcasts a non-secret Host removal hint to every authenticated client", () => {
    const liveUpdates = createLiveUpdateBroadcaster();
    const firstClientMessages: unknown[] = [];
    const secondClientMessages: unknown[] = [];
    const firstSocket = {
      close() {},
      readyState: 1,
      send(message: string) {
        firstClientMessages.push(JSON.parse(message) as unknown);
      },
    };
    const secondSocket = {
      close() {},
      readyState: 1,
      send(message: string) {
        secondClientMessages.push(JSON.parse(message) as unknown);
      },
    };

    liveUpdates.addClient(firstSocket as never, { sessionId: "owner-one" });
    liveUpdates.addClient(secondSocket as never, { sessionId: "owner-two" });
    liveUpdates.broadcastHostRemoved(42);

    expect(firstClientMessages).toEqual([{ hostId: 42, type: "host_removed" }]);
    expect(secondClientMessages).toEqual([
      { hostId: 42, type: "host_removed" },
    ]);
  });

  it("broadcasts a post-commit Host readiness hint with only its Enrollment and Host correlation", () => {
    const liveUpdates = createLiveUpdateBroadcaster();
    const messages: unknown[] = [];
    const socket = {
      close() {},
      readyState: 1,
      send(message: string) {
        messages.push(JSON.parse(message) as unknown);
      },
    };

    liveUpdates.addClient(socket as never, { sessionId: "owner-one" });
    liveUpdates.broadcastHostReady({
      enrollmentId: "enr_1234567890abcdef",
      hostId: 42,
    });

    expect(messages).toEqual([
      {
        enrollmentId: "enr_1234567890abcdef",
        hostId: 42,
        type: "host_ready",
      },
    ]);
  });

  it("requires an Owner session for the browser WebSocket endpoint", async () => {
    const database = await createTemporaryDatabase();
    const { baseUrl, webSocketUrl } = await startHubServer({ database });

    await expect(openWebSocket(webSocketUrl)).rejects.toThrow(
      "unexpected response 401",
    );

    const ownerSession = await loginOwner(baseUrl);
    const socket = await openWebSocket(webSocketUrl, {
      cookie: ownerSession,
    });

    expect(socket.readyState).toBe(WebSocket.OPEN);
    await closeSocket(socket);

    database.close();
  });

  it("closes live update sockets when the Owner session logs out", async () => {
    const database = await createTemporaryDatabase();
    const { baseUrl, webSocketUrl } = await startHubServer({ database });
    const ownerSession = await loginOwner(baseUrl);
    const socket = await openWebSocket(webSocketUrl, {
      cookie: ownerSession,
    });

    const closed = waitForSocketClose(socket);
    const response = await fetch(`${baseUrl}/api/web/auth/logout`, {
      headers: {
        cookie: ownerSession,
      },
      method: "POST",
    });

    expect(response.status).toBe(200);
    await expect(closed).resolves.toBeUndefined();

    database.close();
  });

  it("closes the oldest Owner session socket when a ninth session is issued", async () => {
    const database = await createTemporaryDatabase();
    const { baseUrl, webSocketUrl } = await startHubServer({ database });
    const oldestSession = await loginOwner(baseUrl);
    const socket = await openWebSocket(webSocketUrl, {
      cookie: oldestSession,
    });

    await Promise.all(
      Array.from({ length: 7 }, async () => loginOwner(baseUrl)),
    );
    const closed = waitForSocketClose(socket);
    await loginOwner(baseUrl);

    await expect(closed).resolves.toBeUndefined();
    const rejected = await fetch(`${baseUrl}/api/web/auth/session`, {
      headers: { cookie: oldestSession },
    });
    await expect(rejected.json()).resolves.toEqual({ authenticated: false });

    database.close();
  });

  it("rejects a socket whose Owner session is revoked before it opens", async () => {
    let lifecycle: { onOpen?: (event: unknown, socket: unknown) => void } = {};
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      passwordVerificationBudget: createMemoryPasswordVerificationBudget({
        capacity: 9,
      }),
      webSocket: {
        upgradeWebSocket: ((createLifecycle: (context: unknown) => unknown) =>
          async (context: { text: (body: string) => Response }) => {
            lifecycle = createLifecycle(context) as typeof lifecycle;
            return context.text("upgrade captured");
          }) as never,
      },
    });
    const login = async () => {
      const response = await app.request("/api/web/auth/login", {
        body: JSON.stringify({ password: "correct horse battery staple" }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      return response.headers.get("set-cookie") ?? "";
    };
    const oldestSession = await login();
    for (let index = 1; index < 8; index += 1) {
      await login();
    }

    const upgrade = await app.request("/api/web/ws", {
      headers: { cookie: oldestSession },
    });
    expect(upgrade.status).toBe(200);
    await login();

    let socketClosed = false;
    lifecycle.onOpen?.(
      {},
      {
        close() {
          socketClosed = true;
        },
      },
    );

    expect(socketClosed).toBe(true);
  });

  it("emits host_removed only after a Hub-only Host deletion commits", async () => {
    const database = await createTemporaryDatabase();
    const { baseUrl, webSocketUrl } = await startHubServer({
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(baseUrl);
    const socket = await openWebSocket(webSocketUrl, {
      cookie: ownerSession,
    });
    const enrollmentToken = await createEnrollmentToken(baseUrl, ownerSession);
    const registration = await registerProbe(baseUrl, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const removal = readWebSocketJson(socket);

    const response = await fetch(
      `${baseUrl}/api/web/hosts/${host.id}?mode=hub-only`,
      {
        headers: { cookie: ownerSession },
        method: "DELETE",
      },
    );

    expect(response.status).toBe(200);
    await expect(removal).resolves.toEqual({
      hostId: host.id,
      type: "host_removed",
    });
    expect(database.hosts.findActiveById(host.id)).toBeNull();

    await closeSocket(socket);
    database.close();
  });

  it("emits host_removed through the real WebSocket only after Probe Uninstall Completion", async () => {
    const database = await createTemporaryDatabase();
    const { baseUrl, webSocketUrl } = await startHubServer({ database });
    const ownerSession = await loginOwner(baseUrl);
    const socket = await openWebSocket(webSocketUrl, {
      cookie: ownerSession,
    });
    const enrollmentToken = await createEnrollmentToken(baseUrl, ownerSession);
    const registration = await registerProbe(baseUrl, enrollmentToken);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(registration.probeId) as { id: number };
    const deletion = await fetch(`${baseUrl}/api/web/hosts/${host.id}`, {
      headers: { cookie: ownerSession },
      method: "DELETE",
    });
    const requested = (await deletion.json()) as {
      probeUninstallRequest: { id: number };
    };
    expect(deletion.status).toBe(202);

    const removal = readHostRemoved(socket);
    await completeProbeUninstall(
      baseUrl,
      registration,
      requested.probeUninstallRequest.id,
    );

    await expect(removal).resolves.toEqual({
      hostId: host.id,
      type: "host_removed",
    });
    expect(database.hosts.findActiveById(host.id)).toBeNull();

    await closeSocket(socket);
    database.close();
  });

  it("broadcasts a lightweight Host summary after an accepted Probe report", async () => {
    const database = await createTemporaryDatabase();
    const { baseUrl, webSocketUrl } = await startHubServer({
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(baseUrl);
    const socket = await openWebSocket(webSocketUrl, {
      cookie: ownerSession,
    });
    const enrollmentToken = await createEnrollmentToken(baseUrl, ownerSession);
    const registration = await registerProbe(baseUrl, enrollmentToken);

    socket.send("not-json");
    socket.send(
      JSON.stringify({
        hostId: "not-a-number",
        type: "subscribe_host_detail",
      }),
    );
    await sendStartupReport(baseUrl, registration, {
      bootId: "boot-live-summary",
    });
    const summaryMessages = collectWebSocketJson(socket);
    await sendReport(baseUrl, registration, {
      bootId: "boot-live-summary",
      diskAvailable: false,
      sequence: 2,
    });

    await expect(summaryMessages).resolves.toEqual(
      expect.arrayContaining([
        {
          host: {
            id: 1,
            collectorCapabilities: {
              official: {
                diskHealth: {
                  diagnostic: "SMART data is unsupported",
                  status: 6,
                },
              },
            },
            lastSeenAtMs: 1_725_000_010_000,
            latestMetrics: {
              batteryPercent: null,
              batteryState: null,
              collectedAtMs: 1_725_000_009_500,
              cpuIdlePercent: null,
              cpuIowaitPercent: null,
              cpuPercent: 42.5,
              cpuStealPercent: null,
              cpuSystemPercent: null,
              cpuUserPercent: null,
              diskTotalBytes: 2_048,
              diskUsedBytes: 1_536,
              memoryCacheBytes: null,
              memoryTotalBytes: 2_147_483_648,
              memoryUsedBytes: 1_073_741_824,
              networkRxBitsPerSecond: 6_400,
              networkRxBytesDelta: 4_000,
              networkTxBitsPerSecond: 3_200,
              networkTxBytesDelta: 2_000,
              receivedAtMs: 1_725_000_010_000,
              swapTotalBytes: null,
              swapUsedBytes: null,
              temperatureCelsius: null,
              uptimeSeconds: 86_400,
            },
            status: "online",
            warningFlags: {
              clockSkew: false,
              probeConfigurationError: false,
            },
          },
          type: "host_summary",
        },
      ]),
    );

    await closeSocket(socket);
    database.close();
  });

  it("sends detailed samples only for the subscribed Host", async () => {
    const database = await createTemporaryDatabase();
    const { baseUrl, webSocketUrl } = await startHubServer({
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(baseUrl);
    const socket = await openWebSocket(webSocketUrl, {
      cookie: ownerSession,
    });
    const hostOneEnrollment = await createEnrollmentToken(
      baseUrl,
      ownerSession,
    );
    const hostOneRegistration = await registerProbe(baseUrl, hostOneEnrollment);
    const hostTwoEnrollment = await createEnrollmentToken(
      baseUrl,
      ownerSession,
    );
    const hostTwoRegistration = await registerProbe(baseUrl, hostTwoEnrollment);

    socket.send(
      JSON.stringify({
        hostId: 1,
        type: "subscribe_host_detail",
      }),
    );
    const hostOneMessages = collectWebSocketJson(socket);
    await sendReport(baseUrl, hostOneRegistration, {
      bootId: "boot-host-one",
      cpuPercent: 42.5,
      sequence: 1,
    });

    await expect(hostOneMessages).resolves.toEqual([
      expect.objectContaining({
        host: expect.objectContaining({
          id: 1,
        }),
        type: "host_summary",
      }),
      {
        hostId: 1,
        sample: {
          batteryPercent: null,
          batteryState: null,
          collectedAtMs: 1_725_000_009_500,
          cpuCores: [
            {
              name: "cpu0",
              usagePercent: 15,
            },
          ],
          cpuIdlePercent: null,
          cpuIowaitPercent: null,
          cpuPercent: 42.5,
          cpuStealPercent: null,
          cpuSystemPercent: null,
          cpuUserPercent: null,
          disks: [
            {
              availableBytes: 512,
              filesystemType: "ext4",
              ioUtilizationPercent: null,
              mountPoint: "/",
              readAwaitMs: null,
              readBytesDelta: 0,
              totalBytes: 2_048,
              usedBytes: 1_536,
              weightedIoPercent: null,
              writeAwaitMs: null,
              writeBytesDelta: 0,
            },
          ],
          hostId: 1,
          memoryCacheBytes: null,
          memoryTotalBytes: 2_147_483_648,
          memoryUsedBytes: 1_073_741_824,
          networkInterfaces: [
            {
              name: "eth0",
              rxBytesDelta: 4_000,
              txBytesDelta: 2_000,
            },
          ],
          receivedAtMs: 1_725_000_010_000,
          sequence: 1,
          swapTotalBytes: null,
          swapUsedBytes: null,
          temperatureCelsius: null,
          uptimeSeconds: 86_400,
        },
        type: "host_detail_sample",
      },
    ]);

    const hostTwoMessages = collectWebSocketJson(socket);
    await sendReport(baseUrl, hostTwoRegistration, {
      bootId: "boot-host-two",
      cpuPercent: 12.5,
      sequence: 1,
    });

    await expect(hostTwoMessages).resolves.toEqual([
      expect.objectContaining({
        host: expect.objectContaining({
          id: 2,
        }),
        type: "host_summary",
      }),
    ]);

    socket.send(
      JSON.stringify({
        hostId: 1,
        type: "unsubscribe_host_detail",
      }),
    );
    const unsubscribedMessages = collectWebSocketJson(socket);
    await sendReport(baseUrl, hostOneRegistration, {
      bootId: "boot-host-one",
      cpuPercent: 84,
      sequence: 2,
    });

    await expect(unsubscribedMessages).resolves.toEqual([
      expect.objectContaining({
        host: expect.objectContaining({
          id: 1,
        }),
        type: "host_summary",
      }),
    ]);

    await closeSocket(socket);
    database.close();
  });

  it("broadcasts Host Profile updates to the subscribed Host detail", async () => {
    const database = await createTemporaryDatabase();
    const { baseUrl, webSocketUrl } = await startHubServer({
      database,
      now: () => 1_725_000_010_000,
    });
    const ownerSession = await loginOwner(baseUrl);
    const socket = await openWebSocket(webSocketUrl, {
      cookie: ownerSession,
    });
    const enrollmentToken = await createEnrollmentToken(baseUrl, ownerSession);
    const registration = await registerProbe(baseUrl, enrollmentToken);
    await sendStartupReport(baseUrl, registration, {
      bootId: "boot-profile-live",
    });

    socket.send(
      JSON.stringify({
        hostId: 1,
        type: "subscribe_host_detail",
      }),
    );
    const messages = collectWebSocketJson(socket);
    await sendReport(baseUrl, registration, {
      bootId: "boot-profile-live",
      hostProfile: {
        architecture: "x86_64",
        collectorCapabilities: {
          official: {
            diskHealth: { diagnostic: "", status: 1 },
          },
        },
        cpuCount: 4,
        cpuModel: "AMD EPYC 7B13",
        filesystems: [],
        hostname: "profile-live-host",
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
      },
      sequence: 2,
    });

    await expect(messages).resolves.toEqual(
      expect.arrayContaining([
        {
          hostId: 1,
          hostProfile: expect.objectContaining({
            cpuCount: 4,
            hostname: "profile-live-host",
            probeVersion: "0.2.0",
          }),
          type: "host_profile",
        },
      ]),
    );

    await closeSocket(socket);
    database.close();
  });
});
