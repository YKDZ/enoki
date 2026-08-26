import { Buffer } from "node:buffer";
import { createHash, createSign } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { serve } from "@hono/node-server";
import { afterEach, describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import { hashSecret } from "../src/enrollment/routes";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture";
import { createTestProbeIdentity, signedProbeRequest } from "./probe-test-auth";

const tempRoots: string[] = [];
const HostProfileSnapshot = root.enoki.v1.HostProfileSnapshot;
const testProbePrivateKeys = new WeakMap<Response, string>();
const hostProfileCrossRuntimeCanonicalHash =
  "22843eb296c1643cd0a9b40706f3609fecbaec0ae0114a041923c9adaef07da3";
const bootstrapRecipe = {
  bundleVersion: "0.2.0",
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
  hostname = "managed-host-01",
  headers: Record<string, string> = {},
  options: {
    probeVersion?: string;
    publicKey?: boolean;
    publicKeyPem?: string;
    registrationAttempt?: {
      enrollmentId: string;
      committedSourceProbeSha256: string;
      hostId: string;
      hubOrigin: string;
      nonce?: string;
      oldProbeId: string;
      replacementCommitSha256?: string;
      sourceProbeVersion: string;
      targetAssetSetDigest: string;
      targetBundleTarget: string;
      targetManifestSha256: string;
      targetProbeVersion: string;
    };
    snapshots?: boolean;
  } = {},
) {
  const identity = createTestProbeIdentity();
  const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
  const probePublicKeyPem = options.publicKeyPem ?? identity.publicKeyPem;
  const canonicalAttempt = options.registrationAttempt
    ? root.enoki.v1.ProbeRegistrationAttempt.encode(
        root.enoki.v1.ProbeRegistrationAttempt.create({
          ...options.registrationAttempt,
          candidatePublicKeyPem: probePublicKeyPem,
          nonce: options.registrationAttempt.nonce ?? "a".repeat(64),
          replacementCommitSha256:
            options.registrationAttempt.replacementCommitSha256 ??
            "d".repeat(64),
          schemaVersion: 1,
        }),
      ).finish()
    : undefined;
  const candidateSignature = canonicalAttempt
    ? (() => {
        const signer = createSign("RSA-SHA256");
        signer.update(
          `enoki.probe-registration-attempt.v1\n${createHash("sha256")
            .update(canonicalAttempt)
            .digest("hex")}`,
        );
        signer.end();
        return signer.sign(identity.privateKeyPem);
      })()
    : undefined;

  const response = await app.request("/api/probe/register", {
    body: RegistrationRequest.encode(
      RegistrationRequest.create({
        enrollmentToken,
        candidateSignature,
        canonicalAttempt,
        ...(options.publicKey === false ? {} : { probePublicKeyPem }),
        snapshots:
          options.snapshots === false
            ? []
            : [
                {
                  collectorId: "official.host-profile",
                  hostProfile: sampleHostProfile({
                    hostname,
                    ...(options.probeVersion
                      ? { probeVersion: options.probeVersion }
                      : {}),
                  }),
                },
              ],
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
  expect(registration.hostId).toMatch(/^[1-9][0-9]*$/);

  if (!privateKeyPem) {
    throw new Error("missing test Probe private key");
  }

  return { ...registration, privateKeyPem };
}

function sampleHostProfile(
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
    processCount: 123,
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
    threadCount: 456,
  });
}

function hashStableHostProfile(
  hostProfile: root.enoki.v1.IHostProfileSnapshot,
) {
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

  it("rejects Probe registration requests with a declared body larger than the registration limit", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      database,
    });

    const response = await app.request("/api/probe/register", {
      body: new Uint8Array(),
      headers: {
        "content-length": String(256 * 1024 + 1),
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toEqual({
      error: "probe_registration_too_large",
    });

    database.close();
  });

  it("rejects Probe registration requests that stream past the registration limit", async () => {
    const database = await createTemporaryDatabase();
    const app = createHubApp({
      database,
    });
    const oversizedBody = new Uint8Array(256 * 1024 + 1);

    const response = await app.request(
      new Request("http://localhost/api/probe/register", {
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(oversizedBody.subarray(0, 128 * 1024));
            controller.enqueue(oversizedBody.subarray(128 * 1024));
            controller.close();
          },
        }),
        duplex: "half",
        headers: {
          "content-type": "application/x-protobuf",
        },
        method: "POST",
      } as RequestInit & { duplex: "half" }),
    );

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toEqual({
      error: "probe_registration_too_large",
    });

    database.close();
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

  it("does not use an attacker-controlled rejection message as an existing Probe ID", async () => {
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
      headers: { cookie: ownerSession },
      method: "POST",
    });
    const firstEnrollment = (await createResponse.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
    };
    const registered = await registerProbe(
      app,
      firstEnrollment.enrollmentToken,
    );
    const registration = await decodeRegisteredProbe(registered);
    const repeatedCreateResponse = await app.request("/api/web/enrollments", {
      headers: { cookie: ownerSession },
      method: "POST",
    });
    const repeatedEnrollment = (await repeatedCreateResponse.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
    };
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;

    const rejection = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken: repeatedEnrollment.enrollmentToken,
          installationRejection: {
            code: "existing_probe_installation",
            message: registration.probeId,
          },
        }),
      ).finish(),
      headers: { "content-type": "application/x-protobuf" },
      method: "POST",
    });

    expect(rejection.status).toBe(204);
    const status = await app.request(
      `/api/web/enrollments/${repeatedEnrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    await expect(status.json()).resolves.toEqual(
      expect.objectContaining({
        rejection: {
          code: "existing_probe_installation",
          message: "existing local Probe installation detected",
        },
        hostId: null,
        status: "rejected",
      }),
    );
    const hosts = await app.request("/api/web/hosts", {
      headers: { cookie: ownerSession },
    });
    expect(hosts.status).toBe(200);
    await expect(hosts.json()).resolves.toEqual({
      hosts: [expect.objectContaining({ displayName: "managed-host-01" })],
    });
    expect(database.audit.recent(1)).toEqual([
      expect.objectContaining({
        action: "enrollment.installation_rejected",
        actor: "system",
        outcome: "success",
      }),
    ]);

    database.close();
  });

  it("links a repeated pending Add rejection to its matching active Host through public Probe ID context", async () => {
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
      headers: { cookie: ownerSession },
      method: "POST",
    });
    const enrollment = (await createResponse.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
    };
    const registered = await registerProbe(app, enrollment.enrollmentToken);
    const registration = await decodeRegisteredProbe(registered);
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const repeatedCreateResponse = await app.request("/api/web/enrollments", {
      headers: { cookie: ownerSession },
      method: "POST",
    });
    const repeatedEnrollment = (await repeatedCreateResponse.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
    };
    const rejection = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken: repeatedEnrollment.enrollmentToken,
          installationRejection: {
            code: "existing_probe_installation",
            existingProbeId: registration.probeId,
            message: "attacker controlled text is discarded",
          },
        }),
      ).finish(),
      headers: { "content-type": "application/x-protobuf" },
      method: "POST",
    });

    expect(rejection.status).toBe(204);
    const status = await app.request(
      `/api/web/enrollments/${repeatedEnrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    await expect(status.json()).resolves.toEqual(
      expect.objectContaining({
        hostId: expect.any(Number),
        status: "rejected",
      }),
    );
    expect(registration.probeId).toMatch(/^probe_/);

    database.close();
  });

  it("rejects malformed JSON Enrollment targets before persisting a token", async () => {
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

    const response = await app.request("/api/web/enrollments", {
      body: "{",
      headers: {
        "content-type": "application/json",
        cookie: ownerSession,
      },
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_enrollment_target",
    });
    expect(
      database.sqlite
        .prepare("select count(*) as count from enrollment_tokens")
        .get(),
    ).toEqual({ count: 0 });

    database.close();
  });

  it("binds an empty-snapshot replacement registration and becomes ready only after Boot and a current target Host Profile", async () => {
    const database = await createTemporaryDatabase();
    const nowMs = Date.now();
    const assetDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-replacement-vertical-"),
    );
    tempRoots.push(assetDir);
    const release = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "0.1.0",
      targetVersion: "0.2.0",
      transition: "replacement-required",
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
    const firstRegistration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const firstIdentity = await decodeRegisteredProbe(firstRegistration);
    const host = database.sqlite
      .prepare("select id, probe_id as probeId from managed_hosts")
      .get() as { id: number; probeId: string };
    database.metrics.recordSample({
      bootId: "pre-replacement-boot",
      collectedAtMs: 1_725_000_001_000,
      cpuPercent: 12,
      hostId: host.id,
      probeId: firstIdentity.probeId,
      receivedAtMs: 1_725_000_001_100,
      sequence: 2,
    });
    const enrollmentResponse = await app.request(
      `/api/web/enrollments/manual-reinstall/${host.id}`,
      { headers: { cookie: ownerSession }, method: "POST" },
    );
    expect(enrollmentResponse.status).toBe(201);
    const enrollmentCommand = (await enrollmentResponse.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
      installCommand: string;
    };
    const { enrollmentId, enrollmentToken } = enrollmentCommand;
    expect(enrollmentCommand.installCommand).toContain(enrollmentToken);
    expect(enrollmentCommand.installCommand).not.toContain("&&");
    expect(installCommandEnrollment(enrollmentCommand.installCommand)).toEqual({
      enrollmentToken,
      hubOrigin: "https://hub.example",
      replacementMigration: {
        enrollmentId,
        expectedProbeId: firstIdentity.probeId,
        sourceProbeSha256: release.sourceProbeSha256,
        sourceProbeVersion: "0.1.0",
        targetAssetSetDigest: release.targetAssetSetDigest,
        targetHostId: String(host.id),
        targetProbeVersion: "0.2.0",
      },
      schemaVersion: 1,
    });
    const pendingStatus = await app.request(
      `/api/web/enrollments/${enrollmentId}`,
      {
        headers: { cookie: ownerSession },
      },
    );
    await expect(pendingStatus.json()).resolves.toEqual(
      expect.objectContaining({ replacementMigration: "waiting_host" }),
    );

    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;
    const inspectionResponse = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken,
          installationInspection: {},
        }),
      ).finish(),
      headers: { "content-type": "application/x-protobuf" },
      method: "POST",
    });
    expect(inspectionResponse.status).toBe(200);
    const inspection = RegistrationResponse.decode(
      new Uint8Array(await inspectionResponse.arrayBuffer()),
    ).installationInspection!;
    expect(inspection).toEqual(
      expect.objectContaining({
        enrollmentId,
        sourceProbeSha256: release.sourceProbeSha256,
        sourceProbeVersion: "0.1.0",
        targetHostId: String(host.id),
        targetKind: root.enoki.v1.ProbeEnrollmentTargetKind.MANUAL_REINSTALL,
      }),
    );

    const replacement = await registerProbe(
      app,
      enrollmentToken,
      "replacement-host",
      {},
      {
        registrationAttempt: {
          committedSourceProbeSha256: release.sourceProbeSha256[0]!,
          enrollmentId,
          hostId: String(host.id),
          hubOrigin: "https://hub.example",
          oldProbeId: firstIdentity.probeId,
          sourceProbeVersion: "0.1.0",
          targetAssetSetDigest: release.targetAssetSetDigest,
          targetBundleTarget: release.targetBundles[0]!.target,
          targetManifestSha256: release.targetBundles[0]!.bundleManifestSha256,
          targetProbeVersion: "0.2.0",
        },
        snapshots: false,
      },
    );
    expect(replacement.status).toBe(200);
    const replacementIdentity = await decodeRegisteredProbe(replacement);

    expect(replacementIdentity.probeId).not.toBe(firstIdentity.probeId);
    expect(
      database.sqlite
        .prepare(
          "select id, probe_id as probeId, probe_version as probeVersion from managed_hosts",
        )
        .all(),
    ).toEqual([
      {
        id: host.id,
        probeId: replacementIdentity.probeId,
        probeVersion: null,
      },
    ]);
    expect(
      database.sqlite
        .prepare(
          "select status, used_at_ms as usedAtMs from enrollment_tokens where enrollment_id = ?",
        )
        .get(enrollmentId),
    ).toEqual({ status: "verifying", usedAtMs: expect.any(Number) });
    const verifyingStatus = await app.request(
      `/api/web/enrollments/${enrollmentId}`,
      {
        headers: { cookie: ownerSession },
      },
    );
    await expect(verifyingStatus.json()).resolves.toEqual(
      expect.objectContaining({ replacementMigration: "incomplete" }),
    );

    const ReportRequest = root.enoki.v1.ProbeReportRequest;
    const bootBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "replacement-boot",
        enrollmentId,
        probeAssetBundleVersion: "0.2.0",
        probeConfigurationVersion: "default-v1",
        probeId: replacementIdentity.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [],
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(
            replacementIdentity,
            "/api/probe/report",
            bootBody,
          ),
        )
      ).status,
    ).toBe(200);
    expect(
      database.sqlite
        .prepare("select status from enrollment_tokens where enrollment_id = ?")
        .get(enrollmentId),
    ).toEqual({ status: "verifying" });

    const incompleteHostProfile = sampleHostProfile({
      hostname: "replacement-host",
      probeAssetBundleVersion: "0.2.0",
      probeVersion: "",
    });
    const incompleteObservationBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "replacement-boot",
        enrollmentId,
        metrics: [
          {
            collectedAtMs: nowMs + 2,
            collectorOutcomes: [
              { collectorId: "official.host-profile", state: 1 },
            ],
            sequence: 2,
          },
        ],
        probeAssetBundleVersion: "0.2.0",
        probeConfigurationVersion: "default-v1",
        probeId: replacementIdentity.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: incompleteHostProfile,
            snapshotHash: hashStableHostProfile(incompleteHostProfile),
          },
        ],
      }),
    ).finish();
    expect(
      (
        await app.request(
          "/api/probe/report",
          signedProbeRequest(
            replacementIdentity,
            "/api/probe/report",
            incompleteObservationBody,
          ),
        )
      ).status,
    ).toBe(200);
    expect(
      database.sqlite
        .prepare("select status from enrollment_tokens where enrollment_id = ?")
        .get(enrollmentId),
    ).toEqual({ status: "verifying" });

    const currentHostProfile = sampleHostProfile({
      hostname: "replacement-host",
      probeAssetBundleVersion: "0.2.0",
      probeVersion: "0.2.0",
    });
    const observationBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "replacement-boot",
        enrollmentId,
        metrics: [
          {
            collectedAtMs: nowMs + 3,
            collectorOutcomes: [
              { collectorId: "official.host-profile", state: 1 },
            ],
            sequence: 3,
          },
        ],
        probeAssetBundleVersion: "0.2.0",
        probeConfigurationVersion: "default-v1",
        probeId: replacementIdentity.probeId,
        sequenceEnd: 3,
        sequenceStart: 3,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: currentHostProfile,
            snapshotHash: hashStableHostProfile(currentHostProfile),
          },
        ],
      }),
    ).finish();
    const observationResponse = await app.request(
      "/api/probe/report",
      signedProbeRequest(
        replacementIdentity,
        "/api/probe/report",
        observationBody,
      ),
    );
    expect(observationResponse.status).toBe(200);
    expect(
      database.sqlite
        .prepare("select status from enrollment_tokens where enrollment_id = ?")
        .get(enrollmentId),
    ).toEqual({ status: "ready" });
    const readyStatus = await app.request(
      `/api/web/enrollments/${enrollmentId}`,
      {
        headers: { cookie: ownerSession },
      },
    );
    await expect(readyStatus.json()).resolves.toEqual(
      expect.objectContaining({ replacementMigration: "ready" }),
    );
    expect(
      database.metrics.findSamplesForHost({
        fromCollectedAtMs: 1_725_000_001_000,
        hostId: host.id,
        toCollectedAtMs: 1_725_000_001_000,
      }),
    ).toEqual([expect.objectContaining({ probeId: firstIdentity.probeId })]);
    const replacementAudit = database.audit
      .recent()
      .find(
        (event) => event.action === "probe.manual_reinstall_identity_replaced",
      );
    expect(replacementAudit).toEqual(
      expect.objectContaining({ subjectId: String(host.id) }),
    );
    expect(JSON.parse(replacementAudit?.detailsJson ?? "null")).toEqual(
      expect.objectContaining({
        newProbeId: replacementIdentity.probeId,
        oldProbeId: firstIdentity.probeId,
        targetProbeVersion: "0.2.0",
      }),
    );

    database.close();
  });

  it("replays the exact manual reinstall registration outcome after the first response is lost", async () => {
    const database = await createTemporaryDatabase();
    const nowMs = Date.now();
    const assetDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-registration-replay-"),
    );
    tempRoots.push(assetDir);
    const release = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "0.1.0",
      targetVersion: "0.2.0",
      transition: "replacement-required",
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
    const firstRegistration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
      "response-loss-host",
      {},
      { probeVersion: "0.1.0" },
    );
    const firstIdentity = await decodeRegisteredProbe(firstRegistration);
    const host = database.sqlite
      .prepare("select id, probe_id as probeId from managed_hosts")
      .get() as { id: number; probeId: string };
    const enrollmentToken = `enk_enroll_${"r".repeat(32)}`;
    const enrollmentId = `enr_${"r".repeat(24)}`;
    expect(
      database.enrollments.createPending({
        createdAtMs: nowMs,
        enrollmentId,
        expiresAtMs: nowMs + 3_600_000,
        target: {
          expectedHubOrigin: "https://hub.example",
          expectedProbeId: firstIdentity.probeId,
          expectedProbeVersion: "0.1.0",
          hostId: host.id,
          kind: "manual_reinstall",
          sourceProbeSha256: release.sourceProbeSha256,
          targetAssetSetDigest: release.targetAssetSetDigest,
          targetProbeVersion: "0.2.0",
        },
        tokenHash: hashSecret(enrollmentToken),
      }).kind,
    ).toBe("created");

    const replacementIdentity = createTestProbeIdentity();
    const attemptFields = {
      candidatePublicKeyPem: replacementIdentity.publicKeyPem,
      committedSourceProbeSha256: release.sourceProbeSha256[0]!,
      enrollmentId,
      hostId: String(host.id),
      hubOrigin: "https://hub.example",
      nonce: "a".repeat(64),
      oldProbeId: firstIdentity.probeId,
      replacementCommitSha256: "d".repeat(64),
      schemaVersion: 1,
      sourceProbeVersion: "0.1.0",
      targetAssetSetDigest: release.targetAssetSetDigest,
      targetBundleTarget: release.targetBundles[0]!.target,
      targetManifestSha256: release.targetBundles[0]!.bundleManifestSha256,
      targetProbeVersion: "0.2.0",
    };
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const signedBody = ({
      corruptSignature = false,
      identity = replacementIdentity,
      overrides = {},
      token = enrollmentToken,
    }: {
      corruptSignature?: boolean;
      identity?: ReturnType<typeof createTestProbeIdentity>;
      overrides?: Partial<typeof attemptFields>;
      token?: string;
    } = {}) => {
      const canonicalAttempt = root.enoki.v1.ProbeRegistrationAttempt.encode(
        root.enoki.v1.ProbeRegistrationAttempt.create({
          ...attemptFields,
          candidatePublicKeyPem: identity.publicKeyPem,
          ...overrides,
        }),
      ).finish();
      const signer = createSign("RSA-SHA256");
      signer.update(
        `enoki.probe-registration-attempt.v1\n${createHash("sha256")
          .update(canonicalAttempt)
          .digest("hex")}`,
      );
      signer.end();
      const candidateSignature = signer.sign(identity.privateKeyPem);
      if (corruptSignature) {
        candidateSignature[0] = candidateSignature[0]! ^ 1;
      }
      return RegistrationRequest.encode(
        RegistrationRequest.create({
          candidateSignature,
          canonicalAttempt,
          enrollmentToken: token,
          probePublicKeyPem: identity.publicKeyPem,
        }),
      ).finish();
    };
    const requestBody = signedBody();
    const request = () =>
      app.request("/api/probe/register", {
        body: requestBody,
        headers: { "content-type": "application/x-protobuf" },
        method: "POST",
      });

    const committed = await request();
    expect(committed.status).toBe(200);
    const committedBody = new Uint8Array(await committed.arrayBuffer());

    // 调用方永远看不到 `committedBody`，这等同于网络在 Hub 事务提交后
    // 丢失了响应。
    const replay = await request();
    expect(replay.status).toBe(200);
    expect(new Uint8Array(await replay.arrayBuffer())).toEqual(committedBody);

    const committedOutcome =
      root.enoki.v1.ProbeRegistrationResponse.decode(committedBody);
    const registrationState = () => ({
      audits: database.sqlite
        .prepare("select * from audit_log order by id")
        .all(),
      enrollment: database.sqlite
        .prepare("select * from enrollment_tokens where enrollment_id = ?")
        .get(enrollmentId),
      host: database.sqlite
        .prepare("select * from managed_hosts where id = ?")
        .get(host.id),
    });
    const committedState = registrationState();
    const otherIdentity = createTestProbeIdentity();
    const mismatchBodies = [
      {
        body: signedBody({ identity: otherIdentity }),
        field: "candidateKey",
      },
      {
        body: signedBody({ overrides: { nonce: "b".repeat(64) } }),
        field: "nonce",
      },
      {
        body: signedBody({
          overrides: { enrollmentId: `enr_${"x".repeat(24)}` },
        }),
        field: "enrollmentId",
      },
      {
        body: signedBody({ token: `enk_enroll_${"x".repeat(32)}` }),
        field: "enrollmentToken",
      },
      {
        body: signedBody({
          overrides: { hubOrigin: "https://other.example" },
        }),
        field: "hubOrigin",
      },
      {
        body: signedBody({ overrides: { hostId: String(host.id + 1) } }),
        field: "hostId",
      },
      {
        body: signedBody({
          overrides: { oldProbeId: "probe_mismatched_previous_identity" },
        }),
        field: "oldProbeId",
      },
      {
        body: signedBody({
          overrides: { sourceProbeVersion: "0.1.1" },
        }),
        field: "sourceProbeVersion",
      },
      {
        body: signedBody({
          overrides: { committedSourceProbeSha256: "e".repeat(64) },
        }),
        field: "committedSourceProbeSha256",
      },
      {
        body: signedBody({
          overrides: { targetProbeVersion: "0.2.1" },
        }),
        field: "targetProbeVersion",
      },
      {
        body: signedBody({
          overrides: {
            targetAssetSetDigest: `sha256:${"e".repeat(64)}`,
          },
        }),
        field: "targetAssetSetDigest",
      },
      {
        body: signedBody({
          overrides: {
            targetBundleTarget:
              release.targetBundles[0]!.target === "aarch64-unknown-linux-gnu"
                ? "x86_64-unknown-linux-gnu"
                : "aarch64-unknown-linux-gnu",
          },
        }),
        field: "targetBundleTarget",
      },
      {
        body: signedBody({
          overrides: { targetManifestSha256: "e".repeat(64) },
        }),
        field: "targetManifestSha256",
      },
      {
        body: signedBody({
          overrides: { replacementCommitSha256: "e".repeat(64) },
        }),
        field: "replacementCommitSha256",
      },
      {
        body: signedBody({ corruptSignature: true }),
        field: "candidateSignature",
      },
    ];
    for (const { body, field } of mismatchBodies) {
      const mismatch = await app.request("/api/probe/register", {
        body,
        headers: { "content-type": "application/x-protobuf" },
        method: "POST",
      });
      expect(mismatch.status, field).toBe(401);
      expect(mismatch.headers.get("content-type"), field).toContain(
        "application/json",
      );
      const mismatchBody = await mismatch.text();
      expect(mismatchBody, field).toBe(
        JSON.stringify({ error: "invalid_enrollment_token" }),
      );
      for (const outcomeValue of [
        firstIdentity.probeId,
        committedOutcome.probeId,
        committedOutcome.enrollmentId,
        committedOutcome.hostId,
      ]) {
        expect(mismatchBody, field).not.toContain(outcomeValue);
      }
      expect(new TextEncoder().encode(mismatchBody), field).not.toEqual(
        committedBody,
      );
      expect(mismatchBody, field).not.toContain(
        Buffer.from(committedBody).toString("base64"),
      );
      expect(mismatchBody, field).not.toContain(
        Buffer.from(committedBody).toString("hex"),
      );
      expect(registrationState(), field).toEqual(committedState);
    }
    expect(mismatchBodies.map(({ field }) => field)).toEqual([
      "candidateKey",
      "nonce",
      "enrollmentId",
      "enrollmentToken",
      "hubOrigin",
      "hostId",
      "oldProbeId",
      "sourceProbeVersion",
      "committedSourceProbeSha256",
      "targetProbeVersion",
      "targetAssetSetDigest",
      "targetBundleTarget",
      "targetManifestSha256",
      "replacementCommitSha256",
      "candidateSignature",
    ]);
    await rm(assetDir, { force: true, recursive: true });
    const replayWithoutCurrentRelease = await request();
    expect(replayWithoutCurrentRelease.status).toBe(200);
    expect(
      new Uint8Array(await replayWithoutCurrentRelease.arrayBuffer()),
    ).toEqual(committedBody);
    expect(
      database.sqlite
        .prepare(
          "select count(*) as count from audit_log where action = 'probe.manual_reinstall_identity_replaced'",
        )
        .get(),
    ).toEqual({ count: 1 });
    expect(
      database.sqlite
        .prepare("select probe_id as probeId from managed_hosts where id = ?")
        .get(host.id),
    ).toEqual({
      probeId:
        root.enoki.v1.ProbeRegistrationResponse.decode(committedBody).probeId,
    });

    database.close();
  });

  it("rolls back manual token consumption and identity replacement when the replacement audit cannot be persisted", async () => {
    const database = await createTemporaryDatabase();
    const nowMs = Date.now();
    const assetDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-registration-rollback-"),
    );
    tempRoots.push(assetDir);
    const release = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "0.1.0",
      targetVersion: "0.2.0",
      transition: "replacement-required",
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
    const firstRegistration = await registerProbe(
      app,
      await createEnrollmentToken(app, ownerSession),
    );
    const firstIdentity = await decodeRegisteredProbe(firstRegistration);
    const host = database.sqlite
      .prepare("select id, probe_id as probeId from managed_hosts")
      .get() as { id: number; probeId: string };
    const enrollmentToken = `enk_enroll_${"t".repeat(32)}`;
    const enrollmentId = `enr_${"t".repeat(24)}`;
    expect(
      database.enrollments.createPending({
        createdAtMs: nowMs,
        enrollmentId,
        expiresAtMs: nowMs + 3_600_000,
        target: {
          expectedHubOrigin: "https://hub.example",
          expectedProbeId: firstIdentity.probeId,
          expectedProbeVersion: "0.1.0",
          hostId: host.id,
          kind: "manual_reinstall",
          sourceProbeSha256: release.sourceProbeSha256,
          targetAssetSetDigest: release.targetAssetSetDigest,
          targetProbeVersion: "0.2.0",
        },
        tokenHash: hashSecret(enrollmentToken),
      }).kind,
    ).toBe("created");
    database.sqlite.exec(`
      create trigger reject_manual_reinstall_audit
      before insert on audit_log
      when new.action = 'probe.manual_reinstall_identity_replaced'
      begin
        select raise(abort, 'audit unavailable');
      end
    `);

    const response = await registerProbe(
      app,
      enrollmentToken,
      "replacement-host",
      {},
      {
        registrationAttempt: {
          committedSourceProbeSha256: release.sourceProbeSha256[0]!,
          enrollmentId,
          hostId: String(host.id),
          hubOrigin: "https://hub.example",
          oldProbeId: firstIdentity.probeId,
          sourceProbeVersion: "0.1.0",
          targetAssetSetDigest: release.targetAssetSetDigest,
          targetBundleTarget: release.targetBundles[0]!.target,
          targetManifestSha256: release.targetBundles[0]!.bundleManifestSha256,
          targetProbeVersion: "0.2.0",
        },
        snapshots: false,
      },
    );

    expect(response.status).toBe(500);
    expect(
      database.sqlite
        .prepare(
          "select status, used_at_ms as usedAtMs, managed_host_id as managedHostId from enrollment_tokens where enrollment_id = ?",
        )
        .get(enrollmentId),
    ).toEqual({ managedHostId: null, status: "pending", usedAtMs: null });
    expect(
      database.sqlite
        .prepare("select probe_id as probeId from managed_hosts where id = ?")
        .get(host.id),
    ).toEqual({ probeId: firstIdentity.probeId });
    expect(
      database.sqlite
        .prepare(
          "select count(*) as count from audit_log where action = 'probe.manual_reinstall_identity_replaced'",
        )
        .get(),
    ).toEqual({ count: 0 });

    database.close();
  });

  it("re-enrolls an offline Host with a new formal Probe Identity without creating a second Host", async () => {
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
    const firstEnrollmentToken = await createEnrollmentToken(app, ownerSession);
    const firstRegistration = await registerProbe(app, firstEnrollmentToken);
    const firstIdentity = await decodeRegisteredProbe(firstRegistration);
    const host = database.sqlite
      .prepare("select id, probe_id as probeId from managed_hosts")
      .get() as { id: number; probeId: string };
    expect(
      database.hosts.insertProbeRequestNonce({
        expiresAtMs: Date.now() + 60_000,
        nonce: "a".repeat(32),
        nowMs: Date.now(),
        probeId: firstIdentity.probeId,
      }),
    ).toBe(true);
    database.hosts.updateMetadata(host.id, {
      connectAddress: "203.0.113.42",
      description: "Owner-managed description",
      displayName: "Owner-managed Host",
    });
    const configuration = database.probeConfigurations.updateHostOverride(
      host.id,
      {
        enabledCollectorIds: [],
        metricsCollectionIntervalSeconds: 30,
      },
      1_725_000_001_000,
    );
    database.metrics.recordSample({
      bootId: "old-identity-boot",
      collectedAtMs: 1_725_000_001_000,
      cpuPercent: 12,
      hostId: host.id,
      probeId: firstIdentity.probeId,
      receivedAtMs: 1_725_000_001_100,
      sequence: 2,
    });
    database.audit.record({
      action: "test.history.preserved",
      actor: "owner",
      occurredAtMs: 1_725_000_001_200,
      outcome: "success",
      subjectId: String(host.id),
      subjectType: "host",
    });

    const enrollmentResponse = await app.request("/api/web/enrollments", {
      body: JSON.stringify({
        target: { hostId: host.id, kind: "existing_host" },
      }),
      headers: {
        "content-type": "application/json",
        cookie: ownerSession,
      },
      method: "POST",
    });
    expect(enrollmentResponse.status).toBe(201);
    const enrollment = (await enrollmentResponse.json()) as {
      enrollmentToken: string;
    };
    database.hosts.recordReport(host.id, {
      clockSkewDetected: true,
      lastClockSkewMs: 5_000,
      lastReportAtMs: Date.now(),
      probeConfigurationError: {
        errorCode: "old_identity_configuration_error",
        failedVersion: "default-v1",
        message: "reported by the old Probe",
        reportedAtMs: Date.now(),
      },
    });

    const replacementRegistration = await registerProbe(
      app,
      enrollment.enrollmentToken,
      "re-enrolled-host",
    );
    expect(replacementRegistration.status).toBe(200);
    const replacementIdentity = await decodeRegisteredProbe(
      replacementRegistration,
    );

    const replacementHostSummary = await app.request("/api/web/hosts", {
      headers: { cookie: ownerSession },
    });
    await expect(replacementHostSummary.json()).resolves.toEqual({
      hosts: [
        expect.objectContaining({
          clockSkew: { detected: false, lastDeltaMs: null },
          id: host.id,
          lastReportAtMs: null,
          status: "offline",
        }),
      ],
    });

    expect(replacementIdentity.probeId).not.toBe(firstIdentity.probeId);
    expect(
      database.sqlite
        .prepare(
          "select id, probe_id as probeId, display_name as displayName, description, connect_address as connectAddress from managed_hosts",
        )
        .all(),
    ).toEqual([
      {
        connectAddress: "203.0.113.42",
        description: "Owner-managed description",
        displayName: "Owner-managed Host",
        id: host.id,
        probeId: replacementIdentity.probeId,
      },
    ]);
    expect(
      database.metrics.findSamplesForHost({
        fromCollectedAtMs: 1_725_000_001_000,
        hostId: host.id,
        toCollectedAtMs: 1_725_000_001_000,
      }),
    ).toEqual([expect.objectContaining({ probeId: firstIdentity.probeId })]);
    expect(database.probeConfigurations.getEffectiveForHost(host.id)).toEqual(
      configuration,
    );
    expect(
      database.audit
        .recent()
        .some((event) => event.action === "test.history.preserved"),
    ).toBe(true);
    expect(
      database.sqlite
        .prepare("select count(*) as count from probe_request_nonces")
        .get(),
    ).toEqual({ count: 0 });

    const ConfigurationRequest = root.enoki.v1.ProbeConfigurationRequest;
    const configBody = (probeId: string) =>
      ConfigurationRequest.encode(
        ConfigurationRequest.create({ currentVersion: "", probeId }),
      ).finish();
    const oldIdentityAuthentication = await app.request(
      "/api/probe/config",
      signedProbeRequest(
        firstIdentity,
        "/api/probe/config",
        configBody(firstIdentity.probeId),
      ),
    );
    expect(oldIdentityAuthentication.status).toBe(401);
    const newIdentityAuthentication = await app.request(
      "/api/probe/config",
      signedProbeRequest(
        replacementIdentity,
        "/api/probe/config",
        configBody(replacementIdentity.probeId),
      ),
    );
    expect(newIdentityAuthentication.status).toBe(200);

    database.close();
  });

  it("creates ExistingHost Enrollments only while the real target Host is active and offline", async () => {
    const database = await createTemporaryDatabase();
    let nowMs = 1_725_000_000_000;
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      hostStatus: { offlineAfterMs: 300, staleAfterMs: 100 },
      now: () => nowMs,
    });
    const ownerSession = await loginOwner(app);
    const firstEnrollmentToken = await createEnrollmentToken(app, ownerSession);
    const firstRegistration = await registerProbe(app, firstEnrollmentToken);
    const firstIdentity = await decodeRegisteredProbe(firstRegistration);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(firstIdentity.probeId) as { id: number };
    const createExisting = () =>
      app.request("/api/web/enrollments", {
        body: JSON.stringify({
          target: { hostId: host.id, kind: "existing_host" },
        }),
        headers: {
          "content-type": "application/json",
          cookie: ownerSession,
        },
        method: "POST",
      });

    database.hosts.recordReport(host.id, { lastReportAtMs: nowMs });
    expect((await createExisting()).status).toBe(409);

    nowMs += 200;
    expect((await createExisting()).status).toBe(409);

    nowMs += 101;
    expect((await createExisting()).status).toBe(201);

    expect(database.hosts.softDelete(host.id, nowMs)).not.toBeNull();
    expect((await createExisting()).status).toBe(409);

    database.close();
  });

  it("rejects an ExistingHost Enrollment when the target is soft-deleted before registration", async () => {
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
    const firstEnrollmentToken = await createEnrollmentToken(app, ownerSession);
    const firstRegistration = await registerProbe(app, firstEnrollmentToken);
    const firstIdentity = await decodeRegisteredProbe(firstRegistration);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(firstIdentity.probeId) as { id: number };

    const enrollmentResponse = await app.request("/api/web/enrollments", {
      body: JSON.stringify({
        target: { hostId: host.id, kind: "existing_host" },
      }),
      headers: {
        "content-type": "application/json",
        cookie: ownerSession,
      },
      method: "POST",
    });
    const enrollment = (await enrollmentResponse.json()) as {
      enrollmentToken: string;
    };
    expect(database.hosts.softDelete(host.id, Date.now())).not.toBeNull();

    const rejected = await registerProbe(app, enrollment.enrollmentToken);
    expect(rejected.status).toBe(401);
    await expect(rejected.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });
    expect(
      database.sqlite
        .prepare("select count(*) as count from managed_hosts")
        .get(),
    ).toEqual({ count: 1 });
    expect(
      database.sqlite
        .prepare(
          "select deleted_at_ms as deletedAtMs from managed_hosts where id = ?",
        )
        .get(host.id),
    ).toEqual({ deletedAtMs: expect.any(Number) });

    database.close();
  });

  it("serializes concurrent ExistingHost creation and registration without creating a second Host", async () => {
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
    const firstEnrollmentToken = await createEnrollmentToken(app, ownerSession);
    const firstRegistration = await registerProbe(app, firstEnrollmentToken);
    const firstIdentity = await decodeRegisteredProbe(firstRegistration);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(firstIdentity.probeId) as { id: number };

    const creations = await Promise.all(
      [0, 1].map(() =>
        app.request("/api/web/enrollments", {
          body: JSON.stringify({
            target: { hostId: host.id, kind: "existing_host" },
          }),
          headers: {
            "content-type": "application/json",
            cookie: ownerSession,
          },
          method: "POST",
        }),
      ),
    );
    expect(creations.map((response) => response.status)).toEqual([201, 201]);
    const creationBodies = await Promise.all(
      creations.map(
        async (response) =>
          response.json() as Promise<{
            enrollmentId: string;
            enrollmentToken: string;
          }>,
      ),
    );
    const pending = database.sqlite
      .prepare(
        "select enrollment_id as enrollmentId from enrollment_tokens where target_host_id = ? and status = 'pending'",
      )
      .get(host.id) as { enrollmentId: string };
    const active = creationBodies.find(
      (creation) => creation.enrollmentId === pending.enrollmentId,
    );
    expect(active).toBeDefined();
    expect(
      database.sqlite
        .prepare(
          "select status, rejection_code as rejectionCode from enrollment_tokens where target_host_id = ? order by id",
        )
        .all(host.id),
    ).toEqual([
      { rejectionCode: "superseded", status: "rejected" },
      { rejectionCode: null, status: "pending" },
    ]);

    const registrations = await Promise.all([
      registerProbe(app, active?.enrollmentToken ?? ""),
      registerProbe(app, active?.enrollmentToken ?? ""),
    ]);
    expect(registrations.map((response) => response.status).sort()).toEqual([
      200, 401,
    ]);
    expect(
      database.sqlite
        .prepare("select count(*) as count from managed_hosts")
        .get(),
    ).toEqual({ count: 1 });

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
    expect(decoded.initialConfiguration).toEqual(
      expect.objectContaining({
        enabledCollectorIds: expect.arrayContaining([
          "official.cpu",
          "official.memory",
          "official.disk-health",
        ]),
      }),
    );
    expect(decoded.initialConfiguration?.enabledCollectorIds).not.toContain(
      "official.host-profile",
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

  it("inspects a pending NewHost Enrollment without mutating Enrollment, Host, or identity state", async () => {
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
    const before = database.sqlite
      .prepare(
        "select status, used_at_ms as usedAtMs from enrollment_tokens where token_hash = ?",
      )
      .get(hashSecret(enrollmentToken));
    const auditCount = database.audit.recent().length;
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;

    const response = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken,
          installationInspection: {},
        }),
      ).finish(),
      headers: { "content-type": "application/x-protobuf" },
      method: "POST",
    });

    expect(response.status).toBe(200);
    const inspected = RegistrationResponse.decode(
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(inspected.probeId).toBe("");
    expect(inspected.installationInspection).toEqual(
      expect.objectContaining({
        targetKind: root.enoki.v1.ProbeEnrollmentTargetKind.NEW_HOST,
      }),
    );
    expect(
      database.sqlite
        .prepare(
          "select status, used_at_ms as usedAtMs from enrollment_tokens where token_hash = ?",
        )
        .get(hashSecret(enrollmentToken)),
    ).toEqual(before);
    expect(
      database.sqlite
        .prepare("select count(*) as count from managed_hosts")
        .get(),
    ).toEqual({ count: 0 });
    expect(database.audit.recent()).toHaveLength(auditCount);

    database.close();
  });

  it("inspects an ExistingHost Enrollment after the Host becomes online without changing its identity", async () => {
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
    const firstEnrollmentToken = await createEnrollmentToken(app, ownerSession);
    const firstRegistration = await registerProbe(app, firstEnrollmentToken);
    const firstIdentity = await decodeRegisteredProbe(firstRegistration);
    const host = database.sqlite
      .prepare("select id, probe_id as probeId from managed_hosts")
      .get() as { id: number; probeId: string };
    const created = await app.request("/api/web/enrollments", {
      body: JSON.stringify({
        target: { hostId: host.id, kind: "existing_host" },
      }),
      headers: { "content-type": "application/json", cookie: ownerSession },
      method: "POST",
    });
    expect(created.status).toBe(201);
    const { enrollmentToken } = (await created.json()) as {
      enrollmentToken: string;
    };
    database.hosts.recordReport(host.id, { lastReportAtMs: Date.now() });
    const enrollmentBefore = database.sqlite
      .prepare(
        "select status, used_at_ms as usedAtMs from enrollment_tokens where token_hash = ?",
      )
      .get(hashSecret(enrollmentToken));
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;

    const inspected = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken,
          installationInspection: {},
        }),
      ).finish(),
      headers: { "content-type": "application/x-protobuf" },
      method: "POST",
    });

    expect(inspected.status).toBe(200);
    expect(
      RegistrationResponse.decode(new Uint8Array(await inspected.arrayBuffer()))
        .installationInspection,
    ).toEqual(
      expect.objectContaining({
        targetKind: root.enoki.v1.ProbeEnrollmentTargetKind.EXISTING_HOST,
      }),
    );
    expect(
      database.sqlite
        .prepare("select id, probe_id as probeId from managed_hosts")
        .get(),
    ).toEqual({ id: host.id, probeId: firstIdentity.probeId });
    expect(
      database.sqlite
        .prepare(
          "select status, used_at_ms as usedAtMs from enrollment_tokens where token_hash = ?",
        )
        .get(hashSecret(enrollmentToken)),
    ).toEqual(enrollmentBefore);

    database.close();
  });

  it("rejects unknown and expired installation inspections without changing pending Enrollment state", async () => {
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
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const inspect = (token: string) =>
      app.request("/api/probe/register", {
        body: RegistrationRequest.encode(
          RegistrationRequest.create({
            enrollmentToken: token,
            installationInspection: {},
          }),
        ).finish(),
        headers: { "content-type": "application/x-protobuf" },
        method: "POST",
      });

    const unknown = await inspect("enk_enroll_unknown");
    expect(unknown.status).toBe(401);
    await expect(unknown.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });

    nowMs += 15 * 60 * 1000;
    const expired = await inspect(enrollmentToken);
    expect(expired.status).toBe(401);
    await expect(expired.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });
    expect(
      database.sqlite
        .prepare(
          "select status, used_at_ms as usedAtMs, expired_at_ms as expiredAtMs from enrollment_tokens where token_hash = ?",
        )
        .get(hashSecret(enrollmentToken)),
    ).toEqual({ expiredAtMs: null, status: "pending", usedAtMs: null });

    database.close();
  });

  it("rejects a deleted ExistingHost during inspection and final registration without reviving it", async () => {
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
    const firstEnrollmentToken = await createEnrollmentToken(app, ownerSession);
    const firstRegistration = await registerProbe(app, firstEnrollmentToken);
    const firstIdentity = await decodeRegisteredProbe(firstRegistration);
    const host = database.sqlite
      .prepare("select id from managed_hosts where probe_id = ?")
      .get(firstIdentity.probeId) as { id: number };
    const created = await app.request("/api/web/enrollments", {
      body: JSON.stringify({
        target: { hostId: host.id, kind: "existing_host" },
      }),
      headers: { "content-type": "application/json", cookie: ownerSession },
      method: "POST",
    });
    expect(created.status).toBe(201);
    const { enrollmentToken } = (await created.json()) as {
      enrollmentToken: string;
    };
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const inspectionBody = RegistrationRequest.encode(
      RegistrationRequest.create({
        enrollmentToken,
        installationInspection: {},
      }),
    ).finish();
    const inspected = await app.request("/api/probe/register", {
      body: inspectionBody,
      headers: { "content-type": "application/x-protobuf" },
      method: "POST",
    });
    expect(inspected.status).toBe(200);

    expect(database.hosts.softDelete(host.id, Date.now())).not.toBeNull();
    const deletedInspection = await app.request("/api/probe/register", {
      body: inspectionBody,
      headers: { "content-type": "application/x-protobuf" },
      method: "POST",
    });
    expect(deletedInspection.status).toBe(401);

    const registration = await registerProbe(app, enrollmentToken);
    expect(registration.status).toBe(401);
    await expect(registration.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });
    expect(
      database.sqlite
        .prepare("select count(*) as count from managed_hosts")
        .get(),
    ).toEqual({ count: 1 });
    expect(
      database.sqlite
        .prepare(
          "select deleted_at_ms as deletedAtMs from managed_hosts where id = ?",
        )
        .get(host.id),
    ).toEqual({ deletedAtMs: expect.any(Number) });

    database.close();
  });

  it("stores a Host Profile Snapshot Collector payload from registration and exposes typed Host detail", async () => {
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
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const identity = createTestProbeIdentity();
    const hostProfile = sampleHostProfileSnapshot({
      hostname: "snapshot-host-01",
      kernel: "6.9.0",
      probeVersion: "0.2.0",
    });
    const hostProfileHash = hashStableHostProfile(hostProfile);

    const response = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken,
          probePublicKeyPem: identity.publicKeyPem,
          snapshots: [
            {
              collectorId: "official.host-profile",
              snapshotHash: hostProfileHash,
              hostProfile: HostProfileSnapshot.create(hostProfile),
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

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(hostsResponse.status).toBe(200);
    const hostsBody = (await hostsResponse.json()) as {
      hosts: Array<{ id: number }>;
    };
    const hostId = hostsBody.hosts[0]?.id;
    expect(hostId).toEqual(expect.any(Number));
    if (hostId === undefined) {
      throw new Error("registered Host is missing");
    }

    const detailResponse = await app.request(`/api/web/hosts/${hostId}`, {
      headers: {
        cookie: ownerSession,
      },
    });

    expect(detailResponse.status).toBe(200);
    const storedHostProfile = database.sqlite
      .prepare(
        "select snapshot_hash, hostname, probe_version from official_host_profiles where managed_host_id = ?",
      )
      .get(hostId) as {
      hostname: string;
      probe_version: string;
      snapshot_hash: string;
    };
    expect(storedHostProfile).toEqual({
      hostname: "snapshot-host-01",
      probe_version: "0.2.0",
      snapshot_hash: hostProfileHash,
    });
    await expect(detailResponse.json()).resolves.toEqual({
      host: expect.objectContaining({
        displayName: "snapshot-host-01",
        hostProfile: expect.objectContaining({
          architecture: "x86_64",
          cpuCount: 2,
          hostname: "snapshot-host-01",
          kernel: "6.9.0",
          memoryTotalBytes: 2_147_483_648,
          os: "linux",
          probeVersion: "0.2.0",
        }),
        probeVersion: "0.2.0",
        system: "linux 6.9.0 x86_64",
      }),
    });

    database.close();
  });

  it("accepts a Host Profile Snapshot Collector registration with the Rust canonical fixture hash", async () => {
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
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const identity = createTestProbeIdentity();
    const hostProfile = hostProfileCrossRuntimeCanonicalFixture();

    const response = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken,
          probePublicKeyPem: identity.publicKeyPem,
          snapshots: [
            {
              collectorId: "official.host-profile",
              hostProfile: HostProfileSnapshot.create(hostProfile),
              snapshotHash: hostProfileCrossRuntimeCanonicalHash,
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

  it("rejects a Host Profile Snapshot Collector hash mismatch without consuming the Enrollment Token", async () => {
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
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const identity = createTestProbeIdentity();

    const response = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken,
          probePublicKeyPem: identity.publicKeyPem,
          snapshots: [
            {
              collectorId: "official.host-profile",
              snapshotHash:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              hostProfile: HostProfileSnapshot.create(
                sampleHostProfileSnapshot({
                  hostname: "snapshot-host-01",
                }),
              ),
            },
          ],
        }),
      ).finish(),
      headers: {
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "snapshot_hash_mismatch",
    });

    const retryResponse = await registerProbe(app, enrollmentToken);
    expect(retryResponse.status).toBe(200);

    database.close();
  });

  it("rejects registration with more than one full Host Profile Snapshot", async () => {
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
    const identity = createTestProbeIdentity();
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const first = sampleHostProfileSnapshot({ hostname: "first-profile" });
    const second = sampleHostProfileSnapshot({ hostname: "second-profile" });

    const response = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken,
          probePublicKeyPem: identity.publicKeyPem,
          snapshots: [
            {
              collectorId: "official.host-profile",
              hostProfile: first,
              snapshotHash: hashStableHostProfile(first),
            },
            {
              collectorId: "official.host-profile",
              hostProfile: second,
              snapshotHash: hashStableHostProfile(second),
            },
          ],
        }),
      ).finish(),
      headers: { "content-type": "application/x-protobuf" },
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "malformed_probe_registration",
    });
    expect(
      database.sqlite
        .prepare("select count(*) as count from managed_hosts")
        .get(),
    ).toEqual({ count: 0 });

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
          snapshots: [
            {
              collectorId: "official.host-profile",
              hostProfile: {
                architecture: "x86_64",
                hostname: "managed-host-01",
                kernel: "6.8.0",
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

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual({
      error: "invalid_enrollment_token",
    });

    database.close();
  });

  it("accepts identity-only registration and keeps readiness pending for Runtime Host Profile", async () => {
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
    const identity = createTestProbeIdentity();
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;

    const registered = await app.request("/api/probe/register", {
      body: RegistrationRequest.encode(
        RegistrationRequest.create({
          enrollmentToken,
          probePublicKeyPem: identity.publicKeyPem,
        }),
      ).finish(),
      headers: {
        "content-type": "application/x-protobuf",
      },
      method: "POST",
    });

    expect(registered.status).toBe(200);
    expect(
      database.sqlite
        .prepare(
          "select status, used_at_ms as usedAtMs, managed_host_id as hostId, verification_deadline_at_ms as verificationDeadlineAtMs from enrollment_tokens",
        )
        .get(),
    ).toEqual({
      hostId: expect.any(Number),
      status: "verifying",
      usedAtMs: expect.any(Number),
      verificationDeadlineAtMs: expect.any(Number),
    });
    expect(
      database.sqlite
        .prepare("select count(*) as count from managed_hosts")
        .get(),
    ).toEqual({ count: 1 });

    database.close();
  });

  it("commits NewHost registration, Host Profile, and verifying Enrollment association together", async () => {
    const database = await createTemporaryDatabase();
    let nowMs = 1_725_000_000_000;
    const registeredAtMs = nowMs;
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
      headers: { cookie: ownerSession },
      method: "POST",
    });
    const enrollment = (await created.json()) as {
      enrollmentId: string;
      enrollmentToken: string;
    };

    const registration = await registerProbe(app, enrollment.enrollmentToken);
    expect(registration.status).toBe(200);
    expect(
      database.sqlite
        .prepare(
          `select
            enrollment_tokens.status as status,
            enrollment_tokens.used_at_ms as usedAtMs,
            enrollment_tokens.managed_host_id as hostId,
            enrollment_tokens.verification_deadline_at_ms as verificationDeadlineAtMs,
            (select count(*) from official_host_profiles where managed_host_id = enrollment_tokens.managed_host_id) as profiles
          from enrollment_tokens where enrollment_id = ?`,
        )
        .get(enrollment.enrollmentId),
    ).toEqual({
      hostId: 1,
      profiles: 1,
      status: "verifying",
      usedAtMs: registeredAtMs,
      verificationDeadlineAtMs: registeredAtMs + 60_000,
    });

    nowMs += 60_000;
    const timedOut = await app.request(
      `/api/web/enrollments/${enrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    await expect(timedOut.json()).resolves.toEqual(
      expect.objectContaining({
        rejection: {
          code: "probe_startup_timeout",
          message: null,
        },
        status: "rejected",
      }),
    );

    database.close();
  });

  it("rolls back token consumption and Host creation when Host Profile persistence fails", async () => {
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
    database.sqlite.exec(`
      create trigger reject_enrollment_host_profile
      before insert on official_host_profiles
      begin
        select raise(abort, 'forced Host Profile write failure');
      end;
    `);

    const response = await registerProbe(app, enrollmentToken);

    expect(response.status).toBe(500);
    expect(
      database.sqlite
        .prepare(
          "select status, used_at_ms as usedAtMs, managed_host_id as hostId, verification_deadline_at_ms as verificationDeadlineAtMs from enrollment_tokens",
        )
        .get(),
    ).toEqual({
      hostId: null,
      status: "pending",
      usedAtMs: null,
      verificationDeadlineAtMs: null,
    });
    expect(
      database.sqlite
        .prepare("select count(*) as count from managed_hosts")
        .get(),
    ).toEqual({ count: 0 });

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
    expect(configuration).toEqual(
      expect.objectContaining({
        enabledCollectorIds: expect.arrayContaining([
          "official.cpu",
          "official.memory",
          "official.disk-health",
        ]),
      }),
    );
    expect(configuration.enabledCollectorIds).not.toContain(
      "official.host-profile",
    );

    database.close();
  });

  it("asks a Probe for full Host Profile when a report hash is unknown", async () => {
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

    const startupHostProfile = sampleHostProfile();
    const startupBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
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
          signedProbeRequest(registration, "/api/probe/report", startupBody),
        )
      ).status,
    ).toBe(200);

    const reportBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 2,
        sequenceStart: 2,
        snapshots: [
          {
            collectorId: "official.host-profile",
            snapshotHash:
              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          },
        ],
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
    expect(acknowledgement.requestedSnapshotCollectorIds).toEqual([
      "official.host-profile",
    ]);
    expect(acknowledgement.acceptedSequenceEnd.toString()).toBe("2");
    expect(acknowledgement.currentProbeConfigurationVersion).toBe("default-v1");
    expect(acknowledgement.serverTimeMs.toString()).toBe("1725000000000");

    database.close();
  });

  it("stores a changed full Host Profile snapshot from a Probe report", async () => {
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
    const changedHostProfile = HostProfileSnapshot.create({
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
    const changedHostProfileHash = hashStableHostProfile(changedHostProfile);
    const registration = await decodeRegisteredProbe(registrationResponse);

    const reportBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: changedHostProfile,
            snapshotHash: changedHostProfileHash,
          },
        ],
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
    expect(acknowledgement.requestedSnapshotCollectorIds).toEqual([]);

    const storedHost = database.sqlite
      .prepare(
        "select hostname, probe_version, cpu_count, cpu_model, memory_total_bytes from managed_hosts",
      )
      .get() as {
      cpu_count: number;
      cpu_model: string;
      hostname: string;
      memory_total_bytes: number;
      probe_version: string;
    };
    const storedHostId = database.sqlite
      .prepare("select id from managed_hosts where hostname = ?")
      .get("renamed-host") as { id: number };
    expect(storedHost).toEqual(
      expect.objectContaining({
        cpu_count: 4,
        cpu_model: "AMD EPYC 7B13",
        hostname: "renamed-host",
        memory_total_bytes: 4_294_967_296,
        probe_version: "0.2.0",
      }),
    );
    const storedHostProfile = database.sqlite
      .prepare(
        "select snapshot_hash, payload_json from official_host_profiles where managed_host_id = ?",
      )
      .get(storedHostId.id) as {
      payload_json: string;
      snapshot_hash: string;
    };
    expect(storedHostProfile.snapshot_hash).toBe(changedHostProfileHash);
    expect(JSON.parse(storedHostProfile.payload_json)).toEqual(
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

  it("accepts hash-only reports after shuffled Host Profile repeated fields are canonicalized", async () => {
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
    const shuffledHostProfile = sampleHostProfile({
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
    const canonicalHash = hashStableHostProfile(shuffledHostProfile);
    expect(canonicalHash).toBe(
      "81b44963b7d5790b078d36ad59ac8ffa3da60b6684b58ca152252dfb5574c013",
    );
    const registration = await decodeRegisteredProbe(registrationResponse);

    const fullSnapshotBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: shuffledHostProfile,
            snapshotHash: canonicalHash,
          },
        ],
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
    expect(fullSnapshotAck.requestedSnapshotCollectorIds).toEqual([]);

    const hashOnlyBody = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        probeConfigurationVersion: "default-v1",
        probeId: registration.probeId,
        sequenceEnd: 3,
        sequenceStart: 3,
        snapshots: [
          {
            collectorId: "official.host-profile",
            snapshotHash: canonicalHash,
          },
        ],
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
    expect(hashOnlyAck.requestedSnapshotCollectorIds).toEqual([]);

    const storedHostProfile = database.sqlite
      .prepare("select snapshot_hash from official_host_profiles")
      .get() as { snapshot_hash: string };
    expect(storedHostProfile.snapshot_hash).toBe(canonicalHash);

    const hostsResponse = await app.request("/api/web/hosts", {
      headers: {
        cookie: ownerSession,
      },
    });
    expect(hostsResponse.status).toBe(200);

    database.close();
  });

  it("ignores forwarding headers without trusted direct-peer evidence", async () => {
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
      observed_ip: null,
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
      enrollmentId: "enr_direct_observed_ip",
      expiresAtMs: createdAtMs + 60_000,
      target: { kind: "new_host" },
      tokenHash: hashSecret(enrollmentToken),
    });
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
    const identity = createTestProbeIdentity();

    await withHubServer(app, async (origin) => {
      const response = await fetch(`${origin}/api/probe/register`, {
        body: RegistrationRequest.encode(
          RegistrationRequest.create({
            enrollmentToken,
            probePublicKeyPem: identity.publicKeyPem,
            snapshots: [
              {
                collectorId: "official.host-profile",
                hostProfile: sampleHostProfile(),
              },
            ],
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

function installCommandEnrollment(command: string): unknown {
  const match = /^printf '%s\\n' '([^']+)' \|/.exec(command);
  expect(match?.[1]).toBeTruthy();
  return JSON.parse(match![1]!);
}
