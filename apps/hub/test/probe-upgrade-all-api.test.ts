import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, expect, it, vi } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import type { LiveUpdateBroadcaster } from "../src/live-updates";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture";

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    tempRoots
      .splice(0)
      .map((root) => rm(root, { force: true, recursive: true })),
  );
});

it("rejects client-selected Hosts and target versions for upgrade-all", async () => {
  const fixture = await createFixture();

  const unauthorized = await fixture.app.request(
    "/api/web/hosts/probe-upgrade-requests",
    {
      body: JSON.stringify({}),
      headers: {
        "content-type": "application/json",
        origin: "https://hub.example",
      },
      method: "POST",
    },
  );
  expect(unauthorized.status).toBe(401);

  for (const body of [
    { hostIds: [1] },
    { targetVersion: "0.2.0" },
    { previewToken: "client-snapshot" },
  ]) {
    const response = await fixture.app.request(
      "/api/web/hosts/probe-upgrade-requests",
      {
        body: JSON.stringify(body),
        headers: {
          "content-type": "application/json",
          cookie: fixture.ownerSession,
          origin: "https://hub.example",
        },
        method: "POST",
      },
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_request",
    });
  }

  fixture.database.close();
});

it("submits ordinary requests for every currently eligible active Host and skips current problems", async () => {
  const fixture = await createFixture();
  const eligible = createHost(fixture.database, 1, "0.1.0");
  createHost(fixture.database, 2, "0.2.0");
  const active = createHost(fixture.database, 3, "0.1.0");
  const failed = createHost(fixture.database, 4, "0.1.0");
  const deleted = createHost(fixture.database, 5, "0.1.0");
  const uninstalling = createHost(fixture.database, 6, "0.1.0");
  fixture.database.hosts.softDelete(deleted.id, 1_725_000_000_100);
  fixture.database.probeOperations.createProbeUpgradeRequest(
    probeUpgradeOperation(active.id, "pending"),
  );
  fixture.database.probeOperations.createProbeUpgradeRequest(
    probeUpgradeOperation(failed.id, "failed"),
  );
  fixture.database.probeOperations.createProbeUpgradeRequest({
    ...probeUpgradeOperation(uninstalling.id, "pending"),
    kind: "probe_uninstall",
    targetProbeVersion: "",
  });

  const first = await postUpgradeAll(fixture);
  expect(first.status).toBe(200);
  await expect(first.json()).resolves.toEqual({
    failed: 0,
    skipped: 4,
    submitted: 1,
  });
  expect(
    fixture.database.probeOperations.findLatestForHost(eligible.id),
  ).toEqual(
    expect.objectContaining({
      hostId: eligible.id,
      kind: "probe_upgrade",
      state: "pending",
      targetProbeVersion: "0.2.0",
    }),
  );
  expect(
    fixture.database.probeOperations.findLatestForHost(deleted.id),
  ).toBeNull();
  expect(fixture.database.audit.recent(10)).toContainEqual(
    expect.objectContaining({
      action: "probe_upgrade_request.create",
      actor: "owner",
      outcome: "success",
      subjectType: "probe_upgrade_request",
    }),
  );
  expect(fixture.liveUpdates.broadcastHostSummary).toHaveBeenCalledOnce();
  expect(fixture.liveUpdates.broadcastHostSummary).toHaveBeenCalledWith(
    expect.objectContaining({
      id: eligible.id,
      probeUpgradeProblem: { status: "in_progress" },
    }),
  );

  const repeated = await postUpgradeAll(fixture);
  await expect(repeated.json()).resolves.toEqual({
    failed: 0,
    skipped: 5,
    submitted: 0,
  });
  expect(fixture.liveUpdates.broadcastHostSummary).toHaveBeenCalledOnce();
  expect(
    fixture.database.sqlite
      .prepare("select count(*) as count from probe_operations")
      .get(),
  ).toEqual({ count: 4 });

  fixture.database.close();
});

it("skips all active Hosts when the current Probe Asset Set is blocked", async () => {
  const fixture = await createFixture();
  const firstHost = createHost(fixture.database, 1, "0.1.0");
  const secondHost = createHost(fixture.database, 2, "0.1.0");
  await writeFile(
    path.join(fixture.assetDir, "manifest.json"),
    JSON.stringify({}),
  );

  const response = await postUpgradeAll(fixture);
  await expect(response.json()).resolves.toEqual({
    failed: 0,
    skipped: 2,
    submitted: 0,
  });
  expect(
    fixture.database.probeOperations.findLatestForHost(firstHost.id),
  ).toBeNull();
  expect(
    fixture.database.probeOperations.findLatestForHost(secondHost.id),
  ).toBeNull();

  fixture.database.close();
});

it("skips a Host covered by an authoritative replacement-required transition", async () => {
  const fixture = await createFixture({ transition: "replacement-required" });
  const host = createHost(fixture.database, 1, "0.1.0");

  const response = await postUpgradeAll(fixture);
  await expect(response.json()).resolves.toEqual({
    failed: 0,
    skipped: 1,
    submitted: 0,
  });
  expect(
    fixture.database.probeOperations.findLatestForHost(host.id),
  ).toBeNull();

  fixture.database.close();
});

it("closed-skips Hosts when release transition authority is unavailable or mismatched", async () => {
  const scenarios: Array<{
    arrange?: (
      fixture: Awaited<ReturnType<typeof createFixture>>,
    ) => Promise<void>;
    fixtureOptions?: Parameters<typeof createFixture>[0];
  }> = [
    { fixtureOptions: { includeTrustedRoot: false } },
    {
      arrange: (fixture) =>
        rm(path.join(fixture.assetDir, "release-transition-contract.json")),
    },
    { fixtureOptions: { sourceVersion: "0.0.9" } },
  ];

  for (const scenario of scenarios) {
    const fixture = await createFixture(scenario.fixtureOptions);
    const host = createHost(fixture.database, 1, "0.1.0");
    await scenario.arrange?.(fixture);

    const response = await postUpgradeAll(fixture);
    await expect(response.json()).resolves.toEqual({
      failed: 0,
      skipped: 1,
      submitted: 0,
    });
    expect(
      fixture.database.probeOperations.findLatestForHost(host.id),
    ).toBeNull();

    fixture.database.close();
  }
});

it("keeps successful per-Host requests when one repository creation fails and fills the gap on repeat", async () => {
  const fixture = await createFixture();
  const firstHost = createHost(fixture.database, 1, "0.1.0");
  const secondHost = createHost(fixture.database, 2, "0.1.0");
  const thirdHost = createHost(fixture.database, 3, "0.1.0");
  const createRequest =
    fixture.database.probeOperations.createProbeUpgradeRequest.bind(
      fixture.database.probeOperations,
    );
  fixture.database.probeOperations.createProbeUpgradeRequest = (operation) => {
    if (operation.hostId === secondHost.id) {
      throw new Error("injected per-Host failure");
    }
    return createRequest(operation);
  };

  const partial = await postUpgradeAll(fixture);
  await expect(partial.json()).resolves.toEqual({
    failed: 1,
    skipped: 0,
    submitted: 2,
  });
  expect(
    fixture.database.probeOperations.findLatestForHost(firstHost.id),
  ).toEqual(expect.objectContaining({ state: "pending" }));
  expect(
    fixture.database.probeOperations.findLatestForHost(secondHost.id),
  ).toBeNull();
  expect(
    fixture.database.probeOperations.findLatestForHost(thirdHost.id),
  ).toEqual(expect.objectContaining({ state: "pending" }));

  fixture.database.probeOperations.createProbeUpgradeRequest = createRequest;
  const filled = await postUpgradeAll(fixture);
  await expect(filled.json()).resolves.toEqual({
    failed: 0,
    skipped: 2,
    submitted: 1,
  });

  fixture.database.close();
});

async function createFixture(
  options: {
    includeTrustedRoot?: boolean;
    sourceVersion?: string;
    transition?: "compatible" | "replacement-required";
  } = {},
) {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-bulk-db-"));
  const assetRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-bulk-assets-"));
  tempRoots.push(dataRoot, assetRoot);
  const assetDir = path.join(assetRoot, "assets");
  await mkdir(assetDir, { recursive: true });
  const release = await writeSignedProbeAssetSet(assetDir, {
    sourceVersion: options.sourceVersion ?? "0.1.0",
    targetVersion: "0.2.0",
    transition: options.transition ?? "compatible",
  });
  const database = initializeHubDatabase({
    dataRoot,
    sqlitePath: path.join(dataRoot, "enoki.db"),
  });
  const liveUpdates = recordingLiveUpdates();
  const app = createHubApp({
    auth: {
      failureDelayMs: 0,
      managementOrigin: "https://hub.example",
      ownerPassword: "correct horse battery staple",
      sessionCookieName: "enoki_owner_session",
    },
    database,
    liveUpdates,
    probeAssets: {
      assetDir,
      ...(options.includeTrustedRoot === false
        ? {}
        : { trustedRootPublicKeyPem: release.rootPublicKeyPem }),
    },
  });
  const login = await app.request("/api/web/auth/login", {
    body: JSON.stringify({ password: "correct horse battery staple" }),
    headers: {
      "content-type": "application/json",
      origin: "https://hub.example",
    },
    method: "POST",
  });
  expect(login.status).toBe(200);

  return {
    app,
    assetDir,
    database,
    liveUpdates,
    ownerSession: login.headers.get("set-cookie") ?? "",
  };
}

function recordingLiveUpdates() {
  return {
    addClient: vi.fn(),
    broadcastDetailSample: vi.fn(),
    broadcastHostProfile: vi.fn(),
    broadcastHostReady: vi.fn(),
    broadcastHostRemoved: vi.fn(),
    broadcastHostSummary: vi.fn(),
    closeSession: vi.fn(),
    handleClientMessage: vi.fn(),
    removeClient: vi.fn(),
  } satisfies LiveUpdateBroadcaster;
}

function createHost(
  database: Awaited<ReturnType<typeof createFixture>>["database"],
  id: number,
  probeVersion: string,
) {
  return database.hosts.create({
    clockSkewDetected: false,
    connectAddress: `192.0.2.${id}`,
    createdAtMs: 1_725_000_000_000,
    displayName: `Host ${id}`,
    displayNameEdited: false,
    id,
    lastClockSkewMs: null,
    probeConfigurationVersion: "default-v1",
    probeId: `probe-${id}`,
    probeSecretHash: `secret-${id}`,
    probeVersion,
  });
}

function probeUpgradeOperation(hostId: number, state: "failed" | "pending") {
  return {
    acceptedAtMs: null,
    canceledAtMs: null,
    completedAtMs: state === "failed" ? 1_725_000_000_050 : null,
    createdAtMs: 1_725_000_000_000,
    currentProbeVersion: "0.1.0",
    failureCode: state === "failed" ? "checksum_failure" : null,
    failureMessage: state === "failed" ? "not exposed" : null,
    hostId,
    id: null,
    kind: "probe_upgrade" as const,
    runningAtMs: null,
    state,
    supersededAtMs: null,
    targetProbeVersion: "0.2.0",
    updatedAtMs: 1_725_000_000_050,
  };
}

function postUpgradeAll(fixture: Awaited<ReturnType<typeof createFixture>>) {
  return fixture.app.request("/api/web/hosts/probe-upgrade-requests", {
    body: JSON.stringify({}),
    headers: {
      "content-type": "application/json",
      cookie: fixture.ownerSession,
      origin: "https://hub.example",
    },
    method: "POST",
  });
}
