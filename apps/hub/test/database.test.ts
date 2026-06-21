import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

describe("Hub database", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("applies migrations to a real SQLite file before audit events are stored", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });

    const event = database.audit.record({
      action: "owner.login",
      actor: "owner",
      occurredAtMs: 1_725_000_000_000,
      outcome: "success",
    });

    expect(event.id).toBeGreaterThan(0);
    expect(database.audit.recent()).toEqual([
      expect.objectContaining({
        action: "owner.login",
        actor: "owner",
        outcome: "success",
      }),
    ]);

    database.close();
  });

  it("enforces one active Probe Operation per Host and creates lookup indexes", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });

    const indexes = database.sqlite
      .prepare(
        "select name from sqlite_master where type = 'index' and tbl_name = 'probe_operations'",
      )
      .all()
      .map((row) => (row as { name: string }).name);
    expect(indexes).toEqual(
      expect.arrayContaining([
        "probe_operations_active_for_host_idx",
        "probe_operations_latest_for_host_idx",
        "probe_operations_one_active_per_host_idx",
      ]),
    );

    database.probeOperations.createProbeUpgradeRequest({
      acceptedAtMs: null,
      canceledAtMs: null,
      completedAtMs: null,
      createdAtMs: 1_725_000_000_000,
      currentProbeVersion: "0.1.0",
      failureCode: null,
      failureMessage: null,
      hostId: 7,
      id: null,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "pending",
      supersededAtMs: null,
      targetProbeVersion: "0.2.0",
      updatedAtMs: 1_725_000_000_000,
    });

    expect(() =>
      database.probeOperations.createProbeUpgradeRequest({
        acceptedAtMs: null,
        canceledAtMs: null,
        completedAtMs: null,
        createdAtMs: 1_725_000_001_000,
        currentProbeVersion: "0.1.0",
        failureCode: null,
        failureMessage: null,
        hostId: 7,
        id: null,
        kind: "probe_upgrade",
        runningAtMs: null,
        state: "pending",
        supersededAtMs: null,
        targetProbeVersion: "0.3.0",
        updatedAtMs: 1_725_000_001_000,
      }),
    ).toThrow();

    database.probeOperations.createProbeUpgradeRequest({
      acceptedAtMs: null,
      canceledAtMs: null,
      completedAtMs: 1_725_000_002_000,
      createdAtMs: 1_725_000_001_000,
      currentProbeVersion: "0.1.0",
      failureCode: "manual_failure",
      failureMessage: "Failed for test setup.",
      hostId: 7,
      id: null,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "failed",
      supersededAtMs: null,
      targetProbeVersion: "0.3.0",
      updatedAtMs: 1_725_000_002_000,
    });

    expect(database.probeOperations.findActiveForHost(7)).toEqual(
      expect.objectContaining({
        state: "pending",
        targetProbeVersion: "0.2.0",
      }),
    );
    expect(database.probeOperations.findLatestForHost(7)).toEqual(
      expect.objectContaining({
        state: "failed",
        targetProbeVersion: "0.3.0",
      }),
    );

    database.close();
  });
});
