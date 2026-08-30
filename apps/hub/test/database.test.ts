import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import { issueProbeOperationToken } from "../src/probe/operation-token";

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

  it("adds nullable Runtime failure repair bindings without reclassifying a legacy failed-Upgrade Repair", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const stagedMigrations = path.join(dataRoot, "core-migrations");
    const currentMigration = "20260824132103_messy_madame_hydra";
    await cp(path.resolve("drizzle"), stagedMigrations, { recursive: true });
    await rm(path.join(stagedMigrations, currentMigration), {
      force: true,
      recursive: true,
    });
    const legacyOptions = {
      migrationLayers: [
        {
          historyTable: "__core_migrations",
          migrationsFolder: stagedMigrations,
          name: "core",
        },
        {
          historyTable: "__official_metrics_migrations",
          migrationsFolder: path.resolve("drizzle-official-metrics"),
          name: "official_metrics",
        },
      ],
    };
    const legacy = initializeHubDatabase(
      { dataRoot, sqlitePath: path.join(dataRoot, "enoki.db") },
      legacyOptions,
    );
    createHost(legacy, { id: 73, probeId: "probe-legacy-repair" });
    legacy.sqlite
      .prepare(
        `insert into probe_operations (
        id, managed_host_id, kind, state, target_probe_version,
        repair_failed_operation_id, repair_evidence_sha256,
        created_at_ms, updated_at_ms, accepted_at_ms
      ) values (42, 73, 'probe_repair', 'accepted', '1.2.3', 41, ?, 1, 1, 1)`,
      )
      .run("a".repeat(64));
    legacy.close();

    await cp(
      path.resolve("drizzle", currentMigration),
      path.join(stagedMigrations, currentMigration),
      { recursive: true },
    );
    const migrated = initializeHubDatabase(
      { dataRoot, sqlitePath: path.join(dataRoot, "enoki.db") },
      legacyOptions,
    );
    expect(
      migrated.sqlite
        .prepare(
          "select repair_eligibility_kind as kind, repair_failure_generation as generation from probe_operations where id = 42",
        )
        .get(),
    ).toEqual({ kind: null, generation: null });
    expect(migrated.probeOperations.findById(42)).toEqual(
      expect.objectContaining({
        repairEligibilityKind: "failed_upgrade",
        repairFailedOperationId: 41,
        repairFailureGeneration: null,
      }),
    );
    migrated.close();
  });

  it("adds nullable Forward evidence bindings without reclassifying an existing Host Profile", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const stagedMigrations = path.join(dataRoot, "core-migrations");
    const currentMigration = "20260824121043_minor_payback";
    await cp(path.resolve("drizzle"), stagedMigrations, { recursive: true });
    await rm(path.join(stagedMigrations, currentMigration), {
      force: true,
      recursive: true,
    });
    const options = {
      migrationLayers: [
        {
          historyTable: "__core_migrations",
          migrationsFolder: stagedMigrations,
          name: "core",
        },
        {
          historyTable: "__official_metrics_migrations",
          migrationsFolder: path.resolve("drizzle-official-metrics"),
          name: "official_metrics",
        },
      ],
    };
    const legacy = initializeHubDatabase(
      { dataRoot, sqlitePath: path.join(dataRoot, "enoki.db") },
      options,
    );
    createHost(legacy, { id: 72, probeId: "probe-legacy-profile" });
    legacy.sqlite
      .prepare(
        `insert into official_host_profiles (
           managed_host_id, snapshot_hash, payload_json, hostname, os,
           kernel, architecture, cpu_count, memory_total_bytes, probe_version,
           filesystems_json, network_interfaces_json, updated_at_ms
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        72,
        "legacy-profile-hash",
        JSON.stringify({
          architecture: "x86_64",
          collectorCapabilities: null,
          cpuCount: 2,
          cpuModel: null,
          filesystems: [],
          hostname: "legacy-profile",
          kernel: "6.8.0",
          memoryTotalBytes: 2_147_483_648,
          networkInterfaces: [],
          os: "linux",
          probeVersion: "0.1.0",
        }),
        "legacy-profile",
        "linux",
        "6.8.0",
        "x86_64",
        2,
        2_147_483_648,
        "0.1.0",
        "[]",
        "[]",
        1_725_000_000_000,
      );
    legacy.close();
    await cp(
      path.resolve("drizzle", currentMigration),
      path.join(stagedMigrations, currentMigration),
      { recursive: true },
    );

    const migrated = initializeHubDatabase(
      { dataRoot, sqlitePath: path.join(dataRoot, "enoki.db") },
      options,
    );
    expect(migrated.snapshotCollectors.hostProfile.readObservation(72)).toEqual(
      expect.objectContaining({
        forwardEvidence: null,
        observedAtMs: 1_725_000_000_000,
        view: expect.objectContaining({ probeVersion: "0.1.0" }),
      }),
    );
    migrated.close();
  });

  it("closes an active legacy manual reinstall authority when its signed source receipt is absent", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const stagedMigrations = path.join(dataRoot, "core-migrations");
    const currentMigration = "20260823112609_silent_serpent_society";
    const successorMigration = "20260830034007_volatile_joshua_kane";
    await cp(path.resolve("drizzle"), stagedMigrations, { recursive: true });
    await rm(path.join(stagedMigrations, currentMigration), {
      force: true,
      recursive: true,
    });
    await rm(path.join(stagedMigrations, successorMigration), {
      force: true,
      recursive: true,
    });
    const options = {
      migrationLayers: [
        {
          historyTable: "__core_migrations",
          migrationsFolder: stagedMigrations,
          name: "core",
        },
        {
          historyTable: "__official_metrics_migrations",
          migrationsFolder: path.resolve("drizzle-official-metrics"),
          name: "official_metrics",
        },
      ],
    };
    const legacy = initializeHubDatabase(
      { dataRoot, sqlitePath: path.join(dataRoot, "enoki.db") },
      options,
    );
    createHost(legacy, { id: 71, probeId: "probe-legacy-manual" });
    legacy.sqlite
      .prepare(
        `insert into enrollment_tokens (
           enrollment_id, token_hash, created_at_ms, expires_at_ms,
           target_kind, target_host_id, expected_hub_origin,
           expected_probe_id, expected_probe_version,
           target_asset_set_digest, target_probe_version, status
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        `enr_${"l".repeat(24)}`,
        "legacy-manual-token-hash",
        1_725_000_000_000,
        1_725_003_600_000,
        "manual_reinstall",
        71,
        "https://hub.example",
        "probe-legacy-manual",
        "0.1.74",
        `sha256:${"a".repeat(64)}`,
        "1.2.3",
        "pending",
      );
    legacy.close();
    await cp(
      path.resolve("drizzle", currentMigration),
      path.join(stagedMigrations, currentMigration),
      { recursive: true },
    );
    await cp(
      path.resolve("drizzle", successorMigration),
      path.join(stagedMigrations, successorMigration),
      { recursive: true },
    );

    const migrated = initializeHubDatabase(
      { dataRoot, sqlitePath: path.join(dataRoot, "enoki.db") },
      options,
    );
    expect(
      migrated.sqlite
        .prepare(
          "select status, rejection_code as rejectionCode, source_probe_sha256_json as sourceProbeSha256Json from enrollment_tokens where target_host_id = 71",
        )
        .get(),
    ).toEqual({
      rejectionCode: "manual_reinstall_authority_invalid",
      sourceProbeSha256Json: "[]",
      status: "rejected",
    });
    migrated.close();
  });

  it("applies ordered Migration Layers with independent history tables", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const coreMigrations = path.join(dataRoot, "core-migrations");
    const metricsMigrations = path.join(dataRoot, "metrics-migrations");
    await writeMigration(coreMigrations, "0001_core", [
      "create table core_layer_order (position integer not null)",
      "insert into core_layer_order (position) values (1)",
    ]);
    await writeMigration(metricsMigrations, "0001_metrics", [
      "create table metrics_layer_order (position integer not null)",
      "insert into metrics_layer_order (position) select position + 1 from core_layer_order",
    ]);

    const database = initializeHubDatabase(
      {
        dataRoot,
        sqlitePath: path.join(dataRoot, "enoki.db"),
      },
      {
        migrationLayers: [
          {
            historyTable: "__core_migrations",
            migrationsFolder: coreMigrations,
            name: "core",
          },
          {
            historyTable: "__official_metrics_migrations",
            migrationsFolder: metricsMigrations,
            name: "official_metrics",
          },
        ],
      },
    );

    expect(
      database.sqlite.prepare("select position from metrics_layer_order").get(),
    ).toEqual({ position: 2 });
    expect(migrationHistoryTables(database.sqlite).sort()).toEqual([
      "__core_migrations",
      "__official_metrics_migrations",
    ]);

    database.close();
  });

  it("migrates legacy data and closes Probe Upgrade Requests without Asset Set targets", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const preFeatureMigrations = path.join(dataRoot, "pre-feature-migrations");
    await cp(
      path.resolve("drizzle/20260625011049_outstanding_iron_lad"),
      path.join(preFeatureMigrations, "20260625011049_outstanding_iron_lad"),
      { recursive: true },
    );

    const legacy = initializeHubDatabase(
      {
        dataRoot,
        sqlitePath: path.join(dataRoot, "enoki.db"),
      },
      {
        migrationLayers: [
          {
            historyTable: "__drizzle_migrations",
            migrationsFolder: preFeatureMigrations,
            name: "core",
          },
          {
            historyTable: "__official_metrics_migrations",
            migrationsFolder: path.resolve("drizzle-official-metrics"),
            name: "official_metrics",
          },
        ],
      },
    );
    createHost(legacy, { id: 41, probeId: "probe-preserved" });
    createHost(legacy, { id: 42, probeId: "probe-accepted" });
    createHost(legacy, { id: 43, probeId: "probe-running" });
    legacy.audit.record({
      action: "host.metadata.update",
      actor: "owner",
      occurredAtMs: 1_725_000_001_000,
      outcome: "success",
      subjectId: "41",
      subjectType: "host",
    });
    const insertLegacyOperation = legacy.sqlite.prepare(
      `insert into probe_operations (
          managed_host_id, kind, state, current_probe_version,
          target_probe_version, failure_code, failure_message,
          created_at_ms, updated_at_ms, accepted_at_ms, running_at_ms,
          completed_at_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    insertLegacyOperation.run(
      41,
      "probe_upgrade",
      "pending",
      "0.1.0",
      "0.2.0",
      null,
      null,
      1_725_000_002_000,
      1_725_000_002_000,
      null,
      null,
      null,
    );
    insertLegacyOperation.run(
      42,
      "probe_upgrade",
      "accepted",
      "0.1.0",
      "0.2.0",
      null,
      null,
      1_725_000_002_000,
      1_725_000_003_000,
      1_725_000_003_000,
      null,
      null,
    );
    insertLegacyOperation.run(
      43,
      "probe_upgrade",
      "running",
      "0.1.0",
      "0.2.0",
      null,
      null,
      1_725_000_002_000,
      1_725_000_004_000,
      1_725_000_003_000,
      1_725_000_004_000,
      null,
    );
    insertLegacyOperation.run(
      41,
      "probe_upgrade",
      "failed",
      "0.1.0",
      "0.1.5",
      "accepted_timeout",
      "Historical failure.",
      1_724_000_000_000,
      1_724_000_010_000,
      1_724_000_001_000,
      null,
      1_724_000_010_000,
    );
    legacy.metrics.recordSample({
      bootId: "boot-preserved",
      collectedAtMs: 1_725_000_003_000,
      cpuPercent: 31,
      hostId: 41,
      probeId: "probe-preserved",
      receivedAtMs: 1_725_000_003_500,
      sequence: 1,
    });
    legacy.sqlite
      .prepare(
        `insert into official_host_profiles (
          managed_host_id, snapshot_hash, payload_json, hostname, os, kernel,
          architecture, cpu_count, cpu_model, memory_total_bytes, probe_version,
          collector_capabilities_json, filesystems_json, network_interfaces_json,
          updated_at_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        41,
        "profile-hash",
        "{}",
        "preserved-host",
        "linux",
        "6.8.0",
        "x86_64",
        2,
        null,
        2_147_483_648,
        "0.1.0",
        null,
        "[]",
        "[]",
        1_725_000_004_000,
      );
    const insertLegacyEnrollment = legacy.sqlite.prepare(
      "insert into enrollment_tokens (token_hash, created_at_ms, expires_at_ms, used_at_ms) values (?, ?, ?, ?)",
    );
    insertLegacyEnrollment.run(
      "legacy-unused",
      1_724_999_000_000,
      1_724_999_900_000,
      null,
    );
    insertLegacyEnrollment.run(
      "legacy-used",
      1_724_999_000_000,
      1_724_999_900_000,
      1_724_999_100_000,
    );
    insertLegacyEnrollment.run(
      "legacy-expired",
      1_724_998_000_000,
      1_724_998_900_000,
      null,
    );
    legacy.close();

    const migrated = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });

    expect(
      migrated.sqlite
        .prepare(
          `select enrollment_id as enrollmentId, target_kind as targetKind,
            target_host_id as targetHostId, status from enrollment_tokens
            order by token_hash`,
        )
        .all(),
    ).toEqual([
      {
        enrollmentId: null,
        status: "expired",
        targetHostId: null,
        targetKind: null,
      },
      {
        enrollmentId: null,
        status: "expired",
        targetHostId: null,
        targetKind: null,
      },
      {
        enrollmentId: null,
        status: "expired",
        targetHostId: null,
        targetKind: null,
      },
    ]);
    expect(
      migrated.sqlite
        .prepare(
          `select
            (select count(*) from managed_hosts) as hosts,
            (select count(*) from official_host_profiles) as profiles,
            (select count(*) from metric_samples) as metrics,
            (select count(*) from official_metric_cpu) as officialMetricCpu,
            (select count(*) from probe_operations) as operations,
            (select count(*) from audit_log) as auditEvents`,
        )
        .get(),
    ).toEqual({
      auditEvents: 1,
      hosts: 3,
      metrics: 1,
      officialMetricCpu: 1,
      operations: 4,
      profiles: 1,
    });
    expect(migrated.sqlite.prepare("pragma foreign_key_check").all()).toEqual(
      [],
    );
    const migratedOperations = migrated.sqlite
      .prepare(
        `select managed_host_id as hostId, state, failure_code as failureCode,
          failure_message as failureMessage, completed_at_ms as completedAtMs,
          updated_at_ms as updatedAtMs,
          target_asset_set_digest as targetAssetSetDigest
        from probe_operations order by id`,
      )
      .all();
    expect(migratedOperations.slice(0, 3)).toEqual(
      [41, 42, 43].map((hostId) => ({
        completedAtMs: expect.any(Number),
        failureCode: "probe_upgrade_target_unavailable",
        failureMessage:
          "Probe Upgrade Request predates its required Probe Asset Set target.",
        hostId,
        state: "failed",
        targetAssetSetDigest: null,
        updatedAtMs: expect.any(Number),
      })),
    );
    for (const operation of migratedOperations.slice(0, 3) as Array<{
      completedAtMs: number;
      updatedAtMs: number;
    }>) {
      expect(operation.completedAtMs).toBe(operation.updatedAtMs);
    }
    expect(migratedOperations[3]).toEqual({
      completedAtMs: 1_724_000_010_000,
      failureCode: "accepted_timeout",
      failureMessage: "Historical failure.",
      hostId: 41,
      state: "failed",
      targetAssetSetDigest: null,
      updatedAtMs: 1_724_000_010_000,
    });
    for (const hostId of [41, 42, 43]) {
      expect(migrated.probeOperations.findActiveForHost(hostId)).toBeNull();
    }
    const legacyOperation = migrated.probeOperations.findLatestForHost(41);
    expect(() =>
      issueProbeOperationToken({
        expiresAtMs: 1_725_000_020_000,
        operation: legacyOperation!,
        probeId: "probe-preserved",
        secret: "test-secret",
      }),
    ).toThrow(
      "Cannot issue Probe Operation Token without a Probe Asset Set digest.",
    );

    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database: migrated,
      now: () => 1_725_000_010_000,
    });
    const login = await app.request("/api/web/auth/login", {
      body: JSON.stringify({ password: "correct horse battery staple" }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    const ownerSession = login.headers.get("set-cookie") ?? "";
    const created = await app.request("/api/web/enrollments", {
      headers: { cookie: ownerSession },
      method: "POST",
    });
    expect(created.status).toBe(201);
    const enrollment = (await created.json()) as { enrollmentId: string };
    const status = await app.request(
      `/api/web/enrollments/${enrollment.enrollmentId}`,
      { headers: { cookie: ownerSession } },
    );
    expect(status.status).toBe(200);
    await expect(status.json()).resolves.toEqual(
      expect.objectContaining({
        enrollmentId: enrollment.enrollmentId,
        status: "pending",
        target: { kind: "new_host" },
      }),
    );

    migrated.close();
  });

  it("keeps detailed official Metrics tables out of core-only migrations", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase(
      {
        dataRoot,
        sqlitePath: path.join(dataRoot, "enoki.db"),
      },
      {
        migrationsFolder: path.resolve("drizzle"),
      },
    );

    expect(tables(database.sqlite)).not.toEqual(
      expect.arrayContaining([
        "metric_cpu_cores",
        "metric_disks",
        "metric_network_interfaces",
      ]),
    );

    database.close();
  });

  it("persists exact Snapshot Replay requests and resets fulfillment for a newer tuple", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 88, probeId: "probe-snapshot-replay" });

    const originalRequest = {
      bootId: "boot-before-replacement",
      collectorId: "official.host-profile",
      hostId: 88,
      sequence: 2,
      snapshotHash: "snapshot-before-replacement",
    };
    database.snapshotCollectors.requestSnapshotReplay({
      ...originalRequest,
      requestedAtMs: 1_725_000_000_000,
    });
    expect(
      database.snapshotCollectors.snapshotReplayRequestStatus(originalRequest),
    ).toBe("pending");
    expect(
      database.snapshotCollectors.fulfillSnapshotReplay({
        ...originalRequest,
        acceptedSnapshotHash: originalRequest.snapshotHash,
        acceptedSequence: originalRequest.sequence,
        fulfilledAtMs: 1_725_000_000_100,
        wireShape: "current_sequence",
      }),
    ).toBe(true);
    expect(
      database.snapshotCollectors.snapshotReplayRequestStatus(originalRequest),
    ).toBe("fulfilled");

    const replacementRequest = {
      bootId: "boot-after-replacement",
      collectorId: "official.host-profile",
      hostId: 88,
      sequence: 4,
      snapshotHash: "snapshot-after-replacement",
    };
    database.snapshotCollectors.requestSnapshotReplay({
      ...replacementRequest,
      requestedAtMs: 1_725_000_000_200,
    });

    expect(
      database.snapshotCollectors.snapshotReplayRequestStatus(originalRequest),
    ).toBeNull();
    expect(
      database.snapshotCollectors.snapshotReplayRequestStatus(
        replacementRequest,
      ),
    ).toBe("pending");
    expect(
      database.sqlite
        .prepare(
          "select boot_id, sequence, snapshot_hash, fulfilled_at_ms from snapshot_replay_requests",
        )
        .get(),
    ).toEqual({
      boot_id: "boot-after-replacement",
      fulfilled_at_ms: null,
      sequence: 4,
      snapshot_hash: "snapshot-after-replacement",
    });

    database.close();
  });

  it("migrates unbound legacy Snapshot Replay requests into non-matchable receipts", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const legacyMigrations = path.join(dataRoot, "legacy-replay-migrations");
    await cp(path.resolve("drizzle"), legacyMigrations, { recursive: true });
    await rm(
      path.join(legacyMigrations, "20260810083603_glorious_adam_warlock"),
      { force: true, recursive: true },
    );

    const legacy = initializeHubDatabase(
      {
        dataRoot,
        sqlitePath: path.join(dataRoot, "enoki.db"),
      },
      {
        migrationLayers: [
          {
            historyTable: "__drizzle_migrations",
            migrationsFolder: legacyMigrations,
            name: "core",
          },
          {
            historyTable: "__official_metrics_migrations",
            migrationsFolder: path.resolve("drizzle-official-metrics"),
            name: "official_metrics",
          },
        ],
      },
    );
    createHost(legacy, { id: 89, probeId: "probe-legacy-snapshot-replay" });
    legacy.sqlite
      .prepare(
        "insert into snapshot_replay_requests (managed_host_id, collector_id, requested_at_ms) values (?, ?, ?)",
      )
      .run(89, "official.host-profile", 1_725_000_000_000);
    legacy.close();

    const migrated = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    expect(
      migrated.sqlite
        .prepare(
          "select boot_id, sequence, snapshot_hash, fulfilled_at_ms from snapshot_replay_requests",
        )
        .get(),
    ).toEqual({
      boot_id: "",
      fulfilled_at_ms: null,
      sequence: 0,
      snapshot_hash: "",
    });
    expect(
      migrated.snapshotCollectors.snapshotReplayRequestStatus({
        bootId: "boot-after-migration",
        collectorId: "official.host-profile",
        hostId: 89,
        sequence: 1,
        snapshotHash: "snapshot-after-migration",
      }),
    ).toBeNull();

    migrated.close();
  });

  it("keeps Metrics child rows attached when a sparse official domain row has a different id than its sample", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 77, probeId: "probe-sparse" });

    database.metrics.recordSample({
      bootId: "boot-sparse",
      collectedAtMs: 1_725_000_001_000,
      hostId: 77,
      memoryTotalBytes: 16_000,
      memoryUsedBytes: 8_000,
      probeId: "probe-sparse",
      receivedAtMs: 1_725_000_001_500,
      sequence: 1,
    });
    database.metrics.recordSample({
      bootId: "boot-sparse",
      collectedAtMs: 1_725_000_002_000,
      cpuCores: [
        {
          idle: 80,
          iowait: 1,
          irq: 0,
          name: "cpu0",
          nice: 0,
          softirq: 1,
          steal: 0,
          system: 8,
          usagePercent: 20,
          user: 10,
        },
      ],
      cpuPercent: 20,
      disks: [
        {
          availableBytes: 4_000,
          filesystemType: "ext4",
          mountPoint: "/",
          readBytesDelta: 300,
          totalBytes: 10_000,
          usedBytes: 6_000,
          writeBytesDelta: 700,
        },
      ],
      hostId: 77,
      networkInterfaces: [
        {
          name: "eth0",
          rxBytes: 20_000,
          rxBytesDelta: 2_000,
          txBytes: 10_000,
          txBytesDelta: 1_000,
        },
      ],
      probeId: "probe-sparse",
      receivedAtMs: 1_725_000_002_500,
      sequence: 2,
    });

    const history = database.metrics.findSamplesForHost({
      fromCollectedAtMs: 1_725_000_000_000,
      hostId: 77,
      toCollectedAtMs: 1_725_000_003_000,
    });

    expect(history).toEqual([
      expect.objectContaining({
        cpuCores: [],
        disks: [],
        memoryTotalBytes: 16_000,
        memoryUsedBytes: 8_000,
        networkInterfaces: [],
        sequence: 1,
      }),
      expect.objectContaining({
        cpuCores: [{ name: "cpu0", usagePercent: 20 }],
        cpuPercent: 20,
        disks: [
          expect.objectContaining({
            mountPoint: "/",
            readBytesDelta: 300,
            writeBytesDelta: 700,
          }),
        ],
        networkInterfaces: [
          {
            name: "eth0",
            rxBytesDelta: 2_000,
            txBytesDelta: 1_000,
          },
        ],
        sequence: 2,
      }),
    ]);

    database.close();
  });

  it("creates sample indexes for official Metrics domain tables", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });

    expect(uniqueIndexedColumns(database.sqlite)).toEqual(
      expect.arrayContaining([
        "official_metric_cpu.metric_sample_id",
        "official_metric_disk_summary.metric_sample_id",
        "official_metric_load.metric_sample_id",
        "official_metric_memory.metric_sample_id",
        "official_metric_network_summary.metric_sample_id",
        "official_metric_thermal_power.metric_sample_id",
        "official_metric_uptime.metric_sample_id",
      ]),
    );
    expect(indexedColumns(database.sqlite)).toEqual(
      expect.arrayContaining([
        "metric_cpu_cores.metric_sample_id",
        "metric_disks.metric_sample_id",
        "metric_network_interfaces.metric_sample_id",
      ]),
    );

    database.close();
  });

  it("enforces foreign keys and cascades Metrics child rows", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 66, probeId: "probe-cascade" });

    expect(database.sqlite.prepare("PRAGMA foreign_keys").get()).toEqual({
      foreign_keys: 1,
    });
    expect(() =>
      database.metrics.recordSample({
        bootId: "boot-missing-host",
        collectedAtMs: 1_725_000_000_000,
        hostId: 999,
        probeId: "probe-missing-host",
        receivedAtMs: 1_725_000_000_500,
        sequence: 1,
      }),
    ).toThrow();

    database.metrics.recordSample({
      bootId: "boot-cascade",
      collectedAtMs: 1_725_000_001_000,
      cpuCores: [
        {
          idle: 80,
          iowait: 1,
          irq: 0,
          name: "cpu0",
          nice: 0,
          softirq: 1,
          steal: 0,
          system: 8,
          usagePercent: 20,
          user: 10,
        },
      ],
      cpuPercent: 20,
      hostId: 66,
      memoryTotalBytes: 16_000,
      memoryUsedBytes: 8_000,
      probeId: "probe-cascade",
      receivedAtMs: 1_725_000_001_500,
      sequence: 1,
    });
    const sample = database.sqlite
      .prepare("select id from metric_samples where probe_id = ?")
      .get("probe-cascade") as { id: number };

    database.sqlite
      .prepare("delete from metric_samples where id = ?")
      .run(sample.id);

    expect(
      database.sqlite
        .prepare(
          `
          select
            (select count(*) from official_metric_cpu) as cpu,
            (select count(*) from official_metric_memory) as memory,
            (select count(*) from metric_cpu_cores) as cores
          `,
        )
        .get(),
    ).toEqual({
      cores: 0,
      cpu: 0,
      memory: 0,
    });

    database.close();
  });

  it("stores detailed CPU, disk, and network Metrics when only the official Metrics layer creates their tables", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const coreMigrations = path.join(dataRoot, "core-envelope-migrations");
    await writeMigration(coreMigrations, "0001_core_envelope", [
      `create table metric_samples (
        id integer primary key autoincrement not null,
        managed_host_id integer not null,
        probe_id text not null,
        boot_id text not null,
        sequence integer not null,
        collected_at_ms integer not null,
        received_at_ms integer not null,
        cpu_percent real,
        cpu_user_percent real,
        cpu_system_percent real,
        cpu_iowait_percent real,
        cpu_steal_percent real,
        cpu_idle_percent real,
        memory_used_bytes integer,
        memory_total_bytes integer,
        memory_cache_bytes integer,
        swap_total_bytes integer,
        swap_used_bytes integer,
        load_1 real,
        load_5 real,
        load_15 real,
        uptime_seconds integer,
        temperature_celsius real,
        battery_percent integer,
        battery_state text,
        disk_used_bytes integer,
        disk_total_bytes integer,
        network_rx_bytes_delta integer,
        network_tx_bytes_delta integer
      )`,
      "create unique index metric_samples_probe_boot_sequence_idx on metric_samples (probe_id, boot_id, sequence)",
    ]);

    const database = initializeHubDatabase(
      {
        dataRoot,
        sqlitePath: path.join(dataRoot, "enoki.db"),
      },
      {
        migrationLayers: [
          {
            historyTable: "__core_migrations",
            migrationsFolder: coreMigrations,
            name: "core",
          },
          {
            historyTable: "__official_metrics_migrations",
            migrationsFolder: path.resolve("drizzle-official-metrics"),
            name: "official_metrics",
          },
        ],
      },
    );

    database.metrics.recordSample({
      bootId: "boot-official-detail",
      collectedAtMs: 1_725_000_020_000,
      cpuCores: [
        {
          idle: 60,
          iowait: 2,
          irq: 0,
          name: "cpu0",
          nice: 0,
          softirq: 1,
          steal: 0,
          system: 12,
          usagePercent: 40,
          user: 25,
        },
      ],
      disks: [
        {
          availableBytes: 8_000,
          filesystemType: "xfs",
          ioUtilizationPercent: 9.5,
          mountPoint: "/data",
          readAwaitMs: 1.2,
          readBytesDelta: 900,
          totalBytes: 20_000,
          usedBytes: 12_000,
          weightedIoPercent: 10.5,
          writeAwaitMs: 2.3,
          writeBytesDelta: 1_100,
        },
      ],
      hostId: 88,
      networkInterfaces: [
        {
          name: "ens3",
          rxBytes: 50_000,
          rxBytesDelta: 5_000,
          txBytes: 40_000,
          txBytesDelta: 4_000,
        },
      ],
      probeId: "probe-official-detail",
      receivedAtMs: 1_725_000_020_500,
      sequence: 1,
    });

    expect(
      database.metrics.findSamplesForHost({
        fromCollectedAtMs: 1_725_000_019_000,
        hostId: 88,
        toCollectedAtMs: 1_725_000_021_000,
      }),
    ).toEqual([
      expect.objectContaining({
        cpuCores: [{ name: "cpu0", usagePercent: 40 }],
        disks: [
          expect.objectContaining({
            ioUtilizationPercent: 9.5,
            mountPoint: "/data",
            readAwaitMs: 1.2,
            weightedIoPercent: 10.5,
            writeAwaitMs: 2.3,
          }),
        ],
        networkInterfaces: [
          {
            name: "ens3",
            rxBytesDelta: 5_000,
            txBytesDelta: 4_000,
          },
        ],
      }),
    ]);

    database.close();
  });

  it("returns latest-known low-frequency Disk Health when the latest high-frequency sample is sparse", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 99, probeId: "probe-disk-health" });

    database.metrics.recordSample({
      bootId: "boot-disk-health",
      collectedAtMs: 1_725_000_000_000,
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
      hostId: 99,
      probeId: "probe-disk-health",
      receivedAtMs: 1_725_000_000_500,
      sequence: 1,
    });
    database.metrics.recordSample({
      bootId: "boot-disk-health",
      collectedAtMs: 1_725_000_005_000,
      cpuPercent: 25,
      hostId: 99,
      probeId: "probe-disk-health",
      receivedAtMs: 1_725_000_005_500,
      sequence: 2,
    });

    expect(database.metrics.findLatestSample(99)).toEqual(
      expect.objectContaining({
        cpuPercent: 25,
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
        sequence: 2,
      }),
    );
    expect(
      database.metrics.findSamplesForHost({
        fromCollectedAtMs: 1_725_000_000_000,
        hostId: 99,
        toCollectedAtMs: 1_725_000_006_000,
      }),
    ).toEqual([
      expect.objectContaining({
        diskHealth: [
          expect.objectContaining({
            deviceName: "/dev/sda",
            passed: true,
          }),
        ],
        sequence: 1,
      }),
      expect.objectContaining({
        diskHealth: [],
        sequence: 2,
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
    createHost(database, { id: 7, probeId: "probe-operation" });

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
      targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
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
        targetAssetSetDigest: `sha256:${"b".repeat(64)}`,
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
      targetAssetSetDigest: `sha256:${"b".repeat(64)}`,
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

  it("atomically supersedes pending ExistingHost Enrollments, conflicts while verifying, and permits terminal retry", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 7, probeId: "probe-existing" });
    const create = (enrollmentId: string, createdAtMs: number) =>
      database.enrollments.createPending({
        createdAtMs,
        enrollmentId,
        expiresAtMs: createdAtMs + 60_000,
        target: { hostId: 7, kind: "existing_host" },
        tokenHash: `token-${enrollmentId}`,
      });

    const first = create("enr_existing_first_0001", 1_725_000_000_000);
    const second = create("enr_existing_second_0002", 1_725_000_001_000);
    expect(first.kind).toBe("created");
    expect(second.kind).toBe("created");
    expect(
      database.sqlite
        .prepare(
          "select enrollment_id as enrollmentId, status, rejection_code as rejectionCode from enrollment_tokens order by id",
        )
        .all(),
    ).toEqual([
      {
        enrollmentId: "enr_existing_first_0001",
        rejectionCode: "superseded",
        status: "rejected",
      },
      {
        enrollmentId: "enr_existing_second_0002",
        rejectionCode: null,
        status: "pending",
      },
    ]);

    database.sqlite
      .prepare(
        "update enrollment_tokens set status = 'verifying', used_at_ms = ?, verification_deadline_at_ms = ? where enrollment_id = ?",
      )
      .run(1_725_000_002_000, 1_725_000_062_000, "enr_existing_second_0002");
    expect(create("enr_existing_conflict_0003", 1_725_000_003_000)).toEqual({
      kind: "existing_host_verifying",
    });

    database.sqlite
      .prepare(
        "update enrollment_tokens set status = 'rejected', rejected_at_ms = ? where enrollment_id = ?",
      )
      .run(1_725_000_004_000, "enr_existing_second_0002");
    expect(create("enr_existing_retry_0004", 1_725_000_005_000)).toEqual(
      expect.objectContaining({ kind: "created" }),
    );
    expect(
      database.sqlite
        .prepare(
          "select name from sqlite_master where type = 'index' and name = 'enrollment_tokens_one_active_existing_host_idx'",
        )
        .get(),
    ).toEqual({ name: "enrollment_tokens_one_active_existing_host_idx" });

    database.close();
  });

  it("creates and inspects an independent terminal replacement recovery without Host version truth", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    createHost(database, { id: 7, probeId: "probe-current" });
    const outcome = Buffer.from(
      (enoki.v1.ProbeRegistrationResponse as any).encode(
        (enoki.v1.ProbeRegistrationResponse as any).create({
          hostId: "7",
          probeId: "probe-current",
        }),
      ).finish(),
    );
    database.sqlite
      .prepare(
        `insert into enrollment_tokens (
          enrollment_id, token_hash, created_at_ms, expires_at_ms, used_at_ms,
          target_kind, target_host_id, expected_hub_origin, expected_probe_id,
          expected_probe_version, source_probe_sha256_json, target_asset_set_digest,
          target_probe_version, status, managed_host_id, rejected_at_ms,
          rejection_code, registration_outcome
        ) values (?, ?, ?, ?, ?, 'manual_reinstall', ?, ?, ?, ?, ?, ?, ?, 'rejected', ?, ?, 'probe_startup_timeout', ?)`,
      )
      .run(
        "enr_terminal_predecessor_0001",
        "terminal-token",
        1_725_000_000_000,
        1_725_000_060_000,
        1_725_000_001_000,
        7,
        "https://hub.example.test",
        "probe-before-replacement",
        "1.2.3",
        JSON.stringify(["a".repeat(64)]),
        `sha256:${"b".repeat(64)}`,
        "1.2.3",
        7,
        1_725_000_062_000,
        outcome,
      );
    const predecessor = database.enrollments.terminalReplacementPredecessorForHost({
      currentProbeId: "probe-current",
      hostId: 7,
    });
    expect(predecessor).toEqual({
      enrollmentId: "enr_terminal_predecessor_0001",
      targetAssetSetDigest: `sha256:${"b".repeat(64)}`,
      targetProbeVersion: "1.2.3",
    });
    expect(
      database.enrollments.terminalReplacementPredecessorForHost({
        currentProbeId: "probe-wrong-current",
        hostId: 7,
      }),
    ).toBeNull();
    expect(
      database.enrollments.createPending({
        createdAtMs: 1_725_000_063_000,
        enrollmentId: "enr_terminal_wrong_predecessor_0002",
        expiresAtMs: 1_725_000_123_000,
        target: {
          expectedHubOrigin: "https://hub.example.test",
          expectedProbeId: "probe-current",
          expectedProbeVersion: "1.2.3",
          hostId: 7,
          kind: "manual_reinstall",
          replacementPredecessorEnrollmentId: "enr_missing_predecessor_0000",
          sourceProbeSha256: ["c".repeat(64)],
          targetAssetSetDigest: `sha256:${"d".repeat(64)}`,
          targetProbeVersion: "1.2.4",
        },
        tokenHash: "wrong-predecessor-token",
      }),
    ).toEqual({ kind: "existing_host_unavailable" });
    expect(
      database.enrollments.createPending({
        createdAtMs: 1_725_000_063_000,
        enrollmentId: "enr_terminal_ordinary_null_version_0002",
        expiresAtMs: 1_725_000_123_000,
        target: {
          expectedHubOrigin: "https://hub.example.test",
          expectedProbeId: "probe-current",
          expectedProbeVersion: "1.2.3",
          hostId: 7,
          kind: "manual_reinstall",
          sourceProbeSha256: ["c".repeat(64)],
          targetAssetSetDigest: `sha256:${"d".repeat(64)}`,
          targetProbeVersion: "1.2.4",
        },
        tokenHash: "ordinary-null-version-token",
      }),
    ).toEqual({ kind: "existing_host_unavailable" });
    const created = database.enrollments.createPending({
      createdAtMs: 1_725_000_063_000,
      enrollmentId: "enr_terminal_successor_0002",
      expiresAtMs: 1_725_000_123_000,
      target: {
        expectedHubOrigin: "https://hub.example.test",
        expectedProbeId: "probe-current",
        expectedProbeVersion: "1.2.3",
        hostId: 7,
        kind: "manual_reinstall",
        replacementPredecessorEnrollmentId: "enr_terminal_predecessor_0001",
        sourceProbeSha256: ["c".repeat(64)],
        targetAssetSetDigest: `sha256:${"d".repeat(64)}`,
        targetProbeVersion: "1.2.4",
      },
      tokenHash: "successor-token",
    });
    expect(created.kind).toBe("created");
    expect(
      database.enrollments.inspectPending({
        nowMs: 1_725_000_064_000,
        tokenHash: "successor-token",
      }),
    ).toMatchObject({
      sourceProbeVersion: "1.2.3",
      targetKind: "manual_reinstall",
    });
    const candidate = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const candidatePublicKeyPem = candidate.publicKey.export({
      format: "pem",
      type: "spki",
    });
    const registration = database.enrollments.registerNewHost({
      host: {
        architecture: null,
        clockSkewDetected: false,
        connectAddress: "10.0.0.20",
        createdAtMs: 1_725_000_065_000,
        displayName: "Recovered Host",
        displayNameEdited: false,
        probeConfigurationVersion: "default-v1",
        probeId: "probe-terminal-successor",
        probePublicKeyPem: candidatePublicKeyPem,
        probeSecretHash: "successor-secret",
      },
      hostProfile: null,
      registeredAtMs: 1_725_000_065_000,
      registrationAttempt: {
        candidatePublicKeyPem,
        committedSourceProbeSha256: "c".repeat(64),
        enrollmentId: "enr_terminal_successor_0002",
        hostId: 7,
        hubOrigin: "https://hub.example.test",
        oldProbeId: "probe-current",
        outcome: (host) =>
          Buffer.from(
            (enoki.v1.ProbeRegistrationResponse as any).encode(
              (enoki.v1.ProbeRegistrationResponse as any).create({
                hostId: String(host.id),
                probeId: host.probeId,
              }),
            ).finish(),
          ),
        signedAttemptSha256: "e".repeat(64),
        sourceProbeVersion: "1.2.3",
        targetAssetSetDigest: `sha256:${"d".repeat(64)}`,
        targetProbeVersion: "1.2.4",
      },
      tokenHash: "successor-token",
      verificationDeadlineAtMs: 1_725_000_125_000,
    });
    expect(registration).toMatchObject({
      enrollment: { status: "verifying" },
      host: { id: 7, probeId: "probe-terminal-successor" },
      replayed: false,
    });
    database.close();
  });
});

async function writeMigration(
  migrationsFolder: string,
  name: string,
  statements: string[],
) {
  const migrationFolder = path.join(migrationsFolder, name);
  await mkdir(migrationFolder, { recursive: true });
  await writeFile(
    path.join(migrationFolder, "migration.sql"),
    statements.join(";--> statement-breakpoint\n"),
  );
}

function createHost(
  database: ReturnType<typeof initializeHubDatabase>,
  input: { id: number; probeId: string },
) {
  database.sqlite
    .prepare(`insert into managed_hosts (
    id, probe_id, probe_secret_hash, display_name, display_name_edited,
    connect_address, created_at_ms, clock_skew_detected, last_clock_skew_ms,
    probe_configuration_version
  ) values (?, ?, ?, ?, 0, ?, ?, 0, null, ?)`)
    .run(
      input.id,
      input.probeId,
      `secret-hash-${input.id}`,
      `Host ${input.id}`,
      "10.0.0.20",
      1_725_000_000_000,
      "default-v1",
    );
}

function migrationHistoryTables(sqlite: {
  prepare: (sql: string) => { all: () => unknown[] };
}) {
  return sqlite
    .prepare(
      "select name from sqlite_master where type = 'table' and name like '__%migrations'",
    )
    .all()
    .map((row) => (row as { name: string }).name);
}

function tables(sqlite: {
  prepare: (sql: string) => {
    all: () => unknown[];
  };
}) {
  return sqlite
    .prepare("select name from sqlite_master where type = 'table'")
    .all()
    .map((row) => (row as { name: string }).name);
}

function uniqueIndexedColumns(sqlite: {
  prepare: (sql: string) => {
    all: () => unknown[];
  };
}) {
  return sqlite
    .prepare(
      `
      select m.name || '.' || ii.name as column_name
      from sqlite_master m
      join pragma_index_list(m.name) il
      join pragma_index_info(il.name) ii
      where m.type = 'table' and il."unique" = 1
      order by column_name
      `,
    )
    .all()
    .map((row) => (row as { column_name: string }).column_name);
}

function indexedColumns(sqlite: {
  prepare: (sql: string) => {
    all: () => unknown[];
  };
}) {
  return sqlite
    .prepare(
      `
      select m.name || '.' || ii.name as column_name
      from sqlite_master m
      join pragma_index_list(m.name) il
      join pragma_index_info(il.name) ii
      where m.type = 'table'
      order by column_name
      `,
    )
    .all()
    .map((row) => (row as { column_name: string }).column_name);
}
