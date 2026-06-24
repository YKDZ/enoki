import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { enoki } from "../../../packages/proto/src/generated/ts/enoki_pb.js";
import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

async function createTemporaryDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-host-profile-"));
  tempRoots.push(dataRoot);

  return initializeHubDatabase({
    dataRoot,
    sqlitePath: path.join(dataRoot, "enoki.db"),
  });
}

function fakeHostProfile(
  overrides: Partial<enoki.v1.IHostProfileSnapshot> = {},
): enoki.v1.IHostProfileSnapshot {
  return {
    architecture: "x86_64",
    collectorCapabilities: {
      official: {
        cpu: { available: true },
        disk: { available: false },
      },
    },
    cpuBaseFrequencyMhz: 2_100,
    cpuCount: 8,
    cpuModel: "AMD EPYC",
    filesystems: [
      {
        availableBytes: 30_000,
        filesystemType: "xfs",
        mountPoint: "/data",
        totalBytes: 100_000,
      },
    ],
    hostname: "adapter-host",
    kernel: "6.9.0",
    memoryTotalBytes: 34_359_738_368,
    networkInterfaces: [
      {
        addresses: ["10.0.0.20"],
        name: "eth0",
      },
    ],
    os: "linux",
    probeVersion: "0.3.0",
    processCount: 120,
    ...overrides,
  };
}

describe("Host Profile storage adapter", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("inserts a fake payload and reads the full typed API view", async () => {
    const database = await createTemporaryDatabase();
    const host = database.hosts.create({
      clockSkewDetected: false,
      connectAddress: "10.0.0.20",
      createdAtMs: 1_725_000_000_000,
      displayName: "adapter-host",
      displayNameEdited: false,
      lastClockSkewMs: null,
      probeConfigurationVersion: "default-v1",
      probeId: "probe-adapter",
      probeSecretHash: "secret-hash",
    });

    const result = database.snapshotCollectors.hostProfile.write({
      hostId: host.id,
      payload: fakeHostProfile(),
      snapshotHash: "hash-1",
      updatedAtMs: 1_725_000_000_100,
    });

    expect(result.changed).toBe(true);
    expect(database.snapshotCollectors.hostProfile.read(host.id)).toEqual(
      expect.objectContaining({
        collectorCapabilities: {
          official: {
            cpu: { available: true },
            disk: { available: false },
          },
        },
        cpuBaseFrequencyMhz: 2_100,
        hostname: "adapter-host",
        memoryTotalBytes: 34_359_738_368,
        processCount: 120,
      }),
    );

    database.close();
  });

  it("dispatches Host Profile payload writes by Snapshot Collector id and owns the Host projection", async () => {
    const database = await createTemporaryDatabase();
    const host = database.hosts.create({
      clockSkewDetected: false,
      connectAddress: "10.0.0.20",
      createdAtMs: 1_725_000_000_000,
      displayName: "adapter-host",
      displayNameEdited: false,
      lastClockSkewMs: null,
      probeConfigurationVersion: "default-v1",
      probeId: "probe-adapter-dispatch",
      probeSecretHash: "secret-hash-dispatch",
    });

    const result = database.snapshotCollectors.write({
      collectorId: "official.host-profile",
      hostId: host.id,
      payload: fakeHostProfile({
        cpuCount: 12,
        hostname: "dispatch-host",
        probeVersion: "0.5.0",
      }),
      snapshotHash: "hash-dispatch",
      updatedAtMs: 1_725_000_000_100,
    });

    expect(result).toEqual(
      expect.objectContaining({
        changed: true,
        view: expect.objectContaining({
          cpuCount: 12,
          hostname: "dispatch-host",
          probeVersion: "0.5.0",
        }),
      }),
    );
    expect(database.snapshotCollectors.hostProfile.read(host.id)).toEqual(
      expect.objectContaining({
        cpuCount: 12,
        hostname: "dispatch-host",
        probeVersion: "0.5.0",
      }),
    );
    expect(
      database.sqlite
        .prepare(
          "select hostname, inventory_hash, probe_version from managed_hosts where id = ?",
        )
        .get(host.id),
    ).toEqual({
      hostname: "dispatch-host",
      inventory_hash: "hash-dispatch",
      probe_version: "0.5.0",
    });

    database.close();
  });

  it("does not update the stored Host Profile when the snapshot hash is unchanged", async () => {
    const database = await createTemporaryDatabase();
    const host = database.hosts.create({
      clockSkewDetected: false,
      connectAddress: "10.0.0.20",
      createdAtMs: 1_725_000_000_000,
      displayName: "adapter-host",
      displayNameEdited: false,
      lastClockSkewMs: null,
      probeConfigurationVersion: "default-v1",
      probeId: "probe-adapter-noop",
      probeSecretHash: "secret-hash-noop",
    });

    database.snapshotCollectors.hostProfile.write({
      hostId: host.id,
      payload: fakeHostProfile({ hostname: "adapter-host" }),
      snapshotHash: "hash-1",
      updatedAtMs: 1_725_000_000_100,
    });
    const result = database.snapshotCollectors.hostProfile.write({
      hostId: host.id,
      payload: fakeHostProfile({ hostname: "ignored-host" }),
      snapshotHash: "hash-1",
      updatedAtMs: 1_725_000_000_200,
    });

    expect(result.changed).toBe(false);
    expect(database.snapshotCollectors.hostProfile.read(host.id)).toEqual(
      expect.objectContaining({
        hostname: "adapter-host",
      }),
    );
    expect(
      database.sqlite
        .prepare(
          "select count(*) as count, updated_at_ms from official_host_profiles where managed_host_id = ?",
        )
        .get(host.id),
    ).toEqual({
      count: 1,
      updated_at_ms: 1_725_000_000_100,
    });

    database.close();
  });

  it("updates a fake payload when the snapshot hash changes", async () => {
    const database = await createTemporaryDatabase();
    const host = database.hosts.create({
      clockSkewDetected: false,
      connectAddress: "10.0.0.20",
      createdAtMs: 1_725_000_000_000,
      displayName: "adapter-host",
      displayNameEdited: false,
      lastClockSkewMs: null,
      probeConfigurationVersion: "default-v1",
      probeId: "probe-adapter-update",
      probeSecretHash: "secret-hash-update",
    });

    database.snapshotCollectors.hostProfile.write({
      hostId: host.id,
      payload: fakeHostProfile({ hostname: "adapter-host" }),
      snapshotHash: "hash-1",
      updatedAtMs: 1_725_000_000_100,
    });
    const result = database.snapshotCollectors.hostProfile.write({
      hostId: host.id,
      payload: fakeHostProfile({
        cpuCount: 16,
        hostname: "updated-host",
        probeVersion: "0.4.0",
      }),
      snapshotHash: "hash-2",
      updatedAtMs: 1_725_000_000_200,
    });

    expect(result.changed).toBe(true);
    expect(database.snapshotCollectors.hostProfile.read(host.id)).toEqual(
      expect.objectContaining({
        cpuCount: 16,
        hostname: "updated-host",
        probeVersion: "0.4.0",
      }),
    );
    expect(
      database.sqlite
        .prepare(
          "select snapshot_hash, hostname, probe_version, updated_at_ms from official_host_profiles where managed_host_id = ?",
        )
        .get(host.id),
    ).toEqual({
      hostname: "updated-host",
      probe_version: "0.4.0",
      snapshot_hash: "hash-2",
      updated_at_ms: 1_725_000_000_200,
    });

    database.close();
  });

  it("rolls back Host Profile storage when the Host projection write fails", async () => {
    const database = await createTemporaryDatabase();
    const host = database.hosts.create({
      clockSkewDetected: false,
      connectAddress: "10.0.0.20",
      createdAtMs: 1_725_000_000_000,
      displayName: "adapter-host",
      displayNameEdited: false,
      lastClockSkewMs: null,
      probeConfigurationVersion: "default-v1",
      probeId: "probe-adapter-rollback",
      probeSecretHash: "secret-hash-rollback",
    });
    database.sqlite.exec(`
      create trigger fail_host_profile_projection
      before update of hostname on managed_hosts
      begin
        select raise(abort, 'projection failed');
      end;
    `);

    expect(() =>
      database.snapshotCollectors.hostProfile.write({
        hostId: host.id,
        payload: fakeHostProfile({ hostname: "rollback-host" }),
        snapshotHash: "hash-rollback",
        updatedAtMs: 1_725_000_000_100,
      }),
    ).toThrow("projection failed");
    expect(
      database.sqlite
        .prepare(
          "select count(*) as count from official_host_profiles where managed_host_id = ?",
        )
        .get(host.id),
    ).toEqual({ count: 0 });

    database.close();
  });
});
