import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rename as renamePath,
  rm,
  symlink,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { afterEach, describe, expect, it } from "vitest";

import {
  initializeHubDatabase,
  type HubDatabase,
} from "../src/database/index.js";
import { runHubStateSnapshotCli } from "../src/hub-state-snapshot/cli.js";
import {
  createHubStateSnapshotV1,
  hubStateSnapshotV1,
} from "../src/hub-state-snapshot/index.js";
import { finalizeMetricsArchive } from "../src/metrics-archive/finalizer.js";
import { writeMetricsArchiveFile } from "../src/metrics-archive/writer.js";

const temporaryRoots: string[] = [];
const releaseBaseline = {
  hubImageDigest: `sha256:${"a".repeat(64)}`,
  version: "v1.2.3",
};

afterEach(async () => {
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe("Hub State Snapshot v1", () => {
  it("snapshots and verifies every file in the configured persistent state", async () => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const archiveDirectory = path.join(dataRoot, "metrics-archive");
    const sqlitePath = path.join(dataRoot, "enoki.db");
    const snapshotPath = path.join(root, "snapshot");
    await mkdir(archiveDirectory, { recursive: true });
    await writeFile(sqlitePath, "primary database");
    await writeFile(
      path.join(archiveDirectory, "metrics-archive-2026-07.sqlite"),
      "archived metrics",
    );

    const created = await hubStateSnapshotV1.snapshot({
      hubStopped: true,
      persistentState: { archiveDirectory, dataRoot, sqlitePath },
      releaseBaseline,
      snapshotPath,
    });
    const verified = await hubStateSnapshotV1.verify({
      expectedManifestDigest: created.manifestDigest,
      hubStopped: true,
      releaseBaseline,
      snapshotPath,
    });

    expect(created.manifest).toEqual(verified.manifest);
    expect(created.manifest).toMatchObject({
      recoveryTime: expect.stringMatching(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      ),
      releaseBaseline,
      schemaVersion: 1,
      toolVersion: "v1",
    });
    expect(created.manifest.logicalRoots).toMatchObject([
      {
        id: "data-root",
        kind: "directory",
        payloadPath: "roots/data-root",
        sourcePath: dataRoot,
      },
    ]);
    expect(created.manifest.files).toMatchObject([
      {
        byteLength: 16,
        logicalRoot: "data-root",
        path: "enoki.db",
        sha256: sha256("primary database"),
      },
      {
        byteLength: 16,
        logicalRoot: "data-root",
        path: "metrics-archive/metrics-archive-2026-07.sqlite",
        sha256: sha256("archived metrics"),
      },
    ]);
    expect(
      await readFile(
        path.join(snapshotPath, "roots/data-root/enoki.db"),
        "utf8",
      ),
    ).toBe("primary database");
  });

  it("captures explicitly configured database and Metrics Archive paths outside the data root", async () => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const deploymentDirectory = path.join(root, "deployment");
    const archiveDirectory = path.join(root, "external-archive");
    const sqlitePath = path.join(root, "external-database/enoki.db");
    const snapshotPath = path.join(root, "snapshot");
    await mkdir(dataRoot, { recursive: true });
    await mkdir(path.dirname(sqlitePath), { recursive: true });
    await mkdir(archiveDirectory, { recursive: true });
    await mkdir(deploymentDirectory, { recursive: true });
    await writeFile(path.join(dataRoot, "state.json"), "hot state");
    await writeFile(sqlitePath, "external database");
    await writeFile(path.join(archiveDirectory, "archive.sqlite"), "archive");
    await writeFile(path.join(deploymentDirectory, "compose.yaml"), "secret");

    const created = await hubStateSnapshotV1.snapshot({
      hubStopped: true,
      persistentState: { archiveDirectory, dataRoot, sqlitePath },
      releaseBaseline,
      snapshotPath,
    });

    expect(created.manifest.logicalRoots).toMatchObject([
      {
        id: "data-root",
        kind: "directory",
        payloadPath: "roots/data-root",
        sourcePath: dataRoot,
      },
      {
        id: "sqlite-database",
        kind: "file",
        payloadPath: "roots/sqlite-database",
        sourcePath: sqlitePath,
      },
      {
        id: "metrics-archive",
        kind: "directory",
        payloadPath: "roots/metrics-archive",
        sourcePath: archiveDirectory,
      },
    ]);
    expect(
      created.manifest.files.map((file) => [file.logicalRoot, file.path]),
    ).toEqual([
      ["data-root", "state.json"],
      ["sqlite-database", "."],
      ["metrics-archive", "archive.sqlite"],
    ]);
    expect(
      await readFile(path.join(snapshotPath, "roots/sqlite-database"), "utf8"),
    ).toBe("external database");
    await expect(
      readFile(path.join(snapshotPath, "deployment/compose.yaml"), "utf8"),
    ).rejects.toThrow();
  });

  it("rejects a tampered required file with a stable integrity error", async () => {
    const fixture = await createBasicSnapshot();
    await writeFile(
      path.join(fixture.snapshotPath, "roots/data-root/enoki.db"),
      "tampered database",
    );

    await expect(
      hubStateSnapshotV1.verify({
        expectedManifestDigest: fixture.created.manifestDigest,
        hubStopped: true,
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow(
      "Hub State Snapshot checksum mismatch: data-root/enoki.db",
    );
  });

  it("rejects a missing required file before it can be restored", async () => {
    const fixture = await createBasicSnapshot();
    await rm(path.join(fixture.snapshotPath, "roots/data-root/enoki.db"));

    await expect(
      hubStateSnapshotV1.verify({
        expectedManifestDigest: fixture.created.manifestDigest,
        hubStopped: true,
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow(
      "Hub State Snapshot required file is missing: data-root/enoki.db",
    );
  });

  it("rejects a structurally invalid manifest path", async () => {
    const fixture = await createBasicSnapshot();
    const manifestPath = path.join(fixture.snapshotPath, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      files: { path: string }[];
    };
    manifest.files[0]!.path = "../outside";
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    await expect(
      hubStateSnapshotV1.verify({
        expectedManifestDigest: sha256(await readFile(manifestPath)),
        hubStopped: true,
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow(
      "Hub State Snapshot manifest is structurally invalid: file path",
    );
  });

  it("rejects unmanifested payload content", async () => {
    const fixture = await createBasicSnapshot();
    await writeFile(
      path.join(fixture.snapshotPath, "roots/data-root/unmanifested.db"),
      "unexpected",
    );

    await expect(
      hubStateSnapshotV1.verify({
        expectedManifestDigest: fixture.created.manifestDigest,
        hubStopped: true,
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow(
      "Hub State Snapshot contains unmanifested content: data-root/unmanifested.db",
    );
  });

  it("rejects an unmanifested empty directory", async () => {
    const fixture = await createBasicSnapshot();
    await mkdir(
      path.join(fixture.snapshotPath, "roots/data-root/unmanifested-empty"),
    );

    await expect(
      hubStateSnapshotV1.verify({
        expectedManifestDigest: fixture.created.manifestDigest,
        hubStopped: true,
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow(
      "Hub State Snapshot contains unmanifested content: data-root/unmanifested-empty",
    );
  });

  it("rejects overlapping external logical roots as ambiguous", async () => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const archiveDirectory = path.join(root, "external-archive");
    const sqlitePath = path.join(archiveDirectory, "enoki.db");
    await mkdir(dataRoot);
    await mkdir(archiveDirectory);
    await writeFile(sqlitePath, "database");

    await expect(
      hubStateSnapshotV1.snapshot({
        hubStopped: true,
        persistentState: { archiveDirectory, dataRoot, sqlitePath },
        releaseBaseline,
        snapshotPath: path.join(root, "snapshot"),
      }),
    ).rejects.toThrow(
      "Hub persistent state paths are ambiguous: sqlite-database overlaps metrics-archive",
    );
  });

  it("restores the verified recovery point and removes post-snapshot writes", async () => {
    const fixture = await createBasicSnapshot();
    await writeFile(fixture.sqlitePath, "candidate database");
    await writeFile(path.join(fixture.dataRoot, "candidate-write"), "newer");

    const restored = await hubStateSnapshotV1.restore({
      confirmDataLossAfter: fixture.created.manifest.recoveryTime,
      expectedManifestDigest: fixture.created.manifestDigest,
      hubStopped: true,
      persistentState: {
        archiveDirectory: fixture.archiveDirectory,
        dataRoot: fixture.dataRoot,
        sqlitePath: fixture.sqlitePath,
      },
      releaseBaseline,
      snapshotPath: fixture.snapshotPath,
    });

    expect(await readFile(fixture.sqlitePath, "utf8")).toBe("primary database");
    await expect(
      readFile(path.join(fixture.dataRoot, "candidate-write"), "utf8"),
    ).rejects.toThrow();
    expect(restored.message).toBe(
      `Hub State Snapshot restored to ${fixture.created.manifest.recoveryTime}; writes after this recovery point were permanently lost. Start Hub image ${releaseBaseline.hubImageDigest} (${releaseBaseline.version}).`,
    );
  });

  it("preserves coherent non-empty database references and external Metrics Archive content", async () => {
    const fixture = await createCoherentExternalFixture();
    const created = await hubStateSnapshotV1.snapshot({
      hubStopped: true,
      persistentState: fixture.persistentState,
      releaseBaseline,
      snapshotPath: fixture.snapshotPath,
    });
    const archivedFile = created.manifest.files.find(
      (file) => file.logicalRoot === "metrics-archive",
    );
    expect(archivedFile).toMatchObject({
      byteLength: expect.any(Number),
      path: path.basename(fixture.archivePath),
      sha256: fixture.archiveChecksum,
    });

    await writeFile(fixture.persistentState.sqlitePath, "candidate database");
    await writeFile(fixture.archivePath, "candidate archive");
    await writeFile(
      path.join(fixture.persistentState.dataRoot, "candidate-state"),
      "newer",
    );
    await hubStateSnapshotV1.restore({
      confirmDataLossAfter: created.manifest.recoveryTime,
      expectedManifestDigest: created.manifestDigest,
      hubStopped: true,
      persistentState: fixture.persistentState,
      releaseBaseline,
      snapshotPath: fixture.snapshotPath,
    });

    const restoredDatabase = initializeHubDatabase({
      dataRoot: fixture.persistentState.dataRoot,
      sqlitePath: fixture.persistentState.sqlitePath,
    });
    const restoredRun = restoredDatabase.metricsArchives.findRun(fixture.runId);
    expect(restoredRun).toMatchObject({
      archivePath: fixture.archivePath,
      checksumSha256: fixture.archiveChecksum,
      rowCounts: expect.objectContaining({
        metric_samples: 1,
        report_observations: 1,
      }),
      status: "succeeded",
    });
    restoredDatabase.close();
    expect(sha256(await readFile(fixture.archivePath))).toBe(
      fixture.archiveChecksum,
    );
    const restoredArchive = new DatabaseSync(fixture.archivePath, {
      readOnly: true,
    });
    try {
      expect(
        restoredArchive
          .prepare("select count(*) as count from metric_samples")
          .get(),
      ).toEqual({ count: 1 });
    } finally {
      restoredArchive.close();
    }
    await expect(
      readFile(
        path.join(fixture.persistentState.dataRoot, "candidate-state"),
        "utf8",
      ),
    ).rejects.toThrow();
  });

  it("rejects a snapshot destination that overlaps persistent state", async () => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const archiveDirectory = path.join(dataRoot, "metrics-archive");
    const sqlitePath = path.join(dataRoot, "enoki.db");
    await mkdir(archiveDirectory, { recursive: true });
    await writeFile(sqlitePath, "database");

    await expect(
      hubStateSnapshotV1.snapshot({
        hubStopped: true,
        persistentState: { archiveDirectory, dataRoot, sqlitePath },
        releaseBaseline,
        snapshotPath: path.join(dataRoot, "snapshot"),
      }),
    ).rejects.toThrow(
      "Hub State Snapshot destination must not overlap persistent state",
    );
  });

  it("requires an explicit stopped-Hub acknowledgement", async () => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const archiveDirectory = path.join(dataRoot, "metrics-archive");
    const sqlitePath = path.join(dataRoot, "enoki.db");
    await mkdir(archiveDirectory, { recursive: true });
    await writeFile(sqlitePath, "database");

    await expect(
      hubStateSnapshotV1.snapshot({
        hubStopped: false as true,
        persistentState: { archiveDirectory, dataRoot, sqlitePath },
        releaseBaseline,
        snapshotPath: path.join(root, "snapshot"),
      }),
    ).rejects.toThrow(
      "Hub must be stopped before managing a Hub State Snapshot",
    );
  });

  it("rejects a database with active SQLite sidecar files", async () => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const archiveDirectory = path.join(dataRoot, "metrics-archive");
    const sqlitePath = path.join(dataRoot, "enoki.db");
    await mkdir(archiveDirectory, { recursive: true });
    await writeFile(sqlitePath, "database");
    await writeFile(`${sqlitePath}-wal`, "uncheckpointed writes");

    await expect(
      hubStateSnapshotV1.snapshot({
        hubStopped: true,
        persistentState: { archiveDirectory, dataRoot, sqlitePath },
        releaseBaseline,
        snapshotPath: path.join(root, "snapshot"),
      }),
    ).rejects.toThrow(
      "Hub SQLite database has active sidecar files; stop the Hub cleanly before snapshot",
    );
  });

  it("refuses newer-state replacement until the exact recovery time is confirmed", async () => {
    const fixture = await createBasicSnapshot();
    await writeFile(fixture.sqlitePath, "candidate database");

    await expect(
      hubStateSnapshotV1.restore({
        confirmDataLossAfter: "2026-01-01T00:00:00.000Z",
        expectedManifestDigest: fixture.created.manifestDigest,
        hubStopped: true,
        persistentState: {
          archiveDirectory: fixture.archiveDirectory,
          dataRoot: fixture.dataRoot,
          sqlitePath: fixture.sqlitePath,
        },
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow(
      `Hub Restore will permanently lose writes after ${fixture.created.manifest.recoveryTime}`,
    );
    expect(await readFile(fixture.sqlitePath, "utf8")).toBe(
      "candidate database",
    );
    expect(
      (await readdir(fixture.dataRoot)).filter((entry) =>
        entry.startsWith(".enoki-hub-state-"),
      ),
    ).toEqual([]);
  });

  it("exposes the same v1 verification through the stable CLI", async () => {
    const fixture = await createBasicSnapshot();
    const output: string[] = [];

    await runHubStateSnapshotCli(
      [
        "v1",
        "verify",
        "--snapshot",
        fixture.snapshotPath,
        "--baseline-version",
        releaseBaseline.version,
        "--baseline-image-digest",
        releaseBaseline.hubImageDigest,
        "--confirm-hub-stopped",
        "--expected-manifest-digest",
        fixture.created.manifestDigest,
      ],
      {},
      (line) => output.push(line),
    );

    expect(JSON.parse(output.join(""))).toMatchObject({
      manifest: {
        recoveryTime: fixture.created.manifest.recoveryTime,
        releaseBaseline,
        schemaVersion: 1,
      },
      operation: "verify",
      version: "v1",
    });
  });

  it("documents the external manifest digest trust boundary in CLI help", async () => {
    const output: string[] = [];
    await runHubStateSnapshotCli(["--help"], {}, (line) => output.push(line));
    expect(output.join("")).toContain(
      "copy that digest to an independently trusted runbook or E2E record",
    );
    expect(output.join("")).toContain(
      "verify and restore require that externally trusted digest",
    );
  });

  it("rolls back every logical root when a later atomic replacement fails", async () => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const sqlitePath = path.join(root, "database/enoki.db");
    const archiveDirectory = path.join(root, "archive");
    const archivePath = path.join(archiveDirectory, "archive.sqlite");
    const snapshotPath = path.join(root, "snapshot");
    await mkdir(dataRoot);
    await mkdir(path.dirname(sqlitePath));
    await mkdir(archiveDirectory);
    await writeFile(path.join(dataRoot, "state"), "baseline state");
    await writeFile(sqlitePath, "baseline database");
    await writeFile(archivePath, "baseline archive");
    const persistentState = { archiveDirectory, dataRoot, sqlitePath };
    const created = await hubStateSnapshotV1.snapshot({
      hubStopped: true,
      persistentState,
      releaseBaseline,
      snapshotPath,
    });
    await writeFile(path.join(dataRoot, "state"), "candidate state");
    await writeFile(sqlitePath, "candidate database");
    await writeFile(archivePath, "candidate archive");
    let injectedFailure = false;
    const failingService = createHubStateSnapshotV1({
      transactionFileSystem: {
        async rename(source, destination) {
          if (
            !injectedFailure &&
            source.includes(".enoki-hub-state-stage-") &&
            destination === sqlitePath
          ) {
            injectedFailure = true;
            throw new Error("simulated second-root commit failure");
          }
          await renamePath(source, destination);
        },
      },
    });

    await expect(
      failingService.restore({
        confirmDataLossAfter: created.manifest.recoveryTime,
        expectedManifestDigest: created.manifestDigest,
        hubStopped: true,
        persistentState,
        releaseBaseline,
        snapshotPath,
      }),
    ).rejects.toThrow("simulated second-root commit failure");
    expect(injectedFailure).toBe(true);
    expect(await readFile(path.join(dataRoot, "state"), "utf8")).toBe(
      "candidate state",
    );
    expect(await readFile(sqlitePath, "utf8")).toBe("candidate database");
    expect(await readFile(archivePath, "utf8")).toBe("candidate archive");
    expect(
      (await readdir(dataRoot)).filter((entry) =>
        entry.startsWith(".enoki-hub-state-"),
      ),
    ).toEqual([]);
  });

  it("rejects symbolic links that could escape a logical root", async () => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const archiveDirectory = path.join(dataRoot, "metrics-archive");
    const sqlitePath = path.join(dataRoot, "enoki.db");
    const outside = path.join(root, "outside");
    await mkdir(archiveDirectory, { recursive: true });
    await writeFile(sqlitePath, "database");
    await writeFile(outside, "must not be captured");
    await symlink(outside, path.join(dataRoot, "linked-state"));

    await expect(
      hubStateSnapshotV1.snapshot({
        hubStopped: true,
        persistentState: { archiveDirectory, dataRoot, sqlitePath },
        releaseBaseline,
        snapshotPath: path.join(root, "snapshot"),
      }),
    ).rejects.toThrow(
      "Hub persistent state contains an unsupported entry: linked-state",
    );
  });

  it("never overwrites an existing snapshot destination", async () => {
    const fixture = await createBasicSnapshot();
    const sentinel = path.join(fixture.snapshotPath, "sentinel");
    await writeFile(sentinel, "existing recovery evidence");

    await expect(
      hubStateSnapshotV1.snapshot({
        hubStopped: true,
        persistentState: {
          archiveDirectory: fixture.archiveDirectory,
          dataRoot: fixture.dataRoot,
          sqlitePath: fixture.sqlitePath,
        },
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow(
      "Hub State Snapshot destination already exists; refusing to overwrite",
    );
    expect(await readFile(sentinel, "utf8")).toBe("existing recovery evidence");
  });

  it("rejects a different Release Baseline identity", async () => {
    const fixture = await createBasicSnapshot();

    await expect(
      hubStateSnapshotV1.verify({
        expectedManifestDigest: fixture.created.manifestDigest,
        hubStopped: true,
        releaseBaseline: { ...releaseBaseline, version: "v1.2.4" },
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow("Hub State Snapshot does not match the Release Baseline");
  });

  it("verifies all snapshot bytes before mutating a restore destination", async () => {
    const fixture = await createBasicSnapshot();
    await writeFile(fixture.sqlitePath, "candidate database");
    await writeFile(
      path.join(fixture.snapshotPath, "roots/data-root/enoki.db"),
      "tampered snapshot",
    );

    await expect(
      hubStateSnapshotV1.restore({
        confirmDataLossAfter: fixture.created.manifest.recoveryTime,
        expectedManifestDigest: fixture.created.manifestDigest,
        hubStopped: true,
        persistentState: {
          archiveDirectory: fixture.archiveDirectory,
          dataRoot: fixture.dataRoot,
          sqlitePath: fixture.sqlitePath,
        },
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow("Hub State Snapshot checksum mismatch");
    expect(await readFile(fixture.sqlitePath, "utf8")).toBe(
      "candidate database",
    );
    expect(
      (await readdir(fixture.dataRoot)).filter((entry) =>
        entry.startsWith(".enoki-hub-state-"),
      ),
    ).toEqual([]);
  });

  it("rejects a verify-to-stage symbolic-link swap without mutating persistent state", async () => {
    const fixture = await createBasicSnapshot();
    const payload = path.join(fixture.snapshotPath, "roots/data-root/enoki.db");
    const originalPayload = `${payload}.original`;
    const outside = path.join(fixture.root, "outside");
    await writeFile(fixture.sqlitePath, "candidate database");
    await writeFile(outside, "primary database");
    const swappingService = createHubStateSnapshotV1({
      transactionFileSystem: {
        async checkpoint(name) {
          if (name === "before-stage-copy") {
            await renamePath(payload, originalPayload);
            await symlink(outside, payload);
          }
        },
        rename: renamePath,
      },
    });

    await expect(
      swappingService.restore({
        confirmDataLossAfter: fixture.created.manifest.recoveryTime,
        expectedManifestDigest: fixture.created.manifestDigest,
        hubStopped: true,
        persistentState: {
          archiveDirectory: fixture.archiveDirectory,
          dataRoot: fixture.dataRoot,
          sqlitePath: fixture.sqlitePath,
        },
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow();
    expect(await readFile(fixture.sqlitePath, "utf8")).toBe(
      "candidate database",
    );
  });

  it("preserves and strictly verifies sensitive file and directory ownership and modes", async () => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const protectedDirectory = path.join(dataRoot, "private");
    const archiveDirectory = path.join(dataRoot, "metrics-archive");
    const sqlitePath = path.join(dataRoot, "enoki.db");
    const snapshotPath = path.join(root, "snapshot");
    await mkdir(protectedDirectory, { recursive: true, mode: 0o700 });
    await mkdir(archiveDirectory, { mode: 0o750 });
    await writeFile(path.join(protectedDirectory, "identity.key"), "secret", {
      mode: 0o600,
    });
    await writeFile(sqlitePath, "database", { mode: 0o640 });
    await chmod(dataRoot, 0o710);
    const created = await hubStateSnapshotV1.snapshot({
      hubStopped: true,
      persistentState: { archiveDirectory, dataRoot, sqlitePath },
      releaseBaseline,
      snapshotPath,
    });
    expect(
      created.manifest.files.find(
        (file) => file.path === "private/identity.key",
      ),
    ).toMatchObject({
      gid: process.getgid!(),
      mode: 0o600,
      uid: process.getuid!(),
    });
    expect(
      created.manifest.directories.find(
        (directory) => directory.path === "private",
      ),
    ).toMatchObject({
      gid: process.getgid!(),
      mode: 0o700,
      uid: process.getuid!(),
    });

    const snapshotSecret = path.join(
      snapshotPath,
      "roots/data-root/private/identity.key",
    );
    await chmod(snapshotSecret, 0o644);
    await expect(
      hubStateSnapshotV1.verify({
        expectedManifestDigest: created.manifestDigest,
        hubStopped: true,
        releaseBaseline,
        snapshotPath,
      }),
    ).rejects.toThrow("Hub State Snapshot metadata mismatch");
    await chmod(snapshotSecret, 0o600);
    await chmod(path.join(protectedDirectory, "identity.key"), 0o666);
    await hubStateSnapshotV1.restore({
      confirmDataLossAfter: created.manifest.recoveryTime,
      expectedManifestDigest: created.manifestDigest,
      hubStopped: true,
      persistentState: { archiveDirectory, dataRoot, sqlitePath },
      releaseBaseline,
      snapshotPath,
    });
    expect(
      (await stat(path.join(protectedDirectory, "identity.key"))).mode & 0o7777,
    ).toBe(0o600);
    expect((await stat(protectedDirectory)).mode & 0o7777).toBe(0o700);
  });

  it("rejects jointly altered payload and manifest against the external digest anchor", async () => {
    const fixture = await createBasicSnapshot();
    const manifestPath = path.join(fixture.snapshotPath, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      files: Array<{ byteLength: number; path: string; sha256: string }>;
    };
    const replacement = "attacker-controlled but self-consistent";
    const file = manifest.files.find((entry) => entry.path === "enoki.db")!;
    file.byteLength = Buffer.byteLength(replacement);
    file.sha256 = sha256(replacement);
    await writeFile(
      path.join(fixture.snapshotPath, "roots/data-root/enoki.db"),
      replacement,
    );
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    await expect(
      hubStateSnapshotV1.verify({
        expectedManifestDigest: fixture.created.manifestDigest,
        hubStopped: true,
        releaseBaseline,
        snapshotPath: fixture.snapshotPath,
      }),
    ).rejects.toThrow(
      "Hub State Snapshot manifest digest does not match the trusted expected digest",
    );
  });

  it.each([
    "1.2.3",
    "v01.2.3",
    "v1.02.3",
    "v1.2.03",
    "v1.2.3-alpha",
    "v1.2.3+build.1",
    "v1.2",
  ])("rejects non-stable Release Baseline version %s", async (version) => {
    const root = await temporaryRoot();
    const dataRoot = path.join(root, "data");
    const archiveDirectory = path.join(dataRoot, "metrics-archive");
    const sqlitePath = path.join(dataRoot, "enoki.db");
    await mkdir(archiveDirectory, { recursive: true });
    await writeFile(sqlitePath, "database");
    await expect(
      hubStateSnapshotV1.snapshot({
        hubStopped: true,
        persistentState: { archiveDirectory, dataRoot, sqlitePath },
        releaseBaseline: { ...releaseBaseline, version },
        snapshotPath: path.join(root, "snapshot"),
      }),
    ).rejects.toThrow("stable SemVer tag like v1.2.3");
  });

  it("recovers a SIGKILL-interrupted multi-root restore before the next verify", async () => {
    const fixture = await createCoherentExternalFixture();
    const created = await hubStateSnapshotV1.snapshot({
      hubStopped: true,
      persistentState: fixture.persistentState,
      releaseBaseline,
      snapshotPath: fixture.snapshotPath,
    });
    await writeFile(fixture.persistentState.sqlitePath, "candidate database");
    await writeFile(fixture.archivePath, "candidate archive");

    const child = spawn(
      "pnpm",
      [
        "--filter",
        "@enoki/hub",
        "exec",
        "vitest",
        "run",
        "test/hub-state-snapshot-crash-worker.test.ts",
      ],
      {
        cwd: path.resolve(import.meta.dirname, "../../.."),
        env: {
          ...process.env,
          ENOKI_CRASH_ARCHIVE_DIRECTORY:
            fixture.persistentState.archiveDirectory,
          ENOKI_CRASH_DATA_ROOT: fixture.persistentState.dataRoot,
          ENOKI_CRASH_DIGEST: created.manifestDigest,
          ENOKI_CRASH_RECOVERY_TIME: created.manifest.recoveryTime,
          ENOKI_CRASH_SNAPSHOT: fixture.snapshotPath,
          ENOKI_CRASH_SQLITE_PATH: fixture.persistentState.sqlitePath,
        },
        stdio: "ignore",
      },
    );
    const exit = await new Promise<{
      code: number | null;
      signal: NodeJS.Signals | null;
    }>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });
    expect(exit.code).not.toBe(0);
    await expect(
      readFile(
        path.join(
          fixture.persistentState.dataRoot,
          ".enoki-hub-state-restore-v1.json",
        ),
      ),
    ).resolves.toBeTruthy();

    await hubStateSnapshotV1.verify({
      expectedManifestDigest: created.manifestDigest,
      hubStopped: true,
      releaseBaseline,
      snapshotPath: fixture.snapshotPath,
    });
    expect(await readFile(fixture.persistentState.sqlitePath, "utf8")).toBe(
      "candidate database",
    );
    expect(await readFile(fixture.archivePath, "utf8")).toBe(
      "candidate archive",
    );
    await expect(
      readFile(
        path.join(
          fixture.persistentState.dataRoot,
          ".enoki-hub-state-restore-v1.json",
        ),
      ),
    ).rejects.toThrow();
  }, 30_000);
});

async function temporaryRoot() {
  const root = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-state-"));
  temporaryRoots.push(root);
  return root;
}

function sha256(value: string | Uint8Array) {
  return createHash("sha256").update(value).digest("hex");
}

async function createBasicSnapshot() {
  const root = await temporaryRoot();
  const dataRoot = path.join(root, "data");
  const archiveDirectory = path.join(dataRoot, "metrics-archive");
  const sqlitePath = path.join(dataRoot, "enoki.db");
  const snapshotPath = path.join(root, "snapshot");
  await mkdir(archiveDirectory, { recursive: true });
  await writeFile(sqlitePath, "primary database");
  const created = await hubStateSnapshotV1.snapshot({
    hubStopped: true,
    persistentState: { archiveDirectory, dataRoot, sqlitePath },
    releaseBaseline,
    snapshotPath,
  });
  return {
    archiveDirectory,
    created,
    dataRoot,
    root,
    snapshotPath,
    sqlitePath,
  };
}

async function createCoherentExternalFixture() {
  const root = await temporaryRoot();
  const dataRoot = path.join(root, "data");
  const sqlitePath = path.join(root, "database/enoki.db");
  const archiveDirectory = path.join(root, "archive");
  const archivePath = path.join(
    archiveDirectory,
    "metrics-archive-2026-07.sqlite",
  );
  const temporaryArchivePath = `${archivePath}.tmp`;
  const snapshotPath = path.join(root, "snapshot");
  await mkdir(dataRoot, { recursive: true });
  await writeFile(path.join(dataRoot, "state-marker"), "baseline state");
  const database = initializeHubDatabase({ dataRoot, sqlitePath });
  const host = createArchiveFixtureHost(database);
  const bootId = "boot-snapshot-fixture";
  const collectedAtMs = Date.UTC(2026, 6, 12, 12);
  const receivedAtMs = collectedAtMs + 1_000;
  const plan = {
    identity: {
      fileName: path.basename(archivePath),
      path: archivePath,
      sequence: 1,
    },
    period: "monthly" as const,
    rangeEndMs: Date.UTC(2026, 7, 1),
    rangeStartMs: Date.UTC(2026, 6, 1),
    samples: [
      {
        bootId,
        collectedAtMs,
        probeId: host.probeId,
        receivedAtMs,
        sequence: 1,
      },
    ],
  };
  database.metrics.recordObservationSample({
    observation: {
      bootId,
      hostId: host.id,
      probeId: host.probeId,
      receivedAtMs,
      sequence: 1,
    },
    sample: {
      bootId,
      collectedAtMs,
      hostId: host.id,
      memoryTotalBytes: 16_000,
      memoryUsedBytes: 8_000,
      probeId: host.probeId,
      receivedAtMs,
      sequence: 1,
    },
  });
  const started = database.metricsArchives.startRun({
    nowMs: Date.UTC(2026, 7, 1, 0, 0, 1),
    period: plan.period,
    rangeEndMs: plan.rangeEndMs,
    rangeStartMs: plan.rangeStartMs,
  });
  if (!started.ok) {
    throw new Error("Expected coherent Metrics Archive fixture to start.");
  }
  writeMetricsArchiveFile({
    archivePath: temporaryArchivePath,
    database: database.sqlite,
    nowMs: Date.UTC(2026, 7, 1),
    plan,
  });
  const finalized = finalizeMetricsArchive({
    finalPath: archivePath,
    nowMs: Date.UTC(2026, 7, 1, 0, 0, 2),
    plan,
    repository: database.metricsArchives,
    runId: started.run.id,
    tempPath: temporaryArchivePath,
  });
  database.close();
  if (!finalized.checksumSha256) {
    throw new Error("Expected coherent Metrics Archive checksum.");
  }

  return {
    archiveChecksum: finalized.checksumSha256,
    archivePath,
    persistentState: { archiveDirectory, dataRoot, sqlitePath },
    root,
    runId: started.run.id,
    snapshotPath,
  };
}

function createArchiveFixtureHost(database: HubDatabase) {
  return database.hosts.create({
    architecture: "x86_64",
    clockSkewDetected: false,
    connectAddress: "192.0.2.90",
    connectAddressEdited: false,
    cpuCount: 2,
    cpuModel: "Snapshot Fixture CPU",
    createdAtMs: Date.UTC(2026, 6, 1),
    deletedAtMs: null,
    description: "Hub State Snapshot fixture Host",
    displayName: "Snapshot fixture",
    displayNameEdited: false,
    hostname: "snapshot-fixture",
    kernel: "6.8",
    lastClockSkewMs: null,
    lastReportAtMs: Date.UTC(2026, 6, 12),
    memoryTotalBytes: 16_000,
    observedIp: "192.0.2.90",
    os: "linux",
    probeConfigurationErrorCode: null,
    probeConfigurationErrorFailedVersion: null,
    probeConfigurationErrorMessage: null,
    probeConfigurationErrorReportedAtMs: null,
    probeConfigurationVersion: "config-1",
    probeId: "probe-snapshot-fixture",
    probePublicKeyPem: "snapshot-fixture-public-key",
    probeSecretHash: "snapshot-fixture-secret-hash",
    probeVersion: "1.2.3",
  });
}
