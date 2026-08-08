import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  chown,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
} from "node:fs/promises";
import path from "node:path";

const manifestFileName = "manifest.json";
const transactionFileName = ".enoki-hub-state-restore-v1.json";
const transactionTemporaryFileName = `${transactionFileName}.tmp`;

export type HubPersistentState = {
  archiveDirectory: string;
  dataRoot: string;
  sqlitePath: string;
};

export type ReleaseBaselineIdentity = {
  hubImageDigest: string;
  version: string;
};

export type HubStateSnapshotMetadataV1 = {
  gid: number;
  mode: number;
  uid: number;
};

export type HubStateSnapshotManifestV1 = {
  directories: HubStateSnapshotDirectoryV1[];
  files: HubStateSnapshotFileV1[];
  logicalRoots: HubStateSnapshotLogicalRootV1[];
  recoveryTime: string;
  releaseBaseline: ReleaseBaselineIdentity;
  schemaVersion: 1;
  toolVersion: "v1";
};

export type HubStateSnapshotDirectoryV1 = HubStateSnapshotMetadataV1 & {
  logicalRoot: HubStateSnapshotLogicalRootV1["id"];
  path: string;
};

export type HubStateSnapshotLogicalRootV1 = HubStateSnapshotMetadataV1 & {
  id: "data-root" | "metrics-archive" | "sqlite-database";
  kind: "directory" | "file";
  payloadPath: string;
  sourcePath: string;
};

export type HubStateSnapshotFileV1 = HubStateSnapshotMetadataV1 & {
  byteLength: number;
  logicalRoot: HubStateSnapshotLogicalRootV1["id"];
  path: string;
  sha256: string;
};

export type SnapshotHubStateInputV1 = {
  hubStopped: true;
  persistentState: HubPersistentState;
  releaseBaseline: ReleaseBaselineIdentity;
  snapshotPath: string;
};

export type VerifyHubStateSnapshotInputV1 = {
  expectedManifestDigest: string;
  hubStopped: true;
  releaseBaseline: ReleaseBaselineIdentity;
  snapshotPath: string;
};

export type HubStateSnapshotResultV1 = {
  manifest: HubStateSnapshotManifestV1;
  manifestDigest: string;
  manifestDigestPath: string;
};

export type RestoreHubStateSnapshotInputV1 = VerifyHubStateSnapshotInputV1 & {
  confirmDataLossAfter: string;
  persistentState: HubPersistentState;
};

export type RestoreHubStateSnapshotResultV1 = HubStateSnapshotResultV1 & {
  message: string;
};

export type HubStateSnapshotTransactionFileSystem = {
  checkpoint?: (name: string) => Promise<void>;
  rename: (source: string, destination: string) => Promise<void>;
};

export type HubStateSnapshotServiceV1 = {
  restore: (
    input: RestoreHubStateSnapshotInputV1,
  ) => Promise<RestoreHubStateSnapshotResultV1>;
  snapshot: (
    input: SnapshotHubStateInputV1,
  ) => Promise<HubStateSnapshotResultV1>;
  verify: (
    input: VerifyHubStateSnapshotInputV1,
  ) => Promise<HubStateSnapshotResultV1>;
};

type RestoreStrategy = "directory-contents" | "replacement";

type RestoreJournalRoot = {
  backupPath: string;
  id: HubStateSnapshotLogicalRootV1["id"];
  originalExisted: boolean;
  originalMetadata?: HubStateSnapshotMetadataV1;
  snapshotTopNames: string[];
  stagePath: string;
  strategy: RestoreStrategy;
  targetPath: string;
};

type RestoreJournal = {
  pendingAction: null | { destination: string; source: string };
  phase: "committed" | "committing" | "preparing";
  progress: string[];
  roots: RestoreJournalRoot[];
  schemaVersion: 1;
  snapshotPath: string;
  transactionId: string;
};

type PlannedRoot = RestoreJournalRoot & {
  logicalRoot: HubStateSnapshotLogicalRootV1;
};

export function createHubStateSnapshotV1(
  options: {
    transactionFileSystem?: HubStateSnapshotTransactionFileSystem;
  } = {},
): HubStateSnapshotServiceV1 {
  const transactionFileSystem = options.transactionFileSystem ?? { rename };
  const service: HubStateSnapshotServiceV1 = {
    async snapshot(input) {
      requireStoppedHub(input.hubStopped);
      validateReleaseBaseline(input.releaseBaseline);
      await recoverRestoreTransaction(
        path.resolve(input.persistentState.dataRoot),
        transactionFileSystem,
      );

      const snapshotPath = path.resolve(input.snapshotPath);
      const digestPath = manifestDigestPath(snapshotPath);
      const logicalRoots = await planLogicalRoots(input.persistentState);
      if (
        (await optionalLstat(snapshotPath)) ||
        (await optionalLstat(digestPath))
      ) {
        throw new Error(
          "Hub State Snapshot destination already exists; refusing to overwrite.",
        );
      }
      const physicalSnapshotParent = await realpath(path.dirname(snapshotPath));
      const physicalDestinations = [
        path.join(physicalSnapshotParent, path.basename(snapshotPath)),
        path.join(physicalSnapshotParent, path.basename(digestPath)),
      ];
      for (const destination of physicalDestinations) {
        if (
          logicalRoots.some(
            (root) =>
              isPathInside(root.sourcePath, destination) ||
              isPathInside(destination, root.sourcePath),
          )
        ) {
          throw new Error(
            "Hub State Snapshot destination must not overlap persistent state.",
          );
        }
      }

      await mkdir(path.dirname(snapshotPath), { recursive: true });
      const stagingPath = await mkdtemp(
        path.join(path.dirname(snapshotPath), ".enoki-hub-state-snapshot-"),
      );
      try {
        const directories: HubStateSnapshotDirectoryV1[] = [];
        const files: HubStateSnapshotFileV1[] = [];
        for (const logicalRoot of logicalRoots) {
          const payloadPath = path.join(stagingPath, logicalRoot.payloadPath);
          if (logicalRoot.kind === "directory") {
            await mkdir(payloadPath, { recursive: true });
            await copySourceDirectory({
              destination: payloadPath,
              directories,
              files,
              logicalRoot: logicalRoot.id,
              source: logicalRoot.sourcePath,
            });
            await applyMetadata(payloadPath, logicalRoot);
          } else {
            await mkdir(path.dirname(payloadPath), { recursive: true });
            const captured = await copyRegularFile(
              logicalRoot.sourcePath,
              payloadPath,
            );
            Object.assign(logicalRoot, captured.metadata);
            files.push({
              ...captured.metadata,
              byteLength: captured.byteLength,
              logicalRoot: logicalRoot.id,
              path: ".",
              sha256: captured.sha256,
            });
          }
        }
        const manifest: HubStateSnapshotManifestV1 = {
          directories: canonicalEntries(directories, logicalRoots),
          files: canonicalEntries(files, logicalRoots),
          logicalRoots,
          recoveryTime: new Date().toISOString(),
          releaseBaseline: input.releaseBaseline,
          schemaVersion: 1,
          toolVersion: "v1",
        };
        const manifestBytes = Buffer.from(
          `${JSON.stringify(manifest, null, 2)}\n`,
        );
        const manifestDigest = sha256(manifestBytes);
        await writeDurableFile(
          path.join(stagingPath, manifestFileName),
          manifestBytes,
          0o600,
        );
        await syncTree(stagingPath);
        await rename(stagingPath, snapshotPath);
        await syncDirectory(path.dirname(snapshotPath));
        await writeDurableFile(
          digestPath,
          Buffer.from(`${manifestDigest}\n`),
          0o600,
        );
        return { manifest, manifestDigest, manifestDigestPath: digestPath };
      } catch (error) {
        await rm(stagingPath, { force: true, recursive: true });
        throw error;
      }
    },

    async verify(input) {
      requireStoppedHub(input.hubStopped);
      validateReleaseBaseline(input.releaseBaseline);
      validateManifestDigest(input.expectedManifestDigest);
      const snapshotPath = path.resolve(input.snapshotPath);
      const read = await readManifest(
        snapshotPath,
        input.expectedManifestDigest,
      );
      const dataRoot = read.manifest.logicalRoots.find(
        (root) => root.id === "data-root",
      )!.sourcePath;
      await recoverRestoreTransaction(dataRoot, transactionFileSystem);
      await verifyManifestAndPayload(snapshotPath, read.manifest);
      if (
        read.manifest.releaseBaseline.version !==
          input.releaseBaseline.version ||
        read.manifest.releaseBaseline.hubImageDigest !==
          input.releaseBaseline.hubImageDigest
      ) {
        throw new Error(
          "Hub State Snapshot does not match the Release Baseline.",
        );
      }
      return {
        manifest: read.manifest,
        manifestDigest: read.manifestDigest,
        manifestDigestPath: manifestDigestPath(snapshotPath),
      };
    },

    async restore(input) {
      requireStoppedHub(input.hubStopped);
      const verified = await service.verify(input);
      if (input.confirmDataLossAfter !== verified.manifest.recoveryTime) {
        throw new Error(
          `Hub Restore will permanently lose writes after ${verified.manifest.recoveryTime}. Repeat with that exact recovery time to confirm replacement of newer state.`,
        );
      }
      const destinations = configuredRootDestinations(input.persistentState);
      if (destinations.size !== verified.manifest.logicalRoots.length) {
        throw new Error(
          "Hub Restore destinations do not match the snapshot logical roots.",
        );
      }
      for (const logicalRoot of verified.manifest.logicalRoots) {
        if (destinations.get(logicalRoot.id) !== logicalRoot.sourcePath) {
          throw new Error(
            `Hub Restore destination does not match snapshot logical root: ${logicalRoot.id}`,
          );
        }
      }

      const snapshotPath = path.resolve(input.snapshotPath);
      const dataRoot = path.resolve(input.persistentState.dataRoot);
      const journalPath = path.join(dataRoot, transactionFileName);
      const transactionId = randomUUID();
      const roots = await planRestoreRoots(verified.manifest, transactionId);
      let journal: RestoreJournal = {
        pendingAction: null,
        phase: "preparing",
        progress: [],
        roots: roots.map(stripPlannedRoot),
        schemaVersion: 1,
        snapshotPath,
        transactionId,
      };
      await writeJournal(journalPath, journal);
      try {
        await transactionFileSystem.checkpoint?.("before-stage-copy");
        for (const root of roots) {
          await prepareRoot(root, snapshotPath, verified.manifest);
          journal.progress.push(`prepared:${root.id}`);
          await writeJournal(journalPath, journal);
        }
        await transactionFileSystem.checkpoint?.("after-stage-copy");
        await verifyStagedRoots(roots, verified.manifest);
        journal.phase = "committing";
        await writeJournal(journalPath, journal);
        for (const root of roots) {
          journal = await commitRoot(
            root,
            journal,
            journalPath,
            transactionFileSystem,
          );
        }
        journal.phase = "committed";
        journal.pendingAction = null;
        await writeJournal(journalPath, journal);
        await transactionFileSystem.checkpoint?.("after-commit-decision");
        await finishCommittedTransaction(journalPath, journal);
      } catch (error) {
        try {
          const onDisk = await readJournal(journalPath);
          if (onDisk.phase === "committed") {
            await finishCommittedTransaction(journalPath, onDisk);
          } else {
            await rollbackTransaction(
              journalPath,
              onDisk,
              transactionFileSystem,
            );
          }
        } catch (rollbackError) {
          throw new AggregateError(
            [error, rollbackError],
            "Hub Restore failed and could not completely recover; keep the Hub stopped.",
          );
        }
        throw error;
      }
      return {
        ...verified,
        message: `Hub State Snapshot restored to ${verified.manifest.recoveryTime}; writes after this recovery point were permanently lost. Start Hub image ${verified.manifest.releaseBaseline.hubImageDigest} (${verified.manifest.releaseBaseline.version}).`,
      };
    },
  };
  return service;
}

export const hubStateSnapshotV1 = createHubStateSnapshotV1();

async function copySourceDirectory(input: {
  destination: string;
  directories: HubStateSnapshotDirectoryV1[];
  files: HubStateSnapshotFileV1[];
  logicalRoot: HubStateSnapshotLogicalRootV1["id"];
  relativePath?: string;
  source: string;
}) {
  const relativePath = input.relativePath ?? "";
  const sourceDirectory = path.join(input.source, relativePath);
  const before = await requireDirectoryWithoutLinks(sourceDirectory);
  const entries = await readdir(sourceDirectory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    const entryPath = relativePath
      ? path.posix.join(relativePath, entry.name)
      : entry.name;
    if (
      entryPath === transactionFileName ||
      entryPath === transactionTemporaryFileName
    ) {
      throw new Error(
        "Hub persistent state contains an unfinished Hub Restore transaction.",
      );
    }
    const sourcePath = path.join(input.source, entryPath);
    const destinationPath = path.join(input.destination, entryPath);
    const details = await lstat(sourcePath);
    if (
      entry.isDirectory() &&
      details.isDirectory() &&
      !details.isSymbolicLink()
    ) {
      await mkdir(destinationPath);
      input.directories.push({
        ...metadata(details),
        logicalRoot: input.logicalRoot,
        path: entryPath,
      });
      await copySourceDirectory({ ...input, relativePath: entryPath });
      await applyMetadata(destinationPath, metadata(details));
      continue;
    }
    if (entry.isFile() && details.isFile() && !details.isSymbolicLink()) {
      const captured = await copyRegularFile(sourcePath, destinationPath);
      input.files.push({
        ...captured.metadata,
        byteLength: captured.byteLength,
        logicalRoot: input.logicalRoot,
        path: entryPath,
        sha256: captured.sha256,
      });
      continue;
    }
    throw new Error(
      `Hub persistent state contains an unsupported entry: ${entryPath}`,
    );
  }
  const after = await lstat(sourceDirectory);
  if (!sameIdentity(before, after) || !after.isDirectory()) {
    throw new Error(
      `Hub persistent state changed while it was being captured: ${relativePath || "."}`,
    );
  }
}

async function copyRegularFile(
  source: string,
  destination: string,
  expected?: HubStateSnapshotFileV1,
) {
  const sourceHandle = await open(source, constants.O_RDONLY | noFollowFlag());
  try {
    const before = await sourceHandle.stat();
    if (!before.isFile()) {
      throw new Error(
        `Hub State Snapshot content is not a regular file: ${source}`,
      );
    }
    const contents = await sourceHandle.readFile();
    const after = await sourceHandle.stat();
    if (!sameIdentity(before, after) || after.size !== contents.byteLength) {
      throw new Error(
        `Hub State Snapshot content changed while copying: ${source}`,
      );
    }
    const captured = {
      byteLength: contents.byteLength,
      metadata: metadata(after),
      sha256: sha256(contents),
    };
    if (
      expected &&
      (captured.byteLength !== expected.byteLength ||
        captured.sha256 !== expected.sha256 ||
        !sameMetadata(captured.metadata, expected))
    ) {
      throw new Error(
        `Hub State Snapshot changed while staging: ${expected.logicalRoot}/${expected.path}`,
      );
    }
    await writeDurableFile(destination, contents, captured.metadata.mode);
    await applyMetadata(destination, captured.metadata);
    await syncPath(destination);
    return captured;
  } finally {
    await sourceHandle.close();
  }
}

async function verifyManifestAndPayload(
  snapshotPath: string,
  manifest: HubStateSnapshotManifestV1,
) {
  const topLevel = await listImmediateEntries(snapshotPath);
  if (
    topLevel.directories.join("\0") !== "roots" ||
    topLevel.files.join("\0") !== manifestFileName
  ) {
    throw structuralError("snapshot layout");
  }
  const rootsEntries = await listImmediateEntries(
    path.join(snapshotPath, "roots"),
  );
  const expectedRootEntries = manifest.logicalRoots
    .map((root) => root.id)
    .sort();
  if (
    [...rootsEntries.directories, ...rootsEntries.files].sort().join("\0") !==
    expectedRootEntries.join("\0")
  ) {
    throw structuralError("logical root payloads");
  }

  for (const root of manifest.logicalRoots) {
    const payloadPath = path.join(snapshotPath, root.payloadPath);
    const details = await lstat(payloadPath);
    if (
      details.isSymbolicLink() ||
      (root.kind === "directory" && !details.isDirectory()) ||
      (root.kind === "file" && !details.isFile()) ||
      !sameMetadata(metadata(details), root)
    ) {
      throw structuralError(`logical root payload ${root.id}`);
    }
    if (root.kind === "directory") {
      const actual = await listPayloadEntries(payloadPath);
      const expectedFiles = new Set(
        manifest.files
          .filter((file) => file.logicalRoot === root.id)
          .map((file) => file.path),
      );
      const expectedDirectories = new Set(
        manifest.directories
          .filter((directory) => directory.logicalRoot === root.id)
          .map((directory) => directory.path),
      );
      const unexpected =
        actual.files.find((entry) => !expectedFiles.has(entry)) ??
        actual.directories.find((entry) => !expectedDirectories.has(entry));
      if (unexpected) {
        throw new Error(
          `Hub State Snapshot contains unmanifested content: ${root.id}/${unexpected}`,
        );
      }
    }
  }

  for (const directory of manifest.directories) {
    const candidate = payloadEntry(snapshotPath, directory);
    let details;
    try {
      details = await lstat(candidate);
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        throw new Error(
          `Hub State Snapshot required directory is missing: ${directory.logicalRoot}/${directory.path}`,
        );
      }
      throw error;
    }
    if (
      details.isSymbolicLink() ||
      !details.isDirectory() ||
      !sameMetadata(metadata(details), directory)
    ) {
      throw new Error(
        `Hub State Snapshot metadata mismatch: ${directory.logicalRoot}/${directory.path}`,
      );
    }
  }
  for (const file of manifest.files) {
    const candidate = payloadEntry(snapshotPath, file);
    try {
      const handle = await open(candidate, constants.O_RDONLY | noFollowFlag());
      try {
        const details = await handle.stat();
        if (!details.isFile() || !sameMetadata(metadata(details), file)) {
          throw new Error(
            `Hub State Snapshot metadata mismatch: ${file.logicalRoot}/${file.path}`,
          );
        }
        const contents = await handle.readFile();
        const after = await handle.stat();
        if (
          !sameIdentity(details, after) ||
          contents.byteLength !== file.byteLength ||
          sha256(contents) !== file.sha256
        ) {
          throw new Error(
            `Hub State Snapshot checksum mismatch: ${file.logicalRoot}/${file.path}`,
          );
        }
      } finally {
        await handle.close();
      }
    } catch (error) {
      if (
        isNodeError(error) &&
        (error.code === "ENOENT" || error.code === "ELOOP")
      ) {
        throw new Error(
          `Hub State Snapshot required file is missing: ${file.logicalRoot}/${file.path}`,
        );
      }
      throw error;
    }
  }
}

async function prepareRoot(
  root: PlannedRoot,
  snapshotPath: string,
  manifest: HubStateSnapshotManifestV1,
) {
  const payloadRoot = path.join(snapshotPath, root.logicalRoot.payloadPath);
  if (root.logicalRoot.kind === "directory") {
    await mkdir(root.stagePath, { recursive: false });
    const directories = manifest.directories.filter(
      (entry) => entry.logicalRoot === root.id,
    );
    for (const directory of directories) {
      const destination = path.join(root.stagePath, directory.path);
      await mkdir(destination);
    }
    for (const file of manifest.files.filter(
      (entry) => entry.logicalRoot === root.id,
    )) {
      await copyRegularFile(
        path.join(payloadRoot, file.path),
        path.join(root.stagePath, file.path),
        file,
      );
    }
    for (const directory of [...directories].sort(
      (left, right) =>
        right.path.split("/").length - left.path.split("/").length,
    )) {
      await applyMetadata(path.join(root.stagePath, directory.path), directory);
    }
    await applyMetadata(root.stagePath, root.logicalRoot);
  } else {
    const file = manifest.files.find((entry) => entry.logicalRoot === root.id)!;
    await copyRegularFile(payloadRoot, root.stagePath, file);
  }
  await syncTree(root.stagePath);
}

async function verifyStagedRoots(
  roots: PlannedRoot[],
  manifest: HubStateSnapshotManifestV1,
) {
  for (const root of roots) {
    const details = await lstat(root.stagePath);
    if (
      details.isSymbolicLink() ||
      (root.logicalRoot.kind === "directory" && !details.isDirectory()) ||
      (root.logicalRoot.kind === "file" && !details.isFile()) ||
      !sameMetadata(metadata(details), root.logicalRoot)
    ) {
      throw new Error(`Hub Restore staged metadata mismatch: ${root.id}`);
    }
    if (root.logicalRoot.kind === "directory") {
      const actual = await listPayloadEntries(root.stagePath);
      const expectedDirectories = manifest.directories
        .filter((entry) => entry.logicalRoot === root.id)
        .map((entry) => entry.path);
      const expectedFiles = manifest.files
        .filter((entry) => entry.logicalRoot === root.id)
        .map((entry) => entry.path);
      if (
        actual.directories.join("\0") !== expectedDirectories.join("\0") ||
        actual.files.join("\0") !== expectedFiles.join("\0")
      ) {
        throw new Error(`Hub Restore staged layout mismatch: ${root.id}`);
      }
      for (const directory of manifest.directories.filter(
        (entry) => entry.logicalRoot === root.id,
      )) {
        const staged = await lstat(path.join(root.stagePath, directory.path));
        if (
          !staged.isDirectory() ||
          !sameMetadata(metadata(staged), directory)
        ) {
          throw new Error(
            `Hub Restore staged metadata mismatch: ${directory.logicalRoot}/${directory.path}`,
          );
        }
      }
    }
    for (const file of manifest.files.filter(
      (entry) => entry.logicalRoot === root.id,
    )) {
      const stagedPath =
        root.logicalRoot.kind === "file"
          ? root.stagePath
          : path.join(root.stagePath, file.path);
      const handle = await open(
        stagedPath,
        constants.O_RDONLY | noFollowFlag(),
      );
      try {
        const staged = await handle.stat();
        const contents = await handle.readFile();
        if (
          !staged.isFile() ||
          !sameMetadata(metadata(staged), file) ||
          contents.byteLength !== file.byteLength ||
          sha256(contents) !== file.sha256
        ) {
          throw new Error(
            `Hub Restore staged content mismatch: ${file.logicalRoot}/${file.path}`,
          );
        }
      } finally {
        await handle.close();
      }
    }
  }
}

async function planRestoreRoots(
  manifest: HubStateSnapshotManifestV1,
  transactionId: string,
): Promise<PlannedRoot[]> {
  const planned: PlannedRoot[] = [];
  for (const logicalRoot of manifest.logicalRoots) {
    const targetPath = logicalRoot.sourcePath;
    const existing = await optionalLstat(targetPath);
    if (existing?.isSymbolicLink()) {
      throw new Error(
        `Hub Restore destination must not be a symbolic link: ${logicalRoot.id}`,
      );
    }
    if (
      existing &&
      ((logicalRoot.kind === "directory" && !existing.isDirectory()) ||
        (logicalRoot.kind === "file" && !existing.isFile()))
    ) {
      throw new Error(
        `Hub Restore destination has the wrong type: ${logicalRoot.id}`,
      );
    }
    await mkdir(path.dirname(targetPath), { recursive: true });
    const strategy: RestoreStrategy =
      logicalRoot.id === "data-root" && existing
        ? "directory-contents"
        : "replacement";
    const container =
      strategy === "directory-contents" ? targetPath : path.dirname(targetPath);
    const stagePath = path.join(
      container,
      `.enoki-hub-state-stage-${transactionId}-${logicalRoot.id}`,
    );
    const backupPath = path.join(
      container,
      `.enoki-hub-state-backup-${transactionId}-${logicalRoot.id}`,
    );
    if ((await optionalLstat(stagePath)) || (await optionalLstat(backupPath))) {
      throw new Error(
        `Hub Restore transaction path already exists: ${logicalRoot.id}`,
      );
    }
    const snapshotTopNames =
      logicalRoot.kind === "directory"
        ? [
            ...manifest.directories
              .filter(
                (entry) =>
                  entry.logicalRoot === logicalRoot.id &&
                  !entry.path.includes("/"),
              )
              .map((entry) => entry.path),
            ...manifest.files
              .filter(
                (entry) =>
                  entry.logicalRoot === logicalRoot.id &&
                  !entry.path.includes("/"),
              )
              .map((entry) => entry.path),
          ].sort()
        : [];
    planned.push({
      backupPath,
      id: logicalRoot.id,
      logicalRoot,
      originalExisted: Boolean(existing),
      originalMetadata: existing ? metadata(existing) : undefined,
      snapshotTopNames,
      stagePath,
      strategy,
      targetPath,
    });
  }
  return planned;
}

function stripPlannedRoot(root: PlannedRoot): RestoreJournalRoot {
  return {
    backupPath: root.backupPath,
    id: root.id,
    originalExisted: root.originalExisted,
    originalMetadata: root.originalMetadata,
    snapshotTopNames: root.snapshotTopNames,
    stagePath: root.stagePath,
    strategy: root.strategy,
    targetPath: root.targetPath,
  };
}

async function commitRoot(
  root: PlannedRoot,
  journal: RestoreJournal,
  journalPath: string,
  fileSystem: HubStateSnapshotTransactionFileSystem,
) {
  if (root.strategy === "replacement") {
    if (root.originalExisted) {
      await durableRename(
        root.targetPath,
        root.backupPath,
        journal,
        journalPath,
        fileSystem,
      );
      journal.progress.push(`backed-up:${root.id}`);
      await writeJournal(journalPath, journal);
    }
    await durableRename(
      root.stagePath,
      root.targetPath,
      journal,
      journalPath,
      fileSystem,
    );
    journal.progress.push(`promoted:${root.id}`);
    await writeJournal(journalPath, journal);
    return journal;
  }

  await mkdir(root.backupPath);
  await syncDirectory(root.targetPath);
  const reserved = new Set([
    path.basename(root.backupPath),
    path.basename(root.stagePath),
    transactionFileName,
    transactionTemporaryFileName,
  ]);
  for (const name of (await readdir(root.targetPath)).sort()) {
    if (reserved.has(name)) continue;
    await durableRename(
      path.join(root.targetPath, name),
      path.join(root.backupPath, name),
      journal,
      journalPath,
      fileSystem,
    );
    journal.progress.push(`backed-up:${root.id}:${name}`);
    await writeJournal(journalPath, journal);
  }
  for (const name of (await readdir(root.stagePath)).sort()) {
    if (!root.snapshotTopNames.includes(name)) root.snapshotTopNames.push(name);
    await durableRename(
      path.join(root.stagePath, name),
      path.join(root.targetPath, name),
      journal,
      journalPath,
      fileSystem,
    );
    journal.progress.push(`promoted:${root.id}:${name}`);
    await writeJournal(journalPath, journal);
  }
  await applyMetadata(root.targetPath, root.logicalRoot);
  await syncDirectory(root.targetPath);
  journal.progress.push(`metadata:${root.id}`);
  await writeJournal(journalPath, journal);
  return journal;
}

async function durableRename(
  source: string,
  destination: string,
  journal: RestoreJournal,
  journalPath: string,
  fileSystem: HubStateSnapshotTransactionFileSystem,
) {
  journal.pendingAction = { destination, source };
  await writeJournal(journalPath, journal);
  await fileSystem.checkpoint?.(`before-rename:${source}->${destination}`);
  await fileSystem.rename(source, destination);
  await syncDirectory(path.dirname(source));
  if (path.dirname(source) !== path.dirname(destination)) {
    await syncDirectory(path.dirname(destination));
  }
  journal.pendingAction = null;
  await writeJournal(journalPath, journal);
  await fileSystem.checkpoint?.(`after-rename:${source}->${destination}`);
}

async function recoverRestoreTransaction(
  dataRoot: string,
  fileSystem: HubStateSnapshotTransactionFileSystem,
) {
  const journalPath = path.join(dataRoot, transactionFileName);
  if (!(await optionalLstat(journalPath))) return;
  const journal = await readJournal(journalPath);
  if (journal.phase === "committed") {
    await finishCommittedTransaction(journalPath, journal);
  } else {
    await rollbackTransaction(journalPath, journal, fileSystem);
  }
}

async function rollbackTransaction(
  journalPath: string,
  journal: RestoreJournal,
  fileSystem: HubStateSnapshotTransactionFileSystem,
) {
  for (const root of [...journal.roots].reverse()) {
    if (root.strategy === "replacement") {
      const backupExists = Boolean(await optionalLstat(root.backupPath));
      const stageExists = Boolean(await optionalLstat(root.stagePath));
      const targetExists = Boolean(await optionalLstat(root.targetPath));
      if (backupExists) {
        if (targetExists)
          await rm(root.targetPath, { force: true, recursive: true });
        await fileSystem.rename(root.backupPath, root.targetPath);
        await syncDirectory(path.dirname(root.targetPath));
      } else if (!root.originalExisted && targetExists && !stageExists) {
        await rm(root.targetPath, { force: true, recursive: true });
        await syncDirectory(path.dirname(root.targetPath));
      }
      await rm(root.stagePath, { force: true, recursive: true });
      await rm(root.backupPath, { force: true, recursive: true });
      continue;
    }

    for (const name of root.snapshotTopNames) {
      const stageEntry = path.join(root.stagePath, name);
      const targetEntry = path.join(root.targetPath, name);
      const definitelyPromoted = journal.progress.includes(
        `promoted:${root.id}:${name}`,
      );
      const renameMayHaveCompleted =
        journal.pendingAction?.source === stageEntry &&
        journal.pendingAction.destination === targetEntry &&
        !(await optionalLstat(stageEntry));
      const wasBackedUp = journal.progress.includes(
        `backed-up:${root.id}:${name}`,
      );
      const backupEntryExists = Boolean(
        await optionalLstat(path.join(root.backupPath, name)),
      );
      const alreadyRestored = wasBackedUp && !backupEntryExists;
      if ((definitelyPromoted || renameMayHaveCompleted) && !alreadyRestored) {
        await rm(targetEntry, { force: true, recursive: true });
      }
    }
    if (await optionalLstat(root.backupPath)) {
      for (const name of await readdir(root.backupPath)) {
        await rm(path.join(root.targetPath, name), {
          force: true,
          recursive: true,
        });
        await fileSystem.rename(
          path.join(root.backupPath, name),
          path.join(root.targetPath, name),
        );
      }
    }
    if (root.originalMetadata)
      await applyMetadata(root.targetPath, root.originalMetadata);
    await rm(root.stagePath, { force: true, recursive: true });
    await rm(root.backupPath, { force: true, recursive: true });
    await syncDirectory(root.targetPath);
  }
  await removeJournal(journalPath);
}

async function finishCommittedTransaction(
  journalPath: string,
  journal: RestoreJournal,
) {
  for (const root of journal.roots) {
    await rm(root.stagePath, { force: true, recursive: true });
    await rm(root.backupPath, { force: true, recursive: true });
    await syncDirectory(
      root.strategy === "directory-contents"
        ? root.targetPath
        : path.dirname(root.targetPath),
    );
  }
  await removeJournal(journalPath);
}

async function removeJournal(journalPath: string) {
  await rm(journalPath, { force: true });
  await rm(path.join(path.dirname(journalPath), transactionTemporaryFileName), {
    force: true,
  });
  await syncDirectory(path.dirname(journalPath));
}

async function writeJournal(journalPath: string, journal: RestoreJournal) {
  const temporaryPath = path.join(
    path.dirname(journalPath),
    transactionTemporaryFileName,
  );
  await writeDurableFile(
    temporaryPath,
    Buffer.from(`${JSON.stringify(journal, null, 2)}\n`),
    0o600,
    false,
  );
  await rename(temporaryPath, journalPath);
  await syncDirectory(path.dirname(journalPath));
}

async function readJournal(journalPath: string): Promise<RestoreJournal> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(journalPath, "utf8"));
  } catch {
    throw new Error(
      "Hub Restore transaction journal is unreadable; keep the Hub stopped and recover it manually.",
    );
  }
  if (
    !isRecord(parsed) ||
    parsed.schemaVersion !== 1 ||
    !Array.isArray(parsed.roots)
  ) {
    throw new Error(
      "Hub Restore transaction journal is invalid; keep the Hub stopped and recover it manually.",
    );
  }
  return parsed as RestoreJournal;
}

async function readManifest(snapshotPath: string, expectedDigest: string) {
  let bytes: Buffer;
  try {
    const manifestPath = path.join(snapshotPath, manifestFileName);
    const handle = await open(
      manifestPath,
      constants.O_RDONLY | noFollowFlag(),
    );
    try {
      const details = await handle.stat();
      if (!details.isFile()) throw structuralError("manifest regular file");
      bytes = await handle.readFile();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (
      isNodeError(error) &&
      (error.code === "ENOENT" || error.code === "ELOOP")
    ) {
      throw structuralError("manifest missing");
    }
    throw error;
  }
  const actualDigest = sha256(bytes);
  if (actualDigest !== expectedDigest) {
    throw new Error(
      "Hub State Snapshot manifest digest does not match the trusted expected digest.",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw structuralError("manifest invalid JSON");
  }
  return { manifest: parseManifest(parsed), manifestDigest: actualDigest };
}

function parseManifest(value: unknown): HubStateSnapshotManifestV1 {
  if (!isRecord(value)) throw structuralError("manifest object");
  requireExactKeys(
    value,
    [
      "directories",
      "files",
      "logicalRoots",
      "recoveryTime",
      "releaseBaseline",
      "schemaVersion",
      "toolVersion",
    ],
    "manifest fields",
  );
  if (value.schemaVersion !== 1 || value.toolVersion !== "v1") {
    throw structuralError("unsupported schema version");
  }
  if (
    typeof value.recoveryTime !== "string" ||
    !isCanonicalIsoTime(value.recoveryTime)
  ) {
    throw structuralError("recovery time");
  }
  const releaseBaseline = parseReleaseBaseline(value.releaseBaseline);
  const logicalRoots = parseLogicalRoots(value.logicalRoots);
  const directories = parseDirectories(value.directories, logicalRoots);
  const files = parseFiles(value.files, logicalRoots, directories);
  return {
    directories,
    files,
    logicalRoots,
    recoveryTime: value.recoveryTime,
    releaseBaseline,
    schemaVersion: 1,
    toolVersion: "v1",
  };
}

function parseReleaseBaseline(value: unknown): ReleaseBaselineIdentity {
  if (!isRecord(value)) throw structuralError("Release Baseline identity");
  requireExactKeys(
    value,
    ["hubImageDigest", "version"],
    "Release Baseline identity",
  );
  if (
    typeof value.hubImageDigest !== "string" ||
    typeof value.version !== "string"
  ) {
    throw structuralError("Release Baseline identity");
  }
  try {
    validateReleaseBaseline({
      hubImageDigest: value.hubImageDigest,
      version: value.version,
    });
  } catch {
    throw structuralError("Release Baseline identity");
  }
  return { hubImageDigest: value.hubImageDigest, version: value.version };
}

function parseLogicalRoots(value: unknown): HubStateSnapshotLogicalRootV1[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 3) {
    throw structuralError("logical roots");
  }
  const expectedOrder = [
    "data-root",
    "sqlite-database",
    "metrics-archive",
  ] as const;
  const roots: HubStateSnapshotLogicalRootV1[] = [];
  for (const [index, candidate] of value.entries()) {
    if (!isRecord(candidate)) throw structuralError("logical root");
    requireExactKeys(
      candidate,
      ["gid", "id", "kind", "mode", "payloadPath", "sourcePath", "uid"],
      "logical root",
    );
    const id = candidate.id;
    if (
      id !== "data-root" &&
      id !== "sqlite-database" &&
      id !== "metrics-archive"
    ) {
      throw structuralError("logical root id");
    }
    const expectedKind = id === "sqlite-database" ? "file" : "directory";
    if (
      expectedOrder.indexOf(id) < index ||
      roots.some((root) => root.id === id) ||
      candidate.kind !== expectedKind ||
      candidate.payloadPath !== `roots/${id}` ||
      typeof candidate.sourcePath !== "string" ||
      !path.isAbsolute(candidate.sourcePath) ||
      path.normalize(candidate.sourcePath) !== candidate.sourcePath
    ) {
      throw structuralError("logical root");
    }
    roots.push({
      ...parseMetadata(candidate, "logical root metadata"),
      id,
      kind: expectedKind,
      payloadPath: `roots/${id}`,
      sourcePath: candidate.sourcePath,
    });
  }
  if (roots[0]?.id !== "data-root")
    throw structuralError("data-root logical root");
  for (let left = 0; left < roots.length; left += 1) {
    for (let right = left + 1; right < roots.length; right += 1) {
      if (
        isPathInside(roots[left]!.sourcePath, roots[right]!.sourcePath) ||
        isPathInside(roots[right]!.sourcePath, roots[left]!.sourcePath)
      ) {
        throw structuralError("ambiguous logical roots");
      }
    }
  }
  return roots;
}

function parseDirectories(
  value: unknown,
  roots: HubStateSnapshotLogicalRootV1[],
) {
  if (!Array.isArray(value)) throw structuralError("directories");
  const directories: HubStateSnapshotDirectoryV1[] = [];
  const identities = new Set<string>();
  for (const candidate of value) {
    if (!isRecord(candidate)) throw structuralError("directory");
    requireExactKeys(
      candidate,
      ["gid", "logicalRoot", "mode", "path", "uid"],
      "directory",
    );
    const root = roots.find((item) => item.id === candidate.logicalRoot);
    if (
      !root ||
      root.kind !== "directory" ||
      typeof candidate.path !== "string" ||
      !isSafeRelativePath(candidate.path)
    ) {
      throw structuralError("directory path");
    }
    const identity = `${root.id}/${candidate.path}`;
    if (identities.has(identity)) throw structuralError("duplicate directory");
    identities.add(identity);
    directories.push({
      ...parseMetadata(candidate, "directory metadata"),
      logicalRoot: root.id,
      path: candidate.path,
    });
  }
  requireCanonicalEntryOrder(directories, roots, "directories");
  return directories;
}

function parseFiles(
  value: unknown,
  roots: HubStateSnapshotLogicalRootV1[],
  directories: HubStateSnapshotDirectoryV1[],
) {
  if (!Array.isArray(value)) throw structuralError("files");
  const files: HubStateSnapshotFileV1[] = [];
  const identities = new Set<string>();
  for (const candidate of value) {
    if (!isRecord(candidate)) throw structuralError("file");
    requireExactKeys(
      candidate,
      ["byteLength", "gid", "logicalRoot", "mode", "path", "sha256", "uid"],
      "file",
    );
    const root = roots.find((item) => item.id === candidate.logicalRoot);
    if (
      !root ||
      typeof candidate.path !== "string" ||
      (root.kind === "file" && candidate.path !== ".") ||
      (root.kind === "directory" && !isSafeRelativePath(candidate.path)) ||
      !Number.isSafeInteger(candidate.byteLength) ||
      (candidate.byteLength as number) < 0 ||
      typeof candidate.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(candidate.sha256)
    ) {
      throw structuralError("file path, checksum or size");
    }
    const identity = `${root.id}/${candidate.path}`;
    if (identities.has(identity)) throw structuralError("duplicate file");
    identities.add(identity);
    if (root.kind === "directory") {
      const parent = path.posix.dirname(candidate.path);
      if (
        parent !== "." &&
        !directories.some(
          (directory) =>
            directory.logicalRoot === root.id && directory.path === parent,
        )
      ) {
        throw structuralError("file parent directory");
      }
    }
    files.push({
      ...parseMetadata(candidate, "file metadata"),
      byteLength: candidate.byteLength as number,
      logicalRoot: root.id,
      path: candidate.path,
      sha256: candidate.sha256,
    });
  }
  for (const root of roots) {
    if (
      root.kind === "file" &&
      files.filter((file) => file.logicalRoot === root.id).length !== 1
    ) {
      throw structuralError("file logical root contents");
    }
  }
  requireCanonicalEntryOrder(files, roots, "files");
  return files;
}

function parseMetadata(value: Record<string, unknown>, description: string) {
  if (
    !Number.isSafeInteger(value.mode) ||
    (value.mode as number) < 0 ||
    (value.mode as number) > 0o7777 ||
    !Number.isSafeInteger(value.uid) ||
    (value.uid as number) < 0 ||
    !Number.isSafeInteger(value.gid) ||
    (value.gid as number) < 0
  ) {
    throw structuralError(description);
  }
  return {
    gid: value.gid as number,
    mode: value.mode as number,
    uid: value.uid as number,
  };
}

async function planLogicalRoots(
  persistentState: HubPersistentState,
): Promise<HubStateSnapshotLogicalRootV1[]> {
  const dataRoot = path.resolve(persistentState.dataRoot);
  const sqlitePath = path.resolve(persistentState.sqlitePath);
  const archiveDirectory = path.resolve(persistentState.archiveDirectory);
  const dataMetadata = await requirePathKind(
    dataRoot,
    "directory",
    "Hub data root",
  );
  const sqliteMetadata = await requirePathKind(
    sqlitePath,
    "file",
    "Hub SQLite database",
  );
  for (const suffix of ["-journal", "-shm", "-wal"]) {
    if (await optionalLstat(`${sqlitePath}${suffix}`)) {
      throw new Error(
        "Hub SQLite database has active sidecar files; stop the Hub cleanly before snapshot.",
      );
    }
  }
  const archiveMetadata = await requirePathKind(
    archiveDirectory,
    "directory",
    "Metrics Archive directory",
  );
  if (
    !isPathInside(dataRoot, sqlitePath) &&
    !isPathInside(dataRoot, archiveDirectory) &&
    (isPathInside(archiveDirectory, sqlitePath) ||
      isPathInside(sqlitePath, archiveDirectory))
  ) {
    throw new Error(
      "Hub persistent state paths are ambiguous: sqlite-database overlaps metrics-archive",
    );
  }
  const logicalRoots: HubStateSnapshotLogicalRootV1[] = [
    {
      ...dataMetadata,
      id: "data-root",
      kind: "directory",
      payloadPath: "roots/data-root",
      sourcePath: dataRoot,
    },
  ];
  if (!isPathInside(dataRoot, sqlitePath)) {
    logicalRoots.push({
      ...sqliteMetadata,
      id: "sqlite-database",
      kind: "file",
      payloadPath: "roots/sqlite-database",
      sourcePath: sqlitePath,
    });
  }
  if (!isPathInside(dataRoot, archiveDirectory)) {
    logicalRoots.push({
      ...archiveMetadata,
      id: "metrics-archive",
      kind: "directory",
      payloadPath: "roots/metrics-archive",
      sourcePath: archiveDirectory,
    });
  }
  return logicalRoots;
}

async function requirePathKind(
  candidate: string,
  expected: "directory" | "file",
  description: string,
) {
  const details = await lstat(candidate);
  if (details.isSymbolicLink() || (await realpath(candidate)) !== candidate) {
    throw new Error(`${description} must not contain symbolic links.`);
  }
  const matches =
    expected === "directory" ? details.isDirectory() : details.isFile();
  if (!matches) throw new Error(`${description} must be a ${expected}.`);
  return metadata(details);
}

function configuredRootDestinations(persistentState: HubPersistentState) {
  const dataRoot = path.resolve(persistentState.dataRoot);
  const sqlitePath = path.resolve(persistentState.sqlitePath);
  const archiveDirectory = path.resolve(persistentState.archiveDirectory);
  const destinations = new Map<HubStateSnapshotLogicalRootV1["id"], string>([
    ["data-root", dataRoot],
  ]);
  if (!isPathInside(dataRoot, sqlitePath))
    destinations.set("sqlite-database", sqlitePath);
  if (!isPathInside(dataRoot, archiveDirectory)) {
    destinations.set("metrics-archive", archiveDirectory);
  }
  return destinations;
}

async function listImmediateEntries(candidate: string) {
  const directories: string[] = [];
  const files: string[] = [];
  for (const entry of await readdir(candidate, { withFileTypes: true })) {
    if (entry.isDirectory()) directories.push(entry.name);
    else if (entry.isFile()) files.push(entry.name);
    else throw structuralError(`unsupported entry ${entry.name}`);
  }
  return { directories: directories.sort(), files: files.sort() };
}

async function listPayloadEntries(
  root: string,
  relativePath = "",
): Promise<{ directories: string[]; files: string[] }> {
  const directories: string[] = [];
  const files: string[] = [];
  for (const entry of await readdir(path.join(root, relativePath), {
    withFileTypes: true,
  })) {
    const entryPath = relativePath
      ? path.posix.join(relativePath, entry.name)
      : entry.name;
    const candidate = path.join(root, entryPath);
    const details = await lstat(candidate);
    if (
      entry.isDirectory() &&
      details.isDirectory() &&
      !details.isSymbolicLink()
    ) {
      directories.push(entryPath);
      const nested = await listPayloadEntries(root, entryPath);
      directories.push(...nested.directories);
      files.push(...nested.files);
    } else if (
      entry.isFile() &&
      details.isFile() &&
      !details.isSymbolicLink()
    ) {
      files.push(entryPath);
    } else {
      throw new Error(
        `Hub State Snapshot contains unsupported content: ${entryPath}`,
      );
    }
  }
  return { directories: directories.sort(), files: files.sort() };
}

function payloadEntry(
  snapshotPath: string,
  entry: { logicalRoot: HubStateSnapshotLogicalRootV1["id"]; path: string },
) {
  return path.join(snapshotPath, `roots/${entry.logicalRoot}`, entry.path);
}

function canonicalEntries<
  T extends { logicalRoot: HubStateSnapshotLogicalRootV1["id"]; path: string },
>(entries: T[], roots: HubStateSnapshotLogicalRootV1[]) {
  return entries.sort((left, right) => {
    const rootDifference =
      roots.findIndex((root) => root.id === left.logicalRoot) -
      roots.findIndex((root) => root.id === right.logicalRoot);
    return rootDifference || left.path.localeCompare(right.path);
  });
}

function requireCanonicalEntryOrder(
  entries: Array<{
    logicalRoot: HubStateSnapshotLogicalRootV1["id"];
    path: string;
  }>,
  roots: HubStateSnapshotLogicalRootV1[],
  description: string,
) {
  const sorted = canonicalEntries([...entries], roots);
  if (entries.some((entry, index) => entry !== sorted[index])) {
    throw structuralError(`${description} order`);
  }
}

async function writeDurableFile(
  destination: string,
  contents: Uint8Array,
  mode: number,
  exclusive = true,
) {
  const handle = await open(
    destination,
    exclusive
      ? constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_EXCL |
          noFollowFlag()
      : constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_TRUNC |
          noFollowFlag(),
    mode,
  );
  try {
    await handle.writeFile(contents);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncTree(candidate: string) {
  const details = await lstat(candidate);
  if (details.isFile()) {
    await syncPath(candidate);
    return;
  }
  for (const entry of await readdir(candidate)) {
    await syncTree(path.join(candidate, entry));
  }
  await syncDirectory(candidate);
}

async function syncPath(candidate: string) {
  const handle = await open(candidate, constants.O_RDONLY | noFollowFlag());
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectory(candidate: string) {
  const handle = await open(
    candidate,
    constants.O_RDONLY | constants.O_DIRECTORY | noFollowFlag(),
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function applyMetadata(
  candidate: string,
  expected: HubStateSnapshotMetadataV1,
) {
  await chown(candidate, expected.uid, expected.gid);
  await chmod(candidate, expected.mode);
}

async function requireDirectoryWithoutLinks(candidate: string) {
  const details = await lstat(candidate);
  if (
    details.isSymbolicLink() ||
    !details.isDirectory() ||
    (await realpath(candidate)) !== candidate
  ) {
    throw new Error(
      `Hub State Snapshot directory must not contain symbolic links: ${candidate}`,
    );
  }
  return details;
}

async function optionalLstat(candidate: string) {
  try {
    return await lstat(candidate);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    throw error;
  }
}

function metadata(details: { gid: number; mode: number; uid: number }) {
  return { gid: details.gid, mode: details.mode & 0o7777, uid: details.uid };
}

function sameMetadata(
  left: HubStateSnapshotMetadataV1,
  right: HubStateSnapshotMetadataV1,
) {
  return (
    left.gid === right.gid && left.mode === right.mode && left.uid === right.uid
  );
}

function sameIdentity(
  left: { dev: number | bigint; ino: number | bigint },
  right: { dev: number | bigint; ino: number | bigint },
) {
  return left.dev === right.dev && left.ino === right.ino;
}

function noFollowFlag() {
  return constants.O_NOFOLLOW ?? 0;
}

function manifestDigestPath(snapshotPath: string) {
  return `${snapshotPath}.manifest.sha256`;
}

function validateManifestDigest(value: string) {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(
      "Expected Hub State Snapshot manifest digest must be a sha256 hex digest.",
    );
  }
}

function validateReleaseBaseline(identity: ReleaseBaselineIdentity) {
  if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(identity.version)) {
    throw new Error(
      "Release Baseline version must be a stable SemVer tag like v1.2.3.",
    );
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(identity.hubImageDigest)) {
    throw new Error(
      "Release Baseline Hub image digest must be an exact sha256 digest.",
    );
  }
}

function requireStoppedHub(hubStopped: true) {
  if (hubStopped !== true) {
    throw new Error(
      "Hub must be stopped before managing a Hub State Snapshot.",
    );
  }
}

function requireExactKeys(
  value: Record<string, unknown>,
  expected: string[],
  description: string,
) {
  if (
    Object.keys(value).sort().join("\0") !== [...expected].sort().join("\0")
  ) {
    throw structuralError(description);
  }
}

function isCanonicalIsoTime(value: string) {
  const parsed = new Date(value);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
}

function isSafeRelativePath(candidate: string) {
  return (
    candidate.length > 0 &&
    candidate !== "." &&
    !path.posix.isAbsolute(candidate) &&
    !candidate.includes("\\") &&
    candidate
      .split("/")
      .every((part) => part !== "" && part !== "." && part !== "..")
  );
}

function isPathInside(parent: string, candidate: string) {
  const relative = path.relative(parent, candidate);
  return (
    relative === "" ||
    (!relative.startsWith("..") && !path.isAbsolute(relative))
  );
}

function structuralError(description: string) {
  return new Error(
    `Hub State Snapshot manifest is structurally invalid: ${description}`,
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sha256(contents: Uint8Array) {
  return createHash("sha256").update(contents).digest("hex");
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
