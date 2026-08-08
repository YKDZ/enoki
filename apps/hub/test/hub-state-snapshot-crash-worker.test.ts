import process from "node:process";

import { it } from "vitest";

import { createHubStateSnapshotV1 } from "../src/hub-state-snapshot/index.js";

const enabled = Boolean(process.env.ENOKI_CRASH_SNAPSHOT);

it.skipIf(!enabled)(
  "is killed after the first destination rename",
  async () => {
    const service = createHubStateSnapshotV1({
      transactionFileSystem: {
        async checkpoint(name) {
          if (name.startsWith("after-rename:")) {
            process.kill(process.pid, "SIGKILL");
          }
        },
        async rename(source, destination) {
          const { rename } = await import("node:fs/promises");
          await rename(source, destination);
        },
      },
    });
    await service.restore({
      confirmDataLossAfter: process.env.ENOKI_CRASH_RECOVERY_TIME!,
      expectedManifestDigest: process.env.ENOKI_CRASH_DIGEST!,
      hubStopped: true,
      persistentState: {
        archiveDirectory: process.env.ENOKI_CRASH_ARCHIVE_DIRECTORY!,
        dataRoot: process.env.ENOKI_CRASH_DATA_ROOT!,
        sqlitePath: process.env.ENOKI_CRASH_SQLITE_PATH!,
      },
      releaseBaseline: {
        hubImageDigest: `sha256:${"a".repeat(64)}`,
        version: "v1.2.3",
      },
      snapshotPath: process.env.ENOKI_CRASH_SNAPSHOT!,
    });
  },
);
