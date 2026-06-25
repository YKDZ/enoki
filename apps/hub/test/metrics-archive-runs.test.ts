import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

describe("Metrics Archive run records", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("records a started Metrics Archive run", async () => {
    const database = await createTestDatabase();

    const result = database.metricsArchives.startRun({
      nowMs: 1_725_100_000_000,
      period: "monthly",
      rangeEndMs: 1_725_000_000_000,
      rangeStartMs: 1_722_326_400_000,
    });

    expect(result).toEqual({
      ok: true,
      run: expect.objectContaining({
        archivePath: null,
        checksumSha256: null,
        completedAtMs: null,
        errorMessage: null,
        period: "monthly",
        rangeEndMs: 1_725_000_000_000,
        rangeStartMs: 1_722_326_400_000,
        rowCounts: null,
        startedAtMs: 1_725_100_000_000,
        status: "started",
        updatedAtMs: 1_725_100_000_000,
      }),
    });

    const run = result.ok
      ? database.metricsArchives.findRun(result.run.id)
      : null;
    expect(run).toEqual(result.ok ? result.run : null);

    database.close();
  });

  it("marks a Metrics Archive run succeeded with archive file metadata", async () => {
    const database = await createTestDatabase();
    const started = database.metricsArchives.startRun({
      nowMs: 1_725_100_000_000,
      period: "monthly",
      rangeEndMs: 1_725_000_000_000,
      rangeStartMs: 1_722_326_400_000,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }

    const succeeded = database.metricsArchives.markSucceeded({
      archivePath: "/data/metrics-archive/2024-08.sqlite",
      checksumSha256:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      nowMs: 1_725_100_030_000,
      period: started.run.period,
      rangeEndMs: started.run.rangeEndMs,
      rangeStartMs: started.run.rangeStartMs,
      rowCounts: {
        metric_samples: 42,
        report_observations: 40,
      },
      runId: started.run.id,
    });

    expect(succeeded).toEqual(
      expect.objectContaining({
        archivePath: "/data/metrics-archive/2024-08.sqlite",
        checksumSha256:
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        completedAtMs: 1_725_100_030_000,
        errorMessage: null,
        rowCounts: {
          metric_samples: 42,
          report_observations: 40,
        },
        status: "succeeded",
        updatedAtMs: 1_725_100_030_000,
      }),
    );
    expect(database.metricsArchives.findRun(started.run.id)).toEqual(succeeded);

    database.close();
  });

  it("does not mark a started Metrics Archive run succeeded for the wrong range", async () => {
    const database = await createTestDatabase();
    const started = database.metricsArchives.startRun({
      nowMs: 1_725_100_000_000,
      period: "monthly",
      rangeEndMs: 1_725_000_000_000,
      rangeStartMs: 1_722_326_400_000,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }

    expect(() =>
      database.metricsArchives.markSucceeded({
        archivePath: "/data/metrics-archive/2024-08.sqlite",
        checksumSha256:
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        nowMs: 1_725_100_030_000,
        period: started.run.period,
        rangeEndMs: started.run.rangeEndMs,
        rangeStartMs: started.run.rangeStartMs - 1,
        rowCounts: {
          metric_samples: 42,
        },
        runId: started.run.id,
      }),
    ).toThrow("Failed to mark Metrics Archive run succeeded.");
    expect(database.metricsArchives.findRun(started.run.id)).toEqual(
      started.run,
    );

    database.close();
  });

  it("marks a Metrics Archive run failed with an error message", async () => {
    const database = await createTestDatabase();
    const started = database.metricsArchives.startRun({
      nowMs: 1_725_100_000_000,
      period: "daily",
      rangeEndMs: 1_725_062_400_000,
      rangeStartMs: 1_724_976_000_000,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }

    const failed = database.metricsArchives.markFailed({
      errorMessage: "archive directory is not writable",
      nowMs: 1_725_100_015_000,
      runId: started.run.id,
    });

    expect(failed).toEqual(
      expect.objectContaining({
        archivePath: null,
        checksumSha256: null,
        completedAtMs: 1_725_100_015_000,
        errorMessage: "archive directory is not writable",
        rowCounts: null,
        status: "failed",
        updatedAtMs: 1_725_100_015_000,
      }),
    );
    expect(database.metricsArchives.findRun(started.run.id)).toEqual(failed);

    database.close();
  });

  it("does not rewrite a succeeded Metrics Archive run as failed", async () => {
    const database = await createTestDatabase();
    const started = database.metricsArchives.startRun({
      nowMs: 1_725_100_000_000,
      period: "monthly",
      rangeEndMs: 1_725_000_000_000,
      rangeStartMs: 1_722_326_400_000,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }

    const succeeded = database.metricsArchives.markSucceeded({
      archivePath: "/data/metrics-archive/2024-08.sqlite",
      checksumSha256:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      nowMs: 1_725_100_030_000,
      period: started.run.period,
      rangeEndMs: started.run.rangeEndMs,
      rangeStartMs: started.run.rangeStartMs,
      rowCounts: {
        metric_samples: 42,
      },
      runId: started.run.id,
    });

    expect(() =>
      database.metricsArchives.markFailed({
        errorMessage: "late failure should not overwrite success",
        nowMs: 1_725_100_031_000,
        runId: started.run.id,
      }),
    ).toThrow("Failed to mark Metrics Archive run failed.");
    expect(database.metricsArchives.findRun(started.run.id)).toEqual(succeeded);

    database.close();
  });

  it("does not rewrite a failed Metrics Archive run as succeeded", async () => {
    const database = await createTestDatabase();
    const started = database.metricsArchives.startRun({
      nowMs: 1_725_100_000_000,
      period: "daily",
      rangeEndMs: 1_725_062_400_000,
      rangeStartMs: 1_724_976_000_000,
    });
    if (!started.ok) {
      throw new Error("Expected Metrics Archive run to start.");
    }

    const failed = database.metricsArchives.markFailed({
      errorMessage: "archive directory is not writable",
      nowMs: 1_725_100_015_000,
      runId: started.run.id,
    });

    expect(() =>
      database.metricsArchives.markSucceeded({
        archivePath: "/data/metrics-archive/2024-08.sqlite",
        checksumSha256:
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        nowMs: 1_725_100_030_000,
        period: started.run.period,
        rangeEndMs: started.run.rangeEndMs,
        rangeStartMs: started.run.rangeStartMs,
        rowCounts: {
          metric_samples: 42,
        },
        runId: started.run.id,
      }),
    ).toThrow("Failed to mark Metrics Archive run succeeded.");
    expect(database.metricsArchives.findRun(started.run.id)).toEqual(failed);

    database.close();
  });

  it("returns the active run when a caller tries to start the same or overlapping range", async () => {
    const database = await createTestDatabase();
    const active = database.metricsArchives.startRun({
      nowMs: 1_725_100_000_000,
      period: "monthly",
      rangeEndMs: 1_725_000_000_000,
      rangeStartMs: 1_722_326_400_000,
    });
    if (!active.ok) {
      throw new Error("Expected first Metrics Archive run to start.");
    }

    const sameRange = database.metricsArchives.startRun({
      nowMs: 1_725_100_001_000,
      period: "monthly",
      rangeEndMs: 1_725_000_000_000,
      rangeStartMs: 1_722_326_400_000,
    });
    const overlappingRange = database.metricsArchives.startRun({
      nowMs: 1_725_100_002_000,
      period: "daily",
      rangeEndMs: 1_722_412_800_000,
      rangeStartMs: 1_722_326_400_000,
    });

    expect(sameRange).toEqual({
      ok: false,
      reason: "conflict",
      conflictingRun: active.run,
    });
    expect(overlappingRange).toEqual({
      ok: false,
      reason: "conflict",
      conflictingRun: active.run,
    });

    database.metricsArchives.markSucceeded({
      archivePath: "/data/metrics-archive/2024-08.sqlite",
      checksumSha256:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      nowMs: 1_725_100_030_000,
      period: active.run.period,
      rangeEndMs: active.run.rangeEndMs,
      rangeStartMs: active.run.rangeStartMs,
      rowCounts: {
        metric_samples: 42,
      },
      runId: active.run.id,
    });
    const afterCompletion = database.metricsArchives.startRun({
      nowMs: 1_725_100_031_000,
      period: "monthly",
      rangeEndMs: 1_725_000_000_000,
      rangeStartMs: 1_722_326_400_000,
    });

    expect(afterCompletion).toEqual({
      ok: true,
      run: expect.objectContaining({
        status: "started",
      }),
    });
    if (!afterCompletion.ok) {
      throw new Error(
        "Expected completed Metrics Archive range to be reusable.",
      );
    }
    expect(afterCompletion.run.id).not.toBe(active.run.id);

    database.close();
  });

  it("returns the active run when any Metrics Archive run is already started", async () => {
    const database = await createTestDatabase();
    const first = database.metricsArchives.startRun({
      nowMs: 1_725_100_000_000,
      period: "daily",
      rangeEndMs: 1_725_062_400_000,
      rangeStartMs: 1_724_976_000_000,
    });
    if (!first.ok) {
      throw new Error("Expected first Metrics Archive run to start.");
    }

    const adjacent = database.metricsArchives.startRun({
      nowMs: 1_725_100_001_000,
      period: "daily",
      rangeEndMs: 1_725_148_800_000,
      rangeStartMs: 1_725_062_400_000,
    });

    expect(adjacent).toEqual({
      conflictingRun: first.run,
      ok: false,
      reason: "conflict",
    });

    database.close();
  });
});

async function createTestDatabase() {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-archive-"));
  tempRoots.push(dataRoot);

  return initializeHubDatabase({
    dataRoot,
    sqlitePath: path.join(dataRoot, "enoki.db"),
  });
}
