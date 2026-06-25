import { and, asc, eq, inArray, isNotNull, lt } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";

import {
  metricsArchiveRuns,
  type MetricsArchiveRunRow,
  type NewMetricsArchiveRunRow,
} from "./schema.js";

type MetricsArchiveDatabase = NodeSQLiteDatabase<typeof import("./schema.js")>;

export type MetricsArchivePeriod = "daily" | "monthly";
export type MetricsArchiveCleanupStatus = "pending" | "succeeded" | "failed";
export type MetricsArchiveRunStatus = "started" | "succeeded" | "failed";
export type MetricsArchiveRowCounts = Record<string, number>;

export type MetricsArchiveRun = {
  archivePath: string | null;
  checksumSha256: string | null;
  cleanupCompletedAtMs: number | null;
  cleanupErrorMessage: string | null;
  cleanupStatus: MetricsArchiveCleanupStatus | null;
  completedAtMs: number | null;
  errorMessage: string | null;
  id: number;
  period: MetricsArchivePeriod;
  rangeEndMs: number;
  rangeStartMs: number;
  rowCounts: MetricsArchiveRowCounts | null;
  startedAtMs: number;
  status: MetricsArchiveRunStatus;
  updatedAtMs: number;
};

export type StartMetricsArchiveRunInput = {
  nowMs: number;
  period: MetricsArchivePeriod;
  rangeEndMs: number;
  rangeStartMs: number;
};

export type StartMetricsArchiveRunResult =
  | { ok: true; run: MetricsArchiveRun }
  | { ok: false; reason: "conflict"; conflictingRun: MetricsArchiveRun };

export type MarkMetricsArchiveRunSucceededInput = {
  archivePath: string;
  checksumSha256: string;
  nowMs: number;
  period: MetricsArchivePeriod;
  rangeEndMs: number;
  rangeStartMs: number;
  rowCounts: MetricsArchiveRowCounts;
  runId: number;
};

export type MarkMetricsArchiveRunFailedInput = {
  errorMessage: string;
  nowMs: number;
  runId: number;
};

export type MarkMetricsArchiveCleanupInput = {
  nowMs: number;
  runId: number;
};

export type MarkMetricsArchiveCleanupFailedInput =
  MarkMetricsArchiveCleanupInput & {
    errorMessage: string;
  };

export type MarkStaleMetricsArchiveRunsFailedInput = {
  errorMessage: string;
  nowMs: number;
  startedBeforeMs: number;
};

export type MetricsArchiveRepository = {
  findActiveStartedRun: () => MetricsArchiveRun | null;
  findRun: (id: number) => MetricsArchiveRun | null;
  listRunsNeedingCleanup: () => MetricsArchiveRun[];
  markStaleStartedRunsFailed: (
    input: MarkStaleMetricsArchiveRunsFailedInput,
  ) => MetricsArchiveRun[];
  markCleanupFailed: (
    input: MarkMetricsArchiveCleanupFailedInput,
  ) => MetricsArchiveRun;
  markCleanupSucceeded: (
    input: MarkMetricsArchiveCleanupInput,
  ) => MetricsArchiveRun;
  markFailed: (input: MarkMetricsArchiveRunFailedInput) => MetricsArchiveRun;
  markSucceeded: (
    input: MarkMetricsArchiveRunSucceededInput,
  ) => MetricsArchiveRun;
  startRun: (
    input: StartMetricsArchiveRunInput,
  ) => StartMetricsArchiveRunResult;
};

export function createMetricsArchiveRepository(
  database: MetricsArchiveDatabase,
): MetricsArchiveRepository {
  const findActiveStartedRun = () => {
    const row =
      database
        .select()
        .from(metricsArchiveRuns)
        .where(eq(metricsArchiveRuns.status, "started"))
        .orderBy(
          asc(metricsArchiveRuns.startedAtMs),
          asc(metricsArchiveRuns.id),
        )
        .get() ?? null;

    return row ? rowToMetricsArchiveRun(row) : null;
  };

  return {
    findActiveStartedRun,
    findRun(id) {
      const row =
        database
          .select()
          .from(metricsArchiveRuns)
          .where(eq(metricsArchiveRuns.id, id))
          .get() ?? null;

      return row ? rowToMetricsArchiveRun(row) : null;
    },
    listRunsNeedingCleanup() {
      return database
        .select()
        .from(metricsArchiveRuns)
        .where(
          and(
            eq(metricsArchiveRuns.status, "succeeded"),
            inArray(metricsArchiveRuns.cleanupStatus, ["failed", "pending"]),
            isNotNull(metricsArchiveRuns.archivePath),
            isNotNull(metricsArchiveRuns.checksumSha256),
            isNotNull(metricsArchiveRuns.completedAtMs),
          ),
        )
        .orderBy(
          asc(metricsArchiveRuns.completedAtMs),
          asc(metricsArchiveRuns.id),
        )
        .all()
        .map(rowToMetricsArchiveRun);
    },
    markStaleStartedRunsFailed(input) {
      const rows = database
        .update(metricsArchiveRuns)
        .set({
          archivePath: null,
          checksumSha256: null,
          cleanupCompletedAtMs: null,
          cleanupErrorMessage: null,
          cleanupStatus: null,
          completedAtMs: input.nowMs,
          errorMessage: input.errorMessage,
          rowCountsJson: null,
          status: "failed",
          updatedAtMs: input.nowMs,
        })
        .where(
          and(
            eq(metricsArchiveRuns.status, "started"),
            lt(metricsArchiveRuns.startedAtMs, input.startedBeforeMs),
          ),
        )
        .returning()
        .all();

      return rows.map(rowToMetricsArchiveRun);
    },
    markCleanupFailed(input) {
      const row = database
        .update(metricsArchiveRuns)
        .set({
          cleanupCompletedAtMs: input.nowMs,
          cleanupErrorMessage: input.errorMessage,
          cleanupStatus: "failed",
          updatedAtMs: input.nowMs,
        })
        .where(
          and(
            eq(metricsArchiveRuns.id, input.runId),
            eq(metricsArchiveRuns.status, "succeeded"),
          ),
        )
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to mark Metrics Archive cleanup failed.");
      }

      return rowToMetricsArchiveRun(row);
    },
    markCleanupSucceeded(input) {
      const row = database
        .update(metricsArchiveRuns)
        .set({
          cleanupCompletedAtMs: input.nowMs,
          cleanupErrorMessage: null,
          cleanupStatus: "succeeded",
          updatedAtMs: input.nowMs,
        })
        .where(
          and(
            eq(metricsArchiveRuns.id, input.runId),
            eq(metricsArchiveRuns.status, "succeeded"),
          ),
        )
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to mark Metrics Archive cleanup succeeded.");
      }

      return rowToMetricsArchiveRun(row);
    },
    markFailed(input) {
      const row = database
        .update(metricsArchiveRuns)
        .set({
          archivePath: null,
          checksumSha256: null,
          cleanupCompletedAtMs: null,
          cleanupErrorMessage: null,
          cleanupStatus: null,
          completedAtMs: input.nowMs,
          errorMessage: input.errorMessage,
          rowCountsJson: null,
          status: "failed",
          updatedAtMs: input.nowMs,
        })
        .where(
          and(
            eq(metricsArchiveRuns.id, input.runId),
            eq(metricsArchiveRuns.status, "started"),
          ),
        )
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to mark Metrics Archive run failed.");
      }

      return rowToMetricsArchiveRun(row);
    },
    markSucceeded(input) {
      const row = database
        .update(metricsArchiveRuns)
        .set({
          archivePath: input.archivePath,
          checksumSha256: input.checksumSha256,
          cleanupCompletedAtMs: null,
          cleanupErrorMessage: null,
          cleanupStatus: "pending",
          completedAtMs: input.nowMs,
          errorMessage: null,
          rowCountsJson: JSON.stringify(input.rowCounts),
          status: "succeeded",
          updatedAtMs: input.nowMs,
        })
        .where(
          and(
            eq(metricsArchiveRuns.id, input.runId),
            eq(metricsArchiveRuns.period, input.period),
            eq(metricsArchiveRuns.rangeStartMs, input.rangeStartMs),
            eq(metricsArchiveRuns.rangeEndMs, input.rangeEndMs),
            eq(metricsArchiveRuns.status, "started"),
          ),
        )
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to mark Metrics Archive run succeeded.");
      }

      return rowToMetricsArchiveRun(row);
    },
    startRun(input) {
      const conflictingRun = findActiveStartedRun();

      if (conflictingRun) {
        return {
          conflictingRun,
          ok: false,
          reason: "conflict",
        };
      }

      const row = database
        .insert(metricsArchiveRuns)
        .values(runToStartedRow(input))
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to start Metrics Archive run.");
      }

      return { ok: true, run: rowToMetricsArchiveRun(row) };
    },
  };
}

function runToStartedRow(
  input: StartMetricsArchiveRunInput,
): NewMetricsArchiveRunRow {
  return {
    archivePath: null,
    checksumSha256: null,
    cleanupCompletedAtMs: null,
    cleanupErrorMessage: null,
    cleanupStatus: null,
    completedAtMs: null,
    errorMessage: null,
    period: input.period,
    rangeEndMs: input.rangeEndMs,
    rangeStartMs: input.rangeStartMs,
    rowCountsJson: null,
    startedAtMs: input.nowMs,
    status: "started",
    updatedAtMs: input.nowMs,
  };
}

function rowToMetricsArchiveRun(row: MetricsArchiveRunRow): MetricsArchiveRun {
  return {
    archivePath: row.archivePath,
    checksumSha256: row.checksumSha256,
    cleanupCompletedAtMs: row.cleanupCompletedAtMs,
    cleanupErrorMessage: row.cleanupErrorMessage,
    cleanupStatus: row.cleanupStatus as MetricsArchiveCleanupStatus | null,
    completedAtMs: row.completedAtMs,
    errorMessage: row.errorMessage,
    id: row.id,
    period: row.period as MetricsArchivePeriod,
    rangeEndMs: row.rangeEndMs,
    rangeStartMs: row.rangeStartMs,
    rowCounts: row.rowCountsJson
      ? (JSON.parse(row.rowCountsJson) as MetricsArchiveRowCounts)
      : null,
    startedAtMs: row.startedAtMs,
    status: row.status as MetricsArchiveRunStatus,
    updatedAtMs: row.updatedAtMs,
  };
}
