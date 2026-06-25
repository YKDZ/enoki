import type { DatabaseSync } from "node:sqlite";

import type { AuditRepository } from "../database/audit.js";
import type {
  MetricsArchiveRepository,
  MetricsArchiveRun,
} from "../database/metrics-archives.js";
import { cleanupArchivedMetrics } from "./cleanup.js";
import { finalizeMetricsArchive } from "./finalizer.js";
import type { MetricsArchivePeriodPlan } from "./planner.js";
import {
  writeMetricsArchiveFile,
  type MetricsArchivePlannedSample,
} from "./writer.js";

export type RunMetricsArchiveAttemptInput = {
  audit: AuditRepository;
  cleanup?: typeof cleanupArchivedMetrics;
  database: DatabaseSync;
  finalizer?: typeof finalizeMetricsArchive;
  metricsArchives: MetricsArchiveRepository;
  nowMs: number;
  plan: MetricsArchivePeriodPlan<MetricsArchivePlannedSample>;
  writer?: typeof writeMetricsArchiveFile;
};

export type RunMetricsArchiveAttemptResult =
  | {
      ok: true;
      run: MetricsArchiveRun;
    }
  | {
      errorMessage: string;
      ok: false;
      run: MetricsArchiveRun;
    }
  | {
      conflictingRun: MetricsArchiveRun;
      ok: false;
      reason: "conflict";
    };

export function runMetricsArchiveAttempt(
  input: RunMetricsArchiveAttemptInput,
): RunMetricsArchiveAttemptResult {
  const started = input.metricsArchives.startRun({
    nowMs: input.nowMs,
    period: input.plan.period,
    rangeEndMs: input.plan.rangeEndMs,
    rangeStartMs: input.plan.rangeStartMs,
  });

  if (!started.ok) {
    return {
      conflictingRun: started.conflictingRun,
      ok: false,
      reason: "conflict",
    };
  }

  const runId = started.run.id;
  const tempPath = `${input.plan.identity.path}.tmp`;
  const writer = input.writer ?? writeMetricsArchiveFile;
  const finalizer = input.finalizer ?? finalizeMetricsArchive;
  const cleanup = input.cleanup ?? cleanupArchivedMetrics;

  try {
    writer({
      archivePath: tempPath,
      database: input.database,
      nowMs: input.nowMs,
      plan: input.plan,
    });

    const run = finalizer({
      finalPath: input.plan.identity.path,
      nowMs: input.nowMs,
      plan: input.plan,
      repository: input.metricsArchives,
      runId,
      tempPath,
    });

    cleanup({
      database: input.database,
      period: input.plan.period,
      rangeEndMs: input.plan.rangeEndMs,
      rangeStartMs: input.plan.rangeStartMs,
      runId: run.id,
    });
    const cleanedRun = input.metricsArchives.markCleanupSucceeded({
      nowMs: input.nowMs,
      runId: run.id,
    });

    return { ok: true, run: cleanedRun };
  } catch (error) {
    const errorMessage = messageFromError(error);
    const run = markRunFailedIfStartedOrCleanupFailed({
      errorMessage,
      metricsArchives: input.metricsArchives,
      nowMs: input.nowMs,
      runId,
    });
    recordFailureAudit({
      audit: input.audit,
      errorMessage,
      nowMs: input.nowMs,
      plan: input.plan,
      run,
    });
    return {
      errorMessage,
      ok: false,
      run,
    };
  }
}

function markRunFailedIfStartedOrCleanupFailed(input: {
  errorMessage: string;
  metricsArchives: MetricsArchiveRepository;
  nowMs: number;
  runId: number;
}) {
  const current = input.metricsArchives.findRun(input.runId);
  if (!current) {
    throw new Error(`Metrics Archive run ${input.runId} was not found.`);
  }

  if (current.status !== "started") {
    if (current.status === "succeeded") {
      return input.metricsArchives.markCleanupFailed({
        errorMessage: input.errorMessage,
        nowMs: input.nowMs,
        runId: input.runId,
      });
    }

    return current;
  }

  return input.metricsArchives.markFailed({
    errorMessage: input.errorMessage,
    nowMs: input.nowMs,
    runId: input.runId,
  });
}

function recordFailureAudit(input: {
  audit: AuditRepository;
  errorMessage: string;
  nowMs: number;
  plan: MetricsArchivePeriodPlan<MetricsArchivePlannedSample>;
  run: MetricsArchiveRun;
}) {
  try {
    input.audit.record({
      action: "metrics_archive.failed",
      actor: "system",
      details: {
        errorMessage: input.errorMessage,
        period: input.plan.period,
        rangeEndMs: input.plan.rangeEndMs,
        rangeStartMs: input.plan.rangeStartMs,
      },
      occurredAtMs: input.nowMs,
      outcome: "failure",
      subjectId: String(input.run.id),
      subjectType: "metrics_archive_run",
    });
  } catch {
    // Runtime archive failures must not stop the Hub process.
  }
}

function messageFromError(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
