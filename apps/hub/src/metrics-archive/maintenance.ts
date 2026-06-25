import { readdirSync } from "node:fs";
import path from "node:path";

import type { MetricsConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { HubDatabase } from "../database/index.js";
import type { MetricsArchiveRun } from "../database/metrics-archives.js";
import {
  cleanupArchivedMetrics,
  cleanupMetricsRetentionDirectly,
  cleanupObservationOnlyReportObservations,
} from "./cleanup.js";
import {
  type FinalizedMetricsArchive,
  planMetricsArchivePeriods,
} from "./planner.js";
import { runMetricsArchiveAttempt } from "./runtime.js";
import type { MetricsArchivePlannedSample } from "./writer.js";

export type RunMetricsArchiveMaintenanceInput = {
  database: HubDatabase;
  metrics: MetricsConfig;
  nowMs?: number;
  receivedGraceMs?: number;
};

export type RunMetricsArchiveMaintenanceResult =
  | {
      deletedMetricSamples: number;
      deletedReportObservations: number;
      mode: "direct-cleanup";
      skipped: false;
    }
  | {
      mode: "direct-cleanup";
      skipped: true;
    }
  | {
      attemptedRuns: MetricsArchiveRun[];
      mode: "archive";
      skipped: false;
    }
  | {
      conflictingRun: MetricsArchiveRun;
      mode: "archive";
      reason: "conflict";
      skipped: true;
    };

const defaultReceivedGraceMs = 5 * 60 * 1000;
const staleStartedRunMs = 30 * 60 * 1000;

export function runMetricsArchiveMaintenance(
  input: RunMetricsArchiveMaintenanceInput,
): RunMetricsArchiveMaintenanceResult {
  const nowMs = input.nowMs ?? Date.now();
  const receivedGraceMs = input.receivedGraceMs ?? defaultReceivedGraceMs;

  if (!input.metrics.archive.enabled) {
    const result = cleanupMetricsRetentionDirectly({
      database: input.database.sqlite,
      metrics: input.metrics,
      nowMs,
      receivedGraceMs,
    });

    if (result.skipped) {
      return {
        mode: "direct-cleanup",
        skipped: true,
      };
    }

    return {
      deletedMetricSamples: result.deletedMetricSamples,
      deletedReportObservations: result.deletedReportObservations,
      mode: "direct-cleanup",
      skipped: false,
    };
  }

  const staleRuns = input.database.metricsArchives.markStaleStartedRunsFailed({
    errorMessage:
      "Metrics Archive run marked failed because it was still started after the stale run timeout.",
    nowMs,
    startedBeforeMs: nowMs - staleStartedRunMs,
  });
  for (const run of staleRuns) {
    recordMaintenanceFailureAudit({
      audit: input.database.audit,
      errorMessage:
        run.errorMessage ??
        "Metrics Archive run marked failed during stale recovery.",
      nowMs,
      phase: "stale_started_recovery",
      run,
    });
  }
  const activeRun = input.database.metricsArchives.findActiveStartedRun();
  if (activeRun) {
    return {
      conflictingRun: activeRun,
      mode: "archive",
      reason: "conflict",
      skipped: true,
    };
  }

  cleanupObservationOnlyReportObservations({
    database: input.database.sqlite,
    nowMs,
    receivedGraceMs,
    retentionDays: input.metrics.retentionDays,
  });
  const attemptedRuns = retryFinalizedArchiveCleanups({
    database: input.database,
    nowMs,
  });
  if (attemptedRuns.some((run) => run.cleanupStatus === "failed")) {
    return {
      attemptedRuns,
      mode: "archive",
      skipped: false,
    };
  }

  const plans = planMetricsArchivePeriods({
    archiveDirectory: input.metrics.archive.directory,
    finalizedArchives: [
      ...listFinalizedArchiveRanges(input.database),
      ...listArchiveFiles({
        archiveDirectory: input.metrics.archive.directory,
        period: input.metrics.archive.period,
      }),
    ],
    nowMs,
    period: input.metrics.archive.period,
    receivedGraceMs,
    retentionDays: input.metrics.retentionDays,
    samples: listArchiveCandidateSamples(input.database),
  });

  for (const plan of plans) {
    const result = runMetricsArchiveAttempt({
      audit: input.database.audit,
      database: input.database.sqlite,
      metricsArchives: input.database.metricsArchives,
      nowMs,
      plan,
    });

    if (!result.ok && "reason" in result && result.reason === "conflict") {
      return {
        conflictingRun: result.conflictingRun,
        mode: "archive",
        reason: "conflict",
        skipped: true,
      };
    }

    if ("run" in result) {
      attemptedRuns.push(result.run);
    }
  }

  return {
    attemptedRuns,
    mode: "archive",
    skipped: false,
  };
}

function retryFinalizedArchiveCleanups(input: {
  database: HubDatabase;
  nowMs: number;
}) {
  const attemptedRuns: MetricsArchiveRun[] = [];

  for (const run of input.database.metricsArchives.listRunsNeedingCleanup()) {
    try {
      cleanupArchivedMetrics({
        database: input.database.sqlite,
        period: run.period,
        rangeEndMs: run.rangeEndMs,
        rangeStartMs: run.rangeStartMs,
        runId: run.id,
      });
      attemptedRuns.push(
        input.database.metricsArchives.markCleanupSucceeded({
          nowMs: input.nowMs,
          runId: run.id,
        }),
      );
    } catch (error) {
      const errorMessage = messageFromError(error);
      const failedRun = input.database.metricsArchives.markCleanupFailed({
        errorMessage,
        nowMs: input.nowMs,
        runId: run.id,
      });
      recordMaintenanceFailureAudit({
        audit: input.database.audit,
        errorMessage,
        nowMs: input.nowMs,
        phase: "cleanup_retry",
        run: failedRun,
      });
      attemptedRuns.push(failedRun);
      break;
    }
  }

  return attemptedRuns;
}

function recordMaintenanceFailureAudit(input: {
  audit: AuditRepository;
  errorMessage: string;
  nowMs: number;
  phase: "cleanup_retry" | "stale_started_recovery";
  run: MetricsArchiveRun;
}) {
  try {
    input.audit.record({
      action: "metrics_archive.failed",
      actor: "system",
      details: {
        errorMessage: input.errorMessage,
        period: input.run.period,
        phase: input.phase,
        rangeEndMs: input.run.rangeEndMs,
        rangeStartMs: input.run.rangeStartMs,
      },
      occurredAtMs: input.nowMs,
      outcome: "failure",
      subjectId: String(input.run.id),
      subjectType: "metrics_archive_run",
    });
  } catch {
    // Maintenance recovery failures must not stop the Hub process.
  }
}

function listArchiveCandidateSamples(
  database: HubDatabase,
): MetricsArchivePlannedSample[] {
  return database.sqlite
    .prepare(
      `
      select probe_id, boot_id, sequence, collected_at_ms, received_at_ms
      from metric_samples
      order by collected_at_ms, probe_id, boot_id, sequence
      `,
    )
    .all()
    .map((row) => {
      const sample = row as {
        boot_id: string;
        collected_at_ms: number;
        probe_id: string;
        received_at_ms: number;
        sequence: number;
      };
      return {
        bootId: sample.boot_id,
        collectedAtMs: sample.collected_at_ms,
        probeId: sample.probe_id,
        receivedAtMs: sample.received_at_ms,
        sequence: sample.sequence,
      };
    });
}

function messageFromError(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

function listFinalizedArchiveRanges(
  database: HubDatabase,
): FinalizedMetricsArchive[] {
  return database.sqlite
    .prepare(
      `
      select archive_path, range_start_ms, range_end_ms
      from metrics_archive_runs
      where status = 'succeeded'
        and archive_path is not null
      order by range_start_ms, range_end_ms, id
      `,
    )
    .all()
    .map((row) => {
      const archive = row as {
        archive_path: string;
        range_end_ms: number;
        range_start_ms: number;
      };
      return {
        rangeEndMs: archive.range_end_ms,
        rangeStartMs: archive.range_start_ms,
        sequence:
          sequenceFromArchiveFileName(path.basename(archive.archive_path)) ??
          undefined,
      };
    });
}

function listArchiveFiles(input: {
  archiveDirectory: string;
  period: "daily" | "monthly";
}): FinalizedMetricsArchive[] {
  let fileNames: string[];
  try {
    fileNames = readdirSync(input.archiveDirectory);
  } catch {
    return [];
  }

  return fileNames
    .map((fileName) => archiveFileIdentity(input.period, fileName))
    .filter((archive): archive is FinalizedMetricsArchive => archive !== null);
}

function archiveFileIdentity(
  period: "daily" | "monthly",
  fileName: string,
): FinalizedMetricsArchive | null {
  return period === "daily"
    ? dailyArchiveFileIdentity(fileName)
    : monthlyArchiveFileIdentity(fileName);
}

function dailyArchiveFileIdentity(
  fileName: string,
): FinalizedMetricsArchive | null {
  const match =
    /^metrics-archive-(\d{4})-(\d{2})-(\d{2})(?:-supplement-(\d+))?\.sqlite$/.exec(
      fileName,
    );
  if (!match) {
    return null;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!isValidUtcDateParts(year, month, day)) {
    return null;
  }

  const sequence = sequenceFromArchiveFileName(fileName);
  if (sequence === null) {
    return null;
  }

  const rangeStartMs = Date.UTC(year, month - 1, day);
  return {
    rangeEndMs: rangeStartMs + 24 * 60 * 60 * 1000,
    rangeStartMs,
    sequence,
  };
}

function monthlyArchiveFileIdentity(
  fileName: string,
): FinalizedMetricsArchive | null {
  const match =
    /^metrics-archive-(\d{4})-(\d{2})(?:-supplement-(\d+))?\.sqlite$/.exec(
      fileName,
    );
  if (!match) {
    return null;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  if (!isValidUtcDateParts(year, month, 1)) {
    return null;
  }

  const sequence = sequenceFromArchiveFileName(fileName);
  if (sequence === null) {
    return null;
  }

  return {
    rangeEndMs: Date.UTC(year, month, 1),
    rangeStartMs: Date.UTC(year, month - 1, 1),
    sequence,
  };
}

function sequenceFromArchiveFileName(fileName: string) {
  const match = /-supplement-(\d+)\.sqlite$/.exec(fileName);
  if (!match) {
    return 1;
  }

  const sequence = Number(match[1]);
  return Number.isSafeInteger(sequence) && sequence > 1 ? sequence : null;
}

function isValidUtcDateParts(year: number, month: number, day: number) {
  if (
    !Number.isSafeInteger(year) ||
    !Number.isSafeInteger(month) ||
    !Number.isSafeInteger(day) ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31
  ) {
    return false;
  }

  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}
