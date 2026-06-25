import { createHash } from "node:crypto";
import { linkSync, readFileSync, unlinkSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import type {
  MetricsArchiveRepository,
  MetricsArchiveRun,
  MetricsArchiveRowCounts,
} from "../database/metrics-archives.js";
import type { MetricsArchivePeriodPlan } from "./planner.js";
import type { MetricsArchivePlannedSample } from "./writer.js";

export type FinalizeMetricsArchiveInput = {
  finalPath: string;
  nowMs: number;
  plan: MetricsArchivePeriodPlan<MetricsArchivePlannedSample>;
  repository: MetricsArchiveRepository;
  runId: number;
  tempPath: string;
};

const archiveTables = [
  "archive_metadata",
  "archive_host_snapshots",
  "metric_samples",
  "official_metric_cpu",
  "official_metric_memory",
  "official_metric_load",
  "official_metric_uptime",
  "official_metric_thermal_power",
  "official_metric_disk_summary",
  "official_metric_network_summary",
  "metric_cpu_cores",
  "metric_disks",
  "metric_network_interfaces",
  "official_metric_disk_health",
  "report_observations",
] as const;

export function finalizeMetricsArchive(
  input: FinalizeMetricsArchiveInput,
): MetricsArchiveRun {
  try {
    const rowCounts = validateMetricsArchiveFile(input);
    validateRunMatchesPlan(input);
    publishArchiveFile(input.tempPath, input.finalPath);
    const checksumSha256 = createHash("sha256")
      .update(readFileSync(input.finalPath))
      .digest("hex");

    return input.repository.markSucceeded({
      archivePath: input.finalPath,
      checksumSha256,
      nowMs: input.nowMs,
      period: input.plan.period,
      rangeEndMs: input.plan.rangeEndMs,
      rangeStartMs: input.plan.rangeStartMs,
      rowCounts,
      runId: input.runId,
    });
  } catch (error) {
    input.repository.markFailed({
      errorMessage: errorMessage(error),
      nowMs: input.nowMs,
      runId: input.runId,
    });
    throw error;
  }
}

function validateMetricsArchiveFile(
  input: FinalizeMetricsArchiveInput,
): MetricsArchiveRowCounts {
  const archive = new DatabaseSync(input.tempPath, { readOnly: true });
  try {
    const rowCounts = countArchiveRows(archive);
    const metadata = validateArchiveMetadata(input, archive, rowCounts);

    const sampleCount = countRows(archive, "metric_samples");
    if (sampleCount !== input.plan.samples.length) {
      throw new Error(
        `Metrics Archive validation failed: expected ${input.plan.samples.length} metric_samples rows, found ${sampleCount}.`,
      );
    }

    const observationCount = countRows(archive, "report_observations");
    if (observationCount !== input.plan.samples.length) {
      throw new Error(
        `Metrics Archive validation failed: expected ${input.plan.samples.length} report_observations rows, found ${observationCount}.`,
      );
    }

    validatePlannedIdentities(input, archive, "metric_samples");
    validatePlannedIdentities(input, archive, "report_observations");

    const range = archive
      .prepare(
        `
          select
            min(collected_at_ms) as min_collected_at_ms,
            max(collected_at_ms) as max_collected_at_ms
          from metric_samples
        `,
      )
      .get() as {
      max_collected_at_ms: number | null;
      min_collected_at_ms: number | null;
    };
    if (
      range.min_collected_at_ms !== null &&
      (range.min_collected_at_ms < input.plan.rangeStartMs ||
        range.max_collected_at_ms === null ||
        range.max_collected_at_ms >= input.plan.rangeEndMs)
    ) {
      throw new Error(
        `Metrics Archive validation failed: metric_samples collected_at_ms range is outside planned range ${input.plan.rangeStartMs}-${input.plan.rangeEndMs}.`,
      );
    }

    validateArchiveMetadataRowCounts(metadata.row_counts_json, rowCounts);
    return rowCounts;
  } finally {
    archive.close();
  }
}

function validateArchiveMetadata(
  input: FinalizeMetricsArchiveInput,
  archive: DatabaseSync,
  rowCounts: MetricsArchiveRowCounts,
): {
  period: string;
  range_end_ms: number;
  range_start_ms: number;
  row_counts_json: string;
  sequence: number;
} {
  const metadata = archive
    .prepare(
      `
        select
          period,
          range_start_ms,
          range_end_ms,
          sequence,
          row_counts_json
        from archive_metadata
        where id = 1
      `,
    )
    .get() as
    | {
        period: string;
        range_end_ms: number;
        range_start_ms: number;
        row_counts_json: string;
        sequence: number;
      }
    | undefined;

  if (rowCounts.archive_metadata !== 1 || !metadata) {
    throw new Error(
      "Metrics Archive validation failed: expected one archive_metadata row.",
    );
  }

  if (
    metadata.period !== input.plan.period ||
    metadata.range_start_ms !== input.plan.rangeStartMs ||
    metadata.range_end_ms !== input.plan.rangeEndMs ||
    metadata.sequence !== input.plan.identity.sequence
  ) {
    throw new Error(
      "Metrics Archive validation failed: archive_metadata does not match the planned archive range.",
    );
  }

  return metadata;
}

function validateArchiveMetadataRowCounts(
  rowCountsJson: string,
  rowCounts: MetricsArchiveRowCounts,
) {
  let metadataRowCounts: MetricsArchiveRowCounts;
  try {
    metadataRowCounts = JSON.parse(rowCountsJson) as MetricsArchiveRowCounts;
  } catch {
    throw new Error(
      "Metrics Archive validation failed: archive_metadata row_counts_json is invalid.",
    );
  }

  if (!sameRowCounts(metadataRowCounts, rowCounts)) {
    throw new Error(
      "Metrics Archive validation failed: archive_metadata row_counts_json does not match archive row counts.",
    );
  }
}

function validatePlannedIdentities(
  input: FinalizeMetricsArchiveInput,
  archive: DatabaseSync,
  table: "metric_samples" | "report_observations",
) {
  const statement = archive.prepare(
    `
      select count(*) as count
      from ${table}
      where probe_id = ? and boot_id = ? and sequence = ?
    `,
  );

  for (const sample of input.plan.samples) {
    const count = (
      statement.get(sample.probeId, sample.bootId, sample.sequence) as {
        count: number;
      }
    ).count;

    if (count !== 1) {
      throw new Error(
        `Metrics Archive validation failed: missing planned ${table} row for probe_id=${sample.probeId}, boot_id=${sample.bootId}, sequence=${sample.sequence}.`,
      );
    }
  }
}

function validateRunMatchesPlan(input: FinalizeMetricsArchiveInput) {
  const run = input.repository.findRun(input.runId);
  if (!run) {
    throw new Error(
      `Metrics Archive finalization failed: run ${input.runId} was not found.`,
    );
  }

  if (
    run.period !== input.plan.period ||
    run.rangeStartMs !== input.plan.rangeStartMs ||
    run.rangeEndMs !== input.plan.rangeEndMs
  ) {
    throw new Error(
      `Metrics Archive finalization failed: run ${input.runId} does not match planned archive range ${input.plan.period} ${input.plan.rangeStartMs}-${input.plan.rangeEndMs}.`,
    );
  }
}

function publishArchiveFile(tempPath: string, finalPath: string) {
  try {
    linkSync(tempPath, finalPath);
  } catch (error) {
    if (isErrnoException(error) && error.code === "EEXIST") {
      throw new Error(
        `Metrics Archive finalization failed: finalized archive already exists at ${finalPath}.`,
      );
    }
    throw error;
  }
  unlinkSync(tempPath);
}

function countRows(database: DatabaseSync, table: string) {
  return (
    database.prepare(`select count(*) as count from ${table}`).get() as {
      count: number;
    }
  ).count;
}

function countArchiveRows(database: DatabaseSync): MetricsArchiveRowCounts {
  return Object.fromEntries(
    archiveTables.map((table) => [table, countRows(database, table)]),
  );
}

function sameRowCounts(
  left: MetricsArchiveRowCounts,
  right: MetricsArchiveRowCounts,
) {
  return (
    Object.keys(left).length === archiveTables.length &&
    archiveTables.every((table) => left[table] === right[table])
  );
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
