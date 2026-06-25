import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import type { MetricsConfig } from "../config.js";
import type {
  MetricsArchivePeriod,
  MetricsArchiveRowCounts,
} from "../database/metrics-archives.js";
import { metricsArchiveEligibilityCutoffs } from "./planner.js";

export type CleanupArchivedMetricsInput = {
  database: DatabaseSync;
  period: MetricsArchivePeriod;
  rangeEndMs: number;
  rangeStartMs: number;
  runId: number;
};

export type CleanupArchivedMetricsResult = {
  deletedMetricSamples: number;
  deletedReportObservations: number;
};

export type CleanupMetricsRetentionDirectlyInput = {
  database: DatabaseSync;
  metrics: MetricsConfig;
  nowMs: number;
  receivedGraceMs: number;
};

export type CleanupObservationOnlyReportObservationsInput = {
  database: DatabaseSync;
  nowMs: number;
  receivedGraceMs: number;
  retentionDays: number;
};

export type CleanupMetricsRetentionDirectlyResult =
  | (CleanupArchivedMetricsResult & {
      skipped: false;
    })
  | {
      deletedMetricSamples: 0;
      deletedReportObservations: 0;
      skipped: true;
    };

type ArchivedIdentity = {
  boot_id: string;
  probe_id: string;
  sequence: number;
};

export function cleanupArchivedMetrics(
  input: CleanupArchivedMetricsInput,
): CleanupArchivedMetricsResult {
  const run = findSucceededFinalizedArchiveRun(input);
  const archivedIdentities = loadArchivedIdentities(run);

  let transactionOpen = true;
  input.database.exec("BEGIN IMMEDIATE");
  try {
    stageArchivedIdentities(input.database, {
      metricSamples: archivedIdentities.metricSamples,
      reportObservations: archivedIdentities.reportObservations,
    });

    input.database
      .prepare(
        `
        delete from report_observations
        where exists (
          select 1
          from temp.metrics_archive_cleanup_report_observation_identities archived
          where archived.probe_id = report_observations.probe_id
            and archived.boot_id = report_observations.boot_id
            and archived.sequence = report_observations.sequence
        )
        `,
      )
      .run();
    const deletedReportObservations = changes(input.database);

    input.database
      .prepare(
        `
        delete from metric_samples
        where exists (
          select 1
          from temp.metrics_archive_cleanup_sample_identities archived
          where archived.probe_id = metric_samples.probe_id
            and archived.boot_id = metric_samples.boot_id
            and archived.sequence = metric_samples.sequence
        )
        `,
      )
      .run();
    const deletedMetricSamples = changes(input.database);

    input.database.exec("COMMIT");
    transactionOpen = false;
    dropStagedArchivedIdentities(input.database);

    input.database.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    return {
      deletedMetricSamples,
      deletedReportObservations,
    };
  } catch (error) {
    if (transactionOpen) {
      input.database.exec("ROLLBACK");
    }
    dropStagedArchivedIdentities(input.database);
    throw error;
  }
}

export function cleanupMetricsRetentionDirectly(
  input: CleanupMetricsRetentionDirectlyInput,
): CleanupMetricsRetentionDirectlyResult {
  if (input.metrics.archive.enabled) {
    return {
      deletedMetricSamples: 0,
      deletedReportObservations: 0,
      skipped: true,
    };
  }

  const { receivedCutoffMs, retentionCutoffMs } =
    metricsArchiveEligibilityCutoffs({
      nowMs: input.nowMs,
      receivedGraceMs: input.receivedGraceMs,
      retentionDays: input.metrics.retentionDays,
    });
  let transactionOpen = true;
  input.database.exec("BEGIN IMMEDIATE");
  try {
    input.database
      .prepare(
        `
        delete from report_observations
        where exists (
          select 1
          from metric_samples eligible
          where eligible.probe_id = report_observations.probe_id
            and eligible.boot_id = report_observations.boot_id
            and eligible.sequence = report_observations.sequence
            and eligible.collected_at_ms < ?
            and eligible.received_at_ms <= ?
        )
        `,
      )
      .run(retentionCutoffMs, receivedCutoffMs);
    const deletedSampleBackedReportObservations = changes(input.database);
    const deletedObservationOnlyReportObservations =
      deleteObservationOnlyReportObservations(input.database, {
        receivedCutoffMs,
        retentionCutoffMs,
      });

    input.database
      .prepare(
        `
        delete from metric_samples
        where collected_at_ms < ?
          and received_at_ms <= ?
        `,
      )
      .run(retentionCutoffMs, receivedCutoffMs);
    const deletedMetricSamples = changes(input.database);

    input.database.exec("COMMIT");
    transactionOpen = false;

    input.database.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    return {
      deletedMetricSamples,
      deletedReportObservations:
        deletedSampleBackedReportObservations +
        deletedObservationOnlyReportObservations,
      skipped: false,
    };
  } catch (error) {
    if (transactionOpen) {
      input.database.exec("ROLLBACK");
    }
    throw error;
  }
}

export function cleanupObservationOnlyReportObservations(
  input: CleanupObservationOnlyReportObservationsInput,
) {
  const { receivedCutoffMs, retentionCutoffMs } =
    metricsArchiveEligibilityCutoffs({
      nowMs: input.nowMs,
      receivedGraceMs: input.receivedGraceMs,
      retentionDays: input.retentionDays,
    });
  let transactionOpen = true;
  input.database.exec("BEGIN IMMEDIATE");
  try {
    const deletedReportObservations = deleteObservationOnlyReportObservations(
      input.database,
      {
        receivedCutoffMs,
        retentionCutoffMs,
      },
    );

    input.database.exec("COMMIT");
    transactionOpen = false;

    input.database.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    return { deletedReportObservations };
  } catch (error) {
    if (transactionOpen) {
      input.database.exec("ROLLBACK");
    }
    throw error;
  }
}

function deleteObservationOnlyReportObservations(
  database: DatabaseSync,
  input: {
    receivedCutoffMs: number;
    retentionCutoffMs: number;
  },
) {
  database
    .prepare(
      `
      delete from report_observations
      where received_at_ms < ?
        and received_at_ms <= ?
        and not exists (
          select 1
          from metric_samples
          where metric_samples.probe_id = report_observations.probe_id
            and metric_samples.boot_id = report_observations.boot_id
            and metric_samples.sequence = report_observations.sequence
        )
      `,
    )
    .run(input.retentionCutoffMs, input.receivedCutoffMs);

  return changes(database);
}

function findSucceededFinalizedArchiveRun(input: CleanupArchivedMetricsInput) {
  const run = input.database
    .prepare(
      `
      select archive_path, checksum_sha256, row_counts_json
      from metrics_archive_runs
      where id = ?
        and period = ?
        and range_start_ms = ?
        and range_end_ms = ?
        and status = 'succeeded'
        and archive_path is not null
        and checksum_sha256 is not null
        and completed_at_ms is not null
      limit 1
      `,
    )
    .get(input.runId, input.period, input.rangeStartMs, input.rangeEndMs) as
    | { archive_path: string; checksum_sha256: string; row_counts_json: string }
    | undefined;

  if (!run) {
    throw new Error(
      "Metrics Archive cleanup requires the exact succeeded finalized archive run for the same range.",
    );
  }

  return {
    archivePath: run.archive_path,
    checksumSha256: run.checksum_sha256,
    rowCounts: parseRunRowCounts(run.row_counts_json),
  };
}

function changes(database: DatabaseSync) {
  return (
    database.prepare("select changes() as changes").get() as {
      changes: number;
    }
  ).changes;
}

function loadArchivedIdentities(run: {
  archivePath: string;
  checksumSha256: string;
  rowCounts: MetricsArchiveRowCounts;
}) {
  assertArchiveChecksum(run);
  const archive = new DatabaseSync(run.archivePath, { readOnly: true });
  try {
    const metricSamples = readIdentities(archive, "metric_samples");
    const reportObservations = readIdentities(archive, "report_observations");
    assertArchivedIdentityCount(
      "metric_samples",
      metricSamples.length,
      run.rowCounts,
    );
    assertArchivedIdentityCount(
      "report_observations",
      reportObservations.length,
      run.rowCounts,
    );

    return {
      metricSamples,
      reportObservations,
    };
  } finally {
    archive.close();
  }
}

function assertArchiveChecksum(run: {
  archivePath: string;
  checksumSha256: string;
}) {
  const actualChecksum = createHash("sha256")
    .update(readFileSync(run.archivePath))
    .digest("hex");
  if (actualChecksum !== run.checksumSha256) {
    throw new Error(
      "Metrics Archive cleanup refused: finalized archive checksum does not match the archive file.",
    );
  }
}

function readIdentities(database: DatabaseSync, table: string) {
  return database
    .prepare(
      `
      select probe_id, boot_id, sequence
      from ${table}
      order by probe_id, boot_id, sequence
      `,
    )
    .all() as ArchivedIdentity[];
}

function assertArchivedIdentityCount(
  table: "metric_samples" | "report_observations",
  identityCount: number,
  rowCounts: MetricsArchiveRowCounts,
) {
  if (rowCounts[table] !== identityCount) {
    throw new Error(
      `Metrics Archive cleanup refused: finalized archive ${table} row count ${rowCounts[table] ?? "missing"} does not match ${identityCount} archived identities.`,
    );
  }
}

function parseRunRowCounts(rowCountsJson: string) {
  try {
    return JSON.parse(rowCountsJson) as MetricsArchiveRowCounts;
  } catch {
    throw new Error(
      "Metrics Archive cleanup refused: finalized archive row counts are invalid.",
    );
  }
}

function stageArchivedIdentities(
  database: DatabaseSync,
  identities: {
    metricSamples: ArchivedIdentity[];
    reportObservations: ArchivedIdentity[];
  },
) {
  database.exec(`
    drop table if exists temp.metrics_archive_cleanup_sample_identities;
    drop table if exists temp.metrics_archive_cleanup_report_observation_identities;

    create temp table metrics_archive_cleanup_sample_identities (
      probe_id text not null,
      boot_id text not null,
      sequence integer not null,
      primary key (probe_id, boot_id, sequence)
    );

    create temp table metrics_archive_cleanup_report_observation_identities (
      probe_id text not null,
      boot_id text not null,
      sequence integer not null,
      primary key (probe_id, boot_id, sequence)
    );
  `);

  insertIdentities(
    database,
    "metrics_archive_cleanup_sample_identities",
    identities.metricSamples,
  );
  insertIdentities(
    database,
    "metrics_archive_cleanup_report_observation_identities",
    identities.reportObservations,
  );
}

function insertIdentities(
  database: DatabaseSync,
  table: string,
  identities: ArchivedIdentity[],
) {
  const insert = database.prepare(
    `insert into temp.${table} (probe_id, boot_id, sequence) values (?, ?, ?)`,
  );

  for (const identity of identities) {
    insert.run(identity.probe_id, identity.boot_id, identity.sequence);
  }
}

function dropStagedArchivedIdentities(database: DatabaseSync) {
  database.exec(`
    drop table if exists temp.metrics_archive_cleanup_sample_identities;
    drop table if exists temp.metrics_archive_cleanup_report_observation_identities;
  `);
}
