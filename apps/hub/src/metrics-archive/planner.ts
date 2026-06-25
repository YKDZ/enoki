import path from "node:path";

export type MetricsArchivePeriod = "daily" | "monthly";

export type MetricsArchiveCandidateSample = {
  collectedAtMs: number;
  receivedAtMs: number;
};

export type MetricsArchiveIdentity = {
  fileName: string;
  path: string;
  sequence: number;
};

export type FinalizedMetricsArchive = {
  rangeEndMs: number;
  rangeStartMs: number;
  sequence?: number;
};

export type MetricsArchivePeriodPlan<
  Sample extends MetricsArchiveCandidateSample = MetricsArchiveCandidateSample,
> = {
  identity: MetricsArchiveIdentity;
  period: MetricsArchivePeriod;
  rangeEndMs: number;
  rangeStartMs: number;
  samples: Sample[];
};

export type PlanMetricsArchivePeriodsInput<
  Sample extends MetricsArchiveCandidateSample = MetricsArchiveCandidateSample,
> = {
  archiveDirectory: string;
  finalizedArchives: FinalizedMetricsArchive[];
  nowMs: number;
  period: MetricsArchivePeriod;
  receivedGraceMs: number;
  retentionDays: number;
  samples: Sample[];
};

const dayMs = 24 * 60 * 60 * 1000;

export function metricsArchiveEligibilityCutoffs(input: {
  nowMs: number;
  receivedGraceMs: number;
  retentionDays: number;
}) {
  return {
    receivedCutoffMs: input.nowMs - input.receivedGraceMs,
    retentionCutoffMs: input.nowMs - input.retentionDays * dayMs,
  };
}

export function planMetricsArchivePeriods<
  Sample extends MetricsArchiveCandidateSample,
>(
  input: PlanMetricsArchivePeriodsInput<Sample>,
): MetricsArchivePeriodPlan<Sample>[] {
  const { receivedCutoffMs, retentionCutoffMs } =
    metricsArchiveEligibilityCutoffs(input);
  const plansByRange = new Map<string, MetricsArchivePeriodPlan<Sample>>();

  for (const sample of input.samples) {
    if (
      sample.collectedAtMs >= retentionCutoffMs ||
      sample.receivedAtMs > receivedCutoffMs
    ) {
      continue;
    }

    const range = rangeFor(input.period, sample.collectedAtMs);
    const key = `${range.rangeStartMs}:${range.rangeEndMs}`;
    const existing = plansByRange.get(key);

    if (existing) {
      existing.samples.push(sample);
      continue;
    }

    plansByRange.set(key, {
      identity: createArchiveIdentity({
        archiveDirectory: input.archiveDirectory,
        finalizedArchives: input.finalizedArchives,
        period: input.period,
        rangeEndMs: range.rangeEndMs,
        rangeStartMs: range.rangeStartMs,
      }),
      period: input.period,
      rangeEndMs: range.rangeEndMs,
      rangeStartMs: range.rangeStartMs,
      samples: [sample],
    });
  }

  return [...plansByRange.values()].sort(
    (left, right) => left.rangeStartMs - right.rangeStartMs,
  );
}

function rangeFor(period: MetricsArchivePeriod, timestampMs: number) {
  return period === "daily"
    ? dailyRangeFor(timestampMs)
    : monthlyRangeFor(timestampMs);
}

function dailyRangeFor(timestampMs: number) {
  const date = new Date(timestampMs);
  const rangeStartMs = Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
  );

  return {
    rangeEndMs: rangeStartMs + dayMs,
    rangeStartMs,
  };
}

function monthlyRangeFor(timestampMs: number) {
  const date = new Date(timestampMs);
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth();
  const rangeStartMs = Date.UTC(year, month, 1);

  return {
    rangeEndMs: Date.UTC(year, month + 1, 1),
    rangeStartMs,
  };
}

function createArchiveIdentity(input: {
  archiveDirectory: string;
  finalizedArchives: FinalizedMetricsArchive[];
  period: MetricsArchivePeriod;
  rangeEndMs: number;
  rangeStartMs: number;
}): MetricsArchiveIdentity {
  const occupiedSequences = new Set<number>();
  for (const archive of input.finalizedArchives) {
    if (
      archive.rangeStartMs !== input.rangeStartMs ||
      archive.rangeEndMs !== input.rangeEndMs
    ) {
      continue;
    }

    occupiedSequences.add(
      archive.sequence ?? firstAvailableSequence(occupiedSequences),
    );
  }
  const sequence = firstAvailableSequence(occupiedSequences);
  const label =
    input.period === "daily"
      ? formatDailyLabel(input.rangeStartMs)
      : formatMonthlyLabel(input.rangeStartMs);
  const fileName =
    sequence === 1
      ? `metrics-archive-${label}.sqlite`
      : `metrics-archive-${label}-supplement-${sequence}.sqlite`;

  return {
    fileName,
    path: path.join(input.archiveDirectory, fileName),
    sequence,
  };
}

function firstAvailableSequence(occupiedSequences: Set<number>) {
  let sequence = 1;
  while (occupiedSequences.has(sequence)) {
    sequence += 1;
  }
  return sequence;
}

function formatDailyLabel(rangeStartMs: number) {
  return new Date(rangeStartMs).toISOString().slice(0, 10);
}

function formatMonthlyLabel(rangeStartMs: number) {
  return new Date(rangeStartMs).toISOString().slice(0, 7);
}
