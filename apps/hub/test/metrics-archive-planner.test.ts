import path from "node:path";

import { describe, expect, it } from "vitest";

import { planMetricsArchivePeriods } from "../src/metrics-archive/planner.js";

describe("Metrics Archive period planning", () => {
  it("plans eligible samples into daily UTC archive periods", () => {
    const plans = planMetricsArchivePeriods({
      archiveDirectory: "/data/metrics-archive",
      finalizedArchives: [],
      nowMs: Date.UTC(2024, 7, 20, 12),
      period: "daily",
      receivedGraceMs: 60_000,
      retentionDays: 7,
      samples: [
        {
          collectedAtMs: Date.UTC(2024, 7, 12, 23, 59, 59, 999),
          receivedAtMs: Date.UTC(2024, 7, 13),
        },
      ],
    });

    expect(plans).toEqual([
      {
        identity: {
          fileName: "metrics-archive-2024-08-12.sqlite",
          path: path.join(
            "/data/metrics-archive",
            "metrics-archive-2024-08-12.sqlite",
          ),
          sequence: 1,
        },
        period: "daily",
        rangeEndMs: Date.UTC(2024, 7, 13),
        rangeStartMs: Date.UTC(2024, 7, 12),
        samples: [
          {
            collectedAtMs: Date.UTC(2024, 7, 12, 23, 59, 59, 999),
            receivedAtMs: Date.UTC(2024, 7, 13),
          },
        ],
      },
    ]);
  });

  it("plans eligible samples into monthly UTC archive periods", () => {
    const plans = planMetricsArchivePeriods({
      archiveDirectory: "/data/metrics-archive",
      finalizedArchives: [],
      nowMs: Date.UTC(2024, 3, 10),
      period: "monthly",
      receivedGraceMs: 60_000,
      retentionDays: 7,
      samples: [
        {
          collectedAtMs: Date.UTC(2024, 1, 29, 23, 59, 59, 999),
          receivedAtMs: Date.UTC(2024, 2, 1),
        },
        {
          collectedAtMs: Date.UTC(2024, 2, 1),
          receivedAtMs: Date.UTC(2024, 2, 1),
        },
      ],
    });

    expect(plans).toEqual([
      {
        identity: {
          fileName: "metrics-archive-2024-02.sqlite",
          path: path.join(
            "/data/metrics-archive",
            "metrics-archive-2024-02.sqlite",
          ),
          sequence: 1,
        },
        period: "monthly",
        rangeEndMs: Date.UTC(2024, 2, 1),
        rangeStartMs: Date.UTC(2024, 1, 1),
        samples: [
          {
            collectedAtMs: Date.UTC(2024, 1, 29, 23, 59, 59, 999),
            receivedAtMs: Date.UTC(2024, 2, 1),
          },
        ],
      },
      {
        identity: {
          fileName: "metrics-archive-2024-03.sqlite",
          path: path.join(
            "/data/metrics-archive",
            "metrics-archive-2024-03.sqlite",
          ),
          sequence: 1,
        },
        period: "monthly",
        rangeEndMs: Date.UTC(2024, 3, 1),
        rangeStartMs: Date.UTC(2024, 2, 1),
        samples: [
          {
            collectedAtMs: Date.UTC(2024, 2, 1),
            receivedAtMs: Date.UTC(2024, 2, 1),
          },
        ],
      },
    ]);
  });

  it("uses hot retention days as the collected-at eligibility cutoff independently from archive period", () => {
    const plans = planMetricsArchivePeriods({
      archiveDirectory: "/data/metrics-archive",
      finalizedArchives: [],
      nowMs: Date.UTC(2024, 7, 20),
      period: "monthly",
      receivedGraceMs: 60_000,
      retentionDays: 7,
      samples: [
        {
          collectedAtMs: Date.UTC(2024, 7, 12, 23, 59, 59, 999),
          receivedAtMs: Date.UTC(2024, 7, 19),
        },
        {
          collectedAtMs: Date.UTC(2024, 7, 13),
          receivedAtMs: Date.UTC(2024, 7, 1),
        },
        {
          collectedAtMs: Date.UTC(2024, 6, 31),
          receivedAtMs: Date.UTC(2024, 7, 20),
        },
      ],
    });

    expect(plans).toEqual([
      expect.objectContaining({
        period: "monthly",
        rangeEndMs: Date.UTC(2024, 8, 1),
        rangeStartMs: Date.UTC(2024, 7, 1),
        samples: [
          {
            collectedAtMs: Date.UTC(2024, 7, 12, 23, 59, 59, 999),
            receivedAtMs: Date.UTC(2024, 7, 19),
          },
        ],
      }),
    ]);
  });

  it("requires received-time grace before late samples become eligible", () => {
    const plans = planMetricsArchivePeriods({
      archiveDirectory: "/data/metrics-archive",
      finalizedArchives: [],
      nowMs: Date.UTC(2024, 7, 20, 12),
      period: "daily",
      receivedGraceMs: 5 * 60_000,
      retentionDays: 7,
      samples: [
        {
          collectedAtMs: Date.UTC(2024, 7, 1),
          receivedAtMs: Date.UTC(2024, 7, 20, 11, 55),
        },
        {
          collectedAtMs: Date.UTC(2024, 7, 1, 1),
          receivedAtMs: Date.UTC(2024, 7, 20, 11, 55, 1),
        },
      ],
    });

    expect(plans).toEqual([
      expect.objectContaining({
        rangeEndMs: Date.UTC(2024, 7, 2),
        rangeStartMs: Date.UTC(2024, 7, 1),
        samples: [
          {
            collectedAtMs: Date.UTC(2024, 7, 1),
            receivedAtMs: Date.UTC(2024, 7, 20, 11, 55),
          },
        ],
      }),
    ]);
  });

  it("allocates supplemental archive identities for periods with finalized archives", () => {
    const rangeStartMs = Date.UTC(2024, 7, 12);
    const rangeEndMs = Date.UTC(2024, 7, 13);

    const plans = planMetricsArchivePeriods({
      archiveDirectory: "/data/metrics-archive",
      finalizedArchives: [
        {
          rangeEndMs,
          rangeStartMs,
        },
      ],
      nowMs: Date.UTC(2024, 7, 20, 12),
      period: "daily",
      receivedGraceMs: 60_000,
      retentionDays: 7,
      samples: [
        {
          collectedAtMs: Date.UTC(2024, 7, 12, 1),
          receivedAtMs: Date.UTC(2024, 7, 13),
        },
      ],
    });

    expect(plans).toEqual([
      expect.objectContaining({
        identity: {
          fileName: "metrics-archive-2024-08-12-supplement-2.sqlite",
          path: path.join(
            "/data/metrics-archive",
            "metrics-archive-2024-08-12-supplement-2.sqlite",
          ),
          sequence: 2,
        },
        rangeEndMs,
        rangeStartMs,
      }),
    ]);
  });
});
