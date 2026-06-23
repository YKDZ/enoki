import { describe, expect, it } from "vitest";

import type { CollectorAvailability } from "../../types";
import { cpuMetricCardProps } from "./registry";
import type { CpuMetricCardData } from "./types";

describe("official metrics card props", () => {
  it("builds CPU card props from CPU-only data", () => {
    const capability: CollectorAvailability = { available: true };
    const data: CpuMetricCardData = {
      chartData: {
        aggregate: { name: "使用率", points: [[1_725_000_000_000, 24]] },
        cores: [{ name: "cpu0", points: [[1_725_000_000_000, 24]] }],
      },
      chartStartContinuityGapMs: 4_000,
      hostFacts: {
        cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
        id: 1,
        inventory: { cpuCount: 2 },
      },
      latestSample: null,
    };

    expect(cpuMetricCardProps(capability, data)).toEqual({
      capability,
      data,
    });
  });
});
