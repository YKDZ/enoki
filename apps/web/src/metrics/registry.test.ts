import { describe, expect, it } from "vitest";

import type { CollectorAvailability } from "../types";
import { cpuMetricCardProps } from "./registry";
import type { CpuMetricCardViewModel } from "./view-model";

describe("official metrics card props", () => {
  it("builds CPU card props from CPU-only data", () => {
    const capability: CollectorAvailability = { available: true };
    const data: CpuMetricCardViewModel = {
      chartData: {
        aggregate: { name: "使用率", points: [[1_725_000_000_000, 24]] },
        cores: [{ name: "cpu0", points: [[1_725_000_000_000, 24]] }],
      },
      chartStartContinuityGapMs: 4_000,
      hostFacts: {
        cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
        hostProfile: {
          architecture: "x86_64",
          cpuCount: 2,
          filesystems: [],
          hostname: "managed-host-01",
          kernel: "6.8.0",
          memoryTotalBytes: 8_589_934_592,
          networkInterfaces: [],
          os: "linux",
          probeVersion: "0.1.0",
        },
        id: 1,
      },
      latestSample: null,
    };

    expect(cpuMetricCardProps(capability, data)).toEqual({
      capability,
      data,
    });
  });
});
