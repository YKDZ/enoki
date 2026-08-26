import { describe, expect, it } from "vitest";

import { admitProbeReport } from "../src/probe/report-validation.js";

describe("Probe report admission", () => {
  it("classifies the single empty sequence-one control report as startup", () => {
    const admitted = admitProbeReport({
      bootId: "boot-1",
      metrics: [],
      probeAssetBundleVersion: "1.2.3",
      probeConfigurationVersion: "default-v1",
      sequenceEnd: 1,
      sequenceStart: 1,
      snapshots: [],
    });

    expect(admitted).toMatchObject({
      reportResponsibility: "startup",
      validatedReport: { sequenceEnd: 1, sequenceStart: 1 },
    });
  });

  it("admits an ordinary observation without reclassifying it as startup", () => {
    const admitted = admitProbeReport({
      bootId: "boot-1",
      metrics: [{ collectedAtMs: 1234, sequence: 7 }],
      sequenceEnd: 7,
      sequenceStart: 7,
      snapshots: [],
    });

    expect(admitted?.reportResponsibility).toBe("legacy_observation");
  });

  it("rejects oversized sequence windows and mismatched Host Profile hashes", () => {
    expect(
      admitProbeReport({
        bootId: "boot-1",
        metrics: [],
        sequenceEnd: 10_001,
        sequenceStart: 1,
        snapshots: [],
      }),
    ).toBeNull();

    expect(
      admitProbeReport({
        bootId: "boot-1",
        metrics: [],
        probeConfigurationVersion: "default-v1",
        sequenceEnd: 1,
        sequenceStart: 1,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: { hostname: "host-1" },
            snapshotHash: "0".repeat(64),
          },
        ],
      }),
    ).toBeNull();
  });
});
