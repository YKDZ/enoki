import { describe, expect, it } from "vitest";

import { manualProbeReinstallPolicy } from "../src/probe/manual-reinstall-policy.js";
import type { ProbeUpgradeRequest } from "../src/probe/operation.js";

const manualTarget = {
  sourceProbeVersion: "1.2.2",
  targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
  targetProbeVersion: "1.2.3",
};

function failedOperation(
  overrides: Partial<ProbeUpgradeRequest> = {},
): ProbeUpgradeRequest {
  return {
    acceptedAtMs: 2,
    canceledAtMs: null,
    completedAtMs: 4,
    createdAtMs: 1,
    currentProbeVersion: "1.2.2",
    failureCode: "manual_probe_reinstall_required",
    failureMessage: null,
    hostId: 1,
    id: 2,
    kind: "probe_upgrade",
    runningAtMs: 3,
    state: "failed",
    supersededAtMs: null,
    targetAssetSetDigest: manualTarget.targetAssetSetDigest,
    targetProbeVersion: "1.2.3",
    updatedAtMs: 4,
    ...overrides,
  };
}

function policyInput() {
  return {
    eligibility: {
      currentProbeAssetSetVersion: "1.2.3",
      currentProbeVersion: "1.2.2",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_release_transition_missing" as const,
    },
    hostLastReportAtMs: 1_000,
    hostProbeVersion: "1.2.2",
    latestOperation: failedOperation(),
    nowMs: 100_000,
    offlineAfterMs: 90_000,
    targetAssetSetDigest: manualTarget.targetAssetSetDigest,
    targetProbeVersion: "1.2.3",
  };
}

describe("manual Probe reinstall policy", () => {
  it("returns the one signed replacement-required action", () => {
    expect(
      manualProbeReinstallPolicy({
        ...policyInput(),
        eligibility: {
          ...policyInput().eligibility,
          manualReinstall: manualTarget,
        },
        latestOperation: null,
      }),
    ).toEqual({ ...manualTarget, reason: "signed_transition" });
  });

  it("returns the same action for an offline closed recovery with an exact target", () => {
    expect(manualProbeReinstallPolicy(policyInput())).toEqual({
      ...manualTarget,
      reason: "closed_recovery",
    });
  });

  it("keeps recovery closed until the Host is offline and every target fact matches", () => {
    expect(
      manualProbeReinstallPolicy({
        ...policyInput(),
        nowMs: 90_999,
      }),
    ).toBeNull();
    expect(
      manualProbeReinstallPolicy({
        ...policyInput(),
        targetAssetSetDigest: `sha256:${"b".repeat(64)}`,
      }),
    ).toBeNull();
  });
});
