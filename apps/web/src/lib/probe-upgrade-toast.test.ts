import { describe, expect, it } from "vitest";

import {
  shouldToastProbeUpgradeFailure,
  shouldToastProbeUpgradeSuccess,
} from "./probe-upgrade-toast";

describe("Probe upgrade failure toast", () => {
  it("toasts when an active operation with the same id becomes failed", () => {
    expect(
      shouldToastProbeUpgradeFailure(
        {
          createdAtMs: 1_725_000_000_000,
          failure: {
            code: "running_timeout",
            message:
              "Probe started the upgrade but did not report the target version in time.",
          },
          id: 9,
          state: "failed",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 1_725_000_900_000,
        },
        {
          createdAtMs: 1_725_000_000_000,
          failure: null,
          id: 9,
          state: "running",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 1_725_000_100_000,
        },
      ),
    ).toBe(true);
  });

  it("does not toast repeatedly when the same failed operation refreshes", () => {
    const failedStatus = {
      createdAtMs: 1_725_000_000_000,
      failure: {
        code: "running_timeout",
        message:
          "Probe started the upgrade but did not report the target version in time.",
      },
      id: 9,
      state: "failed" as const,
      targetProbeVersion: "0.2.0",
      updatedAtMs: 1_725_000_900_000,
    };

    expect(shouldToastProbeUpgradeFailure(failedStatus, failedStatus)).toBe(
      false,
    );
  });

  it("does not toast old failed operations on initial detail load", () => {
    expect(
      shouldToastProbeUpgradeFailure(
        {
          createdAtMs: 1_725_000_000_000,
          failure: {
            code: "running_timeout",
            message: "升级超时。",
          },
          id: 9,
          state: "failed",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 1_725_000_900_000,
        },
        null,
      ),
    ).toBe(false);
  });

  it("toasts when an active operation with the same id succeeds", () => {
    expect(
      shouldToastProbeUpgradeSuccess(
        {
          createdAtMs: 1,
          failure: null,
          id: 9,
          state: "succeeded",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 3,
        },
        {
          createdAtMs: 1,
          failure: null,
          id: 9,
          state: "running",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 2,
        },
      ),
    ).toBe(true);
  });

  it("does not toast old succeeded operations on initial detail load", () => {
    expect(
      shouldToastProbeUpgradeSuccess(
        {
          createdAtMs: 1,
          failure: null,
          id: 9,
          state: "succeeded",
          targetProbeVersion: "0.2.0",
          updatedAtMs: 3,
        },
        null,
      ),
    ).toBe(false);
  });
});
