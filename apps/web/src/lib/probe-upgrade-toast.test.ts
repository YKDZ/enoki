import { describe, expect, it } from "vitest";

import type { HostDetail } from "../types";
import {
  probeUpgradeToastTitle,
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

  it("uses the display name in upgrade result toast titles", () => {
    expect(
      probeUpgradeToastTitle(
        hostDetail({
          displayName: "腾讯云轻量",
        }),
        "succeeded",
      ),
    ).toBe("腾讯云轻量 探针升级完成");
  });

  it("falls back to hostname when display name is blank", () => {
    expect(
      probeUpgradeToastTitle(
        hostDetail({
          displayName: " ",
          inventory: {
            hostname: "racknerd-01",
          },
        }),
        "failed",
      ),
    ).toBe("racknerd-01 探针升级失败");
  });
});

function hostDetail(overrides: Partial<HostDetail>) {
  return {
    clockSkew: {
      detected: false,
      lastDeltaMs: null,
    },
    collectorCapabilities: null,
    connectAddress: "10.0.0.1",
    cpu: "1%",
    cpuModel: null,
    description: "",
    displayName: "测试主机",
    hostMetadata: {
      connectAddress: "10.0.0.1",
      description: "",
      displayName: "测试主机",
      observedIp: null,
    },
    id: 1,
    inventory: null,
    lastReportAtMs: null,
    latestMetrics: null,
    memory: "n/a",
    probeConfiguration: {
      configuration: {
        collectCpu: true,
        collectDisk: true,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: true,
        collectUptime: true,
        metricsCollectionIntervalSeconds: 1,
        reportingBatchIntervalSeconds: 3,
        version: "default",
      },
      mode: "inherit",
      version: "default",
    },
    probeUpgradeEligibility: {
      currentProbeAssetSetVersion: null,
      currentProbeVersion: "0.1.45",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_version_current",
    },
    probeUpgradeStatus: null,
    probeVersion: "0.1.45",
    status: "online",
    system: "Linux",
    warnings: [],
    ...overrides,
  } satisfies HostDetail;
}
