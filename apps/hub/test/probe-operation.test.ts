import { describe, expect, it } from "vitest";

import {
  acceptedTimedOutProbeUpgradeRequest,
  cancelProbeUpgradeRequest,
  createProbeUpgradeRequest,
  runningTimedOutProbeUpgradeRequest,
} from "../src/probe/operation";

describe("Probe Upgrade Request lifecycle", () => {
  it("creates a pending Probe Upgrade Request with Unix millisecond timestamps", () => {
    const result = createProbeUpgradeRequest({
      activeOperation: null,
      currentProbeVersion: "0.1.0",
      hostId: 7,
      nowMs: 1_725_000_000_000,
      targetProbeVersion: "0.2.0",
    });

    expect(result.operation).toEqual({
      acceptedAtMs: null,
      canceledAtMs: null,
      completedAtMs: null,
      createdAtMs: 1_725_000_000_000,
      currentProbeVersion: "0.1.0",
      failureCode: null,
      failureMessage: null,
      hostId: 7,
      id: null,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "pending",
      supersededAtMs: null,
      targetProbeVersion: "0.2.0",
      updatedAtMs: 1_725_000_000_000,
    });
    expect(result.events).toEqual([
      {
        action: "created",
        operation: result.operation,
      },
    ]);
  });

  it("reuses an active Probe Upgrade Request for the same Host and target", () => {
    const first = createProbeUpgradeRequest({
      activeOperation: null,
      currentProbeVersion: "0.1.0",
      hostId: 7,
      nowMs: 1_725_000_000_000,
      targetProbeVersion: "0.2.0",
    }).operation;

    const second = createProbeUpgradeRequest({
      activeOperation: { ...first, id: 42 },
      currentProbeVersion: "0.1.0",
      hostId: 7,
      nowMs: 1_725_000_001_000,
      targetProbeVersion: "0.2.0",
    });

    expect(second.operation).toEqual({ ...first, id: 42 });
    expect(second.events).toEqual([]);
  });

  it("supersedes a safe active request when a different target is requested", () => {
    const active = {
      ...createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: 7,
        nowMs: 1_725_000_000_000,
        targetProbeVersion: "0.2.0",
      }).operation,
      id: 42,
    };

    const result = createProbeUpgradeRequest({
      activeOperation: active,
      currentProbeVersion: "0.1.0",
      hostId: 7,
      nowMs: 1_725_000_001_000,
      targetProbeVersion: "0.3.0",
    });

    expect(result.operation).toEqual(
      expect.objectContaining({
        hostId: 7,
        state: "pending",
        targetProbeVersion: "0.3.0",
      }),
    );
    expect(result.events).toEqual([
      {
        action: "superseded",
        operation: {
          ...active,
          state: "superseded",
          supersededAtMs: 1_725_000_001_000,
          updatedAtMs: 1_725_000_001_000,
        },
      },
      {
        action: "created",
        operation: result.operation,
      },
    ]);
  });

  it("rejects a different target while a request is already running", () => {
    const active = {
      ...createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: 7,
        nowMs: 1_725_000_000_000,
        targetProbeVersion: "0.2.0",
      }).operation,
      id: 42,
      runningAtMs: 1_725_000_100_000,
      state: "running" as const,
    };

    expect(
      createProbeUpgradeRequest({
        activeOperation: active,
        currentProbeVersion: "0.1.0",
        hostId: 7,
        nowMs: 1_725_000_200_000,
        targetProbeVersion: "0.3.0",
      }),
    ).toEqual({
      error: "probe_upgrade_request_active",
      events: [],
      operation: null,
    });
  });

  it("cancels pending requests but rejects accepted and running requests", () => {
    const pending = createProbeUpgradeRequest({
      activeOperation: null,
      currentProbeVersion: "0.1.0",
      hostId: 7,
      nowMs: 1_725_000_000_000,
      targetProbeVersion: "0.2.0",
    }).operation;

    expect(
      cancelProbeUpgradeRequest({
        nowMs: 1_725_000_001_000,
        operation: pending,
      }),
    ).toEqual({
      canceled: {
        ...pending,
        canceledAtMs: 1_725_000_001_000,
        state: "canceled",
        updatedAtMs: 1_725_000_001_000,
      },
      error: null,
    });

    for (const state of ["accepted", "running"] as const) {
      expect(
        cancelProbeUpgradeRequest({
          nowMs: 1_725_000_001_000,
          operation: {
            ...pending,
            state,
          },
        }),
      ).toEqual({
        canceled: null,
        error: "probe_upgrade_request_not_cancelable",
      });
    }
  });

  it("fails accepted and running requests after their configured timeout", () => {
    const pending = createProbeUpgradeRequest({
      activeOperation: null,
      currentProbeVersion: "0.1.0",
      hostId: 7,
      nowMs: 1_725_000_000_000,
      targetProbeVersion: "0.2.0",
    }).operation;

    const accepted = {
      ...pending,
      acceptedAtMs: 1_725_000_010_000,
      state: "accepted" as const,
    };
    expect(
      acceptedTimedOutProbeUpgradeRequest({
        acceptedTimeoutMs: 5 * 60 * 1000,
        nowMs: 1_725_000_310_000,
        operation: accepted,
      }),
    ).toEqual({
      ...accepted,
      completedAtMs: 1_725_000_310_000,
      failureCode: "accepted_timeout",
      failureMessage:
        "Probe accepted the upgrade request but did not start it in time.",
      state: "failed",
      updatedAtMs: 1_725_000_310_000,
    });

    const running = {
      ...pending,
      runningAtMs: 1_725_000_020_000,
      state: "running" as const,
    };
    expect(
      runningTimedOutProbeUpgradeRequest({
        nowMs: 1_725_000_920_000,
        operation: running,
        runningTimeoutMs: 15 * 60 * 1000,
      }),
    ).toEqual({
      ...running,
      completedAtMs: 1_725_000_920_000,
      failureCode: "running_timeout",
      failureMessage:
        "Probe started the upgrade but did not report the target version in time.",
      state: "failed",
      updatedAtMs: 1_725_000_920_000,
    });
  });
});
