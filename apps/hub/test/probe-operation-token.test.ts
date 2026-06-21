import { describe, expect, it } from "vitest";

import { createProbeUpgradeRequest } from "../src/probe/operation";
import {
  issueProbeOperationToken,
  validateProbeOperationToken,
} from "../src/probe/operation-token";

describe("Probe Operation Token", () => {
  it("authorizes one Probe Upgrade Request for one Probe Identity until expiration", () => {
    const operation = {
      ...createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: 7,
        nowMs: 1_725_000_000_000,
        targetProbeVersion: "0.2.0",
      }).operation,
      id: 42,
    };
    const token = issueProbeOperationToken({
      expiresAtMs: 1_725_000_060_000,
      operation,
      probeId: "probe_01",
      secret: "test-signing-secret",
    });

    expect(
      validateProbeOperationToken({
        nowMs: 1_725_000_010_000,
        operation,
        probeId: "probe_01",
        secret: "test-signing-secret",
        targetProbeVersion: "0.2.0",
        token,
      }),
    ).toEqual({ error: null });

    expect(
      validateProbeOperationToken({
        nowMs: 1_725_000_010_000,
        operation,
        probeId: "probe_02",
        secret: "test-signing-secret",
        targetProbeVersion: "0.2.0",
        token,
      }),
    ).toEqual({ error: "probe_operation_token_probe_mismatch" });

    expect(
      validateProbeOperationToken({
        nowMs: 1_725_000_010_000,
        operation,
        probeId: "probe_01",
        secret: "test-signing-secret",
        targetProbeVersion: "0.3.0",
        token,
      }),
    ).toEqual({ error: "probe_operation_token_target_mismatch" });

    expect(
      validateProbeOperationToken({
        nowMs: 1_725_000_060_001,
        operation,
        probeId: "probe_01",
        secret: "test-signing-secret",
        targetProbeVersion: "0.2.0",
        token,
      }),
    ).toEqual({ error: "probe_operation_token_expired" });
  });

  it("rejects wrong operation and closed Probe Upgrade Requests", () => {
    const operation = {
      ...createProbeUpgradeRequest({
        activeOperation: null,
        currentProbeVersion: "0.1.0",
        hostId: 7,
        nowMs: 1_725_000_000_000,
        targetProbeVersion: "0.2.0",
      }).operation,
      id: 42,
    };
    const token = issueProbeOperationToken({
      expiresAtMs: 1_725_000_060_000,
      operation,
      probeId: "probe_01",
      secret: "test-signing-secret",
    });

    expect(
      validateProbeOperationToken({
        nowMs: 1_725_000_010_000,
        operation: { ...operation, id: 43 },
        probeId: "probe_01",
        secret: "test-signing-secret",
        targetProbeVersion: "0.2.0",
        token,
      }),
    ).toEqual({ error: "probe_operation_token_operation_mismatch" });

    for (const state of ["canceled", "superseded"] as const) {
      expect(
        validateProbeOperationToken({
          nowMs: 1_725_000_010_000,
          operation: { ...operation, state },
          probeId: "probe_01",
          secret: "test-signing-secret",
          targetProbeVersion: "0.2.0",
          token,
        }),
      ).toEqual({ error: "probe_operation_token_operation_closed" });
    }
  });
});
