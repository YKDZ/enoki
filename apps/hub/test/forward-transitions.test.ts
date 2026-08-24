import { describe, expect, it } from "vitest";

import type { ProbeOperationRepository } from "../src/database/probe-operations";
import { createForwardTransitions } from "../src/probe/forward-transitions";
import type { ProbeUpgradeRequest } from "../src/probe/operation";

describe("ForwardTransitions", () => {
  it("authorizes a compatible upgrade through the signed contract and persists its ordinary Probe Operation", () => {
    const operations: ProbeUpgradeRequest[] = [];
    const repository = memoryProbeOperations(operations);
    const forwardTransitions = createForwardTransitions({
      probeOperations: repository,
    });

    const result = forwardTransitions.authorize({
      intent: {
        kind: "compatible_upgrade",
        hostId: 7,
        sourceProbeVersion: "1.3.0",
        targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
        targetProbeVersion: "1.4.0",
      },
      nowMs: 1_725_000_000_000,
      releaseTransition: {
        classification: "compatible",
        sourceProbeSha256: ["b".repeat(64)],
        sourceProbeVersion: "1.3.0",
        targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
        targetProbeVersion: "1.4.0",
      },
    });

    expect(result).toEqual({
      kind: "authorized",
      operation: expect.objectContaining({
        currentProbeVersion: "1.3.0",
        hostId: 7,
        id: 1,
        kind: "probe_upgrade",
        state: "pending",
        targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
        targetProbeVersion: "1.4.0",
      }),
      reused: false,
    });
    expect(repository.findLatestForHost(7)).toEqual(
      expect.objectContaining({ id: 1, kind: "probe_upgrade" }),
    );
  });

  it("refuses replacement-required contracts and conflicting active Operations", () => {
    const operations: ProbeUpgradeRequest[] = [];
    const forwardTransitions = createForwardTransitions({
      probeOperations: memoryProbeOperations(operations),
    });
    const intent = {
      hostId: 7,
      kind: "compatible_upgrade" as const,
      sourceProbeVersion: "1.3.0",
      targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
      targetProbeVersion: "1.4.0",
    };
    const transition = {
      classification: "compatible" as const,
      sourceProbeSha256: ["b".repeat(64)],
      sourceProbeVersion: "1.3.0",
      targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
      targetProbeVersion: "1.4.0",
    };

    expect(
      forwardTransitions.authorize({
        intent,
        nowMs: 1_725_000_000_000,
        releaseTransition: {
          ...transition,
          classification: "replacement-required",
        },
      }),
    ).toEqual({
      kind: "refused",
      reason: "probe_release_transition_replacement_required",
    });
    expect(operations).toEqual([]);

    operations.push({
      ...failedUpgrade({ failureCode: "unused" }),
      completedAtMs: null,
      failureCode: null,
      id: 1,
      state: "running",
      targetProbeVersion: "1.5.0",
    });
    expect(
      forwardTransitions.authorize({
        intent,
        nowMs: 1_725_000_001_000,
        releaseTransition: transition,
      }),
    ).toEqual({
      kind: "refused",
      reason: "probe_upgrade_request_active",
    });
    expect(operations).toHaveLength(1);
  });

  it("clears a recovered current view without rewriting the failed Operation", () => {
    const failed = failedUpgrade({ failureCode: "running_timeout" });
    const operations = [failed];
    const forwardTransitions = createForwardTransitions({
      probeOperations: memoryProbeOperations(operations),
    });

    expect(
      forwardTransitions.view({
        acceptedHostProfile: {
          kind: "authenticated_host_profile",
          observedAtMs: failed.completedAtMs! + 1,
          probeVersion: "v1.4.0",
        },
        latestOperation: failed,
      }),
    ).toEqual({
      currentOperation: null,
      overviewProblem: null,
      status: null,
    });
    expect(operations[0]).toEqual(failed);
  });

  it("does not collapse an unresolved Repair into Compatible Upgrade recovery", () => {
    const repair = {
      ...failedUpgrade({ failureCode: "lifecycle.repair_unresolved" }),
      id: 2,
      kind: "probe_repair" as const,
    };
    const forwardTransitions = createForwardTransitions({
      probeOperations: memoryProbeOperations([repair]),
    });

    expect(
      forwardTransitions.view({
        acceptedHostProfile: {
          kind: "authenticated_host_profile",
          observedAtMs: repair.completedAtMs! + 1,
          probeVersion: repair.targetProbeVersion,
        },
        latestOperation: repair,
      }).currentOperation,
    ).toBe(repair);
  });

  it("reconciles authenticated Compatible Upgrade evidence through one closed batch", () => {
    const operations: ProbeUpgradeRequest[] = [];
    const forwardTransitions = createForwardTransitions({
      probeOperations: memoryProbeOperations(operations),
    });
    const authorized = forwardTransitions.authorize({
      intent: {
        kind: "compatible_upgrade",
        hostId: 7,
        sourceProbeVersion: "1.3.0",
        targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
        targetProbeVersion: "1.4.0",
      },
      nowMs: 1_725_000_000_000,
      releaseTransition: {
        classification: "compatible",
        sourceProbeSha256: ["b".repeat(64)],
        sourceProbeVersion: "1.3.0",
        targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
        targetProbeVersion: "1.4.0",
      },
    });
    if (authorized.kind !== "authorized") throw new Error("not authorized");

    expect(
      forwardTransitions.reconcileAuthenticatedEvidence({
        evidence: [
          {
            hostId: 7,
            kind: "operation_accepted",
            observedAtMs: 1_725_000_001_000,
            operationId: authorized.operation.id!,
          },
          {
            hostId: 7,
            kind: "operation_running",
            observedAtMs: 1_725_000_002_000,
            operationId: authorized.operation.id!,
          },
        ],
      }),
    ).toEqual({
      kind: "reconciled",
      operations: [expect.objectContaining({ state: "running" })],
    });
    expect(operations[0]).toEqual(
      expect.objectContaining({
        acceptedAtMs: 1_725_000_001_000,
        runningAtMs: 1_725_000_002_000,
        state: "running",
      }),
    );
  });
});

function failedUpgrade(input: { failureCode: string }): ProbeUpgradeRequest {
  return {
    acceptedAtMs: 1_725_000_001_000,
    canceledAtMs: null,
    completedAtMs: 1_725_000_010_000,
    createdAtMs: 1_725_000_000_000,
    currentProbeVersion: "1.3.0",
    failureCode: input.failureCode,
    failureMessage: "private",
    hostId: 7,
    id: 1,
    kind: "probe_upgrade",
    runningAtMs: 1_725_000_002_000,
    state: "failed",
    supersededAtMs: null,
    targetAssetSetDigest: `sha256:${"a".repeat(64)}`,
    targetProbeVersion: "1.4.0",
    updatedAtMs: 1_725_000_010_000,
  };
}

function memoryProbeOperations(
  operations: ProbeUpgradeRequest[],
): ProbeOperationRepository {
  return {
    admitPendingProbeUpgradeRequest: () => null,
    createProbeUpgradeRequest(operation) {
      const persisted = { ...operation, id: operations.length + 1 };
      operations.push(persisted);
      return persisted;
    },
    commitProbeUpgradeAuthorization(events) {
      let authorized: ProbeUpgradeRequest | null = null;
      for (const event of events) {
        if (event.action === "superseded") {
          const index = operations.findIndex(
            ({ id }) => id === event.operation.id,
          );
          operations[index] = event.operation;
          continue;
        }
        authorized = {
          ...event.operation,
          id: operations.length + 1,
        };
        operations.push(authorized);
      }
      if (!authorized) throw new Error("missing created operation");
      return authorized;
    },
    findActiveForHost(hostId) {
      return (
        operations.find(
          (operation) =>
            operation.hostId === hostId &&
            ["pending", "accepted", "running"].includes(operation.state),
        ) ?? null
      );
    },
    findBoundFailedUpgradeForRepair: () => null,
    findById: (id) =>
      operations.find((operation) => operation.id === id) ?? null,
    findByRepairEvidenceSha256: () => null,
    findLatestForHost: (hostId) =>
      operations.findLast((operation) => operation.hostId === hostId) ?? null,
    findLatestForHosts: () => new Map(),
    renewOrCreateProbeRepairRequest: () => null,
    updateProbeUpgradeRequest(operation) {
      const index = operations.findIndex(({ id }) => id === operation.id);
      operations[index] = operation;
      return operation;
    },
  };
}
