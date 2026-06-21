export type ProbeOperationState =
  | "pending"
  | "accepted"
  | "running"
  | "succeeded"
  | "failed"
  | "superseded"
  | "canceled";

export type ProbeOperationKind = "probe_upgrade";

export type ProbeUpgradeRequest = {
  acceptedAtMs: number | null;
  canceledAtMs: number | null;
  completedAtMs: number | null;
  createdAtMs: number;
  currentProbeVersion: string | null;
  failureCode: string | null;
  failureMessage: string | null;
  hostId: number;
  id: number | null;
  kind: ProbeOperationKind;
  runningAtMs: number | null;
  state: ProbeOperationState;
  supersededAtMs: number | null;
  targetProbeVersion: string;
  updatedAtMs: number;
};

export type ProbeUpgradeRequestLifecycleEvent = {
  action: "created" | "superseded";
  operation: ProbeUpgradeRequest;
};

export type CreateProbeUpgradeRequestResult = {
  events: ProbeUpgradeRequestLifecycleEvent[];
  operation: ProbeUpgradeRequest;
};

export function createProbeUpgradeRequest(input: {
  activeOperation: ProbeUpgradeRequest | null;
  currentProbeVersion: string | null;
  hostId: number;
  nowMs: number;
  targetProbeVersion: string;
}): CreateProbeUpgradeRequestResult {
  if (
    input.activeOperation?.targetProbeVersion === input.targetProbeVersion &&
    isActiveProbeOperation(input.activeOperation)
  ) {
    return {
      events: [],
      operation: input.activeOperation,
    };
  }

  const operation = newPendingProbeUpgradeRequest(input);

  if (
    input.activeOperation &&
    isSafeToSupersedeProbeOperation(input.activeOperation)
  ) {
    const superseded = {
      ...input.activeOperation,
      state: "superseded" as const,
      supersededAtMs: input.nowMs,
      updatedAtMs: input.nowMs,
    };

    return {
      events: [
        {
          action: "superseded",
          operation: superseded,
        },
        {
          action: "created",
          operation,
        },
      ],
      operation,
    };
  }

  return {
    events: [
      {
        action: "created",
        operation,
      },
    ],
    operation,
  };
}

export function cancelProbeUpgradeRequest(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): {
  canceled: ProbeUpgradeRequest | null;
  error: "probe_upgrade_request_not_cancelable" | null;
} {
  if (input.operation.state !== "pending") {
    return {
      canceled: null,
      error: "probe_upgrade_request_not_cancelable",
    };
  }

  return {
    canceled: {
      ...input.operation,
      canceledAtMs: input.nowMs,
      state: "canceled",
      updatedAtMs: input.nowMs,
    },
    error: null,
  };
}

export function acceptedTimedOutProbeUpgradeRequest(input: {
  acceptedTimeoutMs: number;
  nowMs: number;
  operation: ProbeUpgradeRequest;
}) {
  if (
    input.operation.state !== "accepted" ||
    input.operation.acceptedAtMs === null ||
    input.nowMs - input.operation.acceptedAtMs < input.acceptedTimeoutMs
  ) {
    return null;
  }

  return failProbeUpgradeRequest({
    code: "accepted_timeout",
    message: "Probe accepted the upgrade request but did not start it in time.",
    nowMs: input.nowMs,
    operation: input.operation,
  });
}

export function runningTimedOutProbeUpgradeRequest(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
  runningTimeoutMs: number;
}) {
  if (
    input.operation.state !== "running" ||
    input.operation.runningAtMs === null ||
    input.nowMs - input.operation.runningAtMs < input.runningTimeoutMs
  ) {
    return null;
  }

  return failProbeUpgradeRequest({
    code: "running_timeout",
    message:
      "Probe started the upgrade but did not report the target version in time.",
    nowMs: input.nowMs,
    operation: input.operation,
  });
}

export function isActiveProbeOperation(operation: ProbeUpgradeRequest) {
  return ["pending", "accepted", "running"].includes(operation.state);
}

function isSafeToSupersedeProbeOperation(operation: ProbeUpgradeRequest) {
  return operation.state === "pending" || operation.state === "accepted";
}

function newPendingProbeUpgradeRequest(input: {
  currentProbeVersion: string | null;
  hostId: number;
  nowMs: number;
  targetProbeVersion: string;
}): ProbeUpgradeRequest {
  return {
    acceptedAtMs: null,
    canceledAtMs: null,
    completedAtMs: null,
    createdAtMs: input.nowMs,
    currentProbeVersion: input.currentProbeVersion,
    failureCode: null,
    failureMessage: null,
    hostId: input.hostId,
    id: null,
    kind: "probe_upgrade",
    runningAtMs: null,
    state: "pending",
    supersededAtMs: null,
    targetProbeVersion: input.targetProbeVersion,
    updatedAtMs: input.nowMs,
  };
}

function failProbeUpgradeRequest(input: {
  code: string;
  message: string;
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): ProbeUpgradeRequest {
  return {
    ...input.operation,
    completedAtMs: input.nowMs,
    failureCode: input.code,
    failureMessage: input.message,
    state: "failed",
    updatedAtMs: input.nowMs,
  };
}
