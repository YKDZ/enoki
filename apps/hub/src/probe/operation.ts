export type ProbeOperationState =
  | "pending"
  | "accepted"
  | "running"
  | "succeeded"
  | "failed"
  | "superseded"
  | "canceled";

export type ProbeOperationKind = "probe_upgrade" | "probe_uninstall";

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

export type CreateProbeUpgradeRequestResult =
  | {
      error: null;
      events: ProbeUpgradeRequestLifecycleEvent[];
      operation: ProbeUpgradeRequest;
    }
  | {
      error: "probe_upgrade_request_active";
      events: [];
      operation: null;
    };

export type CreateProbeUninstallRequestResult =
  | {
      error: null;
      events: ProbeUpgradeRequestLifecycleEvent[];
      operation: ProbeUpgradeRequest;
    }
  | {
      error: "probe_operation_active";
      events: [];
      operation: null;
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
      error: null,
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
      error: null,
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

  if (input.activeOperation && isActiveProbeOperation(input.activeOperation)) {
    return {
      error: "probe_upgrade_request_active",
      events: [],
      operation: null,
    };
  }

  return {
    error: null,
    events: [
      {
        action: "created",
        operation,
      },
    ],
    operation,
  };
}

export function createProbeUninstallRequest(input: {
  activeOperation: ProbeUpgradeRequest | null;
  hostId: number;
  nowMs: number;
}): CreateProbeUninstallRequestResult {
  if (input.activeOperation?.kind === "probe_uninstall") {
    return {
      error: null,
      events: [],
      operation: input.activeOperation,
    };
  }

  const operation = newPendingProbeUninstallRequest(input);

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
      error: null,
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

  if (input.activeOperation && isActiveProbeOperation(input.activeOperation)) {
    return {
      error: "probe_operation_active",
      events: [],
      operation: null,
    };
  }

  return {
    error: null,
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

export function acknowledgeProbeUpgradeRequest(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): {
  acknowledged: ProbeUpgradeRequest;
  error: "probe_operation_not_acknowledgeable" | null;
} {
  if (input.operation.state === "pending") {
    return {
      acknowledged: {
        ...input.operation,
        acceptedAtMs: input.operation.acceptedAtMs ?? input.nowMs,
        state: "accepted",
        updatedAtMs: input.nowMs,
      },
      error: null,
    };
  }

  if (
    input.operation.state === "accepted" ||
    input.operation.state === "running"
  ) {
    return {
      acknowledged: input.operation,
      error: null,
    };
  }

  return {
    acknowledged: input.operation,
    error: "probe_operation_not_acknowledgeable",
  };
}

export function startProbeUpgradeRequest(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): {
  error: "probe_operation_status_invalid" | null;
  operation: ProbeUpgradeRequest;
} {
  if (input.operation.state === "accepted") {
    return {
      error: null,
      operation: {
        ...input.operation,
        runningAtMs: input.operation.runningAtMs ?? input.nowMs,
        state: "running",
        updatedAtMs: input.nowMs,
      },
    };
  }

  if (input.operation.state === "running") {
    return {
      error: null,
      operation: input.operation,
    };
  }

  return {
    error: "probe_operation_status_invalid",
    operation: input.operation,
  };
}

export function failReportedProbeUpgradeRequest(input: {
  code: string;
  message: string;
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): {
  error: "probe_operation_status_invalid" | null;
  operation: ProbeUpgradeRequest;
} {
  if (
    input.operation.state === "accepted" ||
    input.operation.state === "running"
  ) {
    return {
      error: null,
      operation: failProbeUpgradeRequest({
        code: input.code,
        message: input.message,
        nowMs: input.nowMs,
        operation: input.operation,
      }),
    };
  }

  if (input.operation.state === "failed") {
    return {
      error: null,
      operation: input.operation,
    };
  }

  return {
    error: "probe_operation_status_invalid",
    operation: input.operation,
  };
}

export function succeedReportedProbeOperation(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
}): {
  error: "probe_operation_status_invalid" | null;
  operation: ProbeUpgradeRequest;
} {
  if (
    input.operation.kind === "probe_uninstall" &&
    (input.operation.state === "accepted" ||
      input.operation.state === "running")
  ) {
    return {
      error: null,
      operation: {
        ...input.operation,
        completedAtMs: input.nowMs,
        failureCode: null,
        failureMessage: null,
        state: "succeeded",
        updatedAtMs: input.nowMs,
      },
    };
  }

  if (input.operation.state === "succeeded") {
    return {
      error: null,
      operation: input.operation,
    };
  }

  return {
    error: "probe_operation_status_invalid",
    operation: input.operation,
  };
}

export function succeedProbeUpgradeRequestFromInventory(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
  probeVersion: string | null | undefined;
}): ProbeUpgradeRequest | null {
  if (
    input.operation.kind !== "probe_upgrade" ||
    !isActiveProbeOperation(input.operation) ||
    normalizeProbeVersion(input.probeVersion) !==
      normalizeProbeVersion(input.operation.targetProbeVersion)
  ) {
    return null;
  }

  return {
    ...input.operation,
    completedAtMs: input.nowMs,
    failureCode: null,
    failureMessage: null,
    state: "succeeded",
    updatedAtMs: input.nowMs,
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
      input.operation.kind === "probe_uninstall"
        ? "Probe started the uninstall but did not report completion in time."
        : "Probe started the upgrade but did not report the target version in time.",
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

function normalizeProbeVersion(value: string | null | undefined) {
  return typeof value === "string" ? value.trim().replace(/^v/, "") : "";
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

function newPendingProbeUninstallRequest(input: {
  hostId: number;
  nowMs: number;
}): ProbeUpgradeRequest {
  return {
    acceptedAtMs: null,
    canceledAtMs: null,
    completedAtMs: null,
    createdAtMs: input.nowMs,
    currentProbeVersion: null,
    failureCode: null,
    failureMessage: null,
    hostId: input.hostId,
    id: null,
    kind: "probe_uninstall",
    runningAtMs: null,
    state: "pending",
    supersededAtMs: null,
    targetProbeVersion: "",
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
