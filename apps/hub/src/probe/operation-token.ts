import { createHmac, timingSafeEqual } from "node:crypto";

import type { ProbeOperationState, ProbeUpgradeRequest } from "./operation.js";

export type ProbeOperationTokenValidationError =
  | "probe_operation_token_invalid"
  | "probe_operation_token_expired"
  | "probe_operation_token_operation_mismatch"
  | "probe_operation_token_probe_mismatch"
  | "probe_operation_token_target_mismatch"
  | "probe_operation_token_operation_closed";

type ProbeOperationTokenPayload = {
  expiresAtMs: number;
  kind: string;
  operationId: number;
  probeId: string;
  targetProbeVersion?: string;
};

const closedStates: ProbeOperationState[] = [
  "canceled",
  "failed",
  "superseded",
  "succeeded",
];

export const defaultProbeOperationTokenTtlMs = 5 * 60 * 1000;

export function issueProbeOperationToken(input: {
  expiresAtMs: number;
  operation: ProbeUpgradeRequest;
  probeId: string;
  secret: string;
}) {
  if (input.operation.id === null) {
    throw new Error(
      "Cannot issue Probe Operation Token for unsaved operation.",
    );
  }

  const payload: ProbeOperationTokenPayload = {
    expiresAtMs: input.expiresAtMs,
    kind: input.operation.kind,
    operationId: input.operation.id,
    probeId: input.probeId,
    targetProbeVersion:
      input.operation.kind === "probe_upgrade"
        ? input.operation.targetProbeVersion
        : undefined,
  };
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = sign(encodedPayload, input.secret);

  return `${encodedPayload}.${signature}`;
}

export function validateProbeOperationToken(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
  probeId: string;
  secret: string;
  targetProbeVersion: string;
  token: string;
}): { error: ProbeOperationTokenValidationError | null } {
  const payload = decodeAndVerifyToken(input.token, input.secret);

  if (!payload || input.operation.id === null) {
    return { error: "probe_operation_token_invalid" };
  }

  if (payload.operationId !== input.operation.id) {
    return { error: "probe_operation_token_operation_mismatch" };
  }

  if (payload.probeId !== input.probeId) {
    return { error: "probe_operation_token_probe_mismatch" };
  }

  if (payload.kind !== input.operation.kind) {
    return { error: "probe_operation_token_operation_mismatch" };
  }

  if (
    input.operation.kind === "probe_upgrade" &&
    (payload.targetProbeVersion !== input.targetProbeVersion ||
      input.operation.targetProbeVersion !== input.targetProbeVersion)
  ) {
    return { error: "probe_operation_token_target_mismatch" };
  }

  if (input.nowMs > payload.expiresAtMs) {
    return { error: "probe_operation_token_expired" };
  }

  if (closedStates.includes(input.operation.state)) {
    return { error: "probe_operation_token_operation_closed" };
  }

  return { error: null };
}

function decodeAndVerifyToken(token: string, secret: string) {
  const [encodedPayload, signature, extra] = token.split(".");

  if (!encodedPayload || !signature || extra) {
    return null;
  }

  const expectedSignature = sign(encodedPayload, secret);
  if (!safeEqual(signature, expectedSignature)) {
    return null;
  }

  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload));

    if (!isProbeOperationTokenPayload(payload)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function isProbeOperationTokenPayload(
  payload: unknown,
): payload is ProbeOperationTokenPayload {
  return (
    typeof payload === "object" &&
    payload !== null &&
    typeof (payload as ProbeOperationTokenPayload).expiresAtMs === "number" &&
    typeof (payload as ProbeOperationTokenPayload).kind === "string" &&
    typeof (payload as ProbeOperationTokenPayload).operationId === "number" &&
    typeof (payload as ProbeOperationTokenPayload).probeId === "string" &&
    (typeof (payload as ProbeOperationTokenPayload).targetProbeVersion ===
      "string" ||
      typeof (payload as ProbeOperationTokenPayload).targetProbeVersion ===
        "undefined")
  );
}

function sign(encodedPayload: string, secret: string) {
  return createHmac("sha256", secret)
    .update(encodedPayload)
    .digest("base64url");
}

function safeEqual(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  return (
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}

function base64UrlEncode(value: string) {
  return Buffer.from(value, "utf8").toString("base64url");
}

function base64UrlDecode(value: string) {
  return Buffer.from(value, "base64url").toString("utf8");
}
