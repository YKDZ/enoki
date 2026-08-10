import type {
  EnrollmentStatus,
  EnrollmentStatusResponse,
  EnrollmentTarget,
} from "@enoki/api-client";

export const enrollmentStatusValues = [
  "pending",
  "verifying",
  "ready",
  "rejected",
  "expired",
] as const satisfies readonly EnrollmentStatus[];

export const enrollmentTargetKindValues = [
  "new_host",
  "existing_host",
] as const;

export const maxEnrollmentRejectionCodeLength = 64;
export const maxEnrollmentRejectionMessageLength = 512;

export type EnrollmentTargetKind = (typeof enrollmentTargetKindValues)[number];

export type EnrollmentLifecycleRecord = {
  createdAtMs: number;
  enrollmentId: string | null;
  expiredAtMs: number | null;
  expiresAtMs: number;
  hostId: number | null;
  readyAtMs: number | null;
  rejectedAtMs: number | null;
  rejectionCode: string | null;
  rejectionMessage: string | null;
  status: string;
  targetHostId: number | null;
  targetKind: string | null;
  usedAtMs: number | null;
  verificationDeadlineAtMs: number | null;
};

export function enrollmentStatusResponse(
  enrollment: EnrollmentLifecycleRecord,
): EnrollmentStatusResponse | null {
  const status = enrollmentStatus(enrollment.status);
  const target = enrollmentTarget(enrollment);
  const rejection = enrollmentRejection(enrollment);
  if (
    !status ||
    !target ||
    !rejection ||
    !validEnrollmentId(enrollment.enrollmentId)
  ) {
    return null;
  }

  return {
    createdAtMs: enrollment.createdAtMs,
    enrollmentId: enrollment.enrollmentId,
    expiresAtMs: enrollment.expiresAtMs,
    expiredAtMs: enrollment.expiredAtMs,
    hostId: enrollment.hostId,
    readyAtMs: enrollment.readyAtMs,
    rejectedAtMs: enrollment.rejectedAtMs,
    rejection: rejection.value,
    status,
    target,
    verificationDeadlineAtMs: enrollment.verificationDeadlineAtMs,
  };
}

export function isEnrollmentStatus(value: string): value is EnrollmentStatus {
  return enrollmentStatusValues.includes(value as EnrollmentStatus);
}

export function isEnrollmentTargetKind(
  value: string,
): value is EnrollmentTargetKind {
  return enrollmentTargetKindValues.includes(value as EnrollmentTargetKind);
}

export function validEnrollmentId(value: string | null): value is string {
  return typeof value === "string" && /^enr_[A-Za-z0-9_-]{16,}$/.test(value);
}

function enrollmentStatus(value: string): EnrollmentStatus | null {
  return isEnrollmentStatus(value) ? value : null;
}

function enrollmentTarget(
  enrollment: EnrollmentLifecycleRecord,
): EnrollmentTarget | null {
  if (
    enrollment.targetKind === "new_host" &&
    enrollment.targetHostId === null
  ) {
    return { kind: "new_host" };
  }

  if (
    enrollment.targetKind === "existing_host" &&
    positiveInteger(enrollment.targetHostId)
  ) {
    return { hostId: enrollment.targetHostId, kind: "existing_host" };
  }

  return null;
}

function enrollmentRejection(enrollment: EnrollmentLifecycleRecord): {
  value: EnrollmentStatusResponse["rejection"];
} | null {
  if (enrollment.rejectionCode === null) {
    return enrollment.rejectionMessage === null ? { value: null } : null;
  }

  if (
    !boundedText(enrollment.rejectionCode, maxEnrollmentRejectionCodeLength) ||
    !(
      enrollment.rejectionMessage === null ||
      boundedText(
        enrollment.rejectionMessage,
        maxEnrollmentRejectionMessageLength,
      )
    )
  ) {
    return null;
  }

  return {
    value: {
      code: enrollment.rejectionCode,
      message: enrollment.rejectionMessage,
    },
  };
}

function boundedText(value: string, maximumLength: number) {
  return value.length > 0 && value.length <= maximumLength;
}

function positiveInteger(value: number | null): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}
