import type { EnrollmentResponse, EnrollmentStatusResponse } from "../types";

export type EnrollmentDialogState = {
  enrollment: EnrollmentResponse | null;
  enrollmentError: string;
  isCreatingEnrollment: boolean;
};

export function shouldCreateEnrollmentOnOpen(state: EnrollmentDialogState) {
  return !state.isCreatingEnrollment;
}

export function reconcileEnrollmentStatus(
  enrollment: EnrollmentResponse | null,
  status: EnrollmentStatusResponse,
) {
  if (!enrollment || enrollment.enrollmentId !== status.enrollmentId) {
    return {
      enrollment,
      shouldClose: false,
    };
  }

  const reconciled = {
    ...enrollment,
    ...status,
  };

  return {
    enrollment: reconciled,
    shouldClose: ["expired", "ready", "rejected"].includes(status.status),
  };
}

export function enrollmentTerminalMessage(status: EnrollmentStatusResponse): {
  description: string;
  title: string;
} | null {
  if (status.status !== "rejected") {
    return null;
  }

  return {
    description:
      status.rejection?.message ??
      "Probe 未在等待期限内完成与 Hub 的首次报告。",
    title: "Probe 未能就绪",
  };
}
