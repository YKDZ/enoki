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
