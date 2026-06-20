import type { EnrollmentResponse } from "../types";

export type EnrollmentDialogState = {
  enrollment: EnrollmentResponse | null;
  enrollmentError: string;
  isCreatingEnrollment: boolean;
};

export function shouldCreateEnrollmentOnOpen(state: EnrollmentDialogState) {
  return !state.isCreatingEnrollment;
}
