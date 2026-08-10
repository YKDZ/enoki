import type { EnrollmentStatusResponse } from "../types";

export function matchesActiveReadyEnrollment(input: {
  activeEnrollmentId: string | null | undefined;
  isDialogOpen: boolean;
  hintEnrollmentId: string;
}) {
  return (
    input.isDialogOpen && input.activeEnrollmentId === input.hintEnrollmentId
  );
}

export function readyEnrollmentCompletion(
  status: Pick<EnrollmentStatusResponse, "status">,
  activeDetailHostId: number | null,
) {
  return {
    reloadHosts: status.status === "ready",
    returnToOverview: status.status === "ready" && activeDetailHostId !== null,
  };
}
