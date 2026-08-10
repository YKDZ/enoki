import { describe, expect, it } from "vitest";

import {
  matchesActiveReadyEnrollment,
  readyEnrollmentCompletion,
} from "./ready-enrollment-flow";

describe("ready Enrollment flow", () => {
  it("returns from a Host detail page and reloads the overview after authoritative readiness", () => {
    expect(
      readyEnrollmentCompletion(
        {
          status: "ready",
        },
        7,
      ),
    ).toEqual({
      reloadHosts: true,
      returnToOverview: true,
    });
  });

  it("does not let an unrelated ready hint close or redirect the active Enrollment", () => {
    expect(
      matchesActiveReadyEnrollment({
        activeEnrollmentId: "enr_active_1234567890",
        hintEnrollmentId: "enr_other_1234567890",
        isDialogOpen: true,
      }),
    ).toBe(false);
  });
});
