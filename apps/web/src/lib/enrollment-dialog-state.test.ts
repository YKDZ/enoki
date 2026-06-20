import { describe, expect, it } from "vitest";

import type { EnrollmentResponse } from "../types";
import { shouldCreateEnrollmentOnOpen } from "./enrollment-dialog-state";

const existingEnrollment: EnrollmentResponse = {
  enrollmentToken: "enk_enroll_old",
  expiresAtMs: 1_725_000_000_000,
  hubUrl: "https://hub.example",
  installCommand: "curl old",
  installPath: "/usr/local/bin/enoki-probe",
};

describe("enrollment dialog state", () => {
  it("creates a fresh enrollment when the add-host action is opened again", () => {
    expect(
      shouldCreateEnrollmentOnOpen({
        enrollment: existingEnrollment,
        enrollmentError: "",
        isCreatingEnrollment: false,
      }),
    ).toBe(true);
  });

  it("does not start a second enrollment request while one is already running", () => {
    expect(
      shouldCreateEnrollmentOnOpen({
        enrollment: null,
        enrollmentError: "",
        isCreatingEnrollment: true,
      }),
    ).toBe(false);
  });
});
