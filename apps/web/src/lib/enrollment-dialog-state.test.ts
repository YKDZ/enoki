import { describe, expect, it } from "vitest";

import type { EnrollmentResponse, EnrollmentStatusResponse } from "../types";
import {
  reconcileEnrollmentStatus,
  shouldCreateEnrollmentOnOpen,
} from "./enrollment-dialog-state";

const existingEnrollment: EnrollmentResponse = {
  createdAtMs: 1_724_999_100_000,
  enrollmentId: "enr_existing",
  enrollmentToken: "enk_enroll_old",
  expiresAtMs: 1_725_000_000_000,
  expiredAtMs: null,
  hostId: null,
  hubUrl: "https://hub.example",
  installCommand: "curl old",
  installPath: "/usr/local/bin/enoki-probe",
  readyAtMs: null,
  rejectedAtMs: null,
  rejection: null,
  status: "pending",
  target: { kind: "new_host" },
  verificationDeadlineAtMs: null,
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

  it("keeps the command available only for the matching pending Enrollment", () => {
    const reconciled = reconcileEnrollmentStatus(
      existingEnrollment,
      pendingStatus(existingEnrollment.enrollmentId),
    );

    expect(reconciled).toEqual({
      enrollment: expect.objectContaining({
        installCommand: "curl old",
        status: "pending",
      }),
      shouldClose: false,
    });
    expect(
      reconcileEnrollmentStatus(
        existingEnrollment,
        pendingStatus("enr_another"),
      ),
    ).toEqual({
      enrollment: existingEnrollment,
      shouldClose: false,
    });
  });

  it("closes the matching dialog when authoritative status records expiry", () => {
    const reconciled = reconcileEnrollmentStatus(existingEnrollment, {
      ...pendingStatus(existingEnrollment.enrollmentId),
      expiredAtMs: existingEnrollment.expiresAtMs,
      status: "expired",
    });

    expect(reconciled).toEqual({
      enrollment: expect.objectContaining({
        expiredAtMs: existingEnrollment.expiresAtMs,
        status: "expired",
      }),
      shouldClose: true,
    });
  });
});

function pendingStatus(enrollmentId: string): EnrollmentStatusResponse {
  return {
    createdAtMs: 1_724_999_100_000,
    enrollmentId,
    expiresAtMs: 1_725_000_000_000,
    expiredAtMs: null,
    hostId: null,
    readyAtMs: null,
    rejectedAtMs: null,
    rejection: null,
    status: "pending",
    target: { kind: "new_host" },
    verificationDeadlineAtMs: null,
  };
}
