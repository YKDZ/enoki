import { describe, expect, it } from "vitest";

import { enrollmentStatusResponse } from "../src/enrollment/lifecycle";

const validPending = {
  createdAtMs: 1_725_000_000_000,
  enrollmentId: "enr_1234567890abcdef",
  expiredAtMs: null,
  expiresAtMs: 1_725_000_900_000,
  hostId: null,
  readyAtMs: null,
  rejectedAtMs: null,
  rejectionCode: null,
  rejectionMessage: null,
  status: "pending",
  targetHostId: null,
  targetKind: "new_host",
  usedAtMs: null,
  verificationDeadlineAtMs: null,
} as const;

describe("Enrollment lifecycle boundary", () => {
  it("formats only closed Target and Status values for Owner responses", () => {
    expect(enrollmentStatusResponse(validPending)).toEqual({
      createdAtMs: validPending.createdAtMs,
      enrollmentId: validPending.enrollmentId,
      expiredAtMs: null,
      expiresAtMs: validPending.expiresAtMs,
      hostId: null,
      readyAtMs: null,
      rejectedAtMs: null,
      rejection: null,
      status: "pending",
      target: { kind: "new_host" },
      verificationDeadlineAtMs: null,
    });
    expect(
      enrollmentStatusResponse({
        ...validPending,
        status: "not_a_lifecycle_status",
      }),
    ).toBeNull();
    expect(
      enrollmentStatusResponse({
        ...validPending,
        targetKind: "all_hosts",
      }),
    ).toBeNull();
  });

  it("fails closed for unbounded rejection data but retains unknown bounded rejection codes", () => {
    expect(
      enrollmentStatusResponse({
        ...validPending,
        rejectedAtMs: 1_725_000_001_000,
        rejectionCode: "installer_unknown_but_stable",
        rejectionMessage: "A concise safe explanation.",
        status: "rejected",
      }),
    ).toEqual(
      expect.objectContaining({
        rejection: {
          code: "installer_unknown_but_stable",
          message: "A concise safe explanation.",
        },
        status: "rejected",
      }),
    );
    expect(
      enrollmentStatusResponse({
        ...validPending,
        rejectedAtMs: 1_725_000_001_000,
        rejectionCode: "x".repeat(65),
        rejectionMessage: "safe",
        status: "rejected",
      }),
    ).toBeNull();
    expect(
      enrollmentStatusResponse({
        ...validPending,
        rejectionMessage: "orphaned message",
      }),
    ).toBeNull();
  });
});
