import { describe, expect, it } from "vitest";

import type { EnrollmentResponse, EnrollmentStatusResponse } from "../types";
import {
  enrollmentTerminalMessage,
  matchingHostAction,
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

  it("gives a clear, non-secret fallback when readiness is rejected without a typed reason", () => {
    expect(
      enrollmentTerminalMessage({
        ...pendingStatus(existingEnrollment.enrollmentId),
        rejectedAtMs: 1_725_000_060_000,
        status: "rejected",
      }),
    ).toEqual({
      description: "Probe 未在等待期限内完成与 Hub 的首次报告。",
      title: "Probe 未能就绪",
    });
  });

  it("guides a preflight installation rejection to local uninstall and offline re-enrollment", () => {
    expect(
      enrollmentTerminalMessage({
        ...pendingStatus(existingEnrollment.enrollmentId),
        rejection: {
          code: "probe_bound_to_different_hub",
          message: "untrusted local detail that must not be shown",
        },
        status: "rejected",
      }),
    ).toEqual({
      description:
        "此 Probe 已绑定到其他 Hub。请先在目标主机运行 sudo enoki-probe uninstall；即使旧 Hub 离线，也可随后重新生成安装命令。",
      title: "Probe 已绑定到其他 Hub",
    });
  });

  it("never renders an unknown rejection message supplied by a Probe", () => {
    expect(
      enrollmentTerminalMessage({
        ...pendingStatus(existingEnrollment.enrollmentId),
        rejection: { code: "unknown", message: "secret-like untrusted detail" },
        status: "rejected",
      }),
    ).toEqual({
      description: "Probe 未在等待期限内完成与 Hub 的首次报告。",
      title: "Probe 未能就绪",
    });
  });

  it("only offers recovery for one exact offline Host", () => {
    expect(
      matchingHostAction({
        hostId: 7,
        hosts: [{ id: 7, status: "offline" }],
      }),
    ).toBe(7);
    expect(
      matchingHostAction({
        hostId: 7,
        hosts: [{ id: 7, status: "online" }],
      }),
    ).toBeNull();
    expect(
      matchingHostAction({
        hostId: 7,
        hosts: [{ id: 7, status: "stale" }],
      }),
    ).toBeNull();
    expect(matchingHostAction({ hostId: 7, hosts: [] })).toBeNull();
    expect(
      matchingHostAction({
        hostId: 7,
        hosts: [
          { id: 7, status: "offline" },
          { id: 7, status: "offline" },
        ],
      }),
    ).toBeNull();
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
