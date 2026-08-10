import { describe, expect, it, vi } from "vitest";

import type { EnrollmentStatusResponse } from "../types";
import { createEnrollmentStatusReconciler } from "./enrollment-status-reconciliation";

const enrollmentId = "enr_reconciliation";

describe("active Enrollment status reconciliation", () => {
  it("reconciles pending and verifying states with bounded backoff until a terminal status", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const statuses: EnrollmentStatusResponse[] = [
      status("pending", { expiresAtMs: 1_000 }),
      status("verifying", {
        expiresAtMs: 1_000,
        verificationDeadlineAtMs: 100,
      }),
      status("expired", { expiresAtMs: 1_000 }),
    ];
    const received: string[] = [];
    const readStatus = vi.fn(async () => statuses.shift() ?? status("expired"));
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () => status("pending", { expiresAtMs: 1_000 }),
      getActiveEnrollmentId: () => enrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => id === enrollmentId,
      maxAttempts: 4,
      maxDelayMs: 40,
      onStatus: (nextStatus) => received.push(nextStatus.status),
      readStatus,
    });

    reconciler.start();
    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(20);
    await vi.advanceTimersByTimeAsync(10);

    expect(readStatus).toHaveBeenCalledTimes(3);
    expect(received).toEqual(["pending", "verifying", "expired"]);
    expect(reconciler.isRunning()).toBe(false);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(readStatus).toHaveBeenCalledTimes(3);
  });

  it("uses bounded backoff for temporary failures before one expiry-boundary status read", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    let active = true;
    const onTemporaryFailure = vi.fn();
    const readStatus = vi
      .fn<() => Promise<EnrollmentStatusResponse>>()
      .mockRejectedValueOnce(new Error("Hub unavailable"))
      .mockRejectedValueOnce(new Error("Hub unavailable"))
      .mockResolvedValueOnce(status("expired", { expiresAtMs: 35 }));
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () => status("pending", { expiresAtMs: 35 }),
      getActiveEnrollmentId: () => enrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => active && id === enrollmentId,
      maxAttempts: 2,
      maxDelayMs: 40,
      onStatus() {},
      onTemporaryFailure,
      readStatus,
    });

    reconciler.start();
    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(20);

    expect(readStatus).toHaveBeenCalledTimes(2);
    expect(onTemporaryFailure).toHaveBeenCalledTimes(2);
    expect(reconciler.isRunning()).toBe(true);

    await vi.advanceTimersByTimeAsync(5);

    expect(readStatus).toHaveBeenCalledTimes(3);
    expect(reconciler.isRunning()).toBe(false);

    active = false;
    reconciler.start();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(readStatus).toHaveBeenCalledTimes(3);
  });

  it("reads pending Enrollment status again at the authoritative expiry boundary after its early retry budget is spent", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const readStatus = vi
      .fn<() => Promise<EnrollmentStatusResponse>>()
      .mockResolvedValueOnce(status("pending", { expiresAtMs: 100 }))
      .mockResolvedValueOnce(status("expired", { expiresAtMs: 100 }));
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () => status("pending", { expiresAtMs: 100 }),
      getActiveEnrollmentId: () => enrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => id === enrollmentId,
      maxAttempts: 1,
      maxDelayMs: 40,
      onStatus() {},
      readStatus,
    });

    reconciler.start();
    await vi.advanceTimersByTimeAsync(10);

    expect(readStatus).toHaveBeenCalledTimes(1);
    expect(reconciler.isRunning()).toBe(true);

    await vi.advanceTimersByTimeAsync(90);

    expect(readStatus).toHaveBeenCalledTimes(2);
    expect(reconciler.isRunning()).toBe(false);
  });

  it("reads verifying Enrollment status at the verification deadline supplied by the Hub", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const readStatus = vi.fn(async () =>
      status("rejected", {
        verificationDeadlineAtMs: 100,
      }),
    );
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () =>
        status("verifying", { verificationDeadlineAtMs: 100 }),
      getActiveEnrollmentId: () => enrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => id === enrollmentId,
      maxAttempts: 0,
      maxDelayMs: 40,
      onStatus() {},
      readStatus,
    });

    reconciler.start();
    await vi.advanceTimersByTimeAsync(99);

    expect(readStatus).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);

    expect(readStatus).toHaveBeenCalledTimes(1);
    expect(reconciler.isRunning()).toBe(false);
  });

  it("retries a failed authoritative deadline read before stopping reconciliation", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const onTemporaryFailure = vi.fn();
    const readStatus = vi
      .fn<() => Promise<EnrollmentStatusResponse>>()
      .mockRejectedValueOnce(new Error("Hub unavailable"))
      .mockResolvedValueOnce(status("expired", { expiresAtMs: 100 }));
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () => status("pending", { expiresAtMs: 100 }),
      getActiveEnrollmentId: () => enrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => id === enrollmentId,
      maxAttempts: 0,
      maxDelayMs: 40,
      onStatus() {},
      onTemporaryFailure,
      readStatus,
    });

    reconciler.start();
    await vi.advanceTimersByTimeAsync(100);

    expect(readStatus).toHaveBeenCalledTimes(1);
    expect(onTemporaryFailure).toHaveBeenCalledTimes(1);
    expect(reconciler.isRunning()).toBe(true);

    await vi.advanceTimersByTimeAsync(10);

    expect(readStatus).toHaveBeenCalledTimes(2);
    expect(reconciler.isRunning()).toBe(false);
  });

  it("retries when the Hub still authoritatively reports verifying at the local deadline", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const received: string[] = [];
    const readStatus = vi
      .fn<() => Promise<EnrollmentStatusResponse>>()
      .mockResolvedValueOnce(
        status("verifying", { verificationDeadlineAtMs: 100 }),
      )
      .mockResolvedValueOnce(
        status("rejected", { verificationDeadlineAtMs: 100 }),
      );
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () =>
        status("verifying", { verificationDeadlineAtMs: 100 }),
      getActiveEnrollmentId: () => enrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => id === enrollmentId,
      maxAttempts: 0,
      maxDelayMs: 40,
      onStatus: (nextStatus) => received.push(nextStatus.status),
      readStatus,
    });

    reconciler.start();
    await vi.advanceTimersByTimeAsync(100);

    expect(readStatus).toHaveBeenCalledTimes(1);
    expect(received).toEqual(["verifying"]);
    expect(reconciler.isRunning()).toBe(true);

    await vi.advanceTimersByTimeAsync(10);

    expect(readStatus).toHaveBeenCalledTimes(2);
    expect(received).toEqual(["verifying", "rejected"]);
    expect(reconciler.isRunning()).toBe(false);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(readStatus).toHaveBeenCalledTimes(2);
  });

  it("resumes bounded reconciliation when a force read finds an active Enrollment after stopping", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    let activeEnrollment = status("pending", { expiresAtMs: 100 });
    const readStatus = vi
      .fn<() => Promise<EnrollmentStatusResponse>>()
      .mockResolvedValueOnce(status("pending", { expiresAtMs: 100 }))
      .mockResolvedValueOnce(status("pending", { expiresAtMs: 100 }))
      .mockResolvedValueOnce(status("pending", { expiresAtMs: 200 }))
      .mockResolvedValueOnce(status("expired", { expiresAtMs: 200 }));
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () => activeEnrollment,
      getActiveEnrollmentId: () => enrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => id === enrollmentId,
      maxAttempts: 0,
      maxDelayMs: 40,
      onStatus: (nextStatus) => {
        activeEnrollment = nextStatus;
      },
      readStatus,
    });

    reconciler.start();
    await vi.advanceTimersByTimeAsync(110);

    expect(readStatus).toHaveBeenCalledTimes(2);
    expect(reconciler.isRunning()).toBe(false);

    await reconciler.reconcileNow();

    expect(readStatus).toHaveBeenCalledTimes(3);
    expect(reconciler.isRunning()).toBe(true);

    await vi.advanceTimersByTimeAsync(89);

    expect(readStatus).toHaveBeenCalledTimes(3);
    expect(reconciler.isRunning()).toBe(true);

    await vi.advanceTimersByTimeAsync(1);

    expect(readStatus).toHaveBeenCalledTimes(4);
    expect(reconciler.isRunning()).toBe(false);
  });

  it("performs reconnect recovery even after the background phase has stopped", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const received: string[] = [];
    const readStatus = vi
      .fn<() => Promise<EnrollmentStatusResponse>>()
      .mockResolvedValueOnce(status("pending", { expiresAtMs: 100 }))
      .mockRejectedValueOnce(new Error("Hub unavailable"))
      .mockResolvedValueOnce(status("pending", { expiresAtMs: 100 }))
      .mockResolvedValueOnce(status("expired", { expiresAtMs: 100 }));
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () => status("pending", { expiresAtMs: 100 }),
      getActiveEnrollmentId: () => enrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => id === enrollmentId,
      maxAttempts: 1,
      maxDelayMs: 40,
      onStatus: (nextStatus) => received.push(nextStatus.status),
      readStatus,
    });

    reconciler.start();
    await vi.advanceTimersByTimeAsync(100);
    await vi.advanceTimersByTimeAsync(10);

    expect(readStatus).toHaveBeenCalledTimes(3);
    expect(reconciler.isRunning()).toBe(false);

    await reconciler.reconcileNow();

    expect(readStatus).toHaveBeenCalledTimes(4);
    expect(received).toEqual(["pending", "pending", "expired"]);
  });

  it("does not let an old Enrollment request in flight swallow the new generation's first read", async () => {
    const firstEnrollmentId = "enr_first_generation";
    const secondEnrollmentId = "enr_second_generation";
    let activeEnrollmentId = firstEnrollmentId;
    let resolveFirstRead!: (status: EnrollmentStatusResponse) => void;
    const firstRead = new Promise<EnrollmentStatusResponse>((resolve) => {
      resolveFirstRead = resolve;
    });
    const received: string[] = [];
    const readStatus = vi.fn((id: string) =>
      id === firstEnrollmentId
        ? firstRead
        : Promise.resolve(
            status("pending", {
              enrollmentId: secondEnrollmentId,
              expiresAtMs: 1_000,
            }),
          ),
    );
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () =>
        status("pending", {
          enrollmentId: activeEnrollmentId,
          expiresAtMs: 1_000,
        }),
      getActiveEnrollmentId: () => activeEnrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => id === activeEnrollmentId,
      maxAttempts: 1,
      maxDelayMs: 40,
      onStatus: (nextStatus) => received.push(nextStatus.enrollmentId),
      readStatus,
    });

    reconciler.start();
    const oldGenerationRead = reconciler.reconcileNow();

    expect(readStatus).toHaveBeenCalledWith(firstEnrollmentId);

    reconciler.stop();
    activeEnrollmentId = secondEnrollmentId;
    reconciler.start();
    await reconciler.reconcileNow();

    expect(readStatus).toHaveBeenNthCalledWith(2, secondEnrollmentId);

    resolveFirstRead(
      status("expired", {
        enrollmentId: firstEnrollmentId,
        expiresAtMs: 1_000,
      }),
    );
    await oldGenerationRead;

    expect(received).toEqual([secondEnrollmentId]);
    reconciler.stop();
  });

  it("cancels a scheduled reconciliation when the dialog closes", async () => {
    vi.useFakeTimers();
    const readStatus = vi.fn(async () => status("pending"));
    const reconciler = createEnrollmentStatusReconciler({
      getActiveEnrollment: () => status("pending"),
      getActiveEnrollmentId: () => enrollmentId,
      initialDelayMs: 10,
      isActiveEnrollment: (id) => id === enrollmentId,
      maxAttempts: 4,
      maxDelayMs: 40,
      onStatus() {},
      readStatus,
    });

    reconciler.start();
    reconciler.stop();
    await vi.advanceTimersByTimeAsync(1_000);

    expect(readStatus).not.toHaveBeenCalled();
    expect(reconciler.isRunning()).toBe(false);
  });
});

function status(
  state: EnrollmentStatusResponse["status"],
  overrides: Partial<EnrollmentStatusResponse> = {},
): EnrollmentStatusResponse {
  return {
    createdAtMs: 1_725_000_000_000,
    enrollmentId,
    expiresAtMs: 1_725_000_900_000,
    expiredAtMs: state === "expired" ? 1_725_000_900_000 : null,
    hostId: null,
    readyAtMs: null,
    rejectedAtMs: null,
    rejection: null,
    status: state,
    target: { kind: "new_host" },
    verificationDeadlineAtMs: null,
    ...overrides,
  };
}
