import type { EnrollmentStatusResponse } from "../types";

const terminalEnrollmentStatuses = new Set<EnrollmentStatusResponse["status"]>([
  "expired",
  "ready",
  "rejected",
]);

type ReconciliationStage = {
  attempts: number;
  deadlineAtMs: number;
  deadlineAttempted: boolean;
  deadlineRead: boolean;
  enrollmentId: string;
  postDeadlineAttempts: number;
  status: "pending" | "verifying";
};

export type EnrollmentStatusReconciler = {
  isRunning: () => boolean;
  reconcileNow: () => Promise<void>;
  start: () => void;
  stop: () => void;
};

export function createEnrollmentStatusReconciler(options: {
  getActiveEnrollment: () => EnrollmentStatusResponse | null;
  getActiveEnrollmentId: () => string | null;
  initialDelayMs?: number;
  isActiveEnrollment: (enrollmentId: string) => boolean;
  maxAttempts?: number;
  maxDelayMs?: number;
  now?: () => number;
  onStatus: (status: EnrollmentStatusResponse) => void;
  onTemporaryFailure?: (error: unknown) => void;
  readStatus: (enrollmentId: string) => Promise<EnrollmentStatusResponse>;
}): EnrollmentStatusReconciler {
  const initialDelayMs = options.initialDelayMs ?? 1_000;
  const maxAttempts = options.maxAttempts ?? 8;
  const maxPostDeadlineAttempts = Math.max(1, maxAttempts);
  const maxDelayMs = options.maxDelayMs ?? 15_000;
  const now = options.now ?? Date.now;
  let generation = 0;
  const inFlight = new Map<string, Promise<void>>();
  let running = false;
  let stage: ReconciliationStage | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;

  function activeEnrollment() {
    const enrollment = options.getActiveEnrollment();
    return enrollment?.enrollmentId === options.getActiveEnrollmentId()
      ? enrollment
      : null;
  }

  function isApplicable(enrollmentId: string, attemptGeneration: number) {
    return (
      generation === attemptGeneration &&
      options.getActiveEnrollmentId() === enrollmentId &&
      options.isActiveEnrollment(enrollmentId)
    );
  }

  function isCurrent(enrollmentId: string, attemptGeneration: number) {
    return running && isApplicable(enrollmentId, attemptGeneration);
  }

  function clearTimer() {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
  }

  function finishBackgroundReconciliation() {
    running = false;
    clearTimer();
  }

  function stop() {
    generation += 1;
    stage = null;
    finishBackgroundReconciliation();
  }

  function stageFor(
    status: EnrollmentStatusResponse,
    resetAttempts = false,
  ): ReconciliationStage | null {
    const deadlineAtMs =
      status.status === "pending"
        ? status.expiresAtMs
        : status.status === "verifying"
          ? status.verificationDeadlineAtMs
          : null;
    if (
      deadlineAtMs === null ||
      !Number.isFinite(deadlineAtMs) ||
      deadlineAtMs <= 0 ||
      (status.status !== "pending" && status.status !== "verifying")
    ) {
      return null;
    }

    if (
      !resetAttempts &&
      stage?.enrollmentId === status.enrollmentId &&
      stage.status === status.status &&
      stage.deadlineAtMs === deadlineAtMs
    ) {
      return stage;
    }

    return {
      attempts: 0,
      deadlineAtMs,
      deadlineAttempted: false,
      deadlineRead: false,
      enrollmentId: status.enrollmentId,
      postDeadlineAttempts: 0,
      status: status.status,
    };
  }

  function installStage(
    status: EnrollmentStatusResponse | null,
    resetAttempts = false,
  ) {
    stage = status ? stageFor(status, resetAttempts) : null;
  }

  function schedule(delayMs: number) {
    timer = setTimeout(
      () => {
        timer = null;
        void reconcileNow();
      },
      Math.max(0, delayMs),
    );
  }

  function retryDelayMs(attempts: number) {
    return Math.min(
      initialDelayMs * 2 ** Math.max(0, attempts - 1),
      maxDelayMs,
    );
  }

  function scheduleNext() {
    if (!running) {
      return;
    }

    const enrollmentId = options.getActiveEnrollmentId();
    if (!enrollmentId || !options.isActiveEnrollment(enrollmentId)) {
      stop();
      return;
    }

    if (stage?.enrollmentId !== enrollmentId) {
      installStage(activeEnrollment());
    }

    if (!stage) {
      finishBackgroundReconciliation();
      return;
    }

    const remainingMs = stage.deadlineAtMs - now();
    if (remainingMs <= 0) {
      if (!stage.deadlineAttempted) {
        schedule(0);
        return;
      }

      if (!stage.deadlineRead && stage.postDeadlineAttempts === 0) {
        schedule(retryDelayMs(1));
        return;
      }

      if (stage.postDeadlineAttempts >= maxPostDeadlineAttempts) {
        finishBackgroundReconciliation();
        return;
      }

      schedule(retryDelayMs(stage.postDeadlineAttempts + 1));
      return;
    }

    if (stage.attempts >= maxAttempts) {
      schedule(remainingMs);
      return;
    }

    schedule(Math.min(retryDelayMs(stage.attempts + 1), remainingMs));
  }

  async function reconcileNow() {
    clearTimer();
    const enrollmentId = options.getActiveEnrollmentId();
    if (!enrollmentId || !options.isActiveEnrollment(enrollmentId)) {
      if (running) {
        stop();
      }
      return;
    }

    const attemptGeneration = generation;
    const key = `${attemptGeneration}:${enrollmentId}`;
    const existingAttempt = inFlight.get(key);
    if (existingAttempt) {
      return existingAttempt;
    }

    const backgroundAttempt = running;
    if (backgroundAttempt && stage?.enrollmentId !== enrollmentId) {
      installStage(activeEnrollment());
    }
    const stageAtAttempt = backgroundAttempt ? stage : null;
    const attemptAtOrAfterDeadline =
      stageAtAttempt !== null && now() >= stageAtAttempt.deadlineAtMs;
    if (stageAtAttempt) {
      if (attemptAtOrAfterDeadline) {
        if (stageAtAttempt.deadlineAttempted) {
          stageAtAttempt.postDeadlineAttempts += 1;
        } else {
          stageAtAttempt.deadlineAttempted = true;
        }
      } else {
        stageAtAttempt.attempts += 1;
      }
    }

    const attempt = (async () => {
      try {
        const status = await options.readStatus(enrollmentId);
        if (!isApplicable(enrollmentId, attemptGeneration)) {
          return;
        }

        if (attemptAtOrAfterDeadline && stageAtAttempt) {
          stageAtAttempt.deadlineRead = true;
        }
        options.onStatus(status);
        if (terminalEnrollmentStatuses.has(status.status)) {
          finishBackgroundReconciliation();
          return;
        }

        if (backgroundAttempt && isCurrent(enrollmentId, attemptGeneration)) {
          installStage(status);
        } else if (
          !backgroundAttempt &&
          isApplicable(enrollmentId, attemptGeneration)
        ) {
          installStage(status, true);
          running = stage !== null;
          scheduleNext();
        }
      } catch (error) {
        if (!isApplicable(enrollmentId, attemptGeneration)) {
          return;
        }

        options.onTemporaryFailure?.(error);
      }

      if (backgroundAttempt && isCurrent(enrollmentId, attemptGeneration)) {
        scheduleNext();
      }
    })();
    inFlight.set(key, attempt);

    try {
      await attempt;
    } finally {
      if (inFlight.get(key) === attempt) {
        inFlight.delete(key);
      }
    }
  }

  function start() {
    stop();
    const enrollment = activeEnrollment();
    if (
      !enrollment ||
      !options.isActiveEnrollment(enrollment.enrollmentId) ||
      terminalEnrollmentStatuses.has(enrollment.status)
    ) {
      return;
    }

    installStage(enrollment);
    running = stage !== null;
    scheduleNext();
  }

  return {
    isRunning: () => running,
    reconcileNow,
    start,
    stop,
  };
}
