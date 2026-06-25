import { afterEach, describe, expect, it, vi } from "vitest";

import { createMetricsArchiveScheduler } from "../src/metrics-archive/scheduler";

describe("Metrics Archive scheduler", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("starts archive maintenance and stops scheduling on shutdown", async () => {
    vi.useFakeTimers();
    const maintain = vi.fn();
    const scheduler = createMetricsArchiveScheduler({
      intervalMs: 1_000,
      maintain,
    });

    scheduler.start();
    await vi.runOnlyPendingTimersAsync();

    expect(maintain).toHaveBeenCalledTimes(1);

    await scheduler.stop();
    await vi.advanceTimersByTimeAsync(3_000);

    expect(maintain).toHaveBeenCalledTimes(1);
  });

  it("continues future archive maintenance attempts after a runtime failure", async () => {
    vi.useFakeTimers();
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    const maintain = vi
      .fn()
      .mockRejectedValueOnce(new Error("archive path is temporarily full"))
      .mockResolvedValue(undefined);
    const scheduler = createMetricsArchiveScheduler({
      intervalMs: 1_000,
      maintain,
    });

    scheduler.start();
    await vi.advanceTimersByTimeAsync(1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    await scheduler.stop();

    expect(maintain).toHaveBeenCalledTimes(2);
    expect(consoleError).toHaveBeenCalledWith(
      "Metrics Archive maintenance failed.",
      expect.any(Error),
    );

    consoleError.mockRestore();
  });

  it("waits for in-flight archive maintenance during shutdown", async () => {
    vi.useFakeTimers();
    let finishMaintenance!: () => void;
    let stopped = false;
    const maintain = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finishMaintenance = resolve;
        }),
    );
    const scheduler = createMetricsArchiveScheduler({
      intervalMs: 1_000,
      maintain,
    });

    scheduler.start();
    await vi.advanceTimersByTimeAsync(1_000);

    const stopPromise = scheduler.stop().then(() => {
      stopped = true;
    });
    await Promise.resolve();

    expect(stopped).toBe(false);

    finishMaintenance();
    await stopPromise;

    expect(stopped).toBe(true);
    expect(maintain).toHaveBeenCalledTimes(1);
  });
});
