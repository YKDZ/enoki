import { afterEach, describe, expect, it, vi } from "vitest";

import { useProbeUpgradeMonitor } from "./useProbeUpgradeMonitor";

describe("Probe upgrade monitor", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps polling a tracked upgrade after the detail page changes", async () => {
    vi.useFakeTimers();
    const onHostDetail = vi.fn();
    const onSuccess = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      async fetchJson<T>() {
        return {
          host: hostWithUpgradeState("succeeded"),
        } as T;
      },
      onFailure: vi.fn(),
      onHostDetail,
      onSuccess,
      pollIntervalMs: 1_000,
    });

    monitor.track(1, {
      createdAtMs: 1,
      failure: null,
      id: 9,
      state: "running",
      targetProbeVersion: "0.1.25",
      updatedAtMs: 2,
    });

    await vi.advanceTimersByTimeAsync(1_000);

    expect(onHostDetail).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 1,
        probeUpgradeStatus: expect.objectContaining({
          state: "succeeded",
        }),
      }),
    );
    expect(onSuccess).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 1,
      }),
    );
  });

  it("does not repeat a terminal toast after the operation is resolved", async () => {
    vi.useFakeTimers();
    const onSuccess = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      async fetchJson<T>() {
        return {
          host: hostWithUpgradeState("succeeded"),
        } as T;
      },
      onFailure: vi.fn(),
      onSuccess,
      pollIntervalMs: 1_000,
    });

    monitor.track(1, {
      createdAtMs: 1,
      failure: null,
      id: 9,
      state: "running",
      targetProbeVersion: "0.1.25",
      updatedAtMs: 2,
    });

    await vi.advanceTimersByTimeAsync(3_000);

    expect(onSuccess).toHaveBeenCalledOnce();
  });

  it("emits a failure toast with the server failure detail", async () => {
    vi.useFakeTimers();
    const onFailure = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      async fetchJson<T>() {
        return {
          host: {
            ...hostWithUpgradeState("failed"),
            probeUpgradeStatus: {
              createdAtMs: 1,
              failure: {
                code: "running_timeout",
                message: "升级超时。",
              },
              id: 9,
              state: "failed",
              targetProbeVersion: "0.1.25",
              updatedAtMs: 3,
            },
          },
        } as T;
      },
      onFailure,
      onSuccess: vi.fn(),
      pollIntervalMs: 1_000,
    });

    monitor.track(1, {
      createdAtMs: 1,
      failure: null,
      id: 9,
      state: "running",
      targetProbeVersion: "0.1.25",
      updatedAtMs: 2,
    });

    await vi.advanceTimersByTimeAsync(1_000);

    expect(onFailure).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 1,
      }),
      {
        code: "running_timeout",
        message: "升级超时。",
      },
    );
  });
});

function hostWithUpgradeState(state: "failed" | "running" | "succeeded") {
  return {
    id: 1,
    probeUpgradeStatus: {
      createdAtMs: 1,
      failure: null,
      id: 9,
      state,
      targetProbeVersion: "0.1.25",
      updatedAtMs: 3,
    },
  };
}
