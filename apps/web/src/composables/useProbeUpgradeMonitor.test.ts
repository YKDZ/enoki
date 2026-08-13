import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/api";

import { useProbeUpgradeMonitor } from "./useProbeUpgradeMonitor";

describe("Probe upgrade monitor", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps polling a tracked upgrade after the detail page changes", async () => {
    vi.useFakeTimers();
    const onHostDetail = vi.fn();
    const onTransition = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      async fetchJson<T>() {
        return {
          host: hostWithUpgradeState("succeeded"),
        } as T;
      },
      onHostDetail,
      onTransition,
      pollIntervalMs: 1_000,
    });

    monitor.track(1, {
      acceptedAtMs: 1,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      id: 9,
      runningAtMs: 2,
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
    expect(onTransition).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 1,
      }),
      expect.objectContaining({ state: "succeeded" }),
    );
  });

  it("does not repeat a terminal toast after the operation is resolved", async () => {
    vi.useFakeTimers();
    const onTransition = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      async fetchJson<T>() {
        return {
          host: hostWithUpgradeState("succeeded"),
        } as T;
      },
      onTransition,
      pollIntervalMs: 1_000,
    });

    monitor.track(1, {
      acceptedAtMs: 1,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      id: 9,
      runningAtMs: 2,
      state: "running",
      targetProbeVersion: "0.1.25",
      updatedAtMs: 2,
    });

    await vi.advanceTimersByTimeAsync(3_000);

    expect(onTransition).toHaveBeenCalledOnce();
  });

  it("reports a live canceled transition without trusting server failure detail", async () => {
    vi.useFakeTimers();
    const onTransition = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      async fetchJson<T>() {
        return {
          host: {
            ...hostWithUpgradeState("canceled"),
            probeUpgradeStatus: {
              acceptedAtMs: 1,
              completedAtMs: 3,
              createdAtMs: 1,
              failure: null,
              id: 9,
              runningAtMs: 2,
              state: "canceled",
              targetProbeVersion: "0.1.25",
              updatedAtMs: 3,
            },
          },
        } as T;
      },
      onTransition,
      pollIntervalMs: 1_000,
    });

    monitor.track(1, {
      acceptedAtMs: 1,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      id: 9,
      runningAtMs: 2,
      state: "running",
      targetProbeVersion: "0.1.25",
      updatedAtMs: 2,
    });

    await vi.advanceTimersByTimeAsync(1_000);

    expect(onTransition).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 1,
      }),
      expect.objectContaining({ state: "canceled" }),
    );
  });

  it("leaves a failed upgrade for its inline recovery surface without replaying a toast", async () => {
    vi.useFakeTimers();
    const onTransition = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      async fetchJson<T>() {
        return { host: hostWithUpgradeState("failed") } as T;
      },
      onTransition,
      pollIntervalMs: 1_000,
    });
    monitor.track(1, activeStatus(9));
    await vi.advanceTimersByTimeAsync(3_000);

    expect(onTransition).not.toHaveBeenCalled();
  });

  it("observes a superseded individually tracked operation after the Host projection advances", async () => {
    vi.useFakeTimers();
    const onTransition = vi.fn();
    const fetchJson = async <T>(path: string): Promise<T> => {
      if (path === "/api/web/hosts/1") {
        return {
          host: {
            ...hostWithUpgradeState("running"),
            probeUpgradeStatus: {
              ...hostWithUpgradeState("running").probeUpgradeStatus,
              id: 10,
            },
          },
        } as T;
      }
      expect(path).toBe("/api/web/probe-operations/9");
      return {
        probeOperation: {
          ...hostWithUpgradeState("superseded").probeUpgradeStatus,
          hostId: 1,
          kind: "probe_upgrade",
        },
      } as T;
    };
    const monitor = useProbeUpgradeMonitor({
      fetchJson,
      onTransition,
      pollIntervalMs: 1_000,
    });
    monitor.track(1, activeStatus(9));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(onTransition).toHaveBeenCalledWith(
      expect.objectContaining({ id: 1 }),
      expect.objectContaining({ id: 9, state: "superseded" }),
    );
  });

  it("keeps a replacement operation tracked when an older poll resolves after it", async () => {
    vi.useFakeTimers();
    let resolveFirstHost!: (response: unknown) => void;
    const firstHost = new Promise((resolve) => {
      resolveFirstHost = resolve;
    });
    const onTransition = vi.fn();
    let hostReads = 0;
    const fetchPaths: string[] = [];
    const fetchJson = async <T>(path: string): Promise<T> => {
      fetchPaths.push(path);
      if (path === "/api/web/hosts/1") {
        hostReads += 1;
        return (
          hostReads === 1
            ? await firstHost
            : {
                host: {
                  ...hostWithUpgradeState("succeeded"),
                  probeUpgradeStatus: {
                    ...hostWithUpgradeState("succeeded").probeUpgradeStatus,
                    id: 10,
                  },
                },
              }
        ) as T;
      }
      return {
        probeOperation: {
          ...hostWithUpgradeState("superseded").probeUpgradeStatus,
          hostId: 1,
          kind: "probe_upgrade",
        },
      } as T;
    };
    const monitor = useProbeUpgradeMonitor({
      fetchJson,
      onTransition,
      pollIntervalMs: 1_000,
    });
    monitor.track(1, activeStatus(9));
    await vi.advanceTimersByTimeAsync(1_000);
    monitor.track(1, activeStatus(10));
    resolveFirstHost({ host: hostWithUpgradeState("succeeded") });
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(1_000);

    expect(fetchPaths.at(-1)).toBe("/api/web/hosts/1");
    expect(onTransition).toHaveBeenCalledWith(
      expect.objectContaining({ id: 1 }),
      expect.objectContaining({ id: 10, state: "succeeded" }),
    );
  });

  it("does not report a late terminal result after clear invalidates its poll", async () => {
    vi.useFakeTimers();
    let resolveHost!: (response: unknown) => void;
    const pendingHost = new Promise((resolve) => {
      resolveHost = resolve;
    });
    const onTransition = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      fetchJson: async <T>(): Promise<T> => (await pendingHost) as T,
      onTransition,
      pollIntervalMs: 1_000,
    });
    monitor.track(1, activeStatus(9));
    await vi.advanceTimersByTimeAsync(1_000);
    monitor.clear();
    resolveHost({ host: hostWithUpgradeState("succeeded") });
    await vi.advanceTimersByTimeAsync(0);

    expect(onTransition).not.toHaveBeenCalled();
  });

  it("does not report a late superseded operation lookup after clear", async () => {
    vi.useFakeTimers();
    let resolveOperation!: (response: unknown) => void;
    const pendingOperation = new Promise((resolve) => {
      resolveOperation = resolve;
    });
    const onTransition = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      fetchJson: async <T>(path: string): Promise<T> =>
        (path === "/api/web/hosts/1"
          ? {
              host: {
                ...hostWithUpgradeState("running"),
                probeUpgradeStatus: {
                  ...hostWithUpgradeState("running").probeUpgradeStatus,
                  id: 10,
                },
              },
            }
          : await pendingOperation) as T,
      onTransition,
      pollIntervalMs: 1_000,
    });
    monitor.track(1, activeStatus(9));
    await vi.advanceTimersByTimeAsync(1_000);
    monitor.clear();
    resolveOperation({
      probeOperation: {
        ...hostWithUpgradeState("superseded").probeUpgradeStatus,
        hostId: 1,
        kind: "probe_upgrade",
      },
    });
    await vi.advanceTimersByTimeAsync(0);

    expect(onTransition).not.toHaveBeenCalled();
  });

  it("clears tracking and delegates authentication expiry from the old-operation lookup", async () => {
    vi.useFakeTimers();
    const onUnauthorized = vi.fn();
    const onTransition = vi.fn();
    const monitor = useProbeUpgradeMonitor({
      fetchJson: async <T>(path: string): Promise<T> => {
        if (path === "/api/web/hosts/1") {
          return {
            host: {
              ...hostWithUpgradeState("running"),
              probeUpgradeStatus: {
                ...hostWithUpgradeState("running").probeUpgradeStatus,
                id: 10,
              },
            },
          } as T;
        }
        throw new ApiError("Request failed: 401", 401);
      },
      onTransition,
      onUnauthorized,
      pollIntervalMs: 1_000,
    });
    monitor.track(1, activeStatus(9));
    await vi.advanceTimersByTimeAsync(1_000);
    await vi.advanceTimersByTimeAsync(2_000);

    expect(onUnauthorized).toHaveBeenCalledOnce();
    expect(onTransition).not.toHaveBeenCalled();
  });

  it("stops tracking when the old operation is no longer readable", async () => {
    vi.useFakeTimers();
    const onTransition = vi.fn();
    const fetchJson = vi.fn(async <T>(path: string): Promise<T> => {
      if (path === "/api/web/hosts/1") {
        return {
          host: {
            ...hostWithUpgradeState("running"),
            probeUpgradeStatus: {
              ...hostWithUpgradeState("running").probeUpgradeStatus,
              id: 10,
            },
          },
        } as T;
      }
      throw new ApiError("Request failed: 404", 404);
    });
    const monitor = useProbeUpgradeMonitor({
      fetchJson: fetchJson as <T>(path: string) => Promise<T>,
      onTransition,
      pollIntervalMs: 1_000,
    });
    monitor.track(1, activeStatus(9));
    await vi.advanceTimersByTimeAsync(3_000);

    expect(onTransition).not.toHaveBeenCalled();
    expect(fetchJson).toHaveBeenCalledTimes(2);
  });
});

function activeStatus(id: number) {
  return { ...hostWithUpgradeState("running").probeUpgradeStatus, id };
}

function hostWithUpgradeState(
  state: "canceled" | "failed" | "running" | "succeeded" | "superseded",
) {
  return {
    id: 1,
    probeUpgradeStatus: {
      acceptedAtMs: 1,
      completedAtMs: state === "running" ? null : 3,
      createdAtMs: 1,
      failure: null,
      id: 9,
      runningAtMs: 2,
      state,
      targetProbeVersion: "0.1.25",
      updatedAtMs: 3,
    },
  };
}
