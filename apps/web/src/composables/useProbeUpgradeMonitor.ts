import { onScopeDispose } from "vue";

import { apiGet, isUnauthorizedError } from "@/lib/api";
import type { HostDetail, HostDetailResponse } from "@/types";

type FetchJson = <T>(path: string) => Promise<T>;
type ProbeUpgradeStatus = NonNullable<HostDetail["probeUpgradeStatus"]>;

const activeProbeUpgradeStates = new Set(["pending", "accepted", "running"]);

export function useProbeUpgradeMonitor(options: {
  fetchJson?: FetchJson;
  onFailure: (failure: { code: string; message: string }) => void;
  onHostDetail?: (host: HostDetail) => void;
  onSuccess: () => void;
  onUnauthorized?: () => void;
  pollIntervalMs?: number;
}) {
  const fetchJson = options.fetchJson ?? apiGet;
  const pollIntervalMs = options.pollIntervalMs ?? 1_000;
  const trackedOperations = new Map<number, ProbeUpgradeStatus>();
  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  let isPolling = false;

  onScopeDispose(() => {
    clearPollTimer();
  }, true);

  function track(hostId: number, status: HostDetail["probeUpgradeStatus"]) {
    if (!status || !activeProbeUpgradeStates.has(status.state)) {
      return;
    }

    trackedOperations.set(hostId, status);
    schedulePoll();
  }

  function schedulePoll() {
    if (pollTimer !== null || trackedOperations.size === 0) {
      return;
    }

    pollTimer = setTimeout(() => {
      pollTimer = null;
      void poll();
    }, pollIntervalMs);
  }

  async function poll() {
    if (isPolling || trackedOperations.size === 0) {
      schedulePoll();
      return;
    }

    isPolling = true;

    try {
      const entries = [...trackedOperations.entries()];
      for (const [hostId, previousStatus] of entries) {
        await pollHost(hostId, previousStatus);
      }
    } finally {
      isPolling = false;
      schedulePoll();
    }
  }

  async function pollHost(hostId: number, previousStatus: ProbeUpgradeStatus) {
    let response: HostDetailResponse;
    try {
      response = await fetchJson<HostDetailResponse>(
        `/api/web/hosts/${hostId}`,
      );
    } catch (caught) {
      if (isUnauthorizedError(caught)) {
        clear();
        options.onUnauthorized?.();
      }
      return;
    }

    options.onHostDetail?.(response.host);

    const status = response.host.probeUpgradeStatus;
    if (!status || status.id !== previousStatus.id) {
      trackedOperations.delete(hostId);
      return;
    }

    if (status.state === "succeeded") {
      trackedOperations.delete(hostId);
      options.onSuccess();
      return;
    }

    if (status.state === "failed" && status.failure) {
      trackedOperations.delete(hostId);
      options.onFailure(status.failure);
      return;
    }

    if (!activeProbeUpgradeStates.has(status.state)) {
      trackedOperations.delete(hostId);
      return;
    }

    trackedOperations.set(hostId, status);
  }

  function clear() {
    trackedOperations.clear();
    clearPollTimer();
  }

  function clearPollTimer() {
    if (pollTimer === null) {
      return;
    }

    clearTimeout(pollTimer);
    pollTimer = null;
  }

  return {
    clear,
    track,
  };
}
