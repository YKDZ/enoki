import { onScopeDispose } from "vue";

import { apiGet, isUnauthorizedError } from "@/lib/api";
import type { HostDetail, HostDetailResponse } from "@/types";

type FetchJson = <T>(path: string) => Promise<T>;
type ProbeUpgradeStatus = NonNullable<HostDetail["probeUpgradeStatus"]>;
type ProbeUpgradeTerminalTransition = ProbeUpgradeStatus & {
  state: "canceled" | "succeeded" | "superseded";
};
type ProbeOperationResponse = {
  probeOperation: ProbeUpgradeStatus & { hostId: number; kind: string };
};

const activeProbeUpgradeStates = new Set(["pending", "accepted", "running"]);

export function useProbeUpgradeMonitor(options: {
  fetchJson?: FetchJson;
  onHostDetail?: (host: HostDetail) => void;
  onTransition: (
    host: HostDetail,
    status: ProbeUpgradeTerminalTransition,
  ) => void;
  onUnauthorized?: () => void;
  pollIntervalMs?: number;
}) {
  const fetchJson = options.fetchJson ?? apiGet;
  const pollIntervalMs = options.pollIntervalMs ?? 1_000;
  const trackedOperations = new Map<number, TrackedOperation>();
  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  let isPolling = false;

  onScopeDispose(() => {
    clear();
  }, true);

  function track(hostId: number, status: HostDetail["probeUpgradeStatus"]) {
    if (!status || !activeProbeUpgradeStates.has(status.state)) {
      return;
    }

    trackedOperations.set(hostId, { status });
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
      for (const [hostId, tracked] of entries) {
        await pollHost(hostId, tracked);
      }
    } finally {
      isPolling = false;
      schedulePoll();
    }
  }

  async function pollHost(hostId: number, tracked: TrackedOperation) {
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

    if (!isCurrent(hostId, tracked)) return;

    options.onHostDetail?.(response.host);

    const status = response.host.probeUpgradeStatus;
    if (!status || status.id !== tracked.status.id) {
      await resolveReplacedOperation(hostId, tracked, response.host);
      return;
    }

    if (isTerminalTransition(status)) {
      if (!isCurrent(hostId, tracked)) return;
      trackedOperations.delete(hostId);
      options.onTransition(response.host, status);
      return;
    }

    if (!activeProbeUpgradeStates.has(status.state)) {
      if (isCurrent(hostId, tracked)) trackedOperations.delete(hostId);
      return;
    }

    if (isCurrent(hostId, tracked)) trackedOperations.set(hostId, { status });
  }

  async function resolveReplacedOperation(
    hostId: number,
    tracked: TrackedOperation,
    host: HostDetail,
  ) {
    try {
      const response = await fetchJson<ProbeOperationResponse>(
        `/api/web/probe-operations/${tracked.status.id}`,
      );
      const operation = response.probeOperation;
      if (
        isCurrent(hostId, tracked) &&
        operation.hostId === hostId &&
        isTerminalTransition(operation)
      ) {
        trackedOperations.delete(hostId);
        options.onTransition(host, operation);
      }
    } catch (caught) {
      if (isUnauthorizedError(caught)) {
        clear();
        options.onUnauthorized?.();
        return;
      }
    }
    if (isCurrent(hostId, tracked)) trackedOperations.delete(hostId);
  }

  function isCurrent(hostId: number, tracked: TrackedOperation) {
    return trackedOperations.get(hostId) === tracked;
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

type TrackedOperation = { status: ProbeUpgradeStatus };

function isTerminalTransition(
  status: ProbeUpgradeStatus,
): status is ProbeUpgradeTerminalTransition {
  return ["canceled", "succeeded", "superseded"].includes(status.state);
}
