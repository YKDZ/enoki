import type { HostDetail } from "../types";

type ProbeUpgradeStatus = HostDetail["probeUpgradeStatus"];

const activeProbeUpgradeStates = new Set(["pending", "accepted", "running"]);

export function shouldToastProbeUpgradeFailure(
  status: ProbeUpgradeStatus,
  previousStatus: ProbeUpgradeStatus,
) {
  if (status?.state !== "failed" || !status.failure) {
    return false;
  }

  if (!previousStatus || status.id !== previousStatus.id) {
    return false;
  }

  return activeProbeUpgradeStates.has(previousStatus.state);
}

export function shouldToastProbeUpgradeSuccess(
  status: ProbeUpgradeStatus,
  previousStatus: ProbeUpgradeStatus,
) {
  if (status?.state !== "succeeded") {
    return false;
  }

  if (!previousStatus || status.id !== previousStatus.id) {
    return false;
  }

  return activeProbeUpgradeStates.has(previousStatus.state);
}
