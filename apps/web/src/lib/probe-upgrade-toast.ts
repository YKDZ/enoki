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

  if (status.id !== previousStatus?.id) {
    return true;
  }

  return Boolean(
    previousStatus && activeProbeUpgradeStates.has(previousStatus.state),
  );
}
