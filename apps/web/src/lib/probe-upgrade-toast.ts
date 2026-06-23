import type { HostDetail } from "../types";

type ProbeUpgradeStatus = HostDetail["probeUpgradeStatus"];
type ProbeUpgradeToastState = "failed" | "succeeded";

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

export function probeUpgradeToastTitle(
  host: HostDetail,
  state: ProbeUpgradeToastState,
) {
  const hostName = probeUpgradeHostName(host);
  const actionText = state === "succeeded" ? "完成" : "失败";

  return hostName
    ? `${hostName} 探针升级${actionText}`
    : `探针升级${actionText}`;
}

function probeUpgradeHostName(host: HostDetail) {
  const displayName = host.displayName.trim();
  if (displayName) {
    return displayName;
  }

  const inventoryHostname = host.inventory?.hostname;
  return typeof inventoryHostname === "string" && inventoryHostname.trim()
    ? inventoryHostname.trim()
    : "";
}
