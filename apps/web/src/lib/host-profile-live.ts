import type { HostProfileSnapshot, HostSummary } from "@/types";

import { formatBytes } from "./format";

type HostProfileBackedFields = Pick<
  HostSummary,
  | "collectorCapabilities"
  | "cpu"
  | "cpuModel"
  | "memory"
  | "probeVersion"
  | "system"
>;

export function hostProfileBackedFields(
  hostProfile: HostProfileSnapshot,
): HostProfileBackedFields {
  return {
    collectorCapabilities: hostProfile.collectorCapabilities ?? null,
    cpu: `${hostProfile.cpuCount} cores`,
    cpuModel: hostProfile.cpuModel ?? null,
    memory: formatBytes(hostProfile.memoryTotalBytes),
    probeVersion: hostProfile.probeVersion || "n/a",
    system: [hostProfile.os, hostProfile.kernel, hostProfile.architecture]
      .filter((part) => part.trim())
      .join(" "),
  };
}
