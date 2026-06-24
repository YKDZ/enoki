export const probeCollectorIds = [
  "official.cpu",
  "official.memory",
  "official.disk",
  "official.network",
  "official.load",
  "official.uptime",
  "official.temperature",
  "official.battery",
  "official.disk-health",
] as const;

export type ProbeCollectorId = (typeof probeCollectorIds)[number];

const probeCollectorIdSet = new Set<string>(probeCollectorIds);

export const defaultEnabledCollectorIds: ProbeCollectorId[] = [
  ...probeCollectorIds,
];

export function isProbeCollectorId(
  collectorId: string,
): collectorId is ProbeCollectorId {
  return probeCollectorIdSet.has(collectorId);
}

export function normalizeEnabledCollectorIds(
  enabledCollectorIds: readonly string[],
): ProbeCollectorId[] {
  const enabled = new Set(enabledCollectorIds);

  return probeCollectorIds.filter((collectorId) => enabled.has(collectorId));
}
