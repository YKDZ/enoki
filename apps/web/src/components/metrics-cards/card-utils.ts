export function panelStorageKey(hostId: number, panel: string) {
  return `enoki:host:${hostId}:panel:${panel}:collapsed`;
}

export function inventoryText(
  inventory: Record<string, unknown> | null,
  key: string,
) {
  const value = inventory?.[key];

  return value === null || value === undefined || value === ""
    ? "暂无"
    : String(value);
}
