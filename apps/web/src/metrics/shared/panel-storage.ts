export function panelStorageKey(hostId: number, panel: string) {
  return `enoki:host:${hostId}:panel:${panel}:collapsed`;
}
