import type { HostSummary } from "../types";

export function canReenrollHost(host: Pick<HostSummary, "status">) {
  return host.status === "offline";
}
