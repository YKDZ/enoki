import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import type { HostSummary } from "../types";
import HostListView from "./HostListView.vue";

const host = (
  id: number,
  displayName: string,
  status: HostSummary["status"] = "online",
) =>
  ({
    clockSkew: { detected: false, lastDeltaMs: null },
    collectorCapabilities: null,
    connectAddress: "127.0.0.1",
    cpu: "1 core",
    cpuModel: null,
    description: "",
    displayName,
    id,
    lastReportAtMs: 1,
    latestMetrics: null,
    memory: "1 GB",
    probeConfiguration: { mode: "inherit", version: "default-v1" },
    probeVersion: "dev",
    status,
    system: "Linux",
  }) as HostSummary;

describe("Host list ready reveal", () => {
  it("renders the selected sorted page with a focusable highlight marker", async () => {
    const html = await renderToString(
      createSSRApp(HostListView, {
        highlightedHostId: 7,
        hosts: [host(7, "zeta"), host(2, "alpha"), host(4, "beta")],
        page: 3,
        pageSize: 1,
        sortDirection: "asc",
        sortKey: "name",
      }),
    );

    expect(html).toContain('data-enoki-host-id="7"');
    expect(html).toContain("ring-primary");
    expect(html).not.toContain('data-enoki-host-id="2"');
  });

  it("exposes the same Probe Re-enrollment action only on offline rows", async () => {
    const html = await renderToString(
      createSSRApp(HostListView, {
        highlightedHostId: null,
        hosts: [
          host(7, "offline", "offline"),
          host(8, "stale", "stale"),
          host(9, "online"),
        ],
        page: 1,
        pageSize: 3,
        sortDirection: "asc",
        sortKey: null,
      }),
    );

    expect(html.match(/重新注册探针/g)).toHaveLength(1);
  });
});
