import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import type { HostSummary } from "../types";
import HostListView from "./HostListView.vue";

const host = (id: number, displayName: string) =>
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
    probeUpgradeProblem: null,
    probeVersion: "dev",
    status: "online",
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

  it("shows the same compact failed Probe Upgrade problem marker as cards", async () => {
    const html = await renderToString(
      createSSRApp(HostListView, {
        hosts: [
          {
            ...host(1, "failed-host"),
            probeUpgradeProblem: { status: "failed" },
          } as HostSummary,
        ],
        page: 1,
        pageSize: 10,
        sortDirection: "asc",
        sortKey: "name",
      }),
    );

    expect(html).toContain("探针升级失败");
    expect(html).not.toContain("探针升级中");
  });
});
