import { describe, expect, it } from "vitest";

import type { HostListSortKey } from "../components/HostListView.vue";
import type { HostSummary } from "../types";
import { locateReadyHost, sortHostsForOverview } from "./ready-host-reveal";

const readyHostId = 101;
const hosts: HostSummary[] = [
  host({
    cpuPercent: 10,
    diskPercent: 40,
    displayName: "Alpha",
    id: 102,
    memoryPercent: 80,
    rx: 100,
    tx: 400,
    uptimeSeconds: 100,
  }),
  host({
    cpuPercent: 20,
    diskPercent: 60,
    displayName: "Bravo",
    id: 104,
    memoryPercent: 60,
    rx: 200,
    tx: 300,
    uptimeSeconds: 200,
  }),
  host({
    cpuPercent: 30,
    diskPercent: 10,
    displayName: "Charlie",
    id: 103,
    memoryPercent: 20,
    rx: 300,
    tx: 200,
    uptimeSeconds: 300,
  }),
  host({
    cpuPercent: 40,
    diskPercent: 80,
    displayName: "Delta",
    id: readyHostId,
    memoryPercent: 40,
    rx: 400,
    tx: 100,
    uptimeSeconds: 400,
  }),
];

const expectedSorts = {
  cpu: {
    asc: { ids: [102, 104, 103, 101], pages: [4, 2, 2, 1] },
    desc: { ids: [101, 103, 104, 102], pages: [1, 1, 1, 1] },
  },
  disk: {
    asc: { ids: [103, 102, 104, 101], pages: [4, 2, 2, 1] },
    desc: { ids: [101, 104, 102, 103], pages: [1, 1, 1, 1] },
  },
  memory: {
    asc: { ids: [103, 101, 104, 102], pages: [2, 1, 1, 1] },
    desc: { ids: [102, 104, 101, 103], pages: [3, 2, 1, 1] },
  },
  name: {
    asc: { ids: [102, 104, 103, 101], pages: [4, 2, 2, 1] },
    desc: { ids: [101, 103, 104, 102], pages: [1, 1, 1, 1] },
  },
  rx: {
    asc: { ids: [102, 104, 103, 101], pages: [4, 2, 2, 1] },
    desc: { ids: [101, 103, 104, 102], pages: [1, 1, 1, 1] },
  },
  tx: {
    asc: { ids: [101, 103, 104, 102], pages: [1, 1, 1, 1] },
    desc: { ids: [102, 104, 103, 101], pages: [4, 2, 2, 1] },
  },
  uptime: {
    asc: { ids: [102, 104, 103, 101], pages: [4, 2, 2, 1] },
    desc: { ids: [101, 103, 104, 102], pages: [1, 1, 1, 1] },
  },
} as const satisfies Record<
  HostListSortKey,
  Record<"asc" | "desc", { ids: number[]; pages: number[] }>
>;

const pageSizes = [1, 2, 3, 4] as const;

describe("ready Host reveal locator", () => {
  it("uses the exact sorted index and page for every overview sort and direction", () => {
    for (const [listSortKey, directions] of Object.entries(expectedSorts) as [
      HostListSortKey,
      (typeof expectedSorts)[HostListSortKey],
    ][]) {
      for (const listSortDirection of ["asc", "desc"] as const) {
        const expected = directions[listSortDirection];
        expect(
          sortHostsForOverview(hosts, listSortKey, listSortDirection).map(
            (host) => host.id,
          ),
        ).toEqual(expected.ids);

        expect(expected.ids.indexOf(readyHostId)).not.toBe(-1);
        for (const [index, listPageSize] of pageSizes.entries()) {
          expect(
            locateReadyHost({
              cardBatchSize: 2,
              currentCardVisibleCount: 2,
              hosts,
              hostId: readyHostId,
              listPageSize,
              listSortDirection,
              listSortKey,
              overviewView: "list",
            }),
          ).toEqual({
            cardVisibleCount: null,
            listPage: expected.pages[index],
          });
        }
      }
    }
  });

  it("uses source order without a sort and expands cards only through the ready Host", () => {
    expect(sortHostsForOverview(hosts, null, "asc")).toBe(hosts);
    expect(
      locateReadyHost({
        cardBatchSize: 2,
        currentCardVisibleCount: 1,
        hosts,
        hostId: readyHostId,
        listPageSize: 2,
        listSortDirection: "asc",
        listSortKey: null,
        overviewView: "list",
      }),
    ).toEqual({ cardVisibleCount: null, listPage: 2 });
    expect(
      locateReadyHost({
        cardBatchSize: 2,
        currentCardVisibleCount: 1,
        hosts,
        hostId: readyHostId,
        listPageSize: 2,
        listSortDirection: "asc",
        listSortKey: null,
        overviewView: "cards",
      }),
    ).toEqual({ cardVisibleCount: 4, listPage: null });
    expect(
      locateReadyHost({
        cardBatchSize: 2,
        currentCardVisibleCount: 6,
        hosts,
        hostId: readyHostId,
        listPageSize: 2,
        listSortDirection: "asc",
        listSortKey: null,
        overviewView: "cards",
      }),
    ).toEqual({ cardVisibleCount: 6, listPage: null });
  });

  it("fails closed when the requested Host is missing or duplicated", () => {
    const input = {
      cardBatchSize: 2,
      currentCardVisibleCount: 2,
      hosts,
      listPageSize: 2,
      listSortDirection: "desc" as const,
      listSortKey: "memory" as const,
      overviewView: "list" as const,
    };

    expect(locateReadyHost({ ...input, hostId: 999 })).toBeNull();
    const duplicateReadyHost = hosts.find((host) => host.id === readyHostId);
    if (!duplicateReadyHost) {
      throw new Error("ready Host fixture is missing");
    }
    expect(
      locateReadyHost({
        ...input,
        hosts: [...hosts, { ...duplicateReadyHost }],
        hostId: readyHostId,
      }),
    ).toBeNull();
  });
});

function host(input: {
  cpuPercent: number;
  diskPercent: number;
  displayName: string;
  id: number;
  memoryPercent: number;
  rx: number;
  tx: number;
  uptimeSeconds: number;
}): HostSummary {
  const totalBytes = 1_000;
  return {
    clockSkew: { detected: false, lastDeltaMs: null },
    collectorCapabilities: null,
    connectAddress: `192.0.2.${input.id}`,
    cpu: "4 cores",
    cpuModel: null,
    description: "",
    displayName: input.displayName,
    id: input.id,
    lastReportAtMs: 1,
    latestMetrics: {
      collectedAtMs: 1,
      cpuPercent: input.cpuPercent,
      diskTotalBytes: totalBytes,
      diskUsedBytes: (totalBytes * input.diskPercent) / 100,
      memoryTotalBytes: totalBytes,
      memoryUsedBytes: (totalBytes * input.memoryPercent) / 100,
      networkRxBitsPerSecond: input.rx,
      networkTxBitsPerSecond: input.tx,
      receivedAtMs: 1,
      uptimeSeconds: input.uptimeSeconds,
    },
    memory: "8 GB",
    probeConfiguration: { mode: "inherit", version: "default-v1" },
    probeUpgradeProblem: null,
    probeVersion: "dev",
    status: "online",
    system: "Linux",
  };
}
