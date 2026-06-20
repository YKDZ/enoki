import { renderToString } from "@vue/server-renderer";
import { createSSRApp, computed, ref } from "vue";
import { describe, expect, it, vi } from "vitest";

import type { useManagedHostDetail } from "@/composables/useManagedHostDetail";
import ManagedHostDetailPage from "./ManagedHostDetailPage.vue";

describe("Managed Host detail page", () => {
  it("renders warning copy separately from technical Probe error detail", async () => {
    const detail = {
      appendLiveSample: vi.fn(),
      applyLiveSummary: vi.fn(),
      chartRange: computed(() => ({
        maxMs: 1_725_000_000_000,
        minMs: 1_725_000_000_000 - 60 * 60 * 1000,
      })),
      error: ref(""),
      host: ref({
        clockSkew: {
          detected: false,
          lastDeltaMs: null,
        },
        connectAddress: "10.0.0.10",
        cpu: "2 cores",
        cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
        description: "生产数据库",
        displayName: "managed-host-01",
        hostMetadata: {
          connectAddress: "10.0.0.10",
          description: "生产数据库",
          displayName: "managed-host-01",
          observedIp: "203.0.113.10",
        },
        id: 1,
        inventory: {
          architecture: "x86_64",
          cpuCount: 2,
          cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
          hostname: "managed-host-01",
          kernel: "6.8.0",
          memoryTotalBytes: "2147483648",
          os: "linux",
        },
        lastReportAtMs: 1_725_000_000_000,
        latestMetrics: null,
        memory: "2 GiB",
        probeConfiguration: {
          configuration: {
            collectCpu: true,
            collectDisk: true,
            collectLoad: true,
            collectMemory: true,
            collectNetwork: true,
            collectUptime: true,
            metricsCollectionIntervalSeconds: 5,
            reportingBatchIntervalSeconds: 30,
            version: "default-v1",
          },
          mode: "inherit",
          version: "default-v1",
        },
        probeVersion: "0.1.0",
        status: "online",
        system: "linux",
        warnings: [
          {
            code: "probe_configuration_error",
            message: "探针未能应用最新配置，请检查探针连通性或配置下发状态。",
            occurredAtMs: 1_725_000_000_000,
            technicalDetail:
              "Probe 原始信息：report request failed: 503 Service Unavailable",
          },
        ],
      }),
      isEmpty: computed(() => true),
      isLoading: ref(false),
      load: vi.fn(),
      samples: ref([
        {
          collectedAtMs: 1_725_000_000_000,
          cpuCores: [],
          cpuPercent: 24,
          diskTotalBytes: null,
          diskUsedBytes: null,
          disks: [],
          memoryTotalBytes: 2_147_483_648,
          memoryUsedBytes: 1_073_741_824,
          networkInterfaces: [],
          networkRxBitsPerSecond: null,
          networkRxBytesDelta: null,
          networkTxBitsPerSecond: null,
          networkTxBytesDelta: null,
          receivedAtMs: 1_725_000_000_000,
          sequence: 1,
          uptimeSeconds: 3_661,
        },
      ]),
      selectedWindow: ref("1h"),
      switchWindow: vi.fn(),
    } as unknown as ReturnType<typeof useManagedHostDetail>;

    const html = await renderToString(
      createSSRApp(ManagedHostDetailPage, {
        activeHostConfigurationId: null,
        activeHostMetadataId: null,
        deletingHostId: null,
        detail,
        hostConfigurationDraft: null,
        hostConfigurationError: "",
        hostMetadataDraft: null,
        hostMetadataError: "",
        isSavingHostConfiguration: false,
        isSavingHostMetadata: false,
      }),
    );

    expect(html).toContain("探针配置警告");
    expect(html).toContain("1 GiB / 2 GiB");
    expect(html).toContain("1 小时 1 分钟");
    expect(html).toContain("Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz");
    expect(html).toContain("生产数据库");
    expect(html).toContain("IP 地址");
    expect(html).toContain("操作系统");
    expect(html).toContain("探针未能应用最新配置，请检查探针连通性或配置下发状态。");
    expect(html).not.toContain("技术详情");
    expect(html).not.toContain("report request failed: 503 Service Unavailable");
    expect(html).toContain("主机资料");
    expect(html).toContain("配置");
    expect(html).toContain("在线");
  });
});
