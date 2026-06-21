import { renderToString } from "@vue/server-renderer";
import { describe, expect, it, vi } from "vitest";
import { createSSRApp, computed, ref } from "vue";

import type { useHostDetail } from "@/composables/useHostDetail";

import HostDetailPage from "./HostDetailPage.vue";

describe("Host detail page", () => {
  it("renders warning copy separately from technical Probe error detail", async () => {
    const detail = {
      appendLiveSample: vi.fn(),
      applyLiveSummary: vi.fn(),
      chartRange: computed(() => ({
        maxMs: 1_725_000_000_000,
        minMs: 1_725_000_000_000 - 60 * 60 * 1000,
      })),
      createProbeUpgradeRequest: vi.fn(),
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
        memory: "2 GB",
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
        probeUpgradeEligibility: {
          currentProbeAssetSetVersion: "0.2.0",
          currentProbeVersion: "0.1.0",
          isUpgradeable: true,
          nonUpgradeableReason: null,
        },
        probeUpgradeStatus: null,
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
      isCreatingProbeUpgradeRequest: ref(false),
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
    } as unknown as ReturnType<typeof useHostDetail>;

    const renderDetailPage = () =>
      renderToString(
        createSSRApp(HostDetailPage, {
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

    const html = await renderDetailPage();

    expect(html).toContain("探针配置警告");
    expect(html).toContain("1 GB / 2 GB");
    expect(html).toContain("1 小时 1 分钟");
    expect(html).toContain("Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz");
    expect(html).toContain("生产数据库");
    expect(html).toContain("概览");
    expect(html).toContain("1 分钟");
    expect(html).toContain("时间范围");
    expect(html).toContain("IP 地址");
    expect(html).toContain("操作系统");
    expect(html).toContain(
      "探针未能应用最新配置，请检查探针连通性或配置下发状态。",
    );
    expect(html).not.toContain("技术详情");
    expect(html).not.toContain(
      "report request failed: 503 Service Unavailable",
    );
    expect(html).toContain("主机资料");
    expect(html).toContain("当前 Probe 版本");
    expect(html).toContain("Hub 当前 Probe Asset Set 版本");
    expect(html).toContain("0.1.0");
    expect(html).toContain("0.2.0");
    expect(html).toContain("Probe 可升级");
    expect(html).toContain("确认 Probe 升级");
    expect(html).toContain("将此 Host 的 Probe 升级到 0.2.0");
    expect(html).toContain("配置");
    expect(html).toContain("在线");

    const currentHost = detail.host.value;
    expect(currentHost).not.toBeNull();
    if (!currentHost) {
      throw new Error("Host detail fixture is missing a host.");
    }

    detail.host.value = {
      ...currentHost,
      probeUpgradeEligibility: {
        currentProbeAssetSetVersion: "0.2.0",
        currentProbeVersion: "0.2.0",
        isUpgradeable: false,
        nonUpgradeableReason: "probe_version_current",
      },
      probeUpgradeStatus: {
        createdAtMs: 1_725_000_100_000,
        failure: null,
        id: 9,
        state: "pending",
        targetProbeVersion: "0.2.0",
        updatedAtMs: 1_725_000_100_000,
      },
    };

    const pendingHtml = await renderDetailPage();

    expect(pendingHtml).toContain("Probe 升级中");
    expect(pendingHtml).toContain("animate-spin");
    expect(pendingHtml).not.toContain("Probe 可升级");
    expect(pendingHtml).not.toContain("bg-red-500");
    expect(pendingHtml).not.toContain("取消升级");
  });
});
