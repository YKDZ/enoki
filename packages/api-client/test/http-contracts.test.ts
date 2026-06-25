import { describe, expect, it } from "vitest";

import type {
  HostDetailResponse,
  HostMetadataResponse,
  HostMetricSample,
  HostMetricsResponse,
  HostProbeConfigurationResponse,
  HostSummary,
  HostsResponse,
  ProbeConfigurationResponse,
  ProbeUpgradeRequestResponse,
  SessionResponse,
  EnrollmentResponse,
} from "../src/index.js";

describe("HTTP API contracts", () => {
  it("exports Host list, detail, and metrics response contracts", () => {
    const summary = {
      clockSkew: {
        detected: false,
        lastDeltaMs: null,
      },
      collectorCapabilities: {
        official: {
          diskHealth: {
            diagnostic: "",
            status: 1,
          },
        },
      },
      connectAddress: "enoki.local",
      cpu: "8 cores",
      cpuModel: "Example CPU",
      description: "",
      displayName: "enoki-dev",
      id: 1,
      lastReportAtMs: 1_725_000_010_000,
      latestMetrics: null,
      memory: "16 GiB",
      probeConfiguration: {
        mode: "inherit",
        version: "default-v1",
      },
      probeVersion: "0.1.0",
      status: "online",
      system: "Linux",
    } satisfies HostSummary;

    const detail = {
      ...summary,
      hostMetadata: {
        connectAddress: "enoki.local",
        description: "",
        displayName: "enoki-dev",
        observedIp: "127.0.0.1",
      },
      hostProfile: {
        architecture: "x86_64",
        collectorCapabilities: summary.collectorCapabilities,
        cpuCount: 8,
        filesystems: [],
        hostname: "enoki-dev",
        kernel: "6.1.0",
        memoryTotalBytes: 17_179_869_184,
        networkInterfaces: [],
        os: "Linux",
        probeVersion: "0.1.0",
      },
      probeConfiguration: {
        configuration: {
          enabledCollectorIds: ["official.cpu"],
          metricsCollectionIntervalSeconds: 5,
          version: "default-v1",
        },
        mode: "inherit",
      },
      probeUpgradeEligibility: {
        currentProbeAssetSetVersion: null,
        currentProbeVersion: "0.1.0",
        isUpgradeable: false,
        nonUpgradeableReason: "probe_asset_set_version_missing",
      },
      probeUpgradeStatus: null,
      warnings: [],
    } satisfies HostDetailResponse["host"];

    const sample = {
      collectedAtMs: 1_725_000_009_500,
      cpuCores: [],
      cpuPercent: 12,
      diskTotalBytes: null,
      diskUsedBytes: null,
      disks: [],
      memoryTotalBytes: null,
      memoryUsedBytes: null,
      networkInterfaces: [],
      networkRxBitsPerSecond: null,
      networkRxBytesDelta: null,
      networkTxBitsPerSecond: null,
      networkTxBytesDelta: null,
      receivedAtMs: 1_725_000_010_000,
      sequence: 1,
      uptimeSeconds: null,
    } satisfies HostMetricSample;

    const hostsResponse = {
      hosts: [summary],
    } satisfies HostsResponse;
    const detailResponse = {
      host: detail,
    } satisfies HostDetailResponse;
    const metricsResponse = {
      metrics: {
        samples: [sample],
        window: "1m",
      },
    } satisfies HostMetricsResponse;

    expect({ detailResponse, hostsResponse, metricsResponse }).toBeDefined();
  });

  it("exports session, enrollment, configuration, metadata, and upgrade response contracts", () => {
    const session = {
      authenticated: true,
    } satisfies SessionResponse;
    const enrollment = {
      enrollmentToken: "enk_enroll_example",
      expiresAtMs: 1_725_000_900_000,
      hubUrl: "https://hub.example.test",
      installCommand: "curl https://hub.example.test/install.sh | sh",
      installPath: "/opt/enoki",
    } satisfies EnrollmentResponse;
    const probeConfiguration = {
      configuration: {
        enabledCollectorIds: ["official.cpu"],
        metricsCollectionIntervalSeconds: 5,
        version: "global-1",
      },
    } satisfies ProbeConfigurationResponse;
    const hostProbeConfiguration = {
      configuration: probeConfiguration.configuration,
      mode: "override",
    } satisfies HostProbeConfigurationResponse;
    const metadata = {
      connectAddress: "ssh.internal.example",
      description: "production",
      displayName: "enoki-prod-01",
      id: 1,
    } satisfies HostMetadataResponse;
    const probeUpgrade = {
      probeUpgradeRequest: {
        createdAtMs: 1_725_000_800_000,
        failure: null,
        id: 7,
        state: "pending",
        targetProbeVersion: "0.2.0",
        updatedAtMs: 1_725_000_800_000,
      },
    } satisfies ProbeUpgradeRequestResponse;

    expect({
      enrollment,
      hostProbeConfiguration,
      metadata,
      probeConfiguration,
      probeUpgrade,
      session,
    }).toBeDefined();
  });
});
