import { describe, expect, it } from "vitest";

import { createHubRuntimeConfigFromEnvironment } from "../src/config";

describe("Hub runtime configuration", () => {
  it("defaults persistence to the Hub data root and keeps Metrics for 7 days", () => {
    const config = createHubRuntimeConfigFromEnvironment({
      NODE_ENV: "production",
      OWNER_PASSWORD: "correct horse battery staple",
    });

    expect(config.database.dataRoot).toBe("/data");
    expect(config.database.sqlitePath).toBe("/data/enoki.db");
    expect(config.installation.installPath).toBe("/usr/local/bin/enoki-probe");
    expect(config.installation.installScriptPath).toBe("/api/probe/install.sh");
    expect(config.probeAssets).toEqual({
      assetDir: "/app/probe-assets",
      installScriptPath: "/app/probe-assets/install-probe.sh",
    });
    expect(config.clockSkew.thresholdMs).toBe(300_000);
    expect(config.hostStatus).toEqual({
      offlineAfterMs: 90_000,
      staleAfterMs: 30_000,
    });
    expect(config.metrics.retentionDays).toBe(7);
    expect(config.network.trustForwardedProbeHeaders).toBe(false);
    expect(config.probeOperations).toEqual({
      acceptedTimeoutMs: 300_000,
      runningTimeoutMs: 900_000,
    });
  });

  it("allows deployment configuration to override persistence and Metrics retention", () => {
    const config = createHubRuntimeConfigFromEnvironment({
      ENOKI_DATA_ROOT: "/var/lib/enoki",
      ENOKI_INSTALL_SCRIPT_PATH: "/opt/enoki/assets/install.sh",
      ENOKI_CLOCK_SKEW_THRESHOLD_SECONDS: "120",
      ENOKI_HOST_STATUS_OFFLINE_AFTER_SECONDS: "45",
      ENOKI_HOST_STATUS_STALE_AFTER_SECONDS: "10",
      ENOKI_METRICS_RETENTION_DAYS: "14",
      ENOKI_PROBE_ASSET_DIR: "/opt/enoki/assets",
      ENOKI_PROBE_OPERATION_ACCEPTED_TIMEOUT_SECONDS: "60",
      ENOKI_PROBE_OPERATION_RUNNING_TIMEOUT_SECONDS: "600",
      ENOKI_PROBE_INSTALL_PATH: "/opt/enoki/bin/enoki-probe",
      ENOKI_PUBLIC_HUB_URL: "https://hub.example",
      ENOKI_SQLITE_PATH: "/tmp/custom-enoki.db",
      ENOKI_TRUSTED_PROXY_HEADERS: "true",
      OWNER_PASSWORD: "correct horse battery staple",
    });

    expect(config.database.dataRoot).toBe("/var/lib/enoki");
    expect(config.database.sqlitePath).toBe("/tmp/custom-enoki.db");
    expect(config.installation).toEqual({
      installPath: "/opt/enoki/bin/enoki-probe",
      installScriptPath: "/api/probe/install.sh",
      publicHubUrl: "https://hub.example",
    });
    expect(config.probeAssets).toEqual({
      assetDir: "/opt/enoki/assets",
      installScriptPath: "/opt/enoki/assets/install.sh",
    });
    expect(config.clockSkew.thresholdMs).toBe(120_000);
    expect(config.hostStatus).toEqual({
      offlineAfterMs: 45_000,
      staleAfterMs: 10_000,
    });
    expect(config.metrics.retentionDays).toBe(14);
    expect(config.network.trustForwardedProbeHeaders).toBe(true);
    expect(config.probeOperations).toEqual({
      acceptedTimeoutMs: 60_000,
      runningTimeoutMs: 600_000,
    });
  });

  it("rejects Host Status thresholds where offline is not after stale", () => {
    expect(() =>
      createHubRuntimeConfigFromEnvironment({
        ENOKI_HOST_STATUS_OFFLINE_AFTER_SECONDS: "30",
        ENOKI_HOST_STATUS_STALE_AFTER_SECONDS: "30",
        OWNER_PASSWORD: "correct horse battery staple",
      }),
    ).toThrow("ENOKI_HOST_STATUS_OFFLINE_AFTER_SECONDS must be greater");
  });
});
