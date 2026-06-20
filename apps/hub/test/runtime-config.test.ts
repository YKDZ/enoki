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
    expect(config.installation.installScriptUrl).toBe(
      "https://github.com/YKDZ/enoki/releases/latest/download/install-probe.sh",
    );
    expect(config.installation.probeReleaseVersion).toBeUndefined();
    expect(config.clockSkew.thresholdMs).toBe(300_000);
    expect(config.hostStatus).toEqual({
      offlineAfterMs: 90_000,
      staleAfterMs: 30_000,
    });
    expect(config.metrics.retentionDays).toBe(7);
    expect(config.network.trustForwardedProbeHeaders).toBe(false);
  });

  it("allows deployment configuration to override persistence and Metrics retention", () => {
    const config = createHubRuntimeConfigFromEnvironment({
      ENOKI_DATA_ROOT: "/var/lib/enoki",
      ENOKI_INSTALL_SCRIPT_URL:
        "https://github.com/example/enoki/releases/download/v0.2.0/install-probe.sh",
      ENOKI_CLOCK_SKEW_THRESHOLD_SECONDS: "120",
      ENOKI_HOST_STATUS_OFFLINE_AFTER_SECONDS: "45",
      ENOKI_HOST_STATUS_STALE_AFTER_SECONDS: "10",
      ENOKI_METRICS_RETENTION_DAYS: "14",
      ENOKI_PROBE_INSTALL_PATH: "/opt/enoki/bin/enoki-probe",
      ENOKI_PROBE_RELEASE_VERSION: "v0.2.0",
      ENOKI_PUBLIC_HUB_URL: "https://hub.example",
      ENOKI_SQLITE_PATH: "/tmp/custom-enoki.db",
      ENOKI_TRUSTED_PROXY_HEADERS: "true",
      OWNER_PASSWORD: "correct horse battery staple",
    });

    expect(config.database.dataRoot).toBe("/var/lib/enoki");
    expect(config.database.sqlitePath).toBe("/tmp/custom-enoki.db");
    expect(config.installation).toEqual({
      installPath: "/opt/enoki/bin/enoki-probe",
      installScriptUrl:
        "https://github.com/example/enoki/releases/download/v0.2.0/install-probe.sh",
      probeDownloadUrl: undefined,
      probeReleaseVersion: "v0.2.0",
      publicHubUrl: "https://hub.example",
    });
    expect(config.clockSkew.thresholdMs).toBe(120_000);
    expect(config.hostStatus).toEqual({
      offlineAfterMs: 45_000,
      staleAfterMs: 10_000,
    });
    expect(config.metrics.retentionDays).toBe(14);
    expect(config.network.trustForwardedProbeHeaders).toBe(true);
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
