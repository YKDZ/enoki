import { mkdtempSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { createHubRuntimeConfigFromEnvironment } from "../src/config";

describe("Hub runtime configuration", () => {
  it("defaults persistence to the Hub data root and keeps Metrics for 7 days", () => {
    const dataRoot = mkdtempSync(path.join(tmpdir(), "enoki-config-"));

    const config = createHubRuntimeConfigFromEnvironment({
      ENOKI_DATA_ROOT: dataRoot,
      NODE_ENV: "production",
      OWNER_PASSWORD: "correct horse battery staple",
    });

    expect(config.database.dataRoot).toBe(dataRoot);
    expect(config.database.sqlitePath).toBe(path.join(dataRoot, "enoki.db"));
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
    expect(config.metrics).toEqual({
      archive: {
        directory: path.join(dataRoot, "metrics-archive"),
        enabled: true,
        period: "monthly",
      },
      retentionDays: 7,
    });
    expect(statSync(config.metrics.archive.directory).isDirectory()).toBe(true);
    expect(config.network.trustForwardedProbeHeaders).toBe(false);
    expect(config.probeOperations).toEqual({
      acceptedTimeoutMs: 300_000,
      runningTimeoutMs: 900_000,
      tokenSigningSecret: undefined,
    });
  });

  it("allows deployment configuration to override persistence and Metrics retention", () => {
    const archiveDir = mkdtempSync(path.join(tmpdir(), "enoki-archive-"));

    const config = createHubRuntimeConfigFromEnvironment({
      ENOKI_DATA_ROOT: "/var/lib/enoki",
      ENOKI_INSTALL_SCRIPT_PATH: "/opt/enoki/assets/install.sh",
      ENOKI_CLOCK_SKEW_THRESHOLD_SECONDS: "120",
      ENOKI_HOST_STATUS_OFFLINE_AFTER_SECONDS: "45",
      ENOKI_HOST_STATUS_STALE_AFTER_SECONDS: "10",
      ENOKI_METRICS_ARCHIVE_DIR: archiveDir,
      ENOKI_METRICS_ARCHIVE_PERIOD: "daily",
      ENOKI_METRICS_RETENTION_DAYS: "14",
      ENOKI_PROBE_ASSET_DIR: "/opt/enoki/assets",
      ENOKI_PROBE_OPERATION_ACCEPTED_TIMEOUT_SECONDS: "60",
      ENOKI_PROBE_OPERATION_RUNNING_TIMEOUT_SECONDS: "600",
      ENOKI_PROBE_OPERATION_TOKEN_SIGNING_SECRET: "stable-token-secret",
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
    expect(config.metrics).toEqual({
      archive: {
        directory: archiveDir,
        enabled: true,
        period: "daily",
      },
      retentionDays: 14,
    });
    expect(config.network.trustForwardedProbeHeaders).toBe(true);
    expect(config.probeOperations).toEqual({
      acceptedTimeoutMs: 60_000,
      runningTimeoutMs: 600_000,
      tokenSigningSecret: "stable-token-secret",
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

  it("rejects unsupported Metrics Archive periods", () => {
    expect(() =>
      createHubRuntimeConfigFromEnvironment({
        ENOKI_DATA_ROOT: mkdtempSync(path.join(tmpdir(), "enoki-config-")),
        ENOKI_METRICS_ARCHIVE_PERIOD: "weekly",
        OWNER_PASSWORD: "correct horse battery staple",
      }),
    ).toThrow("ENOKI_METRICS_ARCHIVE_PERIOD must be daily or monthly");
  });

  it("disables Metrics Archive without changing hot Metrics retention", () => {
    const dataRoot = mkdtempSync(path.join(tmpdir(), "enoki-config-"));
    const fileParent = path.join(dataRoot, "not-a-directory");
    writeFileSync(fileParent, "");
    const archiveDir = path.join(fileParent, "metrics-archive");

    const config = createHubRuntimeConfigFromEnvironment({
      ENOKI_DATA_ROOT: dataRoot,
      ENOKI_METRICS_ARCHIVE_DIR: archiveDir,
      ENOKI_METRICS_ARCHIVE_ENABLED: "false",
      ENOKI_METRICS_RETENTION_DAYS: "14",
      OWNER_PASSWORD: "correct horse battery staple",
    });

    expect(config.metrics).toEqual({
      archive: {
        directory: archiveDir,
        enabled: false,
        period: "monthly",
      },
      retentionDays: 14,
    });
  });

  it("treats explicitly enabled Metrics Archive configuration like the default", () => {
    const dataRoot = mkdtempSync(path.join(tmpdir(), "enoki-config-"));

    const config = createHubRuntimeConfigFromEnvironment({
      ENOKI_DATA_ROOT: dataRoot,
      ENOKI_METRICS_ARCHIVE_ENABLED: "true",
      OWNER_PASSWORD: "correct horse battery staple",
    });

    expect(config.metrics.archive).toEqual({
      directory: path.join(dataRoot, "metrics-archive"),
      enabled: true,
      period: "monthly",
    });
    expect(statSync(config.metrics.archive.directory).isDirectory()).toBe(true);
  });

  it("fails closed when enabled Metrics Archive storage cannot be prepared", () => {
    const dataRoot = mkdtempSync(path.join(tmpdir(), "enoki-config-"));
    const fileParent = path.join(dataRoot, "not-a-directory");
    writeFileSync(fileParent, "");

    expect(() =>
      createHubRuntimeConfigFromEnvironment({
        ENOKI_DATA_ROOT: dataRoot,
        ENOKI_METRICS_ARCHIVE_DIR: path.join(fileParent, "metrics-archive"),
        OWNER_PASSWORD: "correct horse battery staple",
      }),
    ).toThrow("ENOKI_METRICS_ARCHIVE_DIR must be a writable directory");
  });

  it("rejects blank Probe Operation Token signing secrets", () => {
    const dataRoot = mkdtempSync(path.join(tmpdir(), "enoki-config-"));

    expect(() =>
      createHubRuntimeConfigFromEnvironment({
        ENOKI_DATA_ROOT: dataRoot,
        ENOKI_PROBE_OPERATION_TOKEN_SIGNING_SECRET: "   ",
        OWNER_PASSWORD: "correct horse battery staple",
      }),
    ).toThrow("ENOKI_PROBE_OPERATION_TOKEN_SIGNING_SECRET must not be blank");
  });
});
