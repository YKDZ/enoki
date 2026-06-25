import { randomUUID } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

import {
  createAuthConfigFromEnvironment,
  type AuthConfig,
  type AuthEnvironment,
} from "./auth/config.js";
import {
  createDefaultInstallationCommandConfig,
  type InstallationCommandConfig,
} from "./enrollment/install-command.js";

export type HubEnvironment = AuthEnvironment;

export type DatabaseConfig = {
  dataRoot: string;
  sqlitePath: string;
};

export type MetricsConfig = {
  archive: MetricsArchiveConfig;
  retentionDays: number;
};

export type MetricsArchiveConfig = {
  directory: string;
  enabled: boolean;
  period: MetricsArchivePeriod;
};

export type MetricsArchivePeriod = "daily" | "monthly";

export type ClockSkewConfig = {
  thresholdMs: number;
};

export type HostStatusConfig = {
  offlineAfterMs: number;
  staleAfterMs: number;
};

export type NetworkConfig = {
  trustForwardedProbeHeaders: boolean;
};

export type ProbeAssetConfig = {
  assetDir: string;
  installScriptPath: string;
};

export type ProbeOperationConfig = {
  acceptedTimeoutMs: number;
  runningTimeoutMs: number;
  tokenSigningSecret?: string;
};

export type HubRuntimeConfig = {
  auth: AuthConfig;
  clockSkew: ClockSkewConfig;
  database: DatabaseConfig;
  hostStatus: HostStatusConfig;
  installation: InstallationCommandConfig;
  metrics: MetricsConfig;
  network: NetworkConfig;
  probeAssets: ProbeAssetConfig;
  probeOperations: ProbeOperationConfig;
};

const defaultDataRoot = "/data";
const defaultDatabaseFileName = "enoki.db";
const defaultClockSkewThresholdSeconds = 300;
const defaultHostStatusOfflineAfterSeconds = 90;
const defaultHostStatusStaleAfterSeconds = 30;
const defaultMetricsRetentionDays = 7;
const defaultMetricsArchivePeriod = "monthly";
const defaultProbeAssetDir = "/app/probe-assets";
const defaultProbeOperationAcceptedTimeoutSeconds = 5 * 60;
const defaultProbeOperationRunningTimeoutSeconds = 15 * 60;

export function createHubRuntimeConfigFromEnvironment(
  environment: HubEnvironment,
): HubRuntimeConfig {
  const dataRoot = environment.ENOKI_DATA_ROOT || defaultDataRoot;
  const installation =
    createInstallationCommandConfigFromEnvironment(environment);
  const hostStatus = createHostStatusConfigFromEnvironment(environment);

  return {
    auth: createAuthConfigFromEnvironment(environment),
    clockSkew: {
      thresholdMs:
        readPositiveInteger(
          environment.ENOKI_CLOCK_SKEW_THRESHOLD_SECONDS,
          defaultClockSkewThresholdSeconds,
          "ENOKI_CLOCK_SKEW_THRESHOLD_SECONDS",
        ) * 1000,
    },
    database: {
      dataRoot,
      sqlitePath:
        environment.ENOKI_SQLITE_PATH ??
        path.join(dataRoot, defaultDatabaseFileName),
    },
    hostStatus,
    installation,
    metrics: {
      archive: createMetricsArchiveConfigFromEnvironment(environment, dataRoot),
      retentionDays: readPositiveInteger(
        environment.ENOKI_METRICS_RETENTION_DAYS,
        defaultMetricsRetentionDays,
        "ENOKI_METRICS_RETENTION_DAYS",
      ),
    },
    network: {
      trustForwardedProbeHeaders:
        environment.ENOKI_TRUSTED_PROXY_HEADERS === "true",
    },
    probeAssets: {
      assetDir: environment.ENOKI_PROBE_ASSET_DIR ?? defaultProbeAssetDir,
      installScriptPath:
        environment.ENOKI_INSTALL_SCRIPT_PATH ??
        path.join(
          environment.ENOKI_PROBE_ASSET_DIR ?? defaultProbeAssetDir,
          "install-probe.sh",
        ),
    },
    probeOperations: {
      acceptedTimeoutMs:
        readPositiveInteger(
          environment.ENOKI_PROBE_OPERATION_ACCEPTED_TIMEOUT_SECONDS,
          defaultProbeOperationAcceptedTimeoutSeconds,
          "ENOKI_PROBE_OPERATION_ACCEPTED_TIMEOUT_SECONDS",
        ) * 1000,
      runningTimeoutMs:
        readPositiveInteger(
          environment.ENOKI_PROBE_OPERATION_RUNNING_TIMEOUT_SECONDS,
          defaultProbeOperationRunningTimeoutSeconds,
          "ENOKI_PROBE_OPERATION_RUNNING_TIMEOUT_SECONDS",
        ) * 1000,
      tokenSigningSecret: readOptionalSecret(
        environment.ENOKI_PROBE_OPERATION_TOKEN_SIGNING_SECRET,
        "ENOKI_PROBE_OPERATION_TOKEN_SIGNING_SECRET",
      ),
    },
  };
}

function createMetricsArchiveConfigFromEnvironment(
  environment: HubEnvironment,
  dataRoot: string,
): MetricsArchiveConfig {
  const directory =
    environment.ENOKI_METRICS_ARCHIVE_DIR ??
    path.join(dataRoot, "metrics-archive");
  const enabled = readMetricsArchiveEnabled(
    environment.ENOKI_METRICS_ARCHIVE_ENABLED,
  );
  const config = {
    directory,
    enabled,
    period: readMetricsArchivePeriod(environment.ENOKI_METRICS_ARCHIVE_PERIOD),
  };

  if (config.enabled) {
    prepareWritableDirectory(directory, "ENOKI_METRICS_ARCHIVE_DIR");
  }

  return config;
}

function createHostStatusConfigFromEnvironment(environment: HubEnvironment) {
  const staleAfterSeconds = readPositiveInteger(
    environment.ENOKI_HOST_STATUS_STALE_AFTER_SECONDS,
    defaultHostStatusStaleAfterSeconds,
    "ENOKI_HOST_STATUS_STALE_AFTER_SECONDS",
  );
  const offlineAfterSeconds = readPositiveInteger(
    environment.ENOKI_HOST_STATUS_OFFLINE_AFTER_SECONDS,
    defaultHostStatusOfflineAfterSeconds,
    "ENOKI_HOST_STATUS_OFFLINE_AFTER_SECONDS",
  );

  if (offlineAfterSeconds <= staleAfterSeconds) {
    throw new Error(
      "ENOKI_HOST_STATUS_OFFLINE_AFTER_SECONDS must be greater than ENOKI_HOST_STATUS_STALE_AFTER_SECONDS.",
    );
  }

  return {
    offlineAfterMs: offlineAfterSeconds * 1000,
    staleAfterMs: staleAfterSeconds * 1000,
  };
}

function createInstallationCommandConfigFromEnvironment(
  environment: HubEnvironment,
) {
  const defaults = createDefaultInstallationCommandConfig();

  return {
    installPath: environment.ENOKI_PROBE_INSTALL_PATH ?? defaults.installPath,
    installScriptPath: defaults.installScriptPath,
    publicHubUrl: environment.ENOKI_PUBLIC_HUB_URL,
  };
}

function readMetricsArchiveEnabled(value: string | undefined) {
  return value !== "false";
}

function readMetricsArchivePeriod(
  value: string | undefined,
): MetricsArchivePeriod {
  if (value === undefined || value === "") {
    return defaultMetricsArchivePeriod;
  }

  if (value === "daily" || value === "monthly") {
    return value;
  }

  throw new Error("ENOKI_METRICS_ARCHIVE_PERIOD must be daily or monthly.");
}

function prepareWritableDirectory(directory: string, name: string) {
  try {
    mkdirSync(directory, { recursive: true });
    const probePath = path.join(
      directory,
      `.enoki-write-check-${process.pid}-${randomUUID()}`,
    );
    writeFileSync(probePath, "");
    rmSync(probePath, { force: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${name} must be a writable directory: ${message}`);
  }
}

function readPositiveInteger(
  value: string | undefined,
  fallback: number,
  name: string,
) {
  if (value === undefined || value === "") {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);

  if (!Number.isSafeInteger(parsed) || parsed < 1 || String(parsed) !== value) {
    throw new Error(`${name} must be a positive integer.`);
  }

  return parsed;
}

function readOptionalSecret(value: string | undefined, name: string) {
  if (value === undefined || value === "") {
    return undefined;
  }

  if (value.trim().length === 0) {
    throw new Error(`${name} must not be blank.`);
  }

  return value;
}
