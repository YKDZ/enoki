import { randomUUID } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

import {
  createAuthConfigFromEnvironment,
  type AuthConfig,
  type AuthEnvironment,
} from "./auth/config.js";
import { HubConfigurationError } from "./config-error.js";
import { type InstallationCommandConfig } from "./enrollment/install-command.js";
import { createNoopHubLogger, type HubLogger } from "./hub-logger.js";
import {
  isNonLoopbackHttpOrigin,
  parseTrustedProxyCidrs,
  readHttpOrigin,
  type TrustedProxyCidr,
} from "./network.js";

export type HubEnvironment = AuthEnvironment;

export type DatabaseConfig = {
  dataRoot: string;
  sqlitePath: string;
};

export type HubPersistentStateConfig = {
  archiveDirectory: string;
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
  managementOrigin: string;
  probeApiOrigin: string;
  trustedProxyCidrs: TrustedProxyCidr[];
};

export type ProbeAssetConfig = {
  assetDir: string;
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
  options: { logger?: HubLogger } = {},
): HubRuntimeConfig {
  const logger = options.logger ?? createNoopHubLogger();
  rejectLegacyEnvironment(environment);
  const network = createNetworkConfigFromEnvironment(environment, logger);
  const persistentState =
    createHubPersistentStateConfigFromEnvironment(environment);
  const dataRoot = persistentState.dataRoot;
  const installation =
    createInstallationCommandConfigFromEnvironment(environment);
  const hostStatus = createHostStatusConfigFromEnvironment(environment);

  return {
    auth: {
      ...createAuthConfigFromEnvironment(environment, { logger }),
      managementOrigin: network.managementOrigin,
      trustedProxyCidrs: network.trustedProxyCidrs,
    },
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
      sqlitePath: persistentState.sqlitePath,
    },
    hostStatus,
    installation,
    metrics: {
      archive: createMetricsArchiveConfigFromEnvironment(
        environment,
        persistentState.archiveDirectory,
      ),
      retentionDays: readPositiveInteger(
        environment.ENOKI_METRICS_RETENTION_DAYS,
        defaultMetricsRetentionDays,
        "ENOKI_METRICS_RETENTION_DAYS",
      ),
    },
    network,
    probeAssets: {
      assetDir: environment.ENOKI_PROBE_ASSET_DIR ?? defaultProbeAssetDir,
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

export function createHubPersistentStateConfigFromEnvironment(
  environment: HubEnvironment,
): HubPersistentStateConfig {
  const dataRoot = environment.ENOKI_DATA_ROOT || defaultDataRoot;
  return {
    archiveDirectory:
      environment.ENOKI_METRICS_ARCHIVE_DIR ??
      path.join(dataRoot, "metrics-archive"),
    dataRoot,
    sqlitePath:
      environment.ENOKI_SQLITE_PATH ??
      path.join(dataRoot, defaultDatabaseFileName),
  };
}

function createMetricsArchiveConfigFromEnvironment(
  environment: HubEnvironment,
  directory: string,
): MetricsArchiveConfig {
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
  return {
    probeApiOrigin: readHttpOrigin(
      environment.ENOKI_PROBE_API_ORIGIN ?? environment.ENOKI_MANAGEMENT_ORIGIN,
      "ENOKI_PROBE_API_ORIGIN",
    ),
  };
}

function createNetworkConfigFromEnvironment(
  environment: HubEnvironment,
  logger: HubLogger,
): NetworkConfig {
  const managementOrigin = readHttpOrigin(
    environment.ENOKI_MANAGEMENT_ORIGIN,
    "ENOKI_MANAGEMENT_ORIGIN",
  );
  const probeApiOrigin = readHttpOrigin(
    environment.ENOKI_PROBE_API_ORIGIN ?? managementOrigin,
    "ENOKI_PROBE_API_ORIGIN",
  );

  const insecureOrigins: Array<[string, string]> =
    managementOrigin === probeApiOrigin
      ? [[managementOrigin, "insecure_management_and_probe_api_origin"]]
      : [
          [managementOrigin, "insecure_management_origin"],
          [probeApiOrigin, "insecure_probe_api_origin"],
        ];

  for (const [origin, outcome] of insecureOrigins) {
    if (!isNonLoopbackHttpOrigin(origin)) continue;
    logger.log({
      component: "hub",
      event: "configuration.warning",
      level: "warn",
      outcome,
    });
  }

  return {
    managementOrigin,
    probeApiOrigin,
    trustedProxyCidrs: parseTrustedProxyCidrs(
      environment.ENOKI_TRUSTED_PROXY_CIDRS,
    ),
  };
}

function rejectLegacyEnvironment(environment: HubEnvironment) {
  const migrations: Record<string, string> = {
    ENOKI_PUBLIC_HUB_URL:
      "Set ENOKI_MANAGEMENT_ORIGIN and, when the Probe API differs, ENOKI_PROBE_API_ORIGIN.",
    ENOKI_PUBLIC_HTTPS:
      "Choose http:// or https:// in ENOKI_MANAGEMENT_ORIGIN and ENOKI_PROBE_API_ORIGIN.",
    ENOKI_TRUST_PROXY_HEADERS:
      "Set ENOKI_TRUSTED_PROXY_CIDRS only for forwarded client-address evidence; forwarded host and protocol are ignored.",
    ENOKI_TRUSTED_PROXY_HEADERS:
      "Set ENOKI_TRUSTED_PROXY_CIDRS only for forwarded client-address evidence.",
  };

  for (const [name, migration] of Object.entries(migrations)) {
    if (environment[name] !== undefined) {
      throw new HubConfigurationError(`${name} has been removed. ${migration}`);
    }
  }
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
