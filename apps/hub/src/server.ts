import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { isHubConfigurationError } from "./config-error.js";
import { createHubRuntimeConfigFromEnvironment } from "./config.js";
import { initializeHubDatabase } from "./database/index.js";
import { resolveProbeBootstrapRecipeRecord } from "./enrollment/install-command.js";
import {
  createDelegatingHubLogger,
  createJsonLineHubLogger,
  readHubLogLevel,
} from "./hub-logger.js";
import { createLiveUpdateBroadcaster } from "./live-updates.js";
import { runMetricsArchiveMaintenance } from "./metrics-archive/maintenance.js";
import { createMetricsArchiveScheduler } from "./metrics-archive/scheduler.js";
import {
  createHubNodeServer,
  createProbeApiNodeServer,
  type HubNodeServer,
} from "./node-server.js";
import { readProbeDistributionRootPublicKeyFromImage } from "./probe/distribution-root.js";
import {
  createBoundedHubShutdown,
  installHubFatalHandlers,
} from "./process-lifecycle.js";

const loggerControl = createDelegatingHubLogger(createJsonLineHubLogger());
const logger = loggerControl.logger;
export type HubRuntime = {
  close: () => Promise<void>;
  closeDatabase: () => void;
  closeListeners: () => Promise<void>;
  stopBackground: () => void;
};

export async function startHubRuntime(
  options: {
    environment?: NodeJS.ProcessEnv;
    probeDistributionRootPublicKeyPem?: Buffer | string | null;
  } = {},
): Promise<HubRuntime> {
  const environment = options.environment ?? process.env;
  loggerControl.setLogger(
    createJsonLineHubLogger({
      level: readHubLogLevel(environment.ENOKI_HUB_LOG_LEVEL),
    }),
  );
  const port = readPort(environment.PORT ?? "3000", "PORT");
  const hostname = environment.HOST;
  const probePort = readPort(
    environment.ENOKI_PROBE_PORT ?? "3001",
    "ENOKI_PROBE_PORT",
  );
  const probeHostname = environment.ENOKI_PROBE_HOST ?? hostname;
  const webDistPath =
    environment.ENOKI_WEB_DIST ??
    new URL("../../web/dist", import.meta.url).pathname;
  const config = createHubRuntimeConfigFromEnvironment(environment, { logger });
  const probeAssets = {
    ...config.probeAssets,
    ...(options.probeDistributionRootPublicKeyPem
      ? { trustedRootPublicKeyPem: options.probeDistributionRootPublicKeyPem }
      : {}),
  };
  const database = initializeHubDatabase(config.database);
  const liveUpdates = createLiveUpdateBroadcaster();
  const metricsArchiveScheduler = createMetricsArchiveScheduler({
    intervalMs: 60 * 60 * 1000,
    logger,
    maintain: () => {
      if (!database) return;
      runMetricsArchiveMaintenance({
        database,
        metrics: config.metrics,
      });
    },
  });
  const servers: HubNodeServer[] = [];

  try {
    servers.push(
      await createHubNodeServer({
        auth: config.auth,
        clockSkewThresholdMs: config.clockSkew.thresholdMs,
        database,
        hostname,
        hostStatus: config.hostStatus,
        installation: {
          ...config.installation,
          bootstrapRecipe: resolveProbeBootstrapRecipeRecord({
            deployment: environment.ENOKI_DEPLOYMENT,
            nodeEnvironment: environment.NODE_ENV,
          }),
        },
        logger,
        liveUpdates,
        port,
        probeAssets,
        probeOperationTokenSecret: config.probeOperations.tokenSigningSecret,
        probeOperations: config.probeOperations,
        probeApiOrigin: config.network.probeApiOrigin,
        trustedProxyCidrs: config.network.trustedProxyCidrs,
        webDistPath,
      }),
    );
    logger.log({
      component: "management-listener",
      event: "listener.started",
      level: "info",
      listener: "management",
      outcome: "listening",
    });

    servers.push(
      await createProbeApiNodeServer({
        clockSkewThresholdMs: config.clockSkew.thresholdMs,
        database,
        hostname: probeHostname,
        hostStatus: config.hostStatus,
        liveUpdates,
        logger,
        port: probePort,
        probeAssets,
        probeOperationTokenSecret: config.probeOperations.tokenSigningSecret,
        probeApiOrigin: config.network.probeApiOrigin,
        trustedProxyCidrs: config.network.trustedProxyCidrs,
      }),
    );
    logger.log({
      component: "probe-listener",
      event: "listener.started",
      level: "info",
      listener: "probe",
      outcome: "listening",
    });
    metricsArchiveScheduler.start();
  } catch (error) {
    metricsArchiveScheduler.stop();
    await Promise.all(servers.map((server) => server.close()));
    database.close();
    throw error;
  }

  const closeListeners = () =>
    Promise.all(servers.map((server) => server.close())).then(() => {});
  const stopBackground = () => metricsArchiveScheduler.stop();
  const closeDatabase = () => database.close();
  return {
    close: async () => {
      stopBackground();
      await closeListeners();
      closeDatabase();
    },
    closeDatabase,
    closeListeners,
    stopBackground,
  };
}

async function main() {
  let runtime: HubRuntime | undefined;
  const shutdown = createBoundedHubShutdown({
    closeDatabase: () => runtime?.closeDatabase(),
    closeListeners: () => runtime?.closeListeners() ?? Promise.resolve(),
    exit: (code) => process.exit(code),
    logger,
    stopBackground: () => runtime?.stopBackground() ?? Promise.resolve(),
    timeoutMs: 15_000,
  });
  const fatal = installHubFatalHandlers({ logger, process, shutdown });
  const shutdownRuntime = () => shutdown(0);

  process.once("SIGINT", () => {
    void shutdownRuntime();
  });
  process.once("SIGTERM", () => {
    void shutdownRuntime();
  });

  try {
    runtime = await startHubRuntime({
      probeDistributionRootPublicKeyPem:
        await readProbeDistributionRootPublicKeyFromImage(),
    });
  } catch (error) {
    fatal(
      "startup_failure",
      isHubConfigurationError(error) ? error.publicMessage : undefined,
    );
  }
}

if (isMainModule()) void main();

function isMainModule() {
  const entrypoint = process.argv[1];
  return entrypoint
    ? import.meta.url === pathToFileURL(resolve(entrypoint)).href
    : false;
}

function readPort(value: string, name: string) {
  const port = Number.parseInt(value, 10);

  if (
    !Number.isSafeInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    String(port) !== value
  ) {
    throw new Error(`${name} must be an integer between 1 and 65535.`);
  }

  return port;
}
