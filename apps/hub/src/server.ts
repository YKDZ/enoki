import { isHubConfigurationError } from "./config-error.js";
import { createHubRuntimeConfigFromEnvironment } from "./config.js";
import { initializeHubDatabase, type HubDatabase } from "./database/index.js";
import {
  createDelegatingHubLogger,
  createJsonLineHubLogger,
  readHubLogLevel,
} from "./hub-logger.js";
import { createLiveUpdateBroadcaster } from "./live-updates.js";
import { runMetricsArchiveMaintenance } from "./metrics-archive/maintenance.js";
import {
  createMetricsArchiveScheduler,
  type MetricsArchiveScheduler,
} from "./metrics-archive/scheduler.js";
import {
  createHubNodeServer,
  createProbeApiNodeServer,
  type HubNodeServer,
} from "./node-server.js";
import {
  createBoundedHubShutdown,
  installHubFatalHandlers,
} from "./process-lifecycle.js";

const loggerControl = createDelegatingHubLogger(createJsonLineHubLogger());
const logger = loggerControl.logger;
const servers: HubNodeServer[] = [];
let database: HubDatabase | undefined;
let metricsArchiveScheduler: MetricsArchiveScheduler | undefined;

const shutdown = createBoundedHubShutdown({
  closeDatabase: () => database?.close(),
  closeListeners: () =>
    Promise.all(servers.map((server) => server.close())).then(() => {}),
  exit: (code) => process.exit(code),
  logger,
  stopBackground: () => metricsArchiveScheduler?.stop() ?? Promise.resolve(),
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
  loggerControl.setLogger(
    createJsonLineHubLogger({
      level: readHubLogLevel(process.env.ENOKI_HUB_LOG_LEVEL),
    }),
  );
  const port = readPort(process.env.PORT ?? "3000", "PORT");
  const hostname = process.env.HOST;
  const probePort = readPort(
    process.env.ENOKI_PROBE_PORT ?? "3001",
    "ENOKI_PROBE_PORT",
  );
  const probeHostname = process.env.ENOKI_PROBE_HOST ?? hostname;
  const webDistPath =
    process.env.ENOKI_WEB_DIST ??
    new URL("../../web/dist", import.meta.url).pathname;
  const config = createHubRuntimeConfigFromEnvironment(process.env, { logger });
  database = initializeHubDatabase(config.database);
  const liveUpdates = createLiveUpdateBroadcaster();
  metricsArchiveScheduler = createMetricsArchiveScheduler({
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

  servers.push(
    await createHubNodeServer({
      auth: config.auth,
      clockSkewThresholdMs: config.clockSkew.thresholdMs,
      database,
      hostname,
      hostStatus: config.hostStatus,
      installation: config.installation,
      logger,
      liveUpdates,
      port,
      probeAssets: config.probeAssets,
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
      probeAssets: config.probeAssets,
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
  fatal(
    "startup_failure",
    isHubConfigurationError(error) ? error.publicMessage : undefined,
  );
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
