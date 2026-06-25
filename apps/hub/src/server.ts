import { createHubRuntimeConfigFromEnvironment } from "./config.js";
import { initializeHubDatabase } from "./database/index.js";
import { createLiveUpdateBroadcaster } from "./live-updates.js";
import { runMetricsArchiveMaintenance } from "./metrics-archive/maintenance.js";
import { createMetricsArchiveScheduler } from "./metrics-archive/scheduler.js";
import {
  createHubNodeServer,
  createProbeApiNodeServer,
  type HubNodeServer,
} from "./node-server.js";

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
const config = createHubRuntimeConfigFromEnvironment(process.env);
const database = initializeHubDatabase(config.database);
const liveUpdates = createLiveUpdateBroadcaster();
const servers: HubNodeServer[] = [];
const metricsArchiveScheduler = createMetricsArchiveScheduler({
  intervalMs: 60 * 60 * 1000,
  maintain: () => {
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
    liveUpdates,
    port,
    probeAssets: config.probeAssets,
    probeOperationTokenSecret: config.probeOperations.tokenSigningSecret,
    probeOperations: config.probeOperations,
    trustForwardedProbeHeaders: config.network.trustForwardedProbeHeaders,
    webDistPath,
  }),
);
console.log(`Enoki Hub listening on http://localhost:${port}`);

servers.push(
  await createProbeApiNodeServer({
    clockSkewThresholdMs: config.clockSkew.thresholdMs,
    database,
    hostname: probeHostname,
    hostStatus: config.hostStatus,
    liveUpdates,
    port: probePort,
    probeAssets: config.probeAssets,
    probeOperationTokenSecret: config.probeOperations.tokenSigningSecret,
    trustForwardedProbeHeaders: config.network.trustForwardedProbeHeaders,
  }),
);
console.log(`Enoki Probe API listening on http://localhost:${probePort}`);
metricsArchiveScheduler.start();

process.once("SIGINT", () => {
  void shutdown();
});
process.once("SIGTERM", () => {
  void shutdown();
});

async function shutdown() {
  await metricsArchiveScheduler.stop();
  await Promise.all(servers.map((server) => server.close()));
  database.close();
  process.exit(0);
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
