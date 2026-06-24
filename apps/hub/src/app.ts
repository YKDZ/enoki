import { Hono } from "hono";
import type { UpgradeWebSocket } from "hono/ws";

import { type AuthConfig, type AuthEnvironment } from "./auth/config.js";
import { createOwnerAuth } from "./auth/routes.js";
import {
  createHubRuntimeConfigFromEnvironment,
  type ProbeOperationConfig,
} from "./config.js";
import type { HostStatusThresholds } from "./database/hosts.js";
import type { HubDatabase } from "./database/index.js";
import type { InstallationCommandConfig } from "./enrollment/install-command.js";
import { createEnrollmentRoutes } from "./enrollment/routes.js";
import { createHostRoutes } from "./hosts/routes.js";
import {
  createLiveUpdateBroadcaster,
  type LiveUpdateBroadcaster,
} from "./live-updates.js";
import {
  createHostProbeConfigurationRoutes,
  createProbeConfigurationRoutes,
} from "./probe-configuration/routes.js";
import {
  createProbeAssetRoutes,
  type ProbeAssetRouteOptions,
} from "./probe/assets.js";
import { createProbeRoutes } from "./probe/routes.js";
import { createWebAssetHandler } from "./web-assets.js";

type HubHealth = {
  service: "enoki-hub";
  status: "ok";
};

export type HubAppOptions = {
  app?: Hono;
  auth?: AuthConfig;
  clockSkewThresholdMs?: number;
  database?: HubDatabase;
  installation?: InstallationCommandConfig;
  probeAssets?: ProbeAssetRouteOptions;
  hostStatus?: HostStatusThresholds;
  now?: () => number;
  probeOperations?: ProbeOperationConfig;
  probeOperationTokenSecret?: string;
  trustForwardedProbeHeaders?: boolean;
  liveUpdates?: LiveUpdateBroadcaster;
  webSocket?: {
    upgradeWebSocket: UpgradeWebSocket;
  };
  webDistPath?: string;
};

export type ProbeApiAppOptions = Pick<
  HubAppOptions,
  | "app"
  | "clockSkewThresholdMs"
  | "database"
  | "hostStatus"
  | "liveUpdates"
  | "now"
  | "probeOperationTokenSecret"
  | "probeOperations"
  | "probeAssets"
  | "trustForwardedProbeHeaders"
>;

export function createHubApp(options: HubAppOptions = {}) {
  const app = options.app ?? new Hono();
  const liveUpdates =
    options.liveUpdates ??
    (options.webSocket ? createLiveUpdateBroadcaster() : null);
  const auth = options.auth
    ? createOwnerAuth(options.auth, {
        audit: options.database?.audit,
        onSessionInvalidated: (sessionId) => {
          liveUpdates?.closeSession(sessionId);
        },
      })
    : null;

  mountProbeApiSurface(app, {
    ...options,
    liveUpdates: liveUpdates ?? undefined,
  });
  app.route(
    "/api/probe",
    createProbeAssetRoutes({
      assetDir: options.probeAssets?.assetDir,
      installScriptPath: options.probeAssets?.installScriptPath,
    }),
  );

  if (auth) {
    app.route("/api/web/auth", auth.routes);
    app.use("/api/web/*", auth.requireOwnerSession);
    if (options.webSocket) {
      app.get(
        "/api/web/ws",
        options.webSocket.upgradeWebSocket((context) => {
          const sessionId = auth.currentOwnerSessionId(context.req.raw);

          return {
            onClose(_event, socket) {
              liveUpdates?.removeClient(socket);
            },
            onMessage(event, socket) {
              liveUpdates?.handleClientMessage(socket, event.data);
            },
            onOpen(_event, socket) {
              if (sessionId) {
                liveUpdates?.addClient(socket, { sessionId });
              } else {
                socket.close();
              }
            },
          };
        }),
      );
    }
    if (options.database) {
      app.route(
        "/api/web/enrollments",
        createEnrollmentRoutes({
          audit: options.database.audit,
          enrollments: options.database.enrollments,
          installation: options.installation,
          now: options.now,
        }),
      );
      app.route(
        "/api/web/hosts",
        createHostRoutes({
          audit: options.database.audit,
          hostStatus: options.hostStatus,
          hosts: options.database.hosts,
          metrics: options.database.metrics,
          now: options.now,
          probeAssetDir: options.probeAssets?.assetDir,
          probeOperationTimeouts: options.probeOperations,
          probeConfigurations: options.database.probeConfigurations,
          probeOperations: options.database.probeOperations,
          snapshotCollectors: options.database.snapshotCollectors,
        }),
      );
      app.route(
        "/api/web/probe-configuration",
        createProbeConfigurationRoutes({
          audit: options.database.audit,
          now: options.now,
          probeConfigurations: options.database.probeConfigurations,
        }),
      );
      app.route(
        "/api/web/hosts/:hostId/probe-configuration",
        createHostProbeConfigurationRoutes({
          audit: options.database.audit,
          hosts: options.database.hosts,
          now: options.now,
          probeConfigurations: options.database.probeConfigurations,
        }),
      );
    }
    app.get("/api/web/hosts", (context) => {
      const nowMs = options.now?.() ?? Date.now();

      return context.json({
        hosts:
          options.database?.hosts
            .listSummaries({
              hostProfileForHost: (hostId) =>
                options.database?.snapshotCollectors.hostProfile.read(hostId) ??
                null,
              latestMetricForHost: (hostId) =>
                options.database?.metrics.findLatestSample(hostId) ?? null,
              nowMs,
              probeConfigurationForHost: (hostId) => {
                const effective =
                  options.database?.probeConfigurations.getEffectiveForHost(
                    hostId,
                  );

                return {
                  mode: effective?.mode ?? "inherit",
                  version: effective?.configuration.version ?? "default-v1",
                };
              },
              thresholds: options.hostStatus,
            })
            .map((host) => {
              const effective =
                options.database?.probeConfigurations.getEffectiveForHost(
                  host.id,
                );
              const intervalSeconds =
                effective?.configuration.metricsCollectionIntervalSeconds ?? 5;

              return {
                ...host,
                latestMetrics: host.latestMetrics
                  ? {
                      ...host.latestMetrics,
                      networkRxBitsPerSecond: bitsPerSecond(
                        host.latestMetrics.networkRxBytesDelta,
                        intervalSeconds,
                      ),
                      networkTxBitsPerSecond: bitsPerSecond(
                        host.latestMetrics.networkTxBytesDelta,
                        intervalSeconds,
                      ),
                    }
                  : null,
              };
            }) ?? [],
      });
    });
  }

  if (options.webDistPath) {
    app.get("*", createWebAssetHandler(options.webDistPath));
  }

  return app;
}

export function createProbeApiApp(options: ProbeApiAppOptions = {}) {
  const app = options.app ?? new Hono();

  mountProbeApiSurface(app, options);
  app.route(
    "/api/probe",
    createProbeAssetRoutes({
      assetDir: options.probeAssets?.assetDir,
      installScriptPath: options.probeAssets?.installScriptPath,
    }),
  );

  return app;
}

export function createHubAppFromEnvironment(
  environment: AuthEnvironment,
  options: Omit<HubAppOptions, "auth"> = {},
) {
  const config = createHubRuntimeConfigFromEnvironment(environment);

  return createHubApp({
    ...options,
    auth: config.auth,
    clockSkewThresholdMs: config.clockSkew.thresholdMs,
    hostStatus: config.hostStatus,
    probeOperationTokenSecret: config.probeOperations.tokenSigningSecret,
    probeOperations: config.probeOperations,
  });
}

function bitsPerSecond(bytes: number | null, intervalSeconds: number) {
  if (bytes === null || intervalSeconds <= 0) {
    return null;
  }

  return (bytes * 8) / intervalSeconds;
}

function mountProbeApiSurface(app: Hono, options: ProbeApiAppOptions) {
  app.get("/api/health", (context) =>
    context.json<HubHealth>({
      service: "enoki-hub",
      status: "ok",
    }),
  );

  if (!options.database) {
    return;
  }

  app.route(
    "/api/probe",
    createProbeRoutes({
      enrollments: options.database.enrollments,
      hosts: options.database.hosts,
      metrics: options.database.metrics,
      probeConfigurations: options.database.probeConfigurations,
      probeOperations: options.database.probeOperations,
      snapshotCollectors: options.database.snapshotCollectors,
      clockSkewThresholdMs: options.clockSkewThresholdMs,
      hostStatus: options.hostStatus,
      liveUpdates: options.liveUpdates ?? null,
      now: options.now,
      probeOperationTokenSecret: options.probeOperationTokenSecret,
      trustForwardedHeaders: options.trustForwardedProbeHeaders,
    }),
  );
}
