import type { HostsResponse } from "@enoki/api-client";
import { Hono } from "hono";
import type { Context } from "hono";
import { csrf } from "hono/csrf";
import { HTTPException } from "hono/http-exception";
import type { UpgradeWebSocket } from "hono/ws";

import { createAuditLogRoutes } from "./audit/routes.js";
import { type AuthConfig, type AuthEnvironment } from "./auth/config.js";
import type { OwnerSessionRepository } from "./auth/owner-session-repository.js";
import type { PasswordVerificationBudget } from "./auth/password-verification-budget.js";
import { createOwnerAuth } from "./auth/routes.js";
import {
  createHubRuntimeConfigFromEnvironment,
  type ProbeOperationConfig,
} from "./config.js";
import type { HostStatusThresholds } from "./database/hosts.js";
import type { HubDatabase } from "./database/index.js";
import type { InstallationCommandConfig } from "./enrollment/install-command.js";
import { createEnrollmentRoutes } from "./enrollment/routes.js";
import { defaultProbeOperationTimeouts } from "./hosts/probe-upgrade-timeout.js";
import {
  createHostRoutes,
  createProbeOperationRoutes,
} from "./hosts/routes.js";
import { projectHostSummaries } from "./hosts/summary-projection.js";
import {
  createHubRequestLoggingMiddleware,
  createNoopHubLogger,
  type HubListener,
  type HubLogger,
} from "./hub-logger.js";
import {
  createLiveUpdateBroadcaster,
  type LiveUpdateBroadcaster,
} from "./live-updates.js";
import { createManagementSecurityMiddleware } from "./management-security.js";
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
  listener?: HubListener;
  logger?: HubLogger;
  probeAssets?: HubProbeAssetOptions;
  hostStatus?: HostStatusThresholds;
  now?: () => number;
  ownerSessions?: OwnerSessionRepository;
  passwordVerificationBudget?: PasswordVerificationBudget;
  requestId?: () => string;
  probeOperations?: ProbeOperationConfig;
  probeOperationTokenSecret?: string;
  probeApiOrigin?: string;
  trustedProxyCidrs?: import("./network.js").TrustedProxyCidr[];
  liveUpdates?: LiveUpdateBroadcaster;
  webSocket?: {
    upgradeWebSocket: UpgradeWebSocket;
  };
  webDistPath?: string;
};

export type HubProbeAssetOptions = ProbeAssetRouteOptions & {
  trustedRootPublicKeyPem?: Buffer | string;
};

export type ProbeApiAppOptions = Pick<
  HubAppOptions,
  | "app"
  | "clockSkewThresholdMs"
  | "database"
  | "hostStatus"
  | "liveUpdates"
  | "logger"
  | "now"
  | "probeOperationTokenSecret"
  | "probeOperations"
  | "probeAssets"
  | "requestId"
  | "probeApiOrigin"
  | "trustedProxyCidrs"
>;

export function createHubApp(options: HubAppOptions = {}) {
  const app = options.app ?? new Hono();
  const managementOrigin = options.auth?.managementOrigin;
  app.onError(hubErrorResponse);
  const logger = options.logger ?? createNoopHubLogger();
  app.use(
    "*",
    createHubRequestLoggingMiddleware({
      listener: options.listener ?? "management",
      logger,
      now: options.now,
      requestId: options.requestId,
    }),
  );
  app.use("*", createManagementSecurityMiddleware());
  if (managementOrigin) {
    app.use("/api/web/*", csrf({ origin: managementOrigin }));
    app.use("/api/web/*", async (context, next) => {
      if (
        context.req.method === "POST" &&
        !isJsonContentType(context.req.header("content-type"))
      ) {
        return context.json({ error: "json_content_type_required" }, 415);
      }
      if (context.req.method === "POST") {
        try {
          await context.req.json();
        } catch {
          return context.json({ error: "invalid_json" }, 400);
        }
      }

      return next();
    });
  }
  const liveUpdates =
    options.liveUpdates ??
    (options.webSocket ? createLiveUpdateBroadcaster() : null);
  const auth = options.auth
    ? createOwnerAuth(options.auth, {
        audit: options.database?.audit,
        onSessionInvalidated: (sessionId) => {
          liveUpdates?.closeSession(sessionId);
        },
        ...(options.ownerSessions
          ? { ownerSessions: options.ownerSessions }
          : {}),
        ...(options.passwordVerificationBudget
          ? { passwordVerificationBudget: options.passwordVerificationBudget }
          : {}),
      })
    : null;

  mountProbeApiSurface(app, {
    ...options,
    liveUpdates: liveUpdates ?? undefined,
  });
  app.route("/api/probe", createProbeAssetRoutes(options.probeAssets));

  if (auth) {
    app.route("/api/web/auth", auth.routes);
    app.use("/api/web/*", auth.requireOwnerSession);
    if (options.webSocket) {
      app.get(
        "/api/web/ws",
        async (context, next) => {
          if (
            managementOrigin &&
            context.req.header("origin") !== managementOrigin
          ) {
            return context.text("Forbidden", 403);
          }

          return next();
        },
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
              const activeSessionId = auth.currentOwnerSessionId(
                context.req.raw,
              );

              if (sessionId && activeSessionId === sessionId) {
                liveUpdates?.addClient(socket, { sessionId: activeSessionId });
              } else {
                socket.close();
              }
            },
          };
        }),
      );
    }
    if (options.database) {
      const hostRouteServices = {
        audit: options.database.audit,
        hostStatus: options.hostStatus,
        hosts: options.database.hosts,
        liveUpdates,
        metrics: options.database.metrics,
        now: options.now,
        probeAssetDir: options.probeAssets?.assetDir,
        probeDistributionRootPublicKeyPem:
          options.probeAssets?.trustedRootPublicKeyPem,
        probeOperationTimeouts: options.probeOperations,
        probeConfigurations: options.database.probeConfigurations,
        probeOperations: options.database.probeOperations,
        snapshotCollectors: options.database.snapshotCollectors,
      };
      app.route(
        "/api/web/audit-log",
        createAuditLogRoutes({ audit: options.database.audit }),
      );
      app.route(
        "/api/web/enrollments",
        createEnrollmentRoutes({
          audit: options.database.audit,
          enrollments: options.database.enrollments,
          hostStatus: options.hostStatus,
          hosts: options.database.hosts,
          installation: options.installation,
          now: options.now,
          probeAssetDir: options.probeAssets?.assetDir,
          probeDistributionRootPublicKeyPem:
            options.probeAssets?.trustedRootPublicKeyPem,
        }),
      );
      app.route("/api/web/hosts", createHostRoutes(hostRouteServices));
      app.route(
        "/api/web/probe-operations",
        createProbeOperationRoutes({
          probeOperations: options.database.probeOperations,
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
      const response = {
        hosts: options.database
          ? projectHostSummaries(options.database, {
              nowMs,
              timeouts:
                options.probeOperations ?? defaultProbeOperationTimeouts,
              userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
            }).map((projection) => projection.response)
          : [],
      } satisfies HostsResponse;

      return context.json(response);
    });
  }

  if (options.webDistPath) {
    app.get("*", createWebAssetHandler(options.webDistPath));
  }

  return app;
}

function isJsonContentType(contentType: string | undefined) {
  return /^application\/json(?:\s*;|$)/i.test(contentType ?? "");
}

export function createProbeApiApp(options: ProbeApiAppOptions = {}) {
  const app = options.app ?? new Hono();
  app.onError(hubErrorResponse);
  app.use(
    "*",
    createHubRequestLoggingMiddleware({
      listener: "probe",
      logger: options.logger ?? createNoopHubLogger(),
      now: options.now,
      requestId: options.requestId,
    }),
  );

  mountProbeApiSurface(app, options);
  app.route("/api/probe", createProbeAssetRoutes(options.probeAssets));

  return app;
}

function hubErrorResponse(error: unknown, context: Context) {
  if (error instanceof HTTPException && error.status < 500) {
    return error.getResponse();
  }

  return context.text("Internal Server Error", 500);
}

export function createHubAppFromEnvironment(
  environment: AuthEnvironment,
  options: Omit<HubAppOptions, "auth"> = {},
) {
  const config = createHubRuntimeConfigFromEnvironment(environment, {
    logger: options.logger,
  });

  return createHubApp({
    ...options,
    auth: config.auth,
    clockSkewThresholdMs: config.clockSkew.thresholdMs,
    hostStatus: config.hostStatus,
    probeOperationTokenSecret: config.probeOperations.tokenSigningSecret,
    probeOperations: config.probeOperations,
    probeApiOrigin: config.network.probeApiOrigin,
    trustedProxyCidrs: config.network.trustedProxyCidrs,
  });
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
      audit: options.database.audit,
      enrollments: options.database.enrollments,
      hosts: options.database.hosts,
      metrics: options.database.metrics,
      probeConfigurations: options.database.probeConfigurations,
      probeOperations: options.database.probeOperations,
      probeOperationTimeouts: options.probeOperations,
      reportTransaction: options.database.reportTransaction,
      snapshotCollectors: options.database.snapshotCollectors,
      clockSkewThresholdMs: options.clockSkewThresholdMs,
      hostStatus: options.hostStatus,
      liveUpdates: options.liveUpdates ?? null,
      now: options.now,
      probeOperationTokenSecret: options.probeOperationTokenSecret,
      probeApiOrigin: options.probeApiOrigin,
      trustedProxyCidrs: options.trustedProxyCidrs,
    }),
  );
}
