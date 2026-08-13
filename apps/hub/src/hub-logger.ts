import { randomUUID } from "node:crypto";

import type { MiddlewareHandler } from "hono";

export type HubLogLevel = "debug" | "info" | "warn" | "error";

export type HubLogEvent = {
  component: HubLogComponent;
  configurationMessage?: string;
  durationMs?: number;
  event: HubLogEventName;
  level: HubLogLevel;
  listener?: HubListener;
  method?: string;
  outcome?: string;
  requestId?: string;
  routeId?: HubRouteId;
  status?: number;
};

export type HubLogger = {
  log: (event: HubLogEvent) => void;
  withContext: (
    context: Pick<HubLogEvent, "component" | "requestId">,
  ) => HubLogger;
};

export type HubListener = "management" | "probe";

type HubLogComponent =
  | "hub"
  | "management-listener"
  | "probe-listener"
  | "metrics-archive";

export type HubLogEventName =
  | "background.completed"
  | "background.failed"
  | "configuration.warning"
  | "listener.started"
  | "process.fatal"
  | "process.shutdown.completed"
  | "process.shutdown.started"
  | "request.completed";

export type HubRouteId =
  | "health"
  | "probe_asset"
  | "probe_configuration"
  | "probe_operation_status"
  | "probe_operation_token_validation"
  | "probe_registration"
  | "probe_report"
  | "unknown"
  | "web_audit_log"
  | "web_auth_login"
  | "web_auth_logout"
  | "web_auth_session"
  | "web_enrollment"
  | "web_enrollments"
  | "web_host"
  | "web_host_metadata"
  | "web_host_metrics"
  | "web_hosts"
  | "web_probe_configuration"
  | "web_probe_operation"
  | "web_probe_upgrade_request"
  | "web_static_asset";

type WriteLine = (line: string) => void;

const defaultLevel: HubLogLevel = "info";
const maxDurationMs = 3_600_000;
const maxConfigurationMessageLength = 320;
const maxRequestIdLength = 64;
const levelRank: Record<HubLogLevel, number> = {
  debug: 10,
  error: 40,
  info: 20,
  warn: 30,
};

const components = new Set<HubLogComponent>([
  "hub",
  "management-listener",
  "metrics-archive",
  "probe-listener",
]);
const eventNames = new Set<HubLogEventName>([
  "background.completed",
  "background.failed",
  "configuration.warning",
  "listener.started",
  "process.fatal",
  "process.shutdown.completed",
  "process.shutdown.started",
  "request.completed",
]);
const routeIds = new Set<HubRouteId>([
  "health",
  "probe_asset",
  "probe_configuration",
  "probe_operation_status",
  "probe_operation_token_validation",
  "probe_registration",
  "probe_report",
  "unknown",
  "web_audit_log",
  "web_auth_login",
  "web_auth_logout",
  "web_auth_session",
  "web_enrollment",
  "web_enrollments",
  "web_host",
  "web_host_metadata",
  "web_host_metrics",
  "web_hosts",
  "web_probe_configuration",
  "web_probe_operation",
  "web_probe_upgrade_request",
  "web_static_asset",
]);
const knownRequestOutcomes = new Set([
  "enrollment_not_found",
  "existing_host_reenrollment_unavailable",
  "host_not_found",
  "host_not_upgradeable",
  "invalid_audit_log_limit",
  "invalid_credentials",
  "invalid_enrollment_target",
  "invalid_enrollment_token",
  "invalid_probe_configuration",
  "invalid_probe_configuration_mode",
  "invalid_request",
  "malformed_json",
  "malformed_probe_operation_acknowledgement",
  "malformed_probe_operation_status",
  "malformed_probe_operation_token_validation",
  "malformed_probe_registration",
  "malformed_probe_report",
  "owner_session_required",
  "payload_compression_not_supported",
  "probe_identity_required",
  "probe_operation_active",
  "probe_operation_not_acknowledgeable",
  "probe_operation_not_found",
  "probe_operation_status_invalid",
  "probe_operation_token_expired",
  "probe_operation_token_invalid",
  "probe_operation_token_operation_closed",
  "probe_operation_token_operation_mismatch",
  "probe_operation_token_probe_mismatch",
  "probe_operation_token_target_mismatch",
  "probe_public_key_required",
  "probe_registration_too_large",
  "probe_report_too_large",
  "probe_upgrade_request_active",
  "probe_upgrade_request_not_cancelable",
  "snapshot_hash_mismatch",
  "too_many_login_attempts",
]);

export function createJsonLineHubLogger(
  options: {
    level?: HubLogLevel;
    stderr?: WriteLine;
    stdout?: WriteLine;
  } = {},
): HubLogger {
  const level = options.level ?? defaultLevel;
  const stdout =
    options.stdout ?? ((line: string) => process.stdout.write(line));
  const stderr =
    options.stderr ?? ((line: string) => process.stderr.write(line));

  return createHubLogger(level, (event) => {
    const line = `${JSON.stringify(event)}\n`;
    if (event.level === "error") {
      stderr(line);
      return;
    }

    stdout(line);
  });
}

export function createMemoryHubLogger(
  options: {
    level?: HubLogLevel;
  } = {},
) {
  const events: HubLogEvent[] = [];

  return {
    events,
    logger: createHubLogger(options.level ?? defaultLevel, (event) => {
      events.push(event);
    }),
  };
}

export function createNoopHubLogger(): HubLogger {
  const logger: HubLogger = {
    log() {},
    withContext() {
      return logger;
    },
  };

  return logger;
}

export function createDelegatingHubLogger(initial: HubLogger) {
  let delegate = initial;

  const proxy = (
    context?: Pick<HubLogEvent, "component" | "requestId">,
  ): HubLogger => ({
    log(event) {
      const target = context ? delegate.withContext(context) : delegate;
      target.log(event);
    },
    withContext(nextContext) {
      return proxy(context ? { ...context, ...nextContext } : nextContext);
    },
  });

  return {
    logger: proxy(),
    setLogger(logger: HubLogger) {
      delegate = logger;
    },
  };
}

export function readHubLogLevel(value: string | undefined): HubLogLevel {
  if (value === undefined || value === "") {
    return defaultLevel;
  }

  if (
    value === "debug" ||
    value === "info" ||
    value === "warn" ||
    value === "error"
  ) {
    return value;
  }

  throw new Error("ENOKI_HUB_LOG_LEVEL must be debug, info, warn, or error.");
}

export function createHubRequestLoggingMiddleware(options: {
  listener: HubListener;
  logger: HubLogger;
  now?: () => number;
  requestId?: () => string;
}): MiddlewareHandler {
  const now = options.now ?? Date.now;
  const requestId = options.requestId ?? (() => randomUUID());
  const component =
    options.listener === "management"
      ? "management-listener"
      : "probe-listener";

  return async (context, next) => {
    const startedAtMs = now();
    const generatedRequestId = boundedRequestId(requestId());
    const logger = options.logger.withContext({
      component,
      requestId: generatedRequestId,
    });

    try {
      await next();
    } catch (error) {
      context.header("x-request-id", generatedRequestId);
      logger.log({
        component,
        durationMs: boundedDuration(now() - startedAtMs),
        event: "request.completed",
        level: "error",
        listener: options.listener,
        method: context.req.method,
        outcome: "internal_error",
        requestId: generatedRequestId,
        routeId: hubRouteId(context.req.method, context.req.path),
        status: 500,
      });
      throw error;
    }

    context.header("x-request-id", generatedRequestId);
    const status = context.res.status;
    const routeId = completedHubRouteId(
      context.req.method,
      context.req.path,
      context.res,
    );
    logger.log({
      component,
      durationMs: boundedDuration(now() - startedAtMs),
      event: "request.completed",
      level: requestLogLevel(routeId, context.req.method, status),
      listener: options.listener,
      method: context.req.method,
      outcome: await requestOutcome(context.res),
      requestId: generatedRequestId,
      routeId,
      status,
    });
  };
}

function completedHubRouteId(
  method: string,
  pathname: string,
  response: Response,
): HubRouteId {
  const routeId = hubRouteId(method, pathname);
  if (routeId !== "unknown") return routeId;

  if (
    method === "GET" &&
    !pathname.startsWith("/api/") &&
    response.status < 400 &&
    response.headers.has("content-type")
  ) {
    return "web_static_asset";
  }

  return "unknown";
}

export function hubRouteId(method: string, pathname: string): HubRouteId {
  if (method === "GET" && pathname === "/api/health") return "health";
  if (method === "POST" && pathname === "/api/web/auth/login")
    return "web_auth_login";
  if (method === "POST" && pathname === "/api/web/auth/logout")
    return "web_auth_logout";
  if (method === "GET" && pathname === "/api/web/auth/session")
    return "web_auth_session";
  if (method === "GET" && pathname === "/api/web/audit-log")
    return "web_audit_log";
  if (method === "POST" && pathname === "/api/web/enrollments")
    return "web_enrollments";
  if (
    method === "POST" &&
    /^\/api\/web\/enrollments\/existing-host\/[^/]+$/.test(pathname)
  ) {
    return "web_enrollments";
  }
  if (method === "GET" && /^\/api\/web\/enrollments\/[^/]+$/.test(pathname))
    return "web_enrollment";
  if (method === "GET" && pathname === "/api/web/hosts") return "web_hosts";
  if (method === "GET" && /^\/api\/web\/hosts\/[^/]+\/metrics$/.test(pathname))
    return "web_host_metrics";
  if (method === "PUT" && /^\/api\/web\/hosts\/[^/]+\/metadata$/.test(pathname))
    return "web_host_metadata";
  if (
    (method === "GET" || method === "PUT") &&
    /^\/api\/web\/hosts\/[^/]+\/probe-configuration$/.test(pathname)
  ) {
    return "web_probe_configuration";
  }
  if (
    (method === "GET" || method === "DELETE") &&
    /^\/api\/web\/hosts\/[^/]+$/.test(pathname)
  )
    return "web_host";
  if (
    (method === "GET" || method === "PUT") &&
    pathname === "/api/web/probe-configuration"
  )
    return "web_probe_configuration";
  if (
    method === "GET" &&
    /^\/api\/web\/probe-operations\/[^/]+$/.test(pathname)
  )
    return "web_probe_operation";
  if (method === "POST" && pathname === "/api/probe/register")
    return "probe_registration";
  if (method === "POST" && pathname === "/api/probe/report")
    return "probe_report";
  if (method === "POST" && pathname === "/api/probe/config")
    return "probe_configuration";
  if (
    method === "POST" &&
    /^\/api\/probe\/operations\/[^/]+\/token\/validate$/.test(pathname)
  ) {
    return "probe_operation_token_validation";
  }
  if (
    method === "POST" &&
    /^\/api\/probe\/operations\/[^/]+\/status$/.test(pathname)
  ) {
    return "probe_operation_status";
  }
  if (method === "GET" && pathname.startsWith("/api/probe/assets/")) {
    return "probe_asset";
  }
  if (
    (method === "POST" &&
      /^\/api\/web\/hosts\/[^/]+\/probe-upgrade-requests$/.test(pathname)) ||
    (method === "DELETE" &&
      /^\/api\/web\/hosts\/[^/]+\/probe-upgrade-requests\/[^/]+$/.test(
        pathname,
      ))
  ) {
    return "web_probe_upgrade_request";
  }

  return "unknown";
}

function createHubLogger(
  level: HubLogLevel,
  write: (event: HubLogEvent) => void,
): HubLogger {
  const withContext = (
    context: Pick<HubLogEvent, "component" | "requestId">,
  ): HubLogger => ({
    log(event) {
      log({ ...context, ...event });
    },
    withContext(nextContext) {
      return withContext({ ...context, ...nextContext });
    },
  });

  const log = (event: HubLogEvent) => {
    if (levelRank[event.level] < levelRank[level]) {
      return;
    }

    write(sanitizeHubLogEvent(event));
  };

  return { log, withContext };
}

function sanitizeHubLogEvent(event: HubLogEvent): HubLogEvent {
  const sanitized: HubLogEvent = {
    component: components.has(event.component) ? event.component : "hub",
    event: eventNames.has(event.event) ? event.event : "configuration.warning",
    level: event.level,
  };

  if (event.durationMs !== undefined)
    sanitized.durationMs = boundedDuration(event.durationMs);
  if (event.configurationMessage !== undefined) {
    sanitized.configurationMessage = boundedConfigurationMessage(
      event.configurationMessage,
    );
  }
  if (event.listener === "management" || event.listener === "probe")
    sanitized.listener = event.listener;
  if (event.method !== undefined)
    sanitized.method = boundedMethod(event.method);
  if (event.outcome !== undefined)
    sanitized.outcome = boundedOutcome(event.outcome);
  if (event.requestId !== undefined)
    sanitized.requestId = boundedRequestId(event.requestId);
  if (event.routeId !== undefined) {
    sanitized.routeId = routeIds.has(event.routeId) ? event.routeId : "unknown";
  }
  if (event.status !== undefined)
    sanitized.status = boundedStatus(event.status);

  return sanitized;
}

function requestLogLevel(
  routeId: HubRouteId,
  method: string,
  status: number,
): HubLogLevel {
  if (status >= 500) return "error";
  if (
    routeId === "health" ||
    routeId === "probe_configuration" ||
    routeId === "web_static_asset" ||
    routeId === "probe_report"
  ) {
    return "debug";
  }
  if (method === "GET" || method === "HEAD" || status >= 400) return "debug";

  return "info";
}

async function requestOutcome(response: Response) {
  const status = response.status;
  if (status >= 500) return "internal_error";
  if (status >= 400) {
    const contentType = response.headers.get("content-type");
    if (contentType?.startsWith("application/json")) {
      try {
        const body = (await response.clone().json()) as { error?: unknown };
        if (
          typeof body.error === "string" &&
          knownRequestOutcomes.has(body.error)
        ) {
          return body.error;
        }
      } catch {
        // A malformed error response still receives the bounded HTTP outcome.
      }
    }

    return `http_${status}`;
  }
  return "ok";
}

function boundedRequestId(value: string) {
  const candidate = value.slice(0, maxRequestIdLength);
  return /^[a-zA-Z0-9_-]{8,64}$/.test(candidate) ? candidate : randomUUID();
}

function boundedDuration(value: number) {
  if (!Number.isFinite(value)) return maxDurationMs;
  return Math.max(0, Math.min(Math.floor(value), maxDurationMs));
}

function boundedConfigurationMessage(value: string) {
  return value
    .replace(/[\r\n\t]/g, " ")
    .slice(0, maxConfigurationMessageLength);
}

function boundedMethod(value: string) {
  return /^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(value)
    ? value
    : "OTHER";
}

function boundedOutcome(value: string) {
  return /^[a-z0-9_]{1,64}$/.test(value) ? value : "unknown";
}

function boundedStatus(value: number) {
  return Number.isInteger(value) && value >= 100 && value <= 599 ? value : 500;
}
