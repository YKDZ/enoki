import { randomBytes, timingSafeEqual } from "node:crypto";

import type { SessionResponse } from "@enoki/api-client";
import { getConnInfo } from "@hono/node-server/conninfo";
import { vValidator } from "@hono/valibot-validator";
import { Hono } from "hono";
import type { Context, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import * as v from "valibot";

import type { AuditRepository } from "../database/audit.js";
import type { AuthConfig } from "./config.js";

const loginSchema = v.object({
  password: v.pipe(v.string(), v.minLength(1)),
});

type SessionRecord = {
  expiresAt: number;
};

export type AuthServices = {
  audit?: AuditRepository;
  delay: (milliseconds: number) => Promise<void>;
  now: () => number;
  onSessionInvalidated?: (sessionId: string) => void;
};

export type OwnerAuth = {
  currentOwnerSessionId: (request: Request) => string | null;
  requireOwnerSession: MiddlewareHandler;
  routes: Hono;
};

const sessionDurationMs = 1000 * 60 * 60 * 24 * 7;
const failedLoginWindowMs = 15 * 60 * 1000;
const maxFailedLoginsPerWindow = 5;

export function createOwnerAuth(
  config: AuthConfig,
  services: Partial<AuthServices> = {},
): OwnerAuth {
  const authServices: AuthServices = {
    delay,
    now: Date.now,
    ...services,
  };
  const sessions = new Map<string, SessionRecord>();
  const failedLoginsByRemoteAddress = new Map<string, number[]>();
  const routes = new Hono();

  if (config.noPasswordWebUi) {
    routes.post("/login", (context) => {
      const response = { authenticated: true } satisfies SessionResponse;

      return context.json(response);
    });
  } else {
    routes.post(
      "/login",
      vValidator("json", loginSchema, (result, context) => {
        if (!result.success) {
          return context.json({ error: "invalid_request" }, 400);
        }

        return undefined;
      }),
      async (context) => {
        const { password } = context.req.valid("json");
        const remoteAddress = ownerRemoteAddress(context, config);
        const rateLimitKey = remoteAddress ?? "unknown";

        if (
          !config.ownerPassword ||
          !constantTimeEqual(password, config.ownerPassword)
        ) {
          const failedAttempts = recordFailedLoginAttempt(
            failedLoginsByRemoteAddress,
            rateLimitKey,
            authServices.now(),
          );
          recordLoginAuditEvent(context, authServices, "failure", config);
          if (failedAttempts > maxFailedLoginsPerWindow) {
            return context.json({ error: "too_many_login_attempts" }, 429);
          }

          await authServices.delay(config.failureDelayMs);
          return context.json({ error: "invalid_credentials" }, 401);
        }

        failedLoginsByRemoteAddress.delete(rateLimitKey);

        const sessionId = randomBytes(32).toString("base64url");
        sessions.set(sessionId, {
          expiresAt: authServices.now() + sessionDurationMs,
        });

        setCookie(context, config.sessionCookieName, sessionId, {
          httpOnly: true,
          maxAge: sessionDurationMs / 1000,
          path: "/",
          sameSite: "Lax",
          secure: isSecureRequest(context.req.raw, config),
        });

        recordLoginAuditEvent(context, authServices, "success", config);

        const response = { authenticated: true } satisfies SessionResponse;

        return context.json(response);
      },
    );
  }

  routes.post("/logout", (context) => {
    if (config.noPasswordWebUi) {
      const response = { authenticated: true } satisfies SessionResponse;

      return context.json(response);
    }

    const sessionId = getCookie(context, config.sessionCookieName);

    if (sessionId) {
      invalidateSession(sessionId);
    }

    deleteCookie(context, config.sessionCookieName, {
      path: "/",
      sameSite: "Lax",
      secure: isSecureRequest(context.req.raw, config),
    });

    const response = { authenticated: false } satisfies SessionResponse;

    return context.json(response);
  });

  routes.get("/session", (context) => {
    const response = {
      authenticated: Boolean(currentOwnerSessionId(context.req.raw)),
    } satisfies SessionResponse;

    return context.json(response);
  });

  const requireOwnerSession: MiddlewareHandler = async (context, next) => {
    if (config.noPasswordWebUi) {
      return next();
    }

    if (!currentOwnerSessionId(context.req.raw)) {
      return context.json({ error: "owner_session_required" }, 401);
    }

    return next();
  };

  function currentOwnerSessionId(request: Request) {
    if (config.noPasswordWebUi) {
      return "no-password-web-ui";
    }

    const sessionId = getCookieValue(request, config.sessionCookieName);

    if (!sessionId) {
      return null;
    }

    const session = sessions.get(sessionId);

    if (!session) {
      return null;
    }

    if (session.expiresAt <= authServices.now()) {
      invalidateSession(sessionId);
      return null;
    }

    return sessionId;
  }

  function invalidateSession(sessionId: string) {
    if (!sessions.delete(sessionId)) {
      return;
    }

    authServices.onSessionInvalidated?.(sessionId);
  }

  return {
    currentOwnerSessionId,
    requireOwnerSession,
    routes,
  };
}

function recordLoginAuditEvent(
  context: Context,
  services: AuthServices,
  outcome: "success" | "failure",
  config: AuthConfig,
) {
  const request = context.req.raw;

  services.audit?.record({
    action: "owner.login",
    actor: "owner",
    occurredAtMs: services.now(),
    outcome,
    remoteAddress: ownerRemoteAddress(context, config) ?? undefined,
    userAgent: request.headers.get("user-agent") ?? undefined,
  });
}

function recordFailedLoginAttempt(
  failedLoginsByRemoteAddress: Map<string, number[]>,
  remoteAddress: string,
  nowMs: number,
) {
  const windowStartMs = nowMs - failedLoginWindowMs;
  const attempts = (
    failedLoginsByRemoteAddress.get(remoteAddress) ?? []
  ).filter((attemptedAtMs) => attemptedAtMs > windowStartMs);

  attempts.push(nowMs);
  failedLoginsByRemoteAddress.set(remoteAddress, attempts);

  return attempts.length;
}

function ownerRemoteAddress(context: Context, config: AuthConfig) {
  const request = context.req.raw;
  const forwardedAddress = config.trustProxyHeaders
    ? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      request.headers.get("x-real-ip")?.trim() ||
      null
    : null;

  return forwardedAddress || directRemoteAddress(context);
}

function directRemoteAddress(context: Context) {
  try {
    return normalizeRemoteAddress(getConnInfo(context).remote.address);
  } catch {
    return null;
  }
}

function normalizeRemoteAddress(address: string | undefined) {
  if (!address) {
    return null;
  }

  return address.startsWith("::ffff:") ? address.slice(7) : address;
}

function isSecureRequest(request: Request, config: AuthConfig) {
  const url = new URL(request.url);

  if (url.protocol === "https:" || config.publicHttps) {
    return true;
  }

  if (!config.trustProxyHeaders) {
    return false;
  }

  const forwardedProto = request.headers
    .get("x-forwarded-proto")
    ?.split(",")[0]
    ?.trim()
    .toLowerCase();

  return forwardedProto === "https";
}

function getCookieValue(request: Request, name: string) {
  const cookieHeader = request.headers.get("cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";").map((cookie) => cookie.trim());
  const cookie = cookies.find((value) => value.startsWith(`${name}=`));

  return cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : null;
}

function constantTimeEqual(a: string, b: string) {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);

  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  return timingSafeEqual(aBuffer, bBuffer);
}

function delay(milliseconds: number) {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
