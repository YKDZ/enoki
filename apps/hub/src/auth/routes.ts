import { randomBytes, timingSafeEqual } from "node:crypto";

import { vValidator } from "@hono/valibot-validator";
import { Hono } from "hono";
import type { MiddlewareHandler } from "hono";
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
  const routes = new Hono();

  if (config.noPasswordWebUi) {
    routes.post("/login", (context) => {
      return context.json({ authenticated: true });
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

        if (
          !config.ownerPassword ||
          !constantTimeEqual(password, config.ownerPassword)
        ) {
          recordLoginAuditEvent(context.req.raw, authServices, "failure");
          await authServices.delay(config.failureDelayMs);
          return context.json({ error: "invalid_credentials" }, 401);
        }

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

        recordLoginAuditEvent(context.req.raw, authServices, "success");

        return context.json({ authenticated: true });
      },
    );
  }

  routes.post("/logout", (context) => {
    if (config.noPasswordWebUi) {
      return context.json({ authenticated: true });
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

    return context.json({ authenticated: false });
  });

  routes.get("/session", (context) => {
    return context.json({
      authenticated: Boolean(currentOwnerSessionId(context.req.raw)),
    });
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
  request: Request,
  services: AuthServices,
  outcome: "success" | "failure",
) {
  services.audit?.record({
    action: "owner.login",
    actor: "owner",
    occurredAtMs: services.now(),
    outcome,
    userAgent: request.headers.get("user-agent") ?? undefined,
  });
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
