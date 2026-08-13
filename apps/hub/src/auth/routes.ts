import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import type { SessionResponse } from "@enoki/api-client";
import { getConnInfo } from "@hono/node-server/conninfo";
import { vValidator } from "@hono/valibot-validator";
import { Hono } from "hono";
import type { Context, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import * as v from "valibot";

import type { AuditRepository } from "../database/audit.js";
import { deriveObservedIp } from "../network.js";
import type { AuthConfig } from "./config.js";
import { createMemoryOwnerSessionRepository } from "./memory-owner-session-repository.js";
import type {
  OwnerSessionRecord,
  OwnerSessionRepository,
} from "./owner-session-repository.js";
import {
  createMemoryPasswordVerificationBudget,
  type PasswordVerificationBudget,
} from "./password-verification-budget.js";

const loginSchema = v.object({
  password: v.pipe(v.string(), v.minLength(1)),
});

export type AuthServices = {
  audit?: AuditRepository;
  delay: (milliseconds: number) => Promise<void>;
  now: () => number;
  onSessionInvalidated?: (sessionId: string) => void;
  ownerSessions: OwnerSessionRepository;
  passwordVerificationBudget: PasswordVerificationBudget;
};

export type OwnerAuth = {
  currentOwnerSessionId: (request: Request) => string | null;
  requireOwnerSession: MiddlewareHandler;
  routes: Hono;
};

const sessionDurationMs = 1000 * 60 * 60 * 24 * 7;
const maxOwnerSessions = 8;
const maxFailedLoginDelayMs = 1_000;

export function createOwnerAuth(
  config: AuthConfig,
  services: Partial<AuthServices> = {},
): OwnerAuth {
  const authServices: AuthServices = {
    delay,
    now: Date.now,
    ownerSessions: createMemoryOwnerSessionRepository(),
    passwordVerificationBudget: createMemoryPasswordVerificationBudget(),
    ...services,
  };
  let nextSessionSequence = 0;
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
        const budget = authServices.passwordVerificationBudget.consume();

        if (!budget.accepted) {
          context.header("Retry-After", String(budget.retryAfterSeconds));
          return context.json({ error: "too_many_login_attempts" }, 429);
        }

        if (
          !config.ownerPassword ||
          !constantTimeEqual(password, config.ownerPassword)
        ) {
          recordLoginAuditEvent(context, authServices, "failure", config);
          await authServices.delay(
            Math.max(0, Math.min(config.failureDelayMs, maxFailedLoginDelayMs)),
          );
          return context.json({ error: "invalid_credentials" }, 401);
        }

        const createdAtMs = authServices.now();
        removeExpiredSessions(createdAtMs);
        evictSessionsToMakeRoom();

        const token = randomBytes(32).toString("base64url");
        authServices.ownerSessions.save({
          createdAtMs,
          expiresAtMs: createdAtMs + sessionDurationMs,
          sequence: nextSessionSequence,
          tokenDigest: digestSessionToken(token),
        });
        nextSessionSequence += 1;

        setCookie(context, config.sessionCookieName, token, {
          httpOnly: true,
          maxAge: sessionDurationMs / 1000,
          path: "/api/web",
          sameSite: "Strict",
          secure: isSecureManagementOrigin(config),
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

    const token = getCookie(context, config.sessionCookieName);

    if (token) {
      invalidateSession(digestSessionToken(token));
    }

    deleteCookie(context, config.sessionCookieName, {
      path: "/api/web",
      sameSite: "Strict",
      secure: isSecureManagementOrigin(config),
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

    const token = getCookieValue(request, config.sessionCookieName);

    if (!token) {
      return null;
    }

    const tokenDigest = digestSessionToken(token);
    const session = authServices.ownerSessions.findByTokenDigest(tokenDigest);

    if (!session) {
      return null;
    }

    if (session.expiresAtMs <= authServices.now()) {
      invalidateSession(tokenDigest);
      return null;
    }

    return tokenDigest;
  }

  function invalidateSession(sessionId: string) {
    if (!authServices.ownerSessions.deleteByTokenDigest(sessionId)) {
      return;
    }

    authServices.onSessionInvalidated?.(sessionId);
  }

  function removeExpiredSessions(nowMs: number) {
    for (const session of authServices.ownerSessions.list()) {
      if (session.expiresAtMs <= nowMs) {
        invalidateSession(session.tokenDigest);
      }
    }
  }

  function evictSessionsToMakeRoom() {
    const sessionsByCreationOrder = [...authServices.ownerSessions.list()].sort(
      compareSessionsByCreationOrder,
    );

    while (sessionsByCreationOrder.length >= maxOwnerSessions) {
      const oldest = sessionsByCreationOrder.shift();
      if (oldest) {
        invalidateSession(oldest.tokenDigest);
      }
    }
  }

  return {
    currentOwnerSessionId,
    requireOwnerSession,
    routes,
  };
}

function digestSessionToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

function compareSessionsByCreationOrder(
  left: OwnerSessionRecord,
  right: OwnerSessionRecord,
) {
  return (
    left.createdAtMs - right.createdAtMs ||
    left.sequence - right.sequence ||
    left.tokenDigest.localeCompare(right.tokenDigest)
  );
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

function ownerRemoteAddress(context: Context, config: AuthConfig) {
  const request = context.req.raw;
  return deriveObservedIp({
    directPeer: directRemoteAddress(context),
    trustedProxyCidrs: config.trustedProxyCidrs ?? [],
    xForwardedFor: request.headers.get("x-forwarded-for"),
  });
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

function isSecureManagementOrigin(config: AuthConfig) {
  return (
    new URL(config.managementOrigin ?? "http://localhost").protocol === "https:"
  );
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
