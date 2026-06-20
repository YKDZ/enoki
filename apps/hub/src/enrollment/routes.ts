import { createHash, randomBytes } from "node:crypto";

import { Hono } from "hono";

import type { AuditRepository } from "../database/audit.js";
import type { EnrollmentRepository } from "../database/enrollments.js";
import {
  createDefaultInstallationCommandConfig,
  type InstallationCommandConfig,
  renderInstallCommand,
} from "./install-command.js";

const enrollmentTokenTtlMs = 1000 * 60 * 15;

export type EnrollmentRouteServices = {
  audit?: AuditRepository;
  enrollments: EnrollmentRepository;
  installation?: InstallationCommandConfig;
  now?: () => number;
};

export function createEnrollmentRoutes(services: EnrollmentRouteServices) {
  const routes = new Hono();
  const now = services.now ?? Date.now;
  const installation =
    services.installation ?? createDefaultInstallationCommandConfig();

  routes.post("/", (context) => {
    const createdAtMs = now();
    const expiresAtMs = createdAtMs + enrollmentTokenTtlMs;
    const enrollmentToken = createEnrollmentToken();
    const row = services.enrollments.createPending({
      createdAtMs,
      expiresAtMs,
      tokenHash: hashSecret(enrollmentToken),
    });

    services.audit?.record({
      action: "enrollment_token.create",
      actor: "owner",
      details: {
        expiresAtMs,
      },
      occurredAtMs: createdAtMs,
      outcome: "success",
      subjectId: String(row.id),
      subjectType: "enrollment_token",
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });

    return context.json(
      {
        enrollmentToken,
        expiresAtMs,
        ...renderInstallCommand(installation, {
          enrollmentToken,
          requestUrl: context.req.url,
        }),
      },
      201,
    );
  });

  return routes;
}

export function hashSecret(secret: string) {
  return createHash("sha256").update(secret).digest("hex");
}

function createEnrollmentToken() {
  return `enk_enroll_${randomBytes(32).toString("base64url")}`;
}
