import { Hono } from "hono";

import type { AuditRepository } from "../database/audit.js";

export function createAuditLogRoutes(services: { audit: AuditRepository }) {
  const routes = new Hono();

  routes.get("/", (context) => {
    const requestedLimit = context.req.query("limit");
    const limit = requestedLimit === undefined ? 100 : Number(requestedLimit);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      return context.json({ error: "invalid_audit_log_limit" }, 400);
    }

    return context.json({
      auditLog: services.audit.recent(limit).map((row) => ({
        action: row.action,
        actor: row.actor,
        details: row.detailsJson ? JSON.parse(row.detailsJson) : null,
        id: row.id,
        occurredAtMs: row.occurredAtMs,
        outcome: row.outcome,
        remoteAddress: row.remoteAddress,
        subjectId: row.subjectId,
        subjectType: row.subjectType,
        userAgent: row.userAgent,
      })),
    });
  });

  return routes;
}
