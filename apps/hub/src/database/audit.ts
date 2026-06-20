import { desc } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";

import { auditLog, type AuditLogRow } from "./schema.js";

type AuditDatabase = BetterSQLite3Database<typeof import("./schema.js")>;

export type AuditEventInput = {
  action: string;
  actor: "owner" | "system";
  details?: Record<string, unknown>;
  occurredAtMs: number;
  outcome: "success" | "failure";
  remoteAddress?: string;
  subjectId?: string;
  subjectType?: string;
  userAgent?: string;
};

export type AuditRepository = {
  recent: (limit?: number) => AuditLogRow[];
  record: (event: AuditEventInput) => AuditLogRow;
};

export function createAuditRepository(
  database: AuditDatabase,
): AuditRepository {
  return {
    recent(limit = 20) {
      return database
        .select()
        .from(auditLog)
        .orderBy(desc(auditLog.occurredAtMs), desc(auditLog.id))
        .limit(limit)
        .all();
    },
    record(event) {
      const row = database
        .insert(auditLog)
        .values({
          action: event.action,
          actor: event.actor,
          detailsJson: event.details ? JSON.stringify(event.details) : null,
          occurredAtMs: event.occurredAtMs,
          outcome: event.outcome,
          remoteAddress: event.remoteAddress ?? null,
          subjectId: event.subjectId ?? null,
          subjectType: event.subjectType ?? null,
          userAgent: event.userAgent ?? null,
        })
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to record audit event.");
      }

      return row;
    },
  };
}
