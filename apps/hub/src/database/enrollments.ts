import { and, eq, gt, isNull } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";

import { enrollmentTokens, type EnrollmentTokenRow } from "./schema.js";

type EnrollmentDatabase = BetterSQLite3Database<typeof import("./schema.js")>;

export type CreatePendingEnrollmentInput = {
  createdAtMs: number;
  expiresAtMs: number;
  tokenHash: string;
};

export type EnrollmentRepository = {
  createPending: (input: CreatePendingEnrollmentInput) => EnrollmentTokenRow;
  consume: (tokenHash: string, usedAtMs: number) => EnrollmentTokenRow | null;
};

export function createEnrollmentRepository(
  database: EnrollmentDatabase,
): EnrollmentRepository {
  return {
    createPending(input) {
      const row = database
        .insert(enrollmentTokens)
        .values(input)
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to create Enrollment Token.");
      }

      return row;
    },
    consume(tokenHash, usedAtMs) {
      return (
        database
          .update(enrollmentTokens)
          .set({ usedAtMs })
          .where(
            and(
              eq(enrollmentTokens.tokenHash, tokenHash),
              isNull(enrollmentTokens.usedAtMs),
              gt(enrollmentTokens.expiresAtMs, usedAtMs),
            ),
          )
          .returning()
          .get() ?? null
      );
    },
  };
}
