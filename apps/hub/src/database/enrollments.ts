import { and, eq, gt, isNull, lte } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";

import { validEnrollmentId } from "../enrollment/lifecycle.js";
import type { HostProfilePersistenceValues } from "./host-profiles.js";
import {
  enrollmentTokens,
  hosts,
  officialHostProfiles,
  type EnrollmentTokenRow,
  type HostRow,
  type NewHostRow,
} from "./schema.js";

type EnrollmentDatabase = NodeSQLiteDatabase<typeof import("./schema.js")>;

export type CreatePendingEnrollmentInput = {
  createdAtMs: number;
  enrollmentId: string;
  expiresAtMs: number;
  tokenHash: string;
};

export type RegisterNewHostEnrollmentInput = {
  host: NewHostRow;
  hostProfile: HostProfilePersistenceValues;
  registeredAtMs: number;
  tokenHash: string;
  verificationDeadlineAtMs: number;
};

export type EnrollmentRepository = {
  createPending: (input: CreatePendingEnrollmentInput) => EnrollmentTokenRow;
  registerNewHost: (
    input: RegisterNewHostEnrollmentInput,
  ) => { enrollment: EnrollmentTokenRow; host: HostRow } | null;
  readStatus: (
    enrollmentId: string,
    nowMs: number,
  ) => EnrollmentTokenRow | null;
};

export function createEnrollmentRepository(
  database: EnrollmentDatabase,
): EnrollmentRepository {
  return {
    createPending(input) {
      if (
        !validEnrollmentId(input.enrollmentId) ||
        input.expiresAtMs <= input.createdAtMs
      ) {
        throw new Error("Invalid pending Enrollment lifecycle input.");
      }

      const row = database
        .insert(enrollmentTokens)
        .values({
          ...input,
          status: "pending",
          targetKind: "new_host",
        })
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to create Enrollment Token.");
      }

      return row;
    },
    registerNewHost(input) {
      if (
        input.verificationDeadlineAtMs <= input.registeredAtMs ||
        !input.host.displayName.trim() ||
        !input.host.probeId ||
        !input.host.probePublicKeyPem
      ) {
        throw new Error("Invalid Probe Enrollment registration input.");
      }

      return database.transaction((transaction) => {
        const consumed = transaction
          .update(enrollmentTokens)
          .set({
            status: "verifying",
            usedAtMs: input.registeredAtMs,
          })
          .where(
            and(
              eq(enrollmentTokens.tokenHash, input.tokenHash),
              isNull(enrollmentTokens.usedAtMs),
              eq(enrollmentTokens.status, "pending"),
              eq(enrollmentTokens.targetKind, "new_host"),
              gt(enrollmentTokens.expiresAtMs, input.registeredAtMs),
            ),
          )
          .returning()
          .get();

        if (!consumed) {
          return null;
        }

        const host = transaction
          .insert(hosts)
          .values(input.host)
          .returning()
          .get();
        if (!host) {
          throw new Error("Failed to create Host for Probe Enrollment.");
        }

        transaction
          .insert(officialHostProfiles)
          .values({
            ...input.hostProfile,
            hostId: host.id,
          })
          .run();

        const enrollment = transaction
          .update(enrollmentTokens)
          .set({
            hostId: host.id,
            verificationDeadlineAtMs: input.verificationDeadlineAtMs,
          })
          .where(eq(enrollmentTokens.id, consumed.id))
          .returning()
          .get();

        if (!enrollment) {
          throw new Error(
            "Failed to associate Probe Enrollment with its Host.",
          );
        }

        return { enrollment, host };
      });
    },
    readStatus(enrollmentId, nowMs) {
      return database.transaction((transaction) => {
        const expired = transaction
          .update(enrollmentTokens)
          .set({
            expiredAtMs: nowMs,
            status: "expired",
          })
          .where(
            and(
              eq(enrollmentTokens.enrollmentId, enrollmentId),
              eq(enrollmentTokens.status, "pending"),
              lte(enrollmentTokens.expiresAtMs, nowMs),
            ),
          )
          .returning()
          .get();

        return (
          expired ??
          transaction
            .select()
            .from(enrollmentTokens)
            .where(eq(enrollmentTokens.enrollmentId, enrollmentId))
            .get() ??
          null
        );
      });
    },
  };
}
