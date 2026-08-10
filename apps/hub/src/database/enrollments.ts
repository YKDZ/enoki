import { and, desc, eq, gt, isNull, lte } from "drizzle-orm";
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
  resolveStartupReport: (input: {
    enrollmentId: string | null;
    hostId: number;
    reportedAtMs: number;
  }) =>
    | { enrollment: EnrollmentTokenRow; status: "ready" }
    | { enrollment: EnrollmentTokenRow; status: "rejected" }
    | null;
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
    resolveStartupReport(input) {
      const enrollment =
        database
          .select()
          .from(enrollmentTokens)
          .where(
            and(
              eq(enrollmentTokens.hostId, input.hostId),
              input.enrollmentId
                ? eq(enrollmentTokens.enrollmentId, input.enrollmentId)
                : undefined,
            ),
          )
          // A legacy Probe cannot identify its Enrollment. Its nearest
          // associated Enrollment is therefore deterministic: registration
          // time first, then creation time and row ID as stable ties.
          .orderBy(
            desc(enrollmentTokens.usedAtMs),
            desc(enrollmentTokens.createdAtMs),
            desc(enrollmentTokens.id),
          )
          .limit(1)
          .get() ?? null;

      if (!enrollment) {
        return null;
      }

      if (enrollment.status === "verifying") {
        const ready =
          database
            .update(enrollmentTokens)
            .set({
              readyAtMs: input.reportedAtMs,
              status: "ready",
            })
            .where(
              and(
                eq(enrollmentTokens.id, enrollment.id),
                eq(enrollmentTokens.status, "verifying"),
                gt(
                  enrollmentTokens.verificationDeadlineAtMs,
                  input.reportedAtMs,
                ),
              ),
            )
            .returning()
            .get() ?? null;
        if (ready) {
          return { enrollment: ready, status: "ready" };
        }

        const rejected =
          database
            .update(enrollmentTokens)
            .set({
              rejectedAtMs: input.reportedAtMs,
              rejectionCode: "probe_startup_timeout",
              rejectionMessage: null,
              status: "rejected",
            })
            .where(
              and(
                eq(enrollmentTokens.id, enrollment.id),
                eq(enrollmentTokens.status, "verifying"),
                lte(
                  enrollmentTokens.verificationDeadlineAtMs,
                  input.reportedAtMs,
                ),
              ),
            )
            .returning()
            .get() ?? null;
        if (rejected) {
          return { enrollment: rejected, status: "rejected" };
        }
      }

      // An Owner status read can have persisted the deadline rejection before
      // the Startup Report transaction begins. A legacy report observes that
      // result only when it belongs to the latest associated Enrollment; an
      // older timeout before a newer ready Enrollment is harmless.
      const current =
        database
          .select()
          .from(enrollmentTokens)
          .where(eq(enrollmentTokens.id, enrollment.id))
          .get() ?? null;
      return current?.status === "rejected" &&
        current.rejectionCode === "probe_startup_timeout"
        ? { enrollment: current, status: "rejected" }
        : null;
    },
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

        const timedOut = transaction
          .update(enrollmentTokens)
          .set({
            rejectedAtMs: nowMs,
            rejectionCode: "probe_startup_timeout",
            rejectionMessage: null,
            status: "rejected",
          })
          .where(
            and(
              eq(enrollmentTokens.enrollmentId, enrollmentId),
              eq(enrollmentTokens.status, "verifying"),
              lte(enrollmentTokens.verificationDeadlineAtMs, nowMs),
            ),
          )
          .returning()
          .get();

        return (
          expired ??
          timedOut ??
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
