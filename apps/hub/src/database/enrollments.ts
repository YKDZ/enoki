import { and, desc, eq, gt, inArray, isNull, lte, or } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";

import { validEnrollmentId } from "../enrollment/lifecycle.js";
import { createAuditRepository } from "./audit.js";
import type { HostProfilePersistenceValues } from "./host-profiles.js";
import {
  enrollmentTokens,
  hosts,
  officialHostProfiles,
  probeRequestNonces,
  type EnrollmentTokenRow,
  type HostRow,
  type NewHostRow,
} from "./schema.js";

type EnrollmentDatabase = NodeSQLiteDatabase<typeof import("./schema.js")>;

export type EnrollmentTarget =
  | { kind: "new_host" }
  | { hostId: number; kind: "existing_host" }
  | {
      expectedHubOrigin: string;
      expectedProbeId: string;
      expectedProbeVersion: string;
      hostId: number;
      kind: "manual_reinstall";
      sourceProbeSha256: string[];
      targetAssetSetDigest: string;
      targetProbeVersion: string;
    };

export type CreatePendingEnrollmentInput = {
  createdAtMs: number;
  enrollmentId: string;
  expiresAtMs: number;
  offlineAfterMs?: number;
  target: EnrollmentTarget;
  tokenHash: string;
};

export type PendingEnrollmentCreation =
  | { enrollment: EnrollmentTokenRow; kind: "created" }
  | { kind: "existing_host_unavailable" }
  | { kind: "existing_host_verifying" };

export type PendingEnrollmentInspection =
  | { targetKind: "existing_host" | "new_host" }
  | {
      expectedHubOrigin: string;
      expectedProbeId: string;
      sourceProbeVersion: string;
      sourceProbeSha256: string[];
      targetAssetSetDigest: string;
      targetKind: "manual_reinstall";
      targetProbeVersion: string;
    };

export type InstallationRejectionResult = {
  enrollment: EnrollmentTokenRow;
  outcome: "confirmed" | "rejected";
};

export type RegisterNewHostEnrollmentInput = {
  host: NewHostRow;
  hostProfile: HostProfilePersistenceValues | null;
  registeredAtMs: number;
  tokenHash: string;
  verificationDeadlineAtMs: number;
};

export type EnrollmentRepository = {
  inspectPending: (input: {
    nowMs: number;
    tokenHash: string;
  }) => PendingEnrollmentInspection | null;
  rejectInstallation: (input: {
    code: string;
    message: string;
    rejectedAtMs: number;
    existingProbeId: string | null;
    tokenHash: string;
  }) => InstallationRejectionResult | null;
  resolveStartupReport: (input: {
    enrollmentId: string | null;
    hostId: number;
    probeAssetBundleVersion: string | null;
    probeVersion: string | null;
    producedCurrentHostProfile: boolean;
    reportedAtMs: number;
  }) =>
    | { enrollment: EnrollmentTokenRow; status: "verifying" }
    | { enrollment: EnrollmentTokenRow; status: "ready" }
    | { enrollment: EnrollmentTokenRow; status: "rejected" }
    | null;
  createPending: (
    input: CreatePendingEnrollmentInput,
  ) => PendingEnrollmentCreation;
  registerNewHost: (
    input: RegisterNewHostEnrollmentInput,
  ) => { enrollment: EnrollmentTokenRow; host: HostRow } | null;
  readStatus: (
    enrollmentId: string,
    nowMs: number,
  ) => EnrollmentTokenRow | null;
};

class ExistingHostEnrollmentTargetUnavailable extends Error {}

export function createEnrollmentRepository(
  database: EnrollmentDatabase,
): EnrollmentRepository {
  return {
    inspectPending(input) {
      const pending = database
        .select({
          expectedHubOrigin: enrollmentTokens.expectedHubOrigin,
          expectedProbeId: enrollmentTokens.expectedProbeId,
          expectedProbeVersion: enrollmentTokens.expectedProbeVersion,
          sourceProbeSha256Json: enrollmentTokens.sourceProbeSha256Json,
          targetAssetSetDigest: enrollmentTokens.targetAssetSetDigest,
          targetHostId: enrollmentTokens.targetHostId,
          targetKind: enrollmentTokens.targetKind,
          targetProbeVersion: enrollmentTokens.targetProbeVersion,
        })
        .from(enrollmentTokens)
        .where(
          and(
            eq(enrollmentTokens.tokenHash, input.tokenHash),
            isNull(enrollmentTokens.usedAtMs),
            eq(enrollmentTokens.status, "pending"),
            gt(enrollmentTokens.expiresAtMs, input.nowMs),
          ),
        )
        .get();
      if (!pending) {
        return null;
      }
      if (pending.targetKind === "new_host") {
        return { targetKind: "new_host" };
      }
      if (pending.targetKind === "manual_reinstall") {
        if (
          pending.targetHostId === null ||
          !pending.expectedHubOrigin ||
          !pending.expectedProbeId ||
          !pending.expectedProbeVersion ||
          !pending.sourceProbeSha256Json ||
          !pending.targetAssetSetDigest ||
          !pending.targetProbeVersion
        ) {
          return null;
        }
        const host = database
          .select({
            id: hosts.id,
            probeId: hosts.probeId,
            probeVersion: hosts.probeVersion,
          })
          .from(hosts)
          .where(
            and(eq(hosts.id, pending.targetHostId), isNull(hosts.deletedAtMs)),
          )
          .get();
        if (
          !host ||
          host.probeId !== pending.expectedProbeId ||
          host.probeVersion !== pending.expectedProbeVersion
        ) {
          return null;
        }
        const sourceProbeSha256 = parseSourceProbeSha256(
          pending.sourceProbeSha256Json,
        );
        if (!sourceProbeSha256) {
          return null;
        }
        return {
          expectedHubOrigin: pending.expectedHubOrigin,
          expectedProbeId: pending.expectedProbeId,
          sourceProbeVersion: pending.expectedProbeVersion,
          sourceProbeSha256,
          targetAssetSetDigest: pending.targetAssetSetDigest,
          targetKind: "manual_reinstall",
          targetProbeVersion: pending.targetProbeVersion,
        };
      }
      if (
        pending.targetKind !== "existing_host" ||
        pending.targetHostId === null
      ) {
        return null;
      }
      const host = database
        .select({ id: hosts.id })
        .from(hosts)
        .where(
          and(eq(hosts.id, pending.targetHostId), isNull(hosts.deletedAtMs)),
        )
        .get();
      return host ? { targetKind: "existing_host" } : null;
    },
    rejectInstallation(input) {
      return database.transaction((transaction) => {
        const matchingHost = input.existingProbeId
          ? transaction
              .select({ id: hosts.id })
              .from(hosts)
              .where(
                and(
                  eq(hosts.probeId, input.existingProbeId),
                  isNull(hosts.deletedAtMs),
                ),
              )
              .get()
          : null;
        const rejected =
          transaction
            .update(enrollmentTokens)
            .set({
              ...(matchingHost ? { hostId: matchingHost.id } : {}),
              rejectedAtMs: input.rejectedAtMs,
              rejectionCode: input.code,
              rejectionMessage: input.message,
              status: "rejected",
            })
            .where(
              and(
                eq(enrollmentTokens.tokenHash, input.tokenHash),
                or(
                  and(
                    eq(enrollmentTokens.status, "pending"),
                    gt(enrollmentTokens.expiresAtMs, input.rejectedAtMs),
                  ),
                  and(
                    eq(enrollmentTokens.status, "verifying"),
                    gt(
                      enrollmentTokens.verificationDeadlineAtMs,
                      input.rejectedAtMs,
                    ),
                  ),
                ),
              ),
            )
            .returning()
            .get() ?? null;
        if (rejected) {
          return { enrollment: rejected, outcome: "rejected" };
        }

        const priorRejection = transaction
          .select()
          .from(enrollmentTokens)
          .where(
            and(
              eq(enrollmentTokens.tokenHash, input.tokenHash),
              eq(enrollmentTokens.status, "rejected"),
            ),
          )
          .get();
        const persistedCanonicalHost =
          input.code === "existing_probe_installation" &&
          priorRejection?.hostId !== null &&
          priorRejection?.hostId !== undefined
            ? transaction
                .select({ probeId: hosts.probeId })
                .from(hosts)
                .where(eq(hosts.id, priorRejection.hostId))
                .get()
            : null;
        const sameCanonicalContext =
          input.code !== "existing_probe_installation" ||
          (input.existingProbeId !== null &&
            persistedCanonicalHost?.probeId === input.existingProbeId);
        if (
          priorRejection &&
          priorRejection.rejectionCode === input.code &&
          priorRejection.rejectionMessage === input.message &&
          sameCanonicalContext
        ) {
          return { enrollment: priorRejection, outcome: "confirmed" };
        }
        return null;
      });
    },
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
        if (
          enrollment.targetKind === "manual_reinstall" &&
          (!input.producedCurrentHostProfile ||
            !enrollment.targetProbeVersion ||
            input.probeVersion !== enrollment.targetProbeVersion ||
            input.probeAssetBundleVersion !== enrollment.targetProbeVersion)
        ) {
          return { enrollment, status: "verifying" };
        }
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

      return database.transaction((transaction) => {
        if (input.target.kind === "existing_host") {
          const target = transaction
            .select({
              deletedAtMs: hosts.deletedAtMs,
              id: hosts.id,
              lastReportAtMs: hosts.lastReportAtMs,
            })
            .from(hosts)
            .where(
              and(eq(hosts.id, input.target.hostId), isNull(hosts.deletedAtMs)),
            )
            .get();
          const offlineAfterMs = input.offlineAfterMs ?? 90_000;
          if (
            !target ||
            (target.lastReportAtMs !== null &&
              Math.max(0, input.createdAtMs - target.lastReportAtMs) <
                offlineAfterMs)
          ) {
            return { kind: "existing_host_unavailable" };
          }

          transaction
            .update(enrollmentTokens)
            .set({
              expiredAtMs: input.createdAtMs,
              status: "expired",
            })
            .where(
              and(
                eq(enrollmentTokens.targetKind, "existing_host"),
                eq(enrollmentTokens.targetHostId, input.target.hostId),
                eq(enrollmentTokens.status, "pending"),
                lte(enrollmentTokens.expiresAtMs, input.createdAtMs),
              ),
            )
            .run();
          transaction
            .update(enrollmentTokens)
            .set({
              rejectedAtMs: input.createdAtMs,
              rejectionCode: "probe_startup_timeout",
              rejectionMessage: null,
              status: "rejected",
            })
            .where(
              and(
                eq(enrollmentTokens.targetKind, "existing_host"),
                eq(enrollmentTokens.targetHostId, input.target.hostId),
                eq(enrollmentTokens.status, "verifying"),
                lte(
                  enrollmentTokens.verificationDeadlineAtMs,
                  input.createdAtMs,
                ),
              ),
            )
            .run();

          const active = transaction
            .select()
            .from(enrollmentTokens)
            .where(
              and(
                eq(enrollmentTokens.targetKind, "existing_host"),
                eq(enrollmentTokens.targetHostId, input.target.hostId),
                inArray(enrollmentTokens.status, ["pending", "verifying"]),
              ),
            )
            .get();
          if (active?.status === "verifying") {
            return { kind: "existing_host_verifying" };
          }
          if (active?.status === "pending") {
            transaction
              .update(enrollmentTokens)
              .set({
                rejectedAtMs: input.createdAtMs,
                rejectionCode: "superseded",
                rejectionMessage: null,
                status: "rejected",
              })
              .where(
                and(
                  eq(enrollmentTokens.id, active.id),
                  eq(enrollmentTokens.status, "pending"),
                ),
              )
              .run();
          }
        }

        if (input.target.kind === "manual_reinstall") {
          if (!validSourceProbeSha256(input.target.sourceProbeSha256)) {
            return { kind: "existing_host_unavailable" };
          }
          const target = transaction
            .select({
              id: hosts.id,
              probeId: hosts.probeId,
              probeVersion: hosts.probeVersion,
            })
            .from(hosts)
            .where(
              and(eq(hosts.id, input.target.hostId), isNull(hosts.deletedAtMs)),
            )
            .get();
          if (
            !target ||
            target.probeId !== input.target.expectedProbeId ||
            target.probeVersion !== input.target.expectedProbeVersion
          ) {
            return { kind: "existing_host_unavailable" };
          }

          const active = transaction
            .select()
            .from(enrollmentTokens)
            .where(
              and(
                eq(enrollmentTokens.targetHostId, input.target.hostId),
                inArray(enrollmentTokens.targetKind, [
                  "existing_host",
                  "manual_reinstall",
                ]),
                inArray(enrollmentTokens.status, ["pending", "verifying"]),
              ),
            )
            .get();
          if (active?.status === "verifying") {
            return { kind: "existing_host_verifying" };
          }
          if (active?.status === "pending") {
            transaction
              .update(enrollmentTokens)
              .set({
                rejectedAtMs: input.createdAtMs,
                rejectionCode: "superseded",
                rejectionMessage: null,
                status: "rejected",
              })
              .where(
                and(
                  eq(enrollmentTokens.id, active.id),
                  eq(enrollmentTokens.status, "pending"),
                ),
              )
              .run();
          }
        }

        const row = transaction
          .insert(enrollmentTokens)
          .values({
            createdAtMs: input.createdAtMs,
            enrollmentId: input.enrollmentId,
            expiresAtMs: input.expiresAtMs,
            status: "pending",
            targetHostId:
              input.target.kind === "existing_host" ||
              input.target.kind === "manual_reinstall"
                ? input.target.hostId
                : null,
            expectedHubOrigin:
              input.target.kind === "manual_reinstall"
                ? input.target.expectedHubOrigin
                : null,
            expectedProbeId:
              input.target.kind === "manual_reinstall"
                ? input.target.expectedProbeId
                : null,
            expectedProbeVersion:
              input.target.kind === "manual_reinstall"
                ? input.target.expectedProbeVersion
                : null,
            sourceProbeSha256Json:
              input.target.kind === "manual_reinstall"
                ? JSON.stringify(input.target.sourceProbeSha256)
                : null,
            targetAssetSetDigest:
              input.target.kind === "manual_reinstall"
                ? input.target.targetAssetSetDigest
                : null,
            targetProbeVersion:
              input.target.kind === "manual_reinstall"
                ? input.target.targetProbeVersion
                : null,
            targetKind: input.target.kind,
            tokenHash: input.tokenHash,
          })
          .returning()
          .get();

        if (!row) {
          throw new Error("Failed to create Enrollment Token.");
        }

        return { enrollment: row, kind: "created" };
      });
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

      try {
        return database.transaction((transaction) => {
          const pending = transaction
            .select()
            .from(enrollmentTokens)
            .where(
              and(
                eq(enrollmentTokens.tokenHash, input.tokenHash),
                isNull(enrollmentTokens.usedAtMs),
                eq(enrollmentTokens.status, "pending"),
                gt(enrollmentTokens.expiresAtMs, input.registeredAtMs),
              ),
            )
            .get();

          if (!pending) {
            return null;
          }

          const existingHost =
            (pending.targetKind === "existing_host" ||
              pending.targetKind === "manual_reinstall") &&
            pending.targetHostId !== null
              ? transaction
                  .select()
                  .from(hosts)
                  .where(
                    and(
                      eq(hosts.id, pending.targetHostId),
                      isNull(hosts.deletedAtMs),
                    ),
                  )
                  .get()
              : null;

          if (
            (pending.targetKind === "existing_host" ||
              pending.targetKind === "manual_reinstall") &&
            !existingHost
          ) {
            return null;
          }

          if (
            pending.targetKind !== "new_host" &&
            pending.targetKind !== "existing_host" &&
            pending.targetKind !== "manual_reinstall"
          ) {
            return null;
          }

          if (
            pending.targetKind === "manual_reinstall" &&
            (!pending.expectedHubOrigin ||
              !pending.expectedProbeId ||
              !pending.expectedProbeVersion ||
              !pending.targetAssetSetDigest ||
              !pending.targetProbeVersion ||
              existingHost?.probeId !== pending.expectedProbeId ||
              existingHost.probeVersion !== pending.expectedProbeVersion)
          ) {
            return null;
          }

          const consumed = transaction
            .update(enrollmentTokens)
            .set({
              status: "verifying",
              usedAtMs: input.registeredAtMs,
            })
            .where(
              and(
                eq(enrollmentTokens.id, pending.id),
                isNull(enrollmentTokens.usedAtMs),
                eq(enrollmentTokens.status, "pending"),
                gt(enrollmentTokens.expiresAtMs, input.registeredAtMs),
              ),
            )
            .returning()
            .get();

          if (!consumed) {
            return null;
          }

          const host =
            pending.targetKind === "new_host"
              ? createNewHostForEnrollment(transaction, input)
              : replaceExistingHostProbeIdentity(
                  transaction,
                  existingHost ?? null,
                  input,
                );

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

          if (pending.targetKind === "manual_reinstall") {
            createAuditRepository(transaction).record({
              action: "probe.manual_reinstall_identity_replaced",
              actor: "system",
              details: {
                enrollmentId: enrollment.enrollmentId,
                newProbeId: host.probeId,
                oldProbeId: pending.expectedProbeId,
                sourceProbeSha256: parseSourceProbeSha256(
                  pending.sourceProbeSha256Json ?? "",
                ),
                targetAssetSetDigest: pending.targetAssetSetDigest,
                targetProbeVersion: pending.targetProbeVersion,
              },
              occurredAtMs: input.registeredAtMs,
              outcome: "success",
              subjectId: String(host.id),
              subjectType: "host",
            });
          }

          return { enrollment, host };
        });
      } catch (error) {
        if (error instanceof ExistingHostEnrollmentTargetUnavailable) {
          return null;
        }
        throw error;
      }
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

function parseSourceProbeSha256(value: string) {
  try {
    const parsed = JSON.parse(value) as unknown;
    return validSourceProbeSha256(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function validSourceProbeSha256(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length >= 1 &&
    value.length <= 4 &&
    new Set(value).size === value.length &&
    value.every(
      (digest) => typeof digest === "string" && /^[0-9a-f]{64}$/.test(digest),
    )
  );
}

function createNewHostForEnrollment(
  transaction: EnrollmentDatabase,
  input: RegisterNewHostEnrollmentInput,
) {
  const host = transaction.insert(hosts).values(input.host).returning().get();
  if (!host) {
    throw new Error("Failed to create Host for Probe Enrollment.");
  }

  if (input.hostProfile) {
    transaction
      .insert(officialHostProfiles)
      .values({
        ...input.hostProfile,
        hostId: host.id,
      })
      .run();
  }
  return host;
}

function replaceExistingHostProbeIdentity(
  transaction: EnrollmentDatabase,
  existingHost: HostRow | null,
  input: RegisterNewHostEnrollmentInput,
) {
  if (!existingHost) {
    throw new ExistingHostEnrollmentTargetUnavailable();
  }

  transaction
    .delete(probeRequestNonces)
    .where(eq(probeRequestNonces.probeId, existingHost.probeId))
    .run();

  const host = transaction
    .update(hosts)
    .set({
      architecture: input.host.architecture,
      clockSkewDetected: false,
      connectAddress: existingHost.connectAddressEdited
        ? undefined
        : input.host.connectAddress,
      cpuCount: input.host.cpuCount,
      cpuModel: input.host.cpuModel,
      displayName: existingHost.displayNameEdited
        ? undefined
        : input.host.displayName,
      hostname: input.host.hostname,
      kernel: input.host.kernel,
      lastClockSkewMs: null,
      lastReportAtMs: null,
      memoryTotalBytes: input.host.memoryTotalBytes,
      observedIp: input.host.observedIp,
      probeConfigurationErrorCode: null,
      probeConfigurationErrorFailedVersion: null,
      probeConfigurationErrorMessage: null,
      probeConfigurationErrorReportedAtMs: null,
      os: input.host.os,
      probeId: input.host.probeId,
      probePublicKeyPem: input.host.probePublicKeyPem,
      probeSecretHash: input.host.probeSecretHash,
      probeVersion: input.host.probeVersion,
    })
    .where(and(eq(hosts.id, existingHost.id), isNull(hosts.deletedAtMs)))
    .returning()
    .get();
  if (!host) {
    throw new ExistingHostEnrollmentTargetUnavailable();
  }

  if (input.hostProfile) {
    transaction
      .insert(officialHostProfiles)
      .values({
        ...input.hostProfile,
        hostId: host.id,
      })
      .onConflictDoUpdate({
        set: input.hostProfile,
        target: officialHostProfiles.hostId,
      })
      .run();
  }

  return host;
}
