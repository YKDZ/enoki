import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";
import { and, desc, eq, gt, inArray, isNull, lte, or } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";

import { validEnrollmentId } from "../enrollment/lifecycle.js";
import { normalizeSemVer } from "../probe/asset-set.js";
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
      replacementPredecessorEnrollmentId?: string;
      replacementPredecessorAssetSetDigest?: string;
      targetBundles: ReadonlyArray<{
        bundleManifestSha256: string;
        target: string;
      }>;
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
      enrollmentId: string;
      expectedHubOrigin: string;
      expectedProbeId: string;
      sourceProbeVersion: string;
      sourceProbeSha256: string[];
      targetAssetSetDigest: string;
      targetHostId: number;
      targetKind: "manual_reinstall";
      targetProbeVersion: string;
    };

export type PendingInstallationInspectionDecision =
  | { enrollment: PendingEnrollmentInspection; kind: "ready" }
  | { kind: "legacy_ordinary_hydration_required" }
  | { kind: "invalid" };

export type InstallationRejectionResult = {
  enrollment: EnrollmentTokenRow;
  outcome: "confirmed" | "rejected";
};

export type RegisterNewHostEnrollmentInput = {
  host: NewHostRow | (() => NewHostRow);
  hostProfile: HostProfilePersistenceValues | null;
  registrationAttempt?: {
    candidatePublicKeyPem: string;
    enrollmentId: string;
    hostId: number;
    hubOrigin: string;
    oldProbeId: string;
    outcome: (host: HostRow) => Buffer;
    signedAttemptSha256: string;
    committedSourceProbeSha256: string;
    sourceProbeVersion: string;
    targetBundleTarget: string;
    targetManifestSha256: string;
    targetAssetSetDigest: string;
    targetProbeVersion: string;
  };
  registeredAtMs: number;
  tokenHash: string;
  verificationDeadlineAtMs: number;
};

type ResolvedRegisterNewHostEnrollmentInput = Omit<
  RegisterNewHostEnrollmentInput,
  "host"
> & { host: NewHostRow };

type LegacyOrdinaryPendingClosure = {
  sourceProbeSha256: string[];
  targetAssetSetDigest: string;
  targetBundles: ReadonlyArray<{
    bundleManifestSha256: string;
    target: string;
  }>;
  targetProbeVersion: string;
};

export type EnrollmentRepository = {
  replayRegistrationOutcome: (input: {
    signedAttemptSha256: string;
    tokenHash: string;
  }) => Buffer | null;
  terminalReplacementPredecessorForHost: (input: {
    currentProbeId: string;
    hostId: number;
  }) => {
    enrollmentId: string;
    targetAssetSetDigest: string;
    targetProbeVersion: string;
  } | null;
  lifecycleAuthorityTokenHashForHost: (hostId: number) => string | null;
  inspectPending: (input: {
    nowMs: number;
    tokenHash: string;
  }) => PendingEnrollmentInspection | null;
  hydrateLegacyOrdinaryPendingClosure: (input: {
    closure: LegacyOrdinaryPendingClosure;
    nowMs: number;
    tokenHash: string;
  }) => void;
  installationInspectionDecision: (input: {
    nowMs: number;
    tokenHash: string;
  }) => PendingInstallationInspectionDecision;
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
  registerNewHost: (input: RegisterNewHostEnrollmentInput) => {
    enrollment: EnrollmentTokenRow;
    host: HostRow;
    registrationOutcome: Buffer | null;
    replayed: boolean;
  } | null;
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
    replayRegistrationOutcome(input) {
      const replay = database
        .select({
          outcome: enrollmentTokens.registrationOutcome,
          replacementPredecessorAssetSetDigest:
            enrollmentTokens.replacementPredecessorAssetSetDigest,
          replacementPredecessorEnrollmentId:
            enrollmentTokens.replacementPredecessorEnrollmentId,
          sourceProbeSha256Json: enrollmentTokens.sourceProbeSha256Json,
          targetBundlesJson: enrollmentTokens.targetBundlesJson,
          targetKind: enrollmentTokens.targetKind,
        })
        .from(enrollmentTokens)
        .where(
          and(
            eq(enrollmentTokens.tokenHash, input.tokenHash),
            eq(
              enrollmentTokens.registrationAttemptSha256,
              input.signedAttemptSha256,
            ),
          ),
        )
        .get();
      return replay?.outcome &&
        parseReplacementPredecessorCorrelation(replay) &&
        (replay.targetKind !== "manual_reinstall" ||
          validPersistedManualSourceClosure(replay))
        ? Buffer.from(replay.outcome)
        : null;
    },
    terminalReplacementPredecessorForHost(input) {
      const predecessor = database
        .select()
        .from(enrollmentTokens)
        .where(
          and(
            eq(enrollmentTokens.targetKind, "manual_reinstall"),
            eq(enrollmentTokens.hostId, input.hostId),
            eq(enrollmentTokens.status, "rejected"),
            eq(enrollmentTokens.rejectionCode, "probe_startup_timeout"),
          ),
        )
        .orderBy(desc(enrollmentTokens.rejectedAtMs), desc(enrollmentTokens.id))
        .limit(1)
        .get();
      if (
        !predecessor?.enrollmentId ||
        !predecessor.targetProbeVersion ||
        !predecessor.targetAssetSetDigest ||
        !predecessor.registrationOutcome
      ) {
        return null;
      }
      return terminalReplacementPredecessorMatches(database, {
        currentProbeId: input.currentProbeId,
        hostId: input.hostId,
        pending: {
          expectedProbeId: input.currentProbeId,
          expectedProbeVersion: predecessor.targetProbeVersion,
          replacementPredecessorAssetSetDigest:
            predecessor.targetAssetSetDigest,
          replacementPredecessorEnrollmentId: predecessor.enrollmentId,
          targetAssetSetDigest: predecessor.targetAssetSetDigest,
          targetHostId: input.hostId,
          targetProbeVersion: predecessor.targetProbeVersion,
        },
      })
        ? {
            enrollmentId: predecessor.enrollmentId,
            targetAssetSetDigest: predecessor.targetAssetSetDigest,
            targetProbeVersion: predecessor.targetProbeVersion,
          }
        : null;
    },
    lifecycleAuthorityTokenHashForHost(hostId) {
      return (
        database
          .select({ tokenHash: enrollmentTokens.tokenHash })
          .from(enrollmentTokens)
          .where(eq(enrollmentTokens.hostId, hostId))
          .orderBy(
            desc(enrollmentTokens.usedAtMs),
            desc(enrollmentTokens.createdAtMs),
            desc(enrollmentTokens.id),
          )
          .limit(1)
          .get()?.tokenHash ?? null
      );
    },
    hydrateLegacyOrdinaryPendingClosure(input) {
      if (!validTargetBundles(input.closure.targetBundles)) return;
      database.transaction((transaction) => {
        const pending = transaction
          .select()
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
        const sourceProbeSha256 = parseSourceProbeSha256(
          pending?.sourceProbeSha256Json ?? "",
        );
        const predecessorCorrelation = pending
          ? parseReplacementPredecessorCorrelation(pending)
          : null;
        const host =
          pending?.targetHostId === null || pending?.targetHostId === undefined
            ? null
            : transaction
                .select({
                  probeId: hosts.probeId,
                  probeVersion: hosts.probeVersion,
                })
                .from(hosts)
                .where(
                  and(
                    eq(hosts.id, pending.targetHostId),
                    isNull(hosts.deletedAtMs),
                  ),
                )
                .get();
        if (
          !pending ||
          pending.targetKind !== "manual_reinstall" ||
          predecessorCorrelation?.kind !== "ordinary" ||
          pending.targetBundlesJson !== null ||
          !sourceProbeSha256 ||
          !validLegacyOrdinaryImmutableFields(pending, sourceProbeSha256) ||
          !host ||
          host.probeId !== pending.expectedProbeId ||
          !sameProbeAssetVersion(
            host.probeVersion,
            pending.expectedProbeVersion,
          ) ||
          pending.targetAssetSetDigest !== input.closure.targetAssetSetDigest ||
          pending.targetProbeVersion !== input.closure.targetProbeVersion ||
          JSON.stringify(sourceProbeSha256) !==
            JSON.stringify(input.closure.sourceProbeSha256)
        ) {
          return;
        }
        transaction
          .update(enrollmentTokens)
          .set({
            targetBundlesJson: JSON.stringify(input.closure.targetBundles),
          })
          .where(eq(enrollmentTokens.id, pending.id))
          .run();
      });
    },
    installationInspectionDecision(input) {
      return database.transaction((transaction) => {
        const pending = transaction
          .select({
            enrollmentId: enrollmentTokens.enrollmentId,
            expectedHubOrigin: enrollmentTokens.expectedHubOrigin,
            expectedProbeId: enrollmentTokens.expectedProbeId,
            expectedProbeVersion: enrollmentTokens.expectedProbeVersion,
            sourceProbeSha256Json: enrollmentTokens.sourceProbeSha256Json,
            targetAssetSetDigest: enrollmentTokens.targetAssetSetDigest,
            targetHostId: enrollmentTokens.targetHostId,
            targetKind: enrollmentTokens.targetKind,
            targetProbeVersion: enrollmentTokens.targetProbeVersion,
            replacementPredecessorEnrollmentId:
              enrollmentTokens.replacementPredecessorEnrollmentId,
            replacementPredecessorAssetSetDigest:
              enrollmentTokens.replacementPredecessorAssetSetDigest,
            targetBundlesJson: enrollmentTokens.targetBundlesJson,
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
        if (!pending) return { kind: "invalid" };
        if (pending.targetKind === "new_host") {
          return { enrollment: { targetKind: "new_host" }, kind: "ready" };
        }
        if (
          pending.targetKind === "existing_host" &&
          pending.targetHostId !== null
        ) {
          const host = transaction
            .select({ id: hosts.id })
            .from(hosts)
            .where(
              and(
                eq(hosts.id, pending.targetHostId),
                isNull(hosts.deletedAtMs),
              ),
            )
            .get();
          return host
            ? { enrollment: { targetKind: "existing_host" }, kind: "ready" }
            : { kind: "invalid" };
        }
        if (
          pending.targetKind !== "manual_reinstall" ||
          !pending.enrollmentId ||
          pending.targetHostId === null ||
          !pending.expectedHubOrigin ||
          !pending.expectedProbeId ||
          !pending.expectedProbeVersion ||
          !pending.sourceProbeSha256Json ||
          !pending.targetAssetSetDigest ||
          !pending.targetProbeVersion
        ) {
          return { kind: "invalid" };
        }
        const predecessorCorrelation =
          parseReplacementPredecessorCorrelation(pending);
        if (!predecessorCorrelation) return { kind: "invalid" };
        const host = transaction
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
          (predecessorCorrelation.kind === "ordinary" &&
            !sameProbeAssetVersion(
              host.probeVersion,
              pending.expectedProbeVersion,
            )) ||
          (predecessorCorrelation.kind === "terminal" &&
            !terminalReplacementPredecessorMatches(transaction, {
              currentProbeId: host.probeId,
              hostId: host.id,
              pending,
            }))
        ) {
          return { kind: "invalid" };
        }
        const sourceProbeSha256 = parseSourceProbeSha256(
          pending.sourceProbeSha256Json,
        );
        if (
          !sourceProbeSha256 ||
          !validManualImmutableFields(pending, sourceProbeSha256)
        ) {
          return { kind: "invalid" };
        }
        if (
          pending.targetBundlesJson === null &&
          predecessorCorrelation.kind === "ordinary"
        ) {
          return { kind: "legacy_ordinary_hydration_required" };
        }
        if (
          !pending.targetBundlesJson ||
          !parseTargetBundles(pending.targetBundlesJson)
        ) {
          return { kind: "invalid" };
        }
        return {
          enrollment: {
            enrollmentId: pending.enrollmentId,
            expectedHubOrigin: pending.expectedHubOrigin,
            expectedProbeId: pending.expectedProbeId,
            sourceProbeVersion: pending.expectedProbeVersion,
            sourceProbeSha256,
            targetAssetSetDigest: pending.targetAssetSetDigest,
            targetHostId: pending.targetHostId,
            targetKind: "manual_reinstall",
            targetProbeVersion: pending.targetProbeVersion,
          },
          kind: "ready",
        };
      });
    },
    inspectPending(input) {
      const pending = database
        .select({
          enrollmentId: enrollmentTokens.enrollmentId,
          expectedHubOrigin: enrollmentTokens.expectedHubOrigin,
          expectedProbeId: enrollmentTokens.expectedProbeId,
          expectedProbeVersion: enrollmentTokens.expectedProbeVersion,
          sourceProbeSha256Json: enrollmentTokens.sourceProbeSha256Json,
          targetAssetSetDigest: enrollmentTokens.targetAssetSetDigest,
          targetHostId: enrollmentTokens.targetHostId,
          targetKind: enrollmentTokens.targetKind,
          targetProbeVersion: enrollmentTokens.targetProbeVersion,
          replacementPredecessorEnrollmentId:
            enrollmentTokens.replacementPredecessorEnrollmentId,
          replacementPredecessorAssetSetDigest:
            enrollmentTokens.replacementPredecessorAssetSetDigest,
          targetBundlesJson: enrollmentTokens.targetBundlesJson,
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
          !pending.enrollmentId ||
          pending.targetHostId === null ||
          !pending.expectedHubOrigin ||
          !pending.expectedProbeId ||
          !pending.expectedProbeVersion ||
          !pending.sourceProbeSha256Json ||
          !pending.targetAssetSetDigest ||
          !pending.targetBundlesJson ||
          !pending.targetProbeVersion
        ) {
          return null;
        }
        const predecessorCorrelation =
          parseReplacementPredecessorCorrelation(pending);
        if (!predecessorCorrelation) return null;
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
          (predecessorCorrelation.kind === "ordinary" &&
            !sameProbeAssetVersion(
              host.probeVersion,
              pending.expectedProbeVersion,
            )) ||
          (predecessorCorrelation.kind === "terminal" &&
            !terminalReplacementPredecessorMatches(database, {
              currentProbeId: host.probeId,
              hostId: host.id,
              pending,
            }))
        ) {
          return null;
        }
        const sourceProbeSha256 = parseSourceProbeSha256(
          pending.sourceProbeSha256Json,
        );
        if (
          !sourceProbeSha256 ||
          !parseTargetBundles(pending.targetBundlesJson)
        ) {
          return null;
        }
        return {
          enrollmentId: pending.enrollmentId,
          expectedHubOrigin: pending.expectedHubOrigin,
          expectedProbeId: pending.expectedProbeId,
          sourceProbeVersion: pending.expectedProbeVersion,
          sourceProbeSha256,
          targetAssetSetDigest: pending.targetAssetSetDigest,
          targetHostId: pending.targetHostId,
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
            !sameProbeAssetVersion(
              input.probeVersion,
              enrollment.targetProbeVersion,
            ) ||
            !sameProbeAssetVersion(
              input.probeAssetBundleVersion,
              enrollment.targetProbeVersion,
            ))
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
      const predecessorCorrelation =
        input.target.kind === "manual_reinstall"
          ? parseReplacementPredecessorCorrelation({
              replacementPredecessorAssetSetDigest:
                input.target.replacementPredecessorAssetSetDigest ?? null,
              replacementPredecessorEnrollmentId:
                input.target.replacementPredecessorEnrollmentId ?? null,
            })
          : { kind: "ordinary" as const };
      if (!predecessorCorrelation) {
        return { kind: "existing_host_unavailable" };
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
          if (!validTargetBundles(input.target.targetBundles)) {
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
            (predecessorCorrelation.kind === "ordinary" &&
              !sameProbeAssetVersion(
                target.probeVersion,
                input.target.expectedProbeVersion,
              )) ||
            (predecessorCorrelation.kind === "terminal" &&
              !terminalReplacementPredecessorMatches(transaction, {
                currentProbeId: target.probeId,
                hostId: target.id,
                pending: {
                  expectedProbeId: input.target.expectedProbeId,
                  expectedProbeVersion: input.target.expectedProbeVersion,
                  replacementPredecessorEnrollmentId:
                    predecessorCorrelation.enrollmentId,
                  replacementPredecessorAssetSetDigest:
                    predecessorCorrelation.assetSetDigest,
                  targetAssetSetDigest: input.target.targetAssetSetDigest,
                  targetHostId: input.target.hostId,
                  targetProbeVersion: input.target.targetProbeVersion,
                },
              }))
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
            targetBundlesJson:
              input.target.kind === "manual_reinstall"
                ? JSON.stringify(input.target.targetBundles)
                : null,
            replacementPredecessorEnrollmentId:
              input.target.kind === "manual_reinstall"
                ? predecessorCorrelation.kind === "terminal"
                  ? predecessorCorrelation.enrollmentId
                  : null
                : null,
            replacementPredecessorAssetSetDigest:
              input.target.kind === "manual_reinstall"
                ? predecessorCorrelation.kind === "terminal"
                  ? predecessorCorrelation.assetSetDigest
                  : null
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
      const hostInput = () =>
        typeof input.host === "function" ? input.host() : input.host;
      if (
        input.verificationDeadlineAtMs <= input.registeredAtMs ||
        (typeof input.host !== "function" &&
          (!input.host.displayName.trim() ||
            !input.host.probeId ||
            !input.host.probePublicKeyPem))
      ) {
        throw new Error("Invalid Probe Enrollment registration input.");
      }

      try {
        return database.transaction((transaction) => {
          if (input.registrationAttempt) {
            const attempted = transaction
              .select()
              .from(enrollmentTokens)
              .where(eq(enrollmentTokens.tokenHash, input.tokenHash))
              .get();
            const attemptedCorrelation = attempted
              ? parseReplacementPredecessorCorrelation(attempted)
              : null;
            if (
              attempted?.targetKind === "manual_reinstall" &&
              (!attemptedCorrelation ||
                !validPersistedManualSourceClosure(attempted))
            ) {
              return null;
            }
            if (
              attempted?.usedAtMs !== null &&
              attempted?.registrationAttemptSha256 ===
                input.registrationAttempt.signedAttemptSha256 &&
              attempted.registrationOutcome
            ) {
              const replayHost = attempted.hostId
                ? transaction
                    .select()
                    .from(hosts)
                    .where(eq(hosts.id, attempted.hostId))
                    .get()
                : null;
              if (!replayHost) {
                return null;
              }
              return {
                enrollment: attempted,
                host: replayHost,
                registrationOutcome: attempted.registrationOutcome,
                replayed: true,
              };
            }
            if (attempted?.usedAtMs !== null) {
              return null;
            }
          }
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
          const predecessorCorrelation =
            pending.targetKind === "manual_reinstall"
              ? parseReplacementPredecessorCorrelation(pending)
              : { kind: "ordinary" as const };
          if (!predecessorCorrelation) return null;

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
            (pending.targetKind === "manual_reinstall") !==
            Boolean(input.registrationAttempt)
          ) {
            return null;
          }

          if (
            pending.targetKind === "manual_reinstall" &&
            (!pending.expectedHubOrigin ||
              !pending.expectedProbeId ||
              !pending.expectedProbeVersion ||
              !pending.targetAssetSetDigest ||
              !pending.targetBundlesJson ||
              !pending.targetProbeVersion ||
              existingHost?.probeId !== pending.expectedProbeId ||
              (predecessorCorrelation.kind === "ordinary" &&
                !sameProbeAssetVersion(
                  existingHost.probeVersion,
                  pending.expectedProbeVersion,
                )) ||
              (predecessorCorrelation.kind === "terminal" &&
                !terminalReplacementPredecessorMatches(transaction, {
                  currentProbeId: existingHost.probeId,
                  hostId: existingHost.id,
                  pending,
                })))
          ) {
            return null;
          }
          if (
            input.registrationAttempt &&
            (pending.targetKind !== "manual_reinstall" ||
              pending.enrollmentId !== input.registrationAttempt.enrollmentId ||
              pending.expectedHubOrigin !==
                input.registrationAttempt.hubOrigin ||
              pending.targetHostId !== input.registrationAttempt.hostId ||
              pending.expectedProbeId !==
                input.registrationAttempt.oldProbeId ||
              pending.expectedProbeVersion !==
                input.registrationAttempt.sourceProbeVersion ||
              !sourceReceiptMatchesTargetBundle(
                pending.sourceProbeSha256Json ?? "",
                pending.targetBundlesJson ?? "",
                input.registrationAttempt.targetBundleTarget,
                input.registrationAttempt.committedSourceProbeSha256,
              ) ||
              pending.targetAssetSetDigest !==
                input.registrationAttempt.targetAssetSetDigest ||
              pending.targetProbeVersion !==
                input.registrationAttempt.targetProbeVersion ||
              !targetBundleMatches(
                pending.targetBundlesJson ?? "",
                input.registrationAttempt.targetBundleTarget,
                input.registrationAttempt.targetManifestSha256,
              ))
          ) {
            return null;
          }

          const consumed = transaction
            .update(enrollmentTokens)
            .set({
              registrationAttemptSha256:
                input.registrationAttempt?.signedAttemptSha256 ?? null,
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
              ? createNewHostForEnrollment(transaction, {
                  ...input,
                  host: hostInput(),
                } as ResolvedRegisterNewHostEnrollmentInput)
              : replaceExistingHostProbeIdentity(
                  transaction,
                  existingHost ?? null,
                  {
                    ...input,
                    host: hostInput(),
                  } as ResolvedRegisterNewHostEnrollmentInput,
                );

          if (
            input.registrationAttempt &&
            (host.id !== input.registrationAttempt.hostId ||
              host.probePublicKeyPem !==
                input.registrationAttempt.candidatePublicKeyPem)
          ) {
            throw new ExistingHostEnrollmentTargetUnavailable();
          }
          const registrationOutcome =
            input.registrationAttempt?.outcome(host) ?? null;
          if (input.registrationAttempt && !registrationOutcome?.length) {
            throw new Error("Invalid registration replay outcome.");
          }

          const enrollment = transaction
            .update(enrollmentTokens)
            .set({
              hostId: host.id,
              registrationOutcome,
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

          return {
            enrollment,
            host,
            registrationOutcome,
            replayed: false,
          };
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

function validManualImmutableFields(
  pending: {
    enrollmentId: string | null;
    expectedHubOrigin: string | null;
    expectedProbeId: string | null;
    expectedProbeVersion: string | null;
    targetAssetSetDigest: string | null;
    targetProbeVersion: string | null;
  },
  sourceProbeSha256: string[],
) {
  return (
    validEnrollmentId(pending.enrollmentId) &&
    validHubOrigin(pending.expectedHubOrigin) &&
    validProbeId(pending.expectedProbeId) &&
    validSemver(pending.expectedProbeVersion) &&
    /^sha256:[0-9a-f]{64}$/.test(pending.targetAssetSetDigest ?? "") &&
    validSemver(pending.targetProbeVersion) &&
    sourceProbeSha256.length === probeTargets.length
  );
}

function validLegacyOrdinaryImmutableFields(
  pending: {
    enrollmentId: string | null;
    expectedHubOrigin: string | null;
    expectedProbeId: string | null;
    expectedProbeVersion: string | null;
    targetAssetSetDigest: string | null;
    targetProbeVersion: string | null;
  },
  sourceProbeSha256: string[],
) {
  return validManualImmutableFields(pending, sourceProbeSha256);
}

function validHubOrigin(value: string | null) {
  try {
    const url = new URL(value ?? "");
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      url.origin === value &&
      !url.username &&
      !url.password
    );
  } catch {
    return false;
  }
}

function validProbeId(value: string | null) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

function validSemver(value: string | null) {
  return /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value ?? "");
}

function sameProbeAssetVersion(
  left: string | null | undefined,
  right: string | null | undefined,
) {
  if (left?.trim() !== left || right?.trim() !== right) {
    return false;
  }
  const normalizedLeft = normalizeSemVer(left);
  const normalizedRight = normalizeSemVer(right);
  return normalizedLeft !== null && normalizedLeft === normalizedRight;
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
    value.length === probeTargets.length &&
    new Set(value).size === value.length &&
    value.every(
      (digest) => typeof digest === "string" && /^[0-9a-f]{64}$/.test(digest),
    )
  );
}

const probeTargets = [
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
] as const;

function validTargetBundles(value: unknown) {
  return (
    Array.isArray(value) &&
    value.length === probeTargets.length &&
    value.every(
      (bundle, index) =>
        bundle &&
        typeof bundle === "object" &&
        !Array.isArray(bundle) &&
        bundle.target === probeTargets[index] &&
        /^[0-9a-f]{64}$/.test(bundle.bundleManifestSha256),
    )
  );
}

function parseTargetBundles(value: string) {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) &&
      parsed.every(
        (bundle) =>
          bundle &&
          typeof bundle === "object" &&
          !Array.isArray(bundle) &&
          Object.keys(bundle as object)
            .sort()
            .join(",") === "bundleManifestSha256,target",
      ) &&
      validTargetBundles(
        parsed as Array<{ bundleManifestSha256: string; target: string }>,
      )
      ? (parsed as Array<{ bundleManifestSha256: string; target: string }>)
      : null;
  } catch {
    return null;
  }
}

function targetBundleMatches(
  targetBundlesJson: string,
  target: string,
  bundleManifestSha256: string,
) {
  return (
    parseTargetBundles(targetBundlesJson)?.some(
      (bundle) =>
        bundle.target === target &&
        bundle.bundleManifestSha256 === bundleManifestSha256,
    ) === true
  );
}

function sourceReceiptMatchesTargetBundle(
  sourceProbeSha256Json: string,
  targetBundlesJson: string,
  target: string,
  sourceReceipt: string,
) {
  const sourceProbeSha256 = parseSourceProbeSha256(sourceProbeSha256Json);
  const targetBundles = parseTargetBundles(targetBundlesJson);
  const targetIndex = targetBundles?.findIndex(
    (bundle) => bundle.target === target,
  );
  return (
    sourceProbeSha256 !== null &&
    targetIndex !== undefined &&
    targetIndex >= 0 &&
    sourceProbeSha256[targetIndex] === sourceReceipt
  );
}

function validPersistedManualSourceClosure(input: {
  sourceProbeSha256Json: string | null;
  targetBundlesJson: string | null;
}) {
  return (
    parseSourceProbeSha256(input.sourceProbeSha256Json ?? "") !== null &&
    parseTargetBundles(input.targetBundlesJson ?? "") !== null
  );
}

type ReplacementPredecessorCorrelation =
  | { kind: "ordinary" }
  | {
      assetSetDigest: string;
      enrollmentId: string;
      kind: "terminal";
    };

function parseReplacementPredecessorCorrelation(input: {
  replacementPredecessorAssetSetDigest: string | null;
  replacementPredecessorEnrollmentId: string | null;
}): ReplacementPredecessorCorrelation | null {
  if (
    input.replacementPredecessorEnrollmentId === null &&
    input.replacementPredecessorAssetSetDigest === null
  ) {
    return { kind: "ordinary" };
  }
  if (
    validEnrollmentId(input.replacementPredecessorEnrollmentId) &&
    /^sha256:[0-9a-f]{64}$/.test(
      input.replacementPredecessorAssetSetDigest ?? "",
    )
  ) {
    return {
      assetSetDigest: input.replacementPredecessorAssetSetDigest as string,
      enrollmentId: input.replacementPredecessorEnrollmentId,
      kind: "terminal",
    };
  }
  return null;
}

/**
 * 终态 replacement recovery 只承认 pending 行显式指向的那一条已消费
 * Enrollment；不能以“最近一条”历史代替这项关联。这里故意在每个事务
 * seam 重读 predecessor 与其 canonical registration outcome。
 */
function terminalReplacementPredecessorMatches(
  database: EnrollmentDatabase,
  input: {
    currentProbeId: string;
    hostId: number;
    pending: {
      expectedProbeId: string | null;
      expectedProbeVersion: string | null;
      replacementPredecessorAssetSetDigest: string | null;
      replacementPredecessorEnrollmentId: string | null;
      targetAssetSetDigest: string | null;
      targetHostId: number | null;
      targetProbeVersion: string | null;
    };
  },
) {
  const predecessorCorrelation = parseReplacementPredecessorCorrelation(
    input.pending,
  );
  if (
    predecessorCorrelation?.kind !== "terminal" ||
    input.pending.targetHostId !== input.hostId
  ) {
    return false;
  }
  const predecessorId = predecessorCorrelation.enrollmentId;
  const predecessor = database
    .select()
    .from(enrollmentTokens)
    .where(eq(enrollmentTokens.enrollmentId, predecessorId))
    .get();
  if (
    !predecessor ||
    predecessor.targetKind !== "manual_reinstall" ||
    predecessor.status !== "rejected" ||
    predecessor.rejectionCode !== "probe_startup_timeout" ||
    predecessor.hostId !== input.hostId ||
    predecessor.targetProbeVersion !== input.pending.expectedProbeVersion ||
    predecessor.targetAssetSetDigest !==
      predecessorCorrelation.assetSetDigest ||
    !predecessor.registrationOutcome
  ) {
    return false;
  }
  try {
    const outcome = (enoki.v1.ProbeRegistrationResponse as any).decode(
      predecessor.registrationOutcome,
    ) as { hostId?: string; probeId?: string };
    return (
      outcome.hostId === String(input.hostId) &&
      outcome.probeId === input.currentProbeId &&
      input.pending.expectedProbeId === input.currentProbeId
    );
  } catch {
    return false;
  }
}

function createNewHostForEnrollment(
  transaction: EnrollmentDatabase,
  input: ResolvedRegisterNewHostEnrollmentInput,
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
  input: ResolvedRegisterNewHostEnrollmentInput,
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
