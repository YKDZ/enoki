import { and, desc, eq, gt, inArray, lte, notExists, or } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";
import { alias } from "drizzle-orm/sqlite-core";

import type {
  ProbeUpgradeRequest,
  ProbeUpgradeRequestLifecycleEvent,
} from "../probe/operation.js";
import {
  probeOperations,
  type NewProbeOperationRow,
  type ProbeOperationRow,
} from "./schema.js";

type ProbeOperationDatabase = NodeSQLiteDatabase<typeof import("./schema.js")>;

const activeStates = ["pending", "accepted", "running"] as const;

export type ProbeOperationRepository = {
  admitPendingProbeUpgradeRequest: (
    id: number,
    nowMs: number,
    targetManifestSha256: string,
    upgradeAuthoritySha256: string,
    verifiedStageSha256: string,
  ) => ProbeUpgradeRequest | null;
  createProbeUpgradeRequest: (
    operation: ProbeUpgradeRequest,
  ) => ProbeUpgradeRequest;
  commitProbeUpgradeAuthorization: (
    events: ProbeUpgradeRequestLifecycleEvent[],
  ) => ProbeUpgradeRequest;
  findActiveForHost: (hostId: number) => ProbeUpgradeRequest | null;
  findById: (id: number) => ProbeUpgradeRequest | null;
  findByRepairEvidenceSha256: (sha256: string) => ProbeUpgradeRequest | null;
  findBoundFailedUpgradeForRepair: (
    repair: ProbeUpgradeRequest,
  ) => ProbeUpgradeRequest | null;
  findLatestForHost: (hostId: number) => ProbeUpgradeRequest | null;
  findLatestForHosts: (hostIds: number[]) => Map<number, ProbeUpgradeRequest>;
  renewOrCreateProbeRepairRequest: (
    candidate: ProbeUpgradeRequest,
    nowMs: number,
  ) => ProbeUpgradeRequest | null;
  updateProbeUpgradeRequest: (
    operation: ProbeUpgradeRequest,
  ) => ProbeUpgradeRequest;
};

export function createProbeOperationRepository(
  database: ProbeOperationDatabase,
): ProbeOperationRepository {
  return {
    admitPendingProbeUpgradeRequest(
      id,
      nowMs,
      targetManifestSha256,
      upgradeAuthoritySha256,
      verifiedStageSha256,
    ) {
      const row = database
        .update(probeOperations)
        .set({
          acceptedAtMs: nowMs,
          runningAtMs: nowMs,
          state: "running",
          targetManifestSha256,
          upgradeAuthoritySha256,
          updatedAtMs: nowMs,
          verifiedStageSha256,
        })
        .where(
          and(eq(probeOperations.id, id), eq(probeOperations.state, "pending")),
        )
        .returning()
        .get();
      return row ? rowToProbeUpgradeRequest(row) : null;
    },
    createProbeUpgradeRequest(operation) {
      const row = database
        .insert(probeOperations)
        .values(probeUpgradeRequestToRow(operation))
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to create Probe Upgrade Request.");
      }

      return rowToProbeUpgradeRequest(row);
    },
    commitProbeUpgradeAuthorization(events) {
      if (events.length === 0) {
        throw new Error("A reused Probe Upgrade Request is already persisted.");
      }
      return database.transaction((transaction) => {
        let authorized: ProbeUpgradeRequest | null = null;
        for (const event of events) {
          if (event.action === "superseded") {
            if (event.operation.id === null) {
              throw new Error("Cannot supersede an unsaved Probe Operation.");
            }
            const row = transaction
              .update(probeOperations)
              .set(probeUpgradeRequestToRow(event.operation))
              .where(eq(probeOperations.id, event.operation.id))
              .returning()
              .get();
            if (!row) {
              throw new Error("Failed to supersede Probe Upgrade Request.");
            }
            continue;
          }

          const row = transaction
            .insert(probeOperations)
            .values(probeUpgradeRequestToRow(event.operation))
            .returning()
            .get();
          if (!row) {
            throw new Error("Failed to create Probe Upgrade Request.");
          }
          authorized = rowToProbeUpgradeRequest(row);
        }
        if (!authorized) {
          throw new Error(
            "Probe Upgrade authorization did not create a request.",
          );
        }
        return authorized;
      }) as ProbeUpgradeRequest;
    },
    findActiveForHost(hostId) {
      const row =
        database
          .select()
          .from(probeOperations)
          .where(
            and(
              inArray(probeOperations.state, activeStates),
              eq(probeOperations.managedHostId, hostId),
            ),
          )
          .orderBy(desc(probeOperations.updatedAtMs), desc(probeOperations.id))
          .get() ?? null;

      return row ? rowToProbeUpgradeRequest(row) : null;
    },
    findById(id) {
      const row =
        database
          .select()
          .from(probeOperations)
          .where(eq(probeOperations.id, id))
          .get() ?? null;

      return row ? rowToProbeUpgradeRequest(row) : null;
    },
    findByRepairEvidenceSha256(sha256) {
      const row =
        database
          .select()
          .from(probeOperations)
          .where(eq(probeOperations.repairEvidenceSha256, sha256))
          .get() ?? null;
      return row ? rowToProbeUpgradeRequest(row) : null;
    },
    findBoundFailedUpgradeForRepair(repair) {
      if (
        repair.id === null ||
        repair.kind !== "probe_repair" ||
        repair.repairFailedOperationId === null ||
        repair.repairFailedOperationId === undefined ||
        repair.repairFailedOperationId === repair.id
      ) {
        return null;
      }
      const failedUpgrade = alias(probeOperations, "failed_probe_upgrade");
      const row = database
        .select({ failedUpgrade })
        .from(probeOperations)
        .innerJoin(
          failedUpgrade,
          and(
            eq(failedUpgrade.id, probeOperations.repairFailedOperationId),
            eq(failedUpgrade.managedHostId, probeOperations.managedHostId),
            eq(
              failedUpgrade.targetProbeVersion,
              probeOperations.targetProbeVersion,
            ),
            eq(
              failedUpgrade.targetAssetSetDigest,
              probeOperations.targetAssetSetDigest,
            ),
            eq(
              failedUpgrade.targetManifestSha256,
              probeOperations.targetManifestSha256,
            ),
            eq(
              failedUpgrade.verifiedStageSha256,
              probeOperations.verifiedStageSha256,
            ),
            eq(
              failedUpgrade.upgradeAuthoritySha256,
              probeOperations.upgradeAuthoritySha256,
            ),
          ),
        )
        .where(
          and(
            eq(probeOperations.id, repair.id),
            eq(probeOperations.kind, "probe_repair"),
            eq(failedUpgrade.kind, "probe_upgrade"),
            eq(failedUpgrade.state, "failed"),
          ),
        )
        .get();
      return row ? rowToProbeUpgradeRequest(row.failedUpgrade) : null;
    },
    findLatestForHost(hostId) {
      const row =
        database
          .select()
          .from(probeOperations)
          .where(eq(probeOperations.managedHostId, hostId))
          .orderBy(desc(probeOperations.updatedAtMs), desc(probeOperations.id))
          .get() ?? null;

      return row ? rowToProbeUpgradeRequest(row) : null;
    },
    findLatestForHosts(hostIds) {
      if (hostIds.length === 0) {
        return new Map();
      }

      const newerOperation = alias(probeOperations, "newer_probe_operation");
      const rows = database
        .select()
        .from(probeOperations)
        .where(
          and(
            inArray(probeOperations.managedHostId, hostIds),
            notExists(
              database
                .select({ id: newerOperation.id })
                .from(newerOperation)
                .where(
                  and(
                    eq(
                      newerOperation.managedHostId,
                      probeOperations.managedHostId,
                    ),
                    or(
                      gt(
                        newerOperation.updatedAtMs,
                        probeOperations.updatedAtMs,
                      ),
                      and(
                        eq(
                          newerOperation.updatedAtMs,
                          probeOperations.updatedAtMs,
                        ),
                        gt(newerOperation.id, probeOperations.id),
                      ),
                    ),
                  ),
                ),
            ),
          ),
        )
        .all();

      return new Map(
        rows.map((row) => [row.managedHostId, rowToProbeUpgradeRequest(row)]),
      );
    },
    renewOrCreateProbeRepairRequest(candidate, nowMs) {
      if (
        candidate.id !== null ||
        candidate.kind !== "probe_repair" ||
        candidate.state !== "accepted" ||
        !candidate.repairEvidenceSha256 ||
        !candidate.repairFailedOperationId
      ) {
        throw new Error("Invalid Probe Repair replacement candidate.");
      }
      return database.transaction((transaction) => {
        const existing = transaction
          .select()
          .from(probeOperations)
          .where(
            eq(
              probeOperations.repairEvidenceSha256,
              candidate.repairEvidenceSha256!,
            ),
          )
          .get();
        if (existing) return rowToProbeUpgradeRequest(existing);

        const active = transaction
          .select()
          .from(probeOperations)
          .where(
            and(
              inArray(probeOperations.state, activeStates),
              eq(probeOperations.managedHostId, candidate.hostId),
            ),
          )
          .orderBy(desc(probeOperations.updatedAtMs), desc(probeOperations.id))
          .get();
        if (active) {
          if (
            active.kind !== "probe_repair" ||
            active.state !== "accepted" ||
            active.repairFailedOperationId !==
              candidate.repairFailedOperationId ||
            active.repairAuthorityExpiresAtMs === null ||
            active.repairAuthorityExpiresAtMs > nowMs
          ) {
            return null;
          }
          const terminalized = transaction
            .update(probeOperations)
            .set({
              completedAtMs: nowMs,
              failureCode: "repair_authority_expired",
              failureMessage: null,
              state: "failed",
              updatedAtMs: nowMs,
            })
            .where(
              and(
                eq(probeOperations.id, active.id),
                eq(probeOperations.state, "accepted"),
                lte(probeOperations.repairAuthorityExpiresAtMs, nowMs),
              ),
            )
            .returning({ id: probeOperations.id })
            .get();
          if (!terminalized) return null;
        }
        const inserted = transaction
          .insert(probeOperations)
          .values(probeUpgradeRequestToRow(candidate))
          .returning()
          .get();
        if (!inserted)
          throw new Error("Failed to create Probe Repair Request.");
        return rowToProbeUpgradeRequest(inserted);
      });
    },
    updateProbeUpgradeRequest(operation) {
      if (operation.id === null) {
        throw new Error("Cannot update unsaved Probe Upgrade Request.");
      }

      const row = database
        .update(probeOperations)
        .set(probeUpgradeRequestToRow(operation))
        .where(eq(probeOperations.id, operation.id))
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to update Probe Upgrade Request.");
      }

      return rowToProbeUpgradeRequest(row);
    },
  };
}

function probeUpgradeRequestToRow(
  operation: ProbeUpgradeRequest,
): NewProbeOperationRow {
  return {
    acceptedAtMs: operation.acceptedAtMs,
    canceledAtMs: operation.canceledAtMs,
    completedAtMs: operation.completedAtMs,
    createdAtMs: operation.createdAtMs,
    currentProbeVersion: operation.currentProbeVersion,
    failureCode: operation.failureCode,
    failureMessage: operation.failureMessage,
    id: operation.id ?? undefined,
    kind: operation.kind,
    managedHostId: operation.hostId,
    repairAuthorityExpiresAtMs: operation.repairAuthorityExpiresAtMs,
    repairEligibilityEvidenceJson: operation.repairEligibilityEvidenceJson,
    repairEligibilityEvidenceSha256: operation.repairEligibilityEvidenceSha256,
    repairEvidenceSha256: operation.repairEvidenceSha256,
    repairFailedOperationId: operation.repairFailedOperationId,
    repairNonce: operation.repairNonce,
    runningAtMs: operation.runningAtMs,
    state: operation.state,
    supersededAtMs: operation.supersededAtMs,
    targetAssetSetDigest: operation.targetAssetSetDigest,
    targetManifestSha256: operation.targetManifestSha256,
    targetProbeVersion: operation.targetProbeVersion,
    updatedAtMs: operation.updatedAtMs,
    upgradeAuthoritySha256: operation.upgradeAuthoritySha256,
    verifiedStageSha256: operation.verifiedStageSha256,
  };
}

function rowToProbeUpgradeRequest(row: ProbeOperationRow): ProbeUpgradeRequest {
  return {
    acceptedAtMs: row.acceptedAtMs,
    canceledAtMs: row.canceledAtMs,
    completedAtMs: row.completedAtMs,
    createdAtMs: row.createdAtMs,
    currentProbeVersion: row.currentProbeVersion,
    failureCode: row.failureCode,
    failureMessage: row.failureMessage,
    hostId: row.managedHostId,
    id: row.id,
    kind: row.kind as ProbeUpgradeRequest["kind"],
    repairAuthorityExpiresAtMs: row.repairAuthorityExpiresAtMs,
    repairEligibilityEvidenceJson: row.repairEligibilityEvidenceJson,
    repairEligibilityEvidenceSha256: row.repairEligibilityEvidenceSha256,
    repairEvidenceSha256: row.repairEvidenceSha256,
    repairFailedOperationId: row.repairFailedOperationId,
    repairNonce: row.repairNonce,
    runningAtMs: row.runningAtMs,
    state: row.state as ProbeUpgradeRequest["state"],
    supersededAtMs: row.supersededAtMs,
    targetAssetSetDigest: row.targetAssetSetDigest,
    targetManifestSha256: row.targetManifestSha256,
    targetProbeVersion: row.targetProbeVersion,
    updatedAtMs: row.updatedAtMs,
    upgradeAuthoritySha256: row.upgradeAuthoritySha256,
    verifiedStageSha256: row.verifiedStageSha256,
  };
}
