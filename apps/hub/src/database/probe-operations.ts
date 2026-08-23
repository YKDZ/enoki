import { and, desc, eq, gt, inArray, notExists, or } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";
import { alias } from "drizzle-orm/sqlite-core";

import type { ProbeUpgradeRequest } from "../probe/operation.js";
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
  findActiveForHost: (hostId: number) => ProbeUpgradeRequest | null;
  findById: (id: number) => ProbeUpgradeRequest | null;
  findByRepairEvidenceSha256: (sha256: string) => ProbeUpgradeRequest | null;
  findLatestForHost: (hostId: number) => ProbeUpgradeRequest | null;
  findLatestForHosts: (hostIds: number[]) => Map<number, ProbeUpgradeRequest>;
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
