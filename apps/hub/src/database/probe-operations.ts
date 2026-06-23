import { and, desc, eq, inArray } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";

import type { ProbeUpgradeRequest } from "../probe/operation.js";
import {
  probeOperations,
  type NewProbeOperationRow,
  type ProbeOperationRow,
} from "./schema.js";

type ProbeOperationDatabase = NodeSQLiteDatabase<typeof import("./schema.js")>;

const activeStates = ["pending", "accepted", "running"] as const;

export type ProbeOperationRepository = {
  createProbeUpgradeRequest: (
    operation: ProbeUpgradeRequest,
  ) => ProbeUpgradeRequest;
  findActiveForHost: (hostId: number) => ProbeUpgradeRequest | null;
  findById: (id: number) => ProbeUpgradeRequest | null;
  findLatestForHost: (hostId: number) => ProbeUpgradeRequest | null;
  updateProbeUpgradeRequest: (
    operation: ProbeUpgradeRequest,
  ) => ProbeUpgradeRequest;
};

export function createProbeOperationRepository(
  database: ProbeOperationDatabase,
): ProbeOperationRepository {
  return {
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
    runningAtMs: operation.runningAtMs,
    state: operation.state,
    supersededAtMs: operation.supersededAtMs,
    targetProbeVersion: operation.targetProbeVersion,
    updatedAtMs: operation.updatedAtMs,
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
    runningAtMs: row.runningAtMs,
    state: row.state as ProbeUpgradeRequest["state"],
    supersededAtMs: row.supersededAtMs,
    targetProbeVersion: row.targetProbeVersion,
    updatedAtMs: row.updatedAtMs,
  };
}
