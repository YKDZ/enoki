import { and, eq, isNull } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";

import {
  managedHosts,
  type ManagedHostRow,
  type NewManagedHostRow,
} from "./schema.js";

type ManagedHostDatabase = BetterSQLite3Database<typeof import("./schema.js")>;

export type ManagedHostSummary = {
  clockSkew: {
    detected: boolean;
    lastDeltaMs: number | null;
  };
  connectAddress: string;
  cpu: string;
  cpuModel: string | null;
  description: string;
  displayName: string;
  id: number;
  lastReportAtMs: number | null;
  latestMetrics: {
    collectedAtMs: number;
    cpuPercent: number | null;
    diskTotalBytes: number | null;
    diskUsedBytes: number | null;
    load1: number | null;
    load5: number | null;
    load15: number | null;
    memoryTotalBytes: number | null;
    memoryUsedBytes: number | null;
    networkRxBytesDelta: number | null;
    networkTxBytesDelta: number | null;
    receivedAtMs: number;
    uptimeSeconds: number | null;
  } | null;
  memory: string;
  probeVersion: string;
  probeConfiguration: {
    mode: "inherit" | "override";
    version: string;
  };
  probeConfigurationError: {
    errorCode: string;
    failedVersion: string;
    message: string;
    reportedAtMs: number;
  } | null;
  status: "online" | "stale" | "offline";
  system: string;
};

export type HostStatusThresholds = {
  offlineAfterMs: number;
  staleAfterMs: number;
};

export type ManagedHostSummaryOptions = {
  latestMetricForHost?: (managedHostId: number) => {
    collectedAtMs: number;
    cpuPercent: number | null;
    diskTotalBytes: number | null;
    diskUsedBytes: number | null;
    load1: number | null;
    load5: number | null;
    load15: number | null;
    memoryTotalBytes: number | null;
    memoryUsedBytes: number | null;
    networkRxBytesDelta: number | null;
    networkTxBytesDelta: number | null;
    receivedAtMs: number;
    uptimeSeconds: number | null;
  } | null;
  nowMs?: number;
  probeConfigurationForHost?: (managedHostId: number) => {
    mode: "inherit" | "override";
    version: string;
  };
  thresholds?: HostStatusThresholds;
};

export type ManagedHostRepository = {
  create: (input: NewManagedHostRow) => ManagedHostRow;
  exists: (id: number) => boolean;
  findActiveById: (id: number) => ManagedHostRow | null;
  findByProbeSecretHash: (probeSecretHash: string) => ManagedHostRow | null;
  listSummaries: (options?: ManagedHostSummaryOptions) => ManagedHostSummary[];
  recordReport: (
    id: number,
    input: {
      architecture?: string | null;
      cpuCount?: number | null;
      cpuModel?: string | null;
      hostname?: string | null;
      inventoryHash?: string | null;
      inventoryJson?: string | null;
      kernel?: string | null;
      connectAddress?: string | null;
      clockSkewDetected?: boolean;
      lastClockSkewMs?: number | null;
      lastReportAtMs: number;
      memoryTotalBytes?: number | null;
      observedIp?: string | null;
      os?: string | null;
      probeConfigurationError?: {
        errorCode: string;
        failedVersion: string;
        message: string;
        reportedAtMs: number;
      } | null;
      probeVersion?: string | null;
    },
  ) => ManagedHostRow;
  softDelete: (id: number, deletedAtMs: number) => ManagedHostRow | null;
  updateMetadata: (
    id: number,
    input: {
      connectAddress?: string;
      description?: string;
      displayName?: string;
    },
  ) => ManagedHostRow | null;
};

export function createManagedHostRepository(
  database: ManagedHostDatabase,
): ManagedHostRepository {
  return {
    create(input) {
      const row = database.insert(managedHosts).values(input).returning().get();

      if (!row) {
        throw new Error("Failed to create Managed Host.");
      }

      return row;
    },
    exists(id) {
      const row = database
        .select({ id: managedHosts.id })
        .from(managedHosts)
        .where(and(eq(managedHosts.id, id), isNull(managedHosts.deletedAtMs)))
        .get();

      return Boolean(row);
    },
    findActiveById(id) {
      return (
        database
          .select()
          .from(managedHosts)
          .where(and(eq(managedHosts.id, id), isNull(managedHosts.deletedAtMs)))
          .get() ?? null
      );
    },
    findByProbeSecretHash(probeSecretHash) {
      return (
        database
          .select()
          .from(managedHosts)
          .where(
            and(
              eq(managedHosts.probeSecretHash, probeSecretHash),
              isNull(managedHosts.deletedAtMs),
            ),
          )
          .get() ?? null
      );
    },
    listSummaries(options = {}) {
      const nowMs = options.nowMs ?? Date.now();
      const thresholds = options.thresholds ?? defaultHostStatusThresholds;

      return database
        .select()
        .from(managedHosts)
        .where(isNull(managedHosts.deletedAtMs))
        .all()
        .map((host) => {
          const latestMetric = options.latestMetricForHost?.(host.id) ?? null;

          return {
            connectAddress: host.connectAddress,
            clockSkew: {
              detected: host.clockSkewDetected,
              lastDeltaMs: host.lastClockSkewMs,
            },
            cpu: formatCpu(host.cpuCount),
            cpuModel: host.cpuModel,
            description: host.description,
            displayName: host.displayName,
            id: host.id,
            lastReportAtMs: host.lastReportAtMs,
            latestMetrics: latestMetric
              ? {
                  collectedAtMs: latestMetric.collectedAtMs,
                  cpuPercent: latestMetric.cpuPercent,
                  diskTotalBytes: latestMetric.diskTotalBytes,
                  diskUsedBytes: latestMetric.diskUsedBytes,
                  load1: latestMetric.load1,
                  load5: latestMetric.load5,
                  load15: latestMetric.load15,
                  memoryTotalBytes: latestMetric.memoryTotalBytes,
                  memoryUsedBytes: latestMetric.memoryUsedBytes,
                  networkRxBytesDelta: latestMetric.networkRxBytesDelta,
                  networkTxBytesDelta: latestMetric.networkTxBytesDelta,
                  receivedAtMs: latestMetric.receivedAtMs,
                  uptimeSeconds: latestMetric.uptimeSeconds,
                }
              : null,
            memory: formatBytes(host.memoryTotalBytes),
            probeConfiguration: options.probeConfigurationForHost?.(
              host.id,
            ) ?? {
              mode: "inherit",
              version: host.probeConfigurationVersion,
            },
            probeConfigurationError:
              host.probeConfigurationErrorFailedVersion &&
              host.probeConfigurationErrorCode &&
              host.probeConfigurationErrorMessage &&
              host.probeConfigurationErrorReportedAtMs !== null
                ? {
                    errorCode: host.probeConfigurationErrorCode,
                    failedVersion: host.probeConfigurationErrorFailedVersion,
                    message: host.probeConfigurationErrorMessage,
                    reportedAtMs: host.probeConfigurationErrorReportedAtMs,
                  }
                : null,
            probeVersion: host.probeVersion ?? "n/a",
            status: hostStatus(host.lastReportAtMs, nowMs, thresholds),
            system: formatSystem(host),
          };
        });
    },
    recordReport(id, input) {
      const current = database
        .select()
        .from(managedHosts)
        .where(eq(managedHosts.id, id))
        .get();

      if (!current) {
        throw new Error("Failed to update Managed Host report state.");
      }

      const values = {
        architecture: input.architecture,
        clockSkewDetected: input.clockSkewDetected,
        connectAddress:
          !current.connectAddressEdited && input.connectAddress
            ? input.connectAddress
            : undefined,
        cpuCount: input.cpuCount,
        cpuModel: input.cpuModel,
        displayName:
          !current.displayNameEdited && input.hostname?.trim()
            ? input.hostname.trim()
            : undefined,
        hostname: input.hostname,
        inventoryHash: input.inventoryHash,
        inventoryJson: input.inventoryJson,
        kernel: input.kernel,
        lastClockSkewMs: input.lastClockSkewMs,
        lastReportAtMs: input.lastReportAtMs,
        memoryTotalBytes: input.memoryTotalBytes,
        observedIp: input.observedIp,
        os: input.os,
        probeConfigurationErrorCode:
          input.probeConfigurationError === null
            ? null
            : input.probeConfigurationError?.errorCode,
        probeConfigurationErrorFailedVersion:
          input.probeConfigurationError === null
            ? null
            : input.probeConfigurationError?.failedVersion,
        probeConfigurationErrorMessage:
          input.probeConfigurationError === null
            ? null
            : input.probeConfigurationError?.message,
        probeConfigurationErrorReportedAtMs:
          input.probeConfigurationError === null
            ? null
            : input.probeConfigurationError?.reportedAtMs,
        probeVersion: input.probeVersion,
      };
      const row = database
        .update(managedHosts)
        .set(values)
        .where(eq(managedHosts.id, id))
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to update Managed Host report state.");
      }

      return row;
    },
    softDelete(id, deletedAtMs) {
      return (
        database
          .update(managedHosts)
          .set({
            deletedAtMs,
          })
          .where(and(eq(managedHosts.id, id), isNull(managedHosts.deletedAtMs)))
          .returning()
          .get() ?? null
      );
    },
    updateMetadata(id, input) {
      const current =
        database
          .select()
          .from(managedHosts)
          .where(and(eq(managedHosts.id, id), isNull(managedHosts.deletedAtMs)))
          .get() ?? null;

      if (!current) {
        return null;
      }

      const values: {
        connectAddress?: string;
        connectAddressEdited?: boolean;
        description?: string;
        displayName?: string;
        displayNameEdited?: boolean;
      } = {};

      if (
        input.connectAddress !== undefined &&
        input.connectAddress !== current.connectAddress
      ) {
        values.connectAddress = input.connectAddress;
        values.connectAddressEdited = true;
      }

      if (
        input.displayName !== undefined &&
        input.displayName !== current.displayName
      ) {
        values.displayName = input.displayName;
        values.displayNameEdited = true;
      }

      if (
        input.description !== undefined &&
        input.description !== current.description
      ) {
        values.description = input.description;
      }

      if (Object.keys(values).length === 0) {
        return current;
      }

      const row = database
        .update(managedHosts)
        .set(values)
        .where(and(eq(managedHosts.id, id), isNull(managedHosts.deletedAtMs)))
        .returning()
        .get();

      return row ?? null;
    },
  };
}

const defaultHostStatusThresholds = {
  offlineAfterMs: 90_000,
  staleAfterMs: 30_000,
};

function hostStatus(
  lastReportAtMs: number | null,
  nowMs: number,
  thresholds: HostStatusThresholds,
) {
  if (lastReportAtMs === null) {
    return "offline";
  }

  const ageMs = Math.max(0, nowMs - lastReportAtMs);

  if (ageMs >= thresholds.offlineAfterMs) {
    return "offline";
  }

  if (ageMs >= thresholds.staleAfterMs) {
    return "stale";
  }

  return "online";
}

function formatCpu(cpuCount: number | null) {
  if (!cpuCount) {
    return "n/a";
  }

  return `${cpuCount} ${cpuCount === 1 ? "core" : "cores"}`;
}

function formatBytes(bytes: number | null) {
  if (!bytes) {
    return "n/a";
  }

  const gibibytes = bytes / 1024 ** 3;
  if (gibibytes >= 1) {
    return `${formatNumber(gibibytes)} GiB`;
  }

  const mebibytes = bytes / 1024 ** 2;
  return `${formatNumber(mebibytes)} MiB`;
}

function formatNumber(value: number) {
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

function formatSystem(host: {
  architecture: string | null;
  kernel: string | null;
  os: string | null;
}) {
  const parts = [host.os, host.kernel, host.architecture].filter(
    (part): part is string => Boolean(part),
  );

  return parts.length > 0 ? parts.join(" ") : "n/a";
}
