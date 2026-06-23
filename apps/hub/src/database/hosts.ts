import { and, eq, isNull, lte } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";

import {
  hosts,
  probeRequestNonces,
  type HostRow,
  type NewHostRow,
} from "./schema.js";

type HostDatabase = NodeSQLiteDatabase<typeof import("./schema.js")>;

export type HostSummary = {
  clockSkew: {
    detected: boolean;
    lastDeltaMs: number | null;
  };
  collectorCapabilities: CollectorCapabilities | null;
  connectAddress: string;
  cpu: string;
  cpuModel: string | null;
  description: string;
  displayName: string;
  id: number;
  lastReportAtMs: number | null;
  latestMetrics: {
    collectedAtMs: number;
    batteryPercent: number | null;
    batteryState: string | null;
    cpuIdlePercent: number | null;
    cpuIowaitPercent: number | null;
    cpuPercent: number | null;
    cpuStealPercent: number | null;
    cpuSystemPercent: number | null;
    cpuUserPercent: number | null;
    diskHealth?: Array<{
      deviceName: string;
      model: string | null;
      passed: boolean;
      powerOnHours: number | null;
      serialNumber: string | null;
      temperatureCelsius: number | null;
    }>;
    diskTotalBytes: number | null;
    diskUsedBytes: number | null;
    load1: number | null;
    load5: number | null;
    load15: number | null;
    memoryCacheBytes: number | null;
    memoryTotalBytes: number | null;
    memoryUsedBytes: number | null;
    networkRxBytesDelta: number | null;
    networkTxBytesDelta: number | null;
    receivedAtMs: number;
    swapTotalBytes: number | null;
    swapUsedBytes: number | null;
    temperatureCelsius: number | null;
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

export type CollectorCapabilities = {
  official?: {
    battery?: CollectorAvailability;
    cpu?: CollectorAvailability;
    disk?: CollectorAvailability;
    diskHealth?: CollectorAvailability;
    load?: CollectorAvailability;
    memory?: CollectorAvailability;
    network?: CollectorAvailability;
    temperature?: CollectorAvailability;
    uptime?: CollectorAvailability;
  };
};

export type CollectorAvailability = {
  available: boolean;
};

export type HostStatusThresholds = {
  offlineAfterMs: number;
  staleAfterMs: number;
};

export type HostSummaryOptions = {
  latestMetricForHost?: (hostId: number) => {
    collectedAtMs: number;
    batteryPercent: number | null;
    batteryState: string | null;
    cpuIdlePercent: number | null;
    cpuIowaitPercent: number | null;
    cpuPercent: number | null;
    cpuStealPercent: number | null;
    cpuSystemPercent: number | null;
    cpuUserPercent: number | null;
    diskHealth?: Array<{
      deviceName: string;
      model: string | null;
      passed: boolean;
      powerOnHours: number | null;
      serialNumber: string | null;
      temperatureCelsius: number | null;
    }>;
    diskTotalBytes: number | null;
    diskUsedBytes: number | null;
    load1: number | null;
    load5: number | null;
    load15: number | null;
    memoryCacheBytes: number | null;
    memoryTotalBytes: number | null;
    memoryUsedBytes: number | null;
    networkRxBytesDelta: number | null;
    networkTxBytesDelta: number | null;
    receivedAtMs: number;
    swapTotalBytes: number | null;
    swapUsedBytes: number | null;
    temperatureCelsius: number | null;
    uptimeSeconds: number | null;
  } | null;
  nowMs?: number;
  probeConfigurationForHost?: (hostId: number) => {
    mode: "inherit" | "override";
    version: string;
  };
  thresholds?: HostStatusThresholds;
};

export type HostRepository = {
  create: (input: NewHostRow) => HostRow;
  exists: (id: number) => boolean;
  findActiveById: (id: number) => HostRow | null;
  findByProbeId: (probeId: string) => HostRow | null;
  insertProbeRequestNonce: (input: {
    probeId: string;
    nonce: string;
    expiresAtMs: number;
    nowMs: number;
  }) => boolean;
  listSummaries: (options?: HostSummaryOptions) => HostSummary[];
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
  ) => HostRow;
  softDelete: (id: number, deletedAtMs: number) => HostRow | null;
  updateMetadata: (
    id: number,
    input: {
      connectAddress?: string;
      description?: string;
      displayName?: string;
    },
  ) => HostRow | null;
};

export function createHostRepository(database: HostDatabase): HostRepository {
  return {
    create(input) {
      const row = database.insert(hosts).values(input).returning().get();

      if (!row) {
        throw new Error("Failed to create Host.");
      }

      return row;
    },
    exists(id) {
      const row = database
        .select({ id: hosts.id })
        .from(hosts)
        .where(and(eq(hosts.id, id), isNull(hosts.deletedAtMs)))
        .get();

      return Boolean(row);
    },
    findActiveById(id) {
      return (
        database
          .select()
          .from(hosts)
          .where(and(eq(hosts.id, id), isNull(hosts.deletedAtMs)))
          .get() ?? null
      );
    },
    findByProbeId(probeId) {
      return (
        database
          .select()
          .from(hosts)
          .where(and(eq(hosts.probeId, probeId), isNull(hosts.deletedAtMs)))
          .get() ?? null
      );
    },
    insertProbeRequestNonce(input) {
      database
        .delete(probeRequestNonces)
        .where(lte(probeRequestNonces.expiresAtMs, input.nowMs))
        .run();

      try {
        database
          .insert(probeRequestNonces)
          .values({
            expiresAtMs: input.expiresAtMs,
            nonce: input.nonce,
            probeId: input.probeId,
          })
          .run();
        return true;
      } catch {
        return false;
      }
    },
    listSummaries(options = {}) {
      const nowMs = options.nowMs ?? Date.now();
      const thresholds = options.thresholds ?? defaultHostStatusThresholds;

      return database
        .select()
        .from(hosts)
        .where(isNull(hosts.deletedAtMs))
        .all()
        .map((host) => {
          const latestMetric = options.latestMetricForHost?.(host.id) ?? null;

          return {
            connectAddress: host.connectAddress,
            clockSkew: {
              detected: host.clockSkewDetected,
              lastDeltaMs: host.lastClockSkewMs,
            },
            collectorCapabilities: parseCollectorCapabilities(
              host.inventoryJson,
            ),
            cpu: formatCpu(host.cpuCount),
            cpuModel: host.cpuModel,
            description: host.description,
            displayName: host.displayName,
            id: host.id,
            lastReportAtMs: host.lastReportAtMs,
            latestMetrics: latestMetric
              ? {
                  collectedAtMs: latestMetric.collectedAtMs,
                  batteryPercent: latestMetric.batteryPercent,
                  batteryState: latestMetric.batteryState,
                  cpuIdlePercent: latestMetric.cpuIdlePercent,
                  cpuIowaitPercent: latestMetric.cpuIowaitPercent,
                  cpuPercent: latestMetric.cpuPercent,
                  cpuStealPercent: latestMetric.cpuStealPercent,
                  cpuSystemPercent: latestMetric.cpuSystemPercent,
                  cpuUserPercent: latestMetric.cpuUserPercent,
                  ...(latestMetric.diskHealth?.length
                    ? { diskHealth: latestMetric.diskHealth }
                    : {}),
                  diskTotalBytes: latestMetric.diskTotalBytes,
                  diskUsedBytes: latestMetric.diskUsedBytes,
                  load1: latestMetric.load1,
                  load5: latestMetric.load5,
                  load15: latestMetric.load15,
                  memoryCacheBytes: latestMetric.memoryCacheBytes,
                  memoryTotalBytes: latestMetric.memoryTotalBytes,
                  memoryUsedBytes: latestMetric.memoryUsedBytes,
                  networkRxBytesDelta: latestMetric.networkRxBytesDelta,
                  networkTxBytesDelta: latestMetric.networkTxBytesDelta,
                  receivedAtMs: latestMetric.receivedAtMs,
                  swapTotalBytes: latestMetric.swapTotalBytes,
                  swapUsedBytes: latestMetric.swapUsedBytes,
                  temperatureCelsius: latestMetric.temperatureCelsius,
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
        .from(hosts)
        .where(eq(hosts.id, id))
        .get();

      if (!current) {
        throw new Error("Failed to update Host report state.");
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
        .update(hosts)
        .set(values)
        .where(eq(hosts.id, id))
        .returning()
        .get();

      if (!row) {
        throw new Error("Failed to update Host report state.");
      }

      return row;
    },
    softDelete(id, deletedAtMs) {
      return (
        database
          .update(hosts)
          .set({
            deletedAtMs,
          })
          .where(and(eq(hosts.id, id), isNull(hosts.deletedAtMs)))
          .returning()
          .get() ?? null
      );
    },
    updateMetadata(id, input) {
      const current =
        database
          .select()
          .from(hosts)
          .where(and(eq(hosts.id, id), isNull(hosts.deletedAtMs)))
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
        .update(hosts)
        .set(values)
        .where(and(eq(hosts.id, id), isNull(hosts.deletedAtMs)))
        .returning()
        .get();

      return row ?? null;
    },
  };
}

function parseCollectorCapabilities(
  inventoryJson: string | null,
): CollectorCapabilities | null {
  if (!inventoryJson) {
    return null;
  }

  try {
    const inventory = JSON.parse(inventoryJson) as {
      collectorCapabilities?: CollectorCapabilities;
    };

    return normalizeCollectorCapabilities(inventory.collectorCapabilities);
  } catch {
    return null;
  }
}

function normalizeCollectorCapabilities(
  capabilities: CollectorCapabilities | null | undefined,
) {
  if (!capabilities?.official) {
    return null;
  }

  const official = Object.fromEntries(
    Object.entries(capabilities.official)
      .map(([key, availability]) => [
        key,
        normalizeCollectorAvailability(availability),
      ])
      .filter((entry): entry is [string, CollectorAvailability] =>
        Boolean(entry[1]),
      ),
  ) as CollectorCapabilities["official"];

  return official && Object.keys(official).length > 0 ? { official } : null;
}

function normalizeCollectorAvailability(
  availability: CollectorAvailability | null | undefined,
) {
  if (availability?.available === undefined) {
    return null;
  }

  return {
    available: Boolean(availability.available),
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
    return `${formatNumber(gibibytes)} GB`;
  }

  const mebibytes = bytes / 1024 ** 2;
  return `${formatNumber(mebibytes)} MB`;
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
