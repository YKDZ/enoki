import { eq } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";

import {
  defaultProbeConfiguration,
  nextProbeConfigurationVersion,
  type ProbeConfigurationRecord,
  type ProbeConfigurationValues,
} from "../probe-configuration/model.js";
import {
  probeConfigurationGlobalDefaults,
  probeConfigurationHostOverrides,
} from "./schema.js";

type ProbeConfigurationDatabase = BetterSQLite3Database<
  typeof import("./schema.js")
>;

export type HostProbeConfiguration = {
  configuration: ProbeConfigurationRecord;
  mode: "inherit" | "override";
};

export type ProbeConfigurationRepository = {
  clearHostOverride: (hostId: number) => HostProbeConfiguration;
  getGlobal: () => ProbeConfigurationRecord;
  getEffectiveForHost: (hostId: number) => HostProbeConfiguration;
  updateHostOverride: (
    hostId: number,
    values: ProbeConfigurationValues,
    updatedAtMs: number,
  ) => HostProbeConfiguration;
  updateGlobal: (
    values: ProbeConfigurationValues,
    updatedAtMs: number,
  ) => ProbeConfigurationRecord;
};

export function createProbeConfigurationRepository(
  database: ProbeConfigurationDatabase,
): ProbeConfigurationRepository {
  return {
    clearHostOverride(hostId) {
      database
        .delete(probeConfigurationHostOverrides)
        .where(eq(probeConfigurationHostOverrides.hostId, hostId))
        .run();

      return this.getEffectiveForHost(hostId);
    },
    getGlobal() {
      return rowToConfiguration(
        database.select().from(probeConfigurationGlobalDefaults).get(),
      );
    },
    getEffectiveForHost(hostId) {
      const override = database
        .select()
        .from(probeConfigurationHostOverrides)
        .where(eq(probeConfigurationHostOverrides.hostId, hostId))
        .get();

      if (override) {
        return {
          configuration: rowToConfiguration(override),
          mode: "override",
        };
      }

      return {
        configuration: this.getGlobal(),
        mode: "inherit",
      };
    },
    updateGlobal(values, updatedAtMs) {
      const previous = this.getGlobal();
      const configuration = {
        ...values,
        version: nextProbeConfigurationVersion(
          "global",
          updatedAtMs,
          previous.version,
        ),
      };

      database
        .insert(probeConfigurationGlobalDefaults)
        .values({
          ...configuration,
          id: 1,
          updatedAtMs,
        })
        .onConflictDoUpdate({
          set: {
            ...configuration,
            updatedAtMs,
          },
          target: probeConfigurationGlobalDefaults.id,
        })
        .run();

      return configuration;
    },
    updateHostOverride(hostId, values, updatedAtMs) {
      const previous = this.getEffectiveForHost(hostId).configuration;
      const configuration = {
        ...values,
        version: nextProbeConfigurationVersion(
          `host-${hostId}`,
          updatedAtMs,
          previous.version,
        ),
      };

      database
        .insert(probeConfigurationHostOverrides)
        .values({
          ...configuration,
          hostId,
          updatedAtMs,
        })
        .onConflictDoUpdate({
          set: {
            ...configuration,
            updatedAtMs,
          },
          target: probeConfigurationHostOverrides.hostId,
        })
        .run();

      return this.getEffectiveForHost(hostId);
    },
  };
}

function rowToConfiguration(
  row: (ProbeConfigurationValues & { version: string }) | null | undefined,
): ProbeConfigurationRecord {
  if (!row) {
    return defaultProbeConfiguration;
  }

  return {
    collectCpu: row.collectCpu,
    collectDisk: row.collectDisk,
    collectLoad: row.collectLoad,
    collectMemory: row.collectMemory,
    collectNetwork: row.collectNetwork,
    collectUptime: row.collectUptime,
    metricsCollectionIntervalSeconds: row.metricsCollectionIntervalSeconds,
    reportingBatchIntervalSeconds: row.reportingBatchIntervalSeconds,
    version: row.version,
  };
}
