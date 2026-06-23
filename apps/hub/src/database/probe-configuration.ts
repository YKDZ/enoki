import { eq } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";

import {
  defaultEnabledCollectorIds,
  defaultProbeConfiguration,
  nextProbeConfigurationVersion,
  normalizeProbeConfigurationValues,
  type ProbeConfigurationRecord,
  type ProbeConfigurationValues,
} from "../probe-configuration/model.js";
import {
  probeConfigurationGlobalDefaults,
  probeConfigurationHostOverrides,
} from "./schema.js";

type ProbeConfigurationDatabase = NodeSQLiteDatabase<
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
        ...normalizeProbeConfigurationValues(values),
        version: nextProbeConfigurationVersion(
          "global",
          updatedAtMs,
          previous.version,
        ),
      };

      database
        .insert(probeConfigurationGlobalDefaults)
        .values({
          ...configurationValuesToRow(configuration),
          id: 1,
          updatedAtMs,
        })
        .onConflictDoUpdate({
          set: {
            ...configurationValuesToRow(configuration),
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
        ...normalizeProbeConfigurationValues(values),
        version: nextProbeConfigurationVersion(
          `host-${hostId}`,
          updatedAtMs,
          previous.version,
        ),
      };

      database
        .insert(probeConfigurationHostOverrides)
        .values({
          ...configurationValuesToRow(configuration),
          hostId,
          updatedAtMs,
        })
        .onConflictDoUpdate({
          set: {
            ...configurationValuesToRow(configuration),
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
  row:
    | {
        enabledCollectorIdsJson: string;
        metricsCollectionIntervalSeconds: number;
        version: string;
      }
    | null
    | undefined,
): ProbeConfigurationRecord {
  if (!row) {
    return {
      ...defaultProbeConfiguration,
      enabledCollectorIds: [...defaultProbeConfiguration.enabledCollectorIds],
    };
  }

  return {
    enabledCollectorIds: parseEnabledCollectorIdsJson(
      row.enabledCollectorIdsJson,
    ),
    metricsCollectionIntervalSeconds: row.metricsCollectionIntervalSeconds,
    version: row.version,
  };
}

function configurationValuesToRow(values: ProbeConfigurationRecord) {
  return {
    enabledCollectorIdsJson: JSON.stringify(values.enabledCollectorIds),
    metricsCollectionIntervalSeconds: values.metricsCollectionIntervalSeconds,
    version: values.version,
  };
}

function parseEnabledCollectorIdsJson(value: string) {
  try {
    const parsed = JSON.parse(value);

    if (
      Array.isArray(parsed) &&
      parsed.every((collectorId) => typeof collectorId === "string")
    ) {
      return normalizeProbeConfigurationValues({
        enabledCollectorIds: parsed,
        metricsCollectionIntervalSeconds: 1,
      }).enabledCollectorIds;
    }
  } catch {
    // Fall through to the catalog default for corrupted local state.
  }

  return [...defaultEnabledCollectorIds];
}
