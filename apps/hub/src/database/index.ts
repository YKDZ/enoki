import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { drizzle } from "drizzle-orm/node-sqlite";
import { migrate } from "drizzle-orm/node-sqlite/migrator";

import type { DatabaseConfig } from "../config.js";
import { createAuditRepository, type AuditRepository } from "./audit.js";
import {
  createEnrollmentRepository,
  type EnrollmentRepository,
} from "./enrollments.js";
import {
  createSnapshotCollectorStorageRegistry,
  type SnapshotCollectorStorageRegistry,
} from "./host-profiles.js";
import { createHostRepository, type HostRepository } from "./hosts.js";
import {
  createMetricsArchiveRepository,
  type MetricsArchiveRepository,
} from "./metrics-archives.js";
import { createMetricsRepository, type MetricsRepository } from "./metrics.js";
import {
  createProbeConfigurationRepository,
  type ProbeConfigurationRepository,
} from "./probe-configuration.js";
import {
  createProbeOperationRepository,
  type ProbeOperationRepository,
} from "./probe-operations.js";
import * as schema from "./schema.js";

export type HubDatabase = {
  audit: AuditRepository;
  close: () => void;
  enrollments: EnrollmentRepository;
  hosts: HostRepository;
  metricsArchives: MetricsArchiveRepository;
  metrics: MetricsRepository;
  probeConfigurations: ProbeConfigurationRepository;
  probeOperations: ProbeOperationRepository;
  snapshotCollectors: SnapshotCollectorStorageRegistry;
  sqlite: DatabaseSync;
};

export type InitializeHubDatabaseOptions = {
  migrationLayers?: MigrationLayer[];
  migrationsFolder?: string;
};

export type MigrationLayer = {
  historyTable: string;
  migrationsFolder: string;
  name: string;
};

export function initializeHubDatabase(
  config: DatabaseConfig,
  options: InitializeHubDatabaseOptions = {},
): HubDatabase {
  mkdirSync(config.dataRoot, { recursive: true });
  mkdirSync(dirname(config.sqlitePath), { recursive: true });

  const sqlite = new DatabaseSync(config.sqlitePath);
  sqlite.exec("PRAGMA foreign_keys = ON");
  sqlite.exec("PRAGMA journal_mode = WAL");
  const database = drizzle({ casing: "snake_case", client: sqlite, schema });
  for (const layer of migrationLayers(options)) {
    migrate(database, {
      migrationsFolder: layer.migrationsFolder,
      migrationsTable: layer.historyTable,
    });
  }

  return {
    audit: createAuditRepository(database),
    close() {
      sqlite.close();
    },
    enrollments: createEnrollmentRepository(database),
    hosts: createHostRepository(database),
    metricsArchives: createMetricsArchiveRepository(database),
    metrics: createMetricsRepository(database),
    probeConfigurations: createProbeConfigurationRepository(database),
    probeOperations: createProbeOperationRepository(database),
    snapshotCollectors: createSnapshotCollectorStorageRegistry(database),
    sqlite,
  };
}

function migrationLayers(
  options: InitializeHubDatabaseOptions,
): MigrationLayer[] {
  if (options.migrationLayers) {
    return options.migrationLayers;
  }

  if (!options.migrationsFolder) {
    return [
      {
        historyTable: "__drizzle_migrations",
        migrationsFolder: defaultMigrationsFolder(),
        name: "core",
      },
      {
        historyTable: "__official_metrics_migrations",
        migrationsFolder: defaultOfficialMetricsMigrationsFolder(),
        name: "official_metrics",
      },
    ];
  }

  return [
    {
      historyTable: "__drizzle_migrations",
      migrationsFolder: options.migrationsFolder,
      name: "core",
    },
  ];
}

function defaultMigrationsFolder() {
  const sourceLayoutMigrationsFolder = new URL("../../drizzle", import.meta.url)
    .pathname;
  const candidates = [
    sourceLayoutMigrationsFolder,
    new URL("../../../drizzle", import.meta.url).pathname,
  ];

  return (
    candidates.find((candidate) => existsSync(candidate)) ??
    sourceLayoutMigrationsFolder
  );
}

function defaultOfficialMetricsMigrationsFolder() {
  const sourceLayoutMigrationsFolder = new URL(
    "../../drizzle-official-metrics",
    import.meta.url,
  ).pathname;
  const candidates = [
    sourceLayoutMigrationsFolder,
    new URL("../../../drizzle-official-metrics", import.meta.url).pathname,
  ];

  return (
    candidates.find((candidate) => existsSync(candidate)) ??
    sourceLayoutMigrationsFolder
  );
}
