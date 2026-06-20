import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";

import type { DatabaseConfig } from "../config.js";
import { createAuditRepository, type AuditRepository } from "./audit.js";
import {
  createEnrollmentRepository,
  type EnrollmentRepository,
} from "./enrollments.js";
import {
  createManagedHostRepository,
  type ManagedHostRepository,
} from "./managed-hosts.js";
import { createMetricsRepository, type MetricsRepository } from "./metrics.js";
import {
  createProbeConfigurationRepository,
  type ProbeConfigurationRepository,
} from "./probe-configuration.js";
import * as schema from "./schema.js";

export type HubDatabase = {
  audit: AuditRepository;
  close: () => void;
  enrollments: EnrollmentRepository;
  managedHosts: ManagedHostRepository;
  metrics: MetricsRepository;
  probeConfigurations: ProbeConfigurationRepository;
  sqlite: Database.Database;
};

export type InitializeHubDatabaseOptions = {
  migrationsFolder?: string;
};

export function initializeHubDatabase(
  config: DatabaseConfig,
  options: InitializeHubDatabaseOptions = {},
): HubDatabase {
  mkdirSync(config.dataRoot, { recursive: true });
  mkdirSync(dirname(config.sqlitePath), { recursive: true });

  const sqlite = new Database(config.sqlitePath);
  sqlite.pragma("journal_mode = WAL");
  const database = drizzle(sqlite, { schema });
  migrate(database, {
    migrationsFolder: options.migrationsFolder ?? defaultMigrationsFolder(),
  });

  return {
    audit: createAuditRepository(database),
    close() {
      sqlite.close();
    },
    enrollments: createEnrollmentRepository(database),
    managedHosts: createManagedHostRepository(database),
    metrics: createMetricsRepository(database),
    probeConfigurations: createProbeConfigurationRepository(database),
    sqlite,
  };
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
