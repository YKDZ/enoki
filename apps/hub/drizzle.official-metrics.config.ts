import path from "node:path";

import { defineConfig } from "drizzle-kit";

const dataRoot = process.env.ENOKI_DATA_ROOT ?? "/data";
const sqlitePath =
  process.env.ENOKI_SQLITE_PATH ?? path.join(dataRoot, "enoki.db");

export default defineConfig({
  casing: "snake_case",
  dbCredentials: {
    url: sqlitePath,
  },
  dialect: "sqlite",
  out: "./drizzle-official-metrics",
  schema: "./src/database/schema-official-metrics.ts",
  strict: true,
});
