import path from "node:path";

import { defineConfig, devices } from "@playwright/test";

const port = 38_200;
const probePort = 38_201;
const baseURL = `http://127.0.0.1:${port}`;
const rootDir = process.cwd();
const dataDir = path.join(rootDir, ".scratch/e2e-data");

const hubEnvironment = {
  ENOKI_DATA_ROOT: dataDir,
  ENOKI_INSTALL_SCRIPT_PATH: path.join(rootDir, "scripts/install-probe.sh"),
  ENOKI_PROBE_ASSET_DIR: path.join(rootDir, "probe-assets"),
  ENOKI_PROBE_HOST: "127.0.0.1",
  ENOKI_PROBE_OPERATION_TOKEN_SIGNING_SECRET: "e2e-probe-operation-secret",
  ENOKI_PROBE_PORT: String(probePort),
  ENOKI_PUBLIC_HUB_URL: baseURL,
  ENOKI_SQLITE_PATH: path.join(dataDir, "enoki.db"),
  ENOKI_WEB_DIST: path.join(rootDir, "apps/web/dist"),
  HOST: "127.0.0.1",
  NODE_ENV: "production",
  OWNER_PASSWORD: "correct horse battery staple",
  PORT: String(port),
};

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function environmentPrefix(environment: Record<string, string>) {
  return Object.entries(environment)
    .map(([key, value]) => `${key}=${shellQuote(value)}`)
    .join(" ");
}

export default defineConfig({
  expect: {
    timeout: 10_000,
  },
  fullyParallel: true,
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  reporter: process.env.CI ? [["github"], ["list"]] : "list",
  retries: process.env.CI ? 1 : 0,
  testDir: "./tests/e2e",
  use: {
    baseURL,
    trace: "on-first-retry",
  },
  webServer: {
    command: [
      `rm -rf ${shellQuote(dataDir)}`,
      `mkdir -p ${shellQuote(dataDir)}`,
      "pnpm --filter @enoki/api-client build",
      "pnpm --filter @enoki/web build",
      "pnpm --filter @enoki/hub build",
      `${environmentPrefix(hubEnvironment)} pnpm --filter @enoki/hub start`,
    ].join(" && "),
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    url: `${baseURL}/api/health`,
  },
});
