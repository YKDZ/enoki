import path from "node:path";

import { defineConfig, devices } from "@playwright/test";

import { ownerStorageStatePath } from "./tests/e2e/owner-auth-state";

const port = 38_200;
const probePort = 38_201;
const baseURL = `http://127.0.0.1:${port}`;
const securityPort = 38_210;
const securityProbePort = 38_211;
const securityBaseURL = `http://127.0.0.1:${securityPort}`;
const rootDir = process.cwd();
const dataDir = path.join(rootDir, ".scratch/e2e-data");
const securityDataDir = path.join(rootDir, ".scratch/e2e-security-data");

const hubEnvironment = {
  ENOKI_DATA_ROOT: dataDir,
  ENOKI_INSTALL_SCRIPT_PATH: path.join(rootDir, "scripts/install-probe.sh"),
  ENOKI_PROBE_ASSET_DIR: path.join(rootDir, "probe-assets"),
  ENOKI_PROBE_HOST: "127.0.0.1",
  ENOKI_PROBE_OPERATION_TOKEN_SIGNING_SECRET: "e2e-probe-operation-secret",
  ENOKI_PROBE_PORT: String(probePort),
  ENOKI_MANAGEMENT_ORIGIN: baseURL,
  ENOKI_PROBE_API_ORIGIN: `http://127.0.0.1:${probePort}`,
  ENOKI_SQLITE_PATH: path.join(dataDir, "enoki.db"),
  ENOKI_WEB_DIST: path.join(rootDir, "apps/web/dist"),
  HOST: "127.0.0.1",
  NODE_ENV: "production",
  OWNER_PASSWORD: "correct horse battery staple",
  PORT: String(port),
};

const securityHubEnvironment = {
  ...hubEnvironment,
  ENOKI_DATA_ROOT: securityDataDir,
  ENOKI_MANAGEMENT_ORIGIN: securityBaseURL,
  ENOKI_PROBE_API_ORIGIN: `http://127.0.0.1:${securityProbePort}`,
  ENOKI_PROBE_PORT: String(securityProbePort),
  ENOKI_SQLITE_PATH: path.join(securityDataDir, "enoki.db"),
  PORT: String(securityPort),
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
  globalSetup: "./tests/e2e/global-setup.ts",
  timeout: 60_000,
  workers: 4,
  projects: [
    {
      name: "chromium",
      testIgnore: [
        "management-origin-security.spec.ts",
        "owner-session-cookie.spec.ts",
      ],
      use: {
        ...devices["Desktop Chrome"],
        storageState: ownerStorageStatePath,
      },
    },
    {
      name: "chromium-security",
      testMatch: [
        "management-origin-security.spec.ts",
        "owner-session-cookie.spec.ts",
      ],
      use: {
        ...devices["Desktop Chrome"],
        baseURL: securityBaseURL,
        storageState: { cookies: [], origins: [] },
      },
    },
  ],
  reporter: process.env.CI ? [["github"], ["list"]] : "list",
  retries: process.env.CI ? 1 : 0,
  testDir: "./tests/e2e",
  use: {
    baseURL,
    trace: "on-first-retry",
  },
  webServer: [
    {
      command: [
        `rm -rf ${shellQuote(dataDir)}`,
        `mkdir -p ${shellQuote(dataDir)}`,
        "pnpm --filter @enoki/api-client build",
        "VITE_ENABLE_LAYOUT_LAB=1 pnpm --filter @enoki/web build",
        "pnpm --filter @enoki/hub build",
        `${environmentPrefix(hubEnvironment)} pnpm --filter @enoki/hub start`,
      ].join(" && "),
      reuseExistingServer: false,
      timeout: 120_000,
      url: `${baseURL}/api/health`,
    },
    {
      command: [
        `rm -rf ${shellQuote(securityDataDir)}`,
        `mkdir -p ${shellQuote(securityDataDir)}`,
        `${environmentPrefix(securityHubEnvironment)} pnpm --filter @enoki/hub start`,
      ].join(" && "),
      reuseExistingServer: false,
      timeout: 120_000,
      url: `${securityBaseURL}/api/health`,
    },
  ],
});
