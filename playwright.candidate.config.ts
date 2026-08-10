import path from "node:path";

import { defineConfig, devices } from "@playwright/test";

const baseURL = requiredEnvironment("ENOKI_RELEASE_UI_BASE_URL");
requiredEnvironment("ENOKI_RELEASE_UI_CANDIDATE_VERSION");
requiredEnvironment("ENOKI_RELEASE_UI_OWNER_PASSWORD");
const evidenceDir = requiredEnvironment("ENOKI_RELEASE_UI_EVIDENCE_DIR");

export default defineConfig({
  expect: {
    timeout: 10_000,
  },
  fullyParallel: true,
  projects: [
    {
      name: "candidate-chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  reporter: process.env.CI
    ? [
        ["github"],
        ["list"],
        [
          "html",
          {
            open: "never",
            outputFolder: path.join(evidenceDir, "playwright-report"),
          },
        ],
      ]
    : [
        ["list"],
        [
          "html",
          {
            open: "never",
            outputFolder: path.join(evidenceDir, "playwright-report"),
          },
        ],
      ],
  retries: process.env.CI ? 1 : 0,
  testDir: "./tests/e2e",
  testMatch: [
    "hub-install-command.spec.ts",
    "host-removal-live-update.spec.ts",
    "probe-lifecycle-ui-contract.spec.ts",
  ],
  outputDir: path.join(evidenceDir, "test-results"),
  timeout: 60_000,
  use: {
    baseURL,
    trace: "on-first-retry",
  },
  workers: 4,
});

function requiredEnvironment(name: string) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
