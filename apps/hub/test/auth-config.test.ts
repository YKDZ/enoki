import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { createHubAppFromEnvironment } from "../src/app";
import { createAuthConfigFromEnvironment } from "../src/auth/config";
import { createMemoryHubLogger } from "../src/hub-logger";

describe("Hub Owner authentication configuration", () => {
  it("fails closed in production when OWNER_PASSWORD is missing", () => {
    expect(() =>
      createHubAppFromEnvironment({
        NODE_ENV: "production",
        ENOKI_MANAGEMENT_ORIGIN: "https://hub.example",
      }),
    ).toThrow("OWNER_PASSWORD");
  });

  it("fails closed in Docker mode when OWNER_PASSWORD is missing", () => {
    expect(() =>
      createHubAppFromEnvironment({
        ENOKI_DEPLOYMENT: "docker",
        ENOKI_MANAGEMENT_ORIGIN: "https://hub.example",
      }),
    ).toThrow("OWNER_PASSWORD");
  });

  it("rejects no-password Web UI mode in production unless insecure mode is explicitly allowed", () => {
    expect(() =>
      createHubAppFromEnvironment({
        ENOKI_WEB_UI_NO_PASSWORD: "true",
        ENOKI_MANAGEMENT_ORIGIN: "https://hub.example",
        NODE_ENV: "production",
      }),
    ).toThrow("ENOKI_ALLOW_INSECURE_NO_PASSWORD");
  });

  it("rejects no-password Web UI mode in Docker mode unless insecure mode is explicitly allowed", () => {
    expect(() =>
      createHubAppFromEnvironment({
        ENOKI_DEPLOYMENT: "docker",
        ENOKI_WEB_UI_NO_PASSWORD: "true",
        ENOKI_MANAGEMENT_ORIGIN: "https://hub.example",
      }),
    ).toThrow("ENOKI_ALLOW_INSECURE_NO_PASSWORD");
  });

  it("allows explicitly insecure no-password Web UI mode in Docker mode", () => {
    const memory = createMemoryHubLogger();

    const app = createHubAppFromEnvironment(
      {
        ENOKI_ALLOW_INSECURE_NO_PASSWORD: "true",
        ENOKI_DATA_ROOT: createTempDataRoot(),
        ENOKI_DEPLOYMENT: "docker",
        ENOKI_MANAGEMENT_ORIGIN: "https://hub.example",
        ENOKI_WEB_UI_NO_PASSWORD: "true",
      },
      { logger: memory.logger },
    );

    expect(app).toBeDefined();
    expect(memory.events).toContainEqual(
      expect.objectContaining({ outcome: "no_password_web_ui_enabled" }),
    );
  });

  it("requires an explicit Owner password in development instead of hiding a generated credential", () => {
    const memory = createMemoryHubLogger();

    expect(() =>
      createHubAppFromEnvironment(
        {
          ENOKI_DATA_ROOT: createTempDataRoot(),
          ENOKI_MANAGEMENT_ORIGIN: "https://hub.example",
          NODE_ENV: "development",
        },
        { logger: memory.logger },
      ),
    ).toThrow("OWNER_PASSWORD");
    expect(memory.events).toEqual([]);
  });

  it("reads the explicit Management Origin", () => {
    const config = createAuthConfigFromEnvironment({
      ENOKI_MANAGEMENT_ORIGIN: "https://hub.example",
      OWNER_PASSWORD: "correct horse battery staple",
    });

    expect(config.managementOrigin).toBe("https://hub.example");
  });
});

function createTempDataRoot() {
  return mkdtempSync(path.join(tmpdir(), "enoki-auth-config-"));
}
