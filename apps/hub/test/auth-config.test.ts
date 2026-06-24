import { describe, expect, it, vi } from "vitest";

import { createHubAppFromEnvironment } from "../src/app";
import { createAuthConfigFromEnvironment } from "../src/auth/config";

describe("Hub Owner authentication configuration", () => {
  it("fails closed in production when OWNER_PASSWORD is missing", () => {
    expect(() =>
      createHubAppFromEnvironment({
        NODE_ENV: "production",
      }),
    ).toThrow("OWNER_PASSWORD");
  });

  it("fails closed in Docker mode when OWNER_PASSWORD is missing", () => {
    expect(() =>
      createHubAppFromEnvironment({
        ENOKI_DEPLOYMENT: "docker",
      }),
    ).toThrow("OWNER_PASSWORD");
  });

  it("rejects no-password Web UI mode in production unless insecure mode is explicitly allowed", () => {
    expect(() =>
      createHubAppFromEnvironment({
        ENOKI_WEB_UI_NO_PASSWORD: "true",
        NODE_ENV: "production",
      }),
    ).toThrow("ENOKI_ALLOW_INSECURE_NO_PASSWORD");
  });

  it("rejects no-password Web UI mode in Docker mode unless insecure mode is explicitly allowed", () => {
    expect(() =>
      createHubAppFromEnvironment({
        ENOKI_DEPLOYMENT: "docker",
        ENOKI_WEB_UI_NO_PASSWORD: "true",
      }),
    ).toThrow("ENOKI_ALLOW_INSECURE_NO_PASSWORD");
  });

  it("allows explicitly insecure no-password Web UI mode in Docker mode", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const app = createHubAppFromEnvironment({
      ENOKI_ALLOW_INSECURE_NO_PASSWORD: "true",
      ENOKI_DEPLOYMENT: "docker",
      ENOKI_WEB_UI_NO_PASSWORD: "true",
    });

    expect(app).toBeDefined();
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("ENOKI_WEB_UI_NO_PASSWORD is enabled"),
    );
    warn.mockRestore();
  });

  it("generates and prints a temporary Owner password in development", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const app = createHubAppFromEnvironment({
      NODE_ENV: "development",
    });

    expect(app).toBeDefined();
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("Generated temporary Enoki Owner password"),
    );
    warn.mockRestore();
  });

  it("reads explicit public HTTPS and trusted proxy deployment settings", () => {
    const config = createAuthConfigFromEnvironment({
      ENOKI_PUBLIC_HTTPS: "true",
      ENOKI_TRUST_PROXY_HEADERS: "1",
      OWNER_PASSWORD: "correct horse battery staple",
    });

    expect(config.publicHttps).toBe(true);
    expect(config.trustProxyHeaders).toBe(true);
  });
});
