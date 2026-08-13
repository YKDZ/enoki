import { describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { createHubRuntimeConfigFromEnvironment } from "../src/config";
import { createMemoryHubLogger } from "../src/hub-logger";
import { deriveObservedIp, parseTrustedProxyCidrs } from "../src/network";

const baseEnvironment = {
  ENOKI_DATA_ROOT: "/tmp/enoki-origin-config-test",
  ENOKI_MANAGEMENT_ORIGIN: "https://manage.example",
  OWNER_PASSWORD: "correct horse battery staple",
};

describe("explicit Hub origins", () => {
  it("uses the Management Origin as the default Probe API Origin", () => {
    const config = createHubRuntimeConfigFromEnvironment(baseEnvironment);

    expect(config.network.managementOrigin).toBe("https://manage.example");
    expect(config.network.probeApiOrigin).toBe("https://manage.example");
    expect(config.installation.probeApiOrigin).toBe("https://manage.example");
    expect(config.auth.managementOrigin).toBe("https://manage.example");
  });

  it.each(
    [
      "https://hub.example/prefix",
      "https://hub.example/.",
      "https://hub.example/%2e",
      "https://hub.example/%2E",
      "https://hub.example/?",
      "https://hub.example/?query=value",
      "https://hub.example/#",
      "https://hub.example/#fragment",
      "https://owner@hub.example",
    ].flatMap((origin) =>
      ["ENOKI_MANAGEMENT_ORIGIN", "ENOKI_PROBE_API_ORIGIN"].map(
        (name) => [name, origin] as const,
      ),
    ),
  )("rejects non-Origin configuration: %s=%s", (name, origin) => {
    expect(() =>
      createHubRuntimeConfigFromEnvironment({
        ...baseEnvironment,
        [name]: origin,
      }),
    ).toThrow(`${name} must be an HTTP or HTTPS Origin`);
  });

  it.each([
    "ENOKI_PUBLIC_HUB_URL",
    "ENOKI_PUBLIC_HTTPS",
    "ENOKI_TRUST_PROXY_HEADERS",
    "ENOKI_TRUSTED_PROXY_HEADERS",
  ])("fails startup with migration guidance for %s", (name) => {
    expect(() =>
      createHubRuntimeConfigFromEnvironment({
        ...baseEnvironment,
        [name]: "legacy-value",
      }),
    ).toThrow(name);
  });

  it("warns once for each distinct non-loopback HTTP Origin", () => {
    const memory = createMemoryHubLogger();

    createHubRuntimeConfigFromEnvironment(
      {
        ...baseEnvironment,
        ENOKI_MANAGEMENT_ORIGIN: "http://manage.example",
        ENOKI_PROBE_API_ORIGIN: "http://probe.example",
      },
      { logger: memory.logger },
    );

    expect(memory.events).toEqual([
      expect.objectContaining({
        event: "configuration.warning",
        level: "warn",
        outcome: "insecure_management_origin",
      }),
      expect.objectContaining({
        event: "configuration.warning",
        level: "warn",
        outcome: "insecure_probe_api_origin",
      }),
    ]);
  });

  it("accepts explicitly configured non-loopback HTTP Origins", () => {
    const memory = createMemoryHubLogger();

    const config = createHubRuntimeConfigFromEnvironment(
      {
        ...baseEnvironment,
        ENOKI_MANAGEMENT_ORIGIN: "http://192.0.2.20:3000",
        ENOKI_PROBE_API_ORIGIN: "http://192.0.2.20:3001",
      },
      { logger: memory.logger },
    );

    expect(config.network).toMatchObject({
      managementOrigin: "http://192.0.2.20:3000",
      probeApiOrigin: "http://192.0.2.20:3001",
    });
    expect(memory.events).toHaveLength(2);
  });

  it("emits one warning when both surfaces share one non-loopback HTTP Origin", () => {
    const memory = createMemoryHubLogger();

    createHubRuntimeConfigFromEnvironment(
      {
        ...baseEnvironment,
        ENOKI_MANAGEMENT_ORIGIN: "http://hub.example",
      },
      { logger: memory.logger },
    );

    expect(memory.events).toEqual([
      expect.objectContaining({
        outcome: "insecure_management_and_probe_api_origin",
      }),
    ]);
  });

  it.each(["http://localhost", "http://127.0.0.1", "http://[::1]"])(
    "does not warn for loopback HTTP Origin: %s",
    (origin) => {
      const memory = createMemoryHubLogger();

      createHubRuntimeConfigFromEnvironment(
        { ...baseEnvironment, ENOKI_MANAGEMENT_ORIGIN: origin },
        { logger: memory.logger },
      );

      expect(memory.events).toEqual([]);
    },
  );
});

describe("trusted proxy Observed IP evidence", () => {
  it("peels a valid X-Forwarded-For chain right-to-left through trusted proxies", () => {
    const trusted = parseTrustedProxyCidrs("10.0.0.0/8, 2001:db8::/32");

    expect(
      deriveObservedIp({
        directPeer: "10.0.0.4",
        trustedProxyCidrs: trusted,
        xForwardedFor: "203.0.113.10, 10.1.0.7, 2001:db8::9",
      }),
    ).toBe("203.0.113.10");
  });

  it("falls back to the direct peer for untrusted or malformed forwarding evidence", () => {
    const trusted = parseTrustedProxyCidrs("10.0.0.0/8");

    expect(
      deriveObservedIp({
        directPeer: "198.51.100.8",
        trustedProxyCidrs: trusted,
        xForwardedFor: "203.0.113.10",
      }),
    ).toBe("198.51.100.8");
    expect(
      deriveObservedIp({
        directPeer: "10.0.0.4",
        trustedProxyCidrs: trusted,
        xForwardedFor: "203.0.113.10, unknown",
      }),
    ).toBe("10.0.0.4");
  });
});

describe("Hub transport boundary", () => {
  it("does not redirect HTTP or emit HSTS", async () => {
    const app = createHubApp();

    const response = await app.request("http://hub.internal/api/health");

    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("strict-transport-security")).toBeNull();
  });
});
