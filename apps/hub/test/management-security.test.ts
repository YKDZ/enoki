import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createHubApp, createProbeApiApp } from "../src/app";

const canonicalManagementSecurityHeaders = {
  "content-security-policy": [
    "default-src 'none'",
    "base-uri 'none'",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "img-src 'self'",
    "object-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "style-src-attr 'unsafe-inline'",
    "style-src-elem 'self' 'unsafe-inline'",
  ].join("; "),
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": [
    "accelerometer",
    "attribution-reporting",
    "autoplay",
    "camera",
    "ch-ua",
    "ch-ua-arch",
    "ch-ua-bitness",
    "ch-ua-full-version",
    "ch-ua-full-version-list",
    "ch-ua-mobile",
    "ch-ua-model",
    "ch-ua-platform",
    "ch-ua-platform-version",
    "ch-ua-wow64",
    "clipboard-read",
    "clipboard-write",
    "compute-pressure",
    "cross-origin-isolated",
    "display-capture",
    "encrypted-media",
    "fullscreen",
    "gamepad",
    "geolocation",
    "gyroscope",
    "hid",
    "identity-credentials-get",
    "idle-detection",
    "keyboard-map",
    "magnetometer",
    "microphone",
    "midi",
    "payment",
    "picture-in-picture",
    "publickey-credentials-get",
    "screen-wake-lock",
    "serial",
    "storage-access",
    "sync-xhr",
    "usb",
    "window-management",
    "xr-spatial-tracking",
  ]
    .map((directive) => `${directive}=()`)
    .join(", "),
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-dns-prefetch-control": "off",
  "x-frame-options": "DENY",
} as const;

describe("management browser security policy", () => {
  it("serves Web documents with the canonical browser security headers", async () => {
    const webDistPath = await mkdtemp(join(tmpdir(), "enoki-web-dist-"));
    await writeFile(join(webDistPath, "index.html"), "<main>Enoki Web</main>");

    const response = await createHubApp({ webDistPath }).request("/");

    expect(response.status).toBe(200);
    expect(readSecurityHeaders(response)).toEqual(
      canonicalManagementSecurityHeaders,
    );
    expect(response.headers.has("strict-transport-security")).toBe(false);
  });

  it.each(["http", "https"])(
    "uses the same canonical headers for %s management API responses without HSTS",
    async (scheme) => {
      const response = await createHubApp().request(
        `${scheme}://hub.example.test/api/health`,
      );

      expect(readSecurityHeaders(response)).toEqual(
        canonicalManagementSecurityHeaders,
      );
      expect(response.headers.has("strict-transport-security")).toBe(false);
    },
  );

  it("does not project management browser headers onto the Probe-only listener", async () => {
    const response = await createProbeApiApp().request("/api/health");

    expect(response.status).toBe(200);
    expect(readSecurityHeaders(response)).toEqual(
      Object.fromEntries(
        Object.keys(canonicalManagementSecurityHeaders).map((name) => [
          name,
          null,
        ]),
      ),
    );
    expect(response.headers.has("strict-transport-security")).toBe(false);
  });

  it("denies every reviewed browser capability with a stable empty allowlist", async () => {
    const response = await createHubApp().request("/api/health");
    const directives = response.headers
      .get("permissions-policy")
      ?.split(", ") ?? ["missing-policy"];
    const directiveNames = directives.map((directive) =>
      directive.replace(/=\(\)$/, ""),
    );

    expect(directives).toHaveLength(41);
    expect(directiveNames).toEqual([...new Set(directiveNames)].sort());
    expect(directives.every((directive) => directive.endsWith("=()"))).toBe(
      true,
    );
    expect(directives).toEqual(
      expect.arrayContaining([
        "camera=()",
        "fullscreen=()",
        "hid=()",
        "microphone=()",
        "serial=()",
        "usb=()",
        "xr-spatial-tracking=()",
      ]),
    );
  });
});

function readSecurityHeaders(response: Response) {
  return Object.fromEntries(
    Object.keys(canonicalManagementSecurityHeaders).map((name) => [
      name,
      response.headers.get(name),
    ]),
  );
}
