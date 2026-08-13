import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

describe("Node check resource scheduling", () => {
  it("runs package tests before RSA-heavy root tests and E2E last", async () => {
    const turbo = JSON.parse(await readFile("turbo.json", "utf8"));

    expect(turbo.tasks["//#test:ci"].dependsOn).toEqual([
      "@enoki/api-client#test",
      "@enoki/hub#test:built",
      "@enoki/proto#test",
      "@enoki/web#test",
    ]);
    expect(turbo.tasks["test:built"].dependsOn).toContain("build");
    expect(turbo.tasks["//#test:e2e"].dependsOn).toContain("//#test:ci");
  });

  it("reuses Turbo's Hub build instead of rebuilding inside the startup test", async () => {
    const turbo = JSON.parse(await readFile("turbo.json", "utf8"));
    const startupTest = await readFile(
      "apps/hub/test/server-startup.test.ts",
      "utf8",
    );

    expect(turbo.tasks["test:built"].dependsOn).toContain("build");
    expect(startupTest).not.toMatch(/@enoki\/hub["'],\s*["']build/);
  });

  it("gives the production Web build a local integration-test timeout", async () => {
    const productionSecurityTest = await readFile(
      "apps/web/src/production-security.test.ts",
      "utf8",
    );

    expect(productionSecurityTest).toMatch(/\},\s*30_000\);/);
  });
});
