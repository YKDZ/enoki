import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

describe("Node check resource scheduling", () => {
  it("runs package tests before RSA-heavy root tests and E2E last", async () => {
    const turbo = JSON.parse(await readFile("turbo.json", "utf8"));

    expect(turbo.tasks["//#test"].dependsOn).toEqual([
      "@enoki/api-client#test",
      "@enoki/hub#test",
      "@enoki/proto#test",
      "@enoki/web#test",
    ]);
    expect(turbo.tasks["//#test:e2e"].dependsOn).toContain("//#test");
  });
});
