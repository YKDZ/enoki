import { describe, expect, it } from "vitest";

import { createHubApp } from "../src/app";

describe("Hub health route", () => {
  it("reports that the Hub is ready", async () => {
    const response = await createHubApp().request("/api/health");

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      service: "enoki-hub",
      status: "ok",
    });
  });
});
