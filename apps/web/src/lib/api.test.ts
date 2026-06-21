import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiGet, isUnauthorizedError } from "./api";

describe("API helpers", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps HTTP status available for authentication handling", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("{}", { status: 401 })),
    );

    await expect(apiGet("/api/web/hosts")).rejects.toMatchObject({
      status: 401,
    });

    try {
      await apiGet("/api/web/hosts");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect(isUnauthorizedError(error)).toBe(true);
    }
  });
});
