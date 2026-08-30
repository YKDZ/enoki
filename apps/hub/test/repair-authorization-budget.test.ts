import { describe, expect, it } from "vitest";

import { createMemoryRepairAuthorizationBudget } from "../src/probe/repair-authorization-budget.js";

describe("Repair authorization budget", () => {
  it("bounds anonymous source and verified-host work with finite retry advice", () => {
    let nowMs = 0;
    const budget = createMemoryRepairAuthorizationBudget({
      keyTtlMs: 1_000,
      maxKeys: 2,
      monotonicNow: () => nowMs,
    });

    for (let index = 0; index < 12; index += 1) {
      expect(budget.consumeAnonymous("192.0.2.1")).toEqual({ accepted: true });
    }
    expect(budget.consumeAnonymous("192.0.2.1")).toEqual({
      accepted: false,
      retryAfterSeconds: 10,
    });
    for (let index = 0; index < 6; index += 1) {
      expect(budget.consumeVerifiedHost("host-1")).toEqual({ accepted: true });
    }
    expect(budget.consumeVerifiedHost("host-1")).toEqual({
      accepted: false,
      retryAfterSeconds: 10,
    });

    nowMs = 2_000;
    expect(budget.consumeAnonymous("192.0.2.2")).toEqual({ accepted: true });
    expect(budget.consumeAnonymous("192.0.2.3")).toEqual({ accepted: true });
    expect(budget.consumeAnonymous("192.0.2.4")).toEqual({ accepted: true });
  });
});
