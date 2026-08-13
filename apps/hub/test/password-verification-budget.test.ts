import { describe, expect, it } from "vitest";

import { createMemoryPasswordVerificationBudget } from "../src/auth/password-verification-budget";

describe("Owner password verification budget", () => {
  it("refills continuously from a monotonic clock", () => {
    let nowMs = 100;
    const budget = createMemoryPasswordVerificationBudget({
      monotonicNow: () => nowMs,
    });

    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(budget.consume()).toEqual({ accepted: true });
    }
    expect(budget.consume()).toEqual({
      accepted: false,
      retryAfterSeconds: 180,
    });

    nowMs += 90_000;
    expect(budget.consume()).toEqual({
      accepted: false,
      retryAfterSeconds: 90,
    });

    nowMs += 90_000;
    expect(budget.consume()).toEqual({ accepted: true });
  });

  it("does not issue more than its fixed capacity under concurrent demand", async () => {
    const budget = createMemoryPasswordVerificationBudget({
      monotonicNow: () => 100,
    });

    const decisions = await Promise.all(
      Array.from({ length: 100 }, async () => budget.consume()),
    );

    expect(decisions.filter((decision) => decision.accepted)).toHaveLength(5);
    expect(decisions.filter((decision) => !decision.accepted)).toHaveLength(95);
  });

  it("starts with a fresh in-memory budget after Hub authentication restart", () => {
    const options = { monotonicNow: () => 100 };
    const original = createMemoryPasswordVerificationBudget(options);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(original.consume()).toEqual({ accepted: true });
    }
    expect(original.consume()).toEqual({
      accepted: false,
      retryAfterSeconds: 180,
    });

    const restarted = createMemoryPasswordVerificationBudget(options);
    expect(restarted.consume()).toEqual({ accepted: true });
  });
});
