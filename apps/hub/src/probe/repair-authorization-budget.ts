import {
  createMemoryPasswordVerificationBudget,
  type PasswordVerificationBudget,
  type PasswordVerificationBudgetDecision,
} from "../auth/password-verification-budget.js";

export type RepairAuthorizationBudget = {
  consumeAnonymous: (source: string) => PasswordVerificationBudgetDecision;
  consumeVerifiedHost: (hostId: string) => PasswordVerificationBudgetDecision;
};

type Entry = { budget: PasswordVerificationBudget; touchedAtMs: number };

export function createMemoryRepairAuthorizationBudget(
  options: {
    monotonicNow?: () => number;
    maxKeys?: number;
    keyTtlMs?: number;
  } = {},
): RepairAuthorizationBudget {
  const now = options.monotonicNow ?? (() => performance.now());
  const maxKeys = options.maxKeys ?? 1_024;
  const keyTtlMs = options.keyTtlMs ?? 10 * 60 * 1_000;
  const global = createMemoryPasswordVerificationBudget({
    capacity: 60,
    monotonicNow: now,
    refillIntervalMs: 1_000,
  });
  const sources = new Map<string, Entry>();
  const hosts = new Map<string, Entry>();

  function keyed(
    entries: Map<string, Entry>,
    key: string,
    capacity: number,
  ): PasswordVerificationBudgetDecision {
    const current = now();
    let entry = entries.get(key);
    if (!entry) {
      for (const [candidate, value] of entries) {
        if (current - value.touchedAtMs >= keyTtlMs) entries.delete(candidate);
      }
      if (entries.size >= maxKeys) {
        const oldest = [...entries.entries()].reduce((left, right) =>
          left[1].touchedAtMs <= right[1].touchedAtMs ? left : right,
        );
        entries.delete(oldest[0]);
      }
      entry = {
        budget: createMemoryPasswordVerificationBudget({
          capacity,
          monotonicNow: now,
          refillIntervalMs: 10_000,
        }),
        touchedAtMs: current,
      };
      entries.set(key, entry);
    }
    entry.touchedAtMs = current;
    return entry.budget.consume();
  }

  return {
    consumeAnonymous(source) {
      const globalDecision = global.consume();
      return globalDecision.accepted
        ? keyed(sources, source, 12)
        : globalDecision;
    },
    consumeVerifiedHost(hostId) {
      return keyed(hosts, hostId, 6);
    },
  };
}
