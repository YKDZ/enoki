export type PasswordVerificationBudgetDecision =
  | { accepted: true }
  | { accepted: false; retryAfterSeconds: number };

export type PasswordVerificationBudget = {
  consume: () => PasswordVerificationBudgetDecision;
};

const defaultCapacity = 5;
const defaultRefillIntervalMs = 3 * 60 * 1000;
const maxRetryAfterSeconds = defaultRefillIntervalMs / 1000;

export function createMemoryPasswordVerificationBudget(
  options: {
    capacity?: number;
    monotonicNow?: () => number;
    refillIntervalMs?: number;
  } = {},
): PasswordVerificationBudget {
  const capacity = options.capacity ?? defaultCapacity;
  const monotonicNow = options.monotonicNow ?? (() => performance.now());
  const refillIntervalMs = options.refillIntervalMs ?? defaultRefillIntervalMs;
  let availableTokens = capacity;
  let updatedAtMs = monotonicNow();

  return {
    consume() {
      const nowMs = Math.max(updatedAtMs, monotonicNow());
      availableTokens = Math.min(
        capacity,
        availableTokens + (nowMs - updatedAtMs) / refillIntervalMs,
      );
      updatedAtMs = nowMs;

      if (availableTokens >= 1) {
        availableTokens -= 1;
        return { accepted: true };
      }

      return {
        accepted: false,
        retryAfterSeconds: Math.max(
          1,
          Math.min(
            maxRetryAfterSeconds,
            Math.ceil(((1 - availableTokens) * refillIntervalMs) / 1000),
          ),
        ),
      };
    },
  };
}
