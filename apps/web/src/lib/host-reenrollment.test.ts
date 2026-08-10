import { describe, expect, it } from "vitest";

import { canReenrollHost } from "./host-reenrollment";

describe("Host Re-enrollment eligibility", () => {
  it.each([
    ["offline", true],
    ["online", false],
    ["stale", false],
  ] as const)(
    "exposes recovery for %s Hosts only when eligible",
    (status, eligible) => {
      expect(canReenrollHost({ status })).toBe(eligible);
    },
  );
});
