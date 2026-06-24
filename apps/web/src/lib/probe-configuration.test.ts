import { describe, expect, it } from "vitest";

import {
  defaultEnabledCollectorIds,
  probeCollectorCatalog,
} from "./probe-configuration";

describe("probe configuration collector catalog", () => {
  it("does not expose Host Profile as an Owner-facing Metrics collector", () => {
    expect(probeCollectorCatalog.map((collector) => collector.id)).not.toContain(
      "official.host-profile",
    );
    expect(defaultEnabledCollectorIds).not.toContain("official.host-profile");
  });
});
