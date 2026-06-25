import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it } from "vitest";

import { useHostMetricsWindowStore } from "./window-store";

describe("Host metrics window preferences", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it("keeps each host's selected metrics window independently", () => {
    const store = useHostMetricsWindowStore();

    expect(store.selectedWindowForHost(1)).toBe("1h");
    expect(store.selectedWindowForHost(2)).toBe("1h");

    store.setSelectedWindowForHost(1, "10m");
    store.setSelectedWindowForHost(2, "3d");

    expect(store.selectedWindowForHost(1)).toBe("10m");
    expect(store.selectedWindowForHost(2)).toBe("3d");
  });
});
