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

    store.setSelectedWindowForHost(1, "1m");
    store.setSelectedWindowForHost(2, "7d");

    expect(store.selectedWindowForHost(1)).toBe("1m");
    expect(store.selectedWindowForHost(2)).toBe("7d");
  });
});
