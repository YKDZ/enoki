import { defineStore } from "pinia";

import type { MetricsWindow } from "../types";

const defaultWindow: MetricsWindow = "1h";
const metricsWindows = new Set<MetricsWindow>([
  "1m",
  "10m",
  "1h",
  "6h",
  "24h",
  "3d",
  "7d",
]);

export type HostMetricsWindowPreferences = {
  selectedWindowForHost: (hostId: number) => MetricsWindow;
  setSelectedWindowForHost: (hostId: number, window: MetricsWindow) => void;
};

export const useHostMetricsWindowStore = defineStore("hostMetricsWindow", {
  state: () => ({
    windowsByHostId: {} as Record<string, MetricsWindow>,
  }),
  actions: {
    selectedWindowForHost(hostId: number): MetricsWindow {
      const window = this.windowsByHostId[String(hostId)];

      return window && metricsWindows.has(window) ? window : defaultWindow;
    },
    setSelectedWindowForHost(hostId: number, window: MetricsWindow) {
      if (!hostId || !window || !metricsWindows.has(window)) {
        return;
      }

      this.windowsByHostId[String(hostId)] = window;
    },
  },
  persist: {
    key: "enoki-host-metrics-window",
    pick: ["windowsByHostId"],
  },
});
