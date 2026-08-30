// @vitest-environment happy-dom

import { mount, flushPromises } from "@vue/test-utils";
import { createPinia } from "pinia";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { HostSummary } from "./types";

vi.mock("./composables/useLiveUpdates", () => ({
  useLiveUpdates: () => ({
    connectLiveUpdates: vi.fn(),
    disconnectLiveUpdates: vi.fn(),
    subscribeHostDetail: vi.fn(),
    unsubscribeHostDetail: vi.fn(),
  }),
}));

import App from "./App.vue";

const offlineHost: HostSummary = {
  clockSkew: { detected: false, lastDeltaMs: null },
  collectorCapabilities: null,
  connectAddress: "192.0.2.7",
  cpu: "2 cores",
  cpuModel: null,
  description: "",
  displayName: "offline-host",
  id: 7,
  lastReportAtMs: 1,
  latestMetrics: null,
  memory: "2 GB",
  probeConfiguration: { mode: "inherit", version: "default-v1" },
  probeUpgradeProblem: null,
  probeVersion: "0.1.0",
  status: "offline",
  system: "Linux",
};

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
  window.history.replaceState({}, "", "/");
});

describe("ordinary ExistingHost re-enrollment", () => {
  it.each(["cards", "list"] as const)(
    "posts the canonical typed target from the %s overview",
    async (overview) => {
      localStorage.setItem("enoki-overview-view", overview);
      const requests: Array<{ input: RequestInfo | URL; init?: RequestInit }> =
        [];
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
          requests.push({ input, init });
          const path = String(input);
          if (path === "/api/web/auth/session") {
            return Response.json({ authenticated: true });
          }
          if (path === "/api/web/hosts") {
            return Response.json({ hosts: [offlineHost] });
          }
          if (path === "/api/web/enrollments") {
            return Response.json({
              enrollmentId: "enr_test",
              hostId: 7,
              status: "pending",
              target: { hostId: 7, kind: "existing_host" },
            });
          }
          throw new Error(`unexpected request: ${path}`);
        }),
      );

      const wrapper = mount(App, {
        attachTo: document.body,
        global: {
          plugins: [createPinia()],
          stubs: { EnrollmentDialog: true },
        },
      });
      await flushPromises();

      const action = wrapper
        .findAll("button")
        .find((button) => button.text().includes("重新注册探针"));
      expect(action).toBeDefined();
      await action!.trigger("click");
      await flushPromises();

      const request = requests.find(
        ({ input }) => String(input) === "/api/web/enrollments",
      );
      expect(request?.init).toMatchObject({
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      expect(JSON.parse(String(request?.init?.body))).toEqual({
        target: { hostId: 7, kind: "existing_host" },
      });

      wrapper.unmount();
    },
  );
});
