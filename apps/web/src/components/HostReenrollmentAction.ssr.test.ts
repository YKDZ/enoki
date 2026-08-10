import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import type { HostSummary } from "../types";
import HostReenrollmentAction from "./HostReenrollmentAction.vue";

describe("Host Re-enrollment action", () => {
  it.each([
    ["offline", true],
    ["online", false],
    ["stale", false],
  ] as const)(
    "is discoverable for %s Hosts only when eligible",
    async (status, visible) => {
      const html = await renderToString(
        createSSRApp(HostReenrollmentAction, {
          host: { id: 7, status } satisfies Pick<HostSummary, "id" | "status">,
        }),
      );

      expect(html.includes("重新注册 Probe")).toBe(visible);
    },
  );
});
