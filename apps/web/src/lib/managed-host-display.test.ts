import { describe, expect, it } from "vitest";

import { hostStatusText, warningTitle } from "./managed-host-display";

describe("Managed Host display text", () => {
  it("renders Host Status values in Simplified Chinese", () => {
    expect(hostStatusText("online")).toBe("在线");
    expect(hostStatusText("stale")).toBe("上报延迟");
    expect(hostStatusText("offline")).toBe("离线");
  });

  it("renders warning titles in business-safe Chinese", () => {
    expect(warningTitle("clock_skew")).toBe("时间偏移警告");
    expect(warningTitle("probe_configuration_error")).toBe("探针配置警告");
    expect(warningTitle("unknown_warning")).toBe("主机警告");
  });
});
