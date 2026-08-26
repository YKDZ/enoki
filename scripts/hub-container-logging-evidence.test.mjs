import { describe, expect, it } from "vitest";

import {
  assertListenerConsoleEvidence,
  parseContainerJsonLines,
} from "../apps/hub/scripts/container-logging-contract.mjs";

describe("Hub 容器控制台日志合同", () => {
  it("接受两个 listener 的正常 JSON Lines 事件并限制字段集合", () => {
    const events = parseContainerJsonLines(
      [
        '{"component":"management-listener","event":"listener.started","level":"info","listener":"management","outcome":"listening"}',
        '{"component":"probe-listener","event":"listener.started","level":"info","listener":"probe","outcome":"listening"}',
        '{"component":"management-listener","durationMs":1,"event":"request.completed","level":"debug","listener":"management","method":"GET","outcome":"ok","requestId":"abcdefghi","routeId":"health","status":200}',
        '{"component":"probe-listener","durationMs":1,"event":"request.completed","level":"debug","listener":"probe","method":"GET","outcome":"ok","requestId":"abcdefghi","routeId":"health","status":200}',
        '{"component":"hub","event":"process.shutdown.started","level":"info","outcome":"graceful_shutdown"}',
        '{"component":"hub","event":"process.shutdown.completed","level":"info","outcome":"graceful_shutdown"}',
      ].join("\n"),
    );

    expect(() => assertListenerConsoleEvidence(events)).not.toThrow();
  });

  it("拒绝超出日志白名单的普通字段", () => {
    expect(() =>
      parseContainerJsonLines(
        '{"component":"management-listener","event":"listener.started","level":"info","listener":"management","outcome":"listening","extra":"no"}',
      ),
    ).toThrow("字段白名单");
  });
});
