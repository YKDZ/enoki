import { display, type FeedbackDecision } from "@/feedback/feedback-policy";

export type ProbeUpgradeFeedbackInitiation =
  | "all-hosts"
  | "individual"
  | "untracked";

export type ProbeUpgradeTerminalState = "canceled" | "succeeded" | "superseded";

export type ProbeUpgradeRequestFailedFact = {
  hostId: number;
  kind: "probe-upgrade-request-failed";
};

export type ProbeUpgradeFeedbackFact =
  | ProbeUpgradeRequestFailedFact
  | {
      hostId: number;
      initiation: ProbeUpgradeFeedbackInitiation;
      kind: "probe-upgrade-transition";
      operationId: number;
      state: ProbeUpgradeTerminalState;
    };

export type ProbeUpgradeFeedbackDecision = FeedbackDecision;

const probeUpgradePresentations = {
  requestFailed: {
    aggregateKey: "probe-upgrade-request-failed",
    description: "请稍后重试。",
    level: "error",
    title: "无法创建探针升级请求",
  },
  terminal: {
    canceled: { level: "info", title: "探针升级已取消" },
    succeeded: { level: "success", title: "探针升级完成" },
    superseded: { level: "info", title: "探针升级请求已被替代" },
  },
} as const;

export function decideProbeUpgradeFeedback(
  input: ProbeUpgradeFeedbackFact,
): ProbeUpgradeFeedbackDecision {
  if (input.kind === "probe-upgrade-request-failed") {
    const presentation = probeUpgradePresentations.requestFailed;
    return display(
      presentation.aggregateKey,
      presentation.level,
      presentation.title,
      {
        deduplicationKey: `probe-upgrade-request-failed:${input.hostId}`,
        description: presentation.description,
      },
    );
  }

  if (input.initiation !== "individual") {
    return { kind: "suppress" };
  }

  const presentation = probeUpgradePresentations.terminal[input.state];
  return terminalDisplay(input, presentation.level, presentation.title);
}

function terminalDisplay(
  input: Extract<
    ProbeUpgradeFeedbackFact,
    { kind: "probe-upgrade-transition" }
  >,
  level: "info" | "success",
  title: string,
): ProbeUpgradeFeedbackDecision {
  return display("probe-upgrade-terminal", level, title, {
    deduplicationKey: `probe-upgrade:${input.hostId}:${input.operationId}:${input.state}`,
  });
}
