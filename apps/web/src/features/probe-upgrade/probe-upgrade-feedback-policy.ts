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

export type ProbeUpgradeAllSubmittedFact = {
  attemptId: number;
  failed: number;
  kind: "probe-upgrade-all-submitted";
  skipped: number;
  submitted: number;
};

export type ProbeUpgradeAllRequestFailedFact = {
  attemptId: number;
  kind: "probe-upgrade-all-request-failed";
};

export type ProbeUpgradeFeedbackFact =
  | ProbeUpgradeAllRequestFailedFact
  | ProbeUpgradeAllSubmittedFact
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
  if (input.kind === "probe-upgrade-all-request-failed") {
    const aggregateKey = `probe-upgrade-all-request-failed:${input.attemptId}`;
    return display(aggregateKey, "error", "无法提交全部探针升级", {
      description: "请稍后重试。",
    });
  }

  if (input.kind === "probe-upgrade-all-submitted") {
    const aggregateKey = `probe-upgrade-all-submitted:${input.attemptId}`;
    const level = input.failed > 0 ? "warning" : "success";
    const title =
      input.failed > 0
        ? "已提交部分探针升级"
        : input.submitted > 0
          ? "已提交探针升级"
          : "没有可升级的探针";
    return display(aggregateKey, level, title, {
      description: `已提交 ${input.submitted} 台，跳过 ${input.skipped} 台，失败 ${input.failed} 台。`,
    });
  }

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
