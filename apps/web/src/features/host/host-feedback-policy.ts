import { display, type FeedbackDecision } from "@/feedback/feedback-policy";

export type HostFeedbackFact =
  | {
      hostId: number;
      kind: "clock-skew-detected";
      roundedDeltaSeconds: number | null;
    }
  | {
      hostId: number;
      kind: "host-delete-requested";
      mode: "hub-only" | "uninstall";
    }
  | {
      hostId: number;
      kind: "host-enrollment-retryable-failure";
      reason: "unavailable" | "unclassified" | "verifying";
    };

export function decideHostFeedback(fact: HostFeedbackFact): FeedbackDecision {
  switch (fact.kind) {
    case "clock-skew-detected":
      return display("clock-skew-detected", "warning", "时间不同步", {
        deduplicationKey: `clock-skew:${fact.hostId}:${fact.roundedDeltaSeconds ?? "unknown"}`,
        description:
          fact.roundedDeltaSeconds === null
            ? "探针时间与 Hub 时间存在偏移。"
            : `探针时间与 Hub 时间相差约 ${fact.roundedDeltaSeconds} 秒。`,
      });
    case "host-delete-requested":
      return display(
        "host-delete-requested",
        "success",
        fact.mode === "hub-only"
          ? "已删除 Hub 中的主机"
          : "已下发卸载探针并删除主机请求",
        {
          deduplicationKey: `host-delete-requested:${fact.hostId}:${fact.mode}`,
        },
      );
    case "host-enrollment-retryable-failure":
      return enrollmentFailure(fact);
  }
}

function enrollmentFailure(
  fact: Extract<
    HostFeedbackFact,
    { kind: "host-enrollment-retryable-failure" }
  >,
): FeedbackDecision {
  const hostEnrollmentFailurePresentations = {
    unavailable: ["主机状态已变化", "主机状态已变化，请刷新后重试。"],
    unclassified: ["无法创建主机重新注册命令", "请稍后重试。"],
    verifying: ["已有重新注册进行中", "已有重新注册正在进行中，请刷新后重试。"],
  } as const;
  const [title, description] = hostEnrollmentFailurePresentations[fact.reason];
  return display("host-enrollment-retryable-failure", "error", title, {
    deduplicationKey: `host-enrollment-retryable-failure:${fact.hostId}:${fact.reason}`,
    description,
    action: { hostId: fact.hostId, kind: "retry-host-enrollment" },
  });
}
