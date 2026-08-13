import { display, type FeedbackDecision } from "@/feedback/feedback-policy";

export type EnrollmentFeedbackFact =
  | { enrollmentId: string; kind: "enrollment-expired" }
  | { enrollmentId: string; kind: "enrollment-ready" }
  | {
      enrollmentId: string;
      hostId: number | null;
      kind: "enrollment-rejected";
      reason:
        | "existing-probe-installation"
        | "installation-metadata-invalid"
        | "probe-bound-to-different-hub"
        | "unclassified";
      retryHostEnrollment: boolean;
    };

export function decideEnrollmentFeedback(
  fact: EnrollmentFeedbackFact,
): FeedbackDecision {
  switch (fact.kind) {
    case "enrollment-ready":
      return display("enrollment-ready", "success", "主机已就绪", {
        deduplicationKey: `enrollment:${fact.enrollmentId}:ready`,
        description: "探针已完成与 Hub 的首次报告。",
      });
    case "enrollment-expired":
      return display("enrollment-expired", "error", "安装命令已过期", {
        deduplicationKey: `enrollment:${fact.enrollmentId}:expired`,
        description: "请生成新的安装命令。",
      });
    case "enrollment-rejected":
      return rejected(fact);
  }
}

function rejected(
  fact: Extract<EnrollmentFeedbackFact, { kind: "enrollment-rejected" }>,
): FeedbackDecision {
  const recovery =
    fact.retryHostEnrollment && fact.hostId !== null
      ? {
          action: {
            hostId: fact.hostId,
            kind: "recover-host-enrollment" as const,
          },
        }
      : {};
  const shared = {
    deduplicationKey: `enrollment:${fact.enrollmentId}:rejected:${fact.reason}`,
    ...recovery,
  };
  switch (fact.reason) {
    case "existing-probe-installation":
      return display("enrollment-rejected", "error", "检测到已有探针安装", {
        ...shared,
        description:
          "目标主机已有探针安装痕迹。请先运行 sudo enoki-probe uninstall，然后重新生成安装命令。",
      });
    case "probe-bound-to-different-hub":
      return display("enrollment-rejected", "error", "探针已绑定到其他 Hub", {
        ...shared,
        description:
          "此探针已绑定到其他 Hub。请先在目标主机运行 sudo enoki-probe uninstall；即使旧 Hub 离线，也可随后重新生成安装命令。",
      });
    case "installation-metadata-invalid":
      return display("enrollment-rejected", "error", "探针安装需要本地清理", {
        ...shared,
        description:
          "本地探针安装元数据不安全或不完整。请在目标主机运行 sudo enoki-probe uninstall 后重新安装。",
      });
    case "unclassified":
      return display("enrollment-rejected", "error", "探针未能就绪", {
        ...shared,
        description: "探针未在等待期限内完成与 Hub 的首次报告。",
      });
  }
}
