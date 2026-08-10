import type {
  EnrollmentResponse,
  EnrollmentStatusResponse,
  HostSummary,
} from "../types";

export type EnrollmentDialogState = {
  enrollment: EnrollmentResponse | null;
  enrollmentError: string;
  isCreatingEnrollment: boolean;
};

export function shouldCreateEnrollmentOnOpen(state: EnrollmentDialogState) {
  return !state.isCreatingEnrollment;
}

export function reconcileEnrollmentStatus(
  enrollment: EnrollmentResponse | null,
  status: EnrollmentStatusResponse,
) {
  if (!enrollment || enrollment.enrollmentId !== status.enrollmentId) {
    return {
      enrollment,
      shouldClose: false,
    };
  }

  const reconciled = {
    ...enrollment,
    ...status,
  };

  return {
    enrollment: reconciled,
    shouldClose: ["expired", "ready", "rejected"].includes(status.status),
  };
}

export function enrollmentTerminalMessage(status: EnrollmentStatusResponse): {
  description: string;
  title: string;
} | null {
  if (status.status !== "rejected") {
    return null;
  }

  const code = status.rejection?.code;
  if (code === "existing_probe_installation") {
    return {
      description:
        "目标主机已有 Probe 安装痕迹。请先运行 sudo enoki-probe uninstall，然后重新生成安装命令。",
      title: "检测到已有 Probe 安装",
    };
  }
  if (code === "probe_bound_to_different_hub") {
    return {
      description:
        "此 Probe 已绑定到其他 Hub。请先在目标主机运行 sudo enoki-probe uninstall；即使旧 Hub 离线，也可随后重新生成安装命令。",
      title: "Probe 已绑定到其他 Hub",
    };
  }
  if (code === "probe_installation_metadata_invalid") {
    return {
      description:
        "本地 Probe 安装元数据不安全或不完整。请在目标主机运行 sudo enoki-probe uninstall 后重新安装。",
      title: "Probe 安装需要本地清理",
    };
  }

  return {
    description: "Probe 未在等待期限内完成与 Hub 的首次报告。",
    title: "Probe 未能就绪",
  };
}

export function matchingHostAction(input: {
  hostId: number | null;
  hosts: Array<Pick<HostSummary, "id" | "status">>;
}) {
  if (input.hostId === null) {
    return null;
  }

  const matchingHosts = input.hosts.filter((host) => host.id === input.hostId);
  return matchingHosts.length === 1 && matchingHosts[0]?.status === "offline"
    ? input.hostId
    : null;
}
