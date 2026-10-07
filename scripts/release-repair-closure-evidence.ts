// Installed Bundle Repair 结案证据接缝：把正式 CLI 的本机完成事实、最终普通 Probe 的
// 报告事实、以及同一独立 Probe Repair Operation 的正常 Hub 读数分开记录，再由这一份
// 共享判据决定「修复完成」。正式场景与 Release Verification summary 都调用本模块，
// 产品侧结案算法与预算资格算法仍只在产品内，验收层不复制。

// 08 已接受的正式 CLI 本机完成合同；修复最终结果由 Hub 上同一独立 Probe Repair
// Operation 决定，本机输出只证明本机恢复与最终普通 Probe 已启动。
export const probeRepairLocalCompletionOutput =
  "本机恢复与最终探针启动已完成；修复最终结果以 Hub 为准";

export const hostProfileCollectorId = "official.host-profile";

export type RepairClosureCapture = {
  // 最终普通 Probe 的报告会话 boot（每进程启动新生成），不是故障 epoch 的内核 boot_id。
  bootId: string;
  finalBoot: {
    acceptedSequenceEnd: number;
    ackObservedAtMs: number;
    bootId: string;
    bytes: number;
    payloadSha256: string;
    probeAssetBundleVersion: string;
    probeId: string;
    responseSha256: string;
    sequence: number;
    upstreamStatus: number;
  } | null;
  failedWindows: {
    bootId: string;
    payloadSha256: string;
    sequence: number;
  }[];
  kind: "installed-bundle-repair-closure-capture";
  probeId: string;
  producedProfile: {
    acceptedSequenceEnd: number;
    architecture: string;
    bootId: string;
    bytes: number;
    collectorId: string;
    cpuCount: number;
    hostname: string;
    kernel: string;
    os: string;
    payloadSha256: string;
    probeAssetBundleVersion: string;
    probeId: string;
    probeVersion: string;
    responseSha256: string;
    sequence: number;
    snapshotHash: string;
    upstreamStatus: number;
  } | null;
  repairAuthorization: {
    // 修复授权请求携带的故障 epoch 内核 boot_id。
    bootId: string;
    bundleVersion: string;
    epochGeneration: string;
    hostId: string;
    operationId: string;
    probeId: string;
    requestPayloadSha256: string;
    responseSha256: string;
    upstreamStatus: number;
  } | null;
  schemaVersion: 1;
};

export type LocalRepairCompletion = {
  completedAtMs: number;
  identitySha256: string;
  output: string;
  probeId: string;
  repairedVersion: string;
};

export type HubRepairOperationReading = {
  hostId: number;
  id: string;
  kind: string;
  source: "owner-probe-operation-read";
  state: string;
  targetProbeVersion: string;
};

export type HubHostProfileReading = {
  architecture: string;
  cpuCount: number;
  hostname: string;
  kernel: string;
  os: string;
  probeVersion: string;
};

export type RepairClosureExpectation = {
  // 故障 durable epoch 绑定的内核 boot_id，只用于核对修复授权，不能与普通报告会话 boot 混用。
  failureEpochBootId: string;
  failureEpochGeneration: string;
  hostId: number;
  identitySha256: string;
  probeId: string;
  targetProbeVersion: string;
};

export type RepairClosureJudgment = {
  accepted: boolean;
  associated: {
    bootAckPrecededLocalCompletion: boolean;
    bootId: string;
    finalBootPayloadSha256: string;
    finalBootSequence: number;
    hostId: number;
    localCompletionOutput: string;
    probeId: string;
    producedProfilePayloadSha256: string;
    producedProfileSequence: number;
    repairOperationId: string;
    repairOperationState: string;
    successWindowFollowedFailedWindow: boolean;
    targetProbeVersion: string;
  } | null;
  reasons: string[];
};

// 结案事实记录：正式场景把这份原始事实写入证据，summary 之后用同一判据重新判定；
// 证据里不保存判定结论，避免场景自证结案。
export type RepairClosureFacts = {
  capture: RepairClosureCapture | null | undefined;
  expectation: RepairClosureExpectation;
  hubHostProfile: HubHostProfileReading | null | undefined;
  hubOperation: HubRepairOperationReading | null | undefined;
  localCompletion: LocalRepairCompletion | null | undefined;
};

export function judgeInstalledBundleRepairClosure({
  capture,
  expectation,
  hubHostProfile,
  hubOperation,
  localCompletion,
}: RepairClosureFacts): RepairClosureJudgment {
  const reasons: string[] = [];
  const authorization = capture?.repairAuthorization ?? null;
  const finalBoot = capture?.finalBoot ?? null;
  const producedProfile = capture?.producedProfile ?? null;

  if (!localCompletion) {
    reasons.push("local_completion_missing");
  } else {
    if (localCompletion.output !== probeRepairLocalCompletionOutput) {
      reasons.push("local_completion_missing");
    }
    if (
      localCompletion.probeId !== expectation.probeId ||
      localCompletion.identitySha256 !== expectation.identitySha256
    ) {
      reasons.push("local_identity_not_preserved");
    }
    if (localCompletion.repairedVersion !== expectation.targetProbeVersion) {
      reasons.push("local_repaired_version_mismatch");
    }
  }

  if (!capture) {
    reasons.push("closure_capture_missing");
  } else if (capture.probeId !== expectation.probeId) {
    reasons.push("closure_capture_identity_mismatch");
  }

  if (!authorization) {
    reasons.push("repair_authorization_missing");
  } else {
    if (
      authorization.probeId !== expectation.probeId ||
      authorization.hostId !== String(expectation.hostId) ||
      authorization.bootId !== expectation.failureEpochBootId ||
      authorization.epochGeneration !== expectation.failureEpochGeneration
    ) {
      reasons.push("repair_authorization_binding_mismatch");
    }
    if (authorization.upstreamStatus !== 200) {
      reasons.push("repair_authorization_not_accepted");
    }
    if (!/^[1-9]\d*$/.test(authorization.operationId)) {
      reasons.push("repair_authorization_operation_unreadable");
    }
  }

  if (!finalBoot) {
    reasons.push("final_boot_report_missing");
  } else {
    if (finalBoot.probeId !== expectation.probeId) {
      reasons.push("final_boot_identity_mismatch");
    }
    if (finalBoot.bootId === expectation.failureEpochBootId) {
      reasons.push("final_boot_reuses_failure_epoch_boot");
    }
    if (finalBoot.sequence !== 1) {
      reasons.push("final_boot_not_new_report_session");
    }
    if (capture?.bootId !== finalBoot.bootId) {
      reasons.push("closure_capture_boot_binding_mismatch");
    }
    if (
      normalizedVersion(finalBoot.probeAssetBundleVersion) !==
      normalizedVersion(expectation.targetProbeVersion)
    ) {
      reasons.push("final_boot_version_mismatch");
    }
    if (
      finalBoot.upstreamStatus !== 200 ||
      finalBoot.acceptedSequenceEnd !== finalBoot.sequence
    ) {
      reasons.push("final_boot_ack_missing");
    }
  }

  if (!producedProfile) {
    reasons.push("produced_profile_missing");
  } else {
    if (producedProfile.collectorId !== hostProfileCollectorId) {
      reasons.push("produced_profile_collector_mismatch");
    }
    if (
      producedProfile.bootId !== finalBoot?.bootId ||
      producedProfile.probeId !== expectation.probeId
    ) {
      reasons.push("produced_profile_binding_mismatch");
    }
    if (!/^[0-9a-f]{64}$/.test(producedProfile.snapshotHash)) {
      reasons.push("produced_profile_snapshot_unbound");
    }
    if (
      normalizedVersion(producedProfile.probeAssetBundleVersion) !==
        normalizedVersion(expectation.targetProbeVersion) ||
      normalizedVersion(producedProfile.probeVersion) !==
        normalizedVersion(expectation.targetProbeVersion)
    ) {
      reasons.push("produced_profile_stale");
    }
    if (
      producedProfile.upstreamStatus !== 200 ||
      producedProfile.acceptedSequenceEnd !== producedProfile.sequence
    ) {
      reasons.push("produced_profile_ack_missing");
    }
  }

  if (!hubHostProfile) {
    reasons.push("hub_host_profile_read_missing");
  } else if (
    producedProfile &&
    (hubHostProfile.hostname !== producedProfile.hostname ||
      hubHostProfile.os !== producedProfile.os ||
      hubHostProfile.kernel !== producedProfile.kernel ||
      hubHostProfile.architecture !== producedProfile.architecture ||
      hubHostProfile.cpuCount !== producedProfile.cpuCount ||
      normalizedVersion(hubHostProfile.probeVersion) !==
        normalizedVersion(producedProfile.probeVersion))
  ) {
    reasons.push("produced_profile_not_current_on_hub");
  }

  if (!hubOperation) {
    reasons.push("hub_repair_operation_missing");
  } else {
    if (hubOperation.source !== "owner-probe-operation-read") {
      reasons.push("hub_repair_operation_source_invalid");
    }
    if (hubOperation.kind !== "probe_repair") {
      reasons.push("hub_repair_operation_not_independent");
    }
    if (
      authorization === null ||
      hubOperation.id !== authorization.operationId
    ) {
      reasons.push("hub_repair_operation_not_from_authorization_response");
    }
    if (hubOperation.hostId !== expectation.hostId) {
      reasons.push("hub_repair_operation_host_mismatch");
    }
    if (hubOperation.targetProbeVersion !== expectation.targetProbeVersion) {
      reasons.push("hub_repair_operation_version_mismatch");
    }
    if (hubOperation.state !== "succeeded") {
      reasons.push("hub_repair_operation_not_succeeded");
    }
  }

  const accepted = reasons.length === 0;
  if (
    !accepted ||
    !capture ||
    !authorization ||
    !finalBoot ||
    !producedProfile ||
    !localCompletion ||
    !hubOperation
  ) {
    return { accepted: false, associated: null, reasons };
  }
  return {
    accepted: true,
    associated: {
      bootAckPrecededLocalCompletion:
        finalBoot.ackObservedAtMs <= localCompletion.completedAtMs,
      bootId: finalBoot.bootId,
      finalBootPayloadSha256: finalBoot.payloadSha256,
      finalBootSequence: finalBoot.sequence,
      hostId: expectation.hostId,
      localCompletionOutput: localCompletion.output,
      probeId: expectation.probeId,
      producedProfilePayloadSha256: producedProfile.payloadSha256,
      producedProfileSequence: producedProfile.sequence,
      repairOperationId: authorization.operationId,
      repairOperationState: hubOperation.state,
      successWindowFollowedFailedWindow: capture.failedWindows.some(
        (window) =>
          window.bootId === finalBoot.bootId &&
          window.sequence < producedProfile.sequence,
      ),
      targetProbeVersion: expectation.targetProbeVersion,
    },
    reasons: [],
  };
}

function normalizedVersion(value: unknown): string {
  return typeof value === "string" ? value.trim().replace(/^v/, "") : "";
}
