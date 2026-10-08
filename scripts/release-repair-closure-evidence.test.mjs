import { describe, expect, it } from "vitest";

import {
  hostProfileCollectorId,
  judgeInstalledBundleRepairClosure,
  probeRepairLocalCompletionOutput,
} from "./release-repair-closure-evidence.ts";

const failureEpochBootId = "4f7d3e15-63cc-4d61-8fe4-f5d42773dd51";
const failureEpochGeneration = "8".repeat(64);
const reportSessionBootId = "boot-repaired-session-01";
const probeId = "probe_release_01";
const identitySha256 = "b".repeat(64);
const version = "1.2.3";

function completeFacts() {
  return {
    capture: {
      bootId: reportSessionBootId,
      failedWindows: [
        {
          bootId: reportSessionBootId,
          payloadSha256: "5".repeat(64),
          sequence: 2,
        },
      ],
      finalBoot: {
        acceptedSequenceEnd: 1,
        ackObservedAtMs: 1_000,
        bootId: reportSessionBootId,
        bytes: 220,
        payloadSha256: "1".repeat(64),
        probeAssetBundleVersion: version,
        probeId,
        responseSha256: "2".repeat(64),
        sequence: 1,
        upstreamStatus: 200,
      },
      kind: "installed-bundle-repair-closure-capture",
      probeId,
      producedProfile: {
        acceptedSequenceEnd: 3,
        architecture: "x86_64",
        bootId: reportSessionBootId,
        bytes: 1_024,
        collectorId: hostProfileCollectorId,
        cpuCount: 4,
        hostname: "release-host-01",
        kernel: "5.15.0-139-generic",
        os: "Ubuntu 22.04.5 LTS",
        payloadSha256: "3".repeat(64),
        probeAssetBundleVersion: version,
        probeId,
        probeVersion: version,
        responseSha256: "4".repeat(64),
        sequence: 3,
        snapshotHash: "c".repeat(64),
        upstreamStatus: 200,
      },
      repairAuthorization: {
        bootId: failureEpochBootId,
        bundleVersion: version,
        epochGeneration: failureEpochGeneration,
        hostId: "7",
        operationId: "42",
        probeId,
        requestPayloadSha256: "9".repeat(64),
        responseSha256: "8".repeat(64),
        upstreamStatus: 200,
      },
      schemaVersion: 1,
    },
    expectation: {
      failureEpochBootId,
      failureEpochGeneration,
      hostId: 7,
      identitySha256,
      probeId,
      targetProbeVersion: version,
    },
    hubHostProfile: {
      architecture: "x86_64",
      cpuCount: 4,
      hostname: "release-host-01",
      kernel: "5.15.0-139-generic",
      os: "Ubuntu 22.04.5 LTS",
      probeVersion: version,
    },
    hubOperation: {
      hostId: 7,
      id: "42",
      kind: "probe_repair",
      source: "owner-probe-operation-read",
      state: "succeeded",
      targetProbeVersion: version,
    },
    localCompletion: {
      completedAtMs: 2_000,
      identitySha256,
      output: probeRepairLocalCompletionOutput,
      probeId,
      repairedVersion: version,
    },
  };
}

// mutate(facts, 修改, 期望理由)：正项之外，每一类缺失或错配都必须让同一判据拒绝结案。
function rejectsWith(mutate) {
  const facts = completeFacts();
  mutate(facts);
  return judgeInstalledBundleRepairClosure(facts);
}

describe("Installed Bundle Repair closure judgement", () => {
  it("accepts closure only when every recorded fact is associated", () => {
    const judgment = judgeInstalledBundleRepairClosure(completeFacts());
    expect(judgment).toEqual({
      accepted: true,
      associated: {
        bootAckPrecededLocalCompletion: true,
        bootId: reportSessionBootId,
        finalBootPayloadSha256: "1".repeat(64),
        finalBootSequence: 1,
        hostId: 7,
        localCompletionOutput: probeRepairLocalCompletionOutput,
        probeId,
        producedProfilePayloadSha256: "3".repeat(64),
        producedProfileSequence: 3,
        repairOperationId: "42",
        repairOperationState: "succeeded",
        successWindowFollowedFailedWindow: true,
        targetProbeVersion: version,
      },
      reasons: [],
    });
  });

  it("does not gate closure on the Boot ack being observed first", () => {
    const facts = completeFacts();
    facts.capture.finalBoot.ackObservedAtMs = 3_000;

    const judgment = judgeInstalledBundleRepairClosure(facts);

    expect(judgment.accepted).toBe(true);
    expect(judgment.associated?.bootAckPrecededLocalCompletion).toBe(false);
  });

  it("rejects a local CLI completion that is alone, and one using the retired English output", () => {
    const withoutTransportFacts = rejectsWith((facts) => {
      facts.capture = null;
      facts.hubHostProfile = null;
      facts.hubOperation = null;
    });
    expect(withoutTransportFacts.accepted).toBe(false);
    expect(withoutTransportFacts.reasons).toEqual(
      expect.arrayContaining([
        "closure_capture_missing",
        "repair_authorization_missing",
        "final_boot_report_missing",
        "produced_profile_missing",
        "hub_host_profile_read_missing",
        "hub_repair_operation_missing",
      ]),
    );

    const englishOutput = rejectsWith((facts) => {
      facts.localCompletion.output = "Probe repair completed.";
    });
    expect(englishOutput.reasons).toContain("local_completion_missing");
  });

  it("rejects a single Boot report that never produced a current Host Profile", () => {
    const judgment = rejectsWith((facts) => {
      facts.capture.producedProfile = null;
      facts.hubHostProfile = null;
    });
    expect(judgment.reasons).toEqual(
      expect.arrayContaining([
        "produced_profile_missing",
        "hub_host_profile_read_missing",
      ]),
    );
  });

  it("rejects a Host Profile the Hub no longer reports as current", () => {
    const judgment = rejectsWith((facts) => {
      facts.hubHostProfile.probeVersion = "1.2.2";
    });
    expect(judgment.reasons).toContain("produced_profile_not_current_on_hub");
  });

  it("keeps the failure epoch kernel boot out of the repaired report session", () => {
    const reusedBoot = rejectsWith((facts) => {
      facts.capture.bootId = failureEpochBootId;
      facts.capture.finalBoot.bootId = failureEpochBootId;
      facts.capture.producedProfile.bootId = failureEpochBootId;
    });
    expect(reusedBoot.reasons).toContain(
      "final_boot_reuses_failure_epoch_boot",
    );

    const continuedSession = rejectsWith((facts) => {
      facts.capture.bootId = reportSessionBootId;
      facts.capture.finalBoot.bootId = reportSessionBootId;
      facts.capture.finalBoot.sequence = 4;
      facts.capture.finalBoot.acceptedSequenceEnd = 4;
    });
    expect(continuedSession.reasons).toContain(
      "final_boot_not_new_report_session",
    );

    const wrongEpochBinding = rejectsWith((facts) => {
      facts.capture.repairAuthorization.bootId = reportSessionBootId;
    });
    expect(wrongEpochBinding.reasons).toContain(
      "repair_authorization_binding_mismatch",
    );

    const mismatchedCaptureBoot = rejectsWith((facts) => {
      facts.capture.bootId = "boot-other-session";
    });
    expect(mismatchedCaptureBoot.reasons).toContain(
      "closure_capture_boot_binding_mismatch",
    );
  });

  it("rejects identity, version and acknowledgement mismatches", () => {
    const identity = rejectsWith((facts) => {
      facts.capture.probeId = "probe_release_other";
      facts.capture.finalBoot.probeId = "probe_release_other";
    });
    expect(identity.reasons).toEqual(
      expect.arrayContaining([
        "closure_capture_identity_mismatch",
        "final_boot_identity_mismatch",
      ]),
    );

    const versionMismatch = rejectsWith((facts) => {
      facts.localCompletion.repairedVersion = "1.2.2";
      facts.capture.finalBoot.probeAssetBundleVersion = "1.2.2";
    });
    expect(versionMismatch.reasons).toEqual(
      expect.arrayContaining([
        "local_repaired_version_mismatch",
        "final_boot_version_mismatch",
      ]),
    );

    const noAck = rejectsWith((facts) => {
      facts.capture.finalBoot.upstreamStatus = 500;
      facts.capture.producedProfile.acceptedSequenceEnd = 2;
    });
    expect(noAck.reasons).toEqual(
      expect.arrayContaining([
        "final_boot_ack_missing",
        "produced_profile_ack_missing",
      ]),
    );

    const staleProfile = rejectsWith((facts) => {
      facts.capture.producedProfile.probeVersion = "1.2.2";
    });
    expect(staleProfile.reasons).toEqual(
      expect.arrayContaining([
        "produced_profile_stale",
        "produced_profile_not_current_on_hub",
      ]),
    );

    const unboundSnapshot = rejectsWith((facts) => {
      facts.capture.producedProfile.snapshotHash = "";
    });
    expect(unboundSnapshot.reasons).toContain(
      "produced_profile_snapshot_unbound",
    );
  });

  it("rejects a Repair Operation that is not the independent succeeded Hub operation from the authorization response", () => {
    const notSucceeded = rejectsWith((facts) => {
      facts.hubOperation.state = "failed";
    });
    expect(notSucceeded.reasons).toContain(
      "hub_repair_operation_not_succeeded",
    );

    const notIndependent = rejectsWith((facts) => {
      facts.hubOperation.kind = "probe_upgrade";
    });
    expect(notIndependent.reasons).toContain(
      "hub_repair_operation_not_independent",
    );

    const notFromAuthorization = rejectsWith((facts) => {
      facts.hubOperation.id = "43";
    });
    expect(notFromAuthorization.reasons).toEqual(
      expect.arrayContaining([
        "hub_repair_operation_not_from_authorization_response",
      ]),
    );

    const unreadableOperation = rejectsWith((facts) => {
      facts.capture.repairAuthorization.operationId = "";
      facts.hubOperation = null;
    });
    expect(unreadableOperation.reasons).toEqual(
      expect.arrayContaining([
        "repair_authorization_operation_unreadable",
        "hub_repair_operation_missing",
      ]),
    );

    const wrongHost = rejectsWith((facts) => {
      facts.hubOperation.hostId = 8;
      facts.hubOperation.targetProbeVersion = "1.2.2";
      facts.hubOperation.source = "hub-list-hosts";
    });
    expect(wrongHost.reasons).toEqual(
      expect.arrayContaining([
        "hub_repair_operation_host_mismatch",
        "hub_repair_operation_version_mismatch",
        "hub_repair_operation_source_invalid",
      ]),
    );
  });

  it("rejects a closure capture whose report session boot is not the produced profile boot", () => {
    const judgment = rejectsWith((facts) => {
      facts.capture.producedProfile.bootId = "boot-other-session";
    });
    expect(judgment.reasons).toContain("produced_profile_binding_mismatch");
  });
});
