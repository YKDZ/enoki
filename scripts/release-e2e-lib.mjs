import { createHash, randomUUID } from "node:crypto";

const managedHostPaths = Object.freeze([
  "/usr/local/bin/enoki-probe",
  "/etc/enoki/probe-bootstrap.toml",
  "/etc/enoki/probe-install.toml",
  "/etc/systemd/system/enoki-probe.service",
  "/etc/systemd/system/enoki-probe.service.d/90-enoki-release-e2e-restart-failure.conf",
  "/var/lib/enoki-probe",
  "/etc/sudoers.d/enoki-probe-operations",
  "/etc/sudoers.d/enoki-probe-collector-helpers",
  "/etc/sudoers.d/enoki-probe-upgrader",
]);

const terminalProbeOperationStates = new Set([
  "succeeded",
  "failed",
  "superseded",
  "canceled",
]);

const probeOperationStateRank = Object.freeze({
  accepted: 1,
  canceled: 3,
  failed: 3,
  pending: 0,
  running: 2,
  succeeded: 3,
  superseded: 3,
});

const supportedReleaseTestHostVmTypes = new Set([
  "acrn",
  "amazon",
  "apple",
  "bhyve",
  "bochs",
  "google",
  "kvm",
  "microsoft",
  "oracle",
  "powervm",
  "qemu",
  "qnx",
  "sre",
  "uml",
  "vm-other",
  "vmware",
  "xen",
  "zvm",
]);

export const releaseE2EScenarioRegistry = Object.freeze({
  "baseline-upgrade-uninstall": runBaselineUpgradeUninstallScenario,
  "fresh-install-uninstall": runFreshInstallUninstallScenario,
  "hub-restore-compatibility-window": runHubRestoreCompatibilityWindowScenario,
  "post-replacement-repair-uninstall":
    runPostReplacementRepairUninstallScenario,
});

export async function runReleaseE2EScenario(options) {
  const scenario = options?.scenario;
  const runner = releaseE2EScenarioRegistry[scenario];
  if (!runner) {
    throw new Error(`unsupported Release E2E scenario: ${scenario}`);
  }
  return runner(options);
}

async function runHubRestoreCompatibilityWindowScenario({
  candidateManifest,
  environment,
  evidenceSink,
  ownerPassword,
  runId,
  scenario,
  timing = {},
}) {
  assertRunId(runId);
  assertCandidateManifest(candidateManifest);
  if (!environment?.start || !environment?.cleanup || !evidenceSink?.write) {
    throw new Error("Release E2E environment and evidence sink are required");
  }
  const baseline = candidateManifest.releaseBaseline;

  const poll = normalizedPollTiming(timing);
  const evidence = {
    candidate: candidateManifest.candidate,
    cleanup: null,
    failureBoundary: null,
    hostEvidence: null,
    hubEvidence: null,
    hostProfileContinuity: {
      allowedChanges: [
        "collection and observation timestamps",
        "filesystems[].availableBytes",
        "processCount",
        "threadCount",
      ],
      candidateBeforeRestore: null,
      restoredBaseline: null,
    },
    identity: null,
    image: {
      candidateDigest: candidateManifest.hub.digest,
      expectedBaselineDigest: baseline.hub.imageDigest,
      restoredBaselineDigest: null,
      snapshotVerify: null,
      stateRestore: null,
    },
    infrastructure: null,
    migration: {
      candidateProbeVersion: candidateManifest.probeAssetSet.version,
      operationTimeline: [],
      status: "pending",
    },
    phase: "scenario-running",
    protocol: {
      baselineProbeToCandidateHub: "pending",
      candidateProbeToBaselineHub: "pending",
    },
    releaseBaseline: {
      hubDigest: baseline.hub.imageDigest,
      probeVersion: baseline.probeAssetSet.version,
      tag: baseline.tag,
    },
    releaseTestHost: null,
    reporting: {
      candidateHub: null,
      restoredBaselineHub: null,
    },
    result: { status: "running" },
    runId,
    scenario,
    schemaVersion: 2,
    snapshot: null,
    uninstall: {
      hostCompletion: null,
      hubSoftDeleted: false,
      operationTimeline: [],
      status: "pending",
    },
  };
  let activeBoundary = "infrastructure";
  let resources = null;
  let primaryError = null;
  let evidenceWriteError = null;
  let finalEvidence = evidence;

  try {
    resources = await environment.start({
      candidateManifest,
      hubMode: "baseline",
      runId,
      scenario,
    });
    const { host, hub } = resources ?? {};
    assertHubRestoreScenarioParticipants(host, hub);
    evidence.infrastructure = resources?.infrastructure ?? null;
    evidence.releaseTestHost = resources?.releaseTestHost ?? null;

    await host.assertDisposable(runId);
    await hub.authenticate(ownerPassword);
    const initialHosts = await hub.listHosts();
    if (!Array.isArray(initialHosts) || initialHosts.length !== 0) {
      throw assertionError(
        "restore_baseline_hub_not_empty",
        "Hub Restore scenario requires new Release Baseline Hub state",
      );
    }
    const enrollment = await hub.createEnrollment();
    if (!enrollment?.installCommand) {
      throw assertionError(
        "enrollment_command_missing",
        "Release Baseline Hub did not return its official Probe install command",
      );
    }
    await host.install(enrollment.installCommand, runId);
    await host.assertInstalled(runId, baseline.probeAssetSet.version);
    const baselineIdentity = await host.readProbeIdentity(runId);
    const hostSummary = await waitForObservation({
      code: "restore_probe_enrollment_timeout",
      label: "Release Baseline Probe enrollment before Hub State Snapshot",
      observe: async () => {
        const hosts = await hub.listHosts();
        return Array.isArray(hosts) && hosts.length === 1 ? hosts[0] : null;
      },
      poll,
      ready: (value) => Number.isSafeInteger(value?.id) && value.id > 0,
    });
    const hostId = hostSummary.id;
    evidence.identity = {
      afterRestore: null,
      afterUpgrade: null,
      beforeUpgrade: baselineIdentity,
      hostId,
    };
    await waitForObservation({
      code: "restore_baseline_reporting_timeout",
      label: "Release Baseline core reporting before Hub State Snapshot",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, baseline.probeAssetSet.version),
    });
    await waitForObservation({
      code: "restore_baseline_metrics_timeout",
      label: "Release Baseline portable Metrics before Hub State Snapshot",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: hasAdvancingPortableMetrics,
    });

    activeBoundary = "snapshot";
    evidence.snapshot = await hub.captureBaselineStateSnapshot({
      baselineImageDigest: baseline.hub.imageDigest,
      baselineVersion: baseline.tag,
    });
    assertLiveHubStateSnapshotEvidence(evidence.snapshot, baseline);

    activeBoundary = "migration";
    await hub.switchToCandidate();
    await hub.authenticate(ownerPassword);
    await waitForObservation({
      code: "restore_baseline_probe_candidate_hub_timeout",
      label: "Release Baseline Probe reporting to Candidate Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, baseline.probeAssetSet.version),
    });
    evidence.protocol.baselineProbeToCandidateHub = "succeeded";
    await host.beginUpgradeOwnershipTransition(
      runId,
      candidateManifest.probeAssetSet.version,
    );
    const requestedUpgrade = await hub.requestProbeUpgrade(hostId);
    if (
      requestedUpgrade.targetProbeVersion !==
      candidateManifest.probeAssetSet.version
    ) {
      throw assertionError(
        "probe_upgrade_target_mismatch",
        "Hub Restore scenario Upgrade did not target the Candidate Probe",
      );
    }
    evidence.migration.operationTimeline = [requestedUpgrade];
    await host.bindUpgradeOwnershipTransition(runId, requestedUpgrade);
    evidence.migration.operationTimeline = await hub.waitForProbeOperation(
      requestedUpgrade,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    validateSuccessfulProbeUpgradeTimeline(
      evidence.migration.operationTimeline,
    );
    await host.completeUpgradeOwnershipTransition(
      runId,
      evidence.migration.operationTimeline.at(-1),
    );
    await host.assertInstalled(runId, candidateManifest.probeAssetSet.version);
    activeBoundary = "identity";
    const upgradedIdentity = await host.readProbeIdentity(runId);
    assertSameProbeIdentity(baselineIdentity, upgradedIdentity, "Upgrade");
    evidence.identity.afterUpgrade = upgradedIdentity;
    activeBoundary = "reporting";
    const candidateHost = await waitForObservation({
      code: "restore_candidate_probe_reporting_timeout",
      label: "Candidate Probe core reporting to Candidate Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version),
    });
    const candidateMetrics = await waitForObservation({
      code: "restore_candidate_metrics_timeout",
      label: "Candidate Probe portable Metrics before Hub Restore",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: hasAdvancingPortableMetrics,
    });
    const metricCheckpoint = latestPortableMetric(candidateMetrics);
    if (!metricCheckpoint) {
      throw assertionError(
        "restore_metrics_checkpoint_missing",
        "Hub Restore scenario has no Candidate Probe Metrics checkpoint",
      );
    }
    evidence.reporting.candidateHub = {
      host: compactHostEvidence(candidateHost),
      metrics: compactMetricsEvidence(candidateMetrics),
    };
    evidence.hostProfileContinuity.candidateBeforeRestore =
      stableHostProfileEvidence(candidateHost.hostProfile);
    evidence.migration.status = "succeeded";

    activeBoundary = "image";
    const restored = await hub.restoreBaselineStateSnapshot({
      baselineImageDigest: baseline.hub.imageDigest,
      baselineVersion: baseline.tag,
      expectedManifestDigest: evidence.snapshot.manifestDigest,
      recoveryTime: evidence.snapshot.recoveryTime,
    });
    assertLiveHubRestoreEvidence(
      restored,
      evidence.snapshot.manifestDigest,
      baseline.hub.imageDigest,
    );
    evidence.image.restoredBaselineDigest = restored.image.activeManifestDigest;
    evidence.image.snapshotVerify = restored.verify;
    evidence.image.stateRestore = restored.restore;

    activeBoundary = "protocol";
    await hub.authenticate(ownerPassword);
    const restoredHosts = await hub.listHosts();
    if (
      !Array.isArray(restoredHosts) ||
      restoredHosts.length !== 1 ||
      restoredHosts[0]?.id !== hostId
    ) {
      throw assertionError(
        "restored_host_state_mismatch",
        "Hub Restore did not recover the original Host",
      );
    }
    const restoredHost = await waitForObservation({
      code: "candidate_probe_baseline_hub_compatibility_timeout",
      label: "Candidate Probe reporting to restored Release Baseline Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version),
    });
    evidence.hostProfileContinuity.restoredBaseline = stableHostProfileEvidence(
      restoredHost.hostProfile,
    );
    assertStableHostProfileContinuity(
      evidence.hostProfileContinuity.candidateBeforeRestore,
      evidence.hostProfileContinuity.restoredBaseline,
    );
    await host.assertInstalled(runId, candidateManifest.probeAssetSet.version);
    activeBoundary = "identity";
    const restoredIdentity = await host.readProbeIdentity(runId);
    assertSameProbeIdentity(baselineIdentity, restoredIdentity, "Hub Restore");
    evidence.identity.afterRestore = restoredIdentity;
    activeBoundary = "reporting";
    const restoredMetrics = await waitForObservation({
      code: "candidate_probe_restored_metrics_timeout",
      label: "Candidate Probe portable Metrics after Hub Restore",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: (samples) =>
        hasAdvancingPortableMetrics(samples) &&
        metricsAdvanceBeyond(samples, metricCheckpoint),
    });
    evidence.protocol.candidateProbeToBaselineHub = "succeeded";
    evidence.reporting.restoredBaselineHub = {
      host: compactHostEvidence(restoredHost),
      metrics: compactMetricsEvidence(restoredMetrics),
    };

    activeBoundary = "uninstall";
    const requestedUninstall = await hub.requestProbeUninstall(hostId);
    evidence.uninstall.operationTimeline = [requestedUninstall];
    evidence.uninstall.operationTimeline = await hub.waitForProbeOperation(
      requestedUninstall,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    const finalUninstall = evidence.uninstall.operationTimeline.at(-1);
    if (finalUninstall?.state !== "succeeded" || finalUninstall.failure) {
      throw assertionError(
        "probe_uninstall_failed",
        `Probe Uninstall through the restored Release Baseline Hub did not succeed: ${JSON.stringify(finalUninstall)}`,
      );
    }
    evidence.uninstall.hubSoftDeleted = await hub.isHostSoftDeleted(hostId);
    if (!evidence.uninstall.hubSoftDeleted) {
      throw assertionError(
        "host_not_soft_deleted",
        "Probe Uninstall through the restored Release Baseline Hub succeeded but the Host remains active",
      );
    }
    evidence.uninstall.hostCompletion =
      await host.verifyUninstallCompletion(runId);
    if (
      evidence.uninstall.hostCompletion?.clean !== true ||
      evidence.uninstall.hostCompletion?.journaldRetained !== true ||
      evidence.uninstall.hostCompletion?.sharedDependenciesRetained !== true
    ) {
      throw assertionError(
        "probe_uninstall_residue",
        `Host did not satisfy Probe Uninstall Completion after Hub Restore: ${JSON.stringify(evidence.uninstall.hostCompletion)}`,
      );
    }
    evidence.uninstall.status = "succeeded";
    evidence.result = { status: "succeeded" };
    evidence.phase = "succeeded";
  } catch (error) {
    primaryError = error;
    evidence.failureBoundary = activeBoundary;
    if (Array.isArray(error?.timeline)) {
      if (error.timeline[0]?.kind === "probe_uninstall") {
        evidence.uninstall.operationTimeline = error.timeline;
      } else {
        evidence.migration.operationTimeline = error.timeline;
      }
    }
    evidence.result = { error: serializedError(error), status: "failed" };
    evidence.phase = "failed";
  } finally {
    if (resources?.hub?.collectEvidence) {
      try {
        evidence.hubEvidence = await resources.hub.collectEvidence();
      } catch (error) {
        evidence.hubEvidence = { error: serializedError(error) };
      }
    }
    if (resources?.host?.collectEvidence) {
      try {
        evidence.hostEvidence = await resources.host.collectEvidence(runId);
      } catch (error) {
        evidence.hostEvidence = { error: serializedError(error) };
      }
    }
    const cleanup = {};
    if (resources?.host?.cleanup) {
      try {
        cleanup.host = await resources.host.cleanup(runId);
      } catch (error) {
        cleanup.host = { error: serializedError(error) };
      }
    }
    try {
      cleanup.environment = await environment.cleanup({ resources, runId });
    } catch (error) {
      cleanup.environment = { error: serializedError(error) };
    }
    evidence.cleanup = cleanup;
    if (!primaryError && cleanupDidNotSucceed(cleanup)) {
      primaryError = assertionError(
        "release_e2e_cleanup_failed",
        "Release E2E cleanup did not remove all run-owned state",
      );
      evidence.failureBoundary = "cleanup";
      evidence.result = {
        error: serializedError(primaryError),
        status: "failed",
      };
      evidence.phase = "failed";
    }
    finalEvidence = redactSensitiveEvidence(evidence, [ownerPassword]);
    try {
      await evidenceSink.write(finalEvidence);
    } catch (error) {
      evidenceWriteError = error;
      if (!primaryError) {
        primaryError = assertionError(
          "release_e2e_evidence_write_failed",
          `Release E2E evidence could not be written: ${error.message}`,
        );
      }
    }
  }

  if (primaryError) {
    const failure = new Error(
      `Release E2E ${scenario} failed at ${evidence.failureBoundary}: ${redactSensitiveText(primaryError.message, [ownerPassword])}`,
    );
    failure.code = primaryError.code ?? "release_e2e_failed";
    failure.evidence = finalEvidence;
    if (evidenceWriteError) {
      failure.evidenceWriteError = serializedError(evidenceWriteError);
    }
    throw failure;
  }
  return evidence.result;
}

async function runPostReplacementRepairUninstallScenario({
  candidateManifest,
  environment,
  evidenceSink,
  ownerPassword,
  runId,
  scenario,
  timing = {},
}) {
  assertRunId(runId);
  assertCandidateManifest(candidateManifest);
  if (!environment?.start || !environment?.cleanup || !evidenceSink?.write) {
    throw new Error("Release E2E environment and evidence sink are required");
  }
  const baseline = candidateManifest.releaseBaseline;

  const poll = normalizedPollTiming(timing);
  const evidence = {
    auditLog: null,
    boundaryEvidenceValidation: null,
    candidate: candidateManifest.candidate,
    cleanup: null,
    failureBoundary: null,
    hostEvidence: null,
    hubEvidence: null,
    identityContinuity: null,
    infrastructure: null,
    metrics: { afterRepair: null, beforeUpgrade: null },
    operationTimeline: [],
    phase: "scenario-running",
    probeConfiguration: { afterRepair: null, beforeUpgrade: null },
    releaseBaseline: {
      hubDigest: baseline.hub.imageDigest,
      probeVersion: baseline.probeAssetSet.version,
      tag: baseline.tag,
    },
    releaseTestHost: null,
    repair: null,
    repairHostBoundary: null,
    repairedHost: null,
    result: { status: "running" },
    runId,
    scenario,
    schemaVersion: 2,
    uninstallOperationTimeline: [],
    uninstallCompletion: null,
    uninstall: {
      hostCompletion: null,
      hubSoftDeleted: false,
      operationTimeline: [],
      status: "pending",
    },
  };
  let resources = null;
  let primaryError = null;
  let evidenceWriteError = null;
  let finalEvidence = evidence;

  try {
    resources = await environment.start({
      candidateManifest,
      hubMode: "baseline",
      runId,
      scenario,
    });
    const { host, hub } = resources ?? {};
    assertRepairScenarioParticipants(host, hub);
    evidence.infrastructure = resources?.infrastructure ?? null;
    evidence.releaseTestHost = resources?.releaseTestHost ?? null;

    await host.assertDisposable(runId);
    await hub.authenticate(ownerPassword);
    const initialHosts = await hub.listHosts();
    if (!Array.isArray(initialHosts) || initialHosts.length !== 0) {
      throw assertionError(
        "repair_baseline_hub_not_empty",
        "Probe Repair scenario requires new Release Baseline Hub state",
      );
    }
    const enrollment = await hub.createEnrollment();
    if (!enrollment?.installCommand) {
      throw assertionError(
        "enrollment_command_missing",
        "Release Baseline Hub did not return its official Probe install command",
      );
    }
    await host.install(enrollment.installCommand, runId);
    await host.assertInstalled(runId, baseline.probeAssetSet.version);
    const baselineIdentity = await host.readProbeIdentity(runId);
    const hostSummary = await waitForObservation({
      code: "repair_probe_enrollment_timeout",
      label: "Release Baseline Probe enrollment for Repair",
      observe: async () => {
        const hosts = await hub.listHosts();
        return Array.isArray(hosts) && hosts.length === 1 ? hosts[0] : null;
      },
      poll,
      ready: (value) => Number.isSafeInteger(value?.id) && value.id > 0,
    });
    const hostId = hostSummary.id;
    await waitForObservation({
      code: "repair_baseline_reporting_timeout",
      label: "Release Baseline Probe reporting before Repair scenario Upgrade",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, baseline.probeAssetSet.version),
    });
    evidence.metrics.beforeUpgrade = compactMetricsEvidence(
      await waitForObservation({
        code: "repair_baseline_metrics_timeout",
        label: "Release Baseline portable Metrics before Repair",
        observe: () => hub.getHostMetrics(hostId),
        poll,
        ready: hasAdvancingPortableMetrics,
      }),
    );
    const metricCheckpoint = latestPortableMetric(
      await hub.getHostMetrics(hostId),
    );
    if (!metricCheckpoint) {
      throw assertionError(
        "repair_metrics_checkpoint_missing",
        "Repair scenario has no pre-Upgrade portable Metrics checkpoint",
      );
    }
    evidence.probeConfiguration.beforeUpgrade =
      await proveProbeConfigurationRoundTrip({ hostId, hub, poll });

    await hub.switchToCandidate();
    await hub.authenticate(ownerPassword);
    await waitForObservation({
      code: "repair_baseline_probe_candidate_hub_compatibility_timeout",
      label: "Release Baseline Probe reporting to Candidate Hub before Repair",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, baseline.probeAssetSet.version),
    });

    const candidateProbeVersion = candidateManifest.probeAssetSet.version;
    await host.beginUpgradeOwnershipTransition(runId, candidateProbeVersion);
    await host.armPostReplacementRestartFault(runId, candidateProbeVersion);
    const requestedUpgrade = await hub.requestProbeUpgrade(hostId);
    if (requestedUpgrade.targetProbeVersion !== candidateProbeVersion) {
      throw assertionError(
        "probe_upgrade_target_mismatch",
        "Probe Repair scenario Upgrade did not target the Candidate Probe",
      );
    }
    await host.bindUpgradeOwnershipTransition(runId, requestedUpgrade);
    evidence.operationTimeline = [requestedUpgrade];
    evidence.operationTimeline = await hub.waitForProbeOperation(
      requestedUpgrade,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    const failedUpgrade = evidence.operationTimeline.at(-1);
    if (failedUpgrade?.state !== "failed" || !failedUpgrade.failure) {
      throw assertionError(
        "post_replacement_upgrade_not_failed",
        `Probe Upgrade did not retain a failed operation: ${JSON.stringify(failedUpgrade)}`,
      );
    }
    evidence.failureBoundary = await host.assertPostReplacementUpgradeFailure(
      runId,
      failedUpgrade,
      candidateProbeVersion,
    );

    await host.removePostReplacementRestartFault(runId);
    evidence.repair = await host.repair(runId);
    if (evidence.repair?.repairedVersion !== candidateProbeVersion) {
      throw assertionError(
        "probe_repair_target_mismatch",
        "Probe Repair did not restore the already-installed Candidate Probe version",
      );
    }
    evidence.repairHostBoundary = await host.assertInstalled(
      runId,
      candidateProbeVersion,
    );
    const repairedIdentity = await host.readProbeIdentity(runId);
    if (
      repairedIdentity.probeId !== baselineIdentity.probeId ||
      repairedIdentity.identitySha256 !== baselineIdentity.identitySha256
    ) {
      throw assertionError(
        "probe_identity_changed",
        "Probe Repair changed the Probe Identity",
      );
    }
    evidence.identityContinuity = {
      after: repairedIdentity,
      before: baselineIdentity,
      hostId,
    };
    await host.completeRepairOwnershipTransition(runId, failedUpgrade);

    const preservedFailure = await hub.getProbeOperation(failedUpgrade);
    assertStableTerminalOperation(failedUpgrade, preservedFailure);
    if (preservedFailure.state !== "failed") {
      throw assertionError(
        "repair_rewrote_failed_upgrade",
        "Probe Repair rewrote the failed Probe Upgrade operation",
      );
    }
    const repairedHost = await waitForObservation({
      code: "candidate_probe_repair_reporting_timeout",
      label: "Candidate Probe core reporting after Repair",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateProbeVersion),
    });
    evidence.repairedHost = compactHostEvidence(repairedHost);
    evidence.metrics.afterRepair = compactMetricsEvidence(
      await waitForObservation({
        code: "candidate_probe_repair_metrics_timeout",
        label: "Candidate Probe portable Metrics progression after Repair",
        observe: () => hub.getHostMetrics(hostId),
        poll,
        ready: (samples) =>
          hasAdvancingPortableMetrics(samples) &&
          metricsAdvanceBeyond(samples, metricCheckpoint),
      }),
    );
    evidence.probeConfiguration.afterRepair =
      await proveProbeConfigurationRoundTrip({ hostId, hub, poll });

    const requestedUninstall = await hub.requestProbeUninstall(hostId);
    evidence.uninstallOperationTimeline = [requestedUninstall];
    evidence.uninstallOperationTimeline = await hub.waitForProbeOperation(
      requestedUninstall,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    evidence.uninstall.operationTimeline = evidence.uninstallOperationTimeline;
    const finalUninstall = evidence.uninstallOperationTimeline.at(-1);
    if (finalUninstall?.state !== "succeeded" || finalUninstall.failure) {
      throw assertionError(
        "probe_uninstall_failed",
        `Probe Uninstall after Repair failed: ${JSON.stringify(finalUninstall)}`,
      );
    }
    evidence.uninstall.hubSoftDeleted = await hub.isHostSoftDeleted(hostId);
    if (!evidence.uninstall.hubSoftDeleted) {
      throw assertionError(
        "host_not_soft_deleted",
        "Probe Uninstall after Repair did not soft-delete the Host",
      );
    }
    evidence.auditLog = assertBaselineUpgradeAuditLog(
      await hub.getAuditLog(),
      hostId,
      requestedUpgrade.id,
      requestedUninstall.id,
      candidateProbeVersion,
    );
    evidence.uninstallCompletion = await host.verifyUninstallCompletion(runId);
    evidence.uninstall.hostCompletion = evidence.uninstallCompletion;
    if (
      evidence.uninstallCompletion?.clean !== true ||
      evidence.uninstallCompletion?.journaldRetained !== true ||
      evidence.uninstallCompletion?.sharedDependenciesRetained !== true
    ) {
      throw assertionError(
        "probe_uninstall_residue",
        `Host did not satisfy Probe Uninstall Completion after Repair: ${JSON.stringify(evidence.uninstallCompletion)}`,
      );
    }
    evidence.uninstall.status = "succeeded";
    evidence.result = { status: "succeeded" };
    evidence.phase = "succeeded";
  } catch (error) {
    primaryError = error;
    if (Array.isArray(error?.timeline)) {
      evidence.operationTimeline = error.timeline;
    }
    evidence.result = { error: serializedError(error), status: "failed" };
    evidence.phase = "failed";
  } finally {
    if (resources?.hub?.collectEvidence) {
      try {
        evidence.hubEvidence = await resources.hub.collectEvidence();
      } catch (error) {
        evidence.hubEvidence = { error: serializedError(error) };
      }
    }
    if (resources?.host?.collectEvidence) {
      try {
        evidence.hostEvidence = await resources.host.collectEvidence(runId);
      } catch (error) {
        evidence.hostEvidence = { error: serializedError(error) };
      }
    }
    const cleanup = {};
    if (resources?.host?.cleanup) {
      try {
        cleanup.host = await resources.host.cleanup(runId);
      } catch (error) {
        cleanup.host = { error: serializedError(error) };
      }
    }
    try {
      cleanup.environment = await environment.cleanup({ resources, runId });
    } catch (error) {
      cleanup.environment = { error: serializedError(error) };
    }
    evidence.cleanup = cleanup;
    evidence.boundaryEvidence = createRepairBoundaryEvidence(evidence);
    if (!primaryError && evidence.phase === "succeeded") {
      try {
        validateSuccessfulRepairBoundaryEvidence(evidence, candidateManifest);
        evidence.boundaryEvidenceValidation = { status: "succeeded" };
      } catch (error) {
        primaryError = error;
        evidence.boundaryEvidenceValidation = {
          boundary: error.boundary ?? null,
          error: serializedError(error),
          status: "failed",
        };
        evidence.result = {
          error: serializedError(error),
          status: "failed",
        };
        evidence.phase = "failed";
      }
    } else if (!primaryError && cleanupDidNotSucceed(cleanup)) {
      primaryError = assertionError(
        "release_e2e_cleanup_failed",
        "Release E2E cleanup did not remove all run-owned state",
      );
    }
    finalEvidence = redactSensitiveEvidence(evidence, [ownerPassword]);
    try {
      await evidenceSink.write(finalEvidence);
    } catch (error) {
      evidenceWriteError = error;
      if (!primaryError) {
        primaryError = assertionError(
          "release_e2e_evidence_write_failed",
          `Release E2E evidence could not be written: ${error.message}`,
        );
      }
    }
  }

  if (primaryError) {
    const failure = new Error(
      `Release E2E ${scenario} failed: ${redactSensitiveText(primaryError.message, [ownerPassword])}`,
    );
    failure.code = primaryError.code ?? "release_e2e_failed";
    failure.evidence = finalEvidence;
    if (evidenceWriteError) {
      failure.evidenceWriteError = serializedError(evidenceWriteError);
    }
    throw failure;
  }
  return evidence.result;
}

function createRepairBoundaryEvidence(evidence) {
  return {
    cleanup: {
      orchestrator: evidence.cleanup ?? null,
      uninstallCompletion: evidence.uninstallCompletion ?? null,
    },
    filesystem: {
      afterRepair: evidence.repairHostBoundary?.inventory ?? null,
      postUninstall: evidence.hostEvidence?.inventory ?? null,
    },
    hubApi: {
      apiTimeline: evidence.hubEvidence?.apiTimeline ?? null,
      auditLog: evidence.auditLog ?? null,
      repairedHost: evidence.repairedHost ?? null,
      runtime: evidence.hubEvidence?.runtime ?? null,
    },
    identity: evidence.identityContinuity ?? null,
    privilege: {
      afterRepair: evidence.repairHostBoundary?.sudoers ?? null,
      postUninstall: evidence.hostEvidence?.sudoers ?? null,
    },
    probeOperation: {
      uninstall: evidence.uninstallOperationTimeline ?? [],
      upgrade: evidence.operationTimeline ?? [],
    },
    systemd: {
      afterRepair: evidence.repairHostBoundary?.service ?? null,
      journald: evidence.hostEvidence?.journald ?? null,
      postUninstall: evidence.hostEvidence?.systemd ?? null,
    },
  };
}

export function validateSuccessfulRepairBoundaryEvidence(
  evidence,
  candidateManifest,
) {
  assertCandidateManifest(candidateManifest);
  if (evidence?.hostEvidence?.error) {
    throw repairBoundaryEvidenceError(
      "filesystem",
      new Error("Host evidence collection failed"),
    );
  }
  const validators = [
    ["hub-api", validateRepairHubApiEvidence],
    ["probe-operation", validateRepairOperationEvidence],
    ["systemd", validateRepairSystemdEvidence],
    ["privilege", validateRepairPrivilegeEvidence],
    ["filesystem", validateRepairFilesystemEvidence],
    ["identity", validateRepairIdentityEvidence],
    ["cleanup", validateRepairCleanupEvidence],
  ];
  for (const [boundary, validate] of validators) {
    try {
      validate(evidence, candidateManifest);
    } catch (cause) {
      throw repairBoundaryEvidenceError(boundary, cause);
    }
  }
  return evidence;
}

function repairBoundaryEvidenceError(boundary, cause) {
  const error = assertionError(
    "repair_boundary_evidence_invalid",
    `Probe Repair ${boundary} evidence is invalid: ${cause.message}`,
  );
  error.boundary = boundary;
  error.cause = cause;
  return error;
}

function validateRepairHubApiEvidence(evidence, candidateManifest) {
  if (evidence?.hubEvidence?.error) {
    throw new Error("Hub evidence collection failed");
  }
  const hostId = evidence?.identityContinuity?.hostId;
  const upgrade = evidence?.operationTimeline?.[0];
  const uninstall = evidence?.uninstallOperationTimeline?.[0];
  assertPositiveInteger(hostId, "Repair Host ID");
  assertBaselineUpgradeAuditLog(
    evidence.auditLog,
    hostId,
    upgrade?.id,
    uninstall?.id,
    candidateManifest.probeAssetSet.version,
  );

  const apiTimeline = evidence.hubEvidence?.apiTimeline;
  if (
    !Array.isArray(apiTimeline) ||
    apiTimeline.length === 0 ||
    apiTimeline.some((entry) => {
      const expectedDeletedHostObservation =
        entry?.method === "GET" &&
        entry.pathname === `/api/web/hosts/${hostId}` &&
        entry.status === 404 &&
        typeof entry.error === "string" &&
        entry.error.length > 0;
      return (
        !entry ||
        !/^(?:DELETE|GET|POST|PUT)$/.test(entry.method ?? "") ||
        typeof entry.pathname !== "string" ||
        !entry.pathname.startsWith("/api/") ||
        !Number.isInteger(entry.status) ||
        (!expectedDeletedHostObservation &&
          (entry.status < 200 || entry.status >= 300 || entry.error !== null))
      );
    })
  ) {
    throw new Error("Hub API timeline is missing or contains a failed request");
  }
  for (const expected of [
    ["POST", "/api/web/auth/login"],
    ["POST", `/api/web/hosts/${hostId}/probe-upgrade-requests`],
    ["DELETE", `/api/web/hosts/${hostId}`],
    ["GET", `/api/web/hosts/${hostId}`, 404],
    ["GET", "/api/web/audit-log?limit=200"],
  ]) {
    if (
      !apiTimeline.some(
        (entry) =>
          entry.method === expected[0] &&
          entry.pathname === expected[1] &&
          (expected[2] === undefined || entry.status === expected[2]),
      )
    ) {
      throw new Error(`Hub API timeline is missing ${expected.join(" ")}`);
    }
  }

  const runtime = evidence.hubEvidence?.runtime;
  const baselineDigest = candidateManifest.releaseBaseline.hub.imageDigest;
  const candidateDigest = candidateManifest.hub.digest;
  if (
    runtime?.identityVerified !== true ||
    runtime.activeHub !== "candidate" ||
    runtime.activeManifestDigest !== candidateDigest ||
    runtime.candidateManifestDigest !== candidateDigest ||
    runtime.baselineManifestDigest !== baselineDigest ||
    !/^sha256:[0-9a-f]{64}$/.test(runtime.containerConfigDigest ?? "") ||
    typeof runtime.containerInspect !== "string" ||
    runtime.containerInspect.trim().length === 0 ||
    typeof runtime.imageInspect !== "string" ||
    runtime.imageInspect.trim().length === 0
  ) {
    throw new Error(
      "running Hub identity does not match the Candidate Manifest",
    );
  }
  const runtimeHistory = runtime.runtimeHistory;
  if (!Array.isArray(runtimeHistory) || runtimeHistory.length < 2) {
    throw new Error("Hub runtime history does not prove Baseline to Candidate");
  }
  const baseline = runtimeHistory.find(
    (entry) =>
      entry?.hub === "baseline" && entry.manifestDigest === baselineDigest,
  );
  const candidate = runtimeHistory.find(
    (entry) =>
      entry?.hub === "candidate" && entry.manifestDigest === candidateDigest,
  );
  if (
    !baseline ||
    !candidate ||
    typeof baseline.volume !== "string" ||
    baseline.volume.length === 0 ||
    candidate.volume !== baseline.volume ||
    !/^sha256:[0-9a-f]{64}$/.test(baseline.configDigest ?? "") ||
    !/^sha256:[0-9a-f]{64}$/.test(candidate.configDigest ?? "")
  ) {
    throw new Error("Hub runtime history identities are incomplete");
  }
  if (
    evidence.repairedHost?.id !== hostId ||
    !isCandidateHostReady(
      evidence.repairedHost,
      candidateManifest.probeAssetSet.version,
    ) ||
    !hasAdvancingPortableMetrics(evidence.metrics?.afterRepair) ||
    evidence.probeConfiguration?.afterRepair?.mode !== "override" ||
    typeof evidence.probeConfiguration.afterRepair.version !== "string" ||
    evidence.probeConfiguration.afterRepair.reportedVersion !==
      evidence.probeConfiguration.afterRepair.version
  ) {
    throw new Error("Candidate Probe core reporting evidence is incomplete");
  }
}

function validateRepairOperationEvidence(evidence, candidateManifest) {
  const hostId = evidence?.identityContinuity?.hostId;
  const targetProbeVersion = candidateManifest.probeAssetSet.version;
  validateTerminalRepairOperationTimeline(evidence?.operationTimeline, {
    hostId,
    kind: "probe_upgrade",
    state: "failed",
    targetProbeVersion,
  });
  validateTerminalRepairOperationTimeline(
    evidence?.uninstallOperationTimeline,
    {
      hostId,
      kind: "probe_uninstall",
      state: "succeeded",
    },
  );
  const failedUpgrade = evidence.operationTimeline.at(-1);
  if (
    evidence.failureBoundary?.operationId !== failedUpgrade.id ||
    evidence.failureBoundary?.probeVersion !== targetProbeVersion ||
    evidence.failureBoundary?.hubFailureCode !== failedUpgrade.failure?.code ||
    evidence.failureBoundary?.localFailureCode !==
      "post_replacement_restart_failure"
  ) {
    throw new Error(
      "post-replacement failure evidence is not bound to the failed Upgrade",
    );
  }
}

function validateTerminalRepairOperationTimeline(timeline, expected) {
  if (!Array.isArray(timeline) || timeline.length < 3) {
    throw new Error(`${expected.kind} timeline is incomplete`);
  }
  const requested = timeline[0];
  if (
    requested?.state !== "pending" ||
    requested.acceptedAtMs !== null ||
    requested.runningAtMs !== null ||
    requested.completedAtMs !== null ||
    !Number.isSafeInteger(requested.id) ||
    requested.id <= 0
  ) {
    throw new Error(
      `${expected.kind} request identity or timestamps are invalid`,
    );
  }
  let previous = null;
  let terminal = null;
  for (const operation of timeline) {
    assertProbeOperation(operation, {
      hostId: expected.hostId,
      id: requested.id,
      kind: expected.kind,
      ...(expected.targetProbeVersion
        ? { targetProbeVersion: expected.targetProbeVersion }
        : {}),
    });
    if (previous) assertProbeOperationProgress(previous, operation);
    if (terminal) assertStableTerminalOperation(terminal, operation);
    if (!terminal && terminalProbeOperationStates.has(operation.state)) {
      terminal = operation;
    }
    previous = operation;
  }
  const final = timeline.at(-1);
  const preceding = timeline.at(-2);
  if (
    final?.state !== expected.state ||
    final.acceptedAtMs === null ||
    final.runningAtMs === null ||
    final.completedAtMs === null ||
    preceding?.state !== expected.state
  ) {
    throw new Error(
      `${expected.kind} does not retain confirmed ${expected.state} terminal timestamps`,
    );
  }
  assertStableTerminalOperation(preceding, final);
  if (
    (expected.state === "failed" &&
      (typeof final.failure?.code !== "string" ||
        final.failure.code.length === 0 ||
        typeof final.failure.message !== "string" ||
        final.failure.message.length === 0)) ||
    (expected.state === "succeeded" && final.failure !== null)
  ) {
    throw new Error(`${expected.kind} terminal failure contract is invalid`);
  }
}

function validateRepairSystemdEvidence(evidence) {
  assertSuccessfulCommandEvidence(evidence?.hostEvidence?.systemd, "systemd");
  const service = parseKeyValues(evidence.hostEvidence.systemd.stdout);
  if (
    service.stage !== "post-uninstall" ||
    service.LoadState !== "not-found" ||
    service.ActiveState !== "inactive" ||
    service.unitCount !== "0" ||
    service.failedUnitCount !== "0"
  ) {
    throw new Error("systemd state does not prove post-Uninstall absence");
  }
  assertSuccessfulCommandEvidence(evidence.hostEvidence.journald, "journald");
  const journal = evidence.hostEvidence.journald.stdout.trim();
  if (!journal || journal.includes("-- No entries --")) {
    throw new Error("journald history was not retained");
  }
  const repairedService = evidence?.repairHostBoundary?.service;
  if (
    repairedService?.LoadState !== "loaded" ||
    repairedService.ActiveState !== "active" ||
    repairedService.SubState !== "running" ||
    repairedService.User !== "enoki-probe" ||
    repairedService.Group !== "enoki-probe" ||
    repairedService.FragmentPath !== "/etc/systemd/system/enoki-probe.service"
  ) {
    throw new Error("Repair did not capture a running systemd service");
  }
}

function validateRepairPrivilegeEvidence(evidence) {
  assertSuccessfulCommandEvidence(evidence?.hostEvidence?.sudoers, "sudoers");
  const sudoers = parseKeyValues(evidence.hostEvidence.sudoers.stdout);
  if (
    sudoers.stage !== "post-uninstall" ||
    sudoers.managedSudoersCount !== "0"
  ) {
    throw new Error("post-Uninstall sudoers observation is invalid");
  }
  const repairedSudoers = evidence?.repairHostBoundary?.sudoers;
  if (
    typeof repairedSudoers !== "string" ||
    !repairedSudoers.includes("enoki-probe-uninstaller") ||
    !repairedSudoers.includes("internal-uninstaller")
  ) {
    throw new Error("Repair did not capture the authorized privilege boundary");
  }
}

function validateRepairFilesystemEvidence(evidence, candidateManifest) {
  if (evidence?.hostEvidence?.error) {
    throw new Error("Host evidence collection failed");
  }
  if (evidence?.hostEvidence?.runClaimed !== true) {
    throw new Error("Host evidence was not collected from the run-owned state");
  }
  assertHostInventoryEvidence(evidence?.hostEvidence?.inventory);
  if (inventoryResidue(evidence.hostEvidence.inventory).length > 0) {
    throw new Error("post-Uninstall filesystem inventory contains residue");
  }
  const installed = evidence?.repairHostBoundary;
  assertHostInventoryEvidence(installed?.inventory);
  const installedResidue = inventoryResidue(installed.inventory);
  const required = [
    "user:enoki-probe",
    "group:enoki-probe",
    "/usr/local/bin/enoki-probe",
    "/etc/enoki/probe-bootstrap.toml",
    "/etc/enoki/probe-install.toml",
    "/etc/systemd/system/enoki-probe.service",
    "/var/lib/enoki-probe",
    "/etc/sudoers.d/enoki-probe-operations",
    "enoki-probe.service",
  ];
  if (
    installed?.probeVersion !== candidateManifest.probeAssetSet.version ||
    required.some((entry) => !installedResidue.includes(entry))
  ) {
    throw new Error("post-Repair filesystem inventory is incomplete");
  }
}

function validateRepairIdentityEvidence(evidence, candidateManifest) {
  const continuity = evidence?.identityContinuity;
  assertPositiveInteger(continuity?.hostId, "Repair Host ID");
  for (const identity of [continuity?.before, continuity?.after]) {
    if (
      !identity ||
      Object.keys(identity).sort().join(",") !== "identitySha256,probeId" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(identity.probeId ?? "") ||
      !/^[0-9a-f]{64}$/.test(identity.identitySha256 ?? "")
    ) {
      throw new Error("Probe Identity evidence is incomplete");
    }
  }
  if (
    continuity.before.probeId !== continuity.after.probeId ||
    continuity.before.identitySha256 !== continuity.after.identitySha256 ||
    evidence?.repair?.probeId !== continuity.before.probeId ||
    evidence?.repair?.repairedVersion !==
      candidateManifest.probeAssetSet.version ||
    evidence?.repairedHost?.id !== continuity.hostId
  ) {
    throw new Error("Probe Identity is inconsistent across Repair boundaries");
  }
}

function validateRepairCleanupEvidence(evidence) {
  const completion = evidence?.uninstallCompletion;
  assertHostInventoryEvidence(completion?.inventory);
  if (
    completion.clean !== true ||
    completion.journaldRetained !== true ||
    completion.sharedDependenciesRetained !== true ||
    typeof completion.journald !== "string" ||
    completion.journald.trim().length === 0 ||
    typeof completion.sharedDependencies !== "string" ||
    completion.sharedDependencies.trim().length === 0 ||
    inventoryResidue(completion.inventory).length > 0
  ) {
    throw new Error("Probe Uninstall Completion evidence is invalid");
  }
  if (cleanupDidNotSucceed(evidence?.cleanup ?? {})) {
    throw new Error("scenario cleanup did not complete cleanly");
  }
  if (!evidence.cleanup?.host || !evidence.cleanup?.environment) {
    throw new Error("scenario cleanup observations are incomplete");
  }
  assertCleanEvidenceTree(evidence.cleanup.host, "Host cleanup");
  assertCleanEvidenceTree(evidence.cleanup.environment, "environment cleanup");
}

function assertSuccessfulCommandEvidence(value, label) {
  if (
    !value ||
    value.error ||
    value.code !== 0 ||
    typeof value.stdout !== "string" ||
    typeof value.stderr !== "string"
  ) {
    throw new Error(`${label} evidence command did not complete successfully`);
  }
}

function assertHostInventoryEvidence(inventory) {
  if (
    !inventory ||
    inventory.error ||
    typeof inventory.accounts?.group !== "boolean" ||
    typeof inventory.accounts?.user !== "boolean" ||
    !Array.isArray(inventory.files) ||
    inventory.files.some((entry) => typeof entry !== "string" || !entry) ||
    !Array.isArray(inventory.units) ||
    inventory.units.some((entry) => typeof entry !== "string" || !entry) ||
    Object.keys(inventory).sort().join(",") !== "accounts,files,units" ||
    Object.keys(inventory.accounts).sort().join(",") !== "group,user"
  ) {
    throw new Error("filesystem inventory collection is invalid");
  }
}

function assertCleanEvidenceTree(value, label) {
  if (
    !value ||
    typeof value !== "object" ||
    value.error ||
    value.clean !== true
  ) {
    throw new Error(`${label} did not report clean completion`);
  }
  for (const [key, nested] of Object.entries(value)) {
    if (key === "clean" || key === "skipped" || typeof nested !== "object") {
      continue;
    }
    assertCleanEvidenceTree(nested, `${label}.${key}`);
  }
}

async function runBaselineUpgradeUninstallScenario({
  candidateManifest,
  environment,
  evidenceSink,
  ownerPassword,
  runId,
  scenario,
  timing = {},
}) {
  assertRunId(runId);
  assertCandidateManifest(candidateManifest);
  if (!environment?.start || !environment?.cleanup || !evidenceSink?.write) {
    throw new Error("Release E2E environment and evidence sink are required");
  }

  const baseline = candidateManifest.releaseBaseline;

  const poll = normalizedPollTiming(timing);
  const evidence = {
    auditLog: null,
    candidate: candidateManifest.candidate,
    candidateHost: null,
    cleanup: null,
    compatibility: null,
    hostBoundary: null,
    hostEvidence: null,
    hubEvidence: null,
    identityContinuity: null,
    infrastructure: null,
    metrics: { afterUpgrade: null, beforeUpgrade: null },
    operationTimeline: [],
    phase: "scenario-running",
    probeConfiguration: { afterUpgrade: null, beforeUpgrade: null },
    releaseBaseline: {
      hubDigest: baseline.hub.imageDigest,
      probeVersion: baseline.probeAssetSet.version,
      tag: baseline.tag,
    },
    releaseTestHost: null,
    result: { status: "running" },
    runId,
    scenario,
    schemaVersion: 2,
    uninstall: {
      hostCompletion: null,
      hubSoftDeleted: false,
      operationTimeline: [],
      status: "pending",
    },
    upgradeOperationTimeline: [],
  };
  let resources = null;
  let primaryError = null;
  let evidenceWriteError = null;
  let finalEvidence = evidence;

  try {
    resources = await environment.start({
      candidateManifest,
      hubMode: "baseline",
      runId,
    });
    const { host, hub } = resources ?? {};
    assertBaselineScenarioParticipants(host, hub);
    evidence.infrastructure = resources?.infrastructure ?? null;
    evidence.releaseTestHost = resources?.releaseTestHost ?? null;

    await host.assertDisposable(runId);
    await hub.authenticate(ownerPassword);
    const initialHosts = await hub.listHosts();
    if (!Array.isArray(initialHosts) || initialHosts.length !== 0) {
      throw assertionError(
        "baseline_hub_not_empty",
        "Release Baseline scenario requires a new persisted Hub state with no Hosts",
      );
    }
    const enrollment = await hub.createEnrollment();
    if (!enrollment?.installCommand) {
      throw assertionError(
        "enrollment_command_missing",
        "Release Baseline Hub did not return its official Probe install command",
      );
    }
    await host.install(enrollment.installCommand, runId);
    await host.assertInstalled(runId, baseline.probeAssetSet.version);
    const baselineIdentity = await host.readProbeIdentity(runId);

    const hostSummary = await waitForObservation({
      code: "probe_enrollment_timeout",
      label: "Release Baseline Host enrollment",
      observe: async () => {
        const hosts = await hub.listHosts();
        return Array.isArray(hosts) && hosts.length === 1 ? hosts[0] : null;
      },
      poll,
      ready: (value) => Number.isSafeInteger(value?.id) && value.id > 0,
    });
    const hostId = hostSummary.id;
    await waitForObservation({
      code: "baseline_host_core_reporting_timeout",
      label: "Release Baseline Probe reporting to the Release Baseline Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        isCandidateHostReady(value, baseline.probeAssetSet.version),
    });

    await hub.switchToCandidate();
    await hub.authenticate(ownerPassword);
    const persistedHosts = await hub.listHosts();
    if (
      !Array.isArray(persistedHosts) ||
      persistedHosts.length !== 1 ||
      persistedHosts[0]?.id !== hostId
    ) {
      throw assertionError(
        "baseline_hub_state_not_persisted",
        "Candidate Hub did not retain the Release Baseline Host state",
      );
    }
    const compatibleHost = await waitForObservation({
      code: "baseline_probe_candidate_hub_compatibility_timeout",
      label: "Release Baseline Probe reporting to the Candidate Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, baseline.probeAssetSet.version),
    });
    if (compatibleHost.probeUpgradeStatus !== null) {
      throw assertionError(
        "unattended_probe_upgrade_detected",
        "A Probe Upgrade operation existed before Owner authorization",
      );
    }
    const beforeMetrics = await waitForObservation({
      code: "baseline_probe_metrics_progression_timeout",
      label: "Release Baseline Probe portable Metrics on the Candidate Hub",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: hasAdvancingPortableMetrics,
    });
    evidence.metrics.beforeUpgrade = compactMetricsEvidence(beforeMetrics);
    evidence.probeConfiguration.beforeUpgrade =
      await proveProbeConfigurationRoundTrip({ hostId, hub, poll });
    evidence.compatibility = {
      host: compactHostEvidence(compatibleHost),
      status: "succeeded",
    };

    await host.beginUpgradeOwnershipTransition(
      runId,
      candidateManifest.probeAssetSet.version,
    );
    const requestedUpgrade = await hub.requestProbeUpgrade(hostId);
    if (
      requestedUpgrade.targetProbeVersion !==
      candidateManifest.probeAssetSet.version
    ) {
      throw assertionError(
        "probe_upgrade_target_mismatch",
        `Probe Upgrade targets ${requestedUpgrade.targetProbeVersion ?? "unknown"} instead of Candidate ${candidateManifest.probeAssetSet.version}`,
      );
    }
    evidence.upgradeOperationTimeline = [requestedUpgrade];
    await host.bindUpgradeOwnershipTransition(runId, requestedUpgrade);
    evidence.upgradeOperationTimeline = await hub.waitForProbeOperation(
      requestedUpgrade,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    validateSuccessfulProbeUpgradeTimeline(evidence.upgradeOperationTimeline);

    const candidateHost = await waitForObservation({
      code: "candidate_probe_reporting_timeout",
      label: "Candidate Probe Host Profile after Upgrade",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version),
    });
    evidence.candidateHost = compactHostEvidence(candidateHost);
    evidence.hostBoundary = await host.assertInstalled(
      runId,
      candidateManifest.probeAssetSet.version,
    );
    const candidateIdentity = await host.readProbeIdentity(runId);
    if (
      candidateIdentity.probeId !== baselineIdentity.probeId ||
      candidateIdentity.identitySha256 !== baselineIdentity.identitySha256
    ) {
      throw assertionError(
        "probe_identity_changed",
        "Probe Upgrade changed the Probe Identity",
      );
    }
    evidence.identityContinuity = {
      after: candidateIdentity,
      before: baselineIdentity,
      hostId,
    };
    await host.completeUpgradeOwnershipTransition(
      runId,
      evidence.upgradeOperationTimeline.at(-1),
    );

    const candidateMetricCheckpoint = latestPortableMetric(
      await hub.getHostMetrics(hostId),
    );
    if (!candidateMetricCheckpoint) {
      throw assertionError(
        "candidate_probe_metrics_checkpoint_missing",
        "Candidate Probe Host Profile was observed without a portable Metrics checkpoint",
      );
    }
    const afterMetrics = await waitForObservation({
      code: "candidate_probe_metrics_progression_timeout",
      label: "Candidate Probe portable Metrics after Upgrade",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: (samples) =>
        hasAdvancingPortableMetrics(samples) &&
        metricsAdvanceBeyond(samples, candidateMetricCheckpoint),
    });
    evidence.metrics.afterUpgrade = compactMetricsEvidence(afterMetrics);
    evidence.probeConfiguration.afterUpgrade =
      await proveProbeConfigurationRoundTrip({ hostId, hub, poll });

    const requestedUninstall = await hub.requestProbeUninstall(hostId);
    evidence.operationTimeline = [requestedUninstall];
    evidence.operationTimeline = await hub.waitForProbeOperation(
      requestedUninstall,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    evidence.uninstall.operationTimeline = evidence.operationTimeline;
    const finalUninstall = evidence.operationTimeline.at(-1);
    if (finalUninstall?.state !== "succeeded" || finalUninstall.failure) {
      throw assertionError(
        "probe_uninstall_failed",
        `Probe Uninstall did not succeed: ${JSON.stringify(finalUninstall)}`,
      );
    }
    evidence.uninstall.hubSoftDeleted = await hub.isHostSoftDeleted(hostId);
    if (!evidence.uninstall.hubSoftDeleted) {
      throw assertionError(
        "host_not_soft_deleted",
        "Probe Uninstall succeeded but the Host remains active",
      );
    }
    evidence.auditLog = assertBaselineUpgradeAuditLog(
      await hub.getAuditLog(),
      hostId,
      requestedUpgrade.id,
      requestedUninstall.id,
      candidateManifest.probeAssetSet.version,
    );
    const completion = await host.verifyUninstallCompletion(runId);
    evidence.uninstall.hostCompletion = completion;
    if (
      completion?.clean !== true ||
      completion?.journaldRetained !== true ||
      completion?.sharedDependenciesRetained !== true
    ) {
      throw assertionError(
        "probe_uninstall_residue",
        `Host did not satisfy Probe Uninstall Completion: ${JSON.stringify(completion)}`,
      );
    }
    evidence.uninstall.status = "succeeded";
    evidence.result = { status: "succeeded" };
    evidence.phase = "succeeded";
  } catch (error) {
    primaryError = error;
    if (Array.isArray(error?.timeline)) {
      if (error.timeline[0]?.kind === "probe_upgrade") {
        evidence.upgradeOperationTimeline = error.timeline;
      } else {
        evidence.operationTimeline = error.timeline;
      }
    }
    evidence.result = { error: serializedError(error), status: "failed" };
    evidence.phase = "failed";
  } finally {
    if (resources?.hub?.collectEvidence) {
      try {
        evidence.hubEvidence = await resources.hub.collectEvidence();
      } catch (error) {
        evidence.hubEvidence = { error: serializedError(error) };
      }
    }
    if (resources?.host?.collectEvidence) {
      try {
        evidence.hostEvidence = await resources.host.collectEvidence(runId);
      } catch (error) {
        evidence.hostEvidence = { error: serializedError(error) };
      }
    }
    const cleanup = {};
    if (resources?.host?.cleanup) {
      try {
        cleanup.host = await resources.host.cleanup(runId);
      } catch (error) {
        cleanup.host = { error: serializedError(error) };
      }
    }
    try {
      cleanup.environment = await environment.cleanup({ resources, runId });
    } catch (error) {
      cleanup.environment = { error: serializedError(error) };
    }
    evidence.cleanup = cleanup;
    if (!primaryError && cleanupDidNotSucceed(cleanup)) {
      primaryError = assertionError(
        "release_e2e_cleanup_failed",
        "Release E2E cleanup did not remove all run-owned state",
      );
      evidence.result = {
        error: serializedError(primaryError),
        status: "failed",
      };
      evidence.phase = "failed";
    }
    finalEvidence = redactSensitiveEvidence(evidence, [ownerPassword]);
    try {
      await evidenceSink.write(finalEvidence);
    } catch (error) {
      evidenceWriteError = error;
      if (!primaryError) {
        primaryError = assertionError(
          "release_e2e_evidence_write_failed",
          `Release E2E evidence could not be written: ${error.message}`,
        );
      }
    }
  }

  if (primaryError) {
    const failure = new Error(
      `Release E2E ${scenario} failed: ${redactSensitiveText(primaryError.message, [ownerPassword])}`,
    );
    failure.code = primaryError.code ?? "release_e2e_failed";
    failure.evidence = finalEvidence;
    if (evidenceWriteError) {
      failure.evidenceWriteError = serializedError(evidenceWriteError);
    }
    throw failure;
  }
  return evidence.result;
}

async function runFreshInstallUninstallScenario({
  candidateManifest,
  environment,
  evidenceSink,
  ownerPassword,
  runId,
  scenario,
  timing = {},
}) {
  assertRunId(runId);
  assertCandidateManifest(candidateManifest);
  if (!environment?.start || !environment?.cleanup || !evidenceSink?.write) {
    throw new Error("Release E2E environment and evidence sink are required");
  }

  const poll = normalizedPollTiming(timing);
  const evidence = {
    auditLog: null,
    candidate: candidateManifest.candidate,
    candidateIdentities: {
      hubDigest: candidateManifest.hub.digest,
      probeAssetSetVersion: candidateManifest.probeAssetSet.version,
    },
    cleanup: null,
    host: null,
    hostBoundary: null,
    hostEvidence: null,
    hubEvidence: null,
    infrastructure: null,
    metrics: null,
    operationTimeline: [],
    phase: "scenario-running",
    probeConfiguration: null,
    releaseTestHost: null,
    result: { status: "running" },
    runId,
    scenario,
    schemaVersion: 2,
    uninstall: {
      hostCompletion: null,
      hubSoftDeleted: false,
      operationTimeline: [],
      status: "pending",
    },
  };
  let resources = null;
  let primaryError = null;
  let evidenceWriteError = null;
  let finalEvidence = evidence;

  try {
    resources = await environment.start({ candidateManifest, runId });
    const { host, hub } = resources ?? {};
    assertScenarioParticipants(host, hub);
    evidence.infrastructure = resources?.infrastructure ?? null;
    evidence.releaseTestHost = resources?.releaseTestHost ?? null;

    await host.assertDisposable(runId);
    await hub.authenticate(ownerPassword);
    const initialHosts = await hub.listHosts();
    if (!Array.isArray(initialHosts) || initialHosts.length !== 0) {
      throw assertionError(
        "fresh_hub_not_empty",
        "Fresh-install scenario requires a candidate Hub with no Hosts",
      );
    }

    const enrollment = await hub.createEnrollment();
    if (!enrollment?.installCommand) {
      throw assertionError(
        "enrollment_command_missing",
        "Hub did not return an official Probe install command",
      );
    }
    await host.install(enrollment.installCommand, runId);
    evidence.hostBoundary = await host.assertInstalled(
      runId,
      candidateManifest.probeAssetSet.version,
    );

    const hostSummary = await waitForObservation({
      code: "probe_enrollment_timeout",
      label: "newly enrolled Host",
      observe: async () => {
        const hosts = await hub.listHosts();
        return Array.isArray(hosts) && hosts.length === 1 ? hosts[0] : null;
      },
      poll,
      ready: (value) => Number.isSafeInteger(value?.id) && value.id > 0,
    });
    const hostId = hostSummary.id;
    const ready = await waitForObservation({
      code: "host_core_reporting_timeout",
      label: "online Host with a typed Host Profile",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version),
    });
    evidence.host = compactHostEvidence(ready);

    const samples = await waitForObservation({
      code: "metrics_progression_timeout",
      label: "two advancing portable Metrics samples",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: hasAdvancingPortableMetrics,
    });
    evidence.metrics = compactMetricsEvidence(samples);

    evidence.probeConfiguration = await proveProbeConfigurationRoundTrip({
      hostId,
      hub,
      poll,
    });

    const requested = await hub.requestProbeUninstall(hostId);
    evidence.operationTimeline = [requested];
    evidence.operationTimeline = await hub.waitForProbeOperation(requested, {
      intervalMs: poll.intervalMs,
      timeoutMs: poll.timeoutMs,
    });
    evidence.uninstall.operationTimeline = evidence.operationTimeline;
    const finalOperation = evidence.operationTimeline.at(-1);
    if (finalOperation?.state !== "succeeded" || finalOperation.failure) {
      throw assertionError(
        "probe_uninstall_failed",
        `Probe Uninstall did not succeed: ${JSON.stringify(finalOperation)}`,
      );
    }
    evidence.uninstall.hubSoftDeleted = await hub.isHostSoftDeleted(hostId);
    if (!evidence.uninstall.hubSoftDeleted) {
      throw assertionError(
        "host_not_soft_deleted",
        "Probe Uninstall succeeded but the Host remains active",
      );
    }
    evidence.auditLog = assertLifecycleAuditLog(
      await hub.getAuditLog(),
      hostId,
      requested.id,
    );
    const completion = await host.verifyUninstallCompletion(runId);
    evidence.uninstall.hostCompletion = completion;
    if (
      completion?.clean !== true ||
      completion?.journaldRetained !== true ||
      completion?.sharedDependenciesRetained !== true
    ) {
      throw assertionError(
        "probe_uninstall_residue",
        `Host did not satisfy Probe Uninstall Completion: ${JSON.stringify(completion)}`,
      );
    }
    evidence.uninstall.status = "succeeded";
    evidence.result = { status: "succeeded" };
    evidence.phase = "succeeded";
  } catch (error) {
    primaryError = error;
    if (Array.isArray(error?.timeline)) {
      evidence.operationTimeline = error.timeline;
    }
    evidence.result = { error: serializedError(error), status: "failed" };
    evidence.phase = "failed";
  } finally {
    if (resources?.hub?.collectEvidence) {
      try {
        evidence.hubEvidence = await resources.hub.collectEvidence();
      } catch (error) {
        evidence.hubEvidence = { error: serializedError(error) };
      }
    }
    if (resources?.host?.collectEvidence) {
      try {
        evidence.hostEvidence = await resources.host.collectEvidence(runId);
      } catch (error) {
        evidence.hostEvidence = { error: serializedError(error) };
      }
    }

    const cleanup = {};
    if (resources?.host?.cleanup) {
      try {
        cleanup.host = await resources.host.cleanup(runId);
      } catch (error) {
        cleanup.host = { error: serializedError(error) };
      }
    }
    try {
      cleanup.environment = await environment.cleanup({ resources, runId });
    } catch (error) {
      cleanup.environment = { error: serializedError(error) };
    }
    evidence.cleanup = cleanup;
    if (!primaryError && cleanupDidNotSucceed(cleanup)) {
      primaryError = assertionError(
        "release_e2e_cleanup_failed",
        "Release E2E cleanup did not remove all run-owned state",
      );
      evidence.result = {
        error: serializedError(primaryError),
        status: "failed",
      };
      evidence.phase = "failed";
    }
    finalEvidence = redactSensitiveEvidence(evidence, [ownerPassword]);
    try {
      await evidenceSink.write(finalEvidence);
    } catch (error) {
      evidenceWriteError = error;
      if (!primaryError) {
        primaryError = assertionError(
          "release_e2e_evidence_write_failed",
          `Release E2E evidence could not be written: ${error.message}`,
        );
      }
    }
  }

  if (primaryError) {
    const failure = new Error(
      `Release E2E ${scenario} failed: ${redactSensitiveText(primaryError.message, [ownerPassword])}`,
    );
    failure.code = primaryError.code ?? "release_e2e_failed";
    failure.evidence = finalEvidence;
    if (evidenceWriteError) {
      failure.evidenceWriteError = serializedError(evidenceWriteError);
    }
    throw failure;
  }
  return evidence.result;
}

export function createHubLifecycleClient({
  baseUrl,
  fetch: fetch_ = globalThis.fetch,
  sleep = defaultSleep,
}) {
  const normalizedBaseUrl = new URL(baseUrl);
  const apiTimeline = [];
  let ownerCookie = "";

  async function request(pathname, init = {}, allowedStatuses = []) {
    const headers = new Headers(init.headers);
    headers.set("accept", "application/json");
    if (ownerCookie) headers.set("cookie", ownerCookie);
    if (init.body !== undefined)
      headers.set("content-type", "application/json");
    const response = await fetch_(new URL(pathname, normalizedBaseUrl), {
      ...init,
      headers,
    });
    const text = await response.text();
    const body = text ? parseJson(text, `Hub response for ${pathname}`) : null;
    apiTimeline.push({
      error: body?.error ?? null,
      method: init.method ?? "GET",
      pathname,
      status: response.status,
    });
    if (!response.ok && !allowedStatuses.includes(response.status)) {
      throw new HubApiError({
        body,
        method: init.method ?? "GET",
        pathname,
        response,
      });
    }
    return { body, response };
  }

  return {
    async authenticate(password) {
      if (!password) throw new Error("Owner password is required");
      const { body, response } = await request("/api/web/auth/login", {
        body: JSON.stringify({ password }),
        method: "POST",
      });
      if (body?.authenticated !== true) {
        throw new Error("Hub did not authenticate the Owner");
      }
      const setCookie = response.headers.get("set-cookie");
      ownerCookie = setCookie?.split(";", 1)[0] ?? "";
      return body;
    },

    async collectEvidence() {
      return { apiTimeline: [...apiTimeline] };
    },

    async createEnrollment() {
      const { body } = await request("/api/web/enrollments", {
        method: "POST",
      });
      if (
        typeof body?.enrollmentToken !== "string" ||
        typeof body?.installCommand !== "string"
      ) {
        throw new Error("Hub returned an invalid Enrollment response");
      }
      return body;
    },

    async getHost(hostId) {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(`/api/web/hosts/${hostId}`);
      if (!body?.host || body.host.id !== hostId) {
        throw new Error("Hub returned an invalid Host detail response");
      }
      return body.host;
    },

    async getAuditLog() {
      const { body } = await request("/api/web/audit-log?limit=200");
      if (!Array.isArray(body?.auditLog)) {
        throw new Error("Hub returned an invalid Audit Log response");
      }
      return body.auditLog;
    },

    async getHostMetrics(hostId) {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(
        `/api/web/hosts/${hostId}/metrics?window=1m`,
      );
      if (!Array.isArray(body?.metrics?.samples)) {
        throw new Error("Hub returned an invalid Metrics response");
      }
      return body.metrics.samples;
    },

    async getHostProbeConfiguration(hostId) {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(
        `/api/web/hosts/${hostId}/probe-configuration`,
      );
      assertHostProbeConfiguration(body);
      return body;
    },

    async getProbeOperation(expectedOperation) {
      assertProbeOperation(expectedOperation, {
        hostId: expectedOperation?.hostId,
        id: expectedOperation?.id,
        kind: expectedOperation?.kind,
        targetProbeVersion: expectedOperation?.targetProbeVersion,
      });
      const { body } = await request(
        `/api/web/probe-operations/${expectedOperation.id}`,
      );
      const operation = body?.probeOperation;
      assertProbeOperation(operation, {
        hostId: expectedOperation.hostId,
        id: expectedOperation.id,
        kind: expectedOperation.kind,
        targetProbeVersion: expectedOperation.targetProbeVersion,
      });
      return operation;
    },

    async isHostSoftDeleted(hostId) {
      assertPositiveInteger(hostId, "Host ID");
      const hosts = await this.listHosts();
      const { response } = await request(`/api/web/hosts/${hostId}`, {}, [404]);
      return (
        !hosts.some((host) => host.id === hostId) && response.status === 404
      );
    },

    async listHosts() {
      const { body } = await request("/api/web/hosts");
      if (!Array.isArray(body?.hosts)) {
        throw new Error("Hub returned an invalid Host list response");
      }
      return body.hosts;
    },

    async requestProbeUninstall(hostId) {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(`/api/web/hosts/${hostId}`, {
        method: "DELETE",
      });
      const operation = body?.probeUninstallRequest;
      const boundOperation = {
        ...operation,
        hostId,
        kind: "probe_uninstall",
      };
      assertProbeOperation(boundOperation, {
        hostId,
        kind: "probe_uninstall",
      });
      return boundOperation;
    },

    async requestProbeUpgrade(hostId) {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(
        `/api/web/hosts/${hostId}/probe-upgrade-requests`,
        { method: "POST" },
      );
      const operation = body?.probeUpgradeRequest;
      const boundOperation = {
        ...operation,
        hostId,
        kind: "probe_upgrade",
      };
      assertProbeOperation(boundOperation, {
        hostId,
        kind: "probe_upgrade",
      });
      if (
        !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
          boundOperation.targetProbeVersion ?? "",
        )
      ) {
        throw new Error("Hub returned an invalid Probe Upgrade target version");
      }
      return boundOperation;
    },

    async updateHostProbeConfiguration(hostId, configuration) {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(
        `/api/web/hosts/${hostId}/probe-configuration`,
        { body: JSON.stringify(configuration), method: "PUT" },
      );
      assertHostProbeConfiguration(body);
      return body;
    },

    async waitForProbeOperation(expectedOperation, options) {
      assertProbeOperation(expectedOperation, {
        hostId: expectedOperation?.hostId,
        id: expectedOperation?.id,
        kind: expectedOperation?.kind,
        targetProbeVersion: expectedOperation?.targetProbeVersion,
      });
      const operationId = expectedOperation.id;
      const intervalMs = positiveDuration(options?.intervalMs, "poll interval");
      const timeoutMs = positiveDuration(options?.timeoutMs, "poll timeout");
      const maximumObservations = Math.floor(timeoutMs / intervalMs) + 1;
      const timeline = [{ ...expectedOperation }];
      let previous = expectedOperation;
      let terminalObservation = null;

      for (let attempt = 0; attempt < maximumObservations; attempt += 1) {
        try {
          const { body } = await request(
            `/api/web/probe-operations/${operationId}`,
          );
          const operation = body?.probeOperation;
          assertProbeOperation(operation, {
            hostId: expectedOperation.hostId,
            id: operationId,
            kind: expectedOperation.kind,
            targetProbeVersion: expectedOperation.targetProbeVersion,
          });
          assertProbeOperationProgress(previous, operation);
          timeline.push(operation);
          if (terminalObservation) {
            assertStableTerminalOperation(terminalObservation, operation);
            return timeline;
          }
          if (terminalProbeOperationStates.has(operation.state)) {
            terminalObservation = operation;
          } else if (attempt + 1 < maximumObservations) {
            await sleep(intervalMs);
          }
          previous = operation;
        } catch (error) {
          error.timeline = timeline;
          throw error;
        }
      }

      const error = new Error(
        `Probe Operation ${operationId} did not complete within ${timeoutMs}ms`,
      );
      error.code = "probe_operation_timeout";
      error.timeline = timeline;
      throw error;
    },
  };
}

export function createProbeHostHarness({
  execute,
  ownershipToken = randomUUID(),
}) {
  if (typeof execute !== "function") {
    throw new Error("Probe Host Harness requires an execute function");
  }

  let disposableRunId = null;
  let installCommandForCleanup = null;
  if (!/^[0-9a-f-]{36}$/.test(ownershipToken)) {
    throw new Error("Probe Host Harness ownership token is invalid");
  }
  let runOwnsMutation = false;
  let postReplacementFaultArmed = false;
  let sharedDependenciesBefore = null;

  async function inventory() {
    const result = await execute(hostInventoryScript(), { root: true });
    if (result.code !== 0) {
      throw new Error(
        `Release Test Host inspection failed (${result.code}): ${result.stderr}`,
      );
    }
    const inspected = parseJson(result.stdout, "Release Test Host inventory");
    assertHostInventoryEvidence(inspected);
    return inspected;
  }

  return {
    async assertReleaseTestHost(expected) {
      if (
        expected?.operatingSystem !== "ubuntu" ||
        !/^\d{2}\.\d{2}$/.test(expected.operatingSystemVersion ?? "") ||
        expected.architecture !== "x86_64"
      ) {
        throw new Error("Declared Release Test Host platform is invalid");
      }
      const result = await execute(hostPlatformScript());
      if (result.code !== 0) {
        throw new Error(
          `Release Test Host platform inspection failed (${result.code}): ${result.stderr}`,
        );
      }
      const actual = parseJson(result.stdout, "Release Test Host platform");
      for (const property of [
        "architecture",
        "operatingSystem",
        "operatingSystemVersion",
      ]) {
        if (actual[property] !== expected[property]) {
          throw new Error(
            `Release Test Host ${property} ${actual[property] ?? "unknown"} does not match declared ${expected[property]}`,
          );
        }
      }
      if (actual.pid1 !== "systemd") {
        throw new Error(
          `Release Test Host must use host systemd as PID 1, found ${actual.pid1 ?? "unknown"}`,
        );
      }
      if (!supportedReleaseTestHostVmTypes.has(actual.virtualization)) {
        throw new Error(
          `Release Test Host must be a supported VM, found ${actual.virtualization ?? "unknown"}`,
        );
      }
      return actual;
    },

    async assertDisposable(runId) {
      assertRunId(runId);
      const inspected = await inventory();
      const residue = inventoryResidue(inspected);
      if (residue.length > 0) {
        throw new Error(
          `Release Test Host has a pre-existing Enoki installation not attributable to ${runId}: ${residue.join(", ")}`,
        );
      }
      const dependencies = await execute(dependencyEvidenceScript());
      if (dependencies.code !== 0 || !dependencies.stdout.trim()) {
        throw new Error(
          `Release Test Host shared dependency inspection failed: ${dependencies.stderr}`,
        );
      }
      sharedDependenciesBefore = dependencies.stdout.trim();
      disposableRunId = runId;
      return inspected;
    },

    async install(installCommand, runId) {
      assertRunId(runId);
      if (disposableRunId !== runId) {
        throw new Error(
          "Release Test Host must pass disposable preflight before installation",
        );
      }
      assertInstallCommand(installCommand);
      const claim = await execute(claimRunScript(runId, ownershipToken), {
        root: true,
      });
      if (claim.code !== 0) {
        throw new Error(
          `Could not claim Release Test Host run: ${claim.stderr}`,
        );
      }
      runOwnsMutation = true;
      installCommandForCleanup = installCommand;
      const result = await execute(`${installCommand}\n`, {
        root: true,
        sensitive: true,
      });
      const recorded = await execute(
        recordRunResourcesScript(runId, ownershipToken),
        { root: true },
      );
      if (recorded.code !== 0) {
        throw new Error(
          `Could not record run-owned Probe resources: ${recorded.stderr}`,
        );
      }
      if (result.code !== 0) {
        throw new Error(
          `Probe installation failed (${result.code}): ${result.stderr}`,
        );
      }
      return { runId };
    },

    async assertInstalled(runId, expectedProbeVersion) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (
        !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
          expectedProbeVersion ?? "",
        )
      ) {
        throw new Error("Candidate Probe version is invalid");
      }
      const [inspected, serviceResult, sudoersResult, binaryVersionResult] =
        await Promise.all([
          inventory(),
          execute(serviceBoundaryScript()),
          execute(sudoersBoundaryScript(), { root: true }),
          execute(binaryVersionScript()),
        ]);
      const residue = inventoryResidue(inspected);
      const required = [
        "user:enoki-probe",
        "group:enoki-probe",
        "/usr/local/bin/enoki-probe",
        "/etc/enoki/probe-bootstrap.toml",
        "/etc/enoki/probe-install.toml",
        "/etc/systemd/system/enoki-probe.service",
        "/var/lib/enoki-probe",
        "/etc/sudoers.d/enoki-probe-operations",
        "enoki-probe.service",
      ];
      const missing = required.filter((entry) => !residue.includes(entry));
      if (missing.length > 0) {
        throw new Error(
          `Probe installation is incomplete: missing ${missing.join(", ")}`,
        );
      }
      if (serviceResult.code !== 0) {
        throw new Error(
          `Probe service inspection failed: ${serviceResult.stderr}`,
        );
      }
      const service = parseKeyValues(serviceResult.stdout);
      if (
        service.LoadState !== "loaded" ||
        service.ActiveState !== "active" ||
        service.User !== "enoki-probe" ||
        service.Group !== "enoki-probe" ||
        service.FragmentPath !== "/etc/systemd/system/enoki-probe.service"
      ) {
        throw new Error(
          `Probe service does not satisfy the non-root installation contract: ${JSON.stringify(service)}`,
        );
      }
      if (
        sudoersResult.code !== 0 ||
        !sudoersResult.stdout.includes("enoki-probe-uninstaller") ||
        !sudoersResult.stdout.includes("internal-uninstaller")
      ) {
        throw new Error(
          "Probe operation sudoers boundary is missing or invalid",
        );
      }
      const probeVersion =
        binaryVersionResult.code === 0
          ? binaryVersionResult.stdout
              .trim()
              .match(/(?:^|\s)(\d+\.\d+\.\d+)(?:\s|$)/)?.[1]
          : null;
      if (probeVersion !== expectedProbeVersion) {
        throw new Error(
          `Installed Probe binary version ${probeVersion ?? "unknown"} does not match Candidate ${expectedProbeVersion}`,
        );
      }
      return {
        inventory: inspected,
        probeVersion,
        service,
        sudoers: sudoersResult.stdout,
      };
    },

    async readProbeIdentity(runId) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const result = await execute(probeIdentityScript(), { root: true });
      if (result.code !== 0) {
        throw new Error(
          `Probe Identity inspection failed (${result.code}): ${result.stderr}`,
        );
      }
      const identity = parseJson(result.stdout, "Probe Identity evidence");
      if (
        !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(identity?.probeId ?? "") ||
        !/^[0-9a-f]{64}$/.test(identity?.identitySha256 ?? "") ||
        Object.keys(identity).sort().join(",") !== "identitySha256,probeId"
      ) {
        throw new Error("Probe Identity evidence is invalid");
      }
      return identity;
    },

    async beginUpgradeOwnershipTransition(runId, targetProbeVersion) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeVersion(targetProbeVersion, "Probe Upgrade target version");
      const begun = await execute(
        beginUpgradeOwnershipScript(runId, ownershipToken, targetProbeVersion),
        { root: true },
      );
      if (begun.code !== 0 || begun.stdout.trim() !== "owned") {
        throw new Error(
          `Could not authorize run-owned Probe Upgrade transition: ${begun.stderr}`,
        );
      }
      return { owned: true, targetProbeVersion };
    },

    async armPostReplacementRestartFault(runId, targetProbeVersion) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeVersion(targetProbeVersion, "Probe Repair target version");
      if (postReplacementFaultArmed) {
        throw new Error("post-replacement restart fault is already armed");
      }
      const armed = await execute(
        armPostReplacementRestartFaultScript(
          runId,
          ownershipToken,
          targetProbeVersion,
        ),
        { root: true },
      );
      if (armed.code !== 0 || armed.stdout.trim() !== "armed") {
        throw new Error(
          `Could not arm post-replacement restart fault: ${armed.stderr}`,
        );
      }
      postReplacementFaultArmed = true;
      return { armed: true, targetProbeVersion };
    },

    async bindUpgradeOwnershipTransition(runId, operation) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeOperation(operation, {
        kind: "probe_upgrade",
        targetProbeVersion: operation?.targetProbeVersion,
      });
      if (
        operation.state !== "pending" ||
        operation.acceptedAtMs !== null ||
        operation.runningAtMs !== null ||
        operation.completedAtMs !== null
      ) {
        throw new Error(
          "Probe Upgrade ownership must bind to the pending Owner-authorized operation",
        );
      }
      const bound = await execute(
        bindUpgradeOwnershipScript(runId, ownershipToken, operation),
        { root: true },
      );
      if (bound.code !== 0 || bound.stdout.trim() !== "owned") {
        throw new Error(
          `Could not bind run-owned resources to Probe Upgrade ${operation.id}: ${bound.stderr}`,
        );
      }
      return { operationId: operation.id, owned: true };
    },

    async completeUpgradeOwnershipTransition(runId, operation) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeOperation(operation, {
        kind: "probe_upgrade",
        targetProbeVersion: operation?.targetProbeVersion,
      });
      if (
        operation.state !== "succeeded" ||
        operation.failure ||
        operation.acceptedAtMs === null ||
        operation.runningAtMs === null ||
        operation.completedAtMs === null
      ) {
        throw new Error(
          "Probe Upgrade ownership can complete only from verified successful transition evidence",
        );
      }
      const completed = await execute(
        completeUpgradeOwnershipScript(runId, ownershipToken, operation),
        { root: true },
      );
      if (completed.code !== 0 || completed.stdout.trim() !== "owned") {
        throw new Error(
          `Could not commit run-owned Probe resources after Upgrade ${operation.id}: ${completed.stderr}`,
        );
      }
      return { operationId: operation.id, owned: true };
    },

    async assertPostReplacementUpgradeFailure(
      runId,
      operation,
      expectedProbeVersion,
    ) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeVersion(
        expectedProbeVersion,
        "post-replacement Probe version",
      );
      assertProbeOperation(operation, {
        kind: "probe_upgrade",
        targetProbeVersion: expectedProbeVersion,
      });
      if (operation.state !== "failed" || !operation.failure) {
        throw new Error(
          "post-replacement Repair requires a terminal failed Probe Upgrade",
        );
      }
      const result = await execute(
        postReplacementUpgradeFailureScript(
          runId,
          ownershipToken,
          operation,
          expectedProbeVersion,
        ),
        { root: true },
      );
      if (result.code !== 0) {
        throw new Error(
          `Post-replacement failure evidence is invalid: ${result.stderr}`,
        );
      }
      return parseJson(result.stdout, "post-replacement failure evidence");
    },

    async removePostReplacementRestartFault(runId) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (!postReplacementFaultArmed) {
        throw new Error("post-replacement restart fault is not armed");
      }
      const removed = await execute(
        removePostReplacementRestartFaultScript(runId, ownershipToken),
        { root: true },
      );
      if (removed.code !== 0 || removed.stdout.trim() !== "removed") {
        throw new Error(
          `Could not remove post-replacement restart fault: ${removed.stderr}`,
        );
      }
      postReplacementFaultArmed = false;
      return { removed: true };
    },

    async repair(runId) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (postReplacementFaultArmed) {
        throw new Error(
          "post-replacement restart fault must be removed before Repair",
        );
      }
      const result = await execute(
        "# enoki-release-e2e:probe-repair\n/usr/local/bin/enoki-probe repair\n",
        { root: true },
      );
      const success = result.stdout.match(
        /^Probe Repair succeeded: probe=([^\s]+) version=(\d+\.\d+\.\d+)\s*$/,
      );
      if (result.code !== 0 || !success) {
        const failure = new Error(
          `Probe Repair failed (${result.code}): ${result.stderr || result.stdout}`,
        );
        failure.code =
          result.stderr.match(/code=([a-z0-9_]+)/)?.[1] ??
          "probe_repair_failed";
        throw failure;
      }
      return {
        output: result.stdout.trim(),
        probeId: success[1],
        repairedVersion: success[2],
      };
    },

    async completeRepairOwnershipTransition(runId, operation) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeOperation(operation, {
        kind: "probe_upgrade",
        targetProbeVersion: operation?.targetProbeVersion,
      });
      if (operation.state !== "failed" || !operation.failure) {
        throw new Error(
          "Probe Repair ownership can complete only from a verified failed Probe Upgrade",
        );
      }
      const completed = await execute(
        completeRepairOwnershipScript(runId, ownershipToken, operation),
        { root: true },
      );
      if (completed.code !== 0 || completed.stdout.trim() !== "owned") {
        throw new Error(
          `Could not commit run-owned Probe resources after Repair: ${completed.stderr}`,
        );
      }
      return { operationId: operation.id, owned: true };
    },

    async cleanup(runId) {
      assertRunId(runId);
      if (disposableRunId !== runId || !runOwnsMutation) {
        return { clean: true, skipped: "run_did_not_mutate_host" };
      }
      const errors = [];
      const attempt = async (operation) => {
        try {
          return await operation();
        } catch (error) {
          errors.push(error);
          return null;
        }
      };
      let claimOwned = false;
      await attempt(async () => {
        const claim = await execute(verifyClaimScript(runId, ownershipToken), {
          root: true,
        });
        if (claim.code !== 0 || claim.stdout.trim() !== "owned") {
          throw new Error(
            `Refusing cleanup because Host state is not attributable to run ${runId}: ${claim.stderr}`,
          );
        }
        claimOwned = true;
      });

      if (postReplacementFaultArmed) {
        await attempt(async () => {
          const removed = await execute(
            removePostReplacementRestartFaultScript(runId, ownershipToken),
            { root: true },
          );
          if (removed.code !== 0 || removed.stdout.trim() !== "removed") {
            throw new Error(
              `Run-owned post-replacement fault cleanup failed: ${removed.stderr}`,
            );
          }
          postReplacementFaultArmed = false;
        });
      }

      let inspected = await attempt(() => inventory());
      let residue = inspected ? inventoryResidue(inspected) : null;
      let removedPartialInstallation = false;
      if (residue?.length > 0) {
        const verifiedResources = await execute(
          verifyRunResourcesScript(runId, ownershipToken),
          { root: true },
        );
        let resourcesOwned = verifiedResources.code === 0;
        if (verifiedResources.code !== 0) {
          const authorizedUpgradeResources = await execute(
            verifyAuthorizedUpgradeResourcesScript(runId, ownershipToken),
            { root: true },
          );
          resourcesOwned =
            authorizedUpgradeResources.code === 0 &&
            authorizedUpgradeResources.stdout.trim() === "owned";
          if (!resourcesOwned) {
            errors.push(
              new Error(
                `Refusing cleanup because Probe resources no longer match run ${runId}: ${verifiedResources.stderr}${authorizedUpgradeResources.stderr}`,
              ),
            );
          }
        }
        if (resourcesOwned) {
          const cleanupCommand = await attempt(() =>
            Promise.resolve(uninstallCommand(installCommandForCleanup)),
          );
          if (cleanupCommand) {
            await attempt(async () => {
              const uninstalled = await execute(`${cleanupCommand}\n`, {
                root: true,
                sensitive: true,
              });
              if (uninstalled.code !== 0) {
                throw new Error(
                  `Run-owned Probe cleanup failed (${uninstalled.code}): ${uninstalled.stderr}`,
                );
              }
              removedPartialInstallation = true;
            });
          }
          await attempt(async () => {
            const reloaded = await execute(daemonReloadScript(), {
              root: true,
            });
            if (reloaded.code !== 0) {
              throw new Error(
                `cleanup daemon reload failed: ${reloaded.stderr}`,
              );
            }
          });
          inspected = await attempt(() => inventory());
          residue = inspected ? inventoryResidue(inspected) : null;
          if (residue?.length > 0) {
            errors.push(
              new Error(
                `Run-owned Probe cleanup left residue: ${residue.join(", ")}`,
              ),
            );
          }
        }
      }

      if (claimOwned && Array.isArray(residue) && residue.length === 0) {
        await attempt(async () => {
          const released = await execute(
            removeClaimScript(runId, ownershipToken),
            { root: true },
          );
          if (released.code !== 0) {
            throw new Error(`Could not remove run claim: ${released.stderr}`);
          }
        });
      }
      await attempt(async () => {
        const releasedClaim = await execute(
          inspectClaimScript(runId, ownershipToken),
          { root: true },
        );
        if (
          releasedClaim.code !== 0 ||
          releasedClaim.stdout.trim() !== "absent"
        ) {
          throw new Error("Run claim remains after Host cleanup");
        }
        runOwnsMutation = false;
      });
      if (errors.length > 0) {
        const aggregate = new AggregateError(
          errors,
          `Release Test Host cleanup failed: ${errors.map((error) => error.message).join("; ")}`,
        );
        aggregate.code = "release_test_host_cleanup_failed";
        throw aggregate;
      }
      return { clean: true, removedPartialInstallation };
    },

    async collectEvidence(runId) {
      assertRunId(runId);
      const [inventoryResult, service, journald, sudoers] = await Promise.all([
        execute(hostInventoryScript()),
        execute(systemdEvidenceScript()),
        execute(journaldEvidenceScript(), { root: true }),
        execute(sudoersEvidenceScript(), { root: true }),
      ]);
      return {
        inventory:
          inventoryResult.code === 0
            ? parseJson(inventoryResult.stdout, "Release Test Host inventory")
            : commandEvidence(inventoryResult),
        journald: commandEvidence(journald),
        runClaimed: disposableRunId === runId && runOwnsMutation,
        sudoers: commandEvidence(sudoers),
        systemd: commandEvidence(service),
      };
    },

    async verifyUninstallCompletion(runId) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const reloaded = await execute(daemonReloadScript(), { root: true });
      if (reloaded.code !== 0) {
        throw new Error(`systemd daemon reload failed: ${reloaded.stderr}`);
      }
      const [inspected, journald, dependencies] = await Promise.all([
        inventory(),
        execute(journaldEvidenceScript(), { root: true }),
        execute(dependencyEvidenceScript()),
      ]);
      const residue = inventoryResidue(inspected);
      if (residue.length > 0) {
        throw new Error(
          `Probe Uninstall left Enoki-managed residue: ${residue.join(", ")}`,
        );
      }
      const journaldText = journald.stdout.trim();
      const journaldRetained =
        journald.code === 0 &&
        journaldText.length > 0 &&
        !journaldText.includes("-- No entries --");
      const sharedDependenciesRetained =
        dependencies.code === 0 &&
        dependencies.stdout.trim() === sharedDependenciesBefore;
      return {
        clean: true,
        inventory: inspected,
        journald: journaldText,
        journaldRetained,
        sharedDependencies: dependencies.stdout.trim(),
        sharedDependenciesRetained,
      };
    },

    async verifyClean(runId) {
      assertRunId(runId);
      const reloaded = await execute(daemonReloadScript(), { root: true });
      if (reloaded.code !== 0) {
        throw new Error(
          `verify-clean daemon reload failed: ${reloaded.stderr}`,
        );
      }
      const [inspected, claim] = await Promise.all([
        inventory(),
        execute(inspectClaimScript(runId, ownershipToken), { root: true }),
      ]);
      const residue = inventoryResidue(inspected);
      if (residue.length > 0 || claim.stdout.trim() !== "absent") {
        throw new Error(
          `Release Test Host is not clean: ${[
            ...residue,
            ...(claim.stdout.trim() === "absent"
              ? []
              : [`run-claim:${claim.stdout.trim() || "unknown"}`]),
          ].join(", ")}`,
        );
      }
      return { clean: true, inventory: inspected };
    },
  };
}

function hostPlatformScript() {
  return String.raw`# enoki-release-e2e:platform
set -eu
. /etc/os-release
case "$(uname -m)" in
  x86_64) architecture=x86_64 ;;
  *) architecture="$(uname -m)" ;;
esac
pid1="$(cat /proc/1/comm)"
virtualization="$(systemd-detect-virt --vm 2>/dev/null || printf none)"
printf '{"architecture":"%s","operatingSystem":"%s","operatingSystemVersion":"%s","pid1":"%s","virtualization":"%s"}\n' \
  "$architecture" "$(printf '%s' "$ID" | tr '[:upper:]' '[:lower:]')" "$VERSION_ID" "$pid1" "$virtualization"`;
}

function hostInventoryScript() {
  return String.raw`# enoki-release-e2e:inventory
set -eu
json_bool() { if "$@" >/dev/null 2>&1; then printf true; else printf false; fi; }
printf '{"accounts":{"group":'
json_bool getent group enoki-probe
printf ',"user":'
json_bool getent passwd enoki-probe
printf '},"files":['
separator=
for candidate in ${managedHostPaths.map(shellSingleQuote).join(" ")}; do
  if [ -e "$candidate" ] || [ -L "$candidate" ]; then
    printf '%s"%s"' "$separator" "$candidate"
    separator=,
  fi
done
for candidate in /run/systemd/system/enoki-probe*.service; do
  if [ -e "$candidate" ] || [ -L "$candidate" ]; then
    printf '%s"%s"' "$separator" "$candidate"
    separator=,
  fi
done
printf '],"units":['
separator=
systemctl list-units --all --full --plain 'enoki-probe*.service' --no-legend --no-pager 2>/dev/null |
  while IFS=' ' read -r unit _; do
    [ -n "$unit" ] || continue
    printf '%s"%s"' "$separator" "$unit"
    separator=,
  done
printf ']}\n'
`;
}

function serviceBoundaryScript() {
  return String.raw`# enoki-release-e2e:service-boundary
set -eu
systemctl show enoki-probe.service --no-pager \
  --property=LoadState \
  --property=ActiveState \
  --property=SubState \
  --property=User \
  --property=Group \
  --property=FragmentPath
`;
}

function sudoersBoundaryScript() {
  return String.raw`# enoki-release-e2e:sudoers-boundary
set -eu
cat /etc/sudoers.d/enoki-probe-operations
if [ -e /etc/sudoers.d/enoki-probe-collector-helpers ]; then
  cat /etc/sudoers.d/enoki-probe-collector-helpers
fi
`;
}

function binaryVersionScript() {
  return String.raw`# enoki-release-e2e:binary-version
set -eu
/usr/local/bin/enoki-probe --version
`;
}

function probeIdentityScript() {
  return String.raw`# enoki-release-e2e:probe-identity
set -eu
config=/etc/enoki/probe-bootstrap.toml
[ -f "$config" ]
[ ! -L "$config" ]
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$config")
private_key_line=$(grep -E '^probe_private_key_pem = ".+"$' "$config")
[ "$(grep -c '^probe_id = ' "$config")" -eq 1 ]
[ "$(grep -c '^probe_private_key_pem = ' "$config")" -eq 1 ]
probe_id=\${probe_id_line#probe_id = \"}
probe_id=\${probe_id%\"}
identity_sha256=$(printf '%s\n%s\n' "$probe_id_line" "$private_key_line" | sha256sum | cut -d ' ' -f 1)
printf '{"identitySha256":"%s","probeId":"%s"}\n' "$identity_sha256" "$probe_id"
`;
}

function dependencyEvidenceScript() {
  return String.raw`# enoki-release-e2e:dependencies
set -eu
curl_path=$(command -v curl)
sudo_path=$(command -v sudo)
systemd_run_path=$(command -v systemd-run)
printf '{"curl":"%s","sudo":"%s","systemdRun":"%s"}\n' "$curl_path" "$sudo_path" "$systemd_run_path"
`;
}

function daemonReloadScript() {
  return String.raw`# enoki-release-e2e:daemon-reload
set -eu
systemctl daemon-reload
systemctl reset-failed enoki-probe.service 2>/dev/null || true
`;
}

function journaldEvidenceScript() {
  return String.raw`# enoki-release-e2e:journald
set -eu
journalctl --unit=enoki-probe.service --no-pager --lines=200 --output=short-iso
`;
}

function systemdEvidenceScript() {
  return String.raw`# enoki-release-e2e:systemd-evidence
set -eu
load_state=$(systemctl show enoki-probe.service --no-pager --property=LoadState --value)
active_state=$(systemctl show enoki-probe.service --no-pager --property=ActiveState --value)
unit_count=$(systemctl list-units --all --full --plain 'enoki-probe*.service' --no-legend --no-pager | awk 'NF { count += 1 } END { print count + 0 }')
failed_unit_count=$(systemctl --failed --all --full --plain --no-legend --no-pager | awk '$1 ~ /^enoki-probe.*[.]service$/ { count += 1 } END { print count + 0 }')
[ "$load_state" = not-found ]
[ "$active_state" = inactive ]
[ "$unit_count" = 0 ]
[ "$failed_unit_count" = 0 ]
printf 'stage=post-uninstall\nLoadState=%s\nActiveState=%s\nunitCount=%s\nfailedUnitCount=%s\n' \
  "$load_state" "$active_state" "$unit_count" "$failed_unit_count"
`;
}

function sudoersEvidenceScript() {
  return String.raw`# enoki-release-e2e:sudoers-evidence
set -eu
managed_sudoers_count=0
for candidate in /etc/sudoers.d/enoki-probe-operations /etc/sudoers.d/enoki-probe-collector-helpers /etc/sudoers.d/enoki-probe-upgrader; do
  if [ -e "$candidate" ]; then
    printf 'managed sudoers residue: %s\n' "$candidate" >&2
    managed_sudoers_count=$((managed_sudoers_count + 1))
  fi
done
[ "$managed_sudoers_count" = 0 ] || exit 1
printf 'stage=post-uninstall\nmanagedSudoersCount=0\n'
`;
}

function claimRunScript(runId, token) {
  return `# enoki-release-e2e:claim
set -eu
claim_root=/var/lib/enoki-release-e2e
claim_dir="$claim_root/claim"
install -d -m 0700 "$claim_root"
if ! mkdir -m 0700 "$claim_dir" 2>/dev/null; then
  printf 'Host already claimed by another Release E2E run\n' >&2
  exit 73
fi
cleanup_rejected_claim() { rm -f -- "$claim_dir/run-id" "$claim_dir/token"; rmdir "$claim_dir" 2>/dev/null || true; rmdir "$claim_root" 2>/dev/null || true; }
trap cleanup_rejected_claim EXIT HUP INT TERM
( umask 077; printf '%s\n' ${shellSingleQuote(runId)} > "$claim_dir/run-id"; printf '%s\n' ${shellSingleQuote(token)} > "$claim_dir/token" )
# enoki-release-e2e:claim-empty-recheck
residue=
for candidate in ${managedHostPaths.map(shellSingleQuote).join(" ")} /run/systemd/system/enoki-probe*.service; do
  if [ -e "$candidate" ] || [ -L "$candidate" ]; then residue="$residue $candidate"; fi
done
if getent passwd enoki-probe >/dev/null 2>&1; then residue="$residue user:enoki-probe"; fi
if getent group enoki-probe >/dev/null 2>&1; then residue="$residue group:enoki-probe"; fi
units=$(systemctl list-units --all --full --plain 'enoki-probe*.service' --no-legend --no-pager 2>/dev/null || true)
if [ -n "$units" ]; then residue="$residue enoki-probe-unit"; fi
if [ -n "$residue" ]; then
  printf 'Release Test Host became non-empty before claim:%s\n' "$residue" >&2
  exit 74
fi
trap - EXIT HUP INT TERM
printf 'owned\n'
`;
}

function verifyClaimScript(runId, token) {
  return `# enoki-release-e2e:verify-claim\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\n[ -d "$claim" ]\n[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]\n[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]\nprintf 'owned\\n'\n`;
}

function recordRunResourcesScript(runId, token) {
  return resourceFingerprintScript({
    header: "record-resources",
    runId,
    token,
    verify: false,
  });
}

function verifyRunResourcesScript(runId, token) {
  return resourceFingerprintScript({
    header: "verify-resources",
    runId,
    token,
    verify: true,
  });
}

function resourceFingerprintScript({ header, runId, token, verify }) {
  const action = verify
    ? String.raw`temporary=$(mktemp "$claim/resources.verify.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
cmp --silent "$claim/resources" "$temporary" || { printf 'run-owned resource fingerprint changed\n' >&2; exit 75; }
printf 'owned\n'`
    : String.raw`[ ! -e "$claim/resources" ] || { printf 'run resource evidence already exists\n' >&2; exit 76; }
( umask 077; fingerprint > "$claim/resources" )
printf 'recorded\n'`;
  return `# enoki-release-e2e:${header}
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
${resourceFingerprintFunction()}
${action}
`;
}

function beginUpgradeOwnershipScript(runId, token, targetProbeVersion) {
  return `# enoki-release-e2e:begin-upgrade-ownership
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ -f "$claim/resources" ]
[ ! -e "$claim/upgrade-target" ]
[ ! -e "$claim/upgrade-operation-id" ]
cp -- "$claim/resources" "$claim/upgrade-before-resources"
( umask 077; printf '%s\n' ${shellSingleQuote(targetProbeVersion)} > "$claim/upgrade-target" )
printf 'owned\n'
`;
}

function bindUpgradeOwnershipScript(runId, token, operation) {
  return `# enoki-release-e2e:bind-upgrade-ownership
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ "$(cat "$claim/upgrade-target")" = ${shellSingleQuote(operation.targetProbeVersion)} ]
[ -f "$claim/upgrade-before-resources" ]
cmp --silent "$claim/resources" "$claim/upgrade-before-resources"
[ ! -e "$claim/upgrade-operation-id" ]
( umask 077; printf '%s\n' ${shellSingleQuote(String(operation.id))} > "$claim/upgrade-operation-id" )
printf 'owned\n'
`;
}

function armPostReplacementRestartFaultScript(
  runId,
  token,
  targetProbeVersion,
) {
  return `# enoki-release-e2e:arm-post-replacement-fault
set -eu
claim=/var/lib/enoki-release-e2e/claim
dropin_dir=/etc/systemd/system/enoki-probe.service.d
dropin="$dropin_dir/90-enoki-release-e2e-restart-failure.conf"
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ "$(cat "$claim/upgrade-target")" = ${shellSingleQuote(targetProbeVersion)} ]
[ -f "$claim/upgrade-before-resources" ]
[ ! -e "$claim/post-replacement-fault" ]
[ ! -e "$dropin" ]
[ "$(systemctl is-active enoki-probe.service)" = active ]
install -d -m 0755 "$dropin_dir"
printf '[Service]\nExecStartPre=/bin/false\n' > "$dropin"
chmod 0644 "$dropin"
( umask 077; printf '%s\n' ${shellSingleQuote(targetProbeVersion)} > "$claim/post-replacement-fault" )
systemctl daemon-reload
[ "$(systemctl is-active enoki-probe.service)" = active ]
printf 'armed\n'
`;
}

function postReplacementUpgradeFailureScript(
  runId,
  token,
  operation,
  expectedProbeVersion,
) {
  if (!/^[a-z0-9_]+$/.test(operation.failure?.code ?? "")) {
    throw new Error("failed Probe Upgrade has no stable failure code");
  }
  return `# enoki-release-e2e:post-replacement-failure
set -eu
claim=/var/lib/enoki-release-e2e/claim
dropin=/etc/systemd/system/enoki-probe.service.d/90-enoki-release-e2e-restart-failure.conf
status=/var/lib/enoki-probe/probe-operation-status.toml
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ "$(cat "$claim/upgrade-operation-id")" = ${shellSingleQuote(String(operation.id))} ]
[ "$(cat "$claim/post-replacement-fault")" = ${shellSingleQuote(expectedProbeVersion)} ]
[ -f "$dropin" ]
[ -f "$status" ]
[ ! -L "$status" ]
[ "$(stat -c %u "$status")" = 0 ]
[ "$(stat -c %a "$status")" = 644 ]
version=$(/usr/local/bin/enoki-probe --version | sed -n 's/^enoki-probe //p')
[ "$version" = ${shellSingleQuote(expectedProbeVersion)} ]
[ "$(grep -Fxc ${shellSingleQuote(`operation_id = "${operation.id}"`)} "$status")" -eq 1 ]
[ "$(grep -Fxc ${shellSingleQuote(`target_probe_version = "${expectedProbeVersion}"`)} "$status")" -eq 1 ]
[ "$(grep -Fxc 'status = "failed"' "$status")" -eq 1 ]
[ "$(grep -Fxc 'error_code = "post_replacement_restart_failure"' "$status")" -eq 1 ]
if [ "$(systemctl is-active enoki-probe.service 2>/dev/null || true)" = active ]; then
  printf 'faulted Probe service unexpectedly active\n' >&2
  exit 79
fi
printf '{"hubFailureCode":"%s","localFailureCode":"post_replacement_restart_failure","operationId":%s,"probeVersion":"%s"}\n' \
  ${shellSingleQuote(operation.failure.code)} ${shellSingleQuote(String(operation.id))} "$version"
`;
}

function removePostReplacementRestartFaultScript(runId, token) {
  return `# enoki-release-e2e:remove-post-replacement-fault
set -eu
claim=/var/lib/enoki-release-e2e/claim
dropin_dir=/etc/systemd/system/enoki-probe.service.d
dropin="$dropin_dir/90-enoki-release-e2e-restart-failure.conf"
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ -f "$claim/post-replacement-fault" ]
[ -f "$dropin" ]
rm -- "$dropin" "$claim/post-replacement-fault"
rmdir "$dropin_dir" 2>/dev/null || true
systemctl daemon-reload
systemctl reset-failed enoki-probe.service 2>/dev/null || true
printf 'removed\n'
`;
}

function completeUpgradeOwnershipScript(runId, token, operation) {
  return `# enoki-release-e2e:complete-upgrade-ownership
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ "$(cat "$claim/upgrade-target")" = ${shellSingleQuote(operation.targetProbeVersion)} ]
[ "$(cat "$claim/upgrade-operation-id")" = ${shellSingleQuote(String(operation.id))} ]
[ -f "$claim/upgrade-before-resources" ]
cmp --silent "$claim/resources" "$claim/upgrade-before-resources"
${knownProbeInstallMetadataScript()}
${resourceFingerprintFunction()}
temporary=$(mktemp "$claim/resources.upgrade.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
mv -- "$temporary" "$claim/resources"
trap - EXIT HUP INT TERM
rm -- "$claim/upgrade-before-resources" "$claim/upgrade-target" "$claim/upgrade-operation-id"
printf 'owned\n'
`;
}

function completeRepairOwnershipScript(runId, token, operation) {
  return `# enoki-release-e2e:complete-repair-ownership
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ "$(cat "$claim/upgrade-target")" = ${shellSingleQuote(operation.targetProbeVersion)} ]
[ "$(cat "$claim/upgrade-operation-id")" = ${shellSingleQuote(String(operation.id))} ]
[ -f "$claim/upgrade-before-resources" ]
[ ! -e "$claim/post-replacement-fault" ]
cmp --silent "$claim/resources" "$claim/upgrade-before-resources"
${knownProbeInstallMetadataScript()}
${resourceFingerprintFunction()}
temporary=$(mktemp "$claim/resources.repair.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
mv -- "$temporary" "$claim/resources"
trap - EXIT HUP INT TERM
rm -- "$claim/upgrade-before-resources" "$claim/upgrade-target" "$claim/upgrade-operation-id"
printf 'owned\n'
`;
}

function verifyAuthorizedUpgradeResourcesScript(runId, token) {
  return `# enoki-release-e2e:verify-upgrade-ownership
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ -s "$claim/upgrade-target" ]
[ -s "$claim/upgrade-operation-id" ]
case "$(cat "$claim/upgrade-target")" in
  0.*.*|[1-9]*.*.*) ;;
  *) printf 'invalid authorized Probe Upgrade target\n' >&2; exit 77 ;;
esac
case "$(cat "$claim/upgrade-operation-id")" in
  ''|*[!0-9]*) printf 'invalid authorized Probe Upgrade operation\n' >&2; exit 78 ;;
esac
[ -f "$claim/upgrade-before-resources" ]
cmp --silent "$claim/resources" "$claim/upgrade-before-resources"
${knownProbeInstallMetadataScript()}
${resourceFingerprintFunction()}
temporary=$(mktemp "$claim/resources.transition.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
printf 'owned\n'
`;
}

function resourceFingerprintFunction() {
  return String.raw`fingerprint() {
  for candidate in ${managedHostPaths.map(shellSingleQuote).join(" ")}; do
    if [ -L "$candidate" ]; then printf 'link\t%s\t%s\n' "$candidate" "$(readlink "$candidate")"
    elif [ -f "$candidate" ]; then printf 'file\t%s\n' "$candidate"
    elif [ -d "$candidate" ]; then printf 'directory\t%s\n' "$candidate"
    fi
  done
  if getent passwd enoki-probe >/dev/null 2>&1; then printf 'user\tenoki-probe\n'; fi
  if getent group enoki-probe >/dev/null 2>&1; then printf 'group\tenoki-probe\n'; fi
}`;
}

function knownProbeInstallMetadataScript() {
  return String.raw`metadata=/etc/enoki/probe-install.toml
[ -f "$metadata" ]
[ ! -L "$metadata" ]
[ "$(stat -c %u "$metadata")" = 0 ]
[ -z "$(find "$metadata" -prune -perm /022 -print)" ]
require_metadata_line() { [ "$(grep -Fxc "$1" "$metadata")" -eq 1 ]; }
require_metadata_line 'schema_version = 1'
require_metadata_line 'install_path = "/usr/local/bin/enoki-probe"'
require_metadata_line 'identity_path = "/etc/enoki/probe-bootstrap.toml"'
require_metadata_line 'state_dir = "/var/lib/enoki-probe"'
require_metadata_line 'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"'
require_metadata_line 'service_name = "enoki-probe"'
require_metadata_line 'service_user = "enoki-probe"'
require_metadata_line 'service_group = "enoki-probe"'
require_metadata_line 'service_unit_path = "/etc/systemd/system/enoki-probe.service"'
require_metadata_line 'operation_sudoers_path = "/etc/sudoers.d/enoki-probe-operations"'
require_metadata_line 'collector_helper_sudoers_path = "/etc/sudoers.d/enoki-probe-collector-helpers"'`;
}

function removeClaimScript(runId, token) {
  return `# enoki-release-e2e:remove-claim\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\n[ -d "$claim" ]\n[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]\n[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]\nrm -f -- "$claim/resources" "$claim/upgrade-before-resources" "$claim/upgrade-target" "$claim/upgrade-operation-id" "$claim/post-replacement-fault"\nrm -- "$claim/run-id" "$claim/token"\nrmdir "$claim"\nrmdir /var/lib/enoki-release-e2e 2>/dev/null || true\n`;
}

function inspectClaimScript(runId, token) {
  return `# enoki-release-e2e:inspect-claim\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\nif [ ! -e "$claim" ]; then printf 'absent\\n'; elif [ -d "$claim" ] && [ "$(cat "$claim/run-id" 2>/dev/null || true)" = ${shellSingleQuote(runId)} ] && [ "$(cat "$claim/token" 2>/dev/null || true)" = ${shellSingleQuote(token)} ]; then printf 'owned\\n'; else printf 'foreign\\n'; fi\n`;
}

function inventoryResidue(inventory) {
  const residue = [];
  if (inventory?.accounts?.user) residue.push("user:enoki-probe");
  if (inventory?.accounts?.group) residue.push("group:enoki-probe");
  if (Array.isArray(inventory?.files)) residue.push(...inventory.files);
  if (Array.isArray(inventory?.units)) residue.push(...inventory.units);
  return residue.sort();
}

function parseJson(value, label) {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`${label} was not valid JSON`, { cause: error });
  }
}

function assertRunId(runId) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(runId ?? "")) {
    throw new Error("run ID must be a safe non-empty identifier");
  }
}

function assertOwnedRun(runId, disposableRunId, runOwnsMutation) {
  assertRunId(runId);
  if (disposableRunId !== runId || !runOwnsMutation) {
    throw new Error(`Release Test Host state is not owned by run ${runId}`);
  }
}

function assertInstallCommand(command) {
  if (
    typeof command !== "string" ||
    command.length > 16_384 ||
    command.includes("\n") ||
    !/^curl -fsSL '[^']+\/api\/probe\/install\.sh' \| sudo env /.test(
      command,
    ) ||
    !command.includes("ENOKI_HUB_URL=") ||
    !command.includes("ENOKI_ENROLLMENT_TOKEN=") ||
    !command.endsWith(" bash")
  ) {
    throw new Error("Hub returned an invalid Probe install command");
  }
}

function parseKeyValues(value) {
  const result = {};
  for (const line of value.split("\n")) {
    if (!line) continue;
    const separator = line.indexOf("=");
    if (separator < 1) throw new Error("Host property output is malformed");
    result[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return result;
}

function uninstallCommand(installCommand) {
  assertInstallCommand(installCommand);
  return installCommand.replace(/ bash$/, " ENOKI_UNINSTALL=1 bash");
}

function commandEvidence(result) {
  return {
    code: result.code,
    stderr: result.stderr,
    stdout: result.stdout,
  };
}

function shellSingleQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

class HubApiError extends Error {
  constructor({ body, method, pathname, response }) {
    super(
      `Hub API ${method} ${pathname} failed with ${response.status}: ${body?.error ?? response.statusText}`,
    );
    this.body = body;
    this.code = body?.error ?? "hub_api_error";
    this.status = response.status;
  }
}

function assertProbeOperation(operation, expected = {}) {
  if (
    !operation ||
    typeof operation !== "object" ||
    !Number.isInteger(operation.id) ||
    !Object.hasOwn(probeOperationStateRank, operation.state) ||
    operation.failure === undefined ||
    !Number.isSafeInteger(operation.createdAtMs) ||
    operation.createdAtMs < 0 ||
    !isNullableTimestamp(operation.acceptedAtMs) ||
    !isNullableTimestamp(operation.runningAtMs) ||
    !isNullableTimestamp(operation.completedAtMs) ||
    !Number.isSafeInteger(operation.updatedAtMs) ||
    operation.updatedAtMs < operation.createdAtMs ||
    !hasValidOperationStateTimestamps(operation)
  ) {
    throw new Error("Hub returned an invalid Probe Operation");
  }
  const transitionTimestamps = [
    operation.acceptedAtMs,
    operation.runningAtMs,
    operation.completedAtMs,
  ].filter((value) => value !== null);
  if (
    transitionTimestamps.some(
      (value, index) =>
        value < operation.createdAtMs ||
        value > operation.updatedAtMs ||
        (index > 0 && value < transitionTimestamps[index - 1]),
    )
  ) {
    throw assertionError(
      "probe_operation_timestamp_invalid",
      "Probe Operation transition timestamps are not monotonic",
    );
  }
  if (expected.id !== undefined && operation.id !== expected.id) {
    throw assertionError(
      "probe_operation_identity_mismatch",
      `Hub returned Probe Operation ${operation.id}; expected ${expected.id}`,
    );
  }
  if (expected.hostId !== undefined && operation.hostId !== expected.hostId) {
    throw assertionError(
      "probe_operation_identity_mismatch",
      `Hub returned Probe Operation for Host ${operation.hostId}; expected ${expected.hostId}`,
    );
  }
  if (expected.kind !== undefined && operation.kind !== expected.kind) {
    throw assertionError(
      "probe_operation_identity_mismatch",
      `Hub returned Probe Operation kind ${operation.kind}; expected ${expected.kind}`,
    );
  }
  if (
    expected.targetProbeVersion !== undefined &&
    operation.targetProbeVersion !== expected.targetProbeVersion
  ) {
    throw assertionError(
      "probe_operation_identity_mismatch",
      `Hub returned Probe Operation target ${operation.targetProbeVersion ?? "unknown"}; expected ${expected.targetProbeVersion}`,
    );
  }
  if (operation.state === "failed") {
    if (
      !operation.failure ||
      typeof operation.failure.code !== "string" ||
      typeof operation.failure.message !== "string"
    ) {
      throw assertionError(
        "probe_operation_failure_invalid",
        "Failed Probe Operation has no stable typed failure",
      );
    }
  } else if (operation.failure !== null) {
    throw assertionError(
      "probe_operation_failure_invalid",
      `Probe Operation state ${operation.state} unexpectedly carries a failure`,
    );
  }
}

function assertProbeOperationProgress(previous, operation) {
  for (const field of [
    "createdAtMs",
    "acceptedAtMs",
    "runningAtMs",
    "completedAtMs",
  ]) {
    if (
      (field === "createdAtMs" && operation[field] !== previous[field]) ||
      (previous[field] !== null && operation[field] !== previous[field])
    ) {
      throw assertionError(
        "probe_operation_timestamp_changed",
        `Probe Operation ${field} changed from ${previous[field]} to ${operation[field]}`,
      );
    }
  }
  if (terminalProbeOperationStates.has(previous.state)) return;
  const allowedAfter = {
    accepted: new Set(["accepted", "failed", "running", "succeeded"]),
    pending: new Set(Object.keys(probeOperationStateRank)),
    running: new Set(["failed", "running", "succeeded"]),
  };
  if (
    !allowedAfter[previous.state]?.has(operation.state) ||
    operation.updatedAtMs < previous.updatedAtMs
  ) {
    throw assertionError(
      "probe_operation_state_regressed",
      `Probe Operation regressed from ${previous.state}@${previous.updatedAtMs} to ${operation.state}@${operation.updatedAtMs}`,
    );
  }
}

function assertStableTerminalOperation(previous, operation) {
  if (
    previous.state !== operation.state ||
    JSON.stringify(previous.failure) !== JSON.stringify(operation.failure)
  ) {
    throw assertionError(
      "probe_operation_terminal_changed",
      "Probe Operation terminal state or failure changed while being confirmed",
    );
  }
}

function assertHostProbeConfiguration(value) {
  if (
    !value ||
    (value.mode !== "inherit" && value.mode !== "override") ||
    !Array.isArray(value.configuration?.enabledCollectorIds) ||
    !Number.isSafeInteger(
      value.configuration.metricsCollectionIntervalSeconds,
    ) ||
    typeof value.configuration.version !== "string"
  ) {
    throw new Error("Hub returned an invalid Host Probe Configuration");
  }
}

function assertPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
}

function assertProbeVersion(value, label) {
  if (!/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(value ?? "")) {
    throw new Error(`${label} is invalid`);
  }
}

function positiveDuration(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function defaultSleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function assertCandidateManifest(manifest) {
  const releaseBaseline = manifest?.releaseBaseline;
  const validReleaseBaseline =
    releaseBaseline?.kind === "enoki-release-baseline" &&
    /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      releaseBaseline.tag ?? "",
    ) &&
    /^sha256:[0-9a-f]{64}$/.test(releaseBaseline.hub?.digest ?? "") &&
    /^sha256:[0-9a-f]{64}$/.test(releaseBaseline.hub?.imageDigest ?? "") &&
    releaseBaseline.probeAssetSet?.version === releaseBaseline.tag.slice(1);
  if (
    manifest?.schemaVersion !== 2 ||
    manifest.kind !== "enoki-release-candidate" ||
    !/^[0-9a-f]{40}$/.test(manifest.candidate?.commit ?? "") ||
    !/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      manifest.candidate?.version ?? "",
    ) ||
    !/^sha256:[0-9a-f]{64}$/.test(manifest.hub?.digest ?? "") ||
    manifest.hub?.embeddedProbeVersion !== manifest.probeAssetSet?.version ||
    manifest.probeAssetSet?.version !== manifest.candidate.version.slice(1) ||
    !validReleaseBaseline
  ) {
    throw new Error("Candidate Manifest is invalid or internally inconsistent");
  }
}

function assertScenarioParticipants(host, hub) {
  const hostMethods = [
    "assertDisposable",
    "assertInstalled",
    "cleanup",
    "collectEvidence",
    "install",
    "verifyUninstallCompletion",
  ];
  const hubMethods = [
    "authenticate",
    "createEnrollment",
    "getAuditLog",
    "getHost",
    "getHostMetrics",
    "getHostProbeConfiguration",
    "isHostSoftDeleted",
    "listHosts",
    "requestProbeUninstall",
    "updateHostProbeConfiguration",
    "waitForProbeOperation",
  ];
  if (
    hostMethods.some((method) => typeof host?.[method] !== "function") ||
    hubMethods.some((method) => typeof hub?.[method] !== "function")
  ) {
    throw new Error("Release E2E environment returned invalid participants");
  }
}

function assertBaselineScenarioParticipants(host, hub) {
  assertScenarioParticipants(host, hub);
  const hostMethods = [
    "beginUpgradeOwnershipTransition",
    "bindUpgradeOwnershipTransition",
    "completeUpgradeOwnershipTransition",
    "readProbeIdentity",
  ];
  const hubMethods = ["requestProbeUpgrade", "switchToCandidate"];
  if (
    hostMethods.some((method) => typeof host?.[method] !== "function") ||
    hubMethods.some((method) => typeof hub?.[method] !== "function")
  ) {
    throw new Error(
      "Release E2E environment returned invalid baseline-upgrade participants",
    );
  }
}

function assertHubRestoreScenarioParticipants(host, hub) {
  const hostMethods = [
    "assertDisposable",
    "assertInstalled",
    "beginUpgradeOwnershipTransition",
    "bindUpgradeOwnershipTransition",
    "cleanup",
    "collectEvidence",
    "completeUpgradeOwnershipTransition",
    "install",
    "readProbeIdentity",
    "verifyUninstallCompletion",
  ];
  const hubMethods = [
    "authenticate",
    "captureBaselineStateSnapshot",
    "createEnrollment",
    "getHost",
    "getHostMetrics",
    "listHosts",
    "isHostSoftDeleted",
    "requestProbeUninstall",
    "requestProbeUpgrade",
    "restoreBaselineStateSnapshot",
    "switchToCandidate",
    "waitForProbeOperation",
  ];
  if (
    hostMethods.some((method) => typeof host?.[method] !== "function") ||
    hubMethods.some((method) => typeof hub?.[method] !== "function")
  ) {
    throw new Error(
      "Release E2E environment returned invalid Hub Restore participants",
    );
  }
}

function assertLiveHubStateSnapshotEvidence(snapshot, baseline) {
  if (
    snapshot?.tool !== "enoki-hub-state" ||
    snapshot.version !== "v1" ||
    snapshot.baselineImageDigest !== baseline.hub.imageDigest ||
    snapshot.baselineVersion !== baseline.tag ||
    !/^sha256:[0-9a-f]{64}$/.test(snapshot.manifestDigest ?? "") ||
    !Number.isFinite(Date.parse(snapshot.recoveryTime ?? "")) ||
    !Number.isSafeInteger(snapshot.hotDataFileCount) ||
    snapshot.hotDataFileCount < 1 ||
    !Array.isArray(snapshot.hotDataFiles) ||
    !snapshot.hotDataFiles.includes("data-root/enoki.db") ||
    !Array.isArray(snapshot.roots) ||
    !snapshot.roots.some(
      (root) => root?.id === "data-root" && root.path === "/data",
    ) ||
    !snapshot.roots.some(
      (root) =>
        root?.id === "metrics-archive" &&
        root.path === "/data/metrics-archive" &&
        root.included === true,
    )
  ) {
    throw assertionError(
      "hub_state_snapshot_evidence_invalid",
      "Hub State Snapshot does not prove hot data and the configured Metrics Archive boundary",
    );
  }
}

function assertLiveHubRestoreEvidence(
  restored,
  expectedManifestDigest,
  expectedBaselineImageDigest,
) {
  if (
    restored?.verify?.status !== "succeeded" ||
    restored.verify.manifestDigest !== expectedManifestDigest ||
    restored?.restore?.status !== "succeeded" ||
    restored.restore.manifestDigest !== expectedManifestDigest ||
    restored?.image?.expectedManifestDigest !== expectedBaselineImageDigest ||
    restored.image.activeManifestDigest !== expectedBaselineImageDigest
  ) {
    throw assertionError(
      "hub_state_restore_evidence_invalid",
      "Hub Restore did not verify and restore the snapshot before starting the exact Release Baseline image",
    );
  }
}

function assertSameProbeIdentity(before, after, boundary) {
  if (
    !before ||
    !after ||
    before.probeId !== after.probeId ||
    before.identitySha256 !== after.identitySha256
  ) {
    throw assertionError(
      "probe_identity_changed",
      `${boundary} changed the Probe Identity`,
    );
  }
}

function assertRepairScenarioParticipants(host, hub) {
  assertBaselineScenarioParticipants(host, hub);
  const hostMethods = [
    "armPostReplacementRestartFault",
    "assertPostReplacementUpgradeFailure",
    "completeRepairOwnershipTransition",
    "removePostReplacementRestartFault",
    "repair",
  ];
  if (
    hostMethods.some((method) => typeof host?.[method] !== "function") ||
    typeof hub?.getProbeOperation !== "function"
  ) {
    throw new Error(
      "Release E2E environment returned invalid post-replacement Repair participants",
    );
  }
}

function assertLifecycleAuditLog(auditLog, hostId, operationId) {
  const required = [
    {
      action: "enrollment_token.create",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.subjectType === "enrollment_token",
    },
    {
      action: "probe_configuration.host.override",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.subjectId === String(hostId),
    },
    {
      action: "host.delete",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.subjectId === String(hostId) &&
        event.subjectType === "host" &&
        event.details?.hostId === hostId &&
        event.details?.probeOperationId === operationId,
    },
  ];
  const selected = required.map(({ action, matches }) =>
    auditLog.find((event) => event?.action === action && matches(event)),
  );
  const missing = required
    .filter((_, index) => !selected[index])
    .map(({ action }) => action);
  if (missing.length > 0) {
    throw assertionError(
      "lifecycle_audit_log_missing",
      `Hub Audit Log is missing lifecycle evidence: ${missing.join(", ")}`,
    );
  }
  return selected;
}

function assertBaselineUpgradeAuditLog(
  auditLog,
  hostId,
  upgradeOperationId,
  uninstallOperationId,
  targetProbeVersion,
) {
  const lifecycle = assertLifecycleAuditLog(
    auditLog,
    hostId,
    uninstallOperationId,
  );
  const upgrade = auditLog.find(
    (event) =>
      event?.action === "probe_upgrade_request.create" &&
      isValidLifecycleAuditEvent(event) &&
      event.actor === "owner" &&
      event.outcome === "success" &&
      event.subjectId === String(upgradeOperationId) &&
      event.subjectType === "probe_upgrade_request" &&
      event.details?.hostId === hostId &&
      event.details?.targetProbeVersion === targetProbeVersion,
  );
  if (!upgrade) {
    throw assertionError(
      "lifecycle_audit_log_missing",
      "Hub Audit Log is missing the Owner-authorized Probe Upgrade",
    );
  }
  return [...lifecycle, upgrade];
}

function isValidLifecycleAuditEvent(event) {
  return (
    Number.isSafeInteger(event?.id) &&
    event.id > 0 &&
    Number.isSafeInteger(event.occurredAtMs) &&
    event.occurredAtMs > 0 &&
    typeof event.action === "string" &&
    event.action.length > 0 &&
    typeof event.subjectId === "string" &&
    event.subjectId.length > 0 &&
    typeof event.subjectType === "string" &&
    event.subjectType.length > 0
  );
}

export function validateSuccessfulProbeUpgradeTimeline(timeline) {
  if (!Array.isArray(timeline) || timeline.length < 2) {
    throw assertionError(
      "probe_upgrade_timeline_incomplete",
      "Probe Upgrade did not record its request and terminal operation evidence",
    );
  }
  const requested = timeline[0];
  if (
    requested?.state !== "pending" ||
    requested.acceptedAtMs !== null ||
    requested.runningAtMs !== null ||
    requested.completedAtMs !== null
  ) {
    throw assertionError(
      "probe_upgrade_request_invalid",
      "Probe Upgrade request did not begin as a pending operation",
    );
  }
  let previous = null;
  let terminal = null;
  for (const operation of timeline) {
    assertProbeOperation(operation, {
      hostId: requested.hostId,
      id: requested.id,
      kind: "probe_upgrade",
      targetProbeVersion: requested.targetProbeVersion,
    });
    if (previous) assertProbeOperationProgress(previous, operation);
    if (terminal) assertStableTerminalOperation(terminal, operation);
    if (!terminal && terminalProbeOperationStates.has(operation.state)) {
      terminal = operation;
    }
    previous = operation;
  }
  const finalOperation = timeline.at(-1);
  if (
    finalOperation?.acceptedAtMs === null ||
    finalOperation?.acceptedAtMs === undefined ||
    finalOperation?.runningAtMs === null ||
    finalOperation?.runningAtMs === undefined ||
    finalOperation?.completedAtMs === null ||
    finalOperation?.completedAtMs === undefined ||
    finalOperation?.state !== "succeeded" ||
    finalOperation.failure
  ) {
    throw assertionError(
      "probe_upgrade_timeline_incomplete",
      `Probe Upgrade did not preserve accepted, running, and succeeded transition evidence: ${JSON.stringify(timeline)}`,
    );
  }
}

function isNullableTimestamp(value) {
  return value === null || (Number.isSafeInteger(value) && value >= 0);
}

function hasValidOperationStateTimestamps(operation) {
  const accepted = operation.acceptedAtMs !== null;
  const running = operation.runningAtMs !== null;
  const completed = operation.completedAtMs !== null;
  if (running && !accepted) return false;
  if (completed && !accepted) return false;
  switch (operation.state) {
    case "pending":
      return !accepted && !running && !completed;
    case "accepted":
      return accepted && !running && !completed;
    case "running":
      return accepted && running && !completed;
    case "succeeded":
      return accepted && running && completed;
    case "failed":
      return accepted && completed;
    case "canceled":
      return !running && !completed;
    case "superseded":
      return !running && !completed;
    default:
      return false;
  }
}

async function proveProbeConfigurationRoundTrip({ hostId, hub, poll }) {
  const existing = await hub.getHostProbeConfiguration(hostId);
  const values = existing?.configuration;
  if (
    !values ||
    !Array.isArray(values.enabledCollectorIds) ||
    !Number.isSafeInteger(values.metricsCollectionIntervalSeconds) ||
    !values.enabledCollectorIds.includes("official.cpu") ||
    !values.enabledCollectorIds.includes("official.memory")
  ) {
    throw assertionError(
      "probe_configuration_invalid",
      "Hub returned an invalid Probe Configuration",
    );
  }
  const updated = await hub.updateHostProbeConfiguration(hostId, {
    configuration: {
      enabledCollectorIds: values.enabledCollectorIds,
      metricsCollectionIntervalSeconds:
        values.metricsCollectionIntervalSeconds === 2 ? 3 : 2,
    },
    mode: "override",
  });
  const version = updated?.configuration?.version;
  if (!version) {
    throw assertionError(
      "probe_configuration_version_missing",
      "Hub did not version the updated Probe Configuration",
    );
  }
  const reported = await waitForObservation({
    code: "probe_configuration_round_trip_timeout",
    label: `Probe Configuration ${version}`,
    observe: () => hub.getHost(hostId),
    poll,
    ready: (value) =>
      value?.reportedProbeConfigurationVersion === version &&
      !value.warnings?.some(
        (warning) => warning.code === "probe_configuration_error",
      ),
  });
  return {
    mode: updated.mode,
    reportedVersion: reported.reportedProbeConfigurationVersion,
    version,
  };
}

function metricsAdvanceBeyond(samples, previous) {
  const compact = compactMetricsEvidence(samples);
  const latest = compact.at(-1);
  return (
    latest?.sequence > previous?.sequence &&
    latest?.collectedAtMs > previous?.collectedAtMs
  );
}

function normalizedPollTiming(timing) {
  return {
    intervalMs: timing.intervalMs ?? 2_000,
    sleep: timing.sleep ?? defaultSleep,
    timeoutMs: timing.timeoutMs ?? 120_000,
  };
}

async function waitForObservation({ code, label, observe, poll, ready }) {
  const intervalMs = positiveDuration(poll.intervalMs, "poll interval");
  const timeoutMs = positiveDuration(poll.timeoutMs, "poll timeout");
  const maximumObservations = Math.floor(timeoutMs / intervalMs) + 1;
  let lastValue = null;
  let lastError = null;

  for (let attempt = 0; attempt < maximumObservations; attempt += 1) {
    try {
      lastValue = await observe();
      lastError = null;
      if (ready(lastValue)) return lastValue;
    } catch (error) {
      lastError = error;
    }
    if (attempt + 1 < maximumObservations) await poll.sleep(intervalMs);
  }

  const error = assertionError(
    code,
    `${label} was not observed within ${timeoutMs}ms${
      lastError ? `: ${lastError.message}` : ""
    }`,
  );
  error.lastValue = lastValue;
  throw error;
}

export function isCandidateHostReady(value, expectedProbeVersion) {
  const profile = value?.hostProfile;
  const nonEmptyString = (candidate) =>
    typeof candidate === "string" && candidate.trim().length > 0;
  return (
    value?.status === "online" &&
    profile &&
    nonEmptyString(profile.architecture) &&
    Number.isSafeInteger(profile.cpuCount) &&
    profile.cpuCount >= 1 &&
    profile.cpuCount <= 4_096 &&
    nonEmptyString(profile.hostname) &&
    nonEmptyString(profile.kernel) &&
    Number.isSafeInteger(profile.memoryTotalBytes) &&
    profile.memoryTotalBytes >= 1_048_576 &&
    nonEmptyString(profile.os) &&
    profile.probeVersion === expectedProbeVersion &&
    Array.isArray(profile.filesystems) &&
    Array.isArray(profile.networkInterfaces)
  );
}

function stableHostProfileEvidence(profile) {
  const projection = {
    architecture: profile.architecture,
    collectorCapabilities: canonicalSemanticValue(
      profile.collectorCapabilities ?? null,
    ),
    cpu: {
      baseFrequencyMhz: profile.cpuBaseFrequencyMhz ?? null,
      cacheL3Bytes: profile.cpuCacheL3Bytes ?? null,
      count: profile.cpuCount,
      model: profile.cpuModel ?? null,
      physicalCount: profile.cpuPhysicalCount ?? null,
      socketCount: profile.cpuSocketCount ?? null,
    },
    filesystems: profile.filesystems
      .map((filesystem) => ({
        filesystemType: filesystem.filesystemType,
        mountPoint: filesystem.mountPoint,
        totalBytes: filesystem.totalBytes,
      }))
      .sort((left, right) =>
        `${left.mountPoint}\0${left.filesystemType}`.localeCompare(
          `${right.mountPoint}\0${right.filesystemType}`,
        ),
      ),
    hostname: profile.hostname,
    kernel: profile.kernel,
    memoryTotalBytes: profile.memoryTotalBytes,
    networkInterfaces: profile.networkInterfaces
      .map((networkInterface) => ({
        addresses: [...new Set(networkInterface.addresses ?? [])].sort(),
        name: networkInterface.name,
      }))
      .sort((left, right) => left.name.localeCompare(right.name)),
    os: profile.os,
    probeVersion: profile.probeVersion,
  };
  const serialized = JSON.stringify(projection);
  return {
    projection,
    sha256: createHash("sha256").update(serialized).digest("hex"),
  };
}

function assertStableHostProfileContinuity(candidate, restored) {
  if (
    !candidate ||
    !restored ||
    candidate.sha256 !== restored.sha256 ||
    JSON.stringify(candidate.projection) !== JSON.stringify(restored.projection)
  ) {
    throw assertionError(
      "host_profile_stable_projection_changed",
      "Hub Restore changed the Candidate Probe Host Profile stable semantic projection",
    );
  }
}

function canonicalSemanticValue(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalSemanticValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, entryValue]) => entryValue !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entryValue]) => [key, canonicalSemanticValue(entryValue)]),
    );
  }
  return value;
}

export function hasAdvancingPortableMetrics(samples) {
  if (!Array.isArray(samples)) return false;
  const ordered = samples
    .filter(isPortableMetricSample)
    .sort((a, b) => a.sequence - b.sequence);
  if (ordered.length < 2) return false;
  const first = ordered[0];
  const last = ordered.at(-1);
  return (
    Number.isSafeInteger(first?.sequence) &&
    Number.isSafeInteger(last?.sequence) &&
    last.sequence > first.sequence &&
    Number.isFinite(first.collectedAtMs) &&
    Number.isFinite(last.collectedAtMs) &&
    last.collectedAtMs > first.collectedAtMs &&
    Number.isFinite(first.uptimeSeconds) &&
    Number.isFinite(last.uptimeSeconds) &&
    last.uptimeSeconds >= first.uptimeSeconds
  );
}

function isPortableMetricSample(sample) {
  return (
    Number.isSafeInteger(sample?.sequence) &&
    sample.sequence >= 0 &&
    Number.isSafeInteger(sample.collectedAtMs) &&
    sample.collectedAtMs > 0 &&
    Number.isFinite(sample.uptimeSeconds) &&
    sample.uptimeSeconds >= 0 &&
    Number.isFinite(sample.cpuPercent) &&
    sample.cpuPercent >= 0 &&
    sample.cpuPercent <= 100 &&
    Number.isSafeInteger(sample.memoryTotalBytes) &&
    sample.memoryTotalBytes > 0 &&
    Number.isSafeInteger(sample.memoryUsedBytes) &&
    sample.memoryUsedBytes >= 0 &&
    sample.memoryUsedBytes <= sample.memoryTotalBytes
  );
}

function compactHostEvidence(host) {
  return {
    hostProfile: host.hostProfile,
    id: host.id,
    status: host.status,
  };
}

function compactMetricsEvidence(samples) {
  const ordered = samples
    .filter(isPortableMetricSample)
    .sort((a, b) => a.sequence - b.sequence);
  return [ordered[0], ordered.at(-1)].map((sample) => ({
    collectedAtMs: sample.collectedAtMs,
    cpuPercent: sample.cpuPercent,
    memoryTotalBytes: sample.memoryTotalBytes,
    memoryUsedBytes: sample.memoryUsedBytes,
    sequence: sample.sequence,
    uptimeSeconds: sample.uptimeSeconds,
  }));
}

function latestPortableMetric(samples) {
  if (!Array.isArray(samples)) return null;
  return (
    samples
      .filter(isPortableMetricSample)
      .sort((left, right) => left.sequence - right.sequence)
      .at(-1) ?? null
  );
}

function assertionError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function serializedError(error) {
  const serialized = {
    code: error?.code ?? "error",
    message: error instanceof Error ? error.message : String(error),
  };
  if (error instanceof AggregateError) {
    serialized.errors = error.errors.map((nested) => serializedError(nested));
  }
  return serialized;
}

function redactSensitiveEvidence(value, secrets, key = "") {
  if (
    key &&
    /(?:authorization|cookie|enrollment.?token|headers?|owner.?password|signing.?secret)/i.test(
      key,
    )
  ) {
    return "[REDACTED]";
  }
  if (typeof value === "string") {
    return redactSensitiveText(value, secrets);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveEvidence(item, secrets));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, child]) => [
        childKey,
        redactSensitiveEvidence(child, secrets, childKey),
      ]),
    );
  }
  return value;
}

function redactSensitiveText(value, secrets) {
  let redacted = String(value ?? "");
  for (const secret of secrets) {
    if (secret) redacted = redacted.replaceAll(secret, "[REDACTED]");
  }
  return redacted
    .replace(/enk_enroll_[A-Za-z0-9_-]+/g, "[REDACTED_ENROLLMENT_TOKEN]")
    .replace(
      /(authorization\s*[:=]\s*)(?:Bearer\s+)?[^\s,;]+/gi,
      "$1[REDACTED]",
    )
    .replace(/(cookie\s*[:=]\s*)[^\s,;]+/gi, "$1[REDACTED]")
    .replace(
      /(ENOKI_ENROLLMENT_TOKEN\s*=\s*)('[^']*'|"[^"]*"|[^\s]+)/g,
      "$1[REDACTED]",
    );
}

function cleanupDidNotSucceed(cleanup) {
  return Object.values(cleanup).some(
    (result) => result?.error || result?.clean !== true,
  );
}
