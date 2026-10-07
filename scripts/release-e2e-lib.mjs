import { createHash } from "node:crypto";

import { probeTargets } from "@enoki/probe-release";

import { validateReleaseCatalogSnapshot } from "./release-baseline-lib.mjs";
import {
  hasAdvancingPortableMetrics,
  isCandidateHostReady,
  isPortableMetricSample,
} from "./release-evidence-judgments.ts";
import {
  assertEnrollmentInstallContract,
  assertExactObjectKeys,
  assertHostInventoryEvidence,
  assertInstallCommand,
  assertProbeOperation,
  assertRunId,
  assertionError,
  createProbeHostHarness,
  inventoryResidue,
  parseJson,
  parseKeyValues,
  probeOperationStateRank,
  renderReleaseE2EResourceFingerprint,
  serializedError,
} from "./release-host-harness.ts";
import { proveInstalledBundleFailureRepair } from "./release-installed-bundle-failure-repair.ts";
import { isPositiveSafeInteger } from "./release-json-guards.ts";

export { createProbeHostHarness, renderReleaseE2EResourceFingerprint };

const terminalProbeOperationStates = new Set([
  "succeeded",
  "failed",
  "superseded",
  "canceled",
]);

const hubHostOfflineAfterLocalUninstallMs = 90_000;
const localUninstallOfflineObservationHeadroomMs = 30_000;
const defaultLocalUninstallOfflineObservationTimeoutMs =
  hubHostOfflineAfterLocalUninstallMs +
  localUninstallOfflineObservationHeadroomMs;

export const releaseE2EScenarioRegistry = Object.freeze({
  "compatible-upgrade-uninstall": runCompatibleUpgradeUninstallScenario,
  "fresh-install-uninstall": runFreshInstallUninstallScenario,
  "hub-restore-compatibility-window": runHubRestoreCompatibilityWindowScenario,
  "post-replacement-repair-uninstall":
    runPostReplacementRepairUninstallScenario,
  "replacement-migration-uninstall": runReplacementMigrationUninstallScenario,
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
    auditLog: null,
    baselineInstall: null,
    candidate: candidateManifest.candidate,
    cleanup: null,
    failureBoundary: null,
    hostEvidence: null,
    hubEvidence: null,
    hostProfileContinuity: {
      allowedChanges: [
        "collection and observation timestamps",
        "cpuBaseFrequencyMhz",
        "filesystems[].availableBytes",
        "networkInterfaces with veth names",
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
    migrationRetention: null,
    phase: "scenario-running",
    protocol: {
      baselineProbeToCandidateHub: "pending",
      candidateProbeToBaselineHub: "pending",
    },
    probeConfiguration: { beforeReplacement: null, retained: null },
    releaseBaseline: releaseBaselineEvidence(baseline),
    releaseTestHost: null,
    reporting: {
      candidateHub: null,
      postReplacementCandidateHub: null,
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
    evidence.baselineInstall = await host.install(enrollment, runId);
    await host.assertInstalled(runId, releaseBaselineProbeVersion(baseline));
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
    const baselineIdentity = await host.readProbeIdentity(runId);
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
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
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
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
    });
    evidence.protocol.baselineProbeToCandidateHub = "succeeded";
    const probeBeforeRestoreVersion = candidateManifest.probeAssetSet.version;
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
    await host.assertInstalled(runId, probeBeforeRestoreVersion);
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
        isCandidateHostReady(value, probeBeforeRestoreVersion),
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
        isCandidateHostReady(value, probeBeforeRestoreVersion),
    });
    evidence.hostProfileContinuity.restoredBaseline = stableHostProfileEvidence(
      restoredHost.hostProfile,
    );
    assertStableHostProfileContinuity(
      evidence.hostProfileContinuity.candidateBeforeRestore,
      evidence.hostProfileContinuity.restoredBaseline,
    );
    await host.assertInstalled(runId, probeBeforeRestoreVersion);
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
    await hub.switchToCandidate();
    await hub.authenticate(ownerPassword);
    await waitForObservation({
      code: "candidate_probe_post_restore_hub_timeout",
      label: "Candidate Probe reporting after returning to Candidate Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version),
    });
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
        `Probe Uninstall after Hub Restore did not succeed: ${JSON.stringify(finalUninstall)}`,
      );
    }
    evidence.uninstall.hubSoftDeleted = await hub.isHostSoftDeleted(hostId);
    if (!evidence.uninstall.hubSoftDeleted) {
      throw assertionError(
        "host_not_soft_deleted",
        "Probe Uninstall after Hub Restore succeeded but the Host remains active",
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
    finalEvidence = redactReleaseE2EEvidence(evidence, {
      candidateManifest,
      secrets: [ownerPassword],
    });
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
    baselineInstall: null,
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
    releaseBaseline: releaseBaselineEvidence(baseline),
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
    evidence.baselineInstall = await host.install(enrollment, runId);
    await host.assertInstalled(runId, releaseBaselineProbeVersion(baseline));
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
    const baselineIdentity = await host.readProbeIdentity(runId);
    await waitForObservation({
      code: "repair_baseline_reporting_timeout",
      label: "Release Baseline Probe reporting before Repair scenario Upgrade",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
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
    await hub.switchToCandidate();
    await hub.authenticate(ownerPassword);
    await waitForObservation({
      code: "repair_baseline_probe_candidate_hub_compatibility_timeout",
      label: "Release Baseline Probe reporting to Candidate Hub before Repair",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
    });
    evidence.probeConfiguration.beforeUpgrade =
      await proveProbeConfigurationRoundTrip({ hostId, hub, poll });

    const candidateProbeVersion = candidateManifest.probeAssetSet.version;
    const repairIdentity = baselineIdentity;
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
    evidence.failureBoundary = await waitForObservation({
      code: "post_replacement_upgrade_failure_timeout",
      label: "local post-replacement Upgrade failure before Repair",
      observe: () =>
        host.assertPostReplacementUpgradeFailure(
          runId,
          requestedUpgrade,
          candidateProbeVersion,
        ),
      poll,
      ready: (value) =>
        value?.localFailureCode === "post_replacement_restart_failure" &&
        value.operationId === requestedUpgrade.id &&
        value.probeVersion === candidateProbeVersion,
    });
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
      repairedIdentity.probeId !== repairIdentity.probeId ||
      repairedIdentity.identitySha256 !== repairIdentity.identitySha256
    ) {
      throw assertionError(
        "probe_identity_changed",
        "Probe Repair changed the Probe Identity",
      );
    }
    evidence.identityContinuity = {
      after: repairedIdentity,
      before: repairIdentity,
      hostId,
    };
    evidence.operationTimeline = await hub.waitForProbeOperation(
      requestedUpgrade,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    const failedUpgrade = evidence.operationTimeline.at(-1);
    if (failedUpgrade?.state !== "failed" || !failedUpgrade.failure) {
      throw assertionError(
        "post_replacement_upgrade_not_failed",
        `Probe Upgrade did not retain a failed operation after Repair: ${JSON.stringify(failedUpgrade)}`,
      );
    }
    evidence.failureBoundary.hubFailureCode = failedUpgrade.failure.code;
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
    const auditLog = await hub.getAuditLog();
    evidence.auditLog = assertBaselineUpgradeAuditLog(
      auditLog,
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
      if (
        error.timeline.some(
          (operation) => operation?.kind === "probe_uninstall",
        )
      ) {
        evidence.uninstallOperationTimeline = error.timeline;
        evidence.uninstall.operationTimeline = error.timeline;
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
    finalEvidence = redactReleaseE2EEvidence(evidence, {
      candidateManifest,
      secrets: [ownerPassword],
    });
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
  if (repairedSudoers !== "") {
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
    "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
    "/var/lib/enoki-probe-bootstrap",
    "/etc/enoki/probe-install.toml",
    "/etc/systemd/system/enoki-probe.service",
    "/var/lib/enoki-probe",
    "enoki-probe.service",
  ];
  if (
    installed?.probeVersion !== candidateManifest.probeAssetSet.version ||
    installedResidue.some((entry) =>
      entry.startsWith("/etc/sudoers.d/enoki-probe"),
    ) ||
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

async function runCompatibleUpgradeUninstallScenario(options) {
  return runForwardLifecycleScenario({
    ...options,
    transitionClassification: "compatible",
  });
}

async function runReplacementMigrationUninstallScenario(options) {
  return runForwardLifecycleScenario({
    ...options,
    transitionClassification: "replacement-required",
  });
}

async function runForwardLifecycleScenario({
  candidateManifest,
  environment,
  evidenceSink,
  ownerPassword,
  runId,
  scenario,
  timing = {},
  transitionClassification,
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
    baselineInstall: null,
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
    manualRecovery: null,
    migrationRetention: null,
    operationTimeline: [],
    phase: "scenario-running",
    probeConfiguration: { afterUpgrade: null, beforeUpgrade: null },
    releaseBaseline: releaseBaselineEvidence(baseline),
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
    assertBaselineScenarioParticipants(host, hub, transitionClassification);
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
    evidence.baselineInstall = await host.install(enrollment, runId);
    await host.assertInstalled(runId, releaseBaselineProbeVersion(baseline));

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
    const baselineIdentity = await host.readProbeIdentity(runId);
    await waitForObservation({
      code: "baseline_host_core_reporting_timeout",
      label: "Release Baseline Probe reporting to the Release Baseline Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
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
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
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
    const configuredCompatibleHost = await waitForObservation({
      code: "baseline_probe_configuration_projection_timeout",
      label: "Release Baseline Probe Configuration reporting projection",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)) &&
        value.reportedProbeConfigurationVersion ===
          evidence.probeConfiguration.beforeUpgrade.reportedVersion,
    });
    const baselineHostProjection = stableHubHostProjection(
      configuredCompatibleHost,
    );
    const baselineMetricHistory = metricsHistoryEvidence(beforeMetrics);
    evidence.compatibility = {
      host: compactHostEvidence(configuredCompatibleHost),
      status: "succeeded",
    };

    const replacementRequired =
      transitionClassification === "replacement-required";
    let requestedUpgrade = null;
    let finalUpgrade = null;
    if (replacementRequired) {
      const replacementEnrollment =
        await hub.createManualReinstallEnrollment(hostId);
      if (!replacementEnrollment?.installCommand) {
        throw assertionError(
          "manual_reinstall_enrollment_command_missing",
          "Candidate Hub did not return the production manual Probe reinstall command",
        );
      }
      evidence.manualRecovery = {
        enrollmentId: replacementEnrollment.enrollmentId,
        hostId,
        kind: "trust_epoch_manual_reinstall",
        result: await host.manualReinstall(replacementEnrollment, runId),
      };
    } else {
      await host.beginUpgradeOwnershipTransition(
        runId,
        candidateManifest.probeAssetSet.version,
      );
      requestedUpgrade = await hub.requestProbeUpgrade(hostId);
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
      finalUpgrade = evidence.upgradeOperationTimeline.at(-1);
      if (finalUpgrade?.state === "failed") {
        validateInsufficientPrivilegeProbeUpgradeTimeline(
          evidence.upgradeOperationTimeline,
        );
        throw assertionError(
          "compatible_probe_upgrade_failed",
          `Compatible Probe Upgrade failed without fallback: ${JSON.stringify(finalUpgrade)}`,
        );
      } else {
        validateSuccessfulProbeUpgradeTimeline(
          evidence.upgradeOperationTimeline,
        );
      }
    }

    const candidateHost = await waitForObservation({
      code: replacementRequired
        ? "candidate_probe_configuration_retention_timeout"
        : "candidate_probe_reporting_timeout",
      label: replacementRequired
        ? "Candidate Probe retained Configuration after manual reinstall"
        : "Candidate Probe Host Profile after Upgrade",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version) &&
        (!replacementRequired ||
          (value.reportedProbeConfigurationVersion ===
            evidence.probeConfiguration.beforeUpgrade.reportedVersion &&
            !value.warnings?.some(
              (warning) => warning.code === "probe_configuration_error",
            ))),
    });
    evidence.candidateHost = compactHostEvidence(candidateHost);
    evidence.hostBoundary = await host.assertInstalled(
      runId,
      candidateManifest.probeAssetSet.version,
    );
    const candidateIdentity = await host.readProbeIdentity(runId);
    if (
      replacementRequired
        ? candidateIdentity.probeId === baselineIdentity.probeId ||
          candidateIdentity.identitySha256 === baselineIdentity.identitySha256
        : candidateIdentity.probeId !== baselineIdentity.probeId ||
          candidateIdentity.identitySha256 !== baselineIdentity.identitySha256
    ) {
      throw assertionError(
        "probe_identity_epoch_mismatch",
        replacementRequired
          ? "Trust Epoch manual reinstall did not replace Probe identity and credentials"
          : "Probe Upgrade changed the Probe identity or credentials",
      );
    }
    evidence.identityContinuity = {
      after: candidateIdentity,
      before: baselineIdentity,
      hostId,
    };
    if (replacementRequired) {
      const retainedConfiguration = await hub.getHostProbeConfiguration(hostId);
      if (
        !sameEffectiveProbeConfiguration(
          retainedConfiguration,
          evidence.probeConfiguration.beforeUpgrade,
        )
      ) {
        throw assertionError(
          "manual_reinstall_configuration_not_retained",
          "Trust Epoch manual reinstall did not retain the Host Probe Configuration",
        );
      }
      const candidateHostProjection = stableHubHostProjection(candidateHost);
      if (
        candidateHostProjection.id !== baselineHostProjection.id ||
        JSON.stringify(candidateHostProjection.hostMetadata) !==
          JSON.stringify(baselineHostProjection.hostMetadata)
      ) {
        throw assertionError(
          "manual_reinstall_host_metadata_not_retained",
          "Trust Epoch manual reinstall did not retain Host identity and metadata",
        );
      }
      evidence.migrationRetention = {
        configuration: effectiveProbeConfigurationEvidence(
          retainedConfiguration,
        ),
        hostAfter: candidateHostProjection,
        hostBefore: baselineHostProjection,
        metricHistory: baselineMetricHistory,
        postMetricHistory: null,
      };
    }
    if (!replacementRequired) {
      await host.completeUpgradeOwnershipTransition(runId, finalUpgrade);
    }

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
    if (
      replacementRequired &&
      !retainsMetricHistoryAnchors(afterMetrics, baselineMetricHistory.anchors)
    ) {
      throw assertionError(
        "manual_reinstall_metric_history_not_retained",
        "Trust Epoch manual reinstall did not retain pre-replacement Metrics history",
      );
    }
    if (replacementRequired) {
      evidence.migrationRetention.postMetricHistory = metricsHistoryEvidence(
        afterMetrics,
        { retain: baselineMetricHistory.anchors },
      );
    }
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
    const auditLog = await hub.getAuditLog();
    evidence.auditLog = replacementRequired
      ? assertMigrationLifecycleAuditLog(
          auditLog,
          hostId,
          requestedUninstall.id,
          baselineIdentity,
          candidateIdentity,
        )
      : assertBaselineUpgradeAuditLog(
          auditLog,
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
    finalEvidence = redactReleaseE2EEvidence(evidence, {
      candidateManifest,
      secrets: [ownerPassword],
    });
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
  const offlinePoll = localUninstallOfflineObservationPoll(timing, poll);
  const evidence = {
    auditLog: null,
    candidate: candidateManifest.candidate,
    candidateIdentities: {
      hubDigest: candidateManifest.hub.digest,
      probeAssetSetVersion: candidateManifest.probeAssetSet.version,
    },
    cleanup: null,
    canonicalRuntimeUnavailableReporting: null,
    diagnostics: null,
    finalLocalUninstall: null,
    host: null,
    hostBoundary: null,
    hostEvidence: null,
    hubOnlyDeletion: null,
    hubEvidence: null,
    initialInstall: null,
    infrastructure: null,
    installedBundleFailureRepair: null,
    localUninstall: null,
    metrics: null,
    metricsHistory: null,
    phase: "scenario-running",
    probeConfiguration: null,
    reEnrollment: null,
    releaseBaseline: releaseBaselineEvidence(candidateManifest.releaseBaseline),
    releaseTestHost: null,
    repeatedAdd: null,
    result: { status: "running" },
    runId,
    scenario,
    schemaVersion: 2,
  };
  let resources = null;
  let primaryError = null;
  let evidenceWriteError = null;
  let finalEvidence = evidence;

  try {
    resources = await environment.start({ candidateManifest, runId });
    const { host, hub } = resources ?? {};
    assertFreshInstallScenarioParticipants(host, hub);
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

    const newHostTarget = { kind: "new_host" };
    const enrollment = await hub.createEnrollment(newHostTarget);
    assertCreatedEnrollment(enrollment, newHostTarget);
    const initialInstall = await host.install(enrollment, runId);
    evidence.initialInstall = initialInstall;
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
    const initialIdentity = await host.readProbeIdentity(runId);

    const samples = await waitForObservation({
      code: "metrics_progression_timeout",
      label: "two advancing portable Metrics samples",
      observe: () => hub.getHostMetrics(hostId, { window: "24h" }),
      poll,
      ready: hasAdvancingPortableMetrics,
    });
    evidence.metrics = compactMetricsEvidence(samples);
    evidence.metricsHistory = metricsHistoryEvidence(samples);

    evidence.probeConfiguration = await proveProbeConfigurationRoundTrip({
      hostId,
      hub,
      poll,
    });

    evidence.installedBundleFailureRepair =
      await proveInstalledBundleFailureRepair({
        expectedBundleVersion: candidateManifest.probeAssetSet.version,
        host,
        hostId,
        identityBefore: initialIdentity,
        observeReadyHost: async () =>
          compactHostEvidence(
            await waitForObservation({
              code: "installed_bundle_repair_reporting_timeout",
              label:
                "Candidate Probe reporting after Installed Bundle Failure Repair",
              observe: () => hub.getHost(hostId),
              poll,
              ready: (value) =>
                value?.id === hostId &&
                isCandidateHostReady(
                  value,
                  candidateManifest.probeAssetSet.version,
                ),
            }),
          ),
        runId,
      });

    const repeatedEnrollment = await hub.createEnrollment(newHostTarget);
    assertCreatedEnrollment(repeatedEnrollment, newHostTarget);
    const hostBeforeRepeatedAdd = stableHubHostProjection(
      await hub.getHost(hostId),
    );
    const stateBeforeRepeatedAdd = await host.captureInstallationState(runId);
    const rejection = await host.rejectRepeatedInstall(
      repeatedEnrollment,
      runId,
    );
    const stateAfterRepeatedAdd = await host.captureInstallationState(runId);
    if (
      JSON.stringify(stateAfterRepeatedAdd) !==
      JSON.stringify(stateBeforeRepeatedAdd)
    ) {
      throw assertionError(
        "repeated_add_mutated_installation",
        "Ordinary repeated Add changed the installed Probe boundary",
      );
    }
    const hostAfterRepeatedAdd = stableHubHostProjection(
      await hub.getHost(hostId),
    );
    if (
      JSON.stringify(hostAfterRepeatedAdd) !==
      JSON.stringify(hostBeforeRepeatedAdd)
    ) {
      throw assertionError(
        "repeated_add_mutated_hub_host",
        "Ordinary repeated Add changed the stable Hub Host projection",
      );
    }
    const rejectedEnrollment = await waitForObservation({
      code: "repeated_add_rejection_timeout",
      label: "terminal repeated Add rejection",
      observe: () => hub.getEnrollment(repeatedEnrollment.enrollmentId),
      poll,
      ready: (value) =>
        value?.status === "rejected" &&
        value?.rejection?.code === "existing_probe_installation",
    });
    evidence.repeatedAdd = {
      enrollment: compactEnrollmentEvidence(repeatedEnrollment),
      enrollmentStatus: compactEnrollmentStatusEvidence(rejectedEnrollment),
      rejection,
      hostAfter: hostAfterRepeatedAdd,
      hostBefore: hostBeforeRepeatedAdd,
      stateAfter: stateAfterRepeatedAdd,
      stateBefore: stateBeforeRepeatedAdd,
    };

    const localUninstall = await host.localUninstall(runId);
    assertLocalUninstallCompletion(localUninstall?.completion);
    const hostAfterLocalUninstall = await hub.getHost(hostId);
    if (
      hostAfterLocalUninstall?.id !== hostId ||
      hostAfterLocalUninstall?.status === "offline"
    ) {
      throw assertionError(
        "local_uninstall_host_not_active",
        "Local Probe Uninstall did not leave an active non-offline Hub Host before bounded offline observation",
      );
    }
    const offlineHost = await waitForObservation({
      code: "host_offline_after_local_uninstall_timeout",
      label: "active Host becoming offline after Local Probe Uninstall",
      observe: () => hub.getHost(hostId),
      poll: offlinePoll,
      ready: (value) => value?.id === hostId && value?.status === "offline",
    });
    evidence.localUninstall = {
      activeHost: compactHostEvidence(hostAfterLocalUninstall),
      completion: localUninstall.completion,
      offlineHost: compactHostEvidence(offlineHost),
      output: localUninstall.output,
    };

    const existingHostTarget = { hostId, kind: "existing_host" };
    const reEnrollment = await hub.createEnrollment(existingHostTarget);
    assertCreatedEnrollment(reEnrollment, existingHostTarget);
    const reEnrollmentInstall = await host.install(reEnrollment, runId);
    const reEnrollmentBoundary = await host.assertInstalled(
      runId,
      candidateManifest.probeAssetSet.version,
    );
    const reEnrollmentIdentity = await host.readProbeIdentity(runId);
    if (
      reEnrollmentIdentity.probeId === initialIdentity.probeId ||
      reEnrollmentIdentity.identitySha256 === initialIdentity.identitySha256
    ) {
      throw assertionError(
        "reenrollment_identity_not_replaced",
        "Host Re-enrollment did not replace the Probe Identity",
      );
    }
    const renewed = await waitForObservation({
      code: "host_reenrollment_timeout",
      label: "re-enrolled Host with renewed readiness",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version),
    });
    const reEnrollmentMetrics = await waitForObservation({
      code: "reenrollment_metrics_progression_timeout",
      label: "new portable Metrics after Host Re-enrollment",
      observe: () => hub.getHostMetrics(hostId, { window: "24h" }),
      poll,
      ready: (value) =>
        hasAdvancingPortableMetrics(value) &&
        hasPortableMetricsAfter(value, samples) &&
        retainsInitialMetricSample(value, samples) &&
        retainsMetricHistoryAnchors(value, evidence.metricsHistory.anchors),
    });
    const reEnrollmentConfiguration =
      await hub.getHostProbeConfiguration(hostId);
    if (
      !sameEffectiveProbeConfiguration(
        reEnrollmentConfiguration,
        evidence.probeConfiguration,
      )
    ) {
      throw assertionError(
        "reenrollment_configuration_not_preserved",
        "Host Re-enrollment did not preserve Owner Probe Configuration",
      );
    }
    evidence.reEnrollment = {
      enrollment: compactEnrollmentEvidence(reEnrollment),
      host: compactHostEvidence(renewed),
      hostBoundary: reEnrollmentBoundary,
      hostId,
      identity: { after: reEnrollmentIdentity, before: initialIdentity },
      installer: reEnrollmentInstall,
      metrics: compactMetricsEvidence(reEnrollmentMetrics),
      metricsHistory: metricsHistoryEvidence(reEnrollmentMetrics, {
        retain: evidence.metricsHistory.anchors,
      }),
      probeConfiguration: reEnrollmentConfiguration,
    };

    const canonicalReports = resources?.canonicalReports;
    if (
      typeof canonicalReports?.arm !== "function" ||
      typeof canonicalReports?.waitForEvidence !== "function" ||
      typeof canonicalReports?.diagnostics !== "function" ||
      typeof host.restartCanonicalProbeWithoutObservationRuntime !==
        "function" ||
      typeof host.restoreObservationRuntime !== "function"
    ) {
      throw assertionError(
        "canonical_report_evidence_unavailable",
        "Release E2E environment lacks canonical report response-loss evidence",
      );
    }
    canonicalReports.arm({ expectedProbeId: reEnrollmentIdentity.probeId });
    let canonicalHostEvidence;
    let canonicalReporting;
    let metricsAfterCanonicalFailure;
    let restoreError = null;
    try {
      canonicalHostEvidence =
        await host.restartCanonicalProbeWithoutObservationRuntime(
          runId,
          reEnrollmentIdentity.probeId,
        );
      canonicalReporting = await canonicalReports.waitForEvidence({
        timeoutMs: timing.canonicalReportTimeoutMs ?? 90_000,
      });
      metricsAfterCanonicalFailure = await hub.getHostMetrics(hostId, {
        window: "24h",
      });
      if (
        JSON.stringify(
          portableMetricIdentities(metricsAfterCanonicalFailure),
        ) !== JSON.stringify(portableMetricIdentities(reEnrollmentMetrics))
      ) {
        throw assertionError(
          "canonical_runtime_unavailable_created_metrics",
          "Accepted ObservationWindowFailure created or changed Metrics",
        );
      }
    } finally {
      try {
        await host.restoreObservationRuntime(runId);
      } catch (error) {
        restoreError = error;
      }
    }
    if (restoreError) throw restoreError;
    const canonicalOwnerHost = await waitForObservation({
      code: "canonical_runtime_unavailable_owner_projection_timeout",
      label: "canonical Probe online after accepted Runtime-unavailable report",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        value?.status === "online" &&
        value?.reportedProbeConfigurationVersion ===
          canonicalReporting.bootReport.reconciliation
            .currentProbeConfigurationVersion,
    });
    evidence.canonicalRuntimeUnavailableReporting = {
      host: canonicalHostEvidence,
      ownerProjection: {
        host: compactHostEvidence(canonicalOwnerHost),
        metricsUnchanged: true,
        reportedProbeConfigurationVersion:
          canonicalOwnerHost.reportedProbeConfigurationVersion,
      },
      reporting: canonicalReporting,
    };

    const deletedHost = await hub.deleteHostHubOnly(hostId);
    const deleted = await waitForObservation({
      code: "hub_only_host_deletion_timeout",
      label: "Hub-only Host removal",
      observe: () => hub.isHostSoftDeleted(hostId),
      poll,
      ready: (value) => value === true,
    });
    if (deleted !== true || deletedHost?.id !== hostId) {
      throw assertionError(
        "hub_only_host_deletion_invalid",
        "Hub-only deletion did not remove the expected Host",
      );
    }
    const permanentReportRejection =
      await host.awaitPermanentReportRejection(runId);
    evidence.diagnostics = {
      host: await host.collectDiagnostics(runId),
      hub: await hub.collectEvidence(),
    };
    evidence.hubOnlyDeletion = {
      deletedHost,
      permanentReportRejection,
    };

    const finalLocalUninstall = await host.localUninstall(runId);
    assertLocalUninstallCompletion(finalLocalUninstall?.completion);
    evidence.finalLocalUninstall = finalLocalUninstall;
    evidence.auditLog = assertFreshLifecycleAuditLog(
      await hub.getAuditLog(),
      hostId,
    );
    evidence.result = { status: "succeeded" };
    evidence.phase = "succeeded";
  } catch (error) {
    primaryError = error;
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
    if (evidence.diagnostics === null && resources?.host?.collectDiagnostics) {
      try {
        evidence.diagnostics = {
          host: await resources.host.collectDiagnostics(runId),
          hub: resources?.hub?.collectEvidence
            ? await resources.hub.collectEvidence()
            : null,
        };
      } catch (error) {
        evidence.diagnostics = { error: serializedError(error) };
      }
    }
    if (resources?.canonicalReports?.diagnostics) {
      const transport = resources.canonicalReports.diagnostics();
      evidence.diagnostics = {
        ...(evidence.diagnostics && typeof evidence.diagnostics === "object"
          ? evidence.diagnostics
          : {}),
        transport,
      };
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
    finalEvidence = redactReleaseE2EEvidence(evidence, {
      candidateManifest,
      secrets: [ownerPassword],
    });
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
  const enrollments = new Map();
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

  async function readTrackedEnrollment(enrollmentId) {
    const { body } = await request(`/api/web/enrollments/${enrollmentId}`);
    assertEnrollmentStatus(body, enrollmentId);
    recordEnrollmentEvidence(enrollments, body);
    return body;
  }

  async function refreshTrackedEnrollment(enrollmentId) {
    try {
      await readTrackedEnrollment(enrollmentId);
    } catch (error) {
      const previous = enrollments.get(enrollmentId);
      enrollments.set(enrollmentId, {
        ...previous,
        enrollmentId,
        readError: serializedError(error),
      });
    }
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
      await Promise.all(
        [...enrollments.keys()].map((enrollmentId) =>
          refreshTrackedEnrollment(enrollmentId),
        ),
      );
      return {
        apiTimeline: [...apiTimeline],
        enrollments: [...enrollments.values()],
      };
    },

    async createEnrollment(target) {
      if (target !== undefined) assertEnrollmentTarget(target);
      const { body } = await request("/api/web/enrollments", {
        ...(target === undefined ? {} : { body: JSON.stringify({ target }) }),
        method: "POST",
      });
      if (
        typeof body?.enrollmentToken !== "string" ||
        typeof body?.installCommand !== "string"
      ) {
        throw new Error("Hub returned an invalid Enrollment response");
      }
      assertEnrollmentInstallContract(body);
      recordEnrollmentEvidence(enrollments, body);
      return body;
    },

    async createManualReinstallEnrollment(hostId) {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(
        `/api/web/enrollments/manual-reinstall/${hostId}`,
        { method: "POST" },
      );
      if (
        typeof body?.enrollmentToken !== "string" ||
        typeof body?.installCommand !== "string"
      ) {
        throw new Error(
          "Hub returned an invalid manual Probe reinstall Enrollment response",
        );
      }
      assertEnrollmentInstallContract(body);
      assertEnrollmentTarget(body.target);
      if (
        body.target.kind !== "manual_reinstall" ||
        body.target.hostId !== hostId
      ) {
        throw new Error("Hub manual Probe reinstall Enrollment target changed");
      }
      recordEnrollmentEvidence(enrollments, body);
      return body;
    },

    async deleteHostHubOnly(hostId) {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(`/api/web/hosts/${hostId}?mode=hub-only`, {
        method: "DELETE",
      });
      const deleted = body?.deletedHost;
      if (
        deleted?.id !== hostId ||
        !Number.isSafeInteger(deleted?.deletedAtMs) ||
        deleted.deletedAtMs < 0
      ) {
        throw new Error("Hub returned an invalid Hub-only Host deletion");
      }
      return deleted;
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

    async getEnrollment(enrollmentId) {
      assertEnrollmentId(enrollmentId);
      return readTrackedEnrollment(enrollmentId);
    },

    async getHostMetrics(hostId, { window = "1m" } = {}) {
      assertPositiveInteger(hostId, "Host ID");
      assertMetricsWindow(window);
      const { body } = await request(
        `/api/web/hosts/${hostId}/metrics?window=${window}`,
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
        ...normalizeProbeUninstallOperation(operation),
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
          const operation =
            expectedOperation.kind === "probe_uninstall"
              ? normalizeProbeUninstallOperation(body?.probeOperation)
              : body?.probeOperation;
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

function normalizeProbeUninstallOperation(operation) {
  return {
    ...operation,
    targetProbeVersion: operation?.targetProbeVersion ?? "",
  };
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

function assertEnrollmentTarget(target) {
  if (target?.kind === "new_host" && Object.keys(target).length === 1) {
    return;
  }
  if (
    (target?.kind === "existing_host" || target?.kind === "manual_reinstall") &&
    Object.keys(target).sort().join(",") === "hostId,kind" &&
    Number.isSafeInteger(target.hostId) &&
    target.hostId > 0
  ) {
    return;
  }
  throw new Error("Enrollment target is invalid");
}

function assertEnrollmentId(value) {
  if (!/^enr_[A-Za-z0-9_-]{16,}$/.test(value ?? "")) {
    throw new Error("Enrollment ID is invalid");
  }
}

function assertEnrollmentStatus(value, enrollmentId) {
  const validRejection =
    value?.rejection === null ||
    (typeof value?.rejection?.code === "string" &&
      value.rejection.code.length > 0 &&
      value.rejection.code.length <= 64 &&
      (value.rejection.message === null ||
        (typeof value.rejection.message === "string" &&
          value.rejection.message.length > 0 &&
          value.rejection.message.length <= 512)));
  if (
    value?.enrollmentId !== enrollmentId ||
    !["pending", "verifying", "ready", "rejected", "expired"].includes(
      value?.status,
    ) ||
    (value.hostId !== null &&
      (!Number.isSafeInteger(value.hostId) || value.hostId < 1)) ||
    !validRejection
  ) {
    throw new Error("Hub returned an invalid Enrollment status");
  }
  assertEnrollmentTarget(value.target);
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
  assertExactObjectKeys(manifest, [
    "bootstrapRecipe",
    "candidate",
    "hub",
    "kind",
    "probeAssetSet",
    "releaseBaseline",
    "schemaVersion",
  ]);
  assertExactObjectKeys(manifest.candidate, ["commit", "version"]);
  assertExactObjectKeys(manifest.hub, [
    "archive",
    "archiveSha256",
    "digest",
    "embeddedProbeVersion",
    "size",
  ]);
  assertExactObjectKeys(manifest.probeAssetSet, [
    "directory",
    "files",
    "signingIdentity",
    "version",
  ]);
  assertExactObjectKeys(manifest.probeAssetSet.signingIdentity, [
    "algorithm",
    "publicKeyFile",
    "publicKeySha256",
  ]);
  const bootstrapRecipe = manifest.bootstrapRecipe;
  assertExactObjectKeys(bootstrapRecipe, [
    "bundleVersion",
    "distribution",
    "file",
    "kind",
    "recordFile",
    "recordSha256",
    "recordSize",
    "rootFingerprint",
    "schemaVersion",
    "sha256",
    "size",
    "targets",
    "version",
  ]);
  const candidateVersion = manifest.candidate.version;
  const probeVersion = manifest.probeAssetSet.version;
  const releaseBaseline = assertReleaseBaselineDescriptor(
    manifest.releaseBaseline,
  );
  if (
    manifest.schemaVersion !== 4 ||
    manifest.kind !== "enoki-release-candidate" ||
    !/^[0-9a-f]{40}$/.test(manifest.candidate.commit ?? "") ||
    !/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      candidateVersion ?? "",
    ) ||
    !/^sha256:[0-9a-f]{64}$/.test(manifest.hub.digest ?? "") ||
    !/^[0-9a-f]{64}$/.test(manifest.hub.archiveSha256 ?? "") ||
    manifest.hub.archive !== `hub/enoki-hub-${candidateVersion}.oci.tar` ||
    !isPositiveSafeInteger(manifest.hub.size) ||
    manifest.hub.embeddedProbeVersion !== probeVersion ||
    probeVersion !== candidateVersion.slice(1) ||
    manifest.probeAssetSet.directory !== "probe-assets" ||
    !isCandidateFileList(manifest.probeAssetSet.files) ||
    manifest.probeAssetSet.signingIdentity.algorithm !== "rsa-sha256" ||
    manifest.probeAssetSet.signingIdentity.publicKeyFile !==
      "signing-key.pem" ||
    !/^[0-9a-f]{64}$/.test(
      manifest.probeAssetSet.signingIdentity.publicKeySha256 ?? "",
    ) ||
    bootstrapRecipe.bundleVersion !== probeVersion ||
    bootstrapRecipe.distribution !== "enoki" ||
    bootstrapRecipe.file !== "enoki-probe-bootstrap.py" ||
    bootstrapRecipe.kind !== "enoki-probe-bootstrap-recipe-record" ||
    bootstrapRecipe.recordFile !== "enoki-probe-bootstrap-recipe.json" ||
    !/^[0-9a-f]{64}$/.test(bootstrapRecipe.recordSha256 ?? "") ||
    !isPositiveSafeInteger(bootstrapRecipe.recordSize) ||
    !/^[0-9a-f]{64}$/.test(bootstrapRecipe.rootFingerprint ?? "") ||
    bootstrapRecipe.schemaVersion !== 1 ||
    !/^[0-9a-f]{64}$/.test(bootstrapRecipe.sha256 ?? "") ||
    !isPositiveSafeInteger(bootstrapRecipe.size) ||
    JSON.stringify(bootstrapRecipe.targets) !== JSON.stringify(probeTargets) ||
    bootstrapRecipe.version !== "v1" ||
    releaseBaseline.tag === candidateVersion
  ) {
    throw new Error("Candidate Manifest is invalid or internally inconsistent");
  }
}

function assertReleaseBaselineDescriptor(baseline) {
  const ordinary = baseline?.kind === "enoki-release-baseline";
  const migration = baseline?.kind === "enoki-trust-epoch-migration-baseline";
  assertExactObjectKeys(
    baseline,
    ordinary
      ? [
          "catalogSnapshot",
          "githubRelease",
          "hub",
          "kind",
          "probeAssetSet",
          "schemaVersion",
          "tag",
        ]
      : migration
        ? [
            "authorization",
            "catalogSnapshot",
            "githubRelease",
            "hub",
            "kind",
            "legacyProbeAssets",
            "schemaVersion",
            "tag",
            "transition",
          ]
        : [],
  );
  assertExactObjectKeys(baseline.hub, [
    "archive",
    "archiveSha256",
    "digest",
    "image",
    "imageDigest",
    "mediaType",
    "platform",
    "size",
    "sourceManifest",
    "sourceManifestSha256",
    "sourceManifestSize",
  ]);
  assertExactObjectKeys(baseline.hub.platform, ["architecture", "os"]);
  assertExactObjectKeys(baseline.githubRelease, [
    "id",
    "peeledCommitSha",
    "repository",
    "tagRefSha",
    "targetCommitish",
  ]);
  assertExactObjectKeys(baseline.catalogSnapshot, ["entries", "sha256"]);
  validateReleaseCatalogSnapshot(baseline.catalogSnapshot);
  const snapshotRelease = baseline.catalogSnapshot.entries.find(
    (entry) =>
      entry?.id === baseline.githubRelease.id && entry.tag === baseline.tag,
  );
  if (
    !/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      baseline.tag ?? "",
    ) ||
    baseline.hub.archive !== `hub/enoki-hub-${baseline.tag}.oci.tar` ||
    !/^[0-9a-f]{64}$/.test(baseline.hub.archiveSha256 ?? "") ||
    !/^sha256:[0-9a-f]{64}$/.test(baseline.hub.digest ?? "") ||
    baseline.hub.image !== "ghcr.io/ykdz/enoki-hub" ||
    !new Set([
      "application/vnd.docker.distribution.manifest.list.v2+json",
      "application/vnd.docker.distribution.manifest.v2+json",
      "application/vnd.oci.image.index.v1+json",
      "application/vnd.oci.image.manifest.v1+json",
    ]).has(baseline.hub.mediaType) ||
    !/^sha256:[0-9a-f]{64}$/.test(baseline.hub.imageDigest ?? "") ||
    !isPositiveSafeInteger(baseline.hub.size) ||
    baseline.hub.sourceManifest !== "hub-source-manifest.json" ||
    !/^[0-9a-f]{64}$/.test(baseline.hub.sourceManifestSha256 ?? "") ||
    !isPositiveSafeInteger(baseline.hub.sourceManifestSize) ||
    baseline.hub.platform.architecture !== "amd64" ||
    baseline.hub.platform.os !== "linux" ||
    !Number.isSafeInteger(baseline.githubRelease.id) ||
    baseline.githubRelease.id < 1 ||
    baseline.githubRelease.repository !== "YKDZ/enoki" ||
    !/^[0-9a-f]{40}$/.test(baseline.githubRelease.peeledCommitSha ?? "") ||
    !/^[0-9a-f]{40}$/.test(baseline.githubRelease.tagRefSha ?? "") ||
    typeof baseline.githubRelease.targetCommitish !== "string" ||
    baseline.githubRelease.targetCommitish.length === 0 ||
    !snapshotRelease ||
    snapshotRelease.targetCommitish !==
      baseline.githubRelease.targetCommitish ||
    baseline.hub.digest !== `sha256:${baseline.hub.sourceManifestSha256}`
  ) {
    throw new Error("Candidate Manifest Release Baseline is invalid");
  }
  if (ordinary) {
    assertExactObjectKeys(baseline.probeAssetSet, [
      "directory",
      "files",
      "signingIdentity",
      "trustRoot",
      "version",
    ]);
    assertExactObjectKeys(baseline.probeAssetSet.signingIdentity, [
      "algorithm",
      "publicKeyFile",
      "publicKeySha256",
    ]);
    assertExactObjectKeys(baseline.probeAssetSet.trustRoot, [
      "publicKeySha256",
    ]);
    if (
      baseline.schemaVersion !== 2 ||
      baseline.probeAssetSet.directory !== "probe-assets" ||
      baseline.probeAssetSet.version !== baseline.tag.slice(1) ||
      !isCandidateFileList(baseline.probeAssetSet.files) ||
      baseline.probeAssetSet.signingIdentity.algorithm !== "rsa-sha256" ||
      baseline.probeAssetSet.signingIdentity.publicKeyFile !==
        "signing-key.pem" ||
      !/^[0-9a-f]{64}$/.test(
        baseline.probeAssetSet.signingIdentity.publicKeySha256 ?? "",
      ) ||
      !/^[0-9a-f]{64}$/.test(
        baseline.probeAssetSet.trustRoot.publicKeySha256 ?? "",
      )
    ) {
      throw new Error("Candidate Manifest rooted Release Baseline is invalid");
    }
    return baseline;
  }
  assertExactObjectKeys(baseline.authorization, [
    "file",
    "legacyReleaseSha256",
    "sha256",
    "signatureFile",
    "signatureSha256",
  ]);
  assertExactObjectKeys(baseline.legacyProbeAssets, ["directory", "files"]);
  if (
    baseline.schemaVersion !== 1 ||
    baseline.tag !== "v0.1.74" ||
    baseline.transition !== "replacement-required" ||
    baseline.authorization.file !==
      "trust-epoch-migration-authorization.json" ||
    baseline.authorization.signatureFile !==
      "trust-epoch-migration-authorization.json.sig" ||
    !/^[0-9a-f]{64}$/.test(baseline.authorization.legacyReleaseSha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(baseline.authorization.sha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(baseline.authorization.signatureSha256 ?? "") ||
    baseline.legacyProbeAssets.directory !== "probe-assets" ||
    !isLegacyCandidateFileList(baseline.legacyProbeAssets.files)
  ) {
    throw new Error(
      "Candidate Manifest Trust Epoch Migration Baseline is invalid",
    );
  }
  return baseline;
}

function isTrustEpochMigrationBaseline(baseline) {
  return baseline?.kind === "enoki-trust-epoch-migration-baseline";
}

function releaseBaselineProbeVersion(baseline) {
  assertReleaseBaselineDescriptor(baseline);
  return isTrustEpochMigrationBaseline(baseline)
    ? baseline.tag.slice(1)
    : baseline.probeAssetSet.version;
}

function releaseBaselineEvidence(baseline) {
  assertReleaseBaselineDescriptor(baseline);
  const migration = isTrustEpochMigrationBaseline(baseline);
  return {
    authority: migration
      ? {
          authorizationSha256: baseline.authorization.sha256,
          githubReleaseId: baseline.githubRelease.id,
          legacyReleaseSha256: baseline.authorization.legacyReleaseSha256,
          peeledCommitSha: baseline.githubRelease.peeledCommitSha,
        }
      : {
          githubReleaseId: baseline.githubRelease.id,
          peeledCommitSha: baseline.githubRelease.peeledCommitSha,
          signingPublicKeySha256:
            baseline.probeAssetSet.signingIdentity.publicKeySha256,
          trustRootPublicKeySha256:
            baseline.probeAssetSet.trustRoot.publicKeySha256,
        },
    descriptorSha256: createHash("sha256")
      .update(JSON.stringify(baseline))
      .digest("hex"),
    hubDigest: baseline.hub.imageDigest,
    kind: baseline.kind,
    probeVersion: releaseBaselineProbeVersion(baseline),
    tag: baseline.tag,
  };
}

function isCandidateFileList(files) {
  return (
    Array.isArray(files) &&
    files.length > 0 &&
    files.every((file) => {
      try {
        assertExactObjectKeys(file, ["file", "sha256", "size"]);
      } catch {
        return false;
      }
      return (
        /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(file.file ?? "") &&
        !file.file.includes("..") &&
        /^[0-9a-f]{64}$/.test(file.sha256 ?? "") &&
        isPositiveSafeInteger(file.size)
      );
    })
  );
}

function isLegacyCandidateFileList(files) {
  return (
    Array.isArray(files) &&
    files.length > 0 &&
    files.every((file) => {
      try {
        assertExactObjectKeys(file, ["name", "sha256", "size"]);
      } catch {
        return false;
      }
      return (
        /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(file.name ?? "") &&
        !file.name.includes("..") &&
        /^[0-9a-f]{64}$/.test(file.sha256 ?? "") &&
        isPositiveSafeInteger(file.size)
      );
    })
  );
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
    "getHost",
    "getHostMetrics",
    "isHostSoftDeleted",
    "listHosts",
    "requestProbeUninstall",
    "waitForProbeOperation",
  ];
  if (
    hostMethods.some((method) => typeof host?.[method] !== "function") ||
    hubMethods.some((method) => typeof hub?.[method] !== "function")
  ) {
    throw new Error("Release E2E environment returned invalid participants");
  }
}

function assertFreshInstallScenarioParticipants(host, hub) {
  const hostMethods = [
    "assertDisposable",
    "assertInstalled",
    "awaitPermanentReportRejection",
    "captureInstallationState",
    "cleanup",
    "collectDiagnostics",
    "collectEvidence",
    "install",
    "localUninstall",
    "readProbeIdentity",
    "rejectRepeatedInstall",
    "repairInstalledBundleFailure",
  ];
  const hubMethods = [
    "authenticate",
    "collectEvidence",
    "createEnrollment",
    "deleteHostHubOnly",
    "getAuditLog",
    "getEnrollment",
    "getHost",
    "getHostMetrics",
    "getHostProbeConfiguration",
    "isHostSoftDeleted",
    "listHosts",
    "updateHostProbeConfiguration",
  ];
  if (
    hostMethods.some((method) => typeof host?.[method] !== "function") ||
    hubMethods.some((method) => typeof hub?.[method] !== "function")
  ) {
    throw new Error(
      "Release E2E environment returned invalid fresh-install participants",
    );
  }
}

function assertCreatedEnrollment(enrollment, expectedTarget) {
  if (
    !enrollment?.installCommand ||
    enrollment?.status !== "pending" ||
    JSON.stringify(enrollment.target) !== JSON.stringify(expectedTarget)
  ) {
    throw assertionError(
      "enrollment_command_missing",
      "Hub did not return an official pending Enrollment for the expected target",
    );
  }
  assertEnrollmentId(enrollment.enrollmentId);
  assertInstallCommand(enrollment.installCommand);
}

function compactEnrollmentEvidence(enrollment) {
  return {
    enrollmentId: enrollment.enrollmentId,
    status: enrollment.status,
    target: enrollment.target,
  };
}

function compactEnrollmentStatusEvidence(enrollment) {
  return {
    enrollmentId: enrollment.enrollmentId,
    hostId: enrollment.hostId,
    rejection: enrollment.rejection,
    status: enrollment.status,
    target: enrollment.target,
  };
}

function recordEnrollmentEvidence(enrollments, enrollment) {
  if (typeof enrollment?.enrollmentId !== "string") return;
  enrollments.set(enrollment.enrollmentId, {
    enrollmentId: enrollment.enrollmentId,
    hostId: enrollment.hostId ?? null,
    rejection: enrollment.rejection ?? null,
    readError: null,
    status: enrollment.status ?? null,
    target: enrollment.target ?? null,
  });
}

function assertMetricsWindow(window) {
  if (!new Set(["1m", "10m", "1h", "6h", "24h", "3d", "7d"]).has(window)) {
    throw new Error("Hub Metrics window is invalid");
  }
}

function assertLocalUninstallCompletion(completion) {
  if (
    completion?.clean !== true ||
    completion?.journaldRetained !== true ||
    completion?.sharedDependenciesRetained !== true
  ) {
    throw assertionError(
      "local_probe_uninstall_residue",
      "Local Probe Uninstall did not satisfy the shared no-residue boundary",
    );
  }
  assertHostInventoryEvidence(completion.inventory);
  if (inventoryResidue(completion.inventory).length > 0) {
    throw assertionError(
      "local_probe_uninstall_residue",
      "Local Probe Uninstall left Enoki-managed residue",
    );
  }
}

function hasPortableMetricsAfter(samples, previousSamples) {
  const previous = latestPortableMetric(previousSamples);
  return (
    Boolean(previous) &&
    Array.isArray(samples) &&
    samples.some(
      (sample) =>
        isPortableMetricSample(sample) &&
        sample.collectedAtMs > previous.collectedAtMs,
    )
  );
}

function retainsInitialMetricSample(samples, initialSamples) {
  const initial = compactMetricsEvidence(initialSamples)[0];
  return (
    Boolean(initial) &&
    Array.isArray(samples) &&
    samples.some(
      (sample) =>
        isPortableMetricSample(sample) &&
        sample.sequence === initial.sequence &&
        sample.collectedAtMs === initial.collectedAtMs,
    )
  );
}

function retainsMetricHistoryAnchors(samples, anchors) {
  return (
    Array.isArray(anchors) &&
    anchors.length > 0 &&
    anchors.every((anchor) =>
      samples.some(
        (sample) =>
          isPortableMetricSample(sample) &&
          JSON.stringify(compactMetricAnchor(sample)) ===
            JSON.stringify(anchor),
      ),
    )
  );
}

function assertFreshLifecycleAuditLog(auditLog, hostId) {
  const required = [
    {
      action: "enrollment_token.create",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.details?.target?.kind === "new_host",
    },
    {
      action: "enrollment.installation_rejected",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "system" &&
        event.outcome === "success" &&
        event.details?.code === "existing_probe_installation",
    },
    {
      action: "enrollment_token.create",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.details?.target?.kind === "existing_host" &&
        event.details.target.hostId === hostId,
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
        event.details?.mode === "hub-only",
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
      "fresh_lifecycle_audit_log_missing",
      `Hub Audit Log is missing fresh lifecycle evidence: ${missing.join(", ")}`,
    );
  }
  return selected;
}

function assertBaselineScenarioParticipants(
  host,
  hub,
  transitionClassification,
) {
  assertScenarioParticipants(host, hub);
  const hostMethods = ["readProbeIdentity"];
  const hubMethods = ["switchToCandidate"];
  if (transitionClassification === "replacement-required") {
    hostMethods.push("manualReinstall");
    hubMethods.push(
      "createManualReinstallEnrollment",
      "getAuditLog",
      "getHostProbeConfiguration",
      "updateHostProbeConfiguration",
    );
  } else {
    hostMethods.push(
      "beginUpgradeOwnershipTransition",
      "bindUpgradeOwnershipTransition",
      "completeUpgradeOwnershipTransition",
    );
    hubMethods.push("requestProbeUpgrade");
  }
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
    "cleanup",
    "collectEvidence",
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
    "restoreBaselineStateSnapshot",
    "switchToCandidate",
    "waitForProbeOperation",
  ];
  hostMethods.push(
    "beginUpgradeOwnershipTransition",
    "bindUpgradeOwnershipTransition",
    "completeUpgradeOwnershipTransition",
  );
  hubMethods.push("requestProbeUpgrade");
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
  assertBaselineScenarioParticipants(host, hub, "compatible");
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

function assertMigrationLifecycleAuditLog(
  auditLog,
  hostId,
  operationId,
  oldIdentity,
  newIdentity,
) {
  const selected = assertLifecycleAuditLog(auditLog, hostId, operationId);
  return [
    ...selected,
    ...assertManualReinstallAuditEvent(
      auditLog,
      hostId,
      oldIdentity,
      newIdentity,
    ),
  ];
}

function assertManualReinstallAuditEvent(
  auditLog,
  hostId,
  oldIdentity,
  newIdentity,
) {
  const replacement = auditLog.find(
    (event) =>
      event?.action === "probe.manual_reinstall_identity_replaced" &&
      isValidLifecycleAuditEvent(event) &&
      event.actor === "system" &&
      event.outcome === "success" &&
      event.subjectId === String(hostId) &&
      event.subjectType === "host" &&
      event.details?.oldProbeId === oldIdentity.probeId &&
      event.details?.newProbeId === newIdentity.probeId &&
      Array.isArray(event.details?.sourceProbeSha256) &&
      event.details.sourceProbeSha256.length > 0 &&
      /^sha256:[0-9a-f]{64}$/.test(event.details?.targetAssetSetDigest ?? "") &&
      /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
        event.details?.targetProbeVersion ?? "",
      ),
  );
  if (!replacement) {
    throw assertionError(
      "manual_reinstall_audit_log_missing",
      "Hub Audit Log is missing the production manual reinstall identity replacement event",
    );
  }
  return [replacement];
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

function validateInsufficientPrivilegeProbeUpgradeTimeline(timeline) {
  if (!Array.isArray(timeline) || timeline.length < 3) {
    throw assertionError(
      "probe_upgrade_timeline_incomplete",
      "Probe Upgrade permission failure did not retain bounded terminal evidence",
    );
  }
  const requested = timeline[0];
  let previous = null;
  for (const operation of timeline) {
    assertProbeOperation(operation, {
      hostId: requested?.hostId,
      id: requested?.id,
      kind: "probe_upgrade",
      targetProbeVersion: requested?.targetProbeVersion,
    });
    if (previous) assertProbeOperationProgress(previous, operation);
    previous = operation;
  }
  const finalOperation = timeline.at(-1);
  const confirmedOperation = timeline.at(-2);
  if (
    requested?.state !== "pending" ||
    requested.acceptedAtMs !== null ||
    requested.runningAtMs !== null ||
    requested.completedAtMs !== null ||
    finalOperation?.state !== "failed" ||
    finalOperation.failure?.code !== "insufficient_privilege" ||
    !Number.isSafeInteger(finalOperation.acceptedAtMs) ||
    !Number.isSafeInteger(finalOperation.completedAtMs)
  ) {
    throw assertionError(
      "probe_upgrade_permission_failure_invalid",
      `Probe Upgrade did not preserve a terminal insufficient-privilege failure: ${JSON.stringify(timeline)}`,
    );
  }
  assertStableTerminalOperation(confirmedOperation, finalOperation);
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
    configuration: canonicalSemanticValue(updated.configuration),
    mode: updated.mode,
    reportedVersion: reported.reportedProbeConfigurationVersion,
    version,
  };
}

function sameEffectiveProbeConfiguration(current, expected) {
  return (
    current?.mode === expected?.mode &&
    JSON.stringify(canonicalSemanticValue(current?.configuration)) ===
      JSON.stringify(expected?.configuration)
  );
}

function effectiveProbeConfigurationEvidence(value) {
  return {
    configuration: canonicalSemanticValue(value?.configuration),
    mode: value?.mode,
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

function localUninstallOfflineObservationPoll(timing, poll) {
  return {
    ...poll,
    timeoutMs: Math.max(
      timing.offlineTimeoutMs ?? poll.timeoutMs,
      defaultLocalUninstallOfflineObservationTimeoutMs,
    ),
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

function stableHostProfileEvidence(profile) {
  const projection = {
    architecture: profile.architecture,
    collectorCapabilities: canonicalSemanticValue(
      profile.collectorCapabilities ?? null,
    ),
    cpu: {
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
      .filter((networkInterface) =>
        isStableHostNetworkInterface(networkInterface),
      )
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

function isStableHostNetworkInterface(networkInterface) {
  return (
    typeof networkInterface?.name === "string" &&
    networkInterface.name.length > 0 &&
    !networkInterface.name.startsWith("veth")
  );
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

function compactHostEvidence(host) {
  return {
    hostProfile: host.hostProfile,
    id: host.id,
    status: host.status,
  };
}

function stableHubHostProjection(host) {
  return {
    hostMetadata: canonicalHostMetadata(host?.hostMetadata),
    hostProfile: canonicalSemanticValue(host?.hostProfile),
    id: host?.id,
    reportedProbeConfigurationVersion:
      host?.reportedProbeConfigurationVersion ?? null,
  };
}

function canonicalHostMetadata(metadata) {
  return {
    connectAddress: metadata?.connectAddress ?? null,
    description: metadata?.description ?? null,
    displayName: metadata?.displayName ?? null,
    observedIp: metadata?.observedIp ?? null,
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

function portableMetricIdentities(samples) {
  return samples
    .filter(isPortableMetricSample)
    .map((sample) => ({
      collectedAtMs: sample.collectedAtMs,
      sequence: sample.sequence,
    }))
    .sort(
      (left, right) =>
        left.sequence - right.sequence ||
        left.collectedAtMs - right.collectedAtMs,
    );
}

function metricsHistoryEvidence(samples, { retain = [] } = {}) {
  const ordered = samples
    .filter(isPortableMetricSample)
    .sort((left, right) => left.sequence - right.sequence)
    .map(compactMetricAnchor);
  const selected = [
    ordered[0],
    ordered[Math.floor((ordered.length - 1) / 2)],
    ordered.at(-1),
    ...retain.filter((anchor) =>
      ordered.some(
        (sample) => JSON.stringify(sample) === JSON.stringify(anchor),
      ),
    ),
  ].filter(Boolean);
  const anchors = [
    ...new Map(selected.map((anchor) => [anchor.sequence, anchor])).values(),
  ].sort((left, right) => left.sequence - right.sequence);
  return {
    anchors,
    sha256: createHash("sha256").update(JSON.stringify(anchors)).digest("hex"),
  };
}

function compactMetricAnchor(sample) {
  return {
    collectedAtMs: sample.collectedAtMs,
    cpuPercent: sample.cpuPercent,
    memoryTotalBytes: sample.memoryTotalBytes,
    memoryUsedBytes: sample.memoryUsedBytes,
    sequence: sample.sequence,
    uptimeSeconds: sample.uptimeSeconds,
  };
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

const releaseBaselineAuthorizationEvidencePath = Object.freeze([
  "releaseBaseline",
  "authority",
  "authorizationSha256",
]);

export function redactReleaseE2EEvidence(
  value,
  { candidateManifest, secrets = [] } = {},
) {
  assertCandidateManifest(candidateManifest);
  const baseline = candidateManifest.releaseBaseline;
  return redactSensitiveEvidence(value, secrets, [], {
    expectedReleaseBaselineAuthorizationSha256:
      baseline.authorization?.sha256 ?? null,
  });
}

function isValidatedReleaseBaselineAuthorizationSummary(path, value, expected) {
  return (
    path.length === releaseBaselineAuthorizationEvidencePath.length &&
    path.every(
      (segment, index) =>
        segment === releaseBaselineAuthorizationEvidencePath[index],
    ) &&
    typeof expected === "string" &&
    /^[0-9a-f]{64}$/.test(expected) &&
    value === expected
  );
}

function redactSensitiveEvidence(value, secrets, path, context) {
  const key = path.at(-1) ?? "";
  if (
    key &&
    !isValidatedReleaseBaselineAuthorizationSummary(
      path,
      value,
      context.expectedReleaseBaselineAuthorizationSha256,
    ) &&
    /(?:authorization|cookie|enrollment.?token|headers?|owner.?password|private.?key|signing.?secret|install.?command)/i.test(
      key,
    )
  ) {
    return "[REDACTED]";
  }
  if (typeof value === "string") {
    return redactSensitiveText(value, secrets);
  }
  if (Array.isArray(value)) {
    return value.map((item, index) =>
      redactSensitiveEvidence(item, secrets, [...path, String(index)], context),
    );
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, child]) => [
        childKey,
        redactSensitiveEvidence(child, secrets, [...path, childKey], context),
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
  redacted = redacted.replace(
    /printf '%s\\n' 'enk_enroll_[A-Za-z0-9_-]+' \| python3 -- \.\/enoki-probe-bootstrap\.py --hub-origin 'https?:\/\/[^'\s]+'|curl -fsSL 'https?:\/\/[^'\s]+\/api\/probe\/install\.sh' \| sudo env ENOKI_HUB_URL='https?:\/\/[^'\s]+' ENOKI_ENROLLMENT_TOKEN='enk_enroll_[A-Za-z0-9_-]+' bash/g,
    "[REDACTED_INSTALLER_COMMAND]",
  );
  return redacted
    .replace(/enk_enroll_[A-Za-z0-9_-]+/g, "[REDACTED_ENROLLMENT_TOKEN]")
    .replace(
      /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z]+)? PRIVATE KEY-----/g,
      "[REDACTED_PRIVATE_KEY]",
    )
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
