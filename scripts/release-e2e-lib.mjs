import { createHash, randomUUID } from "node:crypto";

import { probeTargets } from "@enoki/probe-release";

import { validateReleaseCatalogSnapshot } from "./release-baseline-lib.mjs";
import {
  createInstalledBundleFailureRepairHostDriver,
  proveInstalledBundleFailureRepair,
} from "./release-installed-bundle-failure-repair.mjs";

// Release E2E infrastructure has one narrowly scoped, run-owned resource
// definition. It produces the preflight allowlist, recorded fingerprint, and
// emergency-removal plan; the product installer and uninstaller are never
// invoked by this test-only path.
const releaseE2EInfrastructureResources = Object.freeze([
  { kind: "file", path: "/usr/local/bin/enoki-probe" },
  { kind: "file", path: "/usr/local/bin/enoki-probe-bootstrap-acquire" },
  { kind: "file", path: "/usr/local/bin/enoki-probe-bootstrap-activate" },
  {
    kind: "file",
    path: "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
  },
  { kind: "directory", path: "/var/lib/enoki-probe-bootstrap" },
  { kind: "file", path: "/etc/enoki/probe-install.toml" },
  { kind: "file", path: "/etc/systemd/system/enoki-probe.service" },
  {
    kind: "file",
    path: "/etc/systemd/system/enoki-probe.service.d/90-enoki-release-e2e-restart-failure.conf",
  },
  {
    kind: "directory",
    path: "/var/lib/enoki-probe",
    systemdStateDirectoryProjection: true,
  },
  { kind: "file", path: "/etc/sudoers.d/enoki-probe-operations" },
  {
    kind: "file",
    path: "/etc/sudoers.d/enoki-probe-collector-helpers",
  },
  { kind: "file", path: "/etc/sudoers.d/enoki-probe-upgrader" },
  { kind: "user", name: "enoki-probe" },
  { kind: "group", name: "enoki-probe" },
  { kind: "service", name: "enoki-probe.service" },
]);

const releaseE2ESystemdStateProjections = Object.freeze(
  releaseE2EInfrastructureResources
    .filter(
      (resource) =>
        resource.kind === "directory" &&
        resource.systemdStateDirectoryProjection === true,
    )
    .map((resource) => {
      const separator = resource.path.lastIndexOf("/");
      const parent = resource.path.slice(0, separator);
      const name = resource.path.slice(separator + 1);
      return Object.freeze({
        privatePath: `${parent}/private/${name}`,
        publicPath: resource.path,
      });
    }),
);

const managedHostPaths = Object.freeze([
  ...releaseE2EInfrastructureResources
    .filter((resource) => "path" in resource)
    .map((resource) => resource.path),
  ...releaseE2ESystemdStateProjections.map(
    (projection) => projection.privatePath,
  ),
]);

const releaseE2EUsers = Object.freeze(
  releaseE2EInfrastructureResources
    .filter((resource) => resource.kind === "user")
    .map((resource) => resource.name),
);

const releaseE2EGroups = Object.freeze(
  releaseE2EInfrastructureResources
    .filter((resource) => resource.kind === "group")
    .map((resource) => resource.name),
);

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

export function isSupportedReleaseTestHostVirtualization(value) {
  return supportedReleaseTestHostVmTypes.has(value);
}

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

function assertInstalledStateEvidence(state) {
  if (
    !state ||
    Object.keys(state).sort().join(",") !==
      "binarySha256,identity,installMetadataSha256,restartCount,service" ||
    !/^[0-9a-f]{64}$/.test(state.binarySha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(state.installMetadataSha256 ?? "") ||
    !Number.isSafeInteger(state.restartCount) ||
    state.restartCount < 0 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(
      state.identity?.probeId ?? "",
    ) ||
    !/^[0-9a-f]{64}$/.test(state.identity?.identitySha256 ?? "") ||
    state.service?.LoadState !== "loaded" ||
    state.service?.ActiveState !== "active" ||
    state.service?.SubState !== "running" ||
    Object.keys(state.service ?? {})
      .sort()
      .join(",") !== "ActiveState,LoadState,SubState" ||
    Object.keys(state.identity ?? {})
      .sort()
      .join(",") !== "identitySha256,probeId"
  ) {
    throw new Error("installed Probe state evidence is invalid");
  }
}

function assertPermanentReportRejectionEvidence(evidence) {
  if (
    !evidence ||
    Object.keys(evidence).sort().join(",") !==
      "binarySha256,identity,installMetadataSha256,restartCountAfterObservation,restartCountBeforeObservation,service" ||
    !/^[0-9a-f]{64}$/.test(evidence.binarySha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(evidence.installMetadataSha256 ?? "") ||
    !Number.isSafeInteger(evidence.restartCountBeforeObservation) ||
    evidence.restartCountBeforeObservation < 0 ||
    evidence.restartCountAfterObservation !==
      evidence.restartCountBeforeObservation ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(
      evidence.identity?.probeId ?? "",
    ) ||
    !/^[0-9a-f]{64}$/.test(evidence.identity?.identitySha256 ?? "") ||
    evidence.service?.LoadState !== "loaded" ||
    evidence.service?.ActiveState !== "failed" ||
    evidence.service?.SubState !== "failed" ||
    evidence.service?.ExecMainStatus !== 78 ||
    Object.keys(evidence.service ?? {})
      .sort()
      .join(",") !== "ActiveState,ExecMainStatus,LoadState,SubState" ||
    Object.keys(evidence.identity ?? {})
      .sort()
      .join(",") !== "identitySha256,probeId"
  ) {
    throw new Error("permanent Probe report rejection evidence is invalid");
  }
}

function assertInstalledDiagnosticsEvidence(evidence) {
  if (
    !evidence ||
    Object.keys(evidence).sort().join(",") !==
      "binary,identity,installMetadataSha256,service" ||
    !/^[0-9a-f]{64}$/.test(evidence.binary?.sha256 ?? "") ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      evidence.binary?.version ?? "",
    ) ||
    !/^[0-9a-f]{64}$/.test(evidence.installMetadataSha256 ?? "") ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(
      evidence.identity?.probeId ?? "",
    ) ||
    !/^[0-9a-f]{64}$/.test(evidence.identity?.identitySha256 ?? "") ||
    evidence.service?.LoadState !== "loaded" ||
    evidence.service?.ActiveState !== "failed" ||
    evidence.service?.SubState !== "failed" ||
    evidence.service?.ExecMainStatus !== 78 ||
    !Number.isSafeInteger(evidence.service?.NRestarts) ||
    evidence.service.NRestarts < 0 ||
    typeof evidence.service?.Result !== "string" ||
    !evidence.service.Result ||
    Object.keys(evidence.binary ?? {})
      .sort()
      .join(",") !== "sha256,version" ||
    Object.keys(evidence.identity ?? {})
      .sort()
      .join(",") !== "identitySha256,probeId" ||
    Object.keys(evidence.service ?? {})
      .sort()
      .join(",") !==
      "ActiveState,ExecMainStatus,LoadState,NRestarts,Result,SubState"
  ) {
    throw new Error("terminal Probe diagnostic evidence is invalid");
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
    if (isTrustEpochMigrationBaseline(baseline)) {
      await host.assertLegacyReleaseBaselineInstalled(
        runId,
        releaseBaselineProbeVersion(baseline),
      );
    } else {
      await host.assertInstalled(runId, releaseBaselineProbeVersion(baseline));
    }

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
  replacementSourceProbeSha256,
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
      assertEnrollmentInstallContract(body, {
        sourceProbeSha256:
          typeof replacementSourceProbeSha256 === "function"
            ? replacementSourceProbeSha256()
            : replacementSourceProbeSha256,
      });
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

export function createProbeHostHarness({
  execute,
  ownershipToken = randomUUID(),
  prepareInstall,
}) {
  if (typeof execute !== "function") {
    throw new Error("Probe Host Harness requires an execute function");
  }

  let disposableRunId = null;
  if (!/^[0-9a-f-]{36}$/.test(ownershipToken)) {
    throw new Error("Probe Host Harness ownership token is invalid");
  }
  let runOwnsMutation = false;
  let canonicalRuntimeUnavailableArmed = false;
  let postReplacementFaultArmed = false;
  let readyForReinstallation = false;
  let sharedDependenciesBefore = null;
  if (prepareInstall !== undefined && typeof prepareInstall !== "function") {
    throw new Error("Probe Host Harness install preparation is invalid");
  }
  const installedBundleFailureRepair =
    createInstalledBundleFailureRepairHostDriver({
      assertOwnedRun: (runId) =>
        assertOwnedRun(runId, disposableRunId, runOwnsMutation),
      execute,
      ownershipToken,
    });

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

  async function collectDiagnosticComponent({
    label,
    parse = (value) => value,
    script,
    validate = () => {},
  }) {
    let output = null;
    try {
      const result = await execute(script, { root: true });
      output = commandEvidence(result);
      if (result.code !== 0) {
        return {
          available: false,
          error: {
            code: "diagnostic_command_failed",
            message: `${label} diagnostic command exited ${result.code}`,
          },
          output,
        };
      }
      const value = parse(result.stdout);
      validate(value);
      return { available: true, output, value };
    } catch (error) {
      return {
        available: false,
        error: serializedError(error),
        ...(output ? { output } : {}),
      };
    }
  }

  async function prepareEnrollmentInstall(enrollment, runId) {
    const installContract = assertEnrollmentInstallContract(enrollment);
    const prepared = prepareInstall
      ? await prepareInstall({ enrollment, installContract, runId })
      : null;
    const workingDirectory = prepared?.workingDirectory;
    if (
      prepared?.complete !== undefined &&
      typeof prepared.complete !== "function"
    ) {
      throw new Error(
        "Probe Host Harness install ownership completion is invalid",
      );
    }
    if (
      workingDirectory != null &&
      (typeof workingDirectory !== "string" ||
        !/^\/tmp\/enoki-release-e2e-recipe\.[A-Za-z0-9]+$/.test(
          workingDirectory,
        ))
    ) {
      throw new Error(
        "Probe Host Harness install working directory is invalid",
      );
    }
    if (
      installContract.kind === "bootstrap-recipe" &&
      prepareInstall &&
      !workingDirectory
    ) {
      throw new Error(
        "Probe Bootstrap recipe was not staged from the active Hub image",
      );
    }
    return {
      bootstrapRecipeProvenance: prepared?.evidence ?? null,
      complete: prepared?.complete ?? null,
      installContract,
      workingDirectory,
    };
  }

  async function runInstallCommand(enrollment, runId, transition) {
    assertRunId(runId);
    if (disposableRunId !== runId) {
      throw new Error(
        "Release Test Host must pass disposable preflight before installation",
      );
    }
    const reinstallation = runOwnsMutation;
    if (transition === "manual-reinstall") {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (readyForReinstallation) {
        throw new Error(
          "Release Test Host manual reinstall requires the current owned Probe installation",
        );
      }
    } else if (reinstallation && !readyForReinstallation) {
      throw new Error(
        "Release Test Host must complete Local Probe Uninstall before reinstallation",
      );
    }
    if (!reinstallation) {
      const claim = await execute(claimRunScript(runId, ownershipToken), {
        root: true,
      });
      if (claim.code !== 0) {
        throw new Error(
          `Could not claim Release Test Host run: ${claim.stderr}`,
        );
      }
      runOwnsMutation = true;
    }
    const {
      bootstrapRecipeProvenance,
      complete,
      workingDirectory: installWorkingDirectory,
    } = await prepareEnrollmentInstall(enrollment, runId);
    const result = await execute(
      `# enoki-release-e2e:bootstrap-acquire\nset -eu\n[ "$(id -u)" != 0 ]\n${installWorkingDirectory ? `cd -- ${shellSingleQuote(installWorkingDirectory)}\n` : ""}${enrollment.installCommand}\n`,
      {
        root: false,
        sensitive: true,
      },
    );
    const recorded = await execute(
      reinstallation
        ? renewRunResourcesScript(runId, ownershipToken)
        : recordRunResourcesScript(runId, ownershipToken),
      { root: true },
    );
    if (recorded.code !== 0) {
      const error = new Error(
        `Could not record run-owned Probe resources: ${recorded.stderr}`,
      );
      error.code = "probe_resource_recording_failed";
      error.installerEvidence = commandEvidence(result);
      throw error;
    }
    await complete?.();
    if (result.code !== 0) {
      const error = new Error(
        `Probe installation failed (${result.code}); redacted installer evidence was retained`,
      );
      error.code = "probe_installation_failed";
      error.installerEvidence = commandEvidence(result);
      throw error;
    }
    readyForReinstallation = false;
    return {
      bootstrapRecipeProvenance,
      output: commandEvidence(result),
      runId,
    };
  }

  return {
    async repairInstalledBundleFailure(runId, expectedBundleVersion) {
      return installedBundleFailureRepair.repair(runId, expectedBundleVersion);
    },
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
      if (!isSupportedReleaseTestHostVirtualization(actual.virtualization)) {
        throw new Error(
          `Release Test Host must be a supported VM, found ${actual.virtualization ?? "unknown"}`,
        );
      }
      for (const primitive of [
        "deviceView",
        "journaldSocket",
        "rootFilesystem",
        "systemdNotifySocket",
        "unifiedCgroup",
      ]) {
        if (actual[primitive] !== true) {
          throw new Error(
            `Release Test Host required host primitive ${primitive} is unavailable`,
          );
        }
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

    async install(enrollment, runId) {
      return runInstallCommand(enrollment, runId, "fresh");
    },

    async manualReinstall(enrollment, runId) {
      return runInstallCommand(enrollment, runId, "manual-reinstall");
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
      const [
        inspected,
        serviceResult,
        sudoersResult,
        binaryVersionResult,
        generationResult,
      ] = await Promise.all([
        inventory(),
        execute(serviceBoundaryScript()),
        execute(sudoersBoundaryScript(), { root: true }),
        execute(binaryVersionScript()),
        execute(bootstrapGenerationStateScript(), { root: true }),
      ]);
      const residue = inventoryResidue(inspected);
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
      if (sudoersResult.code !== 0 || sudoersResult.stdout.trim() !== "") {
        throw new Error(
          "Probe Bootstrap schema 2 installation must not retain Probe sudoers",
        );
      }
      const generation = generationResult.stdout.trim();
      if (generationResult.code !== 0 || !/^[1-9]\d*$/.test(generation)) {
        throw new Error(
          "Probe Bootstrap delegation generation state is missing or invalid",
        );
      }
      const probeVersion =
        binaryVersionResult.code === 0
          ? binaryVersionResult.stdout
              .trim()
              .match(/(?:^|\s)v?(\d+\.\d+\.\d+)(?:\s|$)/)?.[1]
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
        delegationGeneration: Number(generation),
      };
    },

    async assertLegacyReleaseBaselineInstalled(runId, expectedProbeVersion) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (expectedProbeVersion !== "0.1.74") {
        throw new Error(
          "Legacy Release Baseline boundary is fixed to Probe v0.1.74",
        );
      }
      const [
        inspected,
        serviceResult,
        sudoersResult,
        binaryVersionResult,
        metadataResult,
      ] = await Promise.all([
        inventory(),
        execute(serviceBoundaryScript()),
        execute(legacySudoersBoundaryScript(), { root: true }),
        execute(binaryVersionScript()),
        execute(legacyInstallMetadataBoundaryScript(), { root: true }),
      ]);
      const residue = inventoryResidue(inspected);
      const required = [
        "user:enoki-probe",
        "group:enoki-probe",
        "/usr/local/bin/enoki-probe",
        "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
        "/etc/enoki/probe-install.toml",
        "/etc/systemd/system/enoki-probe.service",
        "/var/lib/enoki-probe",
        "/etc/sudoers.d/enoki-probe-operations",
        "enoki-probe.service",
      ];
      const missing = required.filter((entry) => !residue.includes(entry));
      if (missing.length > 0) {
        throw new Error(
          `Legacy Probe v0.1.74 installation is incomplete: missing ${missing.join(", ")}`,
        );
      }
      const unexpectedCandidateResources = [
        "/usr/local/bin/enoki-probe-bootstrap-acquire",
        "/usr/local/bin/enoki-probe-bootstrap-activate",
        "/var/lib/enoki-probe-bootstrap",
      ].filter((entry) => residue.includes(entry));
      if (unexpectedCandidateResources.length > 0) {
        throw new Error(
          `Legacy Probe v0.1.74 installation contains Candidate Bootstrap resources: ${unexpectedCandidateResources.join(", ")}`,
        );
      }
      if (
        metadataResult.code !== 0 ||
        metadataResult.stdout.trim() !== "verified"
      ) {
        throw new Error(
          `Legacy Probe v0.1.74 install metadata boundary is invalid: ${metadataResult.stderr}`,
        );
      }
      if (serviceResult.code !== 0) {
        throw new Error(
          `Legacy Probe service inspection failed: ${serviceResult.stderr}`,
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
          `Legacy Probe service does not satisfy the v0.1.74 non-root installation contract: ${JSON.stringify(service)}`,
        );
      }
      if (
        sudoersResult.code !== 0 ||
        sudoersResult.stdout.trim() !== "verified"
      ) {
        throw new Error(
          "Legacy Probe v0.1.74 operation sudoers boundary is missing or invalid",
        );
      }
      const probeVersion =
        binaryVersionResult.code === 0
          ? binaryVersionResult.stdout
              .trim()
              .match(/(?:^|\s)v?(\d+\.\d+\.\d+)(?:\s|$)/)?.[1]
          : null;
      if (probeVersion !== expectedProbeVersion) {
        throw new Error(
          `Installed legacy Probe binary version ${probeVersion ?? "unknown"} does not match Release Baseline ${expectedProbeVersion}`,
        );
      }
      return {
        identityPath: "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
        inventory: inspected,
        probeVersion,
        service,
        sudoers: sudoersResult.stdout,
      };
    },

    async captureInstallationState(runId) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const result = await execute(installedStateScript(), { root: true });
      if (result.code !== 0) {
        throw new Error(
          `Installed Probe state inspection failed (${result.code}): ${result.stderr}`,
        );
      }
      const state = parseJson(result.stdout, "installed Probe state");
      assertInstalledStateEvidence(state);
      return state;
    },

    async rejectRepeatedInstall(enrollment, runId) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const { workingDirectory } = await prepareEnrollmentInstall(
        enrollment,
        runId,
      );
      const result = await execute(
        `# enoki-release-e2e:bootstrap-acquire\nset -eu\n[ "$(id -u)" != 0 ]\n${workingDirectory ? `cd -- ${shellSingleQuote(workingDirectory)}\n` : ""}${enrollment.installCommand}\n`,
        {
          root: false,
          sensitive: true,
        },
      );
      const rejection = `${result.stdout}\n${result.stderr}`.match(
        /\bcode=([a-z0-9_]+)\b/,
      )?.[1];
      if (result.code === 0 || rejection !== "existing_probe_installation") {
        throw new Error(
          `Repeated Probe Add did not return existing_probe_installation: ${result.stderr || result.stdout}`,
        );
      }
      return {
        code: rejection,
        output: commandEvidence(result),
      };
    },

    async awaitPermanentReportRejection(runId) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const result = await execute(permanentReportRejectionScript(), {
        root: true,
      });
      if (result.code !== 0) {
        throw new Error(
          `Permanent Probe report rejection was not observed: ${result.stderr}`,
        );
      }
      const evidence = parseJson(
        result.stdout,
        "permanent Probe report rejection evidence",
      );
      assertPermanentReportRejectionEvidence(evidence);
      return evidence;
    },

    async collectDiagnostics(runId) {
      assertRunId(runId);
      const [inventory, installation, journald, sudoers, systemd] =
        await Promise.all([
          collectDiagnosticComponent({
            label: "Host inventory",
            parse: (value) =>
              parseJson(value, "terminal Release Test Host inventory"),
            script: hostInventoryScript(),
            validate: assertHostInventoryEvidence,
          }),
          collectDiagnosticComponent({
            label: "Probe installation",
            parse: (value) =>
              parseJson(value, "terminal Probe diagnostic evidence"),
            script: installedDiagnosticsScript(),
            validate: assertInstalledDiagnosticsEvidence,
          }),
          collectDiagnosticComponent({
            label: "Probe journald",
            script: journaldEvidenceScript(),
          }),
          collectDiagnosticComponent({
            label: "Probe sudoers",
            script: installedSudoersDiagnosticsScript(),
          }),
          collectDiagnosticComponent({
            label: "Probe systemd",
            script: systemdDiagnosticsScript(),
          }),
        ]);
      return {
        installation,
        inventory,
        journald,
        sudoers,
        systemd,
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

    async restartCanonicalProbeWithoutObservationRuntime(
      runId,
      expectedProbeId,
    ) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(expectedProbeId ?? "")) {
        throw new Error("canonical Probe Identity is invalid");
      }
      if (canonicalRuntimeUnavailableArmed) {
        throw new Error(
          "canonical Runtime-unavailable fixture is already armed",
        );
      }
      canonicalRuntimeUnavailableArmed = true;
      const result = await execute(
        canonicalRuntimeUnavailableRestartScript(expectedProbeId),
        { root: true },
      );
      if (result.code !== 0) {
        throw new Error(
          `Canonical Probe did not reach READY without Observation Runtime: ${result.stderr}`,
        );
      }
      const evidence = parseJson(
        result.stdout,
        "canonical Runtime-unavailable Host evidence",
      );
      assertCanonicalRuntimeUnavailableHostEvidence(evidence, expectedProbeId);
      return evidence;
    },

    async restoreObservationRuntime(runId) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (!canonicalRuntimeUnavailableArmed) {
        throw new Error("canonical Runtime-unavailable fixture is not armed");
      }
      const result = await execute(restoreObservationRuntimeScript(), {
        root: true,
      });
      if (result.code !== 0 || result.stdout.trim() !== "restored") {
        throw new Error(
          `Observation Runtime fixture restoration failed: ${result.stderr}`,
        );
      }
      canonicalRuntimeUnavailableArmed = false;
      return { restored: true };
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

    async localUninstall(runId) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const result = await execute(
        "# enoki-release-e2e:local-probe-uninstall\n/usr/local/bin/enoki-probe uninstall\n",
        { root: true },
      );
      if (
        result.code !== 0 ||
        result.stdout.trim() !== "Local Probe Uninstall completed."
      ) {
        throw new Error(
          `Local Probe Uninstall failed (${result.code}): ${result.stderr || result.stdout}`,
        );
      }
      const completion = await this.verifyUninstallCompletion(runId);
      readyForReinstallation = true;
      return { completion, output: commandEvidence(result) };
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

      if (canonicalRuntimeUnavailableArmed) {
        await attempt(async () => {
          const restored = await execute(restoreObservationRuntimeScript(), {
            root: true,
          });
          if (restored.code !== 0 || restored.stdout.trim() !== "restored") {
            throw new Error(
              `Run-owned canonical Runtime fixture cleanup failed: ${restored.stderr}`,
            );
          }
          canonicalRuntimeUnavailableArmed = false;
        });
      }

      await attempt(() => installedBundleFailureRepair.cleanup(runId));

      let inspected = await attempt(() => inventory());
      let residue = inspected ? inventoryResidue(inspected) : null;
      let removedPartialInstallation = false;
      if (residue?.length > 0) {
        const verifiedResources = await execute(
          verifyRunResourcesScript(runId, ownershipToken),
          { root: true },
        );
        const resourcesOwned = verifiedResources.code === 0;
        if (!resourcesOwned) {
          errors.push(
            new Error(
              `Refusing cleanup because Probe resources no longer match run ${runId}: ${verifiedResources.stderr}`,
            ),
          );
        }
        if (resourcesOwned) {
          await attempt(async () => {
            const cleaned = await execute(
              releaseEmergencyCleanupScript(runId, ownershipToken),
              { root: true },
            );
            if (cleaned.code !== 0) {
              throw new Error(
                `Run-owned emergency cleanup failed: ${cleaned.stderr}`,
              );
            }
            removedPartialInstallation = true;
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
        readyForReinstallation = false;
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
json_bool() { if "$@" >/dev/null 2>&1; then printf true; else printf false; fi; }
printf '{"architecture":"%s","deviceView":' \
  "$architecture"
json_bool test -c /dev/null
printf ',"journaldSocket":'
json_bool test -S /run/systemd/journal/socket
printf ',"operatingSystem":"%s","operatingSystemVersion":"%s","pid1":"%s","rootFilesystem":' \
  "$(printf '%s' "$ID" | tr '[:upper:]' '[:lower:]')" "$VERSION_ID" "$pid1"
json_bool sh -c 'test -d /etc && test -d /var/lib && test -w /tmp'
printf ',"systemdNotifySocket":'
json_bool test -S /run/systemd/notify
printf ',"unifiedCgroup":'
json_bool test -f /sys/fs/cgroup/cgroup.controllers
printf ',"virtualization":"%s"}\n' "$virtualization"`;
}

function hostInventoryScript() {
  const group = shellSingleQuote(releaseE2EGroups[0]);
  const user = shellSingleQuote(releaseE2EUsers[0]);
  return String.raw`# enoki-release-e2e:inventory
set -eu
json_bool() { if "$@" >/dev/null 2>&1; then printf true; else printf false; fi; }
printf '{"accounts":{"group":'
json_bool getent group ${group}
printf ',"user":'
json_bool getent passwd ${user}
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

function canonicalRuntimeUnavailableRestartScript(expectedProbeId) {
  return String.raw`# enoki-release-e2e:canonical-runtime-unavailable
set -eu
identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml
attempt_source=/var/lib/enoki-probe-registration/attempt.json
credential=/run/credentials/enoki-probe.service/registration-attempt
registration_drop_in=/run/systemd/system/enoki-probe.service.d/10-enoki-replacement-registration.conf
[ -f "$identity" ] && [ ! -L "$identity" ]
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$identity")
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
[ "$probe_id" = ${shellSingleQuote(expectedProbeId)} ]
! grep -Eq '^[[:space:]]*registration_' "$identity"
[ ! -e "$attempt_source" ] && [ ! -L "$attempt_source" ]
[ ! -e "$credential" ] && [ ! -L "$credential" ]
[ ! -e "$registration_drop_in" ] && [ ! -L "$registration_drop_in" ]
systemctl stop enoki-observation-runtime.socket enoki-observation-runtime.service
systemctl mask --runtime enoki-observation-runtime.socket enoki-observation-runtime.service
systemctl restart enoki-probe.service
probe_load=$(systemctl show enoki-probe.service --property=LoadState --value)
probe_active=$(systemctl show enoki-probe.service --property=ActiveState --value)
probe_sub=$(systemctl show enoki-probe.service --property=SubState --value)
probe_result=$(systemctl show enoki-probe.service --property=Result --value)
probe_type=$(systemctl show enoki-probe.service --property=Type --value)
runtime_service_load=$(systemctl show enoki-observation-runtime.service --property=LoadState --value)
runtime_socket_load=$(systemctl show enoki-observation-runtime.socket --property=LoadState --value)
[ "$probe_load" = loaded ]
[ "$probe_active" = active ]
[ "$probe_sub" = running ]
[ "$probe_result" = success ]
[ "$probe_type" = notify ]
[ "$runtime_service_load" = masked ]
[ "$runtime_socket_load" = masked ]
printf '{"identity":{"probeId":"%s","registrationAttemptCredential":false,"registrationAttemptSource":false,"registrationDropIn":false,"transitionalRegistrationKeys":false},"probe":{"ActiveState":"%s","LoadState":"%s","Result":"%s","SubState":"%s","Type":"%s"},"runtime":{"serviceLoadState":"%s","socketLoadState":"%s"}}\n' \
  "$probe_id" "$probe_active" "$probe_load" "$probe_result" "$probe_sub" "$probe_type" "$runtime_service_load" "$runtime_socket_load"
`;
}

function restoreObservationRuntimeScript() {
  return String.raw`# enoki-release-e2e:restore-observation-runtime
set -eu
systemctl unmask --runtime enoki-observation-runtime.socket enoki-observation-runtime.service
systemctl daemon-reload
systemctl reset-failed enoki-observation-runtime.socket enoki-observation-runtime.service
systemctl start enoki-observation-runtime.socket
printf 'restored\n'
`;
}

function sudoersBoundaryScript() {
  return String.raw`# enoki-release-e2e:sudoers-boundary
set -eu
for candidate in /etc/sudoers.d/enoki-probe-operations /etc/sudoers.d/enoki-probe-collector-helpers /etc/sudoers.d/enoki-probe-upgrader; do
  [ ! -e "$candidate" ]
done
`;
}

function legacySudoersBoundaryScript() {
  return String.raw`# enoki-release-e2e:legacy-sudoers-boundary
set -eu
operation=/etc/sudoers.d/enoki-probe-operations
collector=/etc/sudoers.d/enoki-probe-collector-helpers
expected_operation=$(mktemp /tmp/enoki-release-e2e-legacy-operation.XXXXXX)
expected_collector=$(mktemp /tmp/enoki-release-e2e-legacy-collector.XXXXXX)
trap 'rm -f -- "$expected_operation" "$expected_collector"' EXIT HUP INT TERM
cat >"$expected_operation" <<'ENOKI_OPERATION_EOF'
# Managed by Enoki Probe installer.
enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit=enoki-probe-upgrader --property=Type=exec -- /usr/local/bin/enoki-probe internal-upgrader --config /var/lib/enoki-probe/identity/probe-bootstrap.toml
enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit=enoki-probe-uninstaller --property=Type=exec -- /usr/local/bin/enoki-probe internal-uninstaller --config /var/lib/enoki-probe/identity/probe-bootstrap.toml
ENOKI_OPERATION_EOF
cat >"$expected_collector" <<'ENOKI_COLLECTOR_EOF'
# Managed by Enoki Probe installer.
enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --quiet --pipe --wait --collect --property=RuntimeMaxSec=10 --property=PrivateNetwork=yes /usr/local/bin/enoki-probe internal-privileged-collector-helper --helper disk-health.smartctl
ENOKI_COLLECTOR_EOF
validate_sudoers() {
  candidate=$1
  [ -f "$candidate" ] && [ ! -L "$candidate" ]
  [ "$(stat -c %h "$candidate")" = 1 ]
  [ "$(stat -c %u "$candidate")" = 0 ]
  [ "$(stat -c %g "$candidate")" = 0 ]
  [ "$(stat -c %a "$candidate")" = 440 ]
  ! grep -Fq 'NOPASSWD: ALL' "$candidate"
  /usr/sbin/visudo -cf "$candidate" >/dev/null
}
validate_sudoers "$operation"
cmp --silent "$expected_operation" "$operation"
if [ -e "$collector" ] || [ -L "$collector" ]; then
  validate_sudoers "$collector"
  cmp --silent "$expected_collector" "$collector"
fi
printf 'verified\n'
`;
}

function legacyInstallMetadataBoundaryScript() {
  return String.raw`# enoki-release-e2e:legacy-install-metadata
set -eu
metadata=/etc/enoki/probe-install.toml
identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml
[ -f "$metadata" ] && [ ! -L "$metadata" ]
[ "$(stat -c %u "$metadata")" = 0 ]
[ "$(stat -c %g "$metadata")" = 0 ]
[ "$(stat -c %a "$metadata")" = 600 ]
[ -f "$identity" ] && [ ! -L "$identity" ]
[ "$(stat -c %h "$identity")" = 1 ]
[ "$(stat -c %u "$identity")" = "$(id -u "enoki-probe")" ]
[ "$(stat -c %g "$identity")" = "$(id -g "enoki-probe")" ]
[ "$(stat -c %a "$identity")" = 600 ]
require_metadata_key() { [ "$(grep -Ec "^$1 = " "$metadata")" -eq 1 ]; }
require_metadata_line() {
  expected=$1
  key=$(printf '%s\n' "$expected" | sed 's/ = .*//')
  require_metadata_key "$key" && [ "$(grep -Fxc "$expected" "$metadata")" -eq 1 ]
}
awk '
  /^[[:space:]]*$/ { next }
  $0 !~ /^(schema_version|hub_url|install_path|identity_path|state_dir|operation_status_path|service_name|service_user|service_group|service_unit_path|operation_sudoers_path|collector_helper_sudoers_path|probe_asset_public_key_sha256) = / { exit 1 }
' "$metadata"
require_metadata_line 'schema_version = 1'
require_metadata_key hub_url
grep -Eq '^hub_url = "https?://[^"[:space:]]+"$' "$metadata"
require_metadata_line 'install_path = "/usr/local/bin/enoki-probe"'
require_metadata_line 'identity_path = "/var/lib/enoki-probe/identity/probe-bootstrap.toml"'
require_metadata_line 'state_dir = "/var/lib/enoki-probe"'
require_metadata_line 'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"'
require_metadata_line 'service_name = "enoki-probe"'
require_metadata_line 'service_user = "enoki-probe"'
require_metadata_line 'service_group = "enoki-probe"'
require_metadata_line 'service_unit_path = "/etc/systemd/system/enoki-probe.service"'
require_metadata_line 'operation_sudoers_path = "/etc/sudoers.d/enoki-probe-operations"'
require_metadata_line 'collector_helper_sudoers_path = "/etc/sudoers.d/enoki-probe-collector-helpers"'
require_metadata_key probe_asset_public_key_sha256
grep -Eq '^probe_asset_public_key_sha256 = "[0-9A-Fa-f]{64}"$' "$metadata"
printf 'verified\n'
`;
}

function binaryVersionScript() {
  return String.raw`# enoki-release-e2e:binary-version
set -eu
/usr/local/bin/enoki-probe --version
`;
}

function bootstrapGenerationStateScript() {
  return String.raw`# enoki-release-e2e:bootstrap-generation
set -eu
generation=/var/lib/enoki-probe/trust/delegation-generation
[ -f "$generation" ] && [ ! -L "$generation" ]
[ "$(stat -c %u "$generation")" = 0 ]
[ "$(stat -c %a "$generation")" = 600 ]
value=$(cat -- "$generation")
case "$value" in [1-9]* ) ;; *) exit 1 ;; esac
case "$value" in *[!0-9]* ) exit 1 ;; esac
printf '%s\n' "$value"
`;
}

function installedStateScript() {
  return String.raw`# enoki-release-e2e:installed-state
set -eu
binary=/usr/local/bin/enoki-probe
metadata=/etc/enoki/probe-install.toml
identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml
[ -x "$binary" ]
[ -f "$metadata" ]
[ -f "$identity" ]
load_state=$(systemctl show enoki-probe.service --no-pager --property=LoadState --value)
active_state=$(systemctl show enoki-probe.service --no-pager --property=ActiveState --value)
sub_state=$(systemctl show enoki-probe.service --no-pager --property=SubState --value)
restart_count=$(systemctl show enoki-probe.service --no-pager --property=NRestarts --value)
case "$restart_count" in ''|*[!0-9]*) exit 1 ;; esac
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$identity")
private_key_line=$(grep -E '^probe_private_key_pem = ".+"$' "$identity")
[ "$(grep -c '^probe_id = ' "$identity")" -eq 1 ]
[ "$(grep -c '^probe_private_key_pem = ' "$identity")" -eq 1 ]
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
identity_sha256=$(printf '%s\n%s\n' "$probe_id_line" "$private_key_line" | sha256sum | cut -d ' ' -f 1)
binary_sha256=$(sha256sum -- "$binary" | cut -d ' ' -f 1)
metadata_sha256=$(sha256sum -- "$metadata" | cut -d ' ' -f 1)
printf '{"binarySha256":"%s","identity":{"identitySha256":"%s","probeId":"%s"},"installMetadataSha256":"%s","restartCount":%s,"service":{"ActiveState":"%s","LoadState":"%s","SubState":"%s"}}\n' \
  "$binary_sha256" "$identity_sha256" "$probe_id" "$metadata_sha256" "$restart_count" "$active_state" "$load_state" "$sub_state"`;
}

function permanentReportRejectionScript() {
  return String.raw`# enoki-release-e2e:permanent-report-rejection
set -eu
binary=/usr/local/bin/enoki-probe
metadata=/etc/enoki/probe-install.toml
identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml
read_property() {
  systemctl show enoki-probe.service --no-pager --property="$1" --value
}
for attempt in $(seq 1 60); do
  load_state=$(read_property LoadState)
  active_state=$(read_property ActiveState)
  sub_state=$(read_property SubState)
  exit_status=$(read_property ExecMainStatus)
  restart_count=$(read_property NRestarts)
  case "$restart_count" in ''|*[!0-9]*) exit 1 ;; esac
  if [ "$load_state" = loaded ] && [ "$active_state" = failed ] && [ "$sub_state" = failed ] && [ "$exit_status" = 78 ]; then
    break
  fi
  if [ "$attempt" = 60 ]; then
    printf 'Probe service did not reach permanent report failure: LoadState=%s ActiveState=%s SubState=%s ExecMainStatus=%s NRestarts=%s\n' "$load_state" "$active_state" "$sub_state" "$exit_status" "$restart_count" >&2
    exit 1
  fi
  sleep 2
done
restart_count_before=$restart_count
sleep 10
restart_count_after=$(read_property NRestarts)
case "$restart_count_after" in ''|*[!0-9]*) exit 1 ;; esac
[ "$restart_count_after" = "$restart_count_before" ] || { printf 'Probe restart counter changed after permanent report rejection\n' >&2; exit 1; }
[ -x "$binary" ]
[ -f "$metadata" ]
[ -f "$identity" ]
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$identity")
private_key_line=$(grep -E '^probe_private_key_pem = ".+"$' "$identity")
[ "$(grep -c '^probe_id = ' "$identity")" -eq 1 ]
[ "$(grep -c '^probe_private_key_pem = ' "$identity")" -eq 1 ]
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
identity_sha256=$(printf '%s\n%s\n' "$probe_id_line" "$private_key_line" | sha256sum | cut -d ' ' -f 1)
binary_sha256=$(sha256sum -- "$binary" | cut -d ' ' -f 1)
metadata_sha256=$(sha256sum -- "$metadata" | cut -d ' ' -f 1)
printf '{"binarySha256":"%s","identity":{"identitySha256":"%s","probeId":"%s"},"installMetadataSha256":"%s","restartCountAfterObservation":%s,"restartCountBeforeObservation":%s,"service":{"ActiveState":"%s","ExecMainStatus":%s,"LoadState":"%s","SubState":"%s"}}\n' \
  "$binary_sha256" "$identity_sha256" "$probe_id" "$metadata_sha256" "$restart_count_after" "$restart_count_before" "$active_state" "$exit_status" "$load_state" "$sub_state"`;
}

function installedDiagnosticsScript() {
  return String.raw`# enoki-release-e2e:installed-diagnostics
set -eu
binary=/usr/local/bin/enoki-probe
metadata=/etc/enoki/probe-install.toml
identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml
[ -x "$binary" ]
[ -f "$metadata" ]
[ -f "$identity" ]
read_property() {
  systemctl show enoki-probe.service --no-pager --property="$1" --value
}
binary_version=$("$binary" --version | sed -nE 's/.*v?([0-9]+[.][0-9]+[.][0-9]+).*/\1/p' | head -n 1)
case "$binary_version" in ''|*[!0-9.]*|*..*) exit 1 ;; esac
load_state=$(read_property LoadState)
active_state=$(read_property ActiveState)
sub_state=$(read_property SubState)
exit_status=$(read_property ExecMainStatus)
restart_count=$(read_property NRestarts)
result=$(read_property Result)
case "$exit_status" in ''|*[!0-9]*) exit 1 ;; esac
case "$restart_count" in ''|*[!0-9]*) exit 1 ;; esac
[ -n "$result" ]
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$identity")
private_key_line=$(grep -E '^probe_private_key_pem = ".+"$' "$identity")
[ "$(grep -c '^probe_id = ' "$identity")" -eq 1 ]
[ "$(grep -c '^probe_private_key_pem = ' "$identity")" -eq 1 ]
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
identity_sha256=$(printf '%s\n%s\n' "$probe_id_line" "$private_key_line" | sha256sum | cut -d ' ' -f 1)
binary_sha256=$(sha256sum -- "$binary" | cut -d ' ' -f 1)
metadata_sha256=$(sha256sum -- "$metadata" | cut -d ' ' -f 1)
printf '{"binary":{"sha256":"%s","version":"%s"},"identity":{"identitySha256":"%s","probeId":"%s"},"installMetadataSha256":"%s","service":{"ActiveState":"%s","ExecMainStatus":%s,"LoadState":"%s","NRestarts":%s,"Result":"%s","SubState":"%s"}}\n' \
  "$binary_sha256" "$binary_version" "$identity_sha256" "$probe_id" "$metadata_sha256" "$active_state" "$exit_status" "$load_state" "$restart_count" "$result" "$sub_state"`;
}

function probeIdentityScript() {
  return String.raw`# enoki-release-e2e:probe-identity
set -eu
config=/var/lib/enoki-probe/identity/probe-bootstrap.toml
[ -f "$config" ]
[ ! -L "$config" ]
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$config")
private_key_line=$(grep -E '^probe_private_key_pem = ".+"$' "$config")
[ "$(grep -c '^probe_id = ' "$config")" -eq 1 ]
[ "$(grep -c '^probe_private_key_pem = ' "$config")" -eq 1 ]
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
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

function systemdDiagnosticsScript() {
  return String.raw`# enoki-release-e2e:systemd-diagnostics
set -eu
systemctl show enoki-probe.service --no-pager --property=LoadState --property=ActiveState --property=SubState --property=Result --property=ExecMainStatus --property=NRestarts
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

function installedSudoersDiagnosticsScript() {
  return String.raw`# enoki-release-e2e:installed-sudoers
set -eu
found=false
for candidate in /etc/sudoers.d/enoki-probe-operations /etc/sudoers.d/enoki-probe-collector-helpers /etc/sudoers.d/enoki-probe-upgrader; do
  if [ -f "$candidate" ]; then
    found=true
    printf '### %s\n' "$candidate"
    cat -- "$candidate"
  fi
done
"$found"
`;
}

function claimRunScript(runId, token) {
  const users = releaseE2EUsers.map(shellSingleQuote).join(" ");
  const groups = releaseE2EGroups.map(shellSingleQuote).join(" ");
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
for account in ${users}; do
  if getent passwd "$account" >/dev/null 2>&1; then residue="$residue user:$account"; fi
done
for account in ${groups}; do
  if getent group "$account" >/dev/null 2>&1; then residue="$residue group:$account"; fi
done
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

function renewRunResourcesScript(runId, token) {
  return `# enoki-release-e2e:renew-resources
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ -f "$claim/resources" ]
${resourceFingerprintFunction()}
temporary=$(mktemp "$claim/resources.renew.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
mv -- "$temporary" "$claim/resources"
trap - EXIT HUP INT TERM
printf 'renewed\\n'
`;
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
  return `# enoki-release-e2e:post-replacement-failure
set -eu
fail() {
  printf '%s\n' "$1" >&2
  exit 79
}
claim=/var/lib/enoki-release-e2e/claim
dropin=/etc/systemd/system/enoki-probe.service.d/90-enoki-release-e2e-restart-failure.conf
status=/var/lib/enoki-probe/probe-operation-status.toml
[ -d "$claim" ] || fail 'release E2E ownership claim is missing'
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ] || fail 'release E2E run claim changed'
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ] || fail 'release E2E ownership token changed'
[ "$(cat "$claim/upgrade-operation-id")" = ${shellSingleQuote(String(operation.id))} ] || fail 'post-replacement operation binding changed'
[ "$(cat "$claim/post-replacement-fault")" = ${shellSingleQuote(expectedProbeVersion)} ] || fail 'post-replacement target binding changed'
[ -f "$dropin" ] || fail 'post-replacement restart fault is missing'
if [ ! -f "$status" ]; then
  printf 'null\n'
  exit 0
fi
version_output=$(/usr/local/bin/enoki-probe --version) || fail 'candidate Probe version command failed'
version=\${version_output#"enoki-probe "}
version=\${version#v}
[ "$version" = ${shellSingleQuote(expectedProbeVersion)} ] || fail "candidate Probe version mismatch: $version_output"
grep -Fxq ${shellSingleQuote(`operation_id = "${operation.id}"`)} "$status" || fail 'post-replacement status operation changed'
grep -Fxq ${shellSingleQuote(`target_probe_version = "${expectedProbeVersion}"`)} "$status" || fail 'post-replacement status target changed'
if ! grep -Fxq 'status = "failed"' "$status"; then
  if ! grep -Fxq 'status = "running"' "$status"; then
    fail 'unexpected post-replacement status'
  fi
  printf 'null\n'
  exit 0
fi
grep -Fxq 'error_code = "post_replacement_restart_failure"' "$status" || fail 'unexpected post-replacement failure code'
if [ "$(systemctl is-active enoki-probe.service 2>/dev/null || true)" = active ]; then
  fail 'candidate Probe service is still active after injected restart failure'
fi
printf '{"localFailureCode":"post_replacement_restart_failure","operationId":%s,"probeVersion":"%s"}\n' \
  ${shellSingleQuote(String(operation.id))} "$version"
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
[ "$metadata_schema" = bootstrap-v2 ]
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

function resourceFingerprintFunction() {
  return renderReleaseE2EResourceFingerprint(releaseE2EInfrastructureResources);
}

export function renderReleaseE2EResourceFingerprint(resources) {
  const files = resources
    .filter((resource) => resource.kind === "file")
    .map((resource) => shellSingleQuote(resource.path))
    .join(" ");
  const directories = resources
    .filter(
      (resource) =>
        resource.kind === "directory" &&
        resource.systemdStateDirectoryProjection !== true,
    )
    .map((resource) => shellSingleQuote(resource.path))
    .join(" ");
  const systemdStateDirectories = resources
    .filter(
      (resource) =>
        resource.kind === "directory" &&
        resource.systemdStateDirectoryProjection === true,
    )
    .map((resource) => shellSingleQuote(resource.path))
    .join(" ");
  const users = resources
    .filter((resource) => resource.kind === "user")
    .map((resource) => shellSingleQuote(resource.name))
    .join(" ");
  const groups = resources
    .filter((resource) => resource.kind === "group")
    .map((resource) => shellSingleQuote(resource.name))
    .join(" ");
  return String.raw`fingerprint_path() {
  path=$1
  metadata=$(stat -c '%u\t%g\t%a\t%d\t%i\t%s' -- "$path") || return 1
  path_hash=$(printf '%s' "$path" | sha256sum | awk '{print $1}') || return 1
  if [ -L "$path" ]; then
    type=symlink
    content_hash=$(readlink -- "$path" | sha256sum | awk '{print $1}') || return 1
  elif [ -f "$path" ]; then
    type=file
    content_hash=$(sha256sum -- "$path" | awk '{print $1}') || return 1
  elif [ -d "$path" ]; then
    type=directory
    content_hash=-
  else
    type=$(stat -c '%F' -- "$path") || return 1
    content_hash=-
  fi
  printf 'path\t%s\t%s\t%s\t%s\n' "$path_hash" "$type" "$metadata" "$content_hash"
}
fingerprint_directory() {
  directory=$1
  snapshot=$(mktemp "/tmp/enoki-release-e2e-fingerprint.XXXXXX") || return 1
  members=$(mktemp "/tmp/enoki-release-e2e-members.XXXXXX") || {
    rm -f -- "$snapshot"
    return 1
  }
  if ! find -P "$directory" -xdev -print0 > "$snapshot"; then
    rm -f -- "$snapshot" "$members"
    return 1
  fi
  if ! LC_ALL=C sort -z -o "$snapshot" "$snapshot"; then
    rm -f -- "$snapshot" "$members"
    return 1
  fi
  if ! od -An -t u1 "$snapshot" > "$members"; then
    rm -f -- "$snapshot" "$members"
    return 1
  fi
  record_count=$(awk '{ for (field = 1; field <= NF; field += 1) if ($field == 0) count += 1 } END { print count + 0 }' "$members") || {
    rm -f -- "$snapshot" "$members"
    return 1
  }
  if ! tr '\000' '\n' < "$snapshot" > "$members"; then
    rm -f -- "$snapshot" "$members"
    return 1
  fi
  line_count=$(wc -l < "$members") || {
    rm -f -- "$snapshot" "$members"
    return 1
  }
  if [ "$record_count" -ne "$line_count" ]; then
    rm -f -- "$snapshot" "$members"
    return 1
  fi
  status=0
  while IFS= read -r member; do
    [ -n "$member" ] || continue
    fingerprint_path "$member" || { status=1; break; }
  done < "$members"
  rm -f -- "$snapshot" "$members" || status=1
  return "$status"
}
fingerprint_systemd_state_directory() {
  public=$1
  public_parent=$(dirname -- "$public") || return 1
  public_name=$(basename -- "$public") || return 1
  private_parent="$public_parent/private"
  private_state="$private_parent/$public_name"
  identity="$private_state/identity"
  [ -d "$public_parent" ] && [ ! -L "$public_parent" ] || return 1
  [ "$(stat -c %u -- "$public_parent")" = 0 ] || return 1
  [ "$(stat -c %g -- "$public_parent")" = 0 ] || return 1
  [ "$(stat -c %a -- "$public_parent")" = 755 ] || return 1
  [ -L "$public" ] || return 1
  [ "$(stat -c %u -- "$public")" = 0 ] || return 1
  [ "$(stat -c %g -- "$public")" = 0 ] || return 1
  [ "$(stat -c %a -- "$public")" = 777 ] || return 1
  [ "$(stat -c %h -- "$public")" = 1 ] || return 1
  [ "$(readlink -- "$public")" = "private/$public_name" ] || return 1
  [ -d "$private_parent" ] && [ ! -L "$private_parent" ] || return 1
  [ "$(stat -c %u -- "$private_parent")" = 0 ] || return 1
  [ "$(stat -c %g -- "$private_parent")" = 0 ] || return 1
  [ "$(stat -c %a -- "$private_parent")" = 700 ] || return 1
  [ -d "$private_state" ] && [ ! -L "$private_state" ] || return 1
  state_uid=$(stat -c %u -- "$private_state") || return 1
  state_gid=$(stat -c %g -- "$private_state") || return 1
  [ "$(stat -c %a -- "$private_state")" = 750 ] || return 1
  [ "$(stat -c %h -- "$private_state")" -ge 2 ] || return 1
  [ -d "$identity" ] && [ ! -L "$identity" ] || return 1
  [ "$(stat -c %u -- "$identity")" = "$state_uid" ] || return 1
  [ "$(stat -c %g -- "$identity")" = "$state_gid" ] || return 1
  [ "$(stat -c %a -- "$identity")" = 700 ] || return 1
  [ "$(stat -c %h -- "$identity")" -ge 2 ] || return 1
  [ "$(stat -Lc %d:%i -- "$public")" = "$(stat -c %d:%i -- "$private_state")" ] || return 1
  fingerprint_path "$public" || return 1
  fingerprint_directory "$private_state" || return 1
}
fingerprint() {
  for candidate in ${files}; do
    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
      [ -f "$candidate" ] && [ ! -L "$candidate" ] || return 1
      fingerprint_path "$candidate" || return 1
    fi
  done
  for candidate in ${directories}; do
    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
      [ -d "$candidate" ] && [ ! -L "$candidate" ] || return 1
      fingerprint_directory "$candidate" || return 1
    fi
  done
  for candidate in ${systemdStateDirectories}; do
    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
      fingerprint_systemd_state_directory "$candidate" || return 1
    else
      private_candidate="$(dirname -- "$candidate")/private/$(basename -- "$candidate")"
      [ ! -e "$private_candidate" ] && [ ! -L "$private_candidate" ] || return 1
    fi
  done
  for account in ${users}; do
    if entry=$(getent passwd "$account"); then
      uid=$(printf '%s' "$entry" | cut -d: -f3) || return 1
      gid=$(printf '%s' "$entry" | cut -d: -f4) || return 1
      entry_hash=$(printf '%s' "$entry" | sha256sum | awk '{print $1}') || return 1
      printf 'user\t%s\t%s\t%s\t%s\n' "$account" "$uid" "$gid" "$entry_hash"
    fi
  done
  for account in ${groups}; do
    if entry=$(getent group "$account"); then
      gid=$(printf '%s' "$entry" | cut -d: -f3) || return 1
      entry_hash=$(printf '%s' "$entry" | sha256sum | awk '{print $1}') || return 1
      printf 'group\t%s\t%s\t%s\n' "$account" "$gid" "$entry_hash"
    fi
  done
}`;
}

function knownProbeInstallMetadataScript() {
  return String.raw`metadata=/etc/enoki/probe-install.toml
[ -f "$metadata" ]
[ ! -L "$metadata" ]
[ "$(stat -c %u "$metadata")" = 0 ]
[ "$(stat -c %a "$metadata")" = 600 ]
require_metadata_line() { [ "$(grep -Fxc "$1" "$metadata")" -eq 1 ]; }
require_metadata_line 'schema_version = 2'
require_metadata_line 'install_path = "/usr/local/bin/enoki-probe"'
require_metadata_line 'state_dir = "/var/lib/enoki-probe"'
require_metadata_line 'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"'
require_metadata_line 'service_name = "enoki-probe"'
require_metadata_line 'service_user = "enoki-probe"'
require_metadata_line 'identity_path = "/var/lib/enoki-probe/identity/probe-bootstrap.toml"'
require_metadata_line 'service_group = "enoki-probe"'
require_metadata_line 'service_unit_path = "/etc/systemd/system/enoki-probe.service"'
[ "$(grep -c '^schema_version = ' "$metadata")" -eq 1 ]
! grep -Eq 'sudoers|upgrader' "$metadata"
metadata_schema=bootstrap-v2`;
}

function removeClaimScript(runId, token) {
  return `# enoki-release-e2e:remove-claim\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\n[ -d "$claim" ]\n[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]\n[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]\nrm -f -- "$claim/resources" "$claim/upgrade-before-resources" "$claim/upgrade-target" "$claim/upgrade-operation-id" "$claim/post-replacement-fault"\nrm -- "$claim/run-id" "$claim/token"\nrmdir "$claim"\nrmdir /var/lib/enoki-release-e2e 2>/dev/null || true\n`;
}

function inspectClaimScript(runId, token) {
  return `# enoki-release-e2e:inspect-claim\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\nif [ ! -e "$claim" ]; then printf 'absent\\n'; elif [ -d "$claim" ] && [ "$(cat "$claim/run-id" 2>/dev/null || true)" = ${shellSingleQuote(runId)} ] && [ "$(cat "$claim/token" 2>/dev/null || true)" = ${shellSingleQuote(token)} ]; then printf 'owned\\n'; else printf 'foreign\\n'; fi\n`;
}

function releaseEmergencyCleanupScript(runId, token) {
  const pathsFor = (kind) =>
    releaseE2EInfrastructureResources
      .filter((resource) => resource.kind === kind)
      .map((resource) => shellSingleQuote(resource.path))
      .join(" ");
  const namesFor = (kind) =>
    releaseE2EInfrastructureResources
      .filter((resource) => resource.kind === kind)
      .map((resource) => shellSingleQuote(resource.name))
      .join(" ");
  const files = releaseE2EInfrastructureResources
    .filter(
      (resource) =>
        resource.kind === "file" &&
        !releaseE2ESystemdStateProjections.some((projection) =>
          resource.path.startsWith(`${projection.publicPath}/`),
        ),
    )
    .map((resource) => shellSingleQuote(resource.path))
    .join(" ");
  const privateStateDirectories = releaseE2ESystemdStateProjections
    .map((projection) => shellSingleQuote(projection.privatePath))
    .join(" ");
  const directories = pathsFor("directory");
  const users = namesFor("user");
  const groups = namesFor("group");
  const services = namesFor("service");
  return `# enoki-release-e2e:emergency-cleanup
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ -f "$claim/resources" ]
${resourceFingerprintFunction()}
temporary=$(mktemp "$claim/resources.cleanup.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
cmp --silent "$claim/resources" "$temporary" || { printf 'run-owned resource fingerprint changed\\n' >&2; exit 75; }
systemctl disable --now ${services} >/dev/null 2>&1 || true
rm -f -- ${files}
rm -rf -- ${privateStateDirectories}
rm -rf -- ${directories}
for account in ${users}; do userdel -- "$account" >/dev/null 2>&1 || true; done
for account in ${groups}; do groupdel -- "$account" >/dev/null 2>&1 || true; done
printf 'cleaned\\n'
`;
}

function inventoryResidue(inventory) {
  const residue = [];
  if (inventory?.accounts?.user) {
    residue.push(...releaseE2EUsers.map((account) => `user:${account}`));
  }
  if (inventory?.accounts?.group) {
    residue.push(...releaseE2EGroups.map((account) => `group:${account}`));
  }
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

function assertInstallCommand(command, expectedSourceProbeSha256) {
  if (
    typeof command !== "string" ||
    command.length > 16_384 ||
    command.includes("\n")
  ) {
    throw new Error("Hub returned an invalid Probe install command");
  }
  const recipe = command.match(
    /^printf '%s\\n' '((?:[^'\r\n]|'"'"')*)' \| python3 -- \.\/enoki-probe-bootstrap\.py --hub-origin '(https?:\/\/[^'\s]+)'$/,
  );
  if (recipe) {
    assertInstallHubOrigin(recipe[2]);
    return {
      ...parseBootstrapEnrollmentAuthority(
        decodeShellSingleQuoted(recipe[1]),
        recipe[2],
        expectedSourceProbeSha256,
      ),
      hubUrl: recipe[2],
      kind: "bootstrap-recipe",
    };
  }
  const legacy = command.match(
    /^curl -fsSL '(https?:\/\/[^'\s]+\/api\/probe\/install\.sh)' \| sudo env ENOKI_HUB_URL='(https?:\/\/[^'\s]+)' ENOKI_ENROLLMENT_TOKEN='(enk_enroll_[A-Za-z0-9_-]+)' bash$/,
  );
  if (legacy) {
    assertInstallHubOrigin(legacy[2]);
    if (legacy[1] !== `${legacy[2]}/api/probe/install.sh`) {
      throw new Error("Hub returned an invalid Probe install command");
    }
    return { hubUrl: legacy[2], kind: "legacy-v0.1.74", token: legacy[3] };
  }
  throw new Error("Hub returned an invalid Probe install command");
}

function decodeShellSingleQuoted(value) {
  return value.replaceAll(`'"'"'`, "'");
}

function parseBootstrapEnrollmentAuthority(
  authority,
  commandHubOrigin,
  expectedSourceProbeSha256,
) {
  if (/^enk_enroll_[A-Za-z0-9_-]+$/.test(authority)) {
    return { replacementMigration: null, token: authority };
  }
  let parsed;
  try {
    parsed = JSON.parse(authority);
  } catch {
    throw new Error("Hub returned an invalid Probe install command");
  }
  const migration = parsed?.replacementMigration;
  if (
    !parsed ||
    Array.isArray(parsed) ||
    JSON.stringify(Object.keys(parsed).sort()) !==
      JSON.stringify(
        [
          "enrollmentToken",
          "hubOrigin",
          "replacementMigration",
          "schemaVersion",
        ].sort(),
      ) ||
    parsed.schemaVersion !== 1 ||
    parsed.hubOrigin !== commandHubOrigin ||
    !/^enk_enroll_[A-Za-z0-9_-]+$/.test(parsed.enrollmentToken ?? "") ||
    !migration ||
    Array.isArray(migration) ||
    JSON.stringify(Object.keys(migration).sort()) !==
      JSON.stringify(
        [
          "enrollmentId",
          "expectedProbeId",
          "sourceProbeSha256",
          "sourceProbeVersion",
          "targetAssetSetDigest",
          "targetHostId",
          "targetProbeVersion",
        ].sort(),
      ) ||
    !/^enr_[A-Za-z0-9_-]{16,}$/.test(migration.enrollmentId ?? "") ||
    !/^[A-Za-z0-9_-]+$/.test(migration.expectedProbeId ?? "") ||
    !Array.isArray(migration.sourceProbeSha256) ||
    migration.sourceProbeSha256.length !== probeTargets.length ||
    migration.sourceProbeSha256.some(
      (digest) => !/^[0-9a-f]{64}$/.test(digest ?? ""),
    ) ||
    new Set(migration.sourceProbeSha256).size !== probeTargets.length ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      migration.sourceProbeVersion ?? "",
    ) ||
    !/^sha256:[0-9a-f]{64}$/.test(migration.targetAssetSetDigest ?? "") ||
    !/^[1-9]\d*$/.test(migration.targetHostId ?? "") ||
    !Number.isSafeInteger(Number(migration.targetHostId)) ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      migration.targetProbeVersion ?? "",
    ) ||
    JSON.stringify({
      hubOrigin: parsed.hubOrigin,
      enrollmentToken: parsed.enrollmentToken,
      replacementMigration: {
        enrollmentId: migration.enrollmentId,
        expectedProbeId: migration.expectedProbeId,
        sourceProbeSha256: migration.sourceProbeSha256,
        sourceProbeVersion: migration.sourceProbeVersion,
        targetAssetSetDigest: migration.targetAssetSetDigest,
        targetHostId: migration.targetHostId,
        targetProbeVersion: migration.targetProbeVersion,
      },
      schemaVersion: parsed.schemaVersion,
    }) !== authority ||
    (expectedSourceProbeSha256 !== undefined &&
      JSON.stringify(migration.sourceProbeSha256) !==
        JSON.stringify(expectedSourceProbeSha256))
  ) {
    throw new Error("Hub returned an invalid Probe install command");
  }
  return {
    replacementMigration: migration,
    token: parsed.enrollmentToken,
  };
}

function assertInstallHubOrigin(value) {
  const url = new URL(value);
  if (
    url.origin !== value ||
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username ||
    url.password
  ) {
    throw new Error("Hub returned an invalid Probe install command");
  }
}

function assertEnrollmentInstallContract(enrollment, options = {}) {
  const parsed = assertInstallCommand(
    enrollment?.installCommand,
    options.sourceProbeSha256,
  );
  if (
    enrollment?.enrollmentToken !== parsed.token ||
    enrollment?.hubUrl !== parsed.hubUrl
  ) {
    throw new Error(
      "Hub Enrollment install command is not bound to its token and origin",
    );
  }
  if (parsed.replacementMigration) {
    if (
      enrollment?.enrollmentId !== parsed.replacementMigration.enrollmentId ||
      enrollment?.target?.kind !== "manual_reinstall" ||
      String(enrollment.target.hostId) !==
        parsed.replacementMigration.targetHostId
    ) {
      throw new Error(
        "Hub Enrollment install command is not bound to its Replacement target",
      );
    }
  } else if (enrollment?.target?.kind === "manual_reinstall") {
    throw new Error(
      "Hub manual Probe reinstall Enrollment has no Replacement authority",
    );
  }
  if (parsed.kind === "bootstrap-recipe") {
    assertBootstrapRecipeRecord(enrollment.bootstrapRecipe);
  } else if (enrollment.bootstrapRecipe !== undefined) {
    throw new Error(
      "Legacy Enrollment unexpectedly supplied a Probe Bootstrap recipe",
    );
  }
  return {
    hubUrl: parsed.hubUrl,
    kind: parsed.kind,
    ...(parsed.replacementMigration
      ? { replacementMigration: parsed.replacementMigration }
      : {}),
    token: parsed.token,
  };
}

function assertBootstrapRecipeRecord(record) {
  assertExactObjectKeys(record, [
    "bundleVersion",
    "distribution",
    "kind",
    "recipe",
    "rootFingerprint",
    "schemaVersion",
    "targets",
  ]);
  assertExactObjectKeys(record.recipe, ["file", "sha256", "size", "version"]);
  if (
    record.kind !== "enoki-probe-bootstrap-recipe-record" ||
    record.schemaVersion !== 1 ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      record.bundleVersion ?? "",
    ) ||
    record.distribution !== "enoki" ||
    !/^[0-9a-f]{64}$/.test(record.rootFingerprint ?? "") ||
    JSON.stringify(record.targets) !== JSON.stringify(probeTargets) ||
    record.recipe.file !== "enoki-probe-bootstrap.py" ||
    record.recipe.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(record.recipe.sha256 ?? "") ||
    !isPositiveSafeInteger(record.recipe.size)
  ) {
    throw new Error("Hub returned an invalid Probe Bootstrap recipe record");
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

function assertExactObjectKeys(value, expectedKeys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    JSON.stringify(Object.keys(value).sort()) !==
      JSON.stringify([...expectedKeys].sort())
  ) {
    throw new Error(
      `Release E2E manifest fields must be exactly: ${expectedKeys.join(", ")}`,
    );
  }
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

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
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

function assertCanonicalRuntimeUnavailableHostEvidence(
  evidence,
  expectedProbeId,
) {
  const identity = evidence?.identity;
  const probe = evidence?.probe;
  const runtime = evidence?.runtime;
  if (
    identity?.probeId !== expectedProbeId ||
    identity.registrationAttemptCredential !== false ||
    identity.registrationAttemptSource !== false ||
    identity.registrationDropIn !== false ||
    identity.transitionalRegistrationKeys !== false ||
    probe?.ActiveState !== "active" ||
    probe.LoadState !== "loaded" ||
    probe.Result !== "success" ||
    probe.SubState !== "running" ||
    probe.Type !== "notify" ||
    runtime?.serviceLoadState !== "masked" ||
    runtime.socketLoadState !== "masked"
  ) {
    throw new Error("canonical Runtime-unavailable Host evidence is invalid");
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
    hostMethods.push("assertLegacyReleaseBaselineInstalled", "manualReinstall");
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

export function isCandidateHostReady(value, expectedProbeVersion) {
  const profile = value?.hostProfile;
  const nonEmptyString = (candidate) =>
    typeof candidate === "string" && candidate.trim().length > 0;
  const normalizedProbeVersion = (candidate) =>
    typeof candidate === "string" ? candidate.trim().replace(/^v/, "") : "";
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
    normalizedProbeVersion(profile.probeVersion) ===
      normalizedProbeVersion(expectedProbeVersion) &&
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
  if (error?.installerEvidence) {
    serialized.installerEvidence = error.installerEvidence;
  }
  if (error instanceof AggregateError) {
    serialized.errors = error.errors.map((nested) => serializedError(nested));
  }
  return serialized;
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
