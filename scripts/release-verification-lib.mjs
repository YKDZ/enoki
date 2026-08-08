import {
  hasAdvancingPortableMetrics,
  isCandidateHostReady,
} from "./release-e2e-lib.mjs";
import { createGitHubActionsMatrix } from "./release-e2e-matrix.mjs";

const requiredComponentNames = Object.freeze([
  "inputValidation",
  "standardCi",
  "releaseBaseline",
  "probeBuild",
  "probePreparation",
  "probeSigning",
  "hubOciBuild",
  "candidateAssembly",
  "matrixExpansion",
  "hostMatrix",
  "candidateUiContract",
]);

export function createMatrixGateResult({
  artifactName,
  candidate,
  cellId,
  evidence,
  scenarioOutcome,
  verifyCleanOutcome,
}) {
  const evidenceOutcome = normalizeEvidenceOutcome(evidence?.result?.status);
  const scenarioId = evidence?.scenario ?? null;
  const successfulSteps =
    scenarioOutcome === "success" && verifyCleanOutcome === "success";
  const consistentEvidence =
    typeof scenarioId === "string" &&
    cellId === `${cellIdEnvironment(cellId)}--${scenarioId}` &&
    sameCandidate(evidence?.candidate, candidate);
  const acceptableEvidence = evidenceOutcome === "succeeded";
  const evidenceValidationErrors = validateHostScenarioEvidence(
    evidence,
    evidenceOutcome,
  );

  return {
    artifactName,
    candidate,
    cellId,
    evidenceOutcome,
    evidenceValidationErrors,
    kind: "enoki-release-e2e-gate",
    outcome:
      successfulSteps &&
      consistentEvidence &&
      acceptableEvidence &&
      evidenceValidationErrors.length === 0
        ? evidenceOutcome
        : "failed",
    scenarioId,
    scenarioStepOutcome: scenarioOutcome,
    schemaVersion: 1,
    verifyCleanStepOutcome: verifyCleanOutcome,
  };
}

function validateHostScenarioEvidence(evidence, outcome) {
  if (outcome !== "succeeded") return [];

  const errors = [];
  if (evidence?.schemaVersion !== 2) errors.push("invalid schemaVersion");
  if (evidence?.phase !== "succeeded") errors.push("phase was not succeeded");
  validateCleanupEvidence(evidence?.cleanup, errors);
  validateUninstallEvidence(evidence?.uninstall, errors);

  const requiredByScenario = {
    "baseline-upgrade-uninstall": [
      "auditLog",
      "candidateHost",
      "compatibility",
      "hostBoundary",
      "identityContinuity",
      "metrics",
      "probeConfiguration",
      "upgradeOperationTimeline",
    ],
    "fresh-install-uninstall": [
      "auditLog",
      "host",
      "hostBoundary",
      "metrics",
      "probeConfiguration",
    ],
    "hub-restore-compatibility-window": [
      "hostProfileContinuity",
      "identity",
      "image",
      "migration",
      "protocol",
      "reporting",
      "snapshot",
    ],
    "post-replacement-repair-uninstall": [
      "auditLog",
      "boundaryEvidenceValidation",
      "failureBoundary",
      "identityContinuity",
      "metrics",
      "operationTimeline",
      "probeConfiguration",
      "repair",
      "repairHostBoundary",
      "repairedHost",
    ],
  };
  for (const field of requiredByScenario[evidence?.scenario] ?? []) {
    if (evidence?.[field] == null) errors.push(`missing ${field}`);
  }

  if (evidence?.scenario === "fresh-install-uninstall") {
    validateFreshEvidence(evidence, errors);
  } else if (evidence?.scenario === "baseline-upgrade-uninstall") {
    validateBaselineEvidence(evidence, errors);
  } else if (evidence?.scenario === "post-replacement-repair-uninstall") {
    validateRepairEvidence(evidence, errors);
  } else if (evidence?.scenario === "hub-restore-compatibility-window") {
    validateRestoreEvidence(evidence, errors);
  } else {
    errors.push("unknown Host scenario");
  }
  return [...new Set(errors)];
}

function validateFreshEvidence(evidence, errors) {
  const version = candidateProbeVersion(evidence);
  if (!isCandidateHostReady(evidence?.host, version)) {
    errors.push("fresh Host Profile is invalid");
  }
  validateMetrics(evidence?.metrics, "fresh reporting", errors);
  validateProbeConfiguration(evidence?.probeConfiguration, errors);
  validateLifecycleAuditLog(evidence, false, errors);
  validateInstalledHostBoundary(evidence?.hostBoundary, version, errors);
}

function validateBaselineEvidence(evidence, errors) {
  const version = candidateProbeVersion(evidence);
  validateTerminalOperation(
    evidence?.upgradeOperationTimeline,
    "probe_upgrade",
    "succeeded",
    "baseline Upgrade",
    errors,
  );
  if (
    evidence?.compatibility?.status !== "succeeded" ||
    !isCandidateHostReady(
      evidence.compatibility?.host,
      evidence?.releaseBaseline?.probeVersion,
    )
  ) {
    errors.push("baseline compatibility was not proved");
  }
  if (!isCandidateHostReady(evidence?.candidateHost, version)) {
    errors.push("Candidate Host Profile is invalid");
  }
  validateIdentityContinuity(
    evidence?.identityContinuity,
    evidence?.candidateHost?.id,
    errors,
  );
  validateMetrics(evidence?.metrics?.beforeUpgrade, "pre-Upgrade", errors);
  validateMetrics(evidence?.metrics?.afterUpgrade, "post-Upgrade", errors);
  validateMetricsProgression(
    evidence?.metrics?.beforeUpgrade,
    evidence?.metrics?.afterUpgrade,
    "Upgrade",
    errors,
  );
  validateProbeConfiguration(
    evidence?.probeConfiguration?.beforeUpgrade,
    errors,
  );
  validateProbeConfiguration(
    evidence?.probeConfiguration?.afterUpgrade,
    errors,
  );
  validateLifecycleAuditLog(evidence, true, errors);
  validateInstalledHostBoundary(evidence?.hostBoundary, version, errors);
}

function validateRepairEvidence(evidence, errors) {
  const version = candidateProbeVersion(evidence);
  validateTerminalOperation(
    evidence?.operationTimeline,
    "probe_upgrade",
    "failed",
    "failed Upgrade",
    errors,
  );
  const failed = evidence?.operationTimeline?.at(-1);
  if (
    typeof failed?.failure?.code !== "string" ||
    !failed.failure.code ||
    evidence?.failureBoundary?.hubFailureCode !== failed.failure.code ||
    evidence?.failureBoundary?.localFailureCode !==
      "post_replacement_restart_failure" ||
    evidence?.failureBoundary?.probeVersion !== version
  ) {
    errors.push("post-replacement failure boundary is invalid");
  }
  if (failed?.targetProbeVersion !== version) {
    errors.push("failed Upgrade Candidate version is invalid");
  }
  if (evidence?.boundaryEvidenceValidation?.status !== "succeeded") {
    errors.push("Repair boundary validation did not succeed");
  }
  if (
    evidence?.repair?.repairedVersion !== version ||
    typeof evidence?.repair?.probeId !== "string" ||
    !evidence.repair.probeId
  ) {
    errors.push("Repair completion is incomplete");
  }
  if (!isCandidateHostReady(evidence?.repairedHost, version)) {
    errors.push("repaired Host Profile is invalid");
  }
  validateIdentityContinuity(
    evidence?.identityContinuity,
    evidence?.repairedHost?.id,
    errors,
  );
  if (
    evidence?.repair?.probeId !== evidence?.identityContinuity?.before?.probeId
  ) {
    errors.push("Repair identity continuity is invalid");
  }
  validateMetrics(evidence?.metrics?.beforeUpgrade, "pre-failure", errors);
  validateMetrics(evidence?.metrics?.afterRepair, "post-Repair", errors);
  validateMetricsProgression(
    evidence?.metrics?.beforeUpgrade,
    evidence?.metrics?.afterRepair,
    "Repair",
    errors,
  );
  validateProbeConfiguration(
    evidence?.probeConfiguration?.beforeUpgrade,
    errors,
  );
  validateProbeConfiguration(evidence?.probeConfiguration?.afterRepair, errors);
  validateInstalledHostBoundary(evidence?.repairHostBoundary, version, errors);
  validateLifecycleAuditLog(evidence, true, errors);
}

function validateMetrics(metrics, label, errors) {
  if (!hasAdvancingPortableMetrics(metrics)) {
    errors.push(`${label} metrics are incomplete`);
  }
}

function validateMetricsProgression(before, after, label, errors) {
  const previous = Array.isArray(before) ? before.at(-1) : null;
  const current = Array.isArray(after) ? after.at(-1) : null;
  if (
    !Number.isSafeInteger(previous?.sequence) ||
    !Number.isSafeInteger(current?.sequence) ||
    current.sequence <= previous.sequence ||
    current.collectedAtMs <= previous.collectedAtMs
  ) {
    errors.push(`${label} metrics did not advance across the boundary`);
  }
}

function validateProbeConfiguration(configuration, errors) {
  if (
    configuration?.mode !== "override" ||
    typeof configuration?.version !== "string" ||
    !configuration.version ||
    configuration.reportedVersion !== configuration.version
  ) {
    errors.push("Probe Configuration round-trip is invalid");
  }
}

function validateLifecycleAuditLog(evidence, requiresUpgrade, errors) {
  const auditLog = evidence?.auditLog;
  const requiredActions = [
    "enrollment_token.create",
    "probe_configuration.host.override",
    "host.delete",
    ...(requiresUpgrade ? ["probe_upgrade_request.create"] : []),
  ];
  const hostId =
    evidence?.host?.id ??
    evidence?.candidateHost?.id ??
    evidence?.repairedHost?.id;
  const uninstallId = evidence?.uninstall?.operationTimeline?.[0]?.id;
  const upgradeId =
    evidence?.upgradeOperationTimeline?.[0]?.id ??
    evidence?.operationTimeline?.[0]?.id;
  const validEvent = (event) =>
    event?.actor === "owner" &&
    event.outcome === "success" &&
    Number.isSafeInteger(event.id) &&
    event.id > 0 &&
    Number.isSafeInteger(event.occurredAtMs) &&
    event.occurredAtMs > 0 &&
    typeof event.subjectId === "string" &&
    event.subjectId.length > 0 &&
    typeof event.subjectType === "string" &&
    event.subjectType.length > 0;
  const byAction = (action) =>
    Array.isArray(auditLog)
      ? auditLog.find((event) => event?.action === action)
      : null;
  const deleted = byAction("host.delete");
  const configured = byAction("probe_configuration.host.override");
  const upgraded = byAction("probe_upgrade_request.create");
  if (
    !Array.isArray(auditLog) ||
    requiredActions.some(
      (action) =>
        !auditLog.some(
          (event) => event?.action === action && validEvent(event),
        ),
    ) ||
    configured?.subjectId !== String(hostId) ||
    deleted?.subjectId !== String(hostId) ||
    deleted?.subjectType !== "host" ||
    deleted?.details?.hostId !== hostId ||
    deleted?.details?.probeOperationId !== uninstallId ||
    (requiresUpgrade &&
      (upgraded?.subjectId !== String(upgradeId) ||
        upgraded?.subjectType !== "probe_upgrade_request" ||
        upgraded?.details?.hostId !== hostId ||
        upgraded?.details?.targetProbeVersion !==
          candidateProbeVersion(evidence)))
  ) {
    errors.push("lifecycle Audit Log is invalid");
  }
}

function validateInstalledHostBoundary(boundary, version, errors) {
  const inventory = boundary?.inventory;
  const files = inventory?.files;
  if (
    boundary?.probeVersion !== version ||
    inventory?.accounts?.user !== true ||
    inventory?.accounts?.group !== true ||
    !Array.isArray(files) ||
    !files.includes("/usr/local/bin/enoki-probe") ||
    !files.includes("/etc/systemd/system/enoki-probe.service") ||
    !files.includes("/etc/sudoers.d/enoki-probe-operations") ||
    !Array.isArray(inventory?.units) ||
    !inventory.units.includes("enoki-probe.service") ||
    boundary?.service?.LoadState !== "loaded" ||
    boundary?.service?.ActiveState !== "active" ||
    boundary?.service?.User !== "enoki-probe" ||
    boundary?.service?.Group !== "enoki-probe" ||
    typeof boundary?.sudoers !== "string" ||
    !boundary.sudoers.includes("enoki-probe-uninstaller")
  ) {
    errors.push("Host installation boundary is invalid");
  }
}

function validateIdentityContinuity(identity, hostId, errors) {
  const before = identity?.before;
  const after = identity?.after;
  if (
    !Number.isSafeInteger(identity?.hostId) ||
    identity.hostId !== hostId ||
    typeof before?.probeId !== "string" ||
    !before.probeId ||
    !/^[0-9a-f]{64}$/.test(before?.identitySha256 ?? "") ||
    after?.probeId !== before.probeId ||
    after?.identitySha256 !== before.identitySha256
  ) {
    errors.push("Probe Identity continuity is invalid");
  }
}

function candidateProbeVersion(evidence) {
  const version = evidence?.candidate?.version;
  return typeof version === "string" && version.startsWith("v")
    ? version.slice(1)
    : null;
}

function validateCleanupEvidence(cleanup, errors) {
  if (cleanup?.host?.clean !== true) errors.push("Host cleanup was not clean");
  if (cleanup?.environment?.clean !== true) {
    errors.push("environment cleanup was not clean");
  }
}

function validateUninstallEvidence(uninstall, errors) {
  if (uninstall?.status !== "succeeded") {
    errors.push("Probe Uninstall did not succeed");
  }
  if (uninstall?.hubSoftDeleted !== true) {
    errors.push("Hub Host was not soft-deleted");
  }
  validateTerminalOperation(
    uninstall?.operationTimeline,
    "probe_uninstall",
    "succeeded",
    "Probe Uninstall",
    errors,
  );
  const completion = uninstall?.hostCompletion;
  if (
    completion?.clean !== true ||
    completion?.journaldRetained !== true ||
    completion?.sharedDependenciesRetained !== true
  ) {
    errors.push("Host uninstall completion is incomplete");
  }
  const inventory = completion?.inventory;
  if (
    inventory?.accounts?.user !== false ||
    inventory?.accounts?.group !== false ||
    !Array.isArray(inventory?.files) ||
    inventory.files.length > 0 ||
    !Array.isArray(inventory?.units) ||
    inventory.units.length > 0
  ) {
    errors.push("Host uninstall inventory contains residue");
  }
}

function validateTerminalOperation(timeline, kind, state, label, errors) {
  const requested = Array.isArray(timeline) ? timeline[0] : null;
  const final = Array.isArray(timeline) ? timeline.at(-1) : null;
  const operationIds = new Set(
    Array.isArray(timeline)
      ? timeline.map((entry) => entry?.id).filter(Number.isSafeInteger)
      : [],
  );
  const stable = Array.isArray(timeline) ? timeline.at(-2) : null;
  const validTimestamp = (value) =>
    value === null || (Number.isSafeInteger(value) && value >= 0);
  if (
    !Array.isArray(timeline) ||
    timeline.length < 3 ||
    requested?.kind !== kind ||
    requested?.state !== "pending" ||
    !Number.isSafeInteger(requested?.id) ||
    requested.id < 1 ||
    !Number.isSafeInteger(requested?.hostId) ||
    requested.hostId < 1 ||
    requested.acceptedAtMs !== null ||
    requested.runningAtMs !== null ||
    requested.completedAtMs !== null ||
    timeline.some(
      (operation) =>
        operation?.id !== requested.id ||
        operation?.hostId !== requested.hostId ||
        operation?.kind !== kind ||
        operation?.targetProbeVersion !== requested.targetProbeVersion ||
        !validTimestamp(operation?.acceptedAtMs) ||
        !validTimestamp(operation?.runningAtMs) ||
        !validTimestamp(operation?.completedAtMs),
    ) ||
    final?.kind !== kind ||
    final?.state !== state ||
    (state === "succeeded" ? Boolean(final?.failure) : !final?.failure) ||
    !Number.isSafeInteger(final?.acceptedAtMs) ||
    !Number.isSafeInteger(final?.completedAtMs) ||
    (state === "succeeded" && !Number.isSafeInteger(final?.runningAtMs)) ||
    stable?.state !== final?.state ||
    stable?.failure?.code !== final?.failure?.code ||
    stable?.acceptedAtMs !== final?.acceptedAtMs ||
    stable?.runningAtMs !== final?.runningAtMs ||
    stable?.completedAtMs !== final?.completedAtMs ||
    operationIds.size !== 1
  ) {
    errors.push(`${label} operation timeline is invalid`);
  }
}

function validateRestoreEvidence(evidence, errors) {
  const version = candidateProbeVersion(evidence);
  validateTerminalOperation(
    evidence?.migration?.operationTimeline,
    "probe_upgrade",
    "succeeded",
    "restore migration",
    errors,
  );
  if (evidence?.migration?.status !== "succeeded") {
    errors.push("restore migration did not succeed");
  }
  if (evidence?.migration?.candidateProbeVersion !== version) {
    errors.push("restore migration Candidate version is invalid");
  }
  if (
    evidence?.migration?.operationTimeline?.[0]?.targetProbeVersion !== version
  ) {
    errors.push("restore migration target version is invalid");
  }
  if (
    evidence?.protocol?.baselineProbeToCandidateHub !== "succeeded" ||
    evidence?.protocol?.candidateProbeToBaselineHub !== "succeeded"
  ) {
    errors.push("restore compatibility window was not proved");
  }
  const snapshotDigest = evidence?.snapshot?.manifestDigest;
  const baselineDigest = evidence?.releaseBaseline?.hubDigest;
  if (
    evidence?.snapshot?.tool !== "enoki-hub-state" ||
    evidence?.snapshot?.version !== "v1" ||
    evidence?.snapshot?.baselineImageDigest !== baselineDigest ||
    !Number.isFinite(Date.parse(evidence?.snapshot?.recoveryTime ?? "")) ||
    !Number.isSafeInteger(evidence?.snapshot?.hotDataFileCount) ||
    evidence.snapshot.hotDataFileCount < 1 ||
    !Array.isArray(evidence?.snapshot?.hotDataFiles) ||
    evidence.snapshot.hotDataFiles.length < 1 ||
    !Array.isArray(evidence?.snapshot?.roots) ||
    !evidence.snapshot.roots.some(
      (root) => root?.id === "data-root" && root.path === "/data",
    ) ||
    !evidence.snapshot.roots.some(
      (root) => root?.id === "metrics-archive" && root.included === true,
    ) ||
    evidence?.image?.snapshotVerify?.status !== "succeeded" ||
    evidence?.image?.snapshotVerify?.manifestDigest !== snapshotDigest ||
    evidence?.image?.stateRestore?.status !== "succeeded" ||
    evidence?.image?.stateRestore?.manifestDigest !== snapshotDigest ||
    !/^sha256:[0-9a-f]{64}$/.test(snapshotDigest ?? "") ||
    !/^sha256:[0-9a-f]{64}$/.test(baselineDigest ?? "") ||
    evidence?.image?.expectedBaselineDigest !== baselineDigest ||
    evidence?.image?.restoredBaselineDigest !== baselineDigest
  ) {
    errors.push("snapshot verification or restore evidence is invalid");
  }
  const candidateReporting = evidence?.reporting?.candidateHub;
  const restoredReporting = evidence?.reporting?.restoredBaselineHub;
  if (
    !isCandidateHostReady(candidateReporting?.host, version) ||
    !isCandidateHostReady(restoredReporting?.host, version)
  ) {
    errors.push("Candidate-to-Baseline Host reporting is invalid");
  }
  validateMetrics(candidateReporting?.metrics, "pre-Restore", errors);
  validateMetrics(restoredReporting?.metrics, "post-Restore", errors);
  validateMetricsProgression(
    candidateReporting?.metrics,
    restoredReporting?.metrics,
    "Restore",
    errors,
  );
  const identity = evidence?.identity;
  const identities = [
    identity?.beforeUpgrade,
    identity?.afterUpgrade,
    identity?.afterRestore,
  ];
  if (
    !Number.isSafeInteger(identity?.hostId) ||
    identity.hostId !== candidateReporting?.host?.id ||
    identity.hostId !== restoredReporting?.host?.id ||
    identities.some(
      (value) =>
        typeof value?.probeId !== "string" ||
        !value.probeId ||
        !/^[0-9a-f]{64}$/.test(value?.identitySha256 ?? ""),
    ) ||
    identities.some(
      (value) =>
        value?.probeId !== identities[0]?.probeId ||
        value?.identitySha256 !== identities[0]?.identitySha256,
    )
  ) {
    errors.push("Restore Probe Identity continuity is invalid");
  }
  const beforeProfile = evidence?.hostProfileContinuity?.candidateBeforeRestore;
  const restoredProfile = evidence?.hostProfileContinuity?.restoredBaseline;
  if (
    !/^[0-9a-f]{64}$/.test(beforeProfile?.sha256 ?? "") ||
    restoredProfile?.sha256 !== beforeProfile.sha256 ||
    !beforeProfile?.projection ||
    Object.keys(beforeProfile.projection).length === 0 ||
    JSON.stringify(restoredProfile?.projection) !==
      JSON.stringify(beforeProfile.projection)
  ) {
    errors.push("restored compatibility evidence is incomplete");
  }
}

export function createUiGateResult({
  artifactName,
  candidate,
  playwrightOutcome,
}) {
  return {
    artifactName,
    candidate,
    kind: "enoki-release-ui-contract-gate",
    outcome: playwrightOutcome === "success" ? "succeeded" : "failed",
    playwrightStepOutcome: playwrightOutcome,
    schemaVersion: 1,
  };
}

export function createReleaseVerificationSummary({
  artifactIndex,
  candidateManifest,
  componentResults,
  evidenceErrors = [],
  gateResults,
  hostGates,
  identities = {},
  matrix,
  requested,
  run,
  standardCi,
  uiGate,
}) {
  assertAttemptSummaryInputs({ componentResults, gateResults, requested, run });
  const candidateIsAvailable = isCandidateManifest(candidateManifest);
  const request = requested ?? {
    commit: candidateManifest?.candidate?.commit ?? null,
    version: candidateManifest?.candidate?.version ?? null,
  };
  const components = componentResults
    ? normalizeComponentResults(componentResults)
    : {
        candidateAssembly: gateResults.candidateBuild,
        candidateUiContract: gateResults.uiJob,
        hostMatrix: gateResults.matrixJob,
        matrixExpansion: gateResults.matrixExpansion,
      };
  const normalizedGates = {
    candidateBuild:
      components.candidateAssembly ?? gateResults?.candidateBuild ?? "missing",
    matrixExpansion:
      components.matrixExpansion ?? gateResults?.matrixExpansion ?? "missing",
    matrixJob: components.hostMatrix ?? gateResults?.matrixJob ?? "missing",
    uiJob: components.candidateUiContract ?? gateResults?.uiJob ?? "missing",
  };
  const expectedCells = createGitHubActionsMatrix(matrix).include;
  const artifactUrl = (artifactName) =>
    resolveArtifactUrl(artifactIndex, artifactName, run);
  const providedHostGates = hostGates ?? [];
  const gatesByCell = new Map(
    providedHostGates.map((gate) => [gate.cellId, gate]),
  );
  const hostScenarios = expectedCells.map((cell) => {
    const gate = gatesByCell.get(cell.cellId);
    const expectedOutcome = "succeeded";
    return {
      artifactName: gate?.artifactName ?? null,
      cellId: cell.cellId,
      environmentId: cell.environmentId,
      evidenceOutcome: gate?.evidenceOutcome ?? "missing",
      evidenceUrl: artifactUrl(gate?.artifactName),
      expectedOutcome,
      outcome: gate?.outcome ?? "missing",
      runner: cell.runner,
      scenarioId: cell.scenarioId,
      scenarioStepOutcome: gate?.scenarioStepOutcome ?? "missing",
      verifyCleanStepOutcome: gate?.verifyCleanStepOutcome ?? "missing",
    };
  });
  const uiOutcome = uiGate?.outcome ?? "missing";
  const standardCiIsValid =
    standardCi?.kind === "enoki-standard-ci-evidence" &&
    standardCi?.schemaVersion === 1 &&
    standardCi?.candidateCommit === request.commit &&
    Number.isSafeInteger(standardCi?.runId) &&
    standardCi.runId > 0 &&
    typeof standardCi?.runUrl === "string" &&
    standardCi.runUrl.length > 0 &&
    Array.isArray(standardCi?.jobs) &&
    standardCi.jobs.length > 0 &&
    standardCi.jobs.every(
      (job) => job?.conclusion === "success" && typeof job?.name === "string",
    );
  const verified =
    candidateIsAvailable &&
    sameCandidate(request, candidateManifest.candidate) &&
    standardCiIsValid &&
    (!componentResults ||
      requiredComponentNames.every((name) => components[name] === "success")) &&
    normalizedGates.candidateBuild === "success" &&
    normalizedGates.matrixExpansion === "success" &&
    normalizedGates.matrixJob === "success" &&
    normalizedGates.uiJob === "success" &&
    uiOutcome === "succeeded" &&
    isArtifactName(uiGate?.artifactName) &&
    (!artifactIndex || Boolean(artifactUrl(uiGate?.artifactName))) &&
    sameCandidate(uiGate?.candidate, candidateManifest?.candidate) &&
    providedHostGates.length === expectedCells.length &&
    gatesByCell.size === expectedCells.length &&
    hostScenarios.every(
      (gate) =>
        gate.outcome === gate.expectedOutcome &&
        gate.evidenceOutcome === gate.expectedOutcome &&
        isArtifactName(gatesByCell.get(gate.cellId)?.artifactName) &&
        (!artifactIndex || Boolean(gate.evidenceUrl)) &&
        sameCandidate(
          gatesByCell.get(gate.cellId)?.candidate,
          candidateManifest?.candidate,
        ) &&
        gatesByCell.get(gate.cellId)?.scenarioId === gate.scenarioId,
    );

  const hub = candidateManifest?.hub ?? identities.hub ?? null;
  const probeAssetSet =
    candidateManifest?.probeAssetSet ?? identities.probeAssetSet ?? null;
  const releaseBaseline =
    candidateManifest?.releaseBaseline ?? identities.releaseBaseline ?? null;
  const missingIdentities = [
    !candidateIsAvailable && "candidate-manifest",
    !hub && "hub-oci",
    !probeAssetSet && "probe-asset-set",
    !releaseBaseline && "release-baseline",
    !standardCiIsValid && "standard-ci-evidence",
  ].filter(Boolean);
  const failureReasons = [
    ...Object.entries(components)
      .filter(([, outcome]) => outcome !== "success")
      .map(([component, outcome]) => `${component}: ${outcome}`),
    ...missingIdentities.map(
      (identity) => `${displayIdentity(identity)} identity is missing`,
    ),
    ...evidenceErrors,
  ];
  if (uiOutcome !== "succeeded") {
    failureReasons.push(`candidate UI Contract evidence: ${uiOutcome}`);
  }
  if (artifactIndex && !artifactUrl(uiGate?.artifactName)) {
    failureReasons.push("candidate UI Contract artifact URL is missing");
  }
  for (const gate of hostScenarios) {
    if (gate.outcome !== gate.expectedOutcome) {
      failureReasons.push(`${gate.cellId}: ${gate.outcome}`);
    }
    if (artifactIndex && !gate.evidenceUrl) {
      failureReasons.push(`${gate.cellId}: artifact URL is missing`);
    }
  }

  return {
    candidate: candidateManifest?.candidate ?? null,
    componentResults: components,
    failureReasons: [...new Set(failureReasons)],
    freshCandidateRequiredForPublish: true,
    gates: {
      candidateBuild: { outcome: normalizedGates.candidateBuild },
      candidateUiContract: {
        artifactName: uiGate?.artifactName ?? null,
        evidenceUrl: artifactUrl(uiGate?.artifactName),
        outcome: uiOutcome,
      },
      hostMatrix: { outcome: normalizedGates.matrixJob },
      hostScenarios,
      matrixExpansion: { outcome: normalizedGates.matrixExpansion },
      standardCi: {
        outcome: standardCiIsValid ? "success" : "missing",
        runUrl: standardCi?.runUrl ?? null,
      },
    },
    hub,
    kind: "enoki-release-verification-evidence",
    missingIdentities,
    probeAssetSet,
    promotable: false,
    releaseBaseline,
    requested: request,
    run,
    schemaVersion: 3,
    standardCi: standardCiIsValid ? standardCi : null,
    verified,
  };
}

export function renderReleaseVerificationEvidenceMarkdown(summary) {
  const baseline = summary.releaseBaseline
    ? `${summary.releaseBaseline.tag} @ ${summary.releaseBaseline.githubRelease?.peeledCommitSha ?? "unknown commit"}`
    : "missing";
  const candidate = summary.candidate ?? summary.requested;
  const lines = [
    "# Enoki Release Verification Evidence",
    "",
    `- Verified: **${summary.verified ? "yes" : "no"}**`,
    "- Scope: **Current workflow run only** — this evidence cannot authorize another run.",
    `- Requested: \`${summary.requested.version}\` @ \`${summary.requested.commit}\``,
    `- Candidate Manifest: ${summary.candidate ? `\`${candidate.version}\` @ \`${candidate.commit}\`` : "missing"}`,
    `- Release Baseline: \`${baseline}\``,
    `- Hub OCI digest: \`${summary.hub?.digest ?? "missing"}\``,
    `- Hub archive SHA-256: \`${summary.hub?.archiveSha256 ?? "missing"}\``,
    `- Probe signing key SHA-256: \`${summary.probeAssetSet?.signingIdentity?.publicKeySha256 ?? "missing"}\``,
    "",
    "## Signed Probe Asset Set",
    "",
    "| File | SHA-256 |",
    "| --- | --- |",
    ...(summary.probeAssetSet?.files ?? []).map(
      (file) => `| \`${file.file}\` | \`${file.sha256}\` |`,
    ),
    "",
    "## Required gates",
    "",
    "| Gate | Outcome | Evidence |",
    "| --- | --- | --- |",
    `| Candidate build | ${summary.gates.candidateBuild.outcome} | Candidate Manifest |`,
    `| Standard CI | ${summary.gates.standardCi.outcome} | ${summary.gates.standardCi.runUrl ?? "missing"} |`,
    `| Matrix expansion | ${summary.gates.matrixExpansion.outcome} | central matrix |`,
    `| Candidate-image UI Contract | ${summary.gates.candidateUiContract.outcome} | ${evidenceLink(summary.gates.candidateUiContract)} |`,
    ...summary.gates.hostScenarios.map(
      (gate) =>
        `| \`${gate.cellId}\` | ${gate.outcome} | ${evidenceLink(gate)} |`,
    ),
    "",
    "## Failure reasons",
    "",
    ...(summary.failureReasons.length > 0
      ? summary.failureReasons.map((reason) => `- ${reason}`)
      : ["- None"]),
    "",
  ];
  return `${lines.join("\n")}\n`;
}

function assertAttemptSummaryInputs({
  componentResults,
  gateResults,
  requested,
  run,
}) {
  if ((!componentResults && !gateResults) || !run?.url) {
    throw new Error("Component results and workflow run identity are required");
  }
  if (requested && (!requested.commit || !requested.version)) {
    throw new Error("Requested candidate identity is invalid");
  }
}

function isCandidateManifest(candidateManifest) {
  return (
    candidateManifest?.kind === "enoki-release-candidate" &&
    candidateManifest?.schemaVersion === 2 &&
    Boolean(candidateManifest.candidate) &&
    Boolean(candidateManifest.hub) &&
    Boolean(candidateManifest.probeAssetSet) &&
    Boolean(candidateManifest.releaseBaseline)
  );
}

function displayIdentity(identity) {
  return {
    "candidate-manifest": "Candidate Manifest",
    "hub-oci": "Hub OCI",
    "probe-asset-set": "Probe Asset Set",
    "release-baseline": "Release Baseline",
    "standard-ci-evidence": "standard CI",
  }[identity];
}

function normalizeComponentResults(componentResults) {
  const allowed = new Set(["success", "failure", "cancelled", "skipped"]);
  return Object.fromEntries(
    requiredComponentNames.map((name) => [
      name,
      allowed.has(componentResults?.[name])
        ? componentResults[name]
        : "missing",
    ]),
  );
}

function sameCandidate(left, right) {
  return left?.commit === right?.commit && left?.version === right?.version;
}

function cellIdEnvironment(cellId) {
  if (typeof cellId !== "string" || !cellId.includes("--")) return null;
  return cellId.slice(0, cellId.indexOf("--"));
}

function normalizeEvidenceOutcome(value) {
  return value === "succeeded" || value === "skipped" || value === "failed"
    ? value
    : "missing";
}

function evidenceLink(gate) {
  return gate.evidenceUrl && gate.artifactName
    ? `[${gate.artifactName}](${gate.evidenceUrl})`
    : "missing";
}

function isArtifactName(value) {
  return (
    typeof value === "string" &&
    value.length <= 255 &&
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)
  );
}

function resolveArtifactUrl(artifactIndex, artifactName, run) {
  if (!isArtifactName(artifactName)) return null;
  const candidate = artifactIndex?.[artifactName];
  if (typeof candidate !== "string") return null;
  try {
    const url = new URL(candidate);
    if (
      url.protocol !== "https:" ||
      !url.pathname.includes(`/actions/runs/${run.id}/artifacts/`)
    ) {
      return null;
    }
    return url.href;
  } catch {
    return null;
  }
}
