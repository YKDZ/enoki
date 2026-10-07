import { createHash } from "node:crypto";

import { standardCiEvidenceErrors } from "./release-ci-evidence.ts";
import {
  hasAdvancingPortableMetrics,
  isCandidateHostReady,
  isSupportedReleaseTestHostVirtualization,
} from "./release-evidence-judgments.ts";
import {
  isSafeInteger,
  isUnknownArray,
  isUnknownRecord,
  isFiniteNumber,
  objectView,
  regexInput,
  stringValue,
  type UnknownRecord,
} from "./release-json-guards.ts";

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
  candidateManifest,
  cellId,
  evidence,
  scenarioOutcome,
  verifyCleanOutcome,
}: {
  artifactName: unknown;
  candidateManifest: unknown;
  cellId: unknown;
  evidence: unknown;
  scenarioOutcome: unknown;
  verifyCleanOutcome: unknown;
}) {
  const candidate = objectView(candidateManifest).candidate ?? null;
  const evidenceView = objectView(evidence);
  const evidenceOutcome = normalizeEvidenceOutcome(
    objectView(evidenceView.result).status,
  );
  const scenarioId = evidenceView.scenario ?? null;
  const successfulSteps =
    scenarioOutcome === "success" && verifyCleanOutcome === "success";
  const consistentEvidence =
    isCandidateManifest(candidateManifest) &&
    typeof scenarioId === "string" &&
    cellId === `${cellIdEnvironment(cellId)}--${scenarioId}` &&
    sameCandidate(evidenceView.candidate, candidate);
  const acceptableEvidence = evidenceOutcome === "succeeded";
  const evidenceValidationErrors = validateHostScenarioEvidence(
    evidence,
    evidenceOutcome,
    cellId,
    candidateManifest,
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
    releaseBaselineKind: objectView(evidenceView.releaseBaseline).kind ?? null,
    scenarioId,
    scenarioStepOutcome: scenarioOutcome,
    schemaVersion: 1,
    verifyCleanStepOutcome: verifyCleanOutcome,
  };
}

function validateHostScenarioEvidence(
  evidence: unknown,
  outcome: unknown,
  cellId: unknown,
  candidateManifest: unknown,
) {
  if (outcome !== "succeeded") return [];

  const errors: string[] = [];
  const evidenceView = objectView(evidence);
  if (evidenceView.schemaVersion !== 2) {
    errors.push("invalid schemaVersion");
  }
  if (evidenceView.phase !== "succeeded") {
    errors.push("phase was not succeeded");
  }
  validateReleaseTestHostEvidence(evidence, cellId, errors);
  validateCleanupEvidence(evidenceView.cleanup, errors);
  validateReleaseBaselineEvidence(
    evidenceView.releaseBaseline,
    objectView(candidateManifest).releaseBaseline,
    errors,
  );
  const baselineKind = objectView(evidenceView.releaseBaseline).kind;
  if (
    baselineKind !== "enoki-release-baseline" &&
    baselineKind !== "enoki-trust-epoch-migration-baseline"
  ) {
    errors.push("Release Baseline evidence kind is invalid");
  }
  if (evidenceView.scenario !== "fresh-install-uninstall") {
    validateUninstallEvidence(evidenceView.uninstall, errors);
  }

  const requiredByScenario: Record<string, readonly string[]> = {
    "compatible-upgrade-uninstall": [
      "auditLog",
      "baselineInstall",
      "candidateHost",
      "compatibility",
      "hostBoundary",
      "identityContinuity",
      "metrics",
      "probeConfiguration",
      "upgradeOperationTimeline",
    ],
    "replacement-migration-uninstall": [
      "auditLog",
      "baselineInstall",
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
      "canonicalRuntimeUnavailableReporting",
      "host",
      "hostBoundary",
      "diagnostics",
      "finalLocalUninstall",
      "hubOnlyDeletion",
      "initialInstall",
      "installedBundleFailureRepair",
      "localUninstall",
      "metrics",
      "metricsHistory",
      "probeConfiguration",
      "reEnrollment",
      "repeatedAdd",
    ],
    "hub-restore-compatibility-window": [
      "baselineInstall",
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
      "baselineInstall",
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
  for (const field of requiredByScenario[stringValue(evidenceView.scenario)] ??
    []) {
    if (evidenceView[field] == null) errors.push(`missing ${field}`);
  }

  if (evidenceView.scenario === "fresh-install-uninstall") {
    validateFreshEvidence(evidence, errors, candidateManifest);
  } else if (
    evidenceView.scenario === "compatible-upgrade-uninstall" ||
    evidenceView.scenario === "replacement-migration-uninstall"
  ) {
    validateBaselineEvidence(evidence, errors, candidateManifest);
  } else if (evidenceView.scenario === "post-replacement-repair-uninstall") {
    validateRepairEvidence(evidence, errors, candidateManifest);
  } else if (evidenceView.scenario === "hub-restore-compatibility-window") {
    validateRestoreEvidence(evidence, errors, candidateManifest);
  } else {
    errors.push("unknown Host scenario");
  }
  return [...new Set(errors)];
}

function validateReleaseTestHostEvidence(
  evidence: unknown,
  cellId: unknown,
  errors: string[],
) {
  const evidenceView = objectView(evidence);
  if (!evidenceView.releaseTestHost) {
    errors.push("missing Release Test Host platform evidence");
  }
  if (!evidenceView.infrastructure) {
    errors.push("missing Release E2E infrastructure evidence");
  }
  const expected = /^ubuntu-(22[.]04|24[.]04)-x86_64--[a-z][a-z0-9-]*$/.exec(
    regexInput(cellId),
  );
  if (!expected) {
    errors.push("matrix cell is not a supported Ubuntu x86_64 release gate");
    return;
  }
  const host = objectView(evidenceView.releaseTestHost);
  const expectedHostKeys = [
    "architecture",
    "deviceView",
    "journaldSocket",
    "operatingSystem",
    "operatingSystemVersion",
    "pid1",
    "rootFilesystem",
    "systemdNotifySocket",
    "unifiedCgroup",
    "virtualization",
  ];
  if (
    Object.keys(host).sort().join(",") !== expectedHostKeys.join(",") ||
    host.architecture !== "x86_64" ||
    host.operatingSystem !== "ubuntu" ||
    host.operatingSystemVersion !== expected[1] ||
    host.pid1 !== "systemd" ||
    !isSupportedReleaseTestHostVirtualization(host.virtualization) ||
    ![
      "deviceView",
      "journaldSocket",
      "rootFilesystem",
      "systemdNotifySocket",
      "unifiedCgroup",
    ].every((primitive) => host[primitive] === true)
  ) {
    errors.push(
      "Release Test Host platform evidence does not match the matrix cell",
    );
  }
  const infrastructure = evidenceView.infrastructure;
  const validInfrastructure = [
    {
      artifactAccess: "github-actions",
      connection: "local",
      kind: "ci",
      matrixCellId: cellId,
      provisioning: "github-hosted-runner",
    },
    {
      artifactAccess: "filesystem",
      connection: "ssh",
      kind: "ssh",
      matrixCellId: cellId,
      provisioning: "existing-disposable-host",
    },
  ].some((expectedInfrastructure) =>
    hasExactEvidenceFields(infrastructure, expectedInfrastructure),
  );
  if (!validInfrastructure) {
    errors.push(
      "Release E2E infrastructure evidence does not match the matrix cell",
    );
  }
}

function hasExactEvidenceFields(record: unknown, expected: UnknownRecord) {
  if (!isUnknownRecord(record) || !sameKeySet(record, expected)) {
    return false;
  }
  return Object.entries(expected).every(
    ([key, value]) => record[key] === value,
  );
}

function sameKeySet(actual: unknown, expected: unknown) {
  const actualKeys = Object.keys(objectView(actual)).sort();
  const expectedKeys = Object.keys(objectView(expected)).sort();
  return (
    actualKeys.length === expectedKeys.length &&
    actualKeys.every((key, index) => key === expectedKeys[index])
  );
}

function validateFreshEvidence(
  evidence: unknown,
  errors: string[],
  candidateManifest: unknown,
) {
  const evidenceView = objectView(evidence);
  const evidenceHost = objectView(evidenceView.host);
  const version = candidateProbeVersion(evidence);
  if (!isCandidateHostReady(evidenceView.host, version)) {
    errors.push("fresh Host Profile is invalid");
  }
  validateMetrics(evidenceView.metrics, "fresh reporting", errors);
  validateMetricsHistoryPreservation(evidence, errors);
  validateProbeConfiguration(evidenceView.probeConfiguration, errors);
  validateInstalledBundleFailureRepair(
    evidenceView.installedBundleFailureRepair,
    version,
    evidenceHost.id,
    errors,
  );
  validateFreshLifecycleAuditLog(evidence, errors);
  validateInstalledHostBoundary(evidenceView.hostBoundary, version, errors);
  validateHostInstallResult(
    evidenceView.initialInstall,
    "initial Probe installer",
    errors,
    {
      activeHub: "candidate",
      candidateManifest,
      expectedRunId: evidenceView.runId,
    },
  );
  validateRepeatedAddEvidence(evidenceView.repeatedAdd, errors);
  validateLocalUninstallEvidence(
    evidenceView.localUninstall,
    evidenceHost.id,
    "first Local Probe Uninstall",
    errors,
  );
  validateReEnrollmentEvidence(evidence, errors, candidateManifest);
  validateCanonicalRuntimeUnavailableReporting(evidence, errors);
  validateHubOnlyDeletionEvidence(evidence, errors);
  validateLocalUninstallEvidence(
    evidenceView.finalLocalUninstall,
    null,
    "final Local Probe Uninstall",
    errors,
  );
  validateDiagnosticsEvidence(evidenceView.diagnostics, errors);
}

function validateCanonicalRuntimeUnavailableReporting(
  evidence: unknown,
  errors: string[],
) {
  const evidenceView = objectView(evidence);
  const value = objectView(evidenceView.canonicalRuntimeUnavailableReporting);
  const host = objectView(value.host);
  const identity = objectView(host.identity);
  const probe = objectView(host.probe);
  const runtime = objectView(host.runtime);
  const owner = objectView(value.ownerProjection);
  const reporting = objectView(value.reporting);
  const boot = objectView(reporting.bootReport);
  const bootReconciliation = objectView(boot.reconciliation);
  const failure = objectView(reporting.failureReport);
  const receiptConvergence = objectView(reporting.receiptConvergence);
  const ownerHost = objectView(owner.host);
  const transport = objectView(objectView(evidenceView.diagnostics).transport);
  const expectedProbeId = objectView(
    objectView(objectView(evidenceView.reEnrollment).identity).after,
  ).probeId;
  const validSha256 = (candidate: unknown) =>
    /^[0-9a-f]{64}$/.test(regexInput(candidate));
  const validIdentity =
    sameKeySet(identity ?? {}, {
      probeId: null,
      registrationAttemptCredential: null,
      registrationAttemptSource: null,
      registrationDropIn: null,
      transitionalRegistrationKeys: null,
    }) &&
    identity.probeId === expectedProbeId &&
    identity.registrationAttemptCredential === false &&
    identity.registrationAttemptSource === false &&
    identity.registrationDropIn === false &&
    identity.transitionalRegistrationKeys === false;
  const validHost =
    validIdentity &&
    sameKeySet(probe ?? {}, {
      ActiveState: null,
      LoadState: null,
      Result: null,
      SubState: null,
      Type: null,
    }) &&
    probe.ActiveState === "active" &&
    probe.LoadState === "loaded" &&
    probe.Result === "success" &&
    probe.SubState === "running" &&
    probe.Type === "notify" &&
    sameKeySet(runtime ?? {}, {
      serviceLoadState: null,
      socketLoadState: null,
    }) &&
    runtime.serviceLoadState === "masked" &&
    runtime.socketLoadState === "masked";
  const validBoot =
    sameKeySet(boot ?? {}, {
      acceptedSequenceEnd: null,
      bytes: null,
      payloadSha256: null,
      reconciliation: null,
      responseDelivered: null,
      responseSha256: null,
      sequence: null,
      upstreamStatus: null,
    }) &&
    boot.sequence === 1 &&
    boot.acceptedSequenceEnd === 1 &&
    boot.upstreamStatus === 200 &&
    boot.responseDelivered === true &&
    isSafeInteger(boot.bytes) &&
    boot.bytes > 0 &&
    sameKeySet(boot.reconciliation ?? {}, {
      currentProbeConfigurationVersion: null,
      pendingOperation: null,
      requestedSnapshotCollectorIdsCount: null,
    }) &&
    typeof bootReconciliation.currentProbeConfigurationVersion === "string" &&
    bootReconciliation.currentProbeConfigurationVersion.length > 0 &&
    (bootReconciliation.pendingOperation === "absent" ||
      bootReconciliation.pendingOperation === "present") &&
    isSafeInteger(bootReconciliation.requestedSnapshotCollectorIdsCount) &&
    bootReconciliation.requestedSnapshotCollectorIdsCount >= 0 &&
    validSha256(boot.payloadSha256) &&
    validSha256(boot.responseSha256);
  const validFailureAttempts =
    isUnknownArray(failure.attempts) &&
    failure.attempts.length === 2 &&
    failure.attempts.every((attempt: unknown, index: number) => {
      const attemptView = objectView(attempt);
      return (
        sameKeySet(attemptView, {
          acceptedSequenceEnd: null,
          response: null,
          responseSha256: null,
          upstreamStatus: null,
        }) &&
        attemptView.acceptedSequenceEnd === 2 &&
        attemptView.response === (index === 0 ? "dropped" : "delivered") &&
        validSha256(attemptView.responseSha256) &&
        attemptView.upstreamStatus === 200
      );
    });
  const validFailure =
    sameKeySet(failure ?? {}, {
      attempts: null,
      bytes: null,
      collectionOutcomeCount: null,
      metricsCount: null,
      payloadSha256: null,
      probeConfigurationVersion: null,
      reason: null,
      retryPayloadSha256: null,
      sequence: null,
    }) &&
    failure.sequence === 2 &&
    failure.reason === "observation_runtime_unavailable" &&
    failure.metricsCount === 0 &&
    failure.collectionOutcomeCount === 0 &&
    failure.probeConfigurationVersion ===
      bootReconciliation.currentProbeConfigurationVersion &&
    isSafeInteger(failure.bytes) &&
    failure.bytes > 0 &&
    validSha256(failure.payloadSha256) &&
    failure.retryPayloadSha256 === failure.payloadSha256 &&
    validFailureAttempts;
  const validReporting =
    sameKeySet(reporting ?? {}, {
      bootId: null,
      bootReport: null,
      failureReport: null,
      kind: null,
      probeId: null,
      receiptConvergence: null,
      schemaVersion: null,
    }) &&
    reporting.kind === "canonical-runtime-unavailable-report-evidence" &&
    reporting.schemaVersion === 1 &&
    reporting.probeId === expectedProbeId &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(regexInput(reporting.bootId)) &&
    validBoot &&
    validFailure &&
    sameKeySet(receiptConvergence ?? {}, {
      contract: null,
      key: null,
      requestAttemptCount: null,
      uniquePayloadCount: null,
    }) &&
    receiptConvergence.contract === "report-sequence-ack-idempotency" &&
    sameKeySet(receiptConvergence.key ?? {}, {
      bootId: null,
      probeId: null,
      sequence: null,
    }) &&
    objectView(receiptConvergence.key).probeId === reporting.probeId &&
    objectView(receiptConvergence.key).bootId === reporting.bootId &&
    objectView(receiptConvergence.key).sequence === 2 &&
    receiptConvergence.requestAttemptCount === 2 &&
    receiptConvergence.uniquePayloadCount === 1;
  const validOwnerProjection =
    owner?.metricsUnchanged === true &&
    owner?.reportedProbeConfigurationVersion ===
      bootReconciliation.currentProbeConfigurationVersion &&
    ownerHost.id === objectView(evidenceView.host).id &&
    ownerHost.status === "online" &&
    isCandidateHostReady(owner.host, candidateProbeVersion(evidence));
  const validTransportDiagnostics =
    transport.completed === true &&
    transport.failure === null &&
    transport.failureReportObserved === true &&
    transport.lastUpstreamStatus === 200;
  if (
    !validHost ||
    !validReporting ||
    !validOwnerProjection ||
    !validTransportDiagnostics
  ) {
    errors.push("canonical Runtime-unavailable reporting evidence is invalid");
  }
}

function validateInstalledBundleFailureRepair(
  value: unknown,
  version: unknown,
  expectedHostId: unknown,
  errors: string[],
) {
  const valueView = objectView(value);
  const failure = objectView(valueView.failure);
  const bundle = objectView(failure.bundle);
  const epoch = objectView(failure.failureEpoch);
  const latch = objectView(failure.latch);
  const budget = objectView(failure.recoveryBudget);
  const repair = objectView(valueView.repair);
  const valueIdentity = objectView(valueView.identity);
  const valueHost = objectView(valueView.host);
  const sha256 = (candidate: unknown) =>
    /^[0-9a-f]{64}$/.test(regexInput(candidate));
  if (
    !sameKeySet(failure ?? {}, {
      activeState: null,
      bundle: null,
      failureEpoch: null,
      latch: null,
      recoveryBudget: null,
      result: null,
      role: null,
      status: null,
      unit: null,
      unitSha256: null,
    }) ||
    !sameKeySet(bundle ?? {}, {
      installStateSha256: null,
      manifestSha256: null,
      runtimeFaultSha256: null,
      runtimeSha256: null,
      version: null,
    }) ||
    !sameKeySet(epoch ?? {}, {
      bootId: null,
      generation: null,
      hostId: null,
      identityReceiptSha256: null,
      links: null,
      mode: null,
      ownerUid: null,
      probeId: null,
    }) ||
    !sameKeySet(latch ?? {}, {
      generation: null,
      links: null,
      mode: null,
      ownerUid: null,
    }) ||
    !sameKeySet(budget ?? {}, {
      observedStarts: null,
      startLimitBurst: null,
      startLimitIntervalSeconds: null,
    }) ||
    !sameKeySet(repair ?? {}, {
      failureEpochRemoved: null,
      faultRemoved: null,
      latchRemoved: null,
      output: null,
      probeId: null,
      repairedVersion: null,
      runtimeSha256: null,
      sameBundle: null,
      unit: null,
    }) ||
    failure.activeState !== "failed" ||
    failure.result !== "start-limit-hit" ||
    failure.role !== "observation_runtime" ||
    failure.status !== "latched" ||
    failure.unit !== "enoki-observation-runtime.service" ||
    !sha256(failure.unitSha256) ||
    bundle.version !== version ||
    !sha256(bundle.installStateSha256) ||
    !sha256(bundle.manifestSha256) ||
    !sha256(bundle.runtimeFaultSha256) ||
    !sha256(bundle.runtimeSha256) ||
    bundle.runtimeFaultSha256 === bundle.runtimeSha256 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(regexInput(epoch.bootId)) ||
    !sha256(epoch.generation) ||
    epoch.hostId !== String(expectedHostId) ||
    !sha256(epoch.identityReceiptSha256) ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(regexInput(epoch.probeId)) ||
    epoch.ownerUid !== 0 ||
    epoch.mode !== "0600" ||
    epoch.links !== 1 ||
    latch.generation !== epoch.generation ||
    latch.ownerUid !== 0 ||
    latch.mode !== "0600" ||
    latch.links !== 1 ||
    budget.startLimitBurst !== 3 ||
    budget.startLimitIntervalSeconds !== 60 ||
    budget.observedStarts !== 3 ||
    repair.failureEpochRemoved !== true ||
    repair.faultRemoved !== true ||
    repair.latchRemoved !== true ||
    repair.output !== "Probe repair completed." ||
    repair.repairedVersion !== version ||
    repair.runtimeSha256 !== bundle.runtimeSha256 ||
    repair.sameBundle !== true ||
    repair.unit !== failure.unit ||
    repair.probeId !== epoch.probeId ||
    repair.probeId !== objectView(valueIdentity.after).probeId ||
    JSON.stringify(valueIdentity.after) !==
      JSON.stringify(valueIdentity.before) ||
    valueHost.id !== expectedHostId ||
    !isCandidateHostReady(valueView.host, version)
  ) {
    errors.push("Installed Bundle Failure Repair evidence is invalid");
  }
  validateInstalledHostBoundary(valueView.hostBoundary, version, errors);
}

function validateInstallerEvidence(
  value: unknown,
  label: unknown,
  errors: string[],
) {
  const output = objectView(objectView(value).output);
  if (
    output.code !== 0 ||
    typeof output.stdout !== "string" ||
    typeof output.stderr !== "string" ||
    !output.stdout.includes("ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE") ||
    !output.stdout.includes("Enoki Probe installed as enoki-probe.service.") ||
    containsUnredactedSecret(output)
  ) {
    errors.push(`${label} output is invalid`);
  }
}

function validateHostInstallResult(
  value: unknown,
  label: unknown,
  errors: string[],
  {
    activeHub,
    allowLegacyMigration = false,
    candidateManifest,
    expectedRunId,
  }: {
    activeHub: unknown;
    allowLegacyMigration?: boolean;
    candidateManifest: unknown;
    expectedRunId: unknown;
  },
) {
  validateInstallerEvidence(value, label, errors);
  const valueView = objectView(value);
  const manifestBaseline = objectView(
    objectView(candidateManifest).releaseBaseline,
  );
  if (
    !sameKeySet(value ?? {}, {
      bootstrapRecipeProvenance: null,
      output: null,
      runId: null,
    }) ||
    valueView.runId !== expectedRunId
  ) {
    errors.push(`${label} production result is invalid`);
  }
  if (
    allowLegacyMigration &&
    manifestBaseline.kind === "enoki-trust-epoch-migration-baseline" &&
    valueView.bootstrapRecipeProvenance === null
  ) {
    return;
  }
  validateBootstrapRecipeProvenance(
    valueView.bootstrapRecipeProvenance,
    candidateManifest,
    activeHub,
    errors,
  );
}

function validateBootstrapRecipeProvenance(
  provenance: unknown,
  candidateManifest: unknown,
  activeHub: unknown,
  errors: string[],
) {
  const provenanceView = objectView(provenance);
  const record = objectView(provenanceView.record);
  const recipe = objectView(record.recipe);
  const manifestView = objectView(candidateManifest);
  const baseline = objectView(manifestView.releaseBaseline);
  const expectedDigest =
    activeHub === "candidate"
      ? objectView(manifestView.hub).digest
      : objectView(baseline.hub).imageDigest;
  const expectedVersion =
    activeHub === "candidate"
      ? objectView(manifestView.probeAssetSet).version
      : baseline?.kind === "enoki-release-baseline"
        ? objectView(baseline.probeAssetSet).version
        : null;
  const recordBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`);
  const candidateRecipe = objectView(manifestView.bootstrapRecipe);
  if (
    !sameKeySet(provenance ?? {}, {
      activeHub: null,
      hubDigest: null,
      kind: null,
      record: null,
      recordFile: null,
      recordSha256: null,
      recordSize: null,
      schemaVersion: null,
    }) ||
    !sameKeySet(record ?? {}, {
      bundleVersion: null,
      distribution: null,
      kind: null,
      recipe: null,
      rootFingerprint: null,
      schemaVersion: null,
      targets: null,
    }) ||
    !sameKeySet(recipe ?? {}, {
      file: null,
      sha256: null,
      size: null,
      version: null,
    }) ||
    provenanceView.activeHub !== activeHub ||
    provenanceView.hubDigest !== expectedDigest ||
    provenanceView.kind !== "enoki-release-e2e-bootstrap-recipe-provenance" ||
    provenanceView.recordFile !== "enoki-probe-bootstrap-recipe.json" ||
    provenanceView.recordSha256 !==
      createHash("sha256").update(recordBytes).digest("hex") ||
    provenanceView.recordSize !== recordBytes.byteLength ||
    provenanceView.schemaVersion !== 1 ||
    record.bundleVersion !== expectedVersion ||
    record.distribution !== "enoki" ||
    record.kind !== "enoki-probe-bootstrap-recipe-record" ||
    record.schemaVersion !== 1 ||
    !/^[0-9a-f]{64}$/.test(regexInput(record.rootFingerprint)) ||
    !isUnknownArray(record.targets) ||
    record.targets.length !== 4 ||
    recipe.file !== "enoki-probe-bootstrap.py" ||
    recipe.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(regexInput(recipe.sha256)) ||
    !isSafeInteger(recipe.size) ||
    recipe.size < 1 ||
    (activeHub === "candidate" &&
      (candidateRecipe.recordFile !== provenanceView.recordFile ||
        candidateRecipe.recordSha256 !== provenanceView.recordSha256 ||
        candidateRecipe.recordSize !== provenanceView.recordSize ||
        candidateRecipe.bundleVersion !== record.bundleVersion ||
        candidateRecipe.distribution !== record.distribution ||
        candidateRecipe.kind !== record.kind ||
        candidateRecipe.rootFingerprint !== record.rootFingerprint ||
        candidateRecipe.schemaVersion !== record.schemaVersion ||
        JSON.stringify(candidateRecipe.targets) !==
          JSON.stringify(record.targets) ||
        candidateRecipe.file !== recipe.file ||
        candidateRecipe.sha256 !== recipe.sha256 ||
        candidateRecipe.size !== recipe.size ||
        candidateRecipe.version !== recipe.version))
  ) {
    errors.push(
      `Active ${activeHub} Hub Bootstrap recipe provenance is invalid`,
    );
  }
}

function validateRepeatedAddEvidence(repeatedAdd: unknown, errors: string[]) {
  const addView = objectView(repeatedAdd);
  const enrollmentView = objectView(addView.enrollment);
  const enrollmentTarget = objectView(enrollmentView.target);
  const enrollmentStatus = objectView(addView.enrollmentStatus);
  const enrollmentStatusRejection = objectView(enrollmentStatus.rejection);
  if (
    enrollmentTarget.kind !== "new_host" ||
    enrollmentStatus.status !== "rejected" ||
    enrollmentStatusRejection.code !== "existing_probe_installation" ||
    objectView(addView.rejection).code !== "existing_probe_installation" ||
    !sameHubHostProjection(addView.hostBefore, addView.hostAfter) ||
    JSON.stringify(addView.stateBefore) !==
      JSON.stringify(addView.stateAfter) ||
    !validInstalledState(addView.stateBefore)
  ) {
    errors.push("repeated Add rejection evidence is invalid");
  }
}

function validateLocalUninstallEvidence(
  value: unknown,
  expectedHostId: unknown,
  label: unknown,
  errors: string[],
) {
  const valueView = objectView(value);
  const completion = objectView(valueView.completion);
  const inventory = objectView(completion.inventory);
  const accounts = objectView(inventory.accounts);
  const activeHost = objectView(valueView.activeHost);
  const offlineHost = objectView(valueView.offlineHost);
  if (
    completion.clean !== true ||
    completion.journaldRetained !== true ||
    completion.sharedDependenciesRetained !== true ||
    accounts.user !== false ||
    accounts.group !== false ||
    !isUnknownArray(inventory.files) ||
    inventory.files.length !== 0 ||
    !isUnknownArray(inventory.units) ||
    inventory.units.length !== 0 ||
    (expectedHostId !== null &&
      (activeHost.id !== expectedHostId ||
        activeHost.status === "offline" ||
        offlineHost.id !== expectedHostId ||
        offlineHost.status !== "offline"))
  ) {
    errors.push(`${label} evidence is invalid`);
  }
}

function validateReEnrollmentEvidence(
  evidence: unknown,
  errors: string[],
  candidateManifest: unknown,
) {
  const evidenceView = objectView(evidence);
  const evidenceHost = objectView(evidenceView.host);
  const reEnrollment = objectView(evidenceView.reEnrollment);
  const identityView = objectView(reEnrollment.identity);
  const before = objectView(identityView.before);
  const after = objectView(identityView.after);
  const enrollmentTarget = objectView(
    objectView(reEnrollment.enrollment).target,
  );
  if (
    reEnrollment.hostId !== evidenceHost.id ||
    objectView(reEnrollment.host).id !== evidenceHost.id ||
    enrollmentTarget.kind !== "existing_host" ||
    enrollmentTarget.hostId !== evidenceHost.id ||
    !isCandidateHostReady(reEnrollment.host, candidateProbeVersion(evidence)) ||
    !validProbeIdentity(identityView.before) ||
    !validProbeIdentity(identityView.after) ||
    after.probeId === before.probeId ||
    after.identitySha256 === before.identitySha256 ||
    !hasAdvancingPortableMetrics(reEnrollment.metrics) ||
    !sameEffectiveProbeConfiguration(
      reEnrollment.probeConfiguration,
      evidenceView.probeConfiguration,
    ) ||
    !validInstalledBoundary(
      reEnrollment.hostBoundary,
      candidateProbeVersion(evidence),
    )
  ) {
    errors.push("Host Re-enrollment evidence is invalid");
  }
  validateHostInstallResult(
    reEnrollment.installer,
    "Host Re-enrollment installer",
    errors,
    {
      activeHub: "candidate",
      candidateManifest,
      expectedRunId: evidenceView.runId,
    },
  );
}

function validateMetricsHistoryPreservation(
  evidence: unknown,
  errors: string[],
) {
  const evidenceView = objectView(evidence);
  const initial = objectView(evidenceView.metricsHistory);
  const reEnrollment = objectView(
    objectView(evidenceView.reEnrollment).metricsHistory,
  );
  const initialAnchors = metricsHistoryAnchors(initial);
  const reEnrollmentAnchors = metricsHistoryAnchors(reEnrollment);
  if (
    !validMetricsHistory(initial) ||
    !validMetricsHistory(reEnrollment) ||
    !initialAnchors.every((anchor) =>
      reEnrollmentAnchors.some((candidate) =>
        sameMetricAnchor(candidate, anchor),
      ),
    ) ||
    !reEnrollmentAnchors.some((anchor) => {
      const anchorView = objectView(anchor);
      const initialLast = objectView(initialAnchors.at(-1));
      return (
        gtEvidenceNumbers(anchorView.sequence, initialLast.sequence) &&
        gtEvidenceNumbers(anchorView.collectedAtMs, initialLast.collectedAtMs)
      );
    })
  ) {
    errors.push("Host Re-enrollment Metrics history is invalid");
  }
}

// 复现 JS 关系运算符对 unknown evidence 字段的强制转换：两侧都是字符串时按字典序，
// 否则按 ToPrimitive(number) 再 ToNumber，NaN 让两种比较都得到 false。
function gtEvidenceNumbers(left: unknown, right: unknown): boolean {
  if (typeof left === "string" && typeof right === "string") {
    return left > right;
  }
  return Number(left) > Number(right);
}

function lteEvidenceNumbers(left: unknown, right: unknown): boolean {
  if (typeof left === "string" && typeof right === "string") {
    return left <= right;
  }
  return Number(left) <= Number(right);
}

function metricsHistoryAnchors(value: unknown): readonly unknown[] {
  const anchors = objectView(value).anchors;
  return isUnknownArray(anchors) ? anchors : [];
}

function validMetricsHistory(value: unknown): boolean {
  const valueView = objectView(value);
  const anchors = metricsHistoryAnchors(valueView);
  return (
    sameKeySet(valueView, { anchors: null, sha256: null }) &&
    isUnknownArray(valueView.anchors) &&
    anchors.length >= 2 &&
    anchors.every(validMetricAnchor) &&
    anchors.every((anchor: unknown, index: number) => {
      const anchorView = objectView(anchor);
      const previous = objectView(anchors[index - 1]);
      return (
        index === 0 ||
        (gtEvidenceNumbers(anchorView.sequence, previous.sequence) &&
          gtEvidenceNumbers(anchorView.collectedAtMs, previous.collectedAtMs))
      );
    }) &&
    /^[0-9a-f]{64}$/.test(regexInput(valueView.sha256)) &&
    createHash("sha256").update(JSON.stringify(anchors)).digest("hex") ===
      valueView.sha256
  );
}

function validMetricAnchor(value: unknown): boolean {
  const valueView = objectView(value);
  return (
    sameKeySet(valueView, {
      collectedAtMs: null,
      cpuPercent: null,
      memoryTotalBytes: null,
      memoryUsedBytes: null,
      sequence: null,
      uptimeSeconds: null,
    }) &&
    isSafeInteger(valueView.sequence) &&
    valueView.sequence >= 0 &&
    isSafeInteger(valueView.collectedAtMs) &&
    valueView.collectedAtMs > 0 &&
    isFiniteNumber(valueView.uptimeSeconds) &&
    valueView.uptimeSeconds >= 0 &&
    isFiniteNumber(valueView.cpuPercent) &&
    valueView.cpuPercent >= 0 &&
    valueView.cpuPercent <= 100 &&
    isSafeInteger(valueView.memoryTotalBytes) &&
    valueView.memoryTotalBytes > 0 &&
    isSafeInteger(valueView.memoryUsedBytes) &&
    valueView.memoryUsedBytes >= 0 &&
    valueView.memoryUsedBytes <= valueView.memoryTotalBytes
  );
}

function sameMetricAnchor(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validateHubOnlyDeletionEvidence(evidence: unknown, errors: string[]) {
  const evidenceView = objectView(evidence);
  const deletion = objectView(evidenceView.hubOnlyDeletion);
  const terminal = deletion?.permanentReportRejection;
  const deletedHost = objectView(deletion.deletedHost);
  if (
    deletedHost.id !== objectView(evidenceView.host).id ||
    !isSafeInteger(deletedHost.deletedAtMs) ||
    deletedHost.deletedAtMs < 0 ||
    !validPermanentReportRejection(terminal)
  ) {
    errors.push("Hub-only deletion or permanent rejection evidence is invalid");
  }
}

function validateDiagnosticsEvidence(diagnostics: unknown, errors: string[]) {
  const diagnosticsView = objectView(diagnostics);
  const host = objectView(diagnosticsView.host);
  const installationView = objectView(host.installation);
  const inventoryView = objectView(host.inventory);
  const installation = objectView(installationView.value);
  const inventory = objectView(inventoryView.value);
  const accounts = objectView(inventory.accounts);
  if (
    inventoryView.available !== true ||
    typeof accounts.group !== "boolean" ||
    typeof accounts.user !== "boolean" ||
    !isUnknownArray(inventory.files) ||
    !inventory.files.includes("/usr/local/bin/enoki-probe") ||
    !inventory.files.includes("/etc/enoki/probe-install.toml") ||
    !isUnknownArray(inventory.units) ||
    !inventory.units.includes("enoki-probe.service") ||
    installationView.available !== true ||
    !validTerminalDiagnosticInstallation(installation) ||
    !validAvailableDiagnosticCommand(host.journald) ||
    !validAvailableDiagnosticCommand(host.sudoers) ||
    !validTerminalSystemdDiagnostic(host.systemd) ||
    !isUnknownArray(objectView(diagnosticsView.hub).apiTimeline) ||
    containsUnredactedSecret(diagnostics)
  ) {
    errors.push("redacted failure diagnostics are incomplete");
  }
}

function validAvailableDiagnosticCommand(value: unknown): boolean {
  const valueView = objectView(value);
  const output = objectView(valueView.output);
  return (
    valueView.available === true &&
    validCommandEvidence(valueView.output) &&
    stringValue(output.stdout).trim().length > 0
  );
}

function validTerminalSystemdDiagnostic(value: unknown): boolean {
  const output = objectView(objectView(value).output);
  return (
    validAvailableDiagnosticCommand(value) &&
    /^LoadState=loaded$/m.test(stringValue(output.stdout)) &&
    /^ActiveState=failed$/m.test(stringValue(output.stdout)) &&
    /^ExecMainStatus=78$/m.test(stringValue(output.stdout))
  );
}

function sameHubHostProjection(before: unknown, after: unknown): boolean {
  const beforeView = objectView(before);
  return (
    isSafeInteger(beforeView.id) &&
    beforeView.id > 0 &&
    validHostMetadata(beforeView.hostMetadata) &&
    JSON.stringify(before) === JSON.stringify(after)
  );
}

function validHostMetadata(value: unknown): boolean {
  const keys = ["connectAddress", "description", "displayName", "observedIp"];
  const valueView = objectView(value);
  return (
    Object.keys(valueView).sort().join(",") === keys.sort().join(",") &&
    keys.every(
      (key) => valueView[key] === null || typeof valueView[key] === "string",
    )
  );
}

function sameEffectiveProbeConfiguration(
  current: unknown,
  expected: unknown,
): boolean {
  const currentView = objectView(current);
  const expectedView = objectView(expected);
  return (
    currentView.mode === expectedView.mode &&
    JSON.stringify(canonicalSemanticValue(currentView.configuration)) ===
      JSON.stringify(expectedView.configuration)
  );
}

function canonicalSemanticValue(value: unknown): unknown {
  if (isUnknownArray(value)) return value.map(canonicalSemanticValue);
  if (isUnknownRecord(value)) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entryValue]) => [key, canonicalSemanticValue(entryValue)]),
    );
  }
  return value;
}

function validTerminalDiagnosticInstallation(value: unknown): boolean {
  const valueView = objectView(value);
  const binary = objectView(valueView.binary);
  const service = objectView(valueView.service);
  return (
    /^[0-9a-f]{64}$/.test(regexInput(binary.sha256)) &&
    /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      regexInput(binary.version),
    ) &&
    /^[0-9a-f]{64}$/.test(regexInput(valueView.installMetadataSha256)) &&
    validProbeIdentity(valueView.identity) &&
    service.LoadState === "loaded" &&
    service.ActiveState === "failed" &&
    service.SubState === "failed" &&
    service.ExecMainStatus === 78 &&
    isSafeInteger(service.NRestarts) &&
    service.NRestarts >= 0 &&
    typeof service.Result === "string" &&
    service.Result.length > 0
  );
}

function validCommandEvidence(value: unknown): boolean {
  const valueView = objectView(value);
  return (
    isSafeInteger(valueView.code) &&
    typeof valueView.stdout === "string" &&
    typeof valueView.stderr === "string"
  );
}

function validateFreshLifecycleAuditLog(evidence: unknown, errors: string[]) {
  const evidenceView = objectView(evidence);
  const auditLog = evidenceView.auditLog;
  const hostId = objectView(evidenceView.host).id;
  const validEvent = (event: unknown): boolean => {
    const eventView = objectView(event);
    return (
      isSafeInteger(eventView.id) &&
      eventView.id > 0 &&
      isSafeInteger(eventView.occurredAtMs) &&
      eventView.occurredAtMs > 0 &&
      typeof eventView.subjectId === "string" &&
      eventView.subjectId.length > 0 &&
      typeof eventView.subjectType === "string" &&
      eventView.subjectType.length > 0 &&
      eventView.outcome === "success"
    );
  };
  const find = (predicate: (event: unknown) => boolean) =>
    isUnknownArray(auditLog) ? auditLog.find(predicate) : undefined;
  if (
    !find((event) => {
      const eventView = objectView(event);
      return (
        eventView.action === "enrollment_token.create" &&
        validEvent(event) &&
        eventView.actor === "owner" &&
        objectView(objectView(eventView.details).target).kind === "new_host"
      );
    }) ||
    !find((event) => {
      const eventView = objectView(event);
      return (
        eventView.action === "enrollment.installation_rejected" &&
        validEvent(event) &&
        eventView.actor === "system" &&
        objectView(eventView.details).code === "existing_probe_installation"
      );
    }) ||
    !find((event) => {
      const eventView = objectView(event);
      const targetView = objectView(objectView(eventView.details).target);
      return (
        eventView.action === "enrollment_token.create" &&
        validEvent(event) &&
        eventView.actor === "owner" &&
        targetView.kind === "existing_host" &&
        targetView.hostId === hostId
      );
    }) ||
    !find((event) => {
      const eventView = objectView(event);
      return (
        eventView.action === "probe_configuration.host.override" &&
        validEvent(event) &&
        eventView.actor === "owner" &&
        eventView.subjectId === String(hostId)
      );
    }) ||
    !find((event) => {
      const eventView = objectView(event);
      const detailsView = objectView(eventView.details);
      return (
        eventView.action === "host.delete" &&
        validEvent(event) &&
        eventView.actor === "owner" &&
        eventView.subjectId === String(hostId) &&
        eventView.subjectType === "host" &&
        detailsView.hostId === hostId &&
        detailsView.mode === "hub-only"
      );
    })
  ) {
    errors.push("fresh lifecycle Audit Log is invalid");
  }
}

function validProbeIdentity(identity: unknown): boolean {
  const identityView = objectView(identity);
  return (
    typeof identityView.probeId === "string" &&
    identityView.probeId.length > 0 &&
    /^[0-9a-f]{64}$/.test(regexInput(identityView.identitySha256))
  );
}

function validInstalledState(state: unknown): boolean {
  const stateView = objectView(state);
  const serviceView = objectView(stateView.service);
  return (
    /^[0-9a-f]{64}$/.test(regexInput(stateView.binarySha256)) &&
    /^[0-9a-f]{64}$/.test(regexInput(stateView.installMetadataSha256)) &&
    validProbeIdentity(stateView.identity) &&
    isSafeInteger(stateView.restartCount) &&
    stateView.restartCount >= 0 &&
    serviceView.LoadState === "loaded" &&
    serviceView.ActiveState === "active" &&
    serviceView.SubState === "running"
  );
}

function validInstalledBoundary(boundary: unknown, version: unknown): boolean {
  const errors: string[] = [];
  validateInstalledHostBoundary(boundary, version, errors);
  return errors.length === 0;
}

function validPermanentReportRejection(value: unknown): boolean {
  const valueView = objectView(value);
  const serviceView = objectView(valueView.service);
  return (
    /^[0-9a-f]{64}$/.test(regexInput(valueView.binarySha256)) &&
    /^[0-9a-f]{64}$/.test(regexInput(valueView.installMetadataSha256)) &&
    validProbeIdentity(valueView.identity) &&
    isSafeInteger(valueView.restartCountBeforeObservation) &&
    valueView.restartCountBeforeObservation >= 0 &&
    valueView.restartCountAfterObservation ===
      valueView.restartCountBeforeObservation &&
    serviceView.LoadState === "loaded" &&
    serviceView.ActiveState === "failed" &&
    serviceView.SubState === "failed" &&
    serviceView.ExecMainStatus === 78
  );
}

function containsUnredactedSecret(value: unknown): boolean {
  if (typeof value === "string") {
    return (
      /enk_enroll_[A-Za-z0-9_-]+/.test(value) ||
      /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----/.test(value) ||
      /ENOKI_ENROLLMENT_TOKEN\s*=/.test(value)
    );
  }
  if (isUnknownArray(value)) return value.some(containsUnredactedSecret);
  if (isUnknownRecord(value)) {
    return Object.entries(value).some(([key, child]) =>
      /(?:owner.?password|enrollment.?token|private.?key|signing.?private)/i.test(
        key,
      )
        ? child !== "[REDACTED]"
        : containsUnredactedSecret(child),
    );
  }
  return false;
}

function validateBaselineEvidence(
  evidence: unknown,
  errors: string[],
  candidateManifest: unknown,
) {
  const evidenceView = objectView(evidence);
  const version = candidateProbeVersion(evidence);
  const baselineView = objectView(evidenceView.releaseBaseline);
  const manualRecoveryView = objectView(evidenceView.manualRecovery);
  const candidateHostView = objectView(evidenceView.candidateHost);
  const metricsView = objectView(evidenceView.metrics);
  const configurationView = objectView(evidenceView.probeConfiguration);
  const migration =
    baselineView.kind === "enoki-trust-epoch-migration-baseline";
  validateHostInstallResult(
    evidenceView.baselineInstall,
    "Release Baseline Probe installer",
    errors,
    {
      activeHub: "baseline",
      allowLegacyMigration: true,
      candidateManifest,
      expectedRunId: evidenceView.runId,
    },
  );
  if (migration) {
    if (
      !isUnknownArray(evidenceView.upgradeOperationTimeline) ||
      evidenceView.upgradeOperationTimeline.length !== 0 ||
      manualRecoveryView.kind !== "trust_epoch_manual_reinstall" ||
      manualRecoveryView.hostId !== candidateHostView.id ||
      typeof manualRecoveryView.enrollmentId !== "string" ||
      !manualRecoveryView.enrollmentId
    ) {
      errors.push("Trust Epoch manual reinstall evidence is invalid");
    }
    validateHostInstallResult(
      manualRecoveryView.result,
      "Trust Epoch manual reinstall",
      errors,
      {
        activeHub: "candidate",
        candidateManifest,
        expectedRunId: evidenceView.runId,
      },
    );
  } else {
    if (
      evidenceView.manualRecovery !== null &&
      evidenceView.manualRecovery !== undefined
    ) {
      errors.push("Compatible Upgrade must not use manual recovery");
    }
    validateTerminalOperation(
      evidenceView.upgradeOperationTimeline,
      "probe_upgrade",
      "succeeded",
      "baseline Upgrade",
      errors,
    );
  }
  const compatibilityView = objectView(evidenceView.compatibility);
  if (
    compatibilityView.status !== "succeeded" ||
    !isCandidateHostReady(compatibilityView.host, baselineView.probeVersion)
  ) {
    errors.push("baseline compatibility was not proved");
  }
  if (!isCandidateHostReady(evidenceView.candidateHost, version)) {
    errors.push("Candidate Host Profile is invalid");
  }
  const identityContinuityView = objectView(evidenceView.identityContinuity);
  if (migration) {
    validateIdentityReplacement(
      evidenceView.identityContinuity,
      candidateHostView.id,
      errors,
    );
    validateMigrationRetention(evidenceView.migrationRetention, errors, {
      afterMetrics: metricsView.afterUpgrade,
      expectedCandidateHost: evidenceView.candidateHost,
      expectedConfiguration: configurationView.beforeUpgrade,
      expectedIdentityHostId: identityContinuityView.hostId,
    });
  } else {
    validateIdentityContinuity(
      evidenceView.identityContinuity,
      candidateHostView.id,
      errors,
    );
  }
  validateMetrics(metricsView.beforeUpgrade, "pre-Upgrade", errors);
  validateMetrics(metricsView.afterUpgrade, "post-Upgrade", errors);
  validateMetricsProgression(
    metricsView.beforeUpgrade,
    metricsView.afterUpgrade,
    "Upgrade",
    errors,
  );
  validateProbeConfiguration(configurationView.beforeUpgrade, errors);
  validateProbeConfiguration(configurationView.afterUpgrade, errors);
  validateLifecycleAuditLog(evidence, !migration, errors);
  if (migration) validateManualReinstallAuditLog(evidence, errors);
  validateInstalledHostBoundary(evidenceView.hostBoundary, version, errors);
}

function validateRepairEvidence(
  evidence: unknown,
  errors: string[],
  candidateManifest: unknown,
) {
  const evidenceView = objectView(evidence);
  const version = candidateProbeVersion(evidence);
  validateHostInstallResult(
    evidenceView.baselineInstall,
    "Repair Release Baseline Probe installer",
    errors,
    {
      activeHub: "baseline",
      candidateManifest,
      expectedRunId: evidenceView.runId,
    },
  );
  if (
    objectView(evidenceView.releaseBaseline).kind ===
    "enoki-trust-epoch-migration-baseline"
  ) {
    errors.push(
      "Trust Epoch migration Repair has no production-authorized eligibility sequence",
    );
    return;
  }
  validateTerminalOperation(
    evidenceView.operationTimeline,
    "probe_upgrade",
    "failed",
    "failed Upgrade",
    errors,
  );
  const failed = objectView(
    isUnknownArray(evidenceView.operationTimeline)
      ? evidenceView.operationTimeline.at(-1)
      : null,
  );
  const failedFailure = objectView(failed.failure);
  const failureBoundary = objectView(evidenceView.failureBoundary);
  if (
    typeof failedFailure.code !== "string" ||
    !failedFailure.code ||
    failureBoundary.hubFailureCode !== failedFailure.code ||
    failureBoundary.localFailureCode !== "post_replacement_restart_failure" ||
    failureBoundary.probeVersion !== version
  ) {
    errors.push("post-replacement failure boundary is invalid");
  }
  if (failed.targetProbeVersion !== version) {
    errors.push("failed Upgrade Candidate version is invalid");
  }
  if (
    objectView(evidenceView.boundaryEvidenceValidation).status !== "succeeded"
  ) {
    errors.push("Repair boundary validation did not succeed");
  }
  const repairView = objectView(evidenceView.repair);
  if (
    repairView.repairedVersion !== version ||
    typeof repairView.probeId !== "string" ||
    !repairView.probeId
  ) {
    errors.push("Repair completion is incomplete");
  }
  if (!isCandidateHostReady(evidenceView.repairedHost, version)) {
    errors.push("repaired Host Profile is invalid");
  }
  validateIdentityContinuity(
    evidenceView.identityContinuity,
    objectView(evidenceView.repairedHost).id,
    errors,
  );
  if (
    repairView.probeId !==
    objectView(objectView(evidenceView.identityContinuity).before).probeId
  ) {
    errors.push("Repair identity continuity is invalid");
  }
  const metricsView = objectView(evidenceView.metrics);
  validateMetrics(metricsView.beforeUpgrade, "pre-failure", errors);
  validateMetrics(metricsView.afterRepair, "post-Repair", errors);
  validateMetricsProgression(
    metricsView.beforeUpgrade,
    metricsView.afterRepair,
    "Repair",
    errors,
  );
  const configurationView = objectView(evidenceView.probeConfiguration);
  validateProbeConfiguration(configurationView.beforeUpgrade, errors);
  validateProbeConfiguration(configurationView.afterRepair, errors);
  validateInstalledHostBoundary(
    evidenceView.repairHostBoundary,
    version,
    errors,
  );
  validateLifecycleAuditLog(evidence, true, errors);
}

function validateMetrics(metrics: unknown, label: unknown, errors: string[]) {
  if (!hasAdvancingPortableMetrics(metrics)) {
    errors.push(`${label} metrics are incomplete`);
  }
}

function validateMetricsProgression(
  before: unknown,
  after: unknown,
  label: unknown,
  errors: string[],
) {
  const previous = objectView(isUnknownArray(before) ? before.at(-1) : null);
  const current = objectView(isUnknownArray(after) ? after.at(-1) : null);
  if (
    !isSafeInteger(previous.sequence) ||
    !isSafeInteger(current.sequence) ||
    lteEvidenceNumbers(current.sequence, previous.sequence) ||
    lteEvidenceNumbers(current.collectedAtMs, previous.collectedAtMs)
  ) {
    errors.push(`${label} metrics did not advance across the boundary`);
  }
}

function validateProbeConfiguration(configuration: unknown, errors: string[]) {
  const configurationView = objectView(configuration);
  const innerConfiguration = objectView(configurationView.configuration);
  if (
    !sameKeySet(configurationView, {
      configuration: null,
      mode: null,
      reportedVersion: null,
      version: null,
    }) ||
    !validEffectiveProbeConfiguration({
      configuration: configurationView.configuration,
      mode: configurationView.mode,
    }) ||
    configurationView.mode !== "override" ||
    !configurationView.configuration ||
    !isUnknownArray(innerConfiguration.enabledCollectorIds) ||
    !isSafeInteger(innerConfiguration.metricsCollectionIntervalSeconds) ||
    innerConfiguration.version !== configurationView.version ||
    typeof configurationView.version !== "string" ||
    !configurationView.version ||
    configurationView.reportedVersion !== configurationView.version
  ) {
    errors.push("Probe Configuration round-trip is invalid");
  }
}

// evidence 时间线的第一个条目，保持原 `?.[0]?.` 可选链的读取语义。
function firstTimelineEntry(value: unknown): UnknownRecord {
  if (isUnknownArray(value)) return objectView(value[0]);
  return objectView(objectView(value)[0]);
}

function validateLifecycleAuditLog(
  evidence: unknown,
  requiresUpgrade: boolean,
  errors: string[],
) {
  const evidenceView = objectView(evidence);
  const auditLog = evidenceView.auditLog;
  const events = isUnknownArray(auditLog) ? auditLog : [];
  const requiredActions = [
    "enrollment_token.create",
    "probe_configuration.host.override",
    "host.delete",
    ...(requiresUpgrade ? ["probe_upgrade_request.create"] : []),
  ];
  const hostId =
    objectView(evidenceView.host).id ??
    objectView(evidenceView.candidateHost).id ??
    objectView(evidenceView.repairedHost).id;
  const uninstallId = firstTimelineEntry(
    objectView(evidenceView.uninstall).operationTimeline,
  ).id;
  const firstUpgrade = firstTimelineEntry(
    evidenceView.upgradeOperationTimeline,
  );
  const upgradeId =
    firstUpgrade.id ?? firstTimelineEntry(evidenceView.operationTimeline).id;
  const validEvent = (event: unknown): boolean => {
    const eventView = objectView(event);
    return (
      eventView.actor === "owner" &&
      eventView.outcome === "success" &&
      isSafeInteger(eventView.id) &&
      eventView.id > 0 &&
      isSafeInteger(eventView.occurredAtMs) &&
      eventView.occurredAtMs > 0 &&
      typeof eventView.subjectId === "string" &&
      eventView.subjectId.length > 0 &&
      typeof eventView.subjectType === "string" &&
      eventView.subjectType.length > 0
    );
  };
  const byAction = (action: string): UnknownRecord =>
    objectView(events.find((event) => objectView(event).action === action));
  const deleted = byAction("host.delete");
  const configured = byAction("probe_configuration.host.override");
  const upgraded = byAction("probe_upgrade_request.create");
  const deletedDetails = objectView(deleted.details);
  const upgradedDetails = objectView(upgraded.details);
  if (
    !isUnknownArray(auditLog) ||
    requiredActions.some(
      (action) =>
        !events.some(
          (event) => objectView(event).action === action && validEvent(event),
        ),
    ) ||
    configured.subjectId !== String(hostId) ||
    deleted.subjectId !== String(hostId) ||
    deleted.subjectType !== "host" ||
    deletedDetails.hostId !== hostId ||
    deletedDetails.probeOperationId !== uninstallId ||
    (requiresUpgrade &&
      (upgraded.subjectId !== String(upgradeId) ||
        upgraded.subjectType !== "probe_upgrade_request" ||
        upgradedDetails.hostId !== hostId ||
        upgradedDetails.targetProbeVersion !== candidateProbeVersion(evidence)))
  ) {
    errors.push("lifecycle Audit Log is invalid");
  }
}

function validateInstalledHostBoundary(
  boundary: unknown,
  version: unknown,
  errors: string[],
) {
  const boundaryView = objectView(boundary);
  const inventory = objectView(boundaryView.inventory);
  const accounts = objectView(inventory.accounts);
  const service = objectView(boundaryView.service);
  const filesValue = inventory.files;
  const files = isUnknownArray(filesValue) ? filesValue : [];
  const units = isUnknownArray(inventory.units) ? inventory.units : [];
  if (
    !sameKeySet(boundaryView, {
      delegationGeneration: null,
      inventory: null,
      probeVersion: null,
      service: null,
      sudoers: null,
    }) ||
    !sameKeySet(inventory, { accounts: null, files: null, units: null }) ||
    !sameKeySet(accounts, { group: null, user: null }) ||
    !sameKeySet(service, {
      ActiveState: null,
      FragmentPath: null,
      Group: null,
      LoadState: null,
      SubState: null,
      User: null,
    }) ||
    boundaryView.probeVersion !== version ||
    accounts.user !== true ||
    accounts.group !== true ||
    !isUnknownArray(filesValue) ||
    !files.includes("/usr/local/bin/enoki-probe") ||
    !files.includes("/etc/systemd/system/enoki-probe.service") ||
    files.some((file) =>
      stringValue(file).startsWith("/etc/sudoers.d/enoki-probe"),
    ) ||
    !isUnknownArray(inventory.units) ||
    !units.includes("enoki-probe.service") ||
    service.LoadState !== "loaded" ||
    service.ActiveState !== "active" ||
    service.SubState !== "running" ||
    service.User !== "enoki-probe" ||
    service.Group !== "enoki-probe" ||
    service.FragmentPath !== "/etc/systemd/system/enoki-probe.service" ||
    boundaryView.sudoers !== "" ||
    !isSafeInteger(boundaryView.delegationGeneration) ||
    boundaryView.delegationGeneration < 1
  ) {
    errors.push("Host installation boundary is invalid");
  }
}

function validateIdentityContinuity(
  identity: unknown,
  hostId: unknown,
  errors: string[],
) {
  const identityView = objectView(identity);
  const before = objectView(identityView.before);
  const after = objectView(identityView.after);
  if (
    !isSafeInteger(identityView.hostId) ||
    identityView.hostId !== hostId ||
    typeof before.probeId !== "string" ||
    !before.probeId ||
    !/^[0-9a-f]{64}$/.test(regexInput(before.identitySha256)) ||
    after.probeId !== before.probeId ||
    after.identitySha256 !== before.identitySha256
  ) {
    errors.push("Probe Identity continuity is invalid");
  }
}

function validateIdentityReplacement(
  identity: unknown,
  hostId: unknown,
  errors: string[],
) {
  const identityView = objectView(identity);
  const before = objectView(identityView.before);
  const after = objectView(identityView.after);
  if (
    !isSafeInteger(identityView.hostId) ||
    identityView.hostId !== hostId ||
    !validProbeIdentity(before) ||
    !validProbeIdentity(after) ||
    after.probeId === before.probeId ||
    after.identitySha256 === before.identitySha256
  ) {
    errors.push("Probe Identity replacement is invalid");
  }
}

function validateMigrationRetention(
  retention: unknown,
  errors: string[],
  {
    afterMetrics,
    expectedCandidateHost,
    expectedConfiguration,
    expectedIdentityHostId,
  }: {
    afterMetrics?: unknown;
    expectedCandidateHost?: unknown;
    expectedConfiguration?: unknown;
    expectedIdentityHostId?: unknown;
  } = {},
) {
  const retentionView = objectView(retention);
  const metricHistory = objectView(retentionView.metricHistory);
  const postMetricHistory = objectView(retentionView.postMetricHistory);
  const expectedConfigurationView = objectView(expectedConfiguration);
  const expectedCandidateHostView = objectView(expectedCandidateHost);
  const hostBefore = objectView(retentionView.hostBefore);
  const hostAfter = objectView(retentionView.hostAfter);
  const beforeAnchors = metricsHistoryAnchors(metricHistory);
  const postAnchors = metricsHistoryAnchors(postMetricHistory);
  const afterMetricsList = isUnknownArray(afterMetrics) ? afterMetrics : [];
  const expectedEffectiveConfiguration = {
    configuration: expectedConfigurationView.configuration,
    mode: expectedConfigurationView.mode,
  };
  const latestBeforeAnchor = objectView(beforeAnchors.at(-1));
  if (
    !sameKeySet(retentionView, {
      configuration: null,
      hostAfter: null,
      hostBefore: null,
      metricHistory: null,
      postMetricHistory: null,
    }) ||
    !validRetainedHostProjection(hostBefore) ||
    !validRetainedHostProjection(hostAfter) ||
    !isSafeInteger(hostBefore.id) ||
    hostBefore.id !== hostAfter.id ||
    hostBefore.id !== expectedCandidateHostView.id ||
    hostBefore.id !== expectedIdentityHostId ||
    JSON.stringify(hostAfter.hostProfile) !==
      JSON.stringify(
        canonicalSemanticValue(expectedCandidateHostView.hostProfile),
      ) ||
    !validHostMetadata(hostBefore.hostMetadata) ||
    JSON.stringify(hostBefore.hostMetadata) !==
      JSON.stringify(hostAfter.hostMetadata) ||
    hostBefore.reportedProbeConfigurationVersion !==
      expectedConfigurationView.reportedVersion ||
    hostAfter.reportedProbeConfigurationVersion !==
      expectedConfigurationView.reportedVersion ||
    hostBefore.reportedProbeConfigurationVersion !==
      expectedConfigurationView.version ||
    hostAfter.reportedProbeConfigurationVersion !==
      expectedConfigurationView.version ||
    !validEffectiveProbeConfiguration(retentionView.configuration) ||
    JSON.stringify(retentionView.configuration) !==
      JSON.stringify(expectedEffectiveConfiguration) ||
    !validMetricsHistory(metricHistory) ||
    beforeAnchors.length > 3 ||
    !validMetricsHistory(postMetricHistory) ||
    postAnchors.length > beforeAnchors.length + 3 ||
    afterMetricsList.length !== 2 ||
    !isUnknownArray(metricHistory.anchors) ||
    !beforeAnchors.every((anchor) =>
      postAnchors.some((sample) => sameMetricAnchor(anchor, sample)),
    ) ||
    !afterMetricsList.every((sample) =>
      postAnchors.some((anchor) => sameMetricAnchor(anchor, sample)),
    ) ||
    !isUnknownArray(postMetricHistory.anchors) ||
    !postAnchors.some(
      (anchor) =>
        gtEvidenceNumbers(
          objectView(anchor).sequence,
          latestBeforeAnchor.sequence,
        ) &&
        gtEvidenceNumbers(
          objectView(anchor).collectedAtMs,
          latestBeforeAnchor.collectedAtMs,
        ),
    )
  ) {
    errors.push(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
  }
}

function validEffectiveProbeConfiguration(value: unknown): boolean {
  const valueView = objectView(value);
  const configuration = objectView(valueView.configuration);
  return (
    sameKeySet(valueView, { configuration: null, mode: null }) &&
    valueView.mode === "override" &&
    sameKeySet(configuration, {
      enabledCollectorIds: null,
      metricsCollectionIntervalSeconds: null,
      version: null,
    }) &&
    isUnknownArray(configuration.enabledCollectorIds) &&
    configuration.enabledCollectorIds.every(
      (collectorId: unknown) => typeof collectorId === "string",
    ) &&
    isSafeInteger(configuration.metricsCollectionIntervalSeconds) &&
    typeof configuration.version === "string" &&
    configuration.version.length > 0
  );
}

function validRetainedHostProjection(value: unknown): boolean {
  const valueView = objectView(value);
  return (
    sameKeySet(valueView, {
      hostMetadata: null,
      hostProfile: null,
      id: null,
      reportedProbeConfigurationVersion: null,
    }) &&
    valueView.hostProfile !== null &&
    typeof valueView.hostProfile === "object" &&
    !isUnknownArray(valueView.hostProfile)
  );
}

function validateManualReinstallAuditLog(evidence: unknown, errors: string[]) {
  const evidenceView = objectView(evidence);
  const identity = objectView(evidenceView.identityContinuity);
  const hostId = objectView(evidenceView.candidateHost).id;
  const identityBefore = objectView(identity.before);
  const identityAfter = objectView(identity.after);
  const events = isUnknownArray(evidenceView.auditLog)
    ? evidenceView.auditLog
    : [];
  const event = objectView(
    events.find(
      (entry) =>
        objectView(entry).action === "probe.manual_reinstall_identity_replaced",
    ),
  );
  const details = objectView(event.details);
  if (
    event.actor !== "system" ||
    event.outcome !== "success" ||
    event.subjectId !== String(hostId) ||
    event.subjectType !== "host" ||
    details.oldProbeId !== identityBefore.probeId ||
    details.newProbeId !== identityAfter.probeId ||
    !isUnknownArray(details.sourceProbeSha256) ||
    details.sourceProbeSha256.length < 1 ||
    !/^sha256:[0-9a-f]{64}$/.test(regexInput(details.targetAssetSetDigest)) ||
    details.targetProbeVersion !== candidateProbeVersion(evidence)
  ) {
    errors.push("manual reinstall identity replacement Audit Log is invalid");
  }
}

function candidateProbeVersion(evidence: unknown): string | null {
  const version = objectView(objectView(evidence).candidate).version;
  return typeof version === "string" && version.startsWith("v")
    ? version.slice(1)
    : null;
}

function validateReleaseBaselineEvidence(
  evidence: unknown,
  baseline: unknown,
  errors: string[],
) {
  if (!isReleaseBaselineDescriptor(baseline)) {
    errors.push("Candidate Release Baseline identity is unavailable");
    return;
  }
  const baselineView = objectView(baseline);
  const githubRelease = objectView(baselineView.githubRelease);
  const authorization = objectView(baselineView.authorization);
  const probeAssetSet = objectView(baselineView.probeAssetSet);
  const signingIdentity = objectView(probeAssetSet.signingIdentity);
  const trustRoot = objectView(probeAssetSet.trustRoot);
  const migration =
    baselineView.kind === "enoki-trust-epoch-migration-baseline";
  const expected = {
    authority: migration
      ? {
          authorizationSha256: authorization.sha256,
          githubReleaseId: githubRelease.id,
          legacyReleaseSha256: authorization.legacyReleaseSha256,
          peeledCommitSha: githubRelease.peeledCommitSha,
        }
      : {
          githubReleaseId: githubRelease.id,
          peeledCommitSha: githubRelease.peeledCommitSha,
          signingPublicKeySha256: signingIdentity.publicKeySha256,
          trustRootPublicKeySha256: trustRoot.publicKeySha256,
        },
    descriptorSha256: createHash("sha256")
      .update(JSON.stringify(baseline))
      .digest("hex"),
    hubDigest: objectView(baselineView.hub).imageDigest,
    kind: baselineView.kind,
    probeVersion: migration
      ? stringValue(baselineView.tag).slice(1)
      : probeAssetSet.version,
    tag: baselineView.tag,
  };
  if (JSON.stringify(evidence) !== JSON.stringify(expected)) {
    errors.push("Release Baseline evidence is not bound to the Candidate");
  }
}

function validateCleanupEvidence(cleanup: unknown, errors: string[]) {
  const cleanupView = objectView(cleanup);
  if (objectView(cleanupView.host).clean !== true) {
    errors.push("Host cleanup was not clean");
  }
  if (objectView(cleanupView.environment).clean !== true) {
    errors.push("environment cleanup was not clean");
  }
}

function validateUninstallEvidence(uninstall: unknown, errors: string[]) {
  const uninstallView = objectView(uninstall);
  if (uninstallView.status !== "succeeded") {
    errors.push("Probe Uninstall did not succeed");
  }
  if (uninstallView.hubSoftDeleted !== true) {
    errors.push("Hub Host was not soft-deleted");
  }
  validateTerminalOperation(
    uninstallView.operationTimeline,
    "probe_uninstall",
    "succeeded",
    "Probe Uninstall",
    errors,
  );
  const completion = objectView(uninstallView.hostCompletion);
  const inventory = objectView(completion.inventory);
  const accounts = objectView(inventory.accounts);
  if (
    completion.clean !== true ||
    completion.journaldRetained !== true ||
    completion.sharedDependenciesRetained !== true
  ) {
    errors.push("Host uninstall completion is incomplete");
  }
  if (
    accounts.user !== false ||
    accounts.group !== false ||
    !isUnknownArray(inventory.files) ||
    inventory.files.length > 0 ||
    !isUnknownArray(inventory.units) ||
    inventory.units.length > 0
  ) {
    errors.push("Host uninstall inventory contains residue");
  }
}

function validateTerminalOperation(
  timeline: unknown,
  kind: unknown,
  state: unknown,
  label: unknown,
  errors: string[],
) {
  const entries = isUnknownArray(timeline) ? timeline : [];
  const requested = objectView(entries[0]);
  const final = objectView(entries.at(-1));
  const stable = objectView(entries.at(-2));
  const requestedId = requested.id;
  const requestedHostId = requested.hostId;
  const requestedTargetProbeVersion = requested.targetProbeVersion;
  const finalFailure = objectView(final.failure);
  const stableFailure = objectView(stable.failure);
  const operationIds = new Set(
    entries.map((entry) => objectView(entry).id).filter(isSafeInteger),
  );
  const validTimestamp = (value: unknown) =>
    value === null || (isSafeInteger(value) && value >= 0);
  if (
    !isUnknownArray(timeline) ||
    entries.length < 3 ||
    requested.kind !== kind ||
    requested.state !== "pending" ||
    !isSafeInteger(requestedId) ||
    requestedId < 1 ||
    !isSafeInteger(requestedHostId) ||
    requestedHostId < 1 ||
    requested.acceptedAtMs !== null ||
    requested.runningAtMs !== null ||
    requested.completedAtMs !== null ||
    entries.some((entry) => {
      const operation = objectView(entry);
      return (
        operation.id !== requestedId ||
        operation.hostId !== requestedHostId ||
        operation.kind !== kind ||
        operation.targetProbeVersion !== requestedTargetProbeVersion ||
        !validTimestamp(operation.acceptedAtMs) ||
        !validTimestamp(operation.runningAtMs) ||
        !validTimestamp(operation.completedAtMs)
      );
    }) ||
    final.kind !== kind ||
    final.state !== state ||
    (state === "succeeded" ? Boolean(final.failure) : !final.failure) ||
    !isSafeInteger(final.acceptedAtMs) ||
    !isSafeInteger(final.completedAtMs) ||
    (state === "succeeded" && !isSafeInteger(final.runningAtMs)) ||
    stable.state !== final.state ||
    stableFailure.code !== finalFailure.code ||
    stable.acceptedAtMs !== final.acceptedAtMs ||
    stable.runningAtMs !== final.runningAtMs ||
    stable.completedAtMs !== final.completedAtMs ||
    operationIds.size !== 1
  ) {
    errors.push(`${label} operation timeline is invalid`);
  }
}

function validateRestoreEvidence(
  evidence: unknown,
  errors: string[],
  candidateManifest: unknown,
) {
  const evidenceView = objectView(evidence);
  const version = candidateProbeVersion(evidence);
  const migration =
    objectView(evidenceView.releaseBaseline).kind ===
    "enoki-trust-epoch-migration-baseline";
  if (migration) {
    errors.push(
      "Trust Epoch migration Hub Restore has no production-compatible Candidate Probe identity sequence",
    );
    return;
  }
  validateHostInstallResult(
    evidenceView.baselineInstall,
    "Restore Release Baseline Probe installer",
    errors,
    {
      activeHub: "baseline",
      candidateManifest,
      expectedRunId: evidenceView.runId,
    },
  );
  const migrationView = objectView(evidenceView.migration);
  validateTerminalOperation(
    migrationView.operationTimeline,
    "probe_upgrade",
    "succeeded",
    "restore migration",
    errors,
  );
  if (migrationView.status !== "succeeded") {
    errors.push("restore migration did not succeed");
  }
  if (migrationView.candidateProbeVersion !== version) {
    errors.push("restore migration Candidate version is invalid");
  }
  if (
    firstTimelineEntry(migrationView.operationTimeline).targetProbeVersion !==
    version
  ) {
    errors.push("restore migration target version is invalid");
  }
  const protocolView = objectView(evidenceView.protocol);
  if (
    protocolView.baselineProbeToCandidateHub !== "succeeded" ||
    protocolView.candidateProbeToBaselineHub !== "succeeded"
  ) {
    errors.push("restore compatibility window was not proved");
  }
  const snapshot = objectView(evidenceView.snapshot);
  const image = objectView(evidenceView.image);
  const snapshotVerify = objectView(image.snapshotVerify);
  const stateRestore = objectView(image.stateRestore);
  const snapshotDigest = snapshot.manifestDigest;
  const baselineDigest = objectView(evidenceView.releaseBaseline).hubDigest;
  const hotDataFiles = isUnknownArray(snapshot.hotDataFiles)
    ? snapshot.hotDataFiles
    : [];
  const roots = isUnknownArray(snapshot.roots) ? snapshot.roots : [];
  if (
    snapshot.tool !== "enoki-hub-state" ||
    snapshot.version !== "v1" ||
    snapshot.baselineImageDigest !== baselineDigest ||
    !isFiniteNumber(Date.parse(regexInput(snapshot.recoveryTime))) ||
    !isSafeInteger(snapshot.hotDataFileCount) ||
    snapshot.hotDataFileCount < 1 ||
    !isUnknownArray(snapshot.hotDataFiles) ||
    hotDataFiles.length < 1 ||
    !isUnknownArray(snapshot.roots) ||
    !roots.some(
      (root) =>
        objectView(root).id === "data-root" &&
        objectView(root).path === "/data",
    ) ||
    !roots.some(
      (root) =>
        objectView(root).id === "metrics-archive" &&
        objectView(root).included === true,
    ) ||
    snapshotVerify.status !== "succeeded" ||
    snapshotVerify.manifestDigest !== snapshotDigest ||
    stateRestore.status !== "succeeded" ||
    stateRestore.manifestDigest !== snapshotDigest ||
    !/^sha256:[0-9a-f]{64}$/.test(regexInput(snapshotDigest)) ||
    !/^sha256:[0-9a-f]{64}$/.test(regexInput(baselineDigest)) ||
    image.expectedBaselineDigest !== baselineDigest ||
    image.restoredBaselineDigest !== baselineDigest
  ) {
    errors.push("snapshot verification or restore evidence is invalid");
  }
  const reportingView = objectView(evidenceView.reporting);
  const candidateReporting = objectView(reportingView.candidateHub);
  const restoredReporting = objectView(reportingView.restoredBaselineHub);
  const reportingVersion = version;
  if (
    !isCandidateHostReady(candidateReporting.host, reportingVersion) ||
    !isCandidateHostReady(restoredReporting.host, reportingVersion)
  ) {
    errors.push("Candidate-to-Baseline Host reporting is invalid");
  }
  validateMetrics(candidateReporting.metrics, "pre-Restore", errors);
  validateMetrics(restoredReporting.metrics, "post-Restore", errors);
  validateMetricsProgression(
    candidateReporting.metrics,
    restoredReporting.metrics,
    "Restore",
    errors,
  );
  const identity = objectView(evidenceView.identity);
  const identities = [identity.beforeUpgrade, identity.afterRestore];
  const identityHostId = identity.hostId;
  const firstIdentity = objectView(identities[0]);
  const afterUpgrade = objectView(identity.afterUpgrade);
  if (
    !isSafeInteger(identityHostId) ||
    identityHostId !== objectView(candidateReporting.host).id ||
    identityHostId !== objectView(restoredReporting.host).id ||
    identities.some((value) => {
      const valueView = objectView(value);
      return (
        typeof valueView.probeId !== "string" ||
        !valueView.probeId ||
        !/^[0-9a-f]{64}$/.test(regexInput(valueView.identitySha256))
      );
    }) ||
    identities.some((value) => {
      const valueView = objectView(value);
      return (
        valueView.probeId !== firstIdentity.probeId ||
        valueView.identitySha256 !== firstIdentity.identitySha256
      );
    }) ||
    afterUpgrade.probeId !== firstIdentity.probeId ||
    afterUpgrade.identitySha256 !== firstIdentity.identitySha256
  ) {
    errors.push("Restore Probe Identity continuity is invalid");
  }
  const profileContinuity = objectView(evidenceView.hostProfileContinuity);
  const beforeProfile = objectView(profileContinuity.candidateBeforeRestore);
  const restoredProfile = objectView(profileContinuity.restoredBaseline);
  if (
    !/^[0-9a-f]{64}$/.test(regexInput(beforeProfile.sha256)) ||
    restoredProfile.sha256 !== beforeProfile.sha256 ||
    !isUnknownRecord(beforeProfile.projection) ||
    Object.keys(beforeProfile.projection).length === 0 ||
    JSON.stringify(restoredProfile.projection) !==
      JSON.stringify(beforeProfile.projection)
  ) {
    errors.push("restored compatibility evidence is incomplete");
  }
}

export function createUiGateResult({
  artifactName,
  candidate,
  playwrightOutcome,
}: {
  artifactName: unknown;
  candidate: unknown;
  playwrightOutcome: unknown;
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
  scenarioPlan,
  requested,
  run,
  standardCi,
  uiGate,
}: {
  artifactIndex?: unknown;
  candidateManifest?: unknown;
  componentResults?: unknown;
  evidenceErrors?: readonly string[];
  gateResults?: unknown;
  hostGates?: readonly unknown[];
  identities?: {
    hub?: unknown;
    probeAssetSet?: unknown;
    releaseBaseline?: unknown;
  };
  scenarioPlan?: unknown;
  requested?: unknown;
  run?: unknown;
  standardCi?: unknown;
  uiGate?: unknown;
}) {
  assertAttemptSummaryInputs({ componentResults, gateResults, requested, run });
  const candidateIsAvailable = isCandidateManifest(candidateManifest);
  const manifestView = objectView(candidateManifest);
  const candidateIdentity = objectView(manifestView.candidate);
  const gateResultsView = objectView(gateResults);
  const uiGateView = objectView(uiGate);
  const standardCiView = objectView(standardCi);
  const request = requested ?? {
    commit: candidateIdentity.commit ?? null,
    version: candidateIdentity.version ?? null,
  };
  const requestView = objectView(request);
  const components: Record<string, unknown> = componentResults
    ? normalizeComponentResults(componentResults)
    : {
        candidateAssembly: gateResultsView.candidateBuild,
        candidateUiContract: gateResultsView.uiJob,
        hostMatrix: gateResultsView.matrixJob,
        matrixExpansion: gateResultsView.matrixExpansion,
      };
  const normalizedGates = {
    candidateBuild:
      components.candidateAssembly ??
      gateResultsView.candidateBuild ??
      "missing",
    matrixExpansion:
      components.matrixExpansion ??
      gateResultsView.matrixExpansion ??
      "missing",
    matrixJob: components.hostMatrix ?? gateResultsView.matrixJob ?? "missing",
    uiJob: components.candidateUiContract ?? gateResultsView.uiJob ?? "missing",
  };
  const expectedCells = validateScenarioPlan(scenarioPlan);
  const artifactUrl = (artifactName: unknown) =>
    resolveArtifactUrl(artifactIndex, artifactName, run);
  const providedHostGates = hostGates ?? [];
  const gatesByCell = new Map<unknown, unknown>(
    providedHostGates.map((gate): [unknown, unknown] => [
      objectView(gate).cellId,
      gate,
    ]),
  );
  const hostScenarios = expectedCells.map((cell) => {
    const cellView = objectView(cell);
    const gateView = objectView(gatesByCell.get(cellView.cellId));
    const capabilities = objectView(cell).capabilities;
    const expectedOutcome = "succeeded";
    return {
      artifactName: gateView.artifactName ?? null,
      capabilities: isUnknownArray(capabilities) ? [...capabilities] : [],
      cellId: cellView.cellId,
      environmentId: cellView.environmentId,
      evidenceOutcome: gateView.evidenceOutcome ?? "missing",
      evidenceUrl: artifactUrl(gateView.artifactName),
      expectedOutcome,
      outcome: gateView.outcome ?? "missing",
      releaseBaselineKind: gateView.releaseBaselineKind ?? null,
      runner: cellView.runner,
      scenarioId: cellView.scenarioId,
      scenarioStepOutcome: gateView.scenarioStepOutcome ?? "missing",
      verifyCleanStepOutcome: gateView.verifyCleanStepOutcome ?? "missing",
    };
  });
  const uiOutcome = uiGateView.outcome ?? "missing";
  const standardCiValidationErrors = standardCiEvidenceErrors(
    standardCi,
    requestView.commit,
  );
  const standardCiIsValid = standardCiValidationErrors.length === 0;
  const verified =
    candidateIsAvailable &&
    sameCandidate(request, candidateIdentity) &&
    standardCiIsValid &&
    (!componentResults ||
      requiredComponentNames.every((name) => components[name] === "success")) &&
    normalizedGates.candidateBuild === "success" &&
    normalizedGates.matrixExpansion === "success" &&
    normalizedGates.matrixJob === "success" &&
    normalizedGates.uiJob === "success" &&
    uiOutcome === "succeeded" &&
    isArtifactName(uiGateView.artifactName) &&
    (!artifactIndex || Boolean(artifactUrl(uiGateView.artifactName))) &&
    sameCandidate(uiGateView.candidate, candidateIdentity) &&
    expectedCells.length > 0 &&
    providedHostGates.length === expectedCells.length &&
    gatesByCell.size === expectedCells.length &&
    hostScenarios.every((scenario) => {
      const gateView = objectView(gatesByCell.get(scenario.cellId));
      return (
        scenario.outcome === scenario.expectedOutcome &&
        scenario.evidenceOutcome === scenario.expectedOutcome &&
        isArtifactName(gateView.artifactName) &&
        (!artifactIndex || Boolean(scenario.evidenceUrl)) &&
        sameCandidate(gateView.candidate, candidateIdentity) &&
        gateView.scenarioId === scenario.scenarioId &&
        gateView.releaseBaselineKind ===
          objectView(manifestView.releaseBaseline).kind
      );
    });

  const hub = manifestView.hub ?? identities.hub ?? null;
  const probeAssetSet =
    manifestView.probeAssetSet ?? identities.probeAssetSet ?? null;
  const releaseBaseline =
    manifestView.releaseBaseline ?? identities.releaseBaseline ?? null;
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
  if (artifactIndex && !artifactUrl(uiGateView.artifactName)) {
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
    candidate: manifestView.candidate ?? null,
    componentResults: components,
    failureReasons: [...new Set(failureReasons)],
    freshCandidateRequiredForPublish: true,
    gates: {
      candidateBuild: { outcome: normalizedGates.candidateBuild },
      candidateUiContract: {
        artifactName: uiGateView.artifactName ?? null,
        evidenceUrl: artifactUrl(uiGateView.artifactName),
        outcome: uiOutcome,
      },
      hostMatrix: { outcome: normalizedGates.matrixJob },
      hostScenarios,
      matrixExpansion: { outcome: normalizedGates.matrixExpansion },
      standardCi: {
        outcome: standardCiIsValid ? "success" : "missing",
        runUrl: standardCiView.runUrl ?? null,
      },
    },
    hub,
    kind: "enoki-release-verification-evidence",
    missingIdentities,
    bootstrapRecipe: manifestView.bootstrapRecipe ?? null,
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

export function renderReleaseVerificationEvidenceMarkdown(
  summary: unknown,
): string {
  const summaryView = objectView(summary);
  const baselineView = objectView(summaryView.releaseBaseline);
  const candidateView = objectView(
    summaryView.candidate ?? summaryView.requested,
  );
  const requestedView = objectView(summaryView.requested);
  const hubView = objectView(summaryView.hub);
  const probeAssetSetView = objectView(summaryView.probeAssetSet);
  const signingIdentityView = objectView(probeAssetSetView.signingIdentity);
  const gatesView = objectView(summaryView.gates);
  const files = isUnknownArray(probeAssetSetView.files)
    ? probeAssetSetView.files
    : [];
  const hostScenarios = isUnknownArray(gatesView.hostScenarios)
    ? gatesView.hostScenarios
    : [];
  const failureReasons = isUnknownArray(summaryView.failureReasons)
    ? summaryView.failureReasons
    : [];
  const baseline = summaryView.releaseBaseline
    ? `${stringValue(baselineView.tag)} @ ${objectView(baselineView.githubRelease).peeledCommitSha ?? "unknown commit"}`
    : "missing";
  const candidate = summaryView.candidate ?? summaryView.requested;
  const lines = [
    "# Enoki Release Verification Evidence",
    "",
    `- Verified: **${summaryView.verified ? "yes" : "no"}**`,
    "- Scope: **Current workflow run only** — this evidence cannot authorize another run.",
    `- Requested: \`${requestedView.version}\` @ \`${requestedView.commit}\``,
    `- Candidate Manifest: ${summaryView.candidate ? `\`${candidateView.version}\` @ \`${candidateView.commit}\`` : "missing"}`,
    `- Release Baseline: \`${baseline}\``,
    `- Hub OCI digest: \`${hubView.digest ?? "missing"}\``,
    `- Hub archive SHA-256: \`${hubView.archiveSha256 ?? "missing"}\``,
    `- Probe signing key SHA-256: \`${signingIdentityView.publicKeySha256 ?? "missing"}\``,
    "",
    "## Signed Probe Asset Set",
    "",
    "| File | SHA-256 |",
    "| --- | --- |",
    ...files.map(
      (file) =>
        `| \`${objectView(file).file}\` | \`${objectView(file).sha256}\` |`,
    ),
    "",
    "## Required gates",
    "",
    "| Gate | Capabilities | Outcome | Evidence |",
    "| --- | --- | --- | --- |",
    `| Candidate build | — | ${objectView(gatesView.candidateBuild).outcome} | Candidate Manifest |`,
    `| Standard CI | — | ${objectView(gatesView.standardCi).outcome} | ${objectView(gatesView.standardCi).runUrl ?? "missing"} |`,
    `| Matrix expansion | — | ${objectView(gatesView.matrixExpansion).outcome} | central matrix |`,
    `| Candidate-image UI Contract | — | ${objectView(gatesView.candidateUiContract).outcome} | ${evidenceLink(gatesView.candidateUiContract)} |`,
    ...hostScenarios.map((gate) => {
      const gateView = objectView(gate);
      const capabilities = isUnknownArray(gateView.capabilities)
        ? gateView.capabilities
        : [];
      return `| \`${gateView.cellId}\` | ${capabilities.map((capability) => `\`${capability}\``).join(", ") || "missing"} | ${gateView.outcome} | ${evidenceLink(gate)} |`;
    }),
    "",
    "## Failure reasons",
    "",
    ...(failureReasons.length > 0
      ? failureReasons.map((reason) => `- ${reason}`)
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
}: {
  componentResults: unknown;
  gateResults: unknown;
  requested: unknown;
  run: unknown;
}) {
  if ((!componentResults && !gateResults) || !objectView(run).url) {
    throw new Error("Component results and workflow run identity are required");
  }
  const requestedView = objectView(requested);
  if (requested && (!requestedView.commit || !requestedView.version)) {
    throw new Error("Requested candidate identity is invalid");
  }
}

function isCandidateManifest(candidateManifest: unknown): boolean {
  // 候选目录已由 validateReleaseCandidate 完成内容闭包验证；此处重验其
  // schema 4 描述符，避免汇总器把残缺的已解析值当作可验证的候选。
  const manifestView = objectView(candidateManifest);
  return (
    isPlainObject(candidateManifest) &&
    manifestView.kind === "enoki-release-candidate" &&
    manifestView.schemaVersion === 4 &&
    sameKeySet(manifestView, {
      bootstrapRecipe: null,
      candidate: null,
      hub: null,
      kind: null,
      probeAssetSet: null,
      releaseBaseline: null,
      schemaVersion: null,
    }) &&
    isCandidateIdentity(manifestView.candidate) &&
    isCandidateBootstrapRecipe(
      manifestView.bootstrapRecipe,
      manifestView.candidate,
    ) &&
    isCandidateHub(manifestView.hub, manifestView.candidate) &&
    isCandidateProbeAssetSet(
      manifestView.probeAssetSet,
      manifestView.candidate,
    ) &&
    isReleaseBaselineDescriptor(manifestView.releaseBaseline)
  );
}

function isCandidateBootstrapRecipe(recipe: unknown, candidate: unknown) {
  const recipeView = objectView(recipe);
  const candidateVersion = stringValue(objectView(candidate).version);
  return (
    isPlainObject(recipe) &&
    sameKeySet(recipeView, {
      bundleVersion: null,
      distribution: null,
      file: null,
      kind: null,
      recordFile: null,
      recordSha256: null,
      recordSize: null,
      rootFingerprint: null,
      schemaVersion: null,
      sha256: null,
      size: null,
      targets: null,
      version: null,
    }) &&
    recipeView.bundleVersion === candidateVersion.slice(1) &&
    recipeView.distribution === "enoki" &&
    recipeView.file === "enoki-probe-bootstrap.py" &&
    recipeView.kind === "enoki-probe-bootstrap-recipe-record" &&
    recipeView.recordFile === "enoki-probe-bootstrap-recipe.json" &&
    /^[0-9a-f]{64}$/.test(regexInput(recipeView.recordSha256)) &&
    isSafeInteger(recipeView.recordSize) &&
    recipeView.recordSize > 0 &&
    recipeView.schemaVersion === 1 &&
    isUnknownArray(recipeView.targets) &&
    recipeView.targets.length === 4 &&
    recipeView.version === "v1" &&
    /^[0-9a-f]{64}$/.test(regexInput(recipeView.rootFingerprint)) &&
    /^[0-9a-f]{64}$/.test(regexInput(recipeView.sha256)) &&
    isSafeInteger(recipeView.size) &&
    recipeView.size > 0
  );
}

function isPlainObject(value: unknown): boolean {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isCandidateIdentity(candidate: unknown): boolean {
  const candidateView = objectView(candidate);
  return (
    isPlainObject(candidate) &&
    sameKeySet(candidateView, { commit: null, version: null }) &&
    /^[0-9a-f]{40}$/.test(regexInput(candidateView.commit)) &&
    /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(
      regexInput(candidateView.version),
    )
  );
}

function isCandidateHub(hub: unknown, candidate: unknown): boolean {
  const hubView = objectView(hub);
  const candidateVersion = stringValue(objectView(candidate).version);
  return (
    isPlainObject(hub) &&
    sameKeySet(hubView, {
      archive: null,
      archiveSha256: null,
      digest: null,
      embeddedProbeVersion: null,
      size: null,
    }) &&
    hubView.archive === `hub/enoki-hub-${candidateVersion}.oci.tar` &&
    /^[0-9a-f]{64}$/.test(regexInput(hubView.archiveSha256)) &&
    /^sha256:[0-9a-f]{64}$/.test(regexInput(hubView.digest)) &&
    hubView.embeddedProbeVersion === candidateVersion.slice(1) &&
    isSafeInteger(hubView.size) &&
    hubView.size > 0
  );
}

function isCandidateProbeAssetSet(
  probeAssetSet: unknown,
  candidate: unknown,
): boolean {
  const assetSetView = objectView(probeAssetSet);
  const signingIdentityView = objectView(assetSetView.signingIdentity);
  const candidateVersion = stringValue(objectView(candidate).version);
  return (
    isPlainObject(probeAssetSet) &&
    sameKeySet(assetSetView, {
      directory: null,
      files: null,
      signingIdentity: null,
      version: null,
    }) &&
    assetSetView.directory === "probe-assets" &&
    assetSetView.version === candidateVersion.slice(1) &&
    isUnknownArray(assetSetView.files) &&
    assetSetView.files.length > 0 &&
    assetSetView.files.every((file) => {
      const fileView = objectView(file);
      return (
        isPlainObject(file) &&
        typeof fileView.file === "string" &&
        fileView.file.length > 0 &&
        /^[0-9a-f]{64}$/.test(regexInput(fileView.sha256)) &&
        isSafeInteger(fileView.size) &&
        fileView.size > 0
      );
    }) &&
    isPlainObject(assetSetView.signingIdentity) &&
    sameKeySet(signingIdentityView, {
      algorithm: null,
      publicKeyFile: null,
      publicKeySha256: null,
    }) &&
    signingIdentityView.algorithm === "rsa-sha256" &&
    signingIdentityView.publicKeyFile === "signing-key.pem" &&
    /^[0-9a-f]{64}$/.test(regexInput(signingIdentityView.publicKeySha256))
  );
}

function isReleaseBaselineDescriptor(releaseBaseline: unknown): boolean {
  const releaseBaselineView = objectView(releaseBaseline);
  const githubRelease = objectView(releaseBaselineView.githubRelease);
  const hub = objectView(releaseBaselineView.hub);
  return (
    isPlainObject(releaseBaseline) &&
    (releaseBaselineView.kind === "enoki-release-baseline" ||
      releaseBaselineView.kind === "enoki-trust-epoch-migration-baseline") &&
    typeof releaseBaselineView.tag === "string" &&
    /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(
      releaseBaselineView.tag,
    ) &&
    isPlainObject(releaseBaselineView.githubRelease) &&
    isSafeInteger(githubRelease.id) &&
    githubRelease.id > 0 &&
    /^[0-9a-f]{40}$/.test(regexInput(githubRelease.peeledCommitSha)) &&
    /^[0-9a-f]{40}$/.test(regexInput(githubRelease.tagRefSha)) &&
    isPlainObject(releaseBaselineView.hub) &&
    /^sha256:[0-9a-f]{64}$/.test(regexInput(hub.imageDigest))
  );
}

function displayIdentity(identity: unknown): string | undefined {
  const labels: Record<string, string> = {
    "candidate-manifest": "Candidate Manifest",
    "hub-oci": "Hub OCI",
    "probe-asset-set": "Probe Asset Set",
    "release-baseline": "Release Baseline",
    "standard-ci-evidence": "standard CI",
  };
  return labels[regexInput(identity)];
}

function normalizeComponentResults(
  componentResults: unknown,
): Record<string, unknown> {
  const resultsView = objectView(componentResults);
  const allowed = new Set(["success", "failure", "cancelled", "skipped"]);
  return Object.fromEntries(
    requiredComponentNames.map((name) => [
      name,
      typeof resultsView[name] === "string" && allowed.has(resultsView[name])
        ? resultsView[name]
        : "missing",
    ]),
  );
}

function validateScenarioPlan(plan: unknown): readonly unknown[] {
  if (plan === null || plan === undefined) return [];
  const planView = objectView(plan);
  const cells = isUnknownArray(planView.cells) ? planView.cells : [];
  if (
    planView.kind !== "enoki-release-scenario-plan" ||
    planView.schemaVersion !== 1 ||
    !isUnknownArray(planView.cells) ||
    cells.length === 0 ||
    cells.some((cell) => {
      const cellView = objectView(cell);
      const capabilities = cellView.capabilities;
      return (
        typeof cellView.cellId !== "string" ||
        typeof cellView.environmentId !== "string" ||
        typeof cellView.runner !== "string" ||
        typeof cellView.scenarioId !== "string" ||
        !isUnknownArray(capabilities) ||
        capabilities.some(
          (capability) => typeof capability !== "string" || !capability,
        ) ||
        (cellView.scenarioId === "fresh-install-uninstall" &&
          !capabilities.includes("canonical-report-response-loss"))
      );
    }) ||
    new Set(cells.map((cell) => objectView(cell).cellId)).size !== cells.length
  ) {
    throw new Error("compiled Release Scenario Plan is invalid");
  }
  return cells;
}

function sameCandidate(left: unknown, right: unknown): boolean {
  const leftView = objectView(left);
  const rightView = objectView(right);
  return (
    leftView.commit === rightView.commit &&
    leftView.version === rightView.version
  );
}

function cellIdEnvironment(cellId: unknown): string | null {
  if (typeof cellId !== "string" || !cellId.includes("--")) return null;
  return cellId.slice(0, cellId.indexOf("--"));
}

function normalizeEvidenceOutcome(
  value: unknown,
): "failed" | "skipped" | "succeeded" | "missing" {
  return value === "succeeded" || value === "skipped" || value === "failed"
    ? value
    : "missing";
}

function evidenceLink(gate: unknown): string {
  const gateView = objectView(gate);
  return gateView.evidenceUrl && gateView.artifactName
    ? `[${gateView.artifactName}](${gateView.evidenceUrl})`
    : "missing";
}

function isArtifactName(value: unknown): boolean {
  return (
    typeof value === "string" &&
    value.length <= 255 &&
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)
  );
}

function resolveArtifactUrl(
  artifactIndex: unknown,
  artifactName: unknown,
  run: unknown,
): string | null {
  if (!isArtifactName(artifactName)) return null;
  const candidate = objectView(artifactIndex)[stringValue(artifactName)];
  if (typeof candidate !== "string") return null;
  try {
    const url = new URL(candidate);
    if (
      url.protocol !== "https:" ||
      !url.pathname.includes(`/actions/runs/${objectView(run).id}/artifacts/`)
    ) {
      return null;
    }
    return url.href;
  } catch {
    return null;
  }
}
