import { createHash } from "node:crypto";

import {
  hasAdvancingPortableMetrics,
  isSupportedReleaseTestHostVirtualization,
  isCandidateHostReady,
} from "./release-e2e-lib.mjs";

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
}) {
  const candidate = candidateManifest?.candidate ?? null;
  const evidenceOutcome = normalizeEvidenceOutcome(evidence?.result?.status);
  const scenarioId = evidence?.scenario ?? null;
  const successfulSteps =
    scenarioOutcome === "success" && verifyCleanOutcome === "success";
  const consistentEvidence =
    isCandidateManifest(candidateManifest) &&
    typeof scenarioId === "string" &&
    cellId === `${cellIdEnvironment(cellId)}--${scenarioId}` &&
    sameCandidate(evidence?.candidate, candidate);
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
    releaseBaselineKind: evidence?.releaseBaseline?.kind ?? null,
    scenarioId,
    scenarioStepOutcome: scenarioOutcome,
    schemaVersion: 1,
    verifyCleanStepOutcome: verifyCleanOutcome,
  };
}

function validateHostScenarioEvidence(
  evidence,
  outcome,
  cellId,
  candidateManifest,
) {
  if (outcome !== "succeeded") return [];

  const errors = [];
  if (evidence?.schemaVersion !== 2) errors.push("invalid schemaVersion");
  if (evidence?.phase !== "succeeded") errors.push("phase was not succeeded");
  validateReleaseTestHostEvidence(evidence, cellId, errors);
  validateCleanupEvidence(evidence?.cleanup, errors);
  validateReleaseBaselineEvidence(
    evidence?.releaseBaseline,
    candidateManifest?.releaseBaseline,
    errors,
  );
  const baselineKind = evidence?.releaseBaseline?.kind;
  if (
    baselineKind !== "enoki-release-baseline" &&
    baselineKind !== "enoki-trust-epoch-migration-baseline"
  ) {
    errors.push("Release Baseline evidence kind is invalid");
  }
  if (evidence?.scenario !== "fresh-install-uninstall") {
    validateUninstallEvidence(evidence?.uninstall, errors);
  }

  const requiredByScenario = {
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
  for (const field of requiredByScenario[evidence?.scenario] ?? []) {
    if (evidence?.[field] == null) errors.push(`missing ${field}`);
  }

  if (evidence?.scenario === "fresh-install-uninstall") {
    validateFreshEvidence(evidence, errors, candidateManifest);
  } else if (
    evidence?.scenario === "compatible-upgrade-uninstall" ||
    evidence?.scenario === "replacement-migration-uninstall"
  ) {
    validateBaselineEvidence(evidence, errors, candidateManifest);
  } else if (evidence?.scenario === "post-replacement-repair-uninstall") {
    validateRepairEvidence(evidence, errors, candidateManifest);
  } else if (evidence?.scenario === "hub-restore-compatibility-window") {
    validateRestoreEvidence(evidence, errors, candidateManifest);
  } else {
    errors.push("unknown Host scenario");
  }
  return [...new Set(errors)];
}

function validateReleaseTestHostEvidence(evidence, cellId, errors) {
  if (!evidence?.releaseTestHost) {
    errors.push("missing Release Test Host platform evidence");
  }
  if (!evidence?.infrastructure) {
    errors.push("missing Release E2E infrastructure evidence");
  }
  const expected = /^ubuntu-(22[.]04|24[.]04)-x86_64--[a-z][a-z0-9-]*$/.exec(
    cellId ?? "",
  );
  if (!expected) {
    errors.push("matrix cell is not a supported Ubuntu x86_64 release gate");
    return;
  }
  const host = evidence?.releaseTestHost;
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
    Object.keys(host ?? {})
      .sort()
      .join(",") !== expectedHostKeys.join(",") ||
    host?.architecture !== "x86_64" ||
    host?.operatingSystem !== "ubuntu" ||
    host?.operatingSystemVersion !== expected[1] ||
    host?.pid1 !== "systemd" ||
    !isSupportedReleaseTestHostVirtualization(host?.virtualization) ||
    ![
      "deviceView",
      "journaldSocket",
      "rootFilesystem",
      "systemdNotifySocket",
      "unifiedCgroup",
    ].every((primitive) => host?.[primitive] === true)
  ) {
    errors.push(
      "Release Test Host platform evidence does not match the matrix cell",
    );
  }
  const infrastructure = evidence?.infrastructure;
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

function hasExactEvidenceFields(record, expected) {
  if (
    record == null ||
    typeof record !== "object" ||
    Array.isArray(record) ||
    !sameKeySet(record, expected)
  ) {
    return false;
  }
  return Object.entries(expected).every(
    ([key, value]) => record[key] === value,
  );
}

function sameKeySet(actual, expected) {
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  return (
    actualKeys.length === expectedKeys.length &&
    actualKeys.every((key, index) => key === expectedKeys[index])
  );
}

function validateFreshEvidence(evidence, errors, candidateManifest) {
  const version = candidateProbeVersion(evidence);
  if (!isCandidateHostReady(evidence?.host, version)) {
    errors.push("fresh Host Profile is invalid");
  }
  validateMetrics(evidence?.metrics, "fresh reporting", errors);
  validateMetricsHistoryPreservation(evidence, errors);
  validateProbeConfiguration(evidence?.probeConfiguration, errors);
  validateInstalledBundleFailureRepair(
    evidence?.installedBundleFailureRepair,
    version,
    evidence?.host?.id,
    errors,
  );
  validateFreshLifecycleAuditLog(evidence, errors);
  validateInstalledHostBoundary(evidence?.hostBoundary, version, errors);
  validateHostInstallResult(
    evidence?.initialInstall,
    "initial Probe installer",
    errors,
    {
      activeHub: "candidate",
      candidateManifest,
      expectedRunId: evidence?.runId,
    },
  );
  validateRepeatedAddEvidence(evidence?.repeatedAdd, errors);
  validateLocalUninstallEvidence(
    evidence?.localUninstall,
    evidence?.host?.id,
    "first Local Probe Uninstall",
    errors,
  );
  validateReEnrollmentEvidence(evidence, errors, candidateManifest);
  validateHubOnlyDeletionEvidence(evidence, errors);
  validateLocalUninstallEvidence(
    evidence?.finalLocalUninstall,
    null,
    "final Local Probe Uninstall",
    errors,
  );
  validateDiagnosticsEvidence(evidence?.diagnostics, errors);
}

function validateInstalledBundleFailureRepair(
  value,
  version,
  expectedHostId,
  errors,
) {
  const failure = value?.failure;
  const bundle = failure?.bundle;
  const epoch = failure?.failureEpoch;
  const latch = failure?.latch;
  const budget = failure?.recoveryBudget;
  const repair = value?.repair;
  const sha256 = (candidate) => /^[0-9a-f]{64}$/.test(candidate ?? "");
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
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(epoch.bootId ?? "") ||
    !sha256(epoch.generation) ||
    epoch.hostId !== String(expectedHostId) ||
    !sha256(epoch.identityReceiptSha256) ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(epoch.probeId ?? "") ||
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
    repair.probeId !== value?.identity?.after?.probeId ||
    JSON.stringify(value?.identity?.after) !==
      JSON.stringify(value?.identity?.before) ||
    value?.host?.id !== expectedHostId ||
    !isCandidateHostReady(value?.host, version)
  ) {
    errors.push("Installed Bundle Failure Repair evidence is invalid");
  }
  validateInstalledHostBoundary(value?.hostBoundary, version, errors);
}

function validateInstallerEvidence(value, label, errors) {
  const output = value?.output;
  if (
    output?.code !== 0 ||
    typeof output?.stdout !== "string" ||
    typeof output?.stderr !== "string" ||
    !output.stdout.includes("ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE") ||
    !output.stdout.includes("Enoki Probe installed as enoki-probe.service.") ||
    containsUnredactedSecret(output)
  ) {
    errors.push(`${label} output is invalid`);
  }
}

function validateHostInstallResult(
  value,
  label,
  errors,
  { activeHub, allowLegacyMigration = false, candidateManifest, expectedRunId },
) {
  validateInstallerEvidence(value, label, errors);
  if (
    !sameKeySet(value ?? {}, {
      bootstrapRecipeProvenance: null,
      output: null,
      runId: null,
    }) ||
    value?.runId !== expectedRunId
  ) {
    errors.push(`${label} production result is invalid`);
  }
  if (
    allowLegacyMigration &&
    candidateManifest?.releaseBaseline?.kind ===
      "enoki-trust-epoch-migration-baseline" &&
    value?.bootstrapRecipeProvenance === null
  ) {
    return;
  }
  validateBootstrapRecipeProvenance(
    value?.bootstrapRecipeProvenance,
    candidateManifest,
    activeHub,
    errors,
  );
}

function validateBootstrapRecipeProvenance(
  provenance,
  candidateManifest,
  activeHub,
  errors,
) {
  const record = provenance?.record;
  const recipe = record?.recipe;
  const baseline = candidateManifest?.releaseBaseline;
  const expectedDigest =
    activeHub === "candidate"
      ? candidateManifest?.hub?.digest
      : baseline?.hub?.imageDigest;
  const expectedVersion =
    activeHub === "candidate"
      ? candidateManifest?.probeAssetSet?.version
      : baseline?.kind === "enoki-release-baseline"
        ? baseline.probeAssetSet?.version
        : null;
  const recordBytes = Buffer.from(`${JSON.stringify(record ?? {}, null, 2)}\n`);
  const candidateRecipe = candidateManifest?.bootstrapRecipe;
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
    provenance.activeHub !== activeHub ||
    provenance.hubDigest !== expectedDigest ||
    provenance.kind !== "enoki-release-e2e-bootstrap-recipe-provenance" ||
    provenance.recordFile !== "enoki-probe-bootstrap-recipe.json" ||
    provenance.recordSha256 !==
      createHash("sha256").update(recordBytes).digest("hex") ||
    provenance.recordSize !== recordBytes.byteLength ||
    provenance.schemaVersion !== 1 ||
    record?.bundleVersion !== expectedVersion ||
    record?.distribution !== "enoki" ||
    record?.kind !== "enoki-probe-bootstrap-recipe-record" ||
    record?.schemaVersion !== 1 ||
    !/^[0-9a-f]{64}$/.test(record?.rootFingerprint ?? "") ||
    !Array.isArray(record?.targets) ||
    record.targets.length !== 4 ||
    recipe?.file !== "enoki-probe-bootstrap.py" ||
    recipe?.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(recipe?.sha256 ?? "") ||
    !Number.isSafeInteger(recipe?.size) ||
    recipe.size < 1 ||
    (activeHub === "candidate" &&
      (candidateRecipe?.recordFile !== provenance.recordFile ||
        candidateRecipe?.recordSha256 !== provenance.recordSha256 ||
        candidateRecipe?.recordSize !== provenance.recordSize ||
        candidateRecipe?.bundleVersion !== record.bundleVersion ||
        candidateRecipe?.distribution !== record.distribution ||
        candidateRecipe?.kind !== record.kind ||
        candidateRecipe?.rootFingerprint !== record.rootFingerprint ||
        candidateRecipe?.schemaVersion !== record.schemaVersion ||
        JSON.stringify(candidateRecipe?.targets) !==
          JSON.stringify(record.targets) ||
        candidateRecipe?.file !== recipe.file ||
        candidateRecipe?.sha256 !== recipe.sha256 ||
        candidateRecipe?.size !== recipe.size ||
        candidateRecipe?.version !== recipe.version))
  ) {
    errors.push(
      `Active ${activeHub} Hub Bootstrap recipe provenance is invalid`,
    );
  }
}

function validateRepeatedAddEvidence(repeatedAdd, errors) {
  if (
    repeatedAdd?.enrollment?.target?.kind !== "new_host" ||
    repeatedAdd?.enrollmentStatus?.status !== "rejected" ||
    repeatedAdd?.enrollmentStatus?.rejection?.code !==
      "existing_probe_installation" ||
    repeatedAdd?.rejection?.code !== "existing_probe_installation" ||
    !sameHubHostProjection(repeatedAdd?.hostBefore, repeatedAdd?.hostAfter) ||
    JSON.stringify(repeatedAdd?.stateBefore) !==
      JSON.stringify(repeatedAdd?.stateAfter) ||
    !validInstalledState(repeatedAdd?.stateBefore)
  ) {
    errors.push("repeated Add rejection evidence is invalid");
  }
}

function validateLocalUninstallEvidence(value, expectedHostId, label, errors) {
  const completion = value?.completion;
  const inventory = completion?.inventory;
  const activeHost = value?.activeHost;
  const offlineHost = value?.offlineHost;
  if (
    completion?.clean !== true ||
    completion?.journaldRetained !== true ||
    completion?.sharedDependenciesRetained !== true ||
    inventory?.accounts?.user !== false ||
    inventory?.accounts?.group !== false ||
    !Array.isArray(inventory?.files) ||
    inventory.files.length !== 0 ||
    !Array.isArray(inventory?.units) ||
    inventory.units.length !== 0 ||
    (expectedHostId !== null &&
      (activeHost?.id !== expectedHostId ||
        activeHost?.status === "offline" ||
        offlineHost?.id !== expectedHostId ||
        offlineHost?.status !== "offline"))
  ) {
    errors.push(`${label} evidence is invalid`);
  }
}

function validateReEnrollmentEvidence(evidence, errors, candidateManifest) {
  const reEnrollment = evidence?.reEnrollment;
  const before = reEnrollment?.identity?.before;
  const after = reEnrollment?.identity?.after;
  if (
    reEnrollment?.hostId !== evidence?.host?.id ||
    reEnrollment?.host?.id !== evidence?.host?.id ||
    reEnrollment?.enrollment?.target?.kind !== "existing_host" ||
    reEnrollment.enrollment.target.hostId !== evidence?.host?.id ||
    !isCandidateHostReady(
      reEnrollment?.host,
      candidateProbeVersion(evidence),
    ) ||
    !validProbeIdentity(before) ||
    !validProbeIdentity(after) ||
    after.probeId === before.probeId ||
    after.identitySha256 === before.identitySha256 ||
    !hasAdvancingPortableMetrics(reEnrollment?.metrics) ||
    !sameEffectiveProbeConfiguration(
      reEnrollment?.probeConfiguration,
      evidence?.probeConfiguration,
    ) ||
    !validInstalledBoundary(
      reEnrollment?.hostBoundary,
      candidateProbeVersion(evidence),
    )
  ) {
    errors.push("Host Re-enrollment evidence is invalid");
  }
  validateHostInstallResult(
    reEnrollment?.installer,
    "Host Re-enrollment installer",
    errors,
    {
      activeHub: "candidate",
      candidateManifest,
      expectedRunId: evidence?.runId,
    },
  );
}

function validateMetricsHistoryPreservation(evidence, errors) {
  const initial = evidence?.metricsHistory;
  const reEnrollment = evidence?.reEnrollment?.metricsHistory;
  if (
    !validMetricsHistory(initial) ||
    !validMetricsHistory(reEnrollment) ||
    !initial.anchors.every((anchor) =>
      reEnrollment.anchors.some((candidate) =>
        sameMetricAnchor(candidate, anchor),
      ),
    ) ||
    !reEnrollment.anchors.some(
      (anchor) =>
        anchor.sequence > initial.anchors.at(-1).sequence &&
        anchor.collectedAtMs > initial.anchors.at(-1).collectedAtMs,
    )
  ) {
    errors.push("Host Re-enrollment Metrics history is invalid");
  }
}

function validMetricsHistory(value) {
  return (
    sameKeySet(value ?? {}, { anchors: null, sha256: null }) &&
    Array.isArray(value?.anchors) &&
    value.anchors.length >= 2 &&
    value.anchors.every(validMetricAnchor) &&
    value.anchors.every(
      (anchor, index) =>
        index === 0 ||
        (anchor.sequence > value.anchors[index - 1].sequence &&
          anchor.collectedAtMs > value.anchors[index - 1].collectedAtMs),
    ) &&
    /^[0-9a-f]{64}$/.test(value?.sha256 ?? "") &&
    createHash("sha256").update(JSON.stringify(value.anchors)).digest("hex") ===
      value.sha256
  );
}

function validMetricAnchor(value) {
  return (
    sameKeySet(value ?? {}, {
      collectedAtMs: null,
      cpuPercent: null,
      memoryTotalBytes: null,
      memoryUsedBytes: null,
      sequence: null,
      uptimeSeconds: null,
    }) &&
    Number.isSafeInteger(value?.sequence) &&
    value.sequence >= 0 &&
    Number.isSafeInteger(value?.collectedAtMs) &&
    value.collectedAtMs > 0 &&
    Number.isFinite(value?.uptimeSeconds) &&
    value.uptimeSeconds >= 0 &&
    Number.isFinite(value?.cpuPercent) &&
    value.cpuPercent >= 0 &&
    value.cpuPercent <= 100 &&
    Number.isSafeInteger(value?.memoryTotalBytes) &&
    value.memoryTotalBytes > 0 &&
    Number.isSafeInteger(value?.memoryUsedBytes) &&
    value.memoryUsedBytes >= 0 &&
    value.memoryUsedBytes <= value.memoryTotalBytes
  );
}

function sameMetricAnchor(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validateHubOnlyDeletionEvidence(evidence, errors) {
  const deletion = evidence?.hubOnlyDeletion;
  const terminal = deletion?.permanentReportRejection;
  if (
    deletion?.deletedHost?.id !== evidence?.host?.id ||
    !Number.isSafeInteger(deletion?.deletedHost?.deletedAtMs) ||
    deletion.deletedHost.deletedAtMs < 0 ||
    !validPermanentReportRejection(terminal)
  ) {
    errors.push("Hub-only deletion or permanent rejection evidence is invalid");
  }
}

function validateDiagnosticsEvidence(diagnostics, errors) {
  const host = diagnostics?.host;
  const installation = host?.installation?.value;
  const inventory = host?.inventory?.value;
  if (
    host?.inventory?.available !== true ||
    typeof inventory?.accounts?.group !== "boolean" ||
    typeof inventory?.accounts?.user !== "boolean" ||
    !Array.isArray(inventory?.files) ||
    !inventory.files.includes("/usr/local/bin/enoki-probe") ||
    !inventory.files.includes("/etc/enoki/probe-install.toml") ||
    !Array.isArray(inventory?.units) ||
    !inventory.units.includes("enoki-probe.service") ||
    host?.installation?.available !== true ||
    !validTerminalDiagnosticInstallation(installation) ||
    !validAvailableDiagnosticCommand(host?.journald) ||
    !validAvailableDiagnosticCommand(host?.sudoers) ||
    !validTerminalSystemdDiagnostic(host?.systemd) ||
    !Array.isArray(diagnostics?.hub?.apiTimeline) ||
    containsUnredactedSecret(diagnostics)
  ) {
    errors.push("redacted failure diagnostics are incomplete");
  }
}

function validAvailableDiagnosticCommand(value) {
  return (
    value?.available === true &&
    validCommandEvidence(value?.output) &&
    value.output.stdout.trim().length > 0
  );
}

function validTerminalSystemdDiagnostic(value) {
  return (
    validAvailableDiagnosticCommand(value) &&
    /^LoadState=loaded$/m.test(value.output.stdout) &&
    /^ActiveState=failed$/m.test(value.output.stdout) &&
    /^ExecMainStatus=78$/m.test(value.output.stdout)
  );
}

function sameHubHostProjection(before, after) {
  return (
    Number.isSafeInteger(before?.id) &&
    before.id > 0 &&
    validHostMetadata(before?.hostMetadata) &&
    JSON.stringify(before) === JSON.stringify(after)
  );
}

function validHostMetadata(value) {
  const keys = ["connectAddress", "description", "displayName", "observedIp"];
  return (
    Object.keys(value ?? {})
      .sort()
      .join(",") === keys.sort().join(",") &&
    keys.every((key) => value[key] === null || typeof value[key] === "string")
  );
}

function sameEffectiveProbeConfiguration(current, expected) {
  return (
    current?.mode === expected?.mode &&
    JSON.stringify(canonicalSemanticValue(current?.configuration)) ===
      JSON.stringify(expected?.configuration)
  );
}

function canonicalSemanticValue(value) {
  if (Array.isArray(value)) return value.map(canonicalSemanticValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entryValue]) => [key, canonicalSemanticValue(entryValue)]),
    );
  }
  return value;
}

function validTerminalDiagnosticInstallation(value) {
  return (
    /^[0-9a-f]{64}$/.test(value?.binary?.sha256 ?? "") &&
    /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      value?.binary?.version ?? "",
    ) &&
    /^[0-9a-f]{64}$/.test(value?.installMetadataSha256 ?? "") &&
    validProbeIdentity(value?.identity) &&
    value?.service?.LoadState === "loaded" &&
    value.service?.ActiveState === "failed" &&
    value.service?.SubState === "failed" &&
    value.service?.ExecMainStatus === 78 &&
    Number.isSafeInteger(value.service?.NRestarts) &&
    value.service.NRestarts >= 0 &&
    typeof value.service?.Result === "string" &&
    value.service.Result.length > 0
  );
}

function validCommandEvidence(value) {
  return (
    Number.isSafeInteger(value?.code) &&
    typeof value?.stdout === "string" &&
    typeof value?.stderr === "string"
  );
}

function validateFreshLifecycleAuditLog(evidence, errors) {
  const auditLog = evidence?.auditLog;
  const hostId = evidence?.host?.id;
  const validEvent = (event) =>
    Number.isSafeInteger(event?.id) &&
    event.id > 0 &&
    Number.isSafeInteger(event?.occurredAtMs) &&
    event.occurredAtMs > 0 &&
    typeof event?.subjectId === "string" &&
    event.subjectId.length > 0 &&
    typeof event?.subjectType === "string" &&
    event.subjectType.length > 0 &&
    event.outcome === "success";
  const find = (predicate) =>
    Array.isArray(auditLog) && auditLog.find(predicate);
  if (
    !find(
      (event) =>
        event?.action === "enrollment_token.create" &&
        validEvent(event) &&
        event.actor === "owner" &&
        event.details?.target?.kind === "new_host",
    ) ||
    !find(
      (event) =>
        event?.action === "enrollment.installation_rejected" &&
        validEvent(event) &&
        event.actor === "system" &&
        event.details?.code === "existing_probe_installation",
    ) ||
    !find(
      (event) =>
        event?.action === "enrollment_token.create" &&
        validEvent(event) &&
        event.actor === "owner" &&
        event.details?.target?.kind === "existing_host" &&
        event.details.target.hostId === hostId,
    ) ||
    !find(
      (event) =>
        event?.action === "probe_configuration.host.override" &&
        validEvent(event) &&
        event.actor === "owner" &&
        event.subjectId === String(hostId),
    ) ||
    !find(
      (event) =>
        event?.action === "host.delete" &&
        validEvent(event) &&
        event.actor === "owner" &&
        event.subjectId === String(hostId) &&
        event.subjectType === "host" &&
        event.details?.hostId === hostId &&
        event.details?.mode === "hub-only",
    )
  ) {
    errors.push("fresh lifecycle Audit Log is invalid");
  }
}

function validProbeIdentity(identity) {
  return (
    typeof identity?.probeId === "string" &&
    identity.probeId.length > 0 &&
    /^[0-9a-f]{64}$/.test(identity?.identitySha256 ?? "")
  );
}

function validInstalledState(state) {
  return (
    /^[0-9a-f]{64}$/.test(state?.binarySha256 ?? "") &&
    /^[0-9a-f]{64}$/.test(state?.installMetadataSha256 ?? "") &&
    validProbeIdentity(state?.identity) &&
    Number.isSafeInteger(state?.restartCount) &&
    state.restartCount >= 0 &&
    state.service?.LoadState === "loaded" &&
    state.service?.ActiveState === "active" &&
    state.service?.SubState === "running"
  );
}

function validInstalledBoundary(boundary, version) {
  const errors = [];
  validateInstalledHostBoundary(boundary, version, errors);
  return errors.length === 0;
}

function validPermanentReportRejection(value) {
  return (
    /^[0-9a-f]{64}$/.test(value?.binarySha256 ?? "") &&
    /^[0-9a-f]{64}$/.test(value?.installMetadataSha256 ?? "") &&
    validProbeIdentity(value?.identity) &&
    Number.isSafeInteger(value?.restartCountBeforeObservation) &&
    value.restartCountBeforeObservation >= 0 &&
    value.restartCountAfterObservation ===
      value.restartCountBeforeObservation &&
    value.service?.LoadState === "loaded" &&
    value.service?.ActiveState === "failed" &&
    value.service?.SubState === "failed" &&
    value.service?.ExecMainStatus === 78
  );
}

function containsUnredactedSecret(value) {
  if (typeof value === "string") {
    return (
      /enk_enroll_[A-Za-z0-9_-]+/.test(value) ||
      /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----/.test(value) ||
      /ENOKI_ENROLLMENT_TOKEN\s*=/.test(value)
    );
  }
  if (Array.isArray(value)) return value.some(containsUnredactedSecret);
  if (value && typeof value === "object") {
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

function validateBaselineEvidence(evidence, errors, candidateManifest) {
  const version = candidateProbeVersion(evidence);
  const migration =
    evidence?.releaseBaseline?.kind === "enoki-trust-epoch-migration-baseline";
  validateHostInstallResult(
    evidence?.baselineInstall,
    "Release Baseline Probe installer",
    errors,
    {
      activeHub: "baseline",
      allowLegacyMigration: true,
      candidateManifest,
      expectedRunId: evidence?.runId,
    },
  );
  if (migration) {
    if (
      evidence?.upgradeOperationTimeline?.length !== 0 ||
      evidence?.manualRecovery?.kind !== "trust_epoch_manual_reinstall" ||
      evidence.manualRecovery.hostId !== evidence?.candidateHost?.id ||
      typeof evidence.manualRecovery.enrollmentId !== "string" ||
      !evidence.manualRecovery.enrollmentId
    ) {
      errors.push("Trust Epoch manual reinstall evidence is invalid");
    }
    validateHostInstallResult(
      evidence?.manualRecovery?.result,
      "Trust Epoch manual reinstall",
      errors,
      {
        activeHub: "candidate",
        candidateManifest,
        expectedRunId: evidence?.runId,
      },
    );
  } else {
    if (
      evidence?.manualRecovery !== null &&
      evidence?.manualRecovery !== undefined
    ) {
      errors.push("Compatible Upgrade must not use manual recovery");
    }
    validateTerminalOperation(
      evidence?.upgradeOperationTimeline,
      "probe_upgrade",
      "succeeded",
      "baseline Upgrade",
      errors,
    );
  }
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
  if (migration) {
    validateIdentityReplacement(
      evidence?.identityContinuity,
      evidence?.candidateHost?.id,
      errors,
    );
    validateMigrationRetention(evidence?.migrationRetention, errors, {
      afterMetrics: evidence?.metrics?.afterUpgrade,
      expectedCandidateHost: evidence?.candidateHost,
      expectedConfiguration: evidence?.probeConfiguration?.beforeUpgrade,
      expectedIdentityHostId: evidence?.identityContinuity?.hostId,
    });
  } else {
    validateIdentityContinuity(
      evidence?.identityContinuity,
      evidence?.candidateHost?.id,
      errors,
    );
  }
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
  validateLifecycleAuditLog(evidence, !migration, errors);
  if (migration) validateManualReinstallAuditLog(evidence, errors);
  validateInstalledHostBoundary(evidence?.hostBoundary, version, errors);
}

function validateRepairEvidence(evidence, errors, candidateManifest) {
  const version = candidateProbeVersion(evidence);
  validateHostInstallResult(
    evidence?.baselineInstall,
    "Repair Release Baseline Probe installer",
    errors,
    {
      activeHub: "baseline",
      candidateManifest,
      expectedRunId: evidence?.runId,
    },
  );
  if (
    evidence?.releaseBaseline?.kind === "enoki-trust-epoch-migration-baseline"
  ) {
    errors.push(
      "Trust Epoch migration Repair has no production-authorized eligibility sequence",
    );
    return;
  }
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
    !sameKeySet(configuration ?? {}, {
      configuration: null,
      mode: null,
      reportedVersion: null,
      version: null,
    }) ||
    !validEffectiveProbeConfiguration({
      configuration: configuration?.configuration,
      mode: configuration?.mode,
    }) ||
    configuration?.mode !== "override" ||
    !configuration?.configuration ||
    !Array.isArray(configuration.configuration.enabledCollectorIds) ||
    !Number.isSafeInteger(
      configuration.configuration.metricsCollectionIntervalSeconds,
    ) ||
    configuration.configuration.version !== configuration?.version ||
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
    !sameKeySet(boundary ?? {}, {
      delegationGeneration: null,
      inventory: null,
      probeVersion: null,
      service: null,
      sudoers: null,
    }) ||
    !sameKeySet(inventory ?? {}, {
      accounts: null,
      files: null,
      units: null,
    }) ||
    !sameKeySet(inventory?.accounts ?? {}, { group: null, user: null }) ||
    !sameKeySet(boundary?.service ?? {}, {
      ActiveState: null,
      FragmentPath: null,
      Group: null,
      LoadState: null,
      SubState: null,
      User: null,
    }) ||
    boundary?.probeVersion !== version ||
    inventory?.accounts?.user !== true ||
    inventory?.accounts?.group !== true ||
    !Array.isArray(files) ||
    !files.includes("/usr/local/bin/enoki-probe") ||
    !files.includes("/etc/systemd/system/enoki-probe.service") ||
    files.some((file) => file.startsWith("/etc/sudoers.d/enoki-probe")) ||
    !Array.isArray(inventory?.units) ||
    !inventory.units.includes("enoki-probe.service") ||
    boundary?.service?.LoadState !== "loaded" ||
    boundary?.service?.ActiveState !== "active" ||
    boundary?.service?.SubState !== "running" ||
    boundary?.service?.User !== "enoki-probe" ||
    boundary?.service?.Group !== "enoki-probe" ||
    boundary?.service?.FragmentPath !==
      "/etc/systemd/system/enoki-probe.service" ||
    boundary?.sudoers !== "" ||
    !Number.isSafeInteger(boundary?.delegationGeneration) ||
    boundary.delegationGeneration < 1
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

function validateIdentityReplacement(identity, hostId, errors) {
  const before = identity?.before;
  const after = identity?.after;
  if (
    !Number.isSafeInteger(identity?.hostId) ||
    identity.hostId !== hostId ||
    !validProbeIdentity(before) ||
    !validProbeIdentity(after) ||
    after.probeId === before.probeId ||
    after.identitySha256 === before.identitySha256
  ) {
    errors.push("Probe Identity replacement is invalid");
  }
}

function validateMigrationRetention(
  retention,
  errors,
  {
    afterMetrics,
    expectedCandidateHost,
    expectedConfiguration,
    expectedIdentityHostId,
  } = {},
) {
  const metricHistory = retention?.metricHistory;
  const postMetricHistory = retention?.postMetricHistory;
  const expectedEffectiveConfiguration = {
    configuration: expectedConfiguration?.configuration,
    mode: expectedConfiguration?.mode,
  };
  const latestBeforeAnchor = metricHistory?.anchors?.at(-1);
  if (
    !sameKeySet(retention ?? {}, {
      configuration: null,
      hostAfter: null,
      hostBefore: null,
      metricHistory: null,
      postMetricHistory: null,
    }) ||
    !validRetainedHostProjection(retention?.hostBefore) ||
    !validRetainedHostProjection(retention?.hostAfter) ||
    !Number.isSafeInteger(retention?.hostBefore?.id) ||
    retention.hostBefore.id !== retention?.hostAfter?.id ||
    retention.hostBefore.id !== expectedCandidateHost?.id ||
    retention.hostBefore.id !== expectedIdentityHostId ||
    JSON.stringify(retention.hostAfter.hostProfile) !==
      JSON.stringify(
        canonicalSemanticValue(expectedCandidateHost?.hostProfile),
      ) ||
    !validHostMetadata(retention?.hostBefore?.hostMetadata) ||
    JSON.stringify(retention.hostBefore.hostMetadata) !==
      JSON.stringify(retention?.hostAfter?.hostMetadata) ||
    retention.hostBefore.reportedProbeConfigurationVersion !==
      expectedConfiguration?.reportedVersion ||
    retention.hostAfter.reportedProbeConfigurationVersion !==
      expectedConfiguration?.reportedVersion ||
    retention.hostBefore.reportedProbeConfigurationVersion !==
      expectedConfiguration?.version ||
    retention.hostAfter.reportedProbeConfigurationVersion !==
      expectedConfiguration?.version ||
    !validEffectiveProbeConfiguration(retention?.configuration) ||
    JSON.stringify(retention?.configuration) !==
      JSON.stringify(expectedEffectiveConfiguration) ||
    !validMetricsHistory(metricHistory) ||
    metricHistory?.anchors?.length > 3 ||
    !validMetricsHistory(postMetricHistory) ||
    postMetricHistory?.anchors?.length > metricHistory?.anchors?.length + 3 ||
    (afterMetrics ?? []).length !== 2 ||
    !metricHistory?.anchors?.every((anchor) =>
      postMetricHistory?.anchors?.some((sample) =>
        sameMetricAnchor(anchor, sample),
      ),
    ) ||
    !(afterMetrics ?? []).every((sample) =>
      postMetricHistory?.anchors?.some((anchor) =>
        sameMetricAnchor(anchor, sample),
      ),
    ) ||
    !postMetricHistory?.anchors?.some(
      (anchor) =>
        anchor.sequence > latestBeforeAnchor?.sequence &&
        anchor.collectedAtMs > latestBeforeAnchor?.collectedAtMs,
    )
  ) {
    errors.push(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
  }
}

function validEffectiveProbeConfiguration(value) {
  const configuration = value?.configuration;
  return (
    sameKeySet(value ?? {}, { configuration: null, mode: null }) &&
    value.mode === "override" &&
    sameKeySet(configuration ?? {}, {
      enabledCollectorIds: null,
      metricsCollectionIntervalSeconds: null,
      version: null,
    }) &&
    Array.isArray(configuration.enabledCollectorIds) &&
    configuration.enabledCollectorIds.every(
      (collectorId) => typeof collectorId === "string",
    ) &&
    Number.isSafeInteger(configuration.metricsCollectionIntervalSeconds) &&
    typeof configuration.version === "string" &&
    configuration.version.length > 0
  );
}

function validRetainedHostProjection(value) {
  return (
    sameKeySet(value ?? {}, {
      hostMetadata: null,
      hostProfile: null,
      id: null,
      reportedProbeConfigurationVersion: null,
    }) &&
    value.hostProfile !== null &&
    typeof value.hostProfile === "object" &&
    !Array.isArray(value.hostProfile)
  );
}

function validateManualReinstallAuditLog(evidence, errors) {
  const identity = evidence?.identityContinuity;
  const hostId = evidence?.candidateHost?.id;
  const event = Array.isArray(evidence?.auditLog)
    ? evidence.auditLog.find(
        (entry) => entry?.action === "probe.manual_reinstall_identity_replaced",
      )
    : null;
  if (
    event?.actor !== "system" ||
    event?.outcome !== "success" ||
    event?.subjectId !== String(hostId) ||
    event?.subjectType !== "host" ||
    event?.details?.oldProbeId !== identity?.before?.probeId ||
    event?.details?.newProbeId !== identity?.after?.probeId ||
    !Array.isArray(event?.details?.sourceProbeSha256) ||
    event.details.sourceProbeSha256.length < 1 ||
    !/^sha256:[0-9a-f]{64}$/.test(event?.details?.targetAssetSetDigest ?? "") ||
    event?.details?.targetProbeVersion !== candidateProbeVersion(evidence)
  ) {
    errors.push("manual reinstall identity replacement Audit Log is invalid");
  }
}

function candidateProbeVersion(evidence) {
  const version = evidence?.candidate?.version;
  return typeof version === "string" && version.startsWith("v")
    ? version.slice(1)
    : null;
}

function validateReleaseBaselineEvidence(evidence, baseline, errors) {
  if (!isReleaseBaselineDescriptor(baseline)) {
    errors.push("Candidate Release Baseline identity is unavailable");
    return;
  }
  const migration = baseline.kind === "enoki-trust-epoch-migration-baseline";
  const expected = {
    authority: migration
      ? {
          authorizationSha256: baseline.authorization?.sha256,
          githubReleaseId: baseline.githubRelease.id,
          legacyReleaseSha256: baseline.authorization?.legacyReleaseSha256,
          peeledCommitSha: baseline.githubRelease.peeledCommitSha,
        }
      : {
          githubReleaseId: baseline.githubRelease.id,
          peeledCommitSha: baseline.githubRelease.peeledCommitSha,
          signingPublicKeySha256:
            baseline.probeAssetSet?.signingIdentity?.publicKeySha256,
          trustRootPublicKeySha256:
            baseline.probeAssetSet?.trustRoot?.publicKeySha256,
        },
    descriptorSha256: createHash("sha256")
      .update(JSON.stringify(baseline))
      .digest("hex"),
    hubDigest: baseline.hub.imageDigest,
    kind: baseline.kind,
    probeVersion: migration
      ? baseline.tag.slice(1)
      : baseline.probeAssetSet?.version,
    tag: baseline.tag,
  };
  if (JSON.stringify(evidence) !== JSON.stringify(expected)) {
    errors.push("Release Baseline evidence is not bound to the Candidate");
  }
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

function validateRestoreEvidence(evidence, errors, candidateManifest) {
  const version = candidateProbeVersion(evidence);
  const migration =
    evidence?.releaseBaseline?.kind === "enoki-trust-epoch-migration-baseline";
  if (migration) {
    errors.push(
      "Trust Epoch migration Hub Restore has no production-compatible Candidate Probe identity sequence",
    );
    return;
  }
  validateHostInstallResult(
    evidence?.baselineInstall,
    "Restore Release Baseline Probe installer",
    errors,
    {
      activeHub: "baseline",
      candidateManifest,
      expectedRunId: evidence?.runId,
    },
  );
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
  const reportingVersion = version;
  if (
    !isCandidateHostReady(candidateReporting?.host, reportingVersion) ||
    !isCandidateHostReady(restoredReporting?.host, reportingVersion)
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
  const identities = [identity?.beforeUpgrade, identity?.afterRestore];
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
    ) ||
    identity?.afterUpgrade?.probeId !== identities[0]?.probeId ||
    identity?.afterUpgrade?.identitySha256 !== identities[0]?.identitySha256
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
  scenarioPlan,
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
  const expectedCells = validateScenarioPlan(scenarioPlan);
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
      releaseBaselineKind: gate?.releaseBaselineKind ?? null,
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
    expectedCells.length > 0 &&
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
        gatesByCell.get(gate.cellId)?.scenarioId === gate.scenarioId &&
        gatesByCell.get(gate.cellId)?.releaseBaselineKind ===
          candidateManifest?.releaseBaseline?.kind,
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
    bootstrapRecipe: candidateManifest?.bootstrapRecipe ?? null,
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
  // 候选目录已由 validateReleaseCandidate 完成内容闭包验证；此处重验其
  // schema 4 描述符，避免汇总器把残缺的已解析值当作可验证的候选。
  return (
    isPlainObject(candidateManifest) &&
    candidateManifest?.kind === "enoki-release-candidate" &&
    candidateManifest?.schemaVersion === 4 &&
    sameKeySet(candidateManifest, {
      bootstrapRecipe: null,
      candidate: null,
      hub: null,
      kind: null,
      probeAssetSet: null,
      releaseBaseline: null,
      schemaVersion: null,
    }) &&
    isCandidateIdentity(candidateManifest.candidate) &&
    isCandidateBootstrapRecipe(
      candidateManifest.bootstrapRecipe,
      candidateManifest.candidate,
    ) &&
    isCandidateHub(candidateManifest.hub, candidateManifest.candidate) &&
    isCandidateProbeAssetSet(
      candidateManifest.probeAssetSet,
      candidateManifest.candidate,
    ) &&
    isReleaseBaselineDescriptor(candidateManifest.releaseBaseline)
  );
}

function isCandidateBootstrapRecipe(recipe, candidate) {
  return (
    isPlainObject(recipe) &&
    sameKeySet(recipe, {
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
    recipe.bundleVersion === candidate.version.slice(1) &&
    recipe.distribution === "enoki" &&
    recipe.file === "enoki-probe-bootstrap.py" &&
    recipe.kind === "enoki-probe-bootstrap-recipe-record" &&
    recipe.recordFile === "enoki-probe-bootstrap-recipe.json" &&
    /^[0-9a-f]{64}$/.test(recipe.recordSha256 ?? "") &&
    Number.isSafeInteger(recipe.recordSize) &&
    recipe.recordSize > 0 &&
    recipe.schemaVersion === 1 &&
    Array.isArray(recipe.targets) &&
    recipe.targets.length === 4 &&
    recipe.version === "v1" &&
    /^[0-9a-f]{64}$/.test(recipe.rootFingerprint ?? "") &&
    /^[0-9a-f]{64}$/.test(recipe.sha256 ?? "") &&
    Number.isSafeInteger(recipe.size) &&
    recipe.size > 0
  );
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isCandidateIdentity(candidate) {
  return (
    isPlainObject(candidate) &&
    sameKeySet(candidate, { commit: null, version: null }) &&
    /^[0-9a-f]{40}$/.test(candidate.commit ?? "") &&
    /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(
      candidate.version ?? "",
    )
  );
}

function isCandidateHub(hub, candidate) {
  return (
    isPlainObject(hub) &&
    sameKeySet(hub, {
      archive: null,
      archiveSha256: null,
      digest: null,
      embeddedProbeVersion: null,
      size: null,
    }) &&
    hub.archive === `hub/enoki-hub-${candidate.version}.oci.tar` &&
    /^[0-9a-f]{64}$/.test(hub.archiveSha256 ?? "") &&
    /^sha256:[0-9a-f]{64}$/.test(hub.digest ?? "") &&
    hub.embeddedProbeVersion === candidate.version.slice(1) &&
    Number.isSafeInteger(hub.size) &&
    hub.size > 0
  );
}

function isCandidateProbeAssetSet(probeAssetSet, candidate) {
  return (
    isPlainObject(probeAssetSet) &&
    sameKeySet(probeAssetSet, {
      directory: null,
      files: null,
      signingIdentity: null,
      version: null,
    }) &&
    probeAssetSet.directory === "probe-assets" &&
    probeAssetSet.version === candidate.version.slice(1) &&
    Array.isArray(probeAssetSet.files) &&
    probeAssetSet.files.length > 0 &&
    probeAssetSet.files.every(
      (file) =>
        isPlainObject(file) &&
        typeof file.file === "string" &&
        file.file.length > 0 &&
        /^[0-9a-f]{64}$/.test(file.sha256 ?? "") &&
        Number.isSafeInteger(file.size) &&
        file.size > 0,
    ) &&
    isPlainObject(probeAssetSet.signingIdentity) &&
    sameKeySet(probeAssetSet.signingIdentity, {
      algorithm: null,
      publicKeyFile: null,
      publicKeySha256: null,
    }) &&
    probeAssetSet.signingIdentity.algorithm === "rsa-sha256" &&
    probeAssetSet.signingIdentity.publicKeyFile === "signing-key.pem" &&
    /^[0-9a-f]{64}$/.test(probeAssetSet.signingIdentity.publicKeySha256 ?? "")
  );
}

function isReleaseBaselineDescriptor(releaseBaseline) {
  const githubRelease = releaseBaseline?.githubRelease;
  return (
    isPlainObject(releaseBaseline) &&
    ["enoki-release-baseline", "enoki-trust-epoch-migration-baseline"].includes(
      releaseBaseline.kind,
    ) &&
    typeof releaseBaseline.tag === "string" &&
    /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(
      releaseBaseline.tag,
    ) &&
    isPlainObject(githubRelease) &&
    Number.isSafeInteger(githubRelease.id) &&
    githubRelease.id > 0 &&
    /^[0-9a-f]{40}$/.test(githubRelease.peeledCommitSha ?? "") &&
    /^[0-9a-f]{40}$/.test(githubRelease.tagRefSha ?? "") &&
    isPlainObject(releaseBaseline.hub) &&
    /^sha256:[0-9a-f]{64}$/.test(releaseBaseline.hub.imageDigest ?? "")
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

function validateScenarioPlan(plan) {
  if (plan === null || plan === undefined) return [];
  if (
    plan?.kind !== "enoki-release-scenario-plan" ||
    plan.schemaVersion !== 1 ||
    !Array.isArray(plan.cells) ||
    plan.cells.length === 0 ||
    plan.cells.some(
      (cell) =>
        typeof cell?.cellId !== "string" ||
        typeof cell.environmentId !== "string" ||
        typeof cell.runner !== "string" ||
        typeof cell.scenarioId !== "string",
    ) ||
    new Set(plan.cells.map((cell) => cell.cellId)).size !== plan.cells.length
  ) {
    throw new Error("compiled Release Scenario Plan is invalid");
  }
  return plan.cells;
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
