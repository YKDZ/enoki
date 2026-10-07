// Release Scenario Plan 的纯编译闭包：场景闭包、编译与已编译计划校验。
// 需要签名候选与矩阵读取的编排入口留在 release-scenario-plan.mjs。

import {
  supportedHostEnvironments,
  type ResolvedHostEnvironment,
} from "./release-e2e-matrix.ts";
import {
  isUnknownArray,
  objectView,
  type UnknownRecord,
} from "./release-json-guards.ts";

export type ReleaseTransitionClassification =
  | "compatible"
  | "replacement-required";

export interface CandidateIdentity {
  commit: string;
  version: string;
}

export interface ScenarioDescriptor {
  capabilities: readonly string[];
  designatedEnvironmentId?: string;
  id: string;
}

export interface ScenarioPlanCell {
  architecture: string;
  capabilities: string[];
  cellId: string;
  environmentId: string;
  hostAdapter: "ci";
  operatingSystem: string;
  operatingSystemVersion: string;
  provider: string;
  runner: string;
  scenarioId: string;
  transitionClassification: ReleaseTransitionClassification;
}

export interface VerifiedReleaseTransition {
  classification: ReleaseTransitionClassification;
  sourceProbeVersion: string;
  targetAssetSetDigest: string;
  targetProbeVersion: unknown;
}

export interface ReleaseScenarioPlan {
  candidate: CandidateIdentity;
  cells: ScenarioPlanCell[];
  kind: "enoki-release-scenario-plan";
  schemaVersion: 1;
  scenarios: { capabilities: string[]; id: string }[];
  transition: VerifiedReleaseTransition;
}

const sharedCandidateScenario: ScenarioDescriptor = Object.freeze({
  capabilities: Object.freeze([
    "fresh-install",
    "installed-bundle-failure-repair",
    "canonical-report-response-loss",
    "final-uninstall",
  ]),
  id: "fresh-install-uninstall",
});

const compatibleScenarios: readonly ScenarioDescriptor[] = Object.freeze([
  Object.freeze({
    capabilities: Object.freeze([
      "baseline-forward-communication",
      "identity-preserving-upgrade",
      "final-uninstall",
    ]),
    id: "compatible-upgrade-uninstall",
  }),
  sharedCandidateScenario,
  Object.freeze({
    capabilities: Object.freeze([
      "failed-upgrade-repair",
      "identity-preserving-repair",
      "final-uninstall",
    ]),
    id: "post-replacement-repair-uninstall",
  }),
  Object.freeze({
    capabilities: Object.freeze([
      "baseline-forward-communication",
      "identity-preserving-upgrade",
      "hub-restore-compatible-identity",
    ]),
    designatedEnvironmentId: "ubuntu-24.04-x86_64",
    id: "hub-restore-compatibility-window",
  }),
]);

const replacementScenarios: readonly ScenarioDescriptor[] = Object.freeze([
  Object.freeze({
    capabilities: Object.freeze([
      "baseline-forward-communication",
      "manual-reinstall",
      "host-history-preservation",
      "probe-identity-replacement",
      "old-installation-no-residue",
      "new-identity-readiness",
      "final-uninstall",
    ]),
    id: "replacement-migration-uninstall",
  }),
  sharedCandidateScenario,
]);

export function compileReleaseScenarioPlan({
  candidateManifest,
  releaseTransition,
  supportedHostMatrix,
}: {
  candidateManifest?: unknown;
  releaseTransition?: unknown;
  supportedHostMatrix?: unknown;
}): ReleaseScenarioPlan {
  const candidate = validateVerifiedCandidateIdentity(candidateManifest);
  const transition = validateVerifiedTransition(
    releaseTransition,
    objectView(candidateManifest),
  );
  const environments: ResolvedHostEnvironment[] =
    supportedHostEnvironments(supportedHostMatrix);
  const scenarios =
    transition.classification === "compatible"
      ? compatibleScenarios
      : replacementScenarios;
  const cells = scenarios.flatMap((scenario) =>
    environments
      .filter(
        (environment) =>
          !scenario.designatedEnvironmentId ||
          environment.id === scenario.designatedEnvironmentId,
      )
      .map((environment) => ({
        architecture: environment.architecture,
        capabilities: [...scenario.capabilities],
        cellId: `${environment.id}--${scenario.id}`,
        environmentId: environment.id,
        hostAdapter: environment.hostAdapter,
        operatingSystem: environment.operatingSystem,
        operatingSystemVersion: environment.operatingSystemVersion,
        provider: environment.provider,
        runner: environment.runner,
        scenarioId: scenario.id,
        transitionClassification: transition.classification,
      })),
  );
  if (
    cells.length === 0 ||
    cells.length !== new Set(cells.map(({ cellId }) => cellId)).size
  ) {
    throw new Error("Release Scenario Plan cells are incomplete or duplicated");
  }
  if (
    scenarios.some(
      ({ designatedEnvironmentId }) =>
        designatedEnvironmentId &&
        !environments.some(({ id }) => id === designatedEnvironmentId),
    )
  ) {
    throw new Error("Release Scenario Plan designated Host is unsupported");
  }
  const plan: ReleaseScenarioPlan = {
    candidate,
    cells,
    kind: "enoki-release-scenario-plan",
    schemaVersion: 1,
    scenarios: scenarios.map((scenario) => ({
      capabilities: [...scenario.capabilities],
      id: scenario.id,
    })),
    transition,
  };
  deepFreezeValue(plan);
  return plan;
}

export function createGitHubActionsScenarioMatrix(plan: unknown): {
  include: ScenarioPlanCell[];
} {
  assertCompiledPlan(plan);
  return { include: plan.cells.map((cell) => structuredClone(cell)) };
}

export function resolveReleaseScenarioPlanCell(
  plan: unknown,
  cellId: string,
): ScenarioPlanCell {
  assertCompiledPlan(plan);
  const cell = plan.cells.find((entry) => entry.cellId === cellId);
  if (!cell) {
    throw new Error(`Release Scenario Plan cell is not declared: ${cellId}`);
  }
  return structuredClone(cell);
}

function validateVerifiedCandidateIdentity(
  manifest: unknown,
): CandidateIdentity {
  const manifestView = objectView(manifest);
  const candidateView = objectView(manifestView.candidate);
  const commit = candidateView.commit;
  const version = candidateView.version;
  if (
    manifestView.kind !== "enoki-release-candidate" ||
    manifestView.schemaVersion !== 4 ||
    typeof commit !== "string" ||
    !/^[0-9a-f]{40}$/.test(commit) ||
    typeof version !== "string" ||
    !/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(version) ||
    objectView(manifestView.probeAssetSet).version !== version.slice(1)
  ) {
    throw new Error("verified Candidate Manifest is invalid");
  }
  return { commit, version };
}

function validateVerifiedTransition(
  contract: unknown,
  manifest: UnknownRecord,
): VerifiedReleaseTransition {
  const contractView = objectView(contract);
  const candidateView = objectView(manifest.candidate);
  if (contractView.candidateCommit !== candidateView.commit) {
    throw new Error("Release Transition Contract candidate does not match");
  }
  const classification = contractView.transition ?? contractView.classification;
  const sourceView = objectView(contractView.source);
  const sourceVersion =
    sourceView.version ??
    contractView.sourceProbeVersion ??
    stripPrefix(sourceView.tag, /^v/);
  const targetView = objectView(contractView.target);
  const targetVersion = targetView.version ?? contractView.targetProbeVersion;
  const targetAssetSetManifestSha256 =
    targetView.assetSetManifestSha256 ??
    stripPrefix(contractView.targetAssetSetDigest, /^sha256:/);
  if (
    !isReleaseTransitionClassification(classification) ||
    typeof sourceVersion !== "string" ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(sourceVersion) ||
    targetVersion !== objectView(manifest.probeAssetSet).version ||
    typeof targetAssetSetManifestSha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(targetAssetSetManifestSha256)
  ) {
    throw new Error("verified Release Transition Contract is invalid");
  }
  const baselineView = objectView(manifest.releaseBaseline);
  const baselineVersion =
    baselineView.kind === "enoki-release-baseline"
      ? objectView(baselineView.probeAssetSet).version
      : stripPrefix(baselineView.tag, /^v/);
  if (sourceVersion !== baselineVersion) {
    throw new Error("Release Transition Contract candidate does not match");
  }
  return {
    classification,
    sourceProbeVersion: sourceVersion,
    targetAssetSetDigest: `sha256:${targetAssetSetManifestSha256}`,
    targetProbeVersion: targetVersion,
  };
}

function assertCompiledPlan(
  plan: unknown,
): asserts plan is ReleaseScenarioPlan {
  const planView = objectView(plan);
  const classification = objectView(planView.transition).classification;
  const scenarios =
    classification === "compatible"
      ? compatibleScenarios
      : classification === "replacement-required"
        ? replacementScenarios
        : null;
  const cells = isUnknownArray(planView.cells) ? planView.cells : null;
  const cellViews = cells?.map((cell) => objectView(cell)) ?? [];
  if (
    planView.kind !== "enoki-release-scenario-plan" ||
    planView.schemaVersion !== 1 ||
    !scenarios ||
    !cells ||
    cells.length === 0 ||
    !isUnknownArray(planView.scenarios) ||
    JSON.stringify(planView.scenarios) !==
      JSON.stringify(
        scenarios.map(({ capabilities, id }) => ({ capabilities, id })),
      ) ||
    new Set(cellViews.map(({ cellId }) => cellId)).size !== cells.length ||
    cellViews.some((cell) => {
      const scenario = scenarios.find(({ id }) => id === cell.scenarioId);
      return (
        !scenario ||
        cell.transitionClassification !== classification ||
        cell.cellId !== `${cell.environmentId}--${cell.scenarioId}` ||
        JSON.stringify(cell.capabilities) !==
          JSON.stringify(scenario.capabilities)
      );
    }) ||
    scenarios.some(
      ({ id }) => !cellViews.some(({ scenarioId }) => scenarioId === id),
    )
  ) {
    throw new Error("compiled Release Scenario Plan is invalid");
  }
}

function isReleaseTransitionClassification(
  value: unknown,
): value is ReleaseTransitionClassification {
  return value === "compatible" || value === "replacement-required";
}

function stripPrefix(value: unknown, prefix: RegExp): string | undefined {
  return typeof value === "string" ? value.replace(prefix, "") : undefined;
}

function deepFreezeValue(value: unknown): void {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreezeValue(child);
  }
}
