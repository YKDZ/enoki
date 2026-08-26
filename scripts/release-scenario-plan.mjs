#!/usr/bin/env node

import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  releaseTransitionForValidatedCandidate,
  validateReleaseCandidate,
} from "./release-candidate-lib.mjs";
import {
  readSupportedHostMatrix,
  supportedHostEnvironments,
} from "./release-e2e-matrix.mjs";

const sharedCandidateScenario = Object.freeze({
  capabilities: Object.freeze([
    "fresh-install",
    "installed-bundle-failure-repair",
    "canonical-report-response-loss",
    "final-uninstall",
  ]),
  id: "fresh-install-uninstall",
});

const compatibleScenarios = Object.freeze([
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

const replacementScenarios = Object.freeze([
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
}) {
  const candidate = validateVerifiedCandidateIdentity(candidateManifest);
  const transition = validateVerifiedTransition(
    releaseTransition,
    candidateManifest,
  );
  const environments = supportedHostEnvironments(supportedHostMatrix);
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
  return deepFreeze({
    candidate,
    cells,
    kind: "enoki-release-scenario-plan",
    schemaVersion: 1,
    scenarios: scenarios.map((scenario) => ({
      capabilities: [...scenario.capabilities],
      id: scenario.id,
    })),
    transition,
  });
}

export async function compileVerifiedReleaseScenarioPlan({
  candidateManifestPath,
  matrixPath,
  trustedRootPublicKeyPem,
}) {
  if (!trustedRootPublicKeyPem) {
    throw new Error("Release Scenario Planner requires the trusted root");
  }
  const candidateDir = path.dirname(path.resolve(candidateManifestPath));
  const candidateManifest = await validateReleaseCandidate(candidateDir, {
    trustedRootPublicKeyPem,
  });
  const releaseTransition =
    releaseTransitionForValidatedCandidate(candidateManifest);
  if (!releaseTransition) {
    throw new Error(
      "verified Release Transition Contract is required before Host provisioning",
    );
  }
  const supportedHostMatrix = await readSupportedHostMatrix(matrixPath);
  return compileReleaseScenarioPlan({
    candidateManifest,
    releaseTransition,
    supportedHostMatrix,
  });
}

export function createGitHubActionsScenarioMatrix(plan) {
  validateCompiledPlan(plan);
  return { include: plan.cells.map((cell) => structuredClone(cell)) };
}

export function resolveReleaseScenarioPlanCell(plan, cellId) {
  validateCompiledPlan(plan);
  const cell = plan.cells.find((entry) => entry.cellId === cellId);
  if (!cell) {
    throw new Error(`Release Scenario Plan cell is not declared: ${cellId}`);
  }
  return structuredClone(cell);
}

export async function prepareReleaseScenarioCell({
  cellId,
  compilePlan = () => {
    throw new Error("Release Scenario Plan compiler is required");
  },
  initialize,
  provision,
  release,
}) {
  if (typeof provision !== "function") {
    throw new Error("Release Scenario Plan provisioning adapter is required");
  }
  const plan = await compilePlan();
  const cell = resolveReleaseScenarioPlanCell(plan, cellId);
  const prepared = await provision(cell);
  let cleanupOwnedByInitializer = false;
  try {
    const initialized = initialize
      ? await initialize({
          cell,
          plan,
          prepared,
          takeCleanupOwnership() {
            cleanupOwnedByInitializer = true;
          },
        })
      : undefined;
    return { cell, initialized, plan, prepared };
  } catch (error) {
    if (!cleanupOwnedByInitializer && typeof release === "function") {
      try {
        await release({ cell, plan, prepared });
      } catch (releaseError) {
        if (error && typeof error === "object") {
          error.releaseError = releaseError;
        }
      }
    }
    throw error;
  }
}

function validateVerifiedCandidateIdentity(manifest) {
  if (
    !manifest ||
    typeof manifest !== "object" ||
    Array.isArray(manifest) ||
    manifest.kind !== "enoki-release-candidate" ||
    manifest.schemaVersion !== 4 ||
    !/^[0-9a-f]{40}$/.test(manifest.candidate?.commit ?? "") ||
    !/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      manifest.candidate?.version ?? "",
    ) ||
    manifest.probeAssetSet?.version !== manifest.candidate.version.slice(1)
  ) {
    throw new Error("verified Candidate Manifest is invalid");
  }
  return {
    commit: manifest.candidate.commit,
    version: manifest.candidate.version,
  };
}

function validateVerifiedTransition(contract, manifest) {
  if (contract?.candidateCommit !== manifest.candidate.commit) {
    throw new Error("Release Transition Contract candidate does not match");
  }
  const classification = contract?.transition ?? contract?.classification;
  const sourceVersion =
    contract?.source?.version ??
    contract?.sourceProbeVersion ??
    contract?.source?.tag?.replace(/^v/, "");
  const targetVersion =
    contract?.target?.version ?? contract?.targetProbeVersion;
  const targetAssetSetManifestSha256 =
    contract?.target?.assetSetManifestSha256 ??
    contract?.targetAssetSetDigest?.replace(/^sha256:/, "");
  if (
    !["compatible", "replacement-required"].includes(classification) ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      sourceVersion ?? "",
    ) ||
    targetVersion !== manifest.probeAssetSet.version ||
    !/^[0-9a-f]{64}$/.test(targetAssetSetManifestSha256 ?? "")
  ) {
    throw new Error("verified Release Transition Contract is invalid");
  }
  const baselineVersion =
    manifest.releaseBaseline?.kind === "enoki-release-baseline"
      ? manifest.releaseBaseline.probeAssetSet?.version
      : manifest.releaseBaseline?.tag?.replace(/^v/, "");
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

function validateCompiledPlan(plan) {
  const scenarios =
    plan?.transition?.classification === "compatible"
      ? compatibleScenarios
      : plan?.transition?.classification === "replacement-required"
        ? replacementScenarios
        : null;
  if (
    plan?.kind !== "enoki-release-scenario-plan" ||
    plan.schemaVersion !== 1 ||
    !scenarios ||
    !Array.isArray(plan.cells) ||
    plan.cells.length === 0 ||
    !Array.isArray(plan.scenarios) ||
    JSON.stringify(plan.scenarios) !==
      JSON.stringify(
        scenarios.map(({ capabilities, id }) => ({ capabilities, id })),
      ) ||
    new Set(plan.cells.map(({ cellId }) => cellId)).size !==
      plan.cells.length ||
    plan.cells.some((cell) => {
      const scenario = scenarios.find(({ id }) => id === cell?.scenarioId);
      return (
        !scenario ||
        cell.transitionClassification !== plan.transition.classification ||
        cell.cellId !== `${cell.environmentId}--${cell.scenarioId}` ||
        JSON.stringify(cell.capabilities) !==
          JSON.stringify(scenario.capabilities)
      );
    }) ||
    scenarios.some(
      ({ id }) => !plan.cells.some(({ scenarioId }) => scenarioId === id),
    )
  ) {
    throw new Error("compiled Release Scenario Plan is invalid");
  }
  return plan;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  try {
    const options = parseOptions(process.argv.slice(2));
    const root = process.env[options.rootPublicKeyEnvironment];
    const plan = await compileVerifiedReleaseScenarioPlan({
      candidateManifestPath: options.candidateManifestPath,
      matrixPath: options.matrixPath,
      trustedRootPublicKeyPem: root,
    });
    process.stdout.write(
      `${JSON.stringify(createGitHubActionsScenarioMatrix(plan))}\n`,
    );
  } catch (error) {
    process.stderr.write(`release-scenario-plan: ${error.message}\n`);
    process.exitCode = 1;
  }
}

function parseOptions(arguments_) {
  if (arguments_[0] !== "github-actions" || arguments_.length !== 7) {
    throw new Error(
      "usage: release-scenario-plan.mjs github-actions --candidate-manifest <path> --matrix <path> --root-public-key-env <name>",
    );
  }
  const values = Object.fromEntries([
    [arguments_[1], arguments_[2]],
    [arguments_[3], arguments_[4]],
    [arguments_[5], arguments_[6]],
  ]);
  if (
    !values["--candidate-manifest"] ||
    !values["--matrix"] ||
    !/^[A-Za-z_][A-Za-z0-9_]*$/.test(values["--root-public-key-env"] ?? "")
  ) {
    throw new Error("Release Scenario Planner options are invalid");
  }
  return {
    candidateManifestPath: values["--candidate-manifest"],
    matrixPath: values["--matrix"],
    rootPublicKeyEnvironment: values["--root-public-key-env"],
  };
}
