#!/usr/bin/env node

import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  releaseTransitionForValidatedCandidate,
  validateReleaseCandidate,
} from "./release-candidate-verification.ts";
import { readSupportedHostMatrix } from "./release-e2e-matrix.ts";
import {
  compileReleaseScenarioPlan,
  createGitHubActionsScenarioMatrix,
  resolveReleaseScenarioPlanCell,
} from "./release-scenario-plan-compile.ts";

export {
  compileReleaseScenarioPlan,
  createGitHubActionsScenarioMatrix,
  resolveReleaseScenarioPlanCell,
};

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
