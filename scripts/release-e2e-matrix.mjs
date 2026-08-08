import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { releaseE2EScenarioRegistry } from "./release-e2e-lib.mjs";

const supportedScenarioIds = new Set(Object.keys(releaseE2EScenarioRegistry));

export function validateReleaseE2EMatrix(matrix) {
  assertPlainObject(matrix, "Release E2E matrix");
  assertExactKeys(matrix, [
    "environments",
    "providers",
    "scenarios",
    "schemaVersion",
  ]);
  if (matrix?.schemaVersion !== 1) {
    throw new Error("Release E2E matrix schemaVersion must be 1");
  }
  if (!Array.isArray(matrix.environments) || matrix.environments.length === 0) {
    throw new Error("Release E2E matrix must declare environments");
  }
  if (!Array.isArray(matrix.scenarios) || matrix.scenarios.length === 0) {
    throw new Error("Release E2E matrix must declare scenarios");
  }
  if (!Array.isArray(matrix.providers) || matrix.providers.length === 0) {
    throw new Error("Release E2E matrix must declare providers");
  }
  for (const provider of matrix.providers) {
    validateProvider(provider);
  }
  for (const environment of matrix.environments) {
    validateEnvironmentReference(environment, matrix.providers);
  }
  for (const scenario of matrix.scenarios) {
    validateScenario(scenario, matrix.providers, matrix.environments);
  }
  assertUniqueIds(matrix.providers, "provider");
  assertUniqueIds(
    matrix.environments.map((environment) => ({
      id: resolveEnvironment(matrix.providers, environment).id,
    })),
    "environment",
  );
  assertUniqueIds(matrix.scenarios, "scenario");
  return matrix;
}

function validateProvider(provider) {
  assertPlainObject(provider, "Release E2E provider");
  assertExactKeys(provider, [
    "capabilities",
    "hostAdapter",
    "id",
    "provider",
    "systemd",
  ]);
  if (
    !isStableId(provider.id) ||
    !isStableId(provider.provider) ||
    provider.hostAdapter !== "ci" ||
    provider.systemd !== "host"
  ) {
    throw new Error(
      "Release E2E provider must use a stable provider ID, host systemd, and the CI adapter",
    );
  }
  if (
    !Array.isArray(provider.capabilities) ||
    provider.capabilities.length === 0
  ) {
    throw new Error("Release E2E provider must declare capabilities");
  }
  for (const capability of provider.capabilities) {
    validateProviderCapability(capability);
  }
  assertUniqueIds(
    provider.capabilities,
    `capability for provider ${provider.id}`,
  );
}

function validateProviderCapability(capability) {
  assertPlainObject(capability, "Release E2E provider capability");
  assertExactKeys(capability, [
    "architecture",
    "id",
    "operatingSystem",
    "operatingSystemVersion",
    "runner",
  ]);
  if (!/^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(capability.architecture ?? "")) {
    throw new Error("Release E2E provider capability architecture is invalid");
  }
  if (!isStableId(capability.operatingSystem)) {
    throw new Error(
      "Release E2E provider capability operatingSystem is invalid",
    );
  }
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(
      capability.operatingSystemVersion ?? "",
    )
  ) {
    throw new Error(
      "Release E2E provider capability operatingSystemVersion is invalid",
    );
  }
  const expectedId = `${capability.operatingSystem}-${capability.operatingSystemVersion}-${capability.architecture}`;
  if (capability.id !== expectedId) {
    throw new Error(`Release E2E provider capability id must be ${expectedId}`);
  }
  if (
    typeof capability.runner !== "string" ||
    capability.runner.trim() === ""
  ) {
    throw new Error("Release E2E provider capability runner is invalid");
  }
}

function validateEnvironmentReference(environment, providers) {
  assertPlainObject(environment, "Release E2E environment");
  assertExactKeys(environment, ["capabilityId", "providerId"]);
  if (
    !isStableId(environment.providerId) ||
    !isStableId(environment.capabilityId)
  ) {
    throw new Error(
      "Release E2E environment provider capability reference is invalid",
    );
  }
  resolveEnvironment(providers, environment);
}

function resolveEnvironment(providers, environment) {
  const provider = providers.find(
    (entry) => entry.id === environment.providerId,
  );
  const capability = provider?.capabilities?.find(
    (entry) => entry.id === environment.capabilityId,
  );
  if (!provider || !capability) {
    throw new Error(
      `Release E2E environment capability is not declared: ${environment.providerId}/${environment.capabilityId}`,
    );
  }
  return {
    ...capability,
    hostAdapter: provider.hostAdapter,
    provider: provider.provider,
    systemd: provider.systemd,
  };
}

function validateScenario(scenario, providers, environments) {
  assertPlainObject(scenario, "Release E2E scenario");
  const expectedKeys = scenario.designatedEnvironmentId
    ? ["designatedEnvironmentId", "id"]
    : ["id"];
  assertExactKeys(scenario, expectedKeys);
  if (!/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(scenario.id ?? "")) {
    throw new Error("Release E2E scenario id is invalid");
  }
  if (!supportedScenarioIds.has(scenario.id)) {
    throw new Error(`Release E2E scenario is not supported: ${scenario.id}`);
  }
  if (scenario.designatedEnvironmentId) {
    if (!isStableId(scenario.designatedEnvironmentId)) {
      throw new Error(
        "Release E2E designated environment ID must be a stable ID",
      );
    }
    const declaredEnvironmentIds = new Set(
      environments.map(
        (environment) => resolveEnvironment(providers, environment).id,
      ),
    );
    if (!declaredEnvironmentIds.has(scenario.designatedEnvironmentId)) {
      throw new Error(
        `Release E2E designated environment is not declared: ${scenario.designatedEnvironmentId}`,
      );
    }
  }
}

export function expandReleaseE2EMatrix(matrix, { scenarioId }) {
  validateReleaseE2EMatrix(matrix);
  const scenario = matrix.scenarios.find((entry) => entry.id === scenarioId);
  if (!scenario) {
    throw new Error(`Release E2E scenario is not declared: ${scenarioId}`);
  }
  const environments = scenario.designatedEnvironmentId
    ? matrix.environments.filter(
        (reference) =>
          resolveEnvironment(matrix.providers, reference).id ===
          scenario.designatedEnvironmentId,
      )
    : matrix.environments;
  return environments.map((reference) => {
    const environment = resolveEnvironment(matrix.providers, reference);
    return {
      architecture: environment.architecture,
      cellId: `${environment.id}--${scenario.id}`,
      environmentId: environment.id,
      operatingSystem: environment.operatingSystem,
      operatingSystemVersion: environment.operatingSystemVersion,
      hostAdapter: environment.hostAdapter,
      provider: environment.provider,
      runner: environment.runner,
      scenarioId: scenario.id,
    };
  });
}

export function createGitHubActionsMatrix(matrix) {
  validateReleaseE2EMatrix(matrix);
  return {
    include: matrix.scenarios.flatMap((scenario) =>
      expandReleaseE2EMatrix(matrix, { scenarioId: scenario.id }),
    ),
  };
}

export async function readReleaseE2EMatrix(matrixPath) {
  const matrix = JSON.parse(await readFile(matrixPath, "utf8"));
  return validateReleaseE2EMatrix(matrix);
}

export function resolveReleaseE2EMatrixCell(matrix, cellId) {
  validateReleaseE2EMatrix(matrix);
  for (const scenario of matrix.scenarios) {
    const cell = expandReleaseE2EMatrix(matrix, {
      scenarioId: scenario.id,
    }).find((entry) => entry.cellId === cellId);
    if (cell) return cell;
  }
  throw new Error(`Release E2E matrix cell is not declared: ${cellId}`);
}

function assertUniqueIds(entries, description) {
  const ids = new Set();
  for (const entry of entries) {
    if (ids.has(entry.id)) {
      throw new Error(`duplicate ${description} id: ${entry.id}`);
    }
    ids.add(entry.id);
  }
}

function isStableId(value) {
  return /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/.test(value ?? "");
}

function assertPlainObject(value, description) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
}

function assertExactKeys(value, expectedKeys) {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Release E2E matrix entry keys must be exactly: ${expected.join(", ")}`,
    );
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  try {
    const [command, matrixOption, matrixPath] = process.argv.slice(2);
    if (
      command !== "github-actions" ||
      matrixOption !== "--matrix" ||
      !matrixPath ||
      process.argv.length !== 5
    ) {
      throw new Error(
        "usage: release-e2e-matrix.mjs github-actions --matrix <path>",
      );
    }
    const matrix = await readReleaseE2EMatrix(matrixPath);
    process.stdout.write(
      `${JSON.stringify(createGitHubActionsMatrix(matrix))}\n`,
    );
  } catch (error) {
    process.stderr.write(`release-e2e-matrix: ${error.message}\n`);
    process.exitCode = 1;
  }
}
