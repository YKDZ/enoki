import { readFile } from "node:fs/promises";

export function validateSupportedHostMatrix(matrix) {
  assertPlainObject(matrix, "supported Host matrix");
  assertExactKeys(matrix, ["environments", "providers", "schemaVersion"]);
  if (matrix.schemaVersion !== 2) {
    throw new Error("supported Host matrix schemaVersion must be 2");
  }
  if (!Array.isArray(matrix.environments) || matrix.environments.length === 0) {
    throw new Error("supported Host matrix must declare environments");
  }
  if (!Array.isArray(matrix.providers) || matrix.providers.length === 0) {
    throw new Error("supported Host matrix must declare providers");
  }
  for (const provider of matrix.providers) validateProvider(provider);
  for (const environment of matrix.environments) {
    validateEnvironmentReference(environment, matrix.providers);
  }
  assertUniqueIds(matrix.providers, "provider");
  assertUniqueIds(
    matrix.environments.map((environment) => ({
      id: resolveEnvironment(matrix.providers, environment).id,
    })),
    "environment",
  );
  return matrix;
}

// 过渡期保留面向发布流程的名称：这份数据已不再包含场景。
export const validateReleaseE2EMatrix = validateSupportedHostMatrix;

function validateProvider(provider) {
  assertPlainObject(provider, "supported Host provider");
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
      "supported Host provider must use a stable provider ID, host systemd, and the CI adapter",
    );
  }
  if (
    !Array.isArray(provider.capabilities) ||
    provider.capabilities.length === 0
  ) {
    throw new Error("supported Host provider must declare capabilities");
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
  assertPlainObject(capability, "supported Host provider capability");
  assertExactKeys(capability, [
    "architecture",
    "id",
    "operatingSystem",
    "operatingSystemVersion",
    "runner",
  ]);
  if (!/^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(capability.architecture ?? "")) {
    throw new Error("supported Host capability architecture is invalid");
  }
  if (!isStableId(capability.operatingSystem)) {
    throw new Error("supported Host capability operatingSystem is invalid");
  }
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(
      capability.operatingSystemVersion ?? "",
    )
  ) {
    throw new Error(
      "supported Host capability operatingSystemVersion is invalid",
    );
  }
  const expectedId = `${capability.operatingSystem}-${capability.operatingSystemVersion}-${capability.architecture}`;
  if (capability.id !== expectedId) {
    throw new Error(`supported Host capability id must be ${expectedId}`);
  }
  if (
    typeof capability.runner !== "string" ||
    capability.runner.trim() === ""
  ) {
    throw new Error("supported Host capability runner is invalid");
  }
}

function validateEnvironmentReference(environment, providers) {
  assertPlainObject(environment, "supported Host environment");
  assertExactKeys(environment, ["capabilityId", "providerId"]);
  if (
    !isStableId(environment.providerId) ||
    !isStableId(environment.capabilityId)
  ) {
    throw new Error("supported Host environment reference is invalid");
  }
  resolveEnvironment(providers, environment);
}

export function supportedHostEnvironments(matrix) {
  validateSupportedHostMatrix(matrix);
  return matrix.environments.map((reference) =>
    resolveEnvironment(matrix.providers, reference),
  );
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
      `supported Host capability is not declared: ${environment.providerId}/${environment.capabilityId}`,
    );
  }
  return {
    ...capability,
    hostAdapter: provider.hostAdapter,
    provider: provider.provider,
    systemd: provider.systemd,
  };
}

export async function readSupportedHostMatrix(matrixPath) {
  let matrix;
  try {
    matrix = JSON.parse(await readFile(matrixPath, "utf8"));
  } catch {
    throw new Error("supported Host matrix is missing or malformed");
  }
  return validateSupportedHostMatrix(matrix);
}

export const readReleaseE2EMatrix = readSupportedHostMatrix;

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
      `supported Host matrix entry keys must be exactly: ${expected.join(", ")}`,
    );
  }
}
