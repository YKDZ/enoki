import { readFile } from "node:fs/promises";

import {
  assertPlainObject,
  type UnknownRecord,
  isUnknownArray,
} from "./release-json-guards.ts";

export interface HostProviderCapability {
  architecture: string;
  id: string;
  operatingSystem: string;
  operatingSystemVersion: string;
  runner: string;
}

export interface HostProvider {
  capabilities: HostProviderCapability[];
  hostAdapter: "ci";
  id: string;
  provider: string;
  systemd: "host";
}

export interface HostEnvironmentReference {
  capabilityId: string;
  providerId: string;
}

export interface HostEnvironmentLookup {
  capabilityId: unknown;
  providerId: unknown;
}

export interface SupportedHostMatrix {
  environments: HostEnvironmentReference[];
  providers: HostProvider[];
  schemaVersion: 2;
}

export interface ResolvedHostEnvironment extends HostProviderCapability {
  hostAdapter: "ci";
  provider: string;
  systemd: "host";
}

export function validateSupportedHostMatrix(
  matrix: unknown,
): SupportedHostMatrix {
  validateMatrix(matrix);
  return matrix;
}

// 过渡期保留面向发布流程的名称：这份数据已不再包含场景。
export const validateReleaseE2EMatrix = validateSupportedHostMatrix;

export function supportedHostEnvironments(
  matrix: unknown,
): ResolvedHostEnvironment[] {
  const validated = validateSupportedHostMatrix(matrix);
  return validated.environments.map((reference) =>
    resolveEnvironment(validated.providers, reference),
  );
}

export async function readSupportedHostMatrix(
  matrixPath: string,
): Promise<SupportedHostMatrix> {
  let matrix: unknown;
  try {
    matrix = JSON.parse(await readFile(matrixPath, "utf8"));
  } catch {
    throw new Error("supported Host matrix is missing or malformed");
  }
  return validateSupportedHostMatrix(matrix);
}

export const readReleaseE2EMatrix = readSupportedHostMatrix;

function validateMatrix(
  matrix: unknown,
): asserts matrix is SupportedHostMatrix {
  assertPlainObject(matrix, "supported Host matrix");
  assertExactKeys(matrix, ["environments", "providers", "schemaVersion"]);
  if (matrix.schemaVersion !== 2) {
    throw new Error("supported Host matrix schemaVersion must be 2");
  }
  if (
    !isUnknownArray(matrix.environments) ||
    matrix.environments.length === 0
  ) {
    throw new Error("supported Host matrix must declare environments");
  }
  if (!isUnknownArray(matrix.providers) || matrix.providers.length === 0) {
    throw new Error("supported Host matrix must declare providers");
  }
  const providers: HostProvider[] = [];
  for (const provider of matrix.providers) {
    validateProvider(provider);
    providers.push(provider);
  }
  const environments: HostEnvironmentReference[] = [];
  for (const environment of matrix.environments) {
    validateEnvironmentReference(environment, providers);
    environments.push(environment);
  }
  assertUniqueIds(providers, "provider");
  assertUniqueIds(
    environments.map((environment) => ({
      id: resolveEnvironment(providers, environment).id,
    })),
    "environment",
  );
}

function validateProvider(provider: unknown): asserts provider is HostProvider {
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
    !isUnknownArray(provider.capabilities) ||
    provider.capabilities.length === 0
  ) {
    throw new Error("supported Host provider must declare capabilities");
  }
  const capabilities: HostProviderCapability[] = [];
  for (const capability of provider.capabilities) {
    validateProviderCapability(capability);
    capabilities.push(capability);
  }
  assertUniqueIds(capabilities, `capability for provider ${provider.id}`);
}

function validateProviderCapability(
  capability: unknown,
): asserts capability is HostProviderCapability {
  assertPlainObject(capability, "supported Host provider capability");
  assertExactKeys(capability, [
    "architecture",
    "id",
    "operatingSystem",
    "operatingSystemVersion",
    "runner",
  ]);
  if (
    !/^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(String(capability.architecture ?? ""))
  ) {
    throw new Error("supported Host capability architecture is invalid");
  }
  if (!isStableId(capability.operatingSystem)) {
    throw new Error("supported Host capability operatingSystem is invalid");
  }
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(
      String(capability.operatingSystemVersion ?? ""),
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

function validateEnvironmentReference(
  environment: unknown,
  providers: readonly HostProvider[],
): asserts environment is HostEnvironmentReference {
  assertPlainObject(environment, "supported Host environment");
  assertExactKeys(environment, ["capabilityId", "providerId"]);
  if (
    !isStableId(environment.providerId) ||
    !isStableId(environment.capabilityId)
  ) {
    throw new Error("supported Host environment reference is invalid");
  }
  resolveEnvironment(providers, {
    capabilityId: environment.capabilityId,
    providerId: environment.providerId,
  });
}

function resolveEnvironment(
  providers: readonly HostProvider[],
  environment: HostEnvironmentLookup,
): ResolvedHostEnvironment {
  const provider = providers.find(
    (entry) => entry.id === environment.providerId,
  );
  const capability = provider?.capabilities.find(
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

function assertUniqueIds(
  entries: readonly { id: unknown }[],
  description: string,
): void {
  const ids = new Set<unknown>();
  for (const entry of entries) {
    if (ids.has(entry.id)) {
      throw new Error(`duplicate ${description} id: ${String(entry.id)}`);
    }
    ids.add(entry.id);
  }
}

function isStableId(value: unknown): boolean {
  return /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/.test(String(value ?? ""));
}

function assertExactKeys(
  value: UnknownRecord,
  expectedKeys: readonly string[],
): void {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `supported Host matrix entry keys must be exactly: ${expected.join(", ")}`,
    );
  }
}
