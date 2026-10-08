import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  createDockerHubController,
  loadValidatedCandidate,
} from "./release-e2e-environment.ts";

type DockerHubController = ReturnType<typeof createDockerHubController>;
type HubResources = Awaited<ReturnType<DockerHubController["start"]>>;

type CandidateUiContractOptions = {
  candidateManifestPath: string;
  containerEngine: string;
  evidenceDir?: string;
  hubPort: number;
  rootPublicKeyEnvironment: string;
};

type ValidatedCandidate = Awaited<ReturnType<typeof loadValidatedCandidate>>;

type LoadValidatedCandidate = (
  candidateManifestPath: string,
  options?: { trustedRootPublicKeyPem?: string },
) => Promise<ValidatedCandidate>;

type HubStartInput = Parameters<DockerHubController["start"]>[0];
type HubCleanupResult = { clean?: boolean; error?: string };
type HubEvidence = Record<string, unknown>;

type CandidateHubController = {
  cleanup: (input: {
    resources: HubResources | null;
    runId: string;
  }) => Promise<HubCleanupResult>;
  collectEvidence?: (input: {
    resources?: HubResources | null;
  }) => Promise<HubEvidence>;
  start: (input: HubStartInput) => Promise<HubResources>;
};

type PlaywrightRunResult = { code: number; signal: NodeJS.Signals | null };

type UiContractFailure = Error & { cleanupError?: Error };

type UiContractDependencies = {
  createHubController?: (options: {
    containerEngine: string;
  }) => CandidateHubController;
  loadCandidate?: LoadValidatedCandidate;
  ownerPassword?: string;
  runId?: string;
  runPlaywright?: (input: {
    baseUrl: string;
    candidateVersion: string;
    evidenceDir?: string;
    ownerPassword: string;
  }) => Promise<PlaywrightRunResult>;
};

type OptionDefinition = { default?: string; required?: boolean };

const optionDefinitions: Readonly<Record<string, OptionDefinition>> =
  Object.freeze({
    "--candidate-manifest": { required: true },
    "--container-engine": { default: "docker" },
    "--evidence-dir": { default: "release-ui-contract-evidence" },
    "--hub-port": { default: "38220" },
    "--root-public-key-env": { required: true },
  });

export function parseCandidateUiContractCommandLine(
  arguments_: readonly string[],
): CandidateUiContractOptions {
  if (arguments_.length % 2 !== 0) {
    throw new Error(`option ${arguments_.at(-1)} requires a value`);
  }
  const values: Record<string, string> = {};
  // 上一判据已确认参数成对出现，这里按下标偶数取值，奇数位是前一项的值。
  for (const [index, name] of arguments_.entries()) {
    if (index % 2 !== 0) continue;
    const value = arguments_[index + 1];
    if (!Object.hasOwn(optionDefinitions, name)) {
      throw new Error(`unknown option: ${name}`);
    }
    if (Object.hasOwn(values, name)) {
      throw new Error(`duplicate option: ${name}`);
    }
    if (!value) throw new Error(`${name} requires a value`);
    values[name] = value;
  }
  for (const [name, definition] of Object.entries(optionDefinitions)) {
    if (values[name] === undefined && definition.default !== undefined) {
      values[name] = definition.default;
    }
    if (definition.required && values[name] === undefined) {
      throw new Error(`${name} is required`);
    }
  }
  const candidateManifestPath = values["--candidate-manifest"] ?? "";
  const containerEngine = values["--container-engine"] ?? "";
  const evidenceDir = values["--evidence-dir"] ?? "";
  const rootPublicKeyEnvironment = values["--root-public-key-env"] ?? "";
  if (path.basename(candidateManifestPath) !== "candidate-manifest.json") {
    throw new Error("--candidate-manifest must name candidate-manifest.json");
  }
  if (containerEngine !== "docker") {
    throw new Error("--container-engine must be docker");
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(rootPublicKeyEnvironment)) {
    throw new Error("--root-public-key-env must name an environment variable");
  }
  const hubPort = Number(values["--hub-port"] ?? "");
  if (!Number.isSafeInteger(hubPort) || hubPort < 1 || hubPort > 65_535) {
    throw new Error("--hub-port must be an integer between 1 and 65535");
  }
  return {
    candidateManifestPath,
    containerEngine,
    evidenceDir: path.resolve(evidenceDir),
    hubPort,
    rootPublicKeyEnvironment,
  };
}

export async function runCandidateUiContract(
  options: CandidateUiContractOptions,
  dependencies: UiContractDependencies = {},
): Promise<PlaywrightRunResult | null> {
  const loadCandidate = dependencies.loadCandidate ?? loadValidatedCandidate;
  const createHubController =
    dependencies.createHubController ??
    ((controllerOptions: { containerEngine: string }) =>
      createDockerHubController(controllerOptions));
  const runPlaywright = dependencies.runPlaywright ?? runPlaywrightProcess;
  const ownerPassword = dependencies.ownerPassword;
  const runId = dependencies.runId;
  if (!ownerPassword || !runId) {
    throw new Error("candidate UI Contract runtime identity is required");
  }

  const baseUrl = `http://127.0.0.1:${options.hubPort}/`;
  const controller = createHubController({
    containerEngine: options.containerEngine,
  });
  let resources: HubResources | null = null;
  let result: PlaywrightRunResult | null = null;
  let failure: UiContractFailure | null = null;
  let failurePhase = "candidate-validation";
  let manifest: ValidatedCandidate["manifest"] | null = null;
  const failures: { error: string; phase: string }[] = [];
  let hubEvidence: HubEvidence | null = null;
  let cleanupEvidence: HubCleanupResult | null = null;

  try {
    const trustedRootPublicKeyPem =
      process.env[options.rootPublicKeyEnvironment] ?? "";
    if (!trustedRootPublicKeyPem) {
      throw new Error(
        `Probe Distribution Trust Root environment variable ${options.rootPublicKeyEnvironment} is empty`,
      );
    }
    const loaded = await loadCandidate(options.candidateManifestPath, {
      trustedRootPublicKeyPem,
    });
    manifest = loaded.manifest;
    failurePhase = "hub-startup";
    resources = await controller.start({
      candidateDir: loaded.candidateDir,
      candidateManifest: manifest,
      hubOwnerUrl: baseUrl,
      hubPublicUrl: baseUrl,
      ownerPassword,
      runId,
    });
    failurePhase = "playwright";
    result = await runPlaywright({
      baseUrl,
      candidateVersion: manifest.probeAssetSet.version,
      ...(options.evidenceDir ? { evidenceDir: options.evidenceDir } : {}),
      ownerPassword,
    });
    if (result?.code !== 0) {
      throw new Error(
        `Playwright UI Contract failed with exit code ${result?.code}`,
      );
    }
  } catch (error) {
    failure = toError(error);
    failures.push(serializeUiFailure(failurePhase, error, [ownerPassword]));
  }

  if (typeof controller.collectEvidence === "function") {
    try {
      hubEvidence = await controller.collectEvidence({ resources });
    } catch (error) {
      failures.push(
        serializeUiFailure("hub-diagnostics", error, [ownerPassword]),
      );
      if (!failure) failure = toError(error);
    }
  }

  try {
    const cleanup = await controller.cleanup({ resources, runId });
    cleanupEvidence = cleanup;
    if (cleanup?.clean !== true) {
      throw new Error("candidate Hub cleanup did not report a clean result");
    }
  } catch (error) {
    if (failure) {
      failure.cleanupError = toError(error);
    } else {
      failure = toError(error);
    }
    failures.push(serializeUiFailure("cleanup", error, [ownerPassword]));
    cleanupEvidence = { clean: false, error: errorMessage(error) };
  }

  if (options.evidenceDir) {
    await writeUiEvidence(
      options.evidenceDir,
      {
        candidate: manifest?.candidate ?? null,
        cleanup: cleanupEvidence,
        failures,
        hub: {
          expectedManifestDigest: manifest?.hub?.digest ?? null,
          runtime: hubEvidence,
        },
        kind: "enoki-release-ui-contract-evidence",
        playwright: result,
        result: { status: failure ? "failed" : "succeeded" },
        runId,
        schemaVersion: 1,
      },
      [ownerPassword],
    );
  }

  if (failure) throw failure;
  return result;
}

type UiContractEvidence = {
  candidate: ValidatedCandidate["manifest"]["candidate"] | null;
  cleanup: HubCleanupResult | null;
  failures: { error: string; phase: string }[];
  hub: { expectedManifestDigest: string | null; runtime: HubEvidence | null };
  kind: string;
  playwright: PlaywrightRunResult | null;
  result: { status: string };
  runId: string;
  schemaVersion: number;
};

function runPlaywrightProcess({
  baseUrl,
  candidateVersion,
  evidenceDir,
  ownerPassword,
}: {
  baseUrl: string;
  candidateVersion: string;
  evidenceDir?: string;
  ownerPassword: string;
}): Promise<PlaywrightRunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "pnpm",
      [
        "exec",
        "playwright",
        "test",
        "--config",
        "playwright.candidate.config.ts",
      ],
      {
        env: {
          ...process.env,
          ENOKI_RELEASE_UI_BASE_URL: baseUrl,
          ENOKI_RELEASE_UI_CANDIDATE_VERSION: candidateVersion,
          ENOKI_RELEASE_UI_EVIDENCE_DIR: evidenceDir,
          ENOKI_RELEASE_UI_OWNER_PASSWORD: ownerPassword,
        },
        stdio: "inherit",
      },
    );
    child.once("error", reject);
    child.once("close", (code, signal) => {
      resolve({ code: code ?? 1, signal });
    });
  });
}

function serializeUiFailure(
  phase: string,
  error: unknown,
  secrets: readonly string[],
): { error: string; phase: string } {
  return {
    error: boundAndRedact(errorMessage(error), secrets),
    phase,
  };
}

async function writeUiEvidence(
  evidenceDir: string,
  evidence: UiContractEvidence,
  secrets: readonly string[],
): Promise<void> {
  const destination = path.join(evidenceDir, "runner-evidence.json");
  const temporary = `${destination}.tmp-${randomUUID()}`;
  await mkdir(evidenceDir, { recursive: true });
  const safeEvidence = redactAndBoundValue(evidence, secrets);
  await writeFile(temporary, `${JSON.stringify(safeEvidence, null, 2)}\n`);
  await rename(temporary, destination);
}

function redactAndBoundValue(
  value: unknown,
  secrets: readonly string[],
): unknown {
  if (typeof value === "string") return boundAndRedact(value, secrets);
  if (Array.isArray(value)) {
    return value.map((item) => redactAndBoundValue(item, secrets));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        redactAndBoundValue(item, secrets),
      ]),
    );
  }
  return value;
}

function boundAndRedact(value: string, secrets: readonly string[]): string {
  let redacted = value;
  for (const secret of secrets.filter(Boolean)) {
    redacted = redacted.split(secret).join("[REDACTED]");
  }
  const maximumLength = 256 * 1024;
  return redacted.length > maximumLength
    ? `${redacted.slice(0, maximumLength)}\n[TRUNCATED]`
    : redacted;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
