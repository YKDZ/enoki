import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  createDockerHubController,
  loadValidatedCandidate,
} from "./release-e2e-adapters.mjs";

const optionDefinitions = Object.freeze({
  "--candidate-manifest": { required: true },
  "--container-engine": { default: "docker" },
  "--evidence-dir": { default: "release-ui-contract-evidence" },
  "--hub-port": { default: "38220" },
  "--root-public-key-env": { required: true },
});

export function parseCandidateUiContractCommandLine(arguments_) {
  if (arguments_.length % 2 !== 0) {
    throw new Error(`option ${arguments_.at(-1)} requires a value`);
  }
  const values = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
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
  if (
    path.basename(values["--candidate-manifest"]) !== "candidate-manifest.json"
  ) {
    throw new Error("--candidate-manifest must name candidate-manifest.json");
  }
  if (values["--container-engine"] !== "docker") {
    throw new Error("--container-engine must be docker");
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(values["--root-public-key-env"])) {
    throw new Error("--root-public-key-env must name an environment variable");
  }
  const hubPort = Number(values["--hub-port"]);
  if (!Number.isSafeInteger(hubPort) || hubPort < 1 || hubPort > 65_535) {
    throw new Error("--hub-port must be an integer between 1 and 65535");
  }
  return {
    candidateManifestPath: values["--candidate-manifest"],
    containerEngine: values["--container-engine"],
    evidenceDir: path.resolve(values["--evidence-dir"]),
    hubPort,
    rootPublicKeyEnvironment: values["--root-public-key-env"],
  };
}

export async function runCandidateUiContract(options, dependencies = {}) {
  if (!options.rootPublicKeyEnvironment) {
    throw new Error(
      "candidate UI Contract Probe Distribution Trust Root environment variable is required",
    );
  }
  const trustedRootPublicKeyPem = (dependencies.environment ?? process.env)[
    options.rootPublicKeyEnvironment
  ];
  if (!trustedRootPublicKeyPem) {
    throw new Error(
      `Probe Distribution Trust Root environment variable ${options.rootPublicKeyEnvironment} is empty`,
    );
  }
  const loadCandidate = dependencies.loadCandidate ?? loadValidatedCandidate;
  const createHubController =
    dependencies.createHubController ??
    ((controllerOptions) => createDockerHubController(controllerOptions));
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
  let resources = null;
  let result = null;
  let failure = null;
  let failurePhase = "candidate-validation";
  let manifest = null;
  const failures = [];
  let hubEvidence = null;
  let cleanupEvidence = null;

  try {
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
    failure = error;
    failures.push(serializeUiFailure(failurePhase, error, [ownerPassword]));
  }

  if (typeof controller.collectEvidence === "function") {
    try {
      hubEvidence = await controller.collectEvidence({ resources });
    } catch (error) {
      failures.push(
        serializeUiFailure("hub-diagnostics", error, [ownerPassword]),
      );
      if (!failure) failure = error;
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
      failure.cleanupError = error;
    } else {
      failure = error;
    }
    failures.push(serializeUiFailure("cleanup", error, [ownerPassword]));
    cleanupEvidence = { clean: false, error: error.message };
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

function runPlaywrightProcess({
  baseUrl,
  candidateVersion,
  evidenceDir,
  ownerPassword,
}) {
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

function serializeUiFailure(phase, error, secrets) {
  return {
    error: boundAndRedact(error?.message ?? String(error), secrets),
    phase,
  };
}

async function writeUiEvidence(evidenceDir, evidence, secrets) {
  const destination = path.join(evidenceDir, "runner-evidence.json");
  const temporary = `${destination}.tmp-${randomUUID()}`;
  await mkdir(evidenceDir, { recursive: true });
  const safeEvidence = redactAndBoundValue(evidence, secrets);
  await writeFile(temporary, `${JSON.stringify(safeEvidence, null, 2)}\n`);
  await rename(temporary, destination);
}

function redactAndBoundValue(value, secrets) {
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

function boundAndRedact(value, secrets) {
  let redacted = String(value);
  for (const secret of secrets.filter(Boolean)) {
    redacted = redacted.split(secret).join("[REDACTED]");
  }
  const maximumLength = 256 * 1024;
  return redacted.length > maximumLength
    ? `${redacted.slice(0, maximumLength)}\n[TRUNCATED]`
    : redacted;
}
