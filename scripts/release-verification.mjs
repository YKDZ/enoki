#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import {
  mkdir,
  readFile,
  readdir,
  rename,
  stat,
  writeFile,
} from "node:fs/promises";
import path from "node:path";

import { validateResolvedReleaseBaseline } from "./release-baseline-lib.mjs";
import {
  inspectProbeAssetSet,
  releaseTransitionForValidatedCandidate,
  validateReleaseCandidate,
} from "./release-candidate-lib.mjs";
import { inspectHubOciArchive } from "./release-candidate-oci.mjs";
import { readReleaseE2EMatrix } from "./release-e2e-matrix.mjs";
import { compileReleaseScenarioPlan } from "./release-scenario-plan.mjs";
import {
  createMatrixGateResult,
  createReleaseVerificationSummary,
  createUiGateResult,
  renderReleaseVerificationEvidenceMarkdown,
} from "./release-verification-lib.mjs";

const usage = `Usage:
  node scripts/release-verification.mjs record-matrix-gate --candidate-manifest <path> --evidence <path> --cell-id <id> --scenario-outcome <outcome> --verify-clean-outcome <outcome> --artifact-name <name> --output <path>
  node scripts/release-verification.mjs record-ui-gate --candidate-manifest <path> --candidate-commit <commit> --candidate-version <version> --playwright-outcome <outcome> --artifact-name <name> --output <path>
  node scripts/release-verification.mjs summarize --candidate-dir <path> --root-public-key-env <environment-variable> --release-baseline-dir <path> --probe-assets-dir <path> --hub-oci-dir <path> --matrix <path> --matrix-evidence-root <path> --ui-gate <path> --artifact-index <path> --component-results <path> --standard-ci <path> --requested-commit <commit> --requested-version <version> --run-id <id> --run-attempt <number> --run-url <url> --output <path> --markdown <path>
  node scripts/release-verification.mjs assert-verified --summary <path>`;

const matrixGateOptions = new Set([
  "--artifact-name",
  "--candidate-manifest",
  "--cell-id",
  "--evidence",
  "--output",
  "--scenario-outcome",
  "--verify-clean-outcome",
]);
const uiGateOptions = new Set([
  "--artifact-name",
  "--candidate-commit",
  "--candidate-manifest",
  "--candidate-version",
  "--output",
  "--playwright-outcome",
]);
const summaryOptions = new Set([
  "--artifact-index",
  "--candidate-dir",
  "--component-results",
  "--hub-oci-dir",
  "--markdown",
  "--matrix",
  "--matrix-evidence-root",
  "--output",
  "--probe-assets-dir",
  "--release-baseline-dir",
  "--requested-commit",
  "--requested-version",
  "--root-public-key-env",
  "--run-attempt",
  "--run-id",
  "--run-url",
  "--standard-ci",
  "--ui-gate",
]);

try {
  const [command, ...arguments_] = process.argv.slice(2);
  if (command === "--help") {
    process.stdout.write(`${usage}\n`);
  } else if (command === "record-matrix-gate") {
    await recordMatrixGate(parseOptions(arguments_, matrixGateOptions));
  } else if (command === "record-ui-gate") {
    await recordUiGate(parseOptions(arguments_, uiGateOptions));
  } else if (command === "summarize") {
    await summarize(parseOptions(arguments_, summaryOptions));
  } else if (command === "assert-verified") {
    await assertVerified(parseOptions(arguments_, new Set(["--summary"])));
  } else {
    throw new Error(usage);
  }
} catch (error) {
  process.stderr.write(`release-verification: ${error.message}\n`);
  process.exitCode = 1;
}

async function recordMatrixGate(options) {
  const manifest = await readJson(
    options["--candidate-manifest"],
    "Candidate Manifest",
  );
  const evidence = await readJson(options["--evidence"], "lifecycle evidence");
  const result = createMatrixGateResult({
    artifactName: options["--artifact-name"],
    candidateManifest: manifest,
    cellId: options["--cell-id"],
    evidence,
    scenarioOutcome: options["--scenario-outcome"],
    verifyCleanOutcome: options["--verify-clean-outcome"],
  });
  await writeJsonAtomically(options["--output"], result);
}

async function recordUiGate(options) {
  const manifestEvidence = await readOptionalJson(
    options["--candidate-manifest"],
    "Candidate Manifest",
  );
  const result = createUiGateResult({
    artifactName: options["--artifact-name"],
    candidate: manifestEvidence.value?.candidate ?? {
      commit: options["--candidate-commit"],
      version: options["--candidate-version"],
    },
    playwrightOutcome: options["--playwright-outcome"],
  });
  await writeJsonAtomically(options["--output"], result);
}

async function summarize(options) {
  const identities = await readAttemptIdentities(options);
  let scenarioPlan = null;
  const scenarioPlanErrors = [];
  try {
    scenarioPlan = compileReleaseScenarioPlan({
      candidateManifest: identities.candidateManifest,
      releaseTransition: releaseTransitionForValidatedCandidate(
        identities.candidateManifest,
      ),
      supportedHostMatrix: await readReleaseE2EMatrix(options["--matrix"]),
    });
  } catch (error) {
    scenarioPlanErrors.push(
      `Release Scenario Plan unavailable: ${error.message}`,
    );
  }
  const hostEvidence = await readGateResults(
    options["--matrix-evidence-root"],
    "enoki-release-e2e-gate",
  );
  const uiEvidence = await readOptionalGateResult(
    options["--ui-gate"],
    "enoki-release-ui-contract-gate",
  );
  const componentEvidence = await readOptionalJson(
    options["--component-results"],
    "component results",
  );
  const artifactEvidence = await readOptionalJson(
    options["--artifact-index"],
    "workflow artifact index",
  );
  const standardCiEvidence = await readOptionalJson(
    options["--standard-ci"],
    "standard CI evidence",
  );
  const attempt = Number(options["--run-attempt"]);
  if (!Number.isSafeInteger(attempt) || attempt < 1) {
    throw new Error("run attempt must be a positive integer");
  }
  const summary = createReleaseVerificationSummary({
    artifactIndex: artifactEvidence.value ?? {},
    candidateManifest: identities.candidateManifest,
    componentResults: componentEvidence.value ?? {},
    evidenceErrors: [
      ...identities.errors,
      ...scenarioPlanErrors,
      ...hostEvidence.errors,
      ...uiEvidence.errors,
      ...componentEvidence.errors,
      ...artifactEvidence.errors,
      ...standardCiEvidence.errors,
    ],
    hostGates: hostEvidence.gates,
    identities,
    scenarioPlan,
    requested: {
      commit: options["--requested-commit"],
      version: options["--requested-version"],
    },
    run: {
      attempt,
      id: options["--run-id"],
      url: options["--run-url"],
    },
    standardCi: standardCiEvidence.value,
    uiGate: uiEvidence.gate,
  });
  await Promise.all([
    writeJsonAtomically(options["--output"], summary),
    writeTextAtomically(
      options["--markdown"],
      renderReleaseVerificationEvidenceMarkdown(summary),
    ),
  ]);
}

async function assertVerified(options) {
  const summary = await readJson(options["--summary"], "verification summary");
  if (
    summary?.kind !== "enoki-release-verification-evidence" ||
    summary?.schemaVersion !== 3 ||
    summary.promotable !== false ||
    summary.freshCandidateRequiredForPublish !== true ||
    summary.verified !== true
  ) {
    throw new Error("Release verification did not satisfy every required gate");
  }
  process.stdout.write("Release Verification Evidence is complete\n");
}

function parseOptions(arguments_, allowed) {
  const options = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const option = arguments_[index];
    const value = arguments_[index + 1];
    if (!allowed.has(option) || value === undefined || value.startsWith("--")) {
      throw new Error(`invalid or missing option: ${option ?? "<missing>"}`);
    }
    if (Object.hasOwn(options, option)) {
      throw new Error(`duplicate option: ${option}`);
    }
    options[option] = value;
  }
  for (const option of allowed) {
    if (!Object.hasOwn(options, option)) {
      throw new Error(`required option is missing: ${option}`);
    }
  }
  return options;
}

async function readGateResults(root, expectedKind) {
  let files;
  try {
    files = await findNamedFiles(root, "gate-result.json");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        errors: [`Host gate evidence directory is missing: ${root}`],
        gates: [],
      };
    }
    return { errors: [error.message], gates: [] };
  }
  const gates = [];
  const errors = [];
  for (const file of files.sort()) {
    try {
      const gate = await readJson(file, "gate result");
      assertGateResult(gate, expectedKind);
      gates.push(gate);
    } catch (error) {
      errors.push(error.message);
    }
  }
  return { errors, gates };
}

async function readOptionalGateResult(file, expectedKind) {
  let gate;
  try {
    gate = await readJson(file, "gate result");
  } catch (error) {
    return { errors: [error.message], gate: null };
  }
  try {
    assertGateResult(gate, expectedKind);
    return { errors: [], gate };
  } catch (error) {
    return { errors: [error.message], gate: null };
  }
}

async function readAttemptIdentities(options) {
  const errors = [];
  let candidateManifest = null;
  let hub = null;
  let probeAssetSet = null;
  let releaseBaseline = null;
  const trustedRootPublicKeyPem = process.env[options["--root-public-key-env"]];
  try {
    if (!trustedRootPublicKeyPem) {
      throw new Error(
        `Probe Distribution Trust Root environment variable ${options["--root-public-key-env"]} is empty`,
      );
    }
    candidateManifest = await validateReleaseCandidate(
      options["--candidate-dir"],
      { trustedRootPublicKeyPem },
    );
  } catch (error) {
    errors.push(`Candidate Manifest unavailable: ${error.message}`);
  }
  try {
    releaseBaseline = await validateResolvedReleaseBaseline(
      options["--release-baseline-dir"],
      {
        candidateVersion: options["--requested-version"],
        trustedRootPublicKeyPem,
      },
    );
  } catch (error) {
    errors.push(`Release Baseline identity unavailable: ${error.message}`);
  }
  try {
    const inspected = await inspectProbeAssetSet(
      options["--probe-assets-dir"],
      { trustedRootPublicKeyPem },
    );
    probeAssetSet = {
      directory: "probe-assets",
      files: inspected.files,
      signingIdentity: inspected.signingIdentity,
      version: inspected.version,
    };
  } catch (error) {
    errors.push(`Probe Asset Set identity unavailable: ${error.message}`);
  }
  try {
    const hubDirectory = options["--hub-oci-dir"];
    const archiveName = (await readdir(hubDirectory)).find((name) =>
      name.endsWith(".oci.tar"),
    );
    if (!archiveName) throw new Error("Hub OCI archive is missing");
    if (!probeAssetSet) {
      throw new Error("signed Probe Asset Set identity is unavailable");
    }
    const archivePath = path.join(hubDirectory, archiveName);
    const inspected = await inspectHubOciArchive({
      archivePath,
      probeFiles: probeAssetSet.files,
    });
    hub = {
      archive: archiveName,
      archiveSha256: await fileSha256(archivePath),
      digest: inspected.digest,
      embeddedProbeVersion: probeAssetSet.version,
      size: (await stat(archivePath)).size,
    };
  } catch (error) {
    errors.push(`Hub OCI identity unavailable: ${error.message}`);
  }
  if (candidateManifest) {
    hub = candidateManifest.hub;
    probeAssetSet = candidateManifest.probeAssetSet;
    releaseBaseline = candidateManifest.releaseBaseline;
  }
  return {
    candidateManifest,
    errors,
    hub,
    probeAssetSet,
    releaseBaseline,
  };
}

async function readOptionalJson(file, description) {
  try {
    return { errors: [], value: await readJson(file, description) };
  } catch (error) {
    return { errors: [error.message], value: null };
  }
}

async function fileSha256(file) {
  return createHash("sha256")
    .update(await readFile(file))
    .digest("hex");
}

async function findNamedFiles(root, name) {
  const entries = await readdir(root, { withFileTypes: true });
  const found = [];
  for (const entry of entries) {
    const resolved = path.join(root, entry.name);
    if (entry.isDirectory()) {
      found.push(...(await findNamedFiles(resolved, name)));
    } else if (entry.isFile() && entry.name === name) {
      found.push(resolved);
    }
  }
  return found;
}

function assertGateResult(gate, expectedKind) {
  if (
    gate?.kind !== expectedKind ||
    gate.schemaVersion !== 1 ||
    !gate.candidate ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(gate.artifactName ?? "") ||
    !["succeeded", "skipped", "failed"].includes(gate.outcome)
  ) {
    throw new Error(`${expectedKind} evidence is invalid`);
  }
}

async function readJson(file, description) {
  let value;
  try {
    value = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    const wrapped = new Error(
      `${description} is missing or malformed: ${error.message}`,
    );
    wrapped.causeCode = error?.code;
    throw wrapped;
  }
  return value;
}

async function writeJsonAtomically(file, value) {
  await writeTextAtomically(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function writeTextAtomically(file, contents) {
  const destination = path.resolve(file);
  await mkdir(path.dirname(destination), { recursive: true });
  const temporary = `${destination}.tmp-${randomUUID()}`;
  await writeFile(temporary, contents);
  await rename(temporary, destination);
}
