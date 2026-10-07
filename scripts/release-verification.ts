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

import { validateResolvedReleaseBaseline } from "./release-baseline-verification.ts";
import { inspectHubOciArchive } from "./release-candidate-oci.ts";
import {
  inspectProbeAssetSet,
  releaseTransitionForValidatedCandidate,
  validateReleaseCandidate,
} from "./release-candidate-verification.ts";
import { readReleaseE2EMatrix } from "./release-e2e-matrix.ts";
import { objectView, regexInput } from "./release-json-guards.ts";
import {
  compileReleaseScenarioPlan,
  type ReleaseScenarioPlan,
} from "./release-scenario-plan-compile.ts";
import {
  createMatrixGateResult,
  createReleaseVerificationSummary,
  createUiGateResult,
  renderReleaseVerificationEvidenceMarkdown,
} from "./release-verification-lib.ts";

const usage = `Usage:
  node scripts/release-verification.ts record-matrix-gate --candidate-manifest <path> --evidence <path> --cell-id <id> --scenario-outcome <outcome> --verify-clean-outcome <outcome> --artifact-name <name> --output <path>
  node scripts/release-verification.ts record-ui-gate --candidate-manifest <path> --candidate-commit <commit> --candidate-version <version> --playwright-outcome <outcome> --artifact-name <name> --output <path>
  node scripts/release-verification.ts summarize --candidate-dir <path> --root-public-key-env <environment-variable> --release-baseline-dir <path> --probe-assets-dir <path> --hub-oci-dir <path> --matrix <path> --matrix-evidence-root <path> --ui-gate <path> --artifact-index <path> --component-results <path> --standard-ci <path> --requested-commit <commit> --requested-version <version> --run-id <id> --run-attempt <number> --run-url <url> --output <path> --markdown <path>
  node scripts/release-verification.ts assert-verified --summary <path>`;

const matrixGateOptions = [
  "--artifact-name",
  "--candidate-manifest",
  "--cell-id",
  "--evidence",
  "--output",
  "--scenario-outcome",
  "--verify-clean-outcome",
] as const;
const uiGateOptions = [
  "--artifact-name",
  "--candidate-commit",
  "--candidate-manifest",
  "--candidate-version",
  "--output",
  "--playwright-outcome",
] as const;
const summaryOptions = [
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
] as const;
const assertVerifiedOptions = ["--summary"] as const;

type MatrixGateOptions = Record<(typeof matrixGateOptions)[number], string>;
type UiGateOptions = Record<(typeof uiGateOptions)[number], string>;
type SummaryOptions = Record<(typeof summaryOptions)[number], string>;
type AssertVerifiedOptions = Record<
  (typeof assertVerifiedOptions)[number],
  string
>;

type ProbeAssetSetInspection = Awaited<ReturnType<typeof inspectProbeAssetSet>>;

interface AttemptIdentities {
  candidateManifest: unknown;
  errors: string[];
  hub: unknown;
  probeAssetSet: unknown;
  releaseBaseline: unknown;
}

interface EvidenceReading {
  errors: string[];
  value: unknown;
}

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
    await assertVerified(parseOptions(arguments_, assertVerifiedOptions));
  } else {
    throw new Error(usage);
  }
} catch (error) {
  process.stderr.write(`release-verification: ${errorMessage(error)}\n`);
  process.exitCode = 1;
}

async function recordMatrixGate(options: MatrixGateOptions): Promise<void> {
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

async function recordUiGate(options: UiGateOptions): Promise<void> {
  const manifestEvidence = await readOptionalJson(
    options["--candidate-manifest"],
    "Candidate Manifest",
  );
  const manifestCandidate = objectView(manifestEvidence.value).candidate;
  const result = createUiGateResult({
    artifactName: options["--artifact-name"],
    candidate: manifestCandidate ?? {
      commit: options["--candidate-commit"],
      version: options["--candidate-version"],
    },
    playwrightOutcome: options["--playwright-outcome"],
  });
  await writeJsonAtomically(options["--output"], result);
}

async function summarize(options: SummaryOptions): Promise<void> {
  const identities = await readAttemptIdentities(options);
  let scenarioPlan: ReleaseScenarioPlan | null = null;
  const scenarioPlanErrors: string[] = [];
  try {
    scenarioPlan = compileReleaseScenarioPlan({
      candidateManifest: identities.candidateManifest,
      releaseTransition: releaseTransitionForValidatedCandidate(
        objectView(identities.candidateManifest),
      ),
      supportedHostMatrix: await readReleaseE2EMatrix(options["--matrix"]),
    });
  } catch (error) {
    scenarioPlanErrors.push(
      `Release Scenario Plan unavailable: ${errorMessage(error)}`,
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

async function assertVerified(options: AssertVerifiedOptions): Promise<void> {
  const summary = await readJson(options["--summary"], "verification summary");
  const summaryView = objectView(summary);
  if (
    summaryView.kind !== "enoki-release-verification-evidence" ||
    summaryView.schemaVersion !== 3 ||
    summaryView.promotable !== false ||
    summaryView.freshCandidateRequiredForPublish !== true ||
    summaryView.verified !== true
  ) {
    throw new Error("Release verification did not satisfy every required gate");
  }
  process.stdout.write("Release Verification Evidence is complete\n");
}

function parseOptions<Option extends string>(
  arguments_: readonly string[],
  allowed: readonly Option[],
): Record<Option, string> {
  const allowedNames: ReadonlySet<string> = new Set(allowed);
  const options: Record<string, string> = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const option = arguments_[index];
    const value = arguments_[index + 1];
    if (
      option === undefined ||
      !allowedNames.has(option) ||
      value === undefined ||
      value.startsWith("--")
    ) {
      throw new Error(`invalid or missing option: ${option ?? "<missing>"}`);
    }
    if (Object.hasOwn(options, option)) {
      throw new Error(`duplicate option: ${option}`);
    }
    options[option] = value;
  }
  assertEveryOption(options, allowed);
  return options;
}

function assertEveryOption<Option extends string>(
  options: Record<string, string>,
  allowed: readonly Option[],
): asserts options is Record<Option, string> {
  for (const option of allowed) {
    if (!Object.hasOwn(options, option)) {
      throw new Error(`required option is missing: ${option}`);
    }
  }
}

async function readGateResults(
  root: string,
  expectedKind: string,
): Promise<{ errors: string[]; gates: unknown[] }> {
  let files;
  try {
    files = await findNamedFiles(root, "gate-result.json");
  } catch (error) {
    if (objectView(error).code === "ENOENT") {
      return {
        errors: [`Host gate evidence directory is missing: ${root}`],
        gates: [],
      };
    }
    return { errors: [errorMessage(error)], gates: [] };
  }
  const gates: unknown[] = [];
  const errors: string[] = [];
  for (const file of files.sort()) {
    try {
      const gate = await readJson(file, "gate result");
      assertGateResult(gate, expectedKind);
      gates.push(gate);
    } catch (error) {
      errors.push(errorMessage(error));
    }
  }
  return { errors, gates };
}

async function readOptionalGateResult(
  file: string,
  expectedKind: string,
): Promise<{ errors: string[]; gate: unknown }> {
  let gate: unknown;
  try {
    gate = await readJson(file, "gate result");
  } catch (error) {
    return { errors: [errorMessage(error)], gate: null };
  }
  try {
    assertGateResult(gate, expectedKind);
    return { errors: [], gate };
  } catch (error) {
    return { errors: [errorMessage(error)], gate: null };
  }
}

async function readAttemptIdentities(
  options: SummaryOptions,
): Promise<AttemptIdentities> {
  const errors: string[] = [];
  let candidateManifest: unknown = null;
  let hub: unknown = null;
  let inspectedProbeAssetSet: ProbeAssetSetInspection | null = null;
  let probeAssetSet: unknown = null;
  let releaseBaseline: unknown = null;
  try {
    const trustedRootPublicKeyPem =
      process.env[options["--root-public-key-env"]];
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
    errors.push(`Candidate Manifest unavailable: ${errorMessage(error)}`);
  }
  try {
    releaseBaseline = await validateResolvedReleaseBaseline(
      options["--release-baseline-dir"],
    );
  } catch (error) {
    errors.push(
      `Release Baseline identity unavailable: ${errorMessage(error)}`,
    );
  }
  try {
    const inspected = await inspectProbeAssetSet(options["--probe-assets-dir"]);
    inspectedProbeAssetSet = inspected;
    probeAssetSet = {
      directory: "probe-assets",
      files: inspected.files,
      signingIdentity: inspected.signingIdentity,
      version: inspected.version,
    };
  } catch (error) {
    errors.push(`Probe Asset Set identity unavailable: ${errorMessage(error)}`);
  }
  try {
    const hubDirectory = options["--hub-oci-dir"];
    const archiveName = (await readdir(hubDirectory)).find((name) =>
      name.endsWith(".oci.tar"),
    );
    if (!archiveName) throw new Error("Hub OCI archive is missing");
    if (!inspectedProbeAssetSet) {
      throw new Error("signed Probe Asset Set identity is unavailable");
    }
    const archivePath = path.join(hubDirectory, archiveName);
    const inspected = await inspectHubOciArchive({
      archivePath,
      probeFiles: inspectedProbeAssetSet.files,
    });
    hub = {
      archive: archiveName,
      archiveSha256: await fileSha256(archivePath),
      digest: inspected.digest,
      embeddedProbeVersion: inspectedProbeAssetSet.version,
      size: (await stat(archivePath)).size,
    };
  } catch (error) {
    errors.push(`Hub OCI identity unavailable: ${errorMessage(error)}`);
  }
  if (candidateManifest) {
    const manifestView = objectView(candidateManifest);
    hub = manifestView.hub;
    probeAssetSet = manifestView.probeAssetSet;
    releaseBaseline = manifestView.releaseBaseline;
  }
  return {
    candidateManifest,
    errors,
    hub,
    probeAssetSet,
    releaseBaseline,
  };
}

async function readOptionalJson(
  file: string,
  description: string,
): Promise<EvidenceReading> {
  try {
    return { errors: [], value: await readJson(file, description) };
  } catch (error) {
    return { errors: [errorMessage(error)], value: null };
  }
}

async function fileSha256(file: string): Promise<string> {
  return createHash("sha256")
    .update(await readFile(file))
    .digest("hex");
}

async function findNamedFiles(root: string, name: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const found: string[] = [];
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

function assertGateResult(gate: unknown, expectedKind: string): void {
  const gateView = objectView(gate);
  if (
    gateView.kind !== expectedKind ||
    gateView.schemaVersion !== 1 ||
    !gateView.candidate ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(
      regexInput(gateView.artifactName),
    ) ||
    typeof gateView.outcome !== "string" ||
    !["succeeded", "skipped", "failed"].includes(gateView.outcome)
  ) {
    throw new Error(`${expectedKind} evidence is invalid`);
  }
}

async function readJson(file: string, description: string): Promise<unknown> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    const wrapped = new Error(
      `${description} is missing or malformed: ${errorMessage(error)}`,
    );
    Object.assign(wrapped, { causeCode: objectView(error).code });
    throw wrapped;
  }
  return value;
}

async function writeJsonAtomically(
  file: string,
  value: unknown,
): Promise<void> {
  await writeTextAtomically(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function writeTextAtomically(
  file: string,
  contents: string,
): Promise<void> {
  const destination = path.resolve(file);
  await mkdir(path.dirname(destination), { recursive: true });
  const temporary = `${destination}.tmp-${randomUUID()}`;
  await writeFile(temporary, contents);
  await rename(temporary, destination);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
