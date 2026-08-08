#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import { validateReleaseCandidate } from "./release-candidate-lib.mjs";
import { reconcilePublication } from "./release-publication-lib.mjs";
import { createGitHubGhcrPublicationRemote } from "./release-publication-remote.mjs";

const usage = `Usage:
  node scripts/release-publication.mjs reconcile --candidate-dir <path> --verification-summary <path> --repository <owner/name> --image <registry/image> --run-id <id> --run-attempt <number> --run-url <url> --output <path> --markdown <path>
  node scripts/release-publication.mjs assert-published --summary <path>`;

try {
  const [command, ...arguments_] = process.argv.slice(2);
  if (command === "reconcile") {
    await reconcile(
      parseOptions(
        arguments_,
        new Set([
          "--candidate-dir",
          "--image",
          "--markdown",
          "--output",
          "--repository",
          "--run-attempt",
          "--run-id",
          "--run-url",
          "--verification-summary",
        ]),
      ),
    );
  } else if (command === "assert-published") {
    await assertPublished(parseOptions(arguments_, new Set(["--summary"])));
  } else if (command === "--help") {
    process.stdout.write(`${usage}\n`);
  } else {
    throw new Error(usage);
  }
} catch (error) {
  process.stderr.write(`release-publication: ${error.message}\n`);
  process.exitCode = 1;
}

async function reconcile(options) {
  const workflowRun = {
    attempt: Number(options["--run-attempt"]),
    id: options["--run-id"],
    url: options["--run-url"],
  };
  if (
    !Number.isSafeInteger(workflowRun.attempt) ||
    workflowRun.attempt < 1 ||
    !workflowRun.id ||
    !isHttpsUrl(workflowRun.url)
  ) {
    throw new Error("workflow run identity is invalid");
  }

  let candidateManifest = null;
  let verificationSummary = null;
  let summary;
  try {
    [candidateManifest, verificationSummary] = await Promise.all([
      validateReleaseCandidate(options["--candidate-dir"]),
      readJson(options["--verification-summary"], "verification summary"),
    ]);
    summary = await reconcilePublication({
      candidateDir: options["--candidate-dir"],
      candidateManifest,
      remote: createGitHubGhcrPublicationRemote({
        image: options["--image"],
        repository: options["--repository"],
      }),
      verificationSummary,
      workflowRun,
    });
  } catch (error) {
    summary = {
      candidate: candidateManifest?.candidate ?? null,
      failureReasons: [error.message],
      gates: verificationSummary?.gates ?? null,
      hub: candidateManifest?.hub ?? null,
      kind: "enoki-release-publication-summary",
      probeAssetSet: candidateManifest?.probeAssetSet ?? null,
      releaseBaseline: verificationSummary?.releaseBaseline ?? null,
      schemaVersion: 1,
      smoke: null,
      status: "failed",
      workflowRun,
    };
  }

  if (summary.status === "broken" && !summary.failureReasons) {
    summary.failureReasons = summary.smoke?.failureReasons ?? [
      "post-publication smoke failed",
    ];
  }
  await Promise.all([
    writeJsonAtomically(options["--output"], summary),
    writeTextAtomically(
      options["--markdown"],
      renderPublicationMarkdown(summary),
    ),
  ]);
}

async function assertPublished(options) {
  const summary = await readJson(options["--summary"], "publication summary");
  if (
    summary?.kind !== "enoki-release-publication-summary" ||
    summary?.schemaVersion !== 1 ||
    summary.status !== "published" ||
    summary.smoke?.outcome !== "succeeded" ||
    summary.publication?.tag?.commit !== summary.candidate?.commit ||
    summary.publication?.versionedImage?.digest !==
      summary.hub?.candidateDigest ||
    summary.publication?.latestImage?.digest !== summary.hub?.candidateDigest
  ) {
    throw new Error(
      `release publication is ${summary?.status ?? "invalid"}; immutable outputs must not be changed automatically`,
    );
  }
  process.stdout.write(
    `published ${summary.candidate.version} from ${summary.candidate.commit}\n`,
  );
}

function renderPublicationMarkdown(summary) {
  const lines = [
    "# Enoki Release publication",
    "",
    `- Status: **${summary.status}**`,
    `- Candidate: \`${summary.candidate?.version ?? "missing"}\` @ \`${summary.candidate?.commit ?? "missing"}\``,
    `- Workflow attempt: [${summary.workflowRun.id}/${summary.workflowRun.attempt}](${summary.workflowRun.url})`,
    `- Immutable tag: \`${summary.publication?.tag?.name ?? "missing"}\` @ \`${summary.publication?.tag?.commit ?? "missing"}\``,
    `- GitHub Release: ${summary.publication?.githubRelease?.url ?? "missing"}`,
    `- Versioned Hub digest: \`${summary.publication?.versionedImage?.digest ?? "missing"}\``,
    `- Latest Hub digest: \`${summary.publication?.latestImage?.digest ?? "missing"}\``,
    `- Post-publication smoke: **${summary.smoke?.outcome ?? "not-run"}**`,
    "",
    "## Candidate gates",
    "",
    `- Candidate build: ${summary.gates?.candidateBuild?.outcome ?? "missing"}`,
    `- Candidate UI Contract: ${summary.gates?.candidateUiContract?.outcome ?? "missing"}`,
    `- Host matrix: ${summary.gates?.hostMatrix?.outcome ?? "missing"}`,
    `- Matrix scenarios: ${summary.gates?.hostScenarios?.length ?? 0}`,
    "",
    "## Probe Asset Set",
    "",
    "| File | SHA-256 |",
    "| --- | --- |",
    ...(summary.probeAssetSet?.files ?? []).map(
      ({ file, sha256 }) => `| \`${file}\` | \`${sha256}\` |`,
    ),
    "",
    "## Failure reasons",
    "",
    ...(summary.failureReasons?.length
      ? summary.failureReasons.map((reason) => `- ${reason}`)
      : ["- None"]),
    "",
  ];
  return `${lines.join("\n")}\n`;
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

async function readJson(file, label) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`${label} is invalid: ${error.message}`);
  }
}

async function writeJsonAtomically(file, value) {
  await writeTextAtomically(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function writeTextAtomically(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${randomUUID()}`;
  await writeFile(temporary, value);
  await rename(temporary, file);
}

function isHttpsUrl(value) {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}
