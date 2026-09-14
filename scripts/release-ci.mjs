#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";

import {
  isSelectedStandardCiRun,
  isStandardCiEvidence,
  selectStandardCiRun,
} from "./standard-ci-evidence.ts";

const commitPattern = /^[0-9a-f]{40}$/;

function parseOptions(tokens) {
  const options = new Map();
  for (let index = 0; index < tokens.length; index += 2) {
    const name = tokens[index];
    const value = tokens[index + 1];
    if (!name?.startsWith("--") || value === undefined || options.has(name)) {
      throw new Error(`invalid command-line argument: ${name ?? "<missing>"}`);
    }
    options.set(name, value);
  }
  return options;
}

function required(options, name) {
  const value = options.get(name);
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function readJson(file, description) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch {
    throw new Error(`${description} is not valid JSON`);
  }
}

function assertObject(value, description) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
}

async function select(options) {
  const allowed = new Set(["--commit", "--output", "--workflow-runs"]);
  for (const name of options.keys()) {
    if (!allowed.has(name)) {
      throw new Error(`unknown option for select: ${name}`);
    }
  }

  const commit = required(options, "--commit");
  if (!commitPattern.test(commit)) {
    throw new Error("commit must be a full lowercase 40-character object ID");
  }
  const runsDocument = await readJson(
    required(options, "--workflow-runs"),
    "standard CI workflow runs",
  );
  assertObject(runsDocument, "standard CI workflow runs");
  if (!Array.isArray(runsDocument.workflow_runs)) {
    throw new Error("standard CI workflow runs must contain workflow_runs");
  }
  const run = selectStandardCiRun(runsDocument.workflow_runs, commit);
  if (!run) {
    throw new Error(`standard CI has no run for candidate commit ${commit}`);
  }
  if (!isSelectedStandardCiRun(run, commit)) {
    throw new Error(
      "selected standard CI run is not a successful current attempt",
    );
  }
  await writeFile(
    required(options, "--output"),
    `${JSON.stringify(run, null, 2)}\n`,
  );
}

async function verify(options) {
  const allowed = new Set(["--commit", "--jobs", "--output", "--selected-run"]);
  for (const name of options.keys()) {
    if (!allowed.has(name))
      throw new Error(`unknown option for verify: ${name}`);
  }

  const commit = required(options, "--commit");
  if (!commitPattern.test(commit)) {
    throw new Error("commit must be a full lowercase 40-character object ID");
  }

  const run = await readJson(
    required(options, "--selected-run"),
    "selected standard CI run",
  );
  if (!isSelectedStandardCiRun(run, commit)) {
    throw new Error(
      "selected standard CI run is not a successful current attempt",
    );
  }

  const jobsDocument = await readJson(
    required(options, "--jobs"),
    "standard CI jobs",
  );
  assertObject(jobsDocument, "standard CI jobs");
  if (!Array.isArray(jobsDocument.jobs)) {
    throw new Error("standard CI run must contain jobs");
  }
  const jobs = jobsDocument.jobs.map((job) => {
    if (!job?.name) {
      throw new Error(
        `standard CI job ${job?.name ?? "<unnamed>"} is malformed`,
      );
    }
    return { conclusion: job.conclusion, name: job.name };
  });

  const evidence = {
    candidateCommit: commit,
    event: run.event,
    jobs,
    kind: "enoki-standard-ci-evidence",
    runAttempt: run.run_attempt,
    runId: run.id,
    runUrl: run.html_url,
    schemaVersion: 2,
  };
  if (!isStandardCiEvidence(evidence, commit)) {
    throw new Error("standard CI evidence is incomplete or invalid");
  }
  await writeFile(
    required(options, "--output"),
    `${JSON.stringify(evidence, null, 2)}\n`,
  );
}

try {
  const [command, ...tokens] = process.argv.slice(2);
  const options = parseOptions(tokens);
  if (command === "select") {
    await select(options);
  } else if (command === "verify") {
    await verify(options);
  } else {
    throw new Error(`unknown command: ${command}`);
  }
} catch (error) {
  process.stderr.write(
    `release-ci: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
}
