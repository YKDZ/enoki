#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";

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

async function verify(options) {
  const allowed = new Set([
    "--commit",
    "--jobs",
    "--output",
    "--workflow-runs",
  ]);
  for (const name of options.keys()) {
    if (!allowed.has(name))
      throw new Error(`unknown option for verify: ${name}`);
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
  const matchingRuns = runsDocument.workflow_runs.filter(
    (run) =>
      run?.event === "push" &&
      run?.head_branch === "main" &&
      run?.head_sha === commit,
  );
  const run = matchingRuns.sort((left, right) => right.id - left.id)[0];
  if (!run) {
    throw new Error(
      `standard CI has no push run for candidate commit ${commit}`,
    );
  }
  if (run.status !== "completed" || run.conclusion !== "success") {
    throw new Error(
      `standard CI run ${run.html_url ?? run.id} is ${run.status}/${run.conclusion}`,
    );
  }
  if (!Number.isSafeInteger(run.id) || run.id < 1 || !run.html_url) {
    throw new Error("standard CI run identity is malformed");
  }

  const jobsDocument = await readJson(
    required(options, "--jobs"),
    "standard CI jobs",
  );
  assertObject(jobsDocument, "standard CI jobs");
  if (!Array.isArray(jobsDocument.jobs) || jobsDocument.jobs.length === 0) {
    throw new Error("standard CI run must contain jobs");
  }
  const jobs = jobsDocument.jobs.map((job) => {
    if (!job?.name || job.conclusion !== "success") {
      throw new Error(
        `standard CI job ${job?.name ?? "<unnamed>"} did not succeed`,
      );
    }
    return { conclusion: job.conclusion, name: job.name };
  });

  const evidence = {
    candidateCommit: commit,
    jobs,
    kind: "enoki-standard-ci-evidence",
    runId: run.id,
    runUrl: run.html_url,
    schemaVersion: 1,
  };
  await writeFile(
    required(options, "--output"),
    `${JSON.stringify(evidence, null, 2)}\n`,
  );
}

try {
  const [command, ...tokens] = process.argv.slice(2);
  if (command !== "verify") throw new Error(`unknown command: ${command}`);
  await verify(parseOptions(tokens));
} catch (error) {
  process.stderr.write(
    `release-ci: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
}
