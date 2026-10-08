// 标准 CI 证据的唯一判定实现：运行选择、当前 attempt 归属核对与 schema2 校验。
// 发布前置 CLI 与最终验收汇总消费同一判据，不保留较弱的成功条件。

import {
  isPositiveSafeInteger,
  isUnknownArray,
  objectView,
  type UnknownRecord,
} from "./release-json-guards.ts";

const candidateCommitPattern = /^[0-9a-f]{40}$/;

export const standardCiEvidenceKind = "enoki-standard-ci-evidence";
export const standardCiEvidenceSchemaVersion = 2;

export const standardCiEvents: readonly string[] = Object.freeze([
  "push",
  "workflow_dispatch",
]);

// 既有标准 CI 的七项检查：Node、Rust、四目标 Probe matrix 与 Hub image。
export const standardCiJobNames: readonly string[] = Object.freeze([
  "Hub Docker image / Hub Docker image",
  "Node checks / Node checks",
  "Probe binaries / Probe binary (aarch64-unknown-linux-gnu)",
  "Probe binaries / Probe binary (aarch64-unknown-linux-musl)",
  "Probe binaries / Probe binary (x86_64-unknown-linux-gnu)",
  "Probe binaries / Probe binary (x86_64-unknown-linux-musl)",
  "Rust checks / Rust checks",
]);

export interface StandardCiRun {
  attempt: number;
  conclusion: unknown;
  event: string;
  id: number;
  status: unknown;
  url: string;
}

export interface StandardCiJobEvidence {
  conclusion: string;
  name: string;
}

export interface StandardCiEvidence {
  candidateCommit: string;
  event: string;
  jobs: readonly StandardCiJobEvidence[];
  kind: typeof standardCiEvidenceKind;
  runAttempt: number;
  runId: number;
  runUrl: string;
  schemaVersion: typeof standardCiEvidenceSchemaVersion;
}

export function assertCandidateCommit(commit: unknown): string {
  if (typeof commit !== "string" || !candidateCommitPattern.test(commit)) {
    throw new Error("commit must be a full lowercase 40-character object ID");
  }

  return commit;
}

// 先选择后判定：status、conclusion 与 attempt 都不参与集合过滤，只在选出后核验。
export function selectStandardCiRun(
  document: unknown,
  commit: string,
): StandardCiRun {
  const workflowRuns = objectView(document).workflow_runs;
  if (!isUnknownArray(workflowRuns)) {
    throw new Error("standard CI workflow runs must contain workflow_runs");
  }

  let selected: StandardCiRun | null = null;
  for (const value of workflowRuns) {
    const run = objectView(value);
    if (
      run.head_branch !== "main" ||
      run.head_sha !== commit ||
      !isStandardCiEvent(run.event)
    ) {
      continue;
    }
    const candidate = readStandardCiRun(run);
    if (selected === null || candidate.id > selected.id) {
      selected = candidate;
    }
  }

  if (selected === null) {
    throw new Error(
      `standard CI has no push or workflow_dispatch run for candidate commit ${commit}`,
    );
  }

  return selected;
}

export function assertStandardCiRunSucceeded(run: StandardCiRun): void {
  if (run.status !== "completed" || run.conclusion !== "success") {
    throw new Error(
      `standard CI run ${run.url} is ${String(run.status)}/${String(run.conclusion)}`,
    );
  }
}

export function readStandardCiJobEvidence(
  document: unknown,
  run: StandardCiRun,
  commit: string,
): readonly StandardCiJobEvidence[] {
  const jobs = objectView(document).jobs;
  if (!isUnknownArray(jobs) || jobs.length === 0) {
    throw new Error(
      `standard CI run ${run.id} attempt ${run.attempt} has no jobs`,
    );
  }

  const names: string[] = [];
  for (const value of jobs) {
    const job = objectView(value);
    const name = job.name;
    if (typeof name !== "string" || name.length === 0) {
      throw new Error("standard CI job name is missing");
    }
    if (
      job.head_sha !== commit ||
      job.run_id !== run.id ||
      job.run_attempt !== run.attempt
    ) {
      throw new Error(
        `standard CI job ${name} is not bound to run ${run.id} attempt ${run.attempt} for candidate commit ${commit}`,
      );
    }
    if (job.conclusion !== "success") {
      throw new Error(
        `standard CI job ${name} is ${String(job.status)}/${String(job.conclusion)}`,
      );
    }
    names.push(name);
  }

  const error = exactSevenStandardCiJobNamesError(names);
  if (error !== null) {
    throw new Error(error);
  }

  return standardCiJobNames.map((name) => ({ conclusion: "success", name }));
}

export function createStandardCiEvidence(
  commit: string,
  run: StandardCiRun,
  jobs: readonly StandardCiJobEvidence[],
): StandardCiEvidence {
  const evidence: StandardCiEvidence = {
    candidateCommit: commit,
    event: run.event,
    jobs,
    kind: standardCiEvidenceKind,
    runAttempt: run.attempt,
    runId: run.id,
    runUrl: run.url,
    schemaVersion: standardCiEvidenceSchemaVersion,
  };
  const errors = standardCiEvidenceErrors(evidence, commit);
  if (errors.length > 0) {
    throw new Error(`standard CI evidence is invalid: ${errors.join("; ")}`);
  }

  return evidence;
}

export function standardCiEvidenceErrors(
  evidence: unknown,
  commit: unknown,
): readonly string[] {
  const view = objectView(evidence);
  const errors: string[] = [];
  if (view.kind !== standardCiEvidenceKind) {
    errors.push("standard CI evidence kind is invalid");
  }
  if (view.schemaVersion !== standardCiEvidenceSchemaVersion) {
    errors.push("standard CI evidence must use schema version 2");
  }
  if (typeof commit !== "string" || !candidateCommitPattern.test(commit)) {
    errors.push("candidate commit is not a full lowercase 40-character ID");
  } else if (view.candidateCommit !== commit) {
    errors.push("standard CI evidence is for a different candidate commit");
  }
  if (!isStandardCiEvent(view.event)) {
    errors.push("standard CI event is neither push nor workflow_dispatch");
  }
  if (!isPositiveSafeInteger(view.runId)) {
    errors.push("standard CI run id is invalid");
  }
  if (typeof view.runUrl !== "string" || view.runUrl.length === 0) {
    errors.push("standard CI run URL is missing");
  }
  if (!isPositiveSafeInteger(view.runAttempt)) {
    errors.push("standard CI run attempt is invalid");
  }
  const jobsError = standardCiJobsError(view.jobs);
  if (jobsError !== null) {
    errors.push(jobsError);
  }

  return errors;
}

function isStandardCiEvent(event: unknown): event is string {
  return typeof event === "string" && standardCiEvents.includes(event);
}

function readStandardCiRun(run: UnknownRecord): StandardCiRun {
  const attempt = run.run_attempt;
  const event = run.event;
  const id = run.id;
  const url = run.html_url;
  if (
    !isPositiveSafeInteger(attempt) ||
    !isPositiveSafeInteger(id) ||
    typeof event !== "string" ||
    typeof url !== "string" ||
    url.length === 0
  ) {
    throw new Error("standard CI run identity is malformed");
  }

  return {
    attempt,
    conclusion: run.conclusion,
    event,
    id,
    status: run.status,
    url,
  };
}

function standardCiJobsError(jobs: unknown): string | null {
  if (!isUnknownArray(jobs)) {
    return "standard CI jobs are missing";
  }
  const names: string[] = [];
  for (const value of jobs) {
    const job = objectView(value);
    const name = job.name;
    if (typeof name !== "string" || job.conclusion !== "success") {
      return "standard CI jobs must each record a successful named check";
    }
    names.push(name);
  }

  return exactSevenStandardCiJobNamesError(names);
}

function exactSevenStandardCiJobNamesError(
  names: readonly string[],
): string | null {
  const sorted = [...names].sort();
  if (
    sorted.length !== standardCiJobNames.length ||
    sorted.some((name, index) => name !== standardCiJobNames[index])
  ) {
    return `standard CI jobs are not the exact seven checks: ${sorted.join(", ")}`;
  }

  return null;
}
