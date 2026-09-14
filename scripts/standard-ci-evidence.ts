export const standardCiJobNames = [
  "Node checks / Node checks",
  "Rust checks / Rust checks",
  "Hub Docker image / Hub Docker image",
  "Probe binaries / Probe binary (aarch64-unknown-linux-gnu)",
  "Probe binaries / Probe binary (aarch64-unknown-linux-musl)",
  "Probe binaries / Probe binary (x86_64-unknown-linux-gnu)",
  "Probe binaries / Probe binary (x86_64-unknown-linux-musl)",
] as const;

const standardCiEvents = new Set(["push", "workflow_dispatch"]);
const standardCiJobNameSet = new Set<string>(standardCiJobNames);

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

export function selectStandardCiRun(
  workflowRuns: unknown,
  candidateCommit: string,
): Record<string, unknown> | null {
  if (!Array.isArray(workflowRuns)) return null;

  return workflowRuns.reduce<Record<string, unknown> | null>((latest, run) => {
    if (
      !isObject(run) ||
      !isPositiveSafeInteger(run.id) ||
      run.head_branch !== "main" ||
      run.head_sha !== candidateCommit ||
      !isStandardCiEvent(run.event)
    ) {
      return latest;
    }
    if (!latest || run.id > (latest.id as number)) return run;
    return latest;
  }, null);
}

export function isStandardCiEvent(value: unknown): value is string {
  return typeof value === "string" && standardCiEvents.has(value);
}

export function isSelectedStandardCiRun(
  run: unknown,
  candidateCommit: string,
): run is Record<string, unknown> {
  return (
    isObject(run) &&
    isPositiveSafeInteger(run.id) &&
    typeof run.html_url === "string" &&
    run.html_url.length > 0 &&
    run.head_branch === "main" &&
    run.head_sha === candidateCommit &&
    isStandardCiEvent(run.event) &&
    run.status === "completed" &&
    run.conclusion === "success" &&
    isPositiveSafeInteger(run.run_attempt)
  );
}

export function isStandardCiEvidence(
  evidence: unknown,
  candidateCommit: string,
): boolean {
  return (
    isObject(evidence) &&
    evidence.kind === "enoki-standard-ci-evidence" &&
    evidence.schemaVersion === 2 &&
    evidence.candidateCommit === candidateCommit &&
    isPositiveSafeInteger(evidence.runId) &&
    typeof evidence.runUrl === "string" &&
    evidence.runUrl.length > 0 &&
    isStandardCiEvent(evidence.event) &&
    isPositiveSafeInteger(evidence.runAttempt) &&
    hasExactSuccessfulStandardCiJobs(evidence.jobs)
  );
}

function hasExactSuccessfulStandardCiJobs(jobs: unknown): boolean {
  if (!Array.isArray(jobs) || jobs.length !== standardCiJobNames.length) {
    return false;
  }
  const names = new Set<string>();
  for (const job of jobs) {
    if (
      !isObject(job) ||
      typeof job.name !== "string" ||
      job.conclusion !== "success" ||
      !standardCiJobNameSet.has(job.name) ||
      names.has(job.name)
    ) {
      return false;
    }
    names.add(job.name);
  }
  return names.size === standardCiJobNames.length;
}
