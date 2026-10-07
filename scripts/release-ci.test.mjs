import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { standardCiJobNames } from "./release-ci-evidence.ts";

const execFileAsync = promisify(execFile);
const cli = "scripts/release-ci.ts";
const commit = "1".repeat(40);

function ciRun({
  conclusion = "success",
  event = "push",
  headBranch = "main",
  headSha = commit,
  id,
  runAttempt = 1,
  status = "completed",
}) {
  return {
    conclusion,
    event,
    head_branch: headBranch,
    head_sha: headSha,
    html_url: `https://github.example/actions/runs/${id}`,
    id,
    run_attempt: runAttempt,
    status,
  };
}

function ciJobs(run, names = standardCiJobNames) {
  return {
    jobs: names.map((name) => ({
      conclusion: "success",
      head_sha: run.head_sha,
      name,
      run_attempt: run.run_attempt,
      run_id: run.id,
      status: "completed",
    })),
  };
}

async function runCli(arguments_) {
  try {
    const { stderr, stdout } = await execFileAsync(process.execPath, [
      cli,
      ...arguments_,
    ]);
    return { exitCode: 0, stderr, stdout };
  } catch (error) {
    return {
      exitCode: error.code ?? 1,
      stderr: error.stderr ?? "",
      stdout: error.stdout ?? "",
    };
  }
}

async function withWorkspace(work) {
  const directory = await mkdtemp(path.join(tmpdir(), "enoki-release-ci-"));
  try {
    return await work({
      evidencePath: path.join(directory, "evidence.json"),
      jobsPath: path.join(directory, "jobs.json"),
      runsPath: path.join(directory, "runs.json"),
    });
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

async function writeRuns(inputs, runs) {
  await writeFile(inputs.runsPath, JSON.stringify({ workflow_runs: runs }));
}

async function selectRun(inputs, candidate = commit) {
  return runCli([
    "select",
    "--commit",
    candidate,
    "--workflow-runs",
    inputs.runsPath,
  ]);
}

async function verifyRun(inputs, jobs, runs, candidate = commit) {
  await writeRuns(inputs, runs);
  await writeFile(inputs.jobsPath, JSON.stringify(jobs));
  return runCli([
    "verify",
    "--commit",
    candidate,
    "--jobs",
    inputs.jobsPath,
    "--output",
    inputs.evidencePath,
    "--workflow-runs",
    inputs.runsPath,
  ]);
}

function expectedEvidence(run) {
  return {
    candidateCommit: run.head_sha,
    event: run.event,
    jobs: standardCiJobNames.map((name) => ({ conclusion: "success", name })),
    kind: "enoki-standard-ci-evidence",
    runAttempt: run.run_attempt,
    runId: run.id,
    runUrl: run.html_url,
    schemaVersion: 2,
  };
}

describe("standard CI release prerequisite", () => {
  it("selects the largest run ID and records its event and current attempt", async () => {
    const selected = ciRun({ id: 43 });
    await withWorkspace(async (inputs) => {
      await writeRuns(inputs, [
        ciRun({ event: "pull_request", headBranch: "afk/topic", id: 90 }),
        ciRun({ headSha: "2".repeat(40), id: 80 }),
        ciRun({ id: 42 }),
        selected,
      ]);
      expect(await selectRun(inputs)).toEqual({
        exitCode: 0,
        stderr: "",
        stdout: "43 1\n",
      });

      const result = await verifyRun(inputs, ciJobs(selected), [
        selected,
        ciRun({ id: 42 }),
      ]);
      expect(result.exitCode).toBe(0);
      expect(JSON.parse(await readFile(inputs.evidencePath, "utf8"))).toEqual(
        expectedEvidence(selected),
      );
    });
  });

  it("accepts the same-workflow manual fallback on its current attempt", async () => {
    const olderGreenPush = ciRun({ id: 51, runAttempt: 2 });
    const fallback = ciRun({
      event: "workflow_dispatch",
      id: 52,
      runAttempt: 3,
    });
    await withWorkspace(async (inputs) => {
      await writeRuns(inputs, [fallback, olderGreenPush]);
      expect(await selectRun(inputs)).toEqual({
        exitCode: 0,
        stderr: "",
        stdout: "52 3\n",
      });

      const result = await verifyRun(inputs, ciJobs(fallback), [
        olderGreenPush,
        fallback,
      ]);
      expect(result).toEqual({ exitCode: 0, stderr: "", stdout: "" });
      expect(JSON.parse(await readFile(inputs.evidencePath, "utf8"))).toEqual(
        expectedEvidence(fallback),
      );
    });
  });

  for (const { conclusion, label, status } of [
    { label: "queued", status: "queued" },
    { label: "in progress", status: "in_progress" },
    { conclusion: "failure", label: "failed", status: "completed" },
    { conclusion: "cancelled", label: "cancelled", status: "completed" },
  ]) {
    it(`does not fall back to an older green run while the newest run is ${label}`, async () => {
      const green = ciRun({ id: 43 });
      const newest = ciRun({
        conclusion: conclusion ?? null,
        id: 44,
        status,
      });
      await withWorkspace(async (inputs) => {
        const result = await verifyRun(inputs, ciJobs(green), [green, newest]);
        expect(result.exitCode).toBe(1);
        expect(result.stderr).toContain(
          "standard CI run https://github.example/actions/runs/44",
        );
      });
    });
  }

  for (const { label, run } of [
    {
      label: "a pull_request run",
      run: ciRun({ event: "pull_request", id: 70 }),
    },
    {
      label: "a run on another branch",
      run: ciRun({ headBranch: "afk/topic", id: 71 }),
    },
    {
      label: "a run for another commit",
      run: ciRun({ headSha: "3".repeat(40), id: 72 }),
    },
  ]) {
    it(`refuses to use ${label} as the candidate standard CI proof`, async () => {
      await withWorkspace(async (inputs) => {
        const result = await verifyRun(inputs, ciJobs(run), [run]);
        expect(result.exitCode).toBe(1);
        expect(result.stderr).toContain(
          "standard CI has no push or workflow_dispatch run for candidate commit",
        );
      });
    });
  }

  const attempt = ciRun({ id: 45, runAttempt: 2 });
  for (const { jobs, label, reason } of [
    {
      jobs: (all) => all.slice(1),
      label: "omits one check",
      reason: "standard CI jobs are not the exact seven checks",
    },
    {
      jobs: (all) => [...all, all[0]],
      label: "duplicates one check",
      reason: "standard CI jobs are not the exact seven checks",
    },
    {
      jobs: (all) => [
        ...all,
        { ...all[0], name: "Extra checks / Extra check" },
      ],
      label: "adds an unrelated check",
      reason: "standard CI jobs are not the exact seven checks",
    },
    {
      jobs: (all) =>
        all.map((job, index) =>
          index === 0 ? { ...job, conclusion: "failure" } : job,
        ),
      label: "reports one check as failed",
      reason:
        "standard CI job Hub Docker image / Hub Docker image is completed/failure",
    },
    {
      jobs: (all) =>
        all.map((job, index) =>
          index === 0
            ? { ...job, conclusion: null, status: "in_progress" }
            : job,
        ),
      label: "reports one check as still running",
      reason:
        "standard CI job Hub Docker image / Hub Docker image is in_progress/null",
    },
  ]) {
    it(`rejects the current attempt that ${label}`, async () => {
      await withWorkspace(async (inputs) => {
        const result = await verifyRun(
          inputs,
          { jobs: jobs(ciJobs(attempt).jobs) },
          [attempt],
        );
        expect(result.exitCode).toBe(1);
        expect(result.stderr).toContain(reason);
      });
    });
  }

  for (const { jobs, label } of [
    {
      jobs: (all) => all.map((job) => ({ ...job, run_id: job.run_id + 1 })),
      label: "belongs to another run",
    },
    {
      jobs: (all) =>
        all.map((job) => ({ ...job, run_attempt: job.run_attempt - 1 })),
      label: "belongs to a previous attempt",
    },
    {
      jobs: (all) => all.map((job) => ({ ...job, head_sha: "4".repeat(40) })),
      label: "names another candidate commit",
    },
    {
      jobs: (all) =>
        all.map((job) => ({
          conclusion: job.conclusion,
          name: job.name,
          status: job.status,
        })),
      label: "carries no run identity",
    },
  ]) {
    it(`rejects current-attempt jobs that ${label}`, async () => {
      await withWorkspace(async (inputs) => {
        const result = await verifyRun(
          inputs,
          { jobs: jobs(ciJobs(attempt).jobs) },
          [attempt],
        );
        expect(result.exitCode).toBe(1);
        expect(result.stderr).toContain("is not bound to run 45 attempt 2");
      });
    });
  }

  it("rejects a candidate commit that is not a full object ID", async () => {
    const run = ciRun({ id: 46 });
    await withWorkspace(async (inputs) => {
      const result = await verifyRun(inputs, ciJobs(run), [run], "0123456");
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain(
        "commit must be a full lowercase 40-character object ID",
      );
    });
  });
});
