import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const cli = "scripts/release-ci.mjs";
const commit = "1".repeat(40);

describe("standard CI release prerequisite", () => {
  it("records a manually dispatched current successful attempt for the exact candidate", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-release-ci-"));
    try {
      const runsPath = path.join(directory, "runs.json");
      const jobsPath = path.join(directory, "jobs.json");
      const outputPath = path.join(directory, "evidence.json");
      const selectedRunPath = path.join(directory, "selected-run.json");
      await writeFile(
        runsPath,
        JSON.stringify({
          workflow_runs: [
            {
              conclusion: "success",
              event: "workflow_dispatch",
              head_branch: "main",
              head_sha: commit,
              html_url: "https://github.example/actions/runs/43",
              id: 43,
              run_attempt: 2,
              status: "completed",
            },
          ],
        }),
      );
      await writeFile(jobsPath, JSON.stringify({ jobs: standardCiJobs() }));

      await selectStandardCiRun({
        commit,
        outputPath: selectedRunPath,
        runsPath,
      });
      await verifyStandardCiRun({
        commit,
        jobsPath,
        outputPath,
        selectedRunPath,
      });

      expect(JSON.parse(await readFile(outputPath, "utf8"))).toEqual({
        candidateCommit: commit,
        event: "workflow_dispatch",
        jobs: standardCiJobs(),
        kind: "enoki-standard-ci-evidence",
        runAttempt: 2,
        runId: 43,
        runUrl: "https://github.example/actions/runs/43",
        schemaVersion: 2,
      });
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("selects the numeric newest matching run before evaluating its result", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-release-ci-"));
    try {
      const runsPath = path.join(directory, "runs.json");
      const outputPath = path.join(directory, "selected-run.json");
      const oldStuckRun = {
        conclusion: null,
        event: "push",
        head_branch: "main",
        head_sha: commit,
        html_url: "https://github.example/actions/runs/42",
        id: 42,
        run_attempt: 1,
        status: "queued",
      };
      const latestManualRun = {
        conclusion: "success",
        event: "workflow_dispatch",
        head_branch: "main",
        head_sha: commit,
        html_url: "https://github.example/actions/runs/43",
        id: 43,
        run_attempt: 2,
        status: "completed",
      };
      await writeFile(
        runsPath,
        JSON.stringify({ workflow_runs: [latestManualRun, oldStuckRun] }),
      );

      await selectStandardCiRun({ commit, outputPath, runsPath });
      expect(JSON.parse(await readFile(outputPath, "utf8"))).toEqual(
        latestManualRun,
      );

      await writeFile(
        runsPath,
        JSON.stringify({
          workflow_runs: [
            oldStuckRun,
            { ...latestManualRun, conclusion: "failure" },
          ],
        }),
      );
      await expect(
        selectStandardCiRun({ commit, outputPath, runsPath }),
      ).rejects.toThrow(
        "selected standard CI run is not a successful current attempt",
      );
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("rejects invalid selected attempts and incomplete standard CI jobs", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-release-ci-"));
    try {
      const runsPath = path.join(directory, "runs.json");
      const jobsPath = path.join(directory, "jobs.json");
      const outputPath = path.join(directory, "evidence.json");
      const selectedRunPath = path.join(directory, "selected-run.json");
      const selectedRun = {
        conclusion: "success",
        event: "push",
        head_branch: "main",
        head_sha: commit,
        html_url: "https://github.example/actions/runs/42",
        id: 42,
        run_attempt: 1,
        status: "completed",
      };
      await writeFile(
        runsPath,
        JSON.stringify({ workflow_runs: [selectedRun] }),
      );
      await selectStandardCiRun({
        commit,
        outputPath: selectedRunPath,
        runsPath,
      });

      for (const jobs of [
        standardCiJobs().slice(1),
        [...standardCiJobs(), standardCiJobs()[0]],
        [
          ...standardCiJobs(),
          { conclusion: "success", name: "unrelated check" },
        ],
        standardCiJobs().map((job, index) =>
          index === 0 ? { ...job, conclusion: "failure" } : job,
        ),
      ]) {
        await writeFile(jobsPath, JSON.stringify({ jobs }));
        await expect(
          verifyStandardCiRun({
            commit,
            jobsPath,
            outputPath,
            selectedRunPath,
          }),
        ).rejects.toThrow("standard CI evidence is incomplete or invalid");
      }

      await writeFile(
        selectedRunPath,
        JSON.stringify({ ...selectedRun, run_attempt: 0 }),
      );
      await expect(
        verifyStandardCiRun({
          commit,
          jobsPath,
          outputPath,
          selectedRunPath,
        }),
      ).rejects.toThrow(
        "selected standard CI run is not a successful current attempt",
      );
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("records a successful standard CI run for the exact candidate commit", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-release-ci-"));
    try {
      const runsPath = path.join(directory, "runs.json");
      const jobsPath = path.join(directory, "jobs.json");
      const outputPath = path.join(directory, "evidence.json");
      const selectedRunPath = path.join(directory, "selected-run.json");
      await writeFile(
        runsPath,
        JSON.stringify({
          workflow_runs: [
            {
              conclusion: "success",
              event: "push",
              head_branch: "main",
              head_sha: commit,
              html_url: "https://github.example/actions/runs/42",
              id: 42,
              run_attempt: 1,
              status: "completed",
            },
          ],
        }),
      );
      await writeFile(jobsPath, JSON.stringify({ jobs: standardCiJobs() }));

      await selectStandardCiRun({
        commit,
        outputPath: selectedRunPath,
        runsPath,
      });
      await verifyStandardCiRun({
        commit,
        jobsPath,
        outputPath,
        selectedRunPath,
      });

      expect(JSON.parse(await readFile(outputPath, "utf8"))).toEqual({
        candidateCommit: commit,
        event: "push",
        jobs: standardCiJobs(),
        kind: "enoki-standard-ci-evidence",
        runAttempt: 1,
        runId: 42,
        runUrl: "https://github.example/actions/runs/42",
        schemaVersion: 2,
      });
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("blocks release construction on the existing standard CI run for the same SHA", async () => {
    const workflow = await readFile(
      ".github/workflows/reusable-build-release-candidate.yml",
      "utf8",
    );
    const preflight = workflow.slice(
      workflow.indexOf("  validate-release-configuration:"),
      workflow.indexOf("  resolve-release-baseline:"),
    );

    expect(preflight).toContain("actions/workflows/ci.yml/runs");
    expect(preflight).toContain("release-ci.mjs select");
    expect(preflight).toContain("release-ci.mjs verify");
    expect(preflight).toContain('--commit "$CANDIDATE_COMMIT"');
    expect(preflight).toContain(
      "name: candidate-standard-ci-${{ github.run_id }}",
    );
    expect(preflight).not.toContain(
      "uses: ./.github/workflows/reusable-node-checks.yml",
    );
    expect(preflight).not.toContain(
      "uses: ./.github/workflows/reusable-rust-checks.yml",
    );
    expect(workflow).toContain("standardCi:");
    expect(workflow).toContain("standard-ci-evidence.json");
  });
});

async function selectStandardCiRun({ commit, outputPath, runsPath }) {
  await execFileAsync("node", [
    cli,
    "select",
    "--commit",
    commit,
    "--output",
    outputPath,
    "--workflow-runs",
    runsPath,
  ]);
}

async function verifyStandardCiRun({
  commit,
  jobsPath,
  outputPath,
  selectedRunPath,
}) {
  await execFileAsync("node", [
    cli,
    "verify",
    "--commit",
    commit,
    "--jobs",
    jobsPath,
    "--output",
    outputPath,
    "--selected-run",
    selectedRunPath,
  ]);
}

function standardCiJobs() {
  return [
    { conclusion: "success", name: "Node checks / Node checks" },
    { conclusion: "success", name: "Rust checks / Rust checks" },
    { conclusion: "success", name: "Hub Docker image / Hub Docker image" },
    {
      conclusion: "success",
      name: "Probe binaries / Probe binary (aarch64-unknown-linux-gnu)",
    },
    {
      conclusion: "success",
      name: "Probe binaries / Probe binary (aarch64-unknown-linux-musl)",
    },
    {
      conclusion: "success",
      name: "Probe binaries / Probe binary (x86_64-unknown-linux-gnu)",
    },
    {
      conclusion: "success",
      name: "Probe binaries / Probe binary (x86_64-unknown-linux-musl)",
    },
  ];
}
