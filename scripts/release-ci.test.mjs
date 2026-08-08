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
  it("records a successful standard CI run for the exact candidate commit", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-release-ci-"));
    try {
      const runsPath = path.join(directory, "runs.json");
      const jobsPath = path.join(directory, "jobs.json");
      const outputPath = path.join(directory, "evidence.json");
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
              status: "completed",
            },
          ],
        }),
      );
      await writeFile(
        jobsPath,
        JSON.stringify({
          jobs: [
            { conclusion: "success", name: "Node checks / Node checks" },
            {
              conclusion: "success",
              name: "Hub Docker image / Hub Docker image",
            },
          ],
        }),
      );

      await execFileAsync("node", [
        cli,
        "verify",
        "--commit",
        commit,
        "--jobs",
        jobsPath,
        "--output",
        outputPath,
        "--workflow-runs",
        runsPath,
      ]);

      expect(JSON.parse(await readFile(outputPath, "utf8"))).toEqual({
        candidateCommit: commit,
        jobs: [
          { conclusion: "success", name: "Node checks / Node checks" },
          {
            conclusion: "success",
            name: "Hub Docker image / Hub Docker image",
          },
        ],
        kind: "enoki-standard-ci-evidence",
        runId: 42,
        runUrl: "https://github.example/actions/runs/42",
        schemaVersion: 1,
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
