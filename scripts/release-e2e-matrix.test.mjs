import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  supportedHostEnvironments,
  validateSupportedHostMatrix,
} from "./release-e2e-matrix.mjs";

describe("supported Release Test Host matrix", () => {
  it("contains only supported Host capabilities and no candidate-independent scenarios", async () => {
    const matrix = JSON.parse(
      await readFile(new URL("./release-e2e-matrix.json", import.meta.url)),
    );

    expect(validateSupportedHostMatrix(matrix)).toBe(matrix);
    expect(matrix).not.toHaveProperty("scenarios");
    expect(supportedHostEnvironments(matrix)).toEqual([
      expect.objectContaining({
        id: "ubuntu-22.04-x86_64",
        runner: "ubuntu-22.04",
        systemd: "host",
      }),
      expect.objectContaining({
        id: "ubuntu-24.04-x86_64",
        runner: "ubuntu-24.04",
        systemd: "host",
      }),
    ]);
  });

  it("rejects an unsupported Host reference", () => {
    expect(() =>
      validateSupportedHostMatrix(
        matrixFixture({ capabilityId: "ubuntu-99.99-x86_64" }),
      ),
    ).toThrow(/capability is not declared.*ubuntu-99\.99/i);
  });

  it("rejects duplicate Hosts and non-host-systemd adapters", () => {
    const duplicate = matrixFixture();
    duplicate.environments.push({ ...duplicate.environments[0] });
    expect(() => validateSupportedHostMatrix(duplicate)).toThrow(
      /duplicate environment id/i,
    );

    const container = matrixFixture();
    container.providers[0].hostAdapter = "container";
    expect(() => validateSupportedHostMatrix(container)).toThrow(
      /host systemd.*ci adapter/i,
    );
  });

  it("compiles the candidate-bound Scenario Plan before expanding any Host jobs", async () => {
    const workflow = await readFile(
      new URL(
        "../.github/workflows/reusable-build-release-candidate.yml",
        import.meta.url,
      ),
      "utf8",
    );
    const planningJob = workflow.slice(
      workflow.indexOf("  prepare-release-e2e-matrix:"),
      workflow.indexOf("  candidate-release-e2e:"),
    );

    expect(planningJob).toContain("actions/download-artifact@v8");
    expect(planningJob).toContain("candidate/candidate-manifest.json");
    expect(planningJob).toContain("release-scenario-plan.mjs github-actions");
    expect(planningJob.indexOf("actions/download-artifact@v8")).toBeLessThan(
      planningJob.indexOf("release-scenario-plan.mjs github-actions"),
    );
  });

  it("passes only planner-produced cells to the one existing Orchestrator", async () => {
    const workflow = await readFile(
      new URL(
        "../.github/workflows/reusable-build-release-candidate.yml",
        import.meta.url,
      ),
      "utf8",
    );

    expect(workflow).toContain(
      "matrix: ${{ fromJSON(needs.prepare-release-e2e-matrix.outputs.matrix) }}",
    );
    expect(workflow).toContain('--matrix-cell "$MATRIX_CELL"');
    expect(workflow.match(/release-e2e[.]mjs run/g)).toHaveLength(1);
    expect(workflow).not.toContain("continue-on-error:");
  });

  it("validates the plan before journaling and protects provisioning with release", async () => {
    const entrypoint = await readFile(
      new URL("./release-e2e.mjs", import.meta.url),
      "utf8",
    );
    const run = entrypoint.slice(entrypoint.indexOf("async function run("));

    expect(run.indexOf("compileVerifiedReleaseScenarioPlan({")).toBeLessThan(
      run.indexOf("createRunArtifactJournal({"),
    );
    expect(run.indexOf("createRunArtifactJournal({")).toBeLessThan(
      run.indexOf("prepareReleaseScenarioCell({"),
    );
    expect(run).toContain(
      "release: ({ prepared }) => infrastructure.release({ prepared, runId })",
    );
  });
});

function matrixFixture({ capabilityId = "ubuntu-22.04-x86_64" } = {}) {
  return {
    environments: [{ capabilityId, providerId: "github-actions-host-systemd" }],
    providers: [
      {
        capabilities: [
          {
            architecture: "x86_64",
            id: "ubuntu-22.04-x86_64",
            operatingSystem: "ubuntu",
            operatingSystemVersion: "22.04",
            runner: "ubuntu-22.04",
          },
        ],
        hostAdapter: "ci",
        id: "github-actions-host-systemd",
        provider: "github-actions",
        systemd: "host",
      },
    ],
    schemaVersion: 2,
  };
}
