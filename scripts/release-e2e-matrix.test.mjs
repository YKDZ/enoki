import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import {
  createGitHubActionsMatrix,
  expandReleaseE2EMatrix,
  resolveReleaseE2EMatrixCell,
  validateReleaseE2EMatrix,
} from "./release-e2e-matrix.mjs";

const execFileAsync = promisify(execFile);

describe("Release E2E matrix", () => {
  it("expands the declared fresh scenario into stable equal Ubuntu gates", async () => {
    const matrix = JSON.parse(
      await readFile(new URL("./release-e2e-matrix.json", import.meta.url)),
    );

    expect(validateReleaseE2EMatrix(matrix)).toBe(matrix);
    expect(
      expandReleaseE2EMatrix(matrix, {
        scenarioId: "fresh-install-uninstall",
      }),
    ).toEqual([
      {
        architecture: "x86_64",
        cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
        environmentId: "ubuntu-22.04-x86_64",
        hostAdapter: "ci",
        operatingSystem: "ubuntu",
        operatingSystemVersion: "22.04",
        provider: "github-actions",
        runner: "ubuntu-22.04",
        scenarioId: "fresh-install-uninstall",
      },
      {
        architecture: "x86_64",
        cellId: "ubuntu-24.04-x86_64--fresh-install-uninstall",
        environmentId: "ubuntu-24.04-x86_64",
        hostAdapter: "ci",
        operatingSystem: "ubuntu",
        operatingSystemVersion: "24.04",
        provider: "github-actions",
        runner: "ubuntu-24.04",
        scenarioId: "fresh-install-uninstall",
      },
    ]);
  });

  it("expands baseline upgrade as equal isolated gates on every declared Ubuntu Host", async () => {
    const matrix = JSON.parse(
      await readFile(new URL("./release-e2e-matrix.json", import.meta.url)),
    );

    expect(
      expandReleaseE2EMatrix(matrix, {
        scenarioId: "baseline-upgrade-uninstall",
      }),
    ).toEqual([
      expect.objectContaining({
        cellId: "ubuntu-22.04-x86_64--baseline-upgrade-uninstall",
        environmentId: "ubuntu-22.04-x86_64",
        runner: "ubuntu-22.04",
        scenarioId: "baseline-upgrade-uninstall",
      }),
      expect.objectContaining({
        cellId: "ubuntu-24.04-x86_64--baseline-upgrade-uninstall",
        environmentId: "ubuntu-24.04-x86_64",
        runner: "ubuntu-24.04",
        scenarioId: "baseline-upgrade-uninstall",
      }),
    ]);
    expect(createGitHubActionsMatrix(matrix).include).toHaveLength(7);
  });

  it("expands post-replacement Repair as equal isolated gates on every declared Ubuntu Host", async () => {
    const matrix = JSON.parse(
      await readFile(new URL("./release-e2e-matrix.json", import.meta.url)),
    );

    expect(
      expandReleaseE2EMatrix(matrix, {
        scenarioId: "post-replacement-repair-uninstall",
      }),
    ).toEqual([
      expect.objectContaining({
        cellId: "ubuntu-22.04-x86_64--post-replacement-repair-uninstall",
        environmentId: "ubuntu-22.04-x86_64",
        hostAdapter: "ci",
        runner: "ubuntu-22.04",
        scenarioId: "post-replacement-repair-uninstall",
      }),
      expect.objectContaining({
        cellId: "ubuntu-24.04-x86_64--post-replacement-repair-uninstall",
        environmentId: "ubuntu-24.04-x86_64",
        hostAdapter: "ci",
        runner: "ubuntu-24.04",
        scenarioId: "post-replacement-repair-uninstall",
      }),
    ]);
    expect(createGitHubActionsMatrix(matrix).include).toHaveLength(7);
  });

  it("runs Hub Restore exactly once on its explicitly designated stable environment", async () => {
    const matrix = JSON.parse(
      await readFile(new URL("./release-e2e-matrix.json", import.meta.url)),
    );

    expect(
      expandReleaseE2EMatrix(matrix, {
        scenarioId: "hub-restore-compatibility-window",
      }),
    ).toEqual([
      expect.objectContaining({
        cellId: "ubuntu-24.04-x86_64--hub-restore-compatibility-window",
        environmentId: "ubuntu-24.04-x86_64",
        runner: "ubuntu-24.04",
        scenarioId: "hub-restore-compatibility-window",
      }),
    ]);
    expect(createGitHubActionsMatrix(matrix).include).toHaveLength(7);
  });

  it("rejects a designated scenario whose stable environment is not declared", () => {
    expect(() =>
      validateReleaseE2EMatrix(
        declaredMatrix({
          scenarios: [
            {
              designatedEnvironmentId: "ubuntu-24.04-x86_64",
              id: "hub-restore-compatibility-window",
            },
          ],
        }),
      ),
    ).toThrow(/designated environment is not declared.*ubuntu-24\.04/i);
  });

  it("rejects duplicate stable environment and scenario identifiers", () => {
    const environment = declaredEnvironment();
    expect(() =>
      validateReleaseE2EMatrix(
        declaredMatrix({
          environments: [environment, { ...environment }],
        }),
      ),
    ).toThrow(/duplicate environment id.*ubuntu-22\.04-x86_64/i);

    expect(() =>
      validateReleaseE2EMatrix(
        declaredMatrix({
          environments: [environment],
          scenarios: [
            { id: "fresh-install-uninstall" },
            { id: "fresh-install-uninstall" },
          ],
        }),
      ),
    ).toThrow(/duplicate scenario id.*fresh-install-uninstall/i);
  });

  it("rejects malformed provider capabilities and scenario entries", () => {
    expect(() =>
      validateReleaseE2EMatrix(
        declaredMatrix({
          capabilities: [declaredCapability({ architecture: "amd64!" })],
        }),
      ),
    ).toThrow(/capability architecture is invalid/i);

    expect(() =>
      validateReleaseE2EMatrix(
        declaredMatrix({
          scenarios: [{ id: "Fresh Install" }],
        }),
      ),
    ).toThrow(/scenario id is invalid/i);
  });

  it("rejects a declared scenario until the shared orchestrator supports it", () => {
    expect(() =>
      validateReleaseE2EMatrix(
        declaredMatrix({
          scenarios: [{ id: "not-yet-implemented" }],
        }),
      ),
    ).toThrow(/scenario is not supported.*not-yet-implemented/i);
  });

  it("rejects CI provider declarations that are not host-systemd adapters", () => {
    expect(() =>
      validateReleaseE2EMatrix(
        declaredMatrix({
          provider: declaredProvider({
            hostAdapter: "container",
            systemd: "privileged-container",
          }),
        }),
      ),
    ).toThrow(/provider.*host systemd.*ci adapter/i);

    expect(() =>
      validateReleaseE2EMatrix(
        declaredMatrix({
          environments: [
            declaredEnvironment({ capabilityId: "ubuntu-99.99-x86_64" }),
          ],
        }),
      ),
    ).toThrow(/capability is not declared.*ubuntu-99\.99-x86_64/i);
  });

  it("rejects ubuntu-99.99 until its runner capability is declared in central data", () => {
    expect(() =>
      validateReleaseE2EMatrix(
        declaredMatrix({
          environments: [
            declaredEnvironment({ capabilityId: "ubuntu-99.99-x86_64" }),
          ],
        }),
      ),
    ).toThrow(/capability is not declared.*ubuntu-99\.99-x86_64/i);
  });

  it("expands a future OS runner by changing only central matrix data", () => {
    const matrix = declaredMatrix({
      capabilities: [
        declaredCapability(),
        declaredCapability({
          id: "ubuntu-26.04-x86_64",
          operatingSystemVersion: "26.04",
          runner: "ubuntu-26.04",
        }),
      ],
      environments: [
        declaredEnvironment(),
        declaredEnvironment({ capabilityId: "ubuntu-26.04-x86_64" }),
      ],
    });

    expect(
      expandReleaseE2EMatrix(matrix, {
        scenarioId: "fresh-install-uninstall",
      }),
    ).toEqual([
      expect.objectContaining({ runner: "ubuntu-22.04" }),
      expect.objectContaining({
        environmentId: "ubuntu-26.04-x86_64",
        operatingSystemVersion: "26.04",
        runner: "ubuntu-26.04",
      }),
    ]);
  });

  it("resolves a designated gate by stable cell id instead of array order", () => {
    const matrix = declaredMatrix({
      capabilities: [
        declaredCapability(),
        declaredCapability({
          id: "ubuntu-24.04-x86_64",
          operatingSystemVersion: "24.04",
          runner: "ubuntu-24.04",
        }),
      ],
      environments: [
        declaredEnvironment({ capabilityId: "ubuntu-24.04-x86_64" }),
        declaredEnvironment(),
      ],
    });

    expect(
      resolveReleaseE2EMatrixCell(
        matrix,
        "ubuntu-22.04-x86_64--fresh-install-uninstall",
      ),
    ).toMatchObject({
      environmentId: "ubuntu-22.04-x86_64",
      operatingSystemVersion: "22.04",
      scenarioId: "fresh-install-uninstall",
    });
    expect(() => resolveReleaseE2EMatrixCell(matrix, "0")).toThrow(
      /matrix cell is not declared: 0/i,
    );
  });

  it("emits only data-derived fields for the GitHub Actions strategy", () => {
    const matrix = declaredMatrix();

    expect(createGitHubActionsMatrix(matrix)).toEqual({
      include: [
        {
          architecture: "x86_64",
          cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
          environmentId: "ubuntu-22.04-x86_64",
          operatingSystem: "ubuntu",
          operatingSystemVersion: "22.04",
          hostAdapter: "ci",
          provider: "github-actions",
          runner: "ubuntu-22.04",
          scenarioId: "fresh-install-uninstall",
        },
      ],
    });
  });

  it("provides a workflow CLI that validates and emits the selected matrix", async () => {
    const script = fileURLToPath(
      new URL("./release-e2e-matrix.mjs", import.meta.url),
    );
    const matrix = fileURLToPath(
      new URL("./release-e2e-matrix.json", import.meta.url),
    );
    const { stdout } = await execFileAsync(process.execPath, [
      script,
      "github-actions",
      "--matrix",
      matrix,
    ]);

    const cells = JSON.parse(stdout).include;
    expect(cells).toHaveLength(7);
    expect(
      cells.filter(
        (cell) => cell.scenarioId === "hub-restore-compatibility-window",
      ),
    ).toEqual([
      expect.objectContaining({
        cellId: "ubuntu-24.04-x86_64--hub-restore-compatibility-window",
      }),
    ]);
  });

  it("wires every data-derived cell as an equal blocking fresh-VM gate", async () => {
    const workflow = await readFile(
      new URL(
        "../.github/workflows/reusable-build-release-candidate.yml",
        import.meta.url,
      ),
      "utf8",
    );

    expect(workflow).toContain("id: release-e2e-matrix");
    expect(workflow).toContain(
      "matrix: ${{ fromJSON(needs.prepare-release-e2e-matrix.outputs.matrix) }}",
    );
    expect(workflow).toContain("runs-on: ${{ matrix.runner }}");
    expect(workflow).toContain("fail-fast: false");
    expect(workflow).toContain('--host-adapter "$HOST_ADAPTER"');
    expect(workflow).toContain('--matrix-cell "$MATRIX_CELL"');
    expect(workflow).toContain("github.run_attempt");
    expect(workflow).toContain("if: ${{ always() }}");
    expect(workflow).toContain("run-manifest.json");
    expect(workflow).toContain("evidence.json");
    expect(workflow).not.toContain('test -f "release-e2e-evidence/');
    expect(workflow).not.toContain("continue-on-error:");
    expect(workflow).not.toContain("--scenario fresh-install-uninstall");
    expect(workflow).not.toContain("--scenario\n");
    expect(workflow).not.toContain("fresh-install-uninstall");
    expect(workflow).not.toContain("baseline-upgrade-uninstall");
    expect(workflow).not.toContain("post-replacement-repair-uninstall");
    expect(workflow.match(/release-e2e[.]mjs run/g)).toHaveLength(1);
  });
});

function declaredMatrix({
  capabilities = [declaredCapability()],
  environments = [declaredEnvironment()],
  provider = declaredProvider({ capabilities }),
  scenarios = [{ id: "fresh-install-uninstall" }],
} = {}) {
  return {
    environments,
    providers: [provider],
    scenarios,
    schemaVersion: 1,
  };
}

function declaredEnvironment(overrides = {}) {
  return {
    capabilityId: "ubuntu-22.04-x86_64",
    providerId: "github-actions-host-systemd",
    ...overrides,
  };
}

function declaredProvider(overrides = {}) {
  return {
    capabilities: [declaredCapability()],
    hostAdapter: "ci",
    id: "github-actions-host-systemd",
    provider: "github-actions",
    systemd: "host",
    ...overrides,
  };
}

function declaredCapability(overrides = {}) {
  return {
    architecture: "x86_64",
    id: "ubuntu-22.04-x86_64",
    operatingSystem: "ubuntu",
    operatingSystemVersion: "22.04",
    runner: "ubuntu-22.04",
    ...overrides,
  };
}
