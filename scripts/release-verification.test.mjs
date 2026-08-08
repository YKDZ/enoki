import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import {
  createMatrixGateResult,
  createReleaseVerificationSummary,
  createUiGateResult,
  createVerifyOnlyReleaseSummary,
  renderVerifyOnlyReleaseSummaryMarkdown,
} from "./release-verification-lib.mjs";

const execFileAsync = promisify(execFile);

describe("verify-only release workflow", () => {
  it("keeps the fresh candidate gate non-publishing for both manual modes", async () => {
    const [entrypoint, candidateWorkflow] = await Promise.all([
      readFile(".github/workflows/release.yml", "utf8"),
      readFile(
        ".github/workflows/reusable-build-release-candidate.yml",
        "utf8",
      ),
    ]);

    expect(entrypoint).toContain("workflow_dispatch:");
    expect(entrypoint).not.toMatch(/^  push:/m);
    expect(entrypoint).toMatch(/\n      commit:\n/);
    expect(entrypoint).toMatch(/\n      version:\n/);
    expect(entrypoint).toMatch(
      /\n      mode:\n[\s\S]*?type: choice[\s\S]*?options:\n\s+- verify-only\n\s+- publish/,
    );
    expect(entrypoint).toContain(
      "uses: ./.github/workflows/reusable-build-release-candidate.yml",
    );
    expect(entrypoint).toContain("mode: ${{ inputs.mode }}");
    expect(entrypoint).toContain("group: enoki-release-global");
    const verificationJob = entrypoint.slice(
      entrypoint.indexOf("  verify-candidate:"),
      entrypoint.indexOf("  publish-candidate:"),
    );
    expect(verificationJob).not.toMatch(/contents: write|packages: write/);

    expect(candidateWorkflow).toContain("workflow_call:");
    expect(candidateWorkflow).not.toContain("workflow_dispatch:");
    expect(candidateWorkflow).toMatch(/\n      mode:\n/);
    expect(candidateWorkflow).not.toMatch(
      /contents: write|packages: write|gh release|git tag|docker push|--push|latest/,
    );
  });

  it("keeps every private artifact handoff run-scoped and resumable across failed-job attempts", async () => {
    const [candidateWorkflow, probeWorkflow, publicationWorkflow] =
      await Promise.all([
        readFile(
          ".github/workflows/reusable-build-release-candidate.yml",
          "utf8",
        ),
        readFile(".github/workflows/reusable-build-probe.yml", "utf8"),
        readFile(
          ".github/workflows/reusable-publish-release-candidate.yml",
          "utf8",
        ),
      ]);
    const run = "${{ github.run_id }}";

    expect(probeWorkflow).toContain(
      `name: enoki-probe-${"${{ matrix.target }}"}-${run}`,
    );
    expect(probeWorkflow).toContain("overwrite: true");
    expect(candidateWorkflow).toContain(`pattern: enoki-probe-*-${run}`);
    for (const name of [
      "candidate-release-baseline",
      "candidate-unsigned-probe-assets",
      "candidate-probe-assets",
      "candidate-hub-oci",
    ]) {
      expect(
        candidateWorkflow.match(
          new RegExp(
            `(?:name|pattern): ${name.replaceAll("-", "[-]")}[-]\\$\\{\\{ github[.]run_id \\}\\}`,
            "g",
          ),
        )?.length,
        name,
      ).toBeGreaterThanOrEqual(2);
    }
    expect(candidateWorkflow).toContain(
      `name: release-e2e-${"${{ matrix.cellId }}"}-${run}`,
    );
    expect(candidateWorkflow).toContain(`pattern: release-e2e-*-${run}`);
    expect(candidateWorkflow).toContain(`name: release-ui-contract-${run}`);
    expect(candidateWorkflow).toContain(
      `artifact-name=enoki-release-candidate-${"${CANDIDATE_VERSION}"}-${"${GITHUB_RUN_ID}"}`,
    );
    expect(candidateWorkflow).toContain(
      `artifact-name=release-verification-summary-${"${GITHUB_RUN_ID}"}`,
    );
    expect(candidateWorkflow).toContain("overwrite: true");
    expect(publicationWorkflow).toContain(
      `name: release-publication-summary-${run}`,
    );
    expect(publicationWorkflow).toContain("overwrite: true");

    for (const workflow of [
      candidateWorkflow,
      probeWorkflow,
      publicationWorkflow,
    ]) {
      const artifactLines = workflow
        .split("\n")
        .filter((line) =>
          /(?:name|pattern): .*artifact|(?:name|pattern): (?:candidate-|enoki-probe-|release-)/.test(
            line,
          ),
        );
      expect(artifactLines.join("\n")).not.toContain(
        "${{ github.run_attempt }}",
      );
    }
  });

  it("wires one private candidate through every blocking gate and a fail-closed finalizer", async () => {
    const workflow = await readFile(
      ".github/workflows/reusable-build-release-candidate.yml",
      "utf8",
    );
    const signingJob = workflow.slice(
      workflow.indexOf("  sign-probe-assets:"),
      workflow.indexOf("  build-hub-oci:"),
    );
    const downstream = workflow.slice(workflow.indexOf("  build-hub-oci:"));

    expect(workflow.match(/release-baseline[.]mjs resolve/g)).toHaveLength(1);
    expect(workflow.match(/release-candidate[.]mjs assemble/g)).toHaveLength(1);
    expect(workflow).toContain("id: scenario");
    expect(workflow).toContain("id: verify-clean");
    expect(workflow).toContain("record-matrix-gate");
    expect(workflow).toContain("id: candidate-playwright");
    expect(workflow).toContain("record-ui-gate");
    expect(workflow).toContain("  finalize-verification:");
    expect(workflow).toContain("if: ${{ always() }}");
    expect(workflow).toContain("release-verification.mjs summarize");
    expect(workflow).toContain("release-verification.mjs assert-verified");
    expect(workflow).toContain("release-verification-summary.json");
    expect(workflow).toContain("$GITHUB_STEP_SUMMARY");
    expect(workflow).toContain("pattern: release-e2e-*");
    expect(workflow).toContain("release-ui-contract-${{ github.run_id }}");
    expect(workflow).not.toContain("continue-on-error:");

    const finalizer = workflow.slice(
      workflow.indexOf("  finalize-verification:"),
    );
    for (const dependency of [
      "validate-candidate-inputs",
      "resolve-release-baseline",
      "build-probe",
      "prepare-unsigned-probe-assets",
      "sign-probe-assets",
      "build-hub-oci",
      "assemble-candidate",
      "prepare-release-e2e-matrix",
      "candidate-release-e2e",
      "candidate-ui-contract",
    ]) {
      expect(finalizer).toContain(dependency);
    }
    expect(finalizer).toContain("component-results.json");
    expect(finalizer).toContain("--requested-commit");
    expect(finalizer).toContain("--requested-version");
    expect(finalizer).toContain("--requested-mode");
    expect(finalizer).toMatch(
      /name: Generate the authoritative candidate verification summary\n\s+if: \$\{\{ always\(\) \}\}/,
    );
    expect(finalizer).toMatch(
      /name: Upload the authoritative verification evidence\n\s+if: \$\{\{ always\(\) \}\}/,
    );
    expect(
      finalizer.indexOf("Upload the authoritative verification evidence"),
    ).toBeLessThan(
      finalizer.indexOf("Require every verification gate to have succeeded"),
    );

    expect(signingJob).toContain("ENOKI_PROBE_ASSET_SIGNING_KEY_PEM");
    expect(downstream).not.toContain("ENOKI_PROBE_ASSET_SIGNING_KEY_PEM");
    expect(workflow).toContain("permissions:\n  contents: read");
    expect(workflow).toContain("attestations: write");
    expect(workflow).toContain("id-token: write");
  });

  it("summarizes every candidate gate without making verification promotable", async () => {
    const matrix = JSON.parse(
      await readFile("scripts/release-e2e-matrix.json", "utf8"),
    );
    const candidateManifest = releaseCandidateManifest();
    const hostGates = expectedHostGateResults(matrix, candidateManifest);
    const uiGate = {
      artifactName: "release-ui-contract-12345-1",
      candidate: candidateManifest.candidate,
      outcome: "succeeded",
    };

    const summary = createVerifyOnlyReleaseSummary({
      artifactIndex: releaseArtifactIndex(hostGates, uiGate),
      candidateManifest,
      gateResults: {
        candidateBuild: "success",
        matrixExpansion: "success",
        matrixJob: "success",
        uiJob: "success",
      },
      hostGates,
      matrix,
      run: {
        attempt: 1,
        id: "12345",
        url: "https://github.com/YKDZ/enoki/actions/runs/12345",
      },
      uiGate,
    });

    expect(summary).toMatchObject({
      candidate: candidateManifest.candidate,
      freshCandidateRequiredForPublish: true,
      hub: candidateManifest.hub,
      kind: "enoki-verify-only-summary",
      mode: "verify-only",
      probeAssetSet: candidateManifest.probeAssetSet,
      promotable: false,
      releaseBaseline: candidateManifest.releaseBaseline,
      schemaVersion: 2,
      verified: true,
    });
    expect(summary.gates.hostScenarios).toHaveLength(7);
    expect(
      summary.gates.hostScenarios.filter(
        (gate) => gate.scenarioId === "hub-restore-compatibility-window",
      ),
    ).toEqual([
      expect.objectContaining({
        cellId: "ubuntu-24.04-x86_64--hub-restore-compatibility-window",
        outcome: "succeeded",
      }),
    ]);
    expect(summary.gates.hostScenarios.every((gate) => gate.evidenceUrl)).toBe(
      true,
    );
    expect(summary.gates.candidateUiContract.evidenceUrl).toBe(
      "https://github.com/YKDZ/enoki/actions/runs/12345/artifacts/9000",
    );
  });

  it("binds publish verification to the fresh candidate in the current run", async () => {
    const matrix = JSON.parse(
      await readFile("scripts/release-e2e-matrix.json", "utf8"),
    );
    const candidateManifest = releaseCandidateManifest();
    const hostGates = expectedHostGateResults(matrix, candidateManifest);
    const run = {
      attempt: 4,
      id: "98765",
      url: "https://github.com/YKDZ/enoki/actions/runs/98765/attempts/4",
    };
    const summary = createReleaseVerificationSummary({
      candidateManifest,
      gateResults: {
        candidateBuild: "success",
        matrixExpansion: "success",
        matrixJob: "success",
        uiJob: "success",
      },
      hostGates,
      matrix,
      requested: { ...candidateManifest.candidate, mode: "publish" },
      run,
      uiGate: {
        artifactName: "release-ui-contract-98765-4",
        candidate: candidateManifest.candidate,
        outcome: "succeeded",
      },
    });

    expect(summary).toMatchObject({
      candidate: candidateManifest.candidate,
      freshCandidateRequiredForPublish: true,
      kind: "enoki-publish-verification-summary",
      mode: "publish",
      promotable: false,
      run,
      verified: true,
    });
  });

  it("emits a schema-valid failed attempt when an early component prevents candidate assembly", async () => {
    const matrix = JSON.parse(
      await readFile("scripts/release-e2e-matrix.json", "utf8"),
    );
    const requested = {
      commit: "0123456789abcdef0123456789abcdef01234567",
      mode: "verify-only",
      version: "v1.2.3",
    };
    const componentResults = {
      candidateAssembly: "skipped",
      candidateUiContract: "skipped",
      hubOciBuild: "skipped",
      hostMatrix: "skipped",
      inputValidation: "success",
      matrixExpansion: "skipped",
      probeBuild: "cancelled",
      probePreparation: "skipped",
      probeSigning: "skipped",
      releaseBaseline: "failure",
    };

    const summary = createVerifyOnlyReleaseSummary({
      candidateManifest: null,
      componentResults,
      hostGates: [],
      matrix,
      requested,
      run: {
        attempt: 2,
        id: "12345",
        url: "https://github.com/YKDZ/enoki/actions/runs/12345/attempts/2",
      },
      uiGate: null,
    });

    expect(summary).toMatchObject({
      candidate: null,
      componentResults,
      freshCandidateRequiredForPublish: true,
      hub: null,
      kind: "enoki-verify-only-summary",
      mode: "verify-only",
      probeAssetSet: null,
      promotable: false,
      releaseBaseline: null,
      requested,
      schemaVersion: 2,
      verified: false,
    });
    expect(summary.missingIdentities).toEqual([
      "candidate-manifest",
      "hub-oci",
      "probe-asset-set",
      "release-baseline",
    ]);
    expect(summary.failureReasons).toEqual(
      expect.arrayContaining([
        "releaseBaseline: failure",
        "probeBuild: cancelled",
        "Candidate Manifest identity is missing",
      ]),
    );
    expect(summary.gates.hostScenarios).toHaveLength(7);
    expect(
      summary.gates.hostScenarios.every((gate) => gate.outcome === "missing"),
    ).toBe(true);
  });

  it("writes and renders a failed attempt before assert-verified rejects it when artifacts are absent", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-attempt-summary-"),
    );
    const componentResultsPath = path.join(workDir, "component-results.json");
    const summaryPath = path.join(workDir, "summary.json");
    const markdownPath = path.join(workDir, "summary.md");
    await writeFile(
      componentResultsPath,
      `${JSON.stringify({
        candidateAssembly: "skipped",
        candidateUiContract: "skipped",
        hubOciBuild: "skipped",
        hostMatrix: "skipped",
        inputValidation: "failure",
        matrixExpansion: "skipped",
        probeBuild: "skipped",
        probePreparation: "skipped",
        probeSigning: "skipped",
        releaseBaseline: "skipped",
      })}\n`,
    );

    try {
      await execFileAsync(process.execPath, [
        "scripts/release-verification.mjs",
        "summarize",
        "--candidate-dir",
        path.join(workDir, "missing-candidate"),
        "--release-baseline-dir",
        path.join(workDir, "missing-baseline"),
        "--probe-assets-dir",
        path.join(workDir, "missing-probe-assets"),
        "--hub-oci-dir",
        path.join(workDir, "missing-hub-oci"),
        "--matrix",
        "scripts/release-e2e-matrix.json",
        "--matrix-evidence-root",
        path.join(workDir, "missing-host-evidence"),
        "--ui-gate",
        path.join(workDir, "missing-ui-gate.json"),
        "--component-results",
        componentResultsPath,
        "--artifact-index",
        path.join(workDir, "missing-artifact-index.json"),
        "--requested-commit",
        "not-a-valid-commit",
        "--requested-version",
        "v1.invalid",
        "--requested-mode",
        "verify-only",
        "--run-id",
        "321",
        "--run-attempt",
        "3",
        "--run-url",
        "https://github.com/YKDZ/enoki/actions/runs/321/attempts/3",
        "--output",
        summaryPath,
        "--markdown",
        markdownPath,
      ]);

      const summary = JSON.parse(await readFile(summaryPath, "utf8"));
      expect(summary).toMatchObject({
        requested: {
          commit: "not-a-valid-commit",
          mode: "verify-only",
          version: "v1.invalid",
        },
        schemaVersion: 2,
        verified: false,
      });
      expect(summary.failureReasons.join("\n")).toContain("Candidate Manifest");
      await expect(
        execFileAsync(process.execPath, [
          "scripts/release-verification.mjs",
          "assert-verified",
          "--summary",
          summaryPath,
        ]),
      ).rejects.toMatchObject({ code: 1 });
      expect(await readFile(markdownPath, "utf8")).toContain(
        "not-a-valid-commit",
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("fails closed for any failed, canceled, skipped, missing, or mismatched required gate", async () => {
    const matrix = JSON.parse(
      await readFile("scripts/release-e2e-matrix.json", "utf8"),
    );
    const candidateManifest = releaseCandidateManifest();
    const valid = {
      candidateManifest,
      gateResults: {
        candidateBuild: "success",
        matrixExpansion: "success",
        matrixJob: "success",
        uiJob: "success",
      },
      hostGates: expectedHostGateResults(matrix, candidateManifest),
      matrix,
      run: {
        attempt: 1,
        id: "12345",
        url: "https://github.com/YKDZ/enoki/actions/runs/12345",
      },
      uiGate: {
        artifactName: "release-ui-contract-12345-1",
        candidate: candidateManifest.candidate,
        outcome: "succeeded",
      },
    };

    for (const jobOutcome of ["failure", "cancelled", "skipped"]) {
      expect(
        createVerifyOnlyReleaseSummary({
          ...valid,
          gateResults: { ...valid.gateResults, uiJob: jobOutcome },
        }).verified,
      ).toBe(false);
    }
    expect(
      createVerifyOnlyReleaseSummary({
        ...valid,
        hostGates: valid.hostGates.slice(1),
      }).verified,
    ).toBe(false);
    expect(
      createVerifyOnlyReleaseSummary({
        ...valid,
        hostGates: [...valid.hostGates, valid.hostGates[0]],
      }).verified,
    ).toBe(false);
    expect(
      createVerifyOnlyReleaseSummary({
        ...valid,
        uiGate: {
          ...valid.uiGate,
          candidate: { ...candidateManifest.candidate, version: "v9.9.9" },
        },
      }).verified,
    ).toBe(false);
    expect(
      createVerifyOnlyReleaseSummary({
        ...valid,
        uiGate: { ...valid.uiGate, artifactName: null },
      }).verified,
    ).toBe(false);
    expect(
      createVerifyOnlyReleaseSummary({
        ...valid,
        hostGates: [
          { ...valid.hostGates[0], artifactName: null },
          ...valid.hostGates.slice(1),
        ],
      }).verified,
    ).toBe(false);
  });

  it("accepts skipped baseline-dependent gates only for a validated first formal release", async () => {
    const matrix = JSON.parse(
      await readFile("scripts/release-e2e-matrix.json", "utf8"),
    );
    const candidateManifest = releaseCandidateManifest({
      firstFormalRelease: true,
    });
    const hostGates = expectedHostGateResults(matrix, candidateManifest).map(
      (gate) =>
        gate.scenarioId === "fresh-install-uninstall"
          ? gate
          : {
              ...gate,
              evidenceOutcome: "skipped",
              outcome: "skipped",
            },
    );
    const summary = createVerifyOnlyReleaseSummary({
      candidateManifest,
      gateResults: {
        candidateBuild: "success",
        matrixExpansion: "success",
        matrixJob: "success",
        uiJob: "success",
      },
      hostGates,
      matrix,
      run: {
        attempt: 1,
        id: "12345",
        url: "https://github.com/YKDZ/enoki/actions/runs/12345",
      },
      uiGate: {
        artifactName: "release-ui-contract-12345-1",
        candidate: candidateManifest.candidate,
        outcome: "succeeded",
      },
    });

    expect(summary.verified).toBe(true);
    expect(
      summary.gates.hostScenarios.filter(
        (gate) => gate.expectedOutcome === "skipped",
      ),
    ).toHaveLength(5);
    expect(
      createVerifyOnlyReleaseSummary({
        candidateManifest: releaseCandidateManifest(),
        gateResults: {
          candidateBuild: "success",
          matrixExpansion: "success",
          matrixJob: "success",
          uiJob: "success",
        },
        hostGates,
        matrix,
        run: summary.run,
        uiGate: {
          artifactName: "release-ui-contract-12345-1",
          candidate: releaseCandidateManifest().candidate,
          outcome: "succeeded",
        },
      }).verified,
    ).toBe(false);
  });

  it("records a Host matrix cell from lifecycle evidence and both non-retried steps", () => {
    const candidate = releaseCandidateManifest().candidate;
    const succeeded = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--fresh-install-uninstall-1",
      candidate,
      cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
      evidence: successfulHostEvidence("fresh-install-uninstall", candidate),
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });

    expect(succeeded).toMatchObject({
      candidate,
      evidenceOutcome: "succeeded",
      kind: "enoki-release-e2e-gate",
      outcome: "succeeded",
      scenarioId: "fresh-install-uninstall",
      scenarioStepOutcome: "success",
      schemaVersion: 1,
      verifyCleanStepOutcome: "success",
    });
    expect(
      createMatrixGateResult({
        ...succeeded,
        evidence: successfulHostEvidence("fresh-install-uninstall", candidate),
        scenarioOutcome: "success",
        verifyCleanOutcome: "failure",
      }).outcome,
    ).toBe("failed");
  });

  it.each([
    ["fresh-install-uninstall", "hostBoundary"],
    ["baseline-upgrade-uninstall", "upgradeOperationTimeline"],
    ["post-replacement-repair-uninstall", "boundaryEvidenceValidation"],
    ["hub-restore-compatibility-window", "snapshot"],
  ])(
    "fails closed when %s omits required %s evidence",
    (scenario, missingField) => {
      const candidate = releaseCandidateManifest().candidate;
      const evidence = successfulHostEvidence(scenario, candidate);
      delete evidence[missingField];

      const gate = createMatrixGateResult({
        artifactName: `release-e2e-ubuntu-24.04-x86_64--${scenario}-1`,
        candidate,
        cellId: `ubuntu-24.04-x86_64--${scenario}`,
        evidence,
        scenarioOutcome: "success",
        verifyCleanOutcome: "success",
      });

      expect(gate.outcome).toBe("failed");
      expect(gate.evidenceValidationErrors).toContain(
        `missing ${missingField}`,
      );
    },
  );

  it("fails closed when a succeeded Host scenario lacks uninstall residue or cleanup proof", () => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    evidence.uninstall.hubSoftDeleted = false;
    evidence.uninstall.hostCompletion.inventory.accounts.user = true;
    evidence.cleanup.environment.clean = false;

    const gate = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--fresh-install-uninstall-1",
      candidate,
      cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
      evidence,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });

    expect(gate.outcome).toBe("failed");
    expect(gate.evidenceValidationErrors).toEqual(
      expect.arrayContaining([
        "Hub Host was not soft-deleted",
        "Host uninstall inventory contains residue",
        "environment cleanup was not clean",
      ]),
    );
  });

  it("rejects fresh evidence made only of non-empty containers without business semantics", () => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    evidence.auditLog = {};
    evidence.host = {};
    evidence.hostBoundary = {};
    evidence.metrics = [{}, {}];
    evidence.probeConfiguration = {};

    const gate = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--fresh-install-uninstall-1",
      candidate,
      cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
      evidence,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });

    expect(gate.outcome).toBe("failed");
    expect(gate.evidenceValidationErrors).toEqual(
      expect.arrayContaining([
        "fresh Host Profile is invalid",
        "fresh reporting metrics are incomplete",
        "Probe Configuration round-trip is invalid",
        "lifecycle Audit Log is invalid",
        "Host installation boundary is invalid",
      ]),
    );
  });

  it.each([
    [
      "baseline-upgrade-uninstall",
      (evidence) => {
        evidence.candidateHost = {
          hostProfile: { probeVersion: "1.2.3" },
          id: 7,
          status: "online",
        };
      },
      "Candidate Host Profile is invalid",
    ],
    [
      "post-replacement-repair-uninstall",
      (evidence) => {
        evidence.repair = {
          probeId: "some-probe",
          repairedVersion: "9.9.9",
        };
      },
      "Repair completion is incomplete",
    ],
    [
      "hub-restore-compatibility-window",
      (evidence) => {
        evidence.reporting.restoredBaselineHub = {
          host: { id: 7, status: "online" },
          metrics: [{ sequence: 3 }, { sequence: 4 }],
        };
      },
      "Candidate-to-Baseline Host reporting is invalid",
    ],
  ])(
    "rejects semantically meaningless non-empty %s evidence",
    (scenario, corrupt, expectedError) => {
      const candidate = releaseCandidateManifest().candidate;
      const evidence = successfulHostEvidence(scenario, candidate);
      corrupt(evidence);

      const gate = createMatrixGateResult({
        artifactName: `release-e2e-ubuntu-24.04-x86_64--${scenario}-1`,
        candidate,
        cellId: `ubuntu-24.04-x86_64--${scenario}`,
        evidence,
        scenarioOutcome: "success",
        verifyCleanOutcome: "success",
      });

      expect(gate.outcome).toBe("failed");
      expect(gate.evidenceValidationErrors).toContain(expectedError);
    },
  );

  it.each([
    "fresh-install-uninstall",
    "baseline-upgrade-uninstall",
    "post-replacement-repair-uninstall",
    "hub-restore-compatibility-window",
  ])("accepts semantically complete %s evidence", (scenario) => {
    const candidate = releaseCandidateManifest().candidate;
    const gate = createMatrixGateResult({
      artifactName: `release-e2e-ubuntu-24.04-x86_64--${scenario}-1`,
      candidate,
      cellId: `ubuntu-24.04-x86_64--${scenario}`,
      evidence: successfulHostEvidence(scenario, candidate),
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });

    expect(gate.evidenceValidationErrors).toEqual([]);
    expect(gate.outcome).toBe("succeeded");
  });

  it("records the candidate-image UI Contract as one candidate-bound gate", () => {
    const candidate = releaseCandidateManifest().candidate;

    expect(
      createUiGateResult({
        artifactName: "release-ui-contract-12345-1",
        candidate,
        playwrightOutcome: "success",
      }),
    ).toEqual({
      artifactName: "release-ui-contract-12345-1",
      candidate,
      kind: "enoki-release-ui-contract-gate",
      outcome: "succeeded",
      playwrightStepOutcome: "success",
      schemaVersion: 1,
    });
    expect(
      createUiGateResult({
        artifactName: "release-ui-contract-12345-1",
        candidate,
        playwrightOutcome: "failure",
      }).outcome,
    ).toBe("failed");
  });

  it("records a failed UI gate from the requested identity when setup never produced a Candidate Manifest", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-ui-gate-"));
    const output = path.join(workDir, "gate-result.json");
    try {
      await execFileAsync(process.execPath, [
        "scripts/release-verification.mjs",
        "record-ui-gate",
        "--candidate-manifest",
        path.join(workDir, "missing-candidate-manifest.json"),
        "--candidate-commit",
        "a".repeat(40),
        "--candidate-version",
        "v1.2.3",
        "--playwright-outcome",
        "skipped",
        "--artifact-name",
        "release-ui-contract-12345-2",
        "--output",
        output,
      ]);
      expect(JSON.parse(await readFile(output, "utf8"))).toMatchObject({
        candidate: { commit: "a".repeat(40), version: "v1.2.3" },
        outcome: "failed",
        playwrightStepOutcome: "skipped",
      });
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("renders candidate, baseline, checksum, digest, outcome, and evidence identities", async () => {
    const matrix = JSON.parse(
      await readFile("scripts/release-e2e-matrix.json", "utf8"),
    );
    const candidateManifest = releaseCandidateManifest();
    const hostGates = expectedHostGateResults(matrix, candidateManifest);
    const uiGate = {
      artifactName: "release-ui-contract-12345-1",
      candidate: candidateManifest.candidate,
      outcome: "succeeded",
    };
    const summary = createVerifyOnlyReleaseSummary({
      artifactIndex: releaseArtifactIndex(hostGates, uiGate),
      candidateManifest,
      gateResults: {
        candidateBuild: "success",
        matrixExpansion: "success",
        matrixJob: "success",
        uiJob: "success",
      },
      hostGates,
      matrix,
      run: {
        attempt: 1,
        id: "12345",
        url: "https://github.com/YKDZ/enoki/actions/runs/12345",
      },
      uiGate,
    });

    const markdown = renderVerifyOnlyReleaseSummaryMarkdown(summary);
    expect(markdown).toContain(candidateManifest.candidate.commit);
    expect(markdown).toContain("v1.2.2");
    expect(markdown).toContain(candidateManifest.hub.digest);
    expect(markdown).toContain(candidateManifest.hub.archiveSha256);
    expect(markdown).toContain(candidateManifest.probeAssetSet.files[0].sha256);
    expect(markdown).toContain("Non-promotable");
    expect(markdown).toContain("release-e2e-ubuntu-24.04-x86_64--");
    expect(markdown).toContain("actions/runs/12345/artifacts/9000");
  });
});

function releaseCandidateManifest({ firstFormalRelease = false } = {}) {
  return {
    candidate: {
      commit: "0123456789abcdef0123456789abcdef01234567",
      version: "v1.2.3",
    },
    hub: {
      archive: "hub/enoki-hub-v1.2.3.oci.tar",
      archiveSha256: "a".repeat(64),
      digest: `sha256:${"b".repeat(64)}`,
      embeddedProbeVersion: "1.2.3",
      size: 1234,
    },
    kind: "enoki-release-candidate",
    probeAssetSet: {
      directory: "probe-assets",
      files: [
        {
          file: "enoki-probe-x86_64-unknown-linux-gnu.tar.gz",
          sha256: "c".repeat(64),
        },
      ],
      signingIdentity: {
        algorithm: "rsa-sha256",
        publicKeyFile: "signing-key.pem",
        publicKeySha256: "d".repeat(64),
      },
      version: "1.2.3",
    },
    releaseBaseline: firstFormalRelease
      ? {
          catalogSnapshot: { entries: [], sha256: "e".repeat(64) },
          kind: "first-formal-release",
        }
      : {
          githubRelease: {
            id: 122,
            peeledCommitSha: "f".repeat(40),
            tagRefSha: "1".repeat(40),
          },
          hub: { imageDigest: `sha256:${"2".repeat(64)}` },
          kind: "enoki-release-baseline",
          probeAssetSet: { version: "1.2.2" },
          tag: "v1.2.2",
        },
    schemaVersion: 2,
  };
}

function expectedHostGateResults(matrix, candidateManifest) {
  return matrix.scenarios.flatMap((scenario) => {
    const environments = scenario.designatedEnvironmentId
      ? matrix.environments.filter(
          (environment) =>
            environment.capabilityId === scenario.designatedEnvironmentId,
        )
      : matrix.environments;
    return environments.map((environment) => ({
      artifactName: `release-e2e-${environment.capabilityId}--${scenario.id}-1`,
      candidate: candidateManifest.candidate,
      cellId: `${environment.capabilityId}--${scenario.id}`,
      evidenceOutcome: "succeeded",
      outcome: "succeeded",
      scenarioId: scenario.id,
      scenarioStepOutcome: "success",
      verifyCleanStepOutcome: "success",
    }));
  });
}

function releaseArtifactIndex(hostGates, uiGate) {
  return Object.fromEntries(
    [uiGate, ...hostGates].map((gate, index) => [
      gate.artifactName,
      `https://github.com/YKDZ/enoki/actions/runs/12345/artifacts/${9000 + index}`,
    ]),
  );
}

function successfulHostEvidence(scenario, candidate) {
  const common = {
    candidate,
    cleanup: {
      environment: { clean: true },
      host: { clean: true },
    },
    phase: "succeeded",
    result: { status: "succeeded" },
    scenario,
    schemaVersion: 2,
    uninstall: {
      hostCompletion: {
        clean: true,
        inventory: {
          accounts: { group: false, user: false },
          files: [],
          units: [],
        },
        journald: "retained journal",
        journaldRetained: true,
        sharedDependencies: "curl\n",
        sharedDependenciesRetained: true,
      },
      hubSoftDeleted: true,
      operationTimeline: evidenceOperationTimeline({
        id: 91,
        kind: "probe_uninstall",
        state: "succeeded",
      }),
      status: "succeeded",
    },
  };
  if (scenario === "fresh-install-uninstall") {
    return {
      ...common,
      auditLog: lifecycleAuditLog(),
      host: evidenceHost("1.2.3"),
      hostBoundary: installedHostBoundary("1.2.3"),
      metrics: evidenceMetrics(1),
      probeConfiguration: probeConfigurationEvidence("host-7-1"),
    };
  }
  if (scenario === "baseline-upgrade-uninstall") {
    return {
      ...common,
      auditLog: lifecycleAuditLog({ upgrade: true }),
      candidateHost: evidenceHost("1.2.3"),
      compatibility: { host: evidenceHost("1.2.2"), status: "succeeded" },
      hostBoundary: installedHostBoundary("1.2.3"),
      identityContinuity: identityContinuityEvidence(),
      metrics: {
        afterUpgrade: evidenceMetrics(3),
        beforeUpgrade: evidenceMetrics(1),
      },
      probeConfiguration: {
        afterUpgrade: probeConfigurationEvidence("host-7-2"),
        beforeUpgrade: probeConfigurationEvidence("host-7-1"),
      },
      releaseBaseline: { probeVersion: "1.2.2" },
      upgradeOperationTimeline: evidenceOperationTimeline({
        id: 81,
        kind: "probe_upgrade",
        state: "succeeded",
        targetProbeVersion: "1.2.3",
      }),
    };
  }
  if (scenario === "post-replacement-repair-uninstall") {
    return {
      ...common,
      auditLog: lifecycleAuditLog({ upgrade: true, upgradeId: 82 }),
      boundaryEvidenceValidation: { status: "succeeded" },
      failureBoundary: {
        hubFailureCode: "running_timeout",
        localFailureCode: "post_replacement_restart_failure",
        probeVersion: "1.2.3",
      },
      identityContinuity: identityContinuityEvidence(),
      metrics: {
        afterRepair: evidenceMetrics(3),
        beforeUpgrade: evidenceMetrics(1),
      },
      operationTimeline: evidenceOperationTimeline({
        failureCode: "running_timeout",
        id: 82,
        kind: "probe_upgrade",
        state: "failed",
        targetProbeVersion: "1.2.3",
      }),
      repair: { probeId: "probe_release_01", repairedVersion: "1.2.3" },
      probeConfiguration: {
        afterRepair: probeConfigurationEvidence("host-7-2"),
        beforeUpgrade: probeConfigurationEvidence("host-7-1"),
      },
      repairHostBoundary: installedHostBoundary("1.2.3"),
      repairedHost: evidenceHost("1.2.3"),
    };
  }
  return {
    ...common,
    hostProfileContinuity: {
      candidateBeforeRestore: stableProfileEvidence(),
      restoredBaseline: stableProfileEvidence(),
    },
    identity: {
      afterRestore: probeIdentityEvidence(),
      afterUpgrade: probeIdentityEvidence(),
      beforeUpgrade: probeIdentityEvidence(),
      hostId: 7,
    },
    image: {
      expectedBaselineDigest: `sha256:${"2".repeat(64)}`,
      restoredBaselineDigest: `sha256:${"2".repeat(64)}`,
      snapshotVerify: {
        manifestDigest: `sha256:${"3".repeat(64)}`,
        status: "succeeded",
      },
      stateRestore: {
        manifestDigest: `sha256:${"3".repeat(64)}`,
        status: "succeeded",
      },
    },
    migration: {
      candidateProbeVersion: "1.2.3",
      operationTimeline: evidenceOperationTimeline({
        id: 83,
        kind: "probe_upgrade",
        state: "succeeded",
        targetProbeVersion: "1.2.3",
      }),
      status: "succeeded",
    },
    protocol: {
      baselineProbeToCandidateHub: "succeeded",
      candidateProbeToBaselineHub: "succeeded",
    },
    releaseBaseline: { hubDigest: `sha256:${"2".repeat(64)}` },
    reporting: {
      candidateHub: {
        host: evidenceHost("1.2.3"),
        metrics: evidenceMetrics(1),
      },
      restoredBaselineHub: {
        host: evidenceHost("1.2.3"),
        metrics: evidenceMetrics(3),
      },
    },
    snapshot: {
      baselineImageDigest: `sha256:${"2".repeat(64)}`,
      hotDataFileCount: 1,
      hotDataFiles: ["data-root/enoki.db"],
      manifestDigest: `sha256:${"3".repeat(64)}`,
      recoveryTime: "2026-08-02T12:00:00.000Z",
      roots: [
        { id: "data-root", included: true, path: "/data" },
        {
          id: "metrics-archive",
          included: true,
          path: "/data/metrics-archive",
        },
      ],
      tool: "enoki-hub-state",
      version: "v1",
    },
  };
}

function evidenceHost(version) {
  return {
    hostProfile: {
      architecture: "x86_64",
      cpuCount: 2,
      filesystems: [],
      hostname: "release-test-host",
      kernel: "6.8.0",
      memoryTotalBytes: 2_147_483_648,
      networkInterfaces: [],
      os: "ubuntu",
      probeVersion: version,
    },
    id: 7,
    status: "online",
  };
}

function evidenceMetrics(firstSequence) {
  return [firstSequence, firstSequence + 1].map((sequence) => ({
    collectedAtMs: sequence * 10,
    cpuPercent: 10 + sequence,
    memoryTotalBytes: 2_147_483_648,
    memoryUsedBytes: 536_870_912 + sequence,
    sequence,
    uptimeSeconds: 100 + sequence,
  }));
}

function evidenceOperationTimeline({
  failureCode,
  id,
  kind,
  state,
  targetProbeVersion = null,
}) {
  const requested = {
    acceptedAtMs: null,
    completedAtMs: null,
    failure: null,
    hostId: 7,
    id,
    kind,
    runningAtMs: null,
    state: "pending",
    targetProbeVersion,
  };
  const terminal = {
    ...requested,
    acceptedAtMs: 20,
    completedAtMs: 40,
    failure: failureCode ? { code: failureCode } : null,
    runningAtMs: 30,
    state,
  };
  return [requested, terminal, { ...terminal }];
}

function lifecycleAuditLog({ upgrade = false, upgradeId = 81 } = {}) {
  const actions = [
    ["enrollment_token.create", "1", "enrollment_token"],
    ["probe_configuration.host.override", "7", "host"],
    ["host.delete", "7", "host"],
    ...(upgrade
      ? [
          [
            "probe_upgrade_request.create",
            String(upgradeId),
            "probe_upgrade_request",
          ],
        ]
      : []),
  ];
  return actions.map(([action, subjectId, subjectType], index) => {
    const event = {
      action,
      actor: "owner",
      id: index + 1,
      occurredAtMs: 100 + index,
      outcome: "success",
      subjectId,
      subjectType,
    };
    if (action === "host.delete") {
      event.details = { hostId: 7, probeOperationId: 91 };
    } else if (action === "probe_upgrade_request.create") {
      event.details = { hostId: 7, targetProbeVersion: "1.2.3" };
    }
    return event;
  });
}

function installedHostBoundary(version) {
  return {
    inventory: {
      accounts: { group: true, user: true },
      files: [
        "/usr/local/bin/enoki-probe",
        "/etc/systemd/system/enoki-probe.service",
        "/etc/sudoers.d/enoki-probe-operations",
      ],
      units: ["enoki-probe.service"],
    },
    probeVersion: version,
    service: {
      ActiveState: "active",
      Group: "enoki-probe",
      LoadState: "loaded",
      User: "enoki-probe",
    },
    sudoers: "enoki-probe-uninstaller internal-uninstaller",
  };
}

function probeConfigurationEvidence(version) {
  return { mode: "override", reportedVersion: version, version };
}

function probeIdentityEvidence() {
  return {
    identitySha256: "f".repeat(64),
    probeId: "probe_release_01",
  };
}

function identityContinuityEvidence() {
  return {
    after: probeIdentityEvidence(),
    before: probeIdentityEvidence(),
    hostId: 7,
  };
}

function stableProfileEvidence() {
  return {
    projection: {
      architecture: "x86_64",
      hostname: "release-test-host",
      probeVersion: "1.2.3",
    },
    sha256: "a".repeat(64),
  };
}
