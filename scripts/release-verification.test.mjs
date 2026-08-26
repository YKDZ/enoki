import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { createProbeHostHarness } from "./release-e2e-lib.mjs";
import {
  createMatrixGateResult as createMatrixGateResultFromManifest,
  createReleaseVerificationSummary,
  createUiGateResult,
  renderReleaseVerificationEvidenceMarkdown,
} from "./release-verification-lib.mjs";

const execFileAsync = promisify(execFile);

function createMatrixGateResult({ candidate, candidateManifest, ...options }) {
  const manifest = candidateManifest ?? releaseCandidateManifest();
  expect(candidate ?? manifest.candidate).toEqual(manifest.candidate);
  return createMatrixGateResultFromManifest({
    ...options,
    candidateManifest: manifest,
  });
}

describe("verify-only release workflow", () => {
  it("qualifies the captured protected main revision without receiving a publication mode", async () => {
    const [entrypoint, candidateWorkflow] = await Promise.all([
      readFile(".github/workflows/release.yml", "utf8"),
      readFile(
        ".github/workflows/reusable-build-release-candidate.yml",
        "utf8",
      ),
    ]);

    expect(entrypoint).toContain("workflow_dispatch:");
    expect(entrypoint).not.toMatch(/^  push:/m);
    expect(entrypoint).not.toMatch(/\n      commit:\n/);
    expect(entrypoint).not.toContain(
      `${["first", "formal", "release"].join("-")}:`,
    );
    expect(entrypoint).toMatch(/\n      version:\n/);
    expect(entrypoint).toMatch(
      /\n      mode:\n[\s\S]*?type: choice[\s\S]*?options:\n\s+- verify-only\n\s+- publish/,
    );
    expect(entrypoint).toContain(
      "uses: ./.github/workflows/reusable-build-release-candidate.yml",
    );
    expect(entrypoint).toContain("commit: ${{ github.sha }}");
    expect(entrypoint).toContain("group: enoki-release-global");
    const verificationJob = entrypoint.slice(
      entrypoint.indexOf("  verify-candidate:"),
      entrypoint.indexOf("  publish-candidate:"),
    );
    expect(verificationJob).not.toMatch(/contents: write|packages: write/);

    expect(candidateWorkflow).toContain("workflow_call:");
    expect(candidateWorkflow).not.toContain("workflow_dispatch:");
    expect(candidateWorkflow).not.toMatch(/\n      mode:\n/);
    expect(candidateWorkflow).not.toContain("inputs.mode");
    expect(candidateWorkflow).not.toContain("RELEASE_MODE");
    expect(candidateWorkflow).not.toContain("--requested-mode");
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
    const summaryStep = finalizer.slice(
      finalizer.indexOf(
        "Generate the authoritative candidate verification summary",
      ),
      finalizer.indexOf("Publish the summary to the workflow run"),
    );
    expect(summaryStep).toContain(
      "ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM: ${{ vars.ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM }}",
    );
    expect(summaryStep).toContain(
      "--root-public-key-env ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM",
    );
    expect(finalizer).toContain("--requested-commit");
    expect(finalizer).toContain("--requested-version");
    expect(finalizer).not.toContain("--requested-mode");
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
    expect(workflow).toContain(
      "permissions:\n  actions: read\n  contents: read",
    );
    expect(workflow).toContain("attestations: write");
    expect(workflow).toContain("id-token: write");
  });

  it("derives and embeds the same immutable Bootstrap publication before Hub image construction", async () => {
    const [workflow, dockerfile] = await Promise.all([
      readFile(".github/workflows/reusable-hub-image.yml", "utf8"),
      readFile("apps/hub/Dockerfile", "utf8"),
    ]);
    const derivation = workflow.indexOf("write-bootstrap-publication");
    const firstBuild = workflow.indexOf("docker build", derivation);
    expect(derivation).toBeGreaterThan(0);
    expect(firstBuild).toBeGreaterThan(derivation);
    expect(workflow).toContain("--output source/probe-bootstrap-publication");
    expect(dockerfile).toContain(
      "COPY --from=builder /app/probe-bootstrap-publication probe-bootstrap-publication",
    );
    expect(dockerfile).toContain("chmod 0555 /app/probe-bootstrap-publication");
    expect(dockerfile).toContain(
      "chmod 0444 /app/probe-bootstrap-publication/enoki-probe-bootstrap-recipe.json",
    );
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

    const summary = createReleaseVerificationSummary({
      artifactIndex: releaseArtifactIndex(hostGates, uiGate),
      candidateManifest,
      gateResults: {
        candidateBuild: "success",
        matrixExpansion: "success",
        matrixJob: "success",
        uiJob: "success",
      },
      hostGates,
      scenarioPlan: matrix,
      run: {
        attempt: 1,
        id: "12345",
        url: "https://github.com/YKDZ/enoki/actions/runs/12345",
      },
      standardCi: standardCiEvidence(candidateManifest.candidate),
      uiGate,
    });

    expect(summary).toMatchObject({
      candidate: candidateManifest.candidate,
      freshCandidateRequiredForPublish: true,
      hub: candidateManifest.hub,
      kind: "enoki-release-verification-evidence",
      probeAssetSet: candidateManifest.probeAssetSet,
      promotable: false,
      releaseBaseline: candidateManifest.releaseBaseline,
      schemaVersion: 3,
      standardCi: standardCiEvidence(candidateManifest.candidate),
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

    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-schema4-verification-summary-"),
    );
    const summaryPath = path.join(workDir, "summary.json");
    try {
      await writeFile(summaryPath, `${JSON.stringify(summary)}\n`);
      await expect(
        execFileAsync(process.execPath, [
          "scripts/release-verification.mjs",
          "assert-verified",
          "--summary",
          summaryPath,
        ]),
      ).resolves.toMatchObject({
        stdout: "Release Verification Evidence is complete\n",
      });
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("binds generic verification evidence to the fresh candidate and current run", async () => {
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
      scenarioPlan: matrix,
      requested: candidateManifest.candidate,
      run,
      standardCi: standardCiEvidence(candidateManifest.candidate),
      uiGate: {
        artifactName: "release-ui-contract-98765-4",
        candidate: candidateManifest.candidate,
        outcome: "succeeded",
      },
    });

    expect(summary).toMatchObject({
      candidate: candidateManifest.candidate,
      freshCandidateRequiredForPublish: true,
      kind: "enoki-release-verification-evidence",
      promotable: false,
      run,
      schemaVersion: 3,
      verified: true,
    });
  });

  it("rejects a schema 4 Candidate Manifest whose Probe Asset Set closure is incomplete", async () => {
    const matrix = JSON.parse(
      await readFile("scripts/release-e2e-matrix.json", "utf8"),
    );
    const candidateManifest = releaseCandidateManifest();
    const summary = createReleaseVerificationSummary({
      candidateManifest: {
        ...candidateManifest,
        probeAssetSet: { ...candidateManifest.probeAssetSet, files: [] },
      },
      gateResults: {
        candidateBuild: "success",
        matrixExpansion: "success",
        matrixJob: "success",
        uiJob: "success",
      },
      hostGates: expectedHostGateResults(matrix, candidateManifest),
      scenarioPlan: matrix,
      requested: candidateManifest.candidate,
      run: {
        attempt: 1,
        id: "12345",
        url: "https://github.com/YKDZ/enoki/actions/runs/12345",
      },
      standardCi: standardCiEvidence(candidateManifest.candidate),
      uiGate: {
        artifactName: "release-ui-contract-12345-1",
        candidate: candidateManifest.candidate,
        outcome: "succeeded",
      },
    });

    expect(summary.verified).toBe(false);
    expect(summary.missingIdentities).toContain("candidate-manifest");
  });

  it("emits a schema-valid failed attempt when an early component prevents candidate assembly", async () => {
    const _matrix = JSON.parse(
      await readFile("scripts/release-e2e-matrix.json", "utf8"),
    );
    const requested = {
      commit: "0123456789abcdef0123456789abcdef01234567",
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
      standardCi: "failure",
    };

    const summary = createReleaseVerificationSummary({
      candidateManifest: null,
      componentResults,
      hostGates: [],
      scenarioPlan: null,
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
      kind: "enoki-release-verification-evidence",
      probeAssetSet: null,
      promotable: false,
      releaseBaseline: null,
      requested,
      schemaVersion: 3,
      verified: false,
    });
    expect(summary.missingIdentities).toEqual([
      "candidate-manifest",
      "hub-oci",
      "probe-asset-set",
      "release-baseline",
      "standard-ci-evidence",
    ]);
    expect(summary.failureReasons).toEqual(
      expect.arrayContaining([
        "releaseBaseline: failure",
        "standardCi: failure",
        "probeBuild: cancelled",
        "Candidate Manifest identity is missing",
      ]),
    );
    expect(summary.gates.hostScenarios).toHaveLength(0);
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
        standardCi: "failure",
      })}\n`,
    );

    try {
      await execFileAsync(
        process.execPath,
        [
          "scripts/release-verification.mjs",
          "summarize",
          "--candidate-dir",
          path.join(workDir, "missing-candidate"),
          "--root-public-key-env",
          "ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM",
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
          "--standard-ci",
          path.join(workDir, "missing-standard-ci.json"),
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
        ],
        {
          env: {
            ...process.env,
            ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM: "test-root",
          },
        },
      );

      const summary = JSON.parse(await readFile(summaryPath, "utf8"));
      expect(summary).toMatchObject({
        requested: {
          commit: "not-a-valid-commit",
          version: "v1.invalid",
        },
        schemaVersion: 3,
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
      scenarioPlan: matrix,
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
        createReleaseVerificationSummary({
          ...valid,
          gateResults: { ...valid.gateResults, uiJob: jobOutcome },
        }).verified,
      ).toBe(false);
    }
    expect(
      createReleaseVerificationSummary({
        ...valid,
        hostGates: valid.hostGates.slice(1),
      }).verified,
    ).toBe(false);
    expect(
      createReleaseVerificationSummary({
        ...valid,
        hostGates: [...valid.hostGates, valid.hostGates[0]],
      }).verified,
    ).toBe(false);
    expect(
      createReleaseVerificationSummary({
        ...valid,
        uiGate: {
          ...valid.uiGate,
          candidate: { ...candidateManifest.candidate, version: "v9.9.9" },
        },
      }).verified,
    ).toBe(false);
    expect(
      createReleaseVerificationSummary({
        ...valid,
        uiGate: { ...valid.uiGate, artifactName: null },
      }).verified,
    ).toBe(false);
    expect(
      createReleaseVerificationSummary({
        ...valid,
        hostGates: [
          { ...valid.hostGates[0], artifactName: null },
          ...valid.hostGates.slice(1),
        ],
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

  it("accepts the current schema 2 Host boundary produced by the real Host Harness", async () => {
    const manifest = releaseCandidateManifest();
    const candidate = manifest.candidate;
    const evidence = successfulHostEvidence(
      "compatible-upgrade-uninstall",
      candidate,
    );
    evidence.hostBoundary = await currentInstalledHostBoundaryFromHarness();

    const gate = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--compatible-upgrade-uninstall-1",
      candidate,
      cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
      evidence,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });

    expect(evidence.hostBoundary.sudoers).toBe("");
    expect(evidence.hostBoundary.inventory.files).not.toContain(
      "/etc/sudoers.d/enoki-probe-operations",
    );
    expect(gate.evidenceValidationErrors).not.toContain(
      "Host installation boundary is invalid",
    );
    expect(gate.outcome).toBe("succeeded");

    const legacyBoundary = structuredClone(evidence);
    legacyBoundary.hostBoundary.inventory.files.push(
      "/etc/sudoers.d/enoki-probe-operations",
    );
    legacyBoundary.hostBoundary.sudoers =
      "enoki-probe ALL=(root) NOPASSWD: /usr/local/bin/enoki-probe-uninstaller\n";
    const rejected = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--compatible-upgrade-uninstall-1",
      candidate,
      cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
      evidence: legacyBoundary,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });
    expect(rejected.evidenceValidationErrors).toContain(
      "Host installation boundary is invalid",
    );
    expect(rejected.outcome).toBe("failed");
  });

  it.each([
    ["releaseTestHost", "missing Release Test Host platform evidence"],
    ["infrastructure", "missing Release E2E infrastructure evidence"],
  ])(
    "fails closed when a succeeded Host scenario lacks %s evidence",
    (field, error) => {
      const candidate = releaseCandidateManifest().candidate;
      const evidence = successfulHostEvidence(
        "fresh-install-uninstall",
        candidate,
      );
      delete evidence[field];

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
      expect(gate.evidenceValidationErrors).toContain(error);
    },
  );

  it.each([
    ["fresh-install-uninstall", "hostBoundary"],
    ["compatible-upgrade-uninstall", "upgradeOperationTimeline"],
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
    evidence.finalLocalUninstall.completion.inventory.accounts.user = true;
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
        "final Local Probe Uninstall evidence is invalid",
        "environment cleanup was not clean",
      ]),
    );
  });

  it("rejects legacy fresh-install evidence without the expanded lifecycle contract", () => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    for (const field of [
      "canonicalRuntimeUnavailableReporting",
      "diagnostics",
      "finalLocalUninstall",
      "hubOnlyDeletion",
      "initialInstall",
      "localUninstall",
      "reEnrollment",
      "repeatedAdd",
    ]) {
      delete evidence[field];
    }
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
        "missing repeatedAdd",
        "missing localUninstall",
        "missing reEnrollment",
        "missing hubOnlyDeletion",
        "missing finalLocalUninstall",
        "missing diagnostics",
        "missing initialInstall",
        "missing canonicalRuntimeUnavailableReporting",
      ]),
    );
  });

  it.each([
    [
      "different boot",
      (value) => {
        value.reporting.receiptConvergence.key.bootId = "boot-other";
      },
    ],
    [
      "wrong sequence",
      (value) => {
        value.reporting.failureReport.sequence = 3;
      },
    ],
    [
      "different retry payload",
      (value) => {
        value.reporting.failureReport.retryPayloadSha256 = "9".repeat(64);
      },
    ],
    [
      "Hub non-200",
      (value) => {
        value.reporting.failureReport.attempts[0].upstreamStatus = 503;
      },
    ],
    [
      "Metrics",
      (value) => {
        value.reporting.failureReport.metricsCount = 1;
      },
    ],
    [
      "Collection Outcomes",
      (value) => {
        value.reporting.failureReport.collectionOutcomeCount = 1;
      },
    ],
    [
      "Probe not READY",
      (value) => {
        value.host.probe.ActiveState = "failed";
      },
    ],
    [
      "configuration not reconciled",
      (value) => {
        value.reporting.failureReport.probeConfigurationVersion = "stale-v1";
      },
    ],
    [
      "response not dropped",
      (value) => {
        value.reporting.failureReport.attempts[0].response = "delivered";
      },
    ],
    [
      "retry not delivered",
      (value) => {
        value.reporting.failureReport.attempts.pop();
      },
    ],
    [
      "transport incomplete",
      (_value, evidence) => {
        evidence.diagnostics.transport.completed = false;
      },
    ],
  ])("fails closed when C4 has %s", (_label, corrupt) => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    corrupt(evidence.canonicalRuntimeUnavailableReporting, evidence);
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
    expect(gate.evidenceValidationErrors).toContain(
      "canonical Runtime-unavailable reporting evidence is invalid",
    );
  });

  it("rejects transient Probe service failure as Installed Bundle Failure Repair evidence", () => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    evidence.installedBundleFailureRepair = {
      failure: {
        cause: "installed_bundle_restart_failure",
        probeVersion: "1.2.3",
        status: "failed",
      },
      host: evidenceHost("1.2.3"),
      hostBoundary: installedHostBoundary("1.2.3"),
      identity: {
        after: probeIdentityEvidence(),
        before: probeIdentityEvidence(),
      },
      repair: {
        probeId: "probe_release_01",
        repairedVersion: "1.2.3",
      },
    };

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
    expect(gate.evidenceValidationErrors).toContain(
      "Installed Bundle Failure Repair evidence is invalid",
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
        "fresh lifecycle Audit Log is invalid",
        "Host installation boundary is invalid",
      ]),
    );
  });

  it.each([
    [
      "repeated Add Hub projection",
      (evidence) => {
        evidence.repeatedAdd.hostAfter.id = 8;
      },
      "repeated Add rejection evidence is invalid",
    ],
    [
      "repeated Add Hub host metadata",
      (evidence) => {
        evidence.repeatedAdd.hostAfter.hostMetadata.displayName = "changed";
      },
      "repeated Add rejection evidence is invalid",
    ],
    [
      "re-enrollment effective configuration",
      (evidence) => {
        evidence.reEnrollment.probeConfiguration.configuration.enabledCollectorIds =
          ["official.cpu"];
      },
      "Host Re-enrollment evidence is invalid",
    ],
    [
      "re-enrollment Metrics history anchors",
      (evidence) => {
        evidence.reEnrollment.metricsHistory.anchors =
          evidence.reEnrollment.metricsHistory.anchors.filter(
            (anchor) => anchor.sequence !== 1,
          );
        evidence.reEnrollment.metricsHistory.sha256 = createHash("sha256")
          .update(JSON.stringify(evidence.reEnrollment.metricsHistory.anchors))
          .digest("hex");
      },
      "Host Re-enrollment Metrics history is invalid",
    ],
    [
      "immediate local-uninstall Host status",
      (evidence) => {
        evidence.localUninstall.activeHost.status = "offline";
      },
      "first Local Probe Uninstall evidence is invalid",
    ],
    [
      "successful terminal diagnostics completeness",
      (evidence) => {
        evidence.diagnostics.host.systemd.available = false;
      },
      "redacted failure diagnostics are incomplete",
    ],
  ])("rejects invalid fresh %s", (_label, corrupt, expectedError) => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    corrupt(evidence);

    const gate = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--fresh-install-uninstall-1",
      candidate,
      cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
      evidence,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });

    expect(gate.evidenceValidationErrors).toContain(expectedError);
  });

  it.each([
    [
      "compatible-upgrade-uninstall",
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
    "compatible-upgrade-uninstall",
    "post-replacement-repair-uninstall",
    "hub-restore-compatibility-window",
  ])("accepts semantically complete %s evidence", (scenario) => {
    const candidate = releaseCandidateManifest().candidate;
    const gate = createMatrixGateResult({
      artifactName: `release-e2e-ubuntu-24.04-x86_64--${scenario}-1`,
      candidate,
      cellId: `ubuntu-24.04-x86_64--${scenario}`,
      evidence: successfulHostEvidence(scenario, candidate, {
        operatingSystemVersion: "24.04",
      }),
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });

    expect(gate.evidenceValidationErrors).toEqual([]);
    expect(gate.outcome).toBe("succeeded");
  });

  it("accepts typed Trust Epoch manual reinstall evidence and rejects identity continuity", () => {
    const candidateManifest = trustEpochMigrationCandidateManifest();
    const candidate = candidateManifest.candidate;
    const evidence = successfulHostEvidence(
      "replacement-migration-uninstall",
      candidate,
    );
    const before = probeIdentityEvidence();
    const after = {
      identitySha256: "e".repeat(64),
      probeId: "probe_release_replacement",
    };
    const candidateHost = evidenceHost("1.2.3");
    const candidateHostProjection = {
      hostMetadata: candidateHost.hostMetadata,
      hostProfile: candidateHost.hostProfile,
      id: candidateHost.id,
      reportedProbeConfigurationVersion: "host-7-1",
    };
    const baselineHost = evidenceHost("0.1.74");
    const baselineHostProjection = {
      hostMetadata: baselineHost.hostMetadata,
      hostProfile: baselineHost.hostProfile,
      id: baselineHost.id,
      reportedProbeConfigurationVersion: "host-7-1",
    };
    evidence.candidateHost = candidateHost;
    evidence.releaseBaseline = releaseBaselineEvidenceFixture(
      candidateManifest.releaseBaseline,
    );
    evidence.compatibility.host = evidenceHost("0.1.74");
    evidence.baselineInstall = installerEvidence({
      activeHub: "baseline",
      legacy: true,
      manifest: candidateManifest,
      runId: evidence.runId,
    });
    evidence.upgradeOperationTimeline = [];
    evidence.manualRecovery = {
      enrollmentId: "enr_manual_reinstall_0001",
      hostId: 7,
      kind: "trust_epoch_manual_reinstall",
      result: installerEvidence({
        activeHub: "candidate",
        manifest: candidateManifest,
        runId: evidence.runId,
      }),
    };
    evidence.identityContinuity = { after, before, hostId: 7 };
    const beforeHistorySamples = evidenceMetrics(1);
    const postReplacementSamples = [
      ...beforeHistorySamples,
      ...evidenceMetrics(3),
    ];
    evidence.metrics.afterUpgrade = [
      postReplacementSamples[0],
      postReplacementSamples.at(-1),
    ];
    evidence.migrationRetention = {
      configuration: {
        configuration: structuredClone(
          evidence.probeConfiguration.beforeUpgrade.configuration,
        ),
        mode: evidence.probeConfiguration.beforeUpgrade.mode,
      },
      hostAfter: candidateHostProjection,
      hostBefore: baselineHostProjection,
      metricHistory: metricsHistoryEvidence(beforeHistorySamples),
      postMetricHistory: metricsHistoryEvidence(postReplacementSamples, {
        retain: beforeHistorySamples,
      }),
    };
    evidence.auditLog = [
      ...lifecycleAuditLog(),
      {
        action: "probe.manual_reinstall_identity_replaced",
        actor: "system",
        details: {
          newProbeId: after.probeId,
          oldProbeId: before.probeId,
          sourceProbeSha256: ["a".repeat(64)],
          targetAssetSetDigest: `sha256:${"b".repeat(64)}`,
          targetProbeVersion: "1.2.3",
        },
        id: 9,
        occurredAtMs: 109,
        outcome: "success",
        subjectId: "7",
        subjectType: "host",
      },
    ];
    const gateFor = (value) =>
      createMatrixGateResult({
        artifactName:
          "release-e2e-ubuntu-22.04-x86_64--replacement-migration-uninstall-1",
        candidateManifest,
        cellId: "ubuntu-22.04-x86_64--replacement-migration-uninstall",
        evidence: value,
        scenarioOutcome: "success",
        verifyCleanOutcome: "success",
      });

    expect(gateFor(evidence).evidenceValidationErrors).toEqual([]);
    const unchanged = structuredClone(evidence);
    unchanged.identityContinuity.after.probeId = before.probeId;
    expect(gateFor(unchanged).evidenceValidationErrors).toContain(
      "Probe Identity replacement is invalid",
    );
    const badManualResult = structuredClone(evidence);
    badManualResult.manualRecovery.result.runId = "run-foreign";
    expect(gateFor(badManualResult).evidenceValidationErrors).toContain(
      "Trust Epoch manual reinstall production result is invalid",
    );
    const badHistoryHash = structuredClone(evidence);
    badHistoryHash.migrationRetention.metricHistory.sha256 = "0".repeat(64);
    expect(gateFor(badHistoryHash).evidenceValidationErrors).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
    const staleConfigurationProjection = structuredClone(evidence);
    staleConfigurationProjection.migrationRetention.hostBefore.reportedProbeConfigurationVersion =
      "default-v1";
    expect(
      gateFor(staleConfigurationProjection).evidenceValidationErrors,
    ).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
    const widenedEffectiveConfiguration = structuredClone(evidence);
    widenedEffectiveConfiguration.migrationRetention.configuration.reportedVersion =
      evidence.probeConfiguration.beforeUpgrade.reportedVersion;
    expect(
      gateFor(widenedEffectiveConfiguration).evidenceValidationErrors,
    ).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
    const foreignHost = structuredClone(evidence);
    foreignHost.migrationRetention.hostAfter.id = 8;
    expect(gateFor(foreignHost).evidenceValidationErrors).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
    const widenedProjection = structuredClone(evidence);
    widenedProjection.migrationRetention.hostAfter.status = "online";
    expect(gateFor(widenedProjection).evidenceValidationErrors).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
    const missingPostReplacementAnchor = structuredClone(evidence);
    missingPostReplacementAnchor.metrics.afterUpgrade = evidenceMetrics(3);
    expect(
      gateFor(missingPostReplacementAnchor).evidenceValidationErrors,
    ).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
    const missingMiddleAnchor = structuredClone(evidence);
    missingMiddleAnchor.migrationRetention.postMetricHistory.anchors =
      missingMiddleAnchor.migrationRetention.postMetricHistory.anchors.filter(
        (anchor) => anchor.sequence !== 2,
      );
    missingMiddleAnchor.migrationRetention.postMetricHistory.sha256 =
      createHash("sha256")
        .update(
          JSON.stringify(
            missingMiddleAnchor.migrationRetention.postMetricHistory.anchors,
          ),
        )
        .digest("hex");
    expect(gateFor(missingMiddleAnchor).evidenceValidationErrors).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
    const noContinuedSample = structuredClone(evidence);
    noContinuedSample.migrationRetention.postMetricHistory = structuredClone(
      noContinuedSample.migrationRetention.metricHistory,
    );
    expect(gateFor(noContinuedSample).evidenceValidationErrors).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
    const widenedAnchor = structuredClone(evidence);
    widenedAnchor.migrationRetention.postMetricHistory.anchors[0].source =
      "unbounded";
    widenedAnchor.migrationRetention.postMetricHistory.sha256 = createHash(
      "sha256",
    )
      .update(
        JSON.stringify(
          widenedAnchor.migrationRetention.postMetricHistory.anchors,
        ),
      )
      .digest("hex");
    expect(gateFor(widenedAnchor).evidenceValidationErrors).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
    const unboundedPostHistory = structuredClone(evidence);
    unboundedPostHistory.migrationRetention.postMetricHistory.anchors.push(
      ...evidenceMetrics(5),
      ...evidenceMetrics(7),
    );
    unboundedPostHistory.migrationRetention.postMetricHistory.sha256 =
      createHash("sha256")
        .update(
          JSON.stringify(
            unboundedPostHistory.migrationRetention.postMetricHistory.anchors,
          ),
        )
        .digest("hex");
    expect(gateFor(unboundedPostHistory).evidenceValidationErrors).toContain(
      "Trust Epoch Host, metadata, configuration, or history retention is invalid",
    );
  });

  it("rejects foreign baseline identity and mutated Candidate recipe provenance at the finalizer", () => {
    const candidateManifest = releaseCandidateManifest();
    const candidate = candidateManifest.candidate;
    const gateFor = (evidence) =>
      createMatrixGateResult({
        artifactName:
          "release-e2e-ubuntu-22.04-x86_64--fresh-install-uninstall-1",
        candidateManifest,
        cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
        evidence,
        scenarioOutcome: "success",
        verifyCleanOutcome: "success",
      });

    const foreignBaseline = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    foreignBaseline.releaseBaseline.descriptorSha256 = "0".repeat(64);
    expect(gateFor(foreignBaseline).evidenceValidationErrors).toContain(
      "Release Baseline evidence is not bound to the Candidate",
    );

    const wrongRecord = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    wrongRecord.initialInstall.bootstrapRecipeProvenance.recordSha256 =
      "0".repeat(64);
    expect(gateFor(wrongRecord).evidenceValidationErrors).toContain(
      "Active candidate Hub Bootstrap recipe provenance is invalid",
    );

    const foreignBaselineRecipe = successfulHostEvidence(
      "compatible-upgrade-uninstall",
      candidate,
    );
    foreignBaselineRecipe.baselineInstall.bootstrapRecipeProvenance.hubDigest = `sha256:${"f".repeat(64)}`;
    const baselineGate = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--compatible-upgrade-uninstall-1",
      candidateManifest,
      cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
      evidence: foreignBaselineRecipe,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });
    expect(baselineGate.evidenceValidationErrors).toContain(
      "Active baseline Hub Bootstrap recipe provenance is invalid",
    );
  });

  it("rejects successful migration Repair evidence without production eligibility", () => {
    const candidateManifest = trustEpochMigrationCandidateManifest();
    const candidate = candidateManifest.candidate;
    const evidence = successfulHostEvidence(
      "post-replacement-repair-uninstall",
      candidate,
    );
    evidence.releaseBaseline = releaseBaselineEvidenceFixture(
      candidateManifest.releaseBaseline,
    );
    const gate = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--post-replacement-repair-uninstall-1",
      candidateManifest,
      cellId: "ubuntu-22.04-x86_64--post-replacement-repair-uninstall",
      evidence,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });
    expect(gate.evidenceValidationErrors).toContain(
      "Trust Epoch migration Repair has no production-authorized eligibility sequence",
    );
    expect(gate.outcome).toBe("failed");
  });

  it("rejects pseudo-success Trust Epoch Hub Restore evidence without a legal Candidate Probe identity sequence", () => {
    const candidateManifest = trustEpochMigrationCandidateManifest();
    const candidate = candidateManifest.candidate;
    const evidence = successfulHostEvidence(
      "hub-restore-compatibility-window",
      candidate,
    );
    const before = probeIdentityEvidence();
    const after = {
      identitySha256: "e".repeat(64),
      probeId: "probe_release_replacement",
    };
    const hostProjection = evidenceHost("0.1.74");
    evidence.releaseBaseline = releaseBaselineEvidenceFixture(
      candidateManifest.releaseBaseline,
    );
    evidence.migration.operationTimeline = [
      {
        enrollmentId: "enr_manual_reinstall_restore",
        hostId: 7,
        kind: "trust_epoch_manual_reinstall",
      },
    ];
    evidence.identity = {
      afterRestore: before,
      afterUpgrade: after,
      beforeUpgrade: before,
      hostId: 7,
    };
    evidence.reporting.candidateHub.host = evidenceHost("0.1.74");
    evidence.reporting.restoredBaselineHub.host = evidenceHost("0.1.74");
    evidence.reporting.postReplacementCandidateHub = {
      host: evidenceHost("1.2.3"),
      metrics: evidenceMetrics(5),
    };
    evidence.migrationRetention = {
      configuration: {
        configuration: probeConfigurationValues("host-7-1"),
        mode: "override",
      },
      hostAfter: hostProjection,
      hostBefore: hostProjection,
      metricHistoryAnchors: evidenceMetrics(1),
    };
    evidence.probeConfiguration = {
      beforeReplacement: probeConfigurationEvidence("host-7-1"),
      retained: evidence.migrationRetention.configuration,
    };
    evidence.auditLog = [
      {
        action: "probe.manual_reinstall_identity_replaced",
        actor: "system",
        details: {
          newProbeId: after.probeId,
          oldProbeId: before.probeId,
          sourceProbeSha256: ["a".repeat(64)],
          targetAssetSetDigest: `sha256:${"b".repeat(64)}`,
          targetProbeVersion: "1.2.3",
        },
        id: 9,
        occurredAtMs: 109,
        outcome: "success",
        subjectId: "7",
        subjectType: "host",
      },
    ];
    const gateFor = (value) =>
      createMatrixGateResult({
        artifactName:
          "release-e2e-ubuntu-22.04-x86_64--hub-restore-compatibility-window-1",
        candidateManifest,
        cellId: "ubuntu-22.04-x86_64--hub-restore-compatibility-window",
        evidence: value,
        scenarioOutcome: "success",
        verifyCleanOutcome: "success",
      });

    expect(gateFor(evidence).evidenceValidationErrors).toContain(
      "Trust Epoch migration Hub Restore has no production-compatible Candidate Probe identity sequence",
    );
    expect(gateFor(evidence).outcome).toBe("failed");
  });

  it("fails closed when recorded Host platform or CI infrastructure does not belong to the matrix cell", () => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    evidence.releaseTestHost.operatingSystemVersion = "24.04";
    evidence.infrastructure.matrixCellId =
      "ubuntu-24.04-x86_64--fresh-install-uninstall";

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
        "Release Test Host platform evidence does not match the matrix cell",
        "Release E2E infrastructure evidence does not match the matrix cell",
      ]),
    );
  });

  it("accepts local SSH Host infrastructure bound to the exact matrix cell", () => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
      {
        infrastructureKind: "ssh",
      },
    );
    evidence.releaseTestHost.virtualization = "vmware";

    const gate = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--fresh-install-uninstall-ssh",
      candidate,
      cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
      evidence,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });

    expect(gate.evidenceValidationErrors).toEqual([]);
    expect(gate.outcome).toBe("succeeded");
  });

  it.each(["ci", "ssh"])(
    "accepts %s Host infrastructure with the exact fields in a different JSON key order",
    (infrastructureKind) => {
      const candidate = releaseCandidateManifest().candidate;
      const evidence = successfulHostEvidence(
        "fresh-install-uninstall",
        candidate,
        { infrastructureKind },
      );
      const infrastructure = evidence.infrastructure;
      evidence.infrastructure = {
        provisioning: infrastructure.provisioning,
        matrixCellId: infrastructure.matrixCellId,
        kind: infrastructure.kind,
        connection: infrastructure.connection,
        artifactAccess: infrastructure.artifactAccess,
      };

      const gate = createMatrixGateResult({
        artifactName: `release-e2e-ubuntu-22.04-x86_64--fresh-install-uninstall-${infrastructureKind}`,
        candidate,
        cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
        evidence,
        scenarioOutcome: "success",
        verifyCleanOutcome: "success",
      });

      expect(gate.evidenceValidationErrors).toEqual([]);
      expect(gate.outcome).toBe("succeeded");
    },
  );

  it.each([
    [
      "a missing field",
      (infrastructure) => delete infrastructure.artifactAccess,
    ],
    [
      "an unexpected field",
      (infrastructure) => (infrastructure.untrusted = true),
    ],
    [
      "a mixed CI/SSH adapter",
      (infrastructure) => (infrastructure.connection = "ssh"),
    ],
    [
      "a different matrix cell",
      (infrastructure) =>
        (infrastructure.matrixCellId =
          "ubuntu-24.04-x86_64--fresh-install-uninstall"),
    ],
  ])(
    "fails closed when CI infrastructure has %s",
    (_description, mutateInfrastructure) => {
      const candidate = releaseCandidateManifest().candidate;
      const evidence = successfulHostEvidence(
        "fresh-install-uninstall",
        candidate,
      );
      mutateInfrastructure(evidence.infrastructure);

      const gate = createMatrixGateResult({
        artifactName:
          "release-e2e-ubuntu-22.04-x86_64--fresh-install-uninstall-1",
        candidate,
        cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
        evidence,
        scenarioOutcome: "success",
        verifyCleanOutcome: "success",
      });

      expect(gate.evidenceValidationErrors).toContain(
        "Release E2E infrastructure evidence does not match the matrix cell",
      );
      expect(gate.outcome).toBe("failed");
    },
  );

  it("rejects unsupported Host virtualization in otherwise matching matrix evidence", () => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "fresh-install-uninstall",
      candidate,
    );
    evidence.releaseTestHost.virtualization = "docker";

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
    expect(gate.evidenceValidationErrors).toContain(
      "Release Test Host platform evidence does not match the matrix cell",
    );
  });

  it("rejects Compatible insufficient-privilege Upgrade followed by Installer Recovery", () => {
    const candidate = releaseCandidateManifest().candidate;
    const evidence = successfulHostEvidence(
      "compatible-upgrade-uninstall",
      candidate,
    );
    evidence.upgradeOperationTimeline = evidenceOperationTimeline({
      failureCode: "insufficient_privilege",
      id: 81,
      kind: "probe_upgrade",
      state: "failed",
      targetProbeVersion: "1.2.3",
    });
    evidence.manualRecovery = {
      failedOperationId: 81,
      mode: "installer",
      status: "succeeded",
      targetProbeVersion: "1.2.3",
    };

    const gate = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--compatible-upgrade-uninstall-1",
      candidate,
      cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
      evidence,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });

    expect(gate.evidenceValidationErrors).toContain(
      "Compatible Upgrade must not use manual recovery",
    );
    expect(gate.outcome).toBe("failed");
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
    const summary = createReleaseVerificationSummary({
      artifactIndex: releaseArtifactIndex(hostGates, uiGate),
      candidateManifest,
      gateResults: {
        candidateBuild: "success",
        matrixExpansion: "success",
        matrixJob: "success",
        uiJob: "success",
      },
      hostGates,
      scenarioPlan: matrix,
      run: {
        attempt: 1,
        id: "12345",
        url: "https://github.com/YKDZ/enoki/actions/runs/12345",
      },
      standardCi: standardCiEvidence(candidateManifest.candidate),
      uiGate,
    });

    const markdown = renderReleaseVerificationEvidenceMarkdown(summary);
    expect(markdown).toContain(candidateManifest.candidate.commit);
    expect(markdown).toContain("v1.2.2");
    expect(markdown).toContain(candidateManifest.hub.digest);
    expect(markdown).toContain(candidateManifest.hub.archiveSha256);
    expect(markdown).toContain(candidateManifest.probeAssetSet.files[0].sha256);
    expect(markdown).toContain("Current workflow run only");
    expect(markdown).toContain("`canonical-report-response-loss`");
    expect(markdown).toContain("release-e2e-ubuntu-24.04-x86_64--");
    expect(markdown).toContain("actions/runs/12345/artifacts/9000");
  });
});

function releaseCandidateManifest() {
  const bootstrapRecord = bootstrapRecipeRecord("1.2.3");
  const bootstrapRecordBytes = Buffer.from(
    `${JSON.stringify(bootstrapRecord, null, 2)}\n`,
  );
  return {
    bootstrapRecipe: {
      bundleVersion: bootstrapRecord.bundleVersion,
      distribution: bootstrapRecord.distribution,
      file: bootstrapRecord.recipe.file,
      kind: bootstrapRecord.kind,
      recordFile: "enoki-probe-bootstrap-recipe.json",
      recordSha256: createHash("sha256")
        .update(bootstrapRecordBytes)
        .digest("hex"),
      recordSize: bootstrapRecordBytes.byteLength,
      rootFingerprint: bootstrapRecord.rootFingerprint,
      schemaVersion: bootstrapRecord.schemaVersion,
      sha256: bootstrapRecord.recipe.sha256,
      size: bootstrapRecord.recipe.size,
      targets: bootstrapRecord.targets,
      version: bootstrapRecord.recipe.version,
    },
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
          size: 123,
        },
      ],
      signingIdentity: {
        algorithm: "rsa-sha256",
        publicKeyFile: "signing-key.pem",
        publicKeySha256: "d".repeat(64),
      },
      version: "1.2.3",
    },
    releaseBaseline: {
      githubRelease: {
        id: 122,
        peeledCommitSha: "f".repeat(40),
        tagRefSha: "1".repeat(40),
      },
      hub: { imageDigest: `sha256:${"2".repeat(64)}` },
      kind: "enoki-release-baseline",
      probeAssetSet: {
        signingIdentity: { publicKeySha256: "3".repeat(64) },
        trustRoot: { publicKeySha256: "4".repeat(64) },
        version: "1.2.2",
      },
      tag: "v1.2.2",
    },
    schemaVersion: 4,
  };
}

function bootstrapRecipeRecord(bundleVersion) {
  return {
    bundleVersion,
    distribution: "enoki",
    kind: "enoki-probe-bootstrap-recipe-record",
    recipe: {
      file: "enoki-probe-bootstrap.py",
      sha256: "f".repeat(64),
      size: 123,
      version: "v1",
    },
    rootFingerprint: "e".repeat(64),
    schemaVersion: 1,
    targets: [
      "aarch64-unknown-linux-gnu",
      "aarch64-unknown-linux-musl",
      "x86_64-unknown-linux-gnu",
      "x86_64-unknown-linux-musl",
    ],
  };
}

function trustEpochMigrationCandidateManifest() {
  const manifest = releaseCandidateManifest();
  return {
    ...manifest,
    releaseBaseline: {
      authorization: {
        legacyReleaseSha256: "5".repeat(64),
        sha256: "6".repeat(64),
      },
      githubRelease: {
        id: 74,
        peeledCommitSha: "7".repeat(40),
        tagRefSha: "8".repeat(40),
      },
      hub: { imageDigest: `sha256:${"9".repeat(64)}` },
      kind: "enoki-trust-epoch-migration-baseline",
      tag: "v0.1.74",
    },
  };
}

function standardCiEvidence(candidate) {
  return {
    candidateCommit: candidate.commit,
    jobs: [{ conclusion: "success", name: "Node checks / Node checks" }],
    kind: "enoki-standard-ci-evidence",
    runId: 42,
    runUrl: "https://github.com/YKDZ/enoki/actions/runs/42",
    schemaVersion: 1,
  };
}

function expectedHostGateResults(matrix, candidateManifest) {
  const scenarioIds =
    candidateManifest.releaseBaseline.kind ===
    "enoki-trust-epoch-migration-baseline"
      ? ["replacement-migration-uninstall", "fresh-install-uninstall"]
      : [
          "compatible-upgrade-uninstall",
          "fresh-install-uninstall",
          "post-replacement-repair-uninstall",
          "hub-restore-compatibility-window",
        ];
  const scenarios = scenarioIds.map((id) => ({
    designatedEnvironmentId:
      id === "hub-restore-compatibility-window" ? "ubuntu-24.04-x86_64" : null,
    id,
  }));
  const cells = scenarios.flatMap((scenario) => {
    const environments = scenario.designatedEnvironmentId
      ? matrix.environments.filter(
          (environment) =>
            environment.capabilityId === scenario.designatedEnvironmentId,
        )
      : matrix.environments;
    return environments.map((environment) => ({
      capabilities:
        scenario.id === "fresh-install-uninstall"
          ? ["canonical-report-response-loss"]
          : [],
      environmentId: environment.capabilityId,
      runner: matrix.providers
        .find((provider) => provider.id === environment.providerId)
        .capabilities.find(
          (capability) => capability.id === environment.capabilityId,
        ).runner,
      scenarioId: scenario.id,
      cellId: `${environment.capabilityId}--${scenario.id}`,
    }));
  });
  Object.assign(matrix, {
    cells,
    kind: "enoki-release-scenario-plan",
    schemaVersion: 1,
  });
  return cells.map((cell) => ({
    artifactName: `release-e2e-${cell.cellId}-1`,
    candidate: candidateManifest.candidate,
    cellId: cell.cellId,
    evidenceOutcome: "succeeded",
    outcome: "succeeded",
    releaseBaselineKind: candidateManifest.releaseBaseline.kind,
    scenarioId: cell.scenarioId,
    scenarioStepOutcome: "success",
    verifyCleanStepOutcome: "success",
  }));
}

function releaseArtifactIndex(hostGates, uiGate) {
  return Object.fromEntries(
    [uiGate, ...hostGates].map((gate, index) => [
      gate.artifactName,
      `https://github.com/YKDZ/enoki/actions/runs/12345/artifacts/${9000 + index}`,
    ]),
  );
}

function successfulHostEvidence(
  scenario,
  candidate,
  { infrastructureKind = "ci", operatingSystemVersion = "22.04" } = {},
) {
  const matrixCellId = `ubuntu-${operatingSystemVersion}-x86_64--${scenario}`;
  const runId = `run-${scenario}`;
  const infrastructure =
    infrastructureKind === "ssh"
      ? {
          artifactAccess: "filesystem",
          connection: "ssh",
          kind: "ssh",
          matrixCellId,
          provisioning: "existing-disposable-host",
        }
      : {
          artifactAccess: "github-actions",
          connection: "local",
          kind: "ci",
          matrixCellId,
          provisioning: "github-hosted-runner",
        };
  const common = {
    baselineInstall: installerEvidence({
      activeHub: "baseline",
      manifest: releaseCandidateManifest(),
      runId,
    }),
    candidate,
    cleanup: {
      environment: { clean: true },
      host: { clean: true },
    },
    infrastructure,
    phase: "succeeded",
    releaseBaseline: releaseBaselineEvidenceFixture(
      releaseCandidateManifest().releaseBaseline,
    ),
    releaseTestHost: {
      architecture: "x86_64",
      deviceView: true,
      journaldSocket: true,
      operatingSystem: "ubuntu",
      operatingSystemVersion,
      pid1: "systemd",
      rootFilesystem: true,
      systemdNotifySocket: true,
      unifiedCgroup: true,
      virtualization: "kvm",
    },
    result: { status: "succeeded" },
    runId,
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
    const initialIdentity = probeIdentityEvidence();
    const reEnrolledIdentity = {
      identitySha256: "e".repeat(64),
      probeId: "probe_release_02",
    };
    return {
      ...common,
      auditLog: freshLifecycleAuditLog(),
      diagnostics: {
        host: terminalDiagnosticsEvidence(reEnrolledIdentity),
        hub: { apiTimeline: [{ method: "DELETE", status: 200 }] },
        transport: {
          armed: true,
          bootReportObserved: true,
          completed: true,
          failure: null,
          failureReportObserved: true,
          lastUpstreamStatus: 200,
          reportRequestCount: 3,
        },
      },
      canonicalRuntimeUnavailableReporting:
        canonicalRuntimeUnavailableEvidence(),
      finalLocalUninstall: { completion: common.uninstall.hostCompletion },
      host: evidenceHost("1.2.3"),
      hostBoundary: installedHostBoundary("1.2.3"),
      hubOnlyDeletion: {
        deletedHost: { deletedAtMs: 100, id: 7 },
        permanentReportRejection: {
          binarySha256: "a".repeat(64),
          identity: reEnrolledIdentity,
          installMetadataSha256: "b".repeat(64),
          restartCountAfterObservation: 3,
          restartCountBeforeObservation: 3,
          service: {
            ActiveState: "failed",
            ExecMainStatus: 78,
            LoadState: "loaded",
            SubState: "failed",
          },
        },
      },
      initialInstall: installerEvidence({
        activeHub: "candidate",
        manifest: releaseCandidateManifest(),
        runId,
      }),
      installedBundleFailureRepair: {
        failure: {
          activeState: "failed",
          bundle: {
            installStateSha256: "4".repeat(64),
            manifestSha256: "5".repeat(64),
            runtimeFaultSha256: "6".repeat(64),
            runtimeSha256: "7".repeat(64),
            version: "1.2.3",
          },
          failureEpoch: {
            bootId: "4f7d3e15-63cc-4d61-8fe4-f5d42773dd51",
            generation: "8".repeat(64),
            hostId: "7",
            identityReceiptSha256: "9".repeat(64),
            links: 1,
            mode: "0600",
            ownerUid: 0,
            probeId: initialIdentity.probeId,
          },
          latch: {
            generation: "8".repeat(64),
            links: 1,
            mode: "0600",
            ownerUid: 0,
          },
          recoveryBudget: {
            observedStarts: 3,
            startLimitBurst: 3,
            startLimitIntervalSeconds: 60,
          },
          result: "start-limit-hit",
          role: "observation_runtime",
          status: "latched",
          unit: "enoki-observation-runtime.service",
          unitSha256: "a".repeat(64),
        },
        host: evidenceHost("1.2.3"),
        hostBoundary: installedHostBoundary("1.2.3"),
        identity: { after: initialIdentity, before: initialIdentity },
        repair: {
          failureEpochRemoved: true,
          faultRemoved: true,
          latchRemoved: true,
          output: "Probe repair completed.",
          probeId: initialIdentity.probeId,
          repairedVersion: "1.2.3",
          runtimeSha256: "7".repeat(64),
          sameBundle: true,
          unit: "enoki-observation-runtime.service",
        },
      },
      localUninstall: {
        activeHost: evidenceHost("1.2.3"),
        completion: common.uninstall.hostCompletion,
        offlineHost: { ...evidenceHost("1.2.3"), status: "offline" },
      },
      metrics: evidenceMetrics(1),
      metricsHistory: metricsHistoryEvidence(evidenceMetrics(1)),
      probeConfiguration: probeConfigurationEvidence("host-7-1"),
      reEnrollment: {
        enrollment: {
          enrollmentId: "enr_release_reenrollment",
          status: "pending",
          target: { hostId: 7, kind: "existing_host" },
        },
        host: evidenceHost("1.2.3"),
        hostBoundary: installedHostBoundary("1.2.3"),
        hostId: 7,
        identity: { after: reEnrolledIdentity, before: initialIdentity },
        installer: installerEvidence({
          activeHub: "candidate",
          manifest: releaseCandidateManifest(),
          runId,
        }),
        metrics: evidenceMetrics(3),
        metricsHistory: metricsHistoryEvidence(
          [...evidenceMetrics(1), ...evidenceMetrics(3)],
          {
            retain: metricsHistoryEvidence(evidenceMetrics(1)).anchors,
          },
        ),
        probeConfiguration: {
          configuration: probeConfigurationValues("host-7-1"),
          mode: "override",
        },
      },
      repeatedAdd: {
        enrollment: {
          enrollmentId: "enr_release_repeated",
          status: "pending",
          target: { kind: "new_host" },
        },
        enrollmentStatus: {
          enrollmentId: "enr_release_repeated",
          hostId: null,
          rejection: {
            code: "existing_probe_installation",
            message: "existing local Probe installation detected",
          },
          status: "rejected",
          target: { kind: "new_host" },
        },
        rejection: {
          code: "existing_probe_installation",
          output: { code: 1, stderr: "typed rejection", stdout: "" },
        },
        hostAfter: evidenceHost("1.2.3"),
        hostBefore: evidenceHost("1.2.3"),
        stateAfter: installedStateEvidence(initialIdentity),
        stateBefore: installedStateEvidence(initialIdentity),
      },
    };
  }
  if (
    scenario === "compatible-upgrade-uninstall" ||
    scenario === "replacement-migration-uninstall"
  ) {
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

function releaseBaselineEvidenceFixture(baseline) {
  const migration = baseline.kind === "enoki-trust-epoch-migration-baseline";
  return {
    authority: migration
      ? {
          authorizationSha256: baseline.authorization.sha256,
          githubReleaseId: baseline.githubRelease.id,
          legacyReleaseSha256: baseline.authorization.legacyReleaseSha256,
          peeledCommitSha: baseline.githubRelease.peeledCommitSha,
        }
      : {
          githubReleaseId: baseline.githubRelease.id,
          peeledCommitSha: baseline.githubRelease.peeledCommitSha,
          signingPublicKeySha256:
            baseline.probeAssetSet.signingIdentity.publicKeySha256,
          trustRootPublicKeySha256:
            baseline.probeAssetSet.trustRoot.publicKeySha256,
        },
    descriptorSha256: createHash("sha256")
      .update(JSON.stringify(baseline))
      .digest("hex"),
    hubDigest: baseline.hub.imageDigest,
    kind: baseline.kind,
    probeVersion: migration
      ? baseline.tag.slice(1)
      : baseline.probeAssetSet.version,
    tag: baseline.tag,
  };
}

function evidenceHost(version) {
  return {
    hostMetadata: {
      connectAddress: "release-test-host",
      description: "Release Test Host",
      displayName: "Release Test Host",
      observedIp: "192.0.2.10",
    },
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

function canonicalRuntimeUnavailableEvidence() {
  return {
    host: {
      identity: {
        probeId: "probe_release_02",
        registrationAttemptCredential: false,
        registrationAttemptSource: false,
        registrationDropIn: false,
        transitionalRegistrationKeys: false,
      },
      probe: {
        ActiveState: "active",
        LoadState: "loaded",
        Result: "success",
        SubState: "running",
        Type: "notify",
      },
      runtime: {
        serviceLoadState: "masked",
        socketLoadState: "masked",
      },
    },
    ownerProjection: {
      host: evidenceHost("1.2.3"),
      metricsUnchanged: true,
      reportedProbeConfigurationVersion: "host-7-1",
    },
    reporting: {
      bootId: "boot-c4-01",
      bootReport: {
        acceptedSequenceEnd: 1,
        bytes: 128,
        payloadSha256: "1".repeat(64),
        reconciliation: {
          currentProbeConfigurationVersion: "host-7-1",
          pendingOperation: "absent",
          requestedSnapshotCollectorIdsCount: 0,
        },
        responseDelivered: true,
        responseSha256: "2".repeat(64),
        sequence: 1,
        upstreamStatus: 200,
      },
      failureReport: {
        attempts: [
          {
            acceptedSequenceEnd: 2,
            response: "dropped",
            responseSha256: "4".repeat(64),
            upstreamStatus: 200,
          },
          {
            acceptedSequenceEnd: 2,
            response: "delivered",
            responseSha256: "5".repeat(64),
            upstreamStatus: 200,
          },
        ],
        bytes: 64,
        collectionOutcomeCount: 0,
        metricsCount: 0,
        payloadSha256: "3".repeat(64),
        probeConfigurationVersion: "host-7-1",
        reason: "observation_runtime_unavailable",
        retryPayloadSha256: "3".repeat(64),
        sequence: 2,
      },
      kind: "canonical-runtime-unavailable-report-evidence",
      receiptConvergence: {
        contract: "report-sequence-ack-idempotency",
        key: {
          bootId: "boot-c4-01",
          probeId: "probe_release_02",
          sequence: 2,
        },
        requestAttemptCount: 2,
        uniquePayloadCount: 1,
      },
      probeId: "probe_release_02",
      schemaVersion: 1,
    },
  };
}

function metricsHistoryEvidence(samples, { retain = [] } = {}) {
  const selected = [
    samples[0],
    samples[Math.floor((samples.length - 1) / 2)],
    samples.at(-1),
    ...retain.filter((anchor) =>
      samples.some(
        (sample) => JSON.stringify(sample) === JSON.stringify(anchor),
      ),
    ),
  ].filter(Boolean);
  const anchors = [
    ...new Map(selected.map((anchor) => [anchor.sequence, anchor])).values(),
  ].sort((left, right) => left.sequence - right.sequence);
  return {
    anchors,
    sha256: createHash("sha256").update(JSON.stringify(anchors)).digest("hex"),
  };
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

function freshLifecycleAuditLog() {
  return [
    {
      action: "enrollment_token.create",
      actor: "owner",
      details: { target: { kind: "new_host" } },
      id: 1,
      occurredAtMs: 100,
      outcome: "success",
      subjectId: "1",
      subjectType: "enrollment_token",
    },
    {
      action: "enrollment.installation_rejected",
      actor: "system",
      details: { code: "existing_probe_installation" },
      id: 2,
      occurredAtMs: 101,
      outcome: "success",
      subjectId: "2",
      subjectType: "enrollment_token",
    },
    {
      action: "enrollment_token.create",
      actor: "owner",
      details: { target: { hostId: 7, kind: "existing_host" } },
      id: 3,
      occurredAtMs: 102,
      outcome: "success",
      subjectId: "3",
      subjectType: "enrollment_token",
    },
    {
      action: "probe_configuration.host.override",
      actor: "owner",
      id: 4,
      occurredAtMs: 103,
      outcome: "success",
      subjectId: "7",
      subjectType: "host",
    },
    {
      action: "host.delete",
      actor: "owner",
      details: { hostId: 7, mode: "hub-only" },
      id: 5,
      occurredAtMs: 104,
      outcome: "success",
      subjectId: "7",
      subjectType: "host",
    },
  ];
}

function installedHostBoundary(version) {
  return {
    delegationGeneration: 1,
    inventory: {
      accounts: { group: true, user: true },
      files: [
        "/usr/local/bin/enoki-probe",
        "/etc/systemd/system/enoki-probe.service",
      ],
      units: ["enoki-probe.service"],
    },
    probeVersion: version,
    service: {
      ActiveState: "active",
      FragmentPath: "/etc/systemd/system/enoki-probe.service",
      Group: "enoki-probe",
      LoadState: "loaded",
      SubState: "running",
      User: "enoki-probe",
    },
    sudoers: "",
  };
}

async function currentInstalledHostBoundaryFromHarness() {
  let inventoryCount = 0;
  const harness = createProbeHostHarness({
    execute: async (command) => {
      if (command.includes("# enoki-release-e2e:inventory")) {
        inventoryCount += 1;
        return successfulCommand(
          inventoryCount === 1
            ? {
                accounts: { group: false, user: false },
                files: [],
                units: [],
              }
            : {
                accounts: { group: true, user: true },
                files: [
                  "/usr/local/bin/enoki-probe",
                  "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
                  "/var/lib/enoki-probe-bootstrap",
                  "/etc/enoki/probe-install.toml",
                  "/etc/systemd/system/enoki-probe.service",
                  "/var/lib/enoki-probe",
                ],
                units: ["enoki-probe.service"],
              },
        );
      }
      if (command.includes("# enoki-release-e2e:dependencies")) {
        return successfulCommand({ curl: "/usr/bin/curl" });
      }
      if (command.includes("# enoki-release-e2e:service-boundary")) {
        return successfulCommandText(
          [
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=running",
            "User=enoki-probe",
            "Group=enoki-probe",
            "FragmentPath=/etc/systemd/system/enoki-probe.service",
          ].join("\n"),
        );
      }
      if (command.includes("# enoki-release-e2e:sudoers-boundary")) {
        return successfulCommandText("");
      }
      if (command.includes("# enoki-release-e2e:binary-version")) {
        return successfulCommandText("enoki-probe v1.2.3\n");
      }
      if (command.includes("# enoki-release-e2e:bootstrap-generation")) {
        return successfulCommandText("1\n");
      }
      return successfulCommandText(
        "ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE\nEnoki Probe installed as enoki-probe.service.\n",
      );
    },
  });
  const enrollment = {
    bootstrapRecipe: {
      bundleVersion: "1.2.3",
      distribution: "enoki",
      kind: "enoki-probe-bootstrap-recipe-record",
      recipe: {
        file: "enoki-probe-bootstrap.py",
        sha256: "e".repeat(64),
        size: 123,
        version: "v1",
      },
      rootFingerprint: "d".repeat(64),
      schemaVersion: 1,
      targets: [
        "aarch64-unknown-linux-gnu",
        "aarch64-unknown-linux-musl",
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
      ],
    },
    enrollmentToken: "enk_enroll_current_boundary",
    hubUrl: "https://hub.example",
    installCommand:
      "printf '%s\\n' 'enk_enroll_current_boundary' | python3 -- ./enoki-probe-bootstrap.py --hub-origin 'https://hub.example'",
  };

  await harness.assertDisposable("run-current-boundary");
  await harness.install(enrollment, "run-current-boundary");
  return harness.assertInstalled("run-current-boundary", "1.2.3");
}

function successfulCommand(value) {
  return successfulCommandText(JSON.stringify(value));
}

function successfulCommandText(stdout) {
  return { code: 0, stderr: "", stdout };
}

function probeConfigurationEvidence(version) {
  return {
    configuration: probeConfigurationValues(version),
    mode: "override",
    reportedVersion: version,
    version,
  };
}

function probeConfigurationValues(version) {
  return {
    enabledCollectorIds: ["official.cpu", "official.memory"],
    metricsCollectionIntervalSeconds: 2,
    version,
  };
}

function probeIdentityEvidence() {
  return {
    identitySha256: "f".repeat(64),
    probeId: "probe_release_01",
  };
}

function installedStateEvidence(identity) {
  return {
    binarySha256: "a".repeat(64),
    identity,
    installMetadataSha256: "b".repeat(64),
    restartCount: 3,
    service: {
      ActiveState: "active",
      LoadState: "loaded",
      SubState: "running",
    },
  };
}

function installerEvidence({ activeHub, legacy = false, manifest, runId }) {
  const version =
    activeHub === "candidate"
      ? manifest.probeAssetSet.version
      : manifest.releaseBaseline.kind === "enoki-release-baseline"
        ? manifest.releaseBaseline.probeAssetSet.version
        : manifest.releaseBaseline.tag.slice(1);
  const record = bootstrapRecipeRecord(version);
  const recordBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`);
  return {
    bootstrapRecipeProvenance: legacy
      ? null
      : {
          activeHub,
          hubDigest:
            activeHub === "candidate"
              ? manifest.hub.digest
              : manifest.releaseBaseline.hub.imageDigest,
          kind: "enoki-release-e2e-bootstrap-recipe-provenance",
          record,
          recordFile: "enoki-probe-bootstrap-recipe.json",
          recordSha256: createHash("sha256").update(recordBytes).digest("hex"),
          recordSize: recordBytes.byteLength,
          schemaVersion: 1,
        },
    output: {
      code: 0,
      stderr: "",
      stdout:
        "ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE\nEnoki Probe installed as enoki-probe.service.\n",
    },
    runId,
  };
}

function terminalDiagnosticsEvidence(identity) {
  return {
    installation: {
      available: true,
      output: { code: 0, stderr: "", stdout: "installation captured\n" },
      value: {
        binary: { sha256: "a".repeat(64), version: "1.2.3" },
        identity,
        installMetadataSha256: "b".repeat(64),
        service: {
          ActiveState: "failed",
          ExecMainStatus: 78,
          LoadState: "loaded",
          NRestarts: 3,
          Result: "exit-code",
          SubState: "failed",
        },
      },
    },
    inventory: {
      available: true,
      output: { code: 0, stderr: "", stdout: "inventory captured\n" },
      value: {
        accounts: { group: true, user: true },
        files: ["/usr/local/bin/enoki-probe", "/etc/enoki/probe-install.toml"],
        units: ["enoki-probe.service"],
      },
    },
    journald: {
      available: true,
      output: { code: 0, stderr: "", stdout: "report rejected\n" },
    },
    sudoers: {
      available: true,
      output: { code: 0, stderr: "", stdout: "enoki-probe sudoers\n" },
    },
    systemd: {
      available: true,
      output: {
        code: 0,
        stderr: "",
        stdout: "LoadState=loaded\nActiveState=failed\nExecMainStatus=78\n",
      },
    },
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
