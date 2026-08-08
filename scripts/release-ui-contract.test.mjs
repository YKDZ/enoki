import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import { releaseUiLifecycleVersions } from "../tests/e2e/release-ui-contract-fixture.ts";
import {
  parseCandidateUiContractCommandLine,
  runCandidateUiContract,
} from "./release-ui-contract-lib.mjs";

describe("candidate-image UI Contract gate", () => {
  it("derives lifecycle fixture versions from the Candidate Manifest version with a source default", () => {
    expect(
      releaseUiLifecycleVersions({
        ENOKI_RELEASE_UI_CANDIDATE_VERSION: "7.8.9",
      }),
    ).toEqual({
      candidateVersion: "7.8.9",
      currentProbeVersion: "7.8.8",
      targetProbeVersion: "7.8.9",
    });
    expect(releaseUiLifecycleVersions({})).toEqual({
      candidateVersion: "0.2.0",
      currentProbeVersion: "0.1.0",
      targetProbeVersion: "0.2.0",
    });
  });

  it("is one candidate-level CI gate outside the Host matrix with one retry", async () => {
    const [workflow, playwrightConfig] = await Promise.all([
      readFile(
        ".github/workflows/reusable-build-release-candidate.yml",
        "utf8",
      ),
      readFile("playwright.candidate.config.ts", "utf8"),
    ]);
    const gate = workflow.slice(workflow.indexOf("  candidate-ui-contract:"));

    expect(gate).toContain(
      "needs: [validate-candidate-inputs, assemble-candidate]",
    );
    expect(gate).toContain("needs.assemble-candidate.outputs.artifact-name");
    expect(gate).toContain("pnpm run test:e2e:candidate");
    expect(gate).not.toMatch(/pnpm run test:e2e:candidate --(?:\s|$)/);
    expect(gate).not.toContain("matrix:");
    expect(gate).not.toContain("ssh");
    expect(playwrightConfig).toContain("retries: process.env.CI ? 1 : 0");
    expect(playwrightConfig).toContain(
      'testMatch: "probe-lifecycle-ui-contract.spec.ts"',
    );
  });

  it("uploads one bounded evidence bundle for setup, test, diagnostics, traces, and cleanup on every outcome", async () => {
    const [workflow, playwrightConfig] = await Promise.all([
      readFile(
        ".github/workflows/reusable-build-release-candidate.yml",
        "utf8",
      ),
      readFile("playwright.candidate.config.ts", "utf8"),
    ]);
    const gate = workflow.slice(
      workflow.indexOf("  candidate-ui-contract:"),
      workflow.indexOf("  finalize-verification:"),
    );

    expect(gate).toContain("--evidence-dir");
    expect(gate).toContain("release-ui-contract-evidence/runner-evidence.json");
    expect(gate).toContain("release-ui-contract-evidence/gate-result.json");
    expect(gate).toContain("release-ui-contract-evidence/playwright-report");
    expect(gate).toContain("release-ui-contract-evidence/test-results");
    expect(gate).toContain("release-ui-contract-evidence/workflow-setup.json");
    expect(gate).toMatch(
      /name: Upload candidate-image UI Contract evidence\n\s+if: \$\{\{ always\(\) \}\}/,
    );
    expect(playwrightConfig).toContain("ENOKI_RELEASE_UI_EVIDENCE_DIR");
    expect(playwrightConfig).toContain("outputFolder:");
    expect(playwrightConfig).toContain("outputDir:");
    expect(playwrightConfig).toContain('trace: "on-first-retry"');
  });

  it("accepts one Candidate Manifest and bounded runtime options", () => {
    expect(
      parseCandidateUiContractCommandLine([
        "--candidate-manifest",
        "/candidate/candidate-manifest.json",
        "--hub-port",
        "39123",
      ]),
    ).toEqual({
      candidateManifestPath: "/candidate/candidate-manifest.json",
      containerEngine: "docker",
      evidenceDir: path.resolve("release-ui-contract-evidence"),
      hubPort: 39_123,
    });
  });

  it("rejects inputs that could select source-backed or remote servers", () => {
    expect(() => parseCandidateUiContractCommandLine([])).toThrow(
      "--candidate-manifest is required",
    );
    expect(() =>
      parseCandidateUiContractCommandLine([
        "--candidate-manifest",
        "/candidate/not-the-manifest.json",
      ]),
    ).toThrow("must name candidate-manifest.json");
    expect(() =>
      parseCandidateUiContractCommandLine([
        "--candidate-manifest",
        "/candidate/candidate-manifest.json",
        "--base-url",
        "http://source-server:3000",
      ]),
    ).toThrow("unknown option");
  });

  it("runs Playwright against the validated candidate OCI runtime and always cleans it", async () => {
    const manifest = {
      candidate: { commit: "a".repeat(40), version: "v7.8.9" },
      hub: { digest: `sha256:${"b".repeat(64)}` },
      probeAssetSet: { version: "7.8.9" },
    };
    const start = vi.fn(async () => ({ container: "candidate-hub" }));
    const cleanup = vi.fn(async () => ({ clean: true }));
    const runPlaywright = vi.fn(async () => ({ code: 0 }));

    await expect(
      runCandidateUiContract(
        {
          candidateManifestPath: "/candidate/candidate-manifest.json",
          containerEngine: "docker",
          hubPort: 39_123,
        },
        {
          createHubController: () => ({ cleanup, start }),
          loadCandidate: async () => ({
            candidateDir: "/candidate",
            manifest,
          }),
          ownerPassword: "temporary-owner-password",
          runId: "ui-contract-test",
          runPlaywright,
        },
      ),
    ).resolves.toEqual({ code: 0 });

    expect(start).toHaveBeenCalledWith({
      candidateDir: "/candidate",
      candidateManifest: manifest,
      hubOwnerUrl: "http://127.0.0.1:39123/",
      hubPublicUrl: "http://127.0.0.1:39123/",
      ownerPassword: "temporary-owner-password",
      runId: "ui-contract-test",
    });
    expect(runPlaywright).toHaveBeenCalledWith({
      baseUrl: "http://127.0.0.1:39123/",
      candidateVersion: "7.8.9",
      ownerPassword: "temporary-owner-password",
    });
    expect(cleanup).toHaveBeenCalledWith({
      resources: { container: "candidate-hub" },
      runId: "ui-contract-test",
    });
  });

  it("preserves the Playwright failure after cleaning the candidate runtime", async () => {
    const cleanup = vi.fn(async () => ({ clean: true }));

    await expect(
      runCandidateUiContract(
        {
          candidateManifestPath: "/candidate/candidate-manifest.json",
          containerEngine: "docker",
          hubPort: 39_123,
        },
        {
          createHubController: () => ({
            cleanup,
            start: async () => ({ container: "candidate-hub" }),
          }),
          loadCandidate: async () => ({
            candidateDir: "/candidate",
            manifest: {
              candidate: { commit: "a".repeat(40), version: "v0.2.0" },
              hub: { digest: `sha256:${"b".repeat(64)}` },
              probeAssetSet: { version: "0.2.0" },
            },
          }),
          ownerPassword: "temporary-owner-password",
          runId: "ui-contract-test",
          runPlaywright: async () => ({ code: 1 }),
        },
      ),
    ).rejects.toThrow("Playwright UI Contract failed");
    expect(cleanup).toHaveBeenCalledOnce();
  });

  it("records every cleanup error without masking the Playwright failure", async () => {
    const cleanupError = new AggregateError(
      [new Error("container remained"), new Error("volume removal failed")],
      "Candidate Hub cleanup failed",
    );
    let thrown;

    try {
      await runCandidateUiContract(
        {
          candidateManifestPath: "/candidate/candidate-manifest.json",
          containerEngine: "docker",
          hubPort: 39_123,
        },
        {
          createHubController: () => ({
            cleanup: async () => {
              throw cleanupError;
            },
            start: async () => ({ container: "candidate-hub" }),
          }),
          loadCandidate: async () => ({
            candidateDir: "/candidate",
            manifest: {
              candidate: { commit: "a".repeat(40), version: "v7.8.9" },
              hub: { digest: `sha256:${"b".repeat(64)}` },
              probeAssetSet: { version: "7.8.9" },
            },
          }),
          ownerPassword: "temporary-owner-password",
          runId: "ui-contract-test",
          runPlaywright: async () => ({ code: 1 }),
        },
      );
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({
      cleanupError,
      message: "Playwright UI Contract failed with exit code 1",
    });
    expect(thrown.cleanupError.errors).toEqual([
      expect.objectContaining({ message: "container remained" }),
      expect.objectContaining({ message: "volume removal failed" }),
    ]);
  });

  it("always writes bounded redacted Hub, Playwright, and cleanup diagnostics for combined failures", async () => {
    const evidenceDir = await mkdtemp(
      path.join(tmpdir(), "enoki-ui-evidence-"),
    );
    const ownerPassword = "temporary-owner-password-secret";
    const cleanupError = new Error(
      `cleanup failed but must not leak ${ownerPassword}`,
    );

    try {
      await expect(
        runCandidateUiContract(
          {
            candidateManifestPath: "/candidate/candidate-manifest.json",
            containerEngine: "docker",
            evidenceDir,
            hubPort: 39_123,
          },
          {
            createHubController: () => ({
              cleanup: async () => {
                throw cleanupError;
              },
              collectEvidence: async () => ({
                activeManifestDigest: `sha256:${"b".repeat(64)}`,
                containerInspect: `container ${ownerPassword}`,
                identityVerified: true,
                logs: `${"x".repeat(300_000)} ${ownerPassword}`,
              }),
              start: async () => ({ container: "candidate-hub" }),
            }),
            loadCandidate: async () => ({
              candidateDir: "/candidate",
              manifest: {
                candidate: { commit: "a".repeat(40), version: "v7.8.9" },
                hub: { digest: `sha256:${"b".repeat(64)}` },
                probeAssetSet: { version: "7.8.9" },
              },
            }),
            ownerPassword,
            runId: "ui-contract-test",
            runPlaywright: async () => ({ code: 1 }),
          },
        ),
      ).rejects.toThrow("Playwright UI Contract failed");

      const raw = await readFile(
        path.join(evidenceDir, "runner-evidence.json"),
        "utf8",
      );
      const evidence = JSON.parse(raw);
      expect(evidence).toMatchObject({
        candidate: { commit: "a".repeat(40), version: "v7.8.9" },
        hub: {
          expectedManifestDigest: `sha256:${"b".repeat(64)}`,
          runtime: {
            activeManifestDigest: `sha256:${"b".repeat(64)}`,
            identityVerified: true,
          },
        },
        kind: "enoki-release-ui-contract-evidence",
        result: { status: "failed" },
        runId: "ui-contract-test",
        schemaVersion: 1,
      });
      expect(evidence.failures.map(({ phase }) => phase)).toEqual([
        "playwright",
        "cleanup",
      ]);
      expect(raw).not.toContain(ownerPassword);
      expect(raw.length).toBeLessThan(270_000);
    } finally {
      await rm(evidenceDir, { force: true, recursive: true });
    }
  });

  it("asks the controller to clean partial runtime state after startup fails", async () => {
    const cleanup = vi.fn(async () => ({ clean: true }));

    await expect(
      runCandidateUiContract(
        {
          candidateManifestPath: "/candidate/candidate-manifest.json",
          containerEngine: "docker",
          hubPort: 39_123,
        },
        {
          createHubController: () => ({
            cleanup,
            start: async () => {
              throw new Error("candidate Hub health timeout");
            },
          }),
          loadCandidate: async () => ({
            candidateDir: "/candidate",
            manifest: {
              candidate: { commit: "a".repeat(40), version: "v0.2.0" },
              hub: { digest: `sha256:${"b".repeat(64)}` },
              probeAssetSet: { version: "0.2.0" },
            },
          }),
          ownerPassword: "temporary-owner-password",
          runId: "ui-contract-test",
          runPlaywright: vi.fn(),
        },
      ),
    ).rejects.toThrow("candidate Hub health timeout");
    expect(cleanup).toHaveBeenCalledWith({
      resources: null,
      runId: "ui-contract-test",
    });
  });
});
