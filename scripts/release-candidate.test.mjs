import { execFile } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign as signBytes,
  verify as verifySignature,
} from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import { assertCandidateOnTrustedMain } from "./release-candidate-lib.mjs";

const execFileAsync = promisify(execFile);
const candidateCli = "scripts/release-candidate.mjs";
const commit = "0123456789abcdef0123456789abcdef01234567";
const checkedOutCommit = (
  await execFileAsync("git", ["rev-parse", "HEAD"])
).stdout.trim();
const probeTargets = [
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
];

describe("Enoki Release Candidate", () => {
  it("keeps candidate construction private and confines the production key to a trusted signer checkout", async () => {
    const workflow = await readFile(
      ".github/workflows/reusable-build-release-candidate.yml",
      "utf8",
    );
    const releaseWorkflow = await readFile(
      ".github/workflows/release.yml",
      "utf8",
    );

    expect(workflow).toContain("workflow_call:");
    expect(workflow).not.toContain("workflow_dispatch:");
    expect(releaseWorkflow).toContain("workflow_dispatch:");
    expect(releaseWorkflow).toContain(
      "uses: ./.github/workflows/reusable-build-release-candidate.yml",
    );
    expect(workflow).toContain("commit:");
    expect(workflow).toContain("version:");
    expect(workflow).toContain(
      "node trusted-tool/scripts/release-candidate.mjs assemble",
    );
    expect(workflow).toContain("--output type=oci");
    expect(workflow).toContain("actions/upload-artifact@");
    expect(workflow).not.toMatch(/gh release|docker push|--push|git tag/);

    const validationJob = workflow.slice(
      workflow.indexOf("  validate-candidate-inputs:"),
      workflow.indexOf("  build-probe:"),
    );
    expect(validationJob).not.toMatch(/^    if:/m);
    expect(validationJob).toContain(
      "YKDZ/enoki/.github/workflows/reusable-build-release-candidate.yml@refs/heads/main",
    );
    expect(validationJob).toContain("${{ toJSON(job) }}");
    expect(validationJob).toContain(".workflow_ref");
    expect(validationJob).toContain("${{ github.ref }}");
    expect(validationJob).toContain("exit 1");
    expect(
      validationJob.indexOf("Reject an untrusted workflow invocation"),
    ).toBeLessThan(validationJob.indexOf("Checkout exact candidate commit"));

    const signJob = workflow.slice(
      workflow.indexOf("  sign-probe-assets:"),
      workflow.indexOf("  build-hub-oci:"),
    );
    const prepareJob = workflow.slice(
      workflow.indexOf("  prepare-unsigned-probe-assets:"),
      workflow.indexOf("  sign-probe-assets:"),
    );
    const downstreamJobs = workflow.slice(workflow.indexOf("  build-hub-oci:"));
    expect(prepareJob).toContain("prepare-unsigned-probe-assets");
    expect(prepareJob).not.toContain("ENOKI_PROBE_ASSET_SIGNING_KEY_PEM");
    expect(signJob).toContain("environment: release-signing");
    expect(signJob).not.toContain("if: github.ref == 'refs/heads/main'");
    expect(signJob).toContain(
      "repository: ${{ needs.validate-candidate-inputs.outputs.trusted-workflow-repository }}",
    );
    expect(signJob).toContain(
      "ref: ${{ needs.validate-candidate-inputs.outputs.trusted-workflow-sha }}",
    );
    expect(signJob).toContain("path: trusted-signer");
    expect(signJob).toContain(
      "node trusted-signer/scripts/release-candidate.mjs sign-probe-assets",
    );
    expect(signJob).not.toContain("ref: ${{ inputs.commit }}");
    expect(signJob).toContain("ENOKI_PROBE_ASSET_SIGNING_KEY_PEM");
    expect(downstreamJobs).not.toContain("ENOKI_PROBE_ASSET_SIGNING_KEY_PEM");
    expect(workflow).toContain("actions/attest-build-provenance@v3");
    expect(workflow).toContain("subject-path: candidate.tar.gz");
    const assemblyJob = workflow.slice(
      workflow.indexOf("  assemble-candidate:"),
    );
    expect(assemblyJob).toContain("path: candidate-source");
    expect(assemblyJob).toContain("path: trusted-tool");
    expect(assemblyJob).toContain(
      "repository: ${{ needs.validate-candidate-inputs.outputs.trusted-workflow-repository }}",
    );
    expect(assemblyJob).toContain(
      "ref: ${{ needs.validate-candidate-inputs.outputs.trusted-workflow-sha }}",
    );
    expect(assemblyJob).toContain(
      "node trusted-tool/scripts/release-candidate.mjs assemble",
    );
    expect(assemblyJob).toContain("--source-dir candidate-source");
  });

  it("gates every candidate mode on a pushed commit that is an ancestor of the current protected main", async () => {
    const workflow = await readFile(
      ".github/workflows/reusable-build-release-candidate.yml",
      "utf8",
    );
    const validationJob = workflow.slice(
      workflow.indexOf("  validate-candidate-inputs:"),
      workflow.indexOf("  resolve-release-baseline:"),
    );
    expect(validationJob).toContain("fetch-depth: 0");
    expect(validationJob).toContain(
      "+refs/heads/main:refs/remotes/origin/main",
    );
    expect(validationJob).toContain(
      "release-candidate.mjs validate-source-policy",
    );
    expect(validationJob).toContain(
      "--trusted-main-ref refs/remotes/origin/main",
    );
    expect(validationJob).not.toMatch(/^    if:/m);

    const trustedMain = "1".repeat(40);
    const calls = [];
    const runCommand = async (command, arguments_, options) => {
      calls.push({ arguments_, command, options });
      if (arguments_[0] === "ls-remote") {
        return { stdout: `${trustedMain}\trefs/heads/main\n` };
      }
      if (arguments_[0] === "rev-parse") return { stdout: `${trustedMain}\n` };
      return { stdout: "" };
    };

    await expect(
      assertCandidateOnTrustedMain({
        candidateCommit: commit,
        remote: "origin",
        runCommand,
        sourceDir: ".",
        trustedMainRef: "refs/remotes/origin/main",
      }),
    ).resolves.toEqual({
      candidateCommit: commit,
      trustedMainCommit: trustedMain,
    });
    expect(calls.map(({ arguments_ }) => arguments_)).toEqual([
      ["ls-remote", "--exit-code", "origin", "refs/heads/main"],
      ["rev-parse", "refs/remotes/origin/main^{commit}"],
      ["cat-file", "-e", `${commit}^{commit}`],
      ["merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"],
    ]);
  });

  it.each([
    {
      failCommand: "rev-parse",
      name: "stale local protected-main ref",
      remoteMain: "1".repeat(40),
      trustedMain: "2".repeat(40),
      expected: "trusted main ref is stale",
    },
    {
      failCommand: "cat-file",
      name: "candidate object absent from the canonical checkout",
      remoteMain: "1".repeat(40),
      trustedMain: "1".repeat(40),
      expected: "not present in the canonical repository checkout",
    },
    {
      failCommand: "merge-base",
      name: "pushed commit outside protected main history",
      remoteMain: "1".repeat(40),
      trustedMain: "1".repeat(40),
      expected: "is not an ancestor of protected main",
    },
  ])("rejects a $name", async (scenario) => {
    const runCommand = async (_command, arguments_) => {
      if (arguments_[0] === "ls-remote") {
        return {
          stdout: `${scenario.remoteMain}\trefs/heads/main\n`,
        };
      }
      if (arguments_[0] === "rev-parse") {
        return { stdout: `${scenario.trustedMain}\n` };
      }
      if (arguments_[0] === scenario.failCommand) {
        throw new Error("git rejected the source policy check");
      }
      return { stdout: "" };
    };

    await expect(
      assertCandidateOnTrustedMain({
        candidateCommit: commit,
        remote: "origin",
        runCommand,
        sourceDir: ".",
        trustedMainRef: "refs/remotes/origin/main",
      }),
    ).rejects.toThrow(scenario.expected);
  });

  it("requires an explicit full commit and strict stable SemVer", async () => {
    const accepted = await runCandidateCli([
      "validate-inputs",
      "--commit",
      commit,
      "--version",
      "v1.2.3",
    ]);

    expect(accepted.stdout).toBe(
      `candidate inputs are valid: ${commit} v1.2.3\n`,
    );

    await expect(
      runCandidateCli([
        "validate-inputs",
        "--commit",
        "0123456",
        "--version",
        "v1.2.3",
      ]),
    ).rejects.toThrow("commit must be a full lowercase 40-character object ID");

    await expect(
      runCandidateCli([
        "validate-inputs",
        "--commit",
        commit,
        "--version",
        "v1.2.3-rc.1",
      ]),
    ).rejects.toThrow("version must be a stable SemVer tag like v1.2.3");

    await expect(
      runCandidateCli([
        "validate-inputs",
        "--commit",
        commit,
        "--version",
        "v1.2.3",
        "--unexpected",
        "value",
      ]),
    ).rejects.toThrow("unknown option for validate-inputs: --unexpected");
  });

  it("packages byte-identical Probe archives from identical binaries", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-reproducible-probe-"),
    );

    try {
      const binary = createProbeElf({
        target: "x86_64-unknown-linux-gnu",
        version: "v1.2.3",
      });
      const firstBinary = path.join(workDir, "first-probe");
      const secondBinary = path.join(workDir, "second-probe");
      await writeFile(firstBinary, binary, { mode: 0o700 });
      await writeFile(secondBinary, binary, { mode: 0o755 });
      const firstOutput = path.join(workDir, "first");
      const secondOutput = path.join(workDir, "second");
      const commonArguments = [
        "--source-date-epoch",
        "1234567890",
        "--target",
        "x86_64-unknown-linux-gnu",
        "--version",
        "v1.2.3",
      ];

      await runCandidateCli([
        "package-probe",
        "--binary",
        firstBinary,
        "--output-dir",
        firstOutput,
        ...commonArguments,
      ]);
      await runCandidateCli([
        "package-probe",
        "--binary",
        secondBinary,
        "--output-dir",
        secondOutput,
        ...commonArguments,
      ]);

      const file = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";
      expect(await readFile(path.join(firstOutput, file))).toEqual(
        await readFile(path.join(secondOutput, file)),
      );
      expect(await readFile(path.join(firstOutput, `${file}.sha256`))).toEqual(
        await readFile(path.join(secondOutput, `${file}.sha256`)),
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("pins release toolchain and base inputs while normalizing build metadata", async () => {
    const [toolchain, dockerfile, probeWorkflow, candidateWorkflow] =
      await Promise.all([
        readFile("rust-toolchain.toml", "utf8"),
        readFile("apps/hub/Dockerfile", "utf8"),
        readFile(".github/workflows/reusable-build-probe.yml", "utf8"),
        readFile(
          ".github/workflows/reusable-build-release-candidate.yml",
          "utf8",
        ),
      ]);

    expect(toolchain).toContain('channel = "1.97.1"');
    expect(toolchain).not.toContain('channel = "stable"');
    expect(dockerfile).toMatch(
      /^# syntax=docker[/]dockerfile:1[.]7@sha256:[0-9a-f]{64}$/m,
    );
    for (const from of dockerfile.matchAll(/^FROM ([^\s]+)/gm)) {
      if (from[1].includes(":")) {
        expect(from[1]).toMatch(/@sha256:[0-9a-f]{64}$/);
      }
    }
    expect(probeWorkflow).toContain("rustup toolchain install 1.97.1");
    expect(probeWorkflow).toContain("musl_tools_version: 1.2.2-4");
    expect(probeWorkflow).toContain("musl_tools_version: 1.2.4-2");
    expect(probeWorkflow).toContain(
      'musl-tools="${{ matrix.musl_tools_version }}"',
    );
    expect(probeWorkflow).toContain("--remap-path-prefix=");
    expect(probeWorkflow).toContain("--build-id=none");
    expect(probeWorkflow).toContain("package-probe");
    expect(candidateWorkflow).toContain("rewrite-timestamp=true");
    expect(candidateWorkflow).toContain("package-candidate");
    expect(dockerfile).toContain("su-exec-0.3-r0.apk");
    expect(dockerfile).toContain("ADD --checksum=sha256:");
    expect(dockerfile).toContain(
      "apk add --allow-untrusted --no-network /tmp/su-exec.apk",
    );
  });

  it("makes the formal candidate workflow compare two clean builds of every Probe target and the Hub image", async () => {
    const [probeWorkflow, candidateWorkflow] = await Promise.all([
      readFile(".github/workflows/reusable-build-probe.yml", "utf8"),
      readFile(
        ".github/workflows/reusable-build-release-candidate.yml",
        "utf8",
      ),
    ]);

    expect(candidateWorkflow).toContain("verify-reproducible: true");
    expect(probeWorkflow).toContain("verify-reproducible:");
    expect(probeWorkflow).toContain("rm -rf target/reproducible");
    expect(probeWorkflow).toContain("dist-reproducibility-second");
    expect(probeWorkflow).toContain("cmp --silent");
    expect(candidateWorkflow).toContain("hub-reproducibility-first");
    expect(candidateWorkflow).toContain("hub-reproducibility-second");
    expect(candidateWorkflow).toContain("--no-cache");
    expect(candidateWorkflow).toContain("compare-hub-builds");
    expect(candidateWorkflow).not.toMatch(
      /name: candidate-hub-oci-reproducibility-second/,
    );
  });

  it("rejects two individually valid Hub OCI builds when their image digests differ", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-hub-reproducibility-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const first = await createOciFixture(workDir, probeAssetSetDir, {
        name: "first",
      });
      const second = await createOciFixture(workDir, probeAssetSetDir, {
        extraLayers: [
          async (rootfsDir) => {
            await mkdir(rootfsDir, { recursive: true });
            await writeFile(
              path.join(rootfsDir, "second-build-marker"),
              "different",
            );
          },
        ],
        name: "second",
      });

      await expect(
        runCandidateCli([
          "compare-hub-builds",
          "--first",
          first.archivePath,
          "--second",
          second.archivePath,
          "--probe-assets",
          probeAssetSetDir,
        ]),
      ).rejects.toThrow("Hub OCI builds are not reproducible");
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("binds candidate identity to the checked-out source commit", async () => {
    await expect(
      runCandidateCli([
        "validate-inputs",
        "--commit",
        commit,
        "--version",
        "v1.2.3",
        "--source-dir",
        ".",
      ]),
    ).rejects.toThrow(
      `candidate commit ${commit} does not match checked-out source ${checkedOutCommit}`,
    );
  });

  it("refuses to assemble a candidate whose declared commit is not its source checkout", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-provenance-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const oci = await createOciFixture(workDir, probeAssetSetDir);
      const releaseBaselineDir =
        await createFirstReleaseBaselineFixture(workDir);

      await expect(
        runCandidateCli([
          "assemble",
          "--commit",
          commit,
          "--source-dir",
          ".",
          "--version",
          "v1.2.3",
          "--probe-assets",
          probeAssetSetDir,
          "--hub-oci",
          oci.archivePath,
          "--release-baseline",
          releaseBaselineDir,
          "--output",
          path.join(workDir, "candidate"),
        ]),
      ).rejects.toThrow(
        `candidate commit ${commit} does not match checked-out source ${checkedOutCommit}`,
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("emits one complete signed Probe Asset Set without the private key", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-candidate-sign-"));

    try {
      const { outputDir, privateKey, publicKey } =
        await createProbeAssetSetFixture(workDir);

      const expectedFiles = [
        ...probeTargets.flatMap((target) => [
          `enoki-probe-${target}.tar.gz`,
          `enoki-probe-${target}.tar.gz.sha256`,
        ]),
        "install-probe.sh",
        "manifest.json",
        "manifest.json.sig",
        "signing-key.pem",
      ].sort();
      expect((await readdir(outputDir)).sort()).toEqual(expectedFiles);

      const manifestBytes = await readFile(
        path.join(outputDir, "manifest.json"),
      );
      const manifest = JSON.parse(manifestBytes.toString("utf8"));
      expect(manifest).toMatchObject({
        kind: "enoki-probe-assets",
        version: "1.2.3",
      });
      expect(manifest.assets.map(({ target }) => target)).toEqual(probeTargets);
      expect(
        verifySignature(
          "RSA-SHA256",
          manifestBytes,
          publicKey,
          await readFile(path.join(outputDir, "manifest.json.sig")),
        ),
      ).toBe(true);

      const publicKeySha256 = sha256(Buffer.from(publicKey));
      expect(
        await readFile(path.join(outputDir, "install-probe.sh"), "utf8"),
      ).toContain(publicKeySha256);
      expect(JSON.stringify(await readdir(outputDir))).not.toContain(
        privateKey,
      );

      const validation = await runCandidateCli([
        "validate-probe-assets",
        outputDir,
      ]);
      expect(validation.stdout).toBe(
        `Probe Asset Set is valid: 1.2.3 ${publicKeySha256}\n`,
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a checksum-valid Probe asset that is not a tar.gz archive before signing", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-not-tar-"),
    );

    try {
      await expect(
        createProbeAssetSetFixture(workDir, {
          mutateArchives: async (archivesDir) => {
            const file = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";
            const contents = Buffer.from("not a gzip or tar archive");
            await writeFile(path.join(archivesDir, file), contents);
            await writeFile(
              path.join(archivesDir, `${file}.sha256`),
              `${sha256(contents)}  ${file}\n`,
            );
          },
        }),
      ).rejects.toThrow("is not a valid gzip/tar archive");
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a Probe archive whose ELF target disagrees with its asset name before signing", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-wrong-target-"),
    );

    try {
      await expect(
        createProbeAssetSetFixture(workDir, {
          mutateArchives: async (archivesDir) => {
            const file = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";
            const archivePath = path.join(archivesDir, file);
            await writeProbeArchive(archivePath, {
              target: "aarch64-unknown-linux-gnu",
              version: "v1.2.3",
            });
            const contents = await readFile(archivePath);
            await writeFile(
              `${archivePath}.sha256`,
              `${sha256(contents)}  ${file}\n`,
            );
          },
        }),
      ).rejects.toThrow(
        "enoki-probe-x86_64-unknown-linux-gnu.tar.gz ELF architecture does not match x86_64-unknown-linux-gnu",
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a Probe archive containing payload beyond enoki-probe", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-extra-payload-"),
    );
    try {
      await expect(
        createProbeAssetSetFixture(workDir, {
          mutateArchives: async (archivesDir) => {
            const file = "enoki-probe-aarch64-unknown-linux-musl.tar.gz";
            const archivePath = path.join(archivesDir, file);
            await writeProbeArchive(archivePath, {
              extraPayload: true,
              target: "aarch64-unknown-linux-musl",
              version: "v1.2.3",
            });
            const contents = await readFile(archivePath);
            await writeFile(
              `${archivePath}.sha256`,
              `${sha256(contents)}  ${file}\n`,
            );
          },
        }),
      ).rejects.toThrow("must contain exactly the enoki-probe payload");
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a non-executable Probe archive payload", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-non-executable-"),
    );
    try {
      await expect(
        createProbeAssetSetFixture(workDir, {
          mutateArchives: async (archivesDir) => {
            const file = "enoki-probe-aarch64-unknown-linux-gnu.tar.gz";
            const archivePath = path.join(archivesDir, file);
            await writeProbeArchive(archivePath, {
              mode: 0o644,
              target: "aarch64-unknown-linux-gnu",
              version: "v1.2.3",
            });
            const contents = await readFile(archivePath);
            await writeFile(
              `${archivePath}.sha256`,
              `${sha256(contents)}  ${file}\n`,
            );
          },
        }),
      ).rejects.toThrow("payload must be executable");
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a Probe ELF whose loader ABI disagrees with its target", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-wrong-abi-"),
    );
    try {
      const file = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";
      await expect(
        createProbeAssetSetFixture(workDir, {
          mutateArchives: async (archivesDir) => {
            const archivePath = path.join(archivesDir, file);
            await writeProbeArchive(archivePath, {
              interpreter: "/lib/ld-musl-x86_64.so.1\0",
              target: "x86_64-unknown-linux-gnu",
              version: "v1.2.3",
            });
            const contents = await readFile(archivePath);
            await writeFile(
              `${archivePath}.sha256`,
              `${sha256(contents)}  ${file}\n`,
            );
          },
        }),
      ).rejects.toThrow(
        `${file} ELF ABI does not match x86_64-unknown-linux-gnu`,
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it.each([
    ["x86_64-unknown-linux-gnu", "/lib64/ld-linux-x86-64.so.2.missing\0"],
    ["aarch64-unknown-linux-gnu", "/lib/ld-linux-aarch64.so.1.missing\0"],
    ["x86_64-unknown-linux-musl", "/lib/ld-musl-x86_64.so.1.missing\0"],
    ["aarch64-unknown-linux-musl", "/lib/ld-musl-aarch64.so.1.missing\0"],
  ])(
    "rejects a %s Probe whose dynamic loader only contains the expected path as a prefix",
    async (target, interpreter) => {
      const workDir = await mkdtemp(
        path.join(tmpdir(), "enoki-candidate-loader-suffix-"),
      );
      const file = `enoki-probe-${target}.tar.gz`;

      try {
        await expect(
          createProbeAssetSetFixture(workDir, {
            mutateArchives: async (archivesDir) => {
              const archivePath = path.join(archivesDir, file);
              await writeProbeArchive(archivePath, {
                interpreter,
                target,
                version: "v1.2.3",
              });
              const contents = await readFile(archivePath);
              await writeFile(
                `${archivePath}.sha256`,
                `${sha256(contents)}  ${file}\n`,
              );
            },
          }),
        ).rejects.toThrow(`${file} ELF ABI does not match ${target}`);
      } finally {
        await rm(workDir, { force: true, recursive: true });
      }
    },
  );

  it.each([
    ["x86_64-unknown-linux-musl", "static", undefined],
    ["x86_64-unknown-linux-musl", "dynamic", "/lib/ld-musl-x86_64.so.1\0"],
    ["aarch64-unknown-linux-musl", "static", undefined],
    ["aarch64-unknown-linux-musl", "dynamic", "/lib/ld-musl-aarch64.so.1\0"],
  ])(
    "accepts a %s Probe with its allowlisted %s musl linkage",
    async (target, linkage, interpreter) => {
      const workDir = await mkdtemp(
        path.join(tmpdir(), `enoki-candidate-musl-${linkage}-`),
      );
      const binaryPath = path.join(workDir, "enoki-probe");

      try {
        await writeFile(
          binaryPath,
          createProbeElf({ interpreter, target, version: "v1.2.3" }),
          { mode: 0o755 },
        );
        await expect(
          runCandidateCli([
            "package-probe",
            "--binary",
            binaryPath,
            "--output-dir",
            path.join(workDir, "dist"),
            "--source-date-epoch",
            "0",
            "--target",
            target,
            "--version",
            "v1.2.3",
          ]),
        ).resolves.toMatchObject({ stderr: "" });
      } finally {
        await rm(workDir, { force: true, recursive: true });
      }
    },
  );

  it("offline validation rejects a correctly re-signed Probe archive with the wrong embedded version", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-wrong-version-"),
    );

    try {
      const { candidateDir, privateKey } =
        await createCandidateFixture(workDir);
      const assetDir = path.join(candidateDir, "probe-assets");
      const file = "enoki-probe-x86_64-unknown-linux-musl.tar.gz";
      const archivePath = path.join(assetDir, file);
      await writeProbeArchive(archivePath, {
        target: "x86_64-unknown-linux-musl",
        version: "v9.9.9",
      });
      const archive = await readFile(archivePath);
      const archiveSha256 = sha256(archive);
      await writeFile(`${archivePath}.sha256`, `${archiveSha256}  ${file}\n`);

      const manifestPath = path.join(assetDir, "manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      const asset = manifest.assets.find((entry) => entry.file === file);
      asset.sha256 = archiveSha256;
      asset.size = archive.byteLength;
      const manifestBytes = Buffer.from(
        `${JSON.stringify(manifest, null, 2)}\n`,
      );
      await writeFile(manifestPath, manifestBytes);
      await writeFile(
        path.join(assetDir, "manifest.json.sig"),
        signBytes("RSA-SHA256", manifestBytes, privateKey),
      );

      await expect(runCandidateCli(["validate", candidateDir])).rejects.toThrow(
        `${file} embedded Probe version does not match v1.2.3`,
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("assembles a deterministic Candidate Manifest around byte-identical Hub and Probe content", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-assemble-"),
    );

    try {
      const {
        candidateDir,
        oci,
        probeAssetSetDir,
        publicKey,
        releaseBaselineDir,
      } = await createCandidateFixture(workDir);

      const manifestText = await readFile(
        path.join(candidateDir, "candidate-manifest.json"),
        "utf8",
      );
      const manifest = JSON.parse(manifestText);
      expect(manifest).toMatchObject({
        candidate: { commit: checkedOutCommit, version: "v1.2.3" },
        hub: {
          archive: "hub/enoki-hub-v1.2.3.oci.tar",
          digest: oci.manifestDigest,
          embeddedProbeVersion: "1.2.3",
        },
        kind: "enoki-release-candidate",
        probeAssetSet: {
          directory: "probe-assets",
          signingIdentity: {
            algorithm: "rsa-sha256",
            publicKeyFile: "signing-key.pem",
            publicKeySha256: sha256(Buffer.from(publicKey)),
          },
          version: "1.2.3",
        },
        releaseBaseline: {
          catalogSnapshot: {
            entries: [],
            sha256: sha256(Buffer.from("[]")),
          },
          kind: "first-formal-release",
        },
        schemaVersion: 2,
      });
      expect(manifest.probeAssetSet.files.map(({ file }) => file)).toEqual(
        (await readdir(probeAssetSetDir)).sort(),
      );
      expect(manifestText.endsWith("\n")).toBe(true);

      const secondCandidateDir = path.join(workDir, "candidate-second");
      await runCandidateCli([
        "assemble",
        "--commit",
        checkedOutCommit,
        "--source-dir",
        ".",
        "--version",
        "v1.2.3",
        "--probe-assets",
        probeAssetSetDir,
        "--hub-oci",
        oci.archivePath,
        "--release-baseline",
        releaseBaselineDir,
        "--output",
        secondCandidateDir,
      ]);
      expect(
        await readFile(
          path.join(secondCandidateDir, "candidate-manifest.json"),
          "utf8",
        ),
      ).toBe(manifestText);

      const validation = await runCandidateCli(["validate", candidateDir]);
      expect(validation.stdout).toContain(
        `candidate is valid: ${checkedOutCommit} v1.2.3 ${oci.manifestDigest}`,
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("packages a validated Candidate directory reproducibly", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-reproducible-transfer-"),
    );

    try {
      const { candidateDir } = await createCandidateFixture(workDir);
      const first = path.join(workDir, "first.tar.gz");
      const second = path.join(workDir, "second.tar.gz");
      for (const output of [first, second]) {
        await runCandidateCli([
          "package-candidate",
          "--candidate",
          candidateDir,
          "--output",
          output,
          "--source-date-epoch",
          "0",
        ]);
      }

      expect(await readFile(first)).toEqual(await readFile(second));
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects an incorrectly signed Probe Asset Set", async () => {
    await expectCandidateMutationRejected(async (candidateDir) => {
      await writeFile(
        path.join(candidateDir, "probe-assets", "manifest.json.sig"),
        "not the candidate signature",
      );
    }, "Probe Asset Set manifest signature is invalid");
  });

  it("rejects a Probe archive checksum failure", async () => {
    await expectCandidateMutationRejected(async (candidateDir) => {
      await writeFile(
        path.join(
          candidateDir,
          "probe-assets",
          "enoki-probe-x86_64-unknown-linux-gnu.tar.gz",
        ),
        "modified candidate archive",
      );
    }, "Probe Asset Set checksum does not match enoki-probe-x86_64-unknown-linux-gnu.tar.gz");
  });

  it("rejects Hub and Probe version disagreement", async () => {
    await expectCandidateMutationRejected(async (candidateDir) => {
      const manifestPath = path.join(candidateDir, "candidate-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      manifest.hub.embeddedProbeVersion = "1.2.4";
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    }, "Candidate Manifest Hub and Probe versions disagree");
  });

  it("requires exactly one valid Release Baseline descriptor or first-formal-release marker", async () => {
    await expectCandidateMutationRejected(async (candidateDir) => {
      const manifestPath = path.join(candidateDir, "candidate-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      delete manifest.releaseBaseline;
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    }, "releaseBaseline");

    await expectCandidateMutationRejected(async (candidateDir) => {
      const manifestPath = path.join(candidateDir, "candidate-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      manifest.releaseBaseline.unexpected = "second-path";
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    }, "manifest fields must be exactly: catalogSnapshot, kind");

    await expectCandidateMutationRejected(async (candidateDir) => {
      const manifestPath = path.join(candidateDir, "candidate-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      manifest.releaseBaseline.catalogSnapshot.sha256 = "f".repeat(64);
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    }, "Release catalog snapshot checksum is invalid");
  }, 15_000);

  it("rejects an incomplete Probe target set", async () => {
    await expectCandidateMutationRejected(async (candidateDir) => {
      await unlink(
        path.join(
          candidateDir,
          "probe-assets",
          "enoki-probe-aarch64-unknown-linux-musl.tar.gz.sha256",
        ),
      );
    }, "Probe Asset Set must contain exactly");
  });

  it("rejects additional candidate content and a mismatched Hub digest", async () => {
    await expectCandidateMutationRejected(async (candidateDir) => {
      await writeFile(path.join(candidateDir, "undeclared.txt"), "extra");
    }, "Enoki Release Candidate directory must contain exactly");

    await expectCandidateMutationRejected(async (candidateDir) => {
      const manifestPath = path.join(candidateDir, "candidate-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      manifest.hub.digest = `sha256:${"0".repeat(64)}`;
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    }, "Candidate Hub OCI digest does not match");
  }, 15_000);

  it("rejects a Hub OCI image whose config descriptor is not the OCI image config media type", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-config-media-type-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const oci = await createOciFixture(workDir, probeAssetSetDir, {
        configMediaType: "application/json",
      });

      await expect(
        assembleFixtureCandidate(workDir, probeAssetSetDir, oci.archivePath),
      ).rejects.toThrow(
        "Hub OCI image config descriptor media type is unsupported",
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a Hub OCI image config for a non-amd64 architecture", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-config-architecture-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const oci = await createOciFixture(workDir, probeAssetSetDir, {
        architecture: "arm64",
      });

      await expect(
        assembleFixtureCandidate(workDir, probeAssetSetDir, oci.archivePath),
      ).rejects.toThrow("Hub OCI image config must target linux/amd64");
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a Hub OCI image config for a non-linux operating system", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-config-os-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const oci = await createOciFixture(workDir, probeAssetSetDir, {
        os: "windows",
      });

      await expect(
        assembleFixtureCandidate(workDir, probeAssetSetDir, oci.archivePath),
      ).rejects.toThrow("Hub OCI image config must target linux/amd64");
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a Hub OCI image whose rootfs diff_ids count disagrees with its layers", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-diff-ids-count-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const oci = await createOciFixture(workDir, probeAssetSetDir, {
        diffIds: [],
      });

      await expect(
        assembleFixtureCandidate(workDir, probeAssetSetDir, oci.archivePath),
      ).rejects.toThrow(
        "Hub OCI image rootfs diff_ids must match image layers",
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a Hub OCI image whose rootfs diff_id does not identify the corresponding uncompressed layer", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-diff-id-digest-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const oci = await createOciFixture(workDir, probeAssetSetDir, {
        diffIds: [`sha256:${"0".repeat(64)}`],
      });

      await expect(
        assembleFixtureCandidate(workDir, probeAssetSetDir, oci.archivePath),
      ).rejects.toThrow("Hub OCI image rootfs diff_id does not match layer 0");
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("accepts a gzipped Hub layer only when diff_id identifies its uncompressed tar bytes", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-gzip-diff-id-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const oci = await createOciFixture(workDir, probeAssetSetDir, {
        compressLayers: true,
      });

      await expect(
        assembleFixtureCandidate(workDir, probeAssetSetDir, oci.archivePath),
      ).resolves.toMatchObject({ stderr: "" });
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("evaluates parent whiteouts when validating the Hub final rootfs", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-parent-whiteout-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const oci = await createOciFixture(workDir, probeAssetSetDir, {
        extraLayers: [
          async (rootfsDir) => {
            const appDir = path.join(rootfsDir, "app");
            await mkdir(appDir, { recursive: true });
            await writeFile(path.join(appDir, ".wh.probe-assets"), "");
          },
        ],
      });
      const releaseBaselineDir =
        await createFirstReleaseBaselineFixture(workDir);

      await expect(
        runCandidateCli([
          "assemble",
          "--commit",
          checkedOutCommit,
          "--source-dir",
          ".",
          "--version",
          "v1.2.3",
          "--probe-assets",
          probeAssetSetDir,
          "--hub-oci",
          oci.archivePath,
          "--release-baseline",
          releaseBaselineDir,
          "--output",
          path.join(workDir, "candidate"),
        ]),
      ).rejects.toThrow(
        "Hub OCI embedded Probe Asset Set must contain exactly",
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("evaluates opaque parent directories when validating the Hub final rootfs", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-parent-opaque-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const oci = await createOciFixture(workDir, probeAssetSetDir, {
        extraLayers: [
          async (rootfsDir) => {
            const appDir = path.join(rootfsDir, "app");
            await mkdir(appDir, { recursive: true });
            await writeFile(path.join(appDir, ".wh..wh..opq"), "");
          },
        ],
      });

      await expect(
        assembleFixtureCandidate(workDir, probeAssetSetDir, oci.archivePath),
      ).rejects.toThrow(
        "Hub OCI embedded Probe Asset Set must contain exactly",
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects a non-regular Probe asset entry in the Hub final rootfs", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-entry-type-"),
    );

    try {
      const { outputDir: probeAssetSetDir } =
        await createProbeAssetSetFixture(workDir);
      const replacedFile = "manifest.json";
      const oci = await createOciFixture(workDir, probeAssetSetDir, {
        extraLayers: [
          async (rootfsDir) => {
            const assetDir = path.join(rootfsDir, "app", "probe-assets");
            await mkdir(assetDir, { recursive: true });
            await symlink("signing-key.pem", path.join(assetDir, replacedFile));
          },
        ],
      });

      await expect(
        assembleFixtureCandidate(workDir, probeAssetSetDir, oci.archivePath),
      ).rejects.toThrow(
        `Hub OCI embedded Probe asset differs from ${replacedFile}`,
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });
});

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

async function createProbeAssetSetFixture(
  workDir,
  { mutateArchives, targets = probeTargets, version = "v1.2.3" } = {},
) {
  const archivesDir = path.join(workDir, "archives");
  const outputDir = path.join(workDir, "probe-assets");
  const installerPath = path.join(workDir, "install-probe.sh");
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });

  await mkdir(archivesDir, { recursive: true });
  for (const target of targets) {
    const file = `enoki-probe-${target}.tar.gz`;
    await writeProbeArchive(path.join(archivesDir, file), {
      target,
      version,
    });
    const contents = await readFile(path.join(archivesDir, file));
    const checksum = sha256(contents);
    await writeFile(
      path.join(archivesDir, `${file}.sha256`),
      `${checksum}  ${file}\n`,
    );
  }
  await mutateArchives?.(archivesDir);
  await writeFile(
    installerPath,
    "#!/bin/sh\nreadonly TRUST='__ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256__'\n",
  );

  await runCandidateCli(
    [
      "prepare-probe-assets",
      "--version",
      version,
      "--archives-dir",
      archivesDir,
      "--installer",
      installerPath,
      "--output",
      outputDir,
      "--private-key-env",
      "TEST_PRIVATE_KEY",
      "--public-key-env",
      "TEST_PUBLIC_KEY",
    ],
    {
      TEST_PRIVATE_KEY: privateKey,
      TEST_PUBLIC_KEY: publicKey,
    },
  );

  return { archivesDir, outputDir, privateKey, publicKey };
}

async function writeProbeArchive(
  archivePath,
  { extraPayload = false, interpreter, mode = 0o755, target, version },
) {
  const binaryDir = `${archivePath}.contents`;
  const binaryPath = path.join(binaryDir, "enoki-probe");
  await mkdir(binaryDir, { recursive: true });
  await writeFile(binaryPath, createProbeElf({ interpreter, target, version }));
  await chmod(binaryPath, mode);
  if (extraPayload) {
    await writeFile(path.join(binaryDir, "unexpected"), "not allowlisted");
  }
  await execFileAsync("tar", [
    "--create",
    "--gzip",
    "--file",
    archivePath,
    "--directory",
    binaryDir,
    ...(extraPayload ? ["."] : ["enoki-probe"]),
  ]);
  await rm(binaryDir, { force: true, recursive: true });
}

function createProbeElf({ interpreter: interpreterOverride, target, version }) {
  const architecture = target.startsWith("x86_64-") ? 62 : 183;
  const interpreter =
    interpreterOverride ??
    (target.endsWith("-gnu")
      ? target.startsWith("x86_64-")
        ? "/lib64/ld-linux-x86-64.so.2\0"
        : "/lib/ld-linux-aarch64.so.1\0"
      : "");
  const headerSize = 64;
  const programHeaderSize = interpreter ? 56 : 0;
  const marker = Buffer.from(
    `ENOKI_PROBE_TARGET=${target}\0ENOKI_PROBE_VERSION=${version}\0`,
  );
  const interpreterBytes = Buffer.from(interpreter);
  const result = Buffer.alloc(
    headerSize + programHeaderSize + interpreterBytes.length + marker.length,
  );
  result.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  result.writeUInt16LE(2, 16);
  result.writeUInt16LE(architecture, 18);
  result.writeUInt32LE(1, 20);
  result.writeUInt16LE(headerSize, 52);
  result.writeUInt16LE(56, 54);
  result.writeUInt16LE(interpreter ? 1 : 0, 56);
  if (interpreter) {
    result.writeBigUInt64LE(BigInt(headerSize), 32);
    result.writeUInt32LE(3, headerSize);
    result.writeUInt32LE(4, headerSize + 4);
    result.writeBigUInt64LE(
      BigInt(headerSize + programHeaderSize),
      headerSize + 8,
    );
    result.writeBigUInt64LE(BigInt(interpreterBytes.length), headerSize + 32);
    result.writeBigUInt64LE(BigInt(interpreterBytes.length), headerSize + 40);
    result.set(interpreterBytes, headerSize + programHeaderSize);
  }
  result.set(marker, headerSize + programHeaderSize + interpreterBytes.length);
  return result;
}

async function createOciFixture(
  workDir,
  probeAssetSetDir,
  {
    architecture = "amd64",
    compressLayers = false,
    configMediaType = "application/vnd.oci.image.config.v1+json",
    diffIds,
    extraLayers = [],
    name = "fixture",
    os = "linux",
  } = {},
) {
  const layoutDir = path.join(workDir, `oci-layout-${name}`);
  const blobsDir = path.join(layoutDir, "blobs", "sha256");
  await mkdir(blobsDir, { recursive: true });
  const layerDescriptors = [];
  const layerDiffIds = [];
  const layerWriters = [
    async (rootfsDir) => {
      const embeddedAssetsDir = path.join(rootfsDir, "app", "probe-assets");
      await mkdir(embeddedAssetsDir, { recursive: true });
      await cp(probeAssetSetDir, embeddedAssetsDir, { recursive: true });
    },
    ...extraLayers,
  ];
  for (let index = 0; index < layerWriters.length; index += 1) {
    const rootfsDir = path.join(workDir, `rootfs-${name}-${index}`);
    await layerWriters[index](rootfsDir);
    const layerPath = path.join(workDir, `layer-${name}-${index}.tar`);
    await execFileAsync("tar", ["-cf", layerPath, "-C", rootfsDir, "."]);
    const layerBytes = await readFile(layerPath);
    layerDiffIds.push(`sha256:${sha256(layerBytes)}`);
    const storedLayerBytes = compressLayers ? gzipSync(layerBytes) : layerBytes;
    layerDescriptors.push(
      await writeOciBlob(blobsDir, storedLayerBytes, {
        mediaType: compressLayers
          ? "application/vnd.oci.image.layer.v1.tar+gzip"
          : "application/vnd.oci.image.layer.v1.tar",
      }),
    );
  }

  const configBytes = Buffer.from(
    `${JSON.stringify({
      architecture,
      os,
      rootfs: {
        diff_ids: diffIds ?? layerDiffIds,
        type: "layers",
      },
    })}\n`,
  );
  const configDescriptor = await writeOciBlob(blobsDir, configBytes, {
    mediaType: configMediaType,
  });
  const imageManifestBytes = Buffer.from(
    `${JSON.stringify({
      config: configDescriptor,
      layers: layerDescriptors,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      schemaVersion: 2,
    })}\n`,
  );
  const imageManifestDescriptor = await writeOciBlob(
    blobsDir,
    imageManifestBytes,
    { mediaType: "application/vnd.oci.image.manifest.v1+json" },
  );

  await writeFile(
    path.join(layoutDir, "oci-layout"),
    `${JSON.stringify({ imageLayoutVersion: "1.0.0" })}\n`,
  );
  await writeFile(
    path.join(layoutDir, "index.json"),
    `${JSON.stringify({
      manifests: [imageManifestDescriptor],
      schemaVersion: 2,
    })}\n`,
  );

  const archivePath = path.join(workDir, `hub-${name}.oci.tar`);
  await execFileAsync("tar", ["-cf", archivePath, "-C", layoutDir, "."]);
  return {
    archivePath,
    manifestDigest: imageManifestDescriptor.digest,
  };
}

async function createCandidateFixture(workDir, { version = "v1.2.3" } = {}) {
  const {
    outputDir: probeAssetSetDir,
    privateKey,
    publicKey,
  } = await createProbeAssetSetFixture(workDir, { version });
  const oci = await createOciFixture(workDir, probeAssetSetDir);
  const candidateDir = path.join(workDir, "candidate");
  const releaseBaselineDir = await createFirstReleaseBaselineFixture(workDir);

  await runCandidateCli([
    "assemble",
    "--commit",
    checkedOutCommit,
    "--source-dir",
    ".",
    "--version",
    version,
    "--probe-assets",
    probeAssetSetDir,
    "--hub-oci",
    oci.archivePath,
    "--release-baseline",
    releaseBaselineDir,
    "--output",
    candidateDir,
  ]);

  return {
    candidateDir,
    oci,
    privateKey,
    probeAssetSetDir,
    publicKey,
    releaseBaselineDir,
  };
}

async function writeOciBlob(blobsDir, contents, descriptor) {
  const digestHex = sha256(contents);
  await writeFile(path.join(blobsDir, digestHex), contents);
  return {
    ...descriptor,
    digest: `sha256:${digestHex}`,
    size: contents.byteLength,
  };
}

async function assembleFixtureCandidate(workDir, probeAssetSetDir, hubOciPath) {
  const releaseBaselineDir = await createFirstReleaseBaselineFixture(workDir);
  return runCandidateCli([
    "assemble",
    "--commit",
    checkedOutCommit,
    "--source-dir",
    ".",
    "--version",
    "v1.2.3",
    "--probe-assets",
    probeAssetSetDir,
    "--hub-oci",
    hubOciPath,
    "--release-baseline",
    releaseBaselineDir,
    "--output",
    path.join(workDir, "candidate"),
  ]);
}

async function createFirstReleaseBaselineFixture(workDir) {
  const releaseBaselineDir = path.join(workDir, "release-baseline-input");
  await mkdir(releaseBaselineDir, { recursive: true });
  await writeFile(
    path.join(releaseBaselineDir, "release-baseline.json"),
    `${JSON.stringify(
      {
        catalogSnapshot: {
          entries: [],
          sha256: sha256(Buffer.from("[]")),
        },
        kind: "first-formal-release",
      },
      null,
      2,
    )}\n`,
  );
  return releaseBaselineDir;
}

async function expectCandidateMutationRejected(mutate, expectedMessage) {
  const workDir = await mkdtemp(
    path.join(tmpdir(), "enoki-candidate-invalid-"),
  );
  try {
    const { candidateDir } = await createCandidateFixture(workDir);
    await mutate(candidateDir);
    await expect(runCandidateCli(["validate", candidateDir])).rejects.toThrow(
      expectedMessage,
    );
  } finally {
    await rm(workDir, { force: true, recursive: true });
  }
}

function runCandidateCli(arguments_, environment = {}) {
  return execFileAsync("node", [candidateCli, ...arguments_], {
    cwd: process.cwd(),
    env: { ...process.env, ...environment },
  });
}
