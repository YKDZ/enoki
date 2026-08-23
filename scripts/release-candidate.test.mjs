import { execFile } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
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

import { packageProbeBootstrapArtifact } from "./probe-bootstrap-artifact.mjs";
import { createReleaseCatalogSnapshot } from "./release-baseline-lib.mjs";
import {
  createProbeBootstrapPublication,
  createProbeTrustDelegation,
  inspectProbeAssetSet,
  validateDelegatedProbeSigningIdentity,
  validateProbeSigningIdentity,
  verifyProbeTrustDelegation,
} from "./release-candidate-lib.mjs";
import { loadValidatedCandidate } from "./release-e2e-adapters.mjs";
import { createReleaseTransitionContract } from "./release-transition-contract.mjs";
import { createSignedLegacyProbeAssetSetFixture } from "./release-transition-test-fixture.mjs";
import { createTrustEpochMigrationAuthorization } from "./trust-epoch-migration-lib.mjs";

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
const testDistributionRoot = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

describe("Enoki Release Candidate", { timeout: 15_000 }, () => {
  it("generates the bootstrap recipe from the canonical seven-role bundle closure", async () => {
    const publication = await createProbeBootstrapPublication({
      bundleVersion: "1.2.3",
      sourceDir: process.cwd(),
      trustedRootPublicKeyPem: testDistributionRoot.publicKey,
    });
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-recipe-roles-"));
    const recipePath = path.join(directory, "recipe.py");
    await writeFile(recipePath, publication.recipeBytes);
    const program = String.raw`
import hashlib, importlib.util, io, json, pathlib, sys, tarfile, tempfile
spec = importlib.util.spec_from_file_location("enoki_recipe", sys.argv[1])
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)
assert set(recipe.EXPECTED_ROLES) == {"components", "bootstrapAssets"}
assert len(recipe.EXPECTED_ROLES["components"]) == 5
assert len(recipe.EXPECTED_ROLES["bootstrapAssets"]) == 2
assert recipe.EXPECTED_ROLES["components"]["lifecycle-companion"]["resourceContract"] == "local-lifecycle-v1"
payloads = {}
manifest = {"bootstrapAssets": [], "components": [], "kind": "enoki-probe-bundle", "target": "x86_64-unknown-linux-gnu", "version": "1.2.3"}
for collection in ("components", "bootstrapAssets"):
    for role, contract in recipe.EXPECTED_ROLES[collection].items():
        data = ("verified-" + role).encode()
        payloads[contract["path"]] = data
        entry = {**contract, "role": role, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "version": "1.2.3"}
        manifest[collection].append(entry)
manifest_raw = json.dumps(manifest, separators=(",", ":")).encode()
archive_path = pathlib.Path(tempfile.mkdtemp()) / "bundle.tar.gz"
with tarfile.open(archive_path, "w:gz") as archive:
    for name, data in {"bundle-manifest.json": manifest_raw, **payloads}.items():
        member = tarfile.TarInfo(name)
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
asset = {"bundleManifestSha256": hashlib.sha256(manifest_raw).hexdigest(), "target": "x86_64-unknown-linux-gnu"}
assert recipe.verify_bundle_and_extract_acquirer(archive_path, asset) == payloads["bootstrap/enoki-probe-bootstrap-acquire"]
`;
    await expect(
      execFileAsync("python3", ["-c", program, recipePath], {
        env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
      }),
    ).resolves.toMatchObject({ stderr: "", stdout: "" });
    await rm(directory, { force: true, recursive: true });
  });

  it("executes verified recipe acquirer bytes only through one sealed descriptor", async () => {
    const publication = await createProbeBootstrapPublication({
      bundleVersion: "1.2.3",
      sourceDir: process.cwd(),
      trustedRootPublicKeyPem: testDistributionRoot.publicKey,
    });
    const directory = await mkdtemp(
      path.join(tmpdir(), "enoki-recipe-sealed-fd-"),
    );
    const recipePath = path.join(directory, "recipe.py");
    await writeFile(recipePath, publication.recipeBytes);
    const program = String.raw`
import importlib.util, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("enoki_recipe", path)
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)
verified = b'#!/bin/sh\n[ "$ENOKI_RECIPE_FD" = sealed ] || exit 9\nexit 0\n'
with open(os.devnull, "rb") as input_stream:
    assert recipe.execute_verified_acquirer(verified, {"ENOKI_RECIPE_FD": "sealed"}, input_stream) == 0
`;
    await expect(
      execFileAsync("python3", ["-c", program, recipePath], {
        env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
      }),
    ).resolves.toMatchObject({ stderr: "", stdout: "" });
    await rm(directory, { force: true, recursive: true });
  });

  it("requires exactly one root private-key representation for trust delegations", () => {
    const root = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const release = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const input = {
      distribution: "enoki",
      generation: 1,
      releasePublicKeyPem: release.publicKey,
    };

    expect(() => createProbeTrustDelegation(input)).toThrow(
      /exactly one root private key/,
    );
    expect(() =>
      createProbeTrustDelegation({
        ...input,
        rootPrivateKey: createPrivateKey(root.privateKey),
        rootPrivateKeyPem: root.privateKey,
      }),
    ).toThrow(/exactly one root private key/);
    expect(() =>
      createProbeTrustDelegation({ ...input, rootPrivateKey: root.privateKey }),
    ).toThrow(/root private key must be a KeyObject/);
  });

  it("authorizes a routine signer with one root-signed, domain-separated delegated identity", () => {
    const root = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const release = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const delegation = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 1,
      releasePublicKeyPem: release.publicKey,
      rootPrivateKeyPem: root.privateKey,
    });

    expect(
      validateDelegatedProbeSigningIdentity({
        delegationBytes: delegation.bytes,
        delegationSignature: delegation.signature,
        distribution: "enoki",
        privateKeyPem: release.privateKey,
        publicKeyPem: release.publicKey,
        rootPublicKeyPem: root.publicKey,
      }).delegation.generation,
    ).toBe(1);
  });

  it.each([
    [
      "wrong distribution",
      (input) => {
        input.distribution = "other";
      },
      /binding is invalid/,
    ],
    [
      "old generation",
      (input) => {
        input.highestAcceptedGeneration = 2;
      },
      /not newer/,
    ],
    [
      "unrelated release signer",
      (input) => {
        const unrelated = generateKeyPairSync("rsa", {
          modulusLength: 2048,
          privateKeyEncoding: { format: "pem", type: "pkcs8" },
          publicKeyEncoding: { format: "pem", type: "spki" },
        });
        input.privateKeyPem = unrelated.privateKey;
        input.publicKeyPem = unrelated.publicKey;
      },
      /not authorized/,
    ],
  ])("rejects a %s delegated signing identity", (_label, mutate, expected) => {
    const root = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const release = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const delegation = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 1,
      releasePublicKeyPem: release.publicKey,
      rootPrivateKeyPem: root.privateKey,
    });
    const input = {
      delegationBytes: delegation.bytes,
      delegationSignature: delegation.signature,
      distribution: "enoki",
      privateKeyPem: release.privateKey,
      publicKeyPem: release.publicKey,
      rootPublicKeyPem: root.publicKey,
    };
    mutate(input);
    expect(() => validateDelegatedProbeSigningIdentity(input)).toThrow(
      expected,
    );
  });

  it("rejects a noncanonical or invalid-root-signed Probe Trust Delegation", () => {
    const root = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const release = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const delegation = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 1,
      releasePublicKeyPem: release.publicKey,
      rootPrivateKeyPem: root.privateKey,
    });
    expect(() =>
      verifyProbeTrustDelegation({
        bytes: Buffer.concat([delegation.bytes, Buffer.from(" ")]),
        expectedDistribution: "enoki",
        rootPublicKeyPem: root.publicKey,
        signature: delegation.signature,
      }),
    ).toThrow(/canonical/);
    expect(() =>
      verifyProbeTrustDelegation({
        bytes: delegation.bytes,
        expectedDistribution: "enoki",
        rootPublicKeyPem: root.publicKey,
        signature: Buffer.from("invalid"),
      }),
    ).toThrow(/root signature/);
  });

  it("accepts the current delegation generation again while rejecting only rollback", () => {
    const root = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const release = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const delegation = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 1,
      releasePublicKeyPem: release.publicKey,
      rootPrivateKeyPem: root.privateKey,
    });
    expect(
      verifyProbeTrustDelegation({
        bytes: delegation.bytes,
        expectedDistribution: "enoki",
        highestAcceptedGeneration: 1,
        rootPublicKeyPem: root.publicKey,
        signature: delegation.signature,
      }).generation,
    ).toBe(1);
  });
  it("validates the configured production signing identity before candidate construction", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const root = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const delegation = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 1,
      releasePublicKeyPem: publicKey,
      rootPrivateKeyPem: root.privateKey,
    });
    const rootDir = await mkdtemp(
      path.join(tmpdir(), "enoki-signing-preflight-"),
    );
    const delegationPath = path.join(rootDir, "trust-delegation.json");
    const signaturePath = path.join(rootDir, "trust-delegation.json.sig");
    await writeFile(delegationPath, delegation.bytes);
    await writeFile(signaturePath, delegation.signature);

    const result = await execFileAsync(
      "node",
      [
        candidateCli,
        "validate-signing-identity",
        "--private-key-env",
        "TEST_PROBE_PRIVATE_KEY",
        "--public-key-env",
        "TEST_PROBE_PUBLIC_KEY",
        "--root-public-key-env",
        "TEST_ROOT_PUBLIC_KEY",
        "--distribution",
        "enoki",
        "--trust-delegation",
        delegationPath,
        "--trust-delegation-signature",
        signaturePath,
      ],
      {
        env: {
          ...process.env,
          TEST_PROBE_PRIVATE_KEY: privateKey,
          TEST_PROBE_PUBLIC_KEY: publicKey,
          TEST_ROOT_PUBLIC_KEY: root.publicKey,
        },
      },
    );

    expect(result.stdout).toMatch(
      /^Probe asset signing identity is valid: [0-9a-f]{64}\n$/,
    );
    await rm(rootDir, { force: true, recursive: true });
  });

  it("rejects a production public key that does not match the private key", async () => {
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const { publicKey: unrelatedPublicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });

    expect(() =>
      validateProbeSigningIdentity({
        privateKeyPem: privateKey,
        publicKeyPem: unrelatedPublicKey,
      }),
    ).toThrow("public key does not match private key");
  });

  it("passes one named signing secret and fails closed in a trusted preflight", async () => {
    const [entrypoint, workflow] = await Promise.all([
      readFile(".github/workflows/release.yml", "utf8"),
      readFile(
        ".github/workflows/reusable-build-release-candidate.yml",
        "utf8",
      ),
    ]);

    expect(entrypoint).toContain(
      "probe_asset_signing_key_pem: ${{ secrets.ENOKI_PROBE_ASSET_SIGNING_KEY_PEM }}",
    );
    expect(entrypoint).not.toContain("secrets: inherit");
    expect(workflow).toMatch(
      /workflow_call:[\s\S]*?secrets:[\s\S]*?probe_asset_signing_key_pem:[\s\S]*?required: true/,
    );
    expect(workflow).toContain("  validate-release-configuration:");
    const preflight = workflow.slice(
      workflow.indexOf("  validate-release-configuration:"),
      workflow.indexOf("  resolve-release-baseline:"),
    );
    expect(preflight).toContain(
      "Validate public release migration configuration",
    );
    expect(preflight.indexOf("release-transition-preflight.mjs")).toBeLessThan(
      preflight.indexOf("${{ secrets.probe_asset_signing_key_pem }}"),
    );
    for (const variable of [
      "ENOKI_RELEASE_TRANSITION_CONTRACT_JSON",
      "ENOKI_RELEASE_TRANSITION_CONTRACT_SIGNATURE_BASE64",
      "ENOKI_TRUST_EPOCH_MIGRATION_AUTHORIZATION_JSON",
      "ENOKI_TRUST_EPOCH_MIGRATION_AUTHORIZATION_SIGNATURE_BASE64",
    ]) {
      expect(preflight).toContain(variable);
    }
    expect(preflight).toContain("validate-signing-identity");
    expect(preflight).toContain("${{ secrets.probe_asset_signing_key_pem }}");
    expect(preflight).toContain(
      "${{ vars.ENOKI_PROBE_ASSET_SIGNING_PUBLIC_KEY_PEM }}",
    );
    expect(workflow).not.toContain("environment: release-signing");
    expect(workflow).not.toContain("secrets: inherit");

    const buildProbe = workflow.slice(
      workflow.indexOf("  build-probe:"),
      workflow.indexOf("  prepare-unsigned-probe-assets:"),
    );
    expect(buildProbe).toContain("validate-release-configuration");

    const buildProbeBootstrap = workflow.slice(
      workflow.indexOf("  build-probe-bootstrap:"),
      workflow.indexOf("  prepare-unsigned-probe-assets:"),
    );
    expect(buildProbeBootstrap).toMatch(
      /needs:\s*\[\s*validate-candidate-inputs,\s*validate-release-configuration,\s*resolve-release-baseline,?\s*\]/,
    );
    expect(buildProbeBootstrap).not.toContain("if: ${{ always() }}");
  });

  it("keeps candidate construction private and confines the production key to a trusted signer checkout", async () => {
    const [workflow, releaseWorkflow, hubWorkflow] = await Promise.all([
      readFile(
        ".github/workflows/reusable-build-release-candidate.yml",
        "utf8",
      ),
      readFile(".github/workflows/release.yml", "utf8"),
      readFile(".github/workflows/reusable-hub-image.yml", "utf8"),
    ]);

    expect(workflow).toContain("workflow_call:");
    expect(workflow).not.toContain("workflow_dispatch:");
    expect(releaseWorkflow).toContain("workflow_dispatch:");
    expect(releaseWorkflow).toContain(
      "uses: ./.github/workflows/reusable-build-release-candidate.yml",
    );
    expect(releaseWorkflow).toContain("group: enoki-release-global");
    expect(workflow).not.toMatch(/^concurrency:/m);
    expect(workflow).toContain("commit:");
    expect(workflow).toContain("version:");
    expect(workflow).toContain(
      "node trusted-tool/scripts/release-candidate.mjs assemble",
    );
    expect(hubWorkflow).toContain("--output type=oci");
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
    expect(signJob).not.toContain("environment: release-signing");
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
    expect(signJob).toContain("ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM");
    expect(signJob).toContain("ENOKI_PROBE_TRUST_DELEGATION_JSON");
    expect(signJob).toContain("ENOKI_PROBE_TRUST_DELEGATION_SIGNATURE_BASE64");
    expect(signJob).toContain("--root-public-key-env");
    expect(signJob).toContain("--trust-delegation trust-delegation.json");
    expect(signJob).toContain(
      "--trust-delegation-signature trust-delegation.json.sig",
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

  it("binds candidate source, release tooling, and workflow policy to one protected main revision", async () => {
    const workflow = await readFile(
      ".github/workflows/reusable-build-release-candidate.yml",
      "utf8",
    );
    const validationJob = workflow.slice(
      workflow.indexOf("  validate-candidate-inputs:"),
      workflow.indexOf("  resolve-release-baseline:"),
    );
    expect(validationJob).toContain("TRUSTED_WORKFLOW_SHA:");
    expect(validationJob).toContain(
      'test "$CANDIDATE_COMMIT" = "$TRUSTED_WORKFLOW_SHA"',
    );
    expect(validationJob).toContain(
      "node candidate-source/scripts/release-candidate.mjs validate-inputs",
    );
    expect(validationJob).not.toContain("validate-source-policy");
    expect(validationJob).not.toContain("refs/remotes/origin/main");
    expect(validationJob).not.toMatch(/^    if:/m);
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
      await writeFile(path.join(workDir, "enoki-observation-runtime"), binary, {
        mode: 0o755,
      });
      await writeFile(
        path.join(workDir, "enoki-cpu-resource-provider"),
        binary,
        {
          mode: 0o755,
        },
      );
      await writeFile(
        path.join(workDir, "enoki-disk-health-resource-provider"),
        binary,
        { mode: 0o755 },
      );
      await writeFile(
        path.join(workDir, "enoki-probe-lifecycle-companion"),
        binary,
        { mode: 0o755 },
      );
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
    const [
      toolchain,
      dockerfile,
      probeWorkflow,
      candidateWorkflow,
      hubWorkflow,
    ] = await Promise.all([
      readFile("rust-toolchain.toml", "utf8"),
      readFile("apps/hub/Dockerfile", "utf8"),
      readFile(".github/workflows/reusable-build-probe.yml", "utf8"),
      readFile(
        ".github/workflows/reusable-build-release-candidate.yml",
        "utf8",
      ),
      readFile(".github/workflows/reusable-hub-image.yml", "utf8"),
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
    expect(hubWorkflow).toContain("rewrite-timestamp=true");
    expect(candidateWorkflow).toContain("package-candidate");
    expect(dockerfile).toContain("su-exec-0.3-r0.apk");
    expect(dockerfile).toContain("ADD --checksum=sha256:");
    expect(dockerfile).toContain(
      "apk add --allow-untrusted --no-network /tmp/su-exec.apk",
    );
    expect(dockerfile).toContain(
      "rm -f /app/deploy/node_modules/.modules.yaml",
    );
    expect(dockerfile).toContain("rm -f /var/log/apk.log");
  });

  it("makes the formal candidate workflow compare two clean builds of every Probe target and the Hub image", async () => {
    const [probeWorkflow, candidateWorkflow, hubWorkflow] = await Promise.all([
      readFile(".github/workflows/reusable-build-probe.yml", "utf8"),
      readFile(
        ".github/workflows/reusable-build-release-candidate.yml",
        "utf8",
      ),
      readFile(".github/workflows/reusable-hub-image.yml", "utf8"),
    ]);

    expect(candidateWorkflow).toContain("verify-reproducible: true");
    expect(probeWorkflow).toContain("verify-reproducible:");
    expect(probeWorkflow).toContain("rm -rf target/reproducible");
    expect(probeWorkflow).toContain("dist-reproducibility-second");
    expect(probeWorkflow).toContain("cmp --silent");
    expect(candidateWorkflow).toContain(
      "uses: ./.github/workflows/reusable-hub-image.yml",
    );
    expect(candidateWorkflow).toContain("verify-reproducible: true");
    expect(candidateWorkflow).not.toContain("docker buildx build");
    expect(hubWorkflow).toContain("hub-reproducibility-first");
    expect(hubWorkflow).toContain("hub-reproducibility-second");
    expect(hubWorkflow).toContain("--no-cache");
    expect(hubWorkflow).toContain("compare-hub-builds");
    expect(hubWorkflow).not.toMatch(
      /name: candidate-hub-oci-reproducibility-second/,
    );
  });

  it("grants callers the read permission requested by the shared Hub workflow", async () => {
    const [ciWorkflow, hubWorkflow] = await Promise.all([
      readFile(".github/workflows/ci.yml", "utf8"),
      readFile(".github/workflows/reusable-hub-image.yml", "utf8"),
    ]);

    expect(hubWorkflow).toContain(
      "permissions:\n  actions: read\n  contents: read",
    );
    expect(ciWorkflow).toContain(
      "permissions:\n  actions: read\n  contents: read",
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
      const releaseBaselineDir = await createReleaseBaselineFixture(workDir);

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
      const { outputDir, privateKey, publicKey, root } =
        await createProbeAssetSetFixture(workDir);

      const expectedFiles = [
        ...probeTargets.flatMap((target) => [
          `enoki-probe-${target}.tar.gz`,
          `enoki-probe-${target}.tar.gz.sha256`,
        ]),
        "manifest.json",
        "manifest.json.sig",
        "root-key.pem",
        "signing-key.pem",
        "trust-delegation.json",
        "trust-delegation.json.sig",
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
      for (const asset of manifest.assets) {
        expect(asset.bundleManifestSha256).toMatch(/^[0-9a-f]{64}$/);
      }
      expect(
        verifySignature(
          "RSA-SHA256",
          manifestBytes,
          publicKey,
          await readFile(path.join(outputDir, "manifest.json.sig")),
        ),
      ).toBe(true);

      const publicKeySha256 = sha256(Buffer.from(publicKey));
      const archivePath = path.join(
        outputDir,
        "enoki-probe-x86_64-unknown-linux-gnu.tar.gz",
      );
      const bundleManifestBytes = (
        await execFileAsync("tar", [
          "--extract",
          "--gzip",
          "--to-stdout",
          "--file",
          archivePath,
          "bundle-manifest.json",
        ])
      ).stdout;
      const bundleManifest = JSON.parse(bundleManifestBytes);
      const archiveListing = (
        await execFileAsync("tar", ["--list", "--gzip", "--file", archivePath])
      ).stdout
        .trim()
        .split("\n");
      expect(archiveListing).toEqual([
        "bundle-manifest.json",
        "enoki-probe",
        "enoki-observation-runtime",
        "enoki-cpu-resource-provider",
        "enoki-disk-health-resource-provider",
        "enoki-probe-lifecycle-companion",
        "bootstrap/enoki-probe-bootstrap-acquire",
        "bootstrap/enoki-probe-bootstrap-activate",
      ]);
      expect(bundleManifest.bootstrapAssets).toEqual([
        expect.objectContaining({
          path: "bootstrap/enoki-probe-bootstrap-acquire",
          permissionProfile: "bootstrap-acquirer-v1",
          role: "bootstrap-acquirer",
          version: "1.2.3",
        }),
        expect.objectContaining({
          path: "bootstrap/enoki-probe-bootstrap-activate",
          permissionProfile: "bootstrap-activator-v1",
          role: "bootstrap-activator",
          version: "1.2.3",
        }),
      ]);
      expect(bundleManifest).toEqual(
        expect.objectContaining({
          bootstrapAssets: expect.any(Array),
          components: expect.arrayContaining([
            expect.objectContaining({
              path: "enoki-probe",
              permissionProfile: "probe-v5",
              resourceContract: "hub-reporting-v1",
              role: "probe",
              size: expect.any(Number),
              version: "1.2.3",
            }),
            expect.objectContaining({ role: "observation-runtime" }),
            expect.objectContaining({ role: "system-state-provider" }),
          ]),
          kind: "enoki-probe-bundle",
          target: "x86_64-unknown-linux-gnu",
          version: "1.2.3",
        }),
      );
      expect(bundleManifest.components[0].sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(bundleManifest.components[0].size).toBeGreaterThan(0);
      expect(
        manifest.assets.find(
          (asset) => asset.file === path.basename(archivePath),
        ).bundleManifestSha256,
      ).toBe(sha256(bundleManifestBytes));
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

  it("resolves one replacement transition against the current single-Bundle manifest", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-set-"));
    try {
      const fixture = await createProbeAssetSetFixture(workDir, {
        version: "v1.2.3",
      });
      const sourceRelease = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { format: "pem", type: "pkcs8" },
        publicKeyEncoding: { format: "pem", type: "spki" },
      });
      const source = await createSignedLegacyProbeAssetSetFixture({
        privateKeyPem: sourceRelease.privateKey,
        publicKeyPem: sourceRelease.publicKey,
      });
      const legacyRelease = {
        ...legacyMigrationRelease(),
        assets: source.assets,
        legacySigningKeySha256: sha256(Buffer.from(sourceRelease.publicKey)),
      };
      const authorization = createTrustEpochMigrationAuthorization({
        candidateVersion: "v1.2.3",
        distribution: "enoki",
        legacyRelease,
        rootPrivateKeyPem: fixture.root.privateKey,
      });
      const targetManifestBytes = await readFile(
        path.join(fixture.outputDir, "manifest.json"),
      );
      const transition = await createReleaseTransitionContract({
        authorizationBytes: authorization.bytes,
        authorizationSignature: authorization.signature,
        candidateCommit: checkedOutCommit,
        delegationBytes: await readFile(
          path.join(fixture.outputDir, "trust-delegation.json"),
        ),
        delegationSignature: await readFile(
          path.join(fixture.outputDir, "trust-delegation.json.sig"),
        ),
        legacyRelease,
        rootPrivateKeyPem: fixture.root.privateKey,
        rootPublicKeyPem: fixture.root.publicKey,
        sourceAssetDir: source.assetDir,
        targetManifestBytes,
        targetVersion: "1.2.3",
      });
      await source.cleanup();
      await Promise.all([
        writeFile(
          path.join(fixture.outputDir, "release-transition-contract.json"),
          transition.bytes,
        ),
        writeFile(
          path.join(fixture.outputDir, "release-transition-contract.json.sig"),
          transition.signature,
        ),
        writeFile(
          path.join(
            fixture.outputDir,
            "trust-epoch-migration-authorization.json",
          ),
          authorization.bytes,
        ),
        writeFile(
          path.join(
            fixture.outputDir,
            "trust-epoch-migration-authorization.json.sig",
          ),
          authorization.signature,
        ),
      ]);

      await expect(
        inspectProbeAssetSet(fixture.outputDir, {
          expectedVersion: "1.2.3",
          trustedRootPublicKeyPem: fixture.root.publicKey,
        }),
      ).resolves.toMatchObject({
        releaseTransition: {
          candidateCommit: checkedOutCommit,
          transition: "replacement-required",
          target: { version: "1.2.3" },
        },
      });
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("requires the signer to recheck an unsigned Asset Set against an external root and exact delegation", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-external-trust-"),
    );

    try {
      const { outputDir, root } = await createProbeAssetSetFixture(workDir);
      const delegationBytes = await readFile(
        path.join(outputDir, "trust-delegation.json"),
      );
      const delegationSignature = await readFile(
        path.join(outputDir, "trust-delegation.json.sig"),
      );

      await expect(
        inspectProbeAssetSet(outputDir, {
          expectedDelegationBytes: delegationBytes,
          expectedDelegationSignature: delegationSignature,
          trustedRootPublicKeyPem: root.publicKey,
        }),
      ).resolves.toMatchObject({ version: "1.2.3" });

      const attackerRoot = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { format: "pem", type: "pkcs8" },
        publicKeyEncoding: { format: "pem", type: "spki" },
      });
      await writeFile(
        path.join(outputDir, "root-key.pem"),
        attackerRoot.publicKey,
      );

      await expect(
        inspectProbeAssetSet(outputDir, {
          expectedDelegationBytes: delegationBytes,
          expectedDelegationSignature: delegationSignature,
          trustedRootPublicKeyPem: root.publicKey,
        }),
      ).rejects.toThrow(
        "root key does not match the trusted Probe Distribution Trust Root",
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it("rejects an attacker-created Root, Delegation, and complete signed Asset Set without an external anchor", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-unanchored-root-"),
    );

    try {
      const { outputDir } = await createProbeAssetSetFixture(workDir);

      await expect(inspectProbeAssetSet(outputDir)).rejects.toThrow(
        "Probe Asset Set verification requires an external Probe Distribution Trust Root",
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it.each([
    [
      "missing bundle manifest digest",
      (manifest) => {
        delete manifest.assets[0].bundleManifestSha256;
      },
      /fields must be exactly/,
    ],
    [
      "mismatched bundle manifest digest",
      (manifest) => {
        manifest.assets[0].bundleManifestSha256 = "0".repeat(64);
      },
      /bundle manifest does not match/,
    ],
  ])(
    "rejects a re-signed Asset Set with a %s",
    async (_label, mutate, expected) => {
      const workDir = await mkdtemp(
        path.join(tmpdir(), "enoki-candidate-bundle-digest-"),
      );
      try {
        const { outputDir, privateKey, root } =
          await createProbeAssetSetFixture(workDir);
        const manifestPath = path.join(outputDir, "manifest.json");
        const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
        mutate(manifest);
        const manifestBytes = Buffer.from(
          `${JSON.stringify(manifest, null, 2)}\n`,
        );
        await writeFile(manifestPath, manifestBytes);
        await writeFile(
          path.join(outputDir, "manifest.json.sig"),
          signBytes("RSA-SHA256", manifestBytes, privateKey),
        );

        await expect(
          inspectProbeAssetSet(outputDir, {
            trustedRootPublicKeyPem: root.publicKey,
          }),
        ).rejects.toThrow(expected);
      } finally {
        await rm(workDir, { force: true, recursive: true });
      }
    },
  );

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
      ).rejects.toThrow(
        "must contain exactly its bundle manifest and enoki-probe payload",
      );
    } finally {
      await rm(workDir, { force: true, recursive: true });
    }
  });

  it.each([
    [
      "bundle version",
      (manifest) => {
        manifest.version = "9.9.9";
      },
    ],
    [
      "bundle target",
      (manifest) => {
        manifest.target = "wrong-target";
      },
    ],
    [
      "component role",
      (manifest) => {
        manifest.components[0].role = "runtime";
      },
    ],
    [
      "component path",
      (manifest) => {
        manifest.components[0].path = "other";
      },
    ],
    [
      "component digest",
      (manifest) => {
        manifest.components[0].sha256 = "0".repeat(64);
      },
    ],
    [
      "component size",
      (manifest) => {
        manifest.components[0].size += 1;
      },
    ],
    [
      "component version",
      (manifest) => {
        manifest.components[0].version = "9.9.9";
      },
    ],
    [
      "component permission profile",
      (manifest) => {
        manifest.components[0].permissionProfile = "root-v1";
      },
    ],
    [
      "additional component",
      (manifest) => {
        manifest.components.push({ ...manifest.components[0] });
      },
    ],
  ])(
    "rejects an incoherent %s before signing",
    async (_label, mutateBundleManifest) => {
      const workDir = await mkdtemp(
        path.join(tmpdir(), "enoki-candidate-incoherent-bundle-"),
      );
      try {
        await expect(
          createProbeAssetSetFixture(workDir, {
            bundleManifestMutate: mutateBundleManifest,
          }),
        ).rejects.toThrow("Probe bundle");
      } finally {
        await rm(workDir, { force: true, recursive: true });
      }
    },
  );

  it("rejects a bundle manifest symlink even when its archive pathname is allowlisted", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-bundle-link-"),
    );
    try {
      await expect(
        createProbeAssetSetFixture(workDir, { bundleManifestSymlink: true }),
      ).rejects.toThrow("bundle manifest must be a regular file");
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
        await writeFile(
          path.join(workDir, "enoki-observation-runtime"),
          createProbeElf({ interpreter, target, version: "v1.2.3" }),
          { mode: 0o755 },
        );
        await writeFile(
          path.join(workDir, "enoki-cpu-resource-provider"),
          createProbeElf({ interpreter, target, version: "v1.2.3" }),
          { mode: 0o755 },
        );
        await writeFile(
          path.join(workDir, "enoki-disk-health-resource-provider"),
          createProbeElf({ interpreter, target, version: "v1.2.3" }),
          { mode: 0o755 },
        );
        await writeFile(
          path.join(workDir, "enoki-probe-lifecycle-companion"),
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
          kind: "enoki-release-baseline",
          tag: "v1.2.2",
        },
        schemaVersion: 4,
      });
      expect(manifest).not.toHaveProperty("bootstrap");
      expect(await readdir(candidateDir)).not.toContain("probe-bootstrap");
      const publicRecipeRecord = JSON.parse(
        await readFile(
          path.join(
            candidateDir,
            "recipe",
            manifest.bootstrapRecipe.recordFile,
          ),
          "utf8",
        ),
      );
      expect(publicRecipeRecord).toEqual({
        bundleVersion: manifest.bootstrapRecipe.bundleVersion,
        distribution: manifest.bootstrapRecipe.distribution,
        kind: manifest.bootstrapRecipe.kind,
        recipe: {
          file: manifest.bootstrapRecipe.file,
          sha256: manifest.bootstrapRecipe.sha256,
          size: manifest.bootstrapRecipe.size,
          version: manifest.bootstrapRecipe.version,
        },
        rootFingerprint: manifest.bootstrapRecipe.rootFingerprint,
        schemaVersion: 1,
        targets: probeTargets,
      });
      expect(manifest.probeAssetSet.files.map(({ file }) => file)).toEqual(
        (await readdir(probeAssetSetDir)).sort(),
      );
      expect(manifestText.endsWith("\n")).toBe(true);
      const consumed = await loadValidatedCandidate(
        path.join(candidateDir, "candidate-manifest.json"),
        { trustedRootPublicKeyPem: testDistributionRoot.publicKey },
      );
      expect(consumed.manifest).toEqual(manifest);

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

  it("requires exactly one valid Release Baseline descriptor", async () => {
    await expectCandidateMutationRejected(async (candidateDir) => {
      const manifestPath = path.join(candidateDir, "candidate-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      delete manifest.releaseBaseline;
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    }, "releaseBaseline");

    await expectCandidateMutationRejected(async (candidateDir) => {
      const manifestPath = path.join(candidateDir, "candidate-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      manifest.releaseBaseline.kind = "unsupported-release-baseline";
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    }, "requires one Release Baseline descriptor");

    await expectCandidateMutationRejected(async (candidateDir) => {
      const manifestPath = path.join(candidateDir, "candidate-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      manifest.releaseBaseline.catalogSnapshot.sha256 = "f".repeat(64);
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    }, "Candidate Manifest Release Baseline descriptor does not match content");
  });

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
  });

  it("rejects a Hub OCI image whose config descriptor is not the OCI image config media type", async () => {
    const workDir = await mkdtemp(
      path.join(tmpdir(), "enoki-candidate-config-media-type-"),
    );

    try {
      const { outputDir: probeAssetSetDir, root } =
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
      const { outputDir: probeAssetSetDir, root } =
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
      const { outputDir: probeAssetSetDir, root } =
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
      const { outputDir: probeAssetSetDir, root } =
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
      const { outputDir: probeAssetSetDir, root } =
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
      const { outputDir: probeAssetSetDir, root } =
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
      const { outputDir: probeAssetSetDir, root } =
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
      const releaseBaselineDir = await createReleaseBaselineFixture(workDir);

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

function legacyMigrationRelease() {
  return {
    assets: [
      { name: "manifest.json", sha256: "1".repeat(64), size: 100 },
      { name: "manifest.json.sig", sha256: "2".repeat(64), size: 256 },
      { name: "signing-key.pem", sha256: "3".repeat(64), size: 451 },
    ],
    githubRelease: {
      id: 368250351,
      peeledCommitSha: "6f639fe757785c085be31c3d92c7b1c128db3cb0",
      repository: "YKDZ/enoki",
      tag: "v0.1.74",
      tagRefSha: "4".repeat(40),
      targetCommitish: "main",
    },
    hub: {
      digest: `sha256:${"5".repeat(64)}`,
      image: "ghcr.io/ykdz/enoki-hub",
    },
    legacySigningKeySha256: "3".repeat(64),
  };
}

async function createProbeAssetSetFixture(
  workDir,
  {
    name = "",
    bundleManifestMutate,
    bundleManifestSymlink,
    mutateArchives,
    root: suppliedRoot,
    targets = probeTargets,
    version = "v1.2.3",
  } = {},
) {
  const archivesDir = path.join(workDir, `${name}archives`);
  const outputDir = path.join(workDir, `${name}probe-assets`);
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const root = suppliedRoot ?? testDistributionRoot;
  const delegation = createProbeTrustDelegation({
    distribution: "enoki",
    generation: 1,
    releasePublicKeyPem: publicKey,
    rootPrivateKeyPem: root.privateKey,
  });
  const delegationPath = path.join(workDir, `${name}trust-delegation.json`);
  const delegationSignaturePath = path.join(
    workDir,
    `${name}trust-delegation.json.sig`,
  );
  await writeFile(delegationPath, delegation.bytes);
  await writeFile(delegationSignaturePath, delegation.signature);

  await mkdir(archivesDir, { recursive: true });
  for (const target of targets) {
    const file = `enoki-probe-${target}.tar.gz`;
    await writeProbeArchive(path.join(archivesDir, file), {
      bundleManifestMutate,
      bundleManifestSymlink,
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
  const bootstrapArchivesDir = await createProbeBootstrapArtifactFixture(
    workDir,
    { root, version },
  );
  await runCandidateCli(
    [
      "prepare-probe-assets",
      "--version",
      version,
      "--archives-dir",
      archivesDir,
      "--bootstrap-archives-dir",
      bootstrapArchivesDir,
      "--output",
      outputDir,
      "--private-key-env",
      "TEST_PRIVATE_KEY",
      "--public-key-env",
      "TEST_PUBLIC_KEY",
      "--root-public-key-env",
      "TEST_ROOT_PUBLIC_KEY",
      "--distribution",
      "enoki",
      "--trust-delegation",
      delegationPath,
      "--trust-delegation-signature",
      delegationSignaturePath,
    ],
    {
      TEST_PRIVATE_KEY: privateKey,
      TEST_PUBLIC_KEY: publicKey,
      TEST_ROOT_PUBLIC_KEY: root.publicKey,
    },
  );

  return {
    archivesDir,
    bootstrapArchivesDir,
    outputDir,
    privateKey,
    publicKey,
    root,
  };
}

async function writeProbeArchive(
  archivePath,
  {
    bundleManifestMutate,
    bundleManifestSymlink = false,
    extraPayload = false,
    interpreter,
    mode = 0o755,
    target,
    version,
  },
) {
  const bundledBootstrap = [];
  for (const [archiveMember, permissionProfile, role] of [
    [
      "bootstrap/enoki-probe-bootstrap-acquire",
      "bootstrap-acquirer-v1",
      "bootstrap-acquirer",
    ],
    [
      "bootstrap/enoki-probe-bootstrap-activate",
      "bootstrap-activator-v1",
      "bootstrap-activator",
    ],
  ]) {
    try {
      const { stdout } = await execFileAsync(
        "tar",
        [
          "--extract",
          "--gzip",
          "--to-stdout",
          "--file",
          archivePath,
          archiveMember,
        ],
        { encoding: "buffer" },
      );
      bundledBootstrap.push({
        archiveMember,
        bytes: stdout,
        permissionProfile,
        role,
      });
    } catch {
      bundledBootstrap.length = 0;
      break;
    }
  }
  const binaryDir = `${archivePath}.contents`;
  const binaryPath = path.join(binaryDir, "enoki-probe");
  await mkdir(binaryDir, { recursive: true });
  const binary = createProbeElf({ interpreter, target, version });
  await writeFile(binaryPath, binary);
  await chmod(binaryPath, mode);
  for (const rolePath of [
    "enoki-observation-runtime",
    "enoki-cpu-resource-provider",
    "enoki-disk-health-resource-provider",
    "enoki-probe-lifecycle-companion",
  ]) {
    await writeFile(path.join(binaryDir, rolePath), binary);
    await chmod(path.join(binaryDir, rolePath), mode);
  }
  const bundleManifest = {
    ...(bundledBootstrap.length > 0
      ? {
          bootstrapAssets: bundledBootstrap.map(
            ({ archiveMember, bytes, permissionProfile, role }) => ({
              path: archiveMember,
              permissionProfile,
              role,
              sha256: sha256(bytes),
              size: bytes.byteLength,
              version: version.slice(1),
            }),
          ),
        }
      : {}),
    components: [
      {
        path: "enoki-probe",
        permissionProfile: "probe-v5",
        resourceContract: "hub-reporting-v1",
        role: "probe",
        sha256: sha256(binary),
        size: binary.byteLength,
        version: version.slice(1),
      },
      {
        path: "enoki-observation-runtime",
        permissionProfile: "observation-runtime-v4",
        resourceContract: "official-observation-v2",
        role: "observation-runtime",
        sha256: sha256(binary),
        size: binary.byteLength,
        version: version.slice(1),
      },
      {
        path: "enoki-cpu-resource-provider",
        permissionProfile: "system-state-provider-v5",
        resourceContract: "system-state-v3",
        role: "system-state-provider",
        sha256: sha256(binary),
        size: binary.byteLength,
        version: version.slice(1),
      },
      {
        path: "enoki-disk-health-resource-provider",
        permissionProfile: "disk-health-provider-v3",
        resourceContract: "disk-health-v1",
        role: "disk-health-provider",
        sha256: sha256(binary),
        size: binary.byteLength,
        version: version.slice(1),
      },
      {
        path: "enoki-probe-lifecycle-companion",
        permissionProfile: "lifecycle-companion-v3",
        resourceContract: "local-lifecycle-v1",
        role: "lifecycle-companion",
        sha256: sha256(binary),
        size: binary.byteLength,
        version: version.slice(1),
      },
    ],
    kind: "enoki-probe-bundle",
    target,
    version: version.slice(1),
  };
  bundleManifestMutate?.(bundleManifest);
  await writeFile(
    path.join(binaryDir, "bundle-manifest.json"),
    `${JSON.stringify(bundleManifest)}\n`,
  );
  if (bundleManifestSymlink) {
    await rm(path.join(binaryDir, "bundle-manifest.json"));
    await symlink("enoki-probe", path.join(binaryDir, "bundle-manifest.json"));
  }
  if (extraPayload) {
    await writeFile(path.join(binaryDir, "unexpected"), "not allowlisted");
  }
  for (const { archiveMember, bytes } of bundledBootstrap) {
    const destination = path.join(binaryDir, archiveMember);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, bytes, { mode: 0o755 });
  }
  await execFileAsync("tar", [
    "--create",
    "--gzip",
    "--file",
    archivePath,
    "--directory",
    binaryDir,
    ...(extraPayload
      ? ["."]
      : [
          "bundle-manifest.json",
          "enoki-probe",
          "enoki-observation-runtime",
          "enoki-cpu-resource-provider",
          "enoki-disk-health-resource-provider",
          "enoki-probe-lifecycle-companion",
          ...bundledBootstrap.map(({ archiveMember }) => archiveMember),
        ]),
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

function createBootstrapElf({ identity, target }) {
  const machine = target.startsWith("aarch64") ? 183 : 62;
  const names = Buffer.from("\0.shstrtab\0.enoki_bootstrap\0", "utf8");
  const payload = Buffer.from(JSON.stringify(identity), "utf8");
  const marker = Buffer.concat([
    Buffer.from("ENOKI_BOOTSTRAP_BUILD_IDENTITY_V1\0", "utf8"),
    Buffer.from([
      (payload.byteLength >>> 24) & 0xff,
      (payload.byteLength >>> 16) & 0xff,
      (payload.byteLength >>> 8) & 0xff,
      payload.byteLength & 0xff,
    ]),
    payload,
  ]);
  const sectionOffset = 64;
  const sectionCount = 3;
  const identityOffset = sectionOffset + sectionCount * 64;
  const namesOffset = identityOffset + marker.byteLength;
  const binary = Buffer.alloc(namesOffset + names.byteLength);
  binary.write("\x7fELF", 0, "binary");
  binary[4] = 2;
  binary[5] = 1;
  binary[6] = 1;
  binary.writeUInt16LE(machine, 18);
  binary.writeBigUInt64LE(BigInt(sectionOffset), 40);
  binary.writeUInt16LE(64, 58);
  binary.writeUInt16LE(sectionCount, 60);
  binary.writeUInt16LE(1, 62);
  writeBootstrapSection(binary, sectionOffset + 64, {
    nameOffset: 1,
    offset: namesOffset,
    size: names.byteLength,
  });
  writeBootstrapSection(binary, sectionOffset + 128, {
    nameOffset: 11,
    offset: identityOffset,
    size: marker.byteLength,
  });
  marker.copy(binary, identityOffset);
  names.copy(binary, namesOffset);
  return binary;
}

function writeBootstrapSection(
  binary,
  offset,
  { nameOffset, offset: contents, size },
) {
  binary.writeUInt32LE(nameOffset, offset);
  binary.writeBigUInt64LE(BigInt(contents), offset + 24);
  binary.writeBigUInt64LE(BigInt(size), offset + 32);
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
    manifestBytes: imageManifestBytes,
    manifestDigest: imageManifestDescriptor.digest,
  };
}

async function createCandidateFixture(workDir, { version = "v1.2.3" } = {}) {
  const {
    outputDir: probeAssetSetDir,
    privateKey,
    publicKey,
    root,
  } = await createProbeAssetSetFixture(workDir, { version });
  const oci = await createOciFixture(workDir, probeAssetSetDir);
  const candidateDir = path.join(workDir, "candidate");
  const releaseBaselineDir = await createReleaseBaselineFixture(workDir, {
    root,
  });

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
    root,
  };
}

async function createProbeBootstrapArtifactFixture(workDir, { root, version }) {
  const outputDir = path.join(workDir, `probe-bootstrap-${version}`);
  const rootKeyId = sha256(
    createPublicKey(root.publicKey).export({ format: "pem", type: "spki" }),
  );
  for (const target of probeTargets) {
    const binariesDir = path.join(workDir, `bootstrap-binaries-${target}`);
    await mkdir(binariesDir, { recursive: true });
    const identity = {
      distribution: "enoki",
      rootFingerprint: rootKeyId,
      rootKeyId,
      target,
      version,
    };
    const acquirerPath = path.join(
      binariesDir,
      "enoki-probe-bootstrap-acquire",
    );
    const activatorPath = path.join(
      binariesDir,
      "enoki-probe-bootstrap-activate",
    );
    await writeFile(
      acquirerPath,
      createBootstrapElf({
        identity: { ...identity, role: "acquirer" },
        target,
      }),
      {
        mode: 0o755,
      },
    );
    await writeFile(
      activatorPath,
      createBootstrapElf({
        identity: { ...identity, role: "activator" },
        target,
      }),
      {
        mode: 0o755,
      },
    );
    await packageProbeBootstrapArtifact({
      binaries: { acquirerPath, activatorPath },
      distribution: "enoki",
      outputDir,
      rootKeyId,
      sourceDateEpoch: "0",
      target,
      version,
    });
  }
  return outputDir;
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
  const releaseBaselineDir = await createReleaseBaselineFixture(workDir);
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

async function createReleaseBaselineFixture(workDir, { root } = {}) {
  const releaseBaselineDir = path.join(workDir, "release-baseline-input");
  const { outputDir: probeAssetSetDir, root: baselineRoot } =
    await createProbeAssetSetFixture(workDir, {
      name: "baseline-",
      root,
      version: "v1.2.2",
    });
  const oci = await createOciFixture(workDir, probeAssetSetDir, {
    name: "baseline",
  });
  const inspectedProbe = await inspectProbeAssetSet(probeAssetSetDir, {
    trustedRootPublicKeyPem: baselineRoot.publicKey,
  });
  const archive = "hub/enoki-hub-v1.2.2.oci.tar";
  const archiveBytes = await readFile(oci.archivePath);
  const sourceManifest = "hub-source-manifest.json";
  const release = {
    assets: [],
    draft: false,
    id: 122,
    prerelease: false,
    tagName: "v1.2.2",
    targetCommitish: "main",
  };
  const descriptor = {
    catalogSnapshot: createReleaseCatalogSnapshot([release]),
    githubRelease: {
      id: release.id,
      peeledCommitSha: "e".repeat(40),
      repository: "YKDZ/enoki",
      tagRefSha: "f".repeat(40),
      targetCommitish: release.targetCommitish,
    },
    hub: {
      archive,
      archiveSha256: sha256(archiveBytes),
      digest: oci.manifestDigest,
      image: "ghcr.io/ykdz/enoki-hub",
      imageDigest: oci.manifestDigest,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      platform: { architecture: "amd64", os: "linux" },
      size: archiveBytes.length,
      sourceManifest,
      sourceManifestSha256: sha256(oci.manifestBytes),
      sourceManifestSize: oci.manifestBytes.length,
    },
    kind: "enoki-release-baseline",
    probeAssetSet: {
      ...inspectedProbe,
      directory: "probe-assets",
      trustRoot: {
        publicKeySha256: sha256(Buffer.from(baselineRoot.publicKey)),
      },
    },
    schemaVersion: 2,
    tag: "v1.2.2",
  };
  await mkdir(path.join(releaseBaselineDir, "hub"), { recursive: true });
  await cp(probeAssetSetDir, path.join(releaseBaselineDir, "probe-assets"), {
    recursive: true,
  });
  await writeFile(path.join(releaseBaselineDir, archive), archiveBytes);
  await writeFile(
    path.join(releaseBaselineDir, sourceManifest),
    oci.manifestBytes,
  );
  await writeFile(
    path.join(releaseBaselineDir, "release-baseline.json"),
    `${JSON.stringify(descriptor, null, 2)}\n`,
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

async function runCandidateCli(arguments_, environment = {}) {
  const command = arguments_[0];
  const rootRequiredCommands = new Set([
    "assemble",
    "compare-hub-builds",
    "package-candidate",
    "validate",
    "validate-probe-assets",
  ]);
  if (
    rootRequiredCommands.has(command) &&
    !arguments_.includes("--root-public-key-env")
  ) {
    const optionValue = (name) => {
      const index = arguments_.indexOf(name);
      return index === -1 ? undefined : arguments_[index + 1];
    };
    const assetDir =
      command === "validate-probe-assets"
        ? arguments_[1]
        : command === "validate"
          ? path.join(arguments_[1], "probe-assets")
          : command === "package-candidate"
            ? path.join(optionValue("--candidate"), "probe-assets")
            : optionValue("--probe-assets");
    if (assetDir) {
      const rootPublicKeyPem = await readFile(
        path.join(assetDir, "root-key.pem"),
        "utf8",
      );
      arguments_ = [
        ...arguments_,
        "--root-public-key-env",
        "TEST_EXTERNAL_ROOT_PUBLIC_KEY",
      ];
      environment = {
        ...environment,
        TEST_EXTERNAL_ROOT_PUBLIC_KEY: rootPublicKeyPem,
      };
    }
  }
  return execFileAsync("node", [candidateCli, ...arguments_], {
    cwd: process.cwd(),
    env: { ...process.env, ...environment },
  });
}
