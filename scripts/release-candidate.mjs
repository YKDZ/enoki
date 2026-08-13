#!/usr/bin/env node

import { readFile } from "node:fs/promises";

import {
  assembleReleaseCandidate,
  assertAllowedOptions,
  assertCheckedOutCommit,
  compareHubOciBuilds,
  parseCommandLine,
  prepareProbeAssetSet,
  prepareUnsignedProbeAssetSet,
  inspectProbeAssetSet,
  packageProbeArchive,
  packageReleaseCandidate,
  requiredOption,
  signProbeAssetSet,
  validateCandidateIdentity,
  validateDelegatedProbeSigningIdentity,
  validateProbeSigningIdentity,
  validateReleaseCandidate,
} from "./release-candidate-lib.mjs";

try {
  const arguments_ = process.argv.slice(2);

  if (arguments_[0] === "validate") {
    if (arguments_.length !== 4 || arguments_[2] !== "--root-public-key-env") {
      throw new Error(
        "validate requires a candidate directory and --root-public-key-env",
      );
    }
    const manifest = await validateReleaseCandidate(arguments_[1], {
      trustedRootPublicKeyPem: process.env[arguments_[3]],
    });
    process.stdout.write(
      `candidate is valid: ${manifest.candidate.commit} ${manifest.candidate.version} ${manifest.hub.digest}\n`,
    );
    process.exit(0);
  }

  if (arguments_[0] === "validate-probe-assets") {
    if (arguments_.length !== 4 || arguments_[2] !== "--root-public-key-env") {
      throw new Error(
        "validate-probe-assets requires an Asset Set directory and --root-public-key-env",
      );
    }
    const probe = await inspectProbeAssetSet(arguments_[1], {
      trustedRootPublicKeyPem: process.env[arguments_[3]],
    });
    process.stdout.write(
      `Probe Asset Set is valid: ${probe.version} ${probe.signingIdentity.publicKeySha256}\n`,
    );
    process.exit(0);
  }

  const { command, options } = parseCommandLine(arguments_);

  if (command === "validate-signing-identity") {
    assertAllowedOptions(command, options, [
      "--private-key-env",
      "--public-key-env",
      "--root-public-key-env",
      "--distribution",
      "--trust-delegation",
      "--trust-delegation-signature",
    ]);
    const privateKeyEnvironment = requiredOption(options, "--private-key-env");
    const publicKeyEnvironment = requiredOption(options, "--public-key-env");
    const identity = validateDelegatedProbeSigningIdentity({
      delegationBytes: await readFile(
        requiredOption(options, "--trust-delegation"),
      ),
      delegationSignature: await readFile(
        requiredOption(options, "--trust-delegation-signature"),
      ),
      distribution: requiredOption(options, "--distribution"),
      privateKeyPem: process.env[privateKeyEnvironment],
      publicKeyPem: process.env[publicKeyEnvironment],
      rootPublicKeyPem:
        process.env[requiredOption(options, "--root-public-key-env")],
    });
    process.stdout.write(
      `Probe asset signing identity is valid: ${identity.publicKeySha256}\n`,
    );
  } else if (command === "validate-inputs") {
    assertAllowedOptions(command, options, [
      "--commit",
      "--source-dir",
      "--version",
    ]);
    const identity = validateCandidateIdentity({
      commit: requiredOption(options, "--commit"),
      version: requiredOption(options, "--version"),
    });

    const sourceDir = options.get("--source-dir");
    if (sourceDir) {
      await assertCheckedOutCommit(sourceDir, identity.commit);
    }

    process.stdout.write(
      `candidate inputs are valid: ${identity.commit} ${identity.version}\n`,
    );
  } else if (command === "package-probe") {
    assertAllowedOptions(command, options, [
      "--binary",
      "--output-dir",
      "--source-date-epoch",
      "--target",
      "--version",
    ]);
    const result = await packageProbeArchive({
      binaryPath: requiredOption(options, "--binary"),
      outputDir: requiredOption(options, "--output-dir"),
      sourceDateEpoch: requiredOption(options, "--source-date-epoch"),
      target: requiredOption(options, "--target"),
      version: requiredOption(options, "--version"),
    });
    process.stdout.write(
      `packaged reproducible Probe archive ${result.file} ${result.archiveSha256}\n`,
    );
  } else if (command === "package-candidate") {
    assertAllowedOptions(command, options, [
      "--candidate",
      "--output",
      "--source-date-epoch",
      "--root-public-key-env",
    ]);
    const result = await packageReleaseCandidate({
      candidateDir: requiredOption(options, "--candidate"),
      outputPath: requiredOption(options, "--output"),
      sourceDateEpoch: requiredOption(options, "--source-date-epoch"),
      trustedRootPublicKeyPem:
        process.env[requiredOption(options, "--root-public-key-env")],
    });
    process.stdout.write(
      `packaged reproducible candidate ${result.outputPath} ${result.sha256}\n`,
    );
  } else if (command === "prepare-probe-assets") {
    assertAllowedOptions(command, options, [
      "--archives-dir",
      "--output",
      "--private-key-env",
      "--public-key-env",
      "--root-public-key-env",
      "--distribution",
      "--trust-delegation",
      "--trust-delegation-signature",
      "--version",
    ]);
    const privateKeyEnvironment = requiredOption(options, "--private-key-env");
    const publicKeyEnvironment = requiredOption(options, "--public-key-env");
    const result = await prepareProbeAssetSet({
      archivesDir: requiredOption(options, "--archives-dir"),
      delegationBytes: await readFile(
        requiredOption(options, "--trust-delegation"),
      ),
      delegationSignature: await readFile(
        requiredOption(options, "--trust-delegation-signature"),
      ),
      distribution: requiredOption(options, "--distribution"),
      outputDir: requiredOption(options, "--output"),
      privateKeyPem: process.env[privateKeyEnvironment],
      publicKeyPem: process.env[publicKeyEnvironment],
      rootPublicKeyPem:
        process.env[requiredOption(options, "--root-public-key-env")],
      version: requiredOption(options, "--version"),
    });
    process.stdout.write(
      `signed Probe Asset Set ${result.version} at ${result.outputDir}\n`,
    );
  } else if (command === "prepare-unsigned-probe-assets") {
    assertAllowedOptions(command, options, [
      "--archives-dir",
      "--output",
      "--public-key-env",
      "--root-public-key-env",
      "--distribution",
      "--trust-delegation",
      "--trust-delegation-signature",
      "--version",
    ]);
    const publicKeyEnvironment = requiredOption(options, "--public-key-env");
    const result = await prepareUnsignedProbeAssetSet({
      archivesDir: requiredOption(options, "--archives-dir"),
      delegationBytes: await readFile(
        requiredOption(options, "--trust-delegation"),
      ),
      delegationSignature: await readFile(
        requiredOption(options, "--trust-delegation-signature"),
      ),
      distribution: requiredOption(options, "--distribution"),
      outputDir: requiredOption(options, "--output"),
      publicKeyPem: process.env[publicKeyEnvironment],
      rootPublicKeyPem:
        process.env[requiredOption(options, "--root-public-key-env")],
      version: requiredOption(options, "--version"),
    });
    process.stdout.write(
      `prepared unsigned Probe Asset Set ${result.version} at ${result.outputDir}\n`,
    );
  } else if (command === "sign-probe-assets") {
    assertAllowedOptions(command, options, [
      "--input",
      "--output",
      "--private-key-env",
      "--root-public-key-env",
      "--trust-delegation",
      "--trust-delegation-signature",
    ]);
    const privateKeyEnvironment = requiredOption(options, "--private-key-env");
    const result = await signProbeAssetSet({
      expectedDelegationBytes: await readFile(
        requiredOption(options, "--trust-delegation"),
      ),
      expectedDelegationSignature: await readFile(
        requiredOption(options, "--trust-delegation-signature"),
      ),
      outputDir: requiredOption(options, "--output"),
      privateKeyPem: process.env[privateKeyEnvironment],
      trustedRootPublicKeyPem:
        process.env[requiredOption(options, "--root-public-key-env")],
      unsignedAssetDir: requiredOption(options, "--input"),
    });
    process.stdout.write(
      `signed Probe Asset Set ${result.version} at ${result.outputDir}\n`,
    );
  } else if (command === "compare-hub-builds") {
    assertAllowedOptions(command, options, [
      "--first",
      "--probe-assets",
      "--second",
      "--root-public-key-env",
    ]);
    const result = await compareHubOciBuilds({
      firstPath: requiredOption(options, "--first"),
      probeAssetSetDir: requiredOption(options, "--probe-assets"),
      secondPath: requiredOption(options, "--second"),
      trustedRootPublicKeyPem:
        process.env[requiredOption(options, "--root-public-key-env")],
    });
    process.stdout.write(`Hub OCI builds are reproducible: ${result.digest}\n`);
  } else if (command === "assemble") {
    assertAllowedOptions(command, options, [
      "--bootstrap-artifacts",
      "--commit",
      "--hub-oci",
      "--output",
      "--probe-assets",
      "--release-baseline",
      "--source-dir",
      "--root-public-key-env",
      "--version",
    ]);
    const manifest = await assembleReleaseCandidate({
      bootstrapArtifactDir: requiredOption(options, "--bootstrap-artifacts"),
      commit: requiredOption(options, "--commit"),
      hubOciPath: requiredOption(options, "--hub-oci"),
      outputDir: requiredOption(options, "--output"),
      probeAssetSetDir: requiredOption(options, "--probe-assets"),
      releaseBaselineDir: requiredOption(options, "--release-baseline"),
      sourceDir: requiredOption(options, "--source-dir"),
      trustedRootPublicKeyPem:
        process.env[requiredOption(options, "--root-public-key-env")],
      version: requiredOption(options, "--version"),
    });
    process.stdout.write(
      `assembled candidate ${manifest.candidate.commit} ${manifest.candidate.version} ${manifest.hub.digest}\n`,
    );
  } else {
    throw new Error(`unknown command: ${command ?? "<missing>"}`);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`release-candidate: ${message}\n`);
  process.exitCode = 1;
}
