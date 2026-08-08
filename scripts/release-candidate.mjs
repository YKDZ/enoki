#!/usr/bin/env node

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
  validateProbeSigningIdentity,
  validateReleaseCandidate,
} from "./release-candidate-lib.mjs";

try {
  const arguments_ = process.argv.slice(2);

  if (arguments_[0] === "validate") {
    if (arguments_.length !== 2) {
      throw new Error("validate requires exactly one candidate directory");
    }
    const manifest = await validateReleaseCandidate(arguments_[1]);
    process.stdout.write(
      `candidate is valid: ${manifest.candidate.commit} ${manifest.candidate.version} ${manifest.hub.digest}\n`,
    );
    process.exit(0);
  }

  if (arguments_[0] === "validate-probe-assets") {
    if (arguments_.length !== 2) {
      throw new Error(
        "validate-probe-assets requires exactly one Probe Asset Set directory",
      );
    }
    const probe = await inspectProbeAssetSet(arguments_[1]);
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
    ]);
    const privateKeyEnvironment = requiredOption(options, "--private-key-env");
    const publicKeyEnvironment = requiredOption(options, "--public-key-env");
    const identity = validateProbeSigningIdentity({
      privateKeyPem: process.env[privateKeyEnvironment],
      publicKeyPem: process.env[publicKeyEnvironment],
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
    ]);
    const result = await packageReleaseCandidate({
      candidateDir: requiredOption(options, "--candidate"),
      outputPath: requiredOption(options, "--output"),
      sourceDateEpoch: requiredOption(options, "--source-date-epoch"),
    });
    process.stdout.write(
      `packaged reproducible candidate ${result.outputPath} ${result.sha256}\n`,
    );
  } else if (command === "prepare-probe-assets") {
    assertAllowedOptions(command, options, [
      "--archives-dir",
      "--installer",
      "--output",
      "--private-key-env",
      "--public-key-env",
      "--version",
    ]);
    const privateKeyEnvironment = requiredOption(options, "--private-key-env");
    const publicKeyEnvironment = requiredOption(options, "--public-key-env");
    const result = await prepareProbeAssetSet({
      archivesDir: requiredOption(options, "--archives-dir"),
      installerPath: requiredOption(options, "--installer"),
      outputDir: requiredOption(options, "--output"),
      privateKeyPem: process.env[privateKeyEnvironment],
      publicKeyPem: process.env[publicKeyEnvironment],
      version: requiredOption(options, "--version"),
    });
    process.stdout.write(
      `signed Probe Asset Set ${result.version} at ${result.outputDir}\n`,
    );
  } else if (command === "prepare-unsigned-probe-assets") {
    assertAllowedOptions(command, options, [
      "--archives-dir",
      "--installer",
      "--output",
      "--public-key-env",
      "--version",
    ]);
    const publicKeyEnvironment = requiredOption(options, "--public-key-env");
    const result = await prepareUnsignedProbeAssetSet({
      archivesDir: requiredOption(options, "--archives-dir"),
      installerPath: requiredOption(options, "--installer"),
      outputDir: requiredOption(options, "--output"),
      publicKeyPem: process.env[publicKeyEnvironment],
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
    ]);
    const privateKeyEnvironment = requiredOption(options, "--private-key-env");
    const result = await signProbeAssetSet({
      outputDir: requiredOption(options, "--output"),
      privateKeyPem: process.env[privateKeyEnvironment],
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
    ]);
    const result = await compareHubOciBuilds({
      firstPath: requiredOption(options, "--first"),
      probeAssetSetDir: requiredOption(options, "--probe-assets"),
      secondPath: requiredOption(options, "--second"),
    });
    process.stdout.write(`Hub OCI builds are reproducible: ${result.digest}\n`);
  } else if (command === "assemble") {
    assertAllowedOptions(command, options, [
      "--commit",
      "--hub-oci",
      "--output",
      "--probe-assets",
      "--release-baseline",
      "--source-dir",
      "--version",
    ]);
    const manifest = await assembleReleaseCandidate({
      commit: requiredOption(options, "--commit"),
      hubOciPath: requiredOption(options, "--hub-oci"),
      outputDir: requiredOption(options, "--output"),
      probeAssetSetDir: requiredOption(options, "--probe-assets"),
      releaseBaselineDir: requiredOption(options, "--release-baseline"),
      sourceDir: requiredOption(options, "--source-dir"),
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
