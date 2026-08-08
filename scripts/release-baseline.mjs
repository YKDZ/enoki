#!/usr/bin/env node

import {
  createGhcrRegistryClient,
  createGitHubReleaseClient,
  recheckReleaseBaseline,
  resolveReleaseBaseline,
  validateResolvedReleaseBaseline,
} from "./release-baseline-lib.mjs";
import {
  assertAllowedOptions,
  parseCommandLine,
  requiredOption,
} from "./release-candidate-lib.mjs";

try {
  const arguments_ = process.argv.slice(2);
  if (arguments_[0] === "validate") {
    if (arguments_.length !== 2) {
      throw new Error(
        "validate requires exactly one Release Baseline directory",
      );
    }
    const descriptor = await validateResolvedReleaseBaseline(arguments_[1]);
    process.stdout.write(
      `Release Baseline is valid: ${descriptor.tag ?? descriptor.kind}\n`,
    );
    process.exit(0);
  }

  const { command, options } = parseCommandLine(arguments_);
  if (command !== "resolve" && command !== "recheck") {
    throw new Error(`unknown command: ${command ?? "<missing>"}`);
  }
  assertAllowedOptions(command, options, [
    "--candidate-version",
    "--first-formal-release",
    "--github-api-base-url",
    "--github-repository",
    "--github-token-env",
    "--hub-image",
    "--output",
    "--registry-token-env",
    "--trusted-probe-public-key-env",
    "--bundle",
  ]);
  const githubRepository = requiredOption(options, "--github-repository");
  const githubTokenEnvironment = options.get("--github-token-env");
  const registryTokenEnvironment = options.get("--registry-token-env");
  const githubClient = createGitHubReleaseClient({
    apiBaseUrl: options.get("--github-api-base-url"),
    repository: githubRepository,
    token: githubTokenEnvironment
      ? process.env[githubTokenEnvironment]
      : undefined,
  });
  const trustedProbePublicKeyPem = requiredEnvironmentOption(
    options,
    "--trusted-probe-public-key-env",
  );
  if (command === "recheck") {
    const descriptor = await recheckReleaseBaseline({
      bundleDir: requiredOption(options, "--bundle"),
      candidateVersion: requiredOption(options, "--candidate-version"),
      githubRepository,
      releaseCatalog: githubClient,
      trustedProbePublicKeyPem,
    });
    process.stdout.write(
      `Release Baseline still matches published state: ${descriptor.tag ?? descriptor.kind}\n`,
    );
    process.exit(0);
  }
  const descriptor = await resolveReleaseBaseline({
    assetDownloader: githubClient,
    candidateVersion: requiredOption(options, "--candidate-version"),
    firstFormalRelease: parseBoolean(
      options.get("--first-formal-release") ?? "false",
      "--first-formal-release",
    ),
    githubRepository,
    hubImage: requiredOption(options, "--hub-image"),
    outputDir: requiredOption(options, "--output"),
    registry: createGhcrRegistryClient({
      token: registryTokenEnvironment
        ? process.env[registryTokenEnvironment]
        : undefined,
    }),
    releaseCatalog: githubClient,
    trustedProbePublicKeyPem,
  });
  process.stdout.write(
    `resolved Release Baseline: ${descriptor.tag ?? descriptor.kind}\n`,
  );
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`release-baseline: ${message}\n`);
  process.exitCode = 1;
}

function requiredEnvironmentOption(options, option) {
  const environmentName = requiredOption(options, option);
  const value = process.env[environmentName];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(
      `${option} environment variable ${environmentName} is empty`,
    );
  }
  return value;
}

function parseBoolean(value, option) {
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  throw new Error(`${option} must be true or false`);
}
