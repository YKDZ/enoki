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
    "--github-api-base-url",
    "--github-repository",
    "--github-token-env",
    "--hub-image",
    ...(command === "resolve"
      ? [
          "--trust-epoch-migration-authorization-env",
          "--trust-epoch-migration-signature-env",
        ]
      : []),
    "--output",
    "--registry-token-env",
    "--trusted-root-public-key-env",
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
  const trustedRootPublicKeyPem = requiredEnvironmentOption(
    options,
    "--trusted-root-public-key-env",
  );
  if (command === "recheck") {
    const descriptor = await recheckReleaseBaseline({
      bundleDir: requiredOption(options, "--bundle"),
      candidateVersion: requiredOption(options, "--candidate-version"),
      githubRepository,
      releaseCatalog: githubClient,
      trustedRootPublicKeyPem,
    });
    process.stdout.write(
      `Release Baseline still matches published state: ${descriptor.tag ?? descriptor.kind}\n`,
    );
    process.exit(0);
  }
  const descriptor = await resolveReleaseBaseline({
    assetDownloader: githubClient,
    candidateVersion: requiredOption(options, "--candidate-version"),
    githubRepository,
    hubImage: requiredOption(options, "--hub-image"),
    outputDir: requiredOption(options, "--output"),
    registry: createGhcrRegistryClient({
      token: registryTokenEnvironment
        ? process.env[registryTokenEnvironment]
        : undefined,
    }),
    releaseCatalog: githubClient,
    trustedRootPublicKeyPem,
    ...optionalMigrationAuthorization(options),
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

function optionalMigrationAuthorization(options) {
  const authorizationEnvironment = options.get(
    "--trust-epoch-migration-authorization-env",
  );
  const signatureEnvironment = options.get(
    "--trust-epoch-migration-signature-env",
  );
  if (
    authorizationEnvironment === undefined &&
    signatureEnvironment === undefined
  ) {
    return {};
  }
  if (!authorizationEnvironment || !signatureEnvironment) {
    throw new Error(
      "Trust Epoch Migration Authorization and signature environments must be configured together",
    );
  }
  const authorization = process.env[authorizationEnvironment];
  const signature = process.env[signatureEnvironment];
  if (!authorization || !signature) {
    throw new Error(
      "Trust Epoch Migration Authorization public material is empty",
    );
  }
  return {
    trustEpochMigrationAuthorizationBytes: Buffer.from(authorization, "utf8"),
    trustEpochMigrationAuthorizationSignature: Buffer.from(signature, "base64"),
  };
}
