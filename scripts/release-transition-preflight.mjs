#!/usr/bin/env node

import { preflightReleaseMigrationConfiguration } from "@enoki/probe-release";

const options = parseOptions(process.argv.slice(2));
preflightReleaseMigrationConfiguration({
  authorization: process.env.RELEASE_MIGRATION_AUTHORIZATION ?? "",
  authorizationSignatureBase64:
    process.env.RELEASE_MIGRATION_AUTHORIZATION_SIGNATURE ?? "",
  candidateCommit: required(options, "candidate-commit"),
  candidateVersion: required(options, "candidate-version"),
  contract: process.env.RELEASE_MIGRATION_CONTRACT ?? "",
  contractSignatureBase64:
    process.env.RELEASE_MIGRATION_CONTRACT_SIGNATURE ?? "",
  rootPublicKeyPem: process.env.PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY ?? "",
});

function parseOptions(arguments_) {
  const parsed = new Map();
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error("Release migration preflight arguments are invalid");
    }
    parsed.set(name.slice(2), value);
  }
  return parsed;
}

function required(options, name) {
  const value = options.get(name);
  if (!value) throw new Error(`--${name} is required`);
  return value;
}
