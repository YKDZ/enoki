#!/usr/bin/env node

import { randomUUID } from "node:crypto";

import {
  parseCandidateUiContractCommandLine,
  runCandidateUiContract,
} from "./release-ui-contract-lib.mjs";

const usage = `Usage:
  node scripts/release-ui-contract.mjs \\
    --candidate-manifest <candidate-dir>/candidate-manifest.json \\
    --root-public-key-env <environment-variable> \\
    [--hub-port 38220] [--container-engine docker]`;

try {
  if (process.argv.slice(2).includes("--help")) {
    process.stdout.write(`${usage}\n`);
    process.exit(0);
  }
  const options = parseCandidateUiContractCommandLine(process.argv.slice(2));
  const runId = `ui-${Date.now()}-${randomUUID().slice(0, 8)}`;
  await runCandidateUiContract(options, {
    ownerPassword: `${randomUUID()}${randomUUID()}`,
    runId,
  });
  process.stdout.write(`Candidate-image UI Contract succeeded: ${runId}\n`);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`release-ui-contract: ${message}\n`);
  if (error?.cleanupError) {
    process.stderr.write(
      `release-ui-contract cleanup: ${error.cleanupError.message}\n`,
    );
  }
  process.exitCode = 1;
}
