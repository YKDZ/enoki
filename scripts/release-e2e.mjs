#!/usr/bin/env node

import path from "node:path";

import {
  createCiHostExecutor,
  createCiReleaseInfrastructureAdapter,
  createReleaseEnvironment,
  createRunArtifactJournal,
  createSshReleaseInfrastructureAdapter,
  createSshExecutor,
  newRunIdentity,
  parseReleaseE2ECommandLine,
  readRunManifest,
} from "./release-e2e-adapters.mjs";
import {
  createProbeHostHarness,
  runReleaseE2EScenario,
} from "./release-e2e-lib.mjs";
import {
  readReleaseE2EMatrix,
  resolveReleaseE2EMatrixCell,
} from "./release-e2e-matrix.mjs";

const usage = `Usage:
  node scripts/release-e2e.mjs run \\
    --candidate-manifest <candidate-dir>/candidate-manifest.json \\
    --matrix scripts/release-e2e-matrix.json \\
    --matrix-cell <environment-id>--<scenario-id> \\
    --host-adapter ssh \\
    --ssh-host <user@disposable-host> [--ssh-port 22] [--ssh-key <path>] \\
    --hub-owner-url http://127.0.0.1:<port> \\
    --hub-public-url http://<address-reachable-from-host>:<port> \\
    --owner-password-env <environment-variable> \\
    --evidence-dir <new-or-run-owned-directory>

  node scripts/release-e2e.mjs run \\
    --candidate-manifest <candidate-dir>/candidate-manifest.json \\
    --matrix scripts/release-e2e-matrix.json \\
    --matrix-cell <environment-id>--<scenario-id> \\
    --host-adapter ci \\
    --hub-owner-url http://127.0.0.1:<port> \\
    --hub-public-url http://127.0.0.1:<port> \\
    --owner-password-env <environment-variable> \\
    --evidence-dir <new-run-directory>

  node scripts/release-e2e.mjs verify-clean \\
    --run-manifest <evidence-dir>/run-manifest.json \\
    --host-adapter ssh \\
    --ssh-host <same-user@same-host> [--ssh-port 22] [--ssh-key <same-path>]`;

try {
  if (process.argv.slice(2).includes("--help")) {
    process.stdout.write(`${usage}\n`);
    process.exit(0);
  }
  const parsed = parseReleaseE2ECommandLine(process.argv.slice(2));
  if (parsed.command === "run") {
    await run(parsed.values);
  } else {
    await verifyClean(parsed.values);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`release-e2e: ${message}\n`);
  process.exitCode = 1;
}

async function run(options) {
  const candidateManifestPath = options["--candidate-manifest"];
  const trustedRootPublicKeyPem = process.env[options["--root-public-key-env"]];
  if (!trustedRootPublicKeyPem) {
    throw new Error(
      `Probe Distribution Trust Root environment variable ${options["--root-public-key-env"]} is empty`,
    );
  }
  const evidenceDir = path.resolve(options["--evidence-dir"]);
  const { ownershipToken, runId } = newRunIdentity(options["--run-id"]);
  const ssh =
    options["--host-adapter"] === "ssh"
      ? {
          host: options["--ssh-host"],
          keyPath: options["--ssh-key"]
            ? path.resolve(options["--ssh-key"])
            : null,
          port: Number(options["--ssh-port"]),
        }
      : null;
  const journal = await createRunArtifactJournal({
    evidenceDir,
    inputs: {
      candidateManifestPath: path.resolve(candidateManifestPath),
      hostAdapter: options["--host-adapter"],
      hubOwnerUrl: options["--hub-owner-url"],
      hubPublicUrl: options["--hub-public-url"],
      matrixCellId: options["--matrix-cell"],
      matrixPath: path.resolve(options["--matrix"]),
      ssh,
    },
    ownershipToken,
    runId,
  });
  let failurePhase = "matrix-validation";
  let ownerPassword = null;

  try {
    await journal.update({ phase: failurePhase });
    const matrix = await readReleaseE2EMatrix(options["--matrix"]);
    const matrixCell = resolveReleaseE2EMatrixCell(
      matrix,
      options["--matrix-cell"],
    );
    await journal.update({
      matrixCell,
      phase: "matrix-validated",
      scenario: matrixCell.scenarioId,
    });

    failurePhase = "candidate-prepare";
    await journal.update({ phase: failurePhase });
    const ownerPasswordEnvironment = options["--owner-password-env"];
    ownerPassword = process.env[ownerPasswordEnvironment];
    if (!ownerPassword) {
      throw new Error(
        `Owner password environment variable ${ownerPasswordEnvironment} is empty`,
      );
    }
    const infrastructure =
      options["--host-adapter"] === "ci"
        ? createCiReleaseInfrastructureAdapter({
            candidateManifestPath,
            trustedRootPublicKeyPem,
          })
        : createSshReleaseInfrastructureAdapter({
            candidateManifestPath,
            host: options["--ssh-host"],
            keyPath: options["--ssh-key"],
            knownHostsPath: path.join(evidenceDir, "known_hosts"),
            port: Number(options["--ssh-port"]),
            trustedRootPublicKeyPem,
          });
    const prepared = await infrastructure.prepare({ matrixCell, runId });
    const { candidateDir, manifest } = prepared;
    await journal.update({
      candidate: manifest.candidate,
      hubDigest: manifest.hub.digest,
      infrastructure: prepared.infrastructure,
      phase: "candidate-prepared",
    });
    const environment = createReleaseEnvironment({
      bootstrapProvisioner: prepared.provisionBootstrap,
      candidateDir,
      execute: prepared.execute,
      hubOwnerUrl: options["--hub-owner-url"],
      hubPublicUrl: options["--hub-public-url"],
      infrastructure: prepared.infrastructure,
      matrixCell,
      ownerPassword,
      ownershipToken,
      releaseInfrastructure: (context) => infrastructure.release(context),
    });

    failurePhase = "scenario-running";
    await journal.update({ hostMutationPossible: true, phase: failurePhase });
    await runReleaseE2EScenario({
      candidateManifest: manifest,
      environment,
      evidenceSink: journal.evidenceSink,
      ownerPassword,
      runId,
      scenario: matrixCell.scenarioId,
    });
    await journal.update({ phase: "succeeded" });
    process.stdout.write(
      `Release E2E succeeded: ${runId} (${path.join(evidenceDir, "evidence.json")})\n`,
    );
  } catch (error) {
    try {
      await journal.fail({
        error,
        phase: failurePhase,
        secrets: ownerPassword ? [ownerPassword] : [],
      });
    } catch (journalError) {
      process.stderr.write(
        `release-e2e: secondary artifact journal failure: ${journalError.message}\n`,
      );
    }
    throw error;
  }
}

async function verifyClean(options) {
  const manifestPath = path.resolve(options["--run-manifest"]);
  const manifest = await readRunManifest(manifestPath);
  if (manifest.inputs.hostAdapter !== options["--host-adapter"]) {
    throw new Error("Host adapter does not match the exact run manifest");
  }
  if (!manifest.hostMutationPossible) {
    process.stdout.write(
      `Release Test Host is clean: ${manifest.runId} (no Host mutation was authorized)\n`,
    );
    return;
  }
  let execute;
  if (manifest.inputs.hostAdapter === "ssh") {
    if (
      manifest.ssh?.host !== options["--ssh-host"] ||
      manifest.ssh?.port !== Number(options["--ssh-port"]) ||
      (manifest.ssh?.keyPath ?? null) !==
        (options["--ssh-key"] ? path.resolve(options["--ssh-key"]) : null)
    ) {
      throw new Error("SSH Host does not match the exact run manifest");
    }
    execute = createSshExecutor({
      host: manifest.ssh.host,
      keyPath: manifest.ssh.keyPath ?? undefined,
      knownHostsPath: path.join(path.dirname(manifestPath), "known_hosts"),
      port: manifest.ssh.port,
    });
  } else {
    execute = createCiHostExecutor();
  }
  const host = createProbeHostHarness({
    execute,
    ownershipToken: manifest.ownershipToken,
  });
  await host.assertReleaseTestHost(manifest.matrixCell);
  await host.verifyClean(manifest.runId);
  process.stdout.write(`Release Test Host is clean: ${manifest.runId}\n`);
}
