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
} from "./release-e2e-environment.ts";
import {
  createProbeHostHarness,
  runReleaseE2EScenario,
} from "./release-e2e-orchestration.ts";
import { objectView } from "./release-json-guards.ts";
import {
  resolveReleaseScenarioPlanCell,
  type ScenarioPlanCell,
} from "./release-scenario-plan-compile.ts";
import {
  compileVerifiedReleaseScenarioPlan,
  prepareReleaseScenarioCell,
} from "./release-scenario-plan.ts";

// CLI 参数表由 Environment Adapter 的公开解析器给出，这里只复用同一类型视图。
type ReleaseE2EOptionValues = ReturnType<
  typeof parseReleaseE2ECommandLine
>["values"];

// Host 执行器的形状由 Environment Adapter 的两个公开工厂共同给出。
type ReleaseHostExecutor = ReturnType<typeof createCiHostExecutor>;

const usage = `Usage:
  node scripts/release-e2e.ts run \\
    --candidate-manifest <candidate-dir>/candidate-manifest.json \\
    --matrix scripts/release-e2e-matrix.json \\
    --matrix-cell <environment-id>--<scenario-id> \\
    --host-adapter ssh \\
    --ssh-host <user@disposable-host> [--ssh-port 22] [--ssh-key <path>] \\
    --hub-owner-url http://127.0.0.1:<port> \\
    --hub-public-url http://<address-reachable-from-host>:<port> \\
    --owner-password-env <environment-variable> \\
    --evidence-dir <new-or-run-owned-directory>

  node scripts/release-e2e.ts run \\
    --candidate-manifest <candidate-dir>/candidate-manifest.json \\
    --matrix scripts/release-e2e-matrix.json \\
    --matrix-cell <environment-id>--<scenario-id> \\
    --host-adapter ci \\
    --hub-owner-url http://127.0.0.1:<port> \\
    --hub-public-url http://127.0.0.1:<port> \\
    --owner-password-env <environment-variable> \\
    --evidence-dir <new-run-directory>

  node scripts/release-e2e.ts verify-clean \\
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

// parseReleaseE2ECommandLine 已按命令表校验必填项并填入默认值；这里沿用同一条
// `${name} is required` 失败文本，不新增第二种拒绝。
function requiredOption(values: ReleaseE2EOptionValues, name: string): string {
  const value = values[name];
  if (value === undefined) throw new Error(`${name} is required`);
  return value;
}

async function run(options: ReleaseE2EOptionValues): Promise<void> {
  const candidateManifestPath = requiredOption(options, "--candidate-manifest");
  const rootPublicKeyEnvironment = requiredOption(
    options,
    "--root-public-key-env",
  );
  const trustedRootPublicKeyPem = process.env[rootPublicKeyEnvironment];
  if (!trustedRootPublicKeyPem) {
    throw new Error(
      `Probe Distribution Trust Root environment variable ${rootPublicKeyEnvironment} is empty`,
    );
  }
  const evidenceDir = path.resolve(requiredOption(options, "--evidence-dir"));
  const { ownershipToken, runId } = newRunIdentity(options["--run-id"]);
  const hostAdapter = requiredOption(options, "--host-adapter");
  const ssh =
    hostAdapter === "ssh"
      ? {
          host: requiredOption(options, "--ssh-host"),
          keyPath: options["--ssh-key"]
            ? path.resolve(options["--ssh-key"])
            : null,
          port: Number(requiredOption(options, "--ssh-port")),
        }
      : null;
  const infrastructure =
    hostAdapter === "ci"
      ? createCiReleaseInfrastructureAdapter({
          candidateManifestPath,
          trustedRootPublicKeyPem,
        })
      : createSshReleaseInfrastructureAdapter({
          candidateManifestPath,
          host: requiredOption(options, "--ssh-host"),
          keyPath: options["--ssh-key"],
          knownHostsPath: path.join(evidenceDir, "known_hosts"),
          port: Number(requiredOption(options, "--ssh-port")),
          trustedRootPublicKeyPem,
        });
  const matrixCellId = requiredOption(options, "--matrix-cell");
  const scenarioPlan = await compileVerifiedReleaseScenarioPlan({
    candidateManifestPath,
    matrixPath: requiredOption(options, "--matrix"),
    trustedRootPublicKeyPem,
  });
  const matrixCell = resolveReleaseScenarioPlanCell(scenarioPlan, matrixCellId);
  const journal = await createRunArtifactJournal({
    evidenceDir,
    inputs: {
      candidateManifestPath: path.resolve(candidateManifestPath),
      hostAdapter,
      hubOwnerUrl: requiredOption(options, "--hub-owner-url"),
      hubPublicUrl: requiredOption(options, "--hub-public-url"),
      matrixCellId,
      matrixPath: path.resolve(requiredOption(options, "--matrix")),
      ssh,
    },
    ownershipToken,
    runId,
  });
  let failurePhase = "plan-validated";
  // 与原实现一致：环境变量缺失时先记录 undefined，再由同一 falsy 判据拒绝。
  let ownerPassword: string | null | undefined = null;

  try {
    await journal.update({
      matrixCell,
      phase: "plan-validated",
      scenario: matrixCell.scenarioId,
    });

    const ownerPasswordEnvironment = requiredOption(
      options,
      "--owner-password-env",
    );
    ownerPassword = process.env[ownerPasswordEnvironment];
    if (!ownerPassword) {
      throw new Error(
        `Owner password environment variable ${ownerPasswordEnvironment} is empty`,
      );
    }
    // 场景运行需要精确的 string；catch 仍读取外层 ownerPassword 以便脱敏。
    const runOwnerPassword = ownerPassword;

    failurePhase = "candidate-prepare";
    await journal.update({ phase: failurePhase });
    await prepareReleaseScenarioCell({
      cellId: matrixCell.cellId,
      compilePlan: async () => scenarioPlan,
      initialize: async ({ prepared, takeCleanupOwnership }) => {
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
          hubOwnerUrl: requiredOption(options, "--hub-owner-url"),
          hubPublicUrl: requiredOption(options, "--hub-public-url"),
          infrastructure: prepared.infrastructure,
          matrixCell,
          onCleanupManaged: takeCleanupOwnership,
          ownerPassword: runOwnerPassword,
          ownershipToken,
          releaseInfrastructure: (context) => infrastructure.release(context),
        });

        failurePhase = "scenario-running";
        await journal.update({
          hostMutationPossible: true,
          phase: failurePhase,
        });
        await runReleaseE2EScenario({
          candidateManifest: manifest,
          environment,
          evidenceSink: journal.evidenceSink,
          ownerPassword: runOwnerPassword,
          runId,
          scenario: matrixCell.scenarioId,
        });
      },
      provision: (cell: ScenarioPlanCell) =>
        infrastructure.prepare({ matrixCell: cell, runId }),
      release: ({ prepared }) => infrastructure.release({ prepared, runId }),
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
        `release-e2e: secondary artifact journal failure: ${objectView(journalError).message}\n`,
      );
    }
    throw error;
  }
}

async function verifyClean(options: ReleaseE2EOptionValues): Promise<void> {
  const manifestPath = path.resolve(requiredOption(options, "--run-manifest"));
  const manifest = await readRunManifest(manifestPath);
  if (
    manifest.inputs.hostAdapter !== requiredOption(options, "--host-adapter")
  ) {
    throw new Error("Host adapter does not match the exact run manifest");
  }
  if (!manifest.hostMutationPossible) {
    process.stdout.write(
      `Release Test Host is clean: ${manifest.runId} (no Host mutation was authorized)\n`,
    );
    return;
  }
  let execute: ReleaseHostExecutor;
  if (manifest.inputs.hostAdapter === "ssh") {
    // 原判据用 manifest.ssh?.host 与调用方选项比较：ssh 身份缺失时同样落入本拒绝分支。
    const sshIdentity = manifest.ssh;
    if (
      !sshIdentity ||
      sshIdentity.host !== requiredOption(options, "--ssh-host") ||
      sshIdentity.port !== Number(requiredOption(options, "--ssh-port")) ||
      (sshIdentity.keyPath ?? null) !==
        (options["--ssh-key"] ? path.resolve(options["--ssh-key"]) : null)
    ) {
      throw new Error("SSH Host does not match the exact run manifest");
    }
    execute = createSshExecutor({
      host: sshIdentity.host,
      keyPath: sshIdentity.keyPath ?? undefined,
      knownHostsPath: path.join(path.dirname(manifestPath), "known_hosts"),
      port: sshIdentity.port,
    });
  } else {
    execute = createCiHostExecutor();
  }
  const host = createProbeHostHarness({
    execute,
    ownershipToken: manifest.ownershipToken,
  });
  await host.assertReleaseTestHost(manifest.matrixCell ?? {});
  await host.verifyClean(manifest.runId);
  process.stdout.write(`Release Test Host is clean: ${manifest.runId}\n`);
}
