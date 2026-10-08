import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmod,
  copyFile,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import {
  sha256,
  validateReleaseCandidate,
} from "./release-candidate-verification.ts";
import { createCanonicalReportEvidenceTransport } from "./release-canonical-report-evidence.ts";
import {
  assertCandidateManifest,
  createHubLifecycleClient,
  createProbeHostHarness,
  releaseE2EScenarioRegistry,
} from "./release-e2e-orchestration.ts";
import type {
  HubStateSnapshotEvidence,
  ReleaseE2ECandidateManifest,
} from "./release-e2e-orchestration.ts";
import type {
  CommandExecutor,
  CommandOptions,
  CommandResult,
} from "./release-installed-bundle-failure-repair.ts";
import {
  isNonEmptyString,
  isPositiveSafeInteger,
  isSafeInteger,
  isUnknownArray,
  isUnknownRecord,
  objectView,
  regexInput,
  stringValue,
} from "./release-json-guards.ts";
import type { UnknownRecord } from "./release-json-guards.ts";

const execFileAsync = promisify(execFile);

// —— 进程与命令执行 ——

type ProcessRunOptions = { input?: string; timeoutMs?: number };

type ProcessRunner = (
  command: string,
  arguments_: readonly string[],
  options: ProcessRunOptions,
) => Promise<CommandResult>;

type SleepFunction = (milliseconds: number) => Promise<void>;

// Docker 与 tar 等本地 CLI 经 execFile 执行；失败时 Node 会把退出码放在 error.code，
// 命令缺失时该字段是 ENOENT 之类的字符串。原实现把这个值原样交给调用方的
// code !== 0 判据，这里保留同一取值空间，不把它压成数字。
type DockerCommandResult = {
  code: number | string;
  stderr: string;
  stdout: string;
};

type DockerExecutor = (
  command: string,
  arguments_: readonly string[],
) => Promise<DockerCommandResult>;

type DockerObjectType = "container" | "image" | "volume";

type DockerCreatedFlag =
  | "containerCreated"
  | "snapshotContainerMayExist"
  | "snapshotVolumeCreated"
  | "tagCreated"
  | "volumeCreated";

type DockerObjectOwner = { [key in DockerCreatedFlag]?: boolean };

// —— Candidate、Recipe 与 Infrastructure ——

type CandidateBootstrapRecipe = {
  file: string;
  sha256: string;
  size: number;
  version: string;
};

type ValidatedCandidate = {
  candidateDir: string;
  manifest: ReleaseE2ECandidateManifest;
};

type LoadValidatedCandidate = (
  candidateManifestPath: string,
  options?: { trustedRootPublicKeyPem?: string },
) => Promise<ValidatedCandidate>;

type CandidateArchiveTransfer = (input: {
  destination: string;
  source: string;
}) => Promise<void>;

type BootstrapProvisionResult = {
  evidence?: unknown;
  workingDirectory?: string;
};

type BootstrapProvisioner = (input?: {
  recipe?: CandidateBootstrapRecipe;
  runId?: string;
  sourcePath?: string;
}) => Promise<BootstrapProvisionResult>;

type CandidateBootstrapProvisioner = {
  cleanup: (input: { runId: string }) => Promise<unknown>;
  provision: BootstrapProvisioner;
};

type ReleaseInfrastructureIdentity = {
  artifactAccess: string;
  connection: string;
  kind: string;
  matrixCellId: string;
  provisioning: string;
};

type PreparedReleaseInfrastructure = {
  candidateDir: string;
  execute: CommandExecutor;
  infrastructure: ReleaseInfrastructureIdentity;
  manifest: ReleaseE2ECandidateManifest;
  provisionBootstrap: BootstrapProvisioner;
};

type ReleaseInfrastructureAdapter = {
  kind: string;
  prepare: (input: {
    matrixCell?: ReleaseInfrastructureMatrixCell;
    runId: string;
  }) => Promise<PreparedReleaseInfrastructure>;
  release: (input: { prepared: unknown; runId: string }) => Promise<unknown>;
};

// —— 场景矩阵单元与运行工件 ——

// Infrastructure Adapter 只按原始判据核对调用方是否给出完整矩阵单元，因此这里的
// 字段保持可选，由 prepare 自己拒绝缺字段的调用。
type ReleaseInfrastructureMatrixCell = {
  cellId?: string;
  environmentId?: string;
  scenarioId?: string;
};

// 已验证场景计划的矩阵单元。Journal 与 Environment 只消费下列字段；平台字段由
// writeRunManifest 从真实计划单元写入，verify-clean 的匹配判据仍由已接受的
// Harness assertReleaseTestHost 承担，readRunManifest 不额外新增判据。
type ReleaseScenarioMatrixCell = ReleaseInfrastructureMatrixCell & {
  architecture: string;
  operatingSystem: string;
  operatingSystemVersion: string;
};

type ReleaseE2ESshIdentity = {
  host: string;
  keyPath: string | null;
  port: number;
};

type ReleaseE2ERunInputs = {
  candidateManifestPath: string;
  hostAdapter: string;
  hubOwnerUrl: string;
  hubPublicUrl: string;
  matrixCellId: string;
  matrixPath: string;
  ssh: ReleaseE2ESshIdentity | null;
};

type SerializedRunError = {
  code: string;
  message: string;
  name: string;
};

type ReleaseE2ERunManifest = {
  candidate?: unknown;
  createdAt: string;
  failure: { error: SerializedRunError; phase: string } | null;
  hostMutationPossible: boolean;
  hubDigest?: unknown;
  infrastructure?: ReleaseInfrastructureIdentity | null;
  inputs: ReleaseE2ERunInputs;
  matrixCell: ReleaseScenarioMatrixCell | null;
  ownershipToken: string;
  phase: string;
  runId: string;
  scenario?: string | null;
  schemaVersion: number;
  ssh: ReleaseE2ESshIdentity | null;
  updatedAt: string;
};

type EvidenceSink = { write(evidence: unknown): Promise<void> };

type ReleaseRunArtifactJournal = {
  evidenceSink: EvidenceSink;
  fail: (input: {
    error: unknown;
    phase: string;
    secrets?: readonly string[];
  }) => Promise<void>;
  manifest: ReleaseE2ERunManifest;
  update: (patch: Partial<ReleaseE2ERunManifest>) => Promise<unknown>;
};

// —— Hub 运行资源 ——

type HubRuntime = {
  archivePath: string;
  configDigest: string;
  manifestDigest: string;
  name: string;
  tag: string;
  tagCreated: boolean;
};

type HubRuntimeHistoryEntry = {
  configDigest: string;
  hub: string;
  manifestDigest: string;
  volume: string;
};

// 快照操作证据只作为证据透传；error 字段保持原实现读取 error.message 得到的值，
// 因此不把它收窄成 string。
type HubSnapshotOperationEvidence = {
  error?: unknown;
  manifestDigest?: string;
  operation: string;
  status: string;
};

type HubResources = DockerObjectOwner & {
  activeHub: string;
  baseline: HubRuntime | null;
  candidate: HubRuntime;
  configDigest: string;
  container: string;
  containerCreated: boolean;
  exportedRecipeDirs: string[];
  identityVerified: boolean;
  manifestDigest: string;
  redactionSecrets: string[];
  runId: string;
  runtimeHistory: HubRuntimeHistoryEntry[];
  snapshot: HubStateSnapshotEvidence | null;
  snapshotContainer: string;
  snapshotContainerMayExist: boolean;
  snapshotOperations: HubSnapshotOperationEvidence[];
  snapshotVolume: string;
  snapshotVolumeCreated: boolean;
  tag: string;
  tagCreated: boolean;
  volume: string;
  volumeCreated: boolean;
};

// enoki-hub-state 工具 JSON 输出在本模块读取的字段视图；其余字段只作为证据原样
// 透传，因此保持索引视图。
type HubStateSnapshotToolResult = {
  manifest?: unknown;
  manifestDigest: string;
  [key: string]: unknown;
};

// requireHubStateSnapshotResources 判据确认 Release Baseline 运行态存在后的资源视图。
type HubResourcesWithBaseline = HubResources & { baseline: HubRuntime };

type HubRuntimeEnvironment = {
  hubOwnerUrl: string;
  hubPublicUrl: string;
  operationSigningSecret: string;
  ownerPassword: string;
  ownerPort: string;
  probeOperationRunningTimeoutSeconds: number | null;
  useHubStateSnapshot: boolean;
};

// Hub Enrollment 返回的 Probe Bootstrap Recipe Record。Orchestrator 只把它作为
// 未知证据传递，因此这里的可读视图保持 unknown，由已接受的 provenance 判据校验。
type EnrollmentRecipeRecord = {
  bundleVersion?: unknown;
  distribution?: unknown;
  kind?: unknown;
  recipe?: unknown;
  rootFingerprint?: unknown;
  schemaVersion?: unknown;
  targets?: unknown;
};

type DockerHubController = ReturnType<typeof createDockerHubController>;

type RecipeProvenance = ReturnType<
  typeof verifyActiveHubBootstrapRecipeProvenance
>;

type CanonicalReportTransport = ReturnType<
  typeof createCanonicalReportEvidenceTransport
>;
type CanonicalReportTransportFactory = (input: {
  fetch?: typeof globalThis.fetch;
  listenUrl: string;
  upstreamUrl: string;
}) => CanonicalReportTransport;

type RecipeStagingError = Error & { cleanupError?: Error };

type LocalSshReleaseEnvironmentOptions = {
  candidateDir: string;
  containerEngine?: string;
  docker?: DockerHubController;
  hubOwnerUrl: string;
  hubPublicUrl: string;
  ownerPassword: string;
  ownershipToken?: string;
  sshExecute: CommandExecutor;
};

type ReleaseEnvironmentOptions = {
  bootstrapProvisioner?: BootstrapProvisioner;
  candidateDir: string;
  canonicalReportTransportFactory?: CanonicalReportTransportFactory;
  docker?: DockerHubController;
  execute?: CommandExecutor;
  hubOwnerUrl: string;
  hubPublicUrl: string;
  infrastructure?: unknown;
  matrixCell?: ReleaseScenarioMatrixCell;
  onCleanupManaged?: () => unknown;
  ownerPassword: string;
  ownershipToken?: string;
  releaseInfrastructure?: (input: {
    prepared: unknown;
    runId: string;
  }) => Promise<unknown>;
};

// Environment cleanup 的逐项结果；失败时统一聚合为 AggregateError 抛出。
type ReleaseEnvironmentCleanupReport = {
  hub?: unknown;
  infrastructure?: unknown;
  transport?: unknown;
};

type ReleaseE2EOptionDefinition = { default?: string; required?: boolean };
type ReleaseE2EOptionValues = Record<string, string | undefined>;
type ReleaseE2ECommandName = "run" | "verify-clean";
type ReleaseE2EParsedCommand = {
  command: ReleaseE2ECommandName;
  values: ReleaseE2EOptionValues;
};

const runOptions: Readonly<Record<string, ReleaseE2EOptionDefinition>> =
  Object.freeze({
    "--candidate-manifest": { required: true },
    "--container-engine": { default: "docker" },
    "--evidence-dir": { required: true },
    "--host-adapter": { default: "ssh" },
    "--hub-owner-url": { required: true },
    "--hub-public-url": { required: true },
    "--matrix": { required: true },
    "--matrix-cell": { required: true },
    "--owner-password-env": { required: true },
    "--root-public-key-env": { required: true },
    "--run-id": {},
    "--ssh-host": {},
    "--ssh-key": {},
    "--ssh-port": { default: "22" },
  });

const verifyCleanOptions: Readonly<Record<string, ReleaseE2EOptionDefinition>> =
  Object.freeze({
    "--host-adapter": { default: "ssh" },
    "--run-manifest": { required: true },
    "--ssh-host": {},
    "--ssh-key": {},
    "--ssh-port": { default: "22" },
  });

export function parseReleaseE2ECommandLine(
  arguments_: readonly string[],
): ReleaseE2EParsedCommand {
  const [command, ...tokens] = arguments_;
  if (command !== "run" && command !== "verify-clean") {
    throw new Error("command must be run or verify-clean");
  }
  const definitions = command === "run" ? runOptions : verifyCleanOptions;
  if (tokens.length % 2 !== 0) {
    throw new Error(`option ${tokens.at(-1)} requires a value`);
  }
  const values: ReleaseE2EOptionValues = {};
  for (let index = 0; index < tokens.length; index += 2) {
    const name = tokens[index];
    const value = tokens[index + 1];
    if (!name || !Object.hasOwn(definitions, name)) {
      throw new Error(`unknown option: ${name}`);
    }
    if (Object.hasOwn(values, name)) {
      throw new Error(`duplicate option: ${name}`);
    }
    if (!value) throw new Error(`${name} requires a value`);
    values[name] = value;
  }
  const hostAdapter = values["--host-adapter"] ?? "ssh";
  if (hostAdapter !== "ssh" && hostAdapter !== "ci") {
    throw new Error("--host-adapter must be ssh or ci");
  }
  if (hostAdapter === "ssh" && values["--ssh-host"] === undefined) {
    throw new Error("--ssh-host is required");
  }
  if (
    hostAdapter === "ci" &&
    (values["--ssh-host"] !== undefined ||
      values["--ssh-key"] !== undefined ||
      values["--ssh-port"] !== undefined)
  ) {
    throw new Error("CI Host adapter does not accept SSH options");
  }
  for (const [name, definition] of Object.entries(definitions)) {
    if (values[name] === undefined && definition.default !== undefined) {
      values[name] = definition.default;
    }
    if (definition.required && values[name] === undefined) {
      throw new Error(`${name} is required`);
    }
  }

  if (hostAdapter === "ssh") validateSshOptions(values);
  if (command === "run") {
    // 上方 required 循环已保证这些选项存在；缺失时沿用同一 `${name} is required` 文本。
    const requiredValue = (name: string): string => {
      const value = values[name];
      if (value === undefined) throw new Error(`${name} is required`);
      return value;
    };
    if (
      path.basename(requiredValue("--candidate-manifest")) !==
      "candidate-manifest.json"
    ) {
      throw new Error("--candidate-manifest must name candidate-manifest.json");
    }
    if (
      path.basename(requiredValue("--matrix")) !== "release-e2e-matrix.json"
    ) {
      throw new Error("--matrix must name release-e2e-matrix.json");
    }
    if (
      !/^[a-z0-9][a-z0-9._-]*--[a-z][a-z0-9-]*$/.test(
        requiredValue("--matrix-cell"),
      )
    ) {
      throw new Error("--matrix-cell must be a stable declared cell ID");
    }
    if (values["--container-engine"] !== "docker") {
      throw new Error("--container-engine must be docker");
    }
    if (
      !/^[A-Za-z_][A-Za-z0-9_]*$/.test(requiredValue("--owner-password-env"))
    ) {
      throw new Error(
        "--owner-password-env must be an environment variable name",
      );
    }
    if (
      !/^[A-Za-z_][A-Za-z0-9_]*$/.test(requiredValue("--root-public-key-env"))
    ) {
      throw new Error(
        "--root-public-key-env must name an environment variable",
      );
    }
    for (const option of ["--hub-owner-url", "--hub-public-url"]) {
      const url = new URL(requiredValue(option));
      if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new Error(`${option} must use HTTP or HTTPS`);
      }
      if (url.username || url.password) {
        throw new Error(`${option} must not contain credentials`);
      }
    }
    if (new URL(requiredValue("--hub-owner-url")).protocol !== "http:") {
      throw new Error("--hub-owner-url must use direct HTTP for local Docker");
    }
    assertCandidateHubOwnerUrl(requiredValue("--hub-owner-url"));
  }
  return { command, values };
}

export async function loadValidatedCandidate(
  candidateManifestPath: string,
  { trustedRootPublicKeyPem }: { trustedRootPublicKeyPem?: string } = {},
): Promise<ValidatedCandidate> {
  if (path.basename(candidateManifestPath) !== "candidate-manifest.json") {
    throw new Error(
      "Candidate Manifest path must name candidate-manifest.json",
    );
  }
  const candidateDir = path.dirname(path.resolve(candidateManifestPath));
  if (!trustedRootPublicKeyPem) {
    throw new Error("trusted Probe Distribution Trust Root is required");
  }
  const manifest = await validateReleaseCandidate(candidateDir, {
    trustedRootPublicKeyPem,
  });
  // 03 的候选验证已保证这份 Manifest 的结构；这里复用 Orchestrator 已接受的同一判据，
  // 把它提升到本模块消费的数据 Interface，不重复实现字段校验。
  assertCandidateManifest(manifest);
  return { candidateDir, manifest };
}

export function createSshReleaseInfrastructureAdapter({
  candidateManifestPath,
  host,
  keyPath,
  knownHostsPath,
  loadCandidate = loadValidatedCandidate,
  port = 22,
  runProcess = runSpawnedProcess,
  transferFile,
  trustedRootPublicKeyPem,
}: {
  candidateManifestPath: string;
  host: string;
  keyPath?: string | null;
  knownHostsPath: string;
  loadCandidate?: LoadValidatedCandidate;
  port?: number;
  runProcess?: ProcessRunner;
  transferFile?: CandidateArchiveTransfer;
  trustedRootPublicKeyPem: string;
}): ReleaseInfrastructureAdapter {
  const execute = createSshExecutor({
    host,
    keyPath,
    knownHostsPath,
    port,
    runProcess,
  });
  return createReleaseInfrastructureAdapter({
    artifactAccess: "filesystem",
    candidateManifestPath,
    connection: "ssh",
    execute,
    kind: "ssh",
    loadCandidate,
    provisioning: "existing-disposable-host",
    transferFile:
      transferFile ??
      createSshCandidateArchiveTransfer({
        host,
        keyPath,
        knownHostsPath,
        port,
        runProcess,
      }),
    trustedRootPublicKeyPem,
  });
}

export function createCiReleaseInfrastructureAdapter({
  candidateManifestPath,
  environment = process.env,
  loadCandidate = loadValidatedCandidate,
  runProcess = runSpawnedProcess,
  timeoutMs = 5 * 60 * 1000,
  transferFile = copyCandidateArchive,
  trustedRootPublicKeyPem,
}: {
  candidateManifestPath: string;
  environment?: NodeJS.ProcessEnv;
  loadCandidate?: LoadValidatedCandidate;
  runProcess?: ProcessRunner;
  timeoutMs?: number;
  transferFile?: CandidateArchiveTransfer;
  trustedRootPublicKeyPem: string;
}): ReleaseInfrastructureAdapter {
  if (
    environment.GITHUB_ACTIONS !== "true" ||
    environment.RUNNER_OS !== "Linux" ||
    environment.RUNNER_ARCH !== "X64" ||
    !/^\d+$/.test(environment.GITHUB_RUN_ID ?? "") ||
    !/^\d+$/.test(environment.GITHUB_RUN_ATTEMPT ?? "")
  ) {
    throw new Error(
      "CI Release Test Host requires an x86_64 Linux GitHub Actions runner identity",
    );
  }
  const execute = createCiHostExecutor({ runProcess, timeoutMs });
  return createReleaseInfrastructureAdapter({
    artifactAccess: "github-actions",
    candidateManifestPath,
    connection: "local",
    execute,
    kind: "ci",
    loadCandidate,
    provisioning: "github-hosted-runner",
    transferFile,
    trustedRootPublicKeyPem,
  });
}

export function createCiHostExecutor({
  runProcess = runSpawnedProcess,
  timeoutMs = 5 * 60 * 1000,
}: { runProcess?: ProcessRunner; timeoutMs?: number } = {}): CommandExecutor {
  return (script, options = {}) => {
    if (typeof script !== "string" || !script) {
      throw new Error("local Host script must be non-empty");
    }
    if (options.root) {
      return runProcess("sudo", ["-n", "sh", "-s"], {
        input: script,
        timeoutMs,
      });
    }
    return runProcess("sh", ["-s"], { input: script, timeoutMs });
  };
}

function createReleaseInfrastructureAdapter({
  artifactAccess,
  candidateManifestPath,
  connection,
  execute,
  kind,
  loadCandidate,
  provisioning,
  transferFile,
  trustedRootPublicKeyPem,
}: {
  artifactAccess: string;
  candidateManifestPath: string;
  connection: string;
  execute: CommandExecutor;
  kind: string;
  loadCandidate: LoadValidatedCandidate;
  provisioning: string;
  transferFile: CandidateArchiveTransfer;
  trustedRootPublicKeyPem: string;
}): ReleaseInfrastructureAdapter {
  let preparedRunId: string | null = null;
  let bootstrapProvisioner: CandidateBootstrapProvisioner | null = null;
  return {
    kind,
    async prepare({ matrixCell, runId }) {
      if (
        !matrixCell?.cellId ||
        !matrixCell.environmentId ||
        !matrixCell.scenarioId
      ) {
        throw new Error("Release E2E infrastructure requires a matrix cell");
      }
      if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(runId ?? "")) {
        throw new Error("Release E2E infrastructure run ID is invalid");
      }
      const candidate = await loadCandidate(candidateManifestPath, {
        trustedRootPublicKeyPem,
      });
      bootstrapProvisioner = createCandidateBootstrapProvisioner({
        candidateDir: candidate.candidateDir,
        execute,
        manifest: candidate.manifest,
        transferFile,
      });
      preparedRunId = runId;
      return {
        candidateDir: candidate.candidateDir,
        execute,
        infrastructure: {
          artifactAccess,
          connection,
          kind,
          matrixCellId: matrixCell.cellId,
          provisioning,
        },
        manifest: candidate.manifest,
        provisionBootstrap: bootstrapProvisioner.provision,
      };
    },
    async release({ runId }) {
      if (preparedRunId !== runId) {
        throw new Error("Release E2E infrastructure run ID does not match");
      }
      const recipe = bootstrapProvisioner
        ? await bootstrapProvisioner.cleanup({ runId })
        : { clean: true, skipped: "bootstrap_not_prepared" };
      preparedRunId = null;
      bootstrapProvisioner = null;
      return { clean: true, recipe };
    },
  };
}

function createCandidateBootstrapProvisioner({
  candidateDir,
  execute,
  manifest,
  transferFile,
}: {
  candidateDir: string;
  execute: CommandExecutor;
  manifest: ReleaseE2ECandidateManifest;
  transferFile: CandidateArchiveTransfer;
}): CandidateBootstrapProvisioner {
  const recipe = selectCandidateBootstrapRecipe(manifest);
  const recipePath = path.join(candidateDir, "recipe", recipe.file);
  let provisioned = false;
  let provisionedRunId: string | null | undefined = null;
  let stageDir: string | null = null;
  return {
    async provision({ recipe: requestedRecipe, runId, sourcePath } = {}) {
      const selectedRecipe = requestedRecipe ?? recipe;
      const selectedPath = sourcePath ?? recipePath;
      if (provisioned) {
        const removed = await execute(
          removeCandidateBootstrapRecipeScript(stageDir),
          { sensitive: true },
        );
        if (removed.code !== 0 || removed.stdout.trim() !== "removed") {
          throw new Error(
            `Could not replace staged Probe Bootstrap recipe: ${removed.stderr}`,
          );
        }
        provisioned = false;
        provisionedRunId = null;
        stageDir = null;
      }
      if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(runId ?? "")) {
        throw new Error("Release E2E infrastructure run ID is invalid");
      }
      const staged = await execute(stageCandidateBootstrapRecipeScript(), {
        sensitive: true,
      });
      if (
        staged.code !== 0 ||
        !/^\/tmp\/enoki-release-e2e-recipe\.[A-Za-z0-9]+$/.test(
          staged.stdout.trim(),
        )
      ) {
        throw new Error(
          `Could not stage Candidate Probe Bootstrap recipe as the non-root Host user: ${staged.stderr}`,
        );
      }
      stageDir = staged.stdout.trim();
      provisionedRunId = runId;
      try {
        await transferFile({
          destination: path.join(stageDir, selectedRecipe.file),
          source: selectedPath,
        });
        const verified = await execute(
          verifyCandidateBootstrapRecipeScript({
            recipe: selectedRecipe,
            stageDir,
          }),
          { sensitive: true },
        );
        if (verified.code !== 0 || verified.stdout.trim() !== "verified") {
          throw new Error(
            `Could not verify Candidate Probe Bootstrap recipe staging: ${verified.stderr}`,
          );
        }
      } catch (error) {
        const cleanup = await execute(
          removeCandidateBootstrapRecipeScript(stageDir),
          { sensitive: true },
        ).catch((cleanupError) => ({
          code: -1,
          stderr: cleanupError.message,
          stdout: "",
        }));
        if (cleanup.code === 0 && cleanup.stdout.trim() === "removed") {
          stageDir = null;
        } else if (error instanceof Error) {
          attachRecipeStagingCleanupError(
            error,
            `Could not clean failed Probe Bootstrap recipe staging: ${cleanup.stderr}`,
          );
        }
        throw error;
      }
      provisioned = true;
      return {
        evidence: {
          file: selectedRecipe.file,
          sha256: selectedRecipe.sha256,
          version: selectedRecipe.version,
        },
        workingDirectory: stageDir,
      };
    },
    async cleanup({ runId }) {
      if (!stageDir) return { clean: true, skipped: "recipe_not_staged" };
      if (runId !== provisionedRunId) {
        throw new Error(
          "Candidate Probe Bootstrap recipe run ID does not match",
        );
      }
      const removed = await execute(
        removeCandidateBootstrapRecipeScript(stageDir),
        { sensitive: true },
      );
      if (removed.code !== 0 || removed.stdout.trim() !== "removed") {
        throw new Error(
          `Could not remove Candidate Probe Bootstrap recipe: ${removed.stderr}`,
        );
      }
      stageDir = null;
      provisioned = false;
      provisionedRunId = null;
      return { clean: true };
    },
  };
}

function attachRecipeStagingCleanupError(
  error: RecipeStagingError,
  message: string,
): void {
  error.cleanupError = new Error(message);
}

function selectCandidateBootstrapRecipe(
  manifest: ReleaseE2ECandidateManifest,
): CandidateBootstrapRecipe {
  const recipe = manifest?.bootstrapRecipe;
  assertCandidateBootstrapRecipe(recipe);
  return recipe;
}

function assertCandidateBootstrapRecipe(
  recipe: unknown,
): asserts recipe is CandidateBootstrapRecipe {
  const view = objectView(recipe);
  if (
    view.file !== "enoki-probe-bootstrap.py" ||
    view.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(regexInput(view.sha256)) ||
    !isPositiveSafeInteger(view.size)
  ) {
    throw new Error("Validated Candidate has no exact Probe Bootstrap recipe");
  }
}

function stageCandidateBootstrapRecipeScript() {
  return `# enoki-release-e2e:candidate-bootstrap-recipe-stage\nset -eu\n[ "$(id -u)" != 0 ]\nstage_dir=$(mktemp -d /tmp/enoki-release-e2e-recipe.XXXXXX)\nchmod 0700 "$stage_dir"\nprintf '%s\\n' "$stage_dir"\n`;
}

function verifyCandidateBootstrapRecipeScript({
  recipe,
  stageDir,
}: {
  recipe: CandidateBootstrapRecipe;
  stageDir: string;
}) {
  // sha256sum -c 把逐文件状态行写到 stdout，会污染调用方严格要求等于 verified 的哨兵通道；
  // 状态行丢弃即可，摘要不符仍由 sha256sum 的非 0 退出与 stderr 警告拒绝。
  return `# enoki-release-e2e:candidate-bootstrap-recipe-verify\nset -eu\n[ "$(id -u)" != 0 ]\nstage_dir=${shellSingleQuote(stageDir)}\nrecipe="$stage_dir/${recipe.file}"\n[ -d "$stage_dir" ] && [ ! -L "$stage_dir" ] && [ "$(stat -c %a "$stage_dir")" = 700 ]\n[ -f "$recipe" ] && [ ! -L "$recipe" ]\n[ "$(wc -c < "$recipe" | tr -d ' ')" = ${shellSingleQuote(String(recipe.size))} ]\nprintf '%s  %s\\n' ${shellSingleQuote(recipe.sha256)} "$recipe" | sha256sum -c - >/dev/null\nchmod 0500 "$recipe"\nprintf 'verified\\n'\n`;
}

function removeCandidateBootstrapRecipeScript(stageDir: string | null) {
  return `# enoki-release-e2e:candidate-bootstrap-recipe-remove\nset -eu\n[ "$(id -u)" != 0 ]\nstage_dir=${shellSingleQuote(stageDir)}\ncase "$stage_dir" in /tmp/enoki-release-e2e-recipe.*) ;; *) exit 1 ;; esac\nrm -f -- "$stage_dir/enoki-probe-bootstrap.py"\nrmdir -- "$stage_dir"\nprintf 'removed\\n'\n`;
}

async function copyCandidateArchive({
  destination,
  source,
}: {
  destination: string;
  source: string;
}): Promise<void> {
  await copyFile(source, destination);
  await chmod(destination, 0o600);
}

export function verifyActiveHubBootstrapRecipeProvenance({
  activeHub,
  activeManifestDigest,
  candidateManifest,
  enrollmentRecipe,
  recipeBytes,
}: {
  activeHub: string;
  activeManifestDigest: string;
  candidateManifest: ReleaseE2ECandidateManifest;
  enrollmentRecipe: unknown;
  recipeBytes: Buffer;
}) {
  const record = objectView(enrollmentRecipe);
  const recipe = objectView(record.recipe);
  const expectedHubDigest =
    activeHub === "candidate"
      ? candidateManifest?.hub?.digest
      : activeHub === "baseline"
        ? candidateManifest?.releaseBaseline?.hub?.imageDigest
        : null;
  const expectedBundleVersion =
    activeHub === "candidate"
      ? candidateManifest?.probeAssetSet?.version
      : candidateManifest?.releaseBaseline?.kind === "enoki-release-baseline"
        ? candidateManifest.releaseBaseline.probeAssetSet?.version
        : null;
  if (
    !expectedHubDigest ||
    activeManifestDigest !== expectedHubDigest ||
    !expectedBundleVersion
  ) {
    throw new Error(
      "Active Hub identity is not bound to the verified Candidate or Release Baseline",
    );
  }
  const expectedRecordKeys = [
    "bundleVersion",
    "distribution",
    "kind",
    "recipe",
    "rootFingerprint",
    "schemaVersion",
    "targets",
  ];
  const expectedRecipeKeys = ["file", "sha256", "size", "version"];
  if (
    !hasExactKeys(enrollmentRecipe, expectedRecordKeys) ||
    !hasExactKeys(record.recipe, expectedRecipeKeys) ||
    record.bundleVersion !== expectedBundleVersion ||
    record.distribution !== "enoki" ||
    record.kind !== "enoki-probe-bootstrap-recipe-record" ||
    record.schemaVersion !== 1 ||
    recipe.file !== "enoki-probe-bootstrap.py" ||
    recipe.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(regexInput(record.rootFingerprint)) ||
    !/^[0-9a-f]{64}$/.test(regexInput(recipe.sha256)) ||
    !isPositiveSafeInteger(recipe.size) ||
    !isUnknownArray(record.targets) ||
    record.targets.length !== 4 ||
    !Buffer.isBuffer(recipeBytes) ||
    recipeBytes.byteLength !== recipe.size ||
    sha256(recipeBytes) !== recipe.sha256
  ) {
    throw new Error(
      "Active Hub Enrollment recipe record or exported bytes are invalid",
    );
  }

  const normalizedRecord = {
    bundleVersion: record.bundleVersion,
    distribution: record.distribution,
    kind: record.kind,
    recipe: {
      file: recipe.file,
      sha256: recipe.sha256,
      size: recipe.size,
      version: recipe.version,
    },
    rootFingerprint: record.rootFingerprint,
    schemaVersion: record.schemaVersion,
    targets: record.targets,
  };
  const recordBytes = Buffer.from(
    `${JSON.stringify(normalizedRecord, null, 2)}\n`,
  );
  const recordSha256 = sha256(recordBytes);
  const recordSize = recordBytes.byteLength;
  if (activeHub === "candidate") {
    const candidateRecipe = candidateManifest?.bootstrapRecipe;
    if (
      candidateRecipe?.recordFile !== "enoki-probe-bootstrap-recipe.json" ||
      candidateRecipe?.recordSha256 !== recordSha256 ||
      candidateRecipe?.recordSize !== recordSize ||
      candidateRecipe?.bundleVersion !== normalizedRecord.bundleVersion ||
      candidateRecipe?.distribution !== normalizedRecord.distribution ||
      candidateRecipe?.kind !== normalizedRecord.kind ||
      candidateRecipe?.rootFingerprint !== normalizedRecord.rootFingerprint ||
      candidateRecipe?.schemaVersion !== normalizedRecord.schemaVersion ||
      JSON.stringify(candidateRecipe?.targets) !==
        JSON.stringify(normalizedRecord.targets) ||
      candidateRecipe?.file !== normalizedRecord.recipe.file ||
      candidateRecipe?.sha256 !== normalizedRecord.recipe.sha256 ||
      candidateRecipe?.size !== normalizedRecord.recipe.size ||
      candidateRecipe?.version !== normalizedRecord.recipe.version
    ) {
      throw new Error(
        "Active Candidate Hub Enrollment recipe does not match Candidate Manifest provenance",
      );
    }
  }

  return {
    activeHub,
    hubDigest: activeManifestDigest,
    kind: "enoki-release-e2e-bootstrap-recipe-provenance",
    record: normalizedRecord,
    recordFile: "enoki-probe-bootstrap-recipe.json",
    recordSha256,
    recordSize,
    schemaVersion: 1,
  };
}

function hasExactKeys(value: unknown, keys: readonly string[]): boolean {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

function shellSingleQuote(value: unknown): string {
  return `'${String(value).replaceAll("'", "'\\\"'\\\"'")}'`;
}

function createSshCandidateArchiveTransfer({
  host,
  keyPath,
  knownHostsPath,
  port,
  runProcess,
}: {
  host: string;
  keyPath?: string | null;
  knownHostsPath: string;
  port: number;
  runProcess: ProcessRunner;
}): CandidateArchiveTransfer {
  validateSshOptions({ "--ssh-host": host, "--ssh-port": String(port) });
  return async ({ destination, source }) => {
    if (!knownHostsPath || !source || !destination) {
      throw new Error(
        "SSH Candidate archive transfer is missing an exact path",
      );
    }
    const arguments_ = [
      "-q",
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=15",
      "-o",
      "StrictHostKeyChecking=accept-new",
      "-o",
      `UserKnownHostsFile=${knownHostsPath}`,
      "-P",
      String(port),
    ];
    if (keyPath) arguments_.push("-i", keyPath, "-o", "IdentitiesOnly=yes");
    arguments_.push("--", source, `${host}:${destination}`);
    const result = await runProcess("scp", arguments_, {
      timeoutMs: 5 * 60 * 1000,
    });
    if (result.code !== 0) {
      throw new Error(
        `Could not transfer Candidate Probe Bootstrap archive: ${result.stderr}`,
      );
    }
  };
}

export function createSshExecutor({
  host,
  keyPath,
  knownHostsPath,
  port = 22,
  runProcess = runSpawnedProcess,
  timeoutMs = 5 * 60 * 1000,
}: {
  host: string;
  keyPath?: string | null;
  knownHostsPath: string;
  port?: number;
  runProcess?: ProcessRunner;
  timeoutMs?: number;
}): CommandExecutor {
  validateSshOptions({ "--ssh-host": host, "--ssh-port": String(port) });
  if (!knownHostsPath) throw new Error("SSH known-hosts path is required");
  return async (script: unknown, options: CommandOptions = {}) => {
    if (typeof script !== "string" || !script) {
      throw new Error("SSH script must be non-empty");
    }
    const arguments_ = [
      "-T",
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=15",
      "-o",
      "ServerAliveInterval=10",
      "-o",
      "ServerAliveCountMax=3",
      "-o",
      "StrictHostKeyChecking=accept-new",
      "-o",
      `UserKnownHostsFile=${knownHostsPath}`,
      "-p",
      String(port),
    ];
    if (keyPath) arguments_.push("-i", keyPath, "-o", "IdentitiesOnly=yes");
    arguments_.push(
      "--",
      host,
      options.root
        ? 'if [ "$(id -u)" = 0 ]; then exec sh -s; else exec sudo -n sh -s; fi'
        : "exec sh -s",
    );
    return runProcess("ssh", arguments_, { input: script, timeoutMs });
  };
}

export function createFileEvidenceSink(
  evidenceDir: string,
  { runId }: { runId?: string } = {},
) {
  const resolved = path.resolve(evidenceDir);
  return {
    async write(evidence: unknown): Promise<void> {
      await mkdir(resolved, { recursive: true });
      const destination = path.join(resolved, "evidence.json");
      const record = objectView(evidence);
      if (runId === undefined) {
        await writeJsonAtomically(destination, evidence);
        return;
      }
      if (record.runId !== runId) {
        throw new Error("Release E2E evidence run ID does not match");
      }
      const parsedCurrent: unknown = JSON.parse(
        await readFile(destination, "utf8"),
      );
      const current = objectView(parsedCurrent);
      if (
        current.runId !== runId ||
        objectView(current.result).status !== "running"
      ) {
        throw Object.assign(
          new Error("Release E2E final evidence already exists"),
          { code: "EEXIST" },
        );
      }
      await replaceJsonAtomically(destination, {
        ...current,
        ...record,
        inputs: current.inputs,
        schemaVersion: 2,
      });
    },
  };
}

export async function createRunArtifactJournal({
  evidenceDir,
  inputs,
  ownershipToken,
  runId,
}: {
  evidenceDir: string;
  inputs: ReleaseE2ERunInputs;
  ownershipToken: string;
  runId: string;
}): Promise<ReleaseRunArtifactJournal> {
  const resolved = path.resolve(evidenceDir);
  const createdAt = new Date().toISOString();
  let manifest: ReleaseE2ERunManifest = {
    createdAt,
    failure: null,
    hostMutationPossible: false,
    inputs,
    matrixCell: null,
    ownershipToken,
    phase: "initialized",
    runId,
    scenario: null,
    schemaVersion: 3,
    ssh: inputs.hostAdapter === "ssh" ? inputs.ssh : null,
    updatedAt: createdAt,
  };
  const initialEvidence = {
    cleanup: null,
    diagnostics: null,
    inputs,
    phase: "initialized",
    result: { status: "running" },
    runId,
    scenario: null,
    schemaVersion: 2,
  };
  await mkdir(resolved, { recursive: true });
  await writeJsonAtomically(path.join(resolved, "run-manifest.json"), manifest);
  await writeJsonAtomically(
    path.join(resolved, "evidence.json"),
    initialEvidence,
  );

  return {
    evidenceSink: createFileEvidenceSink(resolved, { runId }),
    get manifest() {
      return manifest;
    },
    async fail({
      error,
      phase,
      secrets = [],
    }: {
      error: unknown;
      phase: string;
      secrets?: readonly string[];
    }): Promise<void> {
      const serialized = serializeRunError(error, secrets);
      manifest = {
        ...manifest,
        failure: { error: serialized, phase },
        phase: "failed",
        updatedAt: new Date().toISOString(),
      };
      await replaceJsonAtomically(
        path.join(resolved, "run-manifest.json"),
        manifest,
      );
      const evidencePath = path.join(resolved, "evidence.json");
      const parsedEvidence: unknown = JSON.parse(
        await readFile(evidencePath, "utf8"),
      );
      const evidence = objectView(parsedEvidence);
      if (
        evidence.runId === runId &&
        objectView(evidence.result).status === "running"
      ) {
        await replaceJsonAtomically(evidencePath, {
          ...evidence,
          diagnostics: { error: serialized },
          phase: "failed",
          result: { error: serialized, status: "failed" },
          scenario: manifest.scenario,
        });
      }
    },
    async update(patch: Partial<ReleaseE2ERunManifest>): Promise<unknown> {
      manifest = {
        ...manifest,
        ...patch,
        updatedAt: new Date().toISOString(),
      };
      await replaceJsonAtomically(
        path.join(resolved, "run-manifest.json"),
        manifest,
      );
      const evidencePath = path.join(resolved, "evidence.json");
      const parsedEvidence: unknown = JSON.parse(
        await readFile(evidencePath, "utf8"),
      );
      const evidence = objectView(parsedEvidence);
      if (
        evidence.runId === runId &&
        objectView(evidence.result).status === "running"
      ) {
        await replaceJsonAtomically(evidencePath, {
          ...evidence,
          phase: manifest.phase,
          scenario: manifest.scenario,
        });
      }
      return manifest;
    },
  };
}

export async function writeRunManifest(
  evidenceDir: string,
  manifest: ReleaseE2ERunManifest,
): Promise<void> {
  await mkdir(evidenceDir, { recursive: true });
  await writeJsonAtomically(
    path.join(evidenceDir, "run-manifest.json"),
    manifest,
  );
}

export async function readRunManifest(
  manifestPath: string,
): Promise<ReleaseE2ERunManifest> {
  const parsedManifest: unknown = JSON.parse(
    await readFile(manifestPath, "utf8"),
  );
  const value = objectView(parsedManifest);
  if (!isReleaseE2ERunManifest(value)) {
    throw new Error("Release E2E run manifest is invalid");
  }
  return value;
}

// 判据与原实现逐条等价（只把「拒绝条件」整体取反）：校验归属、阶段与
// 矩阵/SSH 身份的跨字段一致性，这些正是独立 verify-clean 消费的不变量。
// 属性读取用 objectView，其对非对象 JSON 值给出 undefined，与原 `?.` 取值一致。
function isReleaseE2ERunManifest(
  value: UnknownRecord,
): value is ReleaseE2ERunManifest {
  const inputs = objectView(value.inputs);
  const matrixCell = objectView(value.matrixCell);
  const infrastructure = objectView(value.infrastructure);
  const ssh = objectView(value.ssh);
  const inputsSsh = objectView(inputs.ssh);
  return (
    value.schemaVersion === 3 &&
    /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(regexInput(value.runId)) &&
    /^[0-9a-f-]{36}$/.test(regexInput(value.ownershipToken)) &&
    isUnknownRecord(value.inputs) &&
    (inputs.hostAdapter === "ssh" || inputs.hostAdapter === "ci") &&
    typeof value.hostMutationPossible === "boolean" &&
    /^(?:initialized|plan-validated|candidate-prepare|candidate-prepared|scenario-running|succeeded|failed)$/.test(
      regexInput(value.phase),
    ) &&
    (value.matrixCell === null ||
      (matrixCell.scenarioId === value.scenario &&
        Object.hasOwn(releaseE2EScenarioRegistry, regexInput(value.scenario)) &&
        inputs.matrixCellId === matrixCell.cellId &&
        (!value.infrastructure ||
          matrixCell.cellId === infrastructure.matrixCellId))) &&
    (!value.hostMutationPossible ||
      (!!value.matrixCell && !!value.infrastructure)) &&
    (inputs.hostAdapter !== "ssh" ||
      (!!value.ssh &&
        ssh.host === inputsSsh.host &&
        ssh.port === inputsSsh.port &&
        ssh.keyPath === inputsSsh.keyPath)) &&
    (inputs.hostAdapter !== "ci" || value.ssh === null)
  );
}

export function newRunIdentity(runId?: string) {
  const generated = runId ?? `e2e-${Date.now()}-${randomUUID().slice(0, 8)}`;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(generated)) {
    throw new Error("run ID must be a safe non-empty identifier");
  }
  return { ownershipToken: randomUUID(), runId: generated };
}

export function createLocalSshReleaseEnvironment({
  candidateDir,
  containerEngine = "docker",
  hubOwnerUrl,
  hubPublicUrl,
  ownerPassword,
  ownershipToken,
  sshExecute,
  docker = createDockerHubController({ containerEngine }),
}: LocalSshReleaseEnvironmentOptions) {
  return createReleaseEnvironment({
    candidateDir,
    docker,
    execute: sshExecute,
    hubOwnerUrl,
    hubPublicUrl,
    ownerPassword,
    ownershipToken,
  });
}

export function createReleaseEnvironment({
  bootstrapProvisioner,
  candidateDir,
  canonicalReportTransportFactory = createCanonicalReportEvidenceTransport,
  docker = createDockerHubController(),
  execute,
  hubOwnerUrl,
  hubPublicUrl,
  infrastructure,
  matrixCell,
  ownerPassword,
  onCleanupManaged = () => {},
  ownershipToken,
  releaseInfrastructure = async () => ({ clean: true }),
}: ReleaseEnvironmentOptions) {
  if (typeof execute !== "function") {
    throw new Error("Release E2E environment requires a Host connection");
  }
  if (typeof onCleanupManaged !== "function") {
    throw new Error(
      "Release E2E cleanup ownership callback must be a function",
    );
  }
  let dockerResources: HubResources | null = null;
  let canonicalReports: CanonicalReportTransport | null = null;
  return {
    async start({
      candidateManifest,
      hubMode = "candidate",
      runId,
      scenario = matrixCell?.scenarioId,
    }: {
      candidateManifest: ReleaseE2ECandidateManifest;
      hubMode?: string;
      runId: string;
      scenario?: string;
    }) {
      onCleanupManaged();
      dockerResources = await docker.start({
        candidateDir,
        candidateManifest,
        hubMode,
        hubOwnerUrl,
        hubPublicUrl,
        ownerPassword,
        probeOperationRunningTimeoutSeconds:
          scenario === "post-replacement-repair-uninstall" ? 15 : null,
        runId,
        useHubStateSnapshot: scenario === "hub-restore-compatibility-window",
      });
      canonicalReports = canonicalReportTransportFactory({
        listenUrl: hubPublicUrl,
        upstreamUrl: hubOwnerUrl,
      });
      const transport = await canonicalReports.start();
      if (transport.origin !== new URL(hubPublicUrl).origin) {
        throw new Error(
          "canonical report evidence transport did not bind the declared Probe origin",
        );
      }
      const lifecycle = createHubLifecycleClient({ baseUrl: hubOwnerUrl });
      const host = createProbeHostHarness({
        execute,
        ownershipToken,
        async prepareInstall({ enrollment, installContract }) {
          if (installContract.kind === "legacy-v0.1.74") {
            if (
              candidateManifest.releaseBaseline?.kind !==
                "enoki-trust-epoch-migration-baseline" ||
              candidateManifest.releaseBaseline?.tag !== "v0.1.74" ||
              dockerResources?.activeHub !== "baseline"
            ) {
              throw new Error(
                "Legacy Probe installer is allowed only from the verified v0.1.74 Trust Epoch migration baseline Hub",
              );
            }
            return null;
          }
          if (!bootstrapProvisioner) {
            throw new Error(
              "Release E2E infrastructure cannot stage the active Hub Probe Bootstrap recipe",
            );
          }
          const exported = await docker.exportActiveBootstrapRecipe({
            candidateManifest,
            recipeRecord: enrollment.bootstrapRecipe,
            resources: dockerResources,
            runId,
          });
          const staged = await bootstrapProvisioner({
            recipe: exported.recipe,
            runId,
            sourcePath: exported.sourcePath,
          });
          return { ...staged, evidence: exported.provenance };
        },
      });
      const releaseTestHost = matrixCell
        ? await host.assertReleaseTestHost(matrixCell)
        : null;
      return {
        bootstrap: null,
        canonicalReports,
        docker: dockerResources,
        host,
        hub: {
          ...lifecycle,
          async captureBaselineStateSnapshot(input: {
            baselineImageDigest: string;
            baselineVersion: string;
          }) {
            return docker.captureBaselineStateSnapshot({
              ...input,
              resources: dockerResources,
              runId,
            });
          },
          async restoreBaselineStateSnapshot(input: {
            baselineImageDigest: string;
            baselineVersion: string;
            expectedManifestDigest: string;
            recoveryTime: string;
          }) {
            const result = await docker.restoreBaselineStateSnapshot({
              ...input,
              resources: dockerResources,
              runId,
            });
            return result;
          },
          async switchToCandidate() {
            dockerResources = await docker.switchToCandidate({
              resources: dockerResources,
              runId,
            });
            return { activeHub: dockerResources.activeHub };
          },
          async collectEvidence() {
            const [api, runtime] = await Promise.all([
              lifecycle.collectEvidence(),
              docker.collectEvidence({ resources: dockerResources }),
            ]);
            return { ...api, runtime };
          },
        },
        infrastructure: infrastructure ?? null,
        releaseTestHost,
      };
    },
    async cleanup({ resources, runId }: { resources: unknown; runId: string }) {
      const cleanup: ReleaseEnvironmentCleanupReport = {};
      const errors: unknown[] = [];
      if (canonicalReports) {
        try {
          cleanup.transport = await canonicalReports.close();
        } catch (error) {
          errors.push(error);
          cleanup.transport = {
            clean: false,
            error: objectView(error).message,
          };
        }
      }
      canonicalReports = null;
      try {
        cleanup.hub = await docker.cleanup({
          resources: dockerResources,
          runId,
        });
      } catch (error) {
        errors.push(error);
        cleanup.hub = { clean: false, error: objectView(error).message };
      }
      dockerResources = null;
      try {
        cleanup.infrastructure = await releaseInfrastructure({
          prepared: resources,
          runId,
        });
      } catch (error) {
        errors.push(error);
        cleanup.infrastructure = {
          clean: false,
          error: objectView(error).message,
        };
      }
      if (errors.length > 0) {
        throw new AggregateError(
          errors,
          "Release E2E environment cleanup failed",
        );
      }
      return { clean: true, ...cleanup };
    },
  };
}

export function createDockerHubController({
  containerEngine = "docker",
  exec = execFileWithResult,
  fetch: fetch_ = globalThis.fetch,
  sleep = (milliseconds: number) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)),
}: {
  containerEngine?: string;
  exec?: DockerExecutor;
  fetch?: typeof globalThis.fetch;
  sleep?: SleepFunction;
} = {}) {
  if (containerEngine !== "docker") {
    throw new Error("Only the docker container engine is supported");
  }
  let currentResources: HubResources | null = null;
  let currentRuntimeEnvironment: HubRuntimeEnvironment | null = null;
  return {
    async start({
      candidateDir,
      candidateManifest,
      hubMode = "candidate",
      hubOwnerUrl,
      hubPublicUrl,
      ownerPassword,
      probeOperationRunningTimeoutSeconds = null,
      runId,
      useHubStateSnapshot = false,
    }: {
      candidateDir: string;
      candidateManifest: ReleaseE2ECandidateManifest;
      hubMode?: string;
      hubOwnerUrl: string;
      hubPublicUrl: string;
      ownerPassword: string;
      probeOperationRunningTimeoutSeconds?: number | null;
      runId: string;
      useHubStateSnapshot?: boolean;
    }) {
      assertCandidateHubOwnerUrl(hubOwnerUrl);
      if (
        !ownerPassword ||
        ownerPassword.includes("\r") ||
        ownerPassword.includes("\n") ||
        ownerPassword.includes("\u0000")
      ) {
        throw new Error(
          "Owner password cannot be represented in a Docker env file",
        );
      }
      if (hubMode !== "candidate" && hubMode !== "baseline") {
        throw new Error("Hub mode must be candidate or baseline");
      }
      const candidate = await resolveHubRuntime({
        archivePath: path.join(candidateDir, candidateManifest.hub.archive),
        expectedManifestDigest: candidateManifest.hub.digest,
        name: "candidate",
        tag:
          hubMode === "candidate"
            ? `enoki-release-e2e:${runId}`
            : `enoki-release-e2e-candidate:${runId}`,
      });
      let baseline: HubRuntime | null = null;
      if (hubMode === "baseline") {
        const descriptor = candidateManifest.releaseBaseline;
        if (
          !new Set([
            "enoki-release-baseline",
            "enoki-trust-epoch-migration-baseline",
          ]).has(descriptor?.kind) ||
          typeof descriptor.hub?.archive !== "string" ||
          !descriptor.hub.archive ||
          !/^sha256:[0-9a-f]{64}$/.test(descriptor.hub.imageDigest ?? "")
        ) {
          throw new Error(
            "Candidate Manifest has no runnable Release Baseline descriptor",
          );
        }
        baseline = await resolveHubRuntime({
          archivePath: path.join(
            candidateDir,
            "release-baseline",
            descriptor.hub.archive,
          ),
          expectedManifestDigest: descriptor.hub.imageDigest,
          name: "baseline",
          tag: `enoki-release-e2e-baseline:${runId}`,
        });
      }
      const container = `enoki-e2e-hub-${runId}`;
      const volume = `enoki-e2e-data-${runId}`;
      const snapshotContainer = `enoki-e2e-hub-state-${runId}`;
      const snapshotVolume = `enoki-e2e-snapshot-${runId}`;
      const label = `enoki.release-e2e.run=${runId}`;
      await assertDockerObjectAbsent(
        exec,
        containerEngine,
        "container",
        container,
      );
      await assertDockerObjectAbsent(exec, containerEngine, "volume", volume);
      if (useHubStateSnapshot) {
        await assertDockerObjectAbsent(
          exec,
          containerEngine,
          "container",
          snapshotContainer,
        );
        await assertDockerObjectAbsent(
          exec,
          containerEngine,
          "volume",
          snapshotVolume,
        );
      }
      for (const runtime of [candidate, baseline].filter(
        (entry) => entry !== null,
      )) {
        await assertDockerObjectAbsent(
          exec,
          containerEngine,
          "image",
          runtime.tag,
        );
      }
      const ownerUrl = new URL(hubOwnerUrl);
      const ownerPort =
        ownerUrl.port || (ownerUrl.protocol === "https:" ? "443" : "80");
      const operationSigningSecret = `${randomUUID()}${randomUUID()}`;
      currentRuntimeEnvironment = {
        hubOwnerUrl,
        hubPublicUrl,
        operationSigningSecret,
        ownerPassword,
        ownerPort,
        probeOperationRunningTimeoutSeconds,
        useHubStateSnapshot,
      };
      // baseline 仅在 hubMode === "baseline" 分支内被赋值（否则已抛出），
      // 因此 ?? candidate 与原来的 hubMode === "baseline" ? baseline : candidate 等价。
      const active = baseline ?? candidate;
      currentResources = {
        activeHub: active.name,
        baseline,
        candidate,
        configDigest: active.configDigest,
        container,
        containerCreated: false,
        exportedRecipeDirs: [],
        identityVerified: false,
        manifestDigest: active.manifestDigest,
        redactionSecrets: [ownerPassword, operationSigningSecret],
        runId,
        runtimeHistory: [],
        snapshot: null,
        snapshotContainer,
        snapshotContainerMayExist: false,
        snapshotOperations: [],
        snapshotVolume,
        snapshotVolumeCreated: false,
        tag: active.tag,
        tagCreated: false,
        volume,
        volumeCreated: false,
      };
      await loadHubRuntime(currentResources, active);
      await successfulExec(exec, containerEngine, [
        "volume",
        "create",
        "--label",
        label,
        volume,
      ]);
      currentResources.volumeCreated = true;
      if (useHubStateSnapshot) {
        await successfulExec(exec, containerEngine, [
          "volume",
          "create",
          "--label",
          label,
          snapshotVolume,
        ]);
        currentResources.snapshotVolumeCreated = true;
      }
      await runHubRuntime(currentResources, active);
      return currentResources;
    },

    async exportActiveBootstrapRecipe({
      candidateManifest,
      recipeRecord,
      resources,
      runId,
    }: {
      candidateManifest: ReleaseE2ECandidateManifest;
      recipeRecord?: unknown;
      resources?: HubResources | null;
      runId: string;
    }) {
      const owned = resources ?? currentResources;
      const record = objectView(recipeRecord);
      const recipe = objectView(record.recipe);
      const recipeFile = recipe.file;
      const recipeSha256 = recipe.sha256;
      const recipeSize = recipe.size;
      const recipeVersion = recipe.version;
      if (
        !owned ||
        owned !== currentResources ||
        owned.runId !== runId ||
        !owned.containerCreated ||
        !owned.identityVerified
      ) {
        throw new Error(
          "Active verified Hub runtime is required to export its Probe Bootstrap recipe",
        );
      }
      // typeof 判据是后面字面量/正则/整数判据的逻辑子集，加入后接受集合不变。
      if (
        typeof recipeFile !== "string" ||
        recipeFile !== "enoki-probe-bootstrap.py" ||
        typeof recipeSha256 !== "string" ||
        !/^[0-9a-f]{64}$/.test(recipeSha256) ||
        !isPositiveSafeInteger(recipeSize) ||
        typeof recipeVersion !== "string" ||
        recipeVersion !== "v1"
      ) {
        throw new Error("Active Hub Enrollment recipe descriptor is invalid");
      }
      const exportDir = await mkdtemp(
        path.join(tmpdir(), "enoki-release-e2e-active-recipe."),
      );
      const sourcePath = path.join(exportDir, recipeFile);
      let provenance: RecipeProvenance;
      try {
        await successfulExec(exec, containerEngine, [
          "cp",
          `${owned.container}:/app/probe-bootstrap-publication/${recipeFile}`,
          sourcePath,
        ]);
        const bytes = await readFile(sourcePath);
        if (bytes.length !== recipeSize || sha256(bytes) !== recipeSha256) {
          throw new Error(
            "Active Hub Probe Bootstrap recipe does not match its verified Enrollment record",
          );
        }
        provenance = verifyActiveHubBootstrapRecipeProvenance({
          activeHub: owned.activeHub,
          activeManifestDigest: owned.manifestDigest,
          candidateManifest,
          enrollmentRecipe: recipeRecord,
          recipeBytes: bytes,
        });
      } catch (error) {
        await rm(exportDir, { force: true, recursive: true });
        throw error;
      }
      owned.exportedRecipeDirs.push(exportDir);
      return {
        provenance,
        recipe: {
          file: recipeFile,
          sha256: recipeSha256,
          size: recipeSize,
          version: recipeVersion,
        },
        sourcePath,
      };
    },

    async captureBaselineStateSnapshot({
      baselineImageDigest,
      baselineVersion,
      resources,
      runId,
    }: {
      baselineImageDigest: string;
      baselineVersion: string;
      resources?: HubResources | null;
      runId: string;
    }) {
      const owned = requireHubStateSnapshotResources({
        activeHub: "baseline",
        baselineImageDigest,
        resources,
        runId,
      });
      if (!owned.containerCreated || !owned.identityVerified) {
        throw new Error(
          "Release Baseline Hub must be running before Hub State Snapshot",
        );
      }
      await stopOwnedHub(owned, runId);
      await ensureHubRuntimeLoaded(owned.candidate);
      const result = await invokeHubStateSnapshotTool(owned, {
        arguments_: [
          "snapshot",
          "--snapshot",
          "/snapshot/baseline",
          "--baseline-version",
          baselineVersion,
          "--baseline-image-digest",
          baselineImageDigest,
          "--confirm-hub-stopped",
        ],
        operation: "snapshot",
      });
      // 以下读取全部走 objectView/isUnknownArray，与原来 manifest?.X?.some(...)
      // 的 undefined 短路等价；manifest 由本行动消费的 enoki-hub-state 工具产出。
      const manifest = objectView(result.manifest);
      const releaseBaseline = objectView(manifest.releaseBaseline);
      if (
        releaseBaseline.hubImageDigest !== baselineImageDigest ||
        releaseBaseline.version !== baselineVersion
      ) {
        throw new Error(
          "Hub State Snapshot manifest does not match the pinned Release Baseline",
        );
      }
      const archiveIncluded =
        recordList(manifest.logicalRoots).some(
          (root) => root.id === "metrics-archive",
        ) ||
        recordList(manifest.directories).some(
          (directory) =>
            directory.logicalRoot === "data-root" &&
            (directory.path === "metrics-archive" ||
              stringValue(directory.path).startsWith("metrics-archive/")),
        );
      const files = recordList(manifest.files);
      const snapshot = {
        baselineImageDigest,
        baselineVersion,
        hotDataFileCount: files.length,
        hotDataFiles: files.map(
          (file) => `${String(file.logicalRoot)}/${String(file.path)}`,
        ),
        manifestDigest: result.manifestDigest,
        recoveryTime: stringValue(manifest.recoveryTime),
        roots: [
          { id: "data-root", included: true, path: "/data" },
          {
            id: "metrics-archive",
            included: archiveIncluded === true,
            path: "/data/metrics-archive",
          },
        ],
        tool: "enoki-hub-state",
        version: "v1",
      };
      owned.snapshot = snapshot;
      return snapshot;
    },

    async switchToCandidate({
      resources,
      runId,
    }: {
      resources?: HubResources | null;
      runId: string;
    }): Promise<HubResources> {
      const owned = resources ?? currentResources;
      const stoppedAfterSnapshot =
        owned?.snapshot &&
        !owned.containerCreated &&
        !owned.identityVerified &&
        owned.activeHub === "baseline";
      if (
        !owned ||
        owned !== currentResources ||
        owned.runId !== runId ||
        owned.activeHub !== "baseline" ||
        !owned.baseline ||
        !owned.candidate ||
        (!stoppedAfterSnapshot &&
          (!owned.containerCreated || !owned.identityVerified))
      ) {
        throw new Error(
          "Release Baseline Hub is not running and cannot switch to the Candidate",
        );
      }
      if (
        !(await verifyDockerRunLabel(
          exec,
          containerEngine,
          "volume",
          owned.volume,
          runId,
        ))
      ) {
        throw new Error("Release Baseline Hub persistent volume is absent");
      }
      if (!stoppedAfterSnapshot) {
        await stopOwnedHub(owned, runId);
      }
      await loadHubRuntime(owned, owned.candidate);
      await runHubRuntime(owned, owned.candidate);
      return owned;
    },

    async restoreBaselineStateSnapshot({
      baselineImageDigest,
      baselineVersion,
      expectedManifestDigest,
      recoveryTime,
      resources,
      runId,
    }: {
      baselineImageDigest: string;
      baselineVersion: string;
      expectedManifestDigest: string;
      recoveryTime: string;
      resources?: HubResources | null;
      runId: string;
    }) {
      const owned = requireHubStateSnapshotResources({
        activeHub: "candidate",
        baselineImageDigest,
        resources,
        runId,
      });
      if (
        !owned.snapshot ||
        owned.snapshot.manifestDigest !== expectedManifestDigest ||
        owned.snapshot.recoveryTime !== recoveryTime ||
        owned.snapshot.baselineImageDigest !== baselineImageDigest ||
        owned.snapshot.baselineVersion !== baselineVersion
      ) {
        throw new Error(
          "Hub Restore input does not match the captured Hub State Snapshot",
        );
      }
      if (!owned.containerCreated || !owned.identityVerified) {
        throw new Error("Candidate Hub must be running before Hub Restore");
      }
      await stopOwnedHub(owned, runId);
      const verify = await invokeHubStateSnapshotTool(owned, {
        arguments_: [
          "verify",
          "--snapshot",
          "/snapshot/baseline",
          "--baseline-version",
          baselineVersion,
          "--baseline-image-digest",
          baselineImageDigest,
          "--confirm-hub-stopped",
          "--expected-manifest-digest",
          snapshotManifestDigestForCli(expectedManifestDigest),
        ],
        operation: "verify",
      });
      if (verify.manifestDigest !== expectedManifestDigest) {
        throw new Error(
          "Hub State Snapshot verify returned a different manifest digest",
        );
      }
      const restore = await invokeHubStateSnapshotTool(owned, {
        arguments_: [
          "restore",
          "--snapshot",
          "/snapshot/baseline",
          "--baseline-version",
          baselineVersion,
          "--baseline-image-digest",
          baselineImageDigest,
          "--confirm-hub-stopped",
          "--expected-manifest-digest",
          snapshotManifestDigestForCli(expectedManifestDigest),
          "--confirm-data-loss-after",
          recoveryTime,
        ],
        operation: "restore",
      });
      if (restore.manifestDigest !== expectedManifestDigest) {
        throw new Error(
          "Hub State Snapshot restore returned a different manifest digest",
        );
      }
      await loadHubRuntime(owned, owned.baseline);
      await runHubRuntime(owned, owned.baseline);
      if (owned.manifestDigest !== baselineImageDigest) {
        throw new Error(
          "Restored Hub does not run the exact Release Baseline image digest",
        );
      }
      return {
        image: {
          activeManifestDigest: owned.manifestDigest,
          expectedManifestDigest: baselineImageDigest,
        },
        restore: {
          manifestDigest: restore.manifestDigest,
          status: "succeeded",
        },
        verify: {
          manifestDigest: verify.manifestDigest,
          status: "succeeded",
        },
      };
    },

    async collectEvidence({
      resources,
    }: {
      resources?: HubResources | null;
    } = {}) {
      const owned = resources ?? currentResources;
      if (!owned?.containerCreated || !owned.identityVerified) {
        throw new Error("Hub runtime identity is not available");
      }
      const [containerInspectResult, imageInspectResult, logs] =
        await Promise.all([
          successfulExec(exec, containerEngine, [
            "container",
            "inspect",
            owned.container,
          ]),
          successfulExec(exec, containerEngine, [
            "image",
            "inspect",
            owned.tag,
          ]),
          successfulExec(exec, containerEngine, [
            "logs",
            "--timestamps",
            "--tail",
            "500",
            owned.container,
          ]),
        ]);
      const containerInspect = parseDockerInspectObject(
        containerInspectResult.stdout,
        "Docker container inspect",
      );
      const imageInspect = parseDockerInspectObject(
        imageInspectResult.stdout,
        "Docker image inspect",
      );
      return {
        activeHub: owned.activeHub ?? "candidate",
        activeManifestDigest: owned.manifestDigest,
        baselineManifestDigest: owned.baseline?.manifestDigest ?? null,
        candidateManifestDigest:
          owned.candidate?.manifestDigest ?? owned.manifestDigest,
        containerConfigDigest: owned.configDigest,
        // objectView(X).Y 与原来 X?.Y 的读取结果一致：缺失或非对象都得到 undefined。
        containerInspect: redactText(
          JSON.stringify({
            Id: containerInspect.Id,
            Image: containerInspect.Image,
            ImageName: objectView(containerInspect.Config).Image,
            Labels: objectView(containerInspect.Config).Labels,
            Mounts: containerInspect.Mounts,
            Ports: objectView(containerInspect.NetworkSettings).Ports,
            State: containerInspect.State,
          }),
          owned.redactionSecrets,
        ),
        imageInspect: redactText(
          JSON.stringify({
            Id: imageInspect.Id,
            RepoDigests: imageInspect.RepoDigests,
          }),
          owned.redactionSecrets,
        ),
        identityVerified: true,
        logs: redactText(
          `${logs.stdout}${logs.stderr}`,
          owned.redactionSecrets,
        ),
        runtimeHistory: [...(owned.runtimeHistory ?? [])],
        snapshotOperations: [...(owned.snapshotOperations ?? [])],
      };
    },

    async cleanup({
      resources,
      runId,
    }: {
      resources?: HubResources | null;
      runId: string;
    }) {
      const owned = resources ?? currentResources;
      if (!owned) return { clean: true, skipped: "hub_not_started" };
      const errors: unknown[] = [];
      for (const exportDir of owned.exportedRecipeDirs ?? []) {
        try {
          await rm(exportDir, { force: true, recursive: true });
        } catch (error) {
          errors.push(error);
        }
      }
      owned.exportedRecipeDirs = [];
      await cleanDockerObject({
        createdProperty: "containerCreated",
        name: owned.container,
        owned,
        removeArguments: ["rm", "--force", owned.container],
        type: "container",
        verifyOwnership: () =>
          verifyDockerRunLabel(
            exec,
            containerEngine,
            "container",
            owned.container,
            runId,
          ),
      });
      if (owned.snapshotContainerMayExist) {
        await cleanDockerObject({
          createdProperty: "snapshotContainerMayExist",
          name: owned.snapshotContainer,
          owned,
          removeArguments: ["rm", "--force", owned.snapshotContainer],
          type: "container",
          verifyOwnership: () =>
            verifyDockerRunLabel(
              exec,
              containerEngine,
              "container",
              owned.snapshotContainer,
              runId,
            ),
        });
      }
      await cleanDockerObject({
        createdProperty: "volumeCreated",
        name: owned.volume,
        owned,
        removeArguments: ["volume", "rm", owned.volume],
        type: "volume",
        verifyOwnership: () =>
          verifyDockerRunLabel(
            exec,
            containerEngine,
            "volume",
            owned.volume,
            runId,
          ),
      });
      await cleanDockerObject({
        createdProperty: "snapshotVolumeCreated",
        name: owned.snapshotVolume,
        owned,
        removeArguments: ["volume", "rm", owned.snapshotVolume],
        type: "volume",
        verifyOwnership: () =>
          verifyDockerRunLabel(
            exec,
            containerEngine,
            "volume",
            owned.snapshotVolume,
            runId,
          ),
      });
      const runtimes = owned.candidate
        ? [owned.candidate, owned.baseline].filter(
            (runtime) => runtime !== null,
          )
        : [
            {
              configDigest: owned.configDigest,
              tag: owned.tag,
              tagCreated: owned.tagCreated,
            },
          ];
      for (const runtime of runtimes) {
        await cleanDockerObject({
          createdProperty: "tagCreated",
          name: runtime.tag,
          owned: runtime,
          removeArguments: ["image", "rm", runtime.tag],
          type: "image",
          verifyOwnership: () =>
            verifyDockerImageIdentity(
              exec,
              containerEngine,
              runtime.tag,
              runtime.configDigest,
            ),
        });
      }
      if (owned.candidate) {
        owned.tagCreated = runtimes.some((runtime) => runtime.tagCreated);
      }
      if (
        currentResources === owned &&
        !owned.containerCreated &&
        !owned.volumeCreated &&
        !owned.snapshotContainerMayExist &&
        !owned.snapshotVolumeCreated &&
        !owned.tagCreated
      ) {
        currentResources = null;
        currentRuntimeEnvironment = null;
      }
      if (errors.length > 0) {
        throw new AggregateError(
          errors,
          `Candidate Hub cleanup failed:\n${errors
            .map((error) => `- ${String(errorMessage(error))}`)
            .join("\n")}`,
        );
      }
      return { clean: true };

      async function cleanDockerObject({
        createdProperty,
        name,
        owned: resources_,
        removeArguments,
        type,
        verifyOwnership,
      }: {
        createdProperty: DockerCreatedFlag;
        name: string;
        owned: DockerObjectOwner;
        removeArguments: string[];
        type: DockerObjectType;
        verifyOwnership: () => Promise<boolean>;
      }) {
        if (!resources_[createdProperty]) return;
        let isOwned = false;
        try {
          isOwned = await verifyOwnership();
        } catch (error) {
          errors.push(error);
        }
        if (isOwned) {
          try {
            await successfulExec(exec, containerEngine, removeArguments);
          } catch (error) {
            errors.push(error);
          }
        }
        try {
          await assertDockerObjectAbsent(exec, containerEngine, type, name);
          resources_[createdProperty] = false;
        } catch (error) {
          errors.push(error);
        }
      }
    },
  };

  function requireHubStateSnapshotResources({
    activeHub,
    baselineImageDigest,
    resources,
    runId,
  }: {
    activeHub: string;
    baselineImageDigest: string;
    resources?: HubResources | null;
    runId: string;
  }): HubResourcesWithBaseline {
    const owned = resources ?? currentResources;
    if (
      !owned ||
      owned !== currentResources ||
      owned.runId !== runId ||
      owned.activeHub !== activeHub ||
      !hasPinnedBaseline(owned) ||
      !owned.candidate ||
      !owned.snapshotVolumeCreated ||
      owned.baseline.manifestDigest !== baselineImageDigest
    ) {
      throw new Error(
        `Hub State ${activeHub === "baseline" ? "Snapshot" : "Restore"} does not match the active release resources`,
      );
    }
    return owned;
  }

  async function stopOwnedHub(
    owned: HubResources,
    runId: string,
  ): Promise<void> {
    if (
      !(await verifyDockerRunLabel(
        exec,
        containerEngine,
        "container",
        owned.container,
        runId,
      ))
    ) {
      throw new Error(`Running ${owned.activeHub} Hub container is absent`);
    }
    await successfulExec(exec, containerEngine, [
      "stop",
      "--time",
      "30",
      owned.container,
    ]);
    await successfulExec(exec, containerEngine, ["rm", owned.container]);
    owned.containerCreated = false;
    owned.identityVerified = false;
  }

  async function invokeHubStateSnapshotTool(
    owned: HubResources,
    {
      arguments_,
      operation,
    }: {
      arguments_: string[];
      operation: string;
    },
  ): Promise<HubStateSnapshotToolResult> {
    owned.snapshotContainerMayExist = true;
    try {
      const result = await successfulExec(exec, containerEngine, [
        "run",
        "--rm",
        "--name",
        owned.snapshotContainer,
        "--label",
        `enoki.release-e2e.run=${owned.runId}`,
        "--user",
        "0:0",
        "--entrypoint",
        "/usr/local/bin/enoki-hub-state",
        "--env",
        "ENOKI_DATA_ROOT=/data",
        "--env",
        "ENOKI_SQLITE_PATH=/data/enoki.db",
        "--env",
        "ENOKI_METRICS_ARCHIVE_DIR=/data/metrics-archive",
        "--mount",
        `type=volume,source=${owned.volume},target=/data`,
        "--mount",
        `type=volume,source=${owned.snapshotVolume},target=/snapshot`,
        owned.candidate.tag,
        "v1",
        ...arguments_,
      ]);
      owned.snapshotContainerMayExist = false;
      const parsed = objectView(
        parseCommandJson(result.stdout, `Hub State Snapshot ${operation}`),
      );
      const manifestDigest = canonicalSnapshotManifestDigest(
        parsed.manifestDigest,
      );
      if (
        parsed.operation !== operation ||
        parsed.version !== "v1" ||
        manifestDigest === null
      ) {
        throw new Error(
          `Hub State Snapshot ${operation} returned invalid evidence`,
        );
      }
      owned.snapshotOperations.push({
        manifestDigest,
        operation,
        status: "succeeded",
      });
      return { ...parsed, manifestDigest };
    } catch (error) {
      owned.snapshotOperations.push({
        error: errorMessage(error),
        operation,
        status: "failed",
      });
      throw error;
    }
  }

  async function resolveHubRuntime({
    archivePath,
    expectedManifestDigest,
    name,
    tag,
  }: {
    archivePath: string;
    expectedManifestDigest: string;
    name: string;
    tag: string;
  }): Promise<HubRuntime> {
    const { configDigest, manifestDigest } = await readOciImageIdentities(
      archivePath,
      exec,
    );
    if (manifestDigest !== expectedManifestDigest) {
      throw new Error(
        `${name === "candidate" ? "Candidate" : "Release Baseline"} Hub OCI manifest digest ${manifestDigest} does not match Candidate Manifest ${expectedManifestDigest}`,
      );
    }
    return {
      archivePath,
      configDigest,
      manifestDigest,
      name,
      tag,
      tagCreated: false,
    };
  }

  async function loadHubRuntime(
    owned: HubResources,
    runtime: HubRuntime,
  ): Promise<void> {
    await ensureHubRuntimeLoaded(runtime);
    owned.activeHub = runtime.name;
    owned.configDigest = runtime.configDigest;
    owned.manifestDigest = runtime.manifestDigest;
    owned.tag = runtime.tag;
    owned.tagCreated = true;
  }

  async function ensureHubRuntimeLoaded(runtime: HubRuntime): Promise<void> {
    if (runtime.tagCreated) return;
    const conversionDir = await mkdtemp(
      path.join(tmpdir(), "enoki-release-e2e-docker-archive-"),
    );
    const dockerArchivePath = path.join(conversionDir, "hub.docker.tar");
    try {
      await successfulExec(exec, "skopeo", [
        "copy",
        `oci-archive:${path.resolve(runtime.archivePath)}`,
        `docker-archive:${dockerArchivePath}:${runtime.tag}`,
      ]);
      await successfulExec(exec, containerEngine, [
        "load",
        "--input",
        dockerArchivePath,
      ]);
      runtime.tagCreated = true;
    } finally {
      await rm(conversionDir, { force: true, recursive: true });
    }
  }

  async function runHubRuntime(
    owned: HubResources,
    runtime: HubRuntime,
  ): Promise<void> {
    if (!currentRuntimeEnvironment) {
      throw new Error("Hub runtime environment is unavailable");
    }
    const envDir = await mkdtemp(path.join(tmpdir(), "enoki-release-e2e-"));
    const envFile = path.join(envDir, "hub.env");
    await writeFile(
      envFile,
      [
        `OWNER_PASSWORD=${currentRuntimeEnvironment.ownerPassword}`,
        `ENOKI_MANAGEMENT_ORIGIN=${currentRuntimeEnvironment.hubPublicUrl}`,
        `ENOKI_PROBE_API_ORIGIN=${currentRuntimeEnvironment.hubPublicUrl}`,
        `ENOKI_PROBE_OPERATION_TOKEN_SIGNING_SECRET=${currentRuntimeEnvironment.operationSigningSecret}`,
        ...(currentRuntimeEnvironment.probeOperationRunningTimeoutSeconds ===
        null
          ? []
          : [
              `ENOKI_PROBE_OPERATION_RUNNING_TIMEOUT_SECONDS=${currentRuntimeEnvironment.probeOperationRunningTimeoutSeconds}`,
            ]),
        `ENOKI_METRICS_ARCHIVE_ENABLED=${currentRuntimeEnvironment.useHubStateSnapshot ? "true" : "false"}`,
        ...(currentRuntimeEnvironment.useHubStateSnapshot
          ? ["ENOKI_METRICS_ARCHIVE_DIR=/data/metrics-archive"]
          : []),
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    await chmod(envFile, 0o600);
    try {
      await successfulExec(exec, containerEngine, [
        "run",
        "--detach",
        "--name",
        owned.container,
        "--label",
        `enoki.release-e2e.run=${owned.runId}`,
        "--env-file",
        envFile,
        "--publish",
        `${currentRuntimeEnvironment.ownerPort}:3000`,
        "--mount",
        `type=volume,source=${owned.volume},target=/data`,
        runtime.tag,
      ]);
      owned.containerCreated = true;
      const [loadedImage, containerImage] = await Promise.all([
        successfulExec(exec, containerEngine, [
          "image",
          "inspect",
          "--format",
          "{{.Id}}",
          runtime.tag,
        ]),
        successfulExec(exec, containerEngine, [
          "container",
          "inspect",
          "--format",
          "{{.Image}}",
          owned.container,
        ]),
      ]);
      if (
        loadedImage.stdout.trim() !== runtime.configDigest ||
        containerImage.stdout.trim() !== runtime.configDigest
      ) {
        throw new Error(
          `Running ${runtime.name} Hub image identity does not match its verified OCI config digest`,
        );
      }
      owned.activeHub = runtime.name;
      owned.configDigest = runtime.configDigest;
      owned.manifestDigest = runtime.manifestDigest;
      owned.tag = runtime.tag;
      owned.identityVerified = true;
      await waitForHubHealth(currentRuntimeEnvironment.hubOwnerUrl, {
        fetch: fetch_,
        sleep,
      });
      owned.runtimeHistory.push({
        configDigest: runtime.configDigest,
        hub: runtime.name,
        manifestDigest: runtime.manifestDigest,
        volume: owned.volume,
      });
    } finally {
      await rm(envDir, { force: true, recursive: true });
    }
  }
}

function validateSshOptions(values: ReleaseE2EOptionValues): void {
  if (!/^(?!-)[A-Za-z0-9._%+@:[\]-]+$/.test(values["--ssh-host"] ?? "")) {
    throw new Error("--ssh-host is invalid");
  }
  const port = Number(values["--ssh-port"]);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error("--ssh-port must be an integer between 1 and 65535");
  }
}

function assertCandidateHubOwnerUrl(value: string): void {
  const url = new URL(value);
  const loopbackHosts = new Set(["127.0.0.1", "[::1]", "localhost"]);
  if (
    url.protocol !== "http:" ||
    !loopbackHosts.has(url.hostname) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      "--hub-owner-url must be a loopback HTTP origin owned by the candidate Hub",
    );
  }
}

async function writeJsonAtomically(
  destination: string,
  value: unknown,
): Promise<void> {
  const temporary = `${destination}.tmp-${randomUUID()}`;
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    await link(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
}

async function replaceJsonAtomically(
  destination: string,
  value: unknown,
): Promise<void> {
  const temporary = `${destination}.tmp-${randomUUID()}`;
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
}

function serializeRunError(
  error: unknown,
  secrets: readonly string[],
): SerializedRunError {
  const message = error instanceof Error ? error.message : String(error);
  const code = objectView(error).code;
  return {
    code: typeof code === "string" ? code : "release_e2e_failed",
    message: redactText(message, secrets),
    name: error instanceof Error ? error.name : "Error",
  };
}

function runSpawnedProcess(
  command: string,
  arguments_: readonly string[],
  { input, timeoutMs }: ProcessRunOptions,
): Promise<CommandResult> {
  return new Promise<CommandResult>((resolve, reject) => {
    const usesProcessGroup = process.platform !== "win32";
    const child = spawn(command, arguments_, {
      detached: usesProcessGroup,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    const maximumOutputBytes = 16 * 1024 * 1024;
    let timedOut = false;
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    const signalProcessTree = (signal: NodeJS.Signals): void => {
      try {
        const pid = child.pid;
        if (usesProcessGroup && isSafeInteger(pid)) {
          process.kill(-pid, signal);
        } else {
          child.kill(signal);
        }
      } catch (error) {
        if (objectView(error).code !== "ESRCH") throw error;
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      signalProcessTree("SIGTERM");
      killTimer = setTimeout(() => signalProcessTree("SIGKILL"), 250);
      killTimer.unref?.();
    }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes <= maximumOutputBytes) stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes <= maximumOutputBytes) stderr.push(chunk);
    });
    child.once("error", (error: Error) => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      reject(error);
    });
    child.once(
      "close",
      (code: number | null, signal: NodeJS.Signals | null) => {
        clearTimeout(timer);
        clearTimeout(killTimer);
        const result: CommandResult = {
          code: code ?? 1,
          stderr: Buffer.concat(stderr).toString("utf8"),
          stdout: Buffer.concat(stdout).toString("utf8"),
        };
        if (signal) {
          result.stderr += `\nprocess terminated by ${signal}`;
        }
        if (timedOut) {
          result.code = 1;
          result.stderr += `\nprocess timed out after ${timeoutMs}ms`;
        }
        if (outputBytes > maximumOutputBytes) {
          result.code = 1;
          result.stderr += "\nprocess output exceeded 16 MiB";
        }
        resolve(result);
      },
    );
    child.stdin.end(input);
  });
}

async function execFileWithResult(
  command: string,
  arguments_: readonly string[],
): Promise<DockerCommandResult> {
  try {
    const result = await execFileAsync(command, arguments_, {
      maxBuffer: 64 * 1024 * 1024,
    });
    return { code: 0, stderr: result.stderr, stdout: result.stdout };
  } catch (error) {
    const failure = objectView(error);
    const code = failure.code;
    const stderr = failure.stderr;
    const message = failure.message;
    const stdout = failure.stdout;
    return {
      code: typeof code === "number" || typeof code === "string" ? code : 1,
      stderr:
        typeof stderr === "string"
          ? stderr
          : typeof message === "string"
            ? message
            : "",
      stdout: typeof stdout === "string" ? stdout : "",
    };
  }
}

async function successfulExec(
  exec: DockerExecutor,
  command: string,
  arguments_: readonly string[],
): Promise<DockerCommandResult> {
  const result = await exec(command, arguments_);
  if (result.code !== 0) {
    throw new Error(
      `${command} ${arguments_[0]} failed (${result.code}): ${result.stderr}`,
    );
  }
  return result;
}

async function readOciImageIdentities(
  archivePath: string,
  exec: DockerExecutor,
): Promise<{ configDigest: string; manifestDigest: string }> {
  const indexResult = await successfulExec(exec, "tar", [
    "--extract",
    "--to-stdout",
    "--file",
    archivePath,
    "index.json",
  ]);
  const index: unknown = JSON.parse(indexResult.stdout);
  const manifests = objectView(index).manifests;
  const manifestDigest = objectView(
    isUnknownArray(manifests) ? manifests[0] : undefined,
  ).digest;
  if (!/^sha256:[0-9a-f]{64}$/.test(regexInput(manifestDigest))) {
    throw new Error("Candidate Hub OCI index has no image manifest digest");
  }
  const manifestResult = await successfulExec(exec, "tar", [
    "--extract",
    "--to-stdout",
    "--file",
    archivePath,
    `blobs/sha256/${regexInput(manifestDigest).slice("sha256:".length)}`,
  ]);
  const manifest: unknown = JSON.parse(manifestResult.stdout);
  const configDigest = objectView(manifest).config;
  if (
    !/^sha256:[0-9a-f]{64}$/.test(regexInput(objectView(configDigest).digest))
  ) {
    throw new Error("Candidate Hub OCI manifest has no config digest");
  }
  return {
    configDigest: regexInput(objectView(configDigest).digest),
    manifestDigest: regexInput(manifestDigest),
  };
}

function parseCommandJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`${label} did not return JSON`, { cause: error });
  }
}

function canonicalSnapshotManifestDigest(value: unknown): string | null {
  if (/^[0-9a-f]{64}$/.test(regexInput(value)))
    return `sha256:${regexInput(value)}`;
  if (/^sha256:[0-9a-f]{64}$/.test(regexInput(value))) return regexInput(value);
  return null;
}

function snapshotManifestDigestForCli(value: unknown): string {
  const canonical = canonicalSnapshotManifestDigest(value);
  if (canonical === null) {
    throw new Error("Hub State Snapshot manifest digest is invalid");
  }
  return canonical.slice("sha256:".length);
}

function parseDockerInspectObject(value: string, label: string): UnknownRecord {
  const parsed = parseCommandJson(value, label);
  if (
    !isUnknownArray(parsed) ||
    parsed.length !== 1 ||
    !isUnknownRecord(parsed[0])
  ) {
    throw new Error(`${label} did not return exactly one object`);
  }
  return parsed[0];
}

// 与原来 manifest?.logicalRoots?.some(...) / Array.isArray(manifest?.files) 的
// 读取判据一致：非数组值一律得到空列表，条目通过 objectView 读取字段。
function recordList(value: unknown): readonly UnknownRecord[] {
  return isUnknownArray(value) ? value.map(objectView) : [];
}

// 该谓词就是 requireHubStateSnapshotResources 原有的 !owned.baseline 判据项，
// 把它编码为类型谓词后，restore 读取 baseline 不需要新增运行时检查。
function hasPinnedBaseline(
  owned: HubResources,
): owned is HubResourcesWithBaseline {
  return Boolean(owned.baseline);
}

// 原实现直接读取 error.message；对非 Error 抛出值同样是 undefined，这里保持该读取。
function errorMessage(error: unknown): unknown {
  return objectView(error).message;
}

function redactText(value: unknown, secrets: readonly string[] = []): string {
  let redacted = String(value ?? "");
  for (const secret of secrets) {
    if (secret) redacted = redacted.replaceAll(secret, "[REDACTED]");
  }
  return redacted
    .replace(/enk_enroll_[A-Za-z0-9_-]+/g, "[REDACTED_ENROLLMENT_TOKEN]")
    .replace(/(authorization["'=:\s]+)(?:Bearer\s+)?[^\s"']+/gi, "$1[REDACTED]")
    .replace(/(cookie["'=:\s]+)[^\n"']+/gi, "$1[REDACTED]");
}

async function waitForHubHealth(
  baseUrl: string,
  {
    fetch: fetch_,
    sleep,
  }: { fetch: typeof globalThis.fetch; sleep: SleepFunction },
): Promise<void> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch_(new URL("/api/health", baseUrl));
      if (response.ok) {
        const body: unknown = await response.json();
        if (
          objectView(body).service === "enoki-hub" &&
          objectView(body).status === "ok"
        )
          return;
      }
      lastError = new Error(`health returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    if (attempt < 59) await sleep(1_000);
  }
  throw new Error(
    `Candidate Hub did not become healthy: ${objectView(lastError).message}`,
  );
}

async function verifyDockerRunLabel(
  exec: DockerExecutor,
  engine: string,
  type: DockerObjectType,
  name: string,
  runId: string,
): Promise<boolean> {
  const arguments_ =
    type === "container"
      ? [
          "inspect",
          "--format",
          '{{ index .Config.Labels "enoki.release-e2e.run" }}',
          name,
        ]
      : [
          "volume",
          "inspect",
          "--format",
          '{{ index .Labels "enoki.release-e2e.run" }}',
          name,
        ];
  const result = await exec(engine, arguments_);
  if (result.code !== 0) {
    if (/no such|not found/i.test(result.stderr)) return false;
    throw new Error(
      `Could not prove Docker ${type} ${name} ownership: ${result.stderr}`,
    );
  }
  if (result.stdout.trim() !== runId) {
    throw new Error(`Refusing to remove ${type} ${name}: run label mismatch`);
  }
  return true;
}

async function verifyDockerImageIdentity(
  exec: DockerExecutor,
  engine: string,
  name: string,
  expectedConfigDigest: string,
): Promise<boolean> {
  const result = await exec(engine, [
    "image",
    "inspect",
    "--format",
    "{{.Id}}",
    name,
  ]);
  if (result.code !== 0) {
    if (/no such|not found/i.test(result.stderr)) return false;
    throw new Error(
      `Could not prove Docker image ${name} ownership: ${result.stderr}`,
    );
  }
  if (result.stdout.trim() !== expectedConfigDigest) {
    throw new Error(
      `Refusing to remove image ${name}: image identity mismatch`,
    );
  }
  return true;
}

async function assertDockerObjectAbsent(
  exec: DockerExecutor,
  engine: string,
  type: DockerObjectType,
  name: string,
): Promise<void> {
  const arguments_ =
    type === "container"
      ? ["container", "inspect", name]
      : type === "volume"
        ? ["volume", "inspect", name]
        : ["image", "inspect", name];
  const result = await exec(engine, arguments_);
  if (result.code === 0) {
    throw new Error(`Refusing to reuse pre-existing Docker ${type} ${name}`);
  }
  if (!/no such|not found/i.test(result.stderr)) {
    throw new Error(
      `Could not prove Docker ${type} ${name} is absent: ${result.stderr}`,
    );
  }
}
