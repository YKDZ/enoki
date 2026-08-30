import { execFile, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
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
  releaseTransitionForValidatedCandidate,
  validateReleaseCandidate,
} from "./release-candidate-lib.mjs";
import { createCanonicalReportEvidenceTransport } from "./release-canonical-report-evidence.mjs";
import {
  createHubLifecycleClient,
  createProbeHostHarness,
  releaseE2EScenarioRegistry,
} from "./release-e2e-lib.mjs";

const execFileAsync = promisify(execFile);

const runOptions = Object.freeze({
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

const verifyCleanOptions = Object.freeze({
  "--host-adapter": { default: "ssh" },
  "--run-manifest": { required: true },
  "--ssh-host": {},
  "--ssh-key": {},
  "--ssh-port": { default: "22" },
});

export function parseReleaseE2ECommandLine(arguments_) {
  const [command, ...tokens] = arguments_;
  const definitions =
    command === "run"
      ? runOptions
      : command === "verify-clean"
        ? verifyCleanOptions
        : null;
  if (!definitions) {
    throw new Error("command must be run or verify-clean");
  }
  if (tokens.length % 2 !== 0) {
    throw new Error(`option ${tokens.at(-1)} requires a value`);
  }
  const values = {};
  for (let index = 0; index < tokens.length; index += 2) {
    const name = tokens[index];
    const value = tokens[index + 1];
    if (!Object.hasOwn(definitions, name)) {
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
    if (
      path.basename(values["--candidate-manifest"]) !==
      "candidate-manifest.json"
    ) {
      throw new Error("--candidate-manifest must name candidate-manifest.json");
    }
    if (path.basename(values["--matrix"]) !== "release-e2e-matrix.json") {
      throw new Error("--matrix must name release-e2e-matrix.json");
    }
    if (
      !/^[a-z0-9][a-z0-9._-]*--[a-z][a-z0-9-]*$/.test(values["--matrix-cell"])
    ) {
      throw new Error("--matrix-cell must be a stable declared cell ID");
    }
    if (values["--container-engine"] !== "docker") {
      throw new Error("--container-engine must be docker");
    }
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(values["--owner-password-env"])) {
      throw new Error(
        "--owner-password-env must be an environment variable name",
      );
    }
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(values["--root-public-key-env"])) {
      throw new Error(
        "--root-public-key-env must name an environment variable",
      );
    }
    for (const option of ["--hub-owner-url", "--hub-public-url"]) {
      const url = new URL(values[option]);
      if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new Error(`${option} must use HTTP or HTTPS`);
      }
      if (url.username || url.password) {
        throw new Error(`${option} must not contain credentials`);
      }
    }
    if (new URL(values["--hub-owner-url"]).protocol !== "http:") {
      throw new Error("--hub-owner-url must use direct HTTP for local Docker");
    }
    assertCandidateHubOwnerUrl(values["--hub-owner-url"]);
  }
  return { command, values };
}

export async function loadValidatedCandidate(
  candidateManifestPath,
  { trustedRootPublicKeyPem } = {},
) {
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
}) {
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
}) {
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
} = {}) {
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
}) {
  let preparedRunId = null;
  let bootstrapProvisioner = null;
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
        matrixCell,
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
  matrixCell,
  transferFile,
}) {
  const recipe = selectCandidateBootstrapRecipe(manifest);
  const recipePath = path.join(candidateDir, "recipe", recipe.file);
  let provisioned = false;
  let provisionedRunId = null;
  let binaryOwnership = null;
  let stageDir = null;
  const provision = async ({
    installContract,
    ownershipToken,
    recipe: requestedRecipe,
    runId,
    sourcePath,
  } = {}) => {
    if (installContract?.kind === "production-bootstrap") {
      if (stageDir) {
        const removed = await execute(
          removeCandidateBootstrapStagingScript(stageDir),
          { sensitive: true },
        );
        if (removed.code !== 0 || removed.stdout.trim() !== "removed") {
          throw new Error(
            `Could not replace staged Candidate Bootstrap assets: ${removed.stderr}`,
          );
        }
        stageDir = null;
        provisioned = false;
        provisionedRunId = null;
      }
      if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(runId ?? "")) {
        throw new Error("Release E2E infrastructure run ID is invalid");
      }
      if (!/^[0-9a-f-]{36}$/.test(ownershipToken ?? "")) {
        throw new Error(
          "Release E2E infrastructure ownership token is invalid",
        );
      }
      const extracted = await extractCandidateBootstrapBinaries({
        candidateDir,
        manifest,
        matrixCell,
      });
      binaryOwnership = {
        assets: extracted.assets.map(({ sourcePath: _, ...asset }) => asset),
        ownershipToken,
        runId,
      };
      try {
        const staged = await execute(stageCandidateBootstrapBinariesScript(), {
          sensitive: true,
        });
        if (
          staged.code !== 0 ||
          !/^\/tmp\/enoki-release-e2e-bootstrap\.[A-Za-z0-9]+$/.test(
            staged.stdout.trim(),
          )
        ) {
          throw new Error(
            `Could not stage Candidate Probe Bootstrap binaries as the non-root Host user: ${staged.stderr}`,
          );
        }
        stageDir = staged.stdout.trim();
        provisionedRunId = runId;
        for (const asset of extracted.assets) {
          await transferFile({
            destination: path.join(stageDir, path.basename(asset.path)),
            source: asset.sourcePath,
          });
        }
        const installed = await execute(
          installCandidateBootstrapBinariesScript({
            archiveSha256: extracted.archiveSha256,
            assets: extracted.assets,
            ownershipToken,
            runId,
            stageDir,
          }),
          { root: true, sensitive: true },
        );
        const publication = installed.stdout.trim();
        if (
          installed.code !== 0 ||
          (publication !== "installed" && publication !== "reused")
        ) {
          throw new Error(
            `Could not install verified Candidate Probe Bootstrap binaries: ${installed.stderr}`,
          );
        }
        stageDir = null;
        provisionedRunId = null;
        const reused = publication === "reused";
        if (reused) binaryOwnership = null;
        return {
          complete: reused
            ? async () => {}
            : async () => {
                const completed = await execute(
                  completeCandidateBootstrapBinaryProvisionScript(
                    binaryOwnership,
                  ),
                  { root: true, sensitive: true },
                );
                if (
                  completed.code !== 0 ||
                  completed.stdout.trim() !== "completed"
                ) {
                  throw new Error(
                    `Could not complete Candidate Bootstrap run ownership: ${completed.stderr}`,
                  );
                }
                binaryOwnership = null;
              },
          evidence: {
            archiveSha256: extracted.archiveSha256,
            assets: extracted.assets.map(
              ({ sourcePath: _, ...asset }) => asset,
            ),
            kind: "enoki-release-e2e-candidate-bootstrap-binaries",
            reused,
            schemaVersion: 1,
          },
          workingDirectory: null,
        };
      } catch (error) {
        const provisionCleanup = await execute(
          cleanupCandidateBootstrapBinaryProvisionScript({
            assets: extracted.assets,
            ownershipToken,
            runId,
          }),
          { root: true, sensitive: true },
        ).catch((cleanupError) => ({
          code: -1,
          stderr: cleanupError.message,
          stdout: "",
        }));
        if (
          provisionCleanup.code !== 0 ||
          provisionCleanup.stdout.trim() !== "removed"
        ) {
          error.provisionCleanupError = new Error(
            `Could not recover failed Candidate Bootstrap binary publication: ${provisionCleanup.stderr}`,
          );
        } else {
          binaryOwnership = null;
        }
        if (stageDir) {
          const cleanup = await execute(
            removeCandidateBootstrapStagingScript(stageDir),
            { sensitive: true },
          ).catch((cleanupError) => ({
            code: -1,
            stderr: cleanupError.message,
            stdout: "",
          }));
          if (cleanup.code === 0 && cleanup.stdout.trim() === "removed") {
            stageDir = null;
            provisionedRunId = null;
          } else {
            error.cleanupError = new Error(
              `Could not clean failed Candidate Bootstrap staging: ${cleanup.stderr}`,
            );
          }
        }
        throw error;
      } finally {
        await extracted.cleanup();
      }
    }
    const selectedRecipe = requestedRecipe ?? recipe;
    const selectedPath = sourcePath ?? recipePath;
    if (provisioned) {
      const removed = await execute(
        removeCandidateBootstrapStagingScript(stageDir),
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
        removeCandidateBootstrapStagingScript(stageDir),
        { sensitive: true },
      ).catch((cleanupError) => ({
        code: -1,
        stderr: cleanupError.message,
        stdout: "",
      }));
      if (cleanup.code === 0 && cleanup.stdout.trim() === "removed") {
        stageDir = null;
      } else {
        error.cleanupError = new Error(
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
  };
  provision.cleanupOwnedProvision = async ({ ownershipToken, runId }) => {
    if (!binaryOwnership) return { clean: true, skipped: "binary_not_owned" };
    if (
      binaryOwnership.runId !== runId ||
      binaryOwnership.ownershipToken !== ownershipToken
    ) {
      throw new Error("Candidate Bootstrap binary ownership does not match");
    }
    const removed = await execute(
      cleanupCandidateBootstrapBinaryProvisionScript(binaryOwnership),
      { root: true, sensitive: true },
    );
    if (removed.code !== 0 || removed.stdout.trim() !== "removed") {
      throw new Error(
        `Could not remove run-owned Candidate Bootstrap binaries: ${removed.stderr}`,
      );
    }
    binaryOwnership = null;
    return { clean: true };
  };
  return {
    provision,
    async cleanup({ runId }) {
      if (binaryOwnership) {
        if (runId !== binaryOwnership.runId) {
          throw new Error("Candidate Bootstrap binary run ID does not match");
        }
        await provision.cleanupOwnedProvision({
          ownershipToken: binaryOwnership.ownershipToken,
          runId,
        });
      }
      if (!stageDir) return { clean: true, skipped: "recipe_not_staged" };
      if (runId !== provisionedRunId) {
        throw new Error(
          "Candidate Probe Bootstrap recipe run ID does not match",
        );
      }
      const removed = await execute(
        removeCandidateBootstrapStagingScript(stageDir),
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

function selectCandidateBootstrapRecipe(manifest) {
  const recipe = manifest?.bootstrapRecipe;
  if (
    recipe?.file !== "enoki-probe-bootstrap.py" ||
    recipe?.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(recipe?.sha256 ?? "") ||
    !Number.isSafeInteger(recipe?.size) ||
    recipe.size <= 0
  ) {
    throw new Error("Validated Candidate has no exact Probe Bootstrap recipe");
  }
  return recipe;
}

function stageCandidateBootstrapRecipeScript() {
  return `# enoki-release-e2e:candidate-bootstrap-recipe-stage\nset -eu\n[ "$(id -u)" != 0 ]\nstage_dir=$(mktemp -d /tmp/enoki-release-e2e-recipe.XXXXXX)\nchmod 0700 "$stage_dir"\nprintf '%s\\n' "$stage_dir"\n`;
}

function stageCandidateBootstrapBinariesScript() {
  return `# enoki-release-e2e:candidate-bootstrap-binary-stage\nset -eu\n[ "$(id -u)" != 0 ]\nstage_dir=$(mktemp -d /tmp/enoki-release-e2e-bootstrap.XXXXXX)\nchmod 0700 "$stage_dir"\nprintf '%s\\n' "$stage_dir"\n`;
}

function installCandidateBootstrapBinariesScript({
  archiveSha256,
  assets,
  ownershipToken,
  runId,
  stageDir,
}) {
  const byRole = Object.fromEntries(assets.map((asset) => [asset.role, asset]));
  const acquirer = byRole["bootstrap-acquirer"];
  const activator = byRole["bootstrap-activator"];
  const intent = candidateBootstrapProvisionIntent(assets);
  return `# enoki-release-e2e:candidate-bootstrap-binary-install\nset -eu\narchive_sha256=${shellSingleQuote(archiveSha256)}\nstage_dir=${shellSingleQuote(stageDir)}\nclaim=/var/lib/enoki-release-e2e/claim\nintent="$claim/bootstrap-provision-intent"\n[ -d "$claim" ]\n[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]\n[ "$(cat "$claim/token")" = ${shellSingleQuote(ownershipToken)} ]\n[ -d "$stage_dir" ] && [ ! -L "$stage_dir" ] && [ "$(stat -c %a "$stage_dir")" = 700 ]\nexpected_intent=$(mktemp "$claim/.bootstrap-provision-intent.XXXXXX")\nprintf %s ${shellSingleQuote(intent)} > "$expected_intent"\ntrap 'rm -f -- "$expected_intent"' EXIT HUP INT TERM\nif [ -e "$intent" ]; then\n  [ -f "$intent" ] && [ ! -L "$intent" ] && [ "$(stat -c %u "$intent")" = 0 ] && [ "$(stat -c %g "$intent")" = 0 ] && [ "$(stat -c %a "$intent")" = 600 ] && [ "$(stat -c %h "$intent")" = 1 ]\n  cmp --silent "$expected_intent" "$intent"\n  # enoki-release-e2e:validate-partial-bootstrap-targets\n${candidateBootstrapInstalledOrAbsentChecks(assets)}\nelse\n  if [ -e /usr/local/bin/enoki-probe-bootstrap-acquire ] || [ -L /usr/local/bin/enoki-probe-bootstrap-acquire ] || [ -e /usr/local/bin/enoki-probe-bootstrap-activate ] || [ -L /usr/local/bin/enoki-probe-bootstrap-activate ]; then\n    [ -e /usr/local/bin/enoki-probe-bootstrap-acquire ]\n    [ -e /usr/local/bin/enoki-probe-bootstrap-activate ]\n    resources="$claim/resources"\n    [ -f "$resources" ] && [ ! -L "$resources" ] && [ "$(stat -c %u "$resources")" = 0 ] && [ "$(stat -c %g "$resources")" = 0 ] && [ "$(stat -c %a "$resources")" = 600 ] && [ "$(stat -c %h "$resources")" = 1 ]\n${candidateBootstrapInstalledFileChecks(assets)}\n${candidateBootstrapRunResourceChecks(assets)}\n    rm -f -- "$stage_dir/enoki-probe-bootstrap-acquire" "$stage_dir/enoki-probe-bootstrap-activate" "$expected_intent"\n    rmdir -- "$stage_dir"\n    trap - EXIT HUP INT TERM\n    printf 'reused\\n'\n    exit 0\n  fi\n  install --owner=root --group=root --mode=0600 -- "$expected_intent" "$intent"\nfi\nsource_acquirer="$stage_dir/enoki-probe-bootstrap-acquire"\nsource_activator="$stage_dir/enoki-probe-bootstrap-activate"\n[ -f "$source_acquirer" ] && [ ! -L "$source_acquirer" ] && [ "$(wc -c < "$source_acquirer" | tr -d ' ')" = ${shellSingleQuote(String(acquirer.size))} ]\nprintf '%s  %s\\n' ${shellSingleQuote(acquirer.sha256)} "$source_acquirer" | sha256sum --check --status\n[ -f "$source_activator" ] && [ ! -L "$source_activator" ] && [ "$(wc -c < "$source_activator" | tr -d ' ')" = ${shellSingleQuote(String(activator.size))} ]\nprintf '%s  %s\\n' ${shellSingleQuote(activator.sha256)} "$source_activator" | sha256sum --check --status\ntemporary_dir=$(mktemp -d /usr/local/bin/.enoki-release-e2e-bootstrap.XXXXXX)\ntrap 'rm -f -- "$expected_intent" "$temporary_dir/acquirer" "$temporary_dir/activator"; rmdir -- "$temporary_dir" 2>/dev/null || true' EXIT HUP INT TERM\ntemporary_acquirer="$temporary_dir/acquirer"\ntemporary_activator="$temporary_dir/activator"\ninstall --owner=root --group=root --mode=0555 -- "$source_acquirer" "$temporary_acquirer"\ninstall --owner=root --group=root --mode=0555 -- "$source_activator" "$temporary_activator"\nprintf '%s  %s\\n' ${shellSingleQuote(acquirer.sha256)} "$temporary_acquirer" | sha256sum --check --status\nprintf '%s  %s\\n' ${shellSingleQuote(activator.sha256)} "$temporary_activator" | sha256sum --check --status\nmv -- "$temporary_acquirer" /usr/local/bin/enoki-probe-bootstrap-acquire\nmv -- "$temporary_activator" /usr/local/bin/enoki-probe-bootstrap-activate\n${candidateBootstrapInstalledFileChecks(assets)}\nrm -f -- "$source_acquirer" "$source_activator" "$expected_intent"\nrmdir -- "$stage_dir"\nrmdir -- "$temporary_dir"\ntrap - EXIT HUP INT TERM\nprintf 'installed\\n'\n`;
}

function candidateBootstrapProvisionIntent(assets) {
  return `schema_version=1\n${assets
    .map(
      (asset) =>
        `${asset.role}_sha256=${asset.sha256}\n${asset.role}_size=${asset.size}`,
    )
    .join("\n")}\n`;
}

function candidateBootstrapInstalledFileChecks(assets) {
  return assets
    .map((asset) => {
      const destination = `/usr/local/bin/${path.basename(asset.path)}`;
      return `[ -f ${shellSingleQuote(destination)} ] && [ ! -L ${shellSingleQuote(destination)} ]\n[ "$(stat -c %h ${shellSingleQuote(destination)})" = 1 ]\n[ "$(stat -c %u ${shellSingleQuote(destination)})" = 0 ]\n[ "$(stat -c %g ${shellSingleQuote(destination)})" = 0 ]\n[ "$(stat -c %a ${shellSingleQuote(destination)})" = 555 ]\n[ "$(wc -c < ${shellSingleQuote(destination)} | tr -d ' ')" = ${shellSingleQuote(String(asset.size))} ]\nprintf '%s  %s\\n' ${shellSingleQuote(asset.sha256)} ${shellSingleQuote(destination)} | sha256sum --check --status`;
    })
    .join("\n");
}

function candidateBootstrapRunResourceChecks(assets) {
  const checks = assets
    .map((asset) => {
      const destination = `/usr/local/bin/${path.basename(asset.path)}`;
      return `resource_owns_candidate ${shellSingleQuote(destination)} ${shellSingleQuote(asset.sha256)}`;
    })
    .join("\n");
  return `resource_owns_candidate() {\n  candidate=$1\n  expected_sha256=$2\n  metadata=$(stat -c '%u\\t%g\\t%a\\t%d\\t%i\\t%s' -- "$candidate")\n  path_hash=$(printf '%s' "$candidate" | sha256sum | awk '{print $1}')\n  expected=$(printf 'path\\t%s\\tfile\\t%s\\t%s' "$path_hash" "$metadata" "$expected_sha256")\n  grep -Fxq "$expected" "$resources"\n}\n${checks}`;
}

function candidateBootstrapInstalledOrAbsentChecks(assets) {
  return assets
    .map((asset) => {
      const destination = `/usr/local/bin/${path.basename(asset.path)}`;
      return `if [ -e ${shellSingleQuote(destination)} ] || [ -L ${shellSingleQuote(destination)} ]; then\n${candidateBootstrapInstalledFileChecks([asset])}\nfi`;
    })
    .join("\n");
}

function cleanupCandidateBootstrapBinaryProvisionScript({
  assets,
  ownershipToken,
  runId,
}) {
  const intent = candidateBootstrapProvisionIntent(assets);
  return `# enoki-release-e2e:candidate-bootstrap-binary-cleanup\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\nintent="$claim/bootstrap-provision-intent"\n[ -d "$claim" ]\n[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]\n[ "$(cat "$claim/token")" = ${shellSingleQuote(ownershipToken)} ]\nif [ ! -e "$intent" ]; then printf 'removed\\n'; exit 0; fi\nexpected_intent=$(mktemp "$claim/.bootstrap-provision-intent.XXXXXX")\nprintf %s ${shellSingleQuote(intent)} > "$expected_intent"\ntrap 'rm -f -- "$expected_intent"' EXIT HUP INT TERM\n[ -f "$intent" ] && [ ! -L "$intent" ] && [ "$(stat -c %u "$intent")" = 0 ] && [ "$(stat -c %g "$intent")" = 0 ] && [ "$(stat -c %a "$intent")" = 600 ] && [ "$(stat -c %h "$intent")" = 1 ]\ncmp --silent "$expected_intent" "$intent"\n${candidateBootstrapInstalledOrAbsentChecks(assets)}\nrm -f -- /usr/local/bin/enoki-probe-bootstrap-acquire /usr/local/bin/enoki-probe-bootstrap-activate "$intent" "$expected_intent"\ntrap - EXIT HUP INT TERM\nprintf 'removed\\n'\n`;
}

function completeCandidateBootstrapBinaryProvisionScript({
  assets,
  ownershipToken,
  runId,
}) {
  const intent = candidateBootstrapProvisionIntent(assets);
  return `# enoki-release-e2e:candidate-bootstrap-binary-complete\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\nintent="$claim/bootstrap-provision-intent"\n[ -d "$claim" ]\n[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]\n[ "$(cat "$claim/token")" = ${shellSingleQuote(ownershipToken)} ]\nexpected_intent=$(mktemp "$claim/.bootstrap-provision-intent.XXXXXX")\nprintf %s ${shellSingleQuote(intent)} > "$expected_intent"\ntrap 'rm -f -- "$expected_intent"' EXIT HUP INT TERM\n[ -f "$intent" ] && [ ! -L "$intent" ] && [ "$(stat -c %u "$intent")" = 0 ] && [ "$(stat -c %g "$intent")" = 0 ] && [ "$(stat -c %a "$intent")" = 600 ] && [ "$(stat -c %h "$intent")" = 1 ]\ncmp --silent "$expected_intent" "$intent"\n${candidateBootstrapInstalledFileChecks(assets)}\nrm -- "$intent" "$expected_intent"\ntrap - EXIT HUP INT TERM\nprintf 'completed\\n'\n`;
}

function verifyCandidateBootstrapRecipeScript({ recipe, stageDir }) {
  return `# enoki-release-e2e:candidate-bootstrap-recipe-verify\nset -eu\n[ "$(id -u)" != 0 ]\nstage_dir=${shellSingleQuote(stageDir)}\nrecipe="$stage_dir/${recipe.file}"\n[ -d "$stage_dir" ] && [ ! -L "$stage_dir" ] && [ "$(stat -c %a "$stage_dir")" = 700 ]\n[ -f "$recipe" ] && [ ! -L "$recipe" ]\n[ "$(wc -c < "$recipe" | tr -d ' ')" = ${shellSingleQuote(String(recipe.size))} ]\nprintf '%s  %s\\n' ${shellSingleQuote(recipe.sha256)} "$recipe" | sha256sum --check --status\nchmod 0500 "$recipe"\nprintf 'verified\\n'\n`;
}

function removeCandidateBootstrapStagingScript(stageDir) {
  return `# enoki-release-e2e:candidate-bootstrap-staging-remove\nset -eu\n[ "$(id -u)" != 0 ]\nstage_dir=${shellSingleQuote(stageDir)}\ncase "$stage_dir" in /tmp/enoki-release-e2e-recipe.*|/tmp/enoki-release-e2e-bootstrap.*) ;; *) exit 1 ;; esac\nif [ ! -e "$stage_dir" ] && [ ! -L "$stage_dir" ]; then printf 'removed\\n'; exit 0; fi\nrm -f -- "$stage_dir/enoki-probe-bootstrap.py" "$stage_dir/enoki-probe-bootstrap-acquire" "$stage_dir/enoki-probe-bootstrap-activate"\nrmdir -- "$stage_dir"\nprintf 'removed\\n'\n`;
}

async function extractCandidateBootstrapBinaries({
  candidateDir,
  manifest,
  matrixCell,
}) {
  if (
    matrixCell?.architecture !== "x86_64" ||
    matrixCell?.operatingSystem !== "ubuntu"
  ) {
    throw new Error("Candidate Bootstrap binary target is unsupported");
  }
  const archiveFile = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";
  const descriptor = manifest?.probeAssetSet?.files?.find(
    (file) => file.file === archiveFile,
  );
  if (
    !descriptor ||
    !/^[0-9a-f]{64}$/.test(descriptor.sha256 ?? "") ||
    !Number.isSafeInteger(descriptor.size) ||
    descriptor.size < 1
  ) {
    throw new Error("Validated Candidate has no exact Host Bootstrap bundle");
  }
  const archiveSource = path.join(
    candidateDir,
    manifest.probeAssetSet.directory,
    archiveFile,
  );
  const archive = await readFile(archiveSource);
  if (
    archive.byteLength !== descriptor.size ||
    sha256(archive) !== descriptor.sha256
  ) {
    throw new Error("Candidate Host Bootstrap bundle identity changed");
  }
  const extractionDir = await mkdtemp(
    path.join(tmpdir(), "enoki-release-e2e-bootstrap-bundle."),
  );
  const archiveSnapshot = path.join(extractionDir, archiveFile);
  await writeFile(archiveSnapshot, archive, { flag: "wx", mode: 0o600 });
  try {
    await execFileAsync("tar", [
      "--extract",
      "--gzip",
      "--file",
      archiveSnapshot,
      "--directory",
      extractionDir,
      "bundle-manifest.json",
      "bootstrap/enoki-probe-bootstrap-acquire",
      "bootstrap/enoki-probe-bootstrap-activate",
    ]);
    const bundleManifest = JSON.parse(
      await readFile(path.join(extractionDir, "bundle-manifest.json"), "utf8"),
    );
    if (
      bundleManifest?.kind !== "enoki-probe-bundle" ||
      bundleManifest?.version !== manifest.probeAssetSet.version ||
      !Array.isArray(bundleManifest.bootstrapAssets) ||
      bundleManifest.bootstrapAssets.length !== 2
    ) {
      throw new Error("Candidate Bootstrap bundle manifest is invalid");
    }
    const expected = [
      {
        path: "bootstrap/enoki-probe-bootstrap-acquire",
        permissionProfile: "bootstrap-acquirer-v1",
        role: "bootstrap-acquirer",
      },
      {
        path: "bootstrap/enoki-probe-bootstrap-activate",
        permissionProfile: "bootstrap-activator-v1",
        role: "bootstrap-activator",
      },
    ];
    const assets = [];
    for (const expectedAsset of expected) {
      const asset = bundleManifest?.bootstrapAssets?.find(
        (candidate) => candidate.path === expectedAsset.path,
      );
      if (
        asset?.role !== expectedAsset.role ||
        asset?.permissionProfile !== expectedAsset.permissionProfile ||
        asset?.version !== manifest.probeAssetSet.version ||
        !/^[0-9a-f]{64}$/.test(asset?.sha256 ?? "") ||
        !Number.isSafeInteger(asset?.size) ||
        asset.size < 1
      ) {
        throw new Error("Candidate Bootstrap bundle role identity is invalid");
      }
      const sourcePath = path.join(extractionDir, expectedAsset.path);
      const bytes = await readFile(sourcePath);
      if (bytes.byteLength !== asset.size || sha256(bytes) !== asset.sha256) {
        throw new Error("Candidate Bootstrap binary identity is invalid");
      }
      assets.push({
        path: expectedAsset.path,
        permissionProfile: expectedAsset.permissionProfile,
        role: expectedAsset.role,
        sha256: asset.sha256,
        size: asset.size,
        sourcePath,
        version: asset.version,
      });
    }
    return {
      archiveSha256: descriptor.sha256,
      assets,
      cleanup: () => rm(extractionDir, { force: true, recursive: true }),
    };
  } catch (error) {
    await rm(extractionDir, { force: true, recursive: true });
    throw error;
  }
}

async function copyCandidateArchive({ source, destination }) {
  await copyFile(source, destination);
  await chmod(destination, 0o600);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function verifyActiveHubBootstrapRecipeProvenance({
  activeHub,
  activeManifestDigest,
  candidateManifest,
  enrollmentRecipe,
  recipeBytes,
}) {
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
    !hasExactKeys(enrollmentRecipe.recipe, expectedRecipeKeys) ||
    enrollmentRecipe.bundleVersion !== expectedBundleVersion ||
    enrollmentRecipe.distribution !== "enoki" ||
    enrollmentRecipe.kind !== "enoki-probe-bootstrap-recipe-record" ||
    enrollmentRecipe.schemaVersion !== 1 ||
    enrollmentRecipe.recipe.file !== "enoki-probe-bootstrap.py" ||
    enrollmentRecipe.recipe.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(enrollmentRecipe.rootFingerprint ?? "") ||
    !/^[0-9a-f]{64}$/.test(enrollmentRecipe.recipe.sha256 ?? "") ||
    !Number.isSafeInteger(enrollmentRecipe.recipe.size) ||
    enrollmentRecipe.recipe.size < 1 ||
    !Array.isArray(enrollmentRecipe.targets) ||
    enrollmentRecipe.targets.length !== 4 ||
    !Buffer.isBuffer(recipeBytes) ||
    recipeBytes.byteLength !== enrollmentRecipe.recipe.size ||
    sha256(recipeBytes) !== enrollmentRecipe.recipe.sha256
  ) {
    throw new Error(
      "Active Hub Enrollment recipe record or exported bytes are invalid",
    );
  }

  const normalizedRecord = {
    bundleVersion: enrollmentRecipe.bundleVersion,
    distribution: enrollmentRecipe.distribution,
    kind: enrollmentRecipe.kind,
    recipe: {
      file: enrollmentRecipe.recipe.file,
      sha256: enrollmentRecipe.recipe.sha256,
      size: enrollmentRecipe.recipe.size,
      version: enrollmentRecipe.recipe.version,
    },
    rootFingerprint: enrollmentRecipe.rootFingerprint,
    schemaVersion: enrollmentRecipe.schemaVersion,
    targets: enrollmentRecipe.targets,
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

function hasExactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

function shellSingleQuote(value) {
  return `'${String(value).replaceAll("'", "'\\\"'\\\"'")}'`;
}

function createSshCandidateArchiveTransfer({
  host,
  keyPath,
  knownHostsPath,
  port,
  runProcess,
}) {
  validateSshOptions({ "--ssh-host": host, "--ssh-port": String(port) });
  return async ({ source, destination }) => {
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
}) {
  validateSshOptions({ "--ssh-host": host, "--ssh-port": String(port) });
  if (!knownHostsPath) throw new Error("SSH known-hosts path is required");
  return async (script, options = {}) => {
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

export function createFileEvidenceSink(evidenceDir, { runId } = {}) {
  const resolved = path.resolve(evidenceDir);
  return {
    async write(evidence) {
      await mkdir(resolved, { recursive: true });
      const destination = path.join(resolved, "evidence.json");
      if (runId === undefined) {
        await writeJsonAtomically(destination, evidence);
        return;
      }
      if (evidence?.runId !== runId) {
        throw new Error("Release E2E evidence run ID does not match");
      }
      const current = JSON.parse(await readFile(destination, "utf8"));
      if (current?.runId !== runId || current?.result?.status !== "running") {
        const error = new Error("Release E2E final evidence already exists");
        error.code = "EEXIST";
        throw error;
      }
      await replaceJsonAtomically(destination, {
        ...current,
        ...evidence,
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
}) {
  const resolved = path.resolve(evidenceDir);
  const createdAt = new Date().toISOString();
  let manifest = {
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
    async fail({ error, phase, secrets = [] }) {
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
      const evidence = JSON.parse(await readFile(evidencePath, "utf8"));
      if (evidence?.runId === runId && evidence?.result?.status === "running") {
        await replaceJsonAtomically(evidencePath, {
          ...evidence,
          diagnostics: { error: serialized },
          phase: "failed",
          result: { error: serialized, status: "failed" },
          scenario: manifest.scenario,
        });
      }
    },
    async update(patch) {
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
      const evidence = JSON.parse(await readFile(evidencePath, "utf8"));
      if (evidence?.runId === runId && evidence?.result?.status === "running") {
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

export async function writeRunManifest(evidenceDir, manifest) {
  await mkdir(evidenceDir, { recursive: true });
  await writeJsonAtomically(
    path.join(evidenceDir, "run-manifest.json"),
    manifest,
  );
}

export async function readRunManifest(manifestPath) {
  const value = JSON.parse(await readFile(manifestPath, "utf8"));
  if (
    value?.schemaVersion !== 3 ||
    !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(value.runId ?? "") ||
    !/^[0-9a-f-]{36}$/.test(value.ownershipToken ?? "") ||
    !value.inputs ||
    (value.inputs.hostAdapter !== "ssh" && value.inputs.hostAdapter !== "ci") ||
    typeof value.hostMutationPossible !== "boolean" ||
    !/^(?:initialized|plan-validated|candidate-prepare|candidate-prepared|scenario-running|succeeded|failed)$/.test(
      value.phase ?? "",
    ) ||
    (value.matrixCell !== null &&
      (value.matrixCell?.scenarioId !== value.scenario ||
        !Object.hasOwn(releaseE2EScenarioRegistry, value.scenario) ||
        value.inputs.matrixCellId !== value.matrixCell?.cellId ||
        (value.infrastructure &&
          value.matrixCell?.cellId !== value.infrastructure?.matrixCellId))) ||
    (value.hostMutationPossible &&
      (!value.matrixCell || !value.infrastructure)) ||
    (value.inputs.hostAdapter === "ssh" &&
      (!value.ssh ||
        value.ssh.host !== value.inputs.ssh?.host ||
        value.ssh.port !== value.inputs.ssh?.port ||
        value.ssh.keyPath !== value.inputs.ssh?.keyPath)) ||
    (value.inputs.hostAdapter === "ci" && value.ssh !== null)
  ) {
    throw new Error("Release E2E run manifest is invalid");
  }
  return value;
}

export function newRunIdentity(runId) {
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
}) {
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
}) {
  if (typeof execute !== "function") {
    throw new Error("Release E2E environment requires a Host connection");
  }
  if (typeof onCleanupManaged !== "function") {
    throw new Error(
      "Release E2E cleanup ownership callback must be a function",
    );
  }
  let dockerResources = null;
  let canonicalReports = null;
  return {
    async start({
      candidateManifest,
      hubMode = "candidate",
      runId,
      scenario = matrixCell?.scenarioId,
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
      const lifecycle = createHubLifecycleClient({
        baseUrl: hubOwnerUrl,
        replacementSourceProbeSha256: () => {
          const transition =
            releaseTransitionForValidatedCandidate(candidateManifest);
          return transition?.source?.probeComponents?.map(
            (component) => component.sha256,
          );
        },
      });
      const host = createProbeHostHarness({
        cleanupPreparedInstall: bootstrapProvisioner?.cleanupOwnedProvision,
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
          if (installContract.kind === "production-bootstrap") {
            if (dockerResources?.activeHub !== "candidate") {
              throw new Error(
                "Production Probe Bootstrap binaries require the verified Candidate Hub",
              );
            }
            return bootstrapProvisioner({
              installContract,
              ownershipToken,
              runId,
            });
          }
          const exported = await docker.exportActiveBootstrapRecipe({
            candidateManifest,
            recipeRecord: enrollment.bootstrapRecipe,
            resources: dockerResources,
            runId,
          });
          const staged = await bootstrapProvisioner({
            recipe: enrollment.bootstrapRecipe.recipe,
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
          async captureBaselineStateSnapshot(input) {
            return docker.captureBaselineStateSnapshot({
              ...input,
              resources: dockerResources,
              runId,
            });
          },
          async restoreBaselineStateSnapshot(input) {
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
    async cleanup({ resources, runId }) {
      const cleanup = {};
      const errors = [];
      if (canonicalReports) {
        try {
          cleanup.transport = await canonicalReports.close();
        } catch (error) {
          errors.push(error);
          cleanup.transport = { clean: false, error: error.message };
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
        cleanup.hub = { clean: false, error: error.message };
      }
      dockerResources = null;
      try {
        cleanup.infrastructure = await releaseInfrastructure({
          prepared: resources,
          runId,
        });
      } catch (error) {
        errors.push(error);
        cleanup.infrastructure = { clean: false, error: error.message };
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
  sleep = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)),
} = {}) {
  if (containerEngine !== "docker") {
    throw new Error("Only the docker container engine is supported");
  }
  let currentResources = null;
  let currentRuntimeEnvironment = null;
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
      let baseline = null;
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
      for (const runtime of [candidate, baseline].filter(Boolean)) {
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
      const active = hubMode === "baseline" ? baseline : candidate;
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
    }) {
      const owned = resources ?? currentResources;
      const recipe = recipeRecord?.recipe;
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
      if (
        recipe?.file !== "enoki-probe-bootstrap.py" ||
        !/^[0-9a-f]{64}$/.test(recipe?.sha256 ?? "") ||
        !Number.isSafeInteger(recipe?.size) ||
        recipe.size < 1 ||
        recipe.version !== "v1"
      ) {
        throw new Error("Active Hub Enrollment recipe descriptor is invalid");
      }
      const exportDir = await mkdtemp(
        path.join(tmpdir(), "enoki-release-e2e-active-recipe."),
      );
      const sourcePath = path.join(exportDir, recipe.file);
      let provenance;
      try {
        await successfulExec(exec, containerEngine, [
          "cp",
          `${owned.container}:/app/probe-bootstrap-publication/${recipe.file}`,
          sourcePath,
        ]);
        const bytes = await readFile(sourcePath);
        if (bytes.length !== recipe.size || sha256(bytes) !== recipe.sha256) {
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
        sourcePath,
      };
    },

    async captureBaselineStateSnapshot({
      baselineImageDigest,
      baselineVersion,
      resources,
      runId,
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
      const manifest = result.manifest;
      if (
        manifest?.releaseBaseline?.hubImageDigest !== baselineImageDigest ||
        manifest?.releaseBaseline?.version !== baselineVersion
      ) {
        throw new Error(
          "Hub State Snapshot manifest does not match the pinned Release Baseline",
        );
      }
      const archiveIncluded =
        manifest?.logicalRoots?.some(
          (root) => root?.id === "metrics-archive",
        ) ||
        manifest?.directories?.some(
          (directory) =>
            directory?.logicalRoot === "data-root" &&
            (directory.path === "metrics-archive" ||
              directory.path.startsWith("metrics-archive/")),
        );
      const snapshot = {
        baselineImageDigest,
        baselineVersion,
        hotDataFileCount: Array.isArray(manifest?.files)
          ? manifest.files.length
          : 0,
        hotDataFiles: Array.isArray(manifest?.files)
          ? manifest.files.map((file) => `${file.logicalRoot}/${file.path}`)
          : [],
        manifestDigest: result.manifestDigest,
        recoveryTime: manifest?.recoveryTime,
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

    async switchToCandidate({ resources, runId }) {
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

    async collectEvidence({ resources } = {}) {
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
        containerInspect: redactText(
          JSON.stringify({
            Id: containerInspect.Id,
            Image: containerInspect.Image,
            ImageName: containerInspect.Config?.Image,
            Labels: containerInspect.Config?.Labels,
            Mounts: containerInspect.Mounts,
            Ports: containerInspect.NetworkSettings?.Ports,
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

    async cleanup({ resources, runId }) {
      const owned = resources ?? currentResources;
      if (!owned) return { clean: true, skipped: "hub_not_started" };
      const errors = [];
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
        ? [owned.candidate, owned.baseline].filter(Boolean)
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
            .map((error) => `- ${error.message}`)
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
  }) {
    const owned = resources ?? currentResources;
    if (
      !owned ||
      owned !== currentResources ||
      owned.runId !== runId ||
      owned.activeHub !== activeHub ||
      !owned.baseline ||
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

  async function stopOwnedHub(owned, runId) {
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

  async function invokeHubStateSnapshotTool(owned, { arguments_, operation }) {
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
      const parsed = parseCommandJson(
        result.stdout,
        `Hub State Snapshot ${operation}`,
      );
      const manifestDigest = canonicalSnapshotManifestDigest(
        parsed?.manifestDigest,
      );
      if (
        parsed?.operation !== operation ||
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
        error: error.message,
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
  }) {
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

  async function loadHubRuntime(owned, runtime) {
    await ensureHubRuntimeLoaded(runtime);
    owned.activeHub = runtime.name;
    owned.configDigest = runtime.configDigest;
    owned.manifestDigest = runtime.manifestDigest;
    owned.tag = runtime.tag;
    owned.tagCreated = true;
  }

  async function ensureHubRuntimeLoaded(runtime) {
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

  async function runHubRuntime(owned, runtime) {
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

function validateSshOptions(values) {
  if (!/^(?!-)[A-Za-z0-9._%+@:[\]-]+$/.test(values["--ssh-host"] ?? "")) {
    throw new Error("--ssh-host is invalid");
  }
  const port = Number(values["--ssh-port"]);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error("--ssh-port must be an integer between 1 and 65535");
  }
}

function assertCandidateHubOwnerUrl(value) {
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

async function writeJsonAtomically(destination, value) {
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

async function replaceJsonAtomically(destination, value) {
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

function serializeRunError(error, secrets) {
  const message = error instanceof Error ? error.message : String(error);
  return {
    code: typeof error?.code === "string" ? error.code : "release_e2e_failed",
    message: redactText(message, secrets),
    name: error instanceof Error ? error.name : "Error",
  };
}

function runSpawnedProcess(command, arguments_, { input, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const usesProcessGroup = process.platform !== "win32";
    const child = spawn(command, arguments_, {
      detached: usesProcessGroup,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    const maximumOutputBytes = 16 * 1024 * 1024;
    let timedOut = false;
    let killTimer = null;
    const signalProcessTree = (signal) => {
      try {
        if (usesProcessGroup && Number.isSafeInteger(child.pid)) {
          process.kill(-child.pid, signal);
        } else {
          child.kill(signal);
        }
      } catch (error) {
        if (error?.code !== "ESRCH") throw error;
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      signalProcessTree("SIGTERM");
      killTimer = setTimeout(() => signalProcessTree("SIGKILL"), 250);
      killTimer.unref?.();
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes <= maximumOutputBytes) stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes <= maximumOutputBytes) stderr.push(chunk);
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      const result = {
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
    });
    child.stdin.end(input);
  });
}

async function execFileWithResult(command, arguments_) {
  try {
    const result = await execFileAsync(command, arguments_, {
      maxBuffer: 64 * 1024 * 1024,
    });
    return { code: 0, stderr: result.stderr, stdout: result.stdout };
  } catch (error) {
    return {
      code: error.code ?? 1,
      stderr: error.stderr ?? error.message,
      stdout: error.stdout ?? "",
    };
  }
}

async function successfulExec(exec, command, arguments_) {
  const result = await exec(command, arguments_);
  if (result.code !== 0) {
    throw new Error(
      `${command} ${arguments_[0]} failed (${result.code}): ${result.stderr}`,
    );
  }
  return result;
}

async function readOciImageIdentities(archivePath, exec) {
  const indexResult = await successfulExec(exec, "tar", [
    "--extract",
    "--to-stdout",
    "--file",
    archivePath,
    "index.json",
  ]);
  const index = JSON.parse(indexResult.stdout);
  const manifestDigest = index?.manifests?.[0]?.digest;
  if (!/^sha256:[0-9a-f]{64}$/.test(manifestDigest ?? "")) {
    throw new Error("Candidate Hub OCI index has no image manifest digest");
  }
  const manifestResult = await successfulExec(exec, "tar", [
    "--extract",
    "--to-stdout",
    "--file",
    archivePath,
    `blobs/sha256/${manifestDigest.slice("sha256:".length)}`,
  ]);
  const manifest = JSON.parse(manifestResult.stdout);
  const configDigest = manifest?.config?.digest;
  if (!/^sha256:[0-9a-f]{64}$/.test(configDigest ?? "")) {
    throw new Error("Candidate Hub OCI manifest has no config digest");
  }
  return { configDigest, manifestDigest };
}

function parseCommandJson(value, label) {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`${label} did not return JSON`, { cause: error });
  }
}

function canonicalSnapshotManifestDigest(value) {
  if (/^[0-9a-f]{64}$/.test(value ?? "")) return `sha256:${value}`;
  if (/^sha256:[0-9a-f]{64}$/.test(value ?? "")) return value;
  return null;
}

function snapshotManifestDigestForCli(value) {
  const canonical = canonicalSnapshotManifestDigest(value);
  if (canonical === null) {
    throw new Error("Hub State Snapshot manifest digest is invalid");
  }
  return canonical.slice("sha256:".length);
}

function parseDockerInspectObject(value, label) {
  const parsed = parseCommandJson(value, label);
  if (
    !Array.isArray(parsed) ||
    parsed.length !== 1 ||
    !parsed[0] ||
    typeof parsed[0] !== "object" ||
    Array.isArray(parsed[0])
  ) {
    throw new Error(`${label} did not return exactly one object`);
  }
  return parsed[0];
}

function redactText(value, secrets = []) {
  let redacted = String(value ?? "");
  for (const secret of secrets) {
    if (secret) redacted = redacted.replaceAll(secret, "[REDACTED]");
  }
  return redacted
    .replace(/enk_enroll_[A-Za-z0-9_-]+/g, "[REDACTED_ENROLLMENT_TOKEN]")
    .replace(/(authorization["'=:\s]+)(?:Bearer\s+)?[^\s"']+/gi, "$1[REDACTED]")
    .replace(/(cookie["'=:\s]+)[^\n"']+/gi, "$1[REDACTED]");
}

async function waitForHubHealth(baseUrl, { fetch: fetch_, sleep }) {
  let lastError = null;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch_(new URL("/api/health", baseUrl));
      if (response.ok) {
        const body = await response.json();
        if (body?.service === "enoki-hub" && body.status === "ok") return;
      }
      lastError = new Error(`health returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    if (attempt < 59) await sleep(1_000);
  }
  throw new Error(
    `Candidate Hub did not become healthy: ${lastError?.message}`,
  );
}

async function verifyDockerRunLabel(exec, engine, type, name, runId) {
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
  exec,
  engine,
  name,
  expectedConfigDigest,
) {
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

async function assertDockerObjectAbsent(exec, engine, type, name) {
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
