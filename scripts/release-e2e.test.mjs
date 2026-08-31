import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  chown,
  copyFile,
  lchown,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { renderInstallCommand } from "../apps/hub/src/enrollment/install-command.ts";
import { createReleaseCatalogSnapshot } from "./release-baseline-lib.mjs";
import { createReleaseCandidateManifest } from "./release-candidate-lib.mjs";
import {
  createCiHostExecutor,
  createCiReleaseInfrastructureAdapter,
  createDockerHubController,
  createFileEvidenceSink,
  createReleaseEnvironment,
  createSshReleaseInfrastructureAdapter,
  parseReleaseE2ECommandLine,
  writeRunManifest,
} from "./release-e2e-adapters.mjs";
import {
  createHubLifecycleClient,
  createProbeHostHarness,
  hasAdvancingPortableMetrics,
  isCandidateHostReady,
  redactReleaseE2EEvidence,
  renderReleaseE2EResourceFingerprint,
  releaseE2EScenarioRegistry,
  runReleaseE2EScenario,
  validateSuccessfulRepairBoundaryEvidence,
  validateSuccessfulProbeUpgradeTimeline,
} from "./release-e2e-lib.mjs";
import { createInstalledBundleFailureRepairHostDriver } from "./release-installed-bundle-failure-repair.mjs";
import { createMatrixGateResult } from "./release-verification-lib.mjs";

const execFileAsync = promisify(execFile);

async function createSystemdStateDirectoryFixture(prefix) {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  const publicParent = path.join(root, "var", "lib");
  const privateParent = path.join(publicParent, "private");
  const publicState = path.join(publicParent, "enoki-probe");
  const privateState = path.join(privateParent, "enoki-probe");
  const identity = path.join(privateState, "identity");
  const config = path.join(identity, "probe-bootstrap.toml");
  const resources = [
    {
      kind: "directory",
      path: publicState,
      systemdStateDirectoryProjection: true,
    },
  ];
  await mkdir(identity, { recursive: true });
  await chmod(publicParent, 0o755);
  await chmod(privateParent, 0o700);
  await chmod(privateState, 0o750);
  await chmod(identity, 0o700);
  await writeFile(config, "identity", "utf8");
  await chmod(config, 0o600);
  await symlink("private/enoki-probe", publicState);
  return {
    config,
    privateParent,
    privateState,
    publicParent,
    publicState,
    async fingerprint(environment = process.env) {
      const result = await execFileAsync(
        "sh",
        [
          "-c",
          `${renderReleaseE2EResourceFingerprint(resources)}\nfingerprint`,
        ],
        { env: environment },
      );
      return result.stdout;
    },
    async remove() {
      await rm(root, { force: true, recursive: true });
    },
  };
}

async function createLegacyReleaseRecordingFixture(prefix) {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  const fakeBin = path.join(root, "fake-bin");
  const publicParent = path.join(root, "var", "lib");
  const publicState = path.join(publicParent, "enoki-probe");
  const identity = path.join(publicState, "identity");
  const identityFile = path.join(identity, "probe-bootstrap.toml");
  const metadata = path.join(root, "etc", "enoki", "probe-install.toml");
  const binary = path.join(root, "usr", "local", "bin", "enoki-probe");
  const operationStatus = path.join(publicState, "probe-operation-status.toml");
  const unit = path.join(
    root,
    "etc",
    "systemd",
    "system",
    "enoki-probe.service",
  );
  const operationSudoers = path.join(
    root,
    "etc",
    "sudoers.d",
    "enoki-probe-operations",
  );
  const collectorSudoers = path.join(
    root,
    "etc",
    "sudoers.d",
    "enoki-probe-collector-helpers",
  );
  const environment = {
    ...process.env,
    ENOKI_ACCOUNTS_READY: path.join(root, "accounts-ready"),
    ENOKI_GETENT_GROUP_GID: "65534",
    ENOKI_GETENT_PASSWD_GID: "65534",
    ENOKI_GETENT_PASSWD_UID: "65534",
    ENOKI_ID_GID: "65534",
    ENOKI_ID_UID: "65534",
    PATH: `${fakeBin}:${process.env.PATH}`,
  };
  const mapHostPaths = (command) =>
    command
      .replaceAll("/var/lib/", `${root}/var/lib/`)
      .replaceAll("/usr/local/bin/", `${root}/usr/local/bin/`)
      .replaceAll("/etc/", `${root}/etc/`)
      .replaceAll("/run/", `${root}/run/`);
  const runHostScript = async (command) => {
    try {
      const result = await execFileAsync("sh", ["-c", mapHostPaths(command)], {
        env: environment,
      });
      return successfulCommandText(result.stdout);
    } catch (error) {
      return {
        code: typeof error.code === "number" ? error.code : 1,
        stderr: error.stderr ?? error.message,
        stdout: error.stdout ?? "",
      };
    }
  };

  await mkdir(fakeBin, { recursive: true });
  await writeFile(
    path.join(fakeBin, "getent"),
    `#!/bin/sh
[ -f "$ENOKI_ACCOUNTS_READY" ] || exit 2
case "$1:$2" in
  passwd:enoki-probe) printf 'enoki-probe:x:%s:%s::/var/lib/enoki-probe:/usr/sbin/nologin\\n' "$ENOKI_GETENT_PASSWD_UID" "$ENOKI_GETENT_PASSWD_GID" ;;
  group:enoki-probe) printf 'enoki-probe:x:%s:\\n' "$ENOKI_GETENT_GROUP_GID" ;;
  *) exit 2 ;;
esac
`,
    "utf8",
  );
  await writeFile(
    path.join(fakeBin, "id"),
    `#!/bin/sh
[ -f "$ENOKI_ACCOUNTS_READY" ] || exec /usr/bin/id "$@"
case "$1:$2" in
  -u:enoki-probe) printf '%s\\n' "$ENOKI_ID_UID" ;;
  -g:enoki-probe) printf '%s\\n' "$ENOKI_ID_GID" ;;
  *) exec /usr/bin/id "$@" ;;
esac
`,
    "utf8",
  );
  await writeFile(path.join(fakeBin, "systemctl"), "#!/bin/sh\nexit 0\n");
  for (const command of ["getent", "id", "systemctl"]) {
    await chmod(path.join(fakeBin, command), 0o755);
  }

  return {
    environment,
    paths: {
      binary,
      claimResources: path.join(
        root,
        "var",
        "lib",
        "enoki-release-e2e",
        "claim",
        "resources",
      ),
      collectorSudoers,
      identity,
      identityFile,
      metadata,
      operationStatus,
      operationSudoers,
      publicParent,
      publicState,
      unit,
    },
    async installLegacyFiles({
      extraMetadata = "",
      identityGid = 65534,
      identityMode = 0o600,
      identityUid = 65534,
      stateGid = 65534,
      stateUid = 65534,
    } = {}) {
      await mkdir(identity, { recursive: true });
      for (const candidate of [metadata, binary, unit, operationSudoers]) {
        await mkdir(path.dirname(candidate), { recursive: true });
      }
      await chmod(publicParent, 0o755);
      await chmod(publicState, 0o750);
      await chmod(identity, 0o700);
      await chown(publicState, stateUid, stateGid);
      await chown(identity, stateUid, stateGid);
      await writeFile(identityFile, "identity", "utf8");
      await chmod(identityFile, identityMode);
      await chown(identityFile, identityUid, identityGid);
      await writeFile(
        metadata,
        `schema_version = 1
hub_url = "https://hub.example"
install_path = "${binary}"
identity_path = "${identityFile}"
state_dir = "${publicState}"
operation_status_path = "${operationStatus}"
service_name = "enoki-probe"
service_user = "enoki-probe"
service_group = "enoki-probe"
service_unit_path = "${unit}"
operation_sudoers_path = "${operationSudoers}"
collector_helper_sudoers_path = "${collectorSudoers}"
probe_asset_public_key_sha256 = "${"a".repeat(64)}"
${extraMetadata}`,
        "utf8",
      );
      await chmod(metadata, 0o600);
      await writeFile(binary, "binary", "utf8");
      await chmod(binary, 0o755);
      await writeFile(unit, "unit", "utf8");
      await chmod(unit, 0o644);
      await writeFile(operationSudoers, "sudoers", "utf8");
      await chmod(operationSudoers, 0o440);
      await writeFile(environment.ENOKI_ACCOUNTS_READY, "ready", "utf8");
    },
    async remove() {
      await rm(root, { force: true, recursive: true });
    },
    runHostScript,
  };
}

async function createRuntimeFailureCustodyFixture(prefix) {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  const fakeBin = path.join(root, "fake-bin");
  const claim = path.join(root, "var", "lib", "enoki-release-e2e", "claim");
  const runtime = path.join(
    root,
    "usr",
    "local",
    "bin",
    "enoki-observation-runtime",
  );
  const runtimeDirectory = path.dirname(runtime);
  const runtimeUnit = path.join(
    root,
    "etc",
    "systemd",
    "system",
    "enoki-observation-runtime.service",
  );
  const systemctlLog = path.join(root, "systemctl.log");
  const environment = {
    ...process.env,
    ENOKI_RUNTIME_UNIT: runtimeUnit,
    ENOKI_SYSTEMCTL_LOG: systemctlLog,
    PATH: `${fakeBin}:${process.env.PATH}`,
  };
  const mapHostPaths = (command) =>
    command
      .replaceAll("/var/lib/", `${root}/var/lib/`)
      .replaceAll("/usr/local/bin/", `${root}/usr/local/bin/`)
      .replaceAll("/etc/", `${root}/etc/`)
      .replaceAll("/run/", `${root}/run/`);
  const runHostScript = async (command) => {
    try {
      const result = await execFileAsync("sh", ["-c", mapHostPaths(command)], {
        env: environment,
      });
      return successfulCommandText(result.stdout);
    } catch (error) {
      return {
        code: typeof error.code === "number" ? error.code : 1,
        stderr: error.stderr ?? error.message,
        stdout: error.stdout ?? "",
      };
    }
  };

  await mkdir(fakeBin, { recursive: true });
  await mkdir(claim, { recursive: true, mode: 0o700 });
  await mkdir(runtimeDirectory, { recursive: true });
  await mkdir(path.dirname(runtimeUnit), { recursive: true });
  await writeFile(path.join(claim, "run-id"), "run-runtime-custody\n");
  await writeFile(
    path.join(claim, "token"),
    "00000000-0000-4000-8000-000000000001\n",
  );
  await writeFile(path.join(claim, "resources"), "resources\n");
  for (const member of ["run-id", "token", "resources"]) {
    await chmod(path.join(claim, member), 0o600);
  }
  await writeFile(runtime, "canonical runtime\n");
  await chmod(runtime, 0o755);
  await writeFile(
    runtimeUnit,
    "StartLimitBurst=3\nStartLimitIntervalSec=60s\n",
  );
  await chmod(runtimeUnit, 0o644);
  await writeFile(
    path.join(fakeBin, "systemctl"),
    `#!/bin/sh
printf '%s\\n' "$*" >> "$ENOKI_SYSTEMCTL_LOG"
if [ "$1" = show ] && [ "$3" = --property=FragmentPath ]; then
  printf '%s\\n' "$ENOKI_RUNTIME_UNIT"
  exit 0
fi
exit 1
`,
    "utf8",
  );
  await writeFile(
    path.join(root, "usr", "local", "bin", "enoki-probe"),
    "#!/bin/sh\nprintf 'enoki-probe 1.2.3\\n'\n",
  );
  await chmod(path.join(fakeBin, "systemctl"), 0o755);
  await chmod(path.join(root, "usr", "local", "bin", "enoki-probe"), 0o755);

  return {
    paths: {
      backup: path.join(claim, "observation-runtime-original"),
      backupTemp: path.join(claim, "observation-runtime-original.next"),
      claim,
      restoreTemp: path.join(
        runtimeDirectory,
        ".enoki-observation-runtime.release-e2e.restore",
      ),
      runtime,
      systemctlLog,
    },
    async remove() {
      await rm(root, { force: true, recursive: true });
    },
    runHostScript,
  };
}

async function captureRuntimeFailureCommand(header) {
  let command = null;
  const driver = createInstalledBundleFailureRepairHostDriver({
    assertOwnedRun() {},
    async execute(candidate) {
      if (candidate.includes(`# enoki-release-e2e:${header}`)) {
        command = candidate;
      }
      return { code: 79, stderr: "interrupted", stdout: "" };
    },
    ownershipToken: "00000000-0000-4000-8000-000000000001",
  });
  if (header === "exhaust-observation-runtime-budget") {
    await expect(driver.repair("run-runtime-custody", "1.2.3")).rejects.toThrow(
      /durable Observation Runtime failure eligibility/i,
    );
  } else {
    await expect(driver.cleanup("run-runtime-custody")).rejects.toThrow(
      /cleanup failed/i,
    );
  }
  expect(command).toEqual(expect.any(String));
  return command;
}

describe("Release E2E business assertions", () => {
  it("transfers cleanup ownership when the existing runner enters environment start", async () => {
    const calls = [];
    const environment = createReleaseEnvironment({
      candidateDir: "/tmp/release-candidate",
      docker: {
        async start() {
          calls.push("docker.start");
          throw new Error("Hub initialization failed");
        },
      },
      execute: async () => ({ code: 0, stderr: "", stdout: "" }),
      hubOwnerUrl: "http://hub-owner.test",
      hubPublicUrl: "http://hub-public.test",
      onCleanupManaged() {
        calls.push("cleanup.owned");
      },
      ownerPassword: "owner-password",
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    });

    await expect(
      environment.start({
        candidateManifest: candidateManifest(),
        runId: "run-cleanup-ownership",
      }),
    ).rejects.toThrow("Hub initialization failed");
    expect(calls).toEqual(["cleanup.owned", "docker.start"]);
  });

  it("binds the canonical report transport to the verified Probe upstream origin", async () => {
    const calls = [];
    const environment = createReleaseEnvironment({
      candidateDir: "/tmp/release-candidate",
      canonicalReportTransportFactory(options) {
        calls.push(["transport.create", options]);
        return {
          async close() {
            calls.push("transport.close");
            return { clean: true };
          },
          async start() {
            calls.push("transport.start");
            return { origin: "http://127.0.0.1:33000" };
          },
        };
      },
      docker: {
        async cleanup() {
          calls.push("docker.cleanup");
          return { clean: true };
        },
        async start() {
          calls.push("docker.start");
          return {
            activeHub: "candidate",
            probeUpstreamOrigin: "http://127.0.0.1:49152",
          };
        },
      },
      execute: async () => ({ code: 0, stderr: "", stdout: "" }),
      hubOwnerUrl: "http://127.0.0.1:33001",
      hubPublicUrl: "http://127.0.0.1:33000",
      ownerPassword: "owner-password",
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    });

    const resources = await environment.start({
      candidateManifest: candidateManifest(),
      runId: "run-report-transport",
    });
    expect(resources.canonicalReports).toBeDefined();
    await environment.cleanup({ resources, runId: "run-report-transport" });
    expect(calls).toEqual([
      "docker.start",
      [
        "transport.create",
        {
          listenUrl: "http://127.0.0.1:33000",
          upstreamUrl: "http://127.0.0.1:49152",
        },
      ],
      "transport.start",
      "transport.close",
      "docker.cleanup",
    ]);
  });

  it("retains transport cleanup ownership when its public-origin bind fails", async () => {
    const calls = [];
    const environment = createReleaseEnvironment({
      candidateDir: "/tmp/release-candidate",
      canonicalReportTransportFactory() {
        return {
          async close() {
            calls.push("transport.close");
            return { clean: true };
          },
          async start() {
            throw new Error("public origin unavailable");
          },
        };
      },
      docker: {
        async cleanup() {
          calls.push("docker.cleanup");
          return { clean: true };
        },
        async start() {
          return { activeHub: "candidate" };
        },
      },
      execute: async () => ({ code: 0, stderr: "", stdout: "" }),
      hubOwnerUrl: "http://127.0.0.1:33001",
      hubPublicUrl: "http://127.0.0.1:33000",
      ownerPassword: "owner-password",
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    });

    await expect(
      environment.start({
        candidateManifest: candidateManifest(),
        runId: "run-report-transport-failure",
      }),
    ).rejects.toThrow("public origin unavailable");
    await environment.cleanup({
      resources: null,
      runId: "run-report-transport-failure",
    });
    expect(calls).toEqual(["transport.close", "docker.cleanup"]);
  });

  it("keeps ForwardTransitions authority behind the typed Hub adapter and out of the Host Harness", async () => {
    const host = createProbeHostHarness({
      execute: async () => ({ code: 0, stderr: "", stdout: "" }),
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    });
    const hostMethods = Object.keys(host);
    const hubRoutes = await readFile(
      new URL("../apps/hub/src/hosts/routes.ts", import.meta.url),
      "utf8",
    );

    expect(hostMethods).not.toEqual(
      expect.arrayContaining([
        "authorize",
        "createEnrollment",
        "createOperation",
        "readJournalPhase",
        "requestProbeUpgrade",
        "view",
      ]),
    );
    expect(hubRoutes).toContain("createForwardTransitions({");
    expect(hubRoutes).toContain("}).authorize({");
    expect(hubRoutes).not.toMatch(/release[-_ ]e2e/i);
  });

  it("accepts the exact Bootstrap command boundary and rejects unsafe variants", async () => {
    const enrollment = officialEnrollment();
    const rendered = renderInstallCommand(
      {
        bootstrapRecipe: enrollment.bootstrapRecipe,
        probeApiOrigin: enrollment.hubUrl,
      },
      { enrollmentToken: enrollment.enrollmentToken },
    );
    expect(rendered.installCommand).toBe(officialInstallCommand);

    const unsafeCommands = [
      `${rendered.installCommand}; sh`,
      rendered.installCommand.replace("python3 --", "sudo python3 --"),
      rendered.installCommand.replace(
        "./enoki-probe-bootstrap.py",
        "https://attacker.example/bootstrap.py",
      ),
      "ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_secret' /usr/local/bin/enoki-probe-bootstrap-acquire | sudo -- /usr/local/bin/enoki-probe-bootstrap-activate",
    ];
    for (const installCommand of unsafeCommands) {
      const client = createHubLifecycleClient({
        baseUrl: "https://hub.example",
        fetch: async () => jsonResponse({ ...enrollment, installCommand }, 201),
      });
      await expect(client.createEnrollment()).rejects.toThrow(
        /invalid Probe install command/,
      );
    }
  });

  it("binds the renderer's canonical Replacement authority to the Enrollment response", async () => {
    const sourceProbeSha256 = ["a", "b", "c", "d"].map((value) =>
      value.repeat(64),
    );
    const replacementMigration = {
      enrollmentId: "enr_manual_reinstall_0001",
      expectedProbeId: "probe_release_legacy",
      sourceProbeSha256,
      sourceProbeVersion: "0.1.74",
      targetAssetSetDigest: `sha256:${"b".repeat(64)}`,
      targetHostId: "7",
      targetProbeVersion: "1.2.3",
    };
    const rendered = renderInstallCommand(
      {
        bootstrapRecipe: {
          ...officialEnrollment().bootstrapRecipe,
          distribution: "enoki",
        },
        probeApiOrigin: "https://hub.example",
      },
      {
        enrollmentToken: "enk_enroll_replacement",
        replacementMigration,
      },
    );
    expect(rendered.installCommand).toBe(
      `printf '%s\\n' '${JSON.stringify({
        hubOrigin: "https://hub.example",
        enrollmentToken: "enk_enroll_replacement",
        replacementMigration,
        schemaVersion: 1,
      })}' | python3 -- ./enoki-probe-bootstrap.py --hub-origin 'https://hub.example'`,
    );
    expect(rendered.installCommand).not.toMatch(
      /ENOKI_ENROLLMENT_TOKEN|enoki-probe-bootstrap-(?:acquire|activate)|sudo|curl|github/i,
    );
    const enrollment = officialEnrollment({
      enrollmentId: replacementMigration.enrollmentId,
      enrollmentToken: "enk_enroll_replacement",
      installCommand: rendered.installCommand,
      target: { hostId: 7, kind: "manual_reinstall" },
    });
    const accepted = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: async () => jsonResponse(enrollment, 201),
      replacementSourceProbeSha256: sourceProbeSha256,
    });
    await expect(accepted.createManualReinstallEnrollment(7)).resolves.toEqual(
      enrollment,
    );

    const authority = {
      hubOrigin: enrollment.hubUrl,
      enrollmentToken: enrollment.enrollmentToken,
      replacementMigration,
      schemaVersion: 1,
    };
    const mutations = [
      { ...authority, schemaVersion: 2 },
      { ...authority, hubOrigin: "https://other.example" },
      { ...authority, enrollmentToken: "enk_enroll_other" },
      {
        enrollmentToken: authority.enrollmentToken,
        hubOrigin: authority.hubOrigin,
        replacementMigration,
        schemaVersion: 1,
      },
      {
        ...authority,
        replacementMigration: {
          expectedProbeId: replacementMigration.expectedProbeId,
          enrollmentId: replacementMigration.enrollmentId,
          sourceProbeSha256,
          sourceProbeVersion: replacementMigration.sourceProbeVersion,
          targetAssetSetDigest: replacementMigration.targetAssetSetDigest,
          targetHostId: replacementMigration.targetHostId,
          targetProbeVersion: replacementMigration.targetProbeVersion,
        },
      },
      ...[
        ["enrollmentId", "enr_manual_reinstall_other"],
        ["expectedProbeId", ""],
        ["sourceProbeSha256", ["not-a-sha256"]],
        ["sourceProbeVersion", "v0.1.74"],
        ["targetAssetSetDigest", "not-an-asset-set-digest"],
        ["targetHostId", "8"],
        ["targetProbeVersion", "1.2"],
        ["sourceProbeSha256", sourceProbeSha256.slice(0, 3)],
        [
          "sourceProbeSha256",
          [
            sourceProbeSha256[0],
            sourceProbeSha256[0],
            ...sourceProbeSha256.slice(2),
          ],
        ],
        ["sourceProbeSha256", [...sourceProbeSha256].reverse()],
      ].map(([field, value]) => ({
        ...authority,
        replacementMigration: { ...replacementMigration, [field]: value },
      })),
      { ...authority, unexpected: true },
    ];
    const results = [];
    for (const mutated of mutations) {
      const client = createHubLifecycleClient({
        baseUrl: "https://hub.example",
        fetch: async () =>
          jsonResponse(
            {
              ...enrollment,
              installCommand: bootstrapRecipeCommand(mutated),
            },
            201,
          ),
        replacementSourceProbeSha256: sourceProbeSha256,
      });
      results.push(
        await client.createManualReinstallEnrollment(7).then(
          () => "accepted",
          (error) => error.message,
        ),
      );
    }
    expect(results).toEqual(
      mutations.map(() =>
        expect.stringMatching(
          /invalid.*install command|not bound|target changed/i,
        ),
      ),
    );
  });

  it("accepts only the verified Trust Epoch migration baseline union member", async () => {
    const manifest = candidateManifestWithMigrationBaseline();
    await expect(
      runReleaseE2EScenario({
        candidateManifest: manifest,
        environment: {
          cleanup: async () => ({ clean: true }),
          start: async () => {
            throw new Error("typed migration baseline accepted");
          },
        },
        evidenceSink: { write: async () => {} },
        ownerPassword: "owner-password",
        runId: "run-migration-contract",
        scenario: "replacement-migration-uninstall",
      }),
    ).rejects.toThrow(/typed migration baseline accepted/);

    await expect(
      runReleaseE2EScenario({
        candidateManifest: {
          ...manifest,
          releaseBaseline: { ...manifest.releaseBaseline, kind: "legacy" },
        },
        environment: {
          cleanup: async () => ({ clean: true }),
          start: async () => ({ host: {}, hub: {} }),
        },
        evidenceSink: { write: async () => {} },
        ownerPassword: "owner-password",
        runId: "run-generic-legacy-contract",
        scenario: "replacement-migration-uninstall",
      }),
    ).rejects.toThrow(/manifest fields must be exactly/i);
  });

  it("dispatches Replacement participants from the planned scenario instead of the baseline name", async () => {
    let hostStarted = false;
    const methodObject = (names) =>
      Object.fromEntries(names.map((name) => [name, async () => {}]));
    const host = {
      ...methodObject([
        "assertDisposable",
        "assertInstalled",
        "beginUpgradeOwnershipTransition",
        "bindUpgradeOwnershipTransition",
        "cleanup",
        "collectEvidence",
        "completeUpgradeOwnershipTransition",
        "install",
        "readProbeIdentity",
        "verifyUninstallCompletion",
      ]),
      async assertDisposable() {
        hostStarted = true;
      },
    };
    const hub = methodObject([
      "authenticate",
      "createEnrollment",
      "getHost",
      "getHostMetrics",
      "isHostSoftDeleted",
      "listHosts",
      "requestProbeUninstall",
      "requestProbeUpgrade",
      "switchToCandidate",
      "waitForProbeOperation",
    ]);

    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifestWithBaseline(),
        environment: {
          cleanup: async () => ({ clean: true }),
          start: async () => ({ host, hub }),
        },
        evidenceSink: { write: async () => {} },
        ownerPassword: "owner-password",
        runId: "run-explicit-replacement-dispatch",
        scenario: "replacement-migration-uninstall",
      }),
    ).rejects.toThrow(/invalid baseline-upgrade participants/);
    expect(hostStarted).toBe(false);
  });

  it("executes Trust Epoch baseline migration through production manual reinstall with replacement evidence", async () => {
    const calls = [];
    const written = [];
    const candidateManifest = candidateManifestWithMigrationBaseline();
    await expect(
      runReleaseE2EScenario({
        candidateManifest,
        environment: migrationBaselineEnvironment(calls, candidateManifest),
        evidenceSink: {
          write: async (evidence) => written.push(evidence),
        },
        ownerPassword: "owner-password",
        runId: "run-migration-baseline-behavior",
        scenario: "replacement-migration-uninstall",
        timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
      }),
    ).resolves.toEqual({ status: "succeeded" });
    expect(calls).toContain("host.manualReinstall:manual_reinstall");
    expect(calls).not.toContain("hub.requestProbeUpgrade");
    expect(
      calls
        .filter((call) => call.startsWith("hub.getHost:candidate:"))
        .slice(0, 3),
    ).toEqual([
      "hub.getHost:candidate:default-v1:clean",
      "hub.getHost:candidate:host-7-1:configuration-error",
      "hub.getHost:candidate:host-7-1:clean",
    ]);
    expect(written.at(-1)).toMatchObject({
      identityContinuity: {
        after: { probeId: "probe_release_replacement" },
        before: { probeId: "probe_release_legacy" },
        hostId: 7,
      },
      migrationRetention: {
        hostAfter: { id: 7 },
        hostBefore: { id: 7 },
      },
      result: { status: "succeeded" },
      uninstall: { hubSoftDeleted: true, status: "succeeded" },
    });
    const evidence = written.at(-1);
    expect(evidence.releaseBaseline.authority.authorizationSha256).toBe(
      candidateManifest.releaseBaseline.authorization.sha256,
    );
    const gate = createMatrixGateResult({
      artifactName:
        "release-e2e-ubuntu-22.04-x86_64--replacement-migration-uninstall-1",
      candidateManifest,
      cellId: "ubuntu-22.04-x86_64--replacement-migration-uninstall",
      evidence,
      scenarioOutcome: "success",
      verifyCleanOutcome: "success",
    });
    expect(evidence.migrationRetention.postMetricHistory.anchors).toEqual(
      expect.arrayContaining(evidence.migrationRetention.metricHistory.anchors),
    );
    expect(
      evidence.migrationRetention.metricHistory.anchors.length,
    ).toBeGreaterThanOrEqual(3);
    expect(
      evidence.migrationRetention.postMetricHistory.anchors.length,
    ).toBeLessThanOrEqual(
      evidence.migrationRetention.metricHistory.anchors.length + 3,
    );
    expect(
      evidence.migrationRetention.postMetricHistory.anchors.some(
        (anchor) =>
          anchor.sequence >
            evidence.migrationRetention.metricHistory.anchors.at(-1).sequence &&
          anchor.collectedAtMs >
            evidence.migrationRetention.metricHistory.anchors.at(-1)
              .collectedAtMs,
      ),
    ).toBe(true);
    expect(evidence.migrationRetention.configuration).toEqual({
      configuration: evidence.probeConfiguration.beforeUpgrade.configuration,
      mode: evidence.probeConfiguration.beforeUpgrade.mode,
    });
    expect(
      evidence.migrationRetention.hostBefore.reportedProbeConfigurationVersion,
    ).toBe(evidence.probeConfiguration.beforeUpgrade.reportedVersion);
    expect(
      evidence.migrationRetention.hostAfter.reportedProbeConfigurationVersion,
    ).toBe(evidence.probeConfiguration.beforeUpgrade.version);
    expect(gate.evidenceValidationErrors).toEqual([]);
    expect(gate.outcome).toBe("succeeded");
  });

  it("keeps the explicit Compatible Repair path independent of baseline descriptor kind", async () => {
    const methodObject = (names) =>
      Object.fromEntries(names.map((name) => [name, async () => {}]));
    const host = methodObject([
      "armPostReplacementRestartFault",
      "assertInstalled",
      "assertPostReplacementUpgradeFailure",
      "beginUpgradeOwnershipTransition",
      "bindUpgradeOwnershipTransition",
      "cleanup",
      "collectEvidence",
      "completeRepairOwnershipTransition",
      "completeUpgradeOwnershipTransition",
      "install",
      "readProbeIdentity",
      "removePostReplacementRestartFault",
      "repair",
      "verifyUninstallCompletion",
    ]);
    host.assertDisposable = async () => {
      throw new Error("compatible-repair-entered");
    };
    const hub = methodObject([
      "authenticate",
      "createEnrollment",
      "getAuditLog",
      "getHost",
      "getHostMetrics",
      "getHostProbeConfiguration",
      "getProbeOperation",
      "isHostSoftDeleted",
      "listHosts",
      "requestProbeUninstall",
      "requestProbeUpgrade",
      "switchToCandidate",
      "updateHostProbeConfiguration",
      "waitForProbeOperation",
    ]);

    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifestWithMigrationBaseline(),
        environment: {
          cleanup: async () => ({ clean: true }),
          start: async () => ({ host, hub }),
        },
        evidenceSink: { write: async () => {} },
        ownerPassword: "owner-password",
        runId: "run-explicit-compatible-repair",
        scenario: "post-replacement-repair-uninstall",
      }),
    ).rejects.toThrow("compatible-repair-entered");
  });

  it("reports the dedicated migration Configuration retention timeout", async () => {
    const candidateManifest = candidateManifestWithMigrationBaseline();
    await expect(
      runReleaseE2EScenario({
        candidateManifest,
        environment: migrationBaselineEnvironment([], candidateManifest, {
          candidateConfigurationNeverRetained: true,
        }),
        evidenceSink: { write: async () => {} },
        ownerPassword: "owner-password",
        runId: "run-migration-configuration-timeout",
        scenario: "replacement-migration-uninstall",
        timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 2 },
      }),
    ).rejects.toMatchObject({
      code: "candidate_probe_configuration_retention_timeout",
    });
  });

  it("preserves only the validated public authorization summary in redacted evidence", async () => {
    const written = [];
    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifestWithBaseline(),
        environment: {
          cleanup: async () => ({
            clean: true,
            summaries: {
              authorization: "Bearer release-credential",
              authorizationDigest: "a".repeat(64),
              authorizationPayload: "release-authorization-payload",
              authorizationToken: "release-authorization-token",
              enrollmentToken: "enk_enroll_release_credential",
              headersSha256: "Bearer release-credential",
              invalid: { authorizationSha256: "not-a-sha256-summary" },
              ownerPassword: "owner-password",
              privateKeyFingerprint: "raw-private-key-material",
              privateKeyPem:
                "-----BEGIN PRIVATE KEY-----\nraw-private-key-material\n-----END PRIVATE KEY-----",
              valid: { authorizationSha256: "b".repeat(64) },
            },
          }),
          start: async () => {
            throw new Error("planned scenario failed before Host mutation");
          },
        },
        evidenceSink: {
          write: async (evidence) => written.push(evidence),
        },
        ownerPassword: "owner-password",
        runId: "run-redacted-public-summary",
        scenario: "compatible-upgrade-uninstall",
      }),
    ).rejects.toMatchObject({
      code: "release_e2e_failed",
    });

    expect(written.at(-1).cleanup.environment.summaries).toEqual({
      authorization: "[REDACTED]",
      authorizationDigest: "[REDACTED]",
      authorizationPayload: "[REDACTED]",
      authorizationToken: "[REDACTED]",
      enrollmentToken: "[REDACTED]",
      headersSha256: "[REDACTED]",
      invalid: { authorizationSha256: "[REDACTED]" },
      ownerPassword: "[REDACTED]",
      privateKeyFingerprint: "[REDACTED]",
      privateKeyPem: "[REDACTED]",
      valid: { authorizationSha256: "[REDACTED]" },
    });
  });

  it("binds the public authorization summary to its exact authority path and expected value", () => {
    const candidateManifest = candidateManifestWithMigrationBaseline();
    const expected = candidateManifest.releaseBaseline.authorization.sha256;
    const other = "c".repeat(64);
    expect(
      redactReleaseE2EEvidence(
        {
          cleanup: {
            authorizationSha256: expected,
          },
          releaseBaseline: {
            authority: { authorizationSha256: expected },
          },
        },
        {
          candidateManifest,
        },
      ),
    ).toEqual({
      cleanup: { authorizationSha256: "[REDACTED]" },
      releaseBaseline: {
        authority: { authorizationSha256: expected },
      },
    });
    expect(
      redactReleaseE2EEvidence(
        {
          releaseBaseline: {
            authority: { authorizationSha256: other },
          },
        },
        {
          candidateManifest,
        },
      ),
    ).toEqual({
      releaseBaseline: {
        authority: { authorizationSha256: "[REDACTED]" },
      },
    });
  });

  it("derives baseline kind from the validated Candidate Manifest in workflow", async () => {
    const workflow = await readFile(
      fileURLToPath(
        new URL(
          "../.github/workflows/reusable-build-release-candidate.yml",
          import.meta.url,
        ),
      ),
      "utf8",
    );
    expect(workflow).toContain(
      "--candidate-manifest candidate/candidate-manifest.json",
    );
    expect(workflow).not.toMatch(/--baseline-kind|baseline_kind:/);
    expect(workflow).toContain("--hub-owner-url http://127.0.0.1:33001");
    expect(workflow).toContain("--hub-public-url http://127.0.0.1:33000");
  });

  it("constructs the real Docker Hub controller with default options", () => {
    expect(createDockerHubController()).toBeDefined();
  });

  it("requires a reasonable typed Host Profile from the Candidate Probe", () => {
    expect(isCandidateHostReady(readyHost(), "1.2.3")).toBe(true);
    expect(
      isCandidateHostReady(
        readyHost({
          hostProfile: {
            ...readyHost().hostProfile,
            probeVersion: "v1.2.3",
          },
        }),
        "1.2.3",
      ),
    ).toBe(true);
    expect(
      isCandidateHostReady(
        readyHost({
          hostProfile: {
            ...readyHost().hostProfile,
            probeVersion: "9.9.9",
          },
        }),
        "1.2.3",
      ),
    ).toBe(false);
    expect(
      isCandidateHostReady(
        readyHost({
          hostProfile: { ...readyHost().hostProfile, cpuCount: 0 },
        }),
        "1.2.3",
      ),
    ).toBe(false);
  });

  it("requires two advancing typed official CPU and memory samples", () => {
    const samples = [
      portableMetric({ collectedAtMs: 10, sequence: 1, uptimeSeconds: 100 }),
      portableMetric({ collectedAtMs: 20, sequence: 2, uptimeSeconds: 110 }),
    ];
    expect(hasAdvancingPortableMetrics(samples)).toBe(true);
    expect(
      hasAdvancingPortableMetrics([
        samples[0],
        { ...samples[1], cpuPercent: 101 },
      ]),
    ).toBe(false);
    expect(
      hasAdvancingPortableMetrics([
        samples[0],
        { ...samples[1], memoryUsedBytes: samples[1].memoryTotalBytes + 1 },
      ]),
    ).toBe(false);
  });

  it("proves accepted and running transitions from formal timestamps without requiring an independently-polled accepted state", () => {
    const operation = {
      acceptedAtMs: null,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "pending",
      targetProbeVersion: "1.2.3",
      updatedAtMs: 1,
    };
    expect(() =>
      validateSuccessfulProbeUpgradeTimeline([
        operation,
        {
          ...operation,
          acceptedAtMs: 2,
          runningAtMs: 2,
          state: "running",
          updatedAtMs: 2,
        },
        {
          ...operation,
          acceptedAtMs: 2,
          completedAtMs: 3,
          runningAtMs: 2,
          state: "succeeded",
          updatedAtMs: 3,
        },
      ]),
    ).not.toThrow();
    expect(() =>
      validateSuccessfulProbeUpgradeTimeline([
        operation,
        {
          ...operation,
          runningAtMs: 2,
          state: "running",
          updatedAtMs: 2,
        },
        {
          ...operation,
          completedAtMs: 3,
          runningAtMs: 2,
          state: "succeeded",
          updatedAtMs: 3,
        },
      ]),
    ).toThrow(/invalid Probe Operation|accepted.*evidence/i);
    expect(() =>
      validateSuccessfulProbeUpgradeTimeline([
        operation,
        {
          ...operation,
          acceptedAtMs: 3,
          runningAtMs: 2,
          state: "running",
          updatedAtMs: 3,
        },
        {
          ...operation,
          acceptedAtMs: 3,
          completedAtMs: 4,
          runningAtMs: 2,
          state: "succeeded",
          updatedAtMs: 4,
        },
      ]),
    ).toThrow(/accepted.*running|timestamp/i);
    expect(() =>
      validateSuccessfulProbeUpgradeTimeline([
        operation,
        {
          ...operation,
          acceptedAtMs: 2,
          runningAtMs: 2,
          state: "running",
          updatedAtMs: 2,
        },
        {
          ...operation,
          acceptedAtMs: 2,
          completedAtMs: 3,
          runningAtMs: 2,
          state: "succeeded",
          targetProbeVersion: "1.2.4",
          updatedAtMs: 3,
        },
      ]),
    ).toThrow(/target.*expected 1\.2\.3/i);
  });
});

describe("successful Probe Repair boundary evidence", () => {
  it("accepts only complete, consistent evidence from all seven boundaries", () => {
    const evidence = successfulRepairBoundaryEvidence();

    expect(
      validateSuccessfulRepairBoundaryEvidence(
        evidence,
        candidateManifestWithBaseline(),
      ),
    ).toBe(evidence);
  });

  it("keeps Compatible failed-Upgrade Repair evidence independent of baseline descriptor kind", () => {
    const evidence = successfulRepairBoundaryEvidence();
    const manifest = candidateManifestWithMigrationBaseline();
    bindRepairEvidenceToBaseline(evidence, manifest.releaseBaseline);

    expect(validateSuccessfulRepairBoundaryEvidence(evidence, manifest)).toBe(
      evidence,
    );
  });

  it("rejects manual-reinstall evidence for an explicit Compatible Repair scenario", () => {
    const evidence = successfulRepairBoundaryEvidence();
    const manifest = candidateManifestWithMigrationBaseline();
    bindRepairEvidenceToBaseline(evidence, manifest.releaseBaseline);
    evidence.auditLog = lifecycleAuditLog();
    evidence.failureBoundary = {
      enrollmentId: "enr_manual_reinstall_0001",
      hostId: 7,
      kind: "trust_epoch_manual_reinstall",
    };
    evidence.hubEvidence.apiTimeline.find((entry) =>
      entry.pathname.endsWith("/probe-upgrade-requests"),
    ).pathname = "/api/web/enrollments/manual-reinstall/7";
    evidence.operationTimeline = [];

    expect(() =>
      validateSuccessfulRepairBoundaryEvidence(evidence, manifest),
    ).toThrow(
      expect.objectContaining({
        boundary: "hub-api",
        code: "repair_boundary_evidence_invalid",
      }),
    );
  });

  it.each([
    [
      "hub-api",
      (evidence) => {
        evidence.hubEvidence.runtime.identityVerified = false;
      },
    ],
    [
      "hub-api",
      (evidence) => {
        evidence.auditLog[0].occurredAtMs = null;
      },
    ],
    [
      "probe-operation",
      (evidence) => {
        evidence.uninstallOperationTimeline.at(-1).completedAtMs = null;
      },
    ],
    [
      "systemd",
      (evidence) => {
        evidence.hostEvidence.systemd.stdout =
          "stage=post-uninstall\nLoadState=loaded\nActiveState=active\nunitCount=1\nfailedUnitCount=0\n";
      },
    ],
    [
      "privilege",
      (evidence) => {
        evidence.hostEvidence.sudoers.code = 1;
      },
    ],
    [
      "filesystem",
      (evidence) => {
        evidence.hostEvidence.inventory.files.push(
          "/usr/local/bin/enoki-probe",
        );
      },
    ],
    [
      "identity",
      (evidence) => {
        evidence.identityContinuity.after.identitySha256 = "e".repeat(64);
      },
    ],
    [
      "cleanup",
      (evidence) => {
        evidence.cleanup.host = {
          clean: false,
          error: { code: "cleanup_failed", message: "residue" },
        };
      },
    ],
  ])("rejects invalid %s evidence", (boundary, mutate) => {
    const evidence = successfulRepairBoundaryEvidence();
    mutate(evidence);

    expect(() =>
      validateSuccessfulRepairBoundaryEvidence(
        evidence,
        candidateManifestWithBaseline(),
      ),
    ).toThrow(
      expect.objectContaining({
        boundary,
        code: "repair_boundary_evidence_invalid",
      }),
    );
  });

  it.each([
    ["hub-api", "hubEvidence"],
    ["filesystem", "hostEvidence"],
  ])(
    "rejects a %s collector error even when the business path succeeded",
    (boundary, collection) => {
      const evidence = successfulRepairBoundaryEvidence();
      evidence[collection] = {
        error: { code: "collector_failed", message: "collection failed" },
      };

      expect(() =>
        validateSuccessfulRepairBoundaryEvidence(
          evidence,
          candidateManifestWithBaseline(),
        ),
      ).toThrow(
        expect.objectContaining({
          boundary,
          code: "repair_boundary_evidence_invalid",
        }),
      );
    },
  );
});

describe("Probe Host Harness", () => {
  it.each([
    {
      authority: "enk_enroll_production",
      expectedToken: "enk_enroll_production",
      label: "ordinary Enrollment token",
      workingDirectory: "/tmp/enoki-release-e2e-recipe.abcdef",
    },
    {
      authority:
        '{"hubOrigin":"https://hub.example","enrollmentToken":"enk_enroll_replacement","replacementMigration":{"enrollmentId":"enr_manual_reinstall_0001","expectedProbeId":"probe_release_legacy","sourceProbeSha256":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"sourceProbeVersion":"0.1.74","targetAssetSetDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","targetHostId":"7","targetProbeVersion":"1.2.3"},"schemaVersion":1}',
      expectedToken: "enk_enroll_replacement",
      label: "Replacement migration authority",
      overrides: {
        enrollmentId: "enr_manual_reinstall_0001",
        target: { hostId: 7, kind: "manual_reinstall" },
      },
      workingDirectory: "/tmp/enoki-release-e2e-recipe.abcdef",
    },
  ])(
    "executes the exact Candidate recipe command with $label",
    async ({ authority, expectedToken, overrides = {}, workingDirectory }) => {
      const parsedAuthority = authority.startsWith("{")
        ? JSON.parse(authority)
        : null;
      const commands = [];
      const preparedContracts = [];
      const harness = createProbeHostHarness({
        execute: async (command) => {
          commands.push(command);
          if (command.includes("# enoki-release-e2e:inventory")) {
            return successfulCommand({
              accounts: { group: false, user: false },
              files: [],
              units: [],
            });
          }
          if (command.includes("# enoki-release-e2e:dependencies")) {
            return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
          }
          return successfulCommandText("owned\n");
        },
        prepareInstall: async ({ installContract }) => {
          preparedContracts.push(installContract);
          return {
            evidence: { kind: "candidate-bootstrap-recipe" },
            workingDirectory,
          };
        },
      });
      const enrollment = {
        ...officialEnrollment({
          enrollmentToken: expectedToken,
          installCommand: bootstrapRecipeCommand(authority),
          ...overrides,
        }),
      };

      await harness.assertDisposable("run-bootstrap-recipe");
      await expect(
        harness.install(enrollment, "run-bootstrap-recipe"),
      ).resolves.toMatchObject({
        bootstrapRecipeProvenance: { kind: "candidate-bootstrap-recipe" },
      });
      expect(preparedContracts).toEqual([
        {
          hubUrl: "https://hub.example",
          kind: "bootstrap-recipe",
          ...(parsedAuthority
            ? {
                replacementMigration: parsedAuthority.replacementMigration,
              }
            : {}),
          token: expectedToken,
        },
      ]);
      const install = commands.find((command) =>
        command.includes("# enoki-release-e2e:bootstrap-acquire"),
      );
      expect(install).toContain(enrollment.installCommand);
      expect(install).toContain("cd -- '/tmp/enoki-release-e2e-recipe.abcdef'");
      expect(install).not.toMatch(
        /ENOKI_ENROLLMENT_TOKEN|enoki-probe-bootstrap-(?:acquire|activate)|sudo|curl|github/i,
      );
    },
  );

  it("restarts the canonical Probe READY with Runtime masked and no registration one-shot material", async () => {
    const commands = [];
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:record-resources")) {
          return successfulCommandText("recorded\n");
        }
        if (command.includes("# enoki-release-e2e:local-probe-uninstall")) {
          return successfulCommandText("Local Probe Uninstall completed.\n");
        }
        if (
          command.includes("# enoki-release-e2e:canonical-runtime-unavailable")
        ) {
          return successfulCommand({
            identity: {
              probeId: "probe_release_02",
              registrationAttemptCredential: false,
              registrationAttemptSource: false,
              registrationDropIn: false,
              transitionalRegistrationKeys: false,
            },
            probe: {
              ActiveState: "active",
              LoadState: "loaded",
              Result: "success",
              SubState: "running",
              Type: "notify",
            },
            runtime: {
              serviceLoadState: "masked",
              socketLoadState: "masked",
            },
          });
        }
        if (
          command.includes("# enoki-release-e2e:restore-observation-runtime")
        ) {
          return successfulCommandText("restored\n");
        }
        return successfulCommandText(productInstallerOutput());
      },
    });
    await harness.assertDisposable("run-canonical-reporting");
    await harness.install(officialEnrollment(), "run-canonical-reporting");

    await expect(
      harness.restartCanonicalProbeWithoutObservationRuntime(
        "run-canonical-reporting",
        "probe_release_02",
      ),
    ).resolves.toMatchObject({
      identity: { probeId: "probe_release_02" },
      probe: { ActiveState: "active", SubState: "running", Type: "notify" },
      runtime: { serviceLoadState: "masked", socketLoadState: "masked" },
    });
    await expect(
      harness.restoreObservationRuntime("run-canonical-reporting"),
    ).resolves.toEqual({ restored: true });
    const restart = commands.find((command) =>
      command.includes("# enoki-release-e2e:canonical-runtime-unavailable"),
    );
    expect(restart).toContain("systemctl mask --runtime");
    expect(restart).toContain("systemctl restart enoki-probe.service");
    expect(restart).toContain("registration_");
    expect(restart).toContain("/var/lib/enoki-probe-registration/attempt.json");
    expect(restart).toContain(
      "/run/credentials/enoki-probe.service/registration-attempt",
    );
  });

  it("fingerprints same-path content, recursive directory closure, and file ownership metadata", async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "enoki-e2e-fingerprint-"),
    );
    const binary = path.join(root, "enoki-probe");
    const stateDirectory = path.join(root, "state");
    const identity = path.join(stateDirectory, "identity.toml");
    const resources = [
      { kind: "file", path: binary },
      { kind: "directory", path: stateDirectory },
    ];
    const fingerprint = async () => {
      const result = await execFileAsync("sh", [
        "-c",
        `${renderReleaseE2EResourceFingerprint(resources)}\nfingerprint`,
      ]);
      return result.stdout;
    };

    try {
      await writeFile(binary, "first", "utf8");
      await mkdir(stateDirectory);
      await writeFile(identity, "identity", "utf8");
      await chmod(binary, 0o644);
      const baseline = await fingerprint();

      await writeFile(binary, "other", "utf8");
      await expect(fingerprint()).resolves.not.toBe(baseline);
      await writeFile(binary, "first", "utf8");
      await expect(fingerprint()).resolves.toBe(baseline);

      const unexpectedMember = path.join(stateDirectory, "unexpected");
      await writeFile(unexpectedMember, "new member", "utf8");
      await expect(fingerprint()).resolves.not.toBe(baseline);
      await rm(unexpectedMember);
      await expect(fingerprint()).resolves.toBe(baseline);

      await chmod(binary, 0o600);
      await expect(fingerprint()).resolves.not.toBe(baseline);
      await chmod(binary, 0o644);
      await expect(fingerprint()).resolves.toBe(baseline);

      const externalHardlink = path.join(root, "external-hardlink");
      await link(binary, externalHardlink);
      await expect(fingerprint()).rejects.toBeDefined();
      await unlink(externalHardlink);
      await expect(fingerprint()).resolves.toBe(baseline);
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("fingerprints the canonical systemd StateDirectory projection as one logical directory", async () => {
    const fixture = await createSystemdStateDirectoryFixture(
      "enoki-e2e-state-directory-",
    );

    try {
      const baseline = await fixture.fingerprint();
      expect(baseline).toContain("\tsymlink\t");
      expect(baseline).toContain("\tdirectory\t");
      expect(baseline).toContain("\tfile\t");

      await writeFile(fixture.config, "changed identity", "utf8");
      await expect(fixture.fingerprint()).resolves.not.toBe(baseline);
      await writeFile(fixture.config, "identity", "utf8");
      await expect(fixture.fingerprint()).resolves.toBe(baseline);

      const member = path.join(fixture.privateState, "unexpected");
      await writeFile(member, "new member", "utf8");
      await expect(fixture.fingerprint()).resolves.not.toBe(baseline);
      await rm(member);
      await expect(fixture.fingerprint()).resolves.toBe(baseline);

      await chmod(fixture.config, 0o640);
      await expect(fixture.fingerprint()).resolves.not.toBe(baseline);
    } finally {
      await fixture.remove();
    }
  });

  it("uses one fail-closed directory snapshot for ambiguous members", async () => {
    const outcomes = {};

    for (const effect of ["fail", "insert"]) {
      const fixture = await createSystemdStateDirectoryFixture(
        `enoki-e2e-state-directory-${effect}-`,
      );
      const fakeBin = path.join(fixture.privateState, "fake-bin");
      const calls = path.join(fixture.privateState, "find-calls");
      const fakeFind = path.join(fakeBin, "find");
      await mkdir(fakeBin);
      await writeFile(
        fakeFind,
        `#!/bin/sh
count=$(cat "$ENOKI_FIND_CALLS" 2>/dev/null || printf 0)
count=$((count + 1))
printf '%s' "$count" > "$ENOKI_FIND_CALLS"
/usr/bin/find "$@"
status=$?
if [ "$ENOKI_FIND_EFFECT" = insert ] && [ "$count" -eq 1 ]; then
  printf hidden > "$ENOKI_FIND_INSERT_PATH"
fi
case " $* " in *' -print0 '*) nul_snapshot=true ;; *) nul_snapshot=false ;; esac
if [ "$ENOKI_FIND_EFFECT" = fail ] && { [ "$count" -eq 2 ] || [ "$nul_snapshot" = true ]; }; then
  exit 1
fi
exit "$status"
`,
        "utf8",
      );
      await chmod(fakeFind, 0o755);
      await writeFile(path.join(fixture.privateState, "a"), "visible", "utf8");
      const environment = {
        ...process.env,
        ENOKI_FIND_CALLS: calls,
        ENOKI_FIND_EFFECT: effect,
        ENOKI_FIND_INSERT_PATH: path.join(fixture.privateState, "a\n."),
        PATH: `${fakeBin}:${process.env.PATH}`,
      };

      try {
        outcomes[effect] = await fixture.fingerprint(environment).then(
          () => "resolved",
          (error) => `rejected:${error.code}`,
        );
        outcomes[`${effect}Calls`] = await readFile(calls, "utf8");
        if (effect === "insert") {
          outcomes.insertFollowUp = await fixture.fingerprint().then(
            () => "resolved",
            (error) => `rejected:${error.code}`,
          );
        }
      } finally {
        await fixture.remove();
      }
    }

    expect(outcomes).toEqual({
      fail: "rejected:1",
      failCalls: "1",
      insert: "resolved",
      insertCalls: "1",
      insertFollowUp: "rejected:1",
    });
  });

  it.each([
    ["an ordinary directory symlink", "ordinary-link"],
    ["a non-canonical link target", "link-target"],
    ["public link custody", "public-link-owner"],
    ["public parent custody", "public-parent"],
    ["private parent custody", "private-parent"],
    ["private StateDirectory mode", "state-mode"],
    ["identity custody", "identity-owner"],
    ["a symlinked private referent", "private-state-link"],
  ])(
    "rejects %s in a systemd StateDirectory projection",
    async (_label, tamper) => {
      const fixture = await createSystemdStateDirectoryFixture(
        "enoki-e2e-state-directory-tamper-",
      );

      try {
        if (tamper === "ordinary-link") {
          await rm(fixture.publicState);
          await symlink(fixture.privateState, fixture.publicState);
        } else if (tamper === "link-target") {
          await rm(fixture.publicState);
          await symlink("private/../private/enoki-probe", fixture.publicState);
        } else if (tamper === "public-link-owner") {
          await lchown(fixture.publicState, 65534, 65534);
        } else if (tamper === "public-parent") {
          await chmod(fixture.publicParent, 0o750);
        } else if (tamper === "private-parent") {
          await chmod(fixture.privateParent, 0o755);
        } else if (tamper === "state-mode") {
          await chmod(fixture.privateState, 0o700);
        } else if (tamper === "identity-owner") {
          await chown(fixture.privateState, 65534, 65534);
        } else if (tamper === "private-state-link") {
          const referent = path.join(
            fixture.privateParent,
            "enoki-probe-referent",
          );
          await rename(fixture.privateState, referent);
          await symlink("enoki-probe-referent", fixture.privateState);
        }

        await expect(fixture.fingerprint()).rejects.toMatchObject({
          code: 1,
          stderr: "",
        });
      } finally {
        await fixture.remove();
      }
    },
  );

  it("proves the declared Ubuntu architecture and host systemd boundary", async () => {
    const harness = createProbeHostHarness({
      execute: async (command) => {
        expect(command).toContain("# enoki-release-e2e:platform");
        expect(command).toContain("systemd-detect-virt --vm");
        return successfulCommand({
          architecture: "x86_64",
          deviceView: true,
          journaldSocket: true,
          operatingSystem: "ubuntu",
          operatingSystemVersion: "22.04",
          pid1: "systemd",
          rootFilesystem: true,
          systemdNotifySocket: true,
          unifiedCgroup: true,
          virtualization: "kvm",
        });
      },
    });

    await expect(
      harness.assertReleaseTestHost({
        architecture: "x86_64",
        operatingSystem: "ubuntu",
        operatingSystemVersion: "22.04",
      }),
    ).resolves.toMatchObject({ pid1: "systemd", virtualization: "kvm" });
  });

  it("rejects a container or mismatched Host before disposable preflight", async () => {
    const harness = createProbeHostHarness({
      execute: async () =>
        successfulCommand({
          architecture: "x86_64",
          operatingSystem: "ubuntu",
          operatingSystemVersion: "24.04",
          pid1: "systemd",
          virtualization: "docker",
        }),
    });

    await expect(
      harness.assertReleaseTestHost({
        architecture: "x86_64",
        operatingSystem: "ubuntu",
        operatingSystemVersion: "24.04",
      }),
    ).rejects.toThrow(/must be a supported VM.*docker/i);
  });

  it("rejects bare metal even when PID 1 is systemd", async () => {
    const harness = createProbeHostHarness({
      execute: async () =>
        successfulCommand({
          architecture: "x86_64",
          operatingSystem: "ubuntu",
          operatingSystemVersion: "24.04",
          pid1: "systemd",
          virtualization: "none",
        }),
    });

    await expect(
      harness.assertReleaseTestHost({
        architecture: "x86_64",
        operatingSystem: "ubuntu",
        operatingSystemVersion: "24.04",
      }),
    ).rejects.toThrow(/must be a supported VM.*none/i);
  });

  it.each([
    "deviceView",
    "journaldSocket",
    "rootFilesystem",
    "systemdNotifySocket",
    "unifiedCgroup",
  ])(
    "rejects a VM missing the required %s host primitive",
    async (primitive) => {
      const harness = createProbeHostHarness({
        execute: async () =>
          successfulCommand({
            architecture: "x86_64",
            deviceView: primitive !== "deviceView",
            journaldSocket: primitive !== "journaldSocket",
            operatingSystem: "ubuntu",
            operatingSystemVersion: "24.04",
            pid1: "systemd",
            rootFilesystem: primitive !== "rootFilesystem",
            systemdNotifySocket: primitive !== "systemdNotifySocket",
            unifiedCgroup: primitive !== "unifiedCgroup",
            virtualization: "kvm",
          }),
      });

      await expect(
        harness.assertReleaseTestHost({
          architecture: "x86_64",
          operatingSystem: "ubuntu",
          operatingSystemVersion: "24.04",
        }),
      ).rejects.toThrow(new RegExp(`host primitive.*${primitive}`, "i"));
    },
  );

  it("claims an empty Host atomically and refuses an existing root claim", async () => {
    const commands = [];
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:claim")) {
          return { code: 73, stderr: "Host already claimed", stdout: "" };
        }
        throw new Error("the installer must not run after a rejected claim");
      },
    });

    await harness.assertDisposable("run-claim");
    await expect(
      harness.install(officialEnrollment(), "run-claim"),
    ).rejects.toThrow("Host already claimed");

    const claim = commands.find((command) =>
      command.includes("# enoki-release-e2e:claim"),
    );
    expect(claim).toContain("mkdir -m 0700");
    expect(claim).toContain("# enoki-release-e2e:claim-empty-recheck");
    expect(claim).not.toContain("runs/run-claim");
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-claim-acquire-"));
    const mapped = claim
      .replaceAll("/var/lib/", `${root}/var/lib/`)
      .replaceAll("/run/", `${root}/run/`);
    const token = claim.match(
      /[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/,
    )?.[0];
    expect(token).toMatch(/^[0-9a-f-]{36}$/);
    const active = path.join(root, "var", "lib", "enoki-release-e2e", "claim");
    const acquiring = path.join(
      root,
      "var",
      "lib",
      "enoki-release-e2e",
      "claim-acquiring",
    );
    try {
      await mkdir(active, { recursive: true, mode: 0o700 });
      for (const [name, value] of [
        ["run-id", "run-claim\n"],
        ["token", `${token}\n`],
      ]) {
        await writeFile(path.join(active, name), value, "utf8");
        await chmod(path.join(active, name), 0o600);
      }
      await expect(execFileAsync("sh", ["-c", mapped])).resolves.toMatchObject({
        stdout: "owned\n",
      });
      await mkdir(acquiring, { mode: 0o700 });
      await expect(execFileAsync("sh", ["-c", mapped])).rejects.toMatchObject({
        code: 73,
      });
      await expect(lstat(active)).resolves.toBeDefined();
      await expect(lstat(acquiring)).resolves.toBeDefined();
      await rm(active, { force: true, recursive: true });
      await rm(acquiring, { force: true, recursive: true });
      const unknown = path.join(
        root,
        "var",
        "lib",
        "enoki-release-e2e",
        "foreign",
      );
      await writeFile(unknown, "foreign\n", "utf8");
      await expect(execFileAsync("sh", ["-c", mapped])).rejects.toMatchObject({
        code: 73,
      });
      await expect(lstat(unknown)).resolves.toBeDefined();
      await rm(unknown);
      const lockRoot = path.join(root, "run", "enoki-release-e2e");
      await mkdir(lockRoot, { recursive: true, mode: 0o700 });
      await chmod(lockRoot, 0o755);
      await expect(execFileAsync("sh", ["-c", mapped])).rejects.toMatchObject({
        code: 75,
      });
      await expect(lstat(lockRoot)).resolves.toMatchObject({ mode: 0o40755 });
      await rm(lockRoot, { force: true, recursive: true });
      await chmod(path.dirname(active), 0o755);
      await expect(execFileAsync("sh", ["-c", mapped])).rejects.toMatchObject({
        code: 73,
      });
      await expect(lstat(path.dirname(active))).resolves.toMatchObject({
        mode: 0o40755,
      });
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("refuses a Release Test Host with a pre-existing Enoki installation before mutation", async () => {
    const executions = [];
    const harness = createProbeHostHarness({
      execute: async (command, options) => {
        executions.push({ command, options });
        return {
          code: 0,
          stderr: "",
          stdout: JSON.stringify({
            accounts: { group: true, user: true },
            files: ["/etc/enoki/probe-install.toml"],
            units: ["enoki-probe.service"],
          }),
        };
      },
    });

    await expect(harness.assertDisposable("run-123")).rejects.toThrow(
      /pre-existing Enoki installation.*probe-install\.toml.*enoki-probe\.service/s,
    );
    expect(
      executions.filter(({ command }) =>
        command.includes("# enoki-release-e2e:inventory"),
      ),
    ).toHaveLength(1);
    expect(executions[0].command).toContain("probe-install.toml");
    expect(executions[0].options).toEqual({ root: true });
  });

  it("installs the Hub command once and proves the non-root local privilege boundary", async () => {
    const commands = [];
    let inventoryCount = 0;
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          if (inventoryCount === 1) {
            return successfulCommand({
              accounts: { group: false, user: false },
              files: [],
              units: [],
            });
          }
          return successfulCommand({
            accounts: { group: true, user: true },
            files: [
              "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
              "/var/lib/enoki-probe-bootstrap",
              "/etc/enoki/probe-install.toml",
              "/etc/systemd/system/enoki-probe.service",
              "/usr/local/bin/enoki-probe",
              "/var/lib/enoki-probe",
            ],
            units: ["enoki-probe.service"],
          });
        }
        if (command.includes("# enoki-release-e2e:service-boundary")) {
          return successfulCommandText(
            [
              "LoadState=loaded",
              "ActiveState=active",
              "SubState=running",
              "User=enoki-probe",
              "Group=enoki-probe",
              "FragmentPath=/etc/systemd/system/enoki-probe.service",
            ].join("\n"),
          );
        }
        if (command.includes("# enoki-release-e2e:sudoers-boundary")) {
          return successfulCommandText("");
        }
        if (command.includes("# enoki-release-e2e:binary-version")) {
          return successfulCommandText("enoki-probe v1.2.3\n");
        }
        if (command.includes("# enoki-release-e2e:bootstrap-generation")) {
          return successfulCommandText("1\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:inspect-runtime-failure-custody",
          )
        ) {
          return successfulCommandText("absent\n");
        }
        if (command.includes("# enoki-release-e2e:probe-identity")) {
          return successfulCommand({
            identitySha256: "f".repeat(64),
            probeId: "probe_release_01",
          });
        }
        if (
          command.includes("# enoki-release-e2e:begin-upgrade-ownership") ||
          command.includes("# enoki-release-e2e:bind-upgrade-ownership") ||
          command.includes("# enoki-release-e2e:complete-upgrade-ownership")
        ) {
          return successfulCommandText("owned\n");
        }
        return successfulCommandText(productInstallerOutput());
      },
    });

    await harness.assertDisposable("run-123");
    await harness.install(officialEnrollment(), "run-123");
    const installed = await harness.assertInstalled("run-123", "1.2.3");
    const identity = await harness.readProbeIdentity("run-123");
    await harness.beginUpgradeOwnershipTransition("run-123", "1.2.3");
    await harness.bindUpgradeOwnershipTransition("run-123", {
      acceptedAtMs: null,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "pending",
      targetProbeVersion: "1.2.3",
      updatedAtMs: 1,
    });
    await harness.completeUpgradeOwnershipTransition("run-123", {
      acceptedAtMs: 2,
      completedAtMs: 4,
      createdAtMs: 1,
      failure: null,
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      runningAtMs: 2,
      state: "succeeded",
      targetProbeVersion: "1.2.3",
      updatedAtMs: 4,
    });

    expect(installed.service.User).toBe("enoki-probe");
    expect(installed.service.ActiveState).toBe("active");
    expect(installed.probeVersion).toBe("1.2.3");
    expect(installed.sudoers).toBe("");
    expect(identity).toEqual({
      identitySha256: "f".repeat(64),
      probeId: "probe_release_01",
    });
    expect(
      commands.find((command) =>
        command.includes("# enoki-release-e2e:probe-identity"),
      ),
    ).not.toContain("\\${");
    expect(
      commands.filter((command) =>
        command.includes("# enoki-release-e2e:begin-upgrade-ownership"),
      ),
    ).toHaveLength(1);
    const completedOwnership = commands.find((command) =>
      command.includes("# enoki-release-e2e:complete-upgrade-ownership"),
    );
    expect(completedOwnership).toContain("operation-id");
    expect(completedOwnership).toContain("upgrade-target");
    expect(completedOwnership).toContain(
      'mv -- "$temporary" "$claim/resources"',
    );
    expect(completedOwnership).toContain("schema_version = 2");
    expect(completedOwnership).toContain("! grep -Eq 'sudoers|upgrader'");
    expect(
      commands.filter((command) => command.includes("enk_enroll_secret")),
    ).toHaveLength(1);
  });

  it("reads Bootstrap generation only from its canonical managed root", async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "enoki-e2e-bootstrap-generation-"),
    );
    const managedRoot = path.join(root, "var", "lib", "enoki-probe-bootstrap");
    const generation = path.join(managedRoot, "trust", "delegation-generation");
    const externalRoot = path.join(root, "external");
    const externalGeneration = path.join(
      externalRoot,
      "trust",
      "delegation-generation",
    );
    const mapHostPaths = (command) => command.replaceAll("/var", `${root}/var`);
    const runHostScript = async (command) => {
      try {
        const result = await execFileAsync("sh", ["-c", mapHostPaths(command)]);
        return successfulCommandText(result.stdout);
      } catch (error) {
        return {
          code: typeof error.code === "number" ? error.code : 1,
          stderr: error.stderr ?? error.message,
          stdout: error.stdout ?? "",
        };
      }
    };
    let inventoryCount = 0;
    const harness = createProbeHostHarness({
      execute: async (command) => {
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          return successfulCommand(
            inventoryCount === 1
              ? {
                  accounts: { group: false, user: false },
                  files: [],
                  units: [],
                }
              : {
                  accounts: { group: true, user: true },
                  files: [
                    "/usr/local/bin/enoki-probe",
                    "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
                    "/var/lib/enoki-probe-bootstrap",
                    "/etc/enoki/probe-install.toml",
                    "/etc/systemd/system/enoki-probe.service",
                    "/var/lib/enoki-probe",
                  ],
                  units: ["enoki-probe.service"],
                },
          );
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:service-boundary")) {
          return successfulCommandText(
            "LoadState=loaded\nActiveState=active\nSubState=running\nUser=enoki-probe\nGroup=enoki-probe\nFragmentPath=/etc/systemd/system/enoki-probe.service\n",
          );
        }
        if (command.includes("# enoki-release-e2e:sudoers-boundary")) {
          return successfulCommandText("");
        }
        if (command.includes("# enoki-release-e2e:binary-version")) {
          return successfulCommandText("enoki-probe v1.2.3\n");
        }
        if (command.includes("# enoki-release-e2e:bootstrap-generation")) {
          return runHostScript(command);
        }
        if (command.includes("# enoki-release-e2e:claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:record-resources")) {
          return successfulCommandText("recorded\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:inspect-runtime-failure-custody",
          )
        ) {
          return successfulCommandText("absent\n");
        }
        return successfulCommandText(productInstallerOutput());
      },
    });

    try {
      await mkdir(path.dirname(generation), { recursive: true });
      await chmod(path.join(root, "var", "lib"), 0o755);
      await chmod(managedRoot, 0o700);
      await chmod(path.dirname(generation), 0o700);
      await writeFile(generation, "1\n", "utf8");
      await chmod(generation, 0o600);
      await harness.assertDisposable("run-bootstrap-generation");
      await harness.install(officialEnrollment(), "run-bootstrap-generation");
      await expect(
        harness.assertInstalled("run-bootstrap-generation", "1.2.3"),
      ).resolves.toMatchObject({ delegationGeneration: 1 });

      await mkdir(path.dirname(externalGeneration), { recursive: true });
      await chmod(externalRoot, 0o700);
      await chmod(path.dirname(externalGeneration), 0o700);
      await writeFile(externalGeneration, "2\n", "utf8");
      await chmod(externalGeneration, 0o600);
      await rm(managedRoot, { recursive: true });
      await symlink(externalRoot, managedRoot);
      await expect(
        harness.assertInstalled("run-bootstrap-generation", "1.2.3"),
      ).rejects.toThrow(/delegation generation state is missing or invalid/i);
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("accepts the exact v0.1.74 legacy layout without weakening the Candidate boundary", async () => {
    let collectorSudoersPresent = false;
    let inventoryCount = 0;
    let legacyBoundaryFailure = null;
    const commands = [];
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          if (inventoryCount === 1) {
            return successfulCommand({
              accounts: { group: false, user: false },
              files: [],
              units: [],
            });
          }
          const files = [
            "/usr/local/bin/enoki-probe",
            "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
            "/etc/enoki/probe-install.toml",
            "/etc/systemd/system/enoki-probe.service",
            "/var/lib/enoki-probe",
            "/etc/sudoers.d/enoki-probe-operations",
          ];
          if (collectorSudoersPresent) {
            files.push("/etc/sudoers.d/enoki-probe-collector-helpers");
          }
          return successfulCommand({
            accounts: { group: true, user: true },
            files,
            units: ["enoki-probe.service"],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:service-boundary")) {
          return successfulCommandText(
            "LoadState=loaded\nActiveState=active\nSubState=running\nUser=enoki-probe\nGroup=enoki-probe\nFragmentPath=/etc/systemd/system/enoki-probe.service\n",
          );
        }
        if (command.includes("# enoki-release-e2e:legacy-sudoers-boundary")) {
          const allowsAbsentCollector = command.includes(
            'if [ -e "$collector" ] || [ -L "$collector" ]; then',
          );
          const enforcesExactBoundary =
            command.includes("/usr/sbin/visudo -cf") &&
            command.includes("NOPASSWD: ALL") &&
            command.includes("stat -c %u") &&
            command.includes("internal-upgrader --config") &&
            command.includes(
              "internal-privileged-collector-helper --helper disk-health.smartctl",
            );
          if (!collectorSudoersPresent && !allowsAbsentCollector) {
            return {
              code: 1,
              stderr: "optional legacy collector sudoers is absent",
              stdout: "",
            };
          }
          if (legacyBoundaryFailure === "sudoers" && enforcesExactBoundary) {
            return { code: 1, stderr: "legacy sudoers invalid", stdout: "" };
          }
          return successfulCommandText(
            enforcesExactBoundary
              ? "verified\n"
              : "enoki-probe-uninstaller internal-uninstaller\n",
          );
        }
        if (command.includes("# enoki-release-e2e:legacy-install-metadata")) {
          const enforcesIdentityBoundary =
            command.includes("validate_legacy_install_metadata") &&
            command.includes('id -u "enoki-probe"') &&
            command.includes('id -g "enoki-probe"') &&
            command.includes('stat -c %a "$legacy_identity"') &&
            command.includes('stat -c %h "$legacy_identity"');
          if (
            legacyBoundaryFailure === "identity" &&
            enforcesIdentityBoundary
          ) {
            return { code: 1, stderr: "legacy identity invalid", stdout: "" };
          }
          return successfulCommandText("verified\n");
        }
        if (command.includes("# enoki-release-e2e:binary-version")) {
          return successfulCommandText("enoki-probe v0.1.74\n");
        }
        if (command.includes("# enoki-release-e2e:bootstrap-generation")) {
          return { code: 1, stderr: "not found", stdout: "" };
        }
        return successfulCommandText(productInstallerOutput());
      },
    });

    await harness.assertDisposable("run-legacy-baseline");
    await harness.install(
      {
        enrollmentToken: "enk_enroll_legacy",
        hubUrl: "https://hub.example",
        installCommand:
          "curl -fsSL 'https://hub.example/api/probe/install.sh' | sudo env ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_legacy' bash",
      },
      "run-legacy-baseline",
    );

    await expect(
      harness.assertLegacyReleaseBaselineInstalled(
        "run-legacy-baseline",
        "0.1.74",
      ),
    ).resolves.toMatchObject({
      identityPath: "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
      probeVersion: "0.1.74",
    });
    collectorSudoersPresent = true;
    legacyBoundaryFailure = "sudoers";
    const sudoersMutation = await harness
      .assertLegacyReleaseBaselineInstalled("run-legacy-baseline", "0.1.74")
      .then(
        () => "accepted",
        (error) => error.message,
      );
    legacyBoundaryFailure = "identity";
    const identityMutation = await harness
      .assertLegacyReleaseBaselineInstalled("run-legacy-baseline", "0.1.74")
      .then(
        () => "accepted",
        (error) => error.message,
      );
    expect({ identityMutation, sudoersMutation }).toEqual({
      identityMutation: expect.stringMatching(/metadata boundary.*invalid/i),
      sudoersMutation: expect.stringMatching(/sudoers boundary.*invalid/i),
    });
    legacyBoundaryFailure = null;
    await expect(
      harness.assertInstalled("run-legacy-baseline", "0.1.74"),
    ).rejects.toThrow(/missing \/var\/lib\/enoki-probe-bootstrap/);
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:legacy-install-metadata"),
      ),
    ).toBe(true);
  });

  it("records the exact active v0.1.74 public StateDirectory layout", async () => {
    const fixture = await createLegacyReleaseRecordingFixture(
      "enoki-e2e-legacy-resource-recording-",
    );

    try {
      let inventoryCount = 0;
      let recordResourcesCommand;
      const harness = createProbeHostHarness({
        execute: async (command) => {
          if (command.includes("# enoki-release-e2e:inventory")) {
            inventoryCount += 1;
            return successfulCommand(
              inventoryCount === 1
                ? {
                    accounts: { group: false, user: false },
                    files: [],
                    units: [],
                  }
                : {
                    accounts: { group: true, user: true },
                    files: [
                      "/usr/local/bin/enoki-probe",
                      "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
                      "/etc/enoki/probe-install.toml",
                      "/etc/systemd/system/enoki-probe.service",
                      "/var/lib/enoki-probe",
                      "/etc/sudoers.d/enoki-probe-operations",
                    ],
                    units: ["enoki-probe.service"],
                  },
            );
          }
          if (command.includes("# enoki-release-e2e:dependencies")) {
            return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
          }
          if (command.includes("# enoki-release-e2e:bootstrap-acquire")) {
            await fixture.installLegacyFiles();
            return successfulCommandText(productInstallerOutput());
          }
          if (command.includes("# enoki-release-e2e:claim")) {
            return fixture.runHostScript(command);
          }
          if (command.includes("# enoki-release-e2e:record-resources")) {
            recordResourcesCommand = command;
            return fixture.runHostScript(command);
          }
          if (command.includes("# enoki-release-e2e:service-boundary")) {
            return successfulCommandText(
              "LoadState=loaded\nActiveState=active\nSubState=running\nUser=enoki-probe\nGroup=enoki-probe\nFragmentPath=/etc/systemd/system/enoki-probe.service\n",
            );
          }
          if (command.includes("# enoki-release-e2e:legacy-sudoers-boundary")) {
            return successfulCommandText("verified\n");
          }
          if (command.includes("# enoki-release-e2e:legacy-install-metadata")) {
            return successfulCommandText("verified\n");
          }
          if (command.includes("# enoki-release-e2e:binary-version")) {
            return successfulCommandText("enoki-probe v0.1.74\n");
          }
          return successfulCommandText("");
        },
      });

      await harness.assertDisposable("run-active-legacy-recording");
      await harness.install(
        {
          enrollmentToken: "enk_enroll_legacy",
          hubUrl: "https://hub.example",
          installCommand:
            "curl -fsSL 'https://hub.example/api/probe/install.sh' | sudo env ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_legacy' bash",
        },
        "run-active-legacy-recording",
      );
      const claimDirectory = path.dirname(fixture.paths.claimResources);
      const tokenPath = path.join(claimDirectory, "token");
      const resourcesNext = path.join(claimDirectory, "resources.next");
      const expectedToken = await readFile(tokenPath, "utf8");
      await writeFile(resourcesNext, "pending\n", "utf8");
      await chmod(resourcesNext, 0o600);
      await writeFile(tokenPath, "foreign-token\n", "utf8");
      expect(
        (await fixture.runHostScript(recordResourcesCommand)).code,
      ).not.toBe(0);
      await expect(lstat(resourcesNext)).resolves.toBeDefined();
      await writeFile(tokenPath, expectedToken, "utf8");
      expect(
        (await fixture.runHostScript(recordResourcesCommand)).code,
      ).not.toBe(0);
      await expect(lstat(resourcesNext)).rejects.toMatchObject({
        code: "ENOENT",
      });
      await expect(
        harness.assertLegacyReleaseBaselineInstalled(
          "run-active-legacy-recording",
          "0.1.74",
        ),
      ).resolves.toMatchObject({ probeVersion: "0.1.74" });
    } finally {
      await fixture.remove();
    }
  });

  it("rejects malformed active legacy metadata before recording resources authority", async () => {
    const fixture = await createLegacyReleaseRecordingFixture(
      "enoki-e2e-legacy-resource-rejection-",
    );

    try {
      fixture.environment.ENOKI_ID_GID = "65535";
      fixture.environment.ENOKI_ID_UID = "65535";
      let inventoryCount = 0;
      const harness = createProbeHostHarness({
        execute: async (command) => {
          if (command.includes("# enoki-release-e2e:inventory")) {
            inventoryCount += 1;
            return successfulCommand(
              inventoryCount === 1
                ? {
                    accounts: { group: false, user: false },
                    files: [],
                    units: [],
                  }
                : {
                    accounts: { group: true, user: true },
                    files: [
                      "/usr/local/bin/enoki-probe",
                      "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
                      "/etc/enoki/probe-install.toml",
                      "/etc/systemd/system/enoki-probe.service",
                      "/var/lib/enoki-probe",
                      "/etc/sudoers.d/enoki-probe-operations",
                    ],
                    units: ["enoki-probe.service"],
                  },
            );
          }
          if (command.includes("# enoki-release-e2e:dependencies")) {
            return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
          }
          if (command.includes("# enoki-release-e2e:bootstrap-acquire")) {
            await fixture.installLegacyFiles({
              extraMetadata:
                'schema_version = 2\nbootstrap_state_dir = "/var/lib/enoki-probe-bootstrap"\n',
              identityMode: 0o644,
            });
            return successfulCommandText(productInstallerOutput());
          }
          if (
            command.includes("# enoki-release-e2e:claim") ||
            command.includes("# enoki-release-e2e:record-resources")
          ) {
            return fixture.runHostScript(command);
          }
          return successfulCommandText("");
        },
      });

      await harness.assertDisposable("run-malformed-legacy-recording");
      await expect(
        harness.install(
          {
            enrollmentToken: "enk_enroll_legacy",
            hubUrl: "https://hub.example",
            installCommand:
              "curl -fsSL 'https://hub.example/api/probe/install.sh' | sudo env ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_legacy' bash",
          },
          "run-malformed-legacy-recording",
        ),
      ).rejects.toMatchObject({ code: "probe_resource_recording_failed" });
      await expect(
        readFile(fixture.paths.claimResources, "utf8"),
      ).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await fixture.remove();
    }
  });

  it("rejects an installed Probe binary from a different candidate version", async () => {
    let inventoryCount = 0;
    const harness = createProbeHostHarness({
      execute: async (command) => {
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          if (inventoryCount === 1) {
            return successfulCommand({
              accounts: { group: false, user: false },
              files: [],
              units: [],
            });
          }
          return successfulCommand({
            accounts: { group: true, user: true },
            files: [
              "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
              "/var/lib/enoki-probe-bootstrap",
              "/etc/enoki/probe-install.toml",
              "/etc/systemd/system/enoki-probe.service",
              "/usr/local/bin/enoki-probe",
              "/var/lib/enoki-probe",
            ],
            units: ["enoki-probe.service"],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:service-boundary")) {
          return successfulCommandText(
            "LoadState=loaded\nActiveState=active\nSubState=running\nUser=enoki-probe\nGroup=enoki-probe\nFragmentPath=/etc/systemd/system/enoki-probe.service\n",
          );
        }
        if (command.includes("# enoki-release-e2e:sudoers-boundary")) {
          return successfulCommandText("");
        }
        if (command.includes("# enoki-release-e2e:binary-version")) {
          return successfulCommandText("enoki-probe 9.9.9\n");
        }
        if (command.includes("# enoki-release-e2e:bootstrap-generation")) {
          return successfulCommandText("1\n");
        }
        return successfulCommandText("");
      },
    });

    await harness.assertDisposable("run-version");
    await harness.install(officialEnrollment(), "run-version");
    await expect(
      harness.assertInstalled("run-version", "1.2.3"),
    ).rejects.toThrow(/Probe binary version 9\.9\.9.*Candidate 1\.2\.3/);
  });

  it("uses a run-owned post-replacement fault and the real root-only Probe Repair command", async () => {
    const commands = [];
    const harness = createProbeHostHarness({
      execute: async (command, options) => {
        commands.push({ command, options });
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText(
            '{"curl":"/usr/bin/curl","sudo":"/usr/bin/sudo","systemdRun":"/usr/bin/systemd-run"}\n',
          );
        }
        if (
          command.includes("# enoki-release-e2e:arm-post-replacement-fault")
        ) {
          return successfulCommandText("armed\n");
        }
        if (command.includes("# enoki-release-e2e:post-replacement-failure")) {
          return successfulCommand({
            localFailureCode: "post_replacement_restart_failure",
            operationId: 41,
            probeVersion: "1.2.3",
          });
        }
        if (
          command.includes("# enoki-release-e2e:remove-post-replacement-fault")
        ) {
          return successfulCommandText("removed\n");
        }
        if (command.includes("# enoki-release-e2e:probe-repair")) {
          return successfulCommandText(
            "Probe Repair succeeded: probe=probe_release_01 version=1.2.3\n",
          );
        }
        return successfulCommandText(
          command.includes("# enoki-release-e2e:record-resources")
            ? "recorded\n"
            : "owned\n",
        );
      },
    });
    const pending = {
      acceptedAtMs: null,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "pending",
      targetProbeVersion: "1.2.3",
      updatedAtMs: 1,
    };
    const failed = {
      ...pending,
      acceptedAtMs: 2,
      completedAtMs: 20,
      failure: { code: "running_timeout", message: "timed out" },
      runningAtMs: 2,
      state: "failed",
      updatedAtMs: 20,
    };

    await harness.assertDisposable("run-repair-host");
    await harness.install(officialEnrollment(), "run-repair-host");
    await harness.beginUpgradeOwnershipTransition("run-repair-host", "1.2.3");
    await harness.armPostReplacementRestartFault("run-repair-host", "1.2.3");
    await harness.bindUpgradeOwnershipTransition("run-repair-host", pending);
    await expect(
      harness.assertPostReplacementUpgradeFailure(
        "run-repair-host",
        pending,
        "1.2.3",
      ),
    ).resolves.toMatchObject({
      localFailureCode: "post_replacement_restart_failure",
      probeVersion: "1.2.3",
    });
    await harness.removePostReplacementRestartFault("run-repair-host");
    await harness.repair("run-repair-host");
    await harness.completeRepairOwnershipTransition("run-repair-host", failed);

    const armed = commands.find(({ command }) =>
      command.includes("# enoki-release-e2e:arm-post-replacement-fault"),
    );
    expect(armed.command).toContain("ExecStartPre=/bin/false");
    expect(armed.command).toContain("systemctl is-active enoki-probe.service");
    const boundary = commands.find(({ command }) =>
      command.includes("# enoki-release-e2e:post-replacement-failure"),
    );
    expect(boundary.command).toContain("/usr/local/bin/enoki-probe --version");
    expect(boundary.command).toContain(
      'version=${version_output#"enoki-probe "}',
    );
    expect(boundary.command).toContain("unexpected post-replacement status");
    expect(boundary.command).toContain(
      "candidate Probe service is still active",
    );
    expect(boundary.command).not.toContain("stat -c");
    expect(boundary.command).toContain(
      'error_code = "post_replacement_restart_failure"',
    );
    const repair = commands.find(({ command }) =>
      command.includes("# enoki-release-e2e:probe-repair"),
    );
    expect(
      commands.filter(({ command }) =>
        command.includes("# enoki-release-e2e:probe-repair"),
      ),
    ).toHaveLength(1);
    expect(repair).toEqual({
      command:
        "# enoki-release-e2e:probe-repair\n/usr/local/bin/enoki-probe repair\n",
      options: { root: true },
    });
  });

  it("rejects a transient service failure as Installed Bundle Failure Repair eligibility", async () => {
    const harness = createProbeHostHarness({
      execute: async (command) => {
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText(
            '{"curl":"/usr/bin/curl","sudo":"/usr/bin/sudo","systemdRun":"/usr/bin/systemd-run"}\n',
          );
        }
        if (command.includes("installed-bundle")) {
          return successfulCommand({
            cause: "installed_bundle_restart_failure",
            probeVersion: "1.2.3",
            status: "failed",
          });
        }
        return successfulCommandText(
          command.includes("# enoki-release-e2e:record-resources")
            ? "recorded\n"
            : "owned\n",
        );
      },
    });

    await harness.assertDisposable("run-repair-eligibility");
    await harness.install(officialEnrollment(), "run-repair-eligibility");
    await expect(
      harness.repairInstalledBundleFailure("run-repair-eligibility", "1.2.3"),
    ).rejects.toThrow(/durable Observation Runtime failure eligibility/i);
  });

  it.each([
    [
      "active service state",
      durableRuntimeFailureEvidenceOutput()
        .replace("activeState=failed", "activeState=active")
        .replace("result=start-limit-hit", "result=success")
        .replace("restartCount=2", "restartCount=0"),
    ],
    [
      "ordinary failed result",
      durableRuntimeFailureEvidenceOutput().replace(
        "result=start-limit-hit",
        "result=exit-code",
      ),
    ],
    [
      "free-form failure text",
      `${durableRuntimeFailureEvidenceOutput()}message=start-limit-hit\n`,
    ],
  ])("does not derive Repair authority from %s", async (_label, evidence) => {
    const driver = createInstalledBundleFailureRepairHostDriver({
      assertOwnedRun() {},
      async execute(command) {
        if (
          command.includes(
            "# enoki-release-e2e:exhaust-observation-runtime-budget",
          )
        ) {
          return successfulCommandText(evidence);
        }
        throw new Error("Repair must not run without the exact durable epoch");
      },
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    });

    await expect(
      driver.repair("run-runtime-negative", "1.2.3"),
    ).rejects.toThrow(/durable Observation Runtime failure eligibility/i);
  });

  it.each(["stop", "query"])(
    "fails closed on a Runtime socket %s error before fault cover or Repair",
    async (failureMode) => {
      let exhaustCommand = null;
      let repairCalled = false;
      const driver = createInstalledBundleFailureRepairHostDriver({
        assertOwnedRun() {},
        async execute(command) {
          if (
            command.includes(
              "# enoki-release-e2e:exhaust-observation-runtime-budget",
            )
          ) {
            exhaustCommand = command;
            return {
              code: 79,
              stderr: `Runtime socket ${failureMode} failed\n`,
              stdout: "",
            };
          }
          repairCalled = true;
          return successfulCommandText("");
        },
        ownershipToken: "00000000-0000-4000-8000-000000000001",
      });

      await expect(
        driver.repair("run-runtime-stop-query", "1.2.3"),
      ).rejects.toThrow(/Runtime socket .* failed/);
      expect(repairCalled).toBe(false);

      const fixture = await mkdtemp(
        path.join(os.tmpdir(), "enoki-runtime-stop-query-"),
      );
      try {
        const fakeSystemctl = path.join(fixture, "systemctl");
        const covered = path.join(fixture, "fault-covered");
        await writeFile(
          fakeSystemctl,
          `#!/bin/sh
if [ "$1" = stop ]; then
  [ "$ENOKI_FAILURE_MODE" = stop ] && [ "$2" = enoki-observation-runtime.socket ] && exit 1
  exit 0
fi
if [ "$1" = show ]; then
  [ "$ENOKI_FAILURE_MODE" = query ] && [ "$2" = enoki-observation-runtime.socket ] && exit 1
  printf 'LoadState=loaded\\nActiveState=inactive\\nSubState=dead\\n'
  exit 0
fi
exit 1
`,
          "utf8",
        );
        await chmod(fakeSystemctl, 0o755);
        const helperStart = exhaustCommand.indexOf("read_unit_state() {");
        const helperEnd = exhaustCommand.indexOf('[ -d "$claim" ]');
        const quiescenceStart = exhaustCommand.indexOf(
          "stop_unit enoki-probe.service",
          helperEnd,
        );
        const quiescenceEnd = exhaustCommand.indexOf(
          'systemctl reset-failed "$unit"',
          quiescenceStart,
        );
        const shell = `set -eu
unit=enoki-observation-runtime.service
fail() { printf '%s\\n' "$1" >&2; exit 79; }
${exhaustCommand.slice(helperStart, helperEnd)}
${exhaustCommand.slice(quiescenceStart, quiescenceEnd)}
printf covered > '${covered}'
`;
        await expect(
          execFileAsync("/bin/sh", ["-c", shell], {
            env: {
              ...process.env,
              ENOKI_FAILURE_MODE: failureMode,
              PATH: `${fixture}:/usr/bin:/bin`,
            },
          }),
        ).rejects.toMatchObject({ code: 79 });
        await expect(readFile(covered, "utf8")).rejects.toMatchObject({
          code: "ENOENT",
        });
      } finally {
        await rm(fixture, { force: true, recursive: true });
      }
    },
  );

  it("refuses an unknown claim member before exhaust can publish backup or touch systemd", async () => {
    const fixture = await createRuntimeFailureCustodyFixture(
      "enoki-runtime-exhaust-unknown-member-",
    );
    try {
      const exhaust = await captureRuntimeFailureCommand(
        "exhaust-observation-runtime-budget",
      );
      await writeFile(path.join(fixture.paths.claim, "foreign-member"), "x\n");
      await chmod(path.join(fixture.paths.claim, "foreign-member"), 0o600);

      expect((await fixture.runHostScript(exhaust)).code).not.toBe(0);
      await expect(lstat(fixture.paths.backup)).rejects.toMatchObject({
        code: "ENOENT",
      });
      await expect(
        readFile(fixture.paths.systemctlLog, "utf8"),
      ).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      await fixture.remove();
    }
  });

  it("recovers the exact owner's fixed resources temp before exhaust continues", async () => {
    const fixture = await createRuntimeFailureCustodyFixture(
      "enoki-runtime-exhaust-resources-next-",
    );
    try {
      const exhaust = await captureRuntimeFailureCommand(
        "exhaust-observation-runtime-budget",
      );
      const resourcesNext = path.join(fixture.paths.claim, "resources.next");
      await writeFile(resourcesNext, "interrupted renewal\n");
      await chmod(resourcesNext, 0o600);

      expect((await fixture.runHostScript(exhaust)).code).not.toBe(0);
      await expect(lstat(resourcesNext)).rejects.toMatchObject({
        code: "ENOENT",
      });
      await expect(
        readFile(fixture.paths.systemctlLog, "utf8"),
      ).resolves.toContain("show enoki-observation-runtime.service");
    } finally {
      await fixture.remove();
    }
  });

  it("keeps the fresh canonical Runtime backup target through claim preflight", async () => {
    const fixture = await createRuntimeFailureCustodyFixture(
      "enoki-runtime-fresh-backup-target-",
    );
    let exhaustResult = null;
    try {
      const driver = createInstalledBundleFailureRepairHostDriver({
        assertOwnedRun() {},
        async execute(command) {
          const result = await fixture.runHostScript(command);
          if (
            command.includes(
              "# enoki-release-e2e:exhaust-observation-runtime-budget",
            )
          ) {
            exhaustResult = result;
          }
          return result;
        },
        ownershipToken: "00000000-0000-4000-8000-000000000001",
      });

      await expect(
        driver.repair("run-runtime-custody", "1.2.3"),
      ).rejects.toThrow(/durable Observation Runtime failure eligibility/i);
      expect(exhaustResult.stderr).not.toContain(
        "cp: cannot create regular file '': No such file or directory",
      );
      await expect(readFile(fixture.paths.backup, "utf8")).resolves.toBe(
        "canonical runtime\n",
      );
    } finally {
      await fixture.remove();
    }
  });

  it("discards a partial fixed backup-publication temp before atomically publishing fresh custody", async () => {
    const fixture = await createRuntimeFailureCustodyFixture(
      "enoki-runtime-backup-publication-temp-",
    );
    try {
      const exhaust = await captureRuntimeFailureCommand(
        "exhaust-observation-runtime-budget",
      );
      await writeFile(fixture.paths.backupTemp, "partial copy\n");
      await chmod(fixture.paths.backupTemp, 0o755);

      expect((await fixture.runHostScript(exhaust)).code).not.toBe(0);
      await expect(lstat(fixture.paths.backupTemp)).rejects.toMatchObject({
        code: "ENOENT",
      });
      await expect(readFile(fixture.paths.backup, "utf8")).resolves.toBe(
        "canonical runtime\n",
      );
    } finally {
      await fixture.remove();
    }
  });

  it("rewrites an interrupted fixed restore temp only for the exact active owner", async () => {
    const fixture = await createRuntimeFailureCustodyFixture(
      "enoki-runtime-restore-temp-",
    );
    try {
      const cleanup = await captureRuntimeFailureCommand(
        "cleanup-observation-runtime-failure",
      );
      await writeFile(fixture.paths.backup, "canonical runtime\n");
      await chmod(fixture.paths.backup, 0o755);
      await writeFile(fixture.paths.restoreTemp, "partial copy\n");
      await chmod(fixture.paths.restoreTemp, 0o755);

      expect((await fixture.runHostScript(cleanup)).code).not.toBe(0);
      await expect(lstat(fixture.paths.restoreTemp)).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      await fixture.remove();
    }
  });

  it("retains a foreign fixed restore temp without systemd effects", async () => {
    const fixture = await createRuntimeFailureCustodyFixture(
      "enoki-runtime-restore-temp-foreign-",
    );
    try {
      const cleanup = await captureRuntimeFailureCommand(
        "cleanup-observation-runtime-failure",
      );
      await writeFile(fixture.paths.backup, "canonical runtime\n");
      await chmod(fixture.paths.backup, 0o755);
      await writeFile(fixture.paths.restoreTemp, "foreign\n");
      await chmod(fixture.paths.restoreTemp, 0o644);

      expect((await fixture.runHostScript(cleanup)).code).not.toBe(0);
      await expect(readFile(fixture.paths.restoreTemp, "utf8")).resolves.toBe(
        "foreign\n",
      );
      await expect(
        readFile(fixture.paths.systemctlLog, "utf8"),
      ).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      await fixture.remove();
    }
  });

  it("exhausts the Observation Runtime budget and consumes its durable failure epoch through Repair", async () => {
    const commands = [];
    let inventoryCount = 0;
    const runtimeSha256 = "a".repeat(64);
    const harness = createProbeHostHarness({
      execute: async (command, options) => {
        commands.push({ command, options });
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          if (inventoryCount > 1) {
            return successfulCommand({
              accounts: { group: true, user: true },
              files: [
                "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
                "/var/lib/enoki-probe-bootstrap",
                "/etc/enoki/probe-install.toml",
                "/etc/systemd/system/enoki-probe.service",
                "/usr/local/bin/enoki-probe",
                "/var/lib/enoki-probe",
              ],
              units: ["enoki-probe.service"],
            });
          }
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText(
            '{"curl":"/usr/bin/curl","sudo":"/usr/bin/sudo","systemdRun":"/usr/bin/systemd-run"}\n',
          );
        }
        if (command.includes("# enoki-release-e2e:service-boundary")) {
          return successfulCommandText(
            "LoadState=loaded\nActiveState=active\nSubState=running\nUser=enoki-probe\nGroup=enoki-probe\nFragmentPath=/etc/systemd/system/enoki-probe.service\n",
          );
        }
        if (command.includes("# enoki-release-e2e:sudoers-boundary")) {
          return successfulCommandText("");
        }
        if (command.includes("# enoki-release-e2e:binary-version")) {
          return successfulCommandText("enoki-probe 1.2.3\n");
        }
        if (command.includes("# enoki-release-e2e:bootstrap-generation")) {
          return successfulCommandText("1\n");
        }
        if (command.includes("# enoki-release-e2e:renew-resources")) {
          return successfulCommandText("renewed\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:exhaust-observation-runtime-budget",
          )
        ) {
          return successfulCommandText(
            [
              "activeState=failed",
              "bootId=4f7d3e15-63cc-4d61-8fe4-f5d42773dd51",
              "bundleVersion=1.2.3",
              `epochGeneration=${"b".repeat(64)}`,
              "epochLinks=1",
              "epochMode=600",
              "epochOwner=0",
              "hostId=7",
              `identityReceiptSha256=${"c".repeat(64)}`,
              `installStateSha256=${"d".repeat(64)}`,
              `latchGeneration=${"b".repeat(64)}`,
              "latchLinks=1",
              "latchMode=600",
              "latchOwner=0",
              `manifestSha256=${"e".repeat(64)}`,
              "probeId=probe_release_01",
              "result=start-limit-hit",
              "restartCount=2",
              "role=observation_runtime",
              `runtimeFaultSha256=${"f".repeat(64)}`,
              `runtimeSha256=${runtimeSha256}`,
              "startLimitBurst=3",
              "startLimitIntervalSec=60",
              "unit=enoki-observation-runtime.service",
              `unitSha256=${"1".repeat(64)}`,
              "",
            ].join("\n"),
          );
        }
        if (
          command.includes(
            "# enoki-release-e2e:repair-observation-runtime-failure",
          )
        ) {
          return successfulCommandText(
            [
              "bundleVersion=1.2.3",
              "epochExists=0",
              "faultBackupExists=1",
              "latchExists=0",
              "repairOutput=Probe repair completed.",
              `runtimeSha256=${runtimeSha256}`,
              "unit=enoki-observation-runtime.service",
              "",
            ].join("\n"),
          );
        }
        if (
          command.includes(
            "# enoki-release-e2e:inspect-runtime-failure-custody",
          )
        ) {
          return successfulCommandText("present\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:cleanup-observation-runtime-failure",
          )
        ) {
          return successfulCommandText("recovered=1.2.3\n");
        }
        if (
          command.includes("# enoki-release-e2e:retire-runtime-failure-custody")
        ) {
          return successfulCommandText("retired\n");
        }
        return successfulCommandText(
          command.includes("# enoki-release-e2e:record-resources")
            ? "recorded\n"
            : "owned\n",
        );
      },
    });

    await harness.assertDisposable("run-runtime-repair");
    await harness.install(officialEnrollment(), "run-runtime-repair");
    await expect(
      harness.repairInstalledBundleFailure("run-runtime-repair", "1.2.3"),
    ).resolves.toMatchObject({
      failure: {
        activeState: "failed",
        bundle: { runtimeSha256, version: "1.2.3" },
        failureEpoch: {
          generation: "b".repeat(64),
          hostId: "7",
          ownerUid: 0,
        },
        latch: { generation: "b".repeat(64), ownerUid: 0 },
        recoveryBudget: { observedStarts: 3, startLimitBurst: 3 },
        result: "start-limit-hit",
        role: "observation_runtime",
        status: "latched",
        unit: "enoki-observation-runtime.service",
      },
      repair: {
        failureEpochRemoved: true,
        faultRemoved: true,
        latchRemoved: true,
        runtimeSha256,
        sameBundle: true,
      },
    });

    const exhausted = commands.find(({ command }) =>
      command.includes(
        "# enoki-release-e2e:exhaust-observation-runtime-budget",
      ),
    );
    expect(exhausted.options).toEqual({ root: true });
    expect(exhausted.command).toContain(
      "unit_file=/etc/systemd/system/enoki-observation-runtime.service",
    );
    expect(exhausted.command).toContain(
      "runtime=/usr/local/bin/enoki-observation-runtime",
    );
    expect(exhausted.command).toContain("StartLimitBurst=");
    expect(exhausted.command).toContain('$result" = start-limit-hit');
    const stopProbe = exhausted.command.indexOf(
      "stop_unit enoki-probe.service",
    );
    const stopRuntime = exhausted.command.indexOf('stop_unit "$unit"');
    const installFault = exhausted.command.indexOf(
      'cp --preserve=mode,ownership -- "$temporary" "$runtime"',
    );
    expect(stopProbe).toBeGreaterThan(-1);
    expect(stopRuntime).toBeGreaterThan(stopProbe);
    expect(installFault).toBeGreaterThan(stopRuntime);
    for (const unit of [
      "enoki-probe.service",
      "enoki-observation-runtime.socket",
      '"$unit"',
      "enoki-observation-runtime-failure.service",
    ]) {
      expect(exhausted.command).toContain(`stop_unit ${unit}`);
      expect(exhausted.command).toContain(`require_stopped_unit ${unit}`);
    }
    expect(exhausted.command).toContain(
      'properties=$(systemctl show "$target" --no-pager --property=LoadState --property=ActiveState --property=SubState)',
    );
    expect(exhausted.command).not.toMatch(
      /systemctl stop enoki-observation-runtime\.socket[^\n]*\|\| true/,
    );
    const lastStoppedProof = exhausted.command.lastIndexOf(
      "require_stopped_unit ",
    );
    expect(installFault).toBeGreaterThan(lastStoppedProof);
    expect(exhausted.command).toContain(
      "epoch=/var/lib/enoki-probe/runtime-failure/epoch.toml",
    );
    expect(exhausted.command).toContain(
      "latch=/var/lib/enoki-probe/runtime-failure/latch",
    );
    expect(exhausted.command).not.toContain(
      "runtime=/usr/local/bin/enoki-probe",
    );
    expect(exhausted.command).not.toContain("systemctl is-failed");
    expect(exhausted.command).not.toContain("printf '{");
    await expect(
      execFileAsync("/bin/sh", ["-n", "-c", exhausted.command]),
    ).resolves.toMatchObject({ stderr: "", stdout: "" });
    const repaired = commands.find(({ command }) =>
      command.includes(
        "# enoki-release-e2e:repair-observation-runtime-failure",
      ),
    );
    expect(repaired.command).toContain("/usr/local/bin/enoki-probe repair");
    expect(repaired.command).toContain('[ ! -e "$epoch" ]');
    expect(repaired.command).toContain('[ ! -e "$latch" ]');
    expect(repaired.command).not.toContain('rm -- "$backup"');
    await expect(
      execFileAsync("/bin/sh", ["-n", "-c", repaired.command]),
    ).resolves.toMatchObject({ stderr: "", stdout: "" });
    const renewed = commands.find(({ command }) =>
      command.includes("# enoki-release-e2e:renew-resources"),
    );
    expect(renewed.options).toEqual({ root: true });
    expect(renewed.command).toContain("actual_snapshot=$(fingerprint)");
  });

  it("recovers a durable Observation Runtime fault through the Host driver after process restart", async () => {
    const commands = [];
    let productState = "fresh";
    const driverInput = {
      assertOwnedRun(runId) {
        expect(runId).toBe("run-runtime-recovery");
      },
      async execute(command, options) {
        commands.push({ command, options });
        if (
          command.includes(
            "# enoki-release-e2e:exhaust-observation-runtime-budget",
          )
        ) {
          productState = "exact-pair";
          return successfulCommandText(durableRuntimeFailureEvidenceOutput());
        }
        if (
          command.includes(
            "# enoki-release-e2e:repair-observation-runtime-failure",
          )
        ) {
          productState = "epoch-only";
          return {
            code: 1,
            stderr: "repair interrupted after failure epoch admission",
            stdout: "",
          };
        }
        if (
          command.includes(
            "# enoki-release-e2e:cleanup-observation-runtime-failure",
          )
        ) {
          expect(productState).toBe("epoch-only");
          expect(command).not.toContain("record-runtime-failure");
          expect(command.indexOf('"$companion" retry-runtime')).toBeGreaterThan(
            command.indexOf(
              'cp --preserve=mode,ownership,timestamps -- "$backup" "$runtime"',
            ),
          );
          productState = "consumed";
          return successfulCommandText("recovered=1.2.3\n");
        }
        throw new Error("unexpected production Host command");
      },
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    };
    const interrupted =
      createInstalledBundleFailureRepairHostDriver(driverInput);

    await expect(
      interrupted.repair("run-runtime-recovery", "1.2.3"),
    ).rejects.toThrow("repair interrupted after failure epoch admission");

    const restarted = createInstalledBundleFailureRepairHostDriver(driverInput);
    await expect(restarted.cleanup("run-runtime-recovery")).resolves.toEqual({
      clean: true,
      recoveredBundleVersion: "1.2.3",
    });
    expect(productState).toBe("consumed");
    const cleanup = commands.find(({ command }) =>
      command.includes(
        "# enoki-release-e2e:cleanup-observation-runtime-failure",
      ),
    );
    expect(cleanup.options).toEqual({ root: true });
    expect(cleanup.command).toContain("fail() {");
    expect(cleanup.command).toContain("read_unit_state() {");
    expect(cleanup.command).toContain("stop_unit() {");
    expect(cleanup.command.indexOf("recovered_bundle_version=")).toBeLessThan(
      cleanup.command.indexOf('if [ -f "$backup" ]'),
    );
    expect(cleanup.command).toContain(
      'cp --preserve=mode,ownership,timestamps -- "$backup" "$restore_tmp"',
    );
    expect(cleanup.command).toContain("sync -f /usr/local/bin");
    for (const unit of [
      "enoki-probe.service",
      "enoki-observation-runtime.socket",
      '"$unit"',
      "enoki-observation-runtime-failure.service",
    ]) {
      expect(cleanup.command).toContain(`stop_unit ${unit}`);
      expect(cleanup.command).toContain(`require_stopped_unit ${unit}`);
    }
    expect(cleanup.command).toContain('"$companion" retry-runtime');
    expect(cleanup.command).not.toContain("record-runtime-failure");
    expect(cleanup.command).not.toContain(
      "/var/lib/enoki-probe/runtime-failure/epoch.toml",
    );
    expect(cleanup.command).not.toContain(
      "/var/lib/enoki-probe/runtime-failure/latch",
    );
    expect(cleanup.command).toContain(
      "systemctl start enoki-observation-runtime.socket",
    );
    expect(cleanup.command).toContain("systemctl start enoki-probe.service");
    expect(cleanup.command).toContain(
      "wait_for_unit_state enoki-observation-runtime.socket active listening",
    );
    expect(cleanup.command).toContain(
      "wait_for_unit_state enoki-probe.service active running",
    );
    expect(cleanup.command).toContain(
      'wait_for_unit_state "$unit" active running',
    );
    const stopRuntime = cleanup.command.indexOf('stop_unit "$unit"');
    const runtimeRecovered = cleanup.command.indexOf(
      'wait_for_unit_state "$unit" active running',
    );
    const recorderRecovered = cleanup.command.lastIndexOf(
      "require_stopped_unit enoki-observation-runtime-failure.service",
    );
    const cleaned = cleanup.command.indexOf("printf 'cleaned");
    expect(runtimeRecovered).toBeGreaterThan(stopRuntime);
    expect(recorderRecovered).toBeGreaterThan(runtimeRecovered);
    expect(cleaned).toBeGreaterThan(recorderRecovered);
    expect(cleanup.command).not.toContain('rm -- "$backup"');
    expect(cleanup.command).not.toMatch(
      /runtime-failure\/(?:epoch|latch|retry|receipt)/,
    );
    expect(cleanup.command).not.toMatch(/systemctl stop[^\n]*\|\| true/);
    expect(cleanup.command).not.toMatch(
      /rm .*runtime-failure\/(?:epoch|latch)/,
    );
    await expect(
      execFileAsync("/bin/sh", ["-n", "-c", cleanup.command]),
    ).resolves.toMatchObject({ stderr: "", stdout: "" });
  });

  it("keeps the claim-owned Runtime backup retryable until cleanup recovery succeeds", async () => {
    const cleanupCommands = [];
    let attempt = 0;
    const driverInput = {
      assertOwnedRun() {},
      async execute(command) {
        cleanupCommands.push(command);
        attempt += 1;
        return attempt === 1
          ? {
              code: 79,
              stderr: "could not restart canonical Probe\n",
              stdout: "",
            }
          : successfulCommandText("recovered=1.2.3\n");
      },
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    };
    const driver = createInstalledBundleFailureRepairHostDriver(driverInput);

    await expect(driver.cleanup("run-runtime-cleanup-retry")).rejects.toThrow(
      /could not restart canonical Probe/,
    );
    const restarted = createInstalledBundleFailureRepairHostDriver(driverInput);
    await expect(
      restarted.cleanup("run-runtime-cleanup-retry"),
    ).resolves.toEqual({ clean: true, recoveredBundleVersion: "1.2.3" });
    expect(cleanupCommands).toHaveLength(2);
    expect(cleanupCommands[1]).toBe(cleanupCommands[0]);
    const cleanup = cleanupCommands[0];
    expect(cleanup).not.toContain('rm -- "$backup"');
    expect(cleanup).not.toContain("# enoki-release-e2e:renew-resources");
  });

  it("reenters the fixed Runtime retry entrypoint for a latch with a durable private receipt", async () => {
    let productState = "latch-with-retry-receipt";
    const restarted = createInstalledBundleFailureRepairHostDriver({
      assertOwnedRun() {},
      async execute(command) {
        expect(productState).toBe("latch-with-retry-receipt");
        expect(command).toContain('"$companion" retry-runtime');
        expect(command).not.toMatch(/runtime-failure\/(?:retry|receipt)/);
        productState = "consumed";
        return successfulCommandText("recovered=1.2.3\n");
      },
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    });

    await expect(
      restarted.cleanup("run-runtime-private-receipt"),
    ).resolves.toEqual({ clean: true, recoveredBundleVersion: "1.2.3" });
    expect(productState).toBe("consumed");
  });

  it("renews run ownership only after recovered cleanup passes the installed boundary", async () => {
    const commands = [];
    let inventoryCount = 0;
    const installedInventory = {
      accounts: { group: true, user: true },
      files: [
        "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
        "/var/lib/enoki-probe-bootstrap",
        "/etc/enoki/probe-install.toml",
        "/etc/systemd/system/enoki-probe.service",
        "/usr/local/bin/enoki-probe",
        "/var/lib/enoki-probe",
      ],
      units: ["enoki-probe.service"],
    };
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          return successfulCommand(
            inventoryCount === 1 || inventoryCount === 4
              ? {
                  accounts: { group: false, user: false },
                  files: [],
                  units: [],
                }
              : installedInventory,
          );
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:verify-claim")) {
          return successfulCommandText("owned\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:cleanup-observation-runtime-failure",
          )
        ) {
          return successfulCommandText("recovered=1.2.3\n");
        }
        if (command.includes("# enoki-release-e2e:service-boundary")) {
          return successfulCommandText(
            "LoadState=loaded\nActiveState=active\nSubState=running\nUser=enoki-probe\nGroup=enoki-probe\nFragmentPath=/etc/systemd/system/enoki-probe.service\n",
          );
        }
        if (command.includes("# enoki-release-e2e:sudoers-boundary")) {
          return successfulCommandText("");
        }
        if (command.includes("# enoki-release-e2e:binary-version")) {
          return successfulCommandText("enoki-probe 1.2.3\n");
        }
        if (command.includes("# enoki-release-e2e:bootstrap-generation")) {
          return successfulCommandText("1\n");
        }
        if (
          command.includes("# enoki-release-e2e:capture-resources-snapshot")
        ) {
          return successfulCommandText("asserted-resource-snapshot\n");
        }
        if (command.includes("# enoki-release-e2e:renew-resources")) {
          return successfulCommandText("renewed\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:inspect-runtime-failure-custody",
          )
        ) {
          return successfulCommandText("present\n");
        }
        if (
          command.includes("# enoki-release-e2e:retire-runtime-failure-custody")
        ) {
          return successfulCommandText("retired\n");
        }
        if (command.includes("# enoki-release-e2e:verify-resources")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:inspect-claim")) {
          return successfulCommandText("absent\n");
        }
        if (command.includes("# enoki-release-e2e:record-resources")) {
          return successfulCommandText("recorded\n");
        }
        if (command.includes("# enoki-release-e2e:local-probe-uninstall")) {
          return successfulCommandText("Local Probe Uninstall completed.\n");
        }
        if (command.includes("enk_enroll_secret")) {
          return successfulCommandText(productInstallerOutput());
        }
        return successfulCommandText("");
      },
    });

    await harness.assertDisposable("run-runtime-cleanup-renew");
    await harness.install(officialEnrollment(), "run-runtime-cleanup-renew");
    await expect(harness.cleanup("run-runtime-cleanup-renew")).resolves.toEqual(
      { clean: true, removedPartialInstallation: false },
    );
    const recovered = commands.findIndex((command) =>
      command.includes(
        "# enoki-release-e2e:cleanup-observation-runtime-failure",
      ),
    );
    const installedBoundary = commands.findIndex((command) =>
      command.includes("# enoki-release-e2e:service-boundary"),
    );
    const renewed = commands.findIndex((command) =>
      command.includes("# enoki-release-e2e:renew-resources"),
    );
    const verified = commands.findIndex((command) =>
      command.includes("# enoki-release-e2e:verify-resources"),
    );
    const retired = commands.findIndex((command) =>
      command.includes("# enoki-release-e2e:retire-runtime-failure-custody"),
    );
    const uninstalled = commands.findIndex((command) =>
      command.includes("# enoki-release-e2e:local-probe-uninstall"),
    );
    expect(installedBoundary).toBeGreaterThan(recovered);
    expect(renewed).toBeGreaterThan(installedBoundary);
    expect(verified).toBeGreaterThan(renewed);
    expect(retired).toBeGreaterThan(verified);
    expect(uninstalled).toBeGreaterThan(retired);
  });

  it("rediscovers durable Runtime custody from a fresh Host driver after exact verification is interrupted", async () => {
    const commands = [];
    let custodyPresent = true;
    const driverInput = {
      assertOwnedRun(runId) {
        expect(runId).toBe("run-runtime-custody");
      },
      async execute(command) {
        commands.push(command);
        if (
          command.includes(
            "# enoki-release-e2e:inspect-runtime-failure-custody",
          )
        ) {
          return successfulCommandText(
            custodyPresent ? "present\n" : "absent\n",
          );
        }
        if (
          command.includes("# enoki-release-e2e:retire-runtime-failure-custody")
        ) {
          custodyPresent = false;
          return successfulCommandText("retired\n");
        }
        throw new Error("unexpected production Host command");
      },
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    };
    const interrupted =
      createInstalledBundleFailureRepairHostDriver(driverInput);
    await expect(
      interrupted.inspectCustody("run-runtime-custody"),
    ).resolves.toEqual({
      present: true,
    });
    // The exact claim verification response is lost, so custody is deliberately
    // not retired by this process.
    expect(custodyPresent).toBe(true);

    const restarted = createInstalledBundleFailureRepairHostDriver(driverInput);
    await expect(
      restarted.inspectCustody("run-runtime-custody"),
    ).resolves.toEqual({
      present: true,
    });
    await expect(
      restarted.retireCustody("run-runtime-custody"),
    ).resolves.toEqual({
      retired: true,
    });
    expect(custodyPresent).toBe(false);
    expect(commands).toHaveLength(3);
  });

  it("rejects a changed asserted resource closure before Runtime custody effects", async () => {
    const commands = [];
    let inventoryCount = 0;
    let snapshotCount = 0;
    const installedInventory = {
      accounts: { group: true, user: true },
      files: [
        "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
        "/var/lib/enoki-probe-bootstrap",
        "/etc/enoki/probe-install.toml",
        "/etc/systemd/system/enoki-probe.service",
        "/usr/local/bin/enoki-probe",
        "/var/lib/enoki-probe",
      ],
      units: ["enoki-probe.service"],
    };
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          return successfulCommand(
            inventoryCount === 1
              ? {
                  accounts: { group: false, user: false },
                  files: [],
                  units: [],
                }
              : installedInventory,
          );
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:verify-claim")) {
          return successfulCommandText("owned\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:cleanup-observation-runtime-failure",
          )
        ) {
          return successfulCommandText("recovered=1.2.3\n");
        }
        if (command.includes("# enoki-release-e2e:service-boundary")) {
          return successfulCommandText(
            "LoadState=loaded\nActiveState=active\nSubState=running\nUser=enoki-probe\nGroup=enoki-probe\nFragmentPath=/etc/systemd/system/enoki-probe.service\n",
          );
        }
        if (command.includes("# enoki-release-e2e:sudoers-boundary"))
          return successfulCommandText("");
        if (command.includes("# enoki-release-e2e:binary-version"))
          return successfulCommandText("enoki-probe 1.2.3\n");
        if (command.includes("# enoki-release-e2e:bootstrap-generation"))
          return successfulCommandText("1\n");
        if (
          command.includes("# enoki-release-e2e:capture-resources-snapshot")
        ) {
          snapshotCount += 1;
          return successfulCommandText(
            snapshotCount === 1 ? "closure-before\n" : "closure-after\n",
          );
        }
        if (
          command.includes(
            "# enoki-release-e2e:inspect-runtime-failure-custody",
          )
        )
          return successfulCommandText("present\n");
        if (command.includes("# enoki-release-e2e:renew-resources"))
          return successfulCommandText("renewed\n");
        if (command.includes("# enoki-release-e2e:verify-resources")) {
          return {
            code: 75,
            stderr: "run-owned resource fingerprint changed\n",
            stdout: "",
          };
        }
        if (command.includes("# enoki-release-e2e:inspect-claim"))
          return successfulCommandText("owned\n");
        if (command.includes("# enoki-release-e2e:record-resources"))
          return successfulCommandText("recorded\n");
        if (command.includes("enk_enroll_secret"))
          return successfulCommandText(productInstallerOutput());
        return successfulCommandText("");
      },
    });

    await harness.assertDisposable("run-runtime-custody-failure");
    await harness.install(officialEnrollment(), "run-runtime-custody-failure");
    await expect(
      harness.cleanup("run-runtime-custody-failure"),
    ).rejects.toThrow(/Asserted Probe resource closure changed/);
    for (const marker of [
      "# enoki-release-e2e:renew-resources",
      "# enoki-release-e2e:retire-runtime-failure-custody",
      "# enoki-release-e2e:local-probe-uninstall",
      "# enoki-release-e2e:emergency-cleanup",
      "# enoki-release-e2e:remove-claim",
    ]) {
      expect(commands.some((command) => command.includes(marker))).toBe(false);
    }
  });

  it("does not cross the custody gate when Runtime cleanup commits but its response is lost", async () => {
    const commands = [];
    let inventoryCount = 0;
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          return successfulCommand(
            inventoryCount === 1
              ? {
                  accounts: { group: false, user: false },
                  files: [],
                  units: [],
                }
              : {
                  accounts: { group: true, user: true },
                  files: ["/usr/local/bin/enoki-probe"],
                  units: ["enoki-probe.service"],
                },
          );
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:verify-claim")) {
          return successfulCommandText("owned\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:cleanup-observation-runtime-failure",
          )
        ) {
          return {
            code: 255,
            stderr: "connection lost after remote recovery effect\n",
            stdout: "",
          };
        }
        if (command.includes("# enoki-release-e2e:verify-resources")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:inspect-claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:record-resources")) {
          return successfulCommandText("recorded\n");
        }
        if (command.includes("enk_enroll_secret")) {
          return successfulCommandText(productInstallerOutput());
        }
        return successfulCommandText("");
      },
    });

    await harness.assertDisposable("run-runtime-response-loss");
    await harness.install(officialEnrollment(), "run-runtime-response-loss");
    await expect(harness.cleanup("run-runtime-response-loss")).rejects.toThrow(
      /connection lost after remote recovery effect/,
    );
    expect(inventoryCount).toBe(1);
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:emergency-cleanup"),
      ),
    ).toBe(false);
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:remove-claim"),
      ),
    ).toBe(false);
  });

  it("proves exact uninstall residue while retaining journald and shared dependencies", async () => {
    const dependencies = JSON.stringify({
      curl: "/usr/bin/curl",
      sudo: "/usr/bin/sudo",
      systemdRun: "/usr/bin/systemd-run",
    });
    const harness = createProbeHostHarness({
      execute: async (command) => {
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText(dependencies);
        }
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:journald")) {
          return successfulCommandText(
            "Aug 02 15:00:00 release-host enoki-probe[10]: stopped",
          );
        }
        if (command.includes("# enoki-release-e2e:daemon-reload")) {
          return successfulCommandText("");
        }
        return successfulCommandText("");
      },
    });

    await harness.assertDisposable("run-123");
    await harness.install(officialEnrollment(), "run-123");
    const completion = await harness.verifyUninstallCompletion("run-123");

    expect(completion).toEqual(
      expect.objectContaining({
        clean: true,
        journaldRetained: true,
        sharedDependenciesRetained: true,
      }),
    );
  });

  it("uses the public Local Probe Uninstall command and proves its shared cleanup boundary", async () => {
    const commands = [];
    const dependencies = JSON.stringify({
      curl: "/usr/bin/curl",
      sudo: "/usr/bin/sudo",
      systemdRun: "/usr/bin/systemd-run",
    });
    const harness = createProbeHostHarness({
      execute: async (command, options) => {
        commands.push({ command, options });
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText(dependencies);
        }
        if (command.includes("# enoki-release-e2e:claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:record-resources")) {
          return successfulCommandText("recorded\n");
        }
        if (command.includes("# enoki-release-e2e:daemon-reload")) {
          return successfulCommandText("");
        }
        if (command.includes("# enoki-release-e2e:journald")) {
          return successfulCommandText("retained Probe journal\n");
        }
        if (command.includes("# enoki-release-e2e:local-probe-uninstall")) {
          return successfulCommandText("Local Probe Uninstall completed.\n");
        }
        return successfulCommandText(productInstallerOutput());
      },
    });

    await harness.assertDisposable("run-local-uninstall");
    await harness.install(officialEnrollment(), "run-local-uninstall");
    await expect(
      harness.localUninstall("run-local-uninstall"),
    ).resolves.toMatchObject({
      completion: {
        clean: true,
        journaldRetained: true,
        sharedDependenciesRetained: true,
      },
      output: {
        code: 0,
        stdout: "Local Probe Uninstall completed.\n",
      },
    });
    await harness.install(
      officialEnrollment({ enrollmentToken: "enk_enroll_reenroll" }),
      "run-local-uninstall",
    );
    expect(commands).toContainEqual({
      command:
        "# enoki-release-e2e:local-probe-uninstall\n/usr/local/bin/enoki-probe uninstall\n",
      options: { root: true },
    });
    expect(
      commands.filter(({ command }) =>
        command.includes("# enoki-release-e2e:claim"),
      ),
    ).toHaveLength(1);
    expect(
      commands.some(({ command }) =>
        command.includes("# enoki-release-e2e:renew-resources"),
      ),
    ).toBe(true);
  });

  it("captures an ordinary repeated Add rejection before the installed Probe mutates", async () => {
    const commands = [];
    const state = {
      binarySha256: "a".repeat(64),
      identity: {
        identitySha256: "b".repeat(64),
        probeId: "probe_release_01",
      },
      installMetadataSha256: "c".repeat(64),
      restartCount: 3,
      service: {
        ActiveState: "active",
        LoadState: "loaded",
        SubState: "running",
      },
    };
    const harness = createProbeHostHarness({
      execute: async (command, options) => {
        commands.push({ command, options });
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:record-resources")) {
          return successfulCommandText("recorded\n");
        }
        if (command.includes("# enoki-release-e2e:installed-state")) {
          return successfulCommand(state);
        }
        if (
          command.includes(
            "printf '%s\\n' 'enk_enroll_repeat' | python3 -- ./enoki-probe-bootstrap.py",
          )
        ) {
          return {
            code: 1,
            stderr:
              "Probe Local Lifecycle failed: code=existing_probe_installation message=a pre-existing Enoki Probe installation was found; use Local Probe Uninstall or Host Re-enrollment\nEnoki Probe install failed: staged Probe candidate did not complete the typed Probe Local Lifecycle.\n",
            stdout: "",
          };
        }
        return successfulCommandText(productInstallerOutput());
      },
    });
    const repeatedEnrollment = officialEnrollment({
      enrollmentToken: "enk_enroll_repeat",
      installCommand: bootstrapRecipeCommand("enk_enroll_repeat"),
    });

    await harness.assertDisposable("run-repeat-add");
    await harness.install(officialEnrollment(), "run-repeat-add");
    const before = await harness.captureInstallationState("run-repeat-add");
    await expect(
      harness.rejectRepeatedInstall(repeatedEnrollment, "run-repeat-add"),
    ).resolves.toMatchObject({ code: "existing_probe_installation" });
    const after = await harness.captureInstallationState("run-repeat-add");

    expect(after).toEqual(before);
    expect(commands).toContainEqual({
      command: `# enoki-release-e2e:bootstrap-acquire\nset -eu\n[ "$(id -u)" != 0 ]\n${repeatedEnrollment.installCommand}\n`,
      options: { root: false, sensitive: true },
    });
  });

  it("waits for a permanent report rejection without starting the service again", async () => {
    const commands = [];
    const terminalEvidence = {
      binarySha256: "a".repeat(64),
      identity: {
        identitySha256: "b".repeat(64),
        probeId: "probe_release_02",
      },
      installMetadataSha256: "c".repeat(64),
      restartCountAfterObservation: 4,
      restartCountBeforeObservation: 4,
      service: {
        ActiveState: "failed",
        ExecMainStatus: 78,
        LoadState: "loaded",
        SubState: "failed",
      },
    };
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:record-resources")) {
          return successfulCommandText("recorded\n");
        }
        if (
          command.includes("# enoki-release-e2e:permanent-report-rejection")
        ) {
          return successfulCommand(terminalEvidence);
        }
        return successfulCommandText(productInstallerOutput());
      },
    });

    await harness.assertDisposable("run-terminal-report");
    await harness.install(officialEnrollment(), "run-terminal-report");
    await expect(
      harness.awaitPermanentReportRejection("run-terminal-report"),
    ).resolves.toEqual(terminalEvidence);

    const observation = commands.find((command) =>
      command.includes("# enoki-release-e2e:permanent-report-rejection"),
    );
    expect(observation).toContain("ExecMainStatus");
    expect(observation).toContain("NRestarts");
    expect(observation).toContain("sleep 10");
    expect(observation).not.toContain("systemctl start");
  });

  it("collects redacted terminal diagnostics for the Hub-only deletion boundary", async () => {
    const commands = [];
    let installed = false;
    const diagnostics = {
      binary: { sha256: "a".repeat(64), version: "1.2.3" },
      identity: {
        identitySha256: "b".repeat(64),
        probeId: "probe_release_02",
      },
      installMetadataSha256: "c".repeat(64),
      service: {
        ActiveState: "failed",
        ExecMainStatus: 78,
        LoadState: "loaded",
        NRestarts: 3,
        Result: "exit-code",
        SubState: "failed",
      },
    };
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: installed, user: installed },
            files: installed
              ? ["/usr/local/bin/enoki-probe", "/etc/enoki/probe-install.toml"]
              : [],
            units: installed ? ["enoki-probe.service"] : [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:record-resources")) {
          return successfulCommandText("recorded\n");
        }
        if (command.includes("# enoki-release-e2e:installed-diagnostics")) {
          return successfulCommand(diagnostics);
        }
        if (command.includes("# enoki-release-e2e:journald")) {
          return successfulCommandText(
            "Probe report rejected: code=host_not_found\n",
          );
        }
        if (command.includes("# enoki-release-e2e:installed-sudoers")) {
          return successfulCommandText(
            "enoki-probe ALL=(root) NOPASSWD: /usr/local/bin/enoki-probe-uninstaller\n",
          );
        }
        if (command.includes("# enoki-release-e2e:systemd-diagnostics")) {
          return successfulCommandText(
            "LoadState=loaded\nActiveState=failed\nSubState=failed\n",
          );
        }
        if (command.includes("'enk_enroll_secret' | python3")) installed = true;
        return successfulCommandText(productInstallerOutput());
      },
    });

    await harness.assertDisposable("run-terminal-diagnostics");
    await harness.install(officialEnrollment(), "run-terminal-diagnostics");
    await expect(
      harness.collectDiagnostics("run-terminal-diagnostics"),
    ).resolves.toEqual({
      installation: {
        available: true,
        output: successfulCommand(diagnostics),
        value: diagnostics,
      },
      inventory: {
        available: true,
        output: successfulCommand({
          accounts: { group: true, user: true },
          files: [
            "/usr/local/bin/enoki-probe",
            "/etc/enoki/probe-install.toml",
          ],
          units: ["enoki-probe.service"],
        }),
        value: {
          accounts: { group: true, user: true },
          files: [
            "/usr/local/bin/enoki-probe",
            "/etc/enoki/probe-install.toml",
          ],
          units: ["enoki-probe.service"],
        },
      },
      journald: {
        available: true,
        output: {
          code: 0,
          stderr: "",
          stdout: "Probe report rejected: code=host_not_found\n",
        },
        value: "Probe report rejected: code=host_not_found\n",
      },
      sudoers: {
        available: true,
        output: {
          code: 0,
          stderr: "",
          stdout:
            "enoki-probe ALL=(root) NOPASSWD: /usr/local/bin/enoki-probe-uninstaller\n",
        },
        value:
          "enoki-probe ALL=(root) NOPASSWD: /usr/local/bin/enoki-probe-uninstaller\n",
      },
      systemd: {
        available: true,
        output: {
          code: 0,
          stderr: "",
          stdout: "LoadState=loaded\nActiveState=failed\nSubState=failed\n",
        },
        value: "LoadState=loaded\nActiveState=failed\nSubState=failed\n",
      },
    });
  });

  it("collects successful post-Uninstall systemd, journald, privilege, and filesystem observations", async () => {
    const commands = [];
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:systemd-evidence")) {
          return successfulCommandText(
            "stage=post-uninstall\nLoadState=not-found\nActiveState=inactive\nunitCount=0\nfailedUnitCount=0\n",
          );
        }
        if (command.includes("# enoki-release-e2e:journald")) {
          return successfulCommandText("retained Probe journal\n");
        }
        if (command.includes("# enoki-release-e2e:sudoers-evidence")) {
          return successfulCommandText(
            "stage=post-uninstall\nmanagedSudoersCount=0\n",
          );
        }
        throw new Error("unexpected Host evidence command");
      },
    });

    await expect(harness.collectEvidence("run-evidence")).resolves.toEqual({
      inventory: {
        accounts: { group: false, user: false },
        files: [],
        units: [],
      },
      journald: {
        code: 0,
        stderr: "",
        stdout: "retained Probe journal\n",
      },
      runClaimed: false,
      sudoers: {
        code: 0,
        stderr: "",
        stdout: "stage=post-uninstall\nmanagedSudoersCount=0\n",
      },
      systemd: {
        code: 0,
        stderr: "",
        stdout:
          "stage=post-uninstall\nLoadState=not-found\nActiveState=inactive\nunitCount=0\nfailedUnitCount=0\n",
      },
    });
    const systemd = commands.find((command) =>
      command.includes("# enoki-release-e2e:systemd-evidence"),
    );
    expect(systemd).toContain("set -eu");
    expect(systemd).toContain("stage=post-uninstall");
    expect(systemd).not.toContain("|| true");
    const sudoers = commands.find((command) =>
      command.includes("# enoki-release-e2e:sudoers-evidence"),
    );
    expect(sudoers).toContain("managedSudoersCount=0");
    expect(sudoers).toContain("exit 1");
  });

  it("retains partial component diagnostics before Host ownership is established", async () => {
    const commands = [];
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:installed-diagnostics")) {
          return { code: 1, stderr: "Probe is not installed", stdout: "" };
        }
        if (command.includes("# enoki-release-e2e:journald")) {
          return { code: 1, stderr: "journal unavailable", stdout: "" };
        }
        if (command.includes("# enoki-release-e2e:installed-sudoers")) {
          throw Object.assign(new Error("sudoers collector unavailable"), {
            code: "sudoers_unavailable",
          });
        }
        if (command.includes("# enoki-release-e2e:systemd-diagnostics")) {
          return { code: 1, stderr: "unit not found", stdout: "" };
        }
        throw new Error("unexpected diagnostics command");
      },
    });

    const diagnostics = await harness.collectDiagnostics(
      "run-early-diagnostics",
    );
    expect(diagnostics).toMatchObject({
      installation: {
        available: false,
        error: { code: "diagnostic_command_failed" },
      },
      inventory: {
        available: true,
        value: {
          accounts: { group: false, user: false },
          files: [],
          units: [],
        },
      },
      journald: {
        available: false,
        error: { code: "diagnostic_command_failed" },
      },
      sudoers: {
        available: false,
        error: { code: "sudoers_unavailable" },
      },
      systemd: {
        available: false,
        error: { code: "diagnostic_command_failed" },
      },
    });
    expect(commands).toHaveLength(5);
  });

  it("uses only run-owned emergency infrastructure cleanup for a backup-absent exact claim-bound incomplete installation", async () => {
    const commands = [];
    let inventoryCount = 0;
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          return successfulCommand(
            inventoryCount === 2 || inventoryCount === 3
              ? {
                  accounts: { group: true, user: true },
                  files: [
                    "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
                    "/var/lib/enoki-probe-bootstrap",
                    "/etc/enoki/probe-install.toml",
                    "/etc/systemd/system/enoki-probe.service",
                    "/usr/local/bin/enoki-probe",
                    "/var/lib/enoki-probe",
                  ],
                  units: ["enoki-probe.service"],
                }
              : {
                  accounts: { group: false, user: false },
                  files: [],
                  units: [],
                },
          );
        }
        if (command.includes("# enoki-release-e2e:verify-claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:inspect-claim")) {
          return successfulCommandText("absent\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:cleanup-observation-runtime-failure",
          )
        ) {
          return successfulCommandText("cleaned\n");
        }
        if (
          command.includes("# enoki-release-e2e:claim-bound-bundle-version")
        ) {
          return successfulCommandText("1.2.3\n");
        }
        if (command.includes("# enoki-release-e2e:verify-resources")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:service-boundary")) {
          return successfulCommandText(
            "LoadState=loaded\nActiveState=inactive\nUser=enoki-probe\nGroup=enoki-probe\nFragmentPath=/etc/systemd/system/enoki-probe.service\n",
          );
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("enk_enroll_secret")) {
          return { code: 1, stderr: "interrupted", stdout: "" };
        }
        return successfulCommandText("");
      },
    });
    await harness.assertDisposable("run-partial");
    await expect(
      harness.install(officialEnrollment(), "run-partial"),
    ).rejects.toMatchObject({
      code: "probe_installation_failed",
      installerEvidence: { code: 1, stderr: "interrupted" },
    });

    await expect(harness.cleanup("run-partial")).resolves.toEqual({
      clean: true,
      removedPartialInstallation: true,
    });
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:emergency-cleanup"),
      ),
    ).toBe(true);
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:verify-resources"),
      ),
    ).toBe(true);
    const emergency = commands.find((command) =>
      command.includes("# enoki-release-e2e:emergency-cleanup"),
    );
    expect(emergency).toContain('cat "$claim/run-id"');
    expect(emergency).toContain('cat "$claim/token"');
    expect(emergency).toContain('fingerprint > "$temporary"');
    expect(emergency).toContain("sha256sum");
    expect(emergency).toContain("find -P");
    expect(emergency).toContain("stat -c");
    expect(emergency).not.toContain("expected_resource()");
    expect(emergency).not.toContain('done < "$claim/resources"');
    expect(
      commands.some((command) => command.includes("ENOKI_UNINSTALL")),
    ).toBe(false);
  });

  it("only removes a run-owned StateDirectory after the service is quiescent", async () => {
    const outcomes = [];
    for (const scenario of [
      "normal",
      "partial-before-cleanup",
      "private-state-link-before-cleanup",
      "content-before-cleanup",
      "content-after-outer-verify",
      "query-failure",
      "stop-failure",
      "insert-after-stop",
    ]) {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "enoki-e2e-emergency-cleanup-"),
      );
      const fakeBin = path.join(root, "fake-bin");
      const publicParent = path.join(root, "var", "lib");
      const privateParent = path.join(publicParent, "private");
      const publicState = path.join(publicParent, "enoki-probe");
      const privateState = path.join(privateParent, "enoki-probe");
      const identity = path.join(privateState, "identity");
      const config = path.join(identity, "probe-bootstrap.toml");
      const adjacent = path.join(privateParent, "external", "data");
      const serviceState = path.join(root, "service-state");
      const insertedMember = path.join(privateState, "inserted-after-stop");
      const environment = {
        ...process.env,
        ENOKI_INSERTED_MEMBER: insertedMember,
        ENOKI_SERVICE_SCENARIO: scenario,
        ENOKI_SERVICE_STATE: serviceState,
        PATH: `${fakeBin}:${process.env.PATH}`,
      };
      const mapHostPaths = (command) =>
        command
          .replaceAll("/var/lib/", `${root}/var/lib/`)
          .replaceAll("/usr/local/bin/", `${root}/usr/local/bin/`)
          .replaceAll("/etc/", `${root}/etc/`)
          .replaceAll("/run/", `${root}/run/`);
      const runHostScript = async (command) => {
        try {
          const result = await execFileAsync(
            "sh",
            ["-c", mapHostPaths(command)],
            { env: environment },
          );
          return successfulCommandText(result.stdout);
        } catch (error) {
          return {
            code: typeof error.code === "number" ? error.code : 1,
            stderr: error.stderr ?? error.message,
            stdout: error.stdout ?? "",
          };
        }
      };

      try {
        await mkdir(fakeBin, { recursive: true });
        for (const command of ["groupdel", "userdel"]) {
          const executable = path.join(fakeBin, command);
          await writeFile(executable, "#!/bin/sh\nexit 0\n", "utf8");
          await chmod(executable, 0o755);
        }
        const systemctl = path.join(fakeBin, "systemctl");
        await writeFile(
          systemctl,
          `#!/bin/sh
case "$1" in
  show)
    [ "$ENOKI_SERVICE_SCENARIO" != query-failure ] || exit 1
    printf 'LoadState=loaded\\nActiveState=%s\\n' "$(cat "$ENOKI_SERVICE_STATE")"
    ;;
  disable)
    [ "$ENOKI_SERVICE_SCENARIO" != stop-failure ] || exit 1
    if [ "$ENOKI_SERVICE_SCENARIO" = insert-after-stop ]; then
      printf 'unrecorded' > "$ENOKI_INSERTED_MEMBER"
    fi
    printf inactive > "$ENOKI_SERVICE_STATE"
    ;;
esac
exit 0
`,
          "utf8",
        );
        await chmod(systemctl, 0o755);
        await writeFile(serviceState, "active", "utf8");
        const harness = createProbeHostHarness({
          execute: async (command) => {
            if (command.includes("# enoki-release-e2e:dependencies")) {
              return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
            }
            if (command.includes("# enoki-release-e2e:bootstrap-acquire")) {
              await mkdir(identity, { recursive: true });
              await mkdir(path.dirname(adjacent), { recursive: true });
              await chmod(publicParent, 0o755);
              await chmod(privateParent, 0o700);
              await chmod(privateState, 0o750);
              await chmod(identity, 0o700);
              await writeFile(
                path.join(identity, "probe-bootstrap.toml"),
                "identity",
                "utf8",
              );
              await chmod(path.join(identity, "probe-bootstrap.toml"), 0o600);
              await writeFile(adjacent, "preserved", "utf8");
              await symlink("private/enoki-probe", publicState);
              return successfulCommandText(productInstallerOutput());
            }
            if (
              command.includes(
                "# enoki-release-e2e:cleanup-observation-runtime-failure",
              )
            ) {
              return successfulCommandText("cleaned\n");
            }
            if (
              scenario === "content-after-outer-verify" &&
              command.includes("# enoki-release-e2e:emergency-cleanup")
            ) {
              await writeFile(config, "changed identity", "utf8");
            }
            return runHostScript(command);
          },
        });

        const runId = `run-private-state-cleanup-${scenario}`;
        await harness.assertDisposable(runId);
        await harness.install(officialEnrollment(), runId);
        if (scenario === "partial-before-cleanup") {
          await rm(identity, { force: true, recursive: true });
        }
        if (scenario === "content-before-cleanup") {
          await writeFile(config, "changed identity", "utf8");
        }
        if (scenario === "private-state-link-before-cleanup") {
          await rm(privateState, { force: true, recursive: true });
          await symlink("../external", privateState);
        }
        let clean = true;
        try {
          await harness.cleanup(runId);
        } catch {
          clean = false;
        }
        if (scenario === "content-after-outer-verify") {
          expect(await readFile(serviceState, "utf8")).toBe("active");
        }
        const present = (candidate) =>
          lstat(candidate).then(
            () => true,
            (error) =>
              error.code === "ENOENT" ? false : Promise.reject(error),
          );
        outcomes.push({
          clean,
          projection: await Promise.all([
            present(publicState),
            present(privateState),
            present(identity),
          ]),
          scenario,
          adjacent: await readFile(adjacent, "utf8"),
        });
      } finally {
        await rm(root, { force: true, recursive: true });
      }
    }

    expect(outcomes).toEqual([
      {
        adjacent: "preserved",
        clean: true,
        projection: [false, false, false],
        scenario: "normal",
      },
      {
        adjacent: "preserved",
        clean: true,
        projection: [false, false, false],
        scenario: "partial-before-cleanup",
      },
      {
        adjacent: "preserved",
        clean: false,
        projection: [true, true, false],
        scenario: "private-state-link-before-cleanup",
      },
      ...[
        "content-before-cleanup",
        "content-after-outer-verify",
        "query-failure",
        "stop-failure",
        "insert-after-stop",
      ].map((scenario) => ({
        adjacent: "preserved",
        clean: false,
        projection: [true, true, true],
        scenario,
      })),
    ]);
  });

  it("retains successful installer evidence when run-resource recording fails", async () => {
    const harness = createProbeHostHarness({
      execute: async (command) => {
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:record-resources")) {
          return { code: 1, stderr: "resource recording failed", stdout: "" };
        }
        return successfulCommandText(productInstallerOutput());
      },
    });

    await harness.assertDisposable("run-recording-failure");
    await expect(
      harness.install(officialEnrollment(), "run-recording-failure"),
    ).rejects.toMatchObject({
      code: "probe_resource_recording_failed",
      installerEvidence: {
        code: 0,
        stdout: expect.stringContaining("ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE"),
      },
    });
  });

  it("retains command evidence when a diagnostic parser rejects its output", async () => {
    const harness = createProbeHostHarness({
      execute: async (command) => {
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:installed-diagnostics")) {
          return successfulCommandText("not-json");
        }
        return { code: 1, stderr: "unavailable", stdout: "" };
      },
    });

    await expect(
      harness.collectDiagnostics("run-diagnostic-parser-failure"),
    ).resolves.toMatchObject({
      installation: {
        available: false,
        error: { message: expect.stringContaining("was not valid JSON") },
        output: { code: 0, stderr: "", stdout: "not-json" },
      },
    });
  });

  it("releases the run claim and independently verifies a normally clean Release Test Host", async () => {
    const commands = [];
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          return successfulCommand({
            accounts: { group: false, user: false },
            files: [],
            units: [],
          });
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:verify-claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:inspect-claim")) {
          return successfulCommandText("absent\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:cleanup-observation-runtime-failure",
          )
        ) {
          return successfulCommandText("cleaned\n");
        }
        return successfulCommandText("recorded\n");
      },
    });

    await harness.assertDisposable("run-clean-release");
    await harness.install(officialEnrollment(), "run-clean-release");
    await expect(harness.cleanup("run-clean-release")).resolves.toEqual({
      clean: true,
      removedPartialInstallation: false,
    });
    await expect(harness.verifyClean("run-clean-release")).resolves.toEqual({
      clean: true,
      inventory: {
        accounts: { group: false, user: false },
        files: [],
        units: [],
      },
    });
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:remove-claim"),
      ),
    ).toBe(true);
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:verify-clean"),
      ),
    ).toBe(false);
    expect(
      commands.filter((command) =>
        command.includes("# enoki-release-e2e:daemon-reload"),
      ),
    ).toHaveLength(1);

    const retireClaim = commands.find((command) =>
      command.includes("# enoki-release-e2e:remove-claim"),
    );
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-claim-retire-"));
    const claimRoot = path.join(root, "var", "lib", "enoki-release-e2e");
    const activeClaim = path.join(claimRoot, "claim");
    const retiringClaim = path.join(claimRoot, "claim-retiring");
    const mapped = retireClaim
      .replaceAll("/var/lib/", `${root}/var/lib/`)
      .replaceAll("/run/", `${root}/run/`);
    const token = retireClaim.match(/\$\(cat "\$1\/token"\)" = '([^']+)'/)?.[1];
    expect(token).toMatch(/^[0-9a-f-]{36}$/);
    const writeClaim = async (directory, { unknown = false } = {}) => {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      for (const [name, value] of [
        ["run-id", "run-clean-release\n"],
        ["token", `${token}\n`],
        ["resources", "exact-resource-evidence\n"],
      ]) {
        const target = path.join(directory, name);
        await writeFile(target, value, "utf8");
        await chmod(target, 0o600);
      }
      if (unknown) {
        const target = path.join(directory, "foreign-member");
        await writeFile(target, "foreign\n", "utf8");
        await chmod(target, 0o600);
      }
    };
    try {
      await writeClaim(activeClaim);
      const mappedProduct = path.join(root, "var", "lib", "enoki-probe");
      await mkdir(mappedProduct, { recursive: true, mode: 0o750 });
      await expect(execFileAsync("sh", ["-c", mapped])).rejects.toMatchObject({
        code: 79,
      });
      await expect(
        readFile(path.join(activeClaim, "resources"), "utf8"),
      ).resolves.toBe("exact-resource-evidence\n");
      await rm(mappedProduct, { force: true, recursive: true });
      await expect(execFileAsync("sh", ["-c", mapped])).resolves.toMatchObject({
        stdout: "released\n",
      });
      await expect(lstat(activeClaim)).rejects.toMatchObject({
        code: "ENOENT",
      });
      await expect(lstat(retiringClaim)).rejects.toMatchObject({
        code: "ENOENT",
      });

      await writeClaim(retiringClaim);
      await expect(execFileAsync("sh", ["-c", mapped])).resolves.toMatchObject({
        stdout: "released\n",
      });
      await expect(lstat(retiringClaim)).rejects.toMatchObject({
        code: "ENOENT",
      });

      // 重启时 slot 已经落在合法后缀，仍只能继续既定删除顺序。
      await writeClaim(retiringClaim);
      await unlink(path.join(retiringClaim, "resources"));
      await unlink(path.join(retiringClaim, "token"));
      await expect(execFileAsync("sh", ["-c", mapped])).resolves.toMatchObject({
        stdout: "released\n",
      });
      await expect(lstat(retiringClaim)).rejects.toMatchObject({
        code: "ENOENT",
      });

      await writeClaim(retiringClaim);
      await unlink(path.join(retiringClaim, "resources"));
      await unlink(path.join(retiringClaim, "run-id"));
      await expect(execFileAsync("sh", ["-c", mapped])).resolves.toMatchObject({
        stdout: "released\n",
      });
      await expect(lstat(retiringClaim)).rejects.toMatchObject({
        code: "ENOENT",
      });

      await writeClaim(activeClaim, { unknown: true });
      await expect(execFileAsync("sh", ["-c", mapped])).rejects.toMatchObject({
        code: 79,
      });
      await expect(
        readFile(path.join(activeClaim, "run-id"), "utf8"),
      ).resolves.toBe("run-clean-release\n");

      await rm(activeClaim, { force: true, recursive: true });
      await writeClaim(activeClaim);
      await writeClaim(retiringClaim);
      await expect(execFileAsync("sh", ["-c", mapped])).rejects.toMatchObject({
        code: 79,
      });
      await expect(
        readFile(path.join(activeClaim, "token"), "utf8"),
      ).resolves.toBe(`${token}\n`);
      await expect(
        readFile(path.join(retiringClaim, "token"), "utf8"),
      ).resolves.toBe(`${token}\n`);
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("reenters an atomically retired claim through the existing cleanup action", async () => {
    const commands = [];
    let retiring = true;
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:verify-claim")) {
          return { code: 1, stderr: "active claim is absent\n", stdout: "" };
        }
        if (command.includes("# enoki-release-e2e:inspect-claim")) {
          return successfulCommandText(
            retiring ? "retiring-owned\n" : "absent\n",
          );
        }
        if (command.includes("# enoki-release-e2e:remove-claim")) {
          retiring = false;
          return successfulCommandText("released\n");
        }
        throw new Error("unexpected Host action after claim retirement");
      },
      ownershipToken: "00000000-0000-4000-8000-000000000001",
    });

    await expect(harness.cleanup("run-retiring-claim")).resolves.toEqual({
      clean: true,
      removedPartialInstallation: false,
    });
    expect(retiring).toBe(false);
    expect(
      commands.some((command) =>
        command.includes(
          "# enoki-release-e2e:cleanup-observation-runtime-failure",
        ),
      ),
    ).toBe(false);
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:emergency-cleanup"),
      ),
    ).toBe(false);
  });

  it("aggregates a cleanup failure while continuing run-owned fault removal, uninstall, residue verification, and claim release", async () => {
    const commands = [];
    let inventoryCount = 0;
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          return successfulCommand(
            inventoryCount === 2
              ? {
                  accounts: { group: true, user: true },
                  files: ["/usr/local/bin/enoki-probe"],
                  units: ["enoki-probe.service"],
                }
              : {
                  accounts: { group: false, user: false },
                  files: [],
                  units: [],
                },
          );
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:verify-claim")) {
          return successfulCommandText("owned\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:cleanup-observation-runtime-failure",
          )
        ) {
          return successfulCommandText("cleaned\n");
        }
        if (
          command.includes("# enoki-release-e2e:arm-post-replacement-fault")
        ) {
          return successfulCommandText("armed\n");
        }
        if (
          command.includes("# enoki-release-e2e:remove-post-replacement-fault")
        ) {
          return { code: 70, stderr: "drop-in removal failed", stdout: "" };
        }
        if (command.includes("# enoki-release-e2e:verify-resources")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:inspect-claim")) {
          return successfulCommandText("absent\n");
        }
        return successfulCommandText("");
      },
    });

    await harness.assertDisposable("run-aggregate-cleanup");
    await harness.install(officialEnrollment(), "run-aggregate-cleanup");
    await harness.armPostReplacementRestartFault(
      "run-aggregate-cleanup",
      "1.2.3",
    );

    const failure = await harness
      .cleanup("run-aggregate-cleanup")
      .catch((error) => error);

    expect(failure).toBeInstanceOf(AggregateError);
    expect(failure.errors.map((error) => error.message)).toContain(
      "Run-owned post-replacement fault cleanup failed: drop-in removal failed",
    );
    for (const marker of [
      "# enoki-release-e2e:remove-post-replacement-fault",
      "# enoki-release-e2e:verify-resources",
      "# enoki-release-e2e:daemon-reload",
      "# enoki-release-e2e:remove-claim",
      "# enoki-release-e2e:inspect-claim",
    ]) {
      expect(commands.some((command) => command.includes(marker))).toBe(true);
    }
  });

  it.each([
    ["a same-path file replacement"],
    ["an added member in a recorded directory"],
    ["a recorded owner or mode change"],
  ])("refuses emergency cleanup after %s", async () => {
    const commands = [];
    let inventoryCount = 0;
    const harness = createProbeHostHarness({
      execute: async (command) => {
        commands.push(command);
        if (command.includes("# enoki-release-e2e:inventory")) {
          inventoryCount += 1;
          return successfulCommand(
            inventoryCount === 1
              ? {
                  accounts: { group: false, user: false },
                  files: [],
                  units: [],
                }
              : {
                  accounts: { group: true, user: true },
                  files: ["/usr/local/bin/enoki-probe"],
                  units: ["enoki-probe.service"],
                },
          );
        }
        if (command.includes("# enoki-release-e2e:dependencies")) {
          return successfulCommandText('{"curl":"/usr/bin/curl"}\n');
        }
        if (command.includes("# enoki-release-e2e:verify-claim")) {
          return successfulCommandText("owned\n");
        }
        if (
          command.includes(
            "# enoki-release-e2e:cleanup-observation-runtime-failure",
          )
        ) {
          return successfulCommandText("cleaned\n");
        }
        if (command.includes("# enoki-release-e2e:verify-resources")) {
          return {
            code: 75,
            stderr: "run-owned resource fingerprint changed\n",
            stdout: "",
          };
        }
        if (command.includes("# enoki-release-e2e:inspect-claim")) {
          return successfulCommandText("owned\n");
        }
        return successfulCommandText("recorded\n");
      },
    });

    await harness.assertDisposable("run-foreign-change");
    await harness.install(officialEnrollment(), "run-foreign-change");

    await expect(harness.cleanup("run-foreign-change")).rejects.toThrow(
      /fingerprint changed/,
    );
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:emergency-cleanup"),
      ),
    ).toBe(false);
    expect(
      commands.some((command) =>
        command.includes("# enoki-release-e2e:remove-claim"),
      ),
    ).toBe(false);
  });
});

describe("Hub Lifecycle Client", () => {
  it("creates an ExistingHost Enrollment through the authenticated Owner API", async () => {
    const requests = [];
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: async (url, init = {}) => {
        const pathname = new URL(url).pathname;
        requests.push({
          body: init.body ?? null,
          cookie: new Headers(init.headers).get("cookie"),
          method: init.method ?? "GET",
          pathname,
        });
        if (pathname === "/api/web/auth/login") {
          return jsonResponse({ authenticated: true }, 200, {
            "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
          });
        }
        if (pathname === "/api/web/enrollments") {
          return jsonResponse(
            {
              ...officialEnrollment({
                enrollmentToken: "enk_enroll_release_e2e_test_token",
              }),
              enrollmentId: "enr_existing_host_0001",
              status: "pending",
              target: { hostId: 7, kind: "existing_host" },
            },
            201,
          );
        }
        throw new Error(`unexpected request ${pathname}`);
      },
    });

    await client.authenticate("owner-password");
    await expect(
      client.createEnrollment({ hostId: 7, kind: "existing_host" }),
    ).resolves.toMatchObject({
      enrollmentId: "enr_existing_host_0001",
      target: { hostId: 7, kind: "existing_host" },
    });
    expect(requests).toContainEqual({
      body: JSON.stringify({ target: { hostId: 7, kind: "existing_host" } }),
      cookie: "enoki_owner_session=session-1",
      method: "POST",
      pathname: "/api/web/enrollments",
    });
  });

  it("deletes a Host through the production Hub-only Owner API", async () => {
    const requests = [];
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: async (url, init = {}) => {
        const parsed = new URL(url);
        requests.push({
          cookie: new Headers(init.headers).get("cookie"),
          method: init.method ?? "GET",
          pathname: parsed.pathname,
          search: parsed.search,
        });
        if (parsed.pathname === "/api/web/auth/login") {
          return jsonResponse({ authenticated: true }, 200, {
            "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
          });
        }
        if (parsed.pathname === "/api/web/hosts/7") {
          return jsonResponse(
            { deletedHost: { deletedAtMs: 1_725_000_000_000, id: 7 } },
            200,
          );
        }
        throw new Error(`unexpected request ${parsed.pathname}`);
      },
    });

    await client.authenticate("owner-password");
    await expect(client.deleteHostHubOnly(7)).resolves.toEqual({
      deletedAtMs: 1_725_000_000_000,
      id: 7,
    });
    expect(requests).toContainEqual({
      cookie: "enoki_owner_session=session-1",
      method: "DELETE",
      pathname: "/api/web/hosts/7",
      search: "?mode=hub-only",
    });
  });

  it("以精确 Hub Origin 请求卸载探针", async () => {
    const requests = [];
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example:8443",
      fetch: async (url, init = {}) => {
        const parsed = new URL(url);
        requests.push({
          method: init.method ?? "GET",
          origin: new Headers(init.headers).get("origin"),
          pathname: parsed.pathname,
        });
        if (parsed.pathname === "/api/web/hosts/7") {
          return jsonResponse(
            {
              probeUninstallRequest: {
                acceptedAtMs: null,
                completedAtMs: null,
                createdAtMs: 1_725_000_000_000,
                failure: null,
                id: 42,
                runningAtMs: null,
                state: "pending",
                targetProbeVersion: "1.2.3",
                updatedAtMs: 1_725_000_000_000,
              },
            },
            202,
          );
        }
        throw new Error(`unexpected request ${parsed.pathname}`);
      },
    });

    await expect(client.requestProbeUninstall(7)).resolves.toMatchObject({
      hostId: 7,
      id: 42,
      kind: "probe_uninstall",
      state: "pending",
    });
    expect(requests).toEqual([
      {
        method: "DELETE",
        origin: "https://hub.example:8443",
        pathname: "/api/web/hosts/7",
      },
    ]);
  });

  it("reads the terminal typed rejection for the matching Enrollment", async () => {
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: async (url, init = {}) => {
        const pathname = new URL(url).pathname;
        if (pathname === "/api/web/auth/login") {
          return jsonResponse({ authenticated: true }, 200, {
            "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
          });
        }
        if (pathname === "/api/web/enrollments/enr_repeated_add_0001") {
          return jsonResponse({
            enrollmentId: "enr_repeated_add_0001",
            hostId: null,
            rejection: {
              code: "existing_probe_installation",
              message: "existing local Probe installation detected",
            },
            status: "rejected",
            target: { kind: "new_host" },
          });
        }
        throw new Error(
          `unexpected request ${pathname} ${init.method ?? "GET"}`,
        );
      },
    });

    await client.authenticate("owner-password");
    await expect(
      client.getEnrollment("enr_repeated_add_0001"),
    ).resolves.toMatchObject({
      enrollmentId: "enr_repeated_add_0001",
      rejection: { code: "existing_probe_installation" },
      status: "rejected",
      target: { kind: "new_host" },
    });
  });

  it("authorizes Probe Upgrade once through the authenticated Owner API", async () => {
    const requests = [];
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: async (url, init = {}) => {
        const pathname = new URL(url).pathname;
        requests.push({
          cookie: new Headers(init.headers).get("cookie"),
          method: init.method ?? "GET",
          pathname,
        });
        if (pathname === "/api/web/auth/login") {
          return jsonResponse({ authenticated: true }, 200, {
            "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
          });
        }
        if (pathname === "/api/web/hosts/7/probe-upgrade-requests") {
          return jsonResponse(
            {
              probeUpgradeRequest: {
                acceptedAtMs: null,
                completedAtMs: null,
                createdAtMs: 1,
                failure: null,
                id: 41,
                runningAtMs: null,
                state: "pending",
                targetProbeVersion: "1.2.3",
                updatedAtMs: 1,
              },
            },
            201,
          );
        }
        throw new Error(`unexpected request ${pathname}`);
      },
    });

    await client.authenticate("owner-password");
    await expect(client.requestProbeUpgrade(7)).resolves.toMatchObject({
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      state: "pending",
      targetProbeVersion: "1.2.3",
    });
    expect(
      requests.filter(
        ({ method, pathname }) =>
          method === "POST" &&
          pathname === "/api/web/hosts/7/probe-upgrade-requests",
      ),
    ).toEqual([
      expect.objectContaining({
        cookie: "enoki_owner_session=session-1",
      }),
    ]);
  });

  it("通过生产 Owner API 创建 Trust Epoch manual reinstall Enrollment", async () => {
    const requests = [];
    const sourceProbeSha256 = ["a", "b", "c", "d"].map((value) =>
      value.repeat(64),
    );
    const replacementMigration = {
      enrollmentId: "enr_manual_reinstall_0001",
      expectedProbeId: "probe_release_legacy",
      sourceProbeSha256,
      sourceProbeVersion: "0.1.74",
      targetAssetSetDigest: `sha256:${"b".repeat(64)}`,
      targetHostId: "7",
      targetProbeVersion: "1.2.3",
    };
    const installCommand = bootstrapRecipeCommand({
      hubOrigin: "https://hub.example",
      enrollmentToken: "enk_enroll_secret",
      replacementMigration,
      schemaVersion: 1,
    });
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: async (url, init = {}) => {
        const pathname = new URL(url).pathname;
        requests.push({
          body: init.body,
          contentType: new Headers(init.headers).get("content-type"),
          method: init.method ?? "GET",
          pathname,
        });
        if (pathname === "/api/web/auth/login") {
          return jsonResponse({ authenticated: true }, 200, {
            "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
          });
        }
        if (pathname === "/api/web/enrollments/manual-reinstall/7") {
          return jsonResponse(
            {
              ...officialEnrollment(),
              enrollmentId: "enr_manual_reinstall_0001",
              installCommand,
              target: { hostId: 7, kind: "manual_reinstall" },
            },
            201,
          );
        }
        throw new Error(`unexpected request ${pathname}`);
      },
      replacementSourceProbeSha256: sourceProbeSha256,
    });

    await client.authenticate("owner-password");
    await expect(client.createManualReinstallEnrollment(7)).resolves.toEqual(
      expect.objectContaining({
        installCommand,
        target: { hostId: 7, kind: "manual_reinstall" },
      }),
    );
    expect(requests).toContainEqual({
      body: "{}",
      contentType: "application/json",
      method: "POST",
      pathname: "/api/web/enrollments/manual-reinstall/7",
    });
  });

  it("Hub 在 JSON route 前拒绝请求时保留有界脱敏证据", async () => {
    const secrets = {
      apiKey: "plain-api-key-secret",
      authorization: "plain-authorization-secret",
      cookie: "plain-cookie-secret",
      enrollmentToken: "enk_enroll_plain-token-secret",
      secondaryCookie: "plain-secondary-cookie-secret",
    };
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: async (url) => {
        if (new URL(url).pathname === "/api/web/auth/login") {
          return jsonResponse({ authenticated: true }, 200, {
            "set-cookie": `enoki_owner_session=${secrets.cookie}; Path=/; HttpOnly`,
          });
        }
        return new Response(
          [
            "Forbidden",
            `Authorization: Bearer ${secrets.authorization}`,
            `Cookie: session=${secrets.cookie}; csrf=${secrets.secondaryCookie}`,
            `enrollmentToken=${secrets.enrollmentToken}`,
            `"apiKey":"${secrets.apiKey}"`,
            "x".repeat(1_024),
          ].join("\n"),
          {
            headers: { "content-type": "text/plain; charset=UTF-8" },
            status: 403,
          },
        );
      },
    });

    await client.authenticate("owner-password");
    await expect(client.createManualReinstallEnrollment(7)).rejects.toThrow(
      /not valid JSON/,
    );
    const evidence = await client.collectEvidence();
    const rejectedRequest = evidence.apiTimeline.at(-1);
    expect(rejectedRequest).toEqual(
      expect.objectContaining({
        bodyPreview: expect.any(String),
        contentType: "text/plain; charset=UTF-8",
        method: "POST",
        parseError: "response_body_not_json",
        pathname: "/api/web/enrollments/manual-reinstall/7",
        status: 403,
      }),
    );
    expect(rejectedRequest.bodyPreview.length).toBeLessThanOrEqual(512);
    expect(rejectedRequest.bodyPreview).toContain("Forbidden");
    expect(rejectedRequest.bodyPreview).toContain("[REDACTED]");
    const serializedEvidence = JSON.stringify(evidence);
    for (const secret of Object.values(secrets)) {
      expect(serializedEvidence).not.toContain(secret);
    }
  });

  it("keeps the DELETE response in evidence when the first poll fails", async () => {
    let deletes = 0;
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: async (url, init = {}) => {
        const path = new URL(url).pathname;
        if (path === "/api/web/auth/login") {
          return jsonResponse({ authenticated: true }, 200, {
            "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
          });
        }
        if (path === "/api/web/hosts/7" && init.method === "DELETE") {
          deletes += 1;
          return jsonResponse(
            {
              probeUninstallRequest: {
                acceptedAtMs: null,
                completedAtMs: null,
                createdAtMs: 1,
                failure: null,
                id: 42,
                runningAtMs: null,
                state: "pending",
                updatedAtMs: 1,
              },
            },
            202,
          );
        }
        throw new Error("poll network unavailable");
      },
    });
    await client.authenticate("owner-password");
    const requested = await client.requestProbeUninstall(7);
    expect(requested).toMatchObject({
      hostId: 7,
      kind: "probe_uninstall",
      targetProbeVersion: "",
    });

    await expect(
      client.waitForProbeOperation(requested, {
        intervalMs: 1,
        timeoutMs: 2,
      }),
    ).rejects.toMatchObject({
      message: "poll network unavailable",
      timeline: [expect.objectContaining({ id: 42, state: "pending" })],
    });
    expect(deletes).toBe(1);
  });

  it("times out a non-terminal operation with every bounded observation", async () => {
    const client = operationPollingClient(() => ({
      acceptedAtMs: 2,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      hostId: 7,
      id: 42,
      kind: "probe_uninstall",
      runningAtMs: 2,
      state: "running",
      updatedAtMs: 2,
    }));
    await client.authenticate("owner-password");
    const requested = await client.requestProbeUninstall(7);

    await expect(
      client.waitForProbeOperation(requested, {
        intervalMs: 1,
        timeoutMs: 2,
      }),
    ).rejects.toMatchObject({
      code: "probe_operation_timeout",
      timeline: [
        expect.objectContaining({ state: "pending" }),
        expect.objectContaining({ state: "running" }),
        expect.objectContaining({ state: "running" }),
        expect.objectContaining({ state: "running" }),
      ],
    });
  });

  it("rejects invalid operation states and changing terminal failures", async () => {
    const invalid = operationPollingClient(() => ({
      acceptedAtMs: null,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      hostId: 7,
      id: 42,
      kind: "probe_uninstall",
      runningAtMs: null,
      state: "teleported",
      updatedAtMs: 2,
    }));
    await invalid.authenticate("owner-password");
    const invalidRequest = await invalid.requestProbeUninstall(7);
    await expect(
      invalid.waitForProbeOperation(invalidRequest, {
        intervalMs: 1,
        timeoutMs: 2,
      }),
    ).rejects.toMatchObject({
      timeline: [expect.objectContaining({ state: "pending" })],
    });

    let observation = 0;
    const unstable = operationPollingClient(() => ({
      acceptedAtMs: 2,
      completedAtMs: 2,
      createdAtMs: 1,
      failure: {
        code: "uninstall_failed",
        message: observation++ === 0 ? "first" : "changed",
      },
      hostId: 7,
      id: 42,
      kind: "probe_uninstall",
      runningAtMs: 2,
      state: "failed",
      updatedAtMs: 2,
    }));
    await unstable.authenticate("owner-password");
    const unstableRequest = await unstable.requestProbeUninstall(7);
    await expect(
      unstable.waitForProbeOperation(unstableRequest, {
        intervalMs: 1,
        timeoutMs: 3,
      }),
    ).rejects.toMatchObject({ code: "probe_operation_terminal_changed" });
  });

  it("rejects a polled Probe Operation that is not the requested uninstall", async () => {
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: async (url, init = {}) => {
        const path = new URL(url).pathname;
        if (path === "/api/web/auth/login") {
          return jsonResponse({ authenticated: true }, 200, {
            "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
          });
        }
        if (path === "/api/web/hosts/7" && init.method === "DELETE") {
          return jsonResponse(
            {
              probeUninstallRequest: {
                acceptedAtMs: null,
                completedAtMs: null,
                createdAtMs: 1,
                failure: null,
                id: 42,
                runningAtMs: null,
                state: "pending",
                updatedAtMs: 1,
              },
            },
            202,
          );
        }
        return jsonResponse({
          probeOperation: {
            acceptedAtMs: 2,
            completedAtMs: 2,
            createdAtMs: 1,
            failure: null,
            hostId: 99,
            id: 999,
            kind: "probe_upgrade",
            runningAtMs: 2,
            state: "succeeded",
            updatedAtMs: 2,
          },
        });
      },
      sleep: async () => {},
    });

    await client.authenticate("owner-password");
    const requested = await client.requestProbeUninstall(7);
    const polling = client.waitForProbeOperation(requested, {
      intervalMs: 1,
      timeoutMs: 2,
    });

    await expect(polling).rejects.toMatchObject({
      code: "probe_operation_identity_mismatch",
      timeline: [expect.objectContaining({ id: 42, state: "pending" })],
    });
  });

  it("submits Probe Uninstall exactly once and only polls within its bound", async () => {
    const requests = [];
    const operationStates = ["pending", "running", "succeeded", "succeeded"];
    const fetch_ = async (url, init = {}) => {
      requests.push({ method: init.method ?? "GET", url });
      const path = new URL(url).pathname;
      if (path === "/api/web/auth/login") {
        return jsonResponse({ authenticated: true }, 200, {
          "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
        });
      }
      if (path === "/api/web/hosts/7" && init.method === "DELETE") {
        return jsonResponse(
          {
            probeUninstallRequest: {
              acceptedAtMs: null,
              completedAtMs: null,
              createdAtMs: 1,
              failure: null,
              id: 42,
              runningAtMs: null,
              state: "pending",
              updatedAtMs: 1,
            },
          },
          202,
        );
      }
      if (path === "/api/web/probe-operations/42") {
        const state = operationStates.shift();
        return jsonResponse({
          probeOperation: {
            acceptedAtMs: state === "pending" ? null : 1,
            completedAtMs: state === "succeeded" ? 1 : null,
            createdAtMs: 1,
            failure: null,
            hostId: 7,
            id: 42,
            kind: "probe_uninstall",
            runningAtMs: state === "pending" ? null : 1,
            state,
            updatedAtMs: 1,
          },
        });
      }
      throw new Error(`unexpected request ${init.method ?? "GET"} ${path}`);
    };
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: fetch_,
      sleep: async () => {},
    });

    await client.authenticate("owner-password");
    const requested = await client.requestProbeUninstall(7);
    const timeline = await client.waitForProbeOperation(requested, {
      intervalMs: 1,
      timeoutMs: 20,
    });

    expect(timeline.map(({ state }) => state)).toEqual([
      "pending",
      "pending",
      "running",
      "succeeded",
      "succeeded",
    ]);
    expect(
      requests.filter(
        ({ method, url }) =>
          method === "DELETE" && new URL(url).pathname === "/api/web/hosts/7",
      ),
    ).toHaveLength(1);
  });

  it("drives Enrollment, reporting, Metrics, and Probe Configuration through Owner APIs", async () => {
    let hostDetailRequests = 0;
    const fetch_ = async (url, init = {}) => {
      const { pathname, search } = new URL(url);
      const method = init.method ?? "GET";
      if (pathname === "/api/web/auth/login") {
        return jsonResponse({ authenticated: true }, 200, {
          "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
        });
      }
      if (pathname === "/api/web/enrollments" && method === "POST") {
        return jsonResponse(officialEnrollment(), 201);
      }
      if (pathname === "/api/web/hosts" && method === "GET") {
        return jsonResponse({ hosts: [] });
      }
      if (pathname === "/api/web/hosts/7" && method === "GET") {
        hostDetailRequests += 1;
        if (hostDetailRequests > 1) {
          return jsonResponse({ error: "host_not_found" }, 404);
        }
        return jsonResponse({ host: readyHost() });
      }
      if (
        pathname === "/api/web/hosts/7/metrics" &&
        ["?window=1m", "?window=24h"].includes(search)
      ) {
        return jsonResponse({
          metrics: {
            samples: [{ collectedAtMs: 10, sequence: 1, uptimeSeconds: 100 }],
            window: "1m",
          },
        });
      }
      if (pathname === "/api/web/hosts/7/probe-configuration") {
        return jsonResponse({
          configuration: {
            enabledCollectorIds: ["official.cpu"],
            metricsCollectionIntervalSeconds: 2,
            version: method === "PUT" ? "host-7-1" : "default-v1",
          },
          mode: method === "PUT" ? "override" : "inherit",
        });
      }
      if (pathname === "/api/web/audit-log" && search === "?limit=200") {
        return jsonResponse({
          auditLog: [
            {
              action: "host.delete",
              actor: "owner",
              details: { hostId: 7, probeOperationId: 42 },
              id: 3,
              occurredAtMs: 30,
              outcome: "success",
              subjectId: "7",
              subjectType: "host",
            },
          ],
        });
      }
      throw new Error(`unexpected request ${method} ${pathname}${search}`);
    };
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: fetch_,
    });
    await client.authenticate("owner-password");

    await expect(client.createEnrollment()).resolves.toMatchObject({
      installCommand: officialInstallCommand,
    });
    await expect(client.listHosts()).resolves.toEqual([]);
    await expect(client.getHost(7)).resolves.toMatchObject({ id: 7 });
    await expect(client.getHostMetrics(7)).resolves.toEqual([
      { collectedAtMs: 10, sequence: 1, uptimeSeconds: 100 },
    ]);
    await expect(client.getHostMetrics(7, { window: "24h" })).resolves.toEqual([
      { collectedAtMs: 10, sequence: 1, uptimeSeconds: 100 },
    ]);
    await expect(client.getHostProbeConfiguration(7)).resolves.toMatchObject({
      mode: "inherit",
    });
    await expect(
      client.updateHostProbeConfiguration(7, {
        configuration: {
          enabledCollectorIds: ["official.cpu"],
          metricsCollectionIntervalSeconds: 2,
        },
        mode: "override",
      }),
    ).resolves.toMatchObject({
      configuration: { version: "host-7-1" },
      mode: "override",
    });
    await expect(client.isHostSoftDeleted(7)).resolves.toBe(true);
    await expect(client.getAuditLog()).resolves.toEqual([
      expect.objectContaining({ action: "host.delete", subjectId: "7" }),
    ]);
  });

  it("retains redacted created Enrollment IDs and their latest statuses in client evidence", async () => {
    const fetch_ = async (url, init = {}) => {
      const { pathname } = new URL(url);
      const method = init.method ?? "GET";
      if (pathname === "/api/web/auth/login") {
        return jsonResponse({ authenticated: true }, 200, {
          "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
        });
      }
      if (pathname === "/api/web/enrollments" && method === "POST") {
        return jsonResponse({
          ...officialEnrollment({
            enrollmentToken: "enk_enroll_client_evidence_token",
          }),
          enrollmentId: "enr_client_evidence_0001",
          status: "pending",
          target: { kind: "new_host" },
        });
      }
      if (pathname === "/api/web/enrollments/enr_client_evidence_0001") {
        return jsonResponse({
          enrollmentId: "enr_client_evidence_0001",
          hostId: null,
          rejection: {
            code: "existing_probe_installation",
            message: "existing local Probe installation detected",
          },
          status: "rejected",
          target: { kind: "new_host" },
        });
      }
      throw new Error(`unexpected request ${method} ${pathname}`);
    };
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: fetch_,
    });

    await client.authenticate("owner-password");
    await client.createEnrollment({ kind: "new_host" });

    const evidence = await client.collectEvidence();
    expect(evidence).toMatchObject({
      enrollments: [
        {
          enrollmentId: "enr_client_evidence_0001",
          hostId: null,
          rejection: {
            code: "existing_probe_installation",
            message: "existing local Probe installation detected",
          },
          readError: null,
          status: "rejected",
          target: { kind: "new_host" },
        },
      ],
    });
    const serialized = JSON.stringify(evidence);
    expect(serialized).not.toContain("enk_enroll_client_evidence_token");
    expect(serialized).not.toContain(officialInstallCommand);
  });

  it("retains the last Enrollment state and its refresh error without retry recursion", async () => {
    const requests = [];
    const fetch_ = async (url, init = {}) => {
      const { pathname } = new URL(url);
      const method = init.method ?? "GET";
      requests.push(`${method} ${pathname}`);
      if (pathname === "/api/web/auth/login") {
        return jsonResponse({ authenticated: true }, 200, {
          "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
        });
      }
      if (pathname === "/api/web/enrollments" && method === "POST") {
        return jsonResponse({
          ...officialEnrollment({
            enrollmentToken: "enk_enroll_client_refresh_error_token",
          }),
          enrollmentId: "enr_client_refresh_error_0001",
          status: "pending",
          target: { kind: "new_host" },
        });
      }
      if (pathname === "/api/web/enrollments/enr_client_refresh_error_0001") {
        return jsonResponse({ error: "enrollment_refresh_unavailable" }, 503);
      }
      throw new Error(`unexpected request ${method} ${pathname}`);
    };
    const client = createHubLifecycleClient({
      baseUrl: "https://hub.example",
      fetch: fetch_,
    });

    await client.authenticate("owner-password");
    await client.createEnrollment({ kind: "new_host" });
    await expect(client.collectEvidence()).resolves.toMatchObject({
      enrollments: [
        {
          enrollmentId: "enr_client_refresh_error_0001",
          readError: { code: "enrollment_refresh_unavailable" },
          status: "pending",
        },
      ],
    });
    expect(
      requests.filter(
        (request) =>
          request === "GET /api/web/enrollments/enr_client_refresh_error_0001",
      ),
    ).toHaveLength(1);
  });
});

describe("Release E2E Orchestrator", () => {
  it("rejects legacy Fresh scenario participants that omit the lifecycle contract", async () => {
    const calls = [];
    let hostsObservation = 0;
    let detailObservation = 0;
    let metricsObservation = 0;
    const hub = {
      async authenticate() {
        calls.push("hub.authenticate");
      },
      async createEnrollment() {
        calls.push("hub.createEnrollment");
        return { installCommand: officialInstallCommand };
      },
      async getHost() {
        detailObservation += 1;
        calls.push("hub.getHost");
        return readyHost({
          reportedProbeConfigurationVersion:
            detailObservation >= 2 ? "host-2-1" : "default-v1",
        });
      },
      async getAuditLog() {
        calls.push("hub.getAuditLog");
        return lifecycleAuditLog();
      },
      async getHostMetrics() {
        metricsObservation += 1;
        calls.push("hub.getHostMetrics");
        return metricsObservation === 1
          ? [
              portableMetric({
                collectedAtMs: 10,
                sequence: 1,
                uptimeSeconds: 100,
              }),
            ]
          : [
              portableMetric({
                collectedAtMs: 10,
                sequence: 1,
                uptimeSeconds: 100,
              }),
              portableMetric({
                collectedAtMs: 20,
                sequence: 2,
                uptimeSeconds: 110,
              }),
            ];
      },
      async getHostProbeConfiguration() {
        calls.push("hub.getHostProbeConfiguration");
        return {
          configuration: {
            enabledCollectorIds: ["official.cpu", "official.memory"],
            metricsCollectionIntervalSeconds: 5,
            version: "default-v1",
          },
          mode: "inherit",
        };
      },
      async isHostSoftDeleted() {
        calls.push("hub.isHostSoftDeleted");
        return true;
      },
      async listHosts() {
        hostsObservation += 1;
        calls.push("hub.listHosts");
        return hostsObservation === 1 ? [] : [{ id: 7 }];
      },
      async requestProbeUninstall(hostId) {
        calls.push(`hub.requestProbeUninstall:${hostId}`);
        return { id: 42, state: "pending" };
      },
      async updateHostProbeConfiguration(_hostId, input) {
        calls.push("hub.updateHostProbeConfiguration");
        expect(input.mode).toBe("override");
        return {
          configuration: { ...input.configuration, version: "host-2-1" },
          mode: "override",
        };
      },
      async waitForProbeOperation() {
        calls.push("hub.waitForProbeOperation");
        return [
          { failure: null, id: 42, state: "pending" },
          { failure: null, id: 42, state: "running" },
          { failure: null, id: 42, state: "succeeded" },
        ];
      },
    };
    const host = {
      async assertDisposable() {
        calls.push("host.assertDisposable");
      },
      async assertInstalled() {
        calls.push("host.assertInstalled");
        return { service: { User: "enoki-probe" } };
      },
      async cleanup() {
        calls.push("host.cleanup");
        return { clean: true };
      },
      async collectEvidence() {
        calls.push("host.collectEvidence");
        return { journaldRetained: true };
      },
      async install(command) {
        calls.push("host.install");
        expect(command.installCommand).toBe(officialInstallCommand);
      },
      async verifyUninstallCompletion() {
        calls.push("host.verifyUninstallCompletion");
        return {
          clean: true,
          journaldRetained: true,
          sharedDependenciesRetained: true,
        };
      },
    };
    const written = [];
    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifest(),
        environment: {
          async cleanup() {
            calls.push("environment.cleanup");
            return { clean: true };
          },
          async start() {
            calls.push("environment.start");
            return {
              host,
              hub,
              infrastructure: {
                artifactAccess: "github-actions",
                connection: "local",
                kind: "ci",
                matrixCellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
                provisioning: "github-hosted-runner",
              },
              releaseTestHost: {
                architecture: "x86_64",
                operatingSystem: "ubuntu",
                operatingSystemVersion: "22.04",
                pid1: "systemd",
                virtualization: "kvm",
              },
            };
          },
        },
        evidenceSink: {
          async write(value) {
            written.push(value);
          },
        },
        ownerPassword: "owner-password",
        runId: "run-123",
        scenario: "fresh-install-uninstall",
        timing: { intervalMs: 1, timeoutMs: 10, sleep: async () => {} },
      }),
    ).rejects.toMatchObject({ code: "release_e2e_failed" });
    expect(calls.indexOf("host.collectEvidence")).toBeLessThan(
      calls.indexOf("host.cleanup"),
    );
    expect(calls.at(-1)).toBe("environment.cleanup");
    expect(written.at(-1)).toMatchObject({ result: { status: "failed" } });
  });

  it("proves the expanded fresh installation lifecycle without resubmitting mutations", async () => {
    const calls = [];
    const completion = {
      clean: true,
      inventory: {
        accounts: { group: false, user: false },
        files: [],
        units: [],
      },
      journaldRetained: true,
      sharedDependenciesRetained: true,
    };
    const installedState = {
      binarySha256: "a".repeat(64),
      identity: {
        identitySha256: "b".repeat(64),
        probeId: "probe_release_01",
      },
      installMetadataSha256: "c".repeat(64),
      restartCount: 2,
      service: {
        ActiveState: "active",
        LoadState: "loaded",
        SubState: "running",
      },
    };
    const canonicalReportEvidence = canonicalRuntimeUnavailableEvidence();
    let enrollmentCount = 0;
    let installCount = 0;
    let lifecycle = "empty";
    let canonicalRuntimeState = "available";
    let newEnrollmentCalls = 0;
    let offlineObservations = 0;
    let probeConfiguration = {
      enabledCollectorIds: ["official.cpu", "official.memory"],
      metricsCollectionIntervalSeconds: 5,
    };
    const enrollment = (input) => ({
      enrollmentId: `enr_release_lifecycle_${++enrollmentCount}`,
      enrollmentToken: "enk_enroll_release_e2e_test_token",
      installCommand: officialInstallCommand,
      status: "pending",
      target: input,
    });
    const initialEnrollment = enrollment({ kind: "new_host" });
    const rejectedEnrollment = enrollment({ kind: "new_host" });
    const reenrollment = enrollment({ hostId: 7, kind: "existing_host" });
    const hub = {
      async authenticate() {
        calls.push("hub.authenticate");
      },
      async collectEvidence() {
        calls.push("hub.collectEvidence");
        return { apiTimeline: [{ pathname: "/api/web/hosts/7" }] };
      },
      async createEnrollment(target) {
        calls.push(`hub.createEnrollment:${target.kind}`);
        return target.kind === "existing_host"
          ? reenrollment
          : ++newEnrollmentCalls === 1
            ? initialEnrollment
            : rejectedEnrollment;
      },
      async deleteHostHubOnly(hostId) {
        calls.push(`hub.deleteHostHubOnly:${hostId}`);
        lifecycle = "deleted";
        return { deletedAtMs: 100, id: hostId };
      },
      async getAuditLog() {
        calls.push("hub.getAuditLog");
        return freshLifecycleAuditLog();
      },
      async getEnrollment(enrollmentId) {
        calls.push(`hub.getEnrollment:${enrollmentId}`);
        return {
          enrollmentId,
          hostId: null,
          rejection: {
            code: "existing_probe_installation",
            message: "existing local Probe installation detected",
          },
          status: "rejected",
          target: { kind: "new_host" },
        };
      },
      async getHost() {
        calls.push(`hub.getHost:${lifecycle}`);
        if (lifecycle === "offline") {
          offlineObservations += 1;
          return {
            ...readyHost(),
            status: offlineObservations >= 92 ? "offline" : "stale",
          };
        }
        if (lifecycle === "deleted") {
          throw new Error("deleted Host must not be read");
        }
        return readyHost({
          reportedProbeConfigurationVersion: "host-2-1",
        });
      },
      async getHostMetrics() {
        calls.push("hub.getHostMetrics");
        const samples = [
          portableMetric({
            collectedAtMs: 10,
            sequence: 1,
            uptimeSeconds: 100,
          }),
          portableMetric({
            collectedAtMs: 20,
            sequence: 2,
            uptimeSeconds: 110,
          }),
        ];
        const reenrolled =
          lifecycle === "reenrolled"
            ? [
                ...samples,
                portableMetric({
                  collectedAtMs: 30,
                  sequence: 3,
                  uptimeSeconds: 120,
                }),
                portableMetric({
                  collectedAtMs: 40,
                  sequence: 4,
                  uptimeSeconds: 130,
                }),
              ]
            : samples;
        return canonicalRuntimeState === "restored"
          ? [
              ...reenrolled,
              portableMetric({
                collectedAtMs: 50,
                sequence: 3,
                uptimeSeconds: 140,
              }),
            ]
          : reenrolled;
      },
      async getHostProbeConfiguration() {
        calls.push("hub.getHostProbeConfiguration");
        return {
          configuration: {
            ...probeConfiguration,
            version: "host-2-1",
          },
          mode: "override",
        };
      },
      async isHostSoftDeleted(hostId) {
        calls.push(`hub.isHostSoftDeleted:${hostId}`);
        return lifecycle === "deleted";
      },
      async listHosts() {
        calls.push(`hub.listHosts:${lifecycle}`);
        return lifecycle === "empty"
          ? []
          : lifecycle === "deleted"
            ? []
            : [{ id: 7 }];
      },
      async updateHostProbeConfiguration(_hostId, input) {
        calls.push("hub.updateHostProbeConfiguration");
        probeConfiguration = input.configuration;
        return {
          configuration: { ...input.configuration, version: "host-2-1" },
          mode: "override",
        };
      },
    };
    const host = {
      async assertDisposable() {
        calls.push("host.assertDisposable");
      },
      async assertInstalled() {
        calls.push("host.assertInstalled");
        return { service: { User: "enoki-probe" } };
      },
      async awaitPermanentReportRejection() {
        calls.push("host.awaitPermanentReportRejection");
        return {
          binarySha256: "a".repeat(64),
          identity: {
            identitySha256: "d".repeat(64),
            probeId: "probe_release_02",
          },
          installMetadataSha256: "e".repeat(64),
          restartCountAfterObservation: 3,
          restartCountBeforeObservation: 3,
          service: {
            ActiveState: "failed",
            ExecMainStatus: 78,
            LoadState: "loaded",
            SubState: "failed",
          },
        };
      },
      async captureInstallationState() {
        calls.push("host.captureInstallationState");
        return installedState;
      },
      async cleanup() {
        calls.push("host.cleanup");
        return { clean: true };
      },
      async collectDiagnostics() {
        calls.push("host.collectDiagnostics");
        return {
          inventory: {
            available: true,
            output: { code: 0, stderr: "", stdout: "{}" },
            value: { files: ["/usr/local/bin/enoki-probe"] },
          },
        };
      },
      async collectEvidence() {
        calls.push("host.collectEvidence");
        return { inventory: completion.inventory };
      },
      async install() {
        installCount += 1;
        lifecycle = installCount === 1 ? "online" : "reenrolled";
        calls.push(`host.install:${installCount}`);
        return {
          output: {
            code: 0,
            stderr: "",
            stdout: productInstallerOutput(),
          },
        };
      },
      async localUninstall() {
        calls.push("host.localUninstall");
        lifecycle = lifecycle === "deleted" ? "deleted" : "offline";
        return {
          completion,
          output: {
            code: 0,
            stderr: "",
            stdout: "Local Probe Uninstall completed.",
          },
        };
      },
      async readProbeIdentity() {
        calls.push("host.readProbeIdentity");
        return installCount === 1
          ? installedState.identity
          : { identitySha256: "d".repeat(64), probeId: "probe_release_02" };
      },
      async restartCanonicalProbeWithoutObservationRuntime() {
        calls.push("host.restartCanonicalProbeWithoutObservationRuntime");
        canonicalRuntimeState = "masked";
        return {
          identity: {
            probeId: "probe_release_02",
            registrationAttemptCredential: false,
            registrationAttemptSource: false,
            registrationDropIn: false,
            transitionalRegistrationKeys: false,
          },
          probe: {
            ActiveState: "active",
            LoadState: "loaded",
            Result: "success",
            SubState: "running",
            Type: "notify",
          },
          runtime: {
            serviceLoadState: "masked",
            socketLoadState: "masked",
          },
        };
      },
      async restoreObservationRuntime() {
        calls.push("host.restoreObservationRuntime");
        canonicalRuntimeState = "restored";
        return { restored: true };
      },
      async repairInstalledBundleFailure() {
        calls.push("host.repairInstalledBundleFailure");
        return {
          failure: {
            activeState: "failed",
            failureEpoch: {
              hostId: "7",
              probeId: "probe_release_01",
            },
            role: "observation_runtime",
            status: "latched",
            result: "start-limit-hit",
            unit: "enoki-observation-runtime.service",
          },
          repair: {
            failureEpochRemoved: true,
            faultRemoved: true,
            latchRemoved: true,
            sameBundle: true,
          },
        };
      },
      async rejectRepeatedInstall() {
        calls.push("host.rejectRepeatedInstall");
        return {
          code: "existing_probe_installation",
          output: { code: 1, stderr: "typed rejection", stdout: "" },
        };
      },
      async verifyUninstallCompletion() {
        calls.push("host.verifyUninstallCompletion");
        return completion;
      },
    };
    const written = [];

    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifest(),
        environment: {
          async cleanup() {
            calls.push("environment.cleanup");
            return { clean: true };
          },
          async start() {
            calls.push("environment.start");
            return {
              canonicalReports: {
                arm({ expectedProbeId }) {
                  calls.push(`canonicalReports.arm:${expectedProbeId}`);
                },
                diagnostics() {
                  return { completed: true };
                },
                async waitForEvidence() {
                  calls.push("canonicalReports.waitForEvidence");
                  return canonicalReportEvidence;
                },
              },
              host,
              hub,
            };
          },
        },
        evidenceSink: {
          async write(value) {
            written.push(value);
          },
        },
        ownerPassword: "owner-password",
        runId: "run-expanded-fresh",
        scenario: "fresh-install-uninstall",
        timing: {
          intervalMs: 1,
          sleep: async () => {},
          timeoutMs: 10,
        },
      }),
    ).resolves.toEqual({ status: "succeeded" });

    expect(calls).toEqual(
      expect.arrayContaining([
        "host.rejectRepeatedInstall",
        "host.repairInstalledBundleFailure",
        "host.localUninstall",
        "hub.createEnrollment:existing_host",
        "hub.deleteHostHubOnly:7",
        "host.awaitPermanentReportRejection",
        "canonicalReports.arm:probe_release_02",
        "host.restartCanonicalProbeWithoutObservationRuntime",
        "canonicalReports.waitForEvidence",
        "host.restoreObservationRuntime",
      ]),
    );
    expect(calls.filter((call) => call === "host.install:1")).toHaveLength(1);
    expect(calls.filter((call) => call === "host.install:2")).toHaveLength(1);
    expect(
      calls.filter((call) => call === "hub.createEnrollment:new_host"),
    ).toHaveLength(2);
    expect(
      calls.filter((call) => call === "hub.createEnrollment:existing_host"),
    ).toHaveLength(1);
    expect(
      calls.filter((call) => call === "hub.deleteHostHubOnly:7"),
    ).toHaveLength(1);
    expect(
      calls.filter((call) => call === "hub.updateHostProbeConfiguration"),
    ).toHaveLength(1);
    expect(
      calls.filter((call) => call === "host.rejectRepeatedInstall"),
    ).toHaveLength(1);
    expect(
      calls.filter((call) => call === "host.awaitPermanentReportRejection"),
    ).toHaveLength(1);
    expect(calls.filter((call) => call === "host.localUninstall")).toHaveLength(
      2,
    );
    expect(calls.indexOf("host.repairInstalledBundleFailure")).toBeLessThan(
      calls.indexOf("host.localUninstall"),
    );
    expect(
      calls.indexOf("host.restartCanonicalProbeWithoutObservationRuntime"),
    ).toBeLessThan(calls.indexOf("hub.deleteHostHubOnly:7"));
    expect(calls.indexOf("canonicalReports.waitForEvidence")).toBeLessThan(
      calls.lastIndexOf("hub.getHostMetrics"),
    );
    expect(calls.lastIndexOf("hub.getHostMetrics")).toBeLessThan(
      calls.indexOf("host.restoreObservationRuntime"),
    );
    expect(offlineObservations).toBe(92);
    expect(written.at(-1)).toMatchObject({
      installedBundleFailureRepair: {
        failure: {
          failureEpoch: {
            hostId: "7",
            probeId: "probe_release_01",
          },
          result: "start-limit-hit",
          role: "observation_runtime",
          status: "latched",
        },
        host: {
          hostProfile: { probeVersion: "1.2.3" },
          id: 7,
          status: "online",
        },
        identity: {
          after: installedState.identity,
          before: installedState.identity,
        },
        repair: {
          failureEpochRemoved: true,
          faultRemoved: true,
          latchRemoved: true,
          repairedVersion: "1.2.3",
          sameBundle: true,
        },
      },
      canonicalRuntimeUnavailableReporting: {
        reporting: canonicalReportEvidence,
        host: {
          identity: { probeId: "probe_release_02" },
          probe: { ActiveState: "active", SubState: "running" },
          runtime: {
            serviceLoadState: "masked",
            socketLoadState: "masked",
          },
        },
        ownerProjection: {
          host: { id: 7, status: "online" },
          metricsUnchanged: true,
        },
      },
      finalLocalUninstall: { completion: { clean: true } },
      hubOnlyDeletion: {
        deletedHost: { id: 7 },
        permanentReportRejection: {
          restartCountAfterObservation: 3,
          restartCountBeforeObservation: 3,
        },
      },
      reEnrollment: {
        hostId: 7,
        identity: {
          after: { probeId: "probe_release_02" },
          before: { probeId: "probe_release_01" },
        },
        metricsHistory: {
          anchors: expect.arrayContaining([
            expect.objectContaining({ sequence: 1 }),
            expect.objectContaining({ sequence: 2 }),
            expect.objectContaining({ sequence: 4 }),
          ]),
        },
      },
      metricsHistory: {
        anchors: [
          expect.objectContaining({ sequence: 1 }),
          expect.objectContaining({ sequence: 2 }),
        ],
      },
      repeatedAdd: { rejection: { code: "existing_probe_installation" } },
    });
  });

  it("proves the pinned baseline Probe through Upgrade and retains its reporting timeout", async () => {
    const calls = [];
    let installed = false;
    let activeHub = "baseline";
    let upgraded = false;
    let candidateReportingReady = true;
    let configurationVersion = "default-v1";
    let metricsEpoch = 0;
    const hub = {
      async authenticate() {
        calls.push(`hub.authenticate:${activeHub}`);
      },
      async createEnrollment() {
        calls.push("hub.createEnrollment:baseline");
        expect(activeHub).toBe("baseline");
        return { installCommand: officialInstallCommand };
      },
      async getAuditLog() {
        calls.push("hub.getAuditLog");
        return baselineUpgradeAuditLog();
      },
      async getHost() {
        calls.push(`hub.getHost:${activeHub}:${upgraded}`);
        return readyHost({
          hostProfile: {
            ...readyHost().hostProfile,
            probeVersion:
              upgraded && candidateReportingReady ? "1.2.3" : "1.2.2",
          },
          reportedProbeConfigurationVersion: configurationVersion,
        });
      },
      async getHostMetrics() {
        metricsEpoch += 1;
        calls.push(`hub.getHostMetrics:${activeHub}:${upgraded}`);
        const offset = metricsEpoch * 10;
        return [
          portableMetric({
            collectedAtMs: offset,
            sequence: metricsEpoch * 2 - 1,
            uptimeSeconds: 100 + offset,
          }),
          portableMetric({
            collectedAtMs: offset + 5,
            sequence: metricsEpoch * 2,
            uptimeSeconds: 105 + offset,
          }),
        ];
      },
      async getHostProbeConfiguration() {
        calls.push(`hub.getHostProbeConfiguration:${activeHub}:${upgraded}`);
        return {
          configuration: {
            enabledCollectorIds: ["official.cpu", "official.memory"],
            metricsCollectionIntervalSeconds: 5,
            version: configurationVersion,
          },
          mode: configurationVersion === "default-v1" ? "inherit" : "override",
        };
      },
      async isHostSoftDeleted() {
        calls.push("hub.isHostSoftDeleted");
        return true;
      },
      async listHosts() {
        calls.push(`hub.listHosts:${activeHub}`);
        return installed ? [{ id: 7 }] : [];
      },
      async requestProbeUpgrade(hostId) {
        calls.push(`hub.requestProbeUpgrade:${hostId}`);
        expect(activeHub).toBe("candidate");
        expect(
          calls.some((call) =>
            call.startsWith("hub.getHostProbeConfiguration:candidate:false"),
          ),
        ).toBe(true);
        return {
          acceptedAtMs: null,
          completedAtMs: null,
          createdAtMs: 1,
          failure: null,
          hostId,
          id: 41,
          kind: "probe_upgrade",
          runningAtMs: null,
          state: "pending",
          targetProbeVersion: "1.2.3",
          updatedAtMs: 1,
        };
      },
      async requestProbeUninstall(hostId) {
        calls.push(`hub.requestProbeUninstall:${hostId}`);
        return {
          acceptedAtMs: null,
          completedAtMs: null,
          createdAtMs: 5,
          failure: null,
          hostId,
          id: 42,
          kind: "probe_uninstall",
          runningAtMs: null,
          state: "pending",
          updatedAtMs: 5,
        };
      },
      async switchToCandidate() {
        calls.push("hub.switchToCandidate");
        activeHub = "candidate";
      },
      async updateHostProbeConfiguration(_hostId, input) {
        calls.push(`hub.updateHostProbeConfiguration:${activeHub}`);
        configurationVersion =
          configurationVersion === "default-v1" ? "host-7-1" : "host-7-2";
        calls.push(`hub.updateHostProbeConfiguration:${configurationVersion}`);
        return {
          configuration: {
            ...input.configuration,
            version: configurationVersion,
          },
          mode: "override",
        };
      },
      async waitForProbeOperation(operation) {
        calls.push(`hub.waitForProbeOperation:${operation.kind}`);
        if (operation.kind === "probe_upgrade") {
          upgraded = true;
          return [
            operation,
            {
              ...operation,
              acceptedAtMs: 2,
              runningAtMs: 2,
              state: "running",
              updatedAtMs: 2,
            },
            {
              ...operation,
              acceptedAtMs: 2,
              completedAtMs: 4,
              runningAtMs: 2,
              state: "succeeded",
              updatedAtMs: 4,
            },
            {
              ...operation,
              acceptedAtMs: 2,
              completedAtMs: 4,
              runningAtMs: 2,
              state: "succeeded",
              updatedAtMs: 4,
            },
          ];
        }
        return [
          operation,
          {
            ...operation,
            acceptedAtMs: 6,
            runningAtMs: 6,
            state: "running",
            updatedAtMs: 6,
          },
          {
            ...operation,
            acceptedAtMs: 6,
            completedAtMs: 7,
            runningAtMs: 6,
            state: "succeeded",
            updatedAtMs: 7,
          },
        ];
      },
    };
    const host = {
      async assertDisposable() {
        calls.push("host.assertDisposable");
      },
      async assertInstalled(_runId, version) {
        calls.push(`host.assertInstalled:${version}`);
        return { probeVersion: version };
      },
      async beginUpgradeOwnershipTransition(_runId, targetProbeVersion) {
        calls.push(
          `host.beginUpgradeOwnershipTransition:${targetProbeVersion}`,
        );
        return { owned: true, targetProbeVersion };
      },
      async bindUpgradeOwnershipTransition(_runId, operation) {
        calls.push(`host.bindUpgradeOwnershipTransition:${operation.id}`);
        return { operationId: operation.id, owned: true };
      },
      async cleanup() {
        calls.push("host.cleanup");
        return { clean: true };
      },
      async collectEvidence() {
        calls.push("host.collectEvidence");
        return { journaldRetained: true };
      },
      async completeUpgradeOwnershipTransition(_runId, operation) {
        calls.push(`host.completeUpgradeOwnershipTransition:${operation.id}`);
        return { operationId: operation.id, owned: true };
      },
      async install(command) {
        calls.push("host.install:baseline");
        expect(command.installCommand).toBe(officialInstallCommand);
        installed = true;
      },
      async readProbeIdentity() {
        calls.push(`host.readProbeIdentity:${upgraded}`);
        return {
          identitySha256: "f".repeat(64),
          probeId: "probe_release_01",
        };
      },
      async verifyUninstallCompletion() {
        calls.push("host.verifyUninstallCompletion");
        return {
          clean: true,
          journaldRetained: true,
          sharedDependenciesRetained: true,
        };
      },
    };
    const written = [];

    const result = await runReleaseE2EScenario({
      candidateManifest: candidateManifestWithBaseline(),
      environment: {
        async cleanup() {
          calls.push("environment.cleanup");
          return { clean: true };
        },
        async start(options) {
          calls.push(`environment.start:${options.hubMode}`);
          return { host, hub };
        },
      },
      evidenceSink: { write: async (value) => written.push(value) },
      ownerPassword: "owner-password",
      runId: "run-baseline-upgrade",
      scenario: "compatible-upgrade-uninstall",
      timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
    });

    expect(result).toEqual({ status: "succeeded" });
    const baselineInstallIndex = calls.indexOf("host.install:baseline");
    expect(
      calls.indexOf("hub.listHosts:baseline", baselineInstallIndex),
    ).toBeLessThan(calls.indexOf("host.readProbeIdentity:false"));
    expect(
      calls.filter((call) => call.startsWith("hub.requestProbeUpgrade:")),
    ).toEqual(["hub.requestProbeUpgrade:7"]);
    expect(calls.indexOf("hub.switchToCandidate")).toBeLessThan(
      calls.indexOf("hub.requestProbeUpgrade:7"),
    );
    expect(calls).toContain("host.assertInstalled:1.2.2");
    expect(calls).toContain("host.assertInstalled:1.2.3");
    expect(calls).toContain("host.beginUpgradeOwnershipTransition:1.2.3");
    expect(calls).toContain("host.bindUpgradeOwnershipTransition:41");
    expect(calls).toContain("host.completeUpgradeOwnershipTransition:41");
    expect(written.at(-1)).toMatchObject({
      identityContinuity: {
        after: { probeId: "probe_release_01" },
        before: { probeId: "probe_release_01" },
        hostId: 7,
      },
      releaseBaseline: {
        probeVersion: "1.2.2",
        tag: "v1.2.2",
      },
      result: { status: "succeeded" },
      upgradeOperationTimeline: expect.arrayContaining([
        expect.objectContaining({ state: "pending" }),
        expect.objectContaining({ acceptedAtMs: 2, state: "running" }),
        expect.objectContaining({
          acceptedAtMs: 2,
          completedAtMs: 4,
          runningAtMs: 2,
          state: "succeeded",
        }),
      ]),
    });

    activeHub = "baseline";
    upgraded = false;
    candidateReportingReady = false;
    configurationVersion = "default-v1";
    installed = false;
    metricsEpoch = 0;
    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifestWithBaseline(),
        environment: {
          async cleanup() {
            return { clean: true };
          },
          async start() {
            return { host, hub };
          },
        },
        evidenceSink: { write: async () => {} },
        ownerPassword: "owner-password",
        runId: "run-baseline-upgrade-reporting-timeout",
        scenario: "compatible-upgrade-uninstall",
        timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 2 },
      }),
    ).rejects.toMatchObject({ code: "candidate_probe_reporting_timeout" });
  });

  it("fails a Compatible insufficient-privilege Upgrade without Enrollment fallback", async () => {
    let activeHub = "baseline";
    let configurationVersion = "default-v1";
    let installed = false;
    let candidateEnrollmentCreated = false;
    let metricsEpoch = 0;
    const failedUpgrade = {
      acceptedAtMs: 2,
      completedAtMs: 3,
      createdAtMs: 1,
      failure: {
        code: "insufficient_privilege",
        message: "sudo denied",
      },
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "failed",
      targetProbeVersion: "1.2.3",
      updatedAtMs: 3,
    };
    const hub = {
      async authenticate() {},
      async createEnrollment() {
        if (activeHub === "candidate") candidateEnrollmentCreated = true;
        return { installCommand: officialInstallCommand };
      },
      async getAuditLog() {
        return baselineUpgradeAuditLog();
      },
      async getHost() {
        return readyHost({
          hostProfile: {
            ...readyHost().hostProfile,
            probeVersion: "1.2.2",
          },
          reportedProbeConfigurationVersion: configurationVersion,
        });
      },
      async getHostMetrics() {
        metricsEpoch += 1;
        return [
          portableMetric({
            collectedAtMs: metricsEpoch * 10,
            sequence: metricsEpoch * 2 - 1,
          }),
          portableMetric({
            collectedAtMs: metricsEpoch * 10 + 5,
            sequence: metricsEpoch * 2,
          }),
        ];
      },
      async getHostProbeConfiguration() {
        return {
          configuration: {
            enabledCollectorIds: ["official.cpu", "official.memory"],
            metricsCollectionIntervalSeconds: 5,
            version: configurationVersion,
          },
          mode: configurationVersion === "default-v1" ? "inherit" : "override",
        };
      },
      async isHostSoftDeleted() {
        return true;
      },
      async listHosts() {
        return installed ? [{ id: 7 }] : [];
      },
      async requestProbeUpgrade() {
        return {
          ...failedUpgrade,
          acceptedAtMs: null,
          completedAtMs: null,
          failure: null,
          runningAtMs: null,
          state: "pending",
          updatedAtMs: 1,
        };
      },
      async requestProbeUninstall() {
        return {
          acceptedAtMs: null,
          completedAtMs: null,
          createdAtMs: 5,
          failure: null,
          hostId: 7,
          id: 42,
          kind: "probe_uninstall",
          runningAtMs: null,
          state: "pending",
          targetProbeVersion: "",
          updatedAtMs: 5,
        };
      },
      async switchToCandidate() {
        activeHub = "candidate";
      },
      async updateHostProbeConfiguration(_hostId, input) {
        configurationVersion =
          configurationVersion === "default-v1" ? "host-7-1" : "host-7-2";
        return {
          configuration: {
            ...input.configuration,
            version: configurationVersion,
          },
          mode: "override",
        };
      },
      async waitForProbeOperation(operation) {
        if (operation.kind === "probe_upgrade") {
          return [operation, failedUpgrade, failedUpgrade];
        }
        const succeeded = {
          ...operation,
          acceptedAtMs: 6,
          completedAtMs: 7,
          runningAtMs: 6,
          state: "succeeded",
          updatedAtMs: 7,
        };
        return [operation, succeeded, succeeded];
      },
    };
    const host = {
      async assertDisposable() {},
      async assertInstalled(_runId, version) {
        return { probeVersion: version };
      },
      async beginUpgradeOwnershipTransition() {},
      async bindUpgradeOwnershipTransition() {},
      async cleanup() {
        return { clean: true };
      },
      async collectEvidence() {
        return { journaldRetained: true };
      },
      async completeUpgradeOwnershipTransition() {
        throw new Error("failed Upgrade must not commit automatic ownership");
      },
      async install() {
        installed = true;
      },
      async readProbeIdentity() {
        return {
          identitySha256: "f".repeat(64),
          probeId: "probe_release_01",
        };
      },
      async verifyUninstallCompletion() {
        return {
          clean: true,
          journaldRetained: true,
          sharedDependenciesRetained: true,
        };
      },
    };
    const written = [];

    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifestWithBaseline(),
        environment: {
          async cleanup() {
            return { clean: true };
          },
          async start() {
            return { host, hub };
          },
        },
        evidenceSink: { write: async (value) => written.push(value) },
        ownerPassword: "owner-password",
        runId: "run-permission-recovery",
        scenario: "compatible-upgrade-uninstall",
        timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
      }),
    ).rejects.toMatchObject({ code: "compatible_probe_upgrade_failed" });
    expect(candidateEnrollmentCreated).toBe(false);
    expect(written.at(-1)).toMatchObject({
      candidateHost: null,
      manualRecovery: null,
      result: {
        error: { code: "compatible_probe_upgrade_failed" },
        status: "failed",
      },
      upgradeOperationTimeline: expect.arrayContaining([
        expect.objectContaining({ state: "pending" }),
        expect.objectContaining({
          failure: expect.objectContaining({ code: "insufficient_privilege" }),
          state: "failed",
        }),
      ]),
    });
  });

  it("restores the exact baseline Hub while the Candidate Probe keeps its identity and reporting", async () => {
    const calls = [];
    let activeHub = "baseline";
    let installed = false;
    let upgraded = false;
    let metricsEpoch = 0;
    const snapshotDigest = `sha256:${"d".repeat(64)}`;
    const manifest = candidateManifestWithBaseline();
    const operation = {
      acceptedAtMs: null,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "pending",
      targetProbeVersion: "1.2.3",
      updatedAtMs: 1,
    };
    const hub = {
      async authenticate() {
        calls.push(`hub.authenticate:${activeHub}`);
      },
      async captureBaselineStateSnapshot(input) {
        calls.push("hub.captureBaselineStateSnapshot");
        expect(input).toEqual({
          baselineImageDigest: manifest.releaseBaseline.hub.imageDigest,
          baselineVersion: "v1.2.2",
        });
        return {
          baselineImageDigest: manifest.releaseBaseline.hub.imageDigest,
          baselineVersion: "v1.2.2",
          hotDataFileCount: 1,
          hotDataFiles: ["data-root/enoki.db"],
          manifestDigest: snapshotDigest,
          recoveryTime: "2026-08-02T12:00:00.000Z",
          roots: [
            { id: "data-root", included: true, path: "/data" },
            {
              id: "metrics-archive",
              included: true,
              path: "/data/metrics-archive",
            },
          ],
          tool: "enoki-hub-state",
          version: "v1",
        };
      },
      async createEnrollment() {
        calls.push("hub.createEnrollment:baseline");
        return { installCommand: officialInstallCommand };
      },
      async getHost() {
        calls.push(`hub.getHost:${activeHub}:${upgraded}`);
        const afterRestore = activeHub === "baseline" && upgraded;
        const filesystems = [
          {
            availableBytes: afterRestore ? 700_000_000 : 800_000_000,
            filesystemType: "ext4",
            mountPoint: "/",
            totalBytes: 1_000_000_000,
          },
          {
            availableBytes: afterRestore ? 300_000_000 : 400_000_000,
            filesystemType: "ext4",
            mountPoint: "/var",
            totalBytes: 500_000_000,
          },
        ];
        return readyHost({
          hostProfile: {
            ...readyHost().hostProfile,
            collectorCapabilities: {
              official: {
                diskHealth: { diagnostic: "available", status: 1 },
              },
            },
            cpuBaseFrequencyMhz: afterRestore ? 2_444 : 2_400,
            cpuCacheL3Bytes: 8_388_608,
            cpuModel: "Release Test CPU",
            cpuPhysicalCount: 2,
            cpuSocketCount: 1,
            filesystems: afterRestore ? filesystems.reverse() : filesystems,
            networkInterfaces: [
              {
                addresses: afterRestore
                  ? ["fe80::1", "192.0.2.10"]
                  : ["192.0.2.10", "fe80::1"],
                name: "eth0",
              },
              {
                addresses: [afterRestore ? "fe80::2" : "fe80::1"],
                name: afterRestore ? "veth-restored" : "veth-candidate",
              },
            ],
            processCount: afterRestore ? 120 : 110,
            probeVersion: upgraded ? "1.2.3" : "1.2.2",
            threadCount: afterRestore ? 600 : 550,
          },
        });
      },
      async getHostMetrics() {
        metricsEpoch += 1;
        const offset = metricsEpoch * 10;
        calls.push(`hub.getHostMetrics:${activeHub}:${upgraded}`);
        return [
          portableMetric({
            collectedAtMs: offset,
            sequence: metricsEpoch * 2 - 1,
            uptimeSeconds: 100 + offset,
          }),
          portableMetric({
            collectedAtMs: offset + 5,
            sequence: metricsEpoch * 2,
            uptimeSeconds: 105 + offset,
          }),
        ];
      },
      async listHosts() {
        calls.push(`hub.listHosts:${activeHub}`);
        return installed ? [{ id: 7 }] : [];
      },
      async isHostSoftDeleted(hostId) {
        calls.push(`hub.isHostSoftDeleted:${hostId}`);
        return true;
      },
      async requestProbeUninstall(hostId) {
        calls.push(`hub.requestProbeUninstall:${hostId}:${activeHub}`);
        return {
          ...operation,
          id: 42,
          kind: "probe_uninstall",
          targetProbeVersion: null,
        };
      },
      async requestProbeUpgrade(hostId) {
        calls.push(`hub.requestProbeUpgrade:${hostId}`);
        expect(activeHub).toBe("candidate");
        return operation;
      },
      async restoreBaselineStateSnapshot(input) {
        calls.push("hub.restoreBaselineStateSnapshot");
        expect(input).toEqual({
          baselineImageDigest: manifest.releaseBaseline.hub.imageDigest,
          baselineVersion: "v1.2.2",
          expectedManifestDigest: snapshotDigest,
          recoveryTime: "2026-08-02T12:00:00.000Z",
        });
        activeHub = "baseline";
        return {
          image: {
            activeManifestDigest: manifest.releaseBaseline.hub.imageDigest,
            expectedManifestDigest: manifest.releaseBaseline.hub.imageDigest,
          },
          restore: { manifestDigest: snapshotDigest, status: "succeeded" },
          verify: { manifestDigest: snapshotDigest, status: "succeeded" },
        };
      },
      async switchToCandidate() {
        calls.push("hub.switchToCandidate");
        activeHub = "candidate";
      },
      async waitForProbeOperation(requested) {
        calls.push(`hub.waitForProbeOperation:${requested.kind}`);
        if (requested.kind === "probe_upgrade") {
          upgraded = true;
        }
        return [
          requested,
          {
            ...requested,
            acceptedAtMs: 2,
            runningAtMs: 2,
            state: "running",
            updatedAtMs: 2,
          },
          {
            ...requested,
            acceptedAtMs: 2,
            completedAtMs: 3,
            runningAtMs: 2,
            state: "succeeded",
            updatedAtMs: 3,
          },
        ];
      },
    };
    const host = {
      async assertDisposable() {
        calls.push("host.assertDisposable");
      },
      async assertInstalled(_runId, version) {
        calls.push(`host.assertInstalled:${version}`);
        return { probeVersion: version };
      },
      async beginUpgradeOwnershipTransition() {},
      async bindUpgradeOwnershipTransition() {},
      async cleanup() {
        calls.push("host.cleanup");
        return { clean: true };
      },
      async collectEvidence() {
        return { clean: true };
      },
      async completeUpgradeOwnershipTransition() {},
      async install() {
        installed = true;
        calls.push("host.install:baseline");
      },
      async readProbeIdentity() {
        calls.push(`host.readProbeIdentity:${activeHub}:${upgraded}`);
        return {
          identitySha256: "f".repeat(64),
          probeId: "probe_release_01",
        };
      },
      async verifyUninstallCompletion() {
        calls.push("host.verifyUninstallCompletion");
        return {
          clean: true,
          journaldRetained: true,
          sharedDependenciesRetained: true,
        };
      },
    };
    const written = [];

    const result = await runReleaseE2EScenario({
      candidateManifest: manifest,
      environment: {
        async cleanup() {
          calls.push("environment.cleanup");
          return { clean: true };
        },
        async start(options) {
          expect(options.hubMode).toBe("baseline");
          return { host, hub };
        },
      },
      evidenceSink: { write: async (value) => written.push(value) },
      ownerPassword: "owner-password",
      runId: "run-hub-restore",
      scenario: "hub-restore-compatibility-window",
      timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
    });

    expect(result).toEqual({ status: "succeeded" });
    expect(calls.indexOf("hub.captureBaselineStateSnapshot")).toBeLessThan(
      calls.indexOf("hub.switchToCandidate"),
    );
    expect(calls.indexOf("hub.requestProbeUpgrade:7")).toBeLessThan(
      calls.indexOf("hub.restoreBaselineStateSnapshot"),
    );
    expect(
      calls.filter((call) =>
        call.startsWith("hub.requestProbeUninstall:7:candidate"),
      ),
    ).toEqual(["hub.requestProbeUninstall:7:candidate"]);
    expect(calls.indexOf("hub.restoreBaselineStateSnapshot")).toBeLessThan(
      calls.indexOf("hub.requestProbeUninstall:7:candidate"),
    );
    expect(
      calls.filter((call) => call === "hub.switchToCandidate"),
    ).toHaveLength(2);
    expect(calls).toContain("hub.waitForProbeOperation:probe_uninstall");
    expect(calls).toContain("hub.isHostSoftDeleted:7");
    expect(calls).toContain("host.verifyUninstallCompletion");
    expect(calls).not.toContain("host.downgrade");
    expect(written.at(-1)).toMatchObject({
      cleanup: {
        environment: { clean: true },
        host: { clean: true },
      },
      identity: {
        afterRestore: { probeId: "probe_release_01" },
        afterUpgrade: { probeId: "probe_release_01" },
        beforeUpgrade: { probeId: "probe_release_01" },
        hostId: 7,
      },
      hostProfileContinuity: {
        candidateBeforeRestore: {
          projection: {
            architecture: "x86_64",
            collectorCapabilities: {
              official: {
                diskHealth: { diagnostic: "available", status: 1 },
              },
            },
            cpu: {
              cacheL3Bytes: 8_388_608,
              count: 2,
              model: "Release Test CPU",
              physicalCount: 2,
              socketCount: 1,
            },
            filesystems: [
              {
                filesystemType: "ext4",
                mountPoint: "/",
                totalBytes: 1_000_000_000,
              },
              {
                filesystemType: "ext4",
                mountPoint: "/var",
                totalBytes: 500_000_000,
              },
            ],
            hostname: "release-test-host",
            kernel: "6.8.0",
            memoryTotalBytes: 2_147_483_648,
            networkInterfaces: [
              {
                addresses: ["192.0.2.10", "fe80::1"],
                name: "eth0",
              },
            ],
            os: "ubuntu",
            probeVersion: "1.2.3",
          },
          sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        },
        restoredBaseline: {
          projection: expect.any(Object),
          sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        },
      },
      image: {
        restoredBaselineDigest: manifest.releaseBaseline.hub.imageDigest,
      },
      migration: {
        candidateProbeVersion: "1.2.3",
        status: "succeeded",
      },
      protocol: {
        candidateProbeToBaselineHub: "succeeded",
      },
      uninstall: {
        hostCompletion: {
          clean: true,
          journaldRetained: true,
          sharedDependenciesRetained: true,
        },
        hubSoftDeleted: true,
        operationTimeline: [
          expect.objectContaining({
            kind: "probe_uninstall",
            state: "pending",
          }),
          expect.objectContaining({
            kind: "probe_uninstall",
            state: "running",
          }),
          expect.objectContaining({
            kind: "probe_uninstall",
            state: "succeeded",
          }),
        ],
        status: "succeeded",
      },
      reporting: {
        restoredBaselineHub: {
          host: expect.objectContaining({ id: 7 }),
          metrics: expect.any(Array),
        },
      },
      snapshot: {
        baselineImageDigest: manifest.releaseBaseline.hub.imageDigest,
        manifestDigest: snapshotDigest,
        roots: expect.arrayContaining([
          expect.objectContaining({ id: "data-root" }),
          expect.objectContaining({ id: "metrics-archive" }),
        ]),
      },
    });
    expect(written.at(-1).hostProfileContinuity.restoredBaseline).toEqual(
      written.at(-1).hostProfileContinuity.candidateBeforeRestore,
    );
  });

  it("rejects a typed Candidate Probe Host Profile whose stable semantics change after Hub Restore", async () => {
    let activeHub = "baseline";
    let installed = false;
    let metricsEpoch = 0;
    let upgraded = false;
    const manifest = candidateManifestWithBaseline();
    const snapshotDigest = `sha256:${"d".repeat(64)}`;
    const operation = {
      acceptedAtMs: null,
      completedAtMs: null,
      createdAtMs: 1,
      failure: null,
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      runningAtMs: null,
      state: "pending",
      targetProbeVersion: "1.2.3",
      updatedAtMs: 1,
    };
    const hub = {
      async authenticate() {},
      async captureBaselineStateSnapshot() {
        return {
          baselineImageDigest: manifest.releaseBaseline.hub.imageDigest,
          baselineVersion: "v1.2.2",
          hotDataFileCount: 1,
          hotDataFiles: ["data-root/enoki.db"],
          manifestDigest: snapshotDigest,
          recoveryTime: "2026-08-02T12:00:00.000Z",
          roots: [
            { id: "data-root", included: true, path: "/data" },
            {
              id: "metrics-archive",
              included: true,
              path: "/data/metrics-archive",
            },
          ],
          tool: "enoki-hub-state",
          version: "v1",
        };
      },
      async createEnrollment() {
        return { installCommand: officialInstallCommand };
      },
      async getHost() {
        const host = readyHost({
          hostProfile: {
            ...readyHost().hostProfile,
            probeVersion: upgraded ? "1.2.3" : "1.2.2",
          },
        });
        if (activeHub === "baseline" && upgraded) {
          host.hostProfile.hostname = "typed-but-wrong-hostname";
        }
        return host;
      },
      async getHostMetrics() {
        metricsEpoch += 1;
        return [
          portableMetric({
            collectedAtMs: metricsEpoch * 10,
            sequence: metricsEpoch * 2 - 1,
            uptimeSeconds: 100 + metricsEpoch * 10,
          }),
          portableMetric({
            collectedAtMs: metricsEpoch * 10 + 5,
            sequence: metricsEpoch * 2,
            uptimeSeconds: 105 + metricsEpoch * 10,
          }),
        ];
      },
      async listHosts() {
        return installed ? [{ id: 7 }] : [];
      },
      async isHostSoftDeleted() {
        return true;
      },
      async requestProbeUninstall() {
        throw new Error("uninstall must not be reached after profile failure");
      },
      async requestProbeUpgrade() {
        return operation;
      },
      async restoreBaselineStateSnapshot() {
        activeHub = "baseline";
        return {
          image: {
            activeManifestDigest: manifest.releaseBaseline.hub.imageDigest,
            expectedManifestDigest: manifest.releaseBaseline.hub.imageDigest,
          },
          restore: { manifestDigest: snapshotDigest, status: "succeeded" },
          verify: { manifestDigest: snapshotDigest, status: "succeeded" },
        };
      },
      async switchToCandidate() {
        activeHub = "candidate";
      },
      async waitForProbeOperation() {
        upgraded = true;
        return [
          operation,
          {
            ...operation,
            acceptedAtMs: 2,
            runningAtMs: 2,
            state: "running",
            updatedAtMs: 2,
          },
          {
            ...operation,
            acceptedAtMs: 2,
            completedAtMs: 3,
            runningAtMs: 2,
            state: "succeeded",
            updatedAtMs: 3,
          },
        ];
      },
    };
    const host = {
      async assertDisposable() {},
      async assertInstalled() {},
      async beginUpgradeOwnershipTransition() {},
      async bindUpgradeOwnershipTransition() {},
      async cleanup() {
        return { clean: true };
      },
      async collectEvidence() {
        return { clean: true };
      },
      async completeUpgradeOwnershipTransition() {},
      async install() {
        installed = true;
      },
      async readProbeIdentity() {
        return {
          identitySha256: "f".repeat(64),
          probeId: "probe_release_01",
        };
      },
      async verifyUninstallCompletion() {
        throw new Error("completion must not be reached after profile failure");
      },
    };
    const written = [];

    await expect(
      runReleaseE2EScenario({
        candidateManifest: manifest,
        environment: {
          cleanup: async () => ({ clean: true }),
          start: async () => ({ host, hub }),
        },
        evidenceSink: { write: async (value) => written.push(value) },
        ownerPassword: "owner-password",
        runId: "run-hub-restore-wrong-profile",
        scenario: "hub-restore-compatibility-window",
        timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
      }),
    ).rejects.toMatchObject({
      code: "host_profile_stable_projection_changed",
    });
    expect(written.at(-1)).toMatchObject({
      failureBoundary: "protocol",
      hostProfileContinuity: {
        candidateBeforeRestore: {
          projection: { hostname: "release-test-host" },
          sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        },
        restoredBaseline: {
          projection: { hostname: "typed-but-wrong-hostname" },
          sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        },
      },
      result: {
        error: { code: "host_profile_stable_projection_changed" },
        status: "failed",
      },
    });
    expect(
      written.at(-1).hostProfileContinuity.candidateBeforeRestore.sha256,
    ).not.toBe(written.at(-1).hostProfileContinuity.restoredBaseline.sha256);
  });

  it("proves post-replacement failure, real Repair continuity, and Uninstall Completion", async () => {
    const calls = [];
    let activeHub = "baseline";
    let configurationVersion = "default-v1";
    let installed = false;
    let invalidHostEvidence = false;
    let repaired = false;
    let metricsEpoch = 0;
    const failedUpgrade = {
      acceptedAtMs: 2,
      completedAtMs: 20,
      createdAtMs: 1,
      failure: {
        code: "post_replacement_restart_failure",
        message: "Probe binary was replaced, but restart failed.",
      },
      hostId: 7,
      id: 41,
      kind: "probe_upgrade",
      runningAtMs: 2,
      state: "failed",
      targetProbeVersion: "1.2.3",
      updatedAtMs: 20,
    };
    const hub = {
      async authenticate() {
        calls.push(`hub.authenticate:${activeHub}`);
      },
      async createEnrollment() {
        return { installCommand: officialInstallCommand };
      },
      async getAuditLog() {
        return baselineUpgradeAuditLog();
      },
      async getHost() {
        return readyHost({
          hostProfile: {
            ...readyHost().hostProfile,
            probeVersion: repaired ? "1.2.3" : "1.2.2",
          },
          reportedProbeConfigurationVersion: configurationVersion,
        });
      },
      async getHostMetrics() {
        metricsEpoch += 1;
        const base = repaired ? 10_000 : 0;
        return [
          portableMetric({
            collectedAtMs: base + metricsEpoch * 10,
            sequence: base + metricsEpoch * 2 - 1,
            uptimeSeconds: 100 + metricsEpoch * 10,
          }),
          portableMetric({
            collectedAtMs: base + metricsEpoch * 10 + 5,
            sequence: base + metricsEpoch * 2,
            uptimeSeconds: 105 + metricsEpoch * 10,
          }),
        ];
      },
      async getHostProbeConfiguration() {
        return {
          configuration: {
            enabledCollectorIds: ["official.cpu", "official.memory"],
            metricsCollectionIntervalSeconds: 5,
            version: configurationVersion,
          },
          mode: configurationVersion === "default-v1" ? "inherit" : "override",
        };
      },
      async getProbeOperation() {
        calls.push("hub.getProbeOperation:failed");
        return { ...failedUpgrade };
      },
      async collectEvidence() {
        return successfulRepairBoundaryEvidence().hubEvidence;
      },
      async isHostSoftDeleted() {
        return true;
      },
      async listHosts() {
        return installed ? [{ id: 7 }] : [];
      },
      async requestProbeUpgrade(hostId) {
        calls.push("hub.requestProbeUpgrade");
        return {
          ...failedUpgrade,
          acceptedAtMs: null,
          completedAtMs: null,
          failure: null,
          hostId,
          runningAtMs: null,
          state: "pending",
          updatedAtMs: 1,
        };
      },
      async requestProbeUninstall(hostId) {
        calls.push("hub.requestProbeUninstall");
        return {
          acceptedAtMs: null,
          completedAtMs: null,
          createdAtMs: 30,
          failure: null,
          hostId,
          id: 42,
          kind: "probe_uninstall",
          runningAtMs: null,
          state: "pending",
          targetProbeVersion: "",
          updatedAtMs: 30,
        };
      },
      async switchToCandidate() {
        activeHub = "candidate";
        calls.push("hub.switchToCandidate");
      },
      async updateHostProbeConfiguration(_hostId, input) {
        calls.push(`hub.updateHostProbeConfiguration:${activeHub}`);
        configurationVersion =
          configurationVersion === "default-v1" ? "host-7-1" : "host-7-2";
        return {
          configuration: {
            ...input.configuration,
            version: configurationVersion,
          },
          mode: "override",
        };
      },
      async waitForProbeOperation(operation) {
        if (operation.kind === "probe_upgrade") {
          expect(repaired).toBe(true);
          return [
            operation,
            {
              ...operation,
              acceptedAtMs: 2,
              runningAtMs: 2,
              state: "running",
              updatedAtMs: 2,
            },
            { ...failedUpgrade },
            { ...failedUpgrade },
          ];
        }
        const succeeded = {
          ...operation,
          acceptedAtMs: 31,
          completedAtMs: 32,
          runningAtMs: 31,
          state: "succeeded",
          updatedAtMs: 32,
        };
        return [operation, succeeded, succeeded];
      },
    };
    const host = {
      async armPostReplacementRestartFault() {
        calls.push("host.armPostReplacementRestartFault");
      },
      async assertDisposable() {},
      async assertInstalled(_runId, version) {
        calls.push(`host.assertInstalled:${version}`);
        return version === "1.2.3"
          ? successfulRepairBoundaryEvidence().repairHostBoundary
          : { probeVersion: version };
      },
      async assertPostReplacementUpgradeFailure(_runId, operation, version) {
        calls.push("host.assertPostReplacementUpgradeFailure");
        expect(operation).toMatchObject({ state: "pending" });
        return {
          localFailureCode: "post_replacement_restart_failure",
          operationId: operation.id,
          probeVersion: version,
        };
      },
      async beginUpgradeOwnershipTransition() {},
      async bindUpgradeOwnershipTransition() {},
      async cleanup() {
        return { clean: true };
      },
      async collectEvidence() {
        if (invalidHostEvidence) {
          throw Object.assign(new Error("Host evidence collection failed"), {
            code: "host_evidence_collection_failed",
          });
        }
        return successfulRepairBoundaryEvidence().hostEvidence;
      },
      async completeRepairOwnershipTransition() {
        calls.push("host.completeRepairOwnershipTransition");
      },
      async completeUpgradeOwnershipTransition() {},
      async install() {
        installed = true;
      },
      async readProbeIdentity() {
        return {
          identitySha256: "f".repeat(64),
          probeId: "probe_release_01",
        };
      },
      async removePostReplacementRestartFault() {
        calls.push("host.removePostReplacementRestartFault");
      },
      async repair() {
        calls.push("host.repair");
        repaired = true;
        return {
          output: "Probe Repair succeeded",
          probeId: "probe_release_01",
          repairedVersion: "1.2.3",
        };
      },
      async verifyUninstallCompletion() {
        return successfulRepairBoundaryEvidence().uninstallCompletion;
      },
    };
    const written = [];

    const result = await runReleaseE2EScenario({
      candidateManifest: candidateManifestWithBaseline(),
      environment: {
        async cleanup() {
          return { clean: true };
        },
        async start(options) {
          expect(options).toMatchObject({
            hubMode: "baseline",
            scenario: "post-replacement-repair-uninstall",
          });
          return { host, hub };
        },
      },
      evidenceSink: { write: async (value) => written.push(value) },
      ownerPassword: "owner-password",
      runId: "run-repair",
      scenario: "post-replacement-repair-uninstall",
      timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
    });

    expect(result).toEqual({ status: "succeeded" });
    expect(
      calls.filter((call) => call === "hub.requestProbeUpgrade"),
    ).toHaveLength(1);
    expect(calls.filter((call) => call === "host.repair")).toHaveLength(1);
    expect(
      calls.filter((call) => call === "hub.requestProbeUninstall"),
    ).toHaveLength(1);
    expect(calls.indexOf("host.armPostReplacementRestartFault")).toBeLessThan(
      calls.indexOf("hub.requestProbeUpgrade"),
    );
    expect(
      calls.indexOf("host.assertPostReplacementUpgradeFailure"),
    ).toBeLessThan(calls.indexOf("host.repair"));
    expect(calls).toContain("hub.getProbeOperation:failed");
    expect(calls).toContain("host.assertInstalled:1.2.3");
    expect(calls).toContain("hub.requestProbeUninstall");
    expect(
      calls.filter(
        (call) => call === "hub.updateHostProbeConfiguration:candidate",
      ),
    ).toHaveLength(2);
    expect(calls).not.toContain("hub.updateHostProbeConfiguration:baseline");
    expect(written.at(-1)).toMatchObject({
      boundaryEvidence: {
        cleanup: {
          orchestrator: {
            environment: { clean: true },
            host: { clean: true },
          },
          uninstallCompletion: expect.objectContaining({ clean: true }),
        },
        filesystem: {
          afterRepair: expect.objectContaining({
            files: expect.arrayContaining(["/usr/local/bin/enoki-probe"]),
          }),
          postUninstall: {
            accounts: { group: false, user: false },
            files: [],
            units: [],
          },
        },
        hubApi: {
          apiTimeline: expect.arrayContaining([
            expect.objectContaining({ pathname: "/api/web/auth/login" }),
          ]),
          auditLog: expect.arrayContaining([
            expect.objectContaining({ action: "host.delete" }),
          ]),
          repairedHost: expect.objectContaining({ id: 7, status: "online" }),
          runtime: expect.objectContaining({ identityVerified: true }),
        },
        identity: {
          after: { probeId: "probe_release_01" },
          before: { probeId: "probe_release_01" },
          hostId: 7,
        },
        privilege: {
          afterRepair: "",
          postUninstall: expect.objectContaining({ code: 0 }),
        },
        probeOperation: {
          uninstall: expect.arrayContaining([
            expect.objectContaining({ state: "succeeded" }),
          ]),
          upgrade: expect.arrayContaining([
            expect.objectContaining({ state: "failed" }),
          ]),
        },
        systemd: {
          afterRepair: expect.objectContaining({ ActiveState: "active" }),
          journald: expect.objectContaining({
            code: 0,
            stdout: expect.stringContaining("Probe Repair resumed reporting"),
          }),
          postUninstall: expect.objectContaining({ code: 0 }),
        },
      },
      boundaryEvidenceValidation: { status: "succeeded" },
      failureBoundary: {
        hubFailureCode: "post_replacement_restart_failure",
        localFailureCode: "post_replacement_restart_failure",
        probeVersion: "1.2.3",
      },
      identityContinuity: {
        after: { probeId: "probe_release_01" },
        before: { probeId: "probe_release_01" },
        hostId: 7,
      },
      operationTimeline: expect.arrayContaining([
        expect.objectContaining({ state: "failed" }),
      ]),
      result: { status: "succeeded" },
    });

    const waitForSuccessfulProbeOperation = hub.waitForProbeOperation;
    hub.waitForProbeOperation = async (operation) => {
      const timeline = await waitForSuccessfulProbeOperation(operation);
      if (operation.kind === "probe_uninstall") {
        throw Object.assign(new Error("Probe Uninstall timed out"), {
          code: "probe_operation_timeout",
          timeline,
        });
      }
      return timeline;
    };
    activeHub = "baseline";
    configurationVersion = "default-v1";
    installed = false;
    metricsEpoch = 0;
    repaired = false;
    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifestWithBaseline(),
        environment: {
          async cleanup() {
            return { clean: true };
          },
          async start() {
            return { host, hub };
          },
        },
        evidenceSink: { write: async (value) => written.push(value) },
        ownerPassword: "owner-password",
        runId: "run-repair-uninstall-timeout",
        scenario: "post-replacement-repair-uninstall",
        timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
      }),
    ).rejects.toMatchObject({ code: "probe_operation_timeout" });
    expect(written.at(-1)).toMatchObject({
      operationTimeline: expect.arrayContaining([
        expect.objectContaining({ kind: "probe_upgrade", state: "failed" }),
      ]),
      uninstall: {
        operationTimeline: expect.arrayContaining([
          expect.objectContaining({ kind: "probe_uninstall" }),
        ]),
      },
      uninstallOperationTimeline: expect.arrayContaining([
        expect.objectContaining({ kind: "probe_uninstall" }),
      ]),
    });
    hub.waitForProbeOperation = waitForSuccessfulProbeOperation;

    activeHub = "baseline";
    configurationVersion = "default-v1";
    installed = false;
    invalidHostEvidence = true;
    metricsEpoch = 0;
    repaired = false;
    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifestWithBaseline(),
        environment: {
          async cleanup() {
            calls.push("environment.cleanup:failed");
            throw Object.assign(new Error("VM cleanup observation failed"), {
              code: "environment_cleanup_failed",
            });
          },
          async start() {
            return { host, hub };
          },
        },
        evidenceSink: { write: async (value) => written.push(value) },
        ownerPassword: "owner-password",
        runId: "run-repair-invalid-evidence",
        scenario: "post-replacement-repair-uninstall",
        timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
      }),
    ).rejects.toMatchObject({ code: "repair_boundary_evidence_invalid" });
    expect(written.at(-1)).toMatchObject({
      boundaryEvidenceValidation: {
        boundary: "filesystem",
        error: { code: "repair_boundary_evidence_invalid" },
        status: "failed",
      },
      cleanup: {
        environment: {
          error: { code: "environment_cleanup_failed" },
        },
        host: { clean: true },
      },
      hostEvidence: {
        error: { code: "host_evidence_collection_failed" },
      },
      result: {
        error: { code: "repair_boundary_evidence_invalid" },
        status: "failed",
      },
    });
    expect(calls).toContain("environment.cleanup:failed");
  });

  it("keeps the Repair primary failure while retaining evidence and cleanup failures", async () => {
    const calls = [];
    const primary = Object.assign(new Error("Repair Host preflight failed"), {
      code: "repair_host_preflight_failed",
    });
    const host = Object.fromEntries(
      [
        "armPostReplacementRestartFault",
        "assertDisposable",
        "assertInstalled",
        "assertPostReplacementUpgradeFailure",
        "beginUpgradeOwnershipTransition",
        "bindUpgradeOwnershipTransition",
        "cleanup",
        "collectEvidence",
        "completeRepairOwnershipTransition",
        "completeUpgradeOwnershipTransition",
        "install",
        "readProbeIdentity",
        "removePostReplacementRestartFault",
        "repair",
        "verifyUninstallCompletion",
      ].map((method) => [method, async () => null]),
    );
    host.assertDisposable = async () => {
      throw primary;
    };
    host.collectEvidence = async () => {
      calls.push("host.collectEvidence");
      throw Object.assign(new Error("Host collector failed"), {
        code: "host_collector_failed",
      });
    };
    host.cleanup = async () => {
      calls.push("host.cleanup");
      throw Object.assign(new Error("Host cleanup failed"), {
        code: "host_cleanup_failed",
      });
    };
    const hub = Object.fromEntries(
      [
        "authenticate",
        "createEnrollment",
        "getAuditLog",
        "getHost",
        "getHostMetrics",
        "getHostProbeConfiguration",
        "getProbeOperation",
        "isHostSoftDeleted",
        "listHosts",
        "requestProbeUninstall",
        "requestProbeUpgrade",
        "switchToCandidate",
        "updateHostProbeConfiguration",
        "waitForProbeOperation",
      ].map((method) => [method, async () => null]),
    );
    hub.collectEvidence = async () => {
      calls.push("hub.collectEvidence");
      throw Object.assign(new Error("Hub collector failed"), {
        code: "hub_collector_failed",
      });
    };
    const written = [];

    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifestWithBaseline(),
        environment: {
          async cleanup() {
            calls.push("environment.cleanup");
            throw Object.assign(new Error("Environment cleanup failed"), {
              code: "environment_cleanup_failed",
            });
          },
          async start() {
            return { host, hub };
          },
        },
        evidenceSink: { write: async (value) => written.push(value) },
        ownerPassword: "owner-password",
        runId: "run-repair-primary-failure",
        scenario: "post-replacement-repair-uninstall",
      }),
    ).rejects.toMatchObject({ code: "repair_host_preflight_failed" });
    expect(calls).toEqual([
      "hub.collectEvidence",
      "host.collectEvidence",
      "host.cleanup",
      "environment.cleanup",
    ]);
    expect(written.at(-1)).toMatchObject({
      cleanup: {
        environment: { error: { code: "environment_cleanup_failed" } },
        host: { error: { code: "host_cleanup_failed" } },
      },
      hostEvidence: { error: { code: "host_collector_failed" } },
      hubEvidence: { error: { code: "hub_collector_failed" } },
      result: {
        error: { code: "repair_host_preflight_failed" },
        status: "failed",
      },
    });
  });

  it("captures diagnostics before cleanup without masking the primary failure", async () => {
    const calls = [];
    const primary = Object.assign(
      new Error(
        "Enrollment API unavailable owner-password enk_enroll_secret Authorization: Bearer probe-secret Cookie: owner-session-secret",
      ),
      {
        code: "hub_api_unavailable",
      },
    );
    const participant = async (name, value) => {
      calls.push(name);
      return value;
    };
    const host = {
      assertDisposable: () => participant("host.assertDisposable"),
      assertInstalled: () => participant("host.assertInstalled"),
      cleanup: async () => {
        calls.push("host.cleanup");
        throw new Error("cleanup could not reach Host");
      },
      collectEvidence: () =>
        participant("host.collectEvidence", {
          journald: "enk_enroll_secret owner-password",
          systemd: "captured",
        }),
      collectDiagnostics: () =>
        participant("host.collectDiagnostics", {
          installation: {
            available: false,
            error: { code: "diagnostic_command_failed" },
          },
          inventory: {
            available: true,
            value: {
              accounts: { group: false, user: false },
              files: [],
              units: [],
            },
          },
          journald: {
            available: false,
            error: { code: "diagnostic_command_failed" },
          },
          sudoers: {
            available: false,
            error: { code: "sudoers_unavailable" },
          },
          systemd: {
            available: false,
            error: { code: "diagnostic_command_failed" },
          },
        }),
      install: () => participant("host.install"),
      awaitPermanentReportRejection: () =>
        participant("host.awaitPermanentReportRejection"),
      captureInstallationState: () =>
        participant("host.captureInstallationState"),
      localUninstall: () => participant("host.localUninstall"),
      readProbeIdentity: () => participant("host.readProbeIdentity"),
      rejectRepeatedInstall: () => participant("host.rejectRepeatedInstall"),
      repairInstalledBundleFailure: () =>
        participant("host.repairInstalledBundleFailure"),
      verifyUninstallCompletion: () =>
        participant("host.verifyUninstallCompletion"),
    };
    const hub = {
      authenticate: () => participant("hub.authenticate"),
      async createEnrollment() {
        calls.push("hub.createEnrollment");
        throw primary;
      },
      deleteHostHubOnly: () => participant("hub.deleteHostHubOnly"),
      getHost: () => participant("hub.getHost"),
      getEnrollment: () => participant("hub.getEnrollment"),
      getAuditLog: () => participant("hub.getAuditLog", []),
      getHostMetrics: () => participant("hub.getHostMetrics"),
      getHostProbeConfiguration: () =>
        participant("hub.getHostProbeConfiguration"),
      isHostSoftDeleted: () => participant("hub.isHostSoftDeleted"),
      listHosts: () => participant("hub.listHosts", []),
      collectEvidence: () =>
        participant("hub.collectEvidence", {
          headers:
            "Authorization: Bearer probe-secret Cookie: owner-session-secret",
        }),
      requestProbeUninstall: () => participant("hub.requestProbeUninstall"),
      updateHostProbeConfiguration: () =>
        participant("hub.updateHostProbeConfiguration"),
      waitForProbeOperation: () => participant("hub.waitForProbeOperation"),
    };
    const written = [];

    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifest(),
        environment: {
          async cleanup() {
            calls.push("environment.cleanup");
            return { clean: true };
          },
          async start() {
            return { host, hub };
          },
        },
        evidenceSink: {
          async write(value) {
            written.push(value);
          },
        },
        ownerPassword: "owner-password",
        runId: "run-failure",
        scenario: "fresh-install-uninstall",
      }),
    ).rejects.toMatchObject({
      code: "hub_api_unavailable",
      message: expect.stringContaining("Enrollment API unavailable"),
    });
    expect(calls.indexOf("host.collectEvidence")).toBeLessThan(
      calls.indexOf("host.cleanup"),
    );
    expect(written.at(-1)).toMatchObject({
      cleanup: {
        host: { error: { message: "cleanup could not reach Host" } },
      },
      hostEvidence: {
        journald: expect.stringContaining("[REDACTED"),
        systemd: "captured",
      },
      diagnostics: {
        host: {
          inventory: { available: true },
          installation: { available: false },
          journald: { available: false },
          sudoers: { available: false },
          systemd: { available: false },
        },
      },
      result: {
        error: {
          code: "hub_api_unavailable",
          message: expect.stringContaining("[REDACTED"),
        },
        status: "failed",
      },
    });
    const serialized = JSON.stringify(written.at(-1));
    expect(serialized).not.toContain("owner-password");
    expect(serialized).not.toContain("enk_enroll_secret");
    expect(serialized).not.toContain("probe-secret");
    expect(serialized).not.toContain("owner-session-secret");
  });

  it("retains redacted failed installer evidence without retaining its command", async () => {
    const failure = Object.assign(new Error("Probe installation failed"), {
      code: "probe_installation_failed",
      installerEvidence: {
        code: 1,
        stderr: "installer rejected the token",
        stdout: `${officialInstallCommand}\nENOKI_ENROLLMENT_TOKEN=enk_enroll_failed_installer_token curl install failed`,
      },
    });
    const enrollment = {
      enrollmentId: "enr_failed_installer",
      enrollmentToken: "enk_enroll_failed_installer_token",
      installCommand: officialInstallCommand,
      status: "pending",
      target: { kind: "new_host" },
    };
    const partialDiagnostics = {
      installation: {
        available: false,
        error: { code: "diagnostic_command_failed" },
      },
      inventory: {
        available: true,
        value: {
          accounts: { group: false, user: false },
          files: [],
          units: [],
        },
      },
      journald: {
        available: false,
        error: { code: "diagnostic_command_failed" },
      },
      sudoers: {
        available: false,
        error: { code: "diagnostic_command_failed" },
      },
      systemd: {
        available: false,
        error: { code: "diagnostic_command_failed" },
      },
    };
    const host = {
      assertDisposable: async () => {},
      assertInstalled: async () => {},
      awaitPermanentReportRejection: async () => {},
      captureInstallationState: async () => {},
      cleanup: async () => ({ clean: true }),
      collectDiagnostics: async () => partialDiagnostics,
      collectEvidence: async () => ({ available: true }),
      install: async () => {
        throw failure;
      },
      localUninstall: async () => {},
      readProbeIdentity: async () => {},
      rejectRepeatedInstall: async () => {},
      repairInstalledBundleFailure: async () => {},
    };
    const hub = {
      authenticate: async () => {},
      collectEvidence: async () => ({
        apiTimeline: [],
        enrollments: [
          {
            enrollmentId: enrollment.enrollmentId,
            hostId: null,
            rejection: null,
            status: "pending",
            target: enrollment.target,
          },
        ],
      }),
      createEnrollment: async () => enrollment,
      deleteHostHubOnly: async () => {},
      getAuditLog: async () => [],
      getEnrollment: async () => {},
      getHost: async () => {},
      getHostMetrics: async () => [],
      getHostProbeConfiguration: async () => {},
      isHostSoftDeleted: async () => false,
      listHosts: async () => [],
      updateHostProbeConfiguration: async () => {},
    };
    const written = [];

    await expect(
      runReleaseE2EScenario({
        candidateManifest: candidateManifest(),
        environment: {
          cleanup: async () => ({ clean: true }),
          start: async () => ({ host, hub }),
        },
        evidenceSink: { write: async (value) => written.push(value) },
        ownerPassword: "owner-password",
        runId: "run-failed-installer",
        scenario: "fresh-install-uninstall",
      }),
    ).rejects.toMatchObject({ code: "probe_installation_failed" });

    const artifact = written.at(-1);
    expect(artifact).toMatchObject({
      diagnostics: { host: { inventory: { available: true } } },
      hubEvidence: {
        enrollments: [
          expect.objectContaining({
            enrollmentId: "enr_failed_installer",
            status: "pending",
          }),
        ],
      },
      result: {
        error: {
          code: "probe_installation_failed",
          installerEvidence: {
            code: 1,
            stdout: expect.stringContaining("[REDACTED_INSTALLER_COMMAND]"),
          },
        },
      },
    });
    const serialized = JSON.stringify(artifact);
    expect(serialized).not.toContain("enk_enroll_secret");
    expect(serialized).not.toContain("enk_enroll_failed_installer_token");
    expect(serialized).not.toContain(officialInstallCommand);
  });
});

describe("Release E2E command", () => {
  it("rejects invalid planning inputs before creating artifacts or provisioning", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-release-run-"));
    const evidenceDir = path.join(root, "evidence");
    const matrixPath = path.join(root, "release-e2e-matrix.json");
    const script = fileURLToPath(new URL("./release-e2e.mjs", import.meta.url));
    await writeFile(matrixPath, '{"schemaVersion":999}', "utf8");
    try {
      await expect(
        execFileAsync(
          process.execPath,
          [
            script,
            "run",
            "--candidate-manifest",
            path.join(root, "candidate-manifest.json"),
            "--host-adapter",
            "ci",
            "--matrix",
            matrixPath,
            "--matrix-cell",
            "ubuntu-22.04-x86_64--fresh-install-uninstall",
            "--hub-public-url",
            "http://127.0.0.1:33000",
            "--hub-owner-url",
            "http://127.0.0.1:33000",
            "--owner-password-env",
            "ENOKI_E2E_OWNER_PASSWORD",
            "--root-public-key-env",
            "ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM",
            "--evidence-dir",
            evidenceDir,
            "--run-id",
            "run-early-matrix",
          ],
          {
            env: {
              ...process.env,
              ENOKI_E2E_OWNER_PASSWORD: "must-not-be-recorded",
              ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM: "test-root",
            },
          },
        ),
      ).rejects.toMatchObject({ code: 1 });

      await expect(
        readFile(path.join(evidenceDir, "run-manifest.json"), "utf8"),
      ).rejects.toMatchObject({ code: "ENOENT" });
      await expect(
        readFile(path.join(evidenceDir, "evidence.json"), "utf8"),
      ).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("creates no artifacts when candidate verification or the Host adapter fails preflight", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-release-run-"));
    const script = fileURLToPath(new URL("./release-e2e.mjs", import.meta.url));
    const matrixPath = fileURLToPath(
      new URL("./release-e2e-matrix.json", import.meta.url),
    );
    const cases = [
      {
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_RUN_ATTEMPT: "1",
          GITHUB_RUN_ID: "1234",
          RUNNER_ARCH: "X64",
          RUNNER_OS: "Linux",
        },
        name: "candidate",
      },
      {
        environment: {
          GITHUB_ACTIONS: "",
          GITHUB_RUN_ATTEMPT: "",
          GITHUB_RUN_ID: "",
          RUNNER_ARCH: "",
          RUNNER_OS: "",
        },
        name: "adapter",
      },
    ];
    try {
      for (const testCase of cases) {
        const evidenceDir = path.join(root, testCase.name);
        await expect(
          execFileAsync(
            process.execPath,
            [
              script,
              "run",
              "--candidate-manifest",
              path.join(root, "candidate-manifest.json"),
              "--host-adapter",
              "ci",
              "--matrix",
              matrixPath,
              "--matrix-cell",
              "ubuntu-22.04-x86_64--fresh-install-uninstall",
              "--hub-public-url",
              "http://127.0.0.1:33000",
              "--hub-owner-url",
              "http://127.0.0.1:33000",
              "--owner-password-env",
              "ENOKI_E2E_OWNER_PASSWORD",
              "--root-public-key-env",
              "ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM",
              "--evidence-dir",
              evidenceDir,
              "--run-id",
              `run-early-${testCase.name}`,
            ],
            {
              env: {
                ...process.env,
                ...testCase.environment,
                ENOKI_E2E_OWNER_PASSWORD: "must-not-be-recorded",
                ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM: "test-root",
              },
            },
          ),
        ).rejects.toMatchObject({ code: 1 });
        await expect(
          readFile(path.join(evidenceDir, "run-manifest.json"), "utf8"),
        ).rejects.toMatchObject({ code: "ENOENT" });
        await expect(
          readFile(path.join(evidenceDir, "evidence.json"), "utf8"),
        ).rejects.toMatchObject({ code: "ENOENT" });
      }
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("derives scenario selection from the matrix cell and the shared registry only", () => {
    expect(Object.keys(releaseE2EScenarioRegistry)).toEqual([
      "compatible-upgrade-uninstall",
      "fresh-install-uninstall",
      "hub-restore-compatibility-window",
      "post-replacement-repair-uninstall",
      "replacement-migration-uninstall",
    ]);
    const arguments_ = [
      "run",
      "--candidate-manifest",
      "/candidate/candidate-manifest.json",
      "--host-adapter",
      "ci",
      "--matrix",
      "/source/scripts/release-e2e-matrix.json",
      "--matrix-cell",
      "ubuntu-22.04-x86_64--fresh-install-uninstall",
      "--hub-public-url",
      "http://127.0.0.1:33000",
      "--hub-owner-url",
      "http://127.0.0.1:33000",
      "--owner-password-env",
      "ENOKI_E2E_OWNER_PASSWORD",
      "--root-public-key-env",
      "ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM",
      "--evidence-dir",
      "/tmp/enoki-evidence",
    ];

    expect(parseReleaseE2ECommandLine(arguments_).values).not.toHaveProperty(
      "--scenario",
    );
    const restoreArguments = [...arguments_];
    restoreArguments[restoreArguments.indexOf("--matrix-cell") + 1] =
      "ubuntu-24.04-x86_64--hub-restore-compatibility-window";
    expect(
      parseReleaseE2ECommandLine(restoreArguments).values["--matrix-cell"],
    ).toBe("ubuntu-24.04-x86_64--hub-restore-compatibility-window");
    expect(() =>
      parseReleaseE2ECommandLine([
        ...arguments_,
        "--scenario",
        "fresh-install-uninstall",
      ]),
    ).toThrow(/unknown option: --scenario/i);
  });

  it("registers post-replacement Repair as a shared business scenario", () => {
    expect(Object.keys(releaseE2EScenarioRegistry)).toContain(
      "post-replacement-repair-uninstall",
    );
  });

  it("keeps CI and SSH infrastructure behind one prepare/execute/release contract", async () => {
    const loadedCandidate = {
      candidateDir: "/candidate",
      manifest: candidateManifest(),
    };
    const commandResults = [];
    const runProcess = async (command, arguments_, options) => {
      commandResults.push({ arguments_, command, options });
      return successfulCommandText("ready\n");
    };
    const adapters = [
      createSshReleaseInfrastructureAdapter({
        candidateManifestPath: "/candidate/candidate-manifest.json",
        host: "root@192.0.2.10",
        knownHostsPath: "/tmp/release-e2e-known-hosts",
        loadCandidate: async () => loadedCandidate,
        runProcess,
      }),
      createCiReleaseInfrastructureAdapter({
        candidateManifestPath: "/candidate/candidate-manifest.json",
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_RUN_ATTEMPT: "2",
          GITHUB_RUN_ID: "1234",
          RUNNER_ARCH: "X64",
          RUNNER_OS: "Linux",
        },
        loadCandidate: async () => loadedCandidate,
        runProcess,
      }),
    ];

    for (const adapter of adapters) {
      const prepared = await adapter.prepare({
        matrixCell: freshMatrixCell(),
        runId: "run-adapter",
      });
      expect(Object.keys(prepared).sort()).toEqual([
        "candidateDir",
        "execute",
        "infrastructure",
        "manifest",
        "provisionBootstrap",
      ]);
      await expect(prepared.execute("printf ready")).resolves.toEqual(
        successfulCommandText("ready\n"),
      );
      await expect(prepared.execute("id -u", { root: true })).resolves.toEqual(
        successfulCommandText("ready\n"),
      );
      await expect(
        adapter.release({ prepared, runId: "run-adapter" }),
      ).resolves.toEqual({
        clean: true,
        recipe: { clean: true, skipped: "recipe_not_staged" },
      });
    }

    expect(commandResults.map((call) => call.command)).toEqual([
      "ssh",
      "ssh",
      "sh",
      "sudo",
    ]);
    expect(commandResults[1].arguments_.at(-1)).toMatch(
      /id -u.*exec sh -s.*sudo -n sh -s/,
    );
    expect(commandResults[3].arguments_).toEqual(["-n", "sh", "-s"]);
  });

  it("binds the non-root Bootstrap recipe staging to the validated Candidate recipe", async () => {
    const candidateDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-e2e-bootstrap-candidate-"),
    );
    const recipeDir = path.join(candidateDir, "recipe");
    const file = "enoki-probe-bootstrap.py";
    const recipe = Buffer.from("verified candidate bootstrap recipe");
    const sha256 = createHash("sha256").update(recipe).digest("hex");
    await mkdir(recipeDir);
    await writeFile(path.join(recipeDir, file), recipe);
    const commands = [];
    const transfers = [];
    try {
      const adapter = createCiReleaseInfrastructureAdapter({
        candidateManifestPath: path.join(
          candidateDir,
          "candidate-manifest.json",
        ),
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_RUN_ATTEMPT: "2",
          GITHUB_RUN_ID: "1234",
          RUNNER_ARCH: "X64",
          RUNNER_OS: "Linux",
        },
        loadCandidate: async () => ({
          candidateDir,
          manifest: {
            ...candidateManifest(),
            bootstrapRecipe: {
              ...candidateManifest().bootstrapRecipe,
              file,
              sha256,
              size: recipe.byteLength,
            },
          },
        }),
        transferFile: async (transfer) => transfers.push(transfer),
        runProcess: async (command, arguments_, options) => {
          commands.push({ command, arguments_, options });
          const verifiesRecipe =
            command === "sh" &&
            options.input.includes(
              "# enoki-release-e2e:candidate-bootstrap-recipe-verify",
            );
          return successfulCommandText(
            command === "sh" &&
              options.input.includes(
                "# enoki-release-e2e:candidate-bootstrap-recipe-stage",
              )
              ? "/tmp/enoki-release-e2e-recipe.abcdef\n"
              : verifiesRecipe
                ? options.input.includes("sha256sum --check --status")
                  ? "verified\n"
                  : "/tmp/enoki-release-e2e-recipe.abcdef/enoki-probe-bootstrap.py: OK\nverified\n"
                : "removed\n",
          );
        },
      });
      const prepared = await adapter.prepare({
        matrixCell: freshMatrixCell(),
        runId: "run-bootstrap",
      });
      await expect(
        prepared.provisionBootstrap({ runId: "run-bootstrap" }),
      ).resolves.toEqual({
        evidence: { file, sha256, version: "v1" },
        workingDirectory: "/tmp/enoki-release-e2e-recipe.abcdef",
      });

      const staging = commands.find(({ command }) => command === "sh");
      expect(staging.options.input).toContain(
        "# enoki-release-e2e:candidate-bootstrap-recipe-stage",
      );
      expect(staging.options.input).toContain('[ "$(id -u)" != 0 ]');
      expect(staging.options.input).not.toContain(recipe.toString("base64"));
      expect(staging.options.input).not.toMatch(/curl|wget|http/);
      expect(transfers).toEqual([
        {
          destination:
            "/tmp/enoki-release-e2e-recipe.abcdef/enoki-probe-bootstrap.py",
          source: path.join(recipeDir, file),
        },
      ]);
      const verification = commands.find(
        ({ command, options }) =>
          command === "sh" &&
          options.input.includes(
            "# enoki-release-e2e:candidate-bootstrap-recipe-verify",
          ),
      );
      expect(verification.options.input).toContain(
        `printf '%s  %s\\n' '${sha256}' "$recipe"`,
      );
      expect(verification.options.input).toContain(
        "sha256sum --check --status",
      );
      expect(verification.options.input).toContain('[ "$(id -u)" != 0 ]');
      expect(commands.some(({ command }) => command === "sudo")).toBe(false);
      await expect(
        adapter.release({ runId: "run-bootstrap" }),
      ).resolves.toMatchObject({ clean: true, recipe: { clean: true } });
    } finally {
      await rm(candidateDir, { force: true, recursive: true });
    }
  });

  it("bounds a real local Host process tree timeout without waiting for descendant stdio", async () => {
    const execute = createCiHostExecutor({ timeoutMs: 50 });
    const startedAt = Date.now();

    const result = await execute("trap '' TERM\nsleep 2\n");

    expect(Date.now() - startedAt).toBeLessThan(1_000);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toMatch(/terminated by SIGKILL|timed out/i);
  });

  it("retains failed Bootstrap staging ownership when deletion cannot be verified", async () => {
    const candidateDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-e2e-bootstrap-cleanup-"),
    );
    try {
      const adapter = createCiReleaseInfrastructureAdapter({
        candidateManifestPath: path.join(
          candidateDir,
          "candidate-manifest.json",
        ),
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_RUN_ATTEMPT: "2",
          GITHUB_RUN_ID: "1234",
          RUNNER_ARCH: "X64",
          RUNNER_OS: "Linux",
        },
        loadCandidate: async () => ({
          candidateDir,
          manifest: candidateManifest(),
        }),
        transferFile: async () => {
          throw new Error("transfer failed");
        },
        runProcess: async (_command, _arguments, options) => {
          if (
            options.input.includes(
              "# enoki-release-e2e:candidate-bootstrap-recipe-stage",
            )
          ) {
            return successfulCommandText(
              "/tmp/enoki-release-e2e-recipe.failed01\n",
            );
          }
          return {
            code: 1,
            stderr: "owned stage directory was not removed",
            stdout: "",
          };
        },
      });
      const prepared = await adapter.prepare({
        matrixCell: freshMatrixCell(),
        runId: "run-bootstrap-cleanup",
      });
      await expect(
        prepared.provisionBootstrap({ runId: "run-bootstrap-cleanup" }),
      ).rejects.toMatchObject({
        cleanupError: expect.objectContaining({
          message: expect.stringContaining("was not removed"),
        }),
      });
      await expect(
        adapter.release({ runId: "run-bootstrap-cleanup" }),
      ).rejects.toThrow(/was not removed/);
    } finally {
      await rm(candidateDir, { force: true, recursive: true });
    }
  });

  it("cleans a run-owned 0600 recipe after transfer digest verification fails", async () => {
    const candidateDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-e2e-bootstrap-digest-failure-"),
    );
    const recipeDir = path.join(candidateDir, "recipe");
    const file = "enoki-probe-bootstrap.py";
    const recipe = Buffer.from("verified candidate bootstrap recipe");
    const externalDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-e2e-bootstrap-digest-external-"),
    );
    const externalRecipe = Buffer.from("external recipe must be preserved");
    const hostIdentity =
      process.getuid?.() === 0 ? { gid: 65534, uid: 65534 } : {};
    let deferCleanup = false;
    const runHostProcess = (command, arguments_, options) =>
      deferCleanup &&
      options.input.includes(
        "# enoki-release-e2e:candidate-bootstrap-staging-remove",
      )
        ? Promise.resolve({
            code: 1,
            stderr: "simulated cleanup interruption",
            stdout: "",
          })
        : new Promise((resolve) => {
            const child = execFile(
              command,
              arguments_,
              hostIdentity,
              (error, stdout, stderr) => {
                resolve({
                  code: typeof error?.code === "number" ? error.code : 0,
                  stderr,
                  stdout,
                });
              },
            );
            child.stdin.end(options.input);
          });
    try {
      await mkdir(recipeDir);
      await writeFile(path.join(recipeDir, file), recipe);
      await writeFile(path.join(externalDir, file), externalRecipe);
      if (hostIdentity.uid !== undefined) {
        await chown(externalDir, hostIdentity.uid, hostIdentity.gid);
        await chown(
          path.join(externalDir, file),
          hostIdentity.uid,
          hostIdentity.gid,
        );
      }
      const adapter = createCiReleaseInfrastructureAdapter({
        candidateManifestPath: path.join(
          candidateDir,
          "candidate-manifest.json",
        ),
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_RUN_ATTEMPT: "2",
          GITHUB_RUN_ID: "1234",
          RUNNER_ARCH: "X64",
          RUNNER_OS: "Linux",
        },
        loadCandidate: async () => ({
          candidateDir,
          manifest: {
            ...candidateManifest(),
            bootstrapRecipe: {
              ...candidateManifest().bootstrapRecipe,
              file,
              sha256: createHash("sha256").update(recipe).digest("hex"),
              size: recipe.byteLength,
            },
          },
        }),
        runProcess: runHostProcess,
        transferFile: async ({ destination, source }) => {
          await copyFile(source, destination);
          await chmod(destination, 0o600);
          if (hostIdentity.uid !== undefined) {
            await chown(destination, hostIdentity.uid, hostIdentity.gid);
          }
          await writeFile(destination, "tampered recipe");
        },
      });
      const prepared = await adapter.prepare({
        matrixCell: freshMatrixCell(),
        runId: "run-bootstrap-digest-failure",
      });

      const failure = await prepared
        .provisionBootstrap({ runId: "run-bootstrap-digest-failure" })
        .then(
          () => null,
          (error) => error,
        );
      expect(failure).toMatchObject({
        message: expect.stringMatching(
          /verify Candidate Probe Bootstrap recipe staging/,
        ),
      });
      expect(failure).not.toHaveProperty("cleanupError");

      deferCleanup = true;
      const interruptedCleanup = await prepared
        .provisionBootstrap({ runId: "run-bootstrap-digest-failure" })
        .then(
          () => null,
          (error) => error,
        );
      expect(interruptedCleanup).toMatchObject({
        cleanupError: expect.objectContaining({
          message: expect.stringMatching(/simulated cleanup interruption/),
        }),
      });
      deferCleanup = false;
      await expect(
        adapter.release({ runId: "run-bootstrap-digest-failure" }),
      ).resolves.toMatchObject({ clean: true, recipe: { clean: true } });
      await expect(readFile(path.join(externalDir, file))).resolves.toEqual(
        externalRecipe,
      );
    } finally {
      await rm(candidateDir, { force: true, recursive: true });
      await rm(externalDir, { force: true, recursive: true });
    }
  });

  it("does not follow a replaced Bootstrap staging directory into external resources", async () => {
    const candidateDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-e2e-bootstrap-symlink-candidate-"),
    );
    const externalDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-e2e-bootstrap-symlink-external-"),
    );
    const recipeDir = path.join(candidateDir, "recipe");
    const file = "enoki-probe-bootstrap.py";
    const recipe = Buffer.from("verified candidate bootstrap recipe");
    const externalRecipe = Buffer.from("external resource must be preserved");
    const hostIdentity =
      process.getuid?.() === 0 ? { gid: 65534, uid: 65534 } : {};
    const runHostProcess = (command, arguments_, options) =>
      new Promise((resolve) => {
        const child = execFile(
          command,
          arguments_,
          hostIdentity,
          (error, stdout, stderr) => {
            resolve({
              code: typeof error?.code === "number" ? error.code : 0,
              stderr,
              stdout,
            });
          },
        );
        child.stdin.end(options.input);
      });
    let stageDir = null;
    try {
      await mkdir(recipeDir);
      await writeFile(path.join(recipeDir, file), recipe);
      await writeFile(path.join(externalDir, file), externalRecipe);
      if (hostIdentity.uid !== undefined) {
        await chown(externalDir, hostIdentity.uid, hostIdentity.gid);
        await chown(
          path.join(externalDir, file),
          hostIdentity.uid,
          hostIdentity.gid,
        );
      }
      const adapter = createCiReleaseInfrastructureAdapter({
        candidateManifestPath: path.join(
          candidateDir,
          "candidate-manifest.json",
        ),
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_RUN_ATTEMPT: "2",
          GITHUB_RUN_ID: "1234",
          RUNNER_ARCH: "X64",
          RUNNER_OS: "Linux",
        },
        loadCandidate: async () => ({
          candidateDir,
          manifest: {
            ...candidateManifest(),
            bootstrapRecipe: {
              ...candidateManifest().bootstrapRecipe,
              file,
              sha256: createHash("sha256").update(recipe).digest("hex"),
              size: recipe.byteLength,
            },
          },
        }),
        runProcess: runHostProcess,
        transferFile: async ({ destination, source }) => {
          await copyFile(source, destination);
          if (hostIdentity.uid !== undefined) {
            await chown(destination, hostIdentity.uid, hostIdentity.gid);
          }
        },
      });
      const prepared = await adapter.prepare({
        matrixCell: freshMatrixCell(),
        runId: "run-bootstrap-symlink",
      });
      const provisioned = await prepared.provisionBootstrap({
        runId: "run-bootstrap-symlink",
      });
      stageDir = provisioned.workingDirectory;
      await execFileAsync("rm", [path.join(stageDir, file)], hostIdentity);
      await execFileAsync("rmdir", [stageDir], hostIdentity);
      await execFileAsync("ln", ["-s", externalDir, stageDir], hostIdentity);

      await expect(
        adapter.release({ runId: "run-bootstrap-symlink" }),
      ).rejects.toThrow();
      await expect(readFile(path.join(externalDir, file))).resolves.toEqual(
        externalRecipe,
      );
    } finally {
      if (stageDir) await rm(stageDir, { force: true });
      await rm(candidateDir, { force: true, recursive: true });
      await rm(externalDir, { force: true, recursive: true });
    }
  });

  it("transfers the validated Bootstrap recipe over SSH with fixed scp arguments", async () => {
    const candidateDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-e2e-bootstrap-ssh-candidate-"),
    );
    const recipeDir = path.join(candidateDir, "recipe");
    const file = "enoki-probe-bootstrap.py";
    const recipe = Buffer.from("verified candidate bootstrap recipe");
    const digest = createHash("sha256").update(recipe).digest("hex");
    await mkdir(recipeDir);
    await writeFile(path.join(recipeDir, file), recipe);
    const commands = [];
    try {
      const adapter = createSshReleaseInfrastructureAdapter({
        candidateManifestPath: path.join(
          candidateDir,
          "candidate-manifest.json",
        ),
        host: "release@192.0.2.10",
        knownHostsPath: "/tmp/release-e2e-known-hosts",
        loadCandidate: async () => ({
          candidateDir,
          manifest: {
            ...candidateManifest(),
            bootstrapRecipe: {
              ...candidateManifest().bootstrapRecipe,
              file,
              sha256: digest,
              size: recipe.byteLength,
            },
          },
        }),
        transferFile: undefined,
        runProcess: async (command, arguments_, options) => {
          commands.push({ arguments_, command, options });
          if (command === "scp") return successfulCommandText("");
          if (
            options.input.includes(
              "# enoki-release-e2e:candidate-bootstrap-recipe-stage",
            )
          ) {
            return successfulCommandText(
              "/tmp/enoki-release-e2e-recipe.abcdef\n",
            );
          }
          return successfulCommandText(
            options.input.includes("candidate-bootstrap-recipe-verify")
              ? "verified\n"
              : "installed\n",
          );
        },
      });
      const prepared = await adapter.prepare({
        matrixCell: freshMatrixCell(),
        runId: "run-bootstrap-ssh",
      });
      await prepared.provisionBootstrap({ runId: "run-bootstrap-ssh" });

      const transfer = commands.find(({ command }) => command === "scp");
      expect(transfer.arguments_).toEqual(
        expect.arrayContaining([
          "-q",
          "BatchMode=yes",
          "ConnectTimeout=15",
          "StrictHostKeyChecking=accept-new",
          "UserKnownHostsFile=/tmp/release-e2e-known-hosts",
          "--",
          path.join(recipeDir, file),
          "release@192.0.2.10:/tmp/enoki-release-e2e-recipe.abcdef/enoki-probe-bootstrap.py",
        ]),
      );
      expect(JSON.stringify(transfer)).not.toContain(recipe.toString("base64"));
    } finally {
      await rm(candidateDir, { force: true, recursive: true });
    }
  });

  it("keeps scenario failure, evidence, and cleanup schemas conformant across CI and SSH adapters", async () => {
    const loadedCandidate = {
      candidateDir: "/candidate",
      manifest: candidateManifest(),
    };
    const makeAdapters = () => [
      createSshReleaseInfrastructureAdapter({
        candidateManifestPath: "/candidate/candidate-manifest.json",
        host: "root@192.0.2.10",
        knownHostsPath: "/tmp/release-e2e-known-hosts",
        loadCandidate: async () => loadedCandidate,
        runProcess: async () => successfulCommandText("ready\n"),
      }),
      createCiReleaseInfrastructureAdapter({
        candidateManifestPath: "/candidate/candidate-manifest.json",
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_RUN_ATTEMPT: "2",
          GITHUB_RUN_ID: "1234",
          RUNNER_ARCH: "X64",
          RUNNER_OS: "Linux",
        },
        loadCandidate: async () => loadedCandidate,
        runProcess: async () => successfulCommandText("ready\n"),
      }),
    ];
    const outcomes = [];

    for (const [index, adapter] of makeAdapters().entries()) {
      const runId = `run-conformance-${index}`;
      const prepared = await adapter.prepare({
        matrixCell: freshMatrixCell(),
        runId,
      });
      const failure = Object.assign(new Error("adapter contract failure"), {
        code: "adapter_contract_failure",
      });
      const methods = [
        "assertDisposable",
        "assertInstalled",
        "awaitPermanentReportRejection",
        "captureInstallationState",
        "cleanup",
        "collectDiagnostics",
        "collectEvidence",
        "install",
        "localUninstall",
        "readProbeIdentity",
        "rejectRepeatedInstall",
        "repairInstalledBundleFailure",
        "verifyUninstallCompletion",
      ];
      const host = Object.fromEntries(
        methods.map((method) => [method, async () => ({ clean: true })]),
      );
      host.assertDisposable = async () => {
        throw failure;
      };
      const hubMethods = [
        "authenticate",
        "createEnrollment",
        "deleteHostHubOnly",
        "getAuditLog",
        "getEnrollment",
        "getHost",
        "getHostMetrics",
        "getHostProbeConfiguration",
        "isHostSoftDeleted",
        "listHosts",
        "requestProbeUninstall",
        "updateHostProbeConfiguration",
        "waitForProbeOperation",
      ];
      const hub = Object.fromEntries(
        hubMethods.map((method) => [method, async () => null]),
      );
      hub.collectEvidence = async () => ({ available: true });
      const written = [];
      await expect(
        runReleaseE2EScenario({
          candidateManifest: loadedCandidate.manifest,
          environment: {
            cleanup: ({ runId: cleanupRunId }) =>
              adapter.release({ prepared, runId: cleanupRunId }),
            async start() {
              return {
                host,
                hub,
                infrastructure: prepared.infrastructure,
                releaseTestHost: {
                  architecture: "x86_64",
                  operatingSystem: "ubuntu",
                  operatingSystemVersion: "22.04",
                  pid1: "systemd",
                  virtualization: "kvm",
                },
              };
            },
          },
          evidenceSink: { write: async (value) => written.push(value) },
          ownerPassword: "owner-password",
          runId,
          scenario: "fresh-install-uninstall",
        }),
      ).rejects.toMatchObject({ code: "adapter_contract_failure" });
      outcomes.push(written.at(-1));
    }

    for (const evidence of outcomes) {
      expect(evidence).toMatchObject({
        cleanup: {
          environment: { clean: true },
          host: { clean: true },
        },
        result: {
          error: { code: "adapter_contract_failure" },
          status: "failed",
        },
        scenario: "fresh-install-uninstall",
        schemaVersion: 2,
      });
    }
    expect(Object.keys(outcomes[0]).sort()).toEqual(
      Object.keys(outcomes[1]).sort(),
    );
    expect(Object.keys(outcomes[0].cleanup).sort()).toEqual(
      Object.keys(outcomes[1].cleanup).sort(),
    );
    expect(Object.keys(outcomes[0].result).sort()).toEqual(
      Object.keys(outcomes[1].result).sort(),
    );
  });

  it("keeps the Repair scenario and boundary evidence conformant across CI and SSH adapters", async () => {
    const loadedCandidate = {
      candidateDir: "/candidate",
      manifest: candidateManifestWithBaseline(),
    };
    const adapters = [
      createSshReleaseInfrastructureAdapter({
        candidateManifestPath: "/candidate/candidate-manifest.json",
        host: "root@192.0.2.10",
        knownHostsPath: "/tmp/release-e2e-known-hosts",
        loadCandidate: async () => loadedCandidate,
        runProcess: async () => successfulCommandText("ready\n"),
      }),
      createCiReleaseInfrastructureAdapter({
        candidateManifestPath: "/candidate/candidate-manifest.json",
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_RUN_ATTEMPT: "2",
          GITHUB_RUN_ID: "1234",
          RUNNER_ARCH: "X64",
          RUNNER_OS: "Linux",
        },
        loadCandidate: async () => loadedCandidate,
        runProcess: async () => successfulCommandText("ready\n"),
      }),
    ];
    const outcomes = [];

    for (const [index, adapter] of adapters.entries()) {
      const runId = `run-repair-conformance-${index}`;
      const prepared = await adapter.prepare({
        matrixCell: repairMatrixCell(),
        runId,
      });
      const failure = Object.assign(new Error("Host preflight failed"), {
        code: "filesystem_boundary_failure",
      });
      const hostMethods = [
        "armPostReplacementRestartFault",
        "assertDisposable",
        "assertInstalled",
        "assertPostReplacementUpgradeFailure",
        "beginUpgradeOwnershipTransition",
        "bindUpgradeOwnershipTransition",
        "cleanup",
        "collectEvidence",
        "completeRepairOwnershipTransition",
        "completeUpgradeOwnershipTransition",
        "install",
        "readProbeIdentity",
        "removePostReplacementRestartFault",
        "repair",
        "verifyUninstallCompletion",
      ];
      const host = Object.fromEntries(
        hostMethods.map((method) => [method, async () => ({ clean: true })]),
      );
      host.assertDisposable = async () => {
        throw failure;
      };
      host.collectEvidence = async () => ({
        inventory: { files: ["pre-existing"] },
        journald: { code: 0 },
        sudoers: { code: 0 },
        systemd: { code: 0 },
      });
      const hubMethods = [
        "authenticate",
        "createEnrollment",
        "getAuditLog",
        "getHost",
        "getHostMetrics",
        "getHostProbeConfiguration",
        "getProbeOperation",
        "isHostSoftDeleted",
        "listHosts",
        "requestProbeUninstall",
        "requestProbeUpgrade",
        "switchToCandidate",
        "updateHostProbeConfiguration",
        "waitForProbeOperation",
      ];
      const hub = Object.fromEntries(
        hubMethods.map((method) => [method, async () => null]),
      );
      hub.collectEvidence = async () => ({ apiHealth: { available: true } });
      const written = [];

      await expect(
        runReleaseE2EScenario({
          candidateManifest: loadedCandidate.manifest,
          environment: {
            cleanup: ({ runId: cleanupRunId }) =>
              adapter.release({ prepared, runId: cleanupRunId }),
            async start() {
              return {
                host,
                hub,
                infrastructure: prepared.infrastructure,
                releaseTestHost: {
                  architecture: "x86_64",
                  operatingSystem: "ubuntu",
                  operatingSystemVersion: "22.04",
                  pid1: "systemd",
                  virtualization: "kvm",
                },
              };
            },
          },
          evidenceSink: { write: async (value) => written.push(value) },
          ownerPassword: "owner-password",
          runId,
          scenario: repairMatrixCell().scenarioId,
        }),
      ).rejects.toMatchObject({ code: "filesystem_boundary_failure" });
      outcomes.push(written.at(-1));
    }

    for (const evidence of outcomes) {
      expect(evidence).toMatchObject({
        boundaryEvidence: {
          cleanup: {
            orchestrator: {
              environment: { clean: true },
              host: { clean: true },
            },
            uninstallCompletion: null,
          },
          filesystem: {
            afterRepair: null,
            postUninstall: { files: ["pre-existing"] },
          },
          hubApi: {
            apiTimeline: null,
            auditLog: null,
            repairedHost: null,
            runtime: null,
          },
          privilege: {
            afterRepair: null,
            postUninstall: { code: 0 },
          },
          probeOperation: { uninstall: [], upgrade: [] },
          systemd: {
            afterRepair: null,
            journald: { code: 0 },
            postUninstall: { code: 0 },
          },
        },
        result: {
          error: { code: "filesystem_boundary_failure" },
          status: "failed",
        },
        scenario: "post-replacement-repair-uninstall",
      });
      expect(Object.keys(evidence.boundaryEvidence).sort()).toEqual([
        "cleanup",
        "filesystem",
        "hubApi",
        "identity",
        "privilege",
        "probeOperation",
        "systemd",
      ]);
    }
    expect(Object.keys(outcomes[0]).sort()).toEqual(
      Object.keys(outcomes[1]).sort(),
    );
  });

  it("binds Hub runtime evidence and rejects unsafe Probe upstream mappings", async () => {
    const manifestDigest = `sha256:${"d".repeat(64)}`;
    const configDigest = `sha256:${"e".repeat(64)}`;
    const commands = [];
    const state = { container: false, image: false, volume: false };
    let probePortEvidence = "127.0.0.1:49151\n";
    const exec = async (command, arguments_) => {
      commands.push([command, ...arguments_].join(" "));
      if (command === "tar" && arguments_.at(-1) === "index.json") {
        return successfulCommandText(
          JSON.stringify({ manifests: [{ digest: manifestDigest }] }),
        );
      }
      if (command === "tar") {
        return successfulCommandText(
          JSON.stringify({ config: { digest: configDigest } }),
        );
      }
      if (command === "skopeo" && arguments_[0] === "copy") {
        return successfulCommandText("");
      }
      if (arguments_[0] === "load") {
        state.image = true;
        return successfulCommandText("Loaded image\n");
      }
      if (arguments_[0] === "run") {
        state.container = true;
        return successfulCommandText("container-id\n");
      }
      if (arguments_[0] === "port") {
        return successfulCommandText(probePortEvidence);
      }
      if (arguments_[0] === "logs") {
        return successfulCommandText(
          "owner-secret enk_enroll_leaked Authorization: Bearer probe-secret",
        );
      }
      if (arguments_[0] === "volume" && arguments_[1] === "create") {
        state.volume = true;
        return successfulCommandText("");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "rm") {
        state.volume = false;
        return successfulCommandText("");
      }
      if (arguments_[0] === "image" && arguments_[1] === "rm") {
        state.image = false;
        return successfulCommandText("");
      }
      if (arguments_[0] === "rm") {
        state.container = false;
        return successfulCommandText("");
      }
      if (arguments_[0] === "volume" && arguments_.includes("inspect")) {
        return state.volume
          ? successfulCommandText("run-runtime\n")
          : { code: 1, stderr: "No such volume", stdout: "" };
      }
      if (
        arguments_[0] === "container" &&
        arguments_[1] === "inspect" &&
        arguments_.length === 3
      ) {
        return state.container
          ? successfulCommand([
              {
                Config: {
                  Env: ["OWNER_PASSWORD=owner-secret"],
                  Image: "enoki-release-e2e:run-runtime",
                  Labels: { "enoki.release-e2e.run": "run-runtime" },
                },
                Id: "container-id",
                Image: configDigest,
                Mounts: [],
                NetworkSettings: { Ports: {} },
                State: { Running: true },
              },
            ])
          : { code: 1, stderr: "No such container", stdout: "" };
      }
      if (
        arguments_[0] === "image" &&
        arguments_[1] === "inspect" &&
        arguments_.length === 3
      ) {
        return state.image
          ? successfulCommand([{ Id: configDigest, RepoDigests: [] }])
          : { code: 1, stderr: "No such image", stdout: "" };
      }
      if (arguments_[0] === "image" && arguments_.includes("inspect")) {
        if (!state.image) {
          return { code: 1, stderr: "No such image", stdout: "" };
        }
        return successfulCommandText(
          arguments_.some((value) => value.includes("RepoDigests"))
            ? JSON.stringify({ Id: configDigest, RepoDigests: [] })
            : configDigest,
        );
      }
      if (arguments_.includes("inspect")) {
        if (!state.container) {
          return { code: 1, stderr: "No such container", stdout: "" };
        }
        if (arguments_.some((value) => value.includes("enoki.release-e2e"))) {
          return successfulCommandText("run-runtime\n");
        }
        if (arguments_.some((value) => value.includes('"Mounts"'))) {
          return successfulCommandText(
            JSON.stringify({ Id: "container-id", Image: configDigest }),
          );
        }
        return successfulCommandText(configDigest);
      }
      return successfulCommandText("");
    };
    const controller = createDockerHubController({
      exec,
      fetch: async () => jsonResponse({ service: "enoki-hub", status: "ok" }),
      sleep: async () => {},
    });
    const start = () =>
      controller.start({
        candidateDir: "/candidate",
        candidateManifest: {
          hub: { archive: "hub/candidate.oci.tar", digest: manifestDigest },
        },
        hubOwnerUrl: "http://127.0.0.1:33000",
        hubPublicUrl: "http://192.0.2.20:33000",
        ownerPassword: "owner-secret",
        runId: "run-runtime",
      });
    const resources = await start();

    expect(commands).toEqual(
      expect.arrayContaining([
        expect.stringMatching(
          /^skopeo copy oci-archive:\/candidate\/hub\/candidate\.oci\.tar docker-archive:\/tmp\/enoki-release-e2e-docker-archive-.+\/hub\.docker\.tar:enoki-release-e2e:run-runtime$/,
        ),
        expect.stringMatching(
          /^docker load --input \/tmp\/enoki-release-e2e-docker-archive-.+\/hub\.docker\.tar$/,
        ),
      ]),
    );
    expect(commands.join("\n")).not.toContain("--preserve-digests");
    expect(commands.join("\n")).not.toContain("docker-daemon:");

    const evidence = await controller.collectEvidence({ resources });
    expect(evidence).toMatchObject({
      candidateManifestDigest: manifestDigest,
      containerConfigDigest: configDigest,
      identityVerified: true,
    });
    expect(JSON.stringify(evidence)).not.toContain("owner-secret");
    expect(JSON.stringify(evidence)).not.toContain("enk_enroll_leaked");
    expect(JSON.stringify(evidence)).not.toContain("probe-secret");
    expect(commands.join("\n")).not.toContain("(dict ");

    await expect(
      controller.cleanup({ resources, runId: "run-runtime" }),
    ).resolves.toEqual({ clean: true });
    for (const [label, evidence] of [
      ["absent", ""],
      ["multiple", "127.0.0.1:49151\n127.0.0.1:49152\n"],
      ["wildcard", "0.0.0.0:49151\n"],
      ["non-loopback", "192.0.2.10:49151\n"],
      ["malformed", "not-a-mapping\n"],
      ["malformed IPv4", "999.0.0.1:49151\n"],
      ["wrong-family", "[::1]:49151\n"],
      ["unsafe", "127.0.0.1:65536\n"],
    ]) {
      probePortEvidence = evidence;
      await expect(start(), label).rejects.toThrow(
        /Docker Probe upstream port evidence/,
      );
      await expect(
        controller.cleanup({ runId: "run-runtime" }),
        label,
      ).resolves.toEqual({ clean: true });
    }
    expect(state).toEqual({ container: false, image: false, volume: false });
  });

  it("starts the pinned baseline Hub and switches to the Candidate on the same persisted state", async () => {
    const baselineManifestDigest = `sha256:${"b".repeat(64)}`;
    const baselineConfigDigest = `sha256:${"c".repeat(64)}`;
    const candidateManifestDigest = `sha256:${"d".repeat(64)}`;
    const candidateConfigDigest = `sha256:${"e".repeat(64)}`;
    const commands = [];
    const runArguments = [];
    const runMounts = [];
    const images = new Map();
    let stagedImage = null;
    let stagedTag = null;
    let activeImage = null;
    let container = false;
    let volume = false;
    const exec = async (command, arguments_) => {
      commands.push([command, ...arguments_].join(" "));
      if (command === "tar") {
        const archive = arguments_[arguments_.indexOf("--file") + 1];
        const baseline = archive.includes("release-baseline");
        if (arguments_.at(-1) === "index.json") {
          return successfulCommandText(
            JSON.stringify({
              manifests: [
                {
                  digest: baseline
                    ? baselineManifestDigest
                    : candidateManifestDigest,
                },
              ],
            }),
          );
        }
        return successfulCommandText(
          JSON.stringify({
            config: {
              digest: baseline ? baselineConfigDigest : candidateConfigDigest,
            },
          }),
        );
      }
      if (command === "skopeo" && arguments_[0] === "copy") {
        const baseline = arguments_[1].includes("release-baseline");
        stagedImage = baseline ? baselineConfigDigest : candidateConfigDigest;
        stagedTag = arguments_[2].split("/hub.docker.tar:")[1];
        return successfulCommandText("");
      }
      if (arguments_[0] === "load") {
        images.set(stagedTag, stagedImage);
        stagedImage = null;
        stagedTag = null;
        return successfulCommandText("Loaded image\n");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "create") {
        volume = true;
        return successfulCommandText("");
      }
      if (arguments_[0] === "run") {
        container = true;
        activeImage = images.get(arguments_.at(-1));
        runArguments.push([...arguments_]);
        runMounts.push(arguments_[arguments_.indexOf("--mount") + 1]);
        return successfulCommandText("container-id\n");
      }
      if (arguments_[0] === "port") {
        return successfulCommandText(
          arguments_[2] === "3000/tcp"
            ? "0.0.0.0:33000\n127.0.0.1:49152\n"
            : "127.0.0.1:49152\n",
        );
      }
      if (arguments_[0] === "rm") {
        container = false;
        return successfulCommandText("");
      }
      if (arguments_[0] === "image" && arguments_[1] === "rm") {
        images.delete(arguments_[2]);
        return successfulCommandText("");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "rm") {
        volume = false;
        return successfulCommandText("");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "inspect") {
        return volume
          ? successfulCommandText("run-switch\n")
          : { code: 1, stderr: "No such volume", stdout: "" };
      }
      if (
        arguments_[0] === "container" &&
        arguments_[1] === "inspect" &&
        arguments_.length === 3
      ) {
        return container
          ? successfulCommand([
              {
                Config: {
                  Image: `enoki-release-e2e:${activeImage}`,
                  Labels: { "enoki.release-e2e.run": "run-switch" },
                },
                Id: "container-id",
                Image: activeImage,
                Mounts: [],
                NetworkSettings: { Ports: {} },
                State: { Running: true },
              },
            ])
          : { code: 1, stderr: "No such container", stdout: "" };
      }
      if (
        arguments_[0] === "image" &&
        arguments_[1] === "inspect" &&
        arguments_.length === 3
      ) {
        const digest = images.get(arguments_[2]);
        return digest
          ? successfulCommand([{ Id: digest, RepoDigests: [] }])
          : { code: 1, stderr: "No such image", stdout: "" };
      }
      if (arguments_[0] === "image" && arguments_[1] === "inspect") {
        const digest = images.get(arguments_.at(-1));
        return digest
          ? successfulCommandText(digest)
          : { code: 1, stderr: "No such image", stdout: "" };
      }
      if (arguments_.includes("inspect")) {
        if (!container) {
          return { code: 1, stderr: "No such container", stdout: "" };
        }
        if (arguments_.some((value) => value.includes("enoki.release-e2e"))) {
          return successfulCommandText("run-switch\n");
        }
        return successfulCommandText(activeImage);
      }
      return successfulCommandText("");
    };
    const controller = createDockerHubController({
      exec,
      fetch: async () => jsonResponse({ service: "enoki-hub", status: "ok" }),
      sleep: async () => {},
    });
    const manifest = candidateManifestWithBaseline({
      baselineHubDigest: baselineManifestDigest,
      candidateHubDigest: candidateManifestDigest,
    });
    const resources = await controller.start({
      candidateDir: "/candidate",
      candidateManifest: manifest,
      hubMode: "baseline",
      hubOwnerUrl: "http://127.0.0.1:33000",
      hubPublicUrl: "http://192.0.2.20:33000",
      ownerPassword: "owner-secret",
      runId: "run-switch",
    });

    expect(resources.activeHub).toBe("baseline");
    expect(resources.probeUpstreamOrigin).toBe("http://127.0.0.1:49152");
    await controller.switchToCandidate({ resources, runId: "run-switch" });
    expect(resources.activeHub).toBe("candidate");
    expect(resources.probeUpstreamOrigin).toBe("http://127.0.0.1:49152");
    expect(
      runArguments.map((arguments_) =>
        arguments_.filter(
          (_value, index) => arguments_[index - 1] === "--publish",
        ),
      ),
    ).toEqual([
      ["127.0.0.1:33000:3000", "127.0.0.1::3000"],
      ["127.0.0.1:33000:3000", "127.0.0.1:49152:3001"],
    ]);
    expect(
      commands.filter((command) =>
        command.startsWith("docker port enoki-e2e-hub-run-switch "),
      ),
    ).toEqual([
      "docker port enoki-e2e-hub-run-switch 3000/tcp",
      "docker port enoki-e2e-hub-run-switch 3001/tcp",
    ]);
    expect(runMounts).toEqual([
      "type=volume,source=enoki-e2e-data-run-switch,target=/data",
      "type=volume,source=enoki-e2e-data-run-switch,target=/data",
    ]);
    expect(
      commands.filter((command) => command.includes(" volume create ")),
    ).toHaveLength(1);
    expect(commands).toContain(
      "docker stop --time 30 enoki-e2e-hub-run-switch",
    );
    expect(commands).toContain("docker rm enoki-e2e-hub-run-switch");
    expect(commands).not.toContain(
      "docker rm --force enoki-e2e-hub-run-switch",
    );
    await expect(
      controller.collectEvidence({ resources }),
    ).resolves.toMatchObject({
      activeHub: "candidate",
      runtimeHistory: [
        {
          hub: "baseline",
          manifestDigest: baselineManifestDigest,
          volume: "enoki-e2e-data-run-switch",
        },
        {
          hub: "candidate",
          manifestDigest: candidateManifestDigest,
          volume: "enoki-e2e-data-run-switch",
        },
      ],
    });

    await expect(
      controller.cleanup({ resources, runId: "run-switch" }),
    ).resolves.toEqual({ clean: true });
  });

  it("uses the Owner Hub State Snapshot CLI before atomically restoring the exact baseline image", async () => {
    const baselineManifestDigest = `sha256:${"b".repeat(64)}`;
    const baselineConfigDigest = `sha256:${"c".repeat(64)}`;
    const candidateManifestDigest = `sha256:${"d".repeat(64)}`;
    const candidateConfigDigest = `sha256:${"e".repeat(64)}`;
    const snapshotDigestHex = "f".repeat(64);
    const snapshotDigest = `sha256:${snapshotDigestHex}`;
    const recoveryTime = "2026-08-02T12:00:00.000Z";
    const commands = [];
    const images = new Map();
    const volumes = new Set();
    let stagedImage = null;
    let stagedTag = null;
    let activeImage = null;
    let container = false;
    let probePortEvidence = "127.0.0.1:49153\n";
    const snapshotResult = (operation) => ({
      manifest: {
        directories: [{ logicalRoot: "data-root", path: "metrics-archive" }],
        files: [{ logicalRoot: "data-root", path: "enoki.db" }],
        logicalRoots: [
          { id: "data-root", kind: "directory", sourcePath: "/data" },
        ],
        recoveryTime,
        releaseBaseline: {
          hubImageDigest: baselineManifestDigest,
          version: "v1.2.2",
        },
      },
      manifestDigest: snapshotDigestHex,
      operation,
      version: "v1",
    });
    const exec = async (command, arguments_) => {
      const rendered = [command, ...arguments_].join(" ");
      commands.push(rendered);
      if (command === "tar") {
        const archive = arguments_[arguments_.indexOf("--file") + 1];
        const baseline = archive.includes("release-baseline");
        return successfulCommandText(
          arguments_.at(-1) === "index.json"
            ? JSON.stringify({
                manifests: [
                  {
                    digest: baseline
                      ? baselineManifestDigest
                      : candidateManifestDigest,
                  },
                ],
              })
            : JSON.stringify({
                config: {
                  digest: baseline
                    ? baselineConfigDigest
                    : candidateConfigDigest,
                },
              }),
        );
      }
      if (command === "skopeo" && arguments_[0] === "copy") {
        const baseline = arguments_[1].includes("release-baseline");
        stagedImage = baseline ? baselineConfigDigest : candidateConfigDigest;
        stagedTag = arguments_[2].split("/hub.docker.tar:")[1];
        return successfulCommandText("");
      }
      if (arguments_[0] === "load") {
        images.set(stagedTag, stagedImage);
        stagedImage = null;
        stagedTag = null;
        return successfulCommandText("Loaded image\n");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "create") {
        volumes.add(arguments_.at(-1));
        return successfulCommandText("");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "rm") {
        volumes.delete(arguments_[2]);
        return successfulCommandText("");
      }
      if (
        arguments_[0] === "run" &&
        (arguments_.includes("enoki-hub-state") ||
          arguments_.includes("/usr/local/bin/enoki-hub-state"))
      ) {
        const operation = arguments_[arguments_.indexOf("v1") + 1];
        return successfulCommandText(JSON.stringify(snapshotResult(operation)));
      }
      if (arguments_[0] === "run") {
        container = true;
        activeImage = images.get(arguments_.at(-1));
        return successfulCommandText("container-id\n");
      }
      if (arguments_[0] === "port") {
        return successfulCommandText(
          arguments_[2] === "3000/tcp"
            ? `0.0.0.0:33000\n${probePortEvidence}`
            : probePortEvidence,
        );
      }
      if (arguments_[0] === "stop") {
        container = false;
        return successfulCommandText("");
      }
      if (arguments_[0] === "rm") {
        container = false;
        return successfulCommandText("");
      }
      if (arguments_[0] === "image" && arguments_[1] === "rm") {
        images.delete(arguments_[2]);
        return successfulCommandText("");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "inspect") {
        return volumes.has(arguments_.at(-1))
          ? successfulCommandText("run-restore\n")
          : { code: 1, stderr: "No such volume", stdout: "" };
      }
      if (arguments_[0] === "image" && arguments_[1] === "inspect") {
        const digest = images.get(arguments_.at(-1));
        return digest
          ? successfulCommandText(digest)
          : { code: 1, stderr: "No such image", stdout: "" };
      }
      if (arguments_.includes("inspect")) {
        if (!container) {
          return { code: 1, stderr: "No such container", stdout: "" };
        }
        if (arguments_.some((value) => value.includes("enoki.release-e2e"))) {
          return successfulCommandText("run-restore\n");
        }
        return successfulCommandText(activeImage);
      }
      return successfulCommandText("");
    };
    const controller = createDockerHubController({
      exec,
      fetch: async () => jsonResponse({ service: "enoki-hub", status: "ok" }),
      sleep: async () => {},
    });
    const manifest = candidateManifestWithBaseline({
      baselineHubDigest: baselineManifestDigest,
      candidateHubDigest: candidateManifestDigest,
    });
    const resources = await controller.start({
      candidateDir: "/candidate",
      candidateManifest: manifest,
      hubMode: "baseline",
      hubOwnerUrl: "http://127.0.0.1:33000",
      hubPublicUrl: "http://192.0.2.20:33000",
      ownerPassword: "owner-secret",
      probeOperationRunningTimeoutSeconds: null,
      runId: "run-restore",
      useHubStateSnapshot: true,
    });

    const snapshot = await controller.captureBaselineStateSnapshot({
      baselineImageDigest: baselineManifestDigest,
      baselineVersion: "v1.2.2",
      resources,
      runId: "run-restore",
    });
    expect(snapshot).toMatchObject({
      baselineImageDigest: baselineManifestDigest,
      baselineVersion: "v1.2.2",
      hotDataFileCount: 1,
      hotDataFiles: ["data-root/enoki.db"],
      manifestDigest: snapshotDigest,
      recoveryTime,
      roots: expect.arrayContaining([
        { id: "data-root", included: true, path: "/data" },
        {
          id: "metrics-archive",
          included: true,
          path: "/data/metrics-archive",
        },
      ]),
      tool: "enoki-hub-state",
      version: "v1",
    });
    await controller.switchToCandidate({ resources, runId: "run-restore" });
    const restored = await controller.restoreBaselineStateSnapshot({
      baselineImageDigest: baselineManifestDigest,
      baselineVersion: "v1.2.2",
      expectedManifestDigest: snapshotDigest,
      recoveryTime,
      resources,
      runId: "run-restore",
    });

    expect(restored).toEqual({
      image: {
        activeManifestDigest: baselineManifestDigest,
        expectedManifestDigest: baselineManifestDigest,
      },
      restore: { manifestDigest: snapshotDigest, status: "succeeded" },
      verify: { manifestDigest: snapshotDigest, status: "succeeded" },
    });
    expect(resources.activeHub).toBe("baseline");
    const snapshotCommand = commands.find((entry) =>
      entry.includes("v1 snapshot"),
    );
    const verifyCommand = commands.find((entry) => entry.includes("v1 verify"));
    const restoreCommand = commands.find((entry) =>
      entry.includes("v1 restore"),
    );
    expect(snapshotCommand).toContain(
      "--entrypoint /usr/local/bin/enoki-hub-state",
    );
    expect(snapshotCommand).toContain("--user 0:0");
    expect(snapshotCommand).toContain(
      "type=volume,source=enoki-e2e-data-run-restore,target=/data",
    );
    expect(snapshotCommand).toContain(
      "type=volume,source=enoki-e2e-snapshot-run-restore,target=/snapshot",
    );
    expect(snapshotCommand).toContain(
      `--baseline-image-digest ${baselineManifestDigest}`,
    );
    expect(commands.indexOf(verifyCommand)).toBeLessThan(
      commands.indexOf(restoreCommand),
    );
    expect(verifyCommand).toContain(
      `--expected-manifest-digest ${snapshotDigestHex}`,
    );
    expect(commands.indexOf(restoreCommand)).toBeLessThan(
      commands.findLastIndex(
        (entry) =>
          entry.startsWith("docker run --detach") &&
          entry.endsWith("enoki-release-e2e-baseline:run-restore"),
      ),
    );
    expect(commands.join("\n")).not.toContain("sqlite3");

    probePortEvidence = "127.0.0.1:49154\n";
    await expect(
      controller.switchToCandidate({ resources, runId: "run-restore" }),
    ).rejects.toThrow(/changed.*Probe upstream port/i);

    await expect(
      controller.cleanup({ resources, runId: "run-restore" }),
    ).resolves.toEqual({ clean: true });
    expect(volumes).toEqual(new Set());
  });

  it("refuses to overwrite a run manifest or final evidence", async () => {
    const evidenceDir = await mkdtemp(
      path.join(os.tmpdir(), "enoki-release-evidence-"),
    );
    try {
      await writeRunManifest(evidenceDir, { runId: "first" });
      await expect(
        writeRunManifest(evidenceDir, { runId: "second" }),
      ).rejects.toMatchObject({ code: "EEXIST" });

      const sink = createFileEvidenceSink(evidenceDir);
      await sink.write({ result: { status: "first" } });
      await expect(
        sink.write({ result: { status: "second" } }),
      ).rejects.toMatchObject({ code: "EEXIST" });
    } finally {
      await rm(evidenceDir, { force: true, recursive: true });
    }
  });

  it("requires an explicit Candidate Manifest and disposable SSH Host", () => {
    expect(() =>
      parseReleaseE2ECommandLine([
        "run",
        "--candidate-manifest",
        "/candidate/candidate-manifest.json",
        "--matrix",
        "/source/scripts/release-e2e-matrix.json",
        "--matrix-cell",
        "ubuntu-22.04-x86_64--fresh-install-uninstall",
        "--ssh-host",
        "root@192.0.2.10",
        "--hub-public-url",
        "http://192.0.2.20:33000",
        "--hub-owner-url",
        "http://127.0.0.1:33000",
        "--owner-password-env",
        "ENOKI_E2E_OWNER_PASSWORD",
        "--root-public-key-env",
        "ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM",
        "--evidence-dir",
        "/tmp/enoki-evidence",
      ]),
    ).not.toThrow();
    expect(() =>
      parseReleaseE2ECommandLine([
        "run",
        "--candidate-manifest",
        "/candidate/candidate-manifest.json",
      ]),
    ).toThrow("--ssh-host is required");
    expect(() =>
      parseReleaseE2ECommandLine([
        "run",
        "--candidate-manifest",
        "/candidate/candidate-manifest.json",
        "--matrix",
        "/source/scripts/release-e2e-matrix.json",
        "--matrix-cell",
        "ubuntu-22.04-x86_64--fresh-install-uninstall",
        "--ssh-host",
        "root@192.0.2.10",
        "--hub-public-url",
        "http://192.0.2.20:33000",
        "--hub-owner-url",
        "http://hub.example:33000",
        "--owner-password-env",
        "ENOKI_E2E_OWNER_PASSWORD",
        "--root-public-key-env",
        "ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM",
        "--evidence-dir",
        "/tmp/enoki-evidence",
      ]),
    ).toThrow(/loopback.*candidate Hub/i);
  });

  it("selects a CI Release Test Host by stable matrix cell without SSH flags", () => {
    expect(() =>
      parseReleaseE2ECommandLine([
        "run",
        "--candidate-manifest",
        "/candidate/candidate-manifest.json",
        "--host-adapter",
        "ci",
        "--matrix",
        "/source/scripts/release-e2e-matrix.json",
        "--matrix-cell",
        "ubuntu-22.04-x86_64--fresh-install-uninstall",
        "--hub-public-url",
        "http://127.0.0.1:33000",
        "--hub-owner-url",
        "http://127.0.0.1:33000",
        "--owner-password-env",
        "ENOKI_E2E_OWNER_PASSWORD",
        "--root-public-key-env",
        "ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM",
        "--evidence-dir",
        "/tmp/enoki-evidence",
      ]),
    ).not.toThrow();
  });

  it("cleans run-owned Docker state when candidate Hub startup fails partway", async () => {
    const commands = [];
    let containerCreated = false;
    let imageCreated = false;
    let volumeCreated = false;
    const manifestDigest = `sha256:${"b".repeat(64)}`;
    const configDigest = `sha256:${"c".repeat(64)}`;
    const exec = async (command, arguments_) => {
      commands.push([command, ...arguments_].join(" "));
      if (command === "tar" && arguments_.at(-1) === "index.json") {
        return successfulCommandText(
          JSON.stringify({ manifests: [{ digest: manifestDigest }] }),
        );
      }
      if (command === "tar") {
        return successfulCommandText(
          JSON.stringify({ config: { digest: configDigest } }),
        );
      }
      if (arguments_[0] === "run") {
        return { code: 1, stderr: "port already allocated", stdout: "" };
      }
      if (command === "skopeo" && arguments_[0] === "copy") {
        return successfulCommandText("");
      }
      if (arguments_[0] === "load") {
        imageCreated = true;
        return successfulCommandText("Loaded image\n");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "create") {
        volumeCreated = true;
        return successfulCommandText("");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "rm") {
        volumeCreated = false;
        return successfulCommandText("");
      }
      if (arguments_[0] === "image" && arguments_[1] === "rm") {
        imageCreated = false;
        return successfulCommandText("");
      }
      if (arguments_[0] === "volume" && arguments_.includes("inspect")) {
        return volumeCreated
          ? successfulCommandText("run-docker\n")
          : { code: 1, stderr: "No such volume", stdout: "" };
      }
      if (arguments_[0] === "image" && arguments_.includes("inspect")) {
        return imageCreated
          ? successfulCommandText(configDigest)
          : { code: 1, stderr: "No such image", stdout: "" };
      }
      if (arguments_.includes("inspect")) {
        return containerCreated
          ? successfulCommandText("run-docker\n")
          : { code: 1, stderr: "No such container", stdout: "" };
      }
      return successfulCommandText("");
    };
    const controller = createDockerHubController({ exec });

    await expect(
      controller.start({
        candidateDir: "/candidate",
        candidateManifest: {
          hub: { archive: "hub/candidate.oci.tar", digest: manifestDigest },
        },
        hubOwnerUrl: "http://127.0.0.1:33000",
        hubPublicUrl: "http://192.0.2.20:33000",
        ownerPassword: "password",
        runId: "run-docker",
      }),
    ).rejects.toThrow("port already allocated");
    await expect(
      controller.cleanup({ resources: null, runId: "run-docker" }),
    ).resolves.toMatchObject({ clean: true });
    expect(commands).toContain("docker volume rm enoki-e2e-data-run-docker");
    expect(commands).toContain("docker image rm enoki-release-e2e:run-docker");
  });

  it("continues cleaning every run-owned Docker resource after partial failures", async () => {
    const commands = [];
    const state = { container: true, image: true, volume: true };
    const configDigest = `sha256:${"c".repeat(64)}`;
    const exec = async (command, arguments_) => {
      commands.push([command, ...arguments_].join(" "));
      if (
        arguments_[0] === "inspect" &&
        arguments_.some((value) => value.includes("enoki.release-e2e"))
      ) {
        return successfulCommandText("run-partial-cleanup\n");
      }
      if (arguments_[0] === "rm") {
        return { code: 1, stderr: "container removal failed", stdout: "" };
      }
      if (arguments_[0] === "container" && arguments_[1] === "inspect") {
        return state.container
          ? successfulCommandText("container still exists")
          : { code: 1, stderr: "No such container", stdout: "" };
      }
      if (arguments_[0] === "volume" && arguments_[1] === "inspect") {
        if (arguments_.some((value) => value.includes("enoki.release-e2e"))) {
          return successfulCommandText("run-partial-cleanup\n");
        }
        return state.volume
          ? successfulCommandText("volume still exists")
          : { code: 1, stderr: "No such volume", stdout: "" };
      }
      if (arguments_[0] === "volume" && arguments_[1] === "rm") {
        return { code: 1, stderr: "volume removal failed", stdout: "" };
      }
      if (arguments_[0] === "image" && arguments_[1] === "inspect") {
        return state.image
          ? successfulCommandText(configDigest)
          : { code: 1, stderr: "No such image", stdout: "" };
      }
      if (arguments_[0] === "image" && arguments_[1] === "rm") {
        state.image = false;
        return successfulCommandText("");
      }
      return successfulCommandText("");
    };
    const controller = createDockerHubController({ exec });
    const resources = {
      configDigest,
      container: "enoki-e2e-hub-run-partial-cleanup",
      containerCreated: true,
      tag: "enoki-release-e2e:run-partial-cleanup",
      tagCreated: true,
      volume: "enoki-e2e-data-run-partial-cleanup",
      volumeCreated: true,
    };

    await expect(
      controller.cleanup({ resources, runId: "run-partial-cleanup" }),
    ).rejects.toMatchObject({
      errors: expect.arrayContaining([
        expect.objectContaining({
          message: expect.stringContaining("container removal failed"),
        }),
        expect.objectContaining({
          message: expect.stringContaining("container"),
        }),
        expect.objectContaining({
          message: expect.stringContaining("volume removal failed"),
        }),
      ]),
    });
    expect(commands).toContain(
      "docker volume rm enoki-e2e-data-run-partial-cleanup",
    );
    expect(commands).toContain(
      "docker image rm enoki-release-e2e:run-partial-cleanup",
    );
    expect(commands).toContain(
      "docker container inspect enoki-e2e-hub-run-partial-cleanup",
    );
    expect(commands).toContain(
      "docker volume inspect enoki-e2e-data-run-partial-cleanup",
    );
    expect(commands).toContain(
      "docker image inspect enoki-release-e2e:run-partial-cleanup",
    );
    expect(state).toEqual({ container: true, image: false, volume: true });
  });

  it("does not remove Docker resources whose run ownership cannot be proven", async () => {
    const commands = [];
    const configDigest = `sha256:${"c".repeat(64)}`;
    const exec = async (command, arguments_) => {
      commands.push([command, ...arguments_].join(" "));
      if (
        (arguments_[0] === "inspect" || arguments_[0] === "volume") &&
        arguments_.some((value) => value.includes("enoki.release-e2e"))
      ) {
        return successfulCommandText("another-run\n");
      }
      if (arguments_[0] === "image" && arguments_[1] === "inspect") {
        return successfulCommandText(`sha256:${"d".repeat(64)}`);
      }
      return successfulCommandText("still present");
    };
    const controller = createDockerHubController({ exec });
    const resources = {
      configDigest,
      container: "enoki-e2e-hub-run-ownership",
      containerCreated: true,
      tag: "enoki-release-e2e:run-ownership",
      tagCreated: true,
      volume: "enoki-e2e-data-run-ownership",
      volumeCreated: true,
    };

    await expect(
      controller.cleanup({ resources, runId: "run-ownership" }),
    ).rejects.toMatchObject({
      errors: expect.arrayContaining([
        expect.objectContaining({
          message: expect.stringContaining("run label mismatch"),
        }),
        expect.objectContaining({
          message: expect.stringContaining("image identity mismatch"),
        }),
      ]),
    });
    expect(commands.some((command) => command.startsWith("docker rm "))).toBe(
      false,
    );
    expect(
      commands.some((command) => command.startsWith("docker volume rm ")),
    ).toBe(false);
    expect(
      commands.some((command) => command.startsWith("docker image rm ")),
    ).toBe(false);
    expect(resources).toMatchObject({
      containerCreated: true,
      tagCreated: true,
      volumeCreated: true,
    });
  });
});

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json", ...headers },
    status,
  });
}

function successfulCommand(value) {
  return successfulCommandText(JSON.stringify(value));
}

function successfulCommandText(stdout) {
  return { code: 0, stderr: "", stdout };
}

function durableRuntimeFailureEvidenceOutput(runtimeSha256 = "a".repeat(64)) {
  return [
    "activeState=failed",
    "bootId=4f7d3e15-63cc-4d61-8fe4-f5d42773dd51",
    "bundleVersion=1.2.3",
    `epochGeneration=${"b".repeat(64)}`,
    "epochLinks=1",
    "epochMode=600",
    "epochOwner=0",
    "hostId=7",
    `identityReceiptSha256=${"c".repeat(64)}`,
    `installStateSha256=${"d".repeat(64)}`,
    `latchGeneration=${"b".repeat(64)}`,
    "latchLinks=1",
    "latchMode=600",
    "latchOwner=0",
    `manifestSha256=${"e".repeat(64)}`,
    "probeId=probe_release_01",
    "result=start-limit-hit",
    "restartCount=2",
    "role=observation_runtime",
    `runtimeFaultSha256=${"f".repeat(64)}`,
    `runtimeSha256=${runtimeSha256}`,
    "startLimitBurst=3",
    "startLimitIntervalSec=60",
    "unit=enoki-observation-runtime.service",
    `unitSha256=${"1".repeat(64)}`,
    "",
  ].join("\n");
}

function productInstallerOutput() {
  return "ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE\nEnoki Probe installed as enoki-probe.service.\n";
}

const officialInstallCommand =
  "printf '%s\\n' 'enk_enroll_secret' | python3 -- ./enoki-probe-bootstrap.py --hub-origin 'https://hub.example'";

function bootstrapRecipeCommand(authority) {
  const enrollment =
    typeof authority === "string" ? authority : JSON.stringify(authority);
  return `printf '%s\\n' '${enrollment}' | python3 -- ./enoki-probe-bootstrap.py --hub-origin 'https://hub.example'`;
}

function officialEnrollment(overrides = {}) {
  const enrollmentToken = overrides.enrollmentToken ?? "enk_enroll_secret";
  const hubUrl = overrides.hubUrl ?? "https://hub.example";
  return {
    bootstrapRecipe: {
      bundleVersion: "1.2.3",
      distribution: "enoki",
      kind: "enoki-probe-bootstrap-recipe-record",
      recipe: {
        file: "enoki-probe-bootstrap.py",
        sha256: "e".repeat(64),
        size: 123,
        version: "v1",
      },
      rootFingerprint: "d".repeat(64),
      schemaVersion: 1,
      targets: [
        "aarch64-unknown-linux-gnu",
        "aarch64-unknown-linux-musl",
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
      ],
    },
    enrollmentToken,
    hubUrl,
    installCommand: `printf '%s\\n' '${enrollmentToken}' | python3 -- ./enoki-probe-bootstrap.py --hub-origin '${hubUrl}'`,
    ...overrides,
  };
}

function candidateManifest() {
  return createReleaseCandidateManifest({
    bootstrapRecipe: {
      bundleVersion: "1.2.3",
      distribution: "enoki",
      file: "enoki-probe-bootstrap.py",
      kind: "enoki-probe-bootstrap-recipe-record",
      recordFile: "enoki-probe-bootstrap-recipe.json",
      recordSha256: "c".repeat(64),
      recordSize: 456,
      rootFingerprint: "d".repeat(64),
      schemaVersion: 1,
      sha256: "e".repeat(64),
      size: 123,
      targets: [
        "aarch64-unknown-linux-gnu",
        "aarch64-unknown-linux-musl",
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
      ],
      version: "v1",
    },
    candidate: {
      commit: "0123456789abcdef0123456789abcdef01234567",
      version: "v1.2.3",
    },
    hub: {
      archive: "hub/enoki-hub-v1.2.3.oci.tar",
      archiveSha256: "f".repeat(64),
      digest: `sha256:${"a".repeat(64)}`,
      embeddedProbeVersion: "1.2.3",
      size: 789,
    },
    probeAssetSet: {
      directory: "probe-assets",
      files: [{ file: "manifest.json", sha256: "1".repeat(64), size: 12 }],
      signingIdentity: {
        algorithm: "rsa-sha256",
        publicKeyFile: "signing-key.pem",
        publicKeySha256: "2".repeat(64),
      },
      version: "1.2.3",
    },
    releaseBaseline: ordinaryReleaseBaseline(),
  });
}

function candidateManifestWithBaseline({
  baselineHubDigest = `sha256:${"b".repeat(64)}`,
  candidateHubDigest = `sha256:${"a".repeat(64)}`,
} = {}) {
  return {
    ...candidateManifest(),
    hub: {
      ...candidateManifest().hub,
      digest: candidateHubDigest,
    },
    releaseBaseline: {
      ...ordinaryReleaseBaseline(),
      hub: {
        ...ordinaryReleaseBaseline().hub,
        digest: baselineHubDigest,
        imageDigest: baselineHubDigest,
        sourceManifestSha256: baselineHubDigest.slice("sha256:".length),
      },
    },
  };
}

function candidateManifestWithMigrationBaseline() {
  const base = candidateManifest();
  const recipeRecord = bootstrapRecipeRecord(base);
  const recordBytes = Buffer.from(`${JSON.stringify(recipeRecord, null, 2)}\n`);
  return createReleaseCandidateManifest({
    ...base,
    bootstrapRecipe: {
      ...base.bootstrapRecipe,
      recordSha256: createHash("sha256").update(recordBytes).digest("hex"),
      recordSize: recordBytes.byteLength,
    },
    releaseBaseline: migrationReleaseBaseline(),
  });
}

function bootstrapRecipeRecord(manifest) {
  return {
    bundleVersion: manifest.bootstrapRecipe.bundleVersion,
    distribution: manifest.bootstrapRecipe.distribution,
    kind: manifest.bootstrapRecipe.kind,
    recipe: {
      file: manifest.bootstrapRecipe.file,
      sha256: manifest.bootstrapRecipe.sha256,
      size: manifest.bootstrapRecipe.size,
      version: manifest.bootstrapRecipe.version,
    },
    rootFingerprint: manifest.bootstrapRecipe.rootFingerprint,
    schemaVersion: manifest.bootstrapRecipe.schemaVersion,
    targets: manifest.bootstrapRecipe.targets,
  };
}

function candidateRecipeProvenance(manifest) {
  const record = bootstrapRecipeRecord(manifest);
  const recordBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`);
  return {
    activeHub: "candidate",
    hubDigest: manifest.hub.digest,
    kind: "enoki-release-e2e-bootstrap-recipe-provenance",
    record,
    recordFile: manifest.bootstrapRecipe.recordFile,
    recordSha256: createHash("sha256").update(recordBytes).digest("hex"),
    recordSize: recordBytes.byteLength,
    schemaVersion: 1,
  };
}

function migrationReleaseBaseline() {
  return {
    authorization: {
      file: "trust-epoch-migration-authorization.json",
      legacyReleaseSha256: "a".repeat(64),
      sha256: "b".repeat(64),
      signatureFile: "trust-epoch-migration-authorization.json.sig",
      signatureSha256: "c".repeat(64),
    },
    catalogSnapshot: createReleaseCatalogSnapshot([
      {
        assets: [],
        draft: false,
        id: 74,
        prerelease: false,
        tagName: "v0.1.74",
        targetCommitish: "main",
      },
    ]),
    githubRelease: {
      id: 74,
      peeledCommitSha: "d".repeat(40),
      repository: "YKDZ/enoki",
      tagRefSha: "e".repeat(40),
      targetCommitish: "main",
    },
    hub: {
      archive: "hub/enoki-hub-v0.1.74.oci.tar",
      archiveSha256: "f".repeat(64),
      digest: `sha256:${"3".repeat(64)}`,
      image: "ghcr.io/ykdz/enoki-hub",
      imageDigest: `sha256:${"2".repeat(64)}`,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      platform: { architecture: "amd64", os: "linux" },
      size: 123,
      sourceManifest: "hub-source-manifest.json",
      sourceManifestSha256: "3".repeat(64),
      sourceManifestSize: 456,
    },
    kind: "enoki-trust-epoch-migration-baseline",
    legacyProbeAssets: {
      directory: "probe-assets",
      files: [
        {
          name: "enoki-probe-v0.1.74-x86_64-linux.tar.gz",
          sha256: "4".repeat(64),
          size: 789,
        },
      ],
    },
    schemaVersion: 1,
    tag: "v0.1.74",
    transition: "replacement-required",
  };
}

function ordinaryReleaseBaseline() {
  return {
    catalogSnapshot: createReleaseCatalogSnapshot([
      {
        assets: [],
        draft: false,
        id: 122,
        prerelease: false,
        tagName: "v1.2.2",
        targetCommitish: "main",
      },
    ]),
    githubRelease: {
      id: 122,
      peeledCommitSha: "3".repeat(40),
      repository: "YKDZ/enoki",
      tagRefSha: "4".repeat(40),
      targetCommitish: "main",
    },
    hub: {
      archive: "hub/enoki-hub-v1.2.2.oci.tar",
      archiveSha256: "5".repeat(64),
      digest: `sha256:${"6".repeat(64)}`,
      image: "ghcr.io/ykdz/enoki-hub",
      imageDigest: `sha256:${"b".repeat(64)}`,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      platform: { architecture: "amd64", os: "linux" },
      size: 234,
      sourceManifest: "hub-source-manifest.json",
      sourceManifestSha256: "6".repeat(64),
      sourceManifestSize: 345,
    },
    kind: "enoki-release-baseline",
    probeAssetSet: {
      directory: "probe-assets",
      files: [{ file: "manifest.json", sha256: "7".repeat(64), size: 12 }],
      signingIdentity: {
        algorithm: "rsa-sha256",
        publicKeyFile: "signing-key.pem",
        publicKeySha256: "8".repeat(64),
      },
      trustRoot: { publicKeySha256: "9".repeat(64) },
      version: "1.2.2",
    },
    schemaVersion: 2,
    tag: "v1.2.2",
  };
}

function canonicalRuntimeUnavailableEvidence() {
  return {
    bootId: "boot-c4-01",
    bootReport: {
      acceptedSequenceEnd: 1,
      bytes: 128,
      payloadSha256: "1".repeat(64),
      reconciliation: {
        currentProbeConfigurationVersion: "host-2-1",
        pendingOperation: "absent",
        requestedSnapshotCollectorIdsCount: 0,
      },
      responseDelivered: true,
      responseSha256: "2".repeat(64),
      sequence: 1,
      upstreamStatus: 200,
    },
    failureReport: {
      attempts: [
        {
          acceptedSequenceEnd: 2,
          response: "dropped",
          responseSha256: "4".repeat(64),
          upstreamStatus: 200,
        },
        {
          acceptedSequenceEnd: 2,
          response: "delivered",
          responseSha256: "5".repeat(64),
          upstreamStatus: 200,
        },
      ],
      bytes: 64,
      collectionOutcomeCount: 0,
      metricsCount: 0,
      payloadSha256: "3".repeat(64),
      probeConfigurationVersion: "host-2-1",
      reason: "observation_runtime_unavailable",
      retryPayloadSha256: "3".repeat(64),
      sequence: 2,
    },
    kind: "canonical-runtime-unavailable-report-evidence",
    receiptConvergence: {
      contract: "report-sequence-ack-idempotency",
      key: {
        bootId: "boot-c4-01",
        probeId: "probe_release_02",
        sequence: 2,
      },
      requestAttemptCount: 2,
      uniquePayloadCount: 1,
    },
    probeId: "probe_release_02",
    schemaVersion: 1,
  };
}

function freshMatrixCell() {
  return {
    architecture: "x86_64",
    cellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
    environmentId: "ubuntu-22.04-x86_64",
    operatingSystem: "ubuntu",
    operatingSystemVersion: "22.04",
    runner: "ubuntu-22.04",
    scenarioId: "fresh-install-uninstall",
  };
}

function repairMatrixCell() {
  return {
    ...freshMatrixCell(),
    cellId: "ubuntu-22.04-x86_64--post-replacement-repair-uninstall",
    scenarioId: "post-replacement-repair-uninstall",
  };
}

function readyHost(overrides = {}) {
  return {
    hostProfile: {
      architecture: "x86_64",
      cpuCount: 2,
      filesystems: [],
      hostname: "release-test-host",
      kernel: "6.8.0",
      memoryTotalBytes: 2_147_483_648,
      networkInterfaces: [],
      os: "ubuntu",
      probeVersion: "1.2.3",
    },
    id: 7,
    probeUpgradeStatus: null,
    reportedProbeConfigurationVersion: "default-v1",
    status: "online",
    warnings: [],
    ...overrides,
  };
}

function lifecycleAuditLog() {
  return [
    {
      action: "host.delete",
      actor: "owner",
      details: { hostId: 7, probeOperationId: 42 },
      id: 4,
      occurredAtMs: 40,
      outcome: "success",
      subjectId: "7",
      subjectType: "host",
    },
    {
      action: "probe_configuration.host.override",
      actor: "owner",
      id: 2,
      occurredAtMs: 20,
      outcome: "success",
      subjectId: "7",
      subjectType: "host",
    },
    {
      action: "enrollment_token.create",
      actor: "owner",
      id: 1,
      occurredAtMs: 10,
      outcome: "success",
      subjectId: "1",
      subjectType: "enrollment_token",
    },
  ];
}

function freshLifecycleAuditLog() {
  return [
    {
      action: "enrollment_token.create",
      actor: "owner",
      details: { target: { kind: "new_host" } },
      id: 1,
      occurredAtMs: 10,
      outcome: "success",
      subjectId: "1",
      subjectType: "enrollment_token",
    },
    {
      action: "enrollment.installation_rejected",
      actor: "system",
      details: { code: "existing_probe_installation" },
      id: 2,
      occurredAtMs: 20,
      outcome: "success",
      subjectId: "2",
      subjectType: "enrollment_token",
    },
    {
      action: "probe_configuration.host.override",
      actor: "owner",
      id: 3,
      occurredAtMs: 30,
      outcome: "success",
      subjectId: "7",
      subjectType: "host",
    },
    {
      action: "enrollment_token.create",
      actor: "owner",
      details: { target: { hostId: 7, kind: "existing_host" } },
      id: 4,
      occurredAtMs: 40,
      outcome: "success",
      subjectId: "3",
      subjectType: "enrollment_token",
    },
    {
      action: "host.delete",
      actor: "owner",
      details: { hostId: 7, mode: "hub-only" },
      id: 5,
      occurredAtMs: 50,
      outcome: "success",
      subjectId: "7",
      subjectType: "host",
    },
  ];
}

function baselineUpgradeAuditLog() {
  return [
    ...lifecycleAuditLog(),
    {
      action: "probe_upgrade_request.create",
      actor: "owner",
      details: { hostId: 7, targetProbeVersion: "1.2.3" },
      id: 3,
      occurredAtMs: 30,
      outcome: "success",
      subjectId: "41",
      subjectType: "probe_upgrade_request",
    },
  ];
}

function successfulRepairBoundaryEvidence() {
  const failedUpgrade = {
    acceptedAtMs: 2,
    completedAtMs: 20,
    createdAtMs: 1,
    failure: {
      code: "running_timeout",
      message: "Probe did not report the target version in time.",
    },
    hostId: 7,
    id: 41,
    kind: "probe_upgrade",
    runningAtMs: 2,
    state: "failed",
    targetProbeVersion: "1.2.3",
    updatedAtMs: 20,
  };
  const requestedUpgrade = {
    ...failedUpgrade,
    acceptedAtMs: null,
    completedAtMs: null,
    failure: null,
    runningAtMs: null,
    state: "pending",
    updatedAtMs: 1,
  };
  const runningUpgrade = {
    ...requestedUpgrade,
    acceptedAtMs: 2,
    runningAtMs: 2,
    state: "running",
    updatedAtMs: 2,
  };
  const requestedUninstall = {
    acceptedAtMs: null,
    completedAtMs: null,
    createdAtMs: 30,
    failure: null,
    hostId: 7,
    id: 42,
    kind: "probe_uninstall",
    runningAtMs: null,
    state: "pending",
    targetProbeVersion: "",
    updatedAtMs: 30,
  };
  const succeededUninstall = {
    ...requestedUninstall,
    acceptedAtMs: 31,
    completedAtMs: 32,
    runningAtMs: 31,
    state: "succeeded",
    updatedAtMs: 32,
  };
  const identity = {
    identitySha256: "f".repeat(64),
    probeId: "probe_release_01",
  };
  const cleanInventory = {
    accounts: { group: false, user: false },
    files: [],
    units: [],
  };
  const installedInventory = {
    accounts: { group: true, user: true },
    files: [
      "/usr/local/bin/enoki-probe",
      "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
      "/var/lib/enoki-probe-bootstrap",
      "/etc/enoki/probe-install.toml",
      "/etc/systemd/system/enoki-probe.service",
      "/var/lib/enoki-probe",
    ],
    units: ["enoki-probe.service"],
  };

  return {
    auditLog: baselineUpgradeAuditLog(),
    cleanup: {
      environment: {
        clean: true,
        hub: { clean: true },
        infrastructure: { clean: true },
      },
      host: { clean: true, removedPartialInstallation: false },
    },
    failureBoundary: {
      hubFailureCode: "running_timeout",
      localFailureCode: "post_replacement_restart_failure",
      operationId: 41,
      probeVersion: "1.2.3",
    },
    hostEvidence: {
      inventory: cleanInventory,
      journald: {
        code: 0,
        stderr: "",
        stdout:
          "2026-08-02T12:00:00+0000 release-test-host enoki-probe[123]: Probe Repair resumed reporting\n",
      },
      runClaimed: true,
      sudoers: {
        code: 0,
        stderr: "",
        stdout: "stage=post-uninstall\nmanagedSudoersCount=0\n",
      },
      systemd: {
        code: 0,
        stderr: "",
        stdout:
          "stage=post-uninstall\nLoadState=not-found\nActiveState=inactive\nunitCount=0\nfailedUnitCount=0\n",
      },
    },
    hubEvidence: {
      apiTimeline: [
        {
          error: null,
          method: "POST",
          pathname: "/api/web/auth/login",
          status: 200,
        },
        {
          error: null,
          method: "POST",
          pathname: "/api/web/hosts/7/probe-upgrade-requests",
          status: 202,
        },
        {
          error: null,
          method: "DELETE",
          pathname: "/api/web/hosts/7",
          status: 202,
        },
        {
          error: "host_not_found",
          method: "GET",
          pathname: "/api/web/hosts/7",
          status: 404,
        },
        {
          error: null,
          method: "GET",
          pathname: "/api/web/audit-log?limit=200",
          status: 200,
        },
      ],
      runtime: {
        activeHub: "candidate",
        activeManifestDigest: `sha256:${"a".repeat(64)}`,
        baselineManifestDigest: `sha256:${"b".repeat(64)}`,
        candidateManifestDigest: `sha256:${"a".repeat(64)}`,
        containerConfigDigest: `sha256:${"c".repeat(64)}`,
        containerInspect: '{"State":{"Running":true}}',
        identityVerified: true,
        imageInspect: `{"Id":"sha256:${"c".repeat(64)}"}`,
        logs: "Hub ready",
        runtimeHistory: [
          {
            configDigest: `sha256:${"d".repeat(64)}`,
            hub: "baseline",
            manifestDigest: `sha256:${"b".repeat(64)}`,
            volume: "enoki-e2e-data-run-repair",
          },
          {
            configDigest: `sha256:${"c".repeat(64)}`,
            hub: "candidate",
            manifestDigest: `sha256:${"a".repeat(64)}`,
            volume: "enoki-e2e-data-run-repair",
          },
        ],
      },
    },
    identityContinuity: {
      after: { ...identity },
      before: { ...identity },
      hostId: 7,
    },
    metrics: {
      afterRepair: [
        portableMetric({ collectedAtMs: 100, sequence: 10 }),
        portableMetric({ collectedAtMs: 110, sequence: 11 }),
      ],
      beforeUpgrade: [
        portableMetric({ collectedAtMs: 10, sequence: 1 }),
        portableMetric({ collectedAtMs: 20, sequence: 2 }),
      ],
    },
    operationTimeline: [
      requestedUpgrade,
      runningUpgrade,
      failedUpgrade,
      { ...failedUpgrade },
    ],
    phase: "succeeded",
    probeConfiguration: {
      afterRepair: {
        mode: "override",
        reportedVersion: "host-7-2",
        version: "host-7-2",
      },
      beforeUpgrade: {
        mode: "override",
        reportedVersion: "host-7-1",
        version: "host-7-1",
      },
    },
    repair: {
      output: "Probe Repair succeeded",
      probeId: identity.probeId,
      repairedVersion: "1.2.3",
    },
    repairedHost: readyHost(),
    repairHostBoundary: {
      delegationGeneration: 1,
      inventory: installedInventory,
      probeVersion: "1.2.3",
      service: {
        ActiveState: "active",
        FragmentPath: "/etc/systemd/system/enoki-probe.service",
        Group: "enoki-probe",
        LoadState: "loaded",
        SubState: "running",
        User: "enoki-probe",
      },
      sudoers: "",
    },
    result: { status: "succeeded" },
    uninstallCompletion: {
      clean: true,
      inventory: cleanInventory,
      journald: "retained Probe Repair journal",
      journaldRetained: true,
      sharedDependencies: '{"curl":"/usr/bin/curl"}',
      sharedDependenciesRetained: true,
    },
    uninstallOperationTimeline: [
      requestedUninstall,
      succeededUninstall,
      { ...succeededUninstall },
    ],
  };
}

function bindRepairEvidenceToBaseline(evidence, baseline) {
  const digest = baseline.hub.imageDigest;
  evidence.hubEvidence.runtime.baselineManifestDigest = digest;
  evidence.hubEvidence.runtime.runtimeHistory.find(
    (entry) => entry.hub === "baseline",
  ).manifestDigest = digest;
}

function portableMetric(overrides = {}) {
  return {
    collectedAtMs: 10,
    cpuPercent: 25,
    memoryTotalBytes: 2_147_483_648,
    memoryUsedBytes: 1_073_741_824,
    sequence: 1,
    uptimeSeconds: 100,
    ...overrides,
  };
}

function migrationBaselineEnvironment(
  calls,
  candidateManifest,
  { candidateConfigurationNeverRetained = false } = {},
) {
  const legacyIdentity = {
    identitySha256: "a".repeat(64),
    probeId: "probe_release_legacy",
  };
  const replacementIdentity = {
    identitySha256: "b".repeat(64),
    probeId: "probe_release_replacement",
  };
  const requestedUninstall = {
    acceptedAtMs: null,
    completedAtMs: null,
    createdAtMs: 30,
    failure: null,
    hostId: 7,
    id: 42,
    kind: "probe_uninstall",
    runningAtMs: null,
    state: "pending",
    targetProbeVersion: "",
    updatedAtMs: 30,
  };
  const succeededUninstall = {
    ...requestedUninstall,
    acceptedAtMs: 31,
    completedAtMs: 32,
    runningAtMs: 31,
    state: "succeeded",
    updatedAtMs: 32,
  };
  const uninstallTimeline = [
    requestedUninstall,
    succeededUninstall,
    { ...succeededUninstall },
  ];
  let configuration = {
    enabledCollectorIds: ["official.cpu", "official.memory"],
    metricsCollectionIntervalSeconds: 30,
    version: "default-v1",
  };
  let configurationSequence = 0;
  let listCalls = 0;
  let metricSequence = 3;
  let replaced = false;
  let candidateHostObservations = 0;
  const hostMetadata = {
    connectAddress: "release-test-host",
    description: "retained description",
    displayName: "retained Host",
    observedIp: "192.0.2.10",
  };
  const currentHost = ({
    reportedVersion = configuration.version,
    warnings = [],
  } = {}) =>
    readyHost({
      hostMetadata,
      hostProfile: {
        ...readyHost().hostProfile,
        probeVersion: replaced ? "1.2.3" : "0.1.74",
      },
      reportedProbeConfigurationVersion: reportedVersion,
      warnings,
    });
  const metrics = () =>
    Array.from({ length: metricSequence }, (_, index) =>
      portableMetric({
        collectedAtMs: (index + 1) * 10,
        sequence: index + 1,
      }),
    );
  const auditLog = [
    ...lifecycleAuditLog(),
    {
      action: "probe.manual_reinstall_identity_replaced",
      actor: "system",
      details: {
        enrollmentId: "enr_manual_reinstall_behavior",
        newProbeId: replacementIdentity.probeId,
        oldProbeId: legacyIdentity.probeId,
        sourceProbeSha256: ["c".repeat(64)],
        targetAssetSetDigest: `sha256:${"d".repeat(64)}`,
        targetProbeVersion: "1.2.3",
      },
      id: 9,
      occurredAtMs: 90,
      outcome: "success",
      subjectId: "7",
      subjectType: "host",
    },
  ];
  const successfulInstallResult = (runId, bootstrapRecipeProvenance) => ({
    bootstrapRecipeProvenance,
    output: {
      code: 0,
      stderr: "",
      stdout: productInstallerOutput(),
    },
    runId,
  });
  const host = {
    async assertDisposable() {},
    async assertLegacyReleaseBaselineInstalled(_runId, version) {
      calls.push(`host.assertLegacyReleaseBaselineInstalled:${version}`);
      return { probeVersion: version };
    },
    async assertInstalled() {
      if (!replaced) return { probeVersion: "0.1.74" };
      return {
        delegationGeneration: 1,
        inventory: {
          accounts: { group: true, user: true },
          files: [
            "/usr/local/bin/enoki-probe",
            "/etc/systemd/system/enoki-probe.service",
          ],
          units: ["enoki-probe.service"],
        },
        probeVersion: "1.2.3",
        service: {
          ActiveState: "active",
          FragmentPath: "/etc/systemd/system/enoki-probe.service",
          Group: "enoki-probe",
          LoadState: "loaded",
          SubState: "running",
          User: "enoki-probe",
        },
        sudoers: "",
      };
    },
    async cleanup() {
      return { clean: true };
    },
    async collectEvidence() {
      return { journaldRetained: true };
    },
    async install(enrollment, runId) {
      calls.push("host.install:legacy-v0.1.74");
      expect(enrollment.installCommand).toBe(
        "curl -fsSL 'https://hub.example/api/probe/install.sh' | sudo env ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_legacy' bash",
      );
      return successfulInstallResult(runId, null);
    },
    async manualReinstall(enrollment, runId) {
      calls.push(`host.manualReinstall:${enrollment.target.kind}`);
      expect(enrollment.installCommand).toBe(officialInstallCommand);
      replaced = true;
      metricSequence += 1;
      return successfulInstallResult(
        runId,
        candidateRecipeProvenance(candidateManifest),
      );
    },
    async readProbeIdentity() {
      return replaced ? replacementIdentity : legacyIdentity;
    },
    async verifyUninstallCompletion() {
      return {
        clean: true,
        inventory: {
          accounts: { group: false, user: false },
          files: [],
          units: [],
        },
        journaldRetained: true,
        sharedDependenciesRetained: true,
      };
    },
  };
  const hub = {
    async authenticate() {},
    async captureBaselineStateSnapshot() {
      calls.push("hub.captureBaselineStateSnapshot");
      return {
        baselineImageDigest: `sha256:${"2".repeat(64)}`,
        baselineVersion: "v0.1.74",
        hotDataFileCount: 1,
        hotDataFiles: ["data-root/enoki.db"],
        manifestDigest: `sha256:${"7".repeat(64)}`,
        recoveryTime: "2026-08-23T00:00:00.000Z",
        roots: [
          { id: "data-root", included: true, path: "/data" },
          {
            id: "metrics-archive",
            included: true,
            path: "/data/metrics-archive",
          },
        ],
        tool: "enoki-hub-state",
        version: "v1",
      };
    },
    async collectEvidence() {
      return { apiTimeline: [] };
    },
    async createEnrollment() {
      return {
        enrollmentToken: "enk_enroll_legacy",
        hubUrl: "https://hub.example",
        installCommand:
          "curl -fsSL 'https://hub.example/api/probe/install.sh' | sudo env ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_legacy' bash",
      };
    },
    async createManualReinstallEnrollment() {
      return officialEnrollment({
        enrollmentId: "enr_manual_reinstall_behavior",
        target: { hostId: 7, kind: "manual_reinstall" },
      });
    },
    async getAuditLog() {
      return auditLog;
    },
    async getHost() {
      if (!replaced) return currentHost();
      candidateHostObservations += 1;
      const reportedVersion =
        candidateConfigurationNeverRetained || candidateHostObservations === 1
          ? "default-v1"
          : configuration.version;
      const configurationError = candidateHostObservations === 2;
      calls.push(
        `hub.getHost:candidate:${reportedVersion}:${configurationError ? "configuration-error" : "clean"}`,
      );
      return currentHost({
        reportedVersion,
        warnings: configurationError
          ? [{ code: "probe_configuration_error" }]
          : [],
      });
    },
    async getHostMetrics() {
      const result = metrics();
      metricSequence += 1;
      return result;
    },
    async getHostProbeConfiguration() {
      return { configuration: { ...configuration }, mode: "override" };
    },
    async isHostSoftDeleted() {
      return true;
    },
    async listHosts() {
      listCalls += 1;
      return listCalls === 1 ? [] : [{ id: 7 }];
    },
    async requestProbeUninstall() {
      return uninstallTimeline[0];
    },
    async restoreBaselineStateSnapshot() {
      calls.push("hub.restoreBaselineStateSnapshot");
      return {
        image: {
          activeManifestDigest: `sha256:${"2".repeat(64)}`,
          expectedManifestDigest: `sha256:${"2".repeat(64)}`,
        },
        restore: {
          manifestDigest: `sha256:${"7".repeat(64)}`,
          status: "succeeded",
        },
        verify: {
          manifestDigest: `sha256:${"7".repeat(64)}`,
          status: "succeeded",
        },
      };
    },
    async switchToCandidate() {
      calls.push("hub.switchToCandidate");
    },
    async updateHostProbeConfiguration(_hostId, input) {
      configurationSequence += 1;
      configuration = {
        ...input.configuration,
        version: `host-7-${configurationSequence}`,
      };
      return { configuration: { ...configuration }, mode: "override" };
    },
    async waitForProbeOperation() {
      return uninstallTimeline;
    },
  };
  return {
    async cleanup() {
      return { clean: true };
    },
    async start() {
      return {
        host,
        hub,
        infrastructure: {
          artifactAccess: "github-actions",
          connection: "local",
          kind: "ci",
          matrixCellId: "ubuntu-22.04-x86_64--replacement-migration-uninstall",
          provisioning: "github-hosted-runner",
        },
        releaseTestHost: {
          architecture: "x86_64",
          deviceView: true,
          journaldSocket: true,
          operatingSystem: "ubuntu",
          operatingSystemVersion: "22.04",
          pid1: "systemd",
          rootFilesystem: true,
          systemdNotifySocket: true,
          unifiedCgroup: true,
          virtualization: "kvm",
        },
      };
    },
  };
}

function operationPollingClient(observe) {
  return createHubLifecycleClient({
    baseUrl: "https://hub.example",
    fetch: async (url, init = {}) => {
      const path = new URL(url).pathname;
      if (path === "/api/web/auth/login") {
        return jsonResponse({ authenticated: true }, 200, {
          "set-cookie": "enoki_owner_session=session-1; Path=/; HttpOnly",
        });
      }
      if (path === "/api/web/hosts/7" && init.method === "DELETE") {
        return jsonResponse(
          {
            probeUninstallRequest: {
              acceptedAtMs: null,
              completedAtMs: null,
              createdAtMs: 1,
              failure: null,
              id: 42,
              runningAtMs: null,
              state: "pending",
              updatedAtMs: 1,
            },
          },
          202,
        );
      }
      if (path === "/api/web/probe-operations/42") {
        return jsonResponse({ probeOperation: observe() });
      }
      throw new Error(`unexpected request ${path}`);
    },
    sleep: async () => {},
  });
}
