// Probe Host Harness, migrated verbatim from the createProbeHostHarness region
// of release-e2e-lib.mjs to erasable, strictly typed TypeScript so the Release
// E2E Orchestrator, its Adapters and the business tests keep calling the SAME
// public Harness Interface (createProbeHostHarness over the execute /
// prepareInstall seam) while reaching this single typed implementation. The run
// ownership, claim/permission roles, scenario evidence attribution, the run-owned
// resource cleanup, the independent verify-clean result, the installed-bundle
// failure repair driver and every original failure message and diagnostic are
// preserved unchanged; only parameter, return and evidence types are added.

import { randomUUID } from "node:crypto";

import { probeTargets } from "@enoki/probe-release";

import { isSupportedReleaseTestHostVirtualization } from "./release-evidence-judgments.ts";
import type {
  CommandExecutor,
  CommandResult,
  InstalledBundleFailureRepair,
  ProbeIdentityEvidence,
} from "./release-installed-bundle-failure-repair.ts";
import { createInstalledBundleFailureRepairHostDriver } from "./release-installed-bundle-failure-repair.ts";
import {
  isPositiveSafeInteger,
  isSafeInteger,
  isUnknownArray,
  isUnknownRecord,
  objectView,
  regexInput,
  stringValue,
} from "./release-json-guards.ts";
import { probeRepairLocalCompletionOutput } from "./release-repair-closure-evidence.ts";

// Release E2E infrastructure has one narrowly scoped, run-owned resource
// definition. It produces the preflight allowlist, recorded fingerprint, and
// emergency-removal plan; the product installer and uninstaller are never
// invoked by this test-only path.
type ManagedFileResource = { kind: "file"; path: string };
type ManagedDirectoryResource = { kind: "directory"; path: string };
type ProbeUserResource = { kind: "user"; name: string };
type ProbeGroupResource = { kind: "group"; name: string };
type ProbeServiceResource = { kind: "service"; name: string };
type ManagedPathResource = ManagedFileResource | ManagedDirectoryResource;
type ManagedNameResource =
  | ProbeUserResource
  | ProbeGroupResource
  | ProbeServiceResource;
type InfrastructureResource = ManagedPathResource | ManagedNameResource;

const releaseE2EInfrastructureResources: readonly InfrastructureResource[] =
  Object.freeze([
    { kind: "file", path: "/usr/local/bin/enoki-probe" },
    { kind: "file", path: "/usr/local/bin/enoki-probe-bootstrap-acquire" },
    { kind: "file", path: "/usr/local/bin/enoki-probe-bootstrap-activate" },
    {
      kind: "file",
      path: "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
    },
    { kind: "directory", path: "/var/lib/enoki-probe-bootstrap" },
    { kind: "file", path: "/etc/enoki/probe-install.toml" },
    { kind: "file", path: "/etc/systemd/system/enoki-probe.service" },
    {
      kind: "file",
      path: "/etc/systemd/system/enoki-probe.service.d/90-enoki-release-e2e-restart-failure.conf",
    },
    { kind: "directory", path: "/var/lib/enoki-probe" },
    { kind: "file", path: "/etc/sudoers.d/enoki-probe-operations" },
    {
      kind: "file",
      path: "/etc/sudoers.d/enoki-probe-collector-helpers",
    },
    { kind: "file", path: "/etc/sudoers.d/enoki-probe-upgrader" },
    { kind: "user", name: "enoki-probe" },
    { kind: "group", name: "enoki-probe" },
    { kind: "service", name: "enoki-probe.service" },
  ]);

const managedHostPaths: readonly string[] = Object.freeze(
  releaseE2EInfrastructureResources
    .filter((resource): resource is ManagedPathResource => "path" in resource)
    .map((resource) => resource.path),
);

const releaseE2EUsers: readonly string[] = Object.freeze(
  releaseE2EInfrastructureResources
    .filter(
      (resource): resource is ProbeUserResource => resource.kind === "user",
    )
    .map((resource) => resource.name),
);

const releaseE2EGroups: readonly string[] = Object.freeze(
  releaseE2EInfrastructureResources
    .filter(
      (resource): resource is ProbeGroupResource => resource.kind === "group",
    )
    .map((resource) => resource.name),
);

export type ProbeOperationState =
  | "pending"
  | "accepted"
  | "running"
  | "succeeded"
  | "failed"
  | "canceled"
  | "superseded";

export const probeOperationStateRank: Readonly<
  Record<ProbeOperationState, number>
> = Object.freeze({
  accepted: 1,
  canceled: 3,
  failed: 3,
  pending: 0,
  running: 2,
  succeeded: 3,
  superseded: 3,
});

export type ProbeOperationFailure = {
  code: string;
  message: string;
};

export type ProbeOperation = {
  acceptedAtMs: number | null;
  completedAtMs: number | null;
  createdAtMs: number;
  failure: ProbeOperationFailure | null | undefined;
  hostId?: number;
  id: number;
  kind?: string;
  runningAtMs: number | null;
  state: ProbeOperationState;
  targetProbeVersion: string;
  updatedAtMs: number;
};

export type ProbeOperationExpectation = {
  hostId?: number;
  id?: number;
  kind?: string;
  targetProbeVersion?: string;
};

export type InstallContract = {
  hubUrl: string;
  kind: "bootstrap-recipe" | "legacy-v0.1.74";
  token: string;
};

export type BootstrapRecipeRecord = {
  bundleVersion?: string;
  distribution?: string;
  kind?: string;
  recipe?: { file?: string; sha256?: string; size?: number; version?: string };
  rootFingerprint?: string;
  schemaVersion?: number;
  targets?: unknown;
};

export type Enrollment = {
  bootstrapRecipe?: unknown;
  enrollmentToken?: string;
  hubUrl?: string;
  installCommand?: string;
};

export type PreparedInstall = {
  evidence?: unknown;
  workingDirectory?: string;
};

export type PreparedInstallOptions = {
  enrollment: Enrollment;
  installContract: InstallContract;
  runId: string;
};

export type PrepareInstall = (
  options: PreparedInstallOptions,
) =>
  | PreparedInstall
  | null
  | undefined
  | Promise<PreparedInstall | null | undefined>;

export type PreparedEnrollmentInstall = {
  bootstrapRecipeProvenance: unknown;
  installContract: InstallContract;
  workingDirectory: string | undefined;
};

export type CommandEvidence = {
  code: number;
  stderr: string;
  stdout: string;
};

export type SerializedError = {
  code: unknown;
  message: string;
  installerEvidence?: unknown;
  errors?: SerializedError[];
};

export type DiagnosticComponent =
  | { available: true; output: CommandEvidence; value: unknown }
  | {
      available: false;
      error: SerializedError | { code: string; message: string };
      output?: CommandEvidence;
    };

export type HostInventory = {
  accounts: { group: boolean; user: boolean };
  files: string[];
  units: string[];
};

export type InstalledState = {
  binarySha256: string;
  identity: { identitySha256: string; probeId: string };
  installMetadataSha256: string;
  restartCount: number;
  service: { ActiveState: string; LoadState: string; SubState: string };
};

export type PermanentReportRejection = {
  binarySha256: string;
  identity: { identitySha256: string; probeId: string };
  installMetadataSha256: string;
  restartCountAfterObservation: number;
  restartCountBeforeObservation: number;
  service: {
    ActiveState: string;
    ExecMainStatus: number;
    LoadState: string;
    SubState: string;
  };
};

export type InstalledDiagnostics = {
  binary: { sha256: string; version: string };
  identity: { identitySha256: string; probeId: string };
  installMetadataSha256: string;
  service: {
    ActiveState: string;
    ExecMainStatus: number;
    LoadState: string;
    NRestarts: number;
    Result: string;
    SubState: string;
  };
};

export type HostPlatformExpectation = {
  architecture: string;
  operatingSystem: string;
  operatingSystemVersion: string;
};

type ProbeHostHarnessOptions = {
  execute: CommandExecutor;
  ownershipToken?: string;
  prepareInstall?: PrepareInstall;
};

export function createProbeHostHarness({
  execute,
  ownershipToken = randomUUID(),
  prepareInstall,
}: ProbeHostHarnessOptions) {
  if (typeof execute !== "function") {
    throw new Error("Probe Host Harness requires an execute function");
  }

  let disposableRunId: string | null = null;
  if (!/^[0-9a-f-]{36}$/.test(ownershipToken)) {
    throw new Error("Probe Host Harness ownership token is invalid");
  }
  let runOwnsMutation = false;
  let canonicalRuntimeUnavailableArmed = false;
  let postReplacementFaultArmed = false;
  let readyForReinstallation = false;
  let sharedDependenciesBefore: string | null = null;
  if (prepareInstall !== undefined && typeof prepareInstall !== "function") {
    throw new Error("Probe Host Harness install preparation is invalid");
  }
  const installedBundleFailureRepair =
    createInstalledBundleFailureRepairHostDriver({
      assertOwnedRun: (runId) =>
        assertOwnedRun(runId, disposableRunId, runOwnsMutation),
      execute,
      ownershipToken,
    });

  async function inventory(): Promise<HostInventory> {
    const result = await execute(hostInventoryScript(), { root: true });
    if (result.code !== 0) {
      throw new Error(
        `Release Test Host inspection failed (${result.code}): ${result.stderr}`,
      );
    }
    const inspected = parseJson(result.stdout, "Release Test Host inventory");
    assertHostInventoryEvidence(inspected);
    return inspected;
  }

  async function collectDiagnosticComponent({
    label,
    parse = (value: string) => value,
    script,
    validate = () => {},
  }: {
    label: string;
    parse?: (value: string) => unknown;
    script: string;
    validate?: (value: unknown) => void;
  }): Promise<DiagnosticComponent> {
    let output: CommandEvidence | null = null;
    try {
      const result = await execute(script, { root: true });
      output = commandEvidence(result);
      if (result.code !== 0) {
        return {
          available: false,
          error: {
            code: "diagnostic_command_failed",
            message: `${label} diagnostic command exited ${result.code}`,
          },
          output,
        };
      }
      const value = parse(result.stdout);
      validate(value);
      return { available: true, output, value };
    } catch (error) {
      return {
        available: false,
        error: serializedError(error),
        ...(output ? { output } : {}),
      };
    }
  }

  async function prepareEnrollmentInstall(
    enrollment: Enrollment,
    runId: string,
  ): Promise<PreparedEnrollmentInstall> {
    const installContract = assertEnrollmentInstallContract(enrollment);
    const prepared = prepareInstall
      ? await prepareInstall({ enrollment, installContract, runId })
      : null;
    const workingDirectory = prepared?.workingDirectory;
    if (
      workingDirectory !== undefined &&
      !/^\/tmp\/enoki-release-e2e-recipe\.[A-Za-z0-9]+$/.test(workingDirectory)
    ) {
      throw new Error(
        "Probe Host Harness install working directory is invalid",
      );
    }
    if (
      installContract.kind === "bootstrap-recipe" &&
      prepareInstall &&
      !workingDirectory
    ) {
      throw new Error(
        "Probe Bootstrap recipe was not staged from the active Hub image",
      );
    }
    return {
      bootstrapRecipeProvenance: prepared?.evidence ?? null,
      installContract,
      workingDirectory,
    };
  }

  async function runInstallCommand(
    enrollment: Enrollment,
    runId: string,
    transition: string,
  ) {
    assertRunId(runId);
    if (disposableRunId !== runId) {
      throw new Error(
        "Release Test Host must pass disposable preflight before installation",
      );
    }
    const reinstallation = runOwnsMutation;
    if (transition === "manual-reinstall") {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (readyForReinstallation) {
        throw new Error(
          "Release Test Host manual reinstall requires the current owned Probe installation",
        );
      }
    } else if (reinstallation && !readyForReinstallation) {
      throw new Error(
        "Release Test Host must complete Local Probe Uninstall before reinstallation",
      );
    }
    if (!reinstallation) {
      const claim = await execute(claimRunScript(runId, ownershipToken), {
        root: true,
      });
      if (claim.code !== 0) {
        throw new Error(
          `Could not claim Release Test Host run: ${claim.stderr}`,
        );
      }
      runOwnsMutation = true;
    }
    const {
      bootstrapRecipeProvenance,
      workingDirectory: installWorkingDirectory,
    } = await prepareEnrollmentInstall(enrollment, runId);
    const result = await execute(
      `# enoki-release-e2e:bootstrap-acquire\nset -eu\n[ "$(id -u)" != 0 ]\n${installWorkingDirectory ? `cd -- ${shellSingleQuote(installWorkingDirectory)}\n` : ""}${enrollment.installCommand}\n`,
      {
        root: false,
        sensitive: true,
      },
    );
    const recorded = await execute(
      reinstallation
        ? renewRunResourcesScript(runId, ownershipToken)
        : recordRunResourcesScript(runId, ownershipToken),
      { root: true },
    );
    if (recorded.code !== 0) {
      throw Object.assign(
        new Error(
          `Could not record run-owned Probe resources: ${recorded.stderr}`,
        ),
        {
          code: "probe_resource_recording_failed",
          installerEvidence: commandEvidence(result),
        },
      );
    }
    if (result.code !== 0) {
      throw Object.assign(
        new Error(
          `Probe installation failed (${result.code}); redacted installer evidence was retained`,
        ),
        {
          code: "probe_installation_failed",
          installerEvidence: commandEvidence(result),
        },
      );
    }
    readyForReinstallation = false;
    return {
      bootstrapRecipeProvenance,
      output: commandEvidence(result),
      runId,
    };
  }

  return {
    async repairInstalledBundleFailure(
      runId: string,
      expectedBundleVersion: string,
    ): Promise<InstalledBundleFailureRepair> {
      return installedBundleFailureRepair.repair(runId, expectedBundleVersion);
    },
    async assertReleaseTestHost(expected: Partial<HostPlatformExpectation>) {
      if (
        expected?.operatingSystem !== "ubuntu" ||
        !/^\d{2}\.\d{2}$/.test(expected.operatingSystemVersion ?? "") ||
        expected.architecture !== "x86_64"
      ) {
        throw new Error("Declared Release Test Host platform is invalid");
      }
      const result = await execute(hostPlatformScript());
      if (result.code !== 0) {
        throw new Error(
          `Release Test Host platform inspection failed (${result.code}): ${result.stderr}`,
        );
      }
      const actual = objectView(
        parseJson(result.stdout, "Release Test Host platform"),
      );
      for (const property of [
        "architecture",
        "operatingSystem",
        "operatingSystemVersion",
      ] as const) {
        if (actual[property] !== expected[property]) {
          throw new Error(
            `Release Test Host ${property} ${stringValue(actual[property]) || "unknown"} does not match declared ${expected[property]}`,
          );
        }
      }
      if (actual.pid1 !== "systemd") {
        throw new Error(
          `Release Test Host must use host systemd as PID 1, found ${stringValue(actual.pid1) || "unknown"}`,
        );
      }
      if (!isSupportedReleaseTestHostVirtualization(actual.virtualization)) {
        throw new Error(
          `Release Test Host must be a supported VM, found ${stringValue(actual.virtualization) || "unknown"}`,
        );
      }
      for (const primitive of [
        "deviceView",
        "journaldSocket",
        "rootFilesystem",
        "systemdNotifySocket",
        "unifiedCgroup",
      ] as const) {
        if (actual[primitive] !== true) {
          throw new Error(
            `Release Test Host required host primitive ${primitive} is unavailable`,
          );
        }
      }
      return actual;
    },

    async assertDisposable(runId: string) {
      assertRunId(runId);
      const inspected = await inventory();
      const residue = inventoryResidue(inspected);
      if (residue.length > 0) {
        throw new Error(
          `Release Test Host has a pre-existing Enoki installation not attributable to ${runId}: ${residue.join(", ")}`,
        );
      }
      const dependencies = await execute(dependencyEvidenceScript());
      if (dependencies.code !== 0 || !dependencies.stdout.trim()) {
        throw new Error(
          `Release Test Host shared dependency inspection failed: ${dependencies.stderr}`,
        );
      }
      sharedDependenciesBefore = dependencies.stdout.trim();
      disposableRunId = runId;
      return inspected;
    },

    async install(enrollment: Enrollment, runId: string) {
      return runInstallCommand(enrollment, runId, "fresh");
    },

    async manualReinstall(enrollment: Enrollment, runId: string) {
      return runInstallCommand(enrollment, runId, "manual-reinstall");
    },

    async assertInstalled(runId: string, expectedProbeVersion: string) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (
        !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
          regexInput(expectedProbeVersion),
        )
      ) {
        throw new Error("Candidate Probe version is invalid");
      }
      const [
        inspected,
        serviceResult,
        sudoersResult,
        binaryVersionResult,
        generationResult,
      ] = await Promise.all([
        inventory(),
        execute(serviceBoundaryScript()),
        execute(sudoersBoundaryScript(), { root: true }),
        execute(binaryVersionScript()),
        execute(bootstrapGenerationStateScript(), { root: true }),
      ]);
      const residue = inventoryResidue(inspected);
      const required = [
        "user:enoki-probe",
        "group:enoki-probe",
        "/usr/local/bin/enoki-probe",
        "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
        "/var/lib/enoki-probe-bootstrap",
        "/etc/enoki/probe-install.toml",
        "/etc/systemd/system/enoki-probe.service",
        "/var/lib/enoki-probe",
        "enoki-probe.service",
      ];
      const missing = required.filter((entry) => !residue.includes(entry));
      if (missing.length > 0) {
        throw new Error(
          `Probe installation is incomplete: missing ${missing.join(", ")}`,
        );
      }
      if (serviceResult.code !== 0) {
        throw new Error(
          `Probe service inspection failed: ${serviceResult.stderr}`,
        );
      }
      const service = parseKeyValues(serviceResult.stdout);
      if (
        service.LoadState !== "loaded" ||
        service.ActiveState !== "active" ||
        service.User !== "enoki-probe" ||
        service.Group !== "enoki-probe" ||
        service.FragmentPath !== "/etc/systemd/system/enoki-probe.service"
      ) {
        throw new Error(
          `Probe service does not satisfy the non-root installation contract: ${JSON.stringify(service)}`,
        );
      }
      if (sudoersResult.code !== 0 || sudoersResult.stdout.trim() !== "") {
        throw new Error(
          "Probe Bootstrap schema 2 installation must not retain Probe sudoers",
        );
      }
      const generation = generationResult.stdout.trim();
      if (generationResult.code !== 0 || !/^[1-9]\d*$/.test(generation)) {
        throw new Error(
          "Probe Bootstrap delegation generation state is missing or invalid",
        );
      }
      const probeVersion =
        binaryVersionResult.code === 0
          ? binaryVersionResult.stdout
              .trim()
              .match(/(?:^|\s)v?(\d+\.\d+\.\d+)(?:\s|$)/)?.[1]
          : null;
      if (probeVersion !== expectedProbeVersion) {
        throw new Error(
          `Installed Probe binary version ${probeVersion ?? "unknown"} does not match Candidate ${expectedProbeVersion}`,
        );
      }
      return {
        inventory: inspected,
        probeVersion,
        service,
        sudoers: sudoersResult.stdout,
        delegationGeneration: Number(generation),
      };
    },

    async captureInstallationState(runId: string) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const result = await execute(installedStateScript(), { root: true });
      if (result.code !== 0) {
        throw new Error(
          `Installed Probe state inspection failed (${result.code}): ${result.stderr}`,
        );
      }
      const state = parseJson(result.stdout, "installed Probe state");
      assertInstalledStateEvidence(state);
      return state;
    },

    async rejectRepeatedInstall(enrollment: Enrollment, runId: string) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const { workingDirectory } = await prepareEnrollmentInstall(
        enrollment,
        runId,
      );
      const result = await execute(
        `# enoki-release-e2e:bootstrap-acquire\nset -eu\n[ "$(id -u)" != 0 ]\n${workingDirectory ? `cd -- ${shellSingleQuote(workingDirectory)}\n` : ""}${enrollment.installCommand}\n`,
        {
          root: false,
          sensitive: true,
        },
      );
      const rejection = `${result.stdout}\n${result.stderr}`.match(
        /\bcode=([a-z0-9_]+)\b/,
      )?.[1];
      if (result.code === 0 || rejection !== "existing_probe_installation") {
        throw new Error(
          `Repeated Probe Add did not return existing_probe_installation: ${result.stderr || result.stdout}`,
        );
      }
      return {
        code: rejection,
        output: commandEvidence(result),
      };
    },

    async awaitPermanentReportRejection(runId: string) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const result = await execute(permanentReportRejectionScript(), {
        root: true,
      });
      if (result.code !== 0) {
        throw new Error(
          `Permanent Probe report rejection was not observed: ${result.stderr}`,
        );
      }
      const evidence = parseJson(
        result.stdout,
        "permanent Probe report rejection evidence",
      );
      assertPermanentReportRejectionEvidence(evidence);
      return evidence;
    },

    async collectDiagnostics(runId: string) {
      assertRunId(runId);
      const [inventory, installation, journald, sudoers, systemd] =
        await Promise.all([
          collectDiagnosticComponent({
            label: "Host inventory",
            parse: (value: string) =>
              parseJson(value, "terminal Release Test Host inventory"),
            script: hostInventoryScript(),
            validate: assertHostInventoryEvidence,
          }),
          collectDiagnosticComponent({
            label: "Probe installation",
            parse: (value: string) =>
              parseJson(value, "terminal Probe diagnostic evidence"),
            script: installedDiagnosticsScript(),
            validate: assertInstalledDiagnosticsEvidence,
          }),
          collectDiagnosticComponent({
            label: "Probe journald",
            script: journaldEvidenceScript(),
          }),
          collectDiagnosticComponent({
            label: "Probe sudoers",
            script: installedSudoersDiagnosticsScript(),
          }),
          collectDiagnosticComponent({
            label: "Probe systemd",
            script: systemdDiagnosticsScript(),
          }),
        ]);
      return {
        installation,
        inventory,
        journald,
        sudoers,
        systemd,
      };
    },

    async readProbeIdentity(runId: string): Promise<ProbeIdentityEvidence> {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const result = await execute(probeIdentityScript(), { root: true });
      if (result.code !== 0) {
        throw new Error(
          `Probe Identity inspection failed (${result.code}): ${result.stderr}`,
        );
      }
      const identity = objectView(
        parseJson(result.stdout, "Probe Identity evidence"),
      );
      if (
        !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(
          stringValue(identity.probeId),
        ) ||
        !/^[0-9a-f]{64}$/.test(stringValue(identity.identitySha256)) ||
        Object.keys(identity).sort().join(",") !== "identitySha256,probeId"
      ) {
        throw new Error("Probe Identity evidence is invalid");
      }
      return {
        identitySha256: stringValue(identity.identitySha256),
        probeId: stringValue(identity.probeId),
      };
    },

    async restartCanonicalProbeWithoutObservationRuntime(
      runId: string,
      expectedProbeId: string,
    ) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (
        !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(regexInput(expectedProbeId))
      ) {
        throw new Error("canonical Probe Identity is invalid");
      }
      if (canonicalRuntimeUnavailableArmed) {
        throw new Error(
          "canonical Runtime-unavailable fixture is already armed",
        );
      }
      canonicalRuntimeUnavailableArmed = true;
      const result = await execute(
        canonicalRuntimeUnavailableRestartScript(expectedProbeId),
        { root: true },
      );
      if (result.code !== 0) {
        throw new Error(
          `Canonical Probe did not reach READY without Observation Runtime: ${result.stderr}`,
        );
      }
      const evidence = parseJson(
        result.stdout,
        "canonical Runtime-unavailable Host evidence",
      );
      assertCanonicalRuntimeUnavailableHostEvidence(evidence, expectedProbeId);
      return evidence;
    },

    async restoreObservationRuntime(runId: string) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (!canonicalRuntimeUnavailableArmed) {
        throw new Error("canonical Runtime-unavailable fixture is not armed");
      }
      const result = await execute(restoreObservationRuntimeScript(), {
        root: true,
      });
      if (result.code !== 0 || result.stdout.trim() !== "restored") {
        throw new Error(
          `Observation Runtime fixture restoration failed: ${result.stderr}`,
        );
      }
      canonicalRuntimeUnavailableArmed = false;
      return { restored: true };
    },

    async beginUpgradeOwnershipTransition(
      runId: string,
      targetProbeVersion: string,
    ) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeVersion(targetProbeVersion, "Probe Upgrade target version");
      const begun = await execute(
        beginUpgradeOwnershipScript(runId, ownershipToken, targetProbeVersion),
        { root: true },
      );
      if (begun.code !== 0 || begun.stdout.trim() !== "owned") {
        throw new Error(
          `Could not authorize run-owned Probe Upgrade transition: ${begun.stderr}`,
        );
      }
      return { owned: true, targetProbeVersion };
    },

    async armPostReplacementRestartFault(
      runId: string,
      targetProbeVersion: string,
    ) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeVersion(targetProbeVersion, "Probe Repair target version");
      if (postReplacementFaultArmed) {
        throw new Error("post-replacement restart fault is already armed");
      }
      const armed = await execute(
        armPostReplacementRestartFaultScript(
          runId,
          ownershipToken,
          targetProbeVersion,
        ),
        { root: true },
      );
      if (armed.code !== 0 || armed.stdout.trim() !== "armed") {
        throw new Error(
          `Could not arm post-replacement restart fault: ${armed.stderr}`,
        );
      }
      postReplacementFaultArmed = true;
      return { armed: true, targetProbeVersion };
    },

    async bindUpgradeOwnershipTransition(
      runId: string,
      operation: ProbeOperation,
    ) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeOperation(operation, {
        kind: "probe_upgrade",
        targetProbeVersion: operation?.targetProbeVersion,
      });
      if (
        operation.state !== "pending" ||
        operation.acceptedAtMs !== null ||
        operation.runningAtMs !== null ||
        operation.completedAtMs !== null
      ) {
        throw new Error(
          "Probe Upgrade ownership must bind to the pending Owner-authorized operation",
        );
      }
      const bound = await execute(
        bindUpgradeOwnershipScript(runId, ownershipToken, operation),
        { root: true },
      );
      if (bound.code !== 0 || bound.stdout.trim() !== "owned") {
        throw new Error(
          `Could not bind run-owned resources to Probe Upgrade ${operation.id}: ${bound.stderr}`,
        );
      }
      return { operationId: operation.id, owned: true };
    },

    async completeUpgradeOwnershipTransition(
      runId: string,
      operation: ProbeOperation,
    ) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeOperation(operation, {
        kind: "probe_upgrade",
        targetProbeVersion: operation?.targetProbeVersion,
      });
      if (
        operation.state !== "succeeded" ||
        operation.failure ||
        operation.acceptedAtMs === null ||
        operation.runningAtMs === null ||
        operation.completedAtMs === null
      ) {
        throw new Error(
          "Probe Upgrade ownership can complete only from verified successful transition evidence",
        );
      }
      const completed = await execute(
        completeUpgradeOwnershipScript(runId, ownershipToken, operation),
        { root: true },
      );
      if (completed.code !== 0 || completed.stdout.trim() !== "owned") {
        throw new Error(
          `Could not commit run-owned Probe resources after Upgrade ${operation.id}: ${completed.stderr}`,
        );
      }
      return { operationId: operation.id, owned: true };
    },

    async assertPostReplacementUpgradeFailure(
      runId: string,
      operation: ProbeOperation,
      expectedProbeVersion: string,
    ) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeVersion(
        expectedProbeVersion,
        "post-replacement Probe version",
      );
      assertProbeOperation(operation, {
        kind: "probe_upgrade",
        targetProbeVersion: expectedProbeVersion,
      });
      const result = await execute(
        postReplacementUpgradeFailureScript(
          runId,
          ownershipToken,
          operation,
          expectedProbeVersion,
        ),
        { root: true },
      );
      if (result.code !== 0) {
        throw new Error(
          `Post-replacement failure evidence is invalid: ${result.stderr}`,
        );
      }
      return parseJson(result.stdout, "post-replacement failure evidence");
    },

    async removePostReplacementRestartFault(runId: string) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (!postReplacementFaultArmed) {
        throw new Error("post-replacement restart fault is not armed");
      }
      const removed = await execute(
        removePostReplacementRestartFaultScript(runId, ownershipToken),
        { root: true },
      );
      if (removed.code !== 0 || removed.stdout.trim() !== "removed") {
        throw new Error(
          `Could not remove post-replacement restart fault: ${removed.stderr}`,
        );
      }
      postReplacementFaultArmed = false;
      return { removed: true };
    },

    async repair(runId: string) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      if (postReplacementFaultArmed) {
        throw new Error(
          "post-replacement restart fault must be removed before Repair",
        );
      }
      const result = await execute(
        "# enoki-release-e2e:probe-repair\n/usr/local/bin/enoki-probe repair\n",
        { root: true },
      );
      // 08 已接受的正式 CLI 合同：本机完成行不携带 Probe 身份或版本；恢复后的目标
      // 版本与身份保持由已安装包边界与身份读数独立证明，不从 stdout 解析。
      if (
        result.code !== 0 ||
        result.stdout.trim() !== probeRepairLocalCompletionOutput
      ) {
        throw Object.assign(
          new Error(
            `Probe Repair failed (${result.code}): ${result.stderr || result.stdout}`,
          ),
          {
            code:
              result.stderr.match(/code=([a-z0-9_]+)/)?.[1] ??
              "probe_repair_failed",
          },
        );
      }
      return { output: result.stdout.trim() };
    },

    async completeRepairOwnershipTransition(
      runId: string,
      operation: ProbeOperation,
    ) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      assertProbeOperation(operation, {
        kind: "probe_upgrade",
        targetProbeVersion: operation?.targetProbeVersion,
      });
      if (operation.state !== "failed" || !operation.failure) {
        throw new Error(
          "Probe Repair ownership can complete only from a verified failed Probe Upgrade",
        );
      }
      const completed = await execute(
        completeRepairOwnershipScript(runId, ownershipToken, operation),
        { root: true },
      );
      if (completed.code !== 0 || completed.stdout.trim() !== "owned") {
        throw new Error(
          `Could not commit run-owned Probe resources after Repair: ${completed.stderr}`,
        );
      }
      return { operationId: operation.id, owned: true };
    },

    async localUninstall(runId: string) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const result = await execute(
        "# enoki-release-e2e:local-probe-uninstall\n/usr/local/bin/enoki-probe uninstall\n",
        { root: true },
      );
      if (
        result.code !== 0 ||
        result.stdout.trim() !== "Local Probe Uninstall completed."
      ) {
        throw new Error(
          `Local Probe Uninstall failed (${result.code}): ${result.stderr || result.stdout}`,
        );
      }
      const completion = await this.verifyUninstallCompletion(runId);
      readyForReinstallation = true;
      return { completion, output: commandEvidence(result) };
    },

    async cleanup(runId: string) {
      assertRunId(runId);
      if (disposableRunId !== runId || !runOwnsMutation) {
        return { clean: true, skipped: "run_did_not_mutate_host" };
      }
      const errors: Error[] = [];
      const attempt = async <T>(
        operation: () => Promise<T>,
      ): Promise<T | null> => {
        try {
          return await operation();
        } catch (error) {
          errors.push(
            error instanceof Error ? error : new Error(String(error)),
          );
          return null;
        }
      };
      let claimOwned = false;
      await attempt(async () => {
        const claim = await execute(verifyClaimScript(runId, ownershipToken), {
          root: true,
        });
        if (claim.code !== 0 || claim.stdout.trim() !== "owned") {
          throw new Error(
            `Refusing cleanup because Host state is not attributable to run ${runId}: ${claim.stderr}`,
          );
        }
        claimOwned = true;
      });

      if (postReplacementFaultArmed) {
        await attempt(async () => {
          const removed = await execute(
            removePostReplacementRestartFaultScript(runId, ownershipToken),
            { root: true },
          );
          if (removed.code !== 0 || removed.stdout.trim() !== "removed") {
            throw new Error(
              `Run-owned post-replacement fault cleanup failed: ${removed.stderr}`,
            );
          }
          postReplacementFaultArmed = false;
        });
      }

      if (canonicalRuntimeUnavailableArmed) {
        await attempt(async () => {
          const restored = await execute(restoreObservationRuntimeScript(), {
            root: true,
          });
          if (restored.code !== 0 || restored.stdout.trim() !== "restored") {
            throw new Error(
              `Run-owned canonical Runtime fixture cleanup failed: ${restored.stderr}`,
            );
          }
          canonicalRuntimeUnavailableArmed = false;
        });
      }

      await attempt(() => installedBundleFailureRepair.cleanup(runId));

      let inspected = await attempt(() => inventory());
      let residue = inspected ? inventoryResidue(inspected) : null;
      let removedPartialInstallation = false;
      if ((residue?.length ?? 0) > 0) {
        const verifiedResources = await execute(
          verifyRunResourcesScript(runId, ownershipToken),
          { root: true },
        );
        const resourcesOwned = verifiedResources.code === 0;
        if (!resourcesOwned) {
          errors.push(
            new Error(
              `Refusing cleanup because Probe resources no longer match run ${runId}: ${verifiedResources.stderr}`,
            ),
          );
        }
        if (resourcesOwned) {
          await attempt(async () => {
            const cleaned = await execute(
              releaseEmergencyCleanupScript(runId, ownershipToken),
              { root: true },
            );
            if (cleaned.code !== 0) {
              throw new Error(
                `Run-owned emergency cleanup failed: ${cleaned.stderr}`,
              );
            }
            removedPartialInstallation = true;
            const reloaded = await execute(daemonReloadScript(), {
              root: true,
            });
            if (reloaded.code !== 0) {
              throw new Error(
                `cleanup daemon reload failed: ${reloaded.stderr}`,
              );
            }
          });
          inspected = await attempt(() => inventory());
          residue = inspected ? inventoryResidue(inspected) : null;
          if ((residue?.length ?? 0) > 0) {
            errors.push(
              new Error(
                `Run-owned Probe cleanup left residue: ${residue?.join(", ")}`,
              ),
            );
          }
        }
      }

      if (claimOwned && Array.isArray(residue) && residue.length === 0) {
        await attempt(async () => {
          const released = await execute(
            removeClaimScript(runId, ownershipToken),
            { root: true },
          );
          if (released.code !== 0) {
            throw new Error(`Could not remove run claim: ${released.stderr}`);
          }
        });
      }
      await attempt(async () => {
        const releasedClaim = await execute(
          inspectClaimScript(runId, ownershipToken),
          { root: true },
        );
        if (
          releasedClaim.code !== 0 ||
          releasedClaim.stdout.trim() !== "absent"
        ) {
          throw new Error("Run claim remains after Host cleanup");
        }
        runOwnsMutation = false;
        readyForReinstallation = false;
      });
      if (errors.length > 0) {
        throw Object.assign(
          new AggregateError(
            errors,
            `Release Test Host cleanup failed: ${errors.map((error) => error.message).join("; ")}`,
          ),
          { code: "release_test_host_cleanup_failed" },
        );
      }
      return { clean: true, removedPartialInstallation };
    },

    async collectEvidence(runId: string) {
      assertRunId(runId);
      const [inventoryResult, service, journald, sudoers] = await Promise.all([
        execute(hostInventoryScript()),
        execute(systemdEvidenceScript()),
        execute(journaldEvidenceScript(), { root: true }),
        execute(sudoersEvidenceScript(), { root: true }),
      ]);
      return {
        inventory:
          inventoryResult.code === 0
            ? parseJson(inventoryResult.stdout, "Release Test Host inventory")
            : commandEvidence(inventoryResult),
        journald: commandEvidence(journald),
        runClaimed: disposableRunId === runId && runOwnsMutation,
        sudoers: commandEvidence(sudoers),
        systemd: commandEvidence(service),
      };
    },

    async verifyUninstallCompletion(runId: string) {
      assertOwnedRun(runId, disposableRunId, runOwnsMutation);
      const reloaded = await execute(daemonReloadScript(), { root: true });
      if (reloaded.code !== 0) {
        throw new Error(`systemd daemon reload failed: ${reloaded.stderr}`);
      }
      const [inspected, journald, dependencies] = await Promise.all([
        inventory(),
        execute(journaldEvidenceScript(), { root: true }),
        execute(dependencyEvidenceScript()),
      ]);
      const residue = inventoryResidue(inspected);
      if (residue.length > 0) {
        throw new Error(
          `Probe Uninstall left Enoki-managed residue: ${residue.join(", ")}`,
        );
      }
      const journaldText = journald.stdout.trim();
      const journaldRetained =
        journald.code === 0 &&
        journaldText.length > 0 &&
        !journaldText.includes("-- No entries --");
      const sharedDependenciesRetained =
        dependencies.code === 0 &&
        dependencies.stdout.trim() === sharedDependenciesBefore;
      return {
        clean: true,
        inventory: inspected,
        journald: journaldText,
        journaldRetained,
        sharedDependencies: dependencies.stdout.trim(),
        sharedDependenciesRetained,
      };
    },

    async verifyClean(runId: string) {
      assertRunId(runId);
      const reloaded = await execute(daemonReloadScript(), { root: true });
      if (reloaded.code !== 0) {
        throw new Error(
          `verify-clean daemon reload failed: ${reloaded.stderr}`,
        );
      }
      const [inspected, claim] = await Promise.all([
        inventory(),
        execute(inspectClaimScript(runId, ownershipToken), { root: true }),
      ]);
      const residue = inventoryResidue(inspected);
      if (residue.length > 0 || claim.stdout.trim() !== "absent") {
        throw new Error(
          `Release Test Host is not clean: ${[
            ...residue,
            ...(claim.stdout.trim() === "absent"
              ? []
              : [`run-claim:${claim.stdout.trim() || "unknown"}`]),
          ].join(", ")}`,
        );
      }
      return { clean: true, inventory: inspected };
    },
  };
}

function hostPlatformScript(): string {
  return String.raw`# enoki-release-e2e:platform
set -eu
. /etc/os-release
case "$(uname -m)" in
  x86_64) architecture=x86_64 ;;
  *) architecture="$(uname -m)" ;;
esac
pid1="$(cat /proc/1/comm)"
virtualization="$(systemd-detect-virt --vm 2>/dev/null || printf none)"
json_bool() { if "$@" >/dev/null 2>&1; then printf true; else printf false; fi; }
printf '{"architecture":"%s","deviceView":' \
  "$architecture"
json_bool test -c /dev/null
printf ',"journaldSocket":'
json_bool test -S /run/systemd/journal/socket
printf ',"operatingSystem":"%s","operatingSystemVersion":"%s","pid1":"%s","rootFilesystem":' \
  "$(printf '%s' "$ID" | tr '[:upper:]' '[:lower:]')" "$VERSION_ID" "$pid1"
json_bool sh -c 'test -d /etc && test -d /var/lib && test -w /tmp'
printf ',"systemdNotifySocket":'
json_bool test -S /run/systemd/notify
printf ',"unifiedCgroup":'
json_bool test -f /sys/fs/cgroup/cgroup.controllers
printf ',"virtualization":"%s"}\n' "$virtualization"`;
}

function hostInventoryScript(): string {
  const group = shellSingleQuote(stringValue(releaseE2EGroups[0]));
  const user = shellSingleQuote(stringValue(releaseE2EUsers[0]));
  return String.raw`# enoki-release-e2e:inventory
set -eu
json_bool() { if "$@" >/dev/null 2>&1; then printf true; else printf false; fi; }
printf '{"accounts":{"group":'
json_bool getent group ${group}
printf ',"user":'
json_bool getent passwd ${user}
printf '},"files":['
separator=
for candidate in ${managedHostPaths.map(shellSingleQuote).join(" ")}; do
  if [ -e "$candidate" ] || [ -L "$candidate" ]; then
    printf '%s"%s"' "$separator" "$candidate"
    separator=,
  fi
done
for candidate in /run/systemd/system/enoki-probe*.service; do
  if [ -e "$candidate" ] || [ -L "$candidate" ]; then
    printf '%s"%s"' "$separator" "$candidate"
    separator=,
  fi
done
printf '],"units":['
separator=
systemctl list-units --all --full --plain 'enoki-probe*.service' --no-legend --no-pager 2>/dev/null |
  while IFS=' ' read -r unit _; do
    [ -n "$unit" ] || continue
    printf '%s"%s"' "$separator" "$unit"
    separator=,
  done
printf ']}\n'
`;
}

function serviceBoundaryScript(): string {
  return String.raw`# enoki-release-e2e:service-boundary
set -eu
systemctl show enoki-probe.service --no-pager \
  --property=LoadState \
  --property=ActiveState \
  --property=SubState \
  --property=User \
  --property=Group \
  --property=FragmentPath
`;
}

function canonicalRuntimeUnavailableRestartScript(
  expectedProbeId: string,
): string {
  return String.raw`# enoki-release-e2e:canonical-runtime-unavailable
set -eu
identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml
attempt_source=/var/lib/enoki-probe-registration/attempt.json
credential=/run/credentials/enoki-probe.service/registration-attempt
registration_drop_in=/run/systemd/system/enoki-probe.service.d/10-enoki-replacement-registration.conf
[ -f "$identity" ] && [ ! -L "$identity" ]
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$identity")
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
[ "$probe_id" = ${shellSingleQuote(expectedProbeId)} ]
! grep -Eq '^[[:space:]]*registration_' "$identity"
[ ! -e "$attempt_source" ] && [ ! -L "$attempt_source" ]
[ ! -e "$credential" ] && [ ! -L "$credential" ]
[ ! -e "$registration_drop_in" ] && [ ! -L "$registration_drop_in" ]
systemctl stop enoki-observation-runtime.socket enoki-observation-runtime.service
systemctl mask --runtime enoki-observation-runtime.socket enoki-observation-runtime.service
systemctl restart enoki-probe.service
probe_load=$(systemctl show enoki-probe.service --property=LoadState --value)
probe_active=$(systemctl show enoki-probe.service --property=ActiveState --value)
probe_sub=$(systemctl show enoki-probe.service --property=SubState --value)
probe_result=$(systemctl show enoki-probe.service --property=Result --value)
probe_type=$(systemctl show enoki-probe.service --property=Type --value)
runtime_service_load=$(systemctl show enoki-observation-runtime.service --property=LoadState --value)
runtime_socket_load=$(systemctl show enoki-observation-runtime.socket --property=LoadState --value)
[ "$probe_load" = loaded ]
[ "$probe_active" = active ]
[ "$probe_sub" = running ]
[ "$probe_result" = success ]
[ "$probe_type" = notify ]
[ "$runtime_service_load" = masked ]
[ "$runtime_socket_load" = masked ]
printf '{"identity":{"probeId":"%s","registrationAttemptCredential":false,"registrationAttemptSource":false,"registrationDropIn":false,"transitionalRegistrationKeys":false},"probe":{"ActiveState":"%s","LoadState":"%s","Result":"%s","SubState":"%s","Type":"%s"},"runtime":{"serviceLoadState":"%s","socketLoadState":"%s"}}\n' \
  "$probe_id" "$probe_active" "$probe_load" "$probe_result" "$probe_sub" "$probe_type" "$runtime_service_load" "$runtime_socket_load"
`;
}

function restoreObservationRuntimeScript(): string {
  return String.raw`# enoki-release-e2e:restore-observation-runtime
set -eu
systemctl unmask --runtime enoki-observation-runtime.socket enoki-observation-runtime.service
systemctl daemon-reload
systemctl reset-failed enoki-observation-runtime.socket enoki-observation-runtime.service
systemctl start enoki-observation-runtime.socket
printf 'restored\n'
`;
}

function sudoersBoundaryScript(): string {
  return String.raw`# enoki-release-e2e:sudoers-boundary
set -eu
for candidate in /etc/sudoers.d/enoki-probe-operations /etc/sudoers.d/enoki-probe-collector-helpers /etc/sudoers.d/enoki-probe-upgrader; do
  [ ! -e "$candidate" ]
done
`;
}

function binaryVersionScript(): string {
  return String.raw`# enoki-release-e2e:binary-version
set -eu
/usr/local/bin/enoki-probe --version
`;
}

function bootstrapGenerationStateScript(): string {
  return String.raw`# enoki-release-e2e:bootstrap-generation
set -eu
generation=/var/lib/enoki-probe/trust/delegation-generation
[ -f "$generation" ] && [ ! -L "$generation" ]
[ "$(stat -c %u "$generation")" = 0 ]
[ "$(stat -c %a "$generation")" = 600 ]
value=$(cat -- "$generation")
case "$value" in [1-9]* ) ;; *) exit 1 ;; esac
case "$value" in *[!0-9]* ) exit 1 ;; esac
printf '%s\n' "$value"
`;
}

function installedStateScript(): string {
  return String.raw`# enoki-release-e2e:installed-state
set -eu
binary=/usr/local/bin/enoki-probe
metadata=/etc/enoki/probe-install.toml
identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml
[ -x "$binary" ]
[ -f "$metadata" ]
[ -f "$identity" ]
load_state=$(systemctl show enoki-probe.service --no-pager --property=LoadState --value)
active_state=$(systemctl show enoki-probe.service --no-pager --property=ActiveState --value)
sub_state=$(systemctl show enoki-probe.service --no-pager --property=SubState --value)
restart_count=$(systemctl show enoki-probe.service --no-pager --property=NRestarts --value)
case "$restart_count" in ''|*[!0-9]*) exit 1 ;; esac
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$identity")
private_key_line=$(grep -E '^probe_private_key_pem = ".+"$' "$identity")
[ "$(grep -c '^probe_id = ' "$identity")" -eq 1 ]
[ "$(grep -c '^probe_private_key_pem = ' "$identity")" -eq 1 ]
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
identity_sha256=$(printf '%s\n%s\n' "$probe_id_line" "$private_key_line" | sha256sum | cut -d ' ' -f 1)
binary_sha256=$(sha256sum -- "$binary" | cut -d ' ' -f 1)
metadata_sha256=$(sha256sum -- "$metadata" | cut -d ' ' -f 1)
printf '{"binarySha256":"%s","identity":{"identitySha256":"%s","probeId":"%s"},"installMetadataSha256":"%s","restartCount":%s,"service":{"ActiveState":"%s","LoadState":"%s","SubState":"%s"}}\n' \
  "$binary_sha256" "$identity_sha256" "$probe_id" "$metadata_sha256" "$restart_count" "$active_state" "$load_state" "$sub_state"`;
}

function permanentReportRejectionScript(): string {
  return String.raw`# enoki-release-e2e:permanent-report-rejection
set -eu
binary=/usr/local/bin/enoki-probe
metadata=/etc/enoki/probe-install.toml
identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml
read_property() {
  systemctl show enoki-probe.service --no-pager --property="$1" --value
}
for attempt in $(seq 1 60); do
  load_state=$(read_property LoadState)
  active_state=$(read_property ActiveState)
  sub_state=$(read_property SubState)
  exit_status=$(read_property ExecMainStatus)
  restart_count=$(read_property NRestarts)
  case "$restart_count" in ''|*[!0-9]*) exit 1 ;; esac
  if [ "$load_state" = loaded ] && [ "$active_state" = failed ] && [ "$sub_state" = failed ] && [ "$exit_status" = 78 ]; then
    break
  fi
  if [ "$attempt" = 60 ]; then
    printf 'Probe service did not reach permanent report failure: LoadState=%s ActiveState=%s SubState=%s ExecMainStatus=%s NRestarts=%s\n' "$load_state" "$active_state" "$sub_state" "$exit_status" "$restart_count" >&2
    exit 1
  fi
  sleep 2
done
restart_count_before=$restart_count
sleep 10
restart_count_after=$(read_property NRestarts)
case "$restart_count_after" in ''|*[!0-9]*) exit 1 ;; esac
[ "$restart_count_after" = "$restart_count_before" ] || { printf 'Probe restart counter changed after permanent report rejection\n' >&2; exit 1; }
[ -x "$binary" ]
[ -f "$metadata" ]
[ -f "$identity" ]
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$identity")
private_key_line=$(grep -E '^probe_private_key_pem = ".+"$' "$identity")
[ "$(grep -c '^probe_id = ' "$identity")" -eq 1 ]
[ "$(grep -c '^probe_private_key_pem = ' "$identity")" -eq 1 ]
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
identity_sha256=$(printf '%s\n%s\n' "$probe_id_line" "$private_key_line" | sha256sum | cut -d ' ' -f 1)
binary_sha256=$(sha256sum -- "$binary" | cut -d ' ' -f 1)
metadata_sha256=$(sha256sum -- "$metadata" | cut -d ' ' -f 1)
printf '{"binarySha256":"%s","identity":{"identitySha256":"%s","probeId":"%s"},"installMetadataSha256":"%s","restartCountAfterObservation":%s,"restartCountBeforeObservation":%s,"service":{"ActiveState":"%s","ExecMainStatus":%s,"LoadState":"%s","SubState":"%s"}}\n' \
  "$binary_sha256" "$identity_sha256" "$probe_id" "$metadata_sha256" "$restart_count_after" "$restart_count_before" "$active_state" "$exit_status" "$load_state" "$sub_state"`;
}

function installedDiagnosticsScript(): string {
  return String.raw`# enoki-release-e2e:installed-diagnostics
set -eu
binary=/usr/local/bin/enoki-probe
metadata=/etc/enoki/probe-install.toml
identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml
[ -x "$binary" ]
[ -f "$metadata" ]
[ -f "$identity" ]
read_property() {
  systemctl show enoki-probe.service --no-pager --property="$1" --value
}
binary_version=$("$binary" --version | sed -nE 's/.*v?([0-9]+[.][0-9]+[.][0-9]+).*/\1/p' | head -n 1)
case "$binary_version" in ''|*[!0-9.]*|*..*) exit 1 ;; esac
load_state=$(read_property LoadState)
active_state=$(read_property ActiveState)
sub_state=$(read_property SubState)
exit_status=$(read_property ExecMainStatus)
restart_count=$(read_property NRestarts)
result=$(read_property Result)
case "$exit_status" in ''|*[!0-9]*) exit 1 ;; esac
case "$restart_count" in ''|*[!0-9]*) exit 1 ;; esac
[ -n "$result" ]
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$identity")
private_key_line=$(grep -E '^probe_private_key_pem = ".+"$' "$identity")
[ "$(grep -c '^probe_id = ' "$identity")" -eq 1 ]
[ "$(grep -c '^probe_private_key_pem = ' "$identity")" -eq 1 ]
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
identity_sha256=$(printf '%s\n%s\n' "$probe_id_line" "$private_key_line" | sha256sum | cut -d ' ' -f 1)
binary_sha256=$(sha256sum -- "$binary" | cut -d ' ' -f 1)
metadata_sha256=$(sha256sum -- "$metadata" | cut -d ' ' -f 1)
printf '{"binary":{"sha256":"%s","version":"%s"},"identity":{"identitySha256":"%s","probeId":"%s"},"installMetadataSha256":"%s","service":{"ActiveState":"%s","ExecMainStatus":%s,"LoadState":"%s","NRestarts":%s,"Result":"%s","SubState":"%s"}}\n' \
  "$binary_sha256" "$binary_version" "$identity_sha256" "$probe_id" "$metadata_sha256" "$active_state" "$exit_status" "$load_state" "$restart_count" "$result" "$sub_state"`;
}

function probeIdentityScript(): string {
  return String.raw`# enoki-release-e2e:probe-identity
set -eu
config=/var/lib/enoki-probe/identity/probe-bootstrap.toml
[ -f "$config" ]
[ ! -L "$config" ]
probe_id_line=$(grep -E '^probe_id = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"$' "$config")
private_key_line=$(grep -E '^probe_private_key_pem = ".+"$' "$config")
[ "$(grep -c '^probe_id = ' "$config")" -eq 1 ]
[ "$(grep -c '^probe_private_key_pem = ' "$config")" -eq 1 ]
probe_id=$(printf '%s\n' "$probe_id_line" | cut -d '"' -f 2)
identity_sha256=$(printf '%s\n%s\n' "$probe_id_line" "$private_key_line" | sha256sum | cut -d ' ' -f 1)
printf '{"identitySha256":"%s","probeId":"%s"}\n' "$identity_sha256" "$probe_id"
`;
}

function dependencyEvidenceScript(): string {
  return String.raw`# enoki-release-e2e:dependencies
set -eu
curl_path=$(command -v curl)
sudo_path=$(command -v sudo)
systemd_run_path=$(command -v systemd-run)
printf '{"curl":"%s","sudo":"%s","systemdRun":"%s"}\n' "$curl_path" "$sudo_path" "$systemd_run_path"
`;
}

function daemonReloadScript(): string {
  return String.raw`# enoki-release-e2e:daemon-reload
set -eu
systemctl daemon-reload
systemctl reset-failed enoki-probe.service 2>/dev/null || true
`;
}

function journaldEvidenceScript(): string {
  return String.raw`# enoki-release-e2e:journald
set -eu
journalctl --unit=enoki-probe.service --no-pager --lines=200 --output=short-iso
`;
}

function systemdDiagnosticsScript(): string {
  return String.raw`# enoki-release-e2e:systemd-diagnostics
set -eu
systemctl show enoki-probe.service --no-pager --property=LoadState --property=ActiveState --property=SubState --property=Result --property=ExecMainStatus --property=NRestarts
`;
}

function systemdEvidenceScript(): string {
  return String.raw`# enoki-release-e2e:systemd-evidence
set -eu
load_state=$(systemctl show enoki-probe.service --no-pager --property=LoadState --value)
active_state=$(systemctl show enoki-probe.service --no-pager --property=ActiveState --value)
unit_count=$(systemctl list-units --all --full --plain 'enoki-probe*.service' --no-legend --no-pager | awk 'NF { count += 1 } END { print count + 0 }')
failed_unit_count=$(systemctl --failed --all --full --plain --no-legend --no-pager | awk '$1 ~ /^enoki-probe.*[.]service$/ { count += 1 } END { print count + 0 }')
[ "$load_state" = not-found ]
[ "$active_state" = inactive ]
[ "$unit_count" = 0 ]
[ "$failed_unit_count" = 0 ]
printf 'stage=post-uninstall\nLoadState=%s\nActiveState=%s\nunitCount=%s\nfailedUnitCount=%s\n' \
  "$load_state" "$active_state" "$unit_count" "$failed_unit_count"
`;
}

function sudoersEvidenceScript(): string {
  return String.raw`# enoki-release-e2e:sudoers-evidence
set -eu
managed_sudoers_count=0
for candidate in /etc/sudoers.d/enoki-probe-operations /etc/sudoers.d/enoki-probe-collector-helpers /etc/sudoers.d/enoki-probe-upgrader; do
  if [ -e "$candidate" ]; then
    printf 'managed sudoers residue: %s\n' "$candidate" >&2
    managed_sudoers_count=$((managed_sudoers_count + 1))
  fi
done
[ "$managed_sudoers_count" = 0 ] || exit 1
printf 'stage=post-uninstall\nmanagedSudoersCount=0\n'
`;
}

function installedSudoersDiagnosticsScript(): string {
  return String.raw`# enoki-release-e2e:installed-sudoers
set -eu
found=false
for candidate in /etc/sudoers.d/enoki-probe-operations /etc/sudoers.d/enoki-probe-collector-helpers /etc/sudoers.d/enoki-probe-upgrader; do
  if [ -f "$candidate" ]; then
    found=true
    printf '### %s\n' "$candidate"
    cat -- "$candidate"
  fi
done
"$found"
`;
}

function claimRunScript(runId: string, token: string): string {
  const users = releaseE2EUsers.map(shellSingleQuote).join(" ");
  const groups = releaseE2EGroups.map(shellSingleQuote).join(" ");
  return `# enoki-release-e2e:claim
set -eu
claim_root=/var/lib/enoki-release-e2e
claim_dir="$claim_root/claim"
install -d -m 0700 "$claim_root"
if ! mkdir -m 0700 "$claim_dir" 2>/dev/null; then
  printf 'Host already claimed by another Release E2E run\n' >&2
  exit 73
fi
cleanup_rejected_claim() { rm -f -- "$claim_dir/run-id" "$claim_dir/token"; rmdir "$claim_dir" 2>/dev/null || true; rmdir "$claim_root" 2>/dev/null || true; }
trap cleanup_rejected_claim EXIT HUP INT TERM
( umask 077; printf '%s\n' ${shellSingleQuote(runId)} > "$claim_dir/run-id"; printf '%s\n' ${shellSingleQuote(token)} > "$claim_dir/token" )
# enoki-release-e2e:claim-empty-recheck
residue=
for candidate in ${managedHostPaths.map(shellSingleQuote).join(" ")} /run/systemd/system/enoki-probe*.service; do
  if [ -e "$candidate" ] || [ -L "$candidate" ]; then residue="$residue $candidate"; fi
done
for account in ${users}; do
  if getent passwd "$account" >/dev/null 2>&1; then residue="$residue user:$account"; fi
done
for account in ${groups}; do
  if getent group "$account" >/dev/null 2>&1; then residue="$residue group:$account"; fi
done
units=$(systemctl list-units --all --full --plain 'enoki-probe*.service' --no-legend --no-pager 2>/dev/null || true)
if [ -n "$units" ]; then residue="$residue enoki-probe-unit"; fi
if [ -n "$residue" ]; then
  printf 'Release Test Host became non-empty before claim:%s\n' "$residue" >&2
  exit 74
fi
trap - EXIT HUP INT TERM
printf 'owned\n'
`;
}

function verifyClaimScript(runId: string, token: string): string {
  return `# enoki-release-e2e:verify-claim\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\n[ -d "$claim" ]\n[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]\n[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]\nprintf 'owned\\n'\n`;
}

function recordRunResourcesScript(runId: string, token: string): string {
  return resourceFingerprintScript({
    header: "record-resources",
    runId,
    token,
    verify: false,
  });
}

function renewRunResourcesScript(runId: string, token: string): string {
  return `# enoki-release-e2e:renew-resources
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ -f "$claim/resources" ]
${resourceFingerprintFunction()}
temporary=$(mktemp "$claim/resources.renew.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
mv -- "$temporary" "$claim/resources"
trap - EXIT HUP INT TERM
printf 'renewed\\n'
`;
}

function verifyRunResourcesScript(runId: string, token: string): string {
  return resourceFingerprintScript({
    header: "verify-resources",
    runId,
    token,
    verify: true,
  });
}

function resourceFingerprintScript({
  header,
  runId,
  token,
  verify,
}: {
  header: string;
  runId: string;
  token: string;
  verify: boolean;
}): string {
  const action = verify
    ? String.raw`temporary=$(mktemp "$claim/resources.verify.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
cmp --silent "$claim/resources" "$temporary" || { printf 'run-owned resource fingerprint changed\n' >&2; exit 75; }
printf 'owned\n'`
    : String.raw`[ ! -e "$claim/resources" ] || { printf 'run resource evidence already exists\n' >&2; exit 76; }
( umask 077; fingerprint > "$claim/resources" )
printf 'recorded\n'`;
  return `# enoki-release-e2e:${header}
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
${resourceFingerprintFunction()}
${action}
`;
}

function beginUpgradeOwnershipScript(
  runId: string,
  token: string,
  targetProbeVersion: string,
): string {
  return `# enoki-release-e2e:begin-upgrade-ownership
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ -f "$claim/resources" ]
[ ! -e "$claim/upgrade-target" ]
[ ! -e "$claim/upgrade-operation-id" ]
cp -- "$claim/resources" "$claim/upgrade-before-resources"
( umask 077; printf '%s\n' ${shellSingleQuote(targetProbeVersion)} > "$claim/upgrade-target" )
printf 'owned\n'
`;
}

function bindUpgradeOwnershipScript(
  runId: string,
  token: string,
  operation: ProbeOperation,
): string {
  return `# enoki-release-e2e:bind-upgrade-ownership
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ "$(cat "$claim/upgrade-target")" = ${shellSingleQuote(operation.targetProbeVersion)} ]
[ -f "$claim/upgrade-before-resources" ]
cmp --silent "$claim/resources" "$claim/upgrade-before-resources"
[ ! -e "$claim/upgrade-operation-id" ]
( umask 077; printf '%s\n' ${shellSingleQuote(String(operation.id))} > "$claim/upgrade-operation-id" )
printf 'owned\n'
`;
}

function armPostReplacementRestartFaultScript(
  runId: string,
  token: string,
  targetProbeVersion: string,
): string {
  return `# enoki-release-e2e:arm-post-replacement-fault
set -eu
claim=/var/lib/enoki-release-e2e/claim
dropin_dir=/etc/systemd/system/enoki-probe.service.d
dropin="$dropin_dir/90-enoki-release-e2e-restart-failure.conf"
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ "$(cat "$claim/upgrade-target")" = ${shellSingleQuote(targetProbeVersion)} ]
[ -f "$claim/upgrade-before-resources" ]
[ ! -e "$claim/post-replacement-fault" ]
[ ! -e "$dropin" ]
[ "$(systemctl is-active enoki-probe.service)" = active ]
install -d -m 0755 "$dropin_dir"
printf '[Service]\nExecStartPre=/bin/false\n' > "$dropin"
chmod 0644 "$dropin"
( umask 077; printf '%s\n' ${shellSingleQuote(targetProbeVersion)} > "$claim/post-replacement-fault" )
systemctl daemon-reload
[ "$(systemctl is-active enoki-probe.service)" = active ]
printf 'armed\n'
`;
}

function postReplacementUpgradeFailureScript(
  runId: string,
  token: string,
  operation: ProbeOperation,
  expectedProbeVersion: string,
): string {
  return `# enoki-release-e2e:post-replacement-failure
set -eu
fail() {
  printf '%s\n' "$1" >&2
  exit 79
}
claim=/var/lib/enoki-release-e2e/claim
dropin=/etc/systemd/system/enoki-probe.service.d/90-enoki-release-e2e-restart-failure.conf
status=/var/lib/enoki-probe/probe-operation-status.toml
[ -d "$claim" ] || fail 'release E2E ownership claim is missing'
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ] || fail 'release E2E run claim changed'
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ] || fail 'release E2E ownership token changed'
[ "$(cat "$claim/upgrade-operation-id")" = ${shellSingleQuote(String(operation.id))} ] || fail 'post-replacement operation binding changed'
[ "$(cat "$claim/post-replacement-fault")" = ${shellSingleQuote(expectedProbeVersion)} ] || fail 'post-replacement target binding changed'
[ -f "$dropin" ] || fail 'post-replacement restart fault is missing'
if [ ! -f "$status" ]; then
  printf 'null\n'
  exit 0
fi
version_output=$(/usr/local/bin/enoki-probe --version) || fail 'candidate Probe version command failed'
version=\${version_output#"enoki-probe "}
version=\${version#v}
[ "$version" = ${shellSingleQuote(expectedProbeVersion)} ] || fail "candidate Probe version mismatch: $version_output"
grep -Fxq ${shellSingleQuote(`operation_id = "${operation.id}"`)} "$status" || fail 'post-replacement status operation changed'
grep -Fxq ${shellSingleQuote(`target_probe_version = "${expectedProbeVersion}"`)} "$status" || fail 'post-replacement status target changed'
if ! grep -Fxq 'status = "failed"' "$status"; then
  if ! grep -Fxq 'status = "running"' "$status"; then
    fail 'unexpected post-replacement status'
  fi
  printf 'null\n'
  exit 0
fi
grep -Fxq 'error_code = "post_replacement_restart_failure"' "$status" || fail 'unexpected post-replacement failure code'
if [ "$(systemctl is-active enoki-probe.service 2>/dev/null || true)" = active ]; then
  fail 'candidate Probe service is still active after injected restart failure'
fi
printf '{"localFailureCode":"post_replacement_restart_failure","operationId":%s,"probeVersion":"%s"}\n' \
  ${shellSingleQuote(String(operation.id))} "$version"
`;
}

function removePostReplacementRestartFaultScript(
  runId: string,
  token: string,
): string {
  return `# enoki-release-e2e:remove-post-replacement-fault
set -eu
claim=/var/lib/enoki-release-e2e/claim
dropin_dir=/etc/systemd/system/enoki-probe.service.d
dropin="$dropin_dir/90-enoki-release-e2e-restart-failure.conf"
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ -f "$claim/post-replacement-fault" ]
[ -f "$dropin" ]
rm -- "$dropin" "$claim/post-replacement-fault"
rmdir "$dropin_dir" 2>/dev/null || true
systemctl daemon-reload
systemctl reset-failed enoki-probe.service 2>/dev/null || true
printf 'removed\n'
`;
}

function completeUpgradeOwnershipScript(
  runId: string,
  token: string,
  operation: ProbeOperation,
): string {
  return `# enoki-release-e2e:complete-upgrade-ownership
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ "$(cat "$claim/upgrade-target")" = ${shellSingleQuote(operation.targetProbeVersion)} ]
[ "$(cat "$claim/upgrade-operation-id")" = ${shellSingleQuote(String(operation.id))} ]
[ -f "$claim/upgrade-before-resources" ]
cmp --silent "$claim/resources" "$claim/upgrade-before-resources"
${knownProbeInstallMetadataScript()}
${resourceFingerprintFunction()}
temporary=$(mktemp "$claim/resources.upgrade.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
mv -- "$temporary" "$claim/resources"
trap - EXIT HUP INT TERM
rm -- "$claim/upgrade-before-resources" "$claim/upgrade-target" "$claim/upgrade-operation-id"
printf 'owned\n'
`;
}

function completeRepairOwnershipScript(
  runId: string,
  token: string,
  operation: ProbeOperation,
): string {
  return `# enoki-release-e2e:complete-repair-ownership
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ "$(cat "$claim/upgrade-target")" = ${shellSingleQuote(operation.targetProbeVersion)} ]
[ "$(cat "$claim/upgrade-operation-id")" = ${shellSingleQuote(String(operation.id))} ]
[ -f "$claim/upgrade-before-resources" ]
[ ! -e "$claim/post-replacement-fault" ]
cmp --silent "$claim/resources" "$claim/upgrade-before-resources"
${knownProbeInstallMetadataScript()}
[ "$metadata_schema" = bootstrap-v2 ]
${resourceFingerprintFunction()}
temporary=$(mktemp "$claim/resources.repair.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
mv -- "$temporary" "$claim/resources"
trap - EXIT HUP INT TERM
rm -- "$claim/upgrade-before-resources" "$claim/upgrade-target" "$claim/upgrade-operation-id"
printf 'owned\n'
`;
}

function resourceFingerprintFunction(): string {
  return renderReleaseE2EResourceFingerprint(releaseE2EInfrastructureResources);
}

export function renderReleaseE2EResourceFingerprint(
  resources: readonly InfrastructureResource[],
): string {
  const files = resources
    .filter(
      (resource): resource is ManagedFileResource => resource.kind === "file",
    )
    .map((resource) => shellSingleQuote(resource.path))
    .join(" ");
  const directories = resources
    .filter(
      (resource): resource is ManagedDirectoryResource =>
        resource.kind === "directory",
    )
    .map((resource) => shellSingleQuote(resource.path))
    .join(" ");
  const users = resources
    .filter(
      (resource): resource is ProbeUserResource => resource.kind === "user",
    )
    .map((resource) => shellSingleQuote(resource.name))
    .join(" ");
  const groups = resources
    .filter(
      (resource): resource is ProbeGroupResource => resource.kind === "group",
    )
    .map((resource) => shellSingleQuote(resource.name))
    .join(" ");
  return String.raw`fingerprint_path() {
  path=$1
  metadata=$(stat -c '%u\t%g\t%a\t%d\t%i\t%s' -- "$path") || return 1
  path_hash=$(printf '%s' "$path" | sha256sum | awk '{print $1}') || return 1
  if [ -L "$path" ]; then
    type=symlink
    content_hash=$(readlink -- "$path" | sha256sum | awk '{print $1}') || return 1
  elif [ -f "$path" ]; then
    type=file
    content_hash=$(sha256sum -- "$path" | awk '{print $1}') || return 1
  elif [ -d "$path" ]; then
    type=directory
    content_hash=-
  else
    type=$(stat -c '%F' -- "$path") || return 1
    content_hash=-
  fi
  printf 'path\t%s\t%s\t%s\t%s\n' "$path_hash" "$type" "$metadata" "$content_hash"
}
fingerprint_directory() {
  directory=$1
  members=$(find -P "$directory" -xdev -print | LC_ALL=C sort) || return 1
  printf '%s\n' "$members" | while IFS= read -r member; do
    [ -n "$member" ] || continue
    fingerprint_path "$member" || exit 1
  done
}
fingerprint() {
  for candidate in ${files}; do
    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
      [ -f "$candidate" ] && [ ! -L "$candidate" ] || return 1
      fingerprint_path "$candidate" || return 1
    fi
  done
  for candidate in ${directories}; do
    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
      [ -d "$candidate" ] && [ ! -L "$candidate" ] || return 1
      fingerprint_directory "$candidate" || return 1
    fi
  done
  for account in ${users}; do
    if entry=$(getent passwd "$account"); then
      uid=$(printf '%s' "$entry" | cut -d: -f3) || return 1
      gid=$(printf '%s' "$entry" | cut -d: -f4) || return 1
      entry_hash=$(printf '%s' "$entry" | sha256sum | awk '{print $1}') || return 1
      printf 'user\t%s\t%s\t%s\t%s\n' "$account" "$uid" "$gid" "$entry_hash"
    fi
  done
  for account in ${groups}; do
    if entry=$(getent group "$account"); then
      gid=$(printf '%s' "$entry" | cut -d: -f3) || return 1
      entry_hash=$(printf '%s' "$entry" | sha256sum | awk '{print $1}') || return 1
      printf 'group\t%s\t%s\t%s\n' "$account" "$gid" "$entry_hash"
    fi
  done
}`;
}

function knownProbeInstallMetadataScript(): string {
  return String.raw`metadata=/etc/enoki/probe-install.toml
[ -f "$metadata" ]
[ ! -L "$metadata" ]
[ "$(stat -c %u "$metadata")" = 0 ]
[ "$(stat -c %a "$metadata")" = 600 ]
require_metadata_line() { [ "$(grep -Fxc "$1" "$metadata")" -eq 1 ]; }
require_metadata_line 'schema_version = 2'
require_metadata_line 'install_path = "/usr/local/bin/enoki-probe"'
require_metadata_line 'state_dir = "/var/lib/enoki-probe"'
require_metadata_line 'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"'
require_metadata_line 'service_name = "enoki-probe"'
require_metadata_line 'service_user = "enoki-probe"'
require_metadata_line 'identity_path = "/var/lib/enoki-probe/identity/probe-bootstrap.toml"'
require_metadata_line 'service_group = "enoki-probe"'
require_metadata_line 'service_unit_path = "/etc/systemd/system/enoki-probe.service"'
[ "$(grep -c '^schema_version = ' "$metadata")" -eq 1 ]
! grep -Eq 'sudoers|upgrader' "$metadata"
metadata_schema=bootstrap-v2`;
}

function removeClaimScript(runId: string, token: string): string {
  return `# enoki-release-e2e:remove-claim\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\n[ -d "$claim" ]\n[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]\n[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]\nrm -f -- "$claim/resources" "$claim/upgrade-before-resources" "$claim/upgrade-target" "$claim/upgrade-operation-id" "$claim/post-replacement-fault"\nrm -- "$claim/run-id" "$claim/token"\nrmdir "$claim"\nrmdir /var/lib/enoki-release-e2e 2>/dev/null || true\n`;
}

function inspectClaimScript(runId: string, token: string): string {
  return `# enoki-release-e2e:inspect-claim\nset -eu\nclaim=/var/lib/enoki-release-e2e/claim\nif [ ! -e "$claim" ]; then printf 'absent\\n'; elif [ -d "$claim" ] && [ "$(cat "$claim/run-id" 2>/dev/null || true)" = ${shellSingleQuote(runId)} ] && [ "$(cat "$claim/token" 2>/dev/null || true)" = ${shellSingleQuote(token)} ]; then printf 'owned\\n'; else printf 'foreign\\n'; fi\n`;
}

function releaseEmergencyCleanupScript(runId: string, token: string): string {
  const pathsFor = (kind: "file" | "directory"): string =>
    releaseE2EInfrastructureResources
      .filter(
        (resource): resource is ManagedPathResource => resource.kind === kind,
      )
      .map((resource) => shellSingleQuote(resource.path))
      .join(" ");
  const namesFor = (kind: "user" | "group" | "service"): string =>
    releaseE2EInfrastructureResources
      .filter(
        (resource): resource is ManagedNameResource => resource.kind === kind,
      )
      .map((resource) => shellSingleQuote(resource.name))
      .join(" ");
  const files = pathsFor("file");
  const directories = pathsFor("directory");
  const users = namesFor("user");
  const groups = namesFor("group");
  const services = namesFor("service");
  return `# enoki-release-e2e:emergency-cleanup
set -eu
claim=/var/lib/enoki-release-e2e/claim
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(token)} ]
[ -f "$claim/resources" ]
${resourceFingerprintFunction()}
temporary=$(mktemp "$claim/resources.cleanup.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
fingerprint > "$temporary"
cmp --silent "$claim/resources" "$temporary" || { printf 'run-owned resource fingerprint changed\\n' >&2; exit 75; }
systemctl disable --now ${services} >/dev/null 2>&1 || true
rm -f -- ${files}
rm -rf -- ${directories}
for account in ${users}; do userdel -- "$account" >/dev/null 2>&1 || true; done
for account in ${groups}; do groupdel -- "$account" >/dev/null 2>&1 || true; done
printf 'cleaned\\n'
`;
}

export function inventoryResidue(
  inventory: HostInventory | null | undefined,
): string[] {
  const residue: string[] = [];
  const accounts = inventory?.accounts;
  if (accounts?.user) {
    residue.push(...releaseE2EUsers.map((account) => `user:${account}`));
  }
  if (accounts?.group) {
    residue.push(...releaseE2EGroups.map((account) => `group:${account}`));
  }
  const files = inventory?.files;
  if (Array.isArray(files)) residue.push(...files);
  const units = inventory?.units;
  if (Array.isArray(units)) residue.push(...units);
  return residue.sort();
}

export function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`${label} was not valid JSON`, { cause: error });
  }
}

export function assertRunId(runId: unknown): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(regexInput(runId))) {
    throw new Error("run ID must be a safe non-empty identifier");
  }
}

function assertOwnedRun(
  runId: string,
  disposableRunId: string | null,
  runOwnsMutation: boolean,
): void {
  assertRunId(runId);
  if (disposableRunId !== runId || !runOwnsMutation) {
    throw new Error(`Release Test Host state is not owned by run ${runId}`);
  }
}

export function assertInstallCommand(command: unknown): InstallContract {
  if (
    typeof command !== "string" ||
    command.length > 16_384 ||
    command.includes("\n")
  ) {
    throw new Error("Hub returned an invalid Probe install command");
  }
  const recipe = command.match(
    /^printf '%s\\n' '(enk_enroll_[A-Za-z0-9_-]+)' \| python3 -- \.\/enoki-probe-bootstrap\.py --hub-origin '(https?:\/\/[^'\s]+)'$/,
  );
  if (recipe) {
    const hubUrl = stringValue(recipe[2]);
    assertInstallHubOrigin(hubUrl);
    return { hubUrl, kind: "bootstrap-recipe", token: stringValue(recipe[1]) };
  }
  const legacy = command.match(
    /^curl -fsSL '(https?:\/\/[^'\s]+\/api\/probe\/install\.sh)' \| sudo env ENOKI_HUB_URL='(https?:\/\/[^'\s]+)' ENOKI_ENROLLMENT_TOKEN='(enk_enroll_[A-Za-z0-9_-]+)' bash$/,
  );
  if (legacy) {
    const hubUrl = stringValue(legacy[2]);
    assertInstallHubOrigin(hubUrl);
    if (stringValue(legacy[1]) !== `${hubUrl}/api/probe/install.sh`) {
      throw new Error("Hub returned an invalid Probe install command");
    }
    return {
      hubUrl,
      kind: "legacy-v0.1.74",
      token: stringValue(legacy[3]),
    };
  }
  throw new Error("Hub returned an invalid Probe install command");
}

function assertInstallHubOrigin(value: string): void {
  const url = new URL(value);
  if (
    url.origin !== value ||
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username ||
    url.password
  ) {
    throw new Error("Hub returned an invalid Probe install command");
  }
}

export function assertEnrollmentInstallContract(
  enrollment: Enrollment,
): InstallContract {
  const contract = assertInstallCommand(enrollment?.installCommand);
  if (
    enrollment?.enrollmentToken !== contract.token ||
    enrollment?.hubUrl !== contract.hubUrl
  ) {
    throw new Error(
      "Hub Enrollment install command is not bound to its token and origin",
    );
  }
  if (contract.kind === "bootstrap-recipe") {
    assertBootstrapRecipeRecord(enrollment.bootstrapRecipe);
  } else if (enrollment.bootstrapRecipe !== undefined) {
    throw new Error(
      "Legacy Enrollment unexpectedly supplied a Probe Bootstrap recipe",
    );
  }
  return contract;
}

function assertBootstrapRecipeRecord(record: unknown): void {
  const value = objectView(record);
  const recipe = objectView(value.recipe);
  assertExactObjectKeys(record, [
    "bundleVersion",
    "distribution",
    "kind",
    "recipe",
    "rootFingerprint",
    "schemaVersion",
    "targets",
  ]);
  assertExactObjectKeys(value.recipe, ["file", "sha256", "size", "version"]);
  if (
    value.kind !== "enoki-probe-bootstrap-recipe-record" ||
    value.schemaVersion !== 1 ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      regexInput(value.bundleVersion),
    ) ||
    value.distribution !== "enoki" ||
    !/^[0-9a-f]{64}$/.test(regexInput(value.rootFingerprint)) ||
    JSON.stringify(value.targets) !== JSON.stringify(probeTargets) ||
    recipe.file !== "enoki-probe-bootstrap.py" ||
    recipe.version !== "v1" ||
    !/^[0-9a-f]{64}$/.test(regexInput(recipe.sha256)) ||
    !isPositiveSafeInteger(recipe.size)
  ) {
    throw new Error("Hub returned an invalid Probe Bootstrap recipe record");
  }
}

export function parseKeyValues(value: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of value.split("\n")) {
    if (!line) continue;
    const separator = line.indexOf("=");
    if (separator < 1) throw new Error("Host property output is malformed");
    result[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return result;
}

function commandEvidence(result: CommandResult): CommandEvidence {
  return {
    code: result.code,
    stderr: result.stderr,
    stdout: result.stdout,
  };
}

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function assertProbeOperation(
  operation: ProbeOperation,
  expected: ProbeOperationExpectation = {},
): void {
  if (
    !operation ||
    !Number.isInteger(operation.id) ||
    !Object.hasOwn(probeOperationStateRank, operation.state) ||
    operation.failure === undefined ||
    !isSafeInteger(operation.createdAtMs) ||
    operation.createdAtMs < 0 ||
    !isNullableTimestamp(operation.acceptedAtMs) ||
    !isNullableTimestamp(operation.runningAtMs) ||
    !isNullableTimestamp(operation.completedAtMs) ||
    !isSafeInteger(operation.updatedAtMs) ||
    operation.updatedAtMs < operation.createdAtMs ||
    !hasValidOperationStateTimestamps(operation)
  ) {
    throw new Error("Hub returned an invalid Probe Operation");
  }
  const transitionTimestamps = [
    operation.acceptedAtMs,
    operation.runningAtMs,
    operation.completedAtMs,
  ].filter((value) => value !== null);
  if (
    transitionTimestamps.some((value, index) => {
      const previous = transitionTimestamps[index - 1];
      return (
        value < operation.createdAtMs ||
        value > operation.updatedAtMs ||
        (index > 0 && previous !== undefined && value < previous)
      );
    })
  ) {
    throw assertionError(
      "probe_operation_timestamp_invalid",
      "Probe Operation transition timestamps are not monotonic",
    );
  }
  if (expected.id !== undefined && operation.id !== expected.id) {
    throw assertionError(
      "probe_operation_identity_mismatch",
      `Hub returned Probe Operation ${operation.id}; expected ${expected.id}`,
    );
  }
  if (expected.hostId !== undefined && operation.hostId !== expected.hostId) {
    throw assertionError(
      "probe_operation_identity_mismatch",
      `Hub returned Probe Operation for Host ${operation.hostId}; expected ${expected.hostId}`,
    );
  }
  if (expected.kind !== undefined && operation.kind !== expected.kind) {
    throw assertionError(
      "probe_operation_identity_mismatch",
      `Hub returned Probe Operation kind ${operation.kind}; expected ${expected.kind}`,
    );
  }
  if (
    expected.targetProbeVersion !== undefined &&
    operation.targetProbeVersion !== expected.targetProbeVersion
  ) {
    throw assertionError(
      "probe_operation_identity_mismatch",
      `Hub returned Probe Operation target ${operation.targetProbeVersion ?? "unknown"}; expected ${expected.targetProbeVersion}`,
    );
  }
  if (operation.state === "failed") {
    if (
      !operation.failure ||
      typeof operation.failure.code !== "string" ||
      typeof operation.failure.message !== "string"
    ) {
      throw assertionError(
        "probe_operation_failure_invalid",
        "Failed Probe Operation has no stable typed failure",
      );
    }
  } else if (operation.failure !== null) {
    throw assertionError(
      "probe_operation_failure_invalid",
      `Probe Operation state ${operation.state} unexpectedly carries a failure`,
    );
  }
}

function isNullableTimestamp(value: unknown): value is number | null {
  return value === null || (isSafeInteger(value) && value >= 0);
}

function hasValidOperationStateTimestamps(operation: ProbeOperation): boolean {
  const accepted = operation.acceptedAtMs !== null;
  const running = operation.runningAtMs !== null;
  const completed = operation.completedAtMs !== null;
  if (running && !accepted) return false;
  if (completed && !accepted) return false;
  switch (operation.state) {
    case "pending":
      return !accepted && !running && !completed;
    case "accepted":
      return accepted && !running && !completed;
    case "running":
      return accepted && running && !completed;
    case "succeeded":
      return accepted && running && completed;
    case "failed":
      return accepted && completed;
    case "canceled":
      return !running && !completed;
    case "superseded":
      return !running && !completed;
    default:
      return false;
  }
}

function assertProbeVersion(value: unknown, label: string): void {
  if (
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(regexInput(value))
  ) {
    throw new Error(`${label} is invalid`);
  }
}

export function assertionError(
  code: string,
  message: string,
): Error & { code: string } {
  return Object.assign(new Error(message), { code });
}

export function serializedError(error: unknown): SerializedError {
  const serialized: SerializedError = {
    code: objectView(error).code ?? "error",
    message: error instanceof Error ? error.message : String(error),
  };
  const installerEvidence = objectView(error).installerEvidence;
  if (installerEvidence) {
    serialized.installerEvidence = installerEvidence;
  }
  if (error instanceof AggregateError) {
    serialized.errors = error.errors.map((nested) => serializedError(nested));
  }
  return serialized;
}

export function assertExactObjectKeys(
  value: unknown,
  expectedKeys: readonly string[],
): void {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    JSON.stringify(Object.keys(value).sort()) !==
      JSON.stringify([...expectedKeys].sort())
  ) {
    throw new Error(
      `Release E2E manifest fields must be exactly: ${expectedKeys.join(", ")}`,
    );
  }
}

export function assertHostInventoryEvidence(
  value: unknown,
): asserts value is HostInventory {
  const inventory = objectView(value);
  const accounts = objectView(inventory.accounts);
  const files = inventory.files;
  const units = inventory.units;
  if (
    !isUnknownRecord(value) ||
    inventory.error ||
    typeof accounts.group !== "boolean" ||
    typeof accounts.user !== "boolean" ||
    !isUnknownArray(files) ||
    files.some((entry) => typeof entry !== "string" || !entry) ||
    !isUnknownArray(units) ||
    units.some((entry) => typeof entry !== "string" || !entry) ||
    Object.keys(inventory).sort().join(",") !== "accounts,files,units" ||
    Object.keys(accounts).sort().join(",") !== "group,user"
  ) {
    throw new Error("filesystem inventory collection is invalid");
  }
}

export function assertInstalledStateEvidence(
  value: unknown,
): asserts value is InstalledState {
  const state = objectView(value);
  const identity = objectView(state.identity);
  const service = objectView(state.service);
  const restartCount = state.restartCount;
  if (
    !isUnknownRecord(value) ||
    Object.keys(state).sort().join(",") !==
      "binarySha256,identity,installMetadataSha256,restartCount,service" ||
    !/^[0-9a-f]{64}$/.test(stringValue(state.binarySha256)) ||
    !/^[0-9a-f]{64}$/.test(stringValue(state.installMetadataSha256)) ||
    !isSafeInteger(restartCount) ||
    restartCount < 0 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(
      stringValue(identity.probeId),
    ) ||
    !/^[0-9a-f]{64}$/.test(stringValue(identity.identitySha256)) ||
    service.LoadState !== "loaded" ||
    service.ActiveState !== "active" ||
    service.SubState !== "running" ||
    Object.keys(service).sort().join(",") !==
      "ActiveState,LoadState,SubState" ||
    Object.keys(identity).sort().join(",") !== "identitySha256,probeId"
  ) {
    throw new Error("installed Probe state evidence is invalid");
  }
}

export function assertPermanentReportRejectionEvidence(
  value: unknown,
): asserts value is PermanentReportRejection {
  const evidence = objectView(value);
  const identity = objectView(evidence.identity);
  const service = objectView(evidence.service);
  const restartCountBeforeObservation = evidence.restartCountBeforeObservation;
  if (
    !isUnknownRecord(value) ||
    Object.keys(evidence).sort().join(",") !==
      "binarySha256,identity,installMetadataSha256,restartCountAfterObservation,restartCountBeforeObservation,service" ||
    !/^[0-9a-f]{64}$/.test(stringValue(evidence.binarySha256)) ||
    !/^[0-9a-f]{64}$/.test(stringValue(evidence.installMetadataSha256)) ||
    !isSafeInteger(restartCountBeforeObservation) ||
    restartCountBeforeObservation < 0 ||
    evidence.restartCountAfterObservation !== restartCountBeforeObservation ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(
      stringValue(identity.probeId),
    ) ||
    !/^[0-9a-f]{64}$/.test(stringValue(identity.identitySha256)) ||
    service.LoadState !== "loaded" ||
    service.ActiveState !== "failed" ||
    service.SubState !== "failed" ||
    service.ExecMainStatus !== 78 ||
    Object.keys(service).sort().join(",") !==
      "ActiveState,ExecMainStatus,LoadState,SubState" ||
    Object.keys(identity).sort().join(",") !== "identitySha256,probeId"
  ) {
    throw new Error("permanent Probe report rejection evidence is invalid");
  }
}

export function assertInstalledDiagnosticsEvidence(
  value: unknown,
): asserts value is InstalledDiagnostics {
  const evidence = objectView(value);
  const binary = objectView(evidence.binary);
  const identity = objectView(evidence.identity);
  const service = objectView(evidence.service);
  const nRestarts = service.NRestarts;
  const result = service.Result;
  if (
    !isUnknownRecord(value) ||
    Object.keys(evidence).sort().join(",") !==
      "binary,identity,installMetadataSha256,service" ||
    !/^[0-9a-f]{64}$/.test(stringValue(binary.sha256)) ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      stringValue(binary.version),
    ) ||
    !/^[0-9a-f]{64}$/.test(stringValue(evidence.installMetadataSha256)) ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(
      stringValue(identity.probeId),
    ) ||
    !/^[0-9a-f]{64}$/.test(stringValue(identity.identitySha256)) ||
    service.LoadState !== "loaded" ||
    service.ActiveState !== "failed" ||
    service.SubState !== "failed" ||
    service.ExecMainStatus !== 78 ||
    !isSafeInteger(nRestarts) ||
    nRestarts < 0 ||
    typeof result !== "string" ||
    !result ||
    Object.keys(binary).sort().join(",") !== "sha256,version" ||
    Object.keys(identity).sort().join(",") !== "identitySha256,probeId" ||
    Object.keys(service).sort().join(",") !==
      "ActiveState,ExecMainStatus,LoadState,NRestarts,Result,SubState"
  ) {
    throw new Error("terminal Probe diagnostic evidence is invalid");
  }
}

function assertCanonicalRuntimeUnavailableHostEvidence(
  value: unknown,
  expectedProbeId: string,
): void {
  const evidence = objectView(value);
  const identity = objectView(evidence.identity);
  const probe = objectView(evidence.probe);
  const runtime = objectView(evidence.runtime);
  if (
    identity.probeId !== expectedProbeId ||
    identity.registrationAttemptCredential !== false ||
    identity.registrationAttemptSource !== false ||
    identity.registrationDropIn !== false ||
    identity.transitionalRegistrationKeys !== false ||
    probe.ActiveState !== "active" ||
    probe.LoadState !== "loaded" ||
    probe.Result !== "success" ||
    probe.SubState !== "running" ||
    probe.Type !== "notify" ||
    runtime.serviceLoadState !== "masked" ||
    runtime.socketLoadState !== "masked"
  ) {
    throw new Error("canonical Runtime-unavailable Host evidence is invalid");
  }
}
