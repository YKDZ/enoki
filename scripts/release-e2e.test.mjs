import { execFile } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import {
  createCiHostExecutor,
  createCiReleaseInfrastructureAdapter,
  createDockerHubController,
  createFileEvidenceSink,
  createSshReleaseInfrastructureAdapter,
  parseReleaseE2ECommandLine,
  writeRunManifest,
} from "./release-e2e-adapters.mjs";
import {
  createHubLifecycleClient,
  createProbeHostHarness,
  hasAdvancingPortableMetrics,
  isCandidateHostReady,
  renderReleaseE2EResourceFingerprint,
  releaseE2EScenarioRegistry,
  runReleaseE2EScenario,
  validateSuccessfulRepairBoundaryEvidence,
  validateSuccessfulProbeUpgradeTimeline,
} from "./release-e2e-lib.mjs";

const execFileAsync = promisify(execFile);

describe("Release E2E business assertions", () => {
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
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("proves the declared Ubuntu architecture and host systemd boundary", async () => {
    const harness = createProbeHostHarness({
      execute: async (command) => {
        expect(command).toContain("# enoki-release-e2e:platform");
        expect(command).toContain("systemd-detect-virt --vm");
        return successfulCommand({
          architecture: "x86_64",
          operatingSystem: "ubuntu",
          operatingSystemVersion: "22.04",
          pid1: "systemd",
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
      harness.install(officialInstallCommand, "run-claim"),
    ).rejects.toThrow("Host already claimed");

    const claim = commands.find((command) =>
      command.includes("# enoki-release-e2e:claim"),
    );
    expect(claim).toContain("mkdir -m 0700");
    expect(claim).toContain("# enoki-release-e2e:claim-empty-recheck");
    expect(claim).not.toContain("runs/run-claim");
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
              "/etc/enoki/probe-install.toml",
              "/etc/systemd/system/enoki-probe.service",
              "/etc/sudoers.d/enoki-probe-operations",
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
          return successfulCommandText(
            "enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit=enoki-probe-uninstaller --property=Type=exec -- /usr/local/bin/enoki-probe internal-uninstaller --config /var/lib/enoki-probe/identity/probe-bootstrap.toml",
          );
        }
        if (command.includes("# enoki-release-e2e:binary-version")) {
          return successfulCommandText("enoki-probe v1.2.3\n");
        }
        if (command.includes("# enoki-release-e2e:probe-identity-path")) {
          return successfulCommandText(
            "/var/lib/enoki-probe/identity/probe-bootstrap.toml\n",
          );
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
    await harness.install(
      "curl -fsSL 'https://hub.example/api/probe/install.sh' | sudo env ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_secret' bash",
      "run-123",
    );
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
    expect(installed.sudoers).toContain("enoki-probe-uninstaller");
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
    expect(completedOwnership).toContain("identity_layout=v0_1_72");
    expect(completedOwnership).toContain("identity_layout=current");
    expect(
      commands.filter((command) => command.includes("enk_enroll_secret")),
    ).toHaveLength(1);
  });

  it("recognizes the trusted v0.1.72 Probe identity layout at its legacy path", async () => {
    let inventoryCount = 0;
    const commands = [];
    const root = await mkdtemp(path.join(os.tmpdir(), "enoki-e2e-legacy-"));
    const metadataPath = path.join(root, "etc/enoki/probe-install.toml");
    const identityPath = path.join(root, "etc/enoki/probe-bootstrap.toml");
    await mkdir(path.dirname(metadataPath), { recursive: true });
    await writeFile(
      metadataPath,
      [
        "schema_version = 1",
        'hub_url = "https://hub.example"',
        'install_path = "/usr/local/bin/enoki-probe"',
        'identity_path = "/etc/enoki/probe-bootstrap.toml"',
        'state_dir = "/var/lib/enoki-probe"',
        'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
        'service_name = "enoki-probe"',
        'service_user = "enoki-probe"',
        'service_group = "enoki-probe"',
        'service_unit_path = "/etc/systemd/system/enoki-probe.service"',
        'operation_sudoers_path = "/etc/sudoers.d/enoki-probe-operations"',
        'collector_helper_sudoers_path = "/etc/sudoers.d/enoki-probe-collector-helpers"',
        `probe_asset_public_key_sha256 = "${"a".repeat(64)}"`,
        "",
      ].join("\n"),
      "utf8",
    );
    // v0.1.72 writes this bootstrap material before its first enrollment has
    // completed.  It is a valid installation identity *path*, but not yet a
    // formal Probe identity.  The host boundary must not race that enrollment.
    await writeFile(
      identityPath,
      'enrollment_token = "enk_enroll_temporary"\n',
      "utf8",
    );
    await Promise.all([chmod(metadataPath, 0o600), chmod(identityPath, 0o600)]);

    try {
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
                    files: [
                      "/etc/enoki/probe-bootstrap.toml",
                      "/etc/enoki/probe-install.toml",
                      "/etc/systemd/system/enoki-probe.service",
                      "/etc/sudoers.d/enoki-probe-operations",
                      "/usr/local/bin/enoki-probe",
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
            return successfulCommandText(
              "enoki-probe-uninstaller internal-uninstaller",
            );
          }
          if (command.includes("# enoki-release-e2e:binary-version")) {
            return successfulCommandText("enoki-probe v0.1.72\n");
          }
          if (
            command.includes("# enoki-release-e2e:probe-identity-path") ||
            command.includes("# enoki-release-e2e:probe-identity")
          ) {
            try {
              const { stdout } = await execFileAsync("sh", [
                "-c",
                command
                  .replace(
                    "metadata=/etc/enoki/probe-install.toml",
                    `metadata=${metadataPath}`,
                  )
                  .replace(
                    '[ "$(stat -c %u "$metadata")" = 0 ]',
                    '[ "$(stat -c %u "$metadata")" = "$(id -u)" ]',
                  )
                  .replace(
                    "v0_1_72) identity=/etc/enoki/probe-bootstrap.toml",
                    `v0_1_72) identity=${identityPath}`,
                  ),
              ]);
              return successfulCommandText(
                stdout.replaceAll(
                  identityPath,
                  "/etc/enoki/probe-bootstrap.toml",
                ),
              );
            } catch (error) {
              return {
                code: Number.isInteger(error?.code) ? error.code : 1,
                stderr: error?.stderr ?? "",
                stdout: error?.stdout ?? "",
              };
            }
          }
          return successfulCommandText(
            command.includes("# enoki-release-e2e:record-resources")
              ? "recorded\n"
              : command.includes("# enoki-release-e2e:claim-run")
                ? "claimed\n"
                : productInstallerOutput(),
          );
        },
      });

      await harness.assertDisposable("run-legacy");
      await harness.install(officialInstallCommand, "run-legacy");
      await expect(
        harness.assertInstalled("run-legacy", "0.1.72"),
      ).resolves.toMatchObject({
        identityPath: "/etc/enoki/probe-bootstrap.toml",
        probeVersion: "0.1.72",
      });

      await expect(harness.readProbeIdentity("run-legacy")).rejects.toThrow(
        /Probe Identity inspection failed/,
      );

      await writeFile(
        identityPath,
        'probe_id = "probe_release_legacy"\nprobe_private_key_pem = "test-private-key"\n',
        "utf8",
      );
      await expect(harness.readProbeIdentity("run-legacy")).resolves.toEqual({
        identitySha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        probeId: "probe_release_legacy",
      });

      const identityInspection = commands.find((command) =>
        command.includes("# enoki-release-e2e:probe-identity-path"),
      );
      expect(identityInspection).toContain("identity_layout=v0_1_72");
      expect(identityInspection).toContain(
        "identity=/etc/enoki/probe-bootstrap.toml",
      );
      expect(identityInspection).toContain(
        '[ "$(stat -c %u "$metadata")" = 0 ]',
      );
      expect(identityInspection).toContain(
        "require_metadata_line 'schema_version = 1'",
      );
      expect(identityInspection).toContain(
        '[ "$(stat -c %a "$metadata")" = 600 ]',
      );
      expect(identityInspection).not.toContain("probe_private_key_pem");
      expect(identityInspection).not.toContain("probe_id = ");
      expect(
        commands.find((command) =>
          command.includes("# enoki-release-e2e:record-resources"),
        ),
      ).toContain("/etc/enoki/probe-bootstrap.toml");
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it.each([
    [
      "current",
      "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
      "probe_release_current",
    ],
    ["v0.1.72", "/etc/enoki/probe-bootstrap.toml", "probe_release_legacy"],
  ])(
    "executes the trusted %s metadata layout at its declared identity path",
    async (_layout, identityPath, probeId) => {
      const fixture = await createProbeMetadataShellFixture({
        identityPath,
        probeId,
      });
      try {
        await expect(fixture.readIdentity()).resolves.toMatchObject({
          probeId,
        });
      } finally {
        await fixture.dispose();
      }
    },
  );

  it.skipIf(process.getuid?.() !== 0)(
    "rejects metadata owned by a different existing user without chown",
    async () => {
      const fixture = await createProbeMetadataShellFixture({
        identityPath: "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
        probeId: "probe_release_wrong_owner",
      });
      try {
        const metadata = await readFile(fixture.metadataPath, "utf8");
        await chmod(fixture.root, 0o755);
        await chmod(path.dirname(fixture.metadataPath), 0o777);
        await rm(fixture.metadataPath);
        await execFileAsync("runuser", [
          "-u",
          "nobody",
          "--",
          "sh",
          "-c",
          'umask 077; printf "%s" "$1" > "$2"',
          "sh",
          metadata,
          fixture.metadataPath,
        ]);

        await expect(fixture.readIdentity()).rejects.toThrow(
          /Probe Identity inspection failed/,
        );
      } finally {
        await fixture.dispose();
      }
    },
  );

  it.each([
    [
      "a metadata symlink",
      async (fixture) => {
        const target = path.join(fixture.root, "metadata-target.toml");
        await writeFile(target, await readFile(fixture.metadataPath, "utf8"));
        await rm(fixture.metadataPath);
        await symlink(target, fixture.metadataPath);
      },
    ],
    [
      "group-writable metadata",
      async (fixture) => {
        await chmod(fixture.metadataPath, 0o620);
      },
    ],
    [
      "an unsupported schema",
      async (fixture) => {
        await writeFile(
          fixture.metadataPath,
          (await readFile(fixture.metadataPath, "utf8")).replace(
            "schema_version = 1",
            "schema_version = 2",
          ),
        );
      },
    ],
    [
      "a duplicate schema",
      async (fixture) => {
        await writeFile(
          fixture.metadataPath,
          `${await readFile(fixture.metadataPath, "utf8")}schema_version = 1\n`,
        );
      },
    ],
    [
      "a duplicate mismatched identity path",
      async (fixture) => {
        await writeFile(
          fixture.metadataPath,
          `${await readFile(fixture.metadataPath, "utf8")}identity_path = "/etc/enoki/probe-bootstrap.toml"\n`,
        );
      },
    ],
  ])(
    "rejects %s before trusting Probe installation metadata",
    async (_case, mutate) => {
      const fixture = await createProbeMetadataShellFixture({
        identityPath: "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
        probeId: "probe_release_rejected",
      });
      try {
        await mutate(fixture);
        await expect(fixture.readIdentity()).rejects.toThrow(
          /Probe Identity inspection failed/,
        );
      } finally {
        await fixture.dispose();
      }
    },
  );

  it.each([
    ["Installer Recovery", "recoverUpgradeWithInstaller"],
    ["Repair", "completeRepairOwnershipTransition"],
  ])(
    "executes the current-layout ownership completion shell after %s",
    async (_label, completion) => {
      const fixture = await createOwnershipCompletionShellFixture();
      const operation = failedUpgradeOperation();
      try {
        await fixture.harness.assertDisposable("run-completion");
        await fixture.harness.install(officialInstallCommand, "run-completion");
        await fixture.harness.beginUpgradeOwnershipTransition(
          "run-completion",
          operation.targetProbeVersion,
        );
        await fixture.harness.bindUpgradeOwnershipTransition(
          "run-completion",
          pendingUpgradeOperation(),
        );

        if (completion === "recoverUpgradeWithInstaller") {
          await expect(
            fixture.harness.recoverUpgradeWithInstaller(
              officialInstallCommand,
              "run-completion",
              operation,
            ),
          ).resolves.toMatchObject({ mode: "installer", status: "succeeded" });
        } else {
          await fixture.harness.repair("run-completion");
          await expect(
            fixture.harness.completeRepairOwnershipTransition(
              "run-completion",
              operation,
            ),
          ).resolves.toMatchObject({ owned: true });
        }

        expect(fixture.executedCompletionShell).toBe(true);
      } finally {
        await fixture.dispose();
      }
    },
  );

  it.each([
    ["Installer Recovery", "recoverUpgradeWithInstaller"],
    ["Repair", "completeRepairOwnershipTransition"],
  ])(
    "rejects the legacy v0.1.72 layout without rewriting claim resources after %s",
    async (_label, completion) => {
      const fixture = await createOwnershipCompletionShellFixture();
      const operation = failedUpgradeOperation();
      try {
        await fixture.harness.assertDisposable("run-legacy-completion");
        await fixture.harness.install(
          officialInstallCommand,
          "run-legacy-completion",
        );
        await fixture.harness.beginUpgradeOwnershipTransition(
          "run-legacy-completion",
          operation.targetProbeVersion,
        );
        await fixture.harness.bindUpgradeOwnershipTransition(
          "run-legacy-completion",
          pendingUpgradeOperation(),
        );
        const resourcesBefore = await fixture.readClaimResources();

        if (completion === "recoverUpgradeWithInstaller") {
          fixture.setInstallerIdentityPath("/etc/enoki/probe-bootstrap.toml");
          await expect(
            fixture.harness.recoverUpgradeWithInstaller(
              officialInstallCommand,
              "run-legacy-completion",
              operation,
            ),
          ).rejects.toThrow(/Could not commit run-owned Probe resources/);
        } else {
          await fixture.materializeProbe("/etc/enoki/probe-bootstrap.toml");
          await fixture.harness.repair("run-legacy-completion");
          await expect(
            fixture.harness.completeRepairOwnershipTransition(
              "run-legacy-completion",
              operation,
            ),
          ).rejects.toThrow(/Could not commit run-owned Probe resources/);
        }

        expect(fixture.executedCompletionShell).toBe(true);
        expect(fixture.lastCompletionShell).toContain(
          '[ "$identity_layout" = current ]',
        );
        await expect(fixture.readClaimResources()).resolves.toBe(
          resourcesBefore,
        );
      } finally {
        await fixture.dispose();
      }
    },
  );

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
              "/etc/enoki/probe-install.toml",
              "/etc/systemd/system/enoki-probe.service",
              "/etc/sudoers.d/enoki-probe-operations",
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
          return successfulCommandText(
            "enoki-probe-uninstaller internal-uninstaller",
          );
        }
        if (command.includes("# enoki-release-e2e:binary-version")) {
          return successfulCommandText("enoki-probe 9.9.9\n");
        }
        if (command.includes("# enoki-release-e2e:probe-identity-path")) {
          return successfulCommandText(
            "/var/lib/enoki-probe/identity/probe-bootstrap.toml\n",
          );
        }
        return successfulCommandText("");
      },
    });

    await harness.assertDisposable("run-version");
    await harness.install(officialInstallCommand, "run-version");
    await expect(
      harness.assertInstalled("run-version", "1.2.3"),
    ).rejects.toThrow(/Probe binary version 9\.9\.9.*Candidate 1\.2\.3/);
  });

  it("uses a run-owned systemd fault and the real root-only Probe Repair command", async () => {
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
    await harness.install(officialInstallCommand, "run-repair-host");
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
    await harness.install(officialInstallCommand, "run-123");
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
    await harness.install(officialInstallCommand, "run-local-uninstall");
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
      "curl -fsSL 'https://hub.example/api/probe/install.sh' | sudo env ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_reenroll' bash",
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
        if (command.includes("ENOKI_ENROLLMENT_TOKEN='enk_enroll_repeat'")) {
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
    const repeatedCommand =
      "curl -fsSL 'https://hub.example/api/probe/install.sh' | sudo env ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_repeat' bash";

    await harness.assertDisposable("run-repeat-add");
    await harness.install(officialInstallCommand, "run-repeat-add");
    const before = await harness.captureInstallationState("run-repeat-add");
    await expect(
      harness.rejectRepeatedInstall(repeatedCommand, "run-repeat-add"),
    ).resolves.toMatchObject({ code: "existing_probe_installation" });
    const after = await harness.captureInstallationState("run-repeat-add");

    expect(after).toEqual(before);
    expect(commands).toContainEqual({
      command: `${repeatedCommand}\n`,
      options: { root: true, sensitive: true },
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
    await harness.install(officialInstallCommand, "run-terminal-report");
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
        if (command.includes("ENOKI_ENROLLMENT_TOKEN")) installed = true;
        return successfulCommandText(productInstallerOutput());
      },
    });

    await harness.assertDisposable("run-terminal-diagnostics");
    await harness.install(officialInstallCommand, "run-terminal-diagnostics");
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

  it("uses only run-owned emergency infrastructure cleanup for a partial installation", async () => {
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
        if (command.includes("# enoki-release-e2e:verify-claim")) {
          return successfulCommandText("owned\n");
        }
        if (command.includes("# enoki-release-e2e:inspect-claim")) {
          return successfulCommandText("absent\n");
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
      harness.install(officialInstallCommand, "run-partial"),
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
    const emergency = commands.find((command) =>
      command.includes("# enoki-release-e2e:emergency-cleanup"),
    );
    expect(emergency).toContain('cat "$claim/run-id"');
    expect(emergency).toContain('cat "$claim/token"');
    expect(emergency).toContain('fingerprint > "$temporary"');
    expect(emergency).toContain('cmp --silent "$claim/resources" "$temporary"');
    expect(emergency).toContain("sha256sum");
    expect(emergency).toContain("find -P");
    expect(emergency).toContain("stat -c");
    expect(emergency).toContain("/etc/enoki/probe-bootstrap.toml");
    expect(emergency).not.toContain("expected_resource()");
    expect(emergency).not.toContain('done < "$claim/resources"');
    expect(
      commands.some((command) => command.includes("ENOKI_UNINSTALL")),
    ).toBe(false);
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
      harness.install(officialInstallCommand, "run-recording-failure"),
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
        return successfulCommandText("recorded\n");
      },
    });

    await harness.assertDisposable("run-clean-release");
    await harness.install(officialInstallCommand, "run-clean-release");
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
    await harness.install(officialInstallCommand, "run-aggregate-cleanup");
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
    await harness.install(officialInstallCommand, "run-foreign-change");

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
              enrollmentId: "enr_existing_host_0001",
              enrollmentToken: "enk_enroll_release_e2e_test_token",
              installCommand: officialInstallCommand,
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
        return jsonResponse(
          { enrollmentToken: "secret", installCommand: officialInstallCommand },
          201,
        );
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
          enrollmentId: "enr_client_evidence_0001",
          enrollmentToken: "enk_enroll_client_evidence_token",
          installCommand: officialInstallCommand,
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
          enrollmentId: "enr_client_refresh_error_0001",
          enrollmentToken: "enk_enroll_client_refresh_error_token",
          installCommand: officialInstallCommand,
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
        expect(command).toBe(officialInstallCommand);
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
    let enrollmentCount = 0;
    let installCount = 0;
    let formalIdentityGeneration = 0;
    let identityGeneration = 0;
    let lifecycle = "empty";
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
        if (lifecycle === "online" || lifecycle === "reenrolled") {
          // A Host Profile is the public readiness boundary for the identity
          // minted by this particular install.  In particular, the previous
          // identity must not make a re-enrollment identity readable.
          formalIdentityGeneration = identityGeneration;
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
        return lifecycle === "reenrolled"
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
        identityGeneration += 1;
        formalIdentityGeneration = 0;
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
        calls.push(`host.readProbeIdentity:${identityGeneration}`);
        if (formalIdentityGeneration !== identityGeneration) {
          throw new Error(
            "Probe identity is unavailable until the matching core readiness observation succeeds",
          );
        }
        return identityGeneration === 1
          ? installedState.identity
          : { identitySha256: "d".repeat(64), probeId: "probe_release_02" };
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
            return { host, hub };
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
        "host.localUninstall",
        "hub.createEnrollment:existing_host",
        "hub.deleteHostHubOnly:7",
        "host.awaitPermanentReportRejection",
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
    expect(offlineObservations).toBe(92);
    expect(written.at(-1)).toMatchObject({
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

  it("proves the pinned baseline Probe through one Owner-authorized upgrade and uninstall", async () => {
    const calls = [];
    let installed = false;
    let activeHub = "baseline";
    let upgraded = false;
    let readableIdentityGeneration = null;
    let identityGeneration = "baseline-install";
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
        if (activeHub === "baseline" && !upgraded) {
          readableIdentityGeneration = "baseline-install";
        }
        if (activeHub === "candidate" && upgraded) {
          readableIdentityGeneration = "candidate-upgrade";
        }
        return readyHost({
          hostProfile: {
            ...readyHost().hostProfile,
            probeVersion: upgraded ? "1.2.3" : "1.2.2",
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
          identityGeneration = "candidate-upgrade";
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
        expect(command).toBe(officialInstallCommand);
        installed = true;
      },
      async readProbeIdentity() {
        calls.push(`host.readProbeIdentity:${identityGeneration}`);
        if (readableIdentityGeneration !== identityGeneration) {
          throw new Error(
            "Probe identity is unavailable until the matching core readiness observation succeeds",
          );
        }
        return {
          identitySha256: "f".repeat(64),
          probeId: "probe_release_01",
        };
      },
      async recoverUpgradeWithInstaller() {
        throw new Error("automatic Upgrade must not use Installer Recovery");
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
      scenario: "baseline-upgrade-uninstall",
      timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
    });

    expect(result).toEqual({ status: "succeeded" });
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
  });

  it("recovers a terminal insufficient-privilege Upgrade with the Candidate installer", async () => {
    let activeHub = "baseline";
    let configurationVersion = "default-v1";
    let installed = false;
    let recovered = false;
    let readableIdentityGeneration = null;
    let identityGeneration = "baseline-install";
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
        return { installCommand: officialInstallCommand };
      },
      async getAuditLog() {
        return baselineUpgradeAuditLog();
      },
      async getHost() {
        if (activeHub === "baseline" && !recovered) {
          readableIdentityGeneration = "baseline-install";
        } else if (activeHub === "candidate" && recovered) {
          readableIdentityGeneration = "candidate-recovery";
        }
        return readyHost({
          hostProfile: {
            ...readyHost().hostProfile,
            probeVersion: recovered ? "1.2.3" : "1.2.2",
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
        if (readableIdentityGeneration !== identityGeneration) {
          throw new Error(
            "Probe identity is unavailable until the matching core readiness observation succeeds",
          );
        }
        return {
          identitySha256: "f".repeat(64),
          probeId: "probe_release_01",
        };
      },
      async recoverUpgradeWithInstaller(command, _runId, operation) {
        expect(activeHub).toBe("candidate");
        expect(command).toBe(officialInstallCommand);
        expect(operation).toEqual(failedUpgrade);
        recovered = true;
        identityGeneration = "candidate-recovery";
        return {
          failedOperationId: operation.id,
          mode: "installer",
          status: "succeeded",
          targetProbeVersion: operation.targetProbeVersion,
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
        scenario: "baseline-upgrade-uninstall",
        timing: { intervalMs: 1, sleep: async () => {}, timeoutMs: 10 },
      }),
    ).resolves.toEqual({ status: "succeeded" });
    expect(written.at(-1)).toMatchObject({
      candidateHost: { hostProfile: { probeVersion: "1.2.3" } },
      manualRecovery: {
        failedOperationId: 41,
        mode: "installer",
        status: "succeeded",
        targetProbeVersion: "1.2.3",
      },
      result: { status: "succeeded" },
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
    let readableIdentityGeneration = null;
    let identityGeneration = "baseline-install";
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
        if (activeHub === "baseline" && !upgraded) {
          readableIdentityGeneration = "baseline-install";
        } else if (activeHub === "candidate" && upgraded) {
          readableIdentityGeneration = "candidate-upgrade";
        } else if (activeHub === "baseline" && upgraded) {
          readableIdentityGeneration = "baseline-restored";
        }
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
        identityGeneration = "baseline-restored";
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
          identityGeneration = "candidate-upgrade";
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
        calls.push(`host.readProbeIdentity:${identityGeneration}`);
        if (readableIdentityGeneration !== identityGeneration) {
          throw new Error(
            "Probe identity is unavailable until the matching core readiness observation succeeds",
          );
        }
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
    let readableIdentityGeneration = null;
    let identityGeneration = "baseline-install";
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
        if (activeHub === "baseline" && !repaired) {
          readableIdentityGeneration = "baseline-install";
        } else if (activeHub === "candidate" && repaired) {
          readableIdentityGeneration = "candidate-repair";
        }
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
        if (readableIdentityGeneration !== identityGeneration) {
          throw new Error(
            "Probe identity is unavailable until the matching core readiness observation succeeds",
          );
        }
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
        identityGeneration = "candidate-repair";
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
          afterRepair: expect.stringContaining("internal-uninstaller"),
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
    readableIdentityGeneration = null;
    identityGeneration = "baseline-install";
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
    readableIdentityGeneration = null;
    identityGeneration = "baseline-install";
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
  it("atomically records a matrix-validation failure before candidate preparation", async () => {
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
            "--evidence-dir",
            evidenceDir,
            "--run-id",
            "run-early-matrix",
          ],
          {
            env: {
              ...process.env,
              ENOKI_E2E_OWNER_PASSWORD: "must-not-be-recorded",
            },
          },
        ),
      ).rejects.toMatchObject({ code: 1 });

      const manifest = JSON.parse(
        await readFile(path.join(evidenceDir, "run-manifest.json"), "utf8"),
      );
      const evidence = JSON.parse(
        await readFile(path.join(evidenceDir, "evidence.json"), "utf8"),
      );
      expect(manifest).toMatchObject({
        failure: {
          error: { message: expect.stringMatching(/schemaVersion/i) },
          phase: "matrix-validation",
        },
        hostMutationPossible: false,
        phase: "failed",
        runId: "run-early-matrix",
        schemaVersion: 3,
      });
      expect(manifest.inputs).toMatchObject({
        hostAdapter: "ci",
        matrixCellId: "ubuntu-22.04-x86_64--fresh-install-uninstall",
        matrixPath,
      });
      expect(evidence).toMatchObject({
        diagnostics: {
          error: { message: expect.stringMatching(/schemaVersion/i) },
        },
        phase: "failed",
        result: { status: "failed" },
        runId: "run-early-matrix",
        schemaVersion: 2,
      });
      expect(JSON.stringify({ evidence, manifest })).not.toContain(
        "must-not-be-recorded",
      );

      await expect(
        execFileAsync(process.execPath, [
          script,
          "verify-clean",
          "--run-manifest",
          path.join(evidenceDir, "run-manifest.json"),
          "--host-adapter",
          "ci",
        ]),
      ).resolves.toMatchObject({
        stdout: expect.stringMatching(/no Host mutation was authorized/i),
      });
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("records candidate and CI adapter preparation failures with independently clean manifests", async () => {
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
        expected: /Candidate Manifest|candidate-manifest\.json|ENOENT/i,
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
        expected: /GitHub Actions runner identity/i,
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
              },
            },
          ),
        ).rejects.toMatchObject({ code: 1 });
        const manifest = JSON.parse(
          await readFile(path.join(evidenceDir, "run-manifest.json"), "utf8"),
        );
        const evidence = JSON.parse(
          await readFile(path.join(evidenceDir, "evidence.json"), "utf8"),
        );
        expect(manifest).toMatchObject({
          failure: {
            error: { message: expect.stringMatching(testCase.expected) },
            phase: "candidate-prepare",
          },
          hostMutationPossible: false,
          phase: "failed",
          scenario: "fresh-install-uninstall",
        });
        expect(evidence).toMatchObject({
          phase: "failed",
          result: { status: "failed" },
          scenario: "fresh-install-uninstall",
        });
        expect(JSON.stringify({ evidence, manifest })).not.toContain(
          "must-not-be-recorded",
        );
      }
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("derives scenario selection from the matrix cell and the shared registry only", () => {
    expect(Object.keys(releaseE2EScenarioRegistry)).toEqual([
      "baseline-upgrade-uninstall",
      "fresh-install-uninstall",
      "hub-restore-compatibility-window",
      "post-replacement-repair-uninstall",
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
      ]);
      await expect(prepared.execute("printf ready")).resolves.toEqual(
        successfulCommandText("ready\n"),
      );
      await expect(prepared.execute("id -u", { root: true })).resolves.toEqual(
        successfulCommandText("ready\n"),
      );
      await expect(
        adapter.release({ prepared, runId: "run-adapter" }),
      ).resolves.toEqual({ clean: true });
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

  it("bounds a real local Host process tree timeout without waiting for descendant stdio", async () => {
    const execute = createCiHostExecutor({ timeoutMs: 50 });
    const startedAt = Date.now();

    const result = await execute("trap '' TERM\nsleep 2\n");

    expect(Date.now() - startedAt).toBeLessThan(1_000);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toMatch(/terminated by SIGKILL|timed out/i);
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

  it("binds Hub runtime evidence to the Candidate and verifies clean removal", async () => {
    const manifestDigest = `sha256:${"d".repeat(64)}`;
    const configDigest = `sha256:${"e".repeat(64)}`;
    const commands = [];
    const state = { container: false, image: false, volume: false };
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
    const resources = await controller.start({
      candidateDir: "/candidate",
      candidateManifest: {
        hub: { archive: "hub/candidate.oci.tar", digest: manifestDigest },
      },
      hubOwnerUrl: "http://127.0.0.1:33000",
      hubPublicUrl: "http://192.0.2.20:33000",
      ownerPassword: "owner-secret",
      runId: "run-runtime",
    });

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
    expect(state).toEqual({ container: false, image: false, volume: false });
  });

  it("starts the pinned baseline Hub and switches to the Candidate on the same persisted state", async () => {
    const baselineManifestDigest = `sha256:${"b".repeat(64)}`;
    const baselineConfigDigest = `sha256:${"c".repeat(64)}`;
    const candidateManifestDigest = `sha256:${"d".repeat(64)}`;
    const candidateConfigDigest = `sha256:${"e".repeat(64)}`;
    const commands = [];
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
        runMounts.push(arguments_[arguments_.indexOf("--mount") + 1]);
        return successfulCommandText("container-id\n");
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
    await controller.switchToCandidate({ resources, runId: "run-switch" });
    expect(resources.activeHub).toBe("candidate");
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

function productInstallerOutput() {
  return "ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE\nEnoki Probe installed as enoki-probe.service.\n";
}

const officialInstallCommand =
  "curl -fsSL 'https://hub.example/api/probe/install.sh' | sudo env ENOKI_HUB_URL='https://hub.example' ENOKI_ENROLLMENT_TOKEN='enk_enroll_secret' bash";

function candidateManifest() {
  return {
    candidate: {
      commit: "0123456789abcdef0123456789abcdef01234567",
      version: "v1.2.3",
    },
    hub: {
      archive: "hub/enoki-hub-v1.2.3.oci.tar",
      digest: `sha256:${"a".repeat(64)}`,
      embeddedProbeVersion: "1.2.3",
    },
    kind: "enoki-release-candidate",
    probeAssetSet: { version: "1.2.3" },
    releaseBaseline: {
      hub: {
        archive: "hub/enoki-hub-v1.2.2.oci.tar",
        digest: `sha256:${"b".repeat(64)}`,
        imageDigest: `sha256:${"b".repeat(64)}`,
      },
      kind: "enoki-release-baseline",
      probeAssetSet: { version: "1.2.2" },
      tag: "v1.2.2",
    },
    schemaVersion: 2,
  };
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
      hub: {
        archive: "hub/enoki-hub-v1.2.2.oci.tar",
        digest: baselineHubDigest,
        imageDigest: baselineHubDigest,
      },
      kind: "enoki-release-baseline",
      probeAssetSet: { version: "1.2.2" },
      tag: "v1.2.2",
    },
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
      "/etc/enoki/probe-install.toml",
      "/etc/systemd/system/enoki-probe.service",
      "/var/lib/enoki-probe",
      "/etc/sudoers.d/enoki-probe-operations",
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
      sudoers:
        "enoki-probe ALL=(root) NOPASSWD: /usr/local/bin/enoki-probe-uninstaller internal-uninstaller\n",
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

function probeInstallMetadata(identityPath) {
  return [
    "schema_version = 1",
    'hub_url = "https://hub.example"',
    'install_path = "/usr/local/bin/enoki-probe"',
    `identity_path = "${identityPath}"`,
    'state_dir = "/var/lib/enoki-probe"',
    'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
    'service_name = "enoki-probe"',
    'service_user = "enoki-probe"',
    'service_group = "enoki-probe"',
    'service_unit_path = "/etc/systemd/system/enoki-probe.service"',
    'operation_sudoers_path = "/etc/sudoers.d/enoki-probe-operations"',
    'collector_helper_sudoers_path = "/etc/sudoers.d/enoki-probe-collector-helpers"',
    `probe_asset_public_key_sha256 = "${"a".repeat(64)}"`,
    "",
  ].join("\n");
}

async function createProbeMetadataShellFixture({ identityPath, probeId }) {
  const root = await mkdtemp(path.join(os.tmpdir(), "enoki-e2e-metadata-"));
  const metadataOwnerUid = fixtureOwnerUid();
  const metadataPath = path.join(root, "etc/enoki/probe-install.toml");
  const resolvedIdentityPath = path.join(root, identityPath);
  await mkdir(path.dirname(metadataPath), { recursive: true });
  await mkdir(path.dirname(resolvedIdentityPath), { recursive: true });
  await writeFile(metadataPath, probeInstallMetadata(identityPath), "utf8");
  await writeFile(
    resolvedIdentityPath,
    `probe_id = "${probeId}"\nprobe_private_key_pem = "test-private-key"\n`,
    "utf8",
  );
  await Promise.all([
    chmod(metadataPath, 0o600),
    chmod(resolvedIdentityPath, 0o600),
  ]);

  let claimed = false;
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
        claimed = true;
        return successfulCommandText("owned\n");
      }
      if (command.includes("# enoki-release-e2e:record-resources")) {
        return successfulCommandText("recorded\n");
      }
      if (command.includes("# enoki-release-e2e:probe-identity")) {
        return executeShell(
          remapProbeMetadataFixtureShell(command, root, metadataOwnerUid),
        );
      }
      return successfulCommandText(productInstallerOutput());
    },
  });
  await harness.assertDisposable("run-metadata");
  await harness.install(officialInstallCommand, "run-metadata");
  if (!claimed) {
    throw new Error("metadata fixture did not establish a harness claim");
  }
  return {
    dispose: () => rm(root, { force: true, recursive: true }),
    identityPath: resolvedIdentityPath,
    metadataPath,
    readIdentity: () => harness.readProbeIdentity("run-metadata"),
    root,
  };
}

const completionPathSuffixes = Object.freeze([
  "/var/lib/enoki-release-e2e",
  "/var/lib/enoki-probe",
  "/etc/enoki",
  "/etc/systemd/system",
  "/etc/sudoers.d",
  "/usr/local/bin/enoki-probe",
]);

const metadataRootOwnerCheck = '[ "$(stat -c %u "$metadata")" = 0 ]';

function fixtureOwnerUid() {
  const uid = process.getuid?.();
  if (!Number.isSafeInteger(uid) || uid < 0) {
    throw new Error("Release E2E shell fixture requires a numeric process UID");
  }
  return String(uid);
}

function remapMetadataOwnerCheck(command, metadataOwnerUid) {
  return command
    .split(metadataRootOwnerCheck)
    .join(`[ "$(stat -c %u "$metadata")" = ${metadataOwnerUid} ]`);
}

function remapProbeMetadataFixtureShell(command, root, metadataOwnerUid) {
  return remapMetadataOwnerCheck(
    command
      .replace(
        "metadata=/etc/enoki/probe-install.toml",
        `metadata=${path.join(root, "/etc/enoki/probe-install.toml")}`,
      )
      .replace(
        "current) identity=/var/lib/enoki-probe/identity/probe-bootstrap.toml",
        `current) identity=${path.join(root, "/var/lib/enoki-probe/identity/probe-bootstrap.toml")}`,
      )
      .replace(
        "v0_1_72) identity=/etc/enoki/probe-bootstrap.toml",
        `v0_1_72) identity=${path.join(root, "/etc/enoki/probe-bootstrap.toml")}`,
      ),
    metadataOwnerUid,
  );
}

function remapCompletionShell(command, root) {
  const remappedPaths = completionPathSuffixes.reduce(
    (script, suffix) => script.split(suffix).join(path.join(root, suffix)),
    command,
  );
  return remapMetadataOwnerCheck(remappedPaths, fixtureOwnerUid());
}

async function createOwnershipCompletionShellFixture({
  installerIdentityPath = "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
} = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), "enoki-e2e-completion-"));
  let executedCompletionShell = false;
  let lastCompletionShell = null;
  let nextInstallerIdentityPath = installerIdentityPath;
  const materializeProbe = async (identityPath = nextInstallerIdentityPath) => {
    const binaryPath = path.join(root, "/usr/local/bin/enoki-probe");
    const metadataPath = path.join(root, "/etc/enoki/probe-install.toml");
    const resolvedIdentityPath = path.join(root, identityPath);
    const alternateIdentityPath = path.join(
      root,
      identityPath === "/etc/enoki/probe-bootstrap.toml"
        ? "/var/lib/enoki-probe/identity/probe-bootstrap.toml"
        : "/etc/enoki/probe-bootstrap.toml",
    );
    await Promise.all([
      mkdir(path.dirname(binaryPath), { recursive: true }),
      mkdir(path.dirname(metadataPath), { recursive: true }),
      mkdir(path.dirname(resolvedIdentityPath), { recursive: true }),
    ]);
    await rm(alternateIdentityPath, { force: true });
    await writeFile(binaryPath, "candidate-probe", "utf8");
    await writeFile(
      metadataPath,
      remapCompletionShell(probeInstallMetadata(identityPath), root),
      "utf8",
    );
    await writeFile(
      resolvedIdentityPath,
      'probe_id = "probe_release_completion"\nprobe_private_key_pem = "test-private-key"\n',
      "utf8",
    );
    await Promise.all([
      chmod(metadataPath, 0o600),
      chmod(resolvedIdentityPath, 0o600),
    ]);
  };
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
      if (command.includes("# enoki-release-e2e:probe-repair")) {
        return successfulCommandText(
          "Probe Repair succeeded: probe=probe_release_completion version=1.2.3\n",
        );
      }
      if (!command.includes("# enoki-release-e2e:")) {
        await materializeProbe();
        return successfulCommandText(productInstallerOutput());
      }
      if (
        command.includes(
          "# enoki-release-e2e:complete-installer-recovery-ownership",
        ) ||
        command.includes("# enoki-release-e2e:complete-repair-ownership")
      ) {
        executedCompletionShell = true;
        lastCompletionShell = remapCompletionShell(command, root);
      }
      return executeShell(remapCompletionShell(command, root));
    },
  });
  return {
    dispose: () => rm(root, { force: true, recursive: true }),
    get executedCompletionShell() {
      return executedCompletionShell;
    },
    harness,
    get lastCompletionShell() {
      return lastCompletionShell;
    },
    materializeProbe,
    readClaimResources: () =>
      readFile(
        path.join(root, "/var/lib/enoki-release-e2e/claim/resources"),
        "utf8",
      ),
    setInstallerIdentityPath(identityPath) {
      nextInstallerIdentityPath = identityPath;
    },
  };
}

function pendingUpgradeOperation() {
  return {
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
}

function failedUpgradeOperation() {
  return {
    ...pendingUpgradeOperation(),
    acceptedAtMs: 2,
    completedAtMs: 20,
    failure: { code: "insufficient_privilege", message: "permission denied" },
    runningAtMs: 2,
    state: "failed",
    updatedAtMs: 20,
  };
}

async function executeShell(command) {
  try {
    const { stderr, stdout } = await execFileAsync("sh", ["-c", command]);
    return { code: 0, stderr, stdout };
  } catch (error) {
    return {
      code: typeof error.code === "number" ? error.code : 1,
      stderr: error.stderr ?? error.message,
      stdout: error.stdout ?? "",
    };
  }
}
