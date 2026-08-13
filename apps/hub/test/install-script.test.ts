import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

const tempRoots: string[] = [];
const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const installScript = path.join(repositoryRoot, "scripts/install-probe.sh");

describe("Probe systemd installer", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("installs a verified x86_64 GNU Probe release on glibc Linux as a non-root systemd service", async () => {
    const root = await createTempRoot("enoki-install-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });
    await mkdir(path.join(root, "etc/sudoers.d"), { recursive: true });
    await writeFile(
      path.join(root, "etc/sudoers.d/enoki-probe-upgrader"),
      "legacy sudoers",
    );

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result).toEqual({
      code: 0,
      stderr: "",
      stdout: expect.stringContaining("Enoki Probe installed"),
    });
    await expect(
      readFile(path.join(root, "usr/local/bin/enoki-probe"), "utf8"),
    ).resolves.toContain("local-install");
    await expect(
      readFile(
        path.join(root, "var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        "utf8",
      ),
    ).resolves.toBe(
      [
        'hub_url = "https://hub.example"',
        'enrollment_token = "enk_enroll_test"',
        'state_dir = "/var/lib/enoki-probe"',
        'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
        'install_path = "/usr/local/bin/enoki-probe"',
        'service_name = "enoki-probe"',
        'service_user = "enoki-probe"',
        'operation_sudoers_path = "/etc/sudoers.d/enoki-probe-operations"',
        'collector_helper_sudoers_path = "/etc/sudoers.d/enoki-probe-collector-helpers"',
        `probe_asset_public_key_sha256 = "${assets.publicKeySha256}"`,
        'upgrader_launch = "systemd"',
        'log_level = "info"',
        "",
      ].join("\n"),
    );
    await expect(
      readFile(path.join(root, "etc/enoki/probe-install.toml"), "utf8"),
    ).resolves.toBe(
      [
        "schema_version = 1",
        'hub_url = "https://hub.example"',
        'install_path = "/usr/local/bin/enoki-probe"',
        'identity_path = "/var/lib/enoki-probe/identity/probe-bootstrap.toml"',
        'state_dir = "/var/lib/enoki-probe"',
        'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
        'service_name = "enoki-probe"',
        'service_user = "enoki-probe"',
        'service_group = "enoki-probe"',
        'service_unit_path = "/etc/systemd/system/enoki-probe.service"',
        'operation_sudoers_path = "/etc/sudoers.d/enoki-probe-operations"',
        'collector_helper_sudoers_path = "/etc/sudoers.d/enoki-probe-collector-helpers"',
        `probe_asset_public_key_sha256 = "${assets.publicKeySha256}"`,
        "",
      ].join("\n"),
    );
    await expect(
      stat(path.join(root, "etc/enoki/probe-install.toml")).then(
        (metadata) => metadata.mode & 0o777,
      ),
    ).resolves.toBe(0o600);
    const serviceFile = await readFile(
      path.join(root, "etc/systemd/system/enoki-probe.service"),
      "utf8",
    );
    expect(serviceFile).toContain("User=enoki-probe");
    expect(serviceFile).toContain("Group=enoki-probe");
    expect(serviceFile).toContain("ProtectControlGroups=true");
    expect(serviceFile).not.toContain("ProtectKernelTunables=true");
    expect(serviceFile).not.toContain("LockPersonality=true");
    expect(serviceFile).not.toContain("NoNewPrivileges=true");
    expect(serviceFile).not.toContain("RestrictSUIDSGID=true");
    expect(serviceFile).not.toContain("CapabilityBoundingSet=");
    await expect(
      readFile(path.join(root, "etc/sudoers.d/enoki-probe-operations"), "utf8"),
    ).resolves.toBe(
      [
        "# Managed by Enoki Probe installer.",
        "enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit=enoki-probe-upgrader --property=Type=exec -- /usr/local/bin/enoki-probe internal-upgrader --config /var/lib/enoki-probe/identity/probe-bootstrap.toml",
        "enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit=enoki-probe-uninstaller --property=Type=exec -- /usr/local/bin/enoki-probe internal-uninstaller --config /var/lib/enoki-probe/identity/probe-bootstrap.toml",
        "",
      ].join("\n"),
    );
    const collectorHelperSudoers = await readFile(
      path.join(root, "etc/sudoers.d/enoki-probe-collector-helpers"),
      "utf8",
    );
    expect(collectorHelperSudoers).toBe(
      [
        "# Managed by Enoki Probe installer.",
        "enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --quiet --pipe --wait --collect --property=RuntimeMaxSec=10 --property=PrivateNetwork=yes /usr/local/bin/enoki-probe internal-privileged-collector-helper --helper disk-health.smartctl",
        "",
      ].join("\n"),
    );
    expect(collectorHelperSudoers).not.toContain("*");
    expect(collectorHelperSudoers).not.toContain("--operation-id");
    expect(collectorHelperSudoers).not.toContain("--target-probe-version");
    expect(collectorHelperSudoers).toContain("--collect");
    expect(collectorHelperSudoers).toContain(" /usr/local/bin/enoki-probe ");
    expect(collectorHelperSudoers).toContain("--helper disk-health.smartctl");
    expect(collectorHelperSudoers).not.toContain(
      "internal-privileged-collector --collector",
    );
    expect(collectorHelperSudoers).not.toContain(
      "--collector disk-health.smartctl",
    );
    await expect(
      validateSudoers(path.join(root, "etc/sudoers.d/enoki-probe-operations")),
    ).resolves.toBe(true);
    await expect(
      validateSudoers(
        path.join(root, "etc/sudoers.d/enoki-probe-collector-helpers"),
      ),
    ).resolves.toBe(true);
    await expect(
      stat(path.join(root, "etc/sudoers.d/enoki-probe-operations")).then(
        (metadata) => metadata.mode & 0o777,
      ),
    ).resolves.toBe(0o440);
    await expect(
      stat(path.join(root, "etc/sudoers.d/enoki-probe-collector-helpers")).then(
        (metadata) => metadata.mode & 0o777,
      ),
    ).resolves.toBe(0o440);
    await expect(
      readFile(path.join(root, "etc/sudoers.d/enoki-probe-upgrader"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "tmp/probe-planner.log"), "utf8"),
    ).resolves.toContain(
      "internal-render-collector-helper-sudoers --service-user enoki-probe --probe-binary /usr/local/bin/enoki-probe",
    );
    await expect(
      readFile(path.join(root, "tmp/groupadd.log"), "utf8"),
    ).resolves.toEqual(expect.stringContaining("--system enoki-probe"));
    await expect(
      readFile(path.join(root, "tmp/useradd.log"), "utf8"),
    ).resolves.toEqual(expect.stringContaining("--system"));
    await expect(
      readFile(path.join(root, "tmp/useradd.log"), "utf8"),
    ).resolves.toEqual(expect.stringContaining("--gid enoki-probe"));
    await expect(
      readFile(path.join(root, "tmp/useradd.log"), "utf8"),
    ).resolves.toEqual(expect.stringContaining("enoki-probe"));
    await expect(
      readFile(path.join(root, "tmp/systemctl.log"), "utf8"),
    ).resolves.toContain("enable enoki-probe.service");
    await expect(
      readFile(path.join(root, "tmp/systemctl.log"), "utf8"),
    ).resolves.toContain("start --no-block enoki-probe.service");
    await expect(
      readFile(path.join(root, "tmp/systemctl.log"), "utf8"),
    ).resolves.toContain("is-active --quiet enoki-probe.service");
  });

  it("installs from an explicitly configured non-loopback HTTP Probe API Origin", async () => {
    const root = await createTempRoot("enoki-install-http-origin-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: "http://192.0.2.20:3001",
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(0);
    await expect(
      readFile(path.join(root, "etc/enoki/probe-install.toml"), "utf8"),
    ).resolves.toContain('hub_url = "http://192.0.2.20:3001"');
  });

  it("installs without a collector-helper sudoers file when the Probe planner exposes no helpers", async () => {
    const root = await createTempRoot("enoki-install-no-helper-root-");
    const assets = await createProbeAssets(root, {
      collectorHelperSudoers: "",
    });
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(0);
    await expect(
      readFile(path.join(root, "etc/sudoers.d/enoki-probe-operations"), "utf8"),
    ).resolves.toContain("internal-upgrader --config");
    await expect(
      readFile(
        path.join(root, "etc/sudoers.d/enoki-probe-collector-helpers"),
        "utf8",
      ),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "tmp/probe-planner.log"), "utf8"),
    ).resolves.toContain("internal-render-collector-helper-sudoers");
  });

  it("does not fall back to a shell installation path when the candidate omits the lifecycle completion marker", async () => {
    const root = await createTempRoot("enoki-install-missing-marker-root-");
    const assets = await createProbeAssets(root, {
      localLifecycleCompletes: false,
    });
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      "did not complete the typed Probe Local Lifecycle",
    );
    await expect(
      readFile(path.join(root, "usr/local/bin/enoki-probe"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects install settings that could inject systemd or sudoers directives before writing privileged files", async () => {
    const root = await createTempRoot("enoki-install-invalid-settings-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_CONFIG_PATH: "/etc/enoki/probe bootstrap.toml",
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SERVICE_USER: "enoki-probe\nroot ALL=(root) NOPASSWD: ALL",
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("ENOKI_SERVICE_USER");
    await expect(
      readFile(
        path.join(root, "etc/systemd/system/enoki-probe.service"),
        "utf8",
      ),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "etc/sudoers.d/enoki-probe-upgrader"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects explicitly empty install settings instead of falling back to defaults", async () => {
    const root = await createTempRoot("enoki-install-empty-settings-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_INSTALL_PATH: "",
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("ENOKI_INSTALL_PATH is required");
    await expect(
      readFile(
        path.join(root, "etc/systemd/system/enoki-probe.service"),
        "utf8",
      ),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "etc/sudoers.d/enoki-probe-upgrader"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects install paths with spaces before writing privileged files", async () => {
    const root = await createTempRoot("enoki-install-path-space-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_INSTALL_PATH: "/opt/enoki probe/bin/enoki-probe",
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("ENOKI_INSTALL_PATH");
    await expect(
      readFile(
        path.join(root, "etc/systemd/system/enoki-probe.service"),
        "utf8",
      ),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "etc/sudoers.d/enoki-probe-upgrader"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("preserves an existing Probe installation instead of overwriting it", async () => {
    const root = await createTempRoot("enoki-install-update-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, {
      assetDir: assets.dir,
      serviceGroupExists: true,
      serviceUserExists: true,
    });
    const bootstrapPath = path.join(
      root,
      "var/lib/enoki-probe/identity/probe-bootstrap.toml",
    );
    const operationStatusPath = path.join(
      root,
      "var/lib/enoki-probe/probe-operation-status.toml",
    );
    await mkdir(path.dirname(bootstrapPath), { recursive: true });
    await mkdir(path.dirname(operationStatusPath), { recursive: true });
    await writeFile(
      bootstrapPath,
      [
        'hub_url = "https://hub.example/"',
        'probe_id = "probe_existing"',
        'probe_private_key_pem = "existing-private-key"',
        'probe_configuration_version = "default-v2"',
        "metrics_collection_interval_seconds = 1",
        'enabled_collector_ids = ["official.cpu", "official.memory"]',
        "",
      ].join("\n"),
    );
    await writeFile(
      operationStatusPath,
      [
        'operation_id = "30"',
        'target_probe_version = "0.1.45"',
        'status = "running"',
        "",
      ].join("\n"),
    );

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_reinstall",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("pre-existing Enoki Probe installation");
    await expect(readFile(bootstrapPath, "utf8")).resolves.toBe(
      [
        'hub_url = "https://hub.example/"',
        'probe_id = "probe_existing"',
        'probe_private_key_pem = "existing-private-key"',
        'probe_configuration_version = "default-v2"',
        "metrics_collection_interval_seconds = 1",
        'enabled_collector_ids = ["official.cpu", "official.memory"]',
        "",
      ].join("\n"),
    );
    await expect(readFile(bootstrapPath, "utf8")).resolves.not.toContain(
      "enk_enroll_reinstall",
    );
    await expect(
      readFile(path.join(root, "tmp/systemctl.log"), "utf8"),
    ).resolves.not.toContain("start --no-block enoki-probe.service");
  });

  it("preserves a legacy existing Probe installation instead of replacing its identity", async () => {
    const root = await createTempRoot("enoki-install-update-legacy-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, {
      assetDir: assets.dir,
      serviceGroupExists: true,
      serviceUserExists: true,
    });
    const bootstrapPath = path.join(
      root,
      "var/lib/enoki-probe/identity/probe-bootstrap.toml",
    );
    const operationStatusPath = path.join(
      root,
      "var/lib/enoki-probe/probe-operation-status.toml",
    );
    await mkdir(path.dirname(bootstrapPath), { recursive: true });
    await mkdir(path.dirname(operationStatusPath), { recursive: true });
    await writeFile(
      bootstrapPath,
      [
        'hub_url = "https://hub.example/"',
        'probe_id = "probe_existing"',
        'probe_configuration_version = "default-v2"',
        "",
      ].join("\n"),
    );
    await writeFile(
      operationStatusPath,
      [
        'operation_id = "30"',
        'target_probe_version = "0.1.45"',
        'status = "running"',
        "",
      ].join("\n"),
    );

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_legacy_reinstall",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("pre-existing Enoki Probe installation");
    const bootstrapConfig = await readFile(bootstrapPath, "utf8");
    expect(bootstrapConfig).not.toContain("enk_enroll_legacy_reinstall");
    expect(bootstrapConfig).toContain("probe_existing");
    expect(bootstrapConfig).toContain("probe_configuration_version");
    await expect(stat(operationStatusPath)).resolves.toBeDefined();
  });

  it("preserves an existing Probe from a different Hub", async () => {
    const root = await createTempRoot("enoki-install-update-new-hub-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });
    const bootstrapPath = path.join(
      root,
      "var/lib/enoki-probe/identity/probe-bootstrap.toml",
    );
    await mkdir(path.dirname(bootstrapPath), { recursive: true });
    await writeFile(
      bootstrapPath,
      [
        'hub_url = "https://old-hub.example"',
        'probe_id = "probe_existing"',
        "",
      ].join("\n"),
    );

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_new_hub",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("pre-existing Enoki Probe installation");
    await expect(readFile(bootstrapPath, "utf8")).resolves.not.toContain(
      "enk_enroll_new_hub",
    );
    await expect(readFile(bootstrapPath, "utf8")).resolves.toContain(
      "probe_existing",
    );
  });

  it("selects the aarch64 musl Probe artifact on musl Linux from a release version", async () => {
    const root = await createTempRoot("enoki-install-arm-root-");
    const assets = await createProbeAssets(
      root,
      "aarch64-unknown-linux-musl",
      "v0.2.0",
    );
    const commands = await createCommandMocks(root, {
      architecture: "aarch64",
      assetDir: assets.dir,
      libc: "musl",
    });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_arm",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_INSTALL_PATH: "/opt/enoki/bin/enoki-probe",
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(0);
    await expect(
      readFile(path.join(root, "opt/enoki/bin/enoki-probe"), "utf8"),
    ).resolves.toContain("local-install");
    await expect(
      readFile(path.join(root, "etc/enoki/probe-install.toml"), "utf8"),
    ).resolves.toContain('install_path = "/opt/enoki/bin/enoki-probe"');
    await expect(
      readFile(path.join(root, "tmp/curl.log"), "utf8"),
    ).resolves.toContain(
      "https://hub.example/api/probe/assets/enoki-probe-aarch64-unknown-linux-musl.tar.gz",
    );
    await expect(
      readFile(
        path.join(root, "etc/systemd/system/enoki-probe.service"),
        "utf8",
      ),
    ).resolves.toContain(
      "ExecStart=/opt/enoki/bin/enoki-probe run --config /var/lib/enoki-probe/identity/probe-bootstrap.toml",
    );
  });

  it("trusts the embedded release signing key fingerprint without environment overrides", async () => {
    const root = await createTempRoot("enoki-install-embedded-key-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });
    const embeddedInstaller = path.join(root, "install-probe.sh");
    const source = await readFile(installScript, "utf8");
    await writeFile(
      embeddedInstaller,
      source.replaceAll(
        "__ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256__",
        assets.publicKeySha256,
      ),
    );
    await chmod(embeddedInstaller, 0o755);

    const result = await runInstaller(
      {
        ENOKI_ENROLLMENT_TOKEN: "enk_enroll_embedded",
        ENOKI_HUB_URL: assets.hubUrl,
        ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
        ENOKI_TEST_ROOT: root,
        PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
      },
      embeddedInstaller,
    );

    expect(result).toEqual({
      code: 0,
      stderr: "",
      stdout: expect.stringContaining("Enoki Probe installed"),
    });
  });

  it("escapes bootstrap TOML strings written from environment values", async () => {
    const root = await createTempRoot("enoki-install-escaping-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: 'enk_"quoted"\nsecret\\tail',
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_LOG_LEVEL: 'info"\nnext = "bad',
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(0);
    await expect(
      readFile(
        path.join(root, "var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        "utf8",
      ),
    ).resolves.toBe(
      [
        'hub_url = "https://hub.example"',
        'enrollment_token = "enk_\\"quoted\\"\\nsecret\\\\tail"',
        'state_dir = "/var/lib/enoki-probe"',
        'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
        'install_path = "/usr/local/bin/enoki-probe"',
        'service_name = "enoki-probe"',
        'service_user = "enoki-probe"',
        'operation_sudoers_path = "/etc/sudoers.d/enoki-probe-operations"',
        'collector_helper_sudoers_path = "/etc/sudoers.d/enoki-probe-collector-helpers"',
        `probe_asset_public_key_sha256 = "${assets.publicKeySha256}"`,
        'upgrader_launch = "systemd"',
        'log_level = "info\\"\\nnext = \\"bad"',
        "",
      ].join("\n"),
    );
  });

  it("fails clearly when systemd is unavailable", async () => {
    const root = await createTempRoot("enoki-install-nosystemd-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    await rm(path.join(root, "run/systemd/system"), {
      force: true,
      recursive: true,
    });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("systemd is required");
  });

  it("fails clearly when the installer is not run as root", async () => {
    const root = await createTempRoot("enoki-install-nonroot-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, {
      assetDir: assets.dir,
      currentUserId: "1000",
    });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("must run as root");
  });

  it("rejects a Probe artifact when sha256 verification fails", async () => {
    const root = await createTempRoot("enoki-install-badsha-root-");
    const assets = await createProbeAssets(root, {
      sha256: "0".repeat(64),
    });
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("Probe sha256 verification failed");
    await expect(
      readFile(path.join(root, "usr/local/bin/enoki-probe"), "utf8"),
    ).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("rejects Probe assets when the signed manifest cannot be verified", async () => {
    const root = await createTempRoot("enoki-install-badsig-root-");
    const assets = await createProbeAssets(root, {
      signature: Buffer.from("not a valid signature"),
    });
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      "Probe asset manifest signature verification failed",
    );
  });

  it("rejects Probe assets when the signing key fingerprint is not trusted", async () => {
    const root = await createTempRoot("enoki-install-badkey-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: "0".repeat(64),
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      "Probe asset signing key fingerprint verification failed",
    );
  });

  it("rejects Probe release archives that contain a symlink payload", async () => {
    const root = await createTempRoot("enoki-install-symlink-archive-root-");
    const assets = await createProbeAssets(root, {
      archiveEntry: "symlink",
    });
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: assets.hubUrl,
      ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      "Probe release archive did not contain an enoki-probe binary",
    );
  });

  it.each([
    "http://localhost@evil.example",
    "https://owner:password@hub.example",
    "https://hub.example/path",
    "https://hub.example/path?token=not-allowed",
    "https://hub.example/#fragment",
  ])(
    "rejects Hub URLs with an unsafe authority or request component: %s",
    async (hubUrl) => {
      const root = await createTempRoot("enoki-install-root-");
      const assets = await createProbeAssets(root);
      const commands = await createCommandMocks(root, { assetDir: assets.dir });

      const result = await runInstaller({
        ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
        ENOKI_HUB_URL: hubUrl,
        ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256: assets.publicKeySha256,
        ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
        ENOKI_TEST_ROOT: root,
        PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
      });

      expect(result.code).toBe(1);
      expect(result.stderr).toContain("ENOKI_HUB_URL must");
    },
  );
});

async function createTempRoot(prefix: string) {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  tempRoots.push(root);
  await mkdir(path.join(root, "run/systemd/system"), { recursive: true });
  await mkdir(path.join(root, "tmp"), { recursive: true });

  return root;
}

async function createProbeAssets(
  root: string,
  targetOrOptions:
    | string
    | {
        archiveEntry?: "regular" | "symlink";
        collectorHelperSudoers?: string;
        localLifecycleCompletes?: boolean;
        sha256?: string;
        signature?: Buffer;
        target?: string;
        version?: string;
      } = "x86_64-unknown-linux-gnu",
  version = "v0.1.0",
) {
  const options =
    typeof targetOrOptions === "string"
      ? { target: targetOrOptions, version }
      : targetOrOptions;
  const target = options.target ?? "x86_64-unknown-linux-gnu";
  const assetRoot = path.join(root, "hub-assets");
  const payloadRoot = path.join(root, "payload");
  await mkdir(assetRoot, { recursive: true });
  await mkdir(payloadRoot, { recursive: true });
  const binaryPath = path.join(payloadRoot, "enoki-probe");
  const collectorHelperSudoers =
    typeof targetOrOptions === "object" &&
    "collectorHelperSudoers" in targetOrOptions
      ? (targetOrOptions.collectorHelperSudoers ?? "")
      : [
          "# Managed by Enoki Probe installer.",
          "enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --quiet --pipe --wait --collect --property=RuntimeMaxSec=10 --property=PrivateNetwork=yes /usr/local/bin/enoki-probe internal-privileged-collector-helper --helper disk-health.smartctl",
        ].join("\n");
  const collectorHelperSudoersIsPresent = collectorHelperSudoers.length > 0;
  if (options.archiveEntry === "symlink") {
    await symlink("/tmp/enoki-probe", binaryPath);
  } else {
    await writeFile(
      binaryPath,
      `#!/bin/sh
set -eu

if [ "\${1:-}" = "internal-render-collector-helper-sudoers" ]; then
  printf '%s\\n' "$*" >> '${path.join(root, "tmp/probe-planner.log")}'
  if [ "${collectorHelperSudoersIsPresent ? "1" : "0"}" = "1" ]; then
  cat <<'EOF'
${collectorHelperSudoers}
EOF
  fi
  exit 0
fi

if [ "\${1:-}" != "local-install" ] || [ "\${2:-}" != "--candidate" ]; then
  echo "unexpected Probe test-double command: $*" >&2
  exit 64
fi

if [ "${options.localLifecycleCompletes === false ? "0" : "1"}" = "0" ]; then
  exit 0
fi

install_path="\${ENOKI_INSTALL_PATH-/usr/local/bin/enoki-probe}"
config_path="\${ENOKI_CONFIG_PATH-/var/lib/enoki-probe/identity/probe-bootstrap.toml}"
state_dir="\${ENOKI_STATE_DIR-/var/lib/enoki-probe}"
service_user="\${ENOKI_SERVICE_USER-enoki-probe}"
service_group="\${ENOKI_SERVICE_GROUP-enoki-probe}"
log_level="\${ENOKI_LOG_LEVEL-info}"
metadata_path="\${ENOKI_INSTALL_METADATA_PATH-/etc/enoki/probe-install.toml}"
operation_sudoers="\${ENOKI_OPERATION_SUDOERS_PATH-/etc/sudoers.d/enoki-probe-operations}"
collector_sudoers="\${ENOKI_COLLECTOR_HELPER_SUDOERS_PATH-/etc/sudoers.d/enoki-probe-collector-helpers}"
unit_path="\${ENOKI_SERVICE_UNIT_PATH-/etc/systemd/system/enoki-probe.service}"

fail() {
  echo "invalid Probe Local Lifecycle input: $1" >&2
  exit 1
}

validate_account() {
  case "$2" in
    ""|*[!a-z0-9_-]*|[0-9-]*) fail "$1" ;;
  esac
}

validate_path() {
  case "$2" in
    "" ) fail "$1 is required" ;;
    /* ) ;;
    * ) fail "$1" ;;
  esac
  case "$2" in
    *" "*|*"\n"*|*"\r"*|*"\t"*|*/../*|*/..|*/./*|*/.) fail "$1" ;;
  esac
}

validate_account ENOKI_SERVICE_USER "$service_user"
validate_account ENOKI_SERVICE_GROUP "$service_group"
validate_path ENOKI_INSTALL_PATH "$install_path"
validate_path ENOKI_CONFIG_PATH "$config_path"
validate_path ENOKI_STATE_DIR "$state_dir"

if ! systemctl --version >/dev/null 2>&1 || [ ! -d "\${ENOKI_SYSTEMD_RUNTIME_DIR-/run/systemd/system}" ]; then
  echo "Probe Local Lifecycle systemd failure: systemd is required" >&2
  exit 1
fi
if [ -z "\${ENOKI_TEST_ROOT:-}" ] && [ "$(id -u)" != "0" ]; then
  echo "invalid Probe Local Lifecycle input: Probe Local Lifecycle must run as root" >&2
  exit 1
fi
root="\${ENOKI_TEST_ROOT:?test root is required}"

for managed_path in "$install_path" "$config_path" "$state_dir" "$metadata_path" "$operation_sudoers" "$collector_sudoers" "$unit_path"; do
  if [ -e "$root$managed_path" ]; then
    echo "a pre-existing Enoki Probe installation or residue was found" >&2
    exit 1
  fi
done

toml_string() {
  node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$1"
}

if ! getent group "$service_group" >/dev/null 2>&1; then
  groupadd --system "$service_group"
fi
if ! id -u "$service_user" >/dev/null 2>&1; then
  useradd --system --gid "$service_group" --home-dir "$state_dir" --shell /usr/sbin/nologin "$service_user"
fi

mkdir -p "$(dirname "$root$install_path")" "$(dirname "$root$config_path")" "$root$state_dir" "$(dirname "$root$metadata_path")" "$(dirname "$root$operation_sudoers")" "$(dirname "$root$unit_path")"
cp "$3" "$root$install_path"
chmod 0755 "$root$install_path"

{
  printf 'hub_url = '; toml_string "$ENOKI_HUB_URL"; printf '\\n'
  printf 'enrollment_token = '; toml_string "$ENOKI_ENROLLMENT_TOKEN"; printf '\\n'
  printf 'state_dir = '; toml_string "$state_dir"; printf '\\n'
  printf 'operation_status_path = '; toml_string "$state_dir/probe-operation-status.toml"; printf '\\n'
  printf 'install_path = '; toml_string "$install_path"; printf '\\n'
  printf 'service_name = "enoki-probe"\\n'
  printf 'service_user = '; toml_string "$service_user"; printf '\\n'
  printf 'operation_sudoers_path = '; toml_string "$operation_sudoers"; printf '\\n'
  printf 'collector_helper_sudoers_path = '; toml_string "$collector_sudoers"; printf '\\n'
  printf 'probe_asset_public_key_sha256 = '; toml_string "$ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256"; printf '\\n'
  printf 'upgrader_launch = "systemd"\\n'
  printf 'log_level = '; toml_string "$log_level"; printf '\\n'
} > "$root$config_path"
chmod 0600 "$root$config_path"

hub_without_trailing_slash="\${ENOKI_HUB_URL%/}"
{
  printf 'schema_version = 1\\n'
  printf 'hub_url = '; toml_string "$hub_without_trailing_slash"; printf '\\n'
  printf 'install_path = '; toml_string "$install_path"; printf '\\n'
  printf 'identity_path = '; toml_string "$config_path"; printf '\\n'
  printf 'state_dir = '; toml_string "$state_dir"; printf '\\n'
  printf 'operation_status_path = '; toml_string "$state_dir/probe-operation-status.toml"; printf '\\n'
  printf 'service_name = "enoki-probe"\\n'
  printf 'service_user = '; toml_string "$service_user"; printf '\\n'
  printf 'service_group = '; toml_string "$service_group"; printf '\\n'
  printf 'service_unit_path = "/etc/systemd/system/enoki-probe.service"\\n'
  printf 'operation_sudoers_path = '; toml_string "$operation_sudoers"; printf '\\n'
  printf 'collector_helper_sudoers_path = '; toml_string "$collector_sudoers"; printf '\\n'
  printf 'probe_asset_public_key_sha256 = '; toml_string "$ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256"; printf '\\n'
} > "$root$metadata_path"
chmod 0600 "$root$metadata_path"

cat > "$root$unit_path" <<EOF
[Unit]
Description=Enoki Probe
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
User=$service_user
Group=$service_group
ExecStart=$install_path run --config $config_path
Restart=on-failure
RestartPreventExitStatus=78
RestartSec=5s
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectControlGroups=true
ReadWritePaths=$state_dir $(dirname "$config_path")

[Install]
WantedBy=multi-user.target
EOF

cat > "$root$operation_sudoers" <<EOF
# Managed by Enoki Probe installer.
$service_user ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit=enoki-probe-upgrader --property=Type=exec -- $install_path internal-upgrader --config $config_path
$service_user ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit=enoki-probe-uninstaller --property=Type=exec -- $install_path internal-uninstaller --config $config_path
EOF
chmod 0440 "$root$operation_sudoers"

"$root$install_path" internal-render-collector-helper-sudoers --service-user "$service_user" --probe-binary "$install_path" > "$root$collector_sudoers"
if [ ! -s "$root$collector_sudoers" ]; then
  rm -f "$root$collector_sudoers"
else
  chmod 0440 "$root$collector_sudoers"
fi
rm -f "$root/etc/sudoers.d/enoki-probe-upgrader"
systemctl daemon-reload
systemctl enable enoki-probe.service
systemctl start --no-block enoki-probe.service
systemctl is-active --quiet enoki-probe.service
printf '%s\\n' ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE
`,
    );
    await chmod(binaryPath, 0o755);
  }

  const archivePath = path.join(assetRoot, `enoki-probe-${target}.tar.gz`);
  await spawnProcess("tar", [
    "-czf",
    archivePath,
    "-C",
    payloadRoot,
    "enoki-probe",
  ]);
  const archive = await readFile(archivePath);
  const sha256 =
    options.sha256 ?? createHash("sha256").update(archive).digest("hex");
  const manifest = JSON.stringify(
    {
      assets: [
        {
          file: path.basename(archivePath),
          sha256,
          size: archive.byteLength,
          target,
        },
      ],
      kind: "enoki-probe-assets",
      signature: {
        algorithm: "rsa-sha256",
        file: "manifest.json.sig",
        publicKey: "signing-key.pem",
      },
      version: options.version ?? version,
    },
    null,
    2,
  );
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const signature =
    options.signature ?? sign("RSA-SHA256", Buffer.from(manifest), privateKey);

  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });
  await writeFile(path.join(assetRoot, "manifest.json"), manifest);
  await writeFile(path.join(assetRoot, "manifest.json.sig"), signature);
  await writeFile(path.join(assetRoot, "signing-key.pem"), publicKeyPem);

  return {
    dir: assetRoot,
    hubUrl: "https://hub.example",
    publicKeySha256: createHash("sha256").update(publicKeyPem).digest("hex"),
  };
}

async function createCommandMocks(
  root: string,
  options: {
    architecture?: string;
    assetDir?: string;
    currentUserId?: string;
    libc?: "gnu" | "musl" | "unknown";
    serviceGroupExists?: boolean;
    serviceUserExists?: boolean;
  } = {},
) {
  const bin = path.join(root, "mock-bin");
  await mkdir(bin, { recursive: true });
  await writeExecutable(
    path.join(bin, "curl"),
    `#!/bin/sh
set -eu
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://hub.example/api/probe/assets/* | http://192.0.2.20:3001/api/probe/assets/*) printf '%s\\n' "$url" >> '${path.join(
    root,
    "tmp/curl.log",
  )}'; cp '${options.assetDir ?? root}'/"\${url##*/}" "$out" ;;
  file://*) printf '%s\\n' "$url" >> '${path.join(
    root,
    "tmp/curl.log",
  )}'; cp "\${url#file://}" "$out" ;;
  *) echo "unexpected url: $url" >&2; exit 23 ;;
esac
`,
  );
  await writeExecutable(
    path.join(bin, "id"),
    `#!/bin/sh
if [ "\${1:-}" = "-u" ] && [ "$#" -eq 1 ]; then
  echo ${options.currentUserId ?? "0"}
  exit 0
fi
if [ "\${1:-}" = "-u" ] && [ "\${2:-}" = "enoki-probe" ] && [ "$#" -eq 2 ]; then
  ${options.serviceUserExists ? "echo 995\n  exit 0" : "exit 1"}
fi
exit 1
`,
  );
  await writeExecutable(
    path.join(bin, "getconf"),
    `#!/bin/sh
if [ "\${1:-}" = "GNU_LIBC_VERSION" ] && [ "$#" -eq 1 ]; then
  ${options.libc === "musl" || options.libc === "unknown" ? "exit 1" : "echo glibc 2.39\n  exit 0"}
fi
exit 1
`,
  );
  await writeExecutable(
    path.join(bin, "getent"),
    `#!/bin/sh
if [ "\${1:-}" = "group" ] && [ "\${2:-}" = "enoki-probe" ]; then
  ${
    options.serviceGroupExists
      ? 'echo "enoki-probe:x:995:"\n  exit 0'
      : "exit 2"
  }
fi
exit 2
`,
  );
  await writeExecutable(
    path.join(bin, "groupadd"),
    `#!/bin/sh
printf '%s\\n' "$*" >> '${path.join(root, "tmp/groupadd.log")}'
`,
  );
  await writeExecutable(
    path.join(bin, "groupdel"),
    `#!/bin/sh
printf '%s\\n' "$*" >> '${path.join(root, "tmp/groupdel.log")}'
`,
  );
  await writeExecutable(
    path.join(bin, "ldd"),
    `#!/bin/sh
if [ "\${1:-}" = "--version" ]; then
  ${options.libc === "musl" ? 'echo "musl libc (x86_64)"' : 'echo "ldd (GNU libc) 2.39"'}
  exit 0
fi
exit 1
`,
  );
  await writeExecutable(
    path.join(bin, "systemctl"),
    `#!/bin/sh
printf '%s\\n' "$*" >> '${path.join(root, "tmp/systemctl.log")}'
if [ "\${1:-}" = "--version" ]; then
  echo "systemd 255"
fi
`,
  );
  await writeExecutable(
    path.join(bin, "uname"),
    `#!/bin/sh
case "\${1:-}" in
  -s) echo Linux ;;
  -m) echo ${options.architecture ?? "x86_64"} ;;
  *) echo Linux ;;
esac
`,
  );
  await writeExecutable(
    path.join(bin, "useradd"),
    `#!/bin/sh
printf '%s\\n' "$*" >> '${path.join(root, "tmp/useradd.log")}'
`,
  );
  await writeExecutable(
    path.join(bin, "userdel"),
    `#!/bin/sh
printf '%s\\n' "$*" >> '${path.join(root, "tmp/userdel.log")}'
`,
  );

  return { bin };
}

async function writeExecutable(filePath: string, contents: string) {
  await writeFile(filePath, contents);
  await chmod(filePath, 0o755);
}

async function runInstaller(
  environment: NodeJS.ProcessEnv,
  scriptPath = installScript,
) {
  const child = spawn("bash", [scriptPath], {
    env: {
      ...process.env,
      ...environment,
    },
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });

  const code = await new Promise<number | null>((resolve) => {
    child.on("close", resolve);
  });

  return {
    code,
    stderr,
    stdout,
  };
}

async function spawnProcess(command: string, args: string[]) {
  const child = spawn(command, args);
  const code = await new Promise<number | null>((resolve) => {
    child.on("close", resolve);
  });

  if (code !== 0) {
    throw new Error(`${command} failed with code ${code}`);
  }
}

async function validateSudoers(filePath: string) {
  const child = spawn("visudo", ["-c", "-f", filePath]);
  const code = await new Promise<number | null>((resolve) => {
    child.on("error", () => resolve(null));
    child.on("close", resolve);
  });

  return code === 0;
}
