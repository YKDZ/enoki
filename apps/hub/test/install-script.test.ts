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

  it("installs a verified x86_64 GNU Probe release as a non-root systemd service", async () => {
    const root = await createTempRoot("enoki-install-root-");
    const assets = await createProbeAssets(root);
    const commands = await createCommandMocks(root, { assetDir: assets.dir });

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
    ).resolves.toBe("#!/bin/sh\necho probe\n");
    await expect(
      readFile(path.join(root, "etc/enoki/probe-bootstrap.toml"), "utf8"),
    ).resolves.toBe(
      [
        'hub_url = "https://hub.example"',
        'enrollment_token = "enk_enroll_test"',
        'state_dir = "/var/lib/enoki-probe"',
        'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
        'install_path = "/usr/local/bin/enoki-probe"',
        'service_name = "enoki-probe"',
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
        'install_path = "/usr/local/bin/enoki-probe"',
        'state_dir = "/var/lib/enoki-probe"',
        'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
        'service_name = "enoki-probe"',
        `probe_asset_public_key_sha256 = "${assets.publicKeySha256}"`,
        "",
      ].join("\n"),
    );
    await expect(
      stat(path.join(root, "etc/enoki/probe-install.toml")).then(
        (metadata) => metadata.mode & 0o777,
      ),
    ).resolves.toBe(0o644);
    await expect(
      readFile(
        path.join(root, "etc/systemd/system/enoki-probe.service"),
        "utf8",
      ),
    ).resolves.toContain("User=enoki-probe");
    await expect(
      readFile(
        path.join(root, "etc/systemd/system/enoki-probe.service"),
        "utf8",
      ),
    ).resolves.toContain("Group=enoki-probe");
    await expect(
      readFile(path.join(root, "etc/sudoers.d/enoki-probe-upgrader"), "utf8"),
    ).resolves.toBe(
      [
        "# Managed by Enoki Probe installer.",
        "enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run ^--collect --pipe --wait --unit=enoki-probe-upgrader --property=Type=exec -- /usr/local/bin/enoki-probe internal-upgrader --config /etc/enoki/probe-bootstrap\\.toml$",
        "",
      ].join("\n"),
    );
    const sudoers = await readFile(
      path.join(root, "etc/sudoers.d/enoki-probe-upgrader"),
      "utf8",
    );
    expect(sudoers).not.toContain("*");
    expect(sudoers).not.toContain("--operation-id");
    expect(sudoers).not.toContain("--target-probe-version");
    expect(sudoers).toContain("^--collect");
    expect(sudoers).toContain("\\.toml$");
    expect(sudoers).toContain(" -- /usr/local/bin/enoki-probe ");
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
    ).resolves.toContain("start enoki-probe.service");
  });

  it("selects the aarch64 GNU Probe artifact from a release version", async () => {
    const root = await createTempRoot("enoki-install-arm-root-");
    const assets = await createProbeAssets(
      root,
      "aarch64-unknown-linux-gnu",
      "v0.2.0",
    );
    const commands = await createCommandMocks(root, {
      architecture: "aarch64",
      assetDir: assets.dir,
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
    ).resolves.toBe("#!/bin/sh\necho probe\n");
    await expect(
      readFile(path.join(root, "etc/enoki/probe-install.toml"), "utf8"),
    ).resolves.toContain('install_path = "/opt/enoki/bin/enoki-probe"');
    await expect(
      readFile(path.join(root, "tmp/curl.log"), "utf8"),
    ).resolves.toContain(
      "https://hub.example/api/probe/assets/enoki-probe-aarch64-unknown-linux-gnu.tar.gz",
    );
    await expect(
      readFile(
        path.join(root, "etc/systemd/system/enoki-probe.service"),
        "utf8",
      ),
    ).resolves.toContain(
      "ExecStart=/opt/enoki/bin/enoki-probe run --config /etc/enoki/probe-bootstrap.toml",
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
      readFile(path.join(root, "etc/enoki/probe-bootstrap.toml"), "utf8"),
    ).resolves.toBe(
      [
        'hub_url = "https://hub.example"',
        'enrollment_token = "enk_\\"quoted\\"\\nsecret\\\\tail"',
        'state_dir = "/var/lib/enoki-probe"',
        'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
        'install_path = "/usr/local/bin/enoki-probe"',
        'service_name = "enoki-probe"',
        `probe_asset_public_key_sha256 = "${assets.publicKeySha256}"`,
        'upgrader_launch = "systemd"',
        'log_level = "info\\"\\nnext = \\"bad"',
        "",
      ].join("\n"),
    );
  });

  it("fails clearly when systemd is unavailable", async () => {
    const root = await createTempRoot("enoki-install-nosystemd-root-");
    const commands = await createCommandMocks(root);

    await rm(path.join(root, "run/systemd/system"), {
      force: true,
      recursive: true,
    });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: "https://hub.example",
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("systemd is required");
  });

  it("fails clearly when the installer is not run as root", async () => {
    const root = await createTempRoot("enoki-install-nonroot-root-");
    const commands = await createCommandMocks(root, {
      currentUserId: "1000",
    });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: "https://hub.example",
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("run this installer as root");
  });

  it("uninstalls the systemd service, files, state, and default service account", async () => {
    const root = await createTempRoot("enoki-uninstall-root-");
    const commands = await createCommandMocks(root, {
      serviceGroupExists: true,
      serviceUserExists: true,
    });
    await mkdir(path.join(root, "usr/local/bin"), { recursive: true });
    await mkdir(path.join(root, "etc/enoki"), { recursive: true });
    await mkdir(path.join(root, "etc/sudoers.d"), { recursive: true });
    await mkdir(path.join(root, "etc/systemd/system"), { recursive: true });
    await mkdir(path.join(root, "var/lib/enoki-probe"), { recursive: true });
    await writeFile(path.join(root, "usr/local/bin/enoki-probe"), "probe");
    await writeFile(
      path.join(root, "etc/enoki/probe-bootstrap.toml"),
      "config",
    );
    await writeFile(
      path.join(root, "etc/systemd/system/enoki-probe.service"),
      "service",
    );
    await writeFile(
      path.join(root, "etc/sudoers.d/enoki-probe-upgrader"),
      "sudoers",
    );
    await writeFile(
      path.join(root, "etc/enoki/probe-install.toml"),
      "metadata",
    );
    await writeFile(path.join(root, "var/lib/enoki-probe/state"), "state");

    const result = await runInstaller({
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      ENOKI_UNINSTALL: "1",
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result).toEqual({
      code: 0,
      stderr: "",
      stdout: "Enoki Probe uninstalled.\n",
    });
    await expect(
      readFile(path.join(root, "usr/local/bin/enoki-probe"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "etc/enoki/probe-bootstrap.toml"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(
        path.join(root, "etc/systemd/system/enoki-probe.service"),
        "utf8",
      ),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "etc/sudoers.d/enoki-probe-upgrader"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "etc/enoki/probe-install.toml"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "var/lib/enoki-probe/state"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(root, "tmp/systemctl.log"), "utf8"),
    ).resolves.toContain("stop enoki-probe.service");
    await expect(
      readFile(path.join(root, "tmp/systemctl.log"), "utf8"),
    ).resolves.toContain("disable enoki-probe.service");
    await expect(
      readFile(path.join(root, "tmp/systemctl.log"), "utf8"),
    ).resolves.toContain("daemon-reload");
    await expect(
      readFile(path.join(root, "tmp/systemctl.log"), "utf8"),
    ).resolves.toContain("reset-failed enoki-probe.service");
    await expect(
      readFile(path.join(root, "tmp/userdel.log"), "utf8"),
    ).resolves.toContain("enoki-probe");
    await expect(
      readFile(path.join(root, "tmp/groupdel.log"), "utf8"),
    ).resolves.toContain("enoki-probe");
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
  if (options.archiveEntry === "symlink") {
    await symlink("/tmp/enoki-probe", binaryPath);
  } else {
    await writeFile(binaryPath, "#!/bin/sh\necho probe\n");
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
  https://hub.example/api/probe/assets/*) printf '%s\\n' "$url" >> '${path.join(
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
