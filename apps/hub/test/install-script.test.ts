import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
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
    const release = await createProbeRelease(root);
    const commands = await createCommandMocks(root);

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: "https://hub.example",
      ENOKI_PROBE_DOWNLOAD_URL: release.archiveUrl,
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
        'log_level = "info"',
        "",
      ].join("\n"),
    );
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
    const release = await createProbeRelease(
      root,
      "aarch64-unknown-linux-gnu",
      "v0.2.0",
    );
    const commands = await createCommandMocks(root, {
      architecture: "aarch64",
    });

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_arm",
      ENOKI_GITHUB_RELEASE_BASE_URL: release.releaseBaseUrl,
      ENOKI_HUB_URL: "https://hub.example",
      ENOKI_INSTALL_PATH: "/opt/enoki/bin/enoki-probe",
      ENOKI_PROBE_VERSION: "v0.2.0",
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(0);
    await expect(
      readFile(path.join(root, "opt/enoki/bin/enoki-probe"), "utf8"),
    ).resolves.toBe("#!/bin/sh\necho probe\n");
    await expect(
      readFile(path.join(root, "tmp/curl.log"), "utf8"),
    ).resolves.toContain("v0.2.0/enoki-probe-aarch64-unknown-linux-gnu.tar.gz");
    await expect(
      readFile(
        path.join(root, "etc/systemd/system/enoki-probe.service"),
        "utf8",
      ),
    ).resolves.toContain(
      "ExecStart=/opt/enoki/bin/enoki-probe run --config /etc/enoki/probe-bootstrap.toml",
    );
  });

  it("escapes bootstrap TOML strings written from environment values", async () => {
    const root = await createTempRoot("enoki-install-escaping-root-");
    const release = await createProbeRelease(root);
    const commands = await createCommandMocks(root);

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: 'enk_"quoted"\nsecret\\tail',
      ENOKI_HUB_URL: 'https://hub.example/"quoted"\nnext',
      ENOKI_LOG_LEVEL: 'info"\nnext = "bad',
      ENOKI_PROBE_DOWNLOAD_URL: release.archiveUrl,
      ENOKI_SYSTEMD_RUNTIME_DIR: path.join(root, "run/systemd/system"),
      ENOKI_TEST_ROOT: root,
      PATH: `${commands.bin}:${process.env.PATH ?? ""}`,
    });

    expect(result.code).toBe(0);
    await expect(
      readFile(path.join(root, "etc/enoki/probe-bootstrap.toml"), "utf8"),
    ).resolves.toBe(
      [
        'hub_url = "https://hub.example/\\"quoted\\"\\nnext"',
        'enrollment_token = "enk_\\"quoted\\"\\nsecret\\\\tail"',
        'state_dir = "/var/lib/enoki-probe"',
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

  it("rejects a Probe artifact when sha256 verification fails", async () => {
    const root = await createTempRoot("enoki-install-badsha-root-");
    const release = await createProbeRelease(root);
    const commands = await createCommandMocks(root);
    await writeFile(
      fileURLToPath(`${release.archiveUrl}.sha256`),
      `${"0".repeat(64)}  enoki-probe-x86_64-unknown-linux-gnu.tar.gz\n`,
    );

    const result = await runInstaller({
      ENOKI_ENROLLMENT_TOKEN: "enk_enroll_test",
      ENOKI_HUB_URL: "https://hub.example",
      ENOKI_PROBE_DOWNLOAD_URL: release.archiveUrl,
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
});

async function createTempRoot(prefix: string) {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  tempRoots.push(root);
  await mkdir(path.join(root, "run/systemd/system"), { recursive: true });
  await mkdir(path.join(root, "tmp"), { recursive: true });

  return root;
}

async function createProbeRelease(
  root: string,
  target = "x86_64-unknown-linux-gnu",
  version = "v0.1.0",
) {
  const releaseRoot = path.join(root, "release", version);
  const payloadRoot = path.join(root, "payload");
  await mkdir(releaseRoot, { recursive: true });
  await mkdir(payloadRoot, { recursive: true });
  const binaryPath = path.join(payloadRoot, "enoki-probe");
  await writeFile(binaryPath, "#!/bin/sh\necho probe\n");
  await chmod(binaryPath, 0o755);

  const archivePath = path.join(releaseRoot, `enoki-probe-${target}.tar.gz`);
  await spawnProcess("tar", [
    "-czf",
    archivePath,
    "-C",
    payloadRoot,
    "enoki-probe",
  ]);
  const archive = await readFile(archivePath);
  await writeFile(
    `${archivePath}.sha256`,
    `${createHash("sha256").update(archive).digest("hex")}  ${path.basename(
      archivePath,
    )}\n`,
  );

  return {
    archiveUrl: `file://${archivePath}`,
    releaseBaseUrl: `file://${path.join(root, "release")}`,
  };
}

async function createCommandMocks(
  root: string,
  options: { architecture?: string; currentUserId?: string } = {},
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
exit 1
`,
  );
  await writeExecutable(
    path.join(bin, "getent"),
    `#!/bin/sh
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

  return { bin };
}

async function writeExecutable(filePath: string, contents: string) {
  await writeFile(filePath, contents);
  await chmod(filePath, 0o755);
}

async function runInstaller(environment: NodeJS.ProcessEnv) {
  const child = spawn("bash", [installScript], {
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
