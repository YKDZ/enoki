import { chmod, copyFile, mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { expect } from "vitest";

import type { ProductionBundle } from "./probe-registration-production-recovery-bundle-test-support";
import {
  docker,
  requireCommand,
  runCommand,
} from "./probe-registration-production-recovery-command-test-support";
import { createOldProductionInstall } from "./probe-registration-production-recovery-fixture-test-support";

const systemdImage = process.env.ENOKI_PRODUCTION_SYSTEMD_IMAGE;

export async function startSystemdContainer(input: {
  acquirerPath: string;
  assetDir: string;
  container: string;
  hubOrigin: string;
  lifecycleCompanionPath: string;
  oldProbeId: string;
  sourceProbeBinary: string;
  stateRoot: string;
}) {
  const root = path.join(input.stateRoot, `root-${input.container}`);
  await createOldProductionInstall({
    hubOrigin: input.hubOrigin,
    oldProbeId: input.oldProbeId,
    productionRoot: root,
  });
  const unitPath = path.join(root, "etc/systemd/system/enoki-probe.service");
  const sudoersPath = path.join(root, "etc/sudoers.d/enoki-c4-installer");
  await mkdir(path.dirname(unitPath), { recursive: true });
  await mkdir(path.dirname(sudoersPath), { recursive: true });
  await writeFile(
    unitPath,
    "[Unit]\nDescription=Existing Enoki Probe\n\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n",
    { mode: 0o644 },
  );
  await writeFile(sudoersPath, "enoki-installer ALL=(root) NOPASSWD: ALL\n", {
    mode: 0o440,
  });
  await copyFile(
    input.sourceProbeBinary,
    path.join(root, "usr/local/bin/enoki-probe"),
  );
  await chmod(path.join(root, "usr/local/bin/enoki-probe"), 0o755);

  const started = await runCommand("docker", [
    "run",
    "--detach",
    "--privileged",
    "--cgroupns=host",
    "--name",
    input.container,
    systemdImage!,
    "/sbin/init",
  ]);
  expect(started.code, started.stderr).toBe(0);
  await waitForSystemd(input.container);
  await requireCommand("docker", [
    "exec",
    input.container,
    "mount",
    "--make-shared",
    "/run",
  ]);
  await requireCommand("docker", ["cp", `${root}/.`, `${input.container}:/`]);
  await requireCommand("docker", [
    "cp",
    input.assetDir,
    `${input.container}:/opt/enoki-assets`,
  ]);
  await requireCommand("docker", [
    "cp",
    input.acquirerPath,
    `${input.container}:/opt/enoki-probe-bootstrap-acquire`,
  ]);
  await requireCommand("docker", [
    "cp",
    input.lifecycleCompanionPath,
    `${input.container}:/opt/enoki-probe-lifecycle-companion`,
  ]);
  for (const command of [
    ["groupadd", "--system", "enoki-probe"],
    [
      "useradd",
      "--system",
      "--gid",
      "enoki-probe",
      "--home-dir",
      "/var/lib/enoki-probe",
      "--shell",
      "/usr/sbin/nologin",
      "enoki-probe",
    ],
    ["useradd", "--create-home", "--shell", "/bin/bash", "enoki-installer"],
    ["chown", "-R", "enoki-installer:enoki-installer", "/opt/enoki-assets"],
    ["chmod", "0700", "/opt/enoki-assets"],
    ["chmod", "0755", "/opt/enoki-probe-bootstrap-acquire"],
    ["chmod", "0755", "/opt/enoki-probe-lifecycle-companion"],
    ["systemctl", "daemon-reload"],
    ["systemctl", "enable", "enoki-probe.service"],
  ]) {
    const result = await docker(input.container, command);
    expect(result.code, `${command.join(" ")}: ${result.stderr}`).toBe(0);
  }
}

export async function runDockerAcquirer(input: {
  bundle: ProductionBundle;
  container: string;
  enrollment: string;
  hubOrigin: string;
}) {
  return await runCommand(
    "docker",
    [
      "exec",
      "--interactive",
      "--user",
      "enoki-installer",
      "--env",
      `ENOKI_HUB_URL=${input.hubOrigin}`,
      "--env",
      "ENOKI_PROBE_LOCAL_ASSET_DIR=/opt/enoki-assets",
      "--env",
      `ENOKI_PROBE_LOCAL_BUNDLE_ARCHIVE=/opt/enoki-assets/${path.basename(input.bundle.archivePath)}`,
      input.container,
      "/opt/enoki-probe-bootstrap-acquire",
    ],
    input.enrollment,
  );
}

async function waitForSystemd(container: string) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const state = await docker(container, ["systemctl", "is-system-running"]);
    if (state.stdout.trim() === "running") return;
    await delay(100);
  }
  throw new Error("systemd did not become running");
}

export async function currentDockerBridgeAddress() {
  const override = process.env.ENOKI_PRODUCTION_SYSTEMD_HUB_HOST;
  if (override) return override;
  const inspected = await runCommand("docker", [
    "inspect",
    "--format",
    '{{with index .NetworkSettings.Networks "bridge"}}{{.IPAddress}}{{end}}',
    os.hostname(),
  ]);
  const address = inspected.stdout.trim();
  if (inspected.code !== 0 || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) {
    throw new Error(
      `cannot resolve the workspace Docker bridge address: ${inspected.stderr}`,
    );
  }
  return address;
}

export async function waitForConfigRenameCrashAndDisarm(container: string) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const state = await docker(container, [
      "systemctl",
      "show",
      "--property=ActiveState",
      "--property=ExecMainStartTimestampMonotonic",
      "--property=ExecMainStatus",
      "--property=NRestarts",
      "--property=SubState",
      "enoki-probe.service",
    ]);
    const properties = Object.fromEntries(
      state.stdout
        .trim()
        .split("\n")
        .map((line) => line.split(/=(.*)/s).slice(0, 2)),
    );
    if (
      state.code === 0 &&
      properties.ActiveState === "activating" &&
      Number(properties.ExecMainStatus) === 6 &&
      properties.SubState === "auto-restart"
    ) {
      const disarmed = await docker(container, [
        "systemctl",
        "unset-environment",
        "ENOKI_TEST_SECURE_FILE_PATH",
        "ENOKI_TEST_SECURE_FILE_CRASH_POINT",
      ]);
      expect(disarmed.code, disarmed.stderr).toBe(0);
      const managerEnvironment = await docker(container, [
        "systemctl",
        "show-environment",
      ]);
      expect(managerEnvironment.code, managerEnvironment.stderr).toBe(0);
      expect(managerEnvironment.stdout).not.toContain(
        "ENOKI_TEST_SECURE_FILE_",
      );
      return {
        activeState: properties.ActiveState,
        execMainStartTimestampMonotonic:
          properties.ExecMainStartTimestampMonotonic,
        execMainStatus: Number(properties.ExecMainStatus),
        nRestarts: Number(properties.NRestarts),
        subState: properties.SubState,
      };
    }
    await delay(250);
  }
  const status = await docker(container, [
    "systemctl",
    "status",
    "--no-pager",
    "enoki-probe.service",
  ]);
  throw new Error(
    `Probe did not stop at the first config rename crash:\n${status.stdout}\n${status.stderr}`,
  );
}

async function expectProcFactsHiddenInCanonicalServices(container: string) {
  const hiddenProcPaths = [
    "/proc/stat",
    "/proc/loadavg",
    "/proc/meminfo",
    "/proc/uptime",
    "/proc/cpuinfo",
    "/proc/mounts",
    "/proc/net/dev",
    "/proc/net/route",
    "/proc/net/ipv6_route",
    "/proc/diskstats",
    "/proc/sys/kernel/hostname",
    "/proc/sys/kernel/osrelease",
  ];
  for (const service of [
    "enoki-probe.service",
    "enoki-observation-runtime.service",
  ]) {
    const mainPid = await docker(container, [
      "systemctl",
      "show",
      "--property=MainPID",
      "--value",
      service,
    ]);
    expect(mainPid.code, `${service}: ${mainPid.stderr}`).toBe(0);
    const pid = Number(mainPid.stdout.trim());
    expect(pid, `${service} must have a live main process`).toBeGreaterThan(1);
    for (const hiddenPath of hiddenProcPaths) {
      const hidden = await docker(container, [
        "nsenter",
        `--mount=/proc/${pid}/ns/mnt`,
        "--",
        "test",
        "!",
        "-e",
        hiddenPath,
      ]);
      expect(hidden.code, `${service} can still see ${hiddenPath}`).toBe(0);
    }
  }
}

function delay(milliseconds: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

export async function overwriteContainerFile(
  container: string,
  filePath: string,
  contents: string,
) {
  const overwritten = await runCommand(
    "docker",
    ["exec", "--interactive", container, "tee", filePath],
    contents,
  );
  expect(overwritten.code, overwritten.stderr).toBe(0);
}

export { expectProcFactsHiddenInCanonicalServices };
