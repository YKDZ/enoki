import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import {
  assertListenerConsoleEvidence,
  parseContainerJsonLines,
} from "./container-logging-contract.mjs";

const image = readImage(process.argv.slice(2));
const name = `enoki-hub-logging-${randomUUID().replaceAll("-", "").slice(0, 16)}`;
const dockerTimeoutMs = 15_000;
const outputLimitBytes = 16 * 1024;
const startupTimeoutMs = 30_000;

try {
  await requireDocker();
  await startContainer();
  await Promise.all([waitForHealth(3000), waitForHealth(3001)]);
  await stopContainer();

  const logs = await runDocker("读取 Hub 容器控制台日志", ["logs", name]);
  const events = parseContainerJsonLines(`${logs.stdout}${logs.stderr}`);
  assertListenerConsoleEvidence(events);
  console.log("Hub 容器控制台日志合同验证通过。");
} catch (error) {
  const diagnostic = await collectDiagnostic();
  console.error(`Hub 容器控制台日志合同失败：${message(error)}\n${diagnostic}`);
  process.exitCode = 1;
} finally {
  await runDocker("清理 Hub 容器", ["rm", "--force", "--volumes", name], {
    allowFailure: true,
  });
}

function readImage(args) {
  const index = args.indexOf("--image");
  const value = index === -1 ? undefined : args[index + 1];
  if (!value || value.startsWith("-")) {
    throw new Error("用法：--image <标准生产 Hub 镜像>");
  }
  return value;
}

async function requireDocker() {
  const version = await runDocker(
    "确认 Docker Engine 可用",
    ["version", "--format", "{{.Server.Version}}"],
    { allowFailure: true },
  );
  if (version.code !== 0)
    throw new Error("需要 Docker Engine 才能执行此容器合同。");
}

async function startContainer() {
  await runDocker("启动标准生产 Hub 镜像", [
    "run",
    "--detach",
    "--name",
    name,
    "--network",
    "none",
    "--tmpfs",
    "/data:rw,noexec,nosuid,size=16m,mode=0700",
    "--env",
    "OWNER_PASSWORD=container-contract-owner-password",
    "--env",
    "ENOKI_HUB_LOG_LEVEL=debug",
    "--env",
    "ENOKI_MANAGEMENT_ORIGIN=http://127.0.0.1",
    "--env",
    "ENOKI_PROBE_API_ORIGIN=http://127.0.0.1",
    "--env",
    "ENOKI_METRICS_ARCHIVE_ENABLED=false",
    image,
  ]);
}

async function waitForHealth(port) {
  const deadline = Date.now() + startupTimeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await request(port);
      if (response.status === 200) return;
    } catch {
      // 监听器仍在启动，继续在固定期限内重试。
    }
    await delay(200);
  }
  throw new Error(`端口 ${port} 的 Hub listener 未在期限内就绪。`);
}

async function request(port) {
  const result = await runDocker("请求 Hub listener", [
    "exec",
    "--user",
    "node",
    name,
    "node",
    "--input-type=module",
    "--eval",
    [
      `const response = await fetch("http://127.0.0.1:${port}/api/health", {`,
      "  signal: AbortSignal.timeout(2000),",
      "});",
      "console.log(JSON.stringify({ status: response.status }));",
    ].join("\n"),
  ]);
  return JSON.parse(result.stdout);
}

async function stopContainer() {
  await runDocker("优雅停止 Hub 容器", ["kill", "--signal=SIGTERM", name]);
  const deadline = Date.now() + startupTimeoutMs;
  while (Date.now() < deadline) {
    const state = await runDocker("检查 Hub 容器状态", [
      "inspect",
      "--format",
      "{{.State.Running}}",
      name,
    ]);
    if (state.stdout.trim() === "false") return;
    await delay(100);
  }
  throw new Error("Hub 容器未在优雅关闭期限内退出。");
}

async function collectDiagnostic() {
  const result = await runDocker("读取失败诊断", ["logs", name], {
    allowFailure: true,
    timeoutMs: 5_000,
  });
  return truncate(`${result.stdout}${result.stderr}`, 4 * 1024);
}

function runDocker(label, args, options = {}) {
  return runCommand("docker", args, {
    allowFailure: options.allowFailure,
    label,
    timeoutMs: options.timeoutMs ?? dockerTimeoutMs,
  });
}

function runCommand(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, options.timeoutMs);
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout = appendBounded(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk);
    });
    child.once("error", reject);
    child.once("close", (code) => {
      clearTimeout(timeout);
      const result = {
        code: code ?? 1,
        stderr,
        stdout,
      };
      if ((timedOut || result.code !== 0) && !options.allowFailure) {
        const reason = timedOut
          ? `在 ${options.timeoutMs}ms 后超时`
          : `失败（退出码 ${result.code}）`;
        reject(
          new Error(
            `${options.label}${reason}：${result.stderr || result.stdout}`,
          ),
        );
        return;
      }
      resolve(result);
    });
  });
}

function truncate(value, limit) {
  return Buffer.byteLength(value) <= limit
    ? value
    : Buffer.from(value).subarray(0, limit).toString("utf8");
}

function appendBounded(current, chunk) {
  return truncate(`${current}${chunk}`, outputLimitBytes);
}

function message(error) {
  return error instanceof Error ? error.message : String(error);
}
