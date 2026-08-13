import { spawn } from "node:child_process";

import { createRedactingBoundedBuffer, truncateUtf8 } from "./safe-output.mjs";

const defaultKillGraceMs = 1_000;
const defaultDiagnosticLimitBytes = 4 * 1024;
const defaultOutputLimitBytes = 8 * 1024;

export function runBoundedProcess(label, command, args, options = {}) {
  const timeoutMs = options.timeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error("A positive process timeout is required.");
  }

  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const child = spawn(command, args, {
      detached: process.platform !== "win32",
      env: options.environment
        ? { ...process.env, ...options.environment }
        : process.env,
      signal: controller.signal,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const outputLimitBytes =
      options.outputLimitBytes ?? defaultOutputLimitBytes;
    const stdout = createRedactingBoundedBuffer(
      outputLimitBytes,
      options.redactions,
    );
    const stderr = createRedactingBoundedBuffer(
      outputLimitBytes,
      options.redactions,
    );
    let spawnError;
    let settled = false;
    let timedOut = false;

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout.append(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr.append(chunk);
    });
    child.once("error", (error) => {
      if (error.name !== "AbortError") spawnError = error;
    });

    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    const forceKill = setTimeout(
      () => {
        if (!timedOut || settled) return;
        killProcessTree(child.pid, "SIGKILL");
      },
      timeoutMs + (options.killGraceMs ?? defaultKillGraceMs),
    );

    child.once("close", (code, signal) => {
      settled = true;
      clearTimeout(timeout);
      clearTimeout(forceKill);
      const result = {
        code: code ?? 1,
        signal,
        stderr: stderr.value(),
        stdout: stdout.value(),
      };
      if (timedOut) {
        reject(
          processError(
            `${label} timed out after ${timeoutMs}ms.`,
            result,
            options.diagnosticLimitBytes,
          ),
        );
        return;
      }
      if (spawnError) {
        reject(
          processError(
            `Unable to ${label}: ${spawnError.message}`,
            result,
            options.diagnosticLimitBytes,
          ),
        );
        return;
      }
      if (result.code !== 0 && !options.allowFailure) {
        reject(
          processError(
            `Unable to ${label}: exited with code ${result.code}.`,
            result,
            options.diagnosticLimitBytes,
          ),
        );
        return;
      }
      resolve(result);
    });
  });
}

function killProcessTree(pid, signal) {
  if (!pid) return;
  try {
    process.kill(process.platform === "win32" ? pid : -pid, signal);
  } catch {
    // It already exited between the timeout and the kill attempt.
  }
}

function processError(message, result, diagnosticLimitBytes) {
  const limit = diagnosticLimitBytes ?? defaultDiagnosticLimitBytes;
  const streamLimit = Math.max(
    0,
    Math.floor((limit - message.length - 20) / 2),
  );
  const diagnostic = [
    message,
    `stdout: ${truncateUtf8(result.stdout, streamLimit)}`,
    `stderr: ${truncateUtf8(result.stderr, streamLimit)}`,
  ].join("\n");
  return Object.assign(new Error(truncateUtf8(diagnostic, limit)), result);
}
