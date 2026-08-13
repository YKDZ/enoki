import { spawn } from "node:child_process";

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
    let stdout = "";
    let stderr = "";
    let spawnError;
    let timedOut = false;

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout = appendBounded(stdout, chunk, outputLimitBytes);
    });
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk, outputLimitBytes);
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
        if (!timedOut || child.exitCode !== null) return;
        killProcessTree(child.pid, "SIGKILL");
      },
      timeoutMs + (options.killGraceMs ?? defaultKillGraceMs),
    );

    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      clearTimeout(forceKill);
      const result = sanitizeResult(
        { code: code ?? 1, signal, stderr, stdout },
        options.redactions ?? [],
      );
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

function appendBounded(existing, chunk, limitBytes) {
  const combined = `${existing}${chunk}`;
  if (Buffer.byteLength(combined) <= limitBytes) return combined;
  return Buffer.from(combined).subarray(0, limitBytes).toString("utf8");
}

function sanitizeResult(result, redactions) {
  return {
    ...result,
    stderr: redact(result.stderr, redactions),
    stdout: redact(result.stdout, redactions),
  };
}

function redact(value, redactions) {
  return redactions
    .filter((secret) => typeof secret === "string" && secret.length > 0)
    .reduce((safe, secret) => safe.split(secret).join("[REDACTED]"), value);
}

function truncateUtf8(value, limitBytes) {
  if (Buffer.byteLength(value) <= limitBytes) return value;
  return (
    Buffer.from(value)
      .subarray(0, Math.max(0, limitBytes - 3))
      .toString("utf8") + "..."
  );
}
