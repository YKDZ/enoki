import { execFileSync } from "node:child_process";
import { createServer } from "node:http";

import { describe, expect, it } from "vitest";

import { runBoundedProcess } from "../apps/hub/scripts/bounded-process.mjs";
import { createContainerFetchSource } from "../apps/hub/scripts/container-http.mjs";
import { formatFailureDiagnostic } from "../apps/hub/scripts/safe-diagnostics.mjs";

describe("Hub container logging evidence process boundary", () => {
  it("strongly terminates a command that ignores the graceful timeout signal", async () => {
    const startedAt = Date.now();
    let error;

    try {
      await runBoundedProcess(
        "run hanging fixture",
        process.execPath,
        [
          "--input-type=module",
          "--eval",
          "process.on('SIGTERM', () => {}); console.log(process.pid); setInterval(() => {}, 1000);",
        ],
        { killGraceMs: 20, timeoutMs: 80 },
      );
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(Error);
    expect(error.message).toContain("timed out");
    expect(Date.now() - startedAt).toBeLessThan(2_000);

    const childPid = Number.parseInt(error.stdout, 10);
    expect(Number.isSafeInteger(childPid)).toBe(true);
    expect(() => execFileSync("kill", ["-0", String(childPid)])).toThrow();
  });

  it("reports bounded redacted output when a command fails", async () => {
    const secret = "seeded-runner-secret-never-report";
    let error;

    try {
      await runBoundedProcess(
        "run failing fixture",
        process.execPath,
        [
          "--input-type=module",
          "--eval",
          `console.log('${secret}', '密'.repeat(2000)); console.error('stderr-${secret}'); process.exit(7);`,
        ],
        {
          diagnosticLimitBytes: 512,
          redactions: [secret],
          timeoutMs: 1_000,
        },
      );
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(Error);
    expect(error.message).toContain("stdout:");
    expect(error.message).toContain("stderr:");
    expect(error.message).toContain("[REDACTED]");
    expect(error.message).not.toContain(secret);
    expect(Buffer.byteLength(error.message)).toBeLessThanOrEqual(512);
    expect(error.stdout).not.toContain(secret);
    expect(error.stderr).not.toContain(secret);
  });

  it("aborts a container HTTP request inside its own fixed budget", async () => {
    const server = createServer(() => {});
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const startedAt = Date.now();

    try {
      await expect(
        runBoundedProcess(
          "run hanging HTTP fixture",
          process.execPath,
          ["--input-type=module", "--eval", createContainerFetchSource(50)],
          {
            environment: {
              ENOKI_EVIDENCE_METHOD: "GET",
              ENOKI_EVIDENCE_URL: `http://127.0.0.1:${address.port}`,
            },
            timeoutMs: 1_000,
          },
        ),
      ).rejects.toThrow();
      expect(Date.now() - startedAt).toBeLessThan(500);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("includes bounded redacted container evidence after an assertion failure", () => {
    const secret = "seeded-diagnostic-secret-never-report";
    const diagnostic = formatFailureDiagnostic(
      new Error("missing expected listener event"),
      [
        {
          name: "runtime",
          state: `running ${secret}`,
          stderr: `stderr ${secret}`,
          stdout: `stdout ${secret} ${"x".repeat(4_000)}`,
        },
      ],
      { limitBytes: 768, redactions: [secret] },
    );

    expect(diagnostic).toContain("missing expected listener event");
    expect(diagnostic).toContain("container runtime");
    expect(diagnostic).toContain("state:");
    expect(diagnostic).toContain("stdout:");
    expect(diagnostic).toContain("stderr:");
    expect(diagnostic).toContain("[REDACTED]");
    expect(diagnostic).not.toContain(secret);
    expect(Buffer.byteLength(diagnostic)).toBeLessThanOrEqual(768);
  });
});
