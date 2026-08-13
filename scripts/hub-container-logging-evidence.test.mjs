import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { describe, expect, it } from "vitest";

import { runBoundedProcess } from "../apps/hub/scripts/bounded-process.mjs";
import { createContainerFetchSource } from "../apps/hub/scripts/container-http.mjs";
import { formatFailureDiagnostic } from "../apps/hub/scripts/safe-diagnostics.mjs";
import { createRedactingBoundedBuffer } from "../apps/hub/scripts/safe-output.mjs";

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

  it("kills a descendant holding stdio after its timed-out leader exits", async () => {
    const fixtureDirectory = await mkdtemp(
      path.join(tmpdir(), "enoki-bounded-process-tree-"),
    );
    const pidsPath = path.join(fixtureDirectory, "pids.json");
    const fixture = [
      "const { spawn } = await import('node:child_process');",
      "const { writeFileSync } = await import('node:fs');",
      "const descendant = spawn(process.execPath, ['--input-type=module', '--eval', `process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);`], { stdio: ['ignore', 'inherit', 'inherit'] });",
      "writeFileSync(process.env.PIDS_PATH, JSON.stringify({ leader: process.pid, descendant: descendant.pid }));",
      "process.once('SIGTERM', () => process.exit(0));",
      "setInterval(() => {}, 1000);",
    ].join("\n");
    const running = runBoundedProcess(
      "run leader-exit fixture",
      process.execPath,
      ["--input-type=module", "--eval", fixture],
      {
        environment: { PIDS_PATH: pidsPath },
        killGraceMs: 30,
        timeoutMs: 100,
      },
    );

    let pids;
    try {
      const deadline = Date.now() + 1_000;
      while (!pids && Date.now() < deadline) {
        try {
          pids = JSON.parse(await readFile(pidsPath, "utf8"));
        } catch {
          await delay(10);
        }
      }
      expect(pids).toBeDefined();

      const outcome = await Promise.race([
        running.then(
          () => "settled",
          () => "settled",
        ),
        delay(400, "hung"),
      ]);
      expect(outcome).toBe("settled");
      expect(() =>
        execFileSync("kill", ["-0", String(pids.descendant)]),
      ).toThrow();
    } finally {
      if (pids?.leader) {
        try {
          process.kill(-pids.leader, "SIGKILL");
        } catch {
          // The runner already removed the complete process group.
        }
      }
      await running.catch(() => {});
      await rm(fixtureDirectory, { force: true, recursive: true });
    }
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

  it("redacts a secret crossing the bounded output cutoff", async () => {
    const secret = "ZXQ987-secret-never-report";
    let error;

    try {
      await runBoundedProcess(
        "run boundary fixture",
        process.execPath,
        [
          "--input-type=module",
          "--eval",
          `process.stdout.write('${"x".repeat(58)}'); process.stdout.write('${secret}'); process.stderr.write('${"y".repeat(58)}${secret}'); process.exit(9);`,
        ],
        {
          diagnosticLimitBytes: 512,
          outputLimitBytes: 64,
          redactions: [secret],
          timeoutMs: 1_000,
        },
      );
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(Error);
    expect(error.stdout).not.toContain(secret.slice(0, 6));
    expect(error.stderr).not.toContain(secret.slice(0, 6));
    expect(error.message).not.toContain(secret.slice(0, 6));
    expect(Buffer.byteLength(error.stdout)).toBeLessThanOrEqual(64);
    expect(Buffer.byteLength(error.stderr)).toBeLessThanOrEqual(64);
  });

  it("keeps only bounded output and seed overlap while redacting split chunks", () => {
    const secret = "split-secret-never-report";
    const output = createRedactingBoundedBuffer(64, [secret]);
    const input = `${"a".repeat(58)}${secret}${"b".repeat(100_000)}`;

    for (const character of input) {
      output.append(character);
      expect(output.bufferedBytes()).toBeLessThanOrEqual(
        64 + Buffer.byteLength(secret),
      );
    }

    const value = output.value();
    expect(value).not.toContain(secret);
    expect(value).not.toContain(secret.slice(0, 6));
    expect(Buffer.byteLength(value)).toBeLessThanOrEqual(64);
    expect(Buffer.from(value).toString("utf8")).toBe(value);
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
    const secret = "DGN987-diagnostic-secret-never-report";
    const diagnostic = formatFailureDiagnostic(
      new Error("missing expected listener event"),
      [
        {
          name: "runtime",
          state: `running ${secret}`,
          stderr: `stderr ${secret}`,
          stdout: `stdout ${"x".repeat(165)}${secret}${"x".repeat(4_000)}`,
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
    expect(diagnostic).not.toContain(secret.slice(0, 6));
    expect(Buffer.byteLength(diagnostic)).toBeLessThanOrEqual(768);
  });
});
