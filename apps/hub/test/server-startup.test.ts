import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const hubRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

describe("Hub server startup", () => {
  it("prints the fixed legacy-variable migration from the actual server process", async () => {
    const secret = "legacy-value-must-not-be-logged";
    const result = await runServer({
      ENOKI_MANAGEMENT_ORIGIN: "https://manage.example",
      ENOKI_PUBLIC_HUB_URL: secret,
      OWNER_PASSWORD: "test-owner-password",
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      '"configurationMessage":"ENOKI_PUBLIC_HUB_URL has been removed. Set ENOKI_MANAGEMENT_ORIGIN and, when the Probe API differs, ENOKI_PROBE_API_ORIGIN."',
    );
    expect(`${result.stdout}${result.stderr}`).not.toContain(secret);
  });
});

function runServer(environment: Record<string, string>) {
  return new Promise<{ code: number | null; stderr: string; stdout: string }>(
    (resolve, reject) => {
      const server = spawn(process.execPath, ["dist/src/server.js"], {
        cwd: hubRoot,
        env: { ...process.env, ...environment },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      server.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString();
      });
      server.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString();
      });
      server.once("error", reject);
      server.once("close", (code) => resolve({ code, stderr, stdout }));
    },
  );
}
