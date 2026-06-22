import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { expect, test } from "vitest";

const execFileAsync = promisify(execFile);

test("oxlint reports and fixes Tailwind canonical classes", async () => {
  const directory = await mkdtemp(
    join(process.cwd(), "apps/web/src/.tailwind-lint-"),
  );
  const filename = join(directory, "canonical.tsx");

  try {
    await writeFile(
      filename,
      'export const node = <div className="break-words" />;\n',
    );

    const lint = await execOxlint(filename);
    expect(lint.exitCode).toBe(1);
    expect(lint.stdout).toContain(
      "better-tailwindcss(enforce-canonical-classes)",
    );
    expect(lint.stdout).toContain("wrap-break-word");

    const fix = await execOxlint(filename, "--fix");
    expect(fix.exitCode).toBe(0);
    await expect(readFile(filename, "utf8")).resolves.toContain(
      "wrap-break-word",
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

async function execOxlint(filename, ...extraArgs) {
  try {
    const { stderr, stdout } = await execFileAsync(
      "pnpm",
      [
        "exec",
        "oxlint",
        filename,
        "--config",
        "oxlint.config.ts",
        "--format",
        "json",
        ...extraArgs,
      ],
      {
        cwd: process.cwd(),
      },
    );

    return { exitCode: 0, stderr, stdout };
  } catch (error) {
    return {
      exitCode: error.code,
      stderr: error.stderr ?? "",
      stdout: error.stdout ?? "",
    };
  }
}
