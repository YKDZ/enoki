import { spawnSync } from "node:child_process";

const task = process.argv[2];
const command =
  task === "format:check"
    ? ["exec", "oxfmt", "--list-different", "--config", "oxfmt.config.ts", "."]
    : task === "format:write"
      ? ["exec", "oxfmt", "--write", "--config", "oxfmt.config.ts", "."]
      : task === "lint"
        ? [
            "exec",
            "oxlint",
            "--quiet",
            "--format=unix",
            "--config",
            "oxlint.config.ts",
            ".",
          ]
        : task === "lint:fix"
          ? [
              "exec",
              "oxlint",
              "--format=unix",
              "--config",
              "oxlint.config.ts",
              ".",
              "--fix",
            ]
          : undefined;

if (command === undefined) {
  throw new Error(`Unknown root-owned task: ${task ?? "(missing)"}`);
}

const result = spawnSync("pnpm", command, { stdio: "inherit" });
if (result.error !== undefined) throw result.error;
process.exitCode = result.status ?? 1;
