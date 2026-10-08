#!/usr/bin/env node
// 标准 CI 发布前置取证入口：在同一 workflow、main 分支、精确候选 SHA 的 push 或
// workflow_dispatch 运行中先选数值最大的 run，再核验其当前 attempt 的完整七项检查，
// 写出 schema2 证据供最终验收汇总按同一判据消费。

import { readFile, writeFile } from "node:fs/promises";

import {
  assertCandidateCommit,
  assertStandardCiRunSucceeded,
  createStandardCiEvidence,
  readStandardCiJobEvidence,
  selectStandardCiRun,
  type StandardCiRun,
} from "./release-ci-evidence.ts";

const usage = `Usage:
  node scripts/release-ci.ts select --commit <commit> --workflow-runs <path>
  node scripts/release-ci.ts verify --commit <commit> --jobs <path> --output <path> --workflow-runs <path>`;

const selectOptions = ["--commit", "--workflow-runs"] as const;
const verifyOptions = [
  "--commit",
  "--jobs",
  "--output",
  "--workflow-runs",
] as const;

type SelectOptions = Record<(typeof selectOptions)[number], string>;
type VerifyOptions = Record<(typeof verifyOptions)[number], string>;

try {
  const [command, ...arguments_] = process.argv.slice(2);
  if (command === "select") {
    const { run } = await resolveSucceededRun(
      parseOptions(arguments_, selectOptions),
    );
    process.stdout.write(`${run.id} ${run.attempt}\n`);
  } else if (command === "verify") {
    await verify(parseOptions(arguments_, verifyOptions));
  } else {
    throw new Error(usage);
  }
} catch (error) {
  process.stderr.write(`release-ci: ${errorMessage(error)}\n`);
  process.exitCode = 1;
}

async function resolveSucceededRun(
  options: SelectOptions | VerifyOptions,
): Promise<{ commit: string; run: StandardCiRun }> {
  const commit = assertCandidateCommit(options["--commit"]);
  const runsDocument = await readJson(
    options["--workflow-runs"],
    "standard CI workflow runs",
  );
  const run = selectStandardCiRun(runsDocument, commit);
  assertStandardCiRunSucceeded(run);
  return { commit, run };
}

async function verify(options: VerifyOptions): Promise<void> {
  const { commit, run } = await resolveSucceededRun(options);
  const jobsDocument = await readJson(options["--jobs"], "standard CI jobs");
  const evidence = createStandardCiEvidence(
    commit,
    run,
    readStandardCiJobEvidence(jobsDocument, run, commit),
  );
  await writeFile(
    options["--output"],
    `${JSON.stringify(evidence, null, 2)}\n`,
  );
}

function parseOptions<Option extends string>(
  arguments_: readonly string[],
  allowed: readonly Option[],
): Record<Option, string> {
  const allowedNames: ReadonlySet<string> = new Set(allowed);
  const options: Partial<Record<Option, string>> = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const option = arguments_[index] as Option | undefined;
    const value = arguments_[index + 1];
    if (
      option === undefined ||
      !allowedNames.has(option) ||
      value === undefined ||
      value.startsWith("--")
    ) {
      throw new Error(
        `invalid or missing option: ${arguments_[index] ?? "<missing>"}`,
      );
    }
    if (Object.hasOwn(options, option)) {
      throw new Error(`duplicate option: ${option}`);
    }
    options[option] = value;
  }
  for (const option of allowed) {
    if (!Object.hasOwn(options, option)) {
      throw new Error(`required option is missing: ${option}`);
    }
  }

  return options as Record<Option, string>;
}

async function readJson(file: string, description: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch {
    throw new Error(`${description} is not valid JSON`);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
