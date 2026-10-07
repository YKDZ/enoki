#!/usr/bin/env node

// GitHub Actions 场景计划作业入口：`release-scenario-plan.mjs github-actions` 由
// 发布工作流的 prepare-release-e2e-matrix 作业直接调用。计划编译与 provisioning
// 归属的唯一实现位于 release-scenario-plan.ts，本文件只保留该作业的参数解析与输出。

import { pathToFileURL } from "node:url";

import { createGitHubActionsScenarioMatrix } from "./release-scenario-plan-compile.ts";
import { compileVerifiedReleaseScenarioPlan } from "./release-scenario-plan.ts";

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  try {
    const options = parseOptions(process.argv.slice(2));
    const root = process.env[options.rootPublicKeyEnvironment];
    const plan = await compileVerifiedReleaseScenarioPlan({
      candidateManifestPath: options.candidateManifestPath,
      matrixPath: options.matrixPath,
      trustedRootPublicKeyPem: root,
    });
    process.stdout.write(
      `${JSON.stringify(createGitHubActionsScenarioMatrix(plan))}\n`,
    );
  } catch (error) {
    process.stderr.write(`release-scenario-plan: ${error.message}\n`);
    process.exitCode = 1;
  }
}

function parseOptions(arguments_) {
  if (arguments_[0] !== "github-actions" || arguments_.length !== 7) {
    throw new Error(
      "usage: release-scenario-plan.mjs github-actions --candidate-manifest <path> --matrix <path> --root-public-key-env <name>",
    );
  }
  const values = Object.fromEntries([
    [arguments_[1], arguments_[2]],
    [arguments_[3], arguments_[4]],
    [arguments_[5], arguments_[6]],
  ]);
  if (
    !values["--candidate-manifest"] ||
    !values["--matrix"] ||
    !/^[A-Za-z_][A-Za-z0-9_]*$/.test(values["--root-public-key-env"] ?? "")
  ) {
    throw new Error("Release Scenario Planner options are invalid");
  }
  return {
    candidateManifestPath: values["--candidate-manifest"],
    matrixPath: values["--matrix"],
    rootPublicKeyEnvironment: values["--root-public-key-env"],
  };
}
