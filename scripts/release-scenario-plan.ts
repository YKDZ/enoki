#!/usr/bin/env node

// Release Scenario Plan 的编排闭包与正式作业入口：把已签名候选、已验证 Transition
// Contract 与受支持 Host 矩阵编译成场景计划，并按计划单元交付 provisioning 与清理归属。
// 纯编译判据留在 release-scenario-plan-compile.ts，本模块只负责消费与编排。
// `release-scenario-plan.ts github-actions` 由发布工作流的 prepare-release-e2e-matrix
// 作业直接调用，该作业的参数解析与输出也由本模块承载。

import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  releaseTransitionForValidatedCandidate,
  validateReleaseCandidate,
} from "./release-candidate-verification.ts";
import { readSupportedHostMatrix } from "./release-e2e-matrix.ts";
import {
  compileReleaseScenarioPlan,
  createGitHubActionsScenarioMatrix,
  resolveReleaseScenarioPlanCell,
  type ReleaseScenarioPlan,
  type ScenarioPlanCell,
} from "./release-scenario-plan-compile.ts";

// 主模块判据与原作业壳一致：只有作为进程入口执行时才解析 argv 并写出矩阵，
// 被 Orchestrator 或测试导入时不产生副作用。
const processEntry = process.argv[1];
if (processEntry && import.meta.url === pathToFileURL(processEntry).href) {
  try {
    const options = parseReleaseScenarioPlanJobArguments(process.argv.slice(2));
    const trustedRootPublicKeyPem =
      process.env[options.rootPublicKeyEnvironment];
    const plan = await compileVerifiedReleaseScenarioPlan({
      candidateManifestPath: options.candidateManifestPath,
      matrixPath: options.matrixPath,
      trustedRootPublicKeyPem,
    });
    process.stdout.write(
      `${JSON.stringify(createGitHubActionsScenarioMatrix(plan))}\n`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`release-scenario-plan: ${message}\n`);
    process.exitCode = 1;
  }
}

// 已编译场景计划中单个 cell 的准备上下文；prepared 的具体形状由调用方的
// provision 适配器决定，Infrastructure Adapter 与 CLI 共用同一视图。
type ReleaseScenarioCellContext<Prepared> = {
  cell: ScenarioPlanCell;
  plan: ReleaseScenarioPlan;
  prepared: Prepared;
};

export async function compileVerifiedReleaseScenarioPlan({
  candidateManifestPath,
  matrixPath,
  trustedRootPublicKeyPem,
}: {
  candidateManifestPath: string;
  matrixPath: string;
  trustedRootPublicKeyPem?: string;
}): Promise<ReleaseScenarioPlan> {
  if (!trustedRootPublicKeyPem) {
    throw new Error("Release Scenario Planner requires the trusted root");
  }
  const candidateDir = path.dirname(path.resolve(candidateManifestPath));
  const candidateManifest = await validateReleaseCandidate(candidateDir, {
    trustedRootPublicKeyPem,
  });
  const releaseTransition =
    releaseTransitionForValidatedCandidate(candidateManifest);
  if (!releaseTransition) {
    throw new Error(
      "verified Release Transition Contract is required before Host provisioning",
    );
  }
  const supportedHostMatrix = await readSupportedHostMatrix(matrixPath);
  return compileReleaseScenarioPlan({
    candidateManifest,
    releaseTransition,
    supportedHostMatrix,
  });
}

// Provisioning 在 initialize 之前成功时，清理责任默认属于本函数；initialize 通过
// takeCleanupOwnership 明确接管后，本函数不再调用 release，保证原始失败不被覆盖。
export async function prepareReleaseScenarioCell<Initialized, Prepared>({
  cellId,
  compilePlan = async () => {
    throw new Error("Release Scenario Plan compiler is required");
  },
  initialize,
  provision,
  release,
}: {
  cellId: string;
  compilePlan?: () => Promise<ReleaseScenarioPlan>;
  initialize?: (
    context: ReleaseScenarioCellContext<Prepared> & {
      takeCleanupOwnership: () => void;
    },
  ) => Promise<Initialized>;
  provision: (cell: ScenarioPlanCell) => Promise<Prepared>;
  release?: (context: ReleaseScenarioCellContext<Prepared>) => Promise<unknown>;
}): Promise<{
  cell: ScenarioPlanCell;
  initialized: Initialized | undefined;
  plan: ReleaseScenarioPlan;
  prepared: Prepared;
}> {
  if (typeof provision !== "function") {
    throw new Error("Release Scenario Plan provisioning adapter is required");
  }
  const plan = await compilePlan();
  const cell = resolveReleaseScenarioPlanCell(plan, cellId);
  const prepared = await provision(cell);
  let cleanupOwnedByInitializer = false;
  try {
    const initialized = initialize
      ? await initialize({
          cell,
          plan,
          prepared,
          takeCleanupOwnership() {
            cleanupOwnedByInitializer = true;
          },
        })
      : undefined;
    return { cell, initialized, plan, prepared };
  } catch (error) {
    if (!cleanupOwnedByInitializer && typeof release === "function") {
      try {
        await release({ cell, plan, prepared });
      } catch (releaseError) {
        // 原实现把 release 的失败挂到原始错误对象上，抛出的仍是原始失败。
        if (error && typeof error === "object") {
          Object.assign(error, { releaseError });
        }
      }
    }
    throw error;
  }
}

// 作业参数表：只接受 `github-actions` 与按固定顺序给出的三个必填选项。原判据对
// 信任根环境变量名用 `?? ""` 归一后做正则校验，这里改为先确认它是 string 再校验，
// 缺失与非法名仍走同一条拒绝与同一文本。
function parseReleaseScenarioPlanJobArguments(argv: string[]): {
  candidateManifestPath: string;
  matrixPath: string;
  rootPublicKeyEnvironment: string;
} {
  if (argv[0] !== "github-actions" || argv.length !== 7) {
    throw new Error(
      "usage: release-scenario-plan.ts github-actions --candidate-manifest <path> --matrix <path> --root-public-key-env <name>",
    );
  }
  const values = Object.fromEntries([
    [argv[1], argv[2]],
    [argv[3], argv[4]],
    [argv[5], argv[6]],
  ] as const);
  const candidateManifestPath = values["--candidate-manifest"];
  const matrixPath = values["--matrix"];
  const rootPublicKeyEnvironment = values["--root-public-key-env"];
  if (
    !candidateManifestPath ||
    !matrixPath ||
    typeof rootPublicKeyEnvironment !== "string" ||
    !/^[A-Za-z_][A-Za-z0-9_]*$/.test(rootPublicKeyEnvironment)
  ) {
    throw new Error("Release Scenario Planner options are invalid");
  }
  return { candidateManifestPath, matrixPath, rootPublicKeyEnvironment };
}
