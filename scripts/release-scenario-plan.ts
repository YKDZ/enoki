#!/usr/bin/env node

// Release Scenario Plan 的编排闭包：把已签名候选、已验证 Transition Contract 与
// 受支持 Host 矩阵编译成场景计划，并按计划单元交付 provisioning 与清理归属。
// 纯编译判据留在 release-scenario-plan-compile.ts，本模块只负责消费与编排。

import path from "node:path";

import {
  releaseTransitionForValidatedCandidate,
  validateReleaseCandidate,
} from "./release-candidate-verification.ts";
import { readSupportedHostMatrix } from "./release-e2e-matrix.ts";
import {
  compileReleaseScenarioPlan,
  resolveReleaseScenarioPlanCell,
  type ReleaseScenarioPlan,
  type ScenarioPlanCell,
} from "./release-scenario-plan-compile.ts";

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
