// 受保护签名来源内的有限转换分类声明：只固定已批准的相邻版本对，并与同运行真实
// Release Baseline 交叉核对。未声明的版本对直接失败，不回落默认分类，也不对外
// 提供可配置的策略注册表。
import type { ReleaseTransitionClassification } from "@enoki/probe-release";

export type ReleaseTransitionDeclaration = Readonly<{
  baselineIsTrustEpochMigration: boolean;
  classification: ReleaseTransitionClassification;
  sourceVersion: string;
  targetVersion: string;
}>;

type DeclaredReleaseTransition = Readonly<{
  classification: ReleaseTransitionClassification;
  requiresTrustEpochMigration: boolean;
  sourceVersion: string;
  targetVersion: string;
}>;

const declaredReleaseTransitions: readonly DeclaredReleaseTransition[] = [
  {
    classification: "replacement-required",
    requiresTrustEpochMigration: true,
    sourceVersion: "0.1.74",
    targetVersion: "0.1.75",
  },
  {
    classification: "compatible",
    requiresTrustEpochMigration: false,
    sourceVersion: "0.1.75",
    targetVersion: "0.1.76",
  },
];

export function declareReleaseTransition({
  baselineIsTrustEpochMigration,
  sourceVersion,
  targetVersion,
}: {
  baselineIsTrustEpochMigration: boolean;
  sourceVersion: string;
  targetVersion: string;
}): ReleaseTransitionDeclaration {
  const declared = declaredReleaseTransitions.find(
    (entry) =>
      entry.sourceVersion === sourceVersion &&
      entry.targetVersion === targetVersion,
  );
  if (!declared) {
    throw new Error(
      `Release Transition classification is not declared for ${sourceVersion} -> ${targetVersion}`,
    );
  }
  if (declared.requiresTrustEpochMigration !== baselineIsTrustEpochMigration) {
    throw new Error(
      "Release Transition declaration does not match the verified Release Baseline",
    );
  }
  return {
    baselineIsTrustEpochMigration,
    classification: declared.classification,
    sourceVersion,
    targetVersion,
  };
}
