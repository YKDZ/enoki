import { readFile } from "node:fs/promises";
import path from "node:path";

export type ProbeUpgradeNonUpgradeableReason =
  | "probe_asset_set_version_missing"
  | "probe_asset_set_version_malformed"
  | "probe_version_missing"
  | "probe_version_malformed"
  | "probe_version_development"
  | "probe_version_current"
  | "probe_version_newer";

export type ProbeUpgradeEligibility = {
  currentProbeAssetSetVersion: string | null;
  currentProbeVersion: string | null;
  isUpgradeable: boolean;
  nonUpgradeableReason: ProbeUpgradeNonUpgradeableReason | null;
};

type SemVer = {
  major: number;
  minor: number;
  patch: number;
};

const semverPattern = /^v?(\d+)\.(\d+)\.(\d+)$/;

export function probeAssetSetVersionFromManifest(
  manifestJson: string,
): string | null {
  let manifest: unknown;
  try {
    manifest = JSON.parse(manifestJson) as unknown;
  } catch {
    return null;
  }

  if (!manifest || typeof manifest !== "object") {
    return null;
  }

  const version = (manifest as { version?: unknown }).version;
  if (typeof version !== "string") {
    return null;
  }

  return normalizeSemVer(version);
}

export async function readProbeAssetSetVersionFromDirectory(
  assetDir: string,
): Promise<string | null> {
  try {
    const manifest = await readFile(
      path.join(assetDir, "manifest.json"),
      "utf8",
    );

    return probeAssetSetVersionFromManifest(manifest);
  } catch (error) {
    if (error instanceof Error && "code" in error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") {
        return null;
      }
    }

    throw error;
  }
}

export function evaluateProbeUpgradeEligibility(input: {
  probeAssetSetVersion: string | null | undefined;
  probeVersion: string | null | undefined;
}): ProbeUpgradeEligibility {
  const assetSetVersion = normalizeSemVer(input.probeAssetSetVersion);
  const probeVersion = normalizeSemVer(input.probeVersion);
  const rawProbeVersion =
    typeof input.probeVersion === "string" && input.probeVersion.trim()
      ? input.probeVersion.trim()
      : null;

  if (
    !input.probeAssetSetVersion ||
    !String(input.probeAssetSetVersion).trim()
  ) {
    return notUpgradeable({
      currentProbeAssetSetVersion: null,
      currentProbeVersion: probeVersion,
      reason: "probe_asset_set_version_missing",
    });
  }

  if (!assetSetVersion) {
    return notUpgradeable({
      currentProbeAssetSetVersion: null,
      currentProbeVersion: probeVersion,
      reason: "probe_asset_set_version_malformed",
    });
  }

  if (!input.probeVersion || !String(input.probeVersion).trim()) {
    return notUpgradeable({
      currentProbeAssetSetVersion: assetSetVersion,
      currentProbeVersion: null,
      reason: "probe_version_missing",
    });
  }

  if (!probeVersion) {
    return notUpgradeable({
      currentProbeAssetSetVersion: assetSetVersion,
      currentProbeVersion: rawProbeVersion,
      reason: input.probeVersion.toLowerCase().includes("dev")
        ? "probe_version_development"
        : "probe_version_malformed",
    });
  }

  const comparison = compareSemVer(probeVersion, assetSetVersion);
  if (comparison < 0) {
    return {
      currentProbeAssetSetVersion: assetSetVersion,
      currentProbeVersion: probeVersion,
      isUpgradeable: true,
      nonUpgradeableReason: null,
    };
  }

  return notUpgradeable({
    currentProbeAssetSetVersion: assetSetVersion,
    currentProbeVersion: probeVersion,
    reason: comparison === 0 ? "probe_version_current" : "probe_version_newer",
  });
}

function notUpgradeable(input: {
  currentProbeAssetSetVersion: string | null;
  currentProbeVersion: string | null;
  reason: ProbeUpgradeNonUpgradeableReason;
}): ProbeUpgradeEligibility {
  return {
    currentProbeAssetSetVersion: input.currentProbeAssetSetVersion,
    currentProbeVersion: input.currentProbeVersion,
    isUpgradeable: false,
    nonUpgradeableReason: input.reason,
  };
}

function normalizeSemVer(value: string | null | undefined) {
  if (typeof value !== "string") {
    return null;
  }

  const match = semverPattern.exec(value.trim());
  if (!match) {
    return null;
  }

  return `${Number(match[1])}.${Number(match[2])}.${Number(match[3])}`;
}

function parseSemVer(version: string): SemVer {
  const match = semverPattern.exec(version);
  if (!match) {
    throw new Error(`Invalid SemVer: ${version}`);
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

function compareSemVer(left: string, right: string) {
  const leftVersion = parseSemVer(left);
  const rightVersion = parseSemVer(right);

  return (
    leftVersion.major - rightVersion.major ||
    leftVersion.minor - rightVersion.minor ||
    leftVersion.patch - rightVersion.patch
  );
}
