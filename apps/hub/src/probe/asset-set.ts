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

type ProbeAssetSetVersionNonUpgradeableReason = Extract<
  ProbeUpgradeNonUpgradeableReason,
  "probe_asset_set_version_missing" | "probe_asset_set_version_malformed"
>;

export type ProbeAssetSetVersionResult = {
  version: string | null;
  nonUpgradeableReason: ProbeAssetSetVersionNonUpgradeableReason | null;
};

type SemVer = {
  major: bigint;
  minor: bigint;
  patch: bigint;
};

const semverPattern = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export function probeAssetSetVersionFromManifest(
  manifestJson: string,
): string | null {
  return probeAssetSetVersionResultFromManifest(manifestJson).version;
}

export function probeAssetSetVersionResultFromManifest(
  manifestJson: string,
): ProbeAssetSetVersionResult {
  let manifest: unknown;
  try {
    manifest = JSON.parse(manifestJson) as unknown;
  } catch {
    return probeAssetSetVersionResult(
      null,
      "probe_asset_set_version_malformed",
    );
  }

  if (!manifest || typeof manifest !== "object") {
    return probeAssetSetVersionResult(
      null,
      "probe_asset_set_version_malformed",
    );
  }

  const version = (manifest as { version?: unknown }).version;
  if (typeof version !== "string" || !version.trim()) {
    return probeAssetSetVersionResult(null, "probe_asset_set_version_missing");
  }

  const normalizedVersion = normalizeSemVer(version);
  if (!normalizedVersion) {
    return probeAssetSetVersionResult(
      null,
      "probe_asset_set_version_malformed",
    );
  }

  return probeAssetSetVersionResult(normalizedVersion, null);
}

export async function readProbeAssetSetVersionFromDirectory(
  assetDir: string,
): Promise<ProbeAssetSetVersionResult> {
  try {
    const manifest = await readFile(
      path.join(assetDir, "manifest.json"),
      "utf8",
    );

    return probeAssetSetVersionResultFromManifest(manifest);
  } catch (error) {
    if (error instanceof Error && "code" in error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") {
        return probeAssetSetVersionResult(
          null,
          "probe_asset_set_version_missing",
        );
      }
    }

    throw error;
  }
}

export function evaluateProbeUpgradeEligibility(input: {
  probeAssetSetVersionNonUpgradeableReason?: ProbeAssetSetVersionNonUpgradeableReason | null;
  probeAssetSetVersion: string | null | undefined;
  probeVersion: string | null | undefined;
}): ProbeUpgradeEligibility {
  const assetSetVersion = normalizeSemVer(input.probeAssetSetVersion);
  const probeVersion = normalizeSemVer(input.probeVersion);
  const rawProbeVersion =
    typeof input.probeVersion === "string" && input.probeVersion.trim()
      ? input.probeVersion.trim()
      : null;

  if (input.probeAssetSetVersionNonUpgradeableReason) {
    return notUpgradeable({
      currentProbeAssetSetVersion: null,
      currentProbeVersion: probeVersion,
      reason: input.probeAssetSetVersionNonUpgradeableReason,
    });
  }

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

function probeAssetSetVersionResult(
  version: string | null,
  nonUpgradeableReason: ProbeAssetSetVersionNonUpgradeableReason | null,
): ProbeAssetSetVersionResult {
  return {
    nonUpgradeableReason,
    version,
  };
}

function normalizeSemVer(value: string | null | undefined) {
  if (typeof value !== "string") {
    return null;
  }

  const parts = semVerParts(value.trim());
  if (!parts) {
    return null;
  }

  return parts.join(".");
}

function parseSemVer(version: string): SemVer {
  const parts = semVerParts(version);
  if (!parts) {
    throw new Error(`Invalid SemVer: ${version}`);
  }

  return {
    major: BigInt(parts[0]),
    minor: BigInt(parts[1]),
    patch: BigInt(parts[2]),
  };
}

function semVerParts(value: string): [string, string, string] | null {
  const match = semverPattern.exec(value);
  if (!match || !match[1] || !match[2] || !match[3]) {
    return null;
  }

  return [match[1], match[2], match[3]];
}

function compareSemVer(left: string, right: string) {
  const leftVersion = parseSemVer(left);
  const rightVersion = parseSemVer(right);

  return (
    compareSemVerPart(leftVersion.major, rightVersion.major) ||
    compareSemVerPart(leftVersion.minor, rightVersion.minor) ||
    compareSemVerPart(leftVersion.patch, rightVersion.patch)
  );
}

function compareSemVerPart(left: bigint, right: bigint) {
  if (left < right) {
    return -1;
  }

  if (left > right) {
    return 1;
  }

  return 0;
}
