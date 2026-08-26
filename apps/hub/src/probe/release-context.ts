import { createHash } from "node:crypto";
import { open } from "node:fs/promises";

import {
  probeAssetSetVersionResultFromManifest,
  type ProbeAssetSetVersionResult,
  type VerifiedReleaseTransition,
} from "./asset-set.js";
import { readBoundedMetadataSnapshotFromDirectory } from "./assets.js";
import {
  releaseTransitionMetadataFileNames,
  verifiedReleaseTransitionFromMetadata,
} from "./release-transition.js";

export type ProbeReleaseContext = {
  assetSet: ProbeAssetSetVersionResult & {
    targetAssetSetDigest: string | null;
  };
  releaseTransition: VerifiedReleaseTransition | null;
};

export async function readProbeReleaseContextFromDirectory(input: {
  assetDir: string;
  maxMetadataBytes?: number;
  maxTotalMetadataBytes?: number;
  openFile?: typeof open;
  trustedRootPublicKeyPem?: string | Buffer;
}): Promise<ProbeReleaseContext> {
  const metadata = await readBoundedMetadataSnapshotFromDirectory({
    assetDir: input.assetDir,
    maxFileBytes: input.maxMetadataBytes,
    maxTotalBytes: input.maxTotalMetadataBytes,
    openFile: input.openFile,
    optionalFileNames: releaseTransitionMetadataFileNames.filter(
      (fileName) => fileName !== "manifest.json",
    ),
    requiredFileNames: ["manifest.json"],
  });
  const manifest = metadata?.["manifest.json"] ?? null;
  if (!manifest) {
    return unavailableProbeReleaseContext();
  }

  const version = probeAssetSetVersionResultFromManifest(
    manifest.toString("utf8"),
  );
  const targetAssetSetDigest = version.version
    ? `sha256:${createHash("sha256").update(manifest).digest("hex")}`
    : null;

  return {
    assetSet: {
      ...version,
      targetAssetSetDigest,
    },
    releaseTransition:
      input.trustedRootPublicKeyPem && metadata
        ? verifiedReleaseTransitionFromMetadata({
            files: metadata,
            trustedRootPublicKeyPem: input.trustedRootPublicKeyPem,
          })
        : null,
  };
}

export function unavailableProbeReleaseContext(): ProbeReleaseContext {
  return {
    assetSet: {
      nonUpgradeableReason: "probe_asset_set_version_missing",
      targetAssetSetDigest: null,
      version: null,
    },
    releaseTransition: null,
  };
}
