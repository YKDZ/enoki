import { open } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { readProbeReleaseContextFromDirectory } from "../src/probe/release-context.js";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture.js";

describe("Probe release context", () => {
  it("returns one authoritative version, digest, and transition from one manifest read", async () => {
    const assetDir = await mkdtemp(
      path.join(tmpdir(), "enoki-release-context-"),
    );
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    let manifestOpenCount = 0;

    await expect(
      readProbeReleaseContextFromDirectory({
        assetDir,
        openFile: (filePath, flags) => {
          if (path.basename(String(filePath)) === "manifest.json") {
            manifestOpenCount += 1;
          }
          return open(filePath, flags);
        },
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toEqual({
      assetSet: {
        nonUpgradeableReason: null,
        targetAssetSetDigest: fixture.targetAssetSetDigest,
        version: "1.4.0",
      },
      releaseTransition: {
        classification: "compatible",
        sourceProbeSha256: [5, 6, 7, 8].map((value) =>
          String(value).repeat(64),
        ),
        sourceProbeVersion: "1.3.0",
        targetAssetSetDigest: fixture.targetAssetSetDigest,
        targetProbeVersion: "1.4.0",
      },
    });
    expect(manifestOpenCount).toBe(1);
  });

  it("preserves the manifest version when transition metadata is absent", async () => {
    const assetDir = await mkdtemp(
      path.join(tmpdir(), "enoki-release-context-"),
    );
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    await rm(path.join(assetDir, "release-transition-contract.json"));

    await expect(
      readProbeReleaseContextFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toEqual({
      assetSet: {
        nonUpgradeableReason: null,
        targetAssetSetDigest: fixture.targetAssetSetDigest,
        version: "1.4.0",
      },
      releaseTransition: null,
    });
  });
});
