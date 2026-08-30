import { mkdtemp, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { terminalReplacementRecovery } from "../src/enrollment/routes.js";
import type { VerifiedReleaseTransition } from "../src/probe/asset-set.js";
import { readVerifiedReleaseTransitionFromDirectory } from "../src/probe/release-transition.js";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture.js";

describe("verified Probe release transition", () => {
  it("selects terminal recovery components only from the exact verified asset closure", () => {
    const transition = {
      classification: "replacement-required" as const,
      sourceAssetSetDigest: `sha256:${"1".repeat(64)}`,
      sourceProbeSha256: ["a", "b", "c", "d"].map((value) => value.repeat(64)),
      sourceProbeVersion: "1.3.0",
      targetAssetSetDigest: `sha256:${"2".repeat(64)}`,
      targetProbeSha256: ["e", "f", "0", "9"].map((value) => value.repeat(64)),
      targetProbeVersion: "1.4.0",
    } satisfies VerifiedReleaseTransition;
    const predecessor = {
      enrollmentId: "enr_terminal",
      targetAssetSetDigest: `sha256:${"2".repeat(64)}`,
      targetProbeVersion: "1.4.0",
    } as NonNullable<
      Parameters<typeof terminalReplacementRecovery>[0]["predecessor"]
    >;

    expect(
      terminalReplacementRecovery({
        predecessor,
        releaseTransition: transition,
      }),
    ).toMatchObject({ sourceProbeSha256: transition.targetProbeSha256 });
    expect(
      terminalReplacementRecovery({
        predecessor: {
          ...predecessor,
          targetAssetSetDigest: transition.sourceAssetSetDigest,
          targetProbeVersion: transition.sourceProbeVersion,
        },
        releaseTransition: transition,
      }),
    ).toMatchObject({ sourceProbeSha256: transition.sourceProbeSha256 });
    expect(
      terminalReplacementRecovery({
        predecessor: {
          ...predecessor,
          targetAssetSetDigest: `sha256:${"3".repeat(64)}`,
        },
        releaseTransition: transition,
      }),
    ).toBeNull();
    expect(
      terminalReplacementRecovery({
        predecessor: {
          ...predecessor,
          targetAssetSetDigest: `sha256:${"4".repeat(64)}`,
          targetProbeVersion: transition.sourceProbeVersion,
        },
        releaseTransition: transition,
      }),
    ).toBeNull();
  });

  it("reads the exact Trust Epoch migration closure as replacement-required", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "0.1.74",
      targetVersion: "1.4.0",
      transition: "replacement-required",
      trustEpoch: true,
    });

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toEqual({
      classification: "replacement-required",
      sourceAssetSetDigest: fixture.sourceAssetSetDigest,
      sourceProbeSha256: fixture.sourceProbeSha256,
      sourceProbeVersion: "0.1.74",
      targetProbeSha256: fixture.targetProbeSha256,
      targetAssetSetDigest: fixture.targetAssetSetDigest,
      targetBundles: fixture.targetBundles,
      targetProbeVersion: "1.4.0",
    });
  });

  it("returns no transition when the release does not declare one", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    await rm(path.join(assetDir, "release-transition-contract.json"));

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("reads a root-authorized compatible source-to-target transition", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toEqual({
      classification: "compatible",
      sourceAssetSetDigest: fixture.sourceAssetSetDigest,
      sourceProbeSha256: [5, 6, 7, 8].map((value) => String(value).repeat(64)),
      sourceProbeVersion: "1.3.0",
      targetProbeSha256: fixture.targetProbeSha256,
      targetAssetSetDigest: fixture.targetAssetSetDigest,
      targetBundles: fixture.targetBundles,
      targetProbeVersion: "1.4.0",
    });
  });

  it("preserves an explicit replacement-required classification", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "replacement-required",
    });

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toMatchObject({
      classification: "replacement-required",
      sourceProbeVersion: "1.3.0",
      targetProbeVersion: "1.4.0",
    });
  });

  it("rejects a linked manifest instead of following it", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    const linkedManifest = path.join(assetDir, "linked-manifest.json");
    await rename(path.join(assetDir, "manifest.json"), linkedManifest);
    await symlink(linkedManifest, path.join(assetDir, "manifest.json"));

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("keeps individual files and the complete metadata set bounded", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        maxMetadataBytes: 32,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        maxTotalMetadataBytes: 256,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("maps malformed release metadata to an unavailable transition", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    await writeFile(path.join(assetDir, "root-key.pem"), "not a public key");

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("propagates operational I/O errors", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        openFile: async () => {
          throw Object.assign(new Error("file table exhausted"), {
            code: "EMFILE",
          });
        },
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).rejects.toMatchObject({ code: "EMFILE" });
  });
});
