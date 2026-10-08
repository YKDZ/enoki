import { generateKeyPairSync, sign } from "node:crypto";
import {
  mkdtemp,
  readFile,
  rm,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  createProbeTrustDelegation,
  releaseTransitionContractSigningInput,
} from "@enoki/probe-release";
import { describe, expect, it } from "vitest";

import {
  readVerifiedReleaseTransitionFromDirectory,
  releaseTransitionMetadataFileNames,
  verifiedReleaseTransitionFromMetadata,
} from "../src/probe/release-transition.js";
import {
  type TestProbeReleaseAuthority,
  writeSignedProbeAssetSet,
} from "./probe-release-transition-fixture.js";

describe("verified Probe release transition", () => {
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
      sourceProbeSha256: fixture.sourceProbeSha256,
      sourceProbeVersion: "0.1.74",
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

  it("reads a delegation-authorized compatible source-to-target transition", async () => {
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
      sourceProbeSha256: [5, 6, 7, 8].map((value) => String(value).repeat(64)),
      sourceProbeVersion: "1.3.0",
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

  it("projects the same transition through the metadata entry", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });

    expect(
      verifiedReleaseTransitionFromMetadata({
        files: await readTransitionMetadata(assetDir),
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).toEqual(
      await readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    );
  });

  it("rejects an incomplete metadata set", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    await rm(path.join(assetDir, "trust-delegation.json.sig"));

    expect(
      verifiedReleaseTransitionFromMetadata({
        files: await readTransitionMetadata(assetDir),
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).toBeNull();
  });

  it("rejects a contract signature that does not match the delegated Probe signing identity", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    const signatureFile = path.join(
      assetDir,
      "release-transition-contract.json.sig",
    );
    const signature = await readFile(signatureFile);
    signature.writeUInt8(
      signature.readUInt8(signature.byteLength - 1) ^ 1,
      signature.byteLength - 1,
    );
    await writeFile(signatureFile, signature);

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("rejects a target closure that does not match the served asset set", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    const contract = await readContract(assetDir);
    contract.target.assetClosure[0]!.sha256 = "f".repeat(64);
    await writeResignedContract(assetDir, fixture.release, contract);

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("rejects a transition contract that does not bind a candidate commit", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    const contract = await readContract(assetDir);
    delete contract.candidateCommit;
    await writeResignedContract(assetDir, fixture.release, contract);

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("rejects a delegation that authorizes a different signing identity", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    const otherRelease = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const delegation = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 3,
      releasePublicKeyPem: otherRelease.publicKey.export({
        format: "pem",
        type: "spki",
      }),
      rootPrivateKeyPem: fixture.authority.privateKey,
    });

    await Promise.all([
      writeFile(path.join(assetDir, "trust-delegation.json"), delegation.bytes),
      writeFile(
        path.join(assetDir, "trust-delegation.json.sig"),
        delegation.signature,
      ),
    ]);

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("rejects a migration contract without its one-time root authorization", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "0.1.74",
      targetVersion: "1.4.0",
      transition: "replacement-required",
      trustEpoch: true,
    });
    await rm(path.join(assetDir, "trust-epoch-migration-authorization.json"));

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("rejects a migration contract when no authorization is configured", async () => {
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "0.1.74",
      targetVersion: "1.4.0",
      transition: "replacement-required",
      trustEpoch: true,
    });
    await Promise.all([
      rm(path.join(assetDir, "trust-epoch-migration-authorization.json")),
      rm(path.join(assetDir, "trust-epoch-migration-authorization.json.sig")),
    ]);

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("rejects a migration authorization bound to a different legacy release", async () => {
    const authority = testAuthority();
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const otherAssetDir = await mkdtemp(
      path.join(tmpdir(), "enoki-transition-"),
    );
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      authority,
      sourceVersion: "0.1.74",
      targetVersion: "1.4.0",
      transition: "replacement-required",
      trustEpoch: true,
    });
    const other = await writeSignedProbeAssetSet(otherAssetDir, {
      authority,
      sourceVersion: "0.1.74",
      targetVersion: "1.4.0",
      transition: "replacement-required",
      trustEpoch: true,
    });

    await Promise.all([
      writeFile(
        path.join(assetDir, "trust-epoch-migration-authorization.json"),
        await readFile(
          path.join(otherAssetDir, "trust-epoch-migration-authorization.json"),
        ),
      ),
      writeFile(
        path.join(assetDir, "trust-epoch-migration-authorization.json.sig"),
        await readFile(
          path.join(
            otherAssetDir,
            "trust-epoch-migration-authorization.json.sig",
          ),
        ),
      ),
    ]);

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });

  it("rejects an ordinary contract that carries a migration authorization", async () => {
    const authority = testAuthority();
    const assetDir = await mkdtemp(path.join(tmpdir(), "enoki-transition-"));
    const migrationAssetDir = await mkdtemp(
      path.join(tmpdir(), "enoki-transition-"),
    );
    const fixture = await writeSignedProbeAssetSet(assetDir, {
      authority,
      sourceVersion: "1.3.0",
      targetVersion: "1.4.0",
      transition: "compatible",
    });
    await writeSignedProbeAssetSet(migrationAssetDir, {
      authority,
      sourceVersion: "0.1.74",
      targetVersion: "1.4.0",
      transition: "replacement-required",
      trustEpoch: true,
    });

    await Promise.all([
      writeFile(
        path.join(assetDir, "trust-epoch-migration-authorization.json"),
        await readFile(
          path.join(
            migrationAssetDir,
            "trust-epoch-migration-authorization.json",
          ),
        ),
      ),
      writeFile(
        path.join(assetDir, "trust-epoch-migration-authorization.json.sig"),
        await readFile(
          path.join(
            migrationAssetDir,
            "trust-epoch-migration-authorization.json.sig",
          ),
        ),
      ),
    ]);

    await expect(
      readVerifiedReleaseTransitionFromDirectory({
        assetDir,
        trustedRootPublicKeyPem: fixture.rootPublicKeyPem,
      }),
    ).resolves.toBeNull();
  });
});

type TamperedContract = {
  candidateCommit?: string;
  target: { assetClosure: { sha256: string }[] };
};

async function readContract(assetDir: string): Promise<TamperedContract> {
  const bytes = await readFile(
    path.join(assetDir, "release-transition-contract.json"),
    "utf8",
  );
  return JSON.parse(bytes) as TamperedContract;
}

async function readTransitionMetadata(assetDir: string) {
  const entries = await Promise.all(
    releaseTransitionMetadataFileNames.map(
      async (fileName) =>
        [
          fileName,
          await readFile(path.join(assetDir, fileName)).catch(() => null),
        ] as const,
    ),
  );
  return Object.fromEntries(entries);
}

function testAuthority(): TestProbeReleaseAuthority {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privateKey: pair.privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKey: pair.publicKey.export({ format: "pem", type: "spki" }),
  };
}

async function writeResignedContract(
  assetDir: string,
  signingIdentity: TestProbeReleaseAuthority,
  contract: TamperedContract,
) {
  const bytes = Buffer.from(`${JSON.stringify(contract)}\n`);
  await Promise.all([
    writeFile(path.join(assetDir, "release-transition-contract.json"), bytes),
    writeFile(
      path.join(assetDir, "release-transition-contract.json.sig"),
      sign(
        "RSA-SHA256",
        releaseTransitionContractSigningInput(bytes),
        signingIdentity.privateKey,
      ),
    ),
  ]);
}
