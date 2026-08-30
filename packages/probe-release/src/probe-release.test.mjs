import { generateKeyPairSync } from "node:crypto";
import { appendFileSync, renameSync, truncateSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import {
  createProbeTrustDelegation,
  probeBundleComponentProfiles,
  probeBundledBootstrapAssets,
  readRegularFileSnapshot,
  verifyProbeTrustDelegation,
} from "./index.mjs";

const regularFileSnapshotMutation = vi.hoisted(() => ({
  afterOpen: null,
  afterStat: null,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    async open(...args) {
      const handle = await original.open(...args);
      const openedPath = String(args[0]);
      regularFileSnapshotMutation.afterOpen?.(openedPath);
      regularFileSnapshotMutation.afterOpen = null;
      if (!regularFileSnapshotMutation.afterStat) return handle;
      return new Proxy(handle, {
        get(target, property) {
          if (property === "stat") {
            return async (...statArgs) => {
              const details = await target.stat(...statArgs);
              regularFileSnapshotMutation.afterStat?.(openedPath);
              regularFileSnapshotMutation.afterStat = null;
              return details;
            };
          }
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    },
  };
});

const rsa4096TestIdentities = new Map();

function rsa4096TestKeyPair(slot) {
  let identity = rsa4096TestIdentities.get(slot);
  if (!identity) {
    identity = Object.freeze(
      generateKeyPairSync("rsa", {
        modulusLength: 4096,
        privateKeyEncoding: { format: "pem", type: "pkcs8" },
        publicKeyEncoding: { format: "pem", type: "spki" },
      }),
    );
    rsa4096TestIdentities.set(slot, identity);
  }
  return identity;
}

describe("Probe release primitives", () => {
  it("keeps one opened regular-file snapshot when its pathname is replaced", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-snapshot-"));
    const filePath = path.join(directory, "archive.tar.gz");
    const replacementPath = path.join(directory, "replacement.tar.gz");
    const original = Buffer.from("one verified archive encoding");
    const replacement = Buffer.from("same inner closure, alternate encoding");
    try {
      await Promise.all([
        writeFile(filePath, original),
        writeFile(replacementPath, replacement),
      ]);
      regularFileSnapshotMutation.afterOpen = (openedPath) => {
        if (openedPath === filePath) renameSync(replacementPath, filePath);
      };

      const snapshot = await readRegularFileSnapshot(
        filePath,
        "Probe archive",
        {
          expectedSize: original.byteLength,
          maximumSize: original.byteLength,
        },
      );
      expect(snapshot).toEqual({ bytes: original, size: original.byteLength });
      expect(await readFile(filePath)).toEqual(replacement);
    } finally {
      regularFileSnapshotMutation.afterOpen = null;
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("rejects a regular-file snapshot whose size changes after fstat", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-snapshot-"));
    const filePath = path.join(directory, "archive.tar.gz");
    try {
      await writeFile(filePath, Buffer.from("verified archive"));
      regularFileSnapshotMutation.afterStat = (openedPath) => {
        if (openedPath === filePath) appendFileSync(filePath, Buffer.from("!"));
      };

      await expect(
        readRegularFileSnapshot(filePath, "Probe archive", {
          expectedSize: Buffer.byteLength("verified archive"),
          maximumSize: Buffer.byteLength("verified archive"),
        }),
      ).rejects.toThrow("Probe archive changed while reading");
    } finally {
      regularFileSnapshotMutation.afterStat = null;
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("rejects early EOF from the opened archive descriptor", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-snapshot-"));
    const filePath = path.join(directory, "archive.tar.gz");
    const archive = Buffer.from("verified archive snapshot");
    try {
      await writeFile(filePath, archive);
      regularFileSnapshotMutation.afterStat = (openedPath) => {
        if (openedPath === filePath) truncateSync(filePath, 1);
      };

      await expect(
        readRegularFileSnapshot(filePath, "Probe archive", {
          expectedSize: archive.byteLength,
          maximumSize: archive.byteLength,
        }),
      ).rejects.toThrow("Probe archive changed while reading");
    } finally {
      regularFileSnapshotMutation.afterStat = null;
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("rejects a large archive that disagrees with its declared size before reading", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "enoki-snapshot-"));
    const filePath = path.join(directory, "archive.tar.gz");
    try {
      await writeFile(filePath, "archive");
      truncateSync(filePath, 64 * 1024 * 1024);

      await expect(
        readRegularFileSnapshot(filePath, "Probe archive", {
          expectedSize: 7,
          maximumSize: 1024,
        }),
      ).rejects.toThrow("Probe archive size does not match");
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("keeps the fixed Probe Asset Bundle roles in one package", () => {
    expect(Object.keys(probeBundleComponentProfiles)).toEqual([
      "probe",
      "observation-runtime",
      "system-state-provider",
      "disk-health-provider",
      "lifecycle-companion",
    ]);
    expect(probeBundledBootstrapAssets.map(({ role }) => role)).toEqual([
      "bootstrap-acquirer",
      "bootstrap-activator",
    ]);
  });

  it("creates canonical delegation bytes accepted by the same verifier", () => {
    const root = rsa4096TestKeyPair("probe-release-root");
    const release = rsa4096TestKeyPair("probe-release-signer");
    const signed = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 3,
      releasePublicKeyPem: release.publicKey,
      rootPrivateKeyPem: root.privateKey,
    });

    expect(signed.bytes).toEqual(
      Buffer.from(`${JSON.stringify(signed.delegation)}\n`, "utf8"),
    );
    expect(
      verifyProbeTrustDelegation({
        bytes: signed.bytes,
        expectedDistribution: "enoki",
        rootPublicKeyPem: root.publicKey,
        signature: signed.signature,
      }),
    ).toEqual(signed.delegation);
  });

  it("rejects explicitly weak RSA-2048 production trust identities", () => {
    const root = rsa4096TestKeyPair("probe-release-root");
    const release = rsa4096TestKeyPair("probe-release-signer");
    const weakRejectionOnlyIdentity = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const signed = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 3,
      releasePublicKeyPem: release.publicKey,
      rootPrivateKeyPem: root.privateKey,
    });

    expect(() =>
      createProbeTrustDelegation({
        distribution: "enoki",
        generation: 3,
        releasePublicKeyPem: release.publicKey,
        rootPrivateKeyPem: weakRejectionOnlyIdentity.privateKey,
      }),
    ).toThrow(/Trust Root must be an RSA-4096 private key/);
    expect(() =>
      createProbeTrustDelegation({
        distribution: "enoki",
        generation: 3,
        releasePublicKeyPem: weakRejectionOnlyIdentity.publicKey,
        rootPrivateKeyPem: root.privateKey,
      }),
    ).toThrow(/signing public key must be RSA-4096/);
    expect(() =>
      verifyProbeTrustDelegation({
        bytes: signed.bytes,
        expectedDistribution: "enoki",
        rootPublicKeyPem: weakRejectionOnlyIdentity.publicKey,
        signature: signed.signature,
      }),
    ).toThrow(/Trust Root public key must be RSA-4096/);
  });
});
