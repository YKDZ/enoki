import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { gunzipSync, gzipSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import {
  inspectProbeBootstrapArtifact,
  inspectProbeBootstrapBinary,
  packageProbeBootstrapArtifact,
  withVerifiedProbeBootstrapArchive,
  withVerifiedProbeBootstrapArtifact,
} from "./probe-bootstrap-artifact.mjs";

const execFileAsync = promisify(execFile);
const identity = {
  distribution: "enoki",
  rootFingerprint: "a".repeat(64),
  rootKeyId: "a".repeat(64),
  target: "x86_64-unknown-linux-gnu",
  version: "v1.2.3",
};

describe("Probe Bootstrap build artifact", () => {
  it("requires exact release bytes at the public archive snapshot seam", async () => {
    await withFixture(async ({ acquirerPath, activatorPath, root }) => {
      const artifact = await packageProbeBootstrapArtifact({
        binaries: { acquirerPath, activatorPath },
        outputDir: path.join(root, "out"),
        sourceDateEpoch: "0",
        ...identity,
      });

      await expect(
        withVerifiedProbeBootstrapArchive(
          { archivePath: artifact.archivePath },
          async () => undefined,
        ),
      ).rejects.toThrow(/expected release bytes/);
    });
  });

  it("accepts one exact length-prefixed identity in the expected ELF target", async () => {
    await withFixture(async ({ acquirerPath }) => {
      await writeFile(
        acquirerPath,
        createBootstrapElf({ identity: { ...identity, role: "acquirer" } }),
      );
      await expect(
        inspectProbeBootstrapBinary({
          binaryPath: acquirerPath,
          role: "acquirer",
          ...identity,
        }),
      ).resolves.toMatchObject({ identity: { ...identity, role: "acquirer" } });
    });
  });

  it.each([
    ["wrong ELF machine", { machine: 183 }, /expected ELF target/],
    [
      "duplicate identity section",
      { duplicateIdentitySection: true },
      /exactly one identity section/,
    ],
    [
      "trailing identity data",
      { trailingIdentityData: true },
      /identity section is invalid/,
    ],
  ])("rejects a %s", async (_label, options, expected) => {
    await withFixture(async ({ acquirerPath }) => {
      await writeFile(acquirerPath, createBootstrapElf(options));
      await expect(
        inspectProbeBootstrapBinary({
          binaryPath: acquirerPath,
          role: "acquirer",
          ...identity,
        }),
      ).rejects.toThrow(expected);
    });
  });

  it.each([
    ["missing role", identity, /identity section is invalid/],
    [
      "unknown role",
      { ...identity, role: "observer" },
      /build identity is invalid/,
    ],
  ])(
    "rejects an identity with a %s",
    async (_label, generatedIdentity, expected) => {
      await withFixture(async ({ acquirerPath }) => {
        await writeFile(
          acquirerPath,
          createBootstrapElf({ identity: generatedIdentity }),
        );
        await expect(
          inspectProbeBootstrapBinary({
            binaryPath: acquirerPath,
            role: "acquirer",
            ...identity,
          }),
        ).rejects.toThrow(expected);
      });
    },
  );

  it("rejects a relabelled activator identity at the acquirer boundary", async () => {
    await withFixture(async ({ acquirerPath }) => {
      await writeFile(
        acquirerPath,
        createBootstrapElf({ identity: { ...identity, role: "activator" } }),
      );
      await expect(
        inspectProbeBootstrapBinary({
          binaryPath: acquirerPath,
          role: "acquirer",
          ...identity,
        }),
      ).rejects.toThrow(/embedded build identity does not match/);
    });
  });

  it("rejects an acquirer binary copied into the activator role", async () => {
    await withFixture(async ({ acquirerPath, activatorPath, root }) => {
      await writeFile(activatorPath, await readFile(acquirerPath));
      await expect(
        packageProbeBootstrapArtifact({
          binaries: { acquirerPath, activatorPath },
          outputDir: path.join(root, "out"),
          sourceDateEpoch: "0",
          ...identity,
        }),
      ).rejects.toThrow(/embedded build identity does not match/);
    });
  });

  it("rejects Bootstrap role binaries swapped between their archive members", async () => {
    await withFixture(async ({ acquirerPath, activatorPath, root }) => {
      const acquirer = await readFile(acquirerPath);
      await writeFile(acquirerPath, await readFile(activatorPath));
      await writeFile(activatorPath, acquirer);
      await expect(
        packageProbeBootstrapArtifact({
          binaries: { acquirerPath, activatorPath },
          outputDir: path.join(root, "out"),
          sourceDateEpoch: "0",
          ...identity,
        }),
      ).rejects.toThrow(/embedded build identity does not match/);
    });
  });

  it("packages explicit role binaries from separate clean build directories", async () => {
    await withFixture(async ({ acquirerPath, activatorPath, root }) => {
      const activatorDirectory = path.join(root, "activator-build");
      const isolatedActivatorPath = path.join(
        activatorDirectory,
        path.basename(activatorPath),
      );
      await mkdir(activatorDirectory);
      await writeFile(isolatedActivatorPath, await readFile(activatorPath));
      const artifact = await packageProbeBootstrapArtifact({
        binaries: { acquirerPath, activatorPath: isolatedActivatorPath },
        outputDir: path.join(root, "out"),
        sourceDateEpoch: "0",
        ...identity,
      });
      await expect(
        inspectProbeBootstrapArtifact({
          archivePath: artifact.archivePath,
          ...identity,
        }),
      ).resolves.toMatchObject({
        roles: {
          acquirer: { identity: { ...identity, role: "acquirer" } },
          activator: { identity: { ...identity, role: "activator" } },
        },
      });
    });
  });

  it("provides only inspected role binaries in a private temporary directory and removes it afterwards", async () => {
    await withFixture(async ({ acquirerPath, activatorPath, root }) => {
      const artifact = await packageProbeBootstrapArtifact({
        binaries: { acquirerPath, activatorPath },
        outputDir: path.join(root, "out"),
        sourceDateEpoch: "0",
        ...identity,
      });
      let extractionDirectory;
      await withVerifiedProbeBootstrapArtifact(
        { archivePath: artifact.archivePath, ...identity },
        async ({ extractedRoles, temporaryDirectory }) => {
          extractionDirectory = temporaryDirectory;
          expect(Object.keys(extractedRoles).sort()).toEqual([
            "acquirer",
            "activator",
          ]);
          await expect(
            readFile(extractedRoles.acquirer.binaryPath),
          ).resolves.toEqual(await readFile(acquirerPath));
          await expect(
            readFile(extractedRoles.activator.binaryPath),
          ).resolves.toEqual(await readFile(activatorPath));
        },
      );
      await expect(readFile(extractionDirectory)).rejects.toThrow();
    });
  });

  it("keeps the verified archive snapshot stable when its source changes after verification", async () => {
    await withFixture(async ({ acquirerPath, activatorPath, root }) => {
      const artifact = await packageProbeBootstrapArtifact({
        binaries: { acquirerPath, activatorPath },
        outputDir: path.join(root, "out"),
        sourceDateEpoch: "0",
        ...identity,
      });
      const verifiedBytes = await readFile(artifact.archivePath);

      await withVerifiedProbeBootstrapArtifact(
        {
          archivePath: artifact.archivePath,
          expectedArchive: {
            sha256: artifact.sha256,
            size: artifact.size,
          },
          ...identity,
        },
        async ({ archivePath }) => {
          await writeFile(artifact.archivePath, Buffer.from("source changed"));
          await expect(readFile(archivePath)).resolves.toEqual(verifiedBytes);
        },
      );
    });
  });

  it.each([
    ["an extra regular member", addExtraRegularTarMember],
    ["a GNU long-name extension", (tar) => replaceFirstTarType(tar, "L")],
    ["a PAX extension", (tar) => replaceFirstTarType(tar, "x")],
    ["a GNU sparse extension", (tar) => replaceFirstTarType(tar, "S")],
    ["a non-ustar header", replaceFirstTarMagic],
    ["non-zero member padding", replaceFirstTarPadding],
    [
      "a concatenated gzip member",
      (archive) => Buffer.concat([archive, gzipSync(Buffer.alloc(1024))]),
    ],
  ])("rejects %s before any role is extracted", async (_label, mutate) => {
    await withFixture(async ({ acquirerPath, activatorPath, root }) => {
      const artifact = await packageProbeBootstrapArtifact({
        binaries: { acquirerPath, activatorPath },
        outputDir: path.join(root, "out"),
        sourceDateEpoch: "0",
        ...identity,
      });
      const source = await readFile(artifact.archivePath);
      const unsafe = path.join(root, "unsafe.tar.gz");
      await writeFile(unsafe, mutate(source));
      await expect(
        withVerifiedProbeBootstrapArtifact(
          { archivePath: unsafe, ...identity },
          () => {
            throw new Error(
              "unsafe archive must not reach extraction callback",
            );
          },
        ),
      ).rejects.toThrow(/archive structure is unsafe/);
    });
  });

  it("packages two role-isolated Bootstrap binaries in one reproducible artifact", async () => {
    await withFixture(async ({ acquirerPath, activatorPath, root }) => {
      const first = await packageProbeBootstrapArtifact({
        binaries: { acquirerPath, activatorPath },
        outputDir: path.join(root, "first"),
        sourceDateEpoch: "0",
        ...identity,
      });
      const second = await packageProbeBootstrapArtifact({
        binaries: { acquirerPath, activatorPath },
        outputDir: path.join(root, "second"),
        sourceDateEpoch: "0",
        ...identity,
      });
      expect(await readFile(first.archivePath)).toEqual(
        await readFile(second.archivePath),
      );
      expect(first.file).toBe(
        "enoki-probe-bootstrap-x86_64-unknown-linux-gnu.tar.gz",
      );
      await expect(
        inspectProbeBootstrapArtifact({
          archivePath: first.archivePath,
          ...identity,
        }),
      ).resolves.toMatchObject({
        roles: {
          acquirer: { identity: { ...identity, role: "acquirer" } },
          activator: { identity: { ...identity, role: "activator" } },
        },
      });
      expect(
        (
          await execFileAsync("tar", [
            "--list",
            "--verbose",
            "--gzip",
            "--file",
            first.archivePath,
          ])
        ).stdout,
      ).toMatch(
        /-rwxr-xr-x .* enoki-probe-bootstrap-acquire\n-rwxr-xr-x .* enoki-probe-bootstrap-activate\n/,
      );
    });
  });

  it("rejects a Bootstrap archive whose two roles do not carry the identical build trust", async () => {
    await withFixture(async ({ acquirerPath, activatorPath, root }) => {
      await writeFile(
        activatorPath,
        createBootstrapElf({
          identity: { ...identity, version: "v9.9.9", role: "activator" },
        }),
      );
      await expect(
        packageProbeBootstrapArtifact({
          binaries: { acquirerPath, activatorPath },
          outputDir: path.join(root, "out"),
          sourceDateEpoch: "0",
          ...identity,
        }),
      ).rejects.toThrow(/embedded build identity does not match/);
    });
  });

  it("makes production trust explicit and fails closed in the reusable build", async () => {
    const workflow = await readFile(
      ".github/workflows/reusable-build-probe-bootstrap.yml",
      "utf8",
    );
    expect(workflow).toContain(
      "ENOKI_PROBE_DISTRIBUTION_ROOT_PUBLIC_KEY_PEM is required",
    );
    expect(workflow).toContain(
      "build_role acquirer acquirer,compiled-trust enoki-probe-bootstrap-acquire target/bootstrap-repro-first-acquirer",
    );
    expect(workflow).toContain(
      "build_role activator activator,compiled-trust enoki-probe-bootstrap-activate target/bootstrap-repro-first-activator",
    );
    expect(workflow).toContain("enoki-probe-bootstrap-acquire");
    expect(workflow).toContain("enoki-probe-bootstrap-activate");
    expect(workflow).toContain(
      "cargo tree -p enoki-probe-bootstrap --no-default-features --features activator,compiled-trust",
    );
    expect(workflow).toContain('test "$BOOTSTRAP_DISTRIBUTION" = enoki');
    expect(workflow).toContain("ENOKI_BOOTSTRAP_BUILD_DISTRIBUTION");
    expect(workflow).toContain("ENOKI_BOOTSTRAP_BUILD_ROOT_PEM");
    expect(workflow).toContain(
      "key.asymmetricKeyDetails?.modulusLength !== 4096",
    );
    expect(workflow).toContain("root must be RSA-4096");
    expect(workflow).not.toContain(
      'key.asymmetricKeyType !== "rsa") throw new Error("root must be RSA")',
    );
    const bootstrapBuildScript = await readFile(
      "crates/probe-bootstrap/build.rs",
      "utf8",
    );
    expect(bootstrapBuildScript).toContain("root.n().bits() != 4096");
    expect(bootstrapBuildScript).toContain("must be an RSA-4096 SPKI PEM");
    expect(workflow).toContain('ENOKI_BOOTSTRAP_BUILD_ROLE="$role"');
    expect(workflow).toContain("ENOKI_BOOTSTRAP_BUILD_TARGET");
    expect(workflow).toContain("ENOKI_BOOTSTRAP_BUILD_VERSION");
    expect(workflow).toContain("probe-bootstrap-artifact.mjs package");
    expect(workflow).toContain("probe-bootstrap-artifact.mjs inspect");
    expect(workflow).not.toMatch(/genpkey|openssl genrsa|private key/i);
  });
});

async function withFixture(run) {
  const root = await mkdtemp(
    path.join(os.tmpdir(), "enoki-bootstrap-artifact-"),
  );
  try {
    const acquirerPath = path.join(root, "enoki-probe-bootstrap-acquire");
    const activatorPath = path.join(root, "enoki-probe-bootstrap-activate");
    await writeFile(
      acquirerPath,
      createBootstrapElf({ identity: { ...identity, role: "acquirer" } }),
    );
    await writeFile(
      activatorPath,
      createBootstrapElf({ identity: { ...identity, role: "activator" } }),
    );
    await run({ acquirerPath, activatorPath, root });
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

function createBootstrapElf({
  duplicateIdentitySection = false,
  identity: generatedIdentity = identity,
  machine = 62,
  trailingIdentityData = false,
} = {}) {
  const names = Buffer.from("\0.shstrtab\0.enoki_bootstrap\0", "utf8");
  const payload = Buffer.from(JSON.stringify(generatedIdentity), "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.byteLength);
  const marker = Buffer.concat([
    Buffer.from("ENOKI_BOOTSTRAP_BUILD_IDENTITY_V1\0", "utf8"),
    length,
    payload,
    ...(trailingIdentityData ? [Buffer.from("x")] : []),
  ]);
  const sectionCount = duplicateIdentitySection ? 4 : 3;
  const sectionOffset = 64;
  const sectionTableSize = sectionCount * 64;
  const identityOffset = sectionOffset + sectionTableSize;
  const namesOffset = identityOffset + marker.byteLength;
  const binary = Buffer.alloc(namesOffset + names.byteLength);
  binary.write("\x7fELF", 0, "binary");
  binary[4] = 2;
  binary[5] = 1;
  binary[6] = 1;
  binary.writeUInt16LE(machine, 18);
  binary.writeBigUInt64LE(BigInt(sectionOffset), 40);
  binary.writeUInt16LE(64, 58);
  binary.writeUInt16LE(sectionCount, 60);
  binary.writeUInt16LE(1, 62);
  writeSection(binary, sectionOffset + 64, {
    nameOffset: 1,
    offset: namesOffset,
    size: names.byteLength,
  });
  writeSection(binary, sectionOffset + 128, {
    nameOffset: 11,
    offset: identityOffset,
    size: marker.byteLength,
  });
  if (duplicateIdentitySection) {
    writeSection(binary, sectionOffset + 192, {
      nameOffset: 11,
      offset: identityOffset,
      size: marker.byteLength,
    });
  }
  marker.copy(binary, identityOffset);
  names.copy(binary, namesOffset);
  return binary;
}

function writeSection(binary, offset, { nameOffset, offset: contents, size }) {
  binary.writeUInt32LE(nameOffset, offset);
  binary.writeBigUInt64LE(BigInt(contents), offset + 24);
  binary.writeBigUInt64LE(BigInt(size), offset + 32);
}

function replaceFirstTarType(archive, type) {
  const tar = Buffer.from(gunzipSync(archive));
  tar[156] = type.charCodeAt(0);
  updateTarChecksum(tar.subarray(0, 512));
  return gzipSync(tar);
}

function addExtraRegularTarMember(archive) {
  const tar = Buffer.from(gunzipSync(archive));
  const header = Buffer.alloc(512);
  header.write("extra", 0, "ascii");
  header.write("0000755\0", 100, "ascii");
  header.write("0000000\0", 108, "ascii");
  header.write("0000000\0", 116, "ascii");
  header.write("00000000000\0", 124, "ascii");
  header.write("00000000000\0", 136, "ascii");
  header[156] = "0".charCodeAt(0);
  header.write("ustar\0", 257, "ascii");
  header.write("00", 263, "ascii");
  updateTarChecksum(header);
  return gzipSync(
    Buffer.concat([tar.subarray(0, -1024), header, Buffer.alloc(1024)]),
  );
}

function replaceFirstTarMagic(archive) {
  const tar = Buffer.from(gunzipSync(archive));
  tar.write("gnu", 257, "ascii");
  updateTarChecksum(tar.subarray(0, 512));
  return gzipSync(tar);
}

function replaceFirstTarPadding(archive) {
  const tar = Buffer.from(gunzipSync(archive));
  const size = Number.parseInt(
    tar
      .subarray(124, 136)
      .toString("ascii")
      .replace(/[\0 ]+$/g, ""),
    8,
  );
  tar[512 + size] = 1;
  return gzipSync(tar);
}

function updateTarChecksum(header) {
  header.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
}
