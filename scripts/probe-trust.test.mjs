import { execFile } from "node:child_process";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
} from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { createProbeTrustDelegation } from "./release-candidate-lib.mjs";

const execFileAsync = promisify(execFile);
const cli = "scripts/probe-trust.mjs";

async function runCli(arguments_) {
  return execFileAsync("node", [cli, ...arguments_]);
}

async function expectCliFailure(arguments_) {
  try {
    await runCli(arguments_);
    throw new Error("CLI unexpectedly succeeded");
  } catch (error) {
    return error;
  }
}

async function fileMode(filePath) {
  return (await lstat(filePath)).mode & 0o777;
}

describe("Probe Distribution Trust CLI", { timeout: 60_000 }, () => {
  it("rejects passphrases shorter than 32 bytes before creating a root", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const passphrasePath = path.join(workDir, "short-passphrase");
    const outputDir = path.join(workDir, "root");
    await writeFile(passphrasePath, "too short\n", { mode: 0o600 });

    const failure = await expectCliFailure([
      "init-root",
      "--output-dir",
      outputDir,
      "--passphrase-file",
      passphrasePath,
    ]);

    expect(failure.stderr).toMatch(/at least 32 CSPRNG-random bytes/);
    await expect(lstat(outputDir)).rejects.toMatchObject({ code: "ENOENT" });
    await rm(workDir, { force: true, recursive: true });
  });

  it("rejects EC and RSA-1024 trust identities before publishing a delegation", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const passphrasePath = path.join(workDir, "root-passphrase");
    const rootDir = path.join(workDir, "root");
    const releaseDir = path.join(workDir, "release");
    const ecReleaseKeyPath = path.join(workDir, "ec-release-public-key.pem");
    const weakRootKeyPath = path.join(workDir, "weak-root-private-key.pem");
    await writeFile(
      passphrasePath,
      "correct horse battery staple 0123456789\n",
      {
        mode: 0o600,
      },
    );
    await runCli([
      "init-root",
      "--output-dir",
      rootDir,
      "--passphrase-file",
      passphrasePath,
    ]);
    await runCli(["init-release-key", "--output-dir", releaseDir]);
    const ec = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { format: "pem", type: "spki" },
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
    });
    const weakRoot = generateKeyPairSync("rsa", {
      modulusLength: 1024,
      privateKeyEncoding: {
        cipher: "aes-256-cbc",
        format: "pem",
        passphrase: "correct horse battery staple 0123456789",
        type: "pkcs8",
      },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    await writeFile(ecReleaseKeyPath, ec.publicKey, { mode: 0o600 });
    await writeFile(weakRootKeyPath, weakRoot.privateKey, { mode: 0o600 });

    const authorizationArguments = (
      rootPrivateKey,
      releasePublicKey,
      outputDir,
    ) => [
      "authorize-release-key",
      "--root-private-key",
      rootPrivateKey,
      "--root-passphrase-file",
      passphrasePath,
      "--release-public-key",
      releasePublicKey,
      "--generation",
      "1",
      "--output-dir",
      outputDir,
    ];
    const ecOutput = path.join(workDir, "ec-delegation");
    const weakOutput = path.join(workDir, "weak-delegation");
    const [ecFailure, weakFailure] = await Promise.all([
      expectCliFailure(
        authorizationArguments(
          path.join(rootDir, "root-private-key.pem"),
          ecReleaseKeyPath,
          ecOutput,
        ),
      ),
      expectCliFailure(
        authorizationArguments(
          weakRootKeyPath,
          path.join(releaseDir, "release-public-key.pem"),
          weakOutput,
        ),
      ),
    ]);

    expect(ecFailure.stderr).toMatch(
      /release signing identity must be RSA-4096/,
    );
    expect(weakFailure.stderr).toMatch(
      /root signing identity must be RSA-4096/,
    );
    await expect(lstat(ecOutput)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(weakOutput)).rejects.toMatchObject({ code: "ENOENT" });
    await rm(workDir, { force: true, recursive: true });
  });

  it("refuses a validly signed RSA-1024 delegated signer during ceremony verification", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const passphrase = "correct horse battery staple 0123456789";
    const passphrasePath = path.join(workDir, "root-passphrase");
    const rootDir = path.join(workDir, "root");
    const delegationPath = path.join(workDir, "delegation.json");
    const signaturePath = path.join(workDir, "delegation.json.sig");
    await writeFile(passphrasePath, `${passphrase}\n`, { mode: 0o600 });
    await runCli([
      "init-root",
      "--output-dir",
      rootDir,
      "--passphrase-file",
      passphrasePath,
    ]);
    const weakRelease = generateKeyPairSync("rsa", {
      modulusLength: 1024,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const rootPrivateKey = createPrivateKey({
      key: await readFile(path.join(rootDir, "root-private-key.pem")),
      format: "pem",
      passphrase,
      type: "pkcs8",
    });
    const delegation = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 1,
      releasePublicKeyPem: weakRelease.publicKey,
      rootPrivateKey,
    });
    await writeFile(delegationPath, delegation.bytes);
    await writeFile(signaturePath, delegation.signature);

    const failure = await expectCliFailure([
      "verify",
      "--root-public-key",
      path.join(rootDir, "root-public-key.pem"),
      "--delegation",
      delegationPath,
      "--signature",
      signaturePath,
      "--highest-accepted-generation",
      "0",
    ]);

    expect(failure.stderr).toMatch(/release signing identity must be RSA-4096/);
    await rm(workDir, { force: true, recursive: true });
  });

  it("accepts equivalent LF and CRLF passphrase endings while rejecting hard-linked secrets", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const lfPassphrasePath = path.join(workDir, "lf-passphrase");
    const crlfPassphrasePath = path.join(workDir, "crlf-passphrase");
    const linkedPassphrasePath = path.join(workDir, "linked-passphrase");
    const rootDir = path.join(workDir, "root");
    const releaseDir = path.join(workDir, "release");
    const linkedRootKeyPath = path.join(workDir, "linked-root-private-key.pem");
    const passphrase = "correct horse battery staple 0123456789";
    await writeFile(lfPassphrasePath, `${passphrase}\n`, { mode: 0o600 });
    await writeFile(crlfPassphrasePath, `${passphrase}\r\n`, { mode: 0o600 });
    await runCli([
      "init-root",
      "--output-dir",
      rootDir,
      "--passphrase-file",
      crlfPassphrasePath,
    ]);
    const encryptedRootPrivateKey = await readFile(
      path.join(rootDir, "root-private-key.pem"),
    );
    expect(() =>
      createPrivateKey({
        key: encryptedRootPrivateKey,
        format: "pem",
        passphrase,
        type: "pkcs8",
      }),
    ).not.toThrow();
    await runCli(["init-release-key", "--output-dir", releaseDir]);
    await link(lfPassphrasePath, linkedPassphrasePath);
    await link(path.join(rootDir, "root-private-key.pem"), linkedRootKeyPath);

    const [passphraseFailure, privateKeyFailure] = await Promise.all([
      expectCliFailure([
        "init-root",
        "--output-dir",
        path.join(workDir, "linked-root"),
        "--passphrase-file",
        linkedPassphrasePath,
      ]),
      expectCliFailure([
        "authorize-release-key",
        "--root-private-key",
        linkedRootKeyPath,
        "--root-passphrase-file",
        crlfPassphrasePath,
        "--release-public-key",
        path.join(releaseDir, "release-public-key.pem"),
        "--generation",
        "1",
        "--output-dir",
        path.join(workDir, "delegation"),
      ]),
    ]);
    expect(passphraseFailure.stderr).toMatch(/exactly one hard link/);
    expect(privateKeyFailure.stderr).toMatch(/exactly one hard link/);
    await rm(workDir, { force: true, recursive: true });
  });

  it("refuses an output parent that is shared writable", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const passphrasePath = path.join(workDir, "root-passphrase");
    const sharedParent = path.join(workDir, "shared");
    const outputDir = path.join(sharedParent, "root");
    await writeFile(
      passphrasePath,
      "correct horse battery staple 0123456789\n",
      {
        mode: 0o600,
      },
    );
    await mkdir(sharedParent, { mode: 0o700 });
    await chmod(sharedParent, 0o770);

    const failure = await expectCliFailure([
      "init-root",
      "--output-dir",
      outputDir,
      "--passphrase-file",
      passphrasePath,
    ]);

    expect(failure.stderr).toMatch(/not shared writable/);
    await expect(lstat(outputDir)).rejects.toMatchObject({ code: "ENOENT" });
    await rm(workDir, { force: true, recursive: true });
  });

  it("refuses the filesystem root as the immediate output parent", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const passphrasePath = path.join(workDir, "root-passphrase");
    await writeFile(passphrasePath, `${"r".repeat(48)}\n`, { mode: 0o600 });

    const failure = await expectCliFailure([
      "init-root",
      "--output-dir",
      `/enoki-probe-trust-test-${process.pid}`,
      "--passphrase-file",
      passphrasePath,
    ]);

    expect(failure.stderr).toMatch(/dedicated private parent/);
    await rm(workDir, { force: true, recursive: true });
  });

  it("initializes an encrypted RSA-4096 distribution root in a private new directory", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const passphrasePath = path.join(workDir, "root-passphrase");
    const outputDir = path.join(workDir, "root");
    await writeFile(
      passphrasePath,
      "correct horse battery staple 0123456789\n",
      {
        mode: 0o600,
      },
    );

    const result = await runCli([
      "init-root",
      "--output-dir",
      outputDir,
      "--passphrase-file",
      passphrasePath,
    ]);

    expect(result.stdout).toMatch(
      /^initialized Probe Distribution Trust Root: [0-9a-f]{64}\n$/,
    );
    expect(result.stderr).toBe("");
    expect(await fileMode(outputDir)).toBe(0o700);
    expect(await fileMode(path.join(outputDir, "root-private-key.pem"))).toBe(
      0o600,
    );
    expect(await fileMode(path.join(outputDir, "root-public-key.pem"))).toBe(
      0o644,
    );

    const privateKey = await readFile(
      path.join(outputDir, "root-private-key.pem"),
    );
    expect(privateKey.toString()).toContain("ENCRYPTED PRIVATE KEY");
    expect(() => createPrivateKey(privateKey)).toThrow();
    const decrypted = createPrivateKey({
      key: privateKey,
      format: "pem",
      passphrase: "correct horse battery staple 0123456789",
      type: "pkcs8",
    });
    expect(createPublicKey(decrypted).asymmetricKeyDetails.modulusLength).toBe(
      4096,
    );
    expect(
      createPublicKey(
        await readFile(path.join(outputDir, "root-public-key.pem")),
      ).asymmetricKeyType,
    ).toBe("rsa");

    await rm(workDir, { force: true, recursive: true });
  });

  it("initializes an RSA-4096 routine signing identity with a root-private key file", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const outputDir = path.join(workDir, "release");

    const result = await runCli([
      "init-release-key",
      "--output-dir",
      outputDir,
    ]);

    expect(result.stdout).toMatch(
      /^initialized Probe Asset Signing Identity: [0-9a-f]{64}\n$/,
    );
    expect(result.stderr).toBe("");
    expect(await fileMode(outputDir)).toBe(0o700);
    expect(
      await fileMode(path.join(outputDir, "release-private-key.pem")),
    ).toBe(0o600);
    expect(await fileMode(path.join(outputDir, "release-public-key.pem"))).toBe(
      0o644,
    );

    const privateKey = createPrivateKey(
      await readFile(path.join(outputDir, "release-private-key.pem")),
    );
    expect(createPublicKey(privateKey).asymmetricKeyDetails.modulusLength).toBe(
      4096,
    );
    expect(
      Buffer.from(
        createPublicKey(
          await readFile(path.join(outputDir, "release-public-key.pem")),
        ).export({ format: "pem", type: "spki" }),
      ),
    ).toEqual(await readFile(path.join(outputDir, "release-public-key.pem")));

    await rm(workDir, { force: true, recursive: true });
  });

  it("authorizes and verifies a routine signer through the canonical Probe Trust Delegation", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const passphrasePath = path.join(workDir, "root-passphrase");
    const rootDir = path.join(workDir, "root");
    const releaseDir = path.join(workDir, "release");
    const delegationDir = path.join(workDir, "delegation");
    await writeFile(
      passphrasePath,
      "correct horse battery staple 0123456789\n",
      {
        mode: 0o600,
      },
    );
    await runCli([
      "init-root",
      "--output-dir",
      rootDir,
      "--passphrase-file",
      passphrasePath,
    ]);
    await runCli(["init-release-key", "--output-dir", releaseDir]);

    const authorize = await runCli([
      "authorize-release-key",
      "--root-private-key",
      path.join(rootDir, "root-private-key.pem"),
      "--root-passphrase-file",
      passphrasePath,
      "--release-public-key",
      path.join(releaseDir, "release-public-key.pem"),
      "--generation",
      "7",
      "--output-dir",
      delegationDir,
    ]);
    expect(authorize.stdout).toMatch(
      /^authorized Probe Asset Signing Identity: [0-9a-f]{64} generation 7\n$/,
    );
    expect(authorize.stderr).toBe("");
    expect(
      await readFile(path.join(delegationDir, "trust-delegation.json"), "utf8"),
    ).toMatch(/^\{"distribution":"enoki","generation":7,/);
    expect(
      await fileMode(path.join(delegationDir, "trust-delegation.json.sig")),
    ).toBe(0o644);

    const verify = await runCli([
      "verify",
      "--root-public-key",
      path.join(rootDir, "root-public-key.pem"),
      "--delegation",
      path.join(delegationDir, "trust-delegation.json"),
      "--signature",
      path.join(delegationDir, "trust-delegation.json.sig"),
      "--highest-accepted-generation",
      "7",
    ]);
    expect(verify.stdout).toMatch(
      /^verified Probe Trust Delegation: [0-9a-f]{64} generation 7\n$/,
    );
    expect(verify.stderr).toBe("");

    await rm(workDir, { force: true, recursive: true });
  });

  it("does not publish a delegation when the root passphrase cannot unlock its encrypted key", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const correctPassphrasePath = path.join(workDir, "correct-passphrase");
    const wrongPassphrasePath = path.join(workDir, "wrong-passphrase");
    const rootDir = path.join(workDir, "root");
    const releaseDir = path.join(workDir, "release");
    const delegationDir = path.join(workDir, "delegation");
    await writeFile(
      correctPassphrasePath,
      "correct horse battery staple 0123456789\n",
      {
        mode: 0o600,
      },
    );
    await writeFile(
      wrongPassphrasePath,
      "wrong passphrase 98765432101234567890\n",
      {
        mode: 0o600,
      },
    );
    await runCli([
      "init-root",
      "--output-dir",
      rootDir,
      "--passphrase-file",
      correctPassphrasePath,
    ]);
    await runCli(["init-release-key", "--output-dir", releaseDir]);

    const failure = await expectCliFailure([
      "authorize-release-key",
      "--root-private-key",
      path.join(rootDir, "root-private-key.pem"),
      "--root-passphrase-file",
      wrongPassphrasePath,
      "--release-public-key",
      path.join(releaseDir, "release-public-key.pem"),
      "--generation",
      "1",
      "--output-dir",
      delegationDir,
    ]);

    expect(failure.stderr).toMatch(/could not be unlocked/);
    expect(failure.stderr).not.toContain(
      "wrong passphrase 98765432101234567890",
    );
    await expect(lstat(delegationDir)).rejects.toMatchObject({
      code: "ENOENT",
    });

    await rm(workDir, { force: true, recursive: true });
  });

  it("refuses insecure passphrase files and will not overwrite or follow output directories", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const privatePassphrasePath = path.join(workDir, "private-passphrase");
    const broadPassphrasePath = path.join(workDir, "broad-passphrase");
    const linkedPassphrasePath = path.join(workDir, "linked-passphrase");
    await writeFile(
      privatePassphrasePath,
      "correct horse battery staple 0123456789\n",
      {
        mode: 0o600,
      },
    );
    await writeFile(
      broadPassphrasePath,
      "correct horse battery staple 0123456789\n",
      {
        mode: 0o644,
      },
    );
    await chmod(broadPassphrasePath, 0o644);
    await symlink(privatePassphrasePath, linkedPassphrasePath);

    const broadFailure = await expectCliFailure([
      "init-root",
      "--output-dir",
      path.join(workDir, "broad-root"),
      "--passphrase-file",
      broadPassphrasePath,
    ]);
    expect(broadFailure.stderr).toMatch(
      /permissions must not be wider than 0600/,
    );
    await expect(lstat(path.join(workDir, "broad-root"))).rejects.toMatchObject(
      {
        code: "ENOENT",
      },
    );

    const symlinkFailure = await expectCliFailure([
      "init-root",
      "--output-dir",
      path.join(workDir, "linked-root"),
      "--passphrase-file",
      linkedPassphrasePath,
    ]);
    expect(symlinkFailure.stderr).toMatch(/regular non-symbolic-link file/);

    const existingRoot = path.join(workDir, "existing-root");
    await mkdir(existingRoot, { mode: 0o700 });
    const overwriteFailure = await expectCliFailure([
      "init-root",
      "--output-dir",
      existingRoot,
      "--passphrase-file",
      privatePassphrasePath,
    ]);
    expect(overwriteFailure.stderr).toMatch(/output directory already exists/);

    const linkedRoot = path.join(workDir, "linked-root");
    await symlink(existingRoot, linkedRoot);
    const linkedOutputFailure = await expectCliFailure([
      "init-root",
      "--output-dir",
      linkedRoot,
      "--passphrase-file",
      privatePassphrasePath,
    ]);
    expect(linkedOutputFailure.stderr).toMatch(
      /output directory already exists/,
    );
    expect(await lstat(existingRoot)).toMatchObject({
      isDirectory: expect.any(Function),
    });

    await rm(workDir, { force: true, recursive: true });
  });

  it("fails closed for tampered, wrong-root, wrong-distribution, and rolled-back delegations", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const passphrasePath = path.join(workDir, "root-passphrase");
    const rootDir = path.join(workDir, "root");
    const otherRootDir = path.join(workDir, "other-root");
    const releaseDir = path.join(workDir, "release");
    const delegationDir = path.join(workDir, "delegation");
    const delegationPath = path.join(delegationDir, "trust-delegation.json");
    const signaturePath = path.join(delegationDir, "trust-delegation.json.sig");
    await writeFile(
      passphrasePath,
      "correct horse battery staple 0123456789\n",
      {
        mode: 0o600,
      },
    );
    await runCli([
      "init-root",
      "--output-dir",
      rootDir,
      "--passphrase-file",
      passphrasePath,
    ]);
    await runCli([
      "init-root",
      "--output-dir",
      otherRootDir,
      "--passphrase-file",
      passphrasePath,
    ]);
    await runCli(["init-release-key", "--output-dir", releaseDir]);
    await runCli([
      "authorize-release-key",
      "--root-private-key",
      path.join(rootDir, "root-private-key.pem"),
      "--root-passphrase-file",
      passphrasePath,
      "--release-public-key",
      path.join(releaseDir, "release-public-key.pem"),
      "--generation",
      "7",
      "--output-dir",
      delegationDir,
    ]);
    const delegation = await readFile(delegationPath);
    const tamperedPath = path.join(workDir, "tampered.json");
    const wrongDistributionPath = path.join(workDir, "wrong-distribution.json");
    const invalidGenerationPath = path.join(workDir, "invalid-generation.json");
    await writeFile(
      tamperedPath,
      Buffer.concat([delegation, Buffer.from(" ")]),
    );
    const parsed = JSON.parse(delegation.toString("utf8"));
    await writeFile(
      wrongDistributionPath,
      `${JSON.stringify({ ...parsed, distribution: "other" })}\n`,
    );
    await writeFile(
      invalidGenerationPath,
      `${JSON.stringify({ ...parsed, generation: 0 })}\n`,
    );

    const verifyArguments = (rootPublicKey, delegationInput, generation) => [
      "verify",
      "--root-public-key",
      rootPublicKey,
      "--delegation",
      delegationInput,
      "--signature",
      signaturePath,
      "--highest-accepted-generation",
      generation,
    ];
    const rootPublicKey = path.join(rootDir, "root-public-key.pem");
    const failures = await Promise.all([
      expectCliFailure(verifyArguments(rootPublicKey, tamperedPath, "0")),
      expectCliFailure(
        verifyArguments(
          path.join(otherRootDir, "root-public-key.pem"),
          delegationPath,
          "0",
        ),
      ),
      expectCliFailure(
        verifyArguments(rootPublicKey, wrongDistributionPath, "0"),
      ),
      expectCliFailure(
        verifyArguments(rootPublicKey, invalidGenerationPath, "0"),
      ),
      expectCliFailure(verifyArguments(rootPublicKey, delegationPath, "8")),
    ]);

    for (const failure of failures) {
      expect(failure.stdout).toBe("");
      expect(failure.stderr).not.toContain(
        "correct horse battery staple 0123456789",
      );
    }
    expect(failures[0].stderr).toMatch(/canonical encoding/);
    expect(failures[1].stderr).toMatch(/binding is invalid/);
    expect(failures[2].stderr).toMatch(/binding is invalid/);
    expect(failures[3].stderr).toMatch(/fields are invalid/);
    expect(failures[4].stderr).toMatch(/not newer than installed trust/);

    await rm(workDir, { force: true, recursive: true });
  });

  it("rejects symbolic-link and broadly readable root private-key inputs before authorization", async () => {
    const workDir = await mkdtemp(path.join(tmpdir(), "enoki-probe-trust-"));
    const passphrasePath = path.join(workDir, "root-passphrase");
    const rootDir = path.join(workDir, "root");
    const releaseDir = path.join(workDir, "release");
    const rootPrivateKey = path.join(rootDir, "root-private-key.pem");
    const linkedPrivateKey = path.join(workDir, "linked-root-private-key.pem");
    await writeFile(
      passphrasePath,
      "correct horse battery staple 0123456789\n",
      {
        mode: 0o600,
      },
    );
    await runCli([
      "init-root",
      "--output-dir",
      rootDir,
      "--passphrase-file",
      passphrasePath,
    ]);
    await runCli(["init-release-key", "--output-dir", releaseDir]);
    await symlink(rootPrivateKey, linkedPrivateKey);

    const authorizationArguments = (
      privateKeyPath,
      outputDir,
      generation = "1",
    ) => [
      "authorize-release-key",
      "--root-private-key",
      privateKeyPath,
      "--root-passphrase-file",
      passphrasePath,
      "--release-public-key",
      path.join(releaseDir, "release-public-key.pem"),
      "--generation",
      generation,
      "--output-dir",
      outputDir,
    ];
    const symlinkOutput = path.join(workDir, "symlink-delegation");
    const symlinkFailure = await expectCliFailure(
      authorizationArguments(linkedPrivateKey, symlinkOutput),
    );
    expect(symlinkFailure.stderr).toMatch(/regular non-symbolic-link file/);
    await expect(lstat(symlinkOutput)).rejects.toMatchObject({
      code: "ENOENT",
    });

    await chmod(rootPrivateKey, 0o640);
    const broadOutput = path.join(workDir, "broad-delegation");
    const broadFailure = await expectCliFailure(
      authorizationArguments(rootPrivateKey, broadOutput),
    );
    expect(broadFailure.stderr).toMatch(
      /permissions must not be wider than 0600/,
    );
    await expect(lstat(broadOutput)).rejects.toMatchObject({ code: "ENOENT" });

    const invalidGenerationOutput = path.join(workDir, "invalid-generation");
    const invalidGenerationFailure = await expectCliFailure(
      authorizationArguments(
        rootPrivateKey,
        invalidGenerationOutput,
        "9007199254740992",
      ),
    );
    expect(invalidGenerationFailure.stderr).toMatch(
      /generation must be a safe integer greater than or equal to 1/,
    );
    await expect(lstat(invalidGenerationOutput)).rejects.toMatchObject({
      code: "ENOENT",
    });

    await rm(workDir, { force: true, recursive: true });
  });
});
