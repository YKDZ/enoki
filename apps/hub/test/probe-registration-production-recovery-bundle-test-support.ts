import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// @ts-expect-error 仓库 JavaScript 角色清单没有类型声明。
import * as probeAssetBundle from "../../../scripts/probe-asset-bundle.mjs";
import { requireCommand } from "./probe-registration-production-recovery-command-test-support";

const workspaceRoot = fileURLToPath(new URL("../../..", import.meta.url));
const { probeBundleComponentProfiles, probeBundledBootstrapAssets } =
  probeAssetBundle;

export type ProductionBundle = {
  acquirerPath: string;
  archive: Buffer;
  archivePath: string;
  bundleManifest: Buffer;
};

export async function buildProductionBundle(input: {
  dataRoot: string;
  rootPublicKeyPem: string;
  version: string;
}): Promise<ProductionBundle> {
  const target = "x86_64-unknown-linux-gnu";
  const probeTargetDir = path.join(input.dataRoot, "cargo-probe");
  await requireCommand(
    "cargo",
    [
      "build",
      "-p",
      "enoki-probe",
      "--bins",
      "--features",
      "deterministic-test-seams",
      "--target",
      target,
      "--target-dir",
      probeTargetDir,
    ],
    {
      cwd: workspaceRoot,
      env: { ENOKI_PROBE_VERSION: input.version },
    },
  );
  const probeBinaryDir = path.join(probeTargetDir, target, "debug");
  const bootstrapPaths: Record<"acquirer" | "activator", string> = {
    acquirer: "",
    activator: "",
  };
  for (const role of ["acquirer", "activator"] as const) {
    const binaryName = `enoki-probe-bootstrap-${role === "acquirer" ? "acquire" : "activate"}`;
    const targetDir = path.join(input.dataRoot, `cargo-bootstrap-${role}`);
    await requireCommand(
      "cargo",
      [
        "build",
        "-p",
        "enoki-probe-bootstrap",
        "--bin",
        binaryName,
        "--no-default-features",
        "--features",
        `${role},compiled-trust`,
        "--target",
        target,
        "--target-dir",
        targetDir,
      ],
      {
        cwd: workspaceRoot,
        env: {
          ENOKI_BOOTSTRAP_BUILD_DISTRIBUTION: "enoki",
          ENOKI_BOOTSTRAP_BUILD_ROLE: role,
          ENOKI_BOOTSTRAP_BUILD_ROOT_PEM: input.rootPublicKeyPem,
          ENOKI_BOOTSTRAP_BUILD_TARGET: target,
          ENOKI_BOOTSTRAP_BUILD_VERSION: `v${input.version}`,
        },
      },
    );
    bootstrapPaths[role] = path.join(targetDir, target, "debug", binaryName);
  }

  const staging = path.join(input.dataRoot, "production-bundle");
  await mkdir(path.join(staging, "bootstrap"), { recursive: true });
  const componentProfiles = probeBundleComponentProfiles as Record<
    string,
    {
      path: string;
      permissionProfile: string;
      resourceContract: string;
    }
  >;
  const bootstrapAssets = probeBundledBootstrapAssets as Array<{
    archivePath: string;
    key: "acquirer" | "activator";
    permissionProfile: string;
    role: string;
  }>;
  const components = [];
  for (const [role, profile] of Object.entries(componentProfiles)) {
    const source = path.join(probeBinaryDir, profile.path);
    const destination = path.join(staging, profile.path);
    await copyFile(source, destination);
    await chmod(destination, 0o755);
    const bytes = await readFile(destination);
    components.push({
      path: profile.path,
      permissionProfile: profile.permissionProfile,
      resourceContract: profile.resourceContract,
      role,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.byteLength,
      version: input.version,
    });
  }
  const bootstrapComponents = [];
  for (const asset of bootstrapAssets) {
    const destination = path.join(staging, asset.archivePath);
    await copyFile(bootstrapPaths[asset.key], destination);
    await chmod(destination, 0o755);
    const bytes = await readFile(destination);
    bootstrapComponents.push({
      path: asset.archivePath,
      permissionProfile: asset.permissionProfile,
      role: asset.role,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.byteLength,
      version: input.version,
    });
  }
  const bundleManifest = Buffer.from(
    `${JSON.stringify(
      {
        bootstrapAssets: bootstrapComponents,
        components,
        kind: "enoki-probe-bundle",
        target,
        version: input.version,
      },
      null,
      2,
    )}\n`,
  );
  await writeFile(path.join(staging, "bundle-manifest.json"), bundleManifest);
  const archivePath = path.join(input.dataRoot, `enoki-probe-${target}.tar.gz`);
  await requireCommand("tar", [
    "--create",
    "--gzip",
    "--sort=name",
    "--owner=0",
    "--group=0",
    "--numeric-owner",
    "--blocking-factor=1",
    "--mtime=@0",
    "--format=gnu",
    "--file",
    archivePath,
    "--directory",
    staging,
    "bundle-manifest.json",
    ...Object.values(componentProfiles).map(
      ({ path: componentPath }) => componentPath,
    ),
    ...bootstrapAssets.map(({ archivePath: bootstrapPath }) => bootstrapPath),
  ]);
  return {
    acquirerPath: bootstrapPaths.acquirer,
    archive: await readFile(archivePath),
    archivePath,
    bundleManifest,
  };
}
