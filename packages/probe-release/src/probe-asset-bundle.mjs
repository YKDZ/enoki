import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { inspectProbeElf } from "./legacy-probe-asset-set.mjs";

const execFileAsync = promisify(execFile);

/**
 * 当前单 Probe 产品的固定安装包角色清单。
 *
 * Bootstrap 仍由更窄的构建环境产出，但这里只把它视为同一个公开
 * Probe Asset Bundle 的固定入口，不能从调用方输入推导路径或角色。
 */
export const probeBundleComponentProfiles = Object.freeze({
  probe: Object.freeze({
    path: "enoki-probe",
    permissionProfile: "probe-v5",
    resourceContract: "hub-reporting-v1",
  }),
  "observation-runtime": Object.freeze({
    path: "enoki-observation-runtime",
    permissionProfile: "observation-runtime-v4",
    resourceContract: "official-observation-v2",
  }),
  "system-state-provider": Object.freeze({
    path: "enoki-cpu-resource-provider",
    permissionProfile: "system-state-provider-v5",
    resourceContract: "system-state-v3",
  }),
  "disk-health-provider": Object.freeze({
    path: "enoki-disk-health-resource-provider",
    permissionProfile: "disk-health-provider-v3",
    resourceContract: "disk-health-v1",
  }),
  "lifecycle-companion": Object.freeze({
    path: "enoki-probe-lifecycle-companion",
    permissionProfile: "lifecycle-companion-v3",
    resourceContract: "local-lifecycle-v1",
  }),
});

export const probeBundledBootstrapAssets = Object.freeze([
  Object.freeze({
    archivePath: "bootstrap/enoki-probe-bootstrap-acquire",
    bootstrapBuildRole: "acquirer",
    key: "acquirer",
    permissionProfile: "bootstrap-acquirer-v1",
    role: "bootstrap-acquirer",
  }),
  Object.freeze({
    archivePath: "bootstrap/enoki-probe-bootstrap-activate",
    bootstrapBuildRole: "activator",
    key: "activator",
    permissionProfile: "bootstrap-activator-v1",
    role: "bootstrap-activator",
  }),
]);

export const probeTargets = Object.freeze([
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
]);

export async function inspectProbeBundleArchiveBytes(
  archive,
  { target, version },
) {
  const extractionDir = await mkdtemp(
    path.join(tmpdir(), "enoki-probe-bundle-"),
  );
  const archivePath = path.join(extractionDir, "archive.tar.gz");
  try {
    await writeFile(archivePath, archive, { mode: 0o600 });
    const componentListing = [
      "bundle-manifest.json",
      ...Object.values(probeBundleComponentProfiles).map(({ path }) => path),
    ];
    let listing;
    try {
      ({ stdout: listing } = await execFileAsync(
        "tar",
        ["--list", "--gzip", "--file", archivePath],
        { env: toolEnvironment(), maxBuffer: 1024 * 1024 },
      ));
    } catch {
      throw new Error("Probe bundle archive is invalid");
    }
    const bootstrapListing = [
      ...componentListing,
      ...probeBundledBootstrapAssets.map(({ archivePath }) => archivePath),
    ];
    const hasBundledBootstrap = listing === `${bootstrapListing.join("\n")}\n`;
    if (
      !hasBundledBootstrap &&
      listing !== `${componentListing.join("\n")}\n`
    ) {
      throw new Error("Probe bundle archive closure is invalid");
    }
    try {
      await execFileAsync(
        "tar",
        [
          "--extract",
          "--gzip",
          "--file",
          archivePath,
          "--directory",
          extractionDir,
          "--no-same-owner",
        ],
        { env: toolEnvironment(), maxBuffer: 1024 * 1024 },
      );
    } catch {
      throw new Error("Probe bundle archive is invalid");
    }
    const componentDetails = new Map();
    for (const [role, profile] of Object.entries(
      probeBundleComponentProfiles,
    )) {
      const componentPath = path.join(extractionDir, profile.path);
      const details = await lstat(componentPath);
      if (!details.isFile() || (details.mode & 0o111) === 0) {
        throw new Error("Probe bundle component is invalid");
      }
      const bytes = await readFile(componentPath);
      inspectProbeElf(bytes, { target, version });
      componentDetails.set(role, {
        sha256: sha256(bytes),
        size: bytes.byteLength,
      });
    }
    const bootstrapDetails = hasBundledBootstrap ? new Map() : undefined;
    if (bootstrapDetails) {
      for (const asset of probeBundledBootstrapAssets) {
        const assetPath = path.join(extractionDir, asset.archivePath);
        const details = await lstat(assetPath);
        if (!details.isFile() || (details.mode & 0o111) === 0) {
          throw new Error("Probe bundle Bootstrap asset is invalid");
        }
        const bytes = await readFile(assetPath);
        bootstrapDetails.set(asset.role, {
          sha256: sha256(bytes),
          size: bytes.byteLength,
        });
      }
    }
    const manifestPath = path.join(extractionDir, "bundle-manifest.json");
    const manifestDetails = await lstat(manifestPath);
    if (!manifestDetails.isFile()) {
      throw new Error("Probe bundle manifest is invalid");
    }
    const manifestBytes = await readFile(manifestPath);
    validateProbeBundleManifest(manifestBytes, {
      bootstrapDetails,
      componentDetails,
      target,
      version: version.slice(1),
    });
    return {
      bundleManifestSha256: sha256(manifestBytes),
      probeSha256: componentDetails.get("probe").sha256,
    };
  } finally {
    await rm(extractionDir, { force: true, recursive: true });
  }
}

function validateProbeBundleManifest(
  bytes,
  { bootstrapDetails, componentDetails, target, version },
) {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("Probe bundle manifest is malformed");
  }
  if (
    !plainObject(manifest) ||
    !exactKeys(
      manifest,
      bootstrapDetails
        ? ["bootstrapAssets", "components", "kind", "target", "version"]
        : ["components", "kind", "target", "version"],
    ) ||
    manifest.kind !== "enoki-probe-bundle" ||
    manifest.target !== target ||
    manifest.version !== version ||
    !Array.isArray(manifest.components) ||
    manifest.components.length !==
      Object.keys(probeBundleComponentProfiles).length
  ) {
    throw new Error("Probe bundle manifest is incoherent");
  }
  const byRole = new Map();
  for (const component of manifest.components) {
    if (
      !plainObject(component) ||
      !exactKeys(component, [
        "path",
        "permissionProfile",
        "resourceContract",
        "role",
        "sha256",
        "size",
        "version",
      ]) ||
      typeof component.role !== "string" ||
      byRole.has(component.role)
    ) {
      throw new Error("Probe bundle component is incoherent");
    }
    byRole.set(component.role, component);
  }
  for (const [role, profile] of Object.entries(probeBundleComponentProfiles)) {
    const component = byRole.get(role);
    const details = componentDetails.get(role);
    if (
      !component ||
      component.path !== profile.path ||
      component.permissionProfile !== profile.permissionProfile ||
      component.resourceContract !== profile.resourceContract ||
      component.sha256 !== details?.sha256 ||
      component.size !== details?.size ||
      component.version !== version
    ) {
      throw new Error(
        `Probe bundle component is incoherent: ${role} ${JSON.stringify(component)} ${JSON.stringify(details)}`,
      );
    }
  }
  if (bootstrapDetails) {
    if (
      !Array.isArray(manifest.bootstrapAssets) ||
      manifest.bootstrapAssets.length !== probeBundledBootstrapAssets.length
    ) {
      throw new Error("Probe bundle Bootstrap asset is incoherent");
    }
    const byRole = new Map();
    for (const asset of manifest.bootstrapAssets) {
      if (
        !plainObject(asset) ||
        !exactKeys(asset, [
          "path",
          "permissionProfile",
          "role",
          "sha256",
          "size",
          "version",
        ]) ||
        typeof asset.role !== "string" ||
        byRole.has(asset.role)
      ) {
        throw new Error("Probe bundle Bootstrap asset is incoherent");
      }
      byRole.set(asset.role, asset);
    }
    for (const expected of probeBundledBootstrapAssets) {
      const asset = byRole.get(expected.role);
      const details = bootstrapDetails.get(expected.role);
      if (
        !asset ||
        asset.path !== expected.archivePath ||
        asset.permissionProfile !== expected.permissionProfile ||
        asset.sha256 !== details?.sha256 ||
        asset.size !== details?.size ||
        asset.version !== version
      ) {
        throw new Error("Probe bundle Bootstrap asset is incoherent");
      }
    }
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function plainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
  return (
    plainObject(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

function toolEnvironment() {
  return { LANG: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" };
}
