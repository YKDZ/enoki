import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { createGunzip } from "node:zlib";

import {
  isSafeInteger,
  isUnknownArray,
  isUnknownRecord,
  objectView,
  type UnknownRecord,
} from "./release-json-guards.ts";

const execFileAsync = promisify(execFile);
const imageConfigMediaTypes = new Set<unknown>([
  "application/vnd.docker.container.image.v1+json",
  "application/vnd.oci.image.config.v1+json",
]);
const imageManifestMediaTypes = new Set<unknown>([
  "application/vnd.docker.distribution.manifest.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
]);
const layerMediaTypes = new Set<unknown>([
  "application/vnd.docker.image.rootfs.diff.tar.gzip",
  "application/vnd.oci.image.layer.v1.tar",
  "application/vnd.oci.image.layer.v1.tar+gzip",
]);

export interface ProbeAssetFileIdentity {
  file: string;
  sha256: string;
  size: number;
}

export interface HubOciArchiveInspection {
  digest: string;
}

interface OciDescriptor {
  digest: string;
  mediaType: unknown;
  size: number;
}

interface RootfsProbeFileEntry {
  contents: Buffer | null;
  type: string;
}

interface LayerRootfsState {
  appType: string;
  probeAssetsType: string;
  probeFiles: Map<string, RootfsProbeFileEntry>;
}

interface TarEntry {
  path: string;
  rawName: string;
  type: string;
}

export async function inspectHubOciArchive({
  archivePath,
  probeFiles,
}: {
  archivePath: string;
  probeFiles: readonly ProbeAssetFileIdentity[];
}): Promise<HubOciArchiveInspection> {
  const extractionDir = await mkdtemp(path.join(tmpdir(), "enoki-hub-oci-"));

  try {
    await execFileAsync(
      "tar",
      [
        "--extract",
        "--file",
        archivePath,
        "--directory",
        extractionDir,
        "--no-same-owner",
        "--no-same-permissions",
      ],
      { maxBuffer: 16 * 1024 * 1024 },
    );
    await assertOciLayoutRoot(extractionDir);

    const layout = await readJson(path.join(extractionDir, "oci-layout"));
    if (layout.imageLayoutVersion !== "1.0.0") {
      throw new Error("Hub OCI archive has an unsupported layout version");
    }

    const index = await readJson(path.join(extractionDir, "index.json"));
    const manifests = isUnknownArray(index.manifests)
      ? index.manifests
      : null;
    if (index.schemaVersion !== 2 || !manifests || manifests.length !== 1) {
      throw new Error(
        "Hub OCI archive must contain exactly one image manifest",
      );
    }

    const referencedBlobs = new Set<string>();
    const imageManifestDescriptor = objectView(manifests[0]);
    if (!imageManifestMediaTypes.has(imageManifestDescriptor.mediaType)) {
      throw new Error(
        "Hub OCI archive does not point to an OCI image manifest",
      );
    }
    validateDescriptorShape(imageManifestDescriptor);
    const manifestPath = await verifyDescriptor(
      extractionDir,
      imageManifestDescriptor,
      referencedBlobs,
    );
    const imageManifest = await readJson(manifestPath);
    const imageLayers = isUnknownArray(imageManifest.layers)
      ? imageManifest.layers
      : null;
    if (
      imageManifest.schemaVersion !== 2 ||
      imageManifest.mediaType !== imageManifestDescriptor.mediaType ||
      !imageManifest.config ||
      !imageLayers ||
      imageLayers.length === 0
    ) {
      throw new Error("Hub OCI image manifest is malformed");
    }
    const configDescriptor = objectView(imageManifest.config);
    if (!imageConfigMediaTypes.has(configDescriptor.mediaType)) {
      throw new Error(
        "Hub OCI image config descriptor media type is unsupported",
      );
    }

    const configPath = await verifyDescriptor(
      extractionDir,
      configDescriptor,
      referencedBlobs,
    );
    const imageConfig = await readJson(configPath);
    if (imageConfig.os !== "linux" || imageConfig.architecture !== "amd64") {
      throw new Error("Hub OCI image config must target linux/amd64");
    }
    const rootfsRecord = isUnknownRecord(imageConfig.rootfs)
      ? imageConfig.rootfs
      : null;
    const diffIds = rootfsRecord
      ? isUnknownArray(rootfsRecord.diff_ids)
        ? rootfsRecord.diff_ids
        : null
      : null;
    if (
      !imageConfig.rootfs ||
      !rootfsRecord ||
      !diffIds ||
      rootfsRecord.type !== "layers" ||
      diffIds.length !== imageLayers.length
    ) {
      throw new Error("Hub OCI image rootfs diff_ids must match image layers");
    }
    const rootfs: LayerRootfsState = {
      appType: "absent",
      probeAssetsType: "absent",
      probeFiles: new Map(),
    };
    for (const [position, layer] of imageLayers.entries()) {
      const layerDescriptor = objectView(layer);
      const layerPath = await verifyDescriptor(
        extractionDir,
        layerDescriptor,
        referencedBlobs,
      );
      if (
        diffIds[position] !==
        (await uncompressedLayerDigest(layerPath, layerDescriptor.mediaType))
      ) {
        throw new Error(
          `Hub OCI image rootfs diff_id does not match layer ${position}`,
        );
      }
      await applyProbeAssetsFromLayer(
        layerPath,
        layerDescriptor.mediaType,
        rootfs,
      );
    }

    await assertNoUnreferencedBlobs(extractionDir, referencedBlobs);
    assertEmbeddedProbeFiles(rootfs, probeFiles);

    return {
      digest: imageManifestDescriptor.digest,
    };
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Hub OCI")) {
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Hub OCI archive is invalid: ${message}`);
  } finally {
    await rm(extractionDir, { force: true, recursive: true });
  }
}

async function assertOciLayoutRoot(extractionDir: string): Promise<void> {
  const entries = (await readdir(extractionDir)).sort();
  const expected = ["blobs", "index.json", "oci-layout"];
  if (JSON.stringify(entries) !== JSON.stringify(expected)) {
    throw new Error(
      `Hub OCI archive root must contain exactly: ${expected.join(", ")}`,
    );
  }

  const blobAlgorithms = await readdir(path.join(extractionDir, "blobs"));
  if (blobAlgorithms.length !== 1 || blobAlgorithms[0] !== "sha256") {
    throw new Error("Hub OCI archive must use only sha256-addressed blobs");
  }
}

function validateDescriptorShape(
  descriptor: unknown,
): asserts descriptor is OciDescriptor {
  if (
    !isUnknownRecord(descriptor) ||
    typeof descriptor.digest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(descriptor.digest) ||
    !isSafeInteger(descriptor.size) ||
    descriptor.size < 0
  ) {
    throw new Error("Hub OCI archive contains a malformed descriptor");
  }
}

async function verifyDescriptor(
  extractionDir: string,
  descriptor: unknown,
  referencedBlobs: Set<string>,
): Promise<string> {
  validateDescriptorShape(descriptor);

  const digestHex = descriptor.digest.slice("sha256:".length);
  const blobPath = path.join(extractionDir, "blobs", "sha256", digestHex);
  let details;
  try {
    details = await stat(blobPath);
  } catch {
    throw new Error(`Hub OCI archive is missing blob ${descriptor.digest}`);
  }
  if (!details.isFile() || details.size !== descriptor.size) {
    throw new Error(`Hub OCI blob size does not match ${descriptor.digest}`);
  }
  if ((await fileSha256(blobPath)) !== digestHex) {
    throw new Error(
      `Hub OCI blob digest does not match ${descriptor.digest}`,
    );
  }

  referencedBlobs.add(digestHex);
  return blobPath;
}

async function applyProbeAssetsFromLayer(
  layerPath: string,
  mediaType: unknown,
  rootfs: LayerRootfsState,
): Promise<void> {
  if (!layerMediaTypes.has(mediaType)) {
    throw new Error(
      `Hub OCI image layer media type is unsupported: ${String(mediaType)}`,
    );
  }

  const [{ stdout: namesOutput }, { stdout: verboseOutput }] =
    await Promise.all([
      execFileAsync("tar", ["--list", "--file", layerPath], {
        maxBuffer: 64 * 1024 * 1024,
      }),
      execFileAsync(
        "tar",
        ["--list", "--verbose", "--numeric-owner", "--file", layerPath],
        { maxBuffer: 64 * 1024 * 1024 },
      ),
    ]);
  const rawNames = nonemptyLines(namesOutput);
  const verboseLines = nonemptyLines(verboseOutput);
  if (rawNames.length !== verboseLines.length) {
    throw new Error("Hub OCI image layer entry metadata is malformed");
  }
  const entries: TarEntry[] = [];
  for (const [position, rawName] of rawNames.entries()) {
    const verboseLine = verboseLines[position];
    if (verboseLine === undefined) {
      throw new Error("Hub OCI image layer entry metadata is malformed");
    }
    entries.push({
      path: normalizedTarPath(rawName),
      rawName,
      type: verboseLine.charAt(0),
    });
  }
  for (const entry of entries) {
    if (
      entry.rawName.startsWith("/") ||
      (!entry.path && !/^[.][/]*$/.test(entry.rawName)) ||
      entry.path.startsWith("../") ||
      entry.path.includes("/../") ||
      entry.path === ".."
    ) {
      throw new Error("Hub OCI image layer contains an unsafe path");
    }
  }

  // OCI whiteouts remove lower-layer state before ordinary entries from this
  // layer are applied, including whiteouts in parents of /app/probe-assets.
  for (const entry of entries) {
    applyRelevantWhiteout(entry.path, rootfs);
  }

  for (const entry of entries) {
    if (pathBase(entry.path).startsWith(".wh.")) {
      continue;
    }
    if (entry.path === "app" || entry.path === "app/") {
      rootfs.appType = entry.type;
      if (entry.type !== "d") {
        clearProbeAssets(rootfs);
      }
      continue;
    }
    if (
      entry.path === "app/probe-assets" ||
      entry.path === "app/probe-assets/"
    ) {
      if (entry.type !== "d") {
        clearProbeAssets(rootfs);
        rootfs.probeAssetsType = entry.type;
      } else {
        rootfs.appType = "d";
        rootfs.probeAssetsType = "d";
      }
      continue;
    }

    const prefix = "app/probe-assets/";
    if (!entry.path.startsWith(prefix)) {
      continue;
    }
    const file = entry.path.slice(prefix.length);
    if (!file || file.includes("/")) {
      throw new Error(
        `Hub OCI Probe Asset Set contains nested path ${file}`,
      );
    }
    rootfs.appType = "d";
    rootfs.probeAssetsType = "d";
    if (entry.type !== "-") {
      rootfs.probeFiles.set(file, { contents: null, type: entry.type });
      continue;
    }
    const extracted = await execFileAsync(
      "tar",
      ["--extract", "--to-stdout", "--file", layerPath, entry.rawName],
      { encoding: null, maxBuffer: 1024 * 1024 * 1024 },
    );
    rootfs.probeFiles.set(file, {
      contents: Buffer.from(extracted.stdout),
      type: "-",
    });
  }
}

async function uncompressedLayerDigest(
  layerPath: string,
  mediaType: unknown,
): Promise<string> {
  if (!layerMediaTypes.has(mediaType)) {
    throw new Error(
      `Hub OCI image layer media type is unsupported: ${String(mediaType)}`,
    );
  }

  const hash = createHash("sha256");
  const input = createReadStream(layerPath);
  const contents =
    typeof mediaType === "string" && mediaType.endsWith("+gzip")
      ? input.pipe(createGunzip())
      : input;
  try {
    for await (const chunk of contents) {
      hash.update(chunk);
    }
  } catch {
    throw new Error("Hub OCI image layer compression is invalid");
  }
  return `sha256:${hash.digest("hex")}`;
}

function normalizedTarPath(value: string): string {
  return value
    .replace(/^(?:[.][/])+/, "")
    .replace(/^[/]+/, "")
    .replace(/[/]+$/, "");
}

function assertEmbeddedProbeFiles(
  rootfs: LayerRootfsState,
  probeFiles: readonly ProbeAssetFileIdentity[],
): void {
  const actualNames = [...rootfs.probeFiles.keys()].sort();
  const expectedNames = probeFiles.map(({ file }) => file).sort();
  if (
    rootfs.appType !== "d" ||
    rootfs.probeAssetsType !== "d" ||
    JSON.stringify(actualNames) !== JSON.stringify(expectedNames)
  ) {
    throw new Error(
      `Hub OCI embedded Probe Asset Set must contain exactly: ${expectedNames.join(", ")}`,
    );
  }

  const expectedByName = new Map<string, ProbeAssetFileIdentity>(
    probeFiles.map((entry) => [entry.file, entry]),
  );
  for (const [file, entry] of rootfs.probeFiles) {
    const expected = expectedByName.get(file);
    if (
      entry.type !== "-" ||
      entry.contents === null ||
      entry.contents.byteLength !== expected?.size ||
      sha256(entry.contents) !== expected?.sha256
    ) {
      throw new Error(`Hub OCI embedded Probe asset differs from ${file}`);
    }
  }
}

function applyRelevantWhiteout(entryPath: string, rootfs: LayerRootfsState): void {
  const base = pathBase(entryPath);
  if (!base.startsWith(".wh.")) {
    return;
  }
  const parent = pathParent(entryPath);
  if (base === ".wh..wh..opq") {
    if (parent === "" || parent === "app") {
      clearProbeAssets(rootfs);
      if (parent === "") {
        rootfs.appType = "absent";
      }
    } else if (parent === "app/probe-assets") {
      rootfs.probeFiles.clear();
      rootfs.appType = "d";
      rootfs.probeAssetsType = "d";
    }
    return;
  }

  const removedPath = `${parent ? `${parent}/` : ""}${base.slice(4)}`;
  if (removedPath === "app") {
    rootfs.appType = "absent";
    clearProbeAssets(rootfs);
  } else if (removedPath === "app/probe-assets") {
    clearProbeAssets(rootfs);
  } else if (removedPath.startsWith("app/probe-assets/")) {
    const file = removedPath.slice("app/probe-assets/".length);
    if (!file.includes("/")) {
      rootfs.probeFiles.delete(file);
    }
  }
}

function clearProbeAssets(rootfs: LayerRootfsState): void {
  rootfs.probeAssetsType = "absent";
  rootfs.probeFiles.clear();
}

function nonemptyLines(value: string): string[] {
  return value.split("\n").filter((line) => line.length > 0);
}

function pathBase(value: string): string {
  const index = value.lastIndexOf("/");
  return index === -1 ? value : value.slice(index + 1);
}

function pathParent(value: string): string {
  const index = value.lastIndexOf("/");
  return index === -1 ? "" : value.slice(0, index);
}

async function assertNoUnreferencedBlobs(
  extractionDir: string,
  referencedBlobs: Set<string>,
): Promise<void> {
  const actual = (
    await readdir(path.join(extractionDir, "blobs", "sha256"))
  ).sort();
  const expected = [...referencedBlobs].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("Hub OCI archive contains unreferenced or missing blobs");
  }
}

async function readJson(filePath: string): Promise<UnknownRecord> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(filePath, "utf8"));
  } catch {
    throw new Error(`Hub OCI archive contains malformed JSON at ${filePath}`);
  }
  if (!isUnknownRecord(value)) {
    throw new Error(`Hub OCI archive contains malformed JSON at ${filePath}`);
  }
  return value;
}

async function fileSha256(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filePath)) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

function sha256(contents: Buffer): string {
  return createHash("sha256").update(contents).digest("hex");
}
