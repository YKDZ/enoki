#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const defaultProbeAssetName = "enoki-probe-x86_64-unknown-linux-gnu.tar.gz";

const options = parseArguments(process.argv.slice(2));
const releaseJsonPath = requireOption(options, "release-json");
const hubManifestPath = requireOption(options, "hub-manifest");
const outputDir = requireOption(options, "out");
const probeAssetName = options["probe-asset"] ?? defaultProbeAssetName;

const release = JSON.parse(await readFile(releaseJsonPath, "utf8"));
const hubManifest = JSON.parse(await readFile(hubManifestPath, "utf8"));
const probeAsset = release.assets?.find(
  (asset) => asset.name === probeAssetName,
);

if (!probeAsset) {
  throw new Error(`Release asset not found: ${probeAssetName}`);
}
if (!Array.isArray(hubManifest.layers)) {
  throw new Error("Hub image manifest does not contain a layers array.");
}

const probeSizeBytes = numericSize(probeAsset.size, probeAssetName);
const hubSizeBytes = hubManifest.layers.reduce(
  (total, layer, index) =>
    total + numericSize(layer.size, `hub image layer ${index + 1}`),
  0,
);

await mkdir(outputDir, { recursive: true });
await writeBadge("badge-probe-size.json", {
  color: "brightgreen",
  label: "probe",
  message: formatMegabytes(probeSizeBytes),
});
await writeBadge("badge-hub-size.json", {
  color: "blue",
  label: "hub image",
  message: formatMegabytes(hubSizeBytes),
});

async function writeBadge(fileName, badge) {
  await writeFile(
    path.join(outputDir, fileName),
    `${JSON.stringify(
      {
        schemaVersion: 1,
        ...badge,
      },
      null,
      2,
    )}\n`,
  );
}

function formatMegabytes(bytes) {
  const megabytes = bytes / 1_000_000;
  const precision = megabytes >= 10 ? 1 : 2;

  return `${megabytes.toFixed(precision)} MB`;
}

function numericSize(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Invalid size for ${label}: ${value}`);
  }

  return value;
}

function parseArguments(args) {
  const result = {};

  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    if (!key?.startsWith("--")) {
      throw new Error(`Unexpected argument: ${key}`);
    }

    const value = args[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for ${key}`);
    }

    result[key.slice(2)] = value;
    index += 1;
  }

  return result;
}

function requireOption(options, name) {
  const value = options[name];
  if (!value) {
    throw new Error(`Missing required option: --${name}`);
  }

  return value;
}
