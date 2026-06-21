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
await writeBadgeAssets("badge-probe-size", {
  color: "brightgreen",
  label: "probe",
  message: formatMegabytes(probeSizeBytes),
});
await writeBadgeAssets("badge-hub-size", {
  color: "blue",
  label: "hub image",
  message: formatMegabytes(hubSizeBytes),
});

async function writeBadgeAssets(baseName, badge) {
  await Promise.all([
    writeBadgeJson(`${baseName}.json`, badge),
    writeBadgeSvg(`${baseName}.svg`, badge),
  ]);
}

async function writeBadgeJson(fileName, badge) {
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

async function writeBadgeSvg(fileName, badge) {
  const labelWidth = badgeTextWidth(badge.label);
  const messageWidth = badgeTextWidth(badge.message);
  const width = labelWidth + messageWidth;
  const labelCenter = labelWidth / 2;
  const messageCenter = labelWidth + messageWidth / 2;
  const color = badgeColor(badge.color);

  await writeFile(
    path.join(outputDir, fileName),
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="${escapeXml(badge.label)}: ${escapeXml(badge.message)}">
  <title>${escapeXml(badge.label)}: ${escapeXml(badge.message)}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${width}" height="20" rx="3"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${messageWidth}" height="20" fill="${color}"/>
    <rect width="${width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="${labelCenter * 10}" y="140" transform="scale(.1)" textLength="${(labelWidth - 10) * 10}">${escapeXml(badge.label)}</text>
    <text x="${messageCenter * 10}" y="140" transform="scale(.1)" textLength="${(messageWidth - 10) * 10}">${escapeXml(badge.message)}</text>
  </g>
</svg>
`,
  );
}

function badgeTextWidth(text) {
  return Math.max(30, text.length * 7 + 10);
}

function badgeColor(color) {
  const colors = {
    blue: "#007ec6",
    brightgreen: "#4c1",
  };

  return colors[color] ?? color;
}

function escapeXml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
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
