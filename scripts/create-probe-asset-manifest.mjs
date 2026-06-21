#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const distDir = process.argv[2] ?? "dist";
const version =
  process.env.ENOKI_PROBE_VERSION ?? process.env.RELEASE_TAG ?? "";

if (!version) {
  throw new Error("ENOKI_PROBE_VERSION or RELEASE_TAG is required.");
}

const files = await readdir(distDir);
const assets = [];

for (const file of files.sort()) {
  const match = /^enoki-probe-(.+)[.]tar[.]gz$/.exec(file);
  if (!match) {
    continue;
  }

  const contents = await readFile(path.join(distDir, file));
  assets.push({
    file,
    sha256: createHash("sha256").update(contents).digest("hex"),
    size: contents.byteLength,
    target: match[1],
  });
}

if (assets.length === 0) {
  throw new Error(`no enoki-probe-*.tar.gz assets found in ${distDir}`);
}

await writeFile(
  path.join(distDir, "manifest.json"),
  `${JSON.stringify(
    {
      assets,
      kind: "enoki-probe-assets",
      signature: {
        algorithm: "rsa-sha256",
        file: "manifest.json.sig",
        publicKey: "signing-key.pem",
      },
      version,
    },
    null,
    2,
  )}\n`,
);
