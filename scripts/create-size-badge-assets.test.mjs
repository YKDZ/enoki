import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(import.meta.dirname, "..");

test("create-size-badge-assets emits direct SVG badges for README usage", async () => {
  const workDir = await mkdtemp(path.join(tmpdir(), "enoki-badges-"));
  const outDir = path.join(workDir, "out");
  const releaseJsonPath = path.join(workDir, "release.json");
  const hubManifestPath = path.join(workDir, "hub-manifest.json");

  await writeFile(
    releaseJsonPath,
    JSON.stringify({
      assets: [
        {
          name: "enoki-probe-x86_64-unknown-linux-gnu.tar.gz",
          size: 987_509,
        },
      ],
    }),
  );
  await writeFile(
    hubManifestPath,
    JSON.stringify({
      layers: [{ size: 34_000_000 }, { size: 60_300_000 }],
    }),
  );

  await execFileAsync("node", [
    path.join(repositoryRoot, "scripts/create-size-badge-assets.mjs"),
    "--release-json",
    releaseJsonPath,
    "--hub-manifest",
    hubManifestPath,
    "--out",
    outDir,
  ]);

  const probeJson = JSON.parse(
    await readFile(path.join(outDir, "badge-probe-size.json"), "utf8"),
  );
  const probeSvg = await readFile(
    path.join(outDir, "badge-probe-size.svg"),
    "utf8",
  );
  const hubSvg = await readFile(
    path.join(outDir, "badge-hub-size.svg"),
    "utf8",
  );
  const readme = await readFile(path.join(repositoryRoot, "README.md"), "utf8");

  assert.equal(probeJson.message, "0.99 MB");
  assert.match(probeSvg, /<svg /);
  assert.match(probeSvg, /probe: 0\.99 MB/);
  assert.match(hubSvg, /hub image: 94\.3 MB/);
  assert.match(readme, /releases\/latest\/download\/badge-probe-size\.svg/);
  assert.doesNotMatch(readme, /img\.shields\.io\/endpoint/);
});
