import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const generatedDir = resolve(packageRoot, "src/generated");
const before = snapshotGeneratedOutput(generatedDir);
run("pnpm", ["--filter", "@enoki/proto", "generate"]);
const after = snapshotGeneratedOutput(generatedDir);

if (before !== after) {
  console.error(
    "Generated protobuf outputs drifted. Run `pnpm --filter @enoki/proto generate`.",
  );
  process.exit(1);
}

function run(command, args) {
  const result = spawnSync(command, args, {
    stdio: "inherit",
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function snapshotGeneratedOutput(directory) {
  const hash = createHash("sha256");

  for (const file of listFiles(directory)) {
    hash.update(file);
    hash.update(readFileSync(resolve(directory, file)));
  }

  return hash.digest("hex");
}

function listFiles(directory, prefix = "") {
  return readdirSync(resolve(directory, prefix))
    .flatMap((entry) => {
      const relativePath = prefix ? `${prefix}/${entry}` : entry;
      const absolutePath = resolve(directory, relativePath);

      if (statSync(absolutePath).isDirectory()) {
        return listFiles(directory, relativePath);
      }

      return [relativePath];
    })
    .sort();
}
