import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(packageRoot, "../..");
const protoRoot = resolve(packageRoot, "proto");
const protoFile = resolve(packageRoot, "proto/enoki/v1/probe.proto");
const tsOut = resolve(packageRoot, "src/generated/ts");
const generatedTsFile = resolve(tsOut, "enoki_pb.js");
const generatedTsTypesFile = resolve(tsOut, "enoki_pb.d.ts");
const generatedTsTypesInputFile = resolve(tsOut, "enoki_pb.types-input.js");
const rustOut = resolve(packageRoot, "src/generated/rust");

mkdirSync(tsOut, { recursive: true });
mkdirSync(rustOut, { recursive: true });

run("pnpm", [
  "exec",
  "pbjs",
  "--target",
  "static-module",
  "--wrap",
  "es6",
  "--force-long",
  "--out",
  generatedTsFile,
  protoFile,
]);

run("pnpm", [
  "exec",
  "pbjs",
  "--target",
  "static-module",
  "--wrap",
  "default",
  "--force-long",
  "--out",
  generatedTsTypesInputFile,
  protoFile,
]);

run("pnpm", [
  "exec",
  "pbts",
  "--out",
  generatedTsTypesFile,
  generatedTsTypesInputFile,
]);

rewriteGeneratedEsmImports(generatedTsFile);
removeGeneratedTsTypesInput(generatedTsTypesInputFile);

run("cargo", [
  "run",
  "--quiet",
  "--package",
  "enoki-proto-gen",
  "--",
  protoFile,
  protoRoot,
  rustOut,
]);

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: "inherit",
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function rewriteGeneratedEsmImports(file) {
  const source = readFileSync(file, "utf8");
  const rewritten = source.replace(
    'import * as $protobuf from "protobufjs/minimal";',
    'import $protobuf from "protobufjs/minimal.js";',
  );

  if (rewritten !== source) {
    writeFileSync(file, rewritten);
  }
}

function removeGeneratedTsTypesInput(file) {
  rmSync(file, { force: true });
}
