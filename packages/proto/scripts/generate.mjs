import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(packageRoot, "../..");
const protoRoot = resolve(packageRoot, "proto");
const protoFile = resolve(packageRoot, "proto/enoki/v1/probe.proto");
const generatedOut = resolve(packageRoot, "src/generated");
const tsOut = resolve(generatedOut, "ts");
const generatedTsFile = resolve(tsOut, "enoki_pb.js");
const generatedTsTypesFile = resolve(tsOut, "enoki_pb.d.ts");
const generatedTsTypesInputFile = resolve(tsOut, "enoki_pb.types-input.js");
const rustOut = resolve(generatedOut, "rust");
const stagingOut = mkdtempSync(resolve(dirname(generatedOut), ".generated-"));
const stagingTsOut = resolve(stagingOut, "ts");
const stagingTsFile = resolve(stagingTsOut, "enoki_pb.js");
const stagingTsTypesFile = resolve(stagingTsOut, "enoki_pb.d.ts");
const stagingTsTypesInputFile = resolve(
  stagingTsOut,
  "enoki_pb.types-input.js",
);
const stagingRustOut = resolve(stagingOut, "rust");

class CommandFailedError extends Error {
  constructor(status) {
    super();
    this.status = status;
  }
}

class GenerationInterruptedError extends Error {
  constructor(signal) {
    super();
    this.signal = signal;
  }
}

const signalExitCodes = {
  SIGINT: 130,
  SIGTERM: 143,
};
let interruption;
const signalHandlers = Object.keys(signalExitCodes).map((signal) => {
  const handler = () => {
    interruption ??= signal;
  };

  process.once(signal, handler);
  return [signal, handler];
});

try {
  mkdirSync(stagingTsOut, { recursive: true });
  mkdirSync(stagingRustOut, { recursive: true });

  await run("pnpm", [
    "exec",
    "pbjs",
    "--target",
    "static-module",
    "--path",
    protoRoot,
    "--wrap",
    "es6",
    "--force-long",
    "--out",
    stagingTsFile,
    protoFile,
  ]);

  await run("pnpm", [
    "exec",
    "pbjs",
    "--target",
    "static-module",
    "--path",
    protoRoot,
    "--wrap",
    "default",
    "--out",
    stagingTsTypesInputFile,
    protoFile,
  ]);

  await run("pnpm", [
    "exec",
    "pbts",
    "--out",
    stagingTsTypesFile,
    stagingTsTypesInputFile,
  ]);

  rewriteGeneratedEsmImports(stagingTsFile);
  removeGeneratedTsTypesInput(stagingTsTypesInputFile);

  await run("cargo", [
    "run",
    "--quiet",
    "--package",
    "enoki-proto-gen",
    "--",
    protoFile,
    protoRoot,
    stagingRustOut,
  ]);

  publishGeneratedOutput(stagingTsFile, generatedTsFile);
  publishGeneratedOutput(stagingTsTypesFile, generatedTsTypesFile);
  publishGeneratedOutput(
    resolve(stagingRustOut, "enoki.v1.rs"),
    resolve(rustOut, "enoki.v1.rs"),
  );
  removeGeneratedTsTypesInput(generatedTsTypesInputFile);
} catch (error) {
  if (error instanceof CommandFailedError) {
    process.exitCode = error.status;
  } else if (error instanceof GenerationInterruptedError) {
    process.exitCode = signalExitCodes[error.signal];
  } else {
    throw error;
  }
} finally {
  for (const [signal, handler] of signalHandlers) {
    process.removeListener(signal, handler);
  }
  rmSync(stagingOut, { force: true, recursive: true });
}

function publishGeneratedOutput(source, destination) {
  mkdirSync(dirname(destination), { recursive: true });
  renameSync(source, destination);
}

async function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: "inherit",
  });

  await new Promise((resolve) => setImmediate(resolve));

  if (result.error) {
    throw result.error;
  }

  if (interruption) {
    throw new GenerationInterruptedError(interruption);
  }

  if (result.status !== 0) {
    throw new CommandFailedError(result.status ?? 1);
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
