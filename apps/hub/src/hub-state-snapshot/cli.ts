#!/usr/bin/env node

import { realpathSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { createHubPersistentStateConfigFromEnvironment } from "../config.js";
import { hubStateSnapshotV1, type ReleaseBaselineIdentity } from "./index.js";

type WriteOutput = (line: string) => void;

export async function runHubStateSnapshotCli(
  arguments_: string[],
  environment: Record<string, string | undefined>,
  writeOutput: WriteOutput = (line) => process.stdout.write(line),
) {
  if (arguments_.length === 1 && arguments_[0] === "--help") {
    writeOutput(`${usageText()}\n`);
    return;
  }
  const [version, operation, ...optionArguments] = arguments_;
  if (version !== "v1") {
    throw usageError("first argument must be v1");
  }
  if (
    operation !== "snapshot" &&
    operation !== "verify" &&
    operation !== "restore"
  ) {
    throw usageError("operation must be snapshot, verify, or restore");
  }

  const options = parseOptions(optionArguments);
  const snapshotPath = requiredOption(options, "--snapshot");
  const releaseBaseline: ReleaseBaselineIdentity = {
    hubImageDigest: requiredOption(options, "--baseline-image-digest"),
    version: requiredOption(options, "--baseline-version"),
  };
  requireFlag(options, "--confirm-hub-stopped");
  let result;
  if (operation === "verify") {
    rejectOptions(
      options,
      new Set([
        "--baseline-image-digest",
        "--baseline-version",
        "--confirm-hub-stopped",
        "--expected-manifest-digest",
        "--snapshot",
      ]),
    );
    result = await hubStateSnapshotV1.verify({
      expectedManifestDigest: requiredOption(
        options,
        "--expected-manifest-digest",
      ),
      hubStopped: true,
      releaseBaseline,
      snapshotPath,
    });
  } else {
    const persistentState =
      createHubPersistentStateConfigFromEnvironment(environment);
    if (operation === "snapshot") {
      rejectOptions(
        options,
        new Set([
          "--baseline-image-digest",
          "--baseline-version",
          "--confirm-hub-stopped",
          "--snapshot",
        ]),
      );
      result = await hubStateSnapshotV1.snapshot({
        hubStopped: true,
        persistentState,
        releaseBaseline,
        snapshotPath,
      });
    } else {
      rejectOptions(
        options,
        new Set([
          "--baseline-image-digest",
          "--baseline-version",
          "--confirm-data-loss-after",
          "--confirm-hub-stopped",
          "--expected-manifest-digest",
          "--snapshot",
        ]),
      );
      result = await hubStateSnapshotV1.restore({
        confirmDataLossAfter: requiredOption(
          options,
          "--confirm-data-loss-after",
        ),
        expectedManifestDigest: requiredOption(
          options,
          "--expected-manifest-digest",
        ),
        hubStopped: true,
        persistentState,
        releaseBaseline,
        snapshotPath,
      });
    }
  }
  writeOutput(
    `${JSON.stringify({ operation, version: "v1", ...result }, null, 2)}\n`,
  );
}

type ParsedOption = { kind: "flag" } | { kind: "value"; value: string };

function parseOptions(arguments_: string[]) {
  const options = new Map<string, ParsedOption>();
  for (let index = 0; index < arguments_.length; index += 1) {
    const name = arguments_[index];
    if (!name?.startsWith("--")) {
      throw usageError(`unexpected argument: ${name ?? ""}`);
    }
    if (options.has(name)) {
      throw usageError(`duplicate option: ${name}`);
    }
    if (name === "--confirm-hub-stopped") {
      options.set(name, { kind: "flag" });
      continue;
    }
    const value = arguments_[index + 1];
    if (!value || value.startsWith("--")) {
      throw usageError(`option requires a value: ${name}`);
    }
    options.set(name, { kind: "value", value });
    index += 1;
  }
  return options;
}

function requiredOption(options: Map<string, ParsedOption>, name: string) {
  const option = options.get(name);
  if (!option || option.kind !== "value") {
    throw usageError(`missing required option: ${name}`);
  }
  return option.value;
}

function requireFlag(options: Map<string, ParsedOption>, name: string) {
  if (options.get(name)?.kind !== "flag") {
    throw usageError(
      `${name} is required; this tool never stops or starts the Hub`,
    );
  }
}

function rejectOptions(
  options: Map<string, ParsedOption>,
  allowed: Set<string>,
) {
  const unsupported = [...options.keys()].find((name) => !allowed.has(name));
  if (unsupported) {
    throw usageError(`unsupported option: ${unsupported}`);
  }
}

function usageError(detail: string) {
  return new Error(`Hub State Snapshot CLI: ${detail}. ${usageText()}`);
}

function usageText() {
  return "Usage: enoki-hub-state v1 <snapshot|verify|restore> --snapshot <path> --baseline-version <stable-v-prefixed-SemVer> --baseline-image-digest <sha256:digest> --confirm-hub-stopped [--expected-manifest-digest <sha256-hex>] [--confirm-data-loss-after <recovery-time>]. Trust boundary: snapshot emits a separable manifestDigest and adjacent .manifest.sha256 file; copy that digest to an independently trusted runbook or E2E record. verify and restore require that externally trusted digest and never trust a digest stored with the snapshot itself";
}

const entryPath = process.argv[1]
  ? pathToFileURL(realpathSync(path.resolve(process.argv[1]))).href
  : undefined;
if (entryPath === import.meta.url) {
  try {
    await runHubStateSnapshotCli(process.argv.slice(2), process.env);
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
