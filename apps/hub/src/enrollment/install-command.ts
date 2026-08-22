import { readFileSync } from "node:fs";

import type { ProbeBootstrapRecipeRecord } from "@enoki/api-client";

export type InstallationCommandConfig = {
  bootstrapRecipe?: ProbeBootstrapRecipeRecord;
  probeApiOrigin?: string;
};

export type InstallCommandInput = {
  enrollmentToken: string;
};

export type InstallCommandResult = {
  bootstrapRecipe: ProbeBootstrapRecipeRecord;
  hubUrl: string;
  installCommand: string;
};

const probeBootstrapRecipe = "./enoki-probe-bootstrap.py";
const supportedRecipeTargets = [
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
];
const developmentRecipeRecord: ProbeBootstrapRecipeRecord = {
  bundleVersion: "0.0.0",
  distribution: "enoki-development",
  kind: "enoki-probe-bootstrap-recipe-record",
  recipe: {
    file: "enoki-probe-bootstrap.py",
    sha256: "0".repeat(64),
    size: 1,
    version: "v1",
  },
  rootFingerprint: "0".repeat(64),
  schemaVersion: 1,
  targets: [],
};

export function readProbeBootstrapRecipeRecord(
  filePath = "/app/probe-bootstrap-publication/enoki-probe-bootstrap-recipe.json",
): ProbeBootstrapRecipeRecord {
  const value: unknown = JSON.parse(readFileSync(filePath, "utf8"));
  if (!isProbeBootstrapRecipeRecord(value)) {
    throw new Error("Probe Bootstrap recipe record is invalid");
  }
  return Object.freeze({
    ...value,
    recipe: Object.freeze({ ...value.recipe }),
    targets: Object.freeze([...value.targets]) as unknown as string[],
  });
}

function isProbeBootstrapRecipeRecord(
  value: unknown,
): value is ProbeBootstrapRecipeRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const recipe = record.recipe as Record<string, unknown> | undefined;
  return (
    Object.keys(record).sort().join(",") ===
      "bundleVersion,distribution,kind,recipe,rootFingerprint,schemaVersion,targets" &&
    record.kind === "enoki-probe-bootstrap-recipe-record" &&
    record.schemaVersion === 1 &&
    typeof record.bundleVersion === "string" &&
    /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      record.bundleVersion,
    ) &&
    record.distribution === "enoki" &&
    typeof record.rootFingerprint === "string" &&
    /^[0-9a-f]{64}$/.test(record.rootFingerprint) &&
    Array.isArray(record.targets) &&
    JSON.stringify(record.targets) === JSON.stringify(supportedRecipeTargets) &&
    Boolean(recipe) &&
    Object.keys(recipe!).sort().join(",") === "file,sha256,size,version" &&
    recipe!.file === "enoki-probe-bootstrap.py" &&
    recipe!.version === "v1" &&
    typeof recipe!.size === "number" &&
    Number.isSafeInteger(recipe!.size) &&
    Number(recipe!.size) > 0 &&
    /^[0-9a-f]{64}$/.test(String(recipe!.sha256))
  );
}

export function createDefaultInstallationCommandConfig(): InstallationCommandConfig {
  return {
    bootstrapRecipe: developmentRecipeRecord,
    probeApiOrigin: "http://localhost",
  };
}

export function renderInstallCommand(
  config: InstallationCommandConfig,
  input: InstallCommandInput,
): InstallCommandResult {
  const hubUrl = config.probeApiOrigin ?? "http://localhost";
  return {
    bootstrapRecipe: config.bootstrapRecipe ?? developmentRecipeRecord,
    hubUrl,
    installCommand: [
      "printf",
      "'%s\\n'",
      shellQuote(input.enrollmentToken),
      "|",
      "python3",
      "--",
      probeBootstrapRecipe,
      "--hub-origin",
      shellQuote(hubUrl),
    ].join(" "),
  };
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}
