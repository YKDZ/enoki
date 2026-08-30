import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { expect } from "vitest";

import { createHubApp } from "../src/app";
import { defaultEnabledCollectorIds } from "../src/probe-configuration/model";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture";
import { createTestProbeIdentity } from "./probe-test-auth";

const probeBinary = process.env.ENOKI_PRODUCTION_PROBE_BINARY;
const lifecycleCompanionBinary =
  process.env.ENOKI_PRODUCTION_LIFECYCLE_COMPANION_BINARY;

export async function registrationFixture(input: {
  dataRoot: string;
  enrollmentToken: string;
  capsulePath: string;
}) {
  const capsule = JSON.parse(await readFile(input.capsulePath, "utf8")) as {
    candidatePrivateKeyPem: string;
    requestHex: string;
    signedAttemptSha256: string;
  };
  const request = root.enoki.v1.ProbeRegistrationRequest.decode(
    Buffer.from(capsule.requestHex, "hex"),
  );
  const attempt = root.enoki.v1.ProbeRegistrationAttempt.decode(
    request.canonicalAttempt,
  );
  const configPath = path.join(input.dataRoot, "probe-bootstrap.toml");
  await writeFile(
    configPath,
    [
      `hub_url = ${JSON.stringify(attempt.hubOrigin)}`,
      `enrollment_token = ${JSON.stringify(input.enrollmentToken)}`,
      `registration_attempt_credential_path = ${JSON.stringify(input.capsulePath)}`,
      `registration_enrollment_id = ${JSON.stringify(attempt.enrollmentId)}`,
      `registration_host_id = ${JSON.stringify(attempt.hostId)}`,
      `registration_hub_origin = ${JSON.stringify(attempt.hubOrigin)}`,
      `registration_old_probe_id = ${JSON.stringify(attempt.oldProbeId)}`,
      `registration_source_probe_version = ${JSON.stringify(attempt.sourceProbeVersion)}`,
      `registration_committed_source_probe_sha256 = ${JSON.stringify(attempt.committedSourceProbeSha256)}`,
      `registration_target_probe_version = ${JSON.stringify(attempt.targetProbeVersion)}`,
      `registration_target_bundle_target = ${JSON.stringify(attempt.targetBundleTarget)}`,
      `registration_target_asset_set_digest = ${JSON.stringify(attempt.targetAssetSetDigest)}`,
      `registration_target_manifest_sha256 = ${JSON.stringify(attempt.targetManifestSha256)}`,
      `registration_replacement_commit_sha256 = ${JSON.stringify(attempt.replacementCommitSha256)}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  await chmod(configPath, 0o600);
  return {
    capsulePath: input.capsulePath,
    configPath,
    signedAttemptSha256: capsule.signedAttemptSha256,
  };
}

export async function runProbe(
  args: string[],
  environment: Record<string, string> = {},
) {
  return await new Promise<{ code: number | null; stderr: string }>(
    (resolve, reject) => {
      const child = spawn(probeBinary!, args, {
        env: { ...process.env, ...environment },
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr.setEncoding("utf8").on("data", (chunk) => {
        stderr += chunk;
      });
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, stderr }));
    },
  );
}

type ReplacementInstallEnrollment = {
  enrollmentToken: string;
  hubOrigin: string;
  replacementMigration: {
    enrollmentId: string;
    expectedProbeId: string;
    sourceProbeSha256: string[];
    sourceProbeVersion: string;
    targetAssetSetDigest: string;
    targetHostId: string;
    targetProbeVersion: string;
  };
  schemaVersion: number;
};

export function installCommandEnrollment(
  command: string,
): ReplacementInstallEnrollment {
  const match = /^printf '%s\\n' '([^']+)' \|/.exec(command);
  expect(match?.[1]).toBeTruthy();
  return JSON.parse(match![1]!) as ReplacementInstallEnrollment;
}

export function replacementLifecycleRequest(input: {
  enrollment: ReplacementInstallEnrollment;
  release: Awaited<ReturnType<typeof writeSignedProbeAssetSet>>;
}) {
  const target = input.release.targetBundles.find(
    (bundle) => bundle.target === "x86_64-unknown-linux-gnu",
  )!;
  return JSON.stringify({
    schemaVersion: 1,
    transition: "replacement-migration",
    authority: {
      kind: "replacement-enrollment",
      enrollment_token: input.enrollment.enrollmentToken,
      enrollment_id: input.enrollment.replacementMigration.enrollmentId,
      hub_origin: input.enrollment.hubOrigin,
      host_id: input.enrollment.replacementMigration.targetHostId,
      expected_probe_id: input.enrollment.replacementMigration.expectedProbeId,
      source_probe_version:
        input.enrollment.replacementMigration.sourceProbeVersion,
      source_probe_sha256:
        input.enrollment.replacementMigration.sourceProbeSha256,
      target_asset_set_digest:
        input.enrollment.replacementMigration.targetAssetSetDigest,
      target_bundle_target: target.target,
      target_manifest_sha256: target.bundleManifestSha256,
      bundle_version: input.enrollment.replacementMigration.targetProbeVersion,
    },
  });
}

export async function createOldProductionInstall(input: {
  hubOrigin: string;
  oldProbeId: string;
  productionRoot: string;
}) {
  const binary = path.join(input.productionRoot, "usr/local/bin/enoki-probe");
  const identity = path.join(
    input.productionRoot,
    "etc/enoki/probe-bootstrap.toml",
  );
  const metadata = path.join(
    input.productionRoot,
    "etc/enoki/probe-install.toml",
  );
  await Promise.all([
    mkdir(path.dirname(binary), { recursive: true }),
    mkdir(path.dirname(identity), { recursive: true }),
    mkdir(path.join(input.productionRoot, "var/lib/enoki-probe"), {
      recursive: true,
    }),
  ]);
  await copyFile(probeBinary!, binary);
  await chmod(binary, 0o755);
  const oldIdentity = createTestProbeIdentity();
  await writeFile(
    identity,
    [
      `hub_url = ${JSON.stringify(input.hubOrigin)}`,
      `probe_id = ${JSON.stringify(input.oldProbeId)}`,
      `probe_private_key_pem = ${JSON.stringify(oldIdentity.privateKeyPem)}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  await chmod(identity, 0o600);
  await writeFile(
    metadata,
    [
      "schema_version = 1",
      'install_path = "/usr/local/bin/enoki-probe"',
      `hub_url = ${JSON.stringify(input.hubOrigin)}`,
      'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
      'state_dir = "/var/lib/enoki-probe"',
      'operation_sudoers_path = "/etc/sudoers.d/enoki-probe-operations"',
      'collector_helper_sudoers_path = "/etc/sudoers.d/enoki-probe-collector-helpers"',
      'service_name = "enoki-probe"',
      'service_user = "enoki-probe"',
      'identity_path = "/etc/enoki/probe-bootstrap.toml"',
      'service_group = "enoki-probe"',
      'service_unit_path = "/etc/systemd/system/enoki-probe.service"',
      `probe_asset_public_key_sha256 = ${JSON.stringify("a".repeat(64))}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  await chmod(metadata, 0o600);
}

export async function runLifecycleCompanion(
  request: string,
  environment: Record<string, string>,
) {
  return await new Promise<{
    code: number | null;
    stderr: string;
    stdout: string;
  }>((resolve, reject) => {
    const child = spawn(lifecycleCompanionBinary!, [], {
      env: { ...process.env, ...environment },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stderr, stdout }));
    child.stdin.end(request);
  });
}

export async function loginOwner(app: ReturnType<typeof createHubApp>) {
  const response = await app.request("/api/web/auth/login", {
    body: JSON.stringify({ password: "correct horse battery staple" }),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  expect(response.status).toBe(200);
  return response.headers.get("set-cookie") ?? "";
}

export async function publishProductionFixtureConfiguration(
  app: ReturnType<typeof createHubApp>,
  ownerSession: string,
) {
  const response = await app.request("/api/web/probe-configuration", {
    body: JSON.stringify({
      enabledCollectorIds: [...defaultEnabledCollectorIds],
      metricsCollectionIntervalSeconds: 1,
    }),
    headers: {
      "content-type": "application/json",
      cookie: ownerSession,
    },
    method: "PUT",
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as {
    configuration: {
      metricsCollectionIntervalSeconds: number;
      version: string;
    };
  };
  expect(body.configuration.metricsCollectionIntervalSeconds).toBe(1);
  expect(body.configuration.version).not.toBe("default-v1");
  return body.configuration.version;
}

export function withoutObservedClockOffset(config: string) {
  return config.replace(/^server_time_offset_ms = -?\d+\n/m, "");
}
