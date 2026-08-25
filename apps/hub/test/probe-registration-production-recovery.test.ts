import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { createHash, createSign } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import type { AddressInfo } from "node:net";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { serve } from "@hono/node-server";
import { afterEach, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import { hashSecret } from "../src/enrollment/routes";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture";
import { createTestProbeIdentity } from "./probe-test-auth";

const probeBinary = process.env.ENOKI_PRODUCTION_PROBE_BINARY;
const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    tempRoots
      .splice(0)
      .map((root) => rm(root, { force: true, recursive: true })),
  );
});

it.skipIf(!probeBinary)(
  "fresh production registration processes converge across response loss and identity rename crashes",
  async () => {
    const dataRoot = await mkdtemp(
      path.join(os.tmpdir(), "enoki-production-recovery-"),
    );
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    const assetDir = path.join(dataRoot, "probe-assets");
    await mkdir(assetDir);
    const release = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "0.1.0",
      targetVersion: "0.2.0",
      transition: "replacement-required",
    });
    const proxy = await startResponseLossProxy();
    const proxyOrigin = `http://127.0.0.1:${proxy.port}`;
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      installation: {
        bootstrapRecipe: {
          bundleVersion: "0.2.0",
          distribution: "enoki",
          kind: "enoki-probe-bootstrap-recipe-record",
          recipe: {
            file: "enoki-probe-bootstrap.py",
            sha256: "a".repeat(64),
            size: 123,
            version: "v1",
          },
          rootFingerprint: "b".repeat(64),
          schemaVersion: 1,
          targets: ["x86_64-unknown-linux-gnu"],
        },
        probeApiOrigin: proxyOrigin,
      },
      probeAssets: {
        assetDir,
        trustedRootPublicKeyPem: release.rootPublicKeyPem,
      },
      probeApiOrigin: proxyOrigin,
    });
    const hubServer = serve({
      fetch: app.fetch,
      hostname: "127.0.0.1",
      port: 0,
    });
    await listening(hubServer);
    proxy.setUpstream((hubServer.address() as AddressInfo).port);

    try {
      const oldProbeId = "probe_production_old";
      database.sqlite
        .prepare(`insert into managed_hosts (
        id, probe_id, probe_secret_hash, display_name, display_name_edited,
        connect_address, created_at_ms, clock_skew_detected, last_clock_skew_ms,
        probe_configuration_version, probe_version
      ) values (7, ?, 'old-secret-hash', 'Production Host', 0,
        '127.0.0.1', ?, 0, null, 'default-v1', '0.1.0')`)
        .run(oldProbeId, Date.now());
      const enrollmentToken = `enk_enroll_${"p".repeat(32)}`;
      const enrollmentId = `enr_${"p".repeat(24)}`;
      expect(
        database.enrollments.createPending({
          createdAtMs: Date.now(),
          enrollmentId,
          expiresAtMs: Date.now() + 3_600_000,
          target: {
            expectedHubOrigin: proxyOrigin,
            expectedProbeId: oldProbeId,
            expectedProbeVersion: "0.1.0",
            hostId: 7,
            kind: "manual_reinstall",
            sourceProbeSha256: release.sourceProbeSha256,
            targetAssetSetDigest: release.targetAssetSetDigest,
            targetProbeVersion: "0.2.0",
          },
          tokenHash: hashSecret(enrollmentToken),
        }).kind,
      ).toBe("created");

      const registration = await registrationFixture({
        dataRoot,
        enrollmentId,
        enrollmentToken,
        hubOrigin: proxyOrigin,
        oldProbeId,
        release,
      });
      const args = [
        "register",
        "--config",
        registration.configPath,
        "--enrollment-token",
        enrollmentToken,
        "--hub-url",
        proxyOrigin,
      ];

      proxy.loseNextResponse();
      expect((await runProbe(args)).code).not.toBe(0);
      expect(await readFile(registration.configPath, "utf8")).toContain(
        `enrollment_token = "${enrollmentToken}"`,
      );

      const beforeRename = await runProbe(args, {
        ENOKI_TEST_SECURE_FILE_PATH: registration.configPath,
        ENOKI_TEST_SECURE_FILE_CRASH_POINT: "before-rename",
      });
      expect(beforeRename).toEqual(expect.objectContaining({ code: null }));
      expect(await readFile(registration.configPath, "utf8")).toContain(
        `enrollment_token = "${enrollmentToken}"`,
      );

      const afterRename = await runProbe(args, {
        ENOKI_TEST_SECURE_FILE_PATH: registration.configPath,
        ENOKI_TEST_SECURE_FILE_CRASH_POINT: "after-rename",
      });
      expect(afterRename).toEqual(expect.objectContaining({ code: null }));
      const postRenameIdentity = await readFile(
        registration.configPath,
        "utf8",
      );
      expect(postRenameIdentity).not.toContain("enrollment_token =");
      expect(postRenameIdentity).toContain("probe_private_key_pem =");
      expect(postRenameIdentity).toContain(
        `registration_signed_attempt_sha256 = "${registration.signedAttemptSha256}"`,
      );

      const finalRun = await runProbe(args);
      expect(finalRun.code, finalRun.stderr).toBe(0);
      const convergedIdentity = await readFile(registration.configPath, "utf8");
      expect(withoutObservedClockOffset(convergedIdentity)).toBe(
        withoutObservedClockOffset(postRenameIdentity),
      );
      expect(proxy.requestBodies).toHaveLength(4);
      for (const body of proxy.requestBodies.slice(1)) {
        expect(body).toEqual(proxy.requestBodies[0]);
      }

      const identityProbeId = /probe_id = "([^"]+)"/.exec(
        convergedIdentity,
      )?.[1];
      expect(identityProbeId).toBeTruthy();
      expect(
        database.sqlite
          .prepare("select id, probe_id as probeId from managed_hosts")
          .all(),
      ).toEqual([{ id: 7, probeId: identityProbeId }]);
      expect(
        database.sqlite
          .prepare(
            "select count(*) as count from audit_log where action = 'probe.manual_reinstall_identity_replaced'",
          )
          .get(),
      ).toEqual({ count: 1 });
      expect(
        database.sqlite
          .prepare(
            "select count(*) as count from enrollment_tokens where enrollment_id = ? and used_at_ms is not null",
          )
          .get(enrollmentId),
      ).toEqual({ count: 1 });
      await expect(readFile(registration.capsulePath)).resolves.toBeTruthy();
      await rm(registration.capsulePath);
      const canonicalRestart = await runProbe(
        ["run", "--config", registration.configPath],
        { ENOKI_PROBE_MAX_REPORTS: "1" },
      );
      expect(canonicalRestart.code, canonicalRestart.stderr).toBe(0);
      expect(
        proxy.requestTargets.filter(
          (target) => target === "/api/probe/register",
        ),
      ).toHaveLength(4);
      expect(proxy.requestTargets).toContain("/api/probe/report");
    } finally {
      await Promise.allSettled([proxy.close(), closeServer(hubServer)]);
      database.close();
    }
  },
  30_000,
);

async function registrationFixture(input: {
  dataRoot: string;
  enrollmentId: string;
  enrollmentToken: string;
  hubOrigin: string;
  oldProbeId: string;
  release: Awaited<ReturnType<typeof writeSignedProbeAssetSet>>;
}) {
  const identity = createTestProbeIdentity();
  const attempt = root.enoki.v1.ProbeRegistrationAttempt.encode(
    root.enoki.v1.ProbeRegistrationAttempt.create({
      candidatePublicKeyPem: identity.publicKeyPem,
      committedSourceProbeSha256: input.release.sourceProbeSha256[0]!,
      enrollmentId: input.enrollmentId,
      hostId: "7",
      hubOrigin: input.hubOrigin,
      nonce: "9".repeat(64),
      oldProbeId: input.oldProbeId,
      replacementCommitSha256: "d".repeat(64),
      schemaVersion: 1,
      sourceProbeVersion: "0.1.0",
      targetAssetSetDigest: input.release.targetAssetSetDigest,
      targetBundleTarget: input.release.targetBundles[0]!.target,
      targetManifestSha256:
        input.release.targetBundles[0]!.bundleManifestSha256,
      targetProbeVersion: "0.2.0",
    }),
  ).finish();
  const signer = createSign("RSA-SHA256");
  signer.update(
    `enoki.probe-registration-attempt.v1\n${createHash("sha256")
      .update(attempt)
      .digest("hex")}`,
  );
  signer.end();
  const signature = signer.sign(identity.privateKeyPem);
  const request = root.enoki.v1.ProbeRegistrationRequest.encode(
    root.enoki.v1.ProbeRegistrationRequest.create({
      candidateSignature: signature,
      canonicalAttempt: attempt,
      enrollmentToken: input.enrollmentToken,
      probePublicKeyPem: identity.publicKeyPem,
    }),
  ).finish();
  const signedAttemptSha256 = createHash("sha256")
    .update("enoki.probe-registration-attempt.signed.v1\n")
    .update(attempt)
    .update(signature)
    .digest("hex");
  const capsulePath = path.join(input.dataRoot, "registration-attempt.json");
  const configPath = path.join(input.dataRoot, "probe-bootstrap.toml");
  await writeFile(
    capsulePath,
    JSON.stringify({
      candidatePrivateKeyPem: identity.privateKeyPem,
      enrollmentTokenSha256: createHash("sha256")
        .update(input.enrollmentToken)
        .digest("hex"),
      hubOrigin: input.hubOrigin,
      requestHex: Buffer.from(request).toString("hex"),
      schemaVersion: 1,
      signedAttemptSha256,
    }),
    { mode: 0o600 },
  );
  await chmod(capsulePath, 0o600);
  await writeFile(
    configPath,
    [
      `hub_url = ${JSON.stringify(input.hubOrigin)}`,
      `enrollment_token = ${JSON.stringify(input.enrollmentToken)}`,
      `registration_attempt_credential_path = ${JSON.stringify(capsulePath)}`,
      `registration_enrollment_id = ${JSON.stringify(input.enrollmentId)}`,
      'registration_host_id = "7"',
      `registration_hub_origin = ${JSON.stringify(input.hubOrigin)}`,
      `registration_old_probe_id = ${JSON.stringify(input.oldProbeId)}`,
      'registration_source_probe_version = "0.1.0"',
      `registration_committed_source_probe_sha256 = ${JSON.stringify(input.release.sourceProbeSha256[0])}`,
      'registration_target_probe_version = "0.2.0"',
      `registration_target_bundle_target = ${JSON.stringify(input.release.targetBundles[0]!.target)}`,
      `registration_target_asset_set_digest = ${JSON.stringify(input.release.targetAssetSetDigest)}`,
      `registration_target_manifest_sha256 = ${JSON.stringify(input.release.targetBundles[0]!.bundleManifestSha256)}`,
      `registration_replacement_commit_sha256 = ${JSON.stringify("d".repeat(64))}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  await chmod(configPath, 0o600);
  return { capsulePath, configPath, signedAttemptSha256 };
}

async function runProbe(
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

async function startResponseLossProxy() {
  let upstreamPort = 0;
  let loseNext = false;
  const requestBodies: Buffer[] = [];
  const requestTargets: string[] = [];
  const server = net.createServer((client) => {
    const upstream = net.connect({ host: "127.0.0.1", port: upstreamPort });
    const requestChunks: Buffer[] = [];
    let recorded = false;
    client.on("data", (chunk) => {
      requestChunks.push(Buffer.from(chunk));
      if (!recorded) {
        const request = Buffer.concat(requestChunks);
        const body = completeHttpBody(request);
        if (body) {
          requestBodies.push(body);
          requestTargets.push(
            request
              .subarray(0, request.indexOf("\r\n"))
              .toString("latin1")
              .split(" ")[1] ?? "",
          );
          recorded = true;
        }
      }
    });
    client.pipe(upstream);
    if (!loseNext) {
      upstream.pipe(client);
      return;
    }
    loseNext = false;
    const responseChunks: Buffer[] = [];
    upstream.on("data", (chunk) => {
      responseChunks.push(Buffer.from(chunk));
      if (completeHttpBody(Buffer.concat(responseChunks))) {
        client.destroy();
        upstream.destroy();
      }
    });
  });
  server.listen(0, "127.0.0.1");
  await listening(server);
  return {
    close: () => closeServer(server),
    loseNextResponse: () => {
      loseNext = true;
    },
    port: (server.address() as AddressInfo).port,
    requestBodies,
    requestTargets,
    setUpstream: (port: number) => {
      upstreamPort = port;
    },
  };
}

function completeHttpBody(message: Buffer) {
  const headerEnd = message.indexOf("\r\n\r\n");
  if (headerEnd < 0) return null;
  const header = message.subarray(0, headerEnd).toString("latin1");
  const length = Number(/\r\ncontent-length: (\d+)/i.exec(header)?.[1]);
  if (!Number.isSafeInteger(length) || length < 0) return null;
  const bodyStart = headerEnd + 4;
  return message.length >= bodyStart + length
    ? message.subarray(bodyStart, bodyStart + length)
    : null;
}

function withoutObservedClockOffset(config: string) {
  return config.replace(/^server_time_offset_ms = -?\d+\n/m, "");
}

function listening(server: net.Server) {
  return new Promise<void>((resolve) => server.once("listening", resolve));
}

function closeServer(server: net.Server) {
  return new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
