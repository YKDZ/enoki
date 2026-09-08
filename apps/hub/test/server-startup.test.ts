import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { describe, expect, it } from "vitest";

import { deriveLifecycleAuthorityKey } from "../src/probe/lifecycle-authority";
import {
  canonicalInstalledBundleFailureEvidence,
  signInstalledBundleFailureEvidence,
} from "../src/probe/repair-authority";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture";
import { createTestProbeIdentity } from "./probe-test-auth";

const hubRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
describe("Hub server startup", () => {
  it("prints the fixed legacy-variable migration from the actual server process", async () => {
    const secret = "legacy-value-must-not-be-logged";
    const result = await runServer({
      ENOKI_MANAGEMENT_ORIGIN: "https://manage.example",
      ENOKI_PUBLIC_HUB_URL: secret,
      OWNER_PASSWORD: "test-owner-password",
    });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      '"configurationMessage":"ENOKI_PUBLIC_HUB_URL has been removed. Set ENOKI_MANAGEMENT_ORIGIN and, when the Probe API differs, ENOKI_PROBE_API_ORIGIN."',
    );
    expect(`${result.stdout}${result.stderr}`).not.toContain(secret);
  });

  it.each([
    { expectedStatus: 200, imageRoot: true, name: "the configured image root" },
    { expectedStatus: 409, imageRoot: false, name: "a missing image root" },
  ])(
    "keeps Installed Bundle Failure Repair on the Probe listener safe with $name",
    async ({ expectedStatus, imageRoot: hasImageRoot }) => {
      const dataRoot = await mkdtemp(
        path.join(os.tmpdir(), "enoki-server-db-"),
      );
      const assetDir = await mkdtemp(
        path.join(os.tmpdir(), "enoki-server-assets-"),
      );
      const managementPort = await allocatePort();
      const probePort = await allocatePort();
      const managementOrigin = `http://127.0.0.1:${managementPort}`;
      const probeOrigin = `http://127.0.0.1:${probePort}`;
      const release = await writeSignedProbeAssetSet(assetDir, {
        sourceVersion: "0.0.9",
        targetVersion: "0.1.75",
        transition: "compatible",
      });
      const imageRoot = hasImageRoot
        ? await installImageDistributionRoot(release.rootPublicKeyPem)
        : undefined;
      let server: StartedServer | undefined;

      try {
        server = await startListeningServer({
          ENOKI_DATA_ROOT: dataRoot,
          ENOKI_MANAGEMENT_ORIGIN: managementOrigin,
          ENOKI_PROBE_API_ORIGIN: probeOrigin,
          ENOKI_PROBE_ASSET_DIR: assetDir,
          ENOKI_PROBE_HOST: "127.0.0.1",
          ENOKI_PROBE_PORT: String(probePort),
          HOST: "127.0.0.1",
          OWNER_PASSWORD: "test-owner-password",
          PORT: String(managementPort),
        });
        await expect(waitForHealthy(managementOrigin)).resolves.toBeUndefined();
        await expect(waitForHealthy(probeOrigin)).resolves.toBeUndefined();

        const ownerSession = await loginOwner(managementOrigin);
        const enrollmentToken = await createEnrollment(
          managementOrigin,
          ownerSession,
        );
        const registration = await registerProbe(probeOrigin, enrollmentToken);
        const nowMs = Date.now();
        const evidence = {
          kind: "installed_bundle_failure" as const,
          schemaVersion: 1 as const,
          hubOrigin: probeOrigin,
          hostId: registration.hostId,
          probeId: registration.probeId,
          generation: "a".repeat(64),
          bootId: "4f7d3e15-63cc-4d61-8fe4-f5d42773dd51",
          unit: "enoki-observation-runtime.service" as const,
          unitSha256: "b".repeat(64),
          identityReceiptSha256: "c".repeat(64),
          installStateSha256: "d".repeat(64),
          manifestSha256: release.targetBundles[0]!.bundleManifestSha256,
          bundleVersion: "0.1.75",
          issuedAtMs: nowMs,
          expiresAtMs: nowMs + 60_000,
          requestNonce: "request_nonce_01",
        };
        const installKey = deriveLifecycleAuthorityKey(
          createHash("sha256").update(enrollmentToken).digest(),
          probeOrigin,
        );
        const response = await fetch(
          `${probeOrigin}/api/probe/runtime-failures/${evidence.generation}/repair-authorize`,
          {
            body: JSON.stringify({
              evidence,
              evidenceSignature: signInstalledBundleFailureEvidence(
                canonicalInstalledBundleFailureEvidence(evidence),
                installKey,
              ),
            }),
            headers: { "content-type": "application/json" },
            method: "POST",
          },
        );

        expect(response.status).toBe(expectedStatus);
      } finally {
        await server?.stop();
        await imageRoot?.cleanup();
        await Promise.all([
          rm(dataRoot, { force: true, recursive: true }),
          rm(assetDir, { force: true, recursive: true }),
        ]);
      }
    },
    30_000,
  );
});

type StartedServer = {
  stop: () => Promise<void>;
};

async function allocatePort() {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Expected an ephemeral TCP port.");
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  return address.port;
}

async function installImageDistributionRoot(rootPublicKeyPem: Buffer | string) {
  const directory = "/app/probe-distribution-root";
  const rootPath = path.join(directory, "root-key.pem");
  const appExisted = await pathExists("/app");
  const directoryExisted = await pathExists(directory);
  if (await pathExists(rootPath)) {
    throw new Error(`Test image root already exists at ${rootPath}.`);
  }
  await mkdir(directory, { recursive: true });
  await writeFile(rootPath, rootPublicKeyPem);

  return {
    async cleanup() {
      await rm(rootPath, { force: true });
      if (!directoryExisted)
        await rm(directory, { force: true, recursive: true });
      if (!appExisted) await rm("/app", { force: true, recursive: true });
    },
  };
}

async function pathExists(candidate: string) {
  try {
    await access(candidate);
    return true;
  } catch {
    return false;
  }
}

function startListeningServer(environment: Record<string, string>) {
  return new Promise<StartedServer>((resolve, reject) => {
    const server = spawn(process.execPath, ["dist/src/server.js"], {
      cwd: hubRoot,
      env: { ...process.env, ...environment },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    let started = false;
    const timeout = setTimeout(() => {
      void stopServer(server).then(() => {
        reject(new Error(`Hub did not start both listeners: ${output}`));
      });
    }, 10_000);
    const onOutput = (chunk: Buffer) => {
      output += chunk.toString();
      if (!started && output.includes('"listener":"probe"')) {
        started = true;
        clearTimeout(timeout);
        resolve({ stop: () => stopServer(server) });
      }
    };
    server.stdout.on("data", onOutput);
    server.stderr.on("data", onOutput);
    server.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    server.once("close", (code) => {
      if (!started) {
        clearTimeout(timeout);
        reject(
          new Error(
            `Hub exited before both listeners started (${code}): ${output}`,
          ),
        );
      }
    });
  });
}

async function stopServer(server: ReturnType<typeof spawn>) {
  if (server.exitCode !== null || server.signalCode !== null) return;
  const closed = new Promise<void>((resolve) => server.once("close", resolve));
  server.kill("SIGTERM");
  let forceKill: NodeJS.Timeout | undefined;
  await Promise.race([
    closed,
    new Promise<void>((resolve) => {
      forceKill = setTimeout(() => {
        server.kill("SIGKILL");
        resolve();
      }, 5_000);
    }),
  ]);
  if (forceKill) clearTimeout(forceKill);
  await closed;
}

async function waitForHealthy(origin: string) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`${origin}/api/health`)).status === 200) return;
    } catch {
      // The listener may not have accepted its first connection yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`Hub listener did not become healthy at ${origin}.`);
}

async function loginOwner(origin: string) {
  const response = await fetch(`${origin}/api/web/auth/login`, {
    body: JSON.stringify({ password: "test-owner-password" }),
    headers: { "content-type": "application/json", origin },
    method: "POST",
  });
  expect(response.status).toBe(200);
  return response.headers.get("set-cookie") ?? "";
}

async function createEnrollment(origin: string, ownerSession: string) {
  const response = await fetch(`${origin}/api/web/enrollments`, {
    body: JSON.stringify({}),
    headers: {
      "content-type": "application/json",
      cookie: ownerSession,
      origin,
    },
    method: "POST",
  });
  expect(response.status).toBe(201);
  return ((await response.json()) as { enrollmentToken: string })
    .enrollmentToken;
}

async function registerProbe(origin: string, enrollmentToken: string) {
  const identity = createTestProbeIdentity();
  const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;
  const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;
  const response = await fetch(`${origin}/api/probe/register`, {
    body: RegistrationRequest.encode(
      RegistrationRequest.create({
        enrollmentToken,
        probePublicKeyPem: identity.publicKeyPem,
        snapshots: [
          {
            collectorId: "official.host-profile",
            hostProfile: {
              architecture: "x86_64",
              cpuCount: 2,
              hostname: "managed-host-01",
              kernel: "6.8.0",
              memoryTotalBytes: 2_147_483_648,
              os: "linux",
              probeVersion: "0.1.75",
            },
          },
        ],
      }),
    ).finish(),
    headers: { "content-type": "application/x-protobuf" },
    method: "POST",
  });
  expect(response.status).toBe(200);
  const registration = RegistrationResponse.decode(
    new Uint8Array(await response.arrayBuffer()),
  );
  return { hostId: registration.hostId, probeId: registration.probeId };
}

function runServer(environment: Record<string, string>) {
  return new Promise<{ code: number | null; stderr: string; stdout: string }>(
    (resolve, reject) => {
      const server = spawn(process.execPath, ["dist/src/server.js"], {
        cwd: hubRoot,
        env: { ...process.env, ...environment },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      server.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString();
      });
      server.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString();
      });
      server.once("error", reject);
      server.once("close", (code) => resolve({ code, stderr, stdout }));
    },
  );
}
