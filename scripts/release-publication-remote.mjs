import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { inspectProbeAssetSet } from "./release-candidate-lib.mjs";

const execFileAsync = promisify(execFile);

export function createGitHubGhcrPublicationRemote({
  fetchImpl = globalThis.fetch,
  image,
  repository,
  runCommand = executeCommand,
  smokeService,
}) {
  const command = createSafeCommandRunner(runCommand);
  const publicSmokeService =
    smokeService ??
    createPublicationSmokeService({ fetchImpl, runCommand: command });
  const remote = {
    async getTag({ version }) {
      let reference;
      try {
        reference = await ghJson(
          command,
          `repos/${repository}/git/ref/tags/${version}`,
        );
      } catch (error) {
        if (isNotFound(error)) return null;
        throw error;
      }
      let object = reference.object;
      for (let depth = 0; object?.type === "tag" && depth < 8; depth += 1) {
        const annotated = await ghJson(
          command,
          `repos/${repository}/git/tags/${object.sha}`,
        );
        object = annotated.object;
      }
      if (object?.type !== "commit" || !/^[0-9a-f]{40}$/.test(object.sha)) {
        throw new Error(`tag ${version} does not resolve to a commit`);
      }
      return { commit: object.sha };
    },

    async createTag({ commit, version }) {
      await command("gh", [
        "api",
        "--method",
        "POST",
        `repos/${repository}/git/refs`,
        "-f",
        `ref=refs/tags/${version}`,
        "-f",
        `sha=${commit}`,
      ]);
    },

    async getRelease({ version }) {
      const response = await command("gh", [
        "api",
        "--paginate",
        "--slurp",
        `repos/${repository}/releases?per_page=100`,
      ]);
      const pages = JSON.parse(response.stdout);
      const releases = pages.flat();
      const release = releases.find((item) => item.tag_name === version);
      if (!release) return null;
      return {
        assets: Object.fromEntries(
          release.assets.map((asset) => [
            asset.name,
            {
              downloadUrl: asset.browser_download_url,
              id: asset.id,
              sha256: parseGitHubAssetDigest(asset.digest),
              size: asset.size,
            },
          ]),
        ),
        draft: release.draft,
        id: release.id,
        targetCommit: release.target_commitish,
        url: release.html_url,
      };
    },

    async createDraftRelease({ commit, version }) {
      await command("gh", [
        "api",
        "--method",
        "POST",
        `repos/${repository}/releases`,
        "-f",
        `tag_name=${version}`,
        "-f",
        `target_commitish=${commit}`,
        "-f",
        `name=${version}`,
        "-f",
        `body=Enoki ${version}`,
        "-F",
        "draft=true",
      ]);
    },

    async uploadAsset({ filePath, version }) {
      await command("gh", [
        "release",
        "upload",
        version,
        filePath,
        "--repo",
        repository,
      ]);
    },

    async getImage({ tag }) {
      return inspectRegistryImage(command, `${image}:${tag}`);
    },

    async publishVersionImage({ archivePath, version }) {
      await command("skopeo", [
        "copy",
        "--preserve-digests",
        `oci-archive:${path.resolve(archivePath)}`,
        `docker://${image}:${version}`,
      ]);
    },

    async makeReleasePublic({ version }) {
      const release = await this.getRelease({ version });
      if (!release) throw new Error(`draft Release ${version} disappeared`);
      await command("gh", [
        "api",
        "--method",
        "PATCH",
        `repos/${repository}/releases/${release.id}`,
        "-F",
        "draft=false",
      ]);
    },

    async moveLatest({ digest }) {
      await command("skopeo", [
        "copy",
        "--preserve-digests",
        `docker://${image}@${digest}`,
        `docker://${image}:latest`,
      ]);
    },

    async verifyPublicCandidate({ candidateManifest, version }) {
      return publicSmokeService.verifyPublicCandidate({
        candidateManifest,
        getRelease: (query) => remote.getRelease(query),
        image,
        version,
      });
    },
  };
  return remote;
}

export function createPublicationSmokeService({
  createId = randomUUID,
  fetchImpl = globalThis.fetch,
  inspectProbeAssets = inspectProbeAssetSet,
  runCommand = executeCommand,
  sleep = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)),
} = {}) {
  return {
    verifyPublicCandidate(options) {
      return verifyPublicCandidate({
        ...options,
        createId,
        fetchImpl,
        inspectProbeAssets,
        runCommand,
        sleep,
      });
    },
  };
}

async function verifyPublicCandidate({
  candidateManifest,
  createId,
  fetchImpl,
  getRelease,
  image,
  inspectProbeAssets,
  runCommand,
  sleep,
  version,
}) {
  const checks = {};
  const failureReasons = [];
  const workDir = await mkdtemp(path.join(tmpdir(), "enoki-release-smoke-"));
  const anonymousAuthFile = path.join(workDir, "anonymous-auth.json");
  let publicAssetsReady = false;

  try {
    await writeFile(anonymousAuthFile, '{"auths":{}}\n');
    await smokeCheck("probeChecksums", checks, failureReasons, async () => {
      const release = await getRelease({ version });
      if (!release || release.draft) {
        throw new Error("GitHub Release is not public");
      }
      for (const expected of candidateManifest.probeAssetSet.files) {
        const asset = release.assets[expected.file];
        if (!asset?.downloadUrl) {
          throw new Error(`public Probe asset is missing: ${expected.file}`);
        }
        const response = await fetchImpl(asset.downloadUrl, {
          credentials: "omit",
          redirect: "follow",
        });
        if (!response.ok) {
          throw new Error(
            `public Probe asset ${expected.file} returned ${response.status}`,
          );
        }
        const bytes = Buffer.from(await response.arrayBuffer());
        if (
          bytes.length !== expected.size ||
          sha256(bytes) !== expected.sha256
        ) {
          throw new Error(
            `public Probe asset does not match candidate: ${expected.file}`,
          );
        }
        await writeFile(path.join(workDir, expected.file), bytes);
      }
      publicAssetsReady = true;
    });

    await smokeCheck("probeSignature", checks, failureReasons, async () => {
      if (!publicAssetsReady) {
        throw new Error(
          "public Probe assets were not available for signature verification",
        );
      }
      const inspected = await inspectProbeAssets(workDir);
      if (
        inspected.signingIdentity.publicKeySha256 !==
        candidateManifest.probeAssetSet.signingIdentity.publicKeySha256
      ) {
        throw new Error(
          "public Probe signing identity does not match candidate",
        );
      }
    });

    await smokeCheck("imageDigest", checks, failureReasons, async () => {
      const published = await inspectRegistryImage(
        runCommand,
        `${image}:${version}`,
        { anonymousAuthFile, publicOnly: true },
      );
      if (published?.digest !== candidateManifest.hub.digest) {
        throw new Error(
          `public Hub image digest ${published?.digest ?? "missing"} does not match candidate`,
        );
      }
    });

    let runtimeEvidence = null;
    await smokeCheck("hubHealth", checks, failureReasons, async () => {
      runtimeEvidence = await verifyHubRuntime({
        anonymousAuthFile,
        createId,
        digest: candidateManifest.hub.digest,
        fetchImpl,
        image,
        runCommand,
        sleep,
      });
    });
    await smokeCheck(
      "embeddedProbeVersion",
      checks,
      failureReasons,
      async () => {
        if (!runtimeEvidence) {
          throw new Error("Hub runtime was unavailable");
        }
        if (
          runtimeEvidence.embeddedProbeVersion !==
          candidateManifest.hub.embeddedProbeVersion
        ) {
          throw new Error(
            `Hub serves Probe ${runtimeEvidence.embeddedProbeVersion}, expected ${candidateManifest.hub.embeddedProbeVersion}`,
          );
        }
        if (!runtimeEvidence.installerUsesHubAssets) {
          throw new Error("Hub installer does not use Hub-served Probe assets");
        }
      },
    );
  } finally {
    await rm(workDir, { force: true, recursive: true });
  }

  return {
    checks,
    failureReasons,
    outcome: failureReasons.length === 0 ? "succeeded" : "failed",
  };
}

async function verifyHubRuntime({
  anonymousAuthFile,
  createId,
  digest,
  fetchImpl,
  image,
  runCommand,
  sleep,
}) {
  const smokeId = createId();
  const container = `enoki-release-smoke-${smokeId}`;
  const localImage = `enoki-release-smoke-local:${smokeId}`;
  let localImageCopied = false;
  try {
    await runCommand(
      "skopeo",
      [
        "copy",
        "--src-no-creds",
        "--preserve-digests",
        `docker://${image}@${digest}`,
        `docker-daemon:${localImage}`,
      ],
      { env: { REGISTRY_AUTH_FILE: anonymousAuthFile } },
    );
    localImageCopied = true;
    await runCommand("docker", [
      "run",
      "--detach",
      "--rm",
      "--pull",
      "never",
      "--name",
      container,
      "--publish",
      "127.0.0.1::3000",
      "--env",
      "OWNER_PASSWORD=enoki-release-smoke-only",
      localImage,
    ]);
    const portOutput = await runCommand("docker", [
      "port",
      container,
      "3000/tcp",
    ]);
    const firstBinding = portOutput.stdout.trim().split("\n")[0];
    const port = firstBinding?.match(/:([0-9]+)$/)?.[1];
    if (!port) throw new Error("could not resolve Hub smoke port");
    const baseUrl = new URL(`http://127.0.0.1:${port}`);
    await waitForHubHealth(baseUrl, { fetchImpl, sleep });
    const [manifestResponse, installerResponse] = await Promise.all([
      fetchImpl(new URL("/api/probe/assets/manifest.json", baseUrl), {
        credentials: "omit",
      }),
      fetchImpl(new URL("/api/probe/install.sh", baseUrl), {
        credentials: "omit",
      }),
    ]);
    if (!manifestResponse.ok || !installerResponse.ok) {
      throw new Error("Hub did not serve its embedded Probe Asset Set");
    }
    const manifest = await manifestResponse.json();
    const installer = await installerResponse.text();
    return {
      embeddedProbeVersion: manifest.version,
      installerUsesHubAssets:
        installer.includes("/api/probe/assets/manifest.json") &&
        !installer.includes("releases/latest/download"),
    };
  } finally {
    try {
      await runCommand("docker", ["stop", "--time", "10", container]);
    } catch {
      // A failed or already-exited smoke container still leaves immutable
      // publication state untouched; the caller records the primary failure.
    }
    if (localImageCopied) {
      await runCommand("docker", ["image", "rm", "--force", localImage]);
    }
  }
}

async function waitForHubHealth(baseUrl, { fetchImpl, sleep }) {
  let lastError = new Error("Hub health was not attempted");
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetchImpl(new URL("/api/health", baseUrl), {
        credentials: "omit",
      });
      if (response.ok) {
        const body = await response.json();
        if (body?.status === "ok" && body?.service === "enoki-hub") return;
      }
      lastError = new Error(`Hub health returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(1_000);
  }
  throw new Error(`Hub health timeout: ${lastError.message}`);
}

async function inspectRegistryImage(runCommand, reference, options = {}) {
  const arguments_ = ["inspect", "--format", "{{.Digest}}"];
  if (options.publicOnly) arguments_.push("--no-creds");
  arguments_.push(`docker://${reference}`);
  try {
    const result = await runCommand("skopeo", arguments_, {
      env: options.anonymousAuthFile
        ? { REGISTRY_AUTH_FILE: options.anonymousAuthFile }
        : undefined,
    });
    const digest = result.stdout.trim();
    if (!/^sha256:[0-9a-f]{64}$/.test(digest)) {
      throw new Error(`registry returned an invalid digest for ${reference}`);
    }
    return { digest };
  } catch (error) {
    if (isNotFound(error)) return null;
    throw error;
  }
}

async function smokeCheck(name, checks, failureReasons, operation) {
  try {
    await operation();
    checks[name] = "succeeded";
  } catch (error) {
    checks[name] = "failed";
    failureReasons.push(`${name}: ${redactSensitive(error.message)}`);
  }
}

function redactSensitive(value) {
  return String(value ?? "unknown failure")
    .replace(/\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]+/g, "[redacted]")
    .replace(
      /(authorization:\s*bearer|\bbearer|password\s*=|token\s*=)\s*\S+/gi,
      "$1 [redacted]",
    );
}

async function ghJson(runCommand, endpoint) {
  const result = await runCommand("gh", ["api", endpoint]);
  return JSON.parse(result.stdout);
}

function parseGitHubAssetDigest(digest) {
  return typeof digest === "string" && /^sha256:[0-9a-f]{64}$/.test(digest)
    ? digest.slice("sha256:".length)
    : null;
}

function isNotFound(error) {
  return (
    error?.notFound === true ||
    /(?:HTTP 404|manifest unknown|name unknown|not found)/i.test(
      `${error?.stderr ?? ""}\n${error?.message ?? ""}`,
    ) ||
    (error?.cause ? isNotFound(error.cause) : false)
  );
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function executeCommand(command, arguments_, options = {}) {
  return execFileAsync(command, arguments_, {
    env: { ...process.env, ...options.env },
    maxBuffer: 64 * 1024 * 1024,
  });
}

function createSafeCommandRunner(runCommand) {
  return async (command, arguments_, options) => {
    try {
      return await runCommand(command, arguments_, options);
    } catch (cause) {
      const error = new Error(`${command} command failed`, { cause });
      error.notFound = isNotFound(cause);
      throw error;
    }
  };
}
