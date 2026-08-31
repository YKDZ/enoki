import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { createDockerHubController } from "./release-e2e-adapters.mjs";

describe("Release E2E legacy public-origin adapter", () => {
  it("keeps the authenticated v0.1.74 baseline and Candidate on the same public Probe origin", async () => {
    const docker = dockerCommandTracer();
    const controller = createDockerHubController({
      exec: docker.exec,
      fetch: async () => jsonResponse({ service: "enoki-hub", status: "ok" }),
      sleep: async () => {},
    });
    const resources = await controller.start({
      candidateDir: "/candidate",
      candidateManifest: trustEpochMigrationManifest(),
      hubMode: "baseline",
      hubOwnerUrl: "http://127.0.0.1:33001",
      hubPublicUrl: "http://127.0.0.1:33000",
      ownerPassword: "owner-secret",
      runId: "run-legacy-public-origin",
    });

    await controller.switchToCandidate({
      resources,
      runId: "run-legacy-public-origin",
    });

    expect(docker.envFiles).toEqual([
      expect.arrayContaining([
        "ENOKI_PUBLIC_HUB_URL=http://127.0.0.1:33000",
        "ENOKI_MANAGEMENT_ORIGIN=http://127.0.0.1:33000",
        "ENOKI_PROBE_API_ORIGIN=http://127.0.0.1:33000",
      ]),
      expect.not.arrayContaining([
        "ENOKI_PUBLIC_HUB_URL=http://127.0.0.1:33000",
      ]),
    ]);
    expect(docker.envFiles[1]).toEqual(
      expect.arrayContaining([
        "ENOKI_MANAGEMENT_ORIGIN=http://127.0.0.1:33000",
        "ENOKI_PROBE_API_ORIGIN=http://127.0.0.1:33000",
      ]),
    );
  });

  it("does not infer legacy public-origin configuration from a baseline runtime name", async () => {
    for (const [kind, tag] of [
      ["enoki-release-baseline", "v0.1.74"],
      ["enoki-trust-epoch-migration-baseline", "v0.1.73"],
      ["enoki-release-baseline", "v0.1.73"],
    ]) {
      const docker = dockerCommandTracer();
      const controller = createDockerHubController({
        exec: docker.exec,
        fetch: async () => jsonResponse({ service: "enoki-hub", status: "ok" }),
        sleep: async () => {},
      });
      const manifest = trustEpochMigrationManifest();
      manifest.releaseBaseline.kind = kind;
      manifest.releaseBaseline.tag = tag;

      await controller.start({
        candidateDir: "/candidate",
        candidateManifest: manifest,
        hubMode: "baseline",
        hubOwnerUrl: "http://127.0.0.1:33001",
        hubPublicUrl: "http://127.0.0.1:33000",
        ownerPassword: "owner-secret",
        runId: `run-nonlegacy-${tag.slice(-1)}-${kind.slice(6, 12)}`,
      });

      expect(docker.envFiles).toHaveLength(1);
      expect(docker.envFiles[0]).toEqual(
        expect.not.arrayContaining([
          "ENOKI_PUBLIC_HUB_URL=http://127.0.0.1:33000",
        ]),
      );
    }
  });
});

function trustEpochMigrationManifest() {
  return {
    hub: {
      archive: "hub/candidate.oci.tar",
      digest: `sha256:${"a".repeat(64)}`,
    },
    releaseBaseline: {
      hub: {
        archive: "hub/baseline.oci.tar",
        imageDigest: `sha256:${"b".repeat(64)}`,
      },
      kind: "enoki-trust-epoch-migration-baseline",
      tag: "v0.1.74",
    },
  };
}

function dockerCommandTracer() {
  const envFiles = [];
  const images = new Map();
  const volumes = new Set();
  let activeImage = null;
  let container = false;
  let stagedImage = null;
  let stagedTag = null;

  return {
    envFiles,
    exec: async (command, arguments_) => {
      if (command === "tar") {
        const baseline = arguments_.some((value) =>
          value.includes("release-baseline"),
        );
        return commandResult(
          arguments_.at(-1) === "index.json"
            ? JSON.stringify({
                manifests: [
                  {
                    digest: `sha256:${(baseline ? "b" : "a").repeat(64)}`,
                  },
                ],
              })
            : JSON.stringify({
                config: {
                  digest: `sha256:${(baseline ? "d" : "c").repeat(64)}`,
                },
              }),
        );
      }
      if (command === "skopeo") {
        stagedImage = arguments_[1].includes("release-baseline")
          ? `sha256:${"d".repeat(64)}`
          : `sha256:${"c".repeat(64)}`;
        stagedTag = arguments_[2].split("/hub.docker.tar:")[1];
        return commandResult();
      }
      if (arguments_[0] === "load") {
        images.set(stagedTag, stagedImage);
        stagedImage = null;
        stagedTag = null;
        return commandResult();
      }
      if (arguments_[0] === "volume" && arguments_[1] === "create") {
        volumes.add(arguments_.at(-1));
        return commandResult();
      }
      if (arguments_[0] === "volume" && arguments_[1] === "rm") {
        volumes.delete(arguments_[2]);
        return commandResult();
      }
      if (arguments_[0] === "run") {
        const envFile = arguments_[arguments_.indexOf("--env-file") + 1];
        envFiles.push((await readFile(envFile, "utf8")).trim().split("\n"));
        activeImage = images.get(arguments_.at(-1));
        container = true;
        return commandResult("container-id\n");
      }
      if (arguments_[0] === "port") {
        return commandResult(
          arguments_[2] === "3000/tcp"
            ? "0.0.0.0:33001\n127.0.0.1:49152\n"
            : "127.0.0.1:49152\n",
        );
      }
      if (arguments_[0] === "stop" || arguments_[0] === "rm") {
        container = false;
        return commandResult();
      }
      if (arguments_[0] === "image" && arguments_[1] === "rm") {
        images.delete(arguments_[2]);
        return commandResult();
      }
      if (arguments_[0] === "container" && arguments_[1] === "inspect") {
        if (arguments_.some((value) => value.includes("enoki.release-e2e"))) {
          return container
            ? commandResult("run-legacy-public-origin\n")
            : absent("No such container");
        }
        if (arguments_.includes("--format")) {
          return container
            ? commandResult(activeImage)
            : absent("No such container");
        }
        return container
          ? commandResult("run-legacy-public-origin\n")
          : absent("No such container");
      }
      if (arguments_[0] === "volume" && arguments_[1] === "inspect") {
        return volumes.has(arguments_.at(-1))
          ? commandResult("run-legacy-public-origin\n")
          : absent("No such volume");
      }
      if (arguments_[0] === "image" && arguments_[1] === "inspect") {
        const image = images.get(arguments_.at(-1));
        return image ? commandResult(image) : absent("No such image");
      }
      if (arguments_[0] === "inspect") {
        return container
          ? commandResult("run-legacy-public-origin\n")
          : absent("No such container");
      }
      if (arguments_.includes("inspect")) {
        return container
          ? commandResult(activeImage)
          : absent("No such container");
      }
      return commandResult();
    },
  };
}

function absent(stderr) {
  return { code: 1, stderr, stdout: "" };
}

function commandResult(stdout = "") {
  return { code: 0, stderr: "", stdout };
}

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
    status: 200,
  });
}
