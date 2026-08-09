import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it, vi } from "vitest";

import { reconcilePublication } from "./release-publication-lib.mjs";
import {
  createGitHubGhcrPublicationRemote,
  createPublicationSmokeService,
} from "./release-publication-remote.mjs";

const execFileAsync = promisify(execFile);

describe("Publication Reconciler", () => {
  it("wires one manual publish mode after the complete fresh candidate gate", async () => {
    const [entrypoint, candidateWorkflow, publicationWorkflow, ciHubWorkflow] =
      await Promise.all([
        readFile(".github/workflows/release.yml", "utf8"),
        readFile(
          ".github/workflows/reusable-build-release-candidate.yml",
          "utf8",
        ),
        readFile(
          ".github/workflows/reusable-publish-release-candidate.yml",
          "utf8",
        ),
        readFile(".github/workflows/reusable-hub-image.yml", "utf8"),
      ]);

    expect(entrypoint).toContain("workflow_dispatch:");
    expect(entrypoint).not.toMatch(/^  push:/m);
    expect(entrypoint).toMatch(/options:\n\s+- verify-only\n\s+- publish/);
    expect(entrypoint).not.toContain("mode: ${{ inputs.mode }}");
    expect(entrypoint).toContain("if: ${{ inputs.mode == 'publish' }}");
    expect(entrypoint).toContain(
      "uses: ./.github/workflows/reusable-publish-release-candidate.yml",
    );
    expect(entrypoint).toContain("candidate-artifact-name:");
    expect(entrypoint).toContain("verification-artifact-name:");

    expect(candidateWorkflow).not.toContain("RELEASE_MODE");
    expect(candidateWorkflow).toContain("verification-artifact-name:");
    expect(candidateWorkflow).not.toMatch(
      /contents: write|packages: write|gh release|docker push|--push/,
    );

    expect(publicationWorkflow).toContain("workflow_call:");
    expect(publicationWorkflow).toContain("actions: read");
    expect(publicationWorkflow).toContain("contents: write");
    expect(publicationWorkflow).toContain("packages: write");
    expect(publicationWorkflow).toContain("release-publication.mjs reconcile");
    expect(publicationWorkflow).toContain(
      "release-publication.mjs assert-published",
    );
    expect(publicationWorkflow).not.toMatch(
      /docker build|buildx build|gh release download|--clobber|--force|git tag/,
    );
    expect(publicationWorkflow).not.toContain("docker login");
    expect(ciHubWorkflow).not.toMatch(
      /include-probe-assets|push-image|gh release download|--push|enoki-hub:latest/,
    );
    await expect(
      readFile(".github/workflows/reusable-publish-probe-release.yml", "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects untrusted publication callers before any artifact download or write", async () => {
    const workflow = await readFile(
      ".github/workflows/reusable-publish-release-candidate.yml",
      "utf8",
    );
    const validation = workflow.slice(
      workflow.indexOf("  validate-publication-invocation:"),
      workflow.indexOf("  publish-candidate:"),
    );
    const publication = workflow.slice(
      workflow.indexOf("  publish-candidate:"),
    );

    expect(validation).toContain(
      "YKDZ/enoki/.github/workflows/reusable-publish-release-candidate.yml@refs/heads/main",
    );
    expect(validation).toContain("${{ toJSON(job) }}");
    expect(validation).toContain(".workflow_ref");
    expect(validation).toContain(".workflow_repository");
    expect(validation).toContain(".workflow_sha");
    expect(validation).toContain("CALLER_REF: ${{ github.ref }}");
    expect(validation).toContain("CALLER_REPOSITORY: ${{ github.repository }}");
    expect(validation).not.toMatch(
      /actions\/download-artifact|contents: write|packages: write|release-publication[.]mjs/,
    );

    expect(publication).toContain("needs: validate-publication-invocation");
    expect(publication).toContain("environment: release-publishing");
    expect(publication).toContain(
      "repository: ${{ needs.validate-publication-invocation.outputs.trusted-workflow-repository }}",
    );
    expect(publication).toContain(
      "ref: ${{ needs.validate-publication-invocation.outputs.trusted-workflow-sha }}",
    );
    expect(publication).not.toContain("ref: ${{ github.workflow_sha }}");
  });

  it("publishes the exact verified candidate in the controlled order", async () => {
    const fixture = await createPublicationFixture();
    try {
      const remote = new FakePublicationRemote();
      const result = await reconcilePublication({
        candidateDir: fixture.candidateDir,
        candidateManifest: fixture.candidateManifest,
        remote,
        verificationSummary: fixture.verificationSummary,
        workflowRun: fixture.workflowRun,
      });

      expect(result.status).toBe("published");
      expect(remote.events).toEqual([
        "tag:create",
        "release:create-draft",
        ...fixture.candidateManifest.probeAssetSet.files.map(
          ({ file }) => `asset:upload:${file}`,
        ),
        "image:publish-version",
        "release:make-public",
        "image:move-latest",
        "smoke:verify",
      ]);
      expect(remote.tag).toEqual({
        commit: fixture.candidateManifest.candidate.commit,
      });
      expect(remote.release).toMatchObject({ draft: false });
      expect(remote.images).toEqual({
        latest: fixture.candidateManifest.hub.digest,
        [fixture.candidateManifest.candidate.version]:
          fixture.candidateManifest.hub.digest,
      });
    } finally {
      await fixture.cleanup();
    }
  });

  it("uses the created draft response while the release list is eventually consistent", async () => {
    const fixture = await createPublicationFixture();
    try {
      const remote = new FakePublicationRemote({
        hideEmptyCreatedReleaseReads: 1,
      });
      const result = await reconcilePublication({
        candidateDir: fixture.candidateDir,
        candidateManifest: fixture.candidateManifest,
        remote,
        verificationSummary: fixture.verificationSummary,
        workflowRun: fixture.workflowRun,
      });

      expect(result.status).toBe("published");
      expect(
        remote.events.filter((event) => event === "release:create-draft"),
      ).toHaveLength(1);
    } finally {
      await fixture.cleanup();
    }
  });

  it("resumes the same candidate after interruption at every publication stage", async () => {
    const fixture = await createPublicationFixture();
    try {
      const stages = [
        "tag:create",
        "release:create-draft",
        ...fixture.candidateManifest.probeAssetSet.files.map(
          ({ file }) => `asset:upload:${file}`,
        ),
        "image:publish-version",
        "release:make-public",
        "image:move-latest",
        "smoke:verify",
      ];

      for (const stage of stages) {
        const remote = new FakePublicationRemote({ failAfter: stage });
        await expect(
          reconcilePublication({
            candidateDir: fixture.candidateDir,
            candidateManifest: fixture.candidateManifest,
            remote,
            verificationSummary: fixture.verificationSummary,
            workflowRun: fixture.workflowRun,
          }),
        ).rejects.toThrow(`interrupted after ${stage}`);

        remote.failAfter = null;
        const resumed = await reconcilePublication({
          candidateDir: fixture.candidateDir,
          candidateManifest: fixture.candidateManifest,
          remote,
          verificationSummary: fixture.verificationSummary,
          workflowRun: fixture.workflowRun,
        });
        expect(resumed.status, stage).toBe("published");
        expect(
          remote.events.filter((event) => event === stage),
          stage,
        ).toHaveLength(stage === "smoke:verify" ? 2 : 1);
      }
    } finally {
      await fixture.cleanup();
    }
  });

  it("rejects a Release containing an asset outside the Candidate Manifest", async () => {
    const fixture = await createPublicationFixture();
    try {
      const remote = new FakePublicationRemote();
      remote.tag = { commit: fixture.candidateManifest.candidate.commit };
      remote.release = {
        assets: {
          "unexpected-build.tar.gz": {
            sha256: "f".repeat(64),
            size: 42,
          },
        },
        draft: true,
        targetCommit: fixture.candidateManifest.candidate.commit,
      };

      await expect(
        reconcilePublication({
          candidateDir: fixture.candidateDir,
          candidateManifest: fixture.candidateManifest,
          remote,
          verificationSummary: fixture.verificationSummary,
          workflowRun: fixture.workflowRun,
        }),
      ).rejects.toThrow("unexpected immutable Release asset");
      expect(remote.events).toEqual([]);
    } finally {
      await fixture.cleanup();
    }
  });

  it.each([
    {
      configure: (remote, fixture) => {
        seedMatchingTagAndRelease(remote, fixture, {
          completeAssets: true,
          draft: false,
        });
        remote.tag = null;
        remote.images[fixture.candidateManifest.candidate.version] =
          fixture.candidateManifest.hub.digest;
      },
      expected: "immutable version tag is missing",
      name: "tag",
    },
    {
      configure: (remote, fixture) => {
        seedMatchingTagAndRelease(remote, fixture, { draft: false });
        remote.images[fixture.candidateManifest.candidate.version] =
          fixture.candidateManifest.hub.digest;
      },
      expected: "immutable Probe Asset Set is incomplete",
      name: "Probe asset",
    },
    {
      configure: (remote, fixture) => {
        seedMatchingTagAndRelease(remote, fixture, {
          completeAssets: true,
          draft: false,
        });
      },
      expected: "immutable versioned Hub image is missing",
      name: "versioned Hub image",
    },
    {
      configure: (remote, fixture) => {
        seedMatchingTagAndRelease(remote, fixture, {
          completeAssets: true,
          draft: false,
        });
        remote.tag = { commit: "c".repeat(40) };
        remote.images[fixture.candidateManifest.candidate.version] =
          fixture.candidateManifest.hub.digest;
      },
      expected: "immutable tag",
      name: "mismatched tag",
    },
    {
      configure: (remote, fixture) => {
        seedMatchingTagAndRelease(remote, fixture, {
          completeAssets: true,
          draft: false,
        });
        const asset = fixture.candidateManifest.probeAssetSet.files[0];
        remote.release.assets[asset.file] = {
          sha256: "c".repeat(64),
          size: asset.size,
        };
        remote.images[fixture.candidateManifest.candidate.version] =
          fixture.candidateManifest.hub.digest;
      },
      expected: "immutable Release asset",
      name: "mismatched Probe asset",
    },
    {
      configure: (remote, fixture) => {
        seedMatchingTagAndRelease(remote, fixture, {
          completeAssets: true,
          draft: false,
        });
        remote.images[fixture.candidateManifest.candidate.version] =
          `sha256:${"d".repeat(64)}`;
      },
      expected: "immutable Hub image",
      name: "mismatched versioned Hub image",
    },
  ])(
    "treats a public Release with an incomplete or mismatched $name as a terminal conflict without mutation",
    async ({ configure, expected }) => {
      const fixture = await createPublicationFixture();
      try {
        const remote = new FakePublicationRemote();
        configure(remote, fixture);

        await expect(
          reconcilePublication({
            candidateDir: fixture.candidateDir,
            candidateManifest: fixture.candidateManifest,
            remote,
            verificationSummary: fixture.verificationSummary,
            workflowRun: fixture.workflowRun,
          }),
        ).rejects.toThrow(expected);
        expect(remote.events).toEqual([]);
      } finally {
        await fixture.cleanup();
      }
    },
  );

  it("records a broken release when public smoke fails without rewriting immutable outputs", async () => {
    const fixture = await createPublicationFixture();
    try {
      const remote = new FakePublicationRemote();
      remote.smokeResult = {
        checks: {
          embeddedProbeVersion: "succeeded",
          hubHealth: "failed",
          imageDigest: "succeeded",
          probeChecksums: "succeeded",
          probeSignature: "succeeded",
        },
        failureReasons: ["Hub health returned 503"],
        outcome: "failed",
      };

      const result = await reconcilePublication({
        candidateDir: fixture.candidateDir,
        candidateManifest: fixture.candidateManifest,
        remote,
        verificationSummary: fixture.verificationSummary,
        workflowRun: fixture.workflowRun,
      });

      expect(result).toMatchObject({
        smoke: remote.smokeResult,
        status: "broken",
      });
      expect(remote.release.draft).toBe(false);
      expect(remote.tag.commit).toBe(
        fixture.candidateManifest.candidate.commit,
      );
      expect(remote.images).toEqual({
        latest: fixture.candidateManifest.hub.digest,
        [fixture.candidateManifest.candidate.version]:
          fixture.candidateManifest.hub.digest,
      });
      expect(remote.events.at(-1)).toBe("smoke:verify");
    } finally {
      await fixture.cleanup();
    }
  });

  it.each([
    {
      configure: (remote, _fixture) => {
        remote.tag = { commit: "c".repeat(40) };
      },
      expected: "immutable tag v1.2.3 resolves to",
      name: "tag commit",
    },
    {
      configure: (remote, fixture) => {
        seedMatchingTagAndRelease(remote, fixture);
        const file = fixture.candidateManifest.probeAssetSet.files[0];
        remote.release.assets[file.file] = {
          sha256: "d".repeat(64),
          size: file.size,
        };
      },
      expected: "immutable Release asset",
      name: "Probe asset checksum",
    },
    {
      configure: (remote, fixture) => {
        seedMatchingTagAndRelease(remote, fixture, { completeAssets: true });
        remote.images[fixture.candidateManifest.candidate.version] =
          `sha256:${"e".repeat(64)}`;
      },
      expected: "immutable Hub image",
      name: "Hub image digest",
    },
  ])(
    "rejects a mismatched existing $name without mutation",
    async ({ configure, expected }) => {
      const fixture = await createPublicationFixture();
      try {
        const remote = new FakePublicationRemote();
        configure(remote, fixture);

        await expect(
          reconcilePublication({
            candidateDir: fixture.candidateDir,
            candidateManifest: fixture.candidateManifest,
            remote,
            verificationSummary: fixture.verificationSummary,
            workflowRun: fixture.workflowRun,
          }),
        ).rejects.toThrow(expected);
        expect(remote.events).toEqual([]);
      } finally {
        await fixture.cleanup();
      }
    },
  );

  it("rejects verification from another run and obsolete mode-specific evidence", async () => {
    const fixture = await createPublicationFixture();
    try {
      for (const verificationSummary of [
        {
          ...fixture.verificationSummary,
          run: { ...fixture.workflowRun, id: "another-run" },
        },
        {
          ...fixture.verificationSummary,
          kind: "enoki-verify-only-summary",
        },
        {
          ...fixture.verificationSummary,
          probeAssetSet: {
            ...fixture.verificationSummary.probeAssetSet,
            files: fixture.verificationSummary.probeAssetSet.files.map(
              (file, index) =>
                index === 0 ? { ...file, sha256: "0".repeat(64) } : file,
            ),
          },
        },
      ]) {
        const remote = new FakePublicationRemote();
        await expect(
          reconcilePublication({
            candidateDir: fixture.candidateDir,
            candidateManifest: fixture.candidateManifest,
            remote,
            verificationSummary,
            workflowRun: fixture.workflowRun,
          }),
        ).rejects.toThrow("freshly verified publish candidate");
        expect(remote.events).toEqual([]);
      }
    } finally {
      await fixture.cleanup();
    }
  });

  it("allows a failed publication job to resume in a later attempt of the same workflow run", async () => {
    const fixture = await createPublicationFixture();
    try {
      const result = await reconcilePublication({
        candidateDir: fixture.candidateDir,
        candidateManifest: fixture.candidateManifest,
        remote: new FakePublicationRemote(),
        verificationSummary: fixture.verificationSummary,
        workflowRun: { ...fixture.workflowRun, attempt: 2 },
      });

      expect(result.status).toBe("published");
      expect(result.verificationRun).toEqual(fixture.workflowRun);
      expect(result.workflowRun.attempt).toBe(2);
    } finally {
      await fixture.cleanup();
    }
  });

  it("lets the workflow assert a successful audit and fail closed for a broken smoke audit", async () => {
    const fixture = await createPublicationFixture();
    const summaryPath = path.join(fixture.candidateDir, "publication.json");
    try {
      const published = await reconcilePublication({
        candidateDir: fixture.candidateDir,
        candidateManifest: fixture.candidateManifest,
        remote: new FakePublicationRemote(),
        verificationSummary: fixture.verificationSummary,
        workflowRun: fixture.workflowRun,
      });
      await writeFile(summaryPath, `${JSON.stringify(published)}\n`);
      await expect(
        execFileAsync(process.execPath, [
          "scripts/release-publication.mjs",
          "assert-published",
          "--summary",
          summaryPath,
        ]),
      ).resolves.toMatchObject({ stdout: expect.stringContaining("v1.2.3") });

      const brokenRemote = new FakePublicationRemote();
      brokenRemote.smokeResult = {
        checks: { hubHealth: "failed" },
        failureReasons: ["Hub unavailable"],
        outcome: "failed",
      };
      const broken = await reconcilePublication({
        candidateDir: fixture.candidateDir,
        candidateManifest: fixture.candidateManifest,
        remote: brokenRemote,
        verificationSummary: fixture.verificationSummary,
        workflowRun: fixture.workflowRun,
      });
      await writeFile(summaryPath, `${JSON.stringify(broken)}\n`);
      await expect(
        execFileAsync(process.execPath, [
          "scripts/release-publication.mjs",
          "assert-published",
          "--summary",
          summaryPath,
        ]),
      ).rejects.toMatchObject({ code: 1 });
    } finally {
      await fixture.cleanup();
    }
  });
});

describe("GitHub and GHCR publication adapter", () => {
  it("peels tags, parses draft asset digests, and preserves immutable image content without overwrite commands", async () => {
    const calls = [];
    const expectedCommit = "a".repeat(40);
    const expectedDigest = `sha256:${"b".repeat(64)}`;
    const runCommand = async (command, arguments_) => {
      calls.push([command, ...arguments_]);
      const joined = arguments_.join(" ");
      if (joined.includes("git/ref/tags/v1.2.3")) {
        return {
          stdout: JSON.stringify({
            object: { sha: "c".repeat(40), type: "tag" },
          }),
        };
      }
      if (joined.includes(`git/tags/${"c".repeat(40)}`)) {
        return {
          stdout: JSON.stringify({
            object: { sha: "d".repeat(40), type: "tag" },
          }),
        };
      }
      if (joined.includes(`git/tags/${"d".repeat(40)}`)) {
        return {
          stdout: JSON.stringify({
            object: { sha: expectedCommit, type: "commit" },
          }),
        };
      }
      if (joined.includes("releases?per_page=100")) {
        return {
          stdout: JSON.stringify([
            [
              {
                assets: [
                  {
                    browser_download_url: "https://example/manifest.json",
                    digest: `sha256:${"e".repeat(64)}`,
                    id: 8,
                    name: "manifest.json",
                    size: 42,
                  },
                  {
                    browser_download_url: "https://example/legacy",
                    digest: "unavailable",
                    id: 9,
                    name: "legacy",
                    size: 7,
                  },
                ],
                draft: true,
                html_url: "https://example/release/v1.2.3",
                id: 7,
                tag_name: "v1.2.3",
                target_commitish: expectedCommit,
              },
            ],
          ]),
        };
      }
      if (
        command === "gh" &&
        arguments_.includes("POST") &&
        arguments_.includes("repos/acme/enoki/releases")
      ) {
        return {
          stdout: JSON.stringify({
            assets: [],
            draft: true,
            html_url: "https://example/release/v1.2.3",
            id: 17,
            tag_name: "v1.2.3",
            target_commitish: expectedCommit,
          }),
        };
      }
      if (command === "skopeo" && arguments_[0] === "inspect") {
        return { stdout: `${expectedDigest}\n` };
      }
      return { stdout: "" };
    };
    const remote = createGitHubGhcrPublicationRemote({
      image: "ghcr.io/acme/enoki-hub",
      repository: "acme/enoki",
      runCommand,
    });

    await expect(remote.getTag({ version: "v1.2.3" })).resolves.toEqual({
      commit: expectedCommit,
    });
    await expect(remote.getRelease({ version: "v1.2.3" })).resolves.toEqual({
      assets: {
        legacy: {
          downloadUrl: "https://example/legacy",
          id: 9,
          sha256: null,
          size: 7,
        },
        "manifest.json": {
          downloadUrl: "https://example/manifest.json",
          id: 8,
          sha256: "e".repeat(64),
          size: 42,
        },
      },
      draft: true,
      id: 7,
      targetCommit: expectedCommit,
      url: "https://example/release/v1.2.3",
    });
    await remote.createTag({ commit: expectedCommit, version: "v1.2.3" });
    await expect(
      remote.createDraftRelease({
        commit: expectedCommit,
        version: "v1.2.3",
      }),
    ).resolves.toMatchObject({
      assets: {},
      draft: true,
      id: 17,
      targetCommit: expectedCommit,
    });
    await remote.uploadAsset({
      filePath: "/candidate/manifest.json",
      version: "v1.2.3",
    });
    await remote.publishVersionImage({
      archivePath: "/candidate/hub.oci.tar",
      version: "v1.2.3",
    });
    await remote.makeReleasePublic({ version: "v1.2.3" });
    await remote.moveLatest({ digest: expectedDigest });
    await expect(remote.getImage({ tag: "v1.2.3" })).resolves.toEqual({
      digest: expectedDigest,
    });

    expect(calls).toContainEqual([
      "skopeo",
      "copy",
      "--preserve-digests",
      "oci-archive:/candidate/hub.oci.tar",
      "docker://ghcr.io/acme/enoki-hub:v1.2.3",
    ]);
    expect(calls).toContainEqual([
      "skopeo",
      "copy",
      "--preserve-digests",
      `docker://ghcr.io/acme/enoki-hub@${expectedDigest}`,
      "docker://ghcr.io/acme/enoki-hub:latest",
    ]);
    expect(calls.flat().join(" ")).not.toMatch(
      /--clobber|--force|\bDELETE\b|release delete|tag --force/,
    );
  });

  it("proves public layers and Hub assets anonymously from a unique cache-independent local image", async () => {
    const fixture = await createPublicationFixture();
    try {
      const commands = [];
      const fetches = [];
      let inspectedProbeAssetEntries = [];
      let failImageCleanup = false;
      const publicFiles = new Map();
      for (const expected of fixture.candidateManifest.probeAssetSet.files) {
        publicFiles.set(
          `https://downloads.example/${expected.file}`,
          await readFile(
            path.join(
              fixture.candidateDir,
              fixture.candidateManifest.probeAssetSet.directory,
              expected.file,
            ),
          ),
        );
      }
      const runCommand = async (command, arguments_, options) => {
        commands.push({ arguments_, command, options });
        if (
          failImageCleanup &&
          command === "docker" &&
          arguments_[0] === "image" &&
          arguments_[1] === "rm"
        ) {
          throw new Error("failed to remove local smoke image");
        }
        if (command === "skopeo" && arguments_[0] === "inspect") {
          return { stdout: `${fixture.candidateManifest.hub.digest}\n` };
        }
        if (command === "docker" && arguments_[0] === "port") {
          return { stdout: "127.0.0.1:49152\n" };
        }
        return { stdout: "" };
      };
      const fetchImpl = async (input, init) => {
        const url = input instanceof URL ? input.href : String(input);
        fetches.push({ init, url });
        if (publicFiles.has(url)) {
          return new Response(publicFiles.get(url), { status: 200 });
        }
        if (url === "http://127.0.0.1:49152/api/health") {
          return Response.json({ service: "enoki-hub", status: "ok" });
        }
        if (url === "http://127.0.0.1:49152/api/probe/assets/manifest.json") {
          return Response.json({ version: "1.2.3" });
        }
        if (url === "http://127.0.0.1:49152/api/probe/install.sh") {
          return new Response(
            "fetch /api/probe/assets/manifest.json; fetch /api/probe/assets/archive",
          );
        }
        return new Response("not found", { status: 404 });
      };
      const service = createPublicationSmokeService({
        createId: () => "unique-smoke-id",
        fetchImpl,
        inspectProbeAssets: async (assetDirectory) => {
          inspectedProbeAssetEntries = (await readdir(assetDirectory)).sort();
          return {
            signingIdentity:
              fixture.candidateManifest.probeAssetSet.signingIdentity,
          };
        },
        runCommand,
        sleep: async () => {},
      });
      const release = {
        assets: Object.fromEntries(
          fixture.candidateManifest.probeAssetSet.files.map((file) => [
            file.file,
            {
              downloadUrl: `https://downloads.example/${file.file}`,
              sha256: file.sha256,
              size: file.size,
            },
          ]),
        ),
        draft: false,
      };

      await expect(
        service.verifyPublicCandidate({
          candidateManifest: fixture.candidateManifest,
          getRelease: async () => release,
          image: "ghcr.io/acme/enoki-hub",
          version: "v1.2.3",
        }),
      ).resolves.toEqual({
        checks: {
          embeddedProbeVersion: "succeeded",
          hubHealth: "succeeded",
          imageDigest: "succeeded",
          probeChecksums: "succeeded",
          probeSignature: "succeeded",
        },
        failureReasons: [],
        outcome: "succeeded",
      });

      const inspect = commands.find(
        ({ arguments_, command }) =>
          command === "skopeo" && arguments_[0] === "inspect",
      );
      expect(inspect.arguments_).toContain("--no-creds");
      expect(inspectedProbeAssetEntries).toEqual(
        fixture.candidateManifest.probeAssetSet.files
          .map(({ file }) => file)
          .sort(),
      );
      expect(
        commands.some(
          ({ arguments_, command }) =>
            command === "skopeo" && arguments_[0] === "copy",
        ),
      ).toBe(false);
      const pull = commands.find(
        ({ arguments_, command }) =>
          command === "docker" && arguments_.includes("pull"),
      );
      expect(pull.arguments_).toEqual(
        expect.arrayContaining([
          "--config",
          "pull",
          `ghcr.io/acme/enoki-hub@${fixture.candidateManifest.hub.digest}`,
        ]),
      );
      const run = commands.find(
        ({ arguments_, command }) =>
          command === "docker" && arguments_[0] === "run",
      );
      expect(run.arguments_).toEqual(
        expect.arrayContaining([
          "--pull",
          "never",
          "enoki-release-smoke-local:unique-smoke-id",
        ]),
      );
      expect(run.arguments_).not.toContain(
        `ghcr.io/acme/enoki-hub@${fixture.candidateManifest.hub.digest}`,
      );
      expect(commands).toContainEqual(
        expect.objectContaining({
          arguments_: [
            "image",
            "rm",
            "--force",
            "enoki-release-smoke-local:unique-smoke-id",
            `ghcr.io/acme/enoki-hub@${fixture.candidateManifest.hub.digest}`,
          ],
          command: "docker",
        }),
      );
      for (const request of fetches.filter(({ url }) =>
        url.startsWith("https://downloads.example/"),
      )) {
        expect(request.init).toMatchObject({
          credentials: "omit",
          redirect: "follow",
        });
        expect(request.init?.headers ?? {}).not.toHaveProperty("authorization");
      }
      expect(fetches.map(({ url }) => url)).toEqual(
        expect.arrayContaining([
          "http://127.0.0.1:49152/api/health",
          "http://127.0.0.1:49152/api/probe/assets/manifest.json",
          "http://127.0.0.1:49152/api/probe/install.sh",
        ]),
      );

      failImageCleanup = true;
      const cleanupFailure = await service.verifyPublicCandidate({
        candidateManifest: fixture.candidateManifest,
        getRelease: async () => release,
        image: "ghcr.io/acme/enoki-hub",
        version: "v1.2.3",
      });
      expect(cleanupFailure.outcome).toBe("failed");
      expect(cleanupFailure.checks.hubHealth).toBe("failed");
      expect(cleanupFailure.failureReasons.join(" ")).toContain(
        "failed to remove local smoke image",
      );
    } finally {
      await fixture.cleanup();
    }
  });

  it("uses an injected public smoke service at the external service boundary", async () => {
    const smokeResult = {
      checks: { hubHealth: "succeeded" },
      failureReasons: [],
      outcome: "succeeded",
    };
    const smokeService = {
      verifyPublicCandidate: vi.fn(async () => smokeResult),
    };
    const remote = createGitHubGhcrPublicationRemote({
      image: "ghcr.io/acme/enoki-hub",
      repository: "acme/enoki",
      runCommand: async () => ({ stdout: "" }),
      smokeService,
    });
    const candidateManifest = {
      candidate: { commit: "a".repeat(40), version: "v1.2.3" },
      hub: { digest: `sha256:${"b".repeat(64)}` },
      probeAssetSet: { files: [] },
    };

    await expect(
      remote.verifyPublicCandidate({ candidateManifest, version: "v1.2.3" }),
    ).resolves.toBe(smokeResult);
    expect(smokeService.verifyPublicCandidate).toHaveBeenCalledOnce();
  });

  it("fails remote commands without exposing command credentials", async () => {
    const secret = "ghp_do_not_leak_this_publication_token";
    const remote = createGitHubGhcrPublicationRemote({
      image: "ghcr.io/acme/enoki-hub",
      repository: "acme/enoki",
      runCommand: async () => {
        const error = new Error(
          `request failed with Authorization: Bearer ${secret}`,
        );
        error.stderr = `server rejected token=${secret}`;
        throw error;
      },
    });

    let failure;
    try {
      await remote.createTag({
        commit: "a".repeat(40),
        version: "v1.2.3",
      });
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    expect(failure.message).toContain("gh command failed");
    expect(JSON.stringify(failure)).not.toContain(secret);
    expect(failure.message).not.toContain(secret);
  });

  it("records injected public-service anomalies without leaking credentials", async () => {
    const fixture = await createPublicationFixture();
    const secret = "github_pat_never_include_in_smoke_evidence";
    try {
      const service = createPublicationSmokeService({
        createId: () => "failed-smoke",
        fetchImpl: async () => {
          throw new Error(`download Authorization: Bearer ${secret}`);
        },
        inspectProbeAssets: async () => {
          throw new Error(`signature token=${secret}`);
        },
        runCommand: async () => {
          throw new Error(`registry password=${secret}`);
        },
        sleep: async () => {},
      });
      const result = await service.verifyPublicCandidate({
        candidateManifest: fixture.candidateManifest,
        getRelease: async () => {
          throw new Error(`GitHub service bearer ${secret}`);
        },
        image: "ghcr.io/acme/enoki-hub",
        version: "v1.2.3",
      });

      expect(result.outcome).toBe("failed");
      expect(result.failureReasons).toHaveLength(5);
      expect(JSON.stringify(result)).not.toContain(secret);
      expect(result.failureReasons.join(" ")).toContain("[redacted]");
    } finally {
      await fixture.cleanup();
    }
  });
});

function seedMatchingTagAndRelease(
  remote,
  fixture,
  { completeAssets = false, draft = true } = {},
) {
  remote.tag = { commit: fixture.candidateManifest.candidate.commit };
  remote.release = {
    assets: completeAssets
      ? Object.fromEntries(
          fixture.candidateManifest.probeAssetSet.files.map((file) => [
            file.file,
            { sha256: file.sha256, size: file.size },
          ]),
        )
      : {},
    draft,
    targetCommit: fixture.candidateManifest.candidate.commit,
  };
}

class FakePublicationRemote {
  events = [];
  images = {};
  release = null;
  tag = null;

  constructor({ failAfter = null, hideEmptyCreatedReleaseReads = 0 } = {}) {
    this.failAfter = failAfter;
    this.hideEmptyCreatedReleaseReads = hideEmptyCreatedReleaseReads;
  }

  async getTag() {
    return this.tag;
  }

  async createTag({ commit }) {
    this.tag = { commit };
    this.#record("tag:create");
  }

  async getRelease() {
    if (
      this.release &&
      Object.keys(this.release.assets).length === 0 &&
      this.hideEmptyCreatedReleaseReads > 0
    ) {
      this.hideEmptyCreatedReleaseReads -= 1;
      return null;
    }
    return this.release;
  }

  async createDraftRelease({ commit }) {
    this.release = { assets: {}, draft: true, targetCommit: commit };
    this.#record("release:create-draft");
    return this.release;
  }

  async uploadAsset({ file, sha256, size }) {
    this.release.assets[file] = { sha256, size };
    this.#record(`asset:upload:${file}`);
  }

  async getImage({ tag }) {
    return this.images[tag] ? { digest: this.images[tag] } : null;
  }

  async publishVersionImage({ digest, version }) {
    this.images[version] = digest;
    this.#record("image:publish-version");
  }

  async makeReleasePublic() {
    this.release.draft = false;
    this.#record("release:make-public");
  }

  async moveLatest({ digest }) {
    this.images.latest = digest;
    this.#record("image:move-latest");
  }

  async verifyPublicCandidate() {
    this.#record("smoke:verify");
    return (
      this.smokeResult ?? {
        checks: { hubHealth: "succeeded" },
        outcome: "succeeded",
      }
    );
  }

  #record(event) {
    this.events.push(event);
    if (this.failAfter === event) {
      throw new Error(`interrupted after ${event}`);
    }
  }
}

async function createPublicationFixture() {
  const workDir = await mkdtemp(path.join(tmpdir(), "enoki-publication-"));
  const candidateDir = path.join(workDir, "candidate");
  const probeAssetDir = path.join(candidateDir, "probe-assets");
  const hubDir = path.join(candidateDir, "hub");
  await Promise.all([
    mkdir(probeAssetDir, { recursive: true }),
    mkdir(hubDir, { recursive: true }),
  ]);
  const files = [];
  for (const [file, content] of [
    ["install-probe.sh", "#!/bin/sh\n"],
    ["manifest.json", '{"version":"1.2.3"}\n'],
    ["manifest.json.sig", "signature"],
    ["signing-key.pem", "public key"],
  ]) {
    const bytes = Buffer.from(content);
    await writeFile(path.join(probeAssetDir, file), bytes);
    files.push({ file, sha256: sha256(bytes), size: bytes.length });
  }
  files.sort((left, right) => left.file.localeCompare(right.file));
  const hubArchive = "hub/enoki-hub-v1.2.3.oci.tar";
  const hubBytes = Buffer.from("immutable OCI archive");
  await writeFile(path.join(candidateDir, hubArchive), hubBytes);
  const candidateManifest = {
    candidate: { commit: "a".repeat(40), version: "v1.2.3" },
    hub: {
      archive: hubArchive,
      archiveSha256: sha256(hubBytes),
      digest: `sha256:${"b".repeat(64)}`,
      embeddedProbeVersion: "1.2.3",
      size: hubBytes.length,
    },
    kind: "enoki-release-candidate",
    probeAssetSet: {
      directory: "probe-assets",
      files,
      signingIdentity: {
        algorithm: "rsa-sha256",
        publicKeyFile: "signing-key.pem",
        publicKeySha256: sha256(Buffer.from("public key")),
      },
      version: "1.2.3",
    },
    releaseBaseline: {
      githubRelease: { id: 122, peeledCommitSha: "c".repeat(40) },
      hub: { imageDigest: `sha256:${"d".repeat(64)}` },
      kind: "enoki-release-baseline",
      probeAssetSet: { version: "1.2.2" },
      tag: "v1.2.2",
    },
    schemaVersion: 2,
  };
  const workflowRun = { attempt: 1, id: "123", url: "https://example/run/123" };
  const verificationSummary = {
    candidate: candidateManifest.candidate,
    freshCandidateRequiredForPublish: true,
    hub: candidateManifest.hub,
    kind: "enoki-release-verification-evidence",
    probeAssetSet: candidateManifest.probeAssetSet,
    promotable: false,
    releaseBaseline: candidateManifest.releaseBaseline,
    run: workflowRun,
    schemaVersion: 3,
    verified: true,
  };
  return {
    candidateDir,
    candidateManifest,
    cleanup: () => rm(workDir, { force: true, recursive: true }),
    verificationSummary,
    workflowRun,
  };
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
