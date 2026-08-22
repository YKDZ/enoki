import { createHash } from "node:crypto";
import { chmod, mkdtemp, open, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

export async function reconcilePublication({
  candidateDir,
  candidateManifest,
  remote,
  verificationSummary,
  workflowRun,
}) {
  assertPublishAuthorization({
    candidateManifest,
    verificationSummary,
    workflowRun,
  });
  await verifyCandidatePublicationBytes(candidateDir, candidateManifest);

  const { commit, version } = candidateManifest.candidate;
  const actions = [];
  let [tag, release, versionedImage] = await Promise.all([
    remote.getTag({ version }),
    remote.getRelease({ version }),
    remote.getImage({ tag: version }),
  ]);
  assertExistingPublicationState({
    candidateManifest,
    release,
    tag,
    versionedImage,
  });

  if (!tag) {
    await remote.createTag({ commit, version });
    actions.push({ action: "created", stage: "immutable-version-tag" });
    tag = await remote.getTag({ version });
  } else if (tag.commit !== commit) {
    throw new Error(
      `immutable tag ${version} resolves to ${tag.commit}, expected ${commit}`,
    );
  } else {
    actions.push({
      action: "skipped-identical",
      stage: "immutable-version-tag",
    });
  }
  if (tag?.commit !== commit) {
    throw new Error(`immutable tag ${version} was not created at ${commit}`);
  }

  if (!release) {
    release = await remote.createDraftRelease({ commit, version });
    actions.push({ action: "created", stage: "private-release-draft" });
    release ??= await remote.getRelease({ version });
  } else {
    actions.push({
      action: "skipped-existing",
      stage: "private-release-draft",
    });
  }
  if (!release) {
    throw new Error(`draft Release ${version} was not visible after creation`);
  }
  if (release.targetCommit !== commit) {
    throw new Error(
      `Release ${version} targets ${release.targetCommit}, expected ${commit}`,
    );
  }

  assertNoUnexpectedAssets(release, candidateManifest);

  for (const expected of publicReleaseAssets(candidateManifest)) {
    const existing = release.assets[expected.file];
    if (!existing) {
      if (!release.draft) {
        throw new Error(
          `public Release ${version} is missing immutable asset ${expected.file}`,
        );
      }
      await uploadReleaseAsset({
        candidateDir,
        candidateManifest,
        expected,
        remote,
        version,
      });
      actions.push({
        action: "uploaded",
        file: expected.file,
        sha256: expected.sha256,
        stage: "probe-release-asset",
      });
    } else if (
      existing.sha256 !== expected.sha256 ||
      existing.size !== expected.size
    ) {
      throw new Error(
        `immutable Release asset ${expected.file} does not match the candidate`,
      );
    } else {
      actions.push({
        action: "skipped-identical",
        file: expected.file,
        sha256: expected.sha256,
        stage: "probe-release-asset",
      });
    }
  }
  release = await remote.getRelease({ version });
  assertExactReleaseAssets(release, candidateManifest, version);

  if (!versionedImage) {
    await remote.publishVersionImage({
      archivePath: path.join(candidateDir, candidateManifest.hub.archive),
      digest: candidateManifest.hub.digest,
      version,
    });
    actions.push({ action: "published", stage: "versioned-hub-image" });
    versionedImage = await remote.getImage({ tag: version });
  } else if (versionedImage.digest !== candidateManifest.hub.digest) {
    throw new Error(
      `immutable Hub image ${version} has digest ${versionedImage.digest}, expected ${candidateManifest.hub.digest}`,
    );
  } else {
    actions.push({ action: "skipped-identical", stage: "versioned-hub-image" });
  }
  if (versionedImage?.digest !== candidateManifest.hub.digest) {
    throw new Error(
      `versioned Hub image ${version} did not retain the candidate digest`,
    );
  }

  release = await remote.getRelease({ version });
  assertExactReleaseAssets(release, candidateManifest, version);
  if (release.draft) {
    await remote.makeReleasePublic({ version });
    actions.push({ action: "published", stage: "github-release" });
    release = await remote.getRelease({ version });
  } else {
    actions.push({ action: "skipped-public", stage: "github-release" });
  }
  if (!release || release.draft) {
    throw new Error(`GitHub Release ${version} did not become public`);
  }

  let latest = await remote.getImage({ tag: "latest" });
  if (latest?.digest !== candidateManifest.hub.digest) {
    await remote.moveLatest({ digest: candidateManifest.hub.digest, version });
    actions.push({ action: "moved", stage: "latest-hub-image" });
    latest = await remote.getImage({ tag: "latest" });
  } else {
    actions.push({ action: "skipped-identical", stage: "latest-hub-image" });
  }
  if (latest?.digest !== candidateManifest.hub.digest) {
    throw new Error("latest Hub image did not move to the verified candidate");
  }

  const smoke = await remote.verifyPublicCandidate({
    candidateDir,
    candidateManifest,
    version,
  });
  return {
    actions,
    candidate: candidateManifest.candidate,
    gates: verificationSummary.gates,
    hub: {
      candidateDigest: candidateManifest.hub.digest,
      publishedDigest: candidateManifest.hub.digest,
    },
    kind: "enoki-release-publication-summary",
    publication: {
      githubRelease: {
        id: release.id ?? null,
        url: release.url ?? null,
      },
      latestImage: { digest: latest.digest, reference: "latest" },
      tag: { commit: tag.commit, name: version },
      versionedImage: { digest: versionedImage.digest, reference: version },
    },
    probeAssetSet: candidateManifest.probeAssetSet,
    bootstrapRecipe: candidateManifest.bootstrapRecipe,
    releaseBaseline: verificationSummary.releaseBaseline ?? null,
    schemaVersion: 1,
    smoke,
    status: smoke.outcome === "succeeded" ? "published" : "broken",
    verificationRun: verificationSummary.run,
    workflowRun,
  };
}

async function uploadReleaseAsset({
  candidateDir,
  candidateManifest,
  expected,
  remote,
  version,
}) {
  const sourcePath = path.join(candidateDir, expected.directory, expected.file);
  if (!expected.file.endsWith(".tar.gz")) {
    await remote.uploadAsset({ ...expected, filePath: sourcePath, version });
    return;
  }
  await withExactArchiveSnapshot(sourcePath, expected, (filePath) =>
    remote.uploadAsset({ ...expected, filePath, version }),
  );
}

async function withExactArchiveSnapshot(sourcePath, expected, callback) {
  const temporaryDirectory = await mkdtemp(
    path.join(tmpdir(), "enoki-release-asset-"),
  );
  const snapshotPath = path.join(temporaryDirectory, expected.file);
  let source;
  let snapshot;
  try {
    await chmod(temporaryDirectory, 0o700);
    source = await open(sourcePath, "r");
    const details = await source.stat();
    if (!details.isFile() || details.size !== expected.size) {
      throw new Error(`candidate Probe asset does not match ${expected.file}`);
    }
    snapshot = await open(snapshotPath, "wx", 0o600);
    const digest = createHash("sha256");
    const buffer = Buffer.alloc(64 * 1024);
    let total = 0;
    while (total < expected.size) {
      const { bytesRead } = await source.read(
        buffer,
        0,
        Math.min(buffer.length, expected.size - total),
        total,
      );
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
      let written = 0;
      while (written < bytesRead) {
        const result = await snapshot.write(
          buffer,
          written,
          bytesRead - written,
          total + written,
        );
        if (result.bytesWritten === 0) {
          throw new Error(
            `candidate Probe asset does not match ${expected.file}`,
          );
        }
        written += result.bytesWritten;
      }
      total += bytesRead;
    }
    if (total !== expected.size || digest.digest("hex") !== expected.sha256) {
      throw new Error(`candidate Probe asset does not match ${expected.file}`);
    }
    await snapshot.sync();
    await snapshot.close();
    snapshot = undefined;
    return await callback(snapshotPath);
  } finally {
    await snapshot?.close().catch(() => undefined);
    await source?.close().catch(() => undefined);
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
}

function assertExistingPublicationState({
  candidateManifest,
  release,
  tag,
  versionedImage,
}) {
  const { commit, version } = candidateManifest.candidate;
  if (tag && tag.commit !== commit) {
    throw new Error(
      `immutable tag ${version} resolves to ${tag.commit}, expected ${commit}`,
    );
  }
  if (release?.targetCommit !== undefined && release.targetCommit !== commit) {
    throw new Error(
      `Release ${version} targets ${release.targetCommit}, expected ${commit}`,
    );
  }
  assertNoUnexpectedAssets(release, candidateManifest);
  for (const expected of publicReleaseAssets(candidateManifest)) {
    const actual = release?.assets?.[expected.file];
    if (
      actual &&
      (actual.sha256 !== expected.sha256 || actual.size !== expected.size)
    ) {
      throw new Error(
        `immutable Release asset ${expected.file} does not match the candidate`,
      );
    }
  }
  if (
    versionedImage &&
    versionedImage.digest !== candidateManifest.hub.digest
  ) {
    throw new Error(
      `immutable Hub image ${version} has digest ${versionedImage.digest}, expected ${candidateManifest.hub.digest}`,
    );
  }

  if (release && !release.draft) {
    if (!tag) {
      throw new Error(
        `public Release ${version} is terminally inconsistent: immutable version tag is missing`,
      );
    }
    try {
      assertExactReleaseAssets(release, candidateManifest, version);
    } catch (error) {
      throw new Error(
        `public Release ${version} is terminally inconsistent: immutable Probe Asset Set is incomplete or mismatched (${error.message})`,
      );
    }
    if (!versionedImage) {
      throw new Error(
        `public Release ${version} is terminally inconsistent: immutable versioned Hub image is missing`,
      );
    }
  }
}

function assertNoUnexpectedAssets(release, candidateManifest) {
  const expectedAssetNames = new Set(
    publicReleaseAssets(candidateManifest).map(({ file }) => file),
  );
  for (const file of Object.keys(release?.assets ?? {})) {
    if (!expectedAssetNames.has(file)) {
      throw new Error(`unexpected immutable Release asset ${file}`);
    }
  }
}

function assertExactReleaseAssets(release, candidateManifest, version) {
  if (!release) throw new Error(`GitHub Release ${version} disappeared`);
  assertNoUnexpectedAssets(release, candidateManifest);
  for (const expected of publicReleaseAssets(candidateManifest)) {
    const actual = release.assets[expected.file];
    if (actual?.sha256 !== expected.sha256 || actual?.size !== expected.size) {
      throw new Error(
        `immutable Release asset ${expected.file} does not match the candidate`,
      );
    }
  }
}

function assertPublishAuthorization({
  candidateManifest,
  verificationSummary,
  workflowRun,
}) {
  const candidate = candidateManifest?.candidate;
  if (
    candidateManifest?.kind !== "enoki-release-candidate" ||
    candidateManifest?.schemaVersion !== 4 ||
    verificationSummary?.kind !== "enoki-release-verification-evidence" ||
    verificationSummary?.schemaVersion !== 3 ||
    verificationSummary.verified !== true ||
    verificationSummary.promotable !== false ||
    verificationSummary.freshCandidateRequiredForPublish !== true ||
    !sameCandidate(verificationSummary.candidate, candidate) ||
    verificationSummary.hub?.digest !== candidateManifest.hub?.digest ||
    !sameJson(
      verificationSummary.probeAssetSet,
      candidateManifest.probeAssetSet,
    ) ||
    !sameJson(
      verificationSummary.bootstrapRecipe,
      candidateManifest.bootstrapRecipe,
    ) ||
    !sameJson(
      verificationSummary.releaseBaseline,
      candidateManifest.releaseBaseline,
    ) ||
    verificationSummary.run?.id !== workflowRun?.id ||
    !Number.isSafeInteger(verificationSummary.run?.attempt) ||
    !Number.isSafeInteger(workflowRun?.attempt) ||
    verificationSummary.run.attempt > workflowRun.attempt
  ) {
    throw new Error(
      "publication requires this workflow attempt's freshly verified publish candidate",
    );
  }
}

async function verifyCandidatePublicationBytes(candidateDir, manifest) {
  for (const expected of publicReleaseAssets(manifest)) {
    const filePath = path.join(candidateDir, expected.directory, expected.file);
    const details = await stat(filePath);
    if (
      details.size !== expected.size ||
      (await fileSha256(filePath)) !== expected.sha256
    ) {
      throw new Error(`candidate Probe asset does not match ${expected.file}`);
    }
  }
  const hubPath = path.join(candidateDir, manifest.hub.archive);
  const details = await stat(hubPath);
  if (
    details.size !== manifest.hub.size ||
    (await fileSha256(hubPath)) !== manifest.hub.archiveSha256
  ) {
    throw new Error("candidate Hub OCI archive does not match its manifest");
  }
}

function publicReleaseAssets(manifest) {
  const group = manifest.probeAssetSet;
  const files = (group?.files ?? []).map((file) => ({
    ...file,
    directory: group.directory,
  }));
  if (!group || new Set(files.map(({ file }) => file)).size !== files.length) {
    throw new Error("Candidate public Release assets are malformed");
  }
  const recipe = manifest.bootstrapRecipe;
  if (
    recipe?.file !== "enoki-probe-bootstrap.py" ||
    !/^[0-9a-f]{64}$/.test(recipe.sha256 ?? "") ||
    !Number.isSafeInteger(recipe.size) ||
    recipe.size < 1
  ) {
    throw new Error("Candidate public Bootstrap recipe is malformed");
  }
  return [...files, { ...recipe, directory: "recipe" }];
}

async function fileSha256(file) {
  return createHash("sha256")
    .update(await readFile(file))
    .digest("hex");
}

function sameCandidate(left, right) {
  return left?.commit === right?.commit && left?.version === right?.version;
}

function sameJson(left, right) {
  return (
    JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right))
  );
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, canonicalize(child)]),
    );
  }
  return value;
}
