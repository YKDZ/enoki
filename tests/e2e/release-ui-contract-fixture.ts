export const sourceReleaseUiCandidateVersion = "0.2.0";

export function releaseUiLifecycleVersions(
  environment: Readonly<{
    ENOKI_RELEASE_UI_CANDIDATE_VERSION?: string;
  }> = process.env,
) {
  const candidateVersion =
    environment.ENOKI_RELEASE_UI_CANDIDATE_VERSION ??
    sourceReleaseUiCandidateVersion;
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(
    candidateVersion,
  );
  if (!match) {
    throw new Error(
      "ENOKI_RELEASE_UI_CANDIDATE_VERSION must be a stable SemVer without a v prefix",
    );
  }
  const versionParts: [number, number, number] = [
    Number(match[1]),
    Number(match[2]),
    Number(match[3]),
  ];
  const currentProbeVersion = previousStableVersion(versionParts);

  return {
    candidateVersion,
    currentProbeVersion,
    targetProbeVersion: candidateVersion,
  };
}

function previousStableVersion([major, minor, patch]: [
  number,
  number,
  number,
]) {
  if (patch > 0) return `${major}.${minor}.${patch - 1}`;
  if (minor > 0) return `${major}.${minor - 1}.0`;
  if (major > 0) return `${major - 1}.0.0`;
  throw new Error(
    "ENOKI_RELEASE_UI_CANDIDATE_VERSION must be newer than 0.0.0",
  );
}
