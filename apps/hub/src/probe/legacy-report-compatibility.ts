type ProbeVersion = readonly [major: number, minor: number, patch: number];

type LegacyReportWireCapability = {
  version: ProbeVersion;
  permitsFullHostProfileObservation: boolean;
};

// This is a compatibility registry, not a version range. Each entry records a
// published Probe wire contract that the Hub intentionally continues to read.
// New Probe versions retain the compact Host Profile Observation contract.
const publishedLegacyReportWireCapabilities: readonly LegacyReportWireCapability[] =
  [
    {
      permitsFullHostProfileObservation: true,
      version: [0, 1, 72],
    },
  ];

export function permitsLegacyFullHostProfileObservation(input: {
  reportedProbeVersion: string | null | undefined;
  storedProbeVersion: string | null | undefined;
}) {
  const storedVersion = parseProbeVersion(input.storedProbeVersion);
  const reportedVersion = parseProbeVersion(input.reportedProbeVersion);

  if (
    !storedVersion ||
    !reportedVersion ||
    !sameVersion(storedVersion, reportedVersion)
  ) {
    return false;
  }

  return publishedLegacyReportWireCapabilities.some(
    (capability) =>
      capability.permitsFullHostProfileObservation &&
      sameVersion(capability.version, storedVersion),
  );
}

function parseProbeVersion(
  value: string | null | undefined,
): ProbeVersion | null {
  const match = value
    ?.trim()
    .match(/^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);

  if (!match) {
    return null;
  }

  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function sameVersion(left: ProbeVersion, right: ProbeVersion) {
  return left[0] === right[0] && left[1] === right[1] && left[2] === right[2];
}
