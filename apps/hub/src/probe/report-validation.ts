import type { HostDetailSample } from "@enoki/api-client/websocket";
import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";

import {
  hostProfileCollectorId,
  hostProfileSnapshotFromReport,
  snapshotPayloadBranchesMatchCollectorIds,
} from "./host-profile-snapshots.js";

export type ProtoMessage = Record<string, any>;

const ReportRequest = enoki.v1.ProbeReportRequest as any;

export { hostProfileCollectorId } from "./host-profile-snapshots.js";

const maxReportObservationRange = 10_000;

export class ReportBusinessRejection extends Error {
  constructor(
    readonly code: string,
    readonly status: 400 | 409,
  ) {
    super(code);
  }
}

export function isProbeStartupReport(input: {
  report: { sequenceEnd: number; sequenceStart: number };
  reportedHostProfile: ProtoMessage | null;
  request: ProtoMessage;
}) {
  return (
    input.report.sequenceStart === 1 &&
    input.report.sequenceEnd === 1 &&
    input.reportedHostProfile !== null &&
    (input.request.metrics ?? []).length === 0
  );
}

function isStartupReportShape(
  report: { sequenceEnd: number; sequenceStart: number },
  request: ProtoMessage,
) {
  return (
    report.sequenceStart === 1 &&
    report.sequenceEnd === 1 &&
    (request.metrics ?? []).length === 0 &&
    !request.observationWindowFailure
  );
}

export function hasProducedHostProfile(request: ProtoMessage) {
  return ((request.metrics ?? []) as ProtoMessage[]).some((sample) =>
    ((sample.collectorOutcomes ?? []) as ProtoMessage[]).some(
      (outcome) =>
        outcome.collectorId === hostProfileCollectorId &&
        Number(outcome.state) === 1 &&
        !outcome.failure,
    ),
  );
}

export function nonemptyString(value: unknown) {
  return typeof value === "string" && value.trim() ? value : null;
}

export function liveDetailSampleFromMetricSample(
  hostId: number,
  sample: ProtoMessage,
  receivedAtMs: number,
): HostDetailSample {
  return {
    collectedAtMs: signedNumber(sample.collectedAtMs),
    cpuCores: ((sample.cpuCores ?? []) as ProtoMessage[]).map((core) => ({
      name: core.name ?? "",
      usagePercent: core.usagePercent ?? 0,
    })),
    batteryPercent: metricUnsignedField(sample, "batteryPercent"),
    batteryState: hasMetricField(sample, "batteryState")
      ? sample.batteryState || null
      : null,
    cpuIdlePercent: metricField(sample, "cpuIdlePercent"),
    cpuIowaitPercent: metricField(sample, "cpuIowaitPercent"),
    cpuPercent: metricField(sample, "cpuPercent"),
    cpuStealPercent: metricField(sample, "cpuStealPercent"),
    cpuSystemPercent: metricField(sample, "cpuSystemPercent"),
    cpuUserPercent: metricField(sample, "cpuUserPercent"),
    disks: ((sample.disks ?? []) as ProtoMessage[]).map((disk) => ({
      availableBytes: unsignedNumber(disk.availableBytes),
      filesystemType: disk.filesystemType ?? "",
      ioUtilizationPercent: metricField(disk, "ioUtilizationPercent"),
      mountPoint: disk.mountPoint ?? "",
      readAwaitMs: metricField(disk, "readAwaitMs"),
      readBytesDelta: unsignedNumber(disk.readBytesDelta),
      totalBytes: unsignedNumber(disk.totalBytes),
      usedBytes: unsignedNumber(disk.usedBytes),
      weightedIoPercent: metricField(disk, "weightedIoPercent"),
      writeAwaitMs: metricField(disk, "writeAwaitMs"),
      writeBytesDelta: unsignedNumber(disk.writeBytesDelta),
    })),
    ...(((sample.diskHealth ?? []) as ProtoMessage[]).length
      ? {
          diskHealth: ((sample.diskHealth ?? []) as ProtoMessage[]).map(
            (disk) => ({
              deviceName: disk.deviceName ?? "",
              model: disk.model || null,
              passed: Boolean(disk.passed),
              powerOnHours: unsignedMetricField(disk, "powerOnHours"),
              role: disk.role || null,
              serialNumber: disk.serialNumber || null,
              temperatureCelsius: metricField(disk, "temperatureCelsius"),
              totalBytes: unsignedMetricField(disk, "totalBytes"),
              usageMountPoint: disk.usageMountPoint || null,
              usedBytes: unsignedMetricField(disk, "usedBytes"),
            }),
          ),
        }
      : {}),
    hostId,
    memoryCacheBytes: metricUnsignedField(sample, "memoryCacheBytes"),
    memoryTotalBytes: metricUnsignedField(sample, "memoryTotalBytes"),
    memoryUsedBytes: metricUnsignedField(sample, "memoryUsedBytes"),
    networkInterfaces: ((sample.networkInterfaces ?? []) as ProtoMessage[]).map(
      (networkInterface) => ({
        name: networkInterface.name ?? "",
        rxBytesDelta: unsignedNumber(networkInterface.rxBytesDelta),
        txBytesDelta: unsignedNumber(networkInterface.txBytesDelta),
      }),
    ),
    receivedAtMs,
    sequence: unsignedNumber(sample.sequence),
    swapTotalBytes: metricUnsignedField(sample, "swapTotalBytes"),
    swapUsedBytes: metricUnsignedField(sample, "swapUsedBytes"),
    temperatureCelsius: metricField(sample, "temperatureCelsius"),
    uptimeSeconds: metricUnsignedField(sample, "uptimeSeconds"),
  };
}

export function decodeReportRequest(body: Uint8Array): ProtoMessage | null {
  try {
    return ReportRequest.decode(body) as ProtoMessage;
  } catch {
    return null;
  }
}

export function admitProbeReport(request: ProtoMessage) {
  const validatedReport = validateReportEnvelope(request);
  if (
    !validatedReport ||
    !snapshotPayloadBranchesMatchCollectorIds(request) ||
    !hostProfileOutcomeWindowIsCoherent(request)
  ) {
    return null;
  }

  const hostProfileSnapshot = hostProfileSnapshotFromReport(request);
  if (
    hostProfileSnapshot?.hostProfile &&
    hostProfileSnapshot.snapshotHash &&
    hostProfileSnapshot.snapshotHash !== hostProfileSnapshot.canonicalHash
  ) {
    return null;
  }

  const reportResponsibility = reportResponsibilityFor({
    hostProfileSnapshot,
    report: validatedReport,
    request,
  });
  return reportResponsibility
    ? { hostProfileSnapshot, reportResponsibility, validatedReport }
    : null;
}

export function validateReportEnvelope(request: ProtoMessage) {
  const sequenceStart = unsignedNumber(request.sequenceStart);
  const sequenceEnd = unsignedNumber(request.sequenceEnd);

  if (
    !request.bootId ||
    sequenceStart < 1 ||
    sequenceEnd < sequenceStart ||
    sequenceEnd - sequenceStart + 1 > maxReportObservationRange
  ) {
    return null;
  }

  const samples = request.metrics ?? [];
  const observationWindowFailureReason = observationWindowFailureReasonFor(
    request.observationWindowFailure,
  );
  const cpuResourceCollectionOutcomeReasons = new Map<number, number>();
  const cpuResourceCollectionOutcomes =
    (request.cpuResourceCollectionOutcomes as ProtoMessage[] | undefined) ?? [];
  const sequenceCount = sequenceEnd - sequenceStart + 1;

  if (
    request.observationWindowFailure != null &&
    observationWindowFailureReason === null
  ) {
    return null;
  }
  if (
    observationWindowFailureReason !== null &&
    cpuResourceCollectionOutcomes.length > 0
  ) {
    return null;
  }

  if (observationWindowFailureReason !== null && samples.length !== 0) {
    return null;
  }

  if (
    samples.length === 0 &&
    sequenceCount !== 1 &&
    observationWindowFailureReason === null &&
    cpuResourceCollectionOutcomes.length === 0
  ) {
    return null;
  }

  if (samples.length > 0 && samples.length !== sequenceCount) {
    return null;
  }

  const sampleSequences = new Set<number>();

  for (const outcome of cpuResourceCollectionOutcomes) {
    const sequence = unsignedNumber(outcome.sequence);
    const reason = cpuResourceCollectionOutcomeReasonFor(outcome);
    if (
      sequence < sequenceStart ||
      sequence > sequenceEnd ||
      reason === null ||
      cpuResourceCollectionOutcomeReasons.has(sequence)
    ) {
      return null;
    }
    cpuResourceCollectionOutcomeReasons.set(sequence, reason);
  }
  if (
    samples.length === 0 &&
    observationWindowFailureReason === null &&
    cpuResourceCollectionOutcomes.length > 0 &&
    cpuResourceCollectionOutcomeReasons.size !== sequenceCount
  ) {
    return null;
  }

  for (const sample of samples) {
    const sequence = unsignedNumber(sample.sequence);
    const collectedAtMs = signedNumber(sample.collectedAtMs);

    if (
      sequence < sequenceStart ||
      sequence > sequenceEnd ||
      collectedAtMs < 1 ||
      (hasMetricField(sample, "cpuPercent") &&
        !Number.isFinite(sample.cpuPercent))
    ) {
      return null;
    }

    if (sampleSequences.has(sequence)) {
      return null;
    }

    sampleSequences.add(sequence);
  }

  for (
    let sequence = sequenceStart;
    samples.length > 0 && sequence <= sequenceEnd;
    sequence += 1
  ) {
    if (!sampleSequences.has(sequence)) {
      return null;
    }
  }

  return {
    cpuResourceCollectionOutcomeReasons,
    observationWindowFailureReason,
    sequenceEnd,
    sequenceStart,
  };
}

function cpuResourceCollectionOutcomeReasonFor(
  outcome: unknown,
): number | null {
  if (!outcome || typeof outcome !== "object") {
    return null;
  }
  const reason = unsignedNumber((outcome as ProtoMessage).reason);
  return reason >= 1 && reason <= 3 ? reason : null;
}

function observationWindowFailureReasonFor(failure: unknown): number | null {
  if (!failure || typeof failure !== "object") {
    return null;
  }

  const reason = unsignedNumber((failure as ProtoMessage).reason);
  return reason >= 1 && reason <= 3 ? reason : null;
}

export function reportResponsibilityFor(input: {
  hostProfileSnapshot: ReturnType<typeof hostProfileSnapshotFromReport>;
  report: { sequenceEnd: number; sequenceStart: number };
  request: ProtoMessage;
}):
  | "full_host_profile"
  | "legacy_observation"
  | "observation"
  | "startup"
  | null {
  const snapshots = (input.request.snapshots ?? []) as ProtoMessage[];
  const snapshot = input.hostProfileSnapshot;
  const isCurrentBootReport =
    input.report.sequenceStart === 1 &&
    input.report.sequenceEnd === 1 &&
    nonemptyString(input.request.probeAssetBundleVersion);

  // Current Probe Boot Reports only establish the reporting channel. Any
  // observation-shaped content belongs to a subsequent Observation Batch; do
  // not let a sequence-one report reach report reconciliation with it.
  if (
    isCurrentBootReport &&
    ((input.request.metrics ?? []).length > 0 ||
      snapshots.length > 0 ||
      (input.request.cpuResourceCollectionOutcomes ?? []).length > 0 ||
      input.request.observationWindowFailure != null)
  ) {
    return null;
  }

  // 旧版 Probe 早于紧凑 snapshot reference。保留其普通 Observation Batch
  // 兼容性，包括从未作为 Probe Startup Report 的旧版 sequence-one metrics
  // batch；当前 Probe 则必须使用下方的 typed constructor shape。
  if (snapshots.length === 0) {
    return isStartupReportShape(input.report, input.request) &&
      nonemptyString(input.request.probeAssetBundleVersion)
      ? "startup"
      : "legacy_observation";
  }

  if (
    snapshots.length !== 1 ||
    !snapshot ||
    snapshots[0]?.collectorId !== hostProfileCollectorId
  ) {
    return null;
  }

  if (snapshot.hostProfile === null && !snapshot.snapshotHash) {
    return null;
  }

  const isStartup =
    input.report.sequenceStart === 1 && input.report.sequenceEnd === 1;
  if (isStartup) {
    return snapshot.hostProfile !== null &&
      (input.request.metrics ?? []).length === 0 &&
      typeof input.request.probeConfigurationVersion === "string" &&
      input.request.probeConfigurationVersion.length > 0 &&
      !input.request.probeConfigurationError &&
      !input.request.observationWindowFailure
      ? "startup"
      : null;
  }

  if (snapshot.hostProfile !== null) {
    if (hasProducedHostProfile(input.request)) {
      return "observation";
    }
    return hasSnapshotReplayOnlyContents(input.request)
      ? "full_host_profile"
      : null;
  }

  return "observation";
}

export function hasSnapshotReplayOnlyContents(request: ProtoMessage) {
  return (
    (request.metrics ?? []).length === 0 &&
    !request.observationWindowFailure &&
    !request.probeConfigurationError &&
    (request.operationAcknowledgements ?? []).length === 0 &&
    (request.operationStatuses ?? []).length === 0
  );
}

export function detectClockSkew(
  samples: ProtoMessage[],
  receivedAtMs: number,
  thresholdMs: number,
) {
  const deltas = samples.map((sample) =>
    Math.abs(receivedAtMs - signedNumber(sample.collectedAtMs)),
  );
  const lastDeltaMs = deltas.length > 0 ? Math.max(...deltas) : null;

  return {
    detected: lastDeltaMs !== null && lastDeltaMs >= thresholdMs,
    lastDeltaMs,
  };
}

function firstHostProfileAddress(hostProfile: ProtoMessage | null | undefined) {
  for (const networkInterface of (hostProfile?.networkInterfaces ??
    []) as ProtoMessage[]) {
    const address = (networkInterface.addresses as string[] | undefined)?.find(
      (candidate: string) => candidate.trim() !== "",
    );

    if (address) {
      return address;
    }
  }

  return null;
}

const officialOutcomeCollectors = new Set([
  "official.cpu",
  "official.load",
  "official.memory",
  "official.uptime",
  "official.network",
  "official.disk",
  "official.temperature",
  "official.battery",
  "official.disk-health",
  "official.host-profile",
]);

export function validatedCollectorOutcomes(sample: ProtoMessage) {
  const seen = new Set<string>();
  return ((sample.collectorOutcomes ?? []) as ProtoMessage[]).map((outcome) => {
    const collectorId = outcome.collectorId ?? "";
    const state = Number(outcome.state ?? 0);
    const failure = outcome.failure as ProtoMessage | null | undefined;
    const failurePhase = failure ? Number(failure.phase ?? 0) : null;
    const encodedFailureCode = failure ? String(failure.code ?? "") : null;
    const legacyFailureCode = failure ? Number(failure.legacyCode ?? 0) : 0;
    const normalizedLegacyFailureCode = legacyCollectorFailureCode(
      collectorId,
      failurePhase,
      legacyFailureCode,
    );
    const failureCode = encodedFailureCode
      ? encodedFailureCode
      : normalizedLegacyFailureCode;
    if (
      !officialOutcomeCollectors.has(collectorId) ||
      seen.has(collectorId) ||
      ![1, 2, 3].includes(state) ||
      (state === 3
        ? ![1, 2].includes(failurePhase ?? 0) ||
          !validCollectorFailureCode(failureCode) ||
          !failureCode?.startsWith(`${collectorId}.`) ||
          (legacyFailureCode !== 0 &&
            normalizedLegacyFailureCode !== failureCode)
        : failure !== null && failure !== undefined)
    ) {
      throw new ReportBusinessRejection("malformed_probe_report", 400);
    }
    seen.add(collectorId);
    return {
      collectorId,
      failureCode,
      failurePhase: failurePhase as 1 | 2 | null,
      state: state as 1 | 2 | 3,
    };
  });
}

function legacyCollectorFailureCode(
  collectorId: string,
  phase: number | null,
  code: number,
): string | null {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10].includes(code)) return null;
  if (code === 1) return `${collectorId}.resource-unavailable`;
  if (code === 2) return `${collectorId}.resource-malformed`;
  if (code === 3) return `${collectorId}.activation-budget-exhausted`;
  if (code === 4 && collectorId === "official.cpu")
    return "official.cpu.counters-malformed";
  if (code === 5 && collectorId === "official.load")
    return "official.load.facts-malformed";
  if (code === 6 && collectorId === "official.memory")
    return "official.memory.facts-malformed";
  if (code === 7 && collectorId === "official.uptime")
    return "official.uptime.facts-malformed";
  if (code === 8 && collectorId === "official.host-profile") {
    return phase === 1
      ? "official.host-profile.resource-malformed"
      : "official.host-profile.facts-malformed";
  }
  if (code === 9 && collectorId === "official.host-profile")
    return "official.host-profile.resource-unavailable";
  if (code === 10 && collectorId === "official.host-profile")
    return "official.host-profile.activation-budget-exhausted";
  return null;
}

function validCollectorFailureCode(code: string | null): code is string {
  return (
    code !== null &&
    code.length >= 3 &&
    code.length <= 96 &&
    /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/.test(code)
  );
}

export function hostProfileOutcomeWindowIsCoherent(request: ProtoMessage) {
  const samples = (request.metrics ?? []) as ProtoMessage[];
  const snapshots = ((request.snapshots ?? []) as ProtoMessage[]).filter(
    (snapshot) => snapshot.collectorId === hostProfileCollectorId,
  );
  let outcome: ProtoMessage | undefined;
  for (const [index, sample] of samples.entries()) {
    const matches = ((sample.collectorOutcomes ?? []) as ProtoMessage[]).filter(
      (candidate) => candidate.collectorId === hostProfileCollectorId,
    );
    if (matches.length > 1 || (matches.length === 1 && index !== 0))
      return false;
    outcome ??= matches[0];
  }
  if (!outcome) return true;
  if (Number(outcome.state) === 1 && !outcome.failure) {
    return (
      snapshots.length === 1 &&
      Boolean(snapshots[0]?.snapshotHash) &&
      (!snapshots[0]?.hostProfile ||
        Boolean(
          nonemptyString(snapshots[0]?.hostProfile?.probeAssetBundleVersion),
        ))
    );
  }
  return snapshots.length === 0 && [2, 3].includes(Number(outcome.state));
}

export function reportConnectAddress(
  hostProfile: ProtoMessage | null | undefined,
  host: {
    connectAddress: string;
    observedIp: string | null;
  },
  observedIp: string | null,
) {
  const hostProfileAddress = firstHostProfileAddress(hostProfile);
  if (hostProfileAddress) {
    return hostProfileAddress;
  }

  if (!host.connectAddress || host.connectAddress === host.observedIp) {
    return observedIp;
  }

  return undefined;
}

export function unsignedNumber(
  value: number | { toNumber: () => number } | null | undefined,
) {
  if (value === null || value === undefined) {
    return 0;
  }

  return typeof value === "number" ? value : value.toNumber();
}

export function signedNumber(
  value: number | { toNumber: () => number } | null | undefined,
) {
  return unsignedNumber(value);
}

export function metricField(
  sample: object,
  field:
    | "cpuPercent"
    | "cpuUserPercent"
    | "cpuSystemPercent"
    | "cpuIowaitPercent"
    | "cpuStealPercent"
    | "cpuIdlePercent"
    | "ioUtilizationPercent"
    | "load_1"
    | "load_5"
    | "load_15"
    | "readAwaitMs"
    | "temperatureCelsius"
    | "weightedIoPercent"
    | "writeAwaitMs",
) {
  const value = (sample as Record<string, unknown>)[field];

  return hasMetricField(sample, field) && typeof value === "number"
    ? value
    : null;
}

export function metricUnsignedField(
  sample: object,
  field:
    | "batteryPercent"
    | "memoryCacheBytes"
    | "memoryTotalBytes"
    | "memoryUsedBytes"
    | "swapTotalBytes"
    | "swapUsedBytes"
    | "uptimeSeconds",
) {
  return hasMetricField(sample, field)
    ? unsignedNumber(
        (sample as Record<string, unknown>)[field] as
          | number
          | { toNumber: () => number }
          | null
          | undefined,
      )
    : null;
}

export function unsignedMetricField(sample: object, field: string) {
  return hasMetricField(sample, field)
    ? unsignedNumber(
        (sample as Record<string, unknown>)[field] as
          | number
          | { toNumber: () => number }
          | null
          | undefined,
      )
    : null;
}

export function hasMetricField(sample: object, field: string) {
  return Object.prototype.hasOwnProperty.call(sample, field);
}

export function sumUnsigned<T>(
  values: T[],
  select: (value: T) => number | { toNumber: () => number } | null | undefined,
) {
  return values.reduce((sum, value) => sum + unsignedNumber(select(value)), 0);
}
