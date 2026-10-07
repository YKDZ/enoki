// Release verification evidence judgments shared by the verification summary and
// the Host verification orchestration. Each judgment validates unknown JSON input
// at the existing business check and uses real types internally.

import {
  isFiniteNumber,
  isNonEmptyString,
  isSafeInteger,
  isUnknownArray,
  isUnknownRecord,
} from "./release-json-guards.ts";

const supportedReleaseTestHostVmTypes = new Set([
  "acrn",
  "amazon",
  "apple",
  "bhyve",
  "bochs",
  "google",
  "kvm",
  "microsoft",
  "oracle",
  "powervm",
  "qemu",
  "qnx",
  "sre",
  "uml",
  "vm-other",
  "vmware",
  "xen",
  "zvm",
]);

export type PortableMetricSample = {
  collectedAtMs: number;
  cpuPercent: number;
  memoryTotalBytes: number;
  memoryUsedBytes: number;
  sequence: number;
  uptimeSeconds: number;
};

function normalizedProbeVersion(value: unknown): string {
  return typeof value === "string" ? value.trim().replace(/^v/, "") : "";
}

export function isSupportedReleaseTestHostVirtualization(
  value: unknown,
): boolean {
  return (
    typeof value === "string" && supportedReleaseTestHostVmTypes.has(value)
  );
}

export function isCandidateHostReady(
  value: unknown,
  expectedProbeVersion: unknown,
): boolean {
  if (!isUnknownRecord(value) || value.status !== "online") return false;
  const profileValue = value.hostProfile;
  if (!isUnknownRecord(profileValue)) return false;
  const architecture = profileValue.architecture;
  const cpuCount = profileValue.cpuCount;
  const hostname = profileValue.hostname;
  const kernel = profileValue.kernel;
  const memoryTotalBytes = profileValue.memoryTotalBytes;
  const os = profileValue.os;
  const probeVersion = profileValue.probeVersion;
  const filesystems = profileValue.filesystems;
  const networkInterfaces = profileValue.networkInterfaces;
  return (
    isNonEmptyString(architecture) &&
    isSafeInteger(cpuCount) &&
    cpuCount >= 1 &&
    cpuCount <= 4_096 &&
    isNonEmptyString(hostname) &&
    isNonEmptyString(kernel) &&
    isSafeInteger(memoryTotalBytes) &&
    memoryTotalBytes >= 1_048_576 &&
    isNonEmptyString(os) &&
    normalizedProbeVersion(probeVersion) ===
      normalizedProbeVersion(expectedProbeVersion) &&
    isUnknownArray(filesystems) &&
    isUnknownArray(networkInterfaces)
  );
}

export function isPortableMetricSample(
  sample: unknown,
): sample is PortableMetricSample {
  if (!isUnknownRecord(sample)) return false;
  const sequence = sample.sequence;
  const collectedAtMs = sample.collectedAtMs;
  const uptimeSeconds = sample.uptimeSeconds;
  const cpuPercent = sample.cpuPercent;
  const memoryTotalBytes = sample.memoryTotalBytes;
  const memoryUsedBytes = sample.memoryUsedBytes;
  return (
    isSafeInteger(sequence) &&
    sequence >= 0 &&
    isSafeInteger(collectedAtMs) &&
    collectedAtMs > 0 &&
    isFiniteNumber(uptimeSeconds) &&
    uptimeSeconds >= 0 &&
    isFiniteNumber(cpuPercent) &&
    cpuPercent >= 0 &&
    cpuPercent <= 100 &&
    isSafeInteger(memoryTotalBytes) &&
    memoryTotalBytes > 0 &&
    isSafeInteger(memoryUsedBytes) &&
    memoryUsedBytes >= 0 &&
    memoryUsedBytes <= memoryTotalBytes
  );
}

export function hasAdvancingPortableMetrics(samples: unknown): boolean {
  if (!isUnknownArray(samples)) return false;
  const ordered = samples
    .filter(isPortableMetricSample)
    .sort((left, right) => left.sequence - right.sequence);
  if (ordered.length < 2) return false;
  const first = ordered[0];
  const last = ordered.at(-1);
  if (!first || !last) return false;
  return (
    isSafeInteger(first.sequence) &&
    isSafeInteger(last.sequence) &&
    last.sequence > first.sequence &&
    isFiniteNumber(first.collectedAtMs) &&
    isFiniteNumber(last.collectedAtMs) &&
    last.collectedAtMs > first.collectedAtMs &&
    isFiniteNumber(first.uptimeSeconds) &&
    isFiniteNumber(last.uptimeSeconds) &&
    last.uptimeSeconds >= first.uptimeSeconds
  );
}
