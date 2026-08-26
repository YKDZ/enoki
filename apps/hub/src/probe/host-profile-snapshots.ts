import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";

const HostProfileSnapshotMessage = enoki.v1.HostProfileSnapshot as any;

export const hostProfileCollectorId = "official.host-profile";

type ProtoMessage = Record<string, any>;

/**
 * Owns canonical Host Profile snapshot identity across registration and
 * reports, so both delivery paths persist and compare the same payload.
 */
export function hostProfileSnapshotFromRegistration(request: ProtoMessage) {
  const snapshot = ((request.snapshots ?? []) as ProtoMessage[]).find(
    (snapshot) =>
      snapshot.collectorId === hostProfileCollectorId && snapshot.hostProfile,
  );

  if (!snapshot?.hostProfile) {
    return null;
  }

  const snapshotHash =
    typeof snapshot.snapshotHash === "string" && snapshot.snapshotHash.trim()
      ? snapshot.snapshotHash
      : null;

  return {
    canonicalHash: hashHostProfile(snapshot.hostProfile),
    hostProfile: snapshot.hostProfile,
    snapshotHash,
  };
}

export function hostProfileSnapshotFromReport(request: ProtoMessage) {
  const snapshot = ((request.snapshots ?? []) as ProtoMessage[]).find(
    (snapshot) => snapshot.collectorId === hostProfileCollectorId,
  );

  if (!snapshot) {
    return null;
  }

  const snapshotHash =
    typeof snapshot.snapshotHash === "string" && snapshot.snapshotHash.trim()
      ? snapshot.snapshotHash
      : null;
  const hostProfile = snapshot.hostProfile ?? null;

  return {
    canonicalHash: hostProfile ? hashHostProfile(hostProfile) : null,
    hostProfile,
    snapshotHash,
  };
}

export function snapshotPayloadBranchesMatchCollectorIds(
  request: ProtoMessage,
) {
  return ((request.snapshots ?? []) as ProtoMessage[]).every((snapshot) => {
    if (snapshot.hostProfile) {
      return snapshot.collectorId === hostProfileCollectorId;
    }

    return true;
  });
}

export function hashHostProfile(hostProfile: ProtoMessage) {
  const bytes = HostProfileSnapshotMessage.encode(
    HostProfileSnapshotMessage.create(stableHostProfile(hostProfile)),
  ).finish();

  return createHash("sha256").update(bytes).digest("hex");
}

function stableHostProfile(hostProfile: ProtoMessage): ProtoMessage {
  const { probeAssetBundleVersion: _bundleVersion, ...stable } = hostProfile;
  return {
    ...stable,
    filesystems: [...(hostProfile.filesystems ?? [])].sort(
      (left, right) =>
        compareProtoStrings(left.mountPoint, right.mountPoint) ||
        compareProtoStrings(left.filesystemType, right.filesystemType),
    ),
    networkInterfaces: [...(hostProfile.networkInterfaces ?? [])]
      .map((networkInterface) => ({
        ...networkInterface,
        addresses: [...new Set(networkInterface.addresses ?? [])].sort(
          compareProtoStrings,
        ),
      }))
      .sort((left, right) => compareProtoStrings(left.name, right.name)),
  };
}

function compareProtoStrings(left: unknown, right: unknown) {
  return Buffer.compare(
    Buffer.from(String(left ?? ""), "utf8"),
    Buffer.from(String(right ?? ""), "utf8"),
  );
}
