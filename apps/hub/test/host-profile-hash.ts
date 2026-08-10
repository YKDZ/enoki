import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";

export function hashStableHostProfile(
  hostProfile: root.enoki.v1.IHostProfileSnapshot,
) {
  const HostProfileSnapshot = root.enoki.v1.HostProfileSnapshot;

  return createHash("sha256")
    .update(
      HostProfileSnapshot.encode(
        HostProfileSnapshot.create(stableHostProfile(hostProfile)),
      ).finish(),
    )
    .digest("hex");
}

function stableHostProfile<T extends root.enoki.v1.IHostProfileSnapshot>(
  hostProfile: T,
): T {
  return {
    ...hostProfile,
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
  } as T;
}

function compareProtoStrings(left: unknown, right: unknown) {
  return Buffer.compare(
    Buffer.from(String(left ?? ""), "utf8"),
    Buffer.from(String(right ?? ""), "utf8"),
  );
}
