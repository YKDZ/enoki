import { describe, expect, it } from "vitest";

import {
  hostProfileSnapshotFromRegistration,
  hostProfileSnapshotFromReport,
} from "../src/probe/host-profile-snapshots.js";

describe("Host Profile snapshot identity", () => {
  it("canonicalizes registration and report payloads through one identity Interface", () => {
    const registration = hostProfileSnapshotFromRegistration({
      snapshots: [
        {
          collectorId: "official.host-profile",
          hostProfile: {
            filesystems: [
              { filesystemType: "ext4", mountPoint: "/var" },
              { filesystemType: "ext4", mountPoint: "/" },
            ],
            hostname: "host-1",
            networkInterfaces: [
              { addresses: ["10.0.0.2", "10.0.0.1"], name: "eth0" },
            ],
            probeAssetBundleVersion: "bundle-registration",
          },
        },
      ],
    });
    const report = hostProfileSnapshotFromReport({
      snapshots: [
        {
          collectorId: "official.host-profile",
          hostProfile: {
            filesystems: [
              { filesystemType: "ext4", mountPoint: "/" },
              { filesystemType: "ext4", mountPoint: "/var" },
            ],
            hostname: "host-1",
            networkInterfaces: [
              { addresses: ["10.0.0.1", "10.0.0.2"], name: "eth0" },
            ],
            probeAssetBundleVersion: "bundle-report",
          },
        },
      ],
    });

    expect(registration?.canonicalHash).toMatch(/^[0-9a-f]{64}$/);
    expect(report?.canonicalHash).toBe(registration?.canonicalHash);
  });
});
