import { describe, expect, it } from "vitest";

import root from "../src/generated/ts/enoki_pb.js";

describe("generated Probe protocol TypeScript", () => {
  it("encodes and decodes a Probe registration request", () => {
    const RegistrationRequest = root.enoki.v1.ProbeRegistrationRequest;

    const encoded = RegistrationRequest.encode(
      RegistrationRequest.create({
        enrollmentToken: "enrollment-token",
        inventory: {
          architecture: "x86_64",
          cpuCount: 2,
          cpuModel: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
          filesystems: [
            {
              availableBytes: 60000,
              filesystemType: "ext4",
              mountPoint: "/",
              totalBytes: 100000,
            },
          ],
          hostname: "managed-host-01",
          kernel: "6.8.0",
          memoryTotalBytes: 2147483648,
          networkInterfaces: [
            {
              addresses: ["10.0.0.10"],
              name: "eth0",
            },
          ],
          os: "linux",
          probeVersion: "0.1.0",
        },
      }),
    ).finish();

    const decoded = RegistrationRequest.decode(encoded);

    expect(decoded.enrollmentToken).toBe("enrollment-token");
    expect(decoded.inventory?.hostname).toBe("managed-host-01");
    expect(decoded.inventory?.cpuModel).toBe(
      "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz",
    );
    expect(decoded.inventory?.probeVersion).toBe("0.1.0");
    expect(decoded.inventory?.filesystems?.[0]?.mountPoint).toBe("/");
  });

  it("encodes and decodes a Probe registration response with initial configuration", () => {
    const RegistrationResponse = root.enoki.v1.ProbeRegistrationResponse;

    const encoded = RegistrationResponse.encode(
      RegistrationResponse.create({
        initialConfiguration: {
          collectCpu: true,
          collectDisk: true,
          collectLoad: true,
          collectMemory: true,
          collectNetwork: true,
          collectUptime: true,
          metricsCollectionIntervalSeconds: 5,
          reportingBatchIntervalSeconds: 15,
          version: "default-v1",
        },
        probeId: "probe-01",
        probeSecret: "probe-secret",
        serverTimeMs: 1710000000000,
      }),
    ).finish();

    const decoded = RegistrationResponse.decode(encoded);

    expect(decoded.probeId).toBe("probe-01");
    expect(decoded.initialConfiguration?.version).toBe("default-v1");
    expect(decoded.initialConfiguration?.metricsCollectionIntervalSeconds).toBe(
      5,
    );
    expect(decoded.initialConfiguration).toEqual(
      expect.objectContaining({
        collectCpu: true,
        collectDisk: true,
        collectLoad: true,
        collectMemory: true,
        collectNetwork: true,
        collectUptime: true,
      }),
    );
  });

  it("encodes and decodes repeated Probe metric samples with collected timestamps", () => {
    const ReportRequest = root.enoki.v1.ProbeReportRequest;

    const encoded = ReportRequest.encode(
      ReportRequest.create({
        bootId: "boot-01",
        inventoryHash: "inventory-hash",
        metrics: [
          {
            cpuPercent: 42.5,
            collectedAtMs: 1710000000000,
            memoryUsedBytes: 1048576,
            sequence: 7,
          },
          {
            cpuPercent: 51.25,
            collectedAtMs: 1710000005000,
            memoryUsedBytes: 2097152,
            sequence: 8,
          },
        ],
        probeConfigurationVersion: "config-v1",
        probeId: "probe-01",
        sequenceEnd: 8,
        sequenceStart: 7,
      }),
    ).finish();

    const decoded = ReportRequest.decode(encoded);

    expect(decoded.metrics).toHaveLength(2);
    expect(decoded.metrics[0]?.sequence.toString()).toBe("7");
    expect(decoded.metrics[0]?.collectedAtMs.toString()).toBe("1710000000000");
    expect(decoded.metrics[1]?.cpuPercent).toBe(51.25);
  });

  it("encodes and decodes Probe report acknowledgements", () => {
    const ReportResponse = root.enoki.v1.ProbeReportResponse;

    const encoded = ReportResponse.encode(
      ReportResponse.create({
        acceptedSequenceEnd: 8,
        currentProbeConfigurationVersion: "default-v1",
        inventoryNeeded: false,
        serverTimeMs: 1710000005000,
      }),
    ).finish();

    const decoded = ReportResponse.decode(encoded);

    expect(decoded.acceptedSequenceEnd.toString()).toBe("8");
    expect(decoded.currentProbeConfigurationVersion).toBe("default-v1");
    expect(decoded.serverTimeMs.toString()).toBe("1710000005000");
    expect(decoded.inventoryNeeded).toBe(false);
  });
});
