import { createServer } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import { enoki } from "../packages/proto/src/generated/ts/enoki_pb.js";
import { createCanonicalReportEvidenceTransport } from "./release-canonical-report-evidence.mjs";

const ReportRequest = enoki.v1.ProbeReportRequest;
const ReportResponse = enoki.v1.ProbeReportResponse;

describe("canonical Probe report response-loss evidence", () => {
  const close = [];

  afterEach(async () => {
    await Promise.all(close.splice(0).map((resource) => resource()));
  });

  it("drops only the first committed failure response and proves the byte-identical retry", async () => {
    const upstreamRequests = [];
    const upstream = await listen(async (request, response) => {
      const body = await readBody(request);
      upstreamRequests.push({
        body,
        headers: request.headers,
        path: request.url,
      });
      response.writeHead(200, { "content-type": "application/x-protobuf" });
      response.end(
        ReportResponse.encode({
          acceptedSequenceEnd: ReportRequest.decode(body).sequenceEnd,
          currentProbeConfigurationVersion: "configuration-v7",
          serverTimeMs: 1_725_000_000_000,
        }).finish(),
      );
    });
    close.push(upstream.close);
    const transport = createCanonicalReportEvidenceTransport({
      listenUrl: "http://127.0.0.1:0",
      upstreamUrl: upstream.origin,
    });
    const started = await transport.start();
    close.push(() => transport.close());
    transport.arm({ expectedProbeId: "probe-canonical-01" });

    const boot = reportBytes({
      bootId: "boot-c4-01",
      probeAssetBundleVersion: "1.2.3",
      probeConfigurationVersion: "configuration-v6",
      probeId: "probe-canonical-01",
      sequence: 1,
    });
    const failure = reportBytes({
      bootId: "boot-c4-01",
      failureReason: 1,
      probeConfigurationVersion: "configuration-v7",
      probeId: "probe-canonical-01",
      sequence: 2,
    });
    const bootResponse = await postReport(started.origin, boot);
    expect(bootResponse.status).toBe(200);
    await expect(postReport(started.origin, failure)).rejects.toThrow();
    const retryResponse = await postReport(started.origin, failure);
    expect(retryResponse.status).toBe(200);

    const evidence = await transport.waitForEvidence({ timeoutMs: 1_000 });
    expect(evidence).toMatchObject({
      bootId: "boot-c4-01",
      bootReport: {
        acceptedSequenceEnd: 1,
        responseDelivered: true,
        sequence: 1,
        upstreamStatus: 200,
      },
      failureReport: {
        attempts: [
          {
            acceptedSequenceEnd: 2,
            response: "dropped",
            upstreamStatus: 200,
          },
          {
            acceptedSequenceEnd: 2,
            response: "delivered",
            upstreamStatus: 200,
          },
        ],
        collectionOutcomeCount: 0,
        metricsCount: 0,
        reason: "observation_runtime_unavailable",
        sequence: 2,
      },
      kind: "canonical-runtime-unavailable-report-evidence",
      receiptConvergence: {
        key: {
          bootId: "boot-c4-01",
          probeId: "probe-canonical-01",
          sequence: 2,
        },
        requestAttemptCount: 2,
        uniquePayloadCount: 1,
      },
      probeId: "probe-canonical-01",
      schemaVersion: 1,
    });
    expect(evidence.failureReport.payloadSha256).toBe(
      evidence.failureReport.retryPayloadSha256,
    );
    expect(evidence.failureReport.bytes).toBe(failure.byteLength);
    expect(upstreamRequests).toHaveLength(3);
    expect(
      upstreamRequests.every(({ headers }) =>
        [
          "x-enoki-body-sha256",
          "x-enoki-nonce",
          "x-enoki-probe-id",
          "x-enoki-signature",
          "x-enoki-timestamp-ms",
        ].every((name) => headers[name] === canonicalAuthHeaders[name]),
      ),
    ).toBe(true);
    expect(upstreamRequests[1].body.equals(upstreamRequests[2].body)).toBe(
      true,
    );
    expect(JSON.stringify(evidence)).not.toMatch(
      /signed-request|authorization|body|private|token/i,
    );
  });

  it.each([
    ["different boot", { bootId: "boot-other", sequence: 2 }],
    ["wrong sequence", { bootId: "boot-c4-01", sequence: 3 }],
    ["Metrics", { bootId: "boot-c4-01", metrics: [{}], sequence: 2 }],
    [
      "Collection Outcomes",
      {
        bootId: "boot-c4-01",
        outcomes: [{ reason: 1, sequence: 2 }],
        sequence: 2,
      },
    ],
  ])("fails closed for a %s failure retry", async (_label, retry) => {
    const upstream = await protobufUpstream();
    close.push(upstream.close);
    const transport = createCanonicalReportEvidenceTransport({
      listenUrl: "http://127.0.0.1:0",
      upstreamUrl: upstream.origin,
    });
    const started = await transport.start();
    close.push(() => transport.close());
    transport.arm({ expectedProbeId: "probe-canonical-01" });
    await postReport(
      started.origin,
      reportBytes({
        bootId: "boot-c4-01",
        probeAssetBundleVersion: "1.2.3",
        probeId: "probe-canonical-01",
        sequence: 1,
      }),
    );
    const failure = reportBytes({
      bootId: "boot-c4-01",
      failureReason: 1,
      probeId: "probe-canonical-01",
      sequence: 2,
    });
    await expect(postReport(started.origin, failure)).rejects.toThrow();
    await postReport(
      started.origin,
      reportBytes({
        failureReason: 1,
        probeId: "probe-canonical-01",
        ...retry,
      }),
    ).catch(() => {});

    await expect(transport.waitForEvidence({ timeoutMs: 100 })).rejects.toThrow(
      /canonical|retry|payload|boot|sequence|Metrics|Outcome/i,
    );
  });

  it("distinguishes a Hub non-200 from an unobserved failure report", async () => {
    const upstream = await listen(async (request, response) => {
      const body = await readBody(request);
      const report = ReportRequest.decode(body);
      response.statusCode = Number(report.sequenceEnd) === 2 ? 503 : 200;
      response.end(
        ReportResponse.encode({
          acceptedSequenceEnd: report.sequenceEnd,
          currentProbeConfigurationVersion: "configuration-v7",
        }).finish(),
      );
    });
    close.push(upstream.close);
    const transport = createCanonicalReportEvidenceTransport({
      listenUrl: "http://127.0.0.1:0",
      upstreamUrl: upstream.origin,
    });
    const started = await transport.start();
    close.push(() => transport.close());
    transport.arm({ expectedProbeId: "probe-canonical-01" });
    await postReport(
      started.origin,
      reportBytes({
        bootId: "boot-c4-01",
        probeAssetBundleVersion: "1.2.3",
        probeId: "probe-canonical-01",
        sequence: 1,
      }),
    );
    await postReport(
      started.origin,
      reportBytes({
        bootId: "boot-c4-01",
        failureReason: 1,
        probeId: "probe-canonical-01",
        sequence: 2,
      }),
    );

    await expect(transport.waitForEvidence({ timeoutMs: 100 })).rejects.toThrow(
      /upstream.*503/i,
    );
    expect(transport.diagnostics()).toMatchObject({
      failureReportObserved: true,
      lastUpstreamStatus: 503,
    });
  });

  it("fails closed when an armed canonical report cannot be decoded", async () => {
    const upstream = await listen(async (_request, response) => {
      response.writeHead(200, { "content-type": "application/x-protobuf" });
      response.end(ReportResponse.encode({ acceptedSequenceEnd: 1 }).finish());
    });
    close.push(upstream.close);
    const transport = createCanonicalReportEvidenceTransport({
      listenUrl: "http://127.0.0.1:0",
      upstreamUrl: upstream.origin,
    });
    const started = await transport.start();
    close.push(() => transport.close());
    transport.arm({ expectedProbeId: "probe-canonical-01" });

    await postReport(started.origin, Buffer.from([0xff])).catch(() => {});

    await expect(transport.waitForEvidence({ timeoutMs: 100 })).rejects.toThrow(
      /could not be decoded/i,
    );
    expect(JSON.stringify(transport.diagnostics())).not.toMatch(
      /x-enoki|signature|private|token/i,
    );
  });

  it("closes safely before start and after the listening socket is released", async () => {
    const upstream = await protobufUpstream();
    close.push(upstream.close);
    const transport = createCanonicalReportEvidenceTransport({
      listenUrl: "http://127.0.0.1:0",
      upstreamUrl: upstream.origin,
    });

    await expect(transport.close()).resolves.toEqual({
      clean: true,
      skipped: "not_started",
    });
    await transport.start();
    await expect(transport.close()).resolves.toEqual({ clean: true });
    await expect(transport.close()).resolves.toEqual({
      clean: true,
      skipped: "not_started",
    });
  });
});

function reportBytes({
  bootId,
  failureReason,
  metrics = [],
  outcomes = [],
  probeAssetBundleVersion = "",
  probeConfigurationVersion = "configuration-v7",
  probeId,
  sequence,
}) {
  return Buffer.from(
    ReportRequest.encode({
      bootId,
      cpuResourceCollectionOutcomes: outcomes,
      metrics,
      observationWindowFailure:
        failureReason === undefined ? null : { reason: failureReason },
      probeAssetBundleVersion,
      probeConfigurationVersion,
      probeId,
      sequenceEnd: sequence,
      sequenceStart: sequence,
    }).finish(),
  );
}

async function postReport(origin, body) {
  return fetch(`${origin}/api/probe/report`, {
    body,
    headers: {
      ...canonicalAuthHeaders,
      "content-type": "application/x-protobuf",
    },
    method: "POST",
  });
}

const canonicalAuthHeaders = Object.freeze({
  "x-enoki-body-sha256": "a".repeat(64),
  "x-enoki-nonce": "canonical-nonce",
  "x-enoki-probe-id": "probe-canonical-01",
  "x-enoki-signature": "b".repeat(128),
  "x-enoki-timestamp-ms": "1725000000000",
});

async function protobufUpstream() {
  return listen(async (request, response) => {
    const report = ReportRequest.decode(await readBody(request));
    response.writeHead(200, { "content-type": "application/x-protobuf" });
    response.end(
      ReportResponse.encode({
        acceptedSequenceEnd: report.sequenceEnd,
        currentProbeConfigurationVersion: "configuration-v7",
      }).finish(),
    );
  });
}

async function listen(handler) {
  const server = createServer((request, response) => {
    Promise.resolve(handler(request, response)).catch((error) => {
      response.destroy(error);
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  return {
    close: () => new Promise((resolve) => server.close(resolve)),
    origin: `http://127.0.0.1:${address.port}`,
  };
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
}
