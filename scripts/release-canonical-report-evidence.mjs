import { createHash } from "node:crypto";
import { createServer, request } from "node:http";

import { enoki } from "../packages/proto/src/generated/ts/enoki_pb.js";

const ReportRequest = enoki.v1.ProbeReportRequest;
const ReportResponse = enoki.v1.ProbeReportResponse;
const maxProbeReportPayloadBytes = 1024 * 1024;
const reportPath = "/api/probe/report";

export function createCanonicalReportEvidenceTransport({
  fetch: fetch_ = globalThis.fetch,
  listenUrl,
  upstreamUrl,
}) {
  const listen = validatedHttpOrigin(listenUrl, "listen");
  const upstream = validatedHttpOrigin(upstreamUrl, "upstream");
  if (listen.origin === upstream.origin && listen.port !== "0") {
    throw new Error(
      "canonical report evidence transport requires distinct listen and upstream origins",
    );
  }
  let armed = null;
  let completedEvidence = null;
  let failure = null;
  let listenPublicOrigin = null;
  let server = null;
  let reportRequestCount = 0;
  let lastUpstreamStatus = null;
  const waiters = new Set();

  function notify() {
    for (const waiter of waiters) waiter();
    waiters.clear();
  }

  async function handle(incoming, outgoing) {
    try {
      const target = new URL(incoming.url ?? "/", upstream);
      const isReport =
        incoming.method === "POST" && target.pathname === reportPath;
      if (!isReport) {
        streamTransparent(incoming, outgoing, target);
        return;
      }
      if (contentLengthExceeds(incoming.headers, maxProbeReportPayloadBytes)) {
        rejectOversizedReport(incoming, outgoing);
        return;
      }
      const body = await readCappedBody(incoming, maxProbeReportPayloadBytes);
      if (!body) {
        rejectOversizedReport(incoming, outgoing);
        return;
      }
      const headers = forwardedHeaders(
        incoming.headers,
        body.byteLength,
        listenPublicOrigin,
      );
      const observation =
        isReport && armed && !completedEvidence && !failure
          ? observeReport(body)
          : null;
      const response = await fetch_(target, {
        body:
          incoming.method === "GET" || incoming.method === "HEAD"
            ? undefined
            : body,
        headers,
        method: incoming.method,
        redirect: "manual",
      });
      const responseBody = Buffer.from(await response.arrayBuffer());
      if (isReport) {
        reportRequestCount += 1;
        lastUpstreamStatus = response.status;
      }
      const disposition = observation
        ? acceptUpstreamObservation(observation, response.status, responseBody)
        : "deliver";
      if (disposition === "drop") {
        outgoing.destroy();
        return;
      }
      writeResponse(outgoing, response, responseBody);
    } catch (error) {
      if (!outgoing.destroyed) outgoing.destroy(error);
    }
  }

  function observeReport(body) {
    let report;
    try {
      report = ReportRequest.decode(body);
    } catch (error) {
      fail(`canonical report payload could not be decoded: ${error.message}`);
      return { kind: "invalid" };
    }
    const projected = projectReport(report, body);
    if (projected.probeId !== armed.expectedProbeId) return null;

    if (!armed.boot) {
      if (projected.sequenceStart !== 1 || projected.sequenceEnd !== 1) {
        return null;
      }
      const invalidBoot =
        projected.metricsCount !== 0 ||
        projected.collectionOutcomeCount !== 0 ||
        projected.failureReason !== 0 ||
        !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
          projected.probeAssetBundleVersion,
        );
      if (invalidBoot) {
        fail("canonical sequence-one Boot Report is invalid");
        return { kind: "invalid" };
      }
      armed.boot = projected;
      notify();
      return { kind: "boot", projected };
    }

    const expectedFailure =
      projected.bootId === armed.boot.bootId &&
      projected.sequenceStart === 2 &&
      projected.sequenceEnd === 2 &&
      projected.failureReason === 1 &&
      projected.metricsCount === 0 &&
      projected.collectionOutcomeCount === 0 &&
      projected.probeAssetBundleVersion === "";
    if (!expectedFailure) {
      fail(
        "canonical ObservationWindowFailure retry changed boot, sequence, payload semantics, Metrics, or Collection Outcomes",
      );
      return { kind: "invalid" };
    }
    if (!armed.failure) {
      armed.failure = projected;
      notify();
      return { kind: "first-failure", projected };
    }
    if (!body.equals(armed.failure.body)) {
      fail(
        "canonical ObservationWindowFailure retry payload was not byte-identical",
      );
      return { kind: "invalid" };
    }
    return { kind: "retry", projected };
  }

  function acceptUpstreamObservation(observation, status, responseBody) {
    if (!observation || observation.kind === "invalid") return "deliver";
    if (status !== 200) {
      fail(
        `canonical ${observationLabel(observation.kind)} upstream returned ${status}`,
      );
      return "deliver";
    }
    let response;
    try {
      response = ReportResponse.decode(responseBody);
    } catch (error) {
      fail(`canonical Hub response could not be decoded: ${error.message}`);
      return "deliver";
    }
    const acceptedSequenceEnd = unsignedNumber(response.acceptedSequenceEnd);
    if (acceptedSequenceEnd !== observation.projected.sequenceEnd) {
      fail("canonical Hub response acknowledged the wrong report sequence");
      return "deliver";
    }
    if (observation.kind === "boot") {
      const currentConfigurationVersion =
        response.currentProbeConfigurationVersion ?? "";
      if (!currentConfigurationVersion) {
        fail(
          "canonical Boot Report response omitted configuration reconciliation",
        );
        return "deliver";
      }
      armed.bootResponse = {
        acceptedSequenceEnd,
        currentConfigurationVersion,
        pendingOperation:
          response.pendingOperation == null ? "absent" : "present",
        requestedSnapshotCollectorIdsCount:
          response.requestedSnapshotCollectorIds?.length ?? 0,
        responseSha256: sha256(responseBody),
      };
      notify();
      return "deliver";
    }
    if (
      observation.projected.probeConfigurationVersion !==
      armed.bootResponse?.currentConfigurationVersion
    ) {
      fail(
        "canonical ObservationWindowFailure did not continue configuration reconciliation from the Boot Report response",
      );
      return "deliver";
    }
    if (observation.kind === "first-failure") {
      armed.firstFailureResponse = {
        acceptedSequenceEnd,
        responseSha256: sha256(responseBody),
        upstreamStatus: status,
      };
      notify();
      return "drop";
    }
    if (!armed.firstFailureResponse) {
      fail("canonical retry arrived before the committed response was lost");
      return "deliver";
    }
    completedEvidence = buildEvidence({
      armed,
      retryResponseSha256: sha256(responseBody),
    });
    notify();
    return "deliver";
  }

  function rejectOversizedReport(incoming, outgoing) {
    fail(
      "canonical report payload exceeded the production 1 MiB limit",
      "canonical_report_payload_too_large",
    );
    incoming.destroy();
    if (!outgoing.destroyed) outgoing.destroy();
  }

  function fail(message, code = "canonical_report_evidence_invalid") {
    if (!failure) {
      failure = new Error(message);
      failure.code = code;
      notify();
    }
  }

  return {
    arm({ expectedProbeId }) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(expectedProbeId ?? "")) {
        throw new Error("canonical report evidence Probe ID is invalid");
      }
      if (armed || completedEvidence || failure) {
        throw new Error(
          "canonical report evidence transport can be armed only once",
        );
      }
      armed = {
        boot: null,
        bootResponse: null,
        expectedProbeId,
        failure: null,
      };
    },

    async close() {
      if (!server) return { clean: true, skipped: "not_started" };
      const closing = server;
      server = null;
      await new Promise((resolve, reject) =>
        closing.close((error) => (error ? reject(error) : resolve())),
      );
      return { clean: true };
    },

    diagnostics() {
      return {
        armed: Boolean(armed),
        bootReportObserved: Boolean(armed?.boot),
        completed: Boolean(completedEvidence),
        failure: failure
          ? { code: failure.code, message: failure.message }
          : null,
        failureReportObserved: Boolean(armed?.failure),
        lastUpstreamStatus,
        reportRequestCount,
      };
    },

    async start() {
      if (server)
        throw new Error(
          "canonical report evidence transport is already started",
        );
      server = createServer((incoming, outgoing) => {
        handle(incoming, outgoing);
      });
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(Number(listen.port), listen.hostname, resolve);
      });
      const address = server.address();
      const origin = `${listen.protocol}//${listen.hostname}:${address.port}`;
      listenPublicOrigin = new URL(origin);
      return { origin };
    },

    async waitForEvidence({ timeoutMs }) {
      if (!armed)
        throw new Error("canonical report evidence transport is not armed");
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
        throw new Error("canonical report evidence timeout is invalid");
      }
      const deadline = Date.now() + timeoutMs;
      while (!completedEvidence && !failure && Date.now() < deadline) {
        await new Promise((resolve) => {
          const remaining = Math.max(1, deadline - Date.now());
          const timer = setTimeout(() => {
            waiters.delete(wake);
            resolve();
          }, remaining);
          const wake = () => {
            clearTimeout(timer);
            resolve();
          };
          waiters.add(wake);
        });
      }
      if (failure) throw failure;
      if (completedEvidence) return structuredClone(completedEvidence);
      const missing = !armed.boot
        ? "Boot Report was not sent"
        : !armed.bootResponse
          ? "Boot Report did not receive Hub 200"
          : !armed.failure
            ? "ObservationWindowFailure was not sent"
            : !armed.firstFailureResponse
              ? "ObservationWindowFailure did not receive Hub 200"
              : "ObservationWindowFailure retry was not sent";
      const error = new Error(
        `canonical report evidence timed out: ${missing}`,
      );
      error.code = "canonical_report_evidence_timeout";
      throw error;
    },
  };
}

function streamTransparent(incoming, outgoing, target) {
  let upstreamResponse = null;
  const upstreamRequest = request(
    target,
    {
      headers: transparentHeaders(incoming.headers),
      method: incoming.method,
    },
    (response) => {
      upstreamResponse = response;
      outgoing.writeHead(
        response.statusCode ?? 502,
        response.statusMessage ?? undefined,
        transparentHeaders(response.headers),
      );
      response.once("error", (error) => outgoing.destroy(error));
      response.pipe(outgoing);
    },
  );
  const releaseUpstream = () => {
    if (!outgoing.writableEnded) {
      upstreamResponse?.destroy();
      upstreamRequest.destroy();
    }
  };
  incoming.once("aborted", releaseUpstream);
  outgoing.once("close", releaseUpstream);
  upstreamRequest.once("error", (error) => {
    if (!outgoing.destroyed) outgoing.destroy(error);
  });
  incoming.pipe(upstreamRequest);
}

function buildEvidence({ armed, retryResponseSha256 }) {
  const boot = armed.boot;
  const failure = armed.failure;
  return {
    bootId: boot.bootId,
    bootReport: {
      acceptedSequenceEnd: armed.bootResponse.acceptedSequenceEnd,
      bytes: boot.bytes,
      payloadSha256: boot.payloadSha256,
      reconciliation: {
        currentProbeConfigurationVersion:
          armed.bootResponse.currentConfigurationVersion,
        pendingOperation: armed.bootResponse.pendingOperation,
        requestedSnapshotCollectorIdsCount:
          armed.bootResponse.requestedSnapshotCollectorIdsCount,
      },
      responseDelivered: true,
      responseSha256: armed.bootResponse.responseSha256,
      sequence: 1,
      upstreamStatus: 200,
    },
    failureReport: {
      attempts: [
        {
          acceptedSequenceEnd: 2,
          response: "dropped",
          responseSha256: armed.firstFailureResponse.responseSha256,
          upstreamStatus: 200,
        },
        {
          acceptedSequenceEnd: 2,
          response: "delivered",
          responseSha256: retryResponseSha256,
          upstreamStatus: 200,
        },
      ],
      bytes: failure.bytes,
      collectionOutcomeCount: failure.collectionOutcomeCount,
      metricsCount: failure.metricsCount,
      payloadSha256: failure.payloadSha256,
      probeConfigurationVersion: failure.probeConfigurationVersion,
      reason: "observation_runtime_unavailable",
      retryPayloadSha256: failure.payloadSha256,
      sequence: 2,
    },
    kind: "canonical-runtime-unavailable-report-evidence",
    receiptConvergence: {
      contract: "report-sequence-ack-idempotency",
      key: {
        bootId: failure.bootId,
        probeId: failure.probeId,
        sequence: 2,
      },
      requestAttemptCount: 2,
      uniquePayloadCount: 1,
    },
    probeId: boot.probeId,
    schemaVersion: 1,
  };
}

function projectReport(report, body) {
  return {
    body,
    bootId: report.bootId ?? "",
    bytes: body.byteLength,
    collectionOutcomeCount: report.cpuResourceCollectionOutcomes?.length ?? 0,
    enrollmentId: report.enrollmentId ?? "",
    failureReason:
      report.observationWindowFailure == null
        ? 0
        : unsignedNumber(report.observationWindowFailure.reason),
    metricsCount: report.metrics?.length ?? 0,
    payloadSha256: sha256(body),
    probeAssetBundleVersion: report.probeAssetBundleVersion ?? "",
    probeConfigurationVersion: report.probeConfigurationVersion ?? "",
    probeId: report.probeId ?? "",
    sequenceEnd: unsignedNumber(report.sequenceEnd),
    sequenceStart: unsignedNumber(report.sequenceStart),
  };
}

function observationLabel(kind) {
  return kind === "boot" ? "Boot Report" : "ObservationWindowFailure";
}

function unsignedNumber(value) {
  const number =
    typeof value === "number" ? value : Number(value?.toString?.() ?? value);
  return Number.isSafeInteger(number) && number >= 0 ? number : -1;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validatedHttpOrigin(value, label) {
  const url = new URL(value);
  if (
    url.protocol !== "http:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    !url.hostname ||
    !/^\d+$/.test(url.port || "0")
  ) {
    throw new Error(
      `canonical report evidence ${label} URL must be an HTTP origin`,
    );
  }
  return url;
}

function forwardedHeaders(source, length, publicOrigin) {
  if (!publicOrigin) {
    throw new Error("canonical report evidence transport is not listening");
  }
  const headers = new Headers();
  for (const [name, value] of Object.entries(source)) {
    if (
      value !== undefined &&
      !new Set([
        "connection",
        "content-length",
        "host",
        "transfer-encoding",
        "x-forwarded-host",
        "x-forwarded-proto",
      ]).has(name.toLowerCase())
    ) {
      headers.set(name, Array.isArray(value) ? value.join(", ") : value);
    }
  }
  headers.set("content-length", String(length));
  headers.set("x-forwarded-host", publicOrigin.host);
  headers.set("x-forwarded-proto", publicOrigin.protocol.slice(0, -1));
  return headers;
}

function transparentHeaders(source) {
  const headers = {};
  for (const [name, value] of Object.entries(source)) {
    if (
      value !== undefined &&
      !new Set([
        "connection",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
      ]).has(name.toLowerCase())
    ) {
      headers[name] = value;
    }
  }
  return headers;
}

function contentLengthExceeds(headers, maxBytes) {
  const value = headers["content-length"];
  const contentLength = Array.isArray(value) ? value[0] : value?.trim();
  return Boolean(
    contentLength &&
    /^\d+$/.test(contentLength) &&
    Number(contentLength) > maxBytes,
  );
}

function writeResponse(outgoing, response, body) {
  const headers = {};
  response.headers.forEach((value, name) => {
    if (
      !new Set(["connection", "content-length", "transfer-encoding"]).has(name)
    ) {
      headers[name] = value;
    }
  });
  headers["content-length"] = String(body.byteLength);
  outgoing.writeHead(response.status, headers);
  outgoing.end(body);
}

async function readCappedBody(request, maxBytes) {
  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of request) {
    totalBytes += chunk.byteLength;
    if (totalBytes > maxBytes) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, totalBytes);
}
