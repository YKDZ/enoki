import { createHash } from "node:crypto";

import { Hono } from "hono";

import type { HostRepository } from "../database/hosts.js";
import { broadcastHostSummaryHint } from "../hosts/live-summary.js";
import { defaultProbeOperationTimeouts } from "../hosts/probe-upgrade-timeout.js";
import {
  broadcastHostReadyHint,
  broadcastHostRemovedHint,
} from "../live-updates.js";
import { verifyProbeRequestSignature } from "./probe-identity.js";
import { reconcileProbeReportTransaction } from "./report-transaction-reconciliation.js";
import {
  ReportBusinessRejection,
  admitProbeReport,
  decodeReportRequest,
} from "./report-validation.js";
import {
  observedIpFromContext,
  probeJsonError,
  readCappedRequestBody,
} from "./route-http.js";
import type { ProbeRouteServices } from "./route-services.js";

const maxProbeReportPayloadBytes = 1024 * 1024;
const probeRequestSignatureNonceTtlMs = 5 * 60 * 1000;
const acceptedProbeRequestClockSkewMs = 5 * 60 * 1000;

export function createProbeReportRoutes(services: ProbeRouteServices) {
  const routes = new Hono();
  const now = services.now ?? Date.now;

  routes.post("/report", async (context) => {
    if (
      contentLengthExceeds(context.req.raw.headers, maxProbeReportPayloadBytes)
    ) {
      return probeJsonError("probe_report_too_large", 413);
    }

    const requestBody = await readCappedRequestBody(
      context.req.raw,
      maxProbeReportPayloadBytes,
    );
    if (!requestBody) {
      return probeJsonError("probe_report_too_large", 413);
    }

    const host = authenticateProbe(
      services.hosts,
      context.req.raw,
      requestBody,
      services.probeApiOrigin,
    );
    if (!host) {
      return probeJsonError("probe_identity_required", 401);
    }

    const request = decodeReportRequest(requestBody);
    if (!request) {
      return probeJsonError("malformed_probe_report", 400);
    }
    if (request.probeId !== host.probeId) {
      return probeJsonError("probe_identity_required", 401);
    }

    const admission = admitProbeReport(request);
    if (!admission) {
      return probeJsonError("malformed_probe_report", 400);
    }

    let outcome: ReturnType<typeof reconcileProbeReportTransaction>;
    try {
      outcome = reconcileProbeReportTransaction(
        {
          admission,
          host,
          observedIp: observedIpFromContext(
            context,
            services.trustedProxyCidrs,
          ),
          reportReceivedAtMs: now(),
          request,
        },
        services,
      );
    } catch (error) {
      if (error instanceof ReportBusinessRejection) {
        return probeJsonError(error.code, error.status);
      }
      throw error;
    }

    if (outcome.startupRejection) {
      return probeJsonError(
        outcome.startupRejection.code,
        outcome.startupRejection.status,
      );
    }

    broadcastHostSummaryHint(services, {
      hostId: host.id,
      nowMs: outcome.reportReceivedAtMs,
      timeouts:
        services.probeOperationTimeouts ?? defaultProbeOperationTimeouts,
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });
    if (outcome.hostProfileUpdate) {
      services.liveUpdates?.broadcastHostProfile(
        host.id,
        outcome.hostProfileUpdate,
      );
    }
    for (const sample of outcome.detailSamples) {
      services.liveUpdates?.broadcastDetailSample(sample);
    }
    if (outcome.readyEnrollment?.enrollmentId) {
      broadcastHostReadyHint(services.liveUpdates, {
        enrollmentId: outcome.readyEnrollment.enrollmentId,
        hostId: host.id,
      });
    }
    for (const removedHostId of outcome.hostRemovedIds) {
      broadcastHostRemovedHint(services.liveUpdates, removedHostId);
    }

    return context.body(toArrayBuffer(outcome.responseBody), 200, {
      "cache-control": "no-store",
      "content-type": "application/x-protobuf",
    });
  });

  return routes;
}

function authenticateProbe(
  hosts: HostRepository,
  request: Request,
  body: Uint8Array,
  probeApiOrigin = "http://localhost",
) {
  const headers = request.headers;
  const probeId = headers.get("x-enoki-probe-id")?.trim() ?? "";
  const timestamp = headers.get("x-enoki-timestamp-ms")?.trim() ?? "";
  const nonce = headers.get("x-enoki-nonce")?.trim() ?? "";
  const bodySha256 = headers.get("x-enoki-body-sha256")?.trim() ?? "";
  const signature = headers.get("x-enoki-signature")?.trim() ?? "";

  if (
    !probeId ||
    !timestamp ||
    !nonce ||
    !bodySha256 ||
    !signature ||
    !/^\d+$/.test(timestamp) ||
    !/^[0-9a-fA-F]{32}$/.test(nonce) ||
    !/^[0-9a-fA-F]{64}$/.test(bodySha256) ||
    !/^[0-9a-fA-F]+$/.test(signature)
  ) {
    return null;
  }

  const host = hosts.findByProbeId(probeId);
  if (!host?.probePublicKeyPem) {
    return null;
  }

  const timestampMs = Number(timestamp);
  if (
    !Number.isSafeInteger(timestampMs) ||
    Math.abs(Date.now() - timestampMs) > acceptedProbeRequestClockSkewMs ||
    bodySha256 !== createHash("sha256").update(body).digest("hex")
  ) {
    return null;
  }

  const url = new URL(request.url);
  const payload = [
    request.method.toUpperCase(),
    `${probeApiOrigin}${url.pathname}${url.search}`,
    timestamp,
    nonce,
    bodySha256,
  ].join("\n");
  if (
    !verifyProbeRequestSignature(host.probePublicKeyPem, payload, signature)
  ) {
    return null;
  }

  const nowMs = Date.now();
  return hosts.insertProbeRequestNonce({
    expiresAtMs: nowMs + probeRequestSignatureNonceTtlMs,
    nonce,
    nowMs,
    probeId,
  })
    ? host
    : null;
}

function contentLengthExceeds(headers: Headers, maxBytes: number) {
  const contentLength = headers.get("content-length")?.trim();
  return Boolean(
    contentLength &&
    /^\d+$/.test(contentLength) &&
    Number(contentLength) > maxBytes,
  );
}

function toArrayBuffer(bytes: Uint8Array) {
  const output = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(output).set(bytes);
  return output;
}
