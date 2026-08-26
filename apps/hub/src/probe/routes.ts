import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";
import { Hono } from "hono";

import type { HostRepository } from "../database/hosts.js";
import { broadcastHostRemovedHint } from "../live-updates.js";
import { createForwardTransitions } from "./forward-transitions.js";
import {
  canonicalLifecycleUpgradeAuthority,
  deriveLifecycleAuthorityKey,
  signLifecycleUpgradeAuthority,
  type LifecycleUpgradeAuthority,
} from "./lifecycle-authority.js";
import {
  defaultProbeOperationTokenTtlMs,
  validateProbeOperationToken,
} from "./operation-token.js";
import {
  acknowledgeProbeUpgradeRequest,
  failReportedProbeUpgradeRequest,
  startProbeUpgradeRequest,
  succeedReportedProbeOperation,
  type ProbeUpgradeRequest,
} from "./operation.js";
import { verifyProbeRequestSignature } from "./probe-identity.js";
import { createProbeRegistrationRoutes } from "./registration-delivery.js";
import { readProbeReleaseContextFromDirectory } from "./release-context.js";
import { createProbeRepairAuthorizationRoutes } from "./repair-routes.js";
import { createProbeReportRoutes } from "./report-reconciliation.js";
import {
  parseProbeOperationId,
  probeJsonError,
  readCappedRequestBody,
} from "./route-http.js";
import {
  defaultProbeOperationTokenSecret,
  type ProbeRouteServices,
} from "./route-services.js";
const ConfigurationRequest = enoki.v1.ProbeConfigurationRequest as any;
const ConfigurationResponse = enoki.v1.ProbeConfigurationResponse as any;
const maxProbeOperationPayloadBytes = 16 * 1024;

export type { ProbeRouteServices } from "./route-services.js";

export function createProbeRoutes(services: ProbeRouteServices) {
  const routes = new Hono();
  const now = services.now ?? Date.now;
  const forwardTransitions =
    services.forwardTransitions ??
    createForwardTransitions({
      audit: services.audit,
      probeOperations: services.probeOperations!,
    });
  routes.use("*", async (context, next) => {
    if (!isIdentityContentEncoding(context.req.raw.headers)) {
      return probeJsonError("payload_compression_not_supported", 415);
    }

    return next();
  });
  routes.route("/", createProbeRepairAuthorizationRoutes(services));
  routes.route("/", createProbeRegistrationRoutes(services));
  routes.route("/", createProbeReportRoutes(services));

  routes.post("/operations/:operationId/token/validate", async (context) => {
    const requestBody = await readCappedRequestBody(
      context.req.raw,
      maxProbeOperationPayloadBytes,
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

    const operationId = parseProbeOperationId(context.req.param("operationId"));
    if (operationId === null) {
      return probeJsonError("probe_operation_not_found", 404);
    }

    const operation = services.probeOperations?.findById(operationId) ?? null;
    if (!operation) {
      return probeJsonError("probe_operation_not_found", 404);
    }

    if (operation.hostId !== host.id) {
      return probeJsonError("probe_operation_token_probe_mismatch", 403);
    }

    const body = readTokenValidationBody(requestBody);
    if (!body) {
      return probeJsonError("malformed_probe_operation_token_validation", 400);
    }

    const operationNowMs = now();
    const result = validateProbeOperationToken({
      nowMs: operationNowMs,
      operation,
      probeId: host.probeId,
      secret: probeOperationTokenSecret(services),
      targetAssetSetDigest: body.targetAssetSetDigest ?? "",
      targetProbeVersion: body.targetProbeVersion ?? "",
      token: body.token,
    });

    if (result.error) {
      return probeJsonError(result.error, 403);
    }

    if (operation.kind === "probe_upgrade") {
      return context.json({ valid: true }, 200, {
        "cache-control": "no-store",
      });
    }

    const acknowledged = acknowledgeProbeUpgradeRequest({
      nowMs: operationNowMs,
      operation,
    });
    const started = startProbeUpgradeRequest({
      nowMs: operationNowMs,
      operation: acknowledged.acknowledged,
    });
    if (acknowledged.error || started.error) {
      return probeJsonError("probe_operation_status_invalid", 400);
    }
    services.probeOperations?.updateProbeUpgradeRequest(started.operation);

    return context.json({ valid: true }, 200, {
      "cache-control": "no-store",
    });
  });

  routes.post(
    "/operations/:operationId/upgrade-stage/admit",
    async (context) => {
      const requestBody = await readCappedRequestBody(
        context.req.raw,
        maxProbeOperationPayloadBytes,
      );
      if (!requestBody) return probeJsonError("probe_report_too_large", 413);
      const host = authenticateProbe(
        services.hosts,
        context.req.raw,
        requestBody,
        services.probeApiOrigin,
      );
      if (!host) return probeJsonError("probe_identity_required", 401);
      const operationId = parseProbeOperationId(
        context.req.param("operationId"),
      );
      const body = readUpgradeStageAdmissionBody(requestBody);
      const operation =
        operationId === null
          ? null
          : (services.probeOperations?.findById(operationId) ?? null);
      if (!operation || operation.hostId !== host.id) {
        return probeJsonError("probe_operation_not_found", 404);
      }
      if (!body || operation.kind !== "probe_upgrade") {
        return probeJsonError("malformed_probe_upgrade_stage_admission", 400);
      }
      const operationNowMs = now();
      const token = validateProbeOperationToken({
        nowMs: operationNowMs,
        operation,
        probeId: host.probeId,
        secret: probeOperationTokenSecret(services),
        targetAssetSetDigest: body.targetAssetSetDigest,
        targetProbeVersion: body.targetBundleVersion,
        token: body.token,
      });
      if (token.error) return probeJsonError(token.error, 403);
      if (
        !services.probeAssetDir ||
        !services.probeDistributionRootPublicKeyPem
      ) {
        return probeJsonError("probe_upgrade_authority_unavailable", 503);
      }
      const release = await readProbeReleaseContextFromDirectory({
        assetDir: services.probeAssetDir,
        trustedRootPublicKeyPem: services.probeDistributionRootPublicKeyPem,
      });
      const transition = release.releaseTransition;
      if (
        transition?.classification !== "compatible" ||
        transition.sourceProbeVersion !== body.sourceBundleVersion ||
        transition.targetProbeVersion !== body.targetBundleVersion ||
        transition.targetAssetSetDigest !== body.targetAssetSetDigest ||
        !transition.targetBundles?.some(
          (bundle) => bundle.bundleManifestSha256 === body.targetManifestSha256,
        )
      ) {
        return probeJsonError("probe_upgrade_authority_rejected", 409);
      }
      const authority: LifecycleUpgradeAuthority = {
        schemaVersion: 1,
        hubOrigin: services.probeApiOrigin ?? "",
        hostId: String(host.id),
        probeId: host.probeId,
        operationId: String(operation.id),
        sourceBundleVersion: body.sourceBundleVersion,
        sourceInstallStateSha256: body.sourceInstallStateSha256,
        sourceManifestSha256: body.sourceManifestSha256,
        targetBundleVersion: body.targetBundleVersion,
        targetAssetSetDigest: body.targetAssetSetDigest,
        targetManifestSha256: body.targetManifestSha256,
        verifiedStageSha256: body.verifiedStageSha256,
        expiresAtMs: operationNowMs + defaultProbeOperationTokenTtlMs,
      };
      const tokenHash = services.enrollments.lifecycleAuthorityTokenHashForHost(
        host.id,
      );
      const hubOrigin = services.probeApiOrigin ?? "";
      if (!tokenHash || !/^[0-9a-f]{64}$/.test(tokenHash) || !hubOrigin) {
        return probeJsonError("probe_upgrade_authority_unavailable", 503);
      }
      const key = deriveLifecycleAuthorityKey(
        Buffer.from(tokenHash, "hex"),
        hubOrigin,
      );
      const canonicalAuthority = canonicalLifecycleUpgradeAuthority(authority);
      const admitted =
        services.probeOperations?.admitPendingProbeUpgradeRequest(
          operationId!,
          operationNowMs,
          body.targetManifestSha256,
          createHash("sha256").update(canonicalAuthority).digest("hex"),
          body.verifiedStageSha256,
        );
      if (!admitted) {
        return probeJsonError("probe_operation_status_invalid", 409);
      }
      return context.json(
        {
          authority,
          signature: signLifecycleUpgradeAuthority(canonicalAuthority, key),
        },
        200,
        { "cache-control": "no-store" },
      );
    },
  );

  routes.post("/operations/:operationId/status", async (context) => {
    const requestBody = await readCappedRequestBody(
      context.req.raw,
      maxProbeOperationPayloadBytes,
    );

    if (!requestBody) {
      return probeJsonError("probe_report_too_large", 413);
    }

    const operationId = parseProbeOperationId(context.req.param("operationId"));
    if (operationId === null) {
      return probeJsonError("probe_operation_not_found", 404);
    }

    const operation = services.probeOperations?.findById(operationId) ?? null;
    if (!operation) {
      return probeJsonError("probe_operation_not_found", 404);
    }

    const body = readOperationStatusBody(requestBody);
    if (!body) {
      return probeJsonError("malformed_probe_operation_status", 400);
    }

    const allowDeletedTerminalUninstall =
      operation.kind === "probe_uninstall" &&
      operation.state === "succeeded" &&
      body.status === "succeeded";
    const host = authenticateProbeOperationStatus(
      services.hosts,
      context.req.raw,
      requestBody,
      services.probeApiOrigin,
      allowDeletedTerminalUninstall,
    );

    if (!host) {
      return probeJsonError("probe_identity_required", 401);
    }

    if (operation.hostId !== host.id) {
      return probeJsonError("probe_operation_token_probe_mismatch", 403);
    }

    const tokenResult = validateProbeOperationToken({
      allowSucceededUninstallReplay: allowDeletedTerminalUninstall,
      nowMs: now(),
      operation,
      probeId: host.probeId,
      secret: probeOperationTokenSecret(services),
      targetAssetSetDigest: body.targetAssetSetDigest ?? "",
      targetProbeVersion: body.targetProbeVersion ?? "",
      token: body.token,
    });

    if (tokenResult.error) {
      return probeJsonError(tokenResult.error, 403);
    }

    if (operation.kind !== "probe_uninstall" && body.status === "failed") {
      const reconciled = forwardTransitions.reconcileAuthenticatedEvidence({
        evidence: [
          {
            code: body.errorCode ?? "probe_operation_failed",
            hostId: host.id,
            kind: "operation_failed",
            message: body.message ?? "",
            observedAtMs: now(),
            operationId,
          },
        ],
      });
      if (reconciled.kind === "refused") {
        return probeJsonError("malformed_probe_operation_status", 400);
      }
      return context.json({ accepted: true }, 200, {
        "cache-control": "no-store",
      });
    }

    const statusResult =
      body.status === "succeeded"
        ? succeedReportedProbeOperation({ nowMs: now(), operation })
        : failReportedProbeUpgradeRequest({
            code: body.errorCode ?? "probe_operation_failed",
            message: body.message ?? "",
            nowMs: now(),
            operation,
          });

    if (statusResult.error) {
      return probeJsonError("malformed_probe_operation_status", 400);
    }

    const updated =
      services.probeOperations?.updateProbeUpgradeRequest(
        statusResult.operation,
      ) ?? statusResult.operation;
    const removedHostId = completeProbeUninstallIfSucceeded({
      nowMs: now(),
      operation: updated,
      services,
    });
    if (removedHostId !== null) {
      broadcastHostRemovedHint(services.liveUpdates, removedHostId);
    }

    return context.json({ accepted: true }, 200, {
      "cache-control": "no-store",
    });
  });

  routes.post("/config", async (context) => {
    const requestBody = await readCappedRequestBody(
      context.req.raw,
      maxProbeOperationPayloadBytes,
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

    const request = decodeConfigurationRequest(requestBody);

    if (!request || request.probeId !== host.probeId) {
      return probeJsonError("probe_identity_required", 401);
    }

    const body = ConfigurationResponse.encode(
      ConfigurationResponse.create(
        services.probeConfigurations.getEffectiveForHost(host.id).configuration,
      ),
    ).finish();

    return context.body(toArrayBuffer(body), 200, {
      "cache-control": "no-store",
      "content-type": "application/x-protobuf",
    });
  });

  return routes;
}

function probeOperationTokenSecret(services: ProbeRouteServices) {
  return services.probeOperationTokenSecret ?? defaultProbeOperationTokenSecret;
}

function readTokenValidationBody(requestBody: Uint8Array) {
  try {
    const body = JSON.parse(new TextDecoder().decode(requestBody)) as {
      targetAssetSetDigest?: unknown;
      targetProbeVersion?: unknown;
      token?: unknown;
    };

    if (
      typeof body.token !== "string" ||
      body.token.length === 0 ||
      (Object.hasOwn(body, "targetAssetSetDigest") &&
        typeof body.targetAssetSetDigest !== "string") ||
      (Object.hasOwn(body, "targetProbeVersion") &&
        typeof body.targetProbeVersion !== "string")
    ) {
      return null;
    }

    return {
      targetAssetSetDigest:
        typeof body.targetAssetSetDigest === "string"
          ? body.targetAssetSetDigest
          : undefined,
      targetProbeVersion:
        typeof body.targetProbeVersion === "string"
          ? body.targetProbeVersion
          : undefined,
      token: body.token,
    };
  } catch {
    return null;
  }
}

function readUpgradeStageAdmissionBody(requestBody: Uint8Array) {
  try {
    const body = JSON.parse(new TextDecoder().decode(requestBody)) as Record<
      string,
      unknown
    >;
    const keys = [
      "sourceBundleVersion",
      "sourceInstallStateSha256",
      "sourceManifestSha256",
      "targetAssetSetDigest",
      "targetBundleVersion",
      "targetManifestSha256",
      "token",
      "verifiedStageSha256",
    ];
    if (
      Object.keys(body).sort().join("\0") !== keys.sort().join("\0") ||
      keys.some((key) => typeof body[key] !== "string") ||
      !/^[0-9a-f]{64}$/.test(String(body.sourceInstallStateSha256)) ||
      !/^[0-9a-f]{64}$/.test(String(body.sourceManifestSha256)) ||
      !/^sha256:[0-9a-f]{64}$/.test(String(body.targetAssetSetDigest)) ||
      !/^[0-9a-f]{64}$/.test(String(body.targetManifestSha256)) ||
      !/^[0-9a-f]{64}$/.test(String(body.verifiedStageSha256)) ||
      !/^(?:0|[1-9]\d*)[.](?:0|[1-9]\d*)[.](?:0|[1-9]\d*)$/.test(
        String(body.sourceBundleVersion),
      ) ||
      !/^(?:0|[1-9]\d*)[.](?:0|[1-9]\d*)[.](?:0|[1-9]\d*)$/.test(
        String(body.targetBundleVersion),
      ) ||
      !(body.token as string).length
    ) {
      return null;
    }
    return body as {
      sourceBundleVersion: string;
      sourceInstallStateSha256: string;
      sourceManifestSha256: string;
      targetAssetSetDigest: string;
      targetBundleVersion: string;
      targetManifestSha256: string;
      token: string;
      verifiedStageSha256: string;
    };
  } catch {
    return null;
  }
}

function readOperationStatusBody(requestBody: Uint8Array) {
  try {
    const body = JSON.parse(new TextDecoder().decode(requestBody)) as {
      errorCode?: unknown;
      message?: unknown;
      status?: unknown;
      targetAssetSetDigest?: unknown;
      targetProbeVersion?: unknown;
      token?: unknown;
    };

    if (
      typeof body.token !== "string" ||
      body.token.length === 0 ||
      (body.status !== "succeeded" && body.status !== "failed") ||
      (Object.hasOwn(body, "targetAssetSetDigest") &&
        typeof body.targetAssetSetDigest !== "string") ||
      (Object.hasOwn(body, "targetProbeVersion") &&
        typeof body.targetProbeVersion !== "string") ||
      (Object.hasOwn(body, "errorCode") &&
        typeof body.errorCode !== "string") ||
      (Object.hasOwn(body, "message") && typeof body.message !== "string")
    ) {
      return null;
    }

    return {
      errorCode: typeof body.errorCode === "string" ? body.errorCode : null,
      message: typeof body.message === "string" ? body.message : null,
      status: body.status,
      targetAssetSetDigest:
        typeof body.targetAssetSetDigest === "string"
          ? body.targetAssetSetDigest
          : undefined,
      targetProbeVersion:
        typeof body.targetProbeVersion === "string"
          ? body.targetProbeVersion
          : undefined,
      token: body.token,
    };
  } catch {
    return null;
  }
}

function completeProbeUninstallIfSucceeded(input: {
  nowMs: number;
  operation: ProbeUpgradeRequest;
  services: ProbeRouteServices;
}) {
  if (
    input.operation.kind !== "probe_uninstall" ||
    input.operation.state !== "succeeded"
  ) {
    return null;
  }

  const deleted = input.services.hosts.softDelete(
    input.operation.hostId,
    input.nowMs,
  );
  if (deleted) {
    return deleted.id;
  }
  return null;
}

function decodeConfigurationRequest(body: Uint8Array): any | null {
  try {
    return ConfigurationRequest.decode(body);
  } catch {
    return null;
  }
}

const probeRequestSignatureNonceTtlMs = 5 * 60 * 1000;
const acceptedProbeRequestClockSkewMs = 5 * 60 * 1000;

type SignedProbeAuthentication =
  | {
      kind: "authenticated";
      host: NonNullable<ReturnType<HostRepository["findByProbeId"]>>;
    }
  | { kind: "invalid" };

function authenticateProbe(
  hosts: HostRepository,
  request: Request,
  body: Uint8Array,
  probeApiOrigin = "http://localhost",
) {
  const signedAuthentication = authenticateSignedProbeRequest(
    hosts,
    request,
    body,
    probeApiOrigin,
  );
  if (signedAuthentication.kind === "authenticated") {
    return signedAuthentication.host;
  }

  return null;
}

function authenticateProbeOperationStatus(
  hosts: HostRepository,
  request: Request,
  body: Uint8Array,
  probeApiOrigin: string | undefined,
  allowDeletedTerminalUninstall: boolean,
) {
  const authentication = authenticateSignedProbeRequest(
    hosts,
    request,
    body,
    probeApiOrigin,
    allowDeletedTerminalUninstall,
  );
  return authentication.kind === "authenticated" ? authentication.host : null;
}

function authenticateSignedProbeRequest(
  hosts: HostRepository,
  request: Request,
  body: Uint8Array,
  probeApiOrigin = "http://localhost",
  includeDeleted = false,
): SignedProbeAuthentication {
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
    return { kind: "invalid" };
  }

  const host = includeDeleted
    ? hosts.findByProbeIdIncludingDeleted(probeId)
    : hosts.findByProbeId(probeId);
  if (!host?.probePublicKeyPem) {
    return { kind: "invalid" };
  }

  const timestampMs = Number(timestamp);
  if (
    !Number.isSafeInteger(timestampMs) ||
    Math.abs(Date.now() - timestampMs) > acceptedProbeRequestClockSkewMs
  ) {
    return { kind: "invalid" };
  }

  if (bodySha256 !== createHash("sha256").update(body).digest("hex")) {
    return { kind: "invalid" };
  }

  const payload = probeRequestSignaturePayload({
    bodySha256,
    method: request.method,
    nonce,
    canonicalOriginPathAndQuery: canonicalOriginPathAndQuery(
      request,
      probeApiOrigin,
    ),
    timestampMs: timestamp,
  });

  if (
    !verifyProbeRequestSignature(host.probePublicKeyPem, payload, signature)
  ) {
    return { kind: "invalid" };
  }

  const nowMs = Date.now();
  if (
    !hosts.insertProbeRequestNonce({
      expiresAtMs: nowMs + probeRequestSignatureNonceTtlMs,
      nonce,
      nowMs,
      probeId,
    })
  ) {
    return { kind: "invalid" };
  }

  return { kind: "authenticated", host };
}

function probeRequestSignaturePayload(input: {
  bodySha256: string;
  canonicalOriginPathAndQuery: string;
  method: string;
  nonce: string;
  timestampMs: string;
}) {
  return [
    input.method.toUpperCase(),
    input.canonicalOriginPathAndQuery,
    input.timestampMs,
    input.nonce,
    input.bodySha256,
  ].join("\n");
}

function canonicalOriginPathAndQuery(request: Request, probeApiOrigin: string) {
  const url = new URL(request.url);
  return `${probeApiOrigin}${url.pathname}${url.search}`;
}

function isIdentityContentEncoding(headers: Headers) {
  const contentEncoding = headers.get("content-encoding");

  return (
    contentEncoding === null ||
    contentEncoding.trim() === "" ||
    contentEncoding.toLowerCase() === "identity"
  );
}

function toArrayBuffer(bytes: Uint8Array) {
  const output = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(output).set(bytes);
  return output;
}
