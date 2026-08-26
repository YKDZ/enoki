import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";

import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";
import { Hono } from "hono";

import { hostProfilePersistenceValues } from "../database/host-profiles.js";
import {
  maxEnrollmentRejectionCodeLength,
  maxEnrollmentRejectionMessageLength,
} from "../enrollment/lifecycle.js";
import { hashSecret } from "../enrollment/routes.js";
import { defaultProbeConfiguration } from "./configuration.js";
import {
  hostProfileCollectorId,
  hostProfileSnapshotFromRegistration,
  snapshotPayloadBranchesMatchCollectorIds,
} from "./host-profile-snapshots.js";
import { validProbePublicKeyPem } from "./probe-identity.js";
import { resolveRegistrationAttempt } from "./registration-attempt.js";
import {
  observedIpFromContext,
  probeJsonError,
  readCappedRequestBody,
} from "./route-http.js";
import type { ProbeRouteServices } from "./route-services.js";

const RegistrationRequest = enoki.v1.ProbeRegistrationRequest as any;
const RegistrationResponse = enoki.v1.ProbeRegistrationResponse as any;
const maxProbeRegistrationPayloadBytes = 256 * 1024;
const enrollmentVerificationTtlMs = 60 * 1000;

type ProtoMessage = Record<string, any>;

type RegistrationDeliveryServices = Pick<
  ProbeRouteServices,
  | "audit"
  | "enrollments"
  | "now"
  | "probeAssetDir"
  | "probeDistributionRootPublicKeyPem"
  | "trustedProxyCidrs"
>;

/**
 * 持有 protobuf registration admission、inspection/rejection 与一次性 Host
 * enrollment 写入，且不依赖 route composition。
 */
export function createProbeRegistrationRoutes(
  services: RegistrationDeliveryServices,
) {
  const routes = new Hono();
  const now = services.now ?? Date.now;

  routes.post("/register", async (context) => {
    if (
      contentLengthExceeds(
        context.req.raw.headers,
        maxProbeRegistrationPayloadBytes,
      )
    ) {
      return probeJsonError("probe_registration_too_large", 413);
    }

    const requestBody = await readCappedRequestBody(
      context.req.raw,
      maxProbeRegistrationPayloadBytes,
    );

    if (!requestBody) {
      return probeJsonError("probe_registration_too_large", 413);
    }

    const request = decodeRegistrationRequest(requestBody);

    if (!request?.enrollmentToken) {
      return probeJsonError("invalid_enrollment_token", 401);
    }

    const installationRejection = registrationInstallationRejection(request);
    if (installationRejection === "invalid") {
      return probeJsonError("malformed_probe_registration", 400);
    }
    const installationInspection = registrationInstallationInspection(request);
    if (installationInspection === "invalid") {
      return probeJsonError("malformed_probe_registration", 400);
    }
    if (installationInspection) {
      const enrollment = services.enrollments.inspectPending({
        nowMs: now(),
        tokenHash: hashSecret(request.enrollmentToken),
      });
      if (!enrollment) {
        return probeJsonError("invalid_enrollment_token", 401);
      }
      const body = RegistrationResponse.encode(
        RegistrationResponse.create({
          installationInspection: {
            targetKind:
              enrollment.targetKind === "new_host"
                ? enoki.v1.ProbeEnrollmentTargetKind.NEW_HOST
                : enrollment.targetKind === "existing_host"
                  ? enoki.v1.ProbeEnrollmentTargetKind.EXISTING_HOST
                  : enoki.v1.ProbeEnrollmentTargetKind.MANUAL_REINSTALL,
            expectedHubOrigin:
              enrollment.targetKind === "manual_reinstall"
                ? enrollment.expectedHubOrigin
                : "",
            enrollmentId:
              enrollment.targetKind === "manual_reinstall"
                ? enrollment.enrollmentId
                : "",
            targetHostId:
              enrollment.targetKind === "manual_reinstall"
                ? String(enrollment.targetHostId)
                : "",
            expectedProbeId:
              enrollment.targetKind === "manual_reinstall"
                ? enrollment.expectedProbeId
                : "",
            sourceProbeVersion:
              enrollment.targetKind === "manual_reinstall"
                ? enrollment.sourceProbeVersion
                : "",
            sourceProbeSha256:
              enrollment.targetKind === "manual_reinstall"
                ? enrollment.sourceProbeSha256
                : [],
            targetAssetSetDigest:
              enrollment.targetKind === "manual_reinstall"
                ? enrollment.targetAssetSetDigest
                : "",
            targetProbeVersion:
              enrollment.targetKind === "manual_reinstall"
                ? enrollment.targetProbeVersion
                : "",
          },
        }),
      ).finish();
      return context.body(toArrayBuffer(body), 200, {
        "cache-control": "no-store",
        "content-type": "application/x-protobuf",
      });
    }
    if (installationRejection) {
      const { existingProbeId, ...rejection } = installationRejection;
      const rejectionResult = services.enrollments.rejectInstallation({
        ...rejection,
        existingProbeId,
        rejectedAtMs: now(),
        tokenHash: hashSecret(request.enrollmentToken),
      });
      if (!rejectionResult) {
        return probeJsonError("invalid_enrollment_token", 401);
      }
      if (rejectionResult.outcome === "rejected") {
        services.audit?.record({
          action: "enrollment.installation_rejected",
          actor: "system",
          details: {
            code: installationRejection.code,
            enrollmentId: rejectionResult.enrollment.enrollmentId,
          },
          occurredAtMs: rejectionResult.enrollment.rejectedAtMs ?? now(),
          outcome: "success",
          subjectId: String(rejectionResult.enrollment.id),
          subjectType: "enrollment_token",
        });
      }
      return context.body(null, 204, { "cache-control": "no-store" });
    }

    const tokenHash = hashSecret(request.enrollmentToken);
    const registrationAttemptResolution = await resolveRegistrationAttempt({
      enrollments: services.enrollments,
      probeAssetDir: services.probeAssetDir,
      probeDistributionRootPublicKeyPem:
        services.probeDistributionRootPublicKeyPem,
      request,
      tokenHash,
    });
    if (registrationAttemptResolution.kind === "invalid") {
      return probeJsonError("invalid_enrollment_token", 401);
    }
    if (registrationAttemptResolution.kind === "replay") {
      return context.body(
        toArrayBuffer(registrationAttemptResolution.outcome),
        200,
        {
          "cache-control": "no-store",
          "content-type": "application/x-protobuf",
        },
      );
    }
    const registrationAttempt =
      registrationAttemptResolution.kind === "accepted"
        ? registrationAttemptResolution.attempt
        : null;

    if (!validProbePublicKeyPem(request.probePublicKeyPem)) {
      return probeJsonError("probe_public_key_required", 400);
    }

    if (!snapshotPayloadBranchesMatchCollectorIds(request)) {
      return probeJsonError("malformed_probe_registration", 400);
    }

    if (!validRegistrationResponsibilities(request)) {
      return probeJsonError("malformed_probe_registration", 400);
    }

    const hostProfileSnapshot = hostProfileSnapshotFromRegistration(request);
    if (
      hostProfileSnapshot?.snapshotHash &&
      hostProfileSnapshot.snapshotHash !== hostProfileSnapshot.canonicalHash
    ) {
      return probeJsonError("snapshot_hash_mismatch", 400);
    }

    const hostProfile = hostProfileSnapshot?.hostProfile ?? null;

    const registeredAtMs = now();
    const hostProfileHash = hostProfileSnapshot?.canonicalHash ?? null;
    const observedIp = observedIpFromContext(
      context,
      services.trustedProxyCidrs,
    );
    const registration = services.enrollments.registerNewHost({
      host: () => {
        const probeId = createProbeId();
        const probeSecretPlaceholder = createProbeSecret();
        return {
          architecture: hostProfile?.architecture || null,
          clockSkewDetected: false,
          connectAddress:
            firstHostProfileAddress(hostProfile) ?? observedIp ?? "",
          createdAtMs: registeredAtMs,
          cpuCount: hostProfile?.cpuCount || null,
          cpuModel: hostProfile?.cpuModel?.trim() || null,
          displayName:
            hostProfile?.hostname?.trim() || fallbackDisplayName(probeId),
          displayNameEdited: false,
          hostname: hostProfile?.hostname || null,
          kernel: hostProfile?.kernel || null,
          lastClockSkewMs: null,
          lastReportAtMs: null,
          memoryTotalBytes: hostProfile?.memoryTotalBytes
            ? Number(hostProfile.memoryTotalBytes)
            : null,
          observedIp,
          probePublicKeyPem: request.probePublicKeyPem,
          os: hostProfile?.os || null,
          probeConfigurationVersion: defaultProbeConfiguration.version,
          probeId,
          probeSecretHash: hashSecret(probeSecretPlaceholder),
          probeVersion: hostProfile?.probeVersion || null,
        };
      },
      hostProfile:
        hostProfile && hostProfileHash
          ? hostProfilePersistenceValues({
              payload: hostProfile,
              snapshotHash: hostProfileHash,
              updatedAtMs: registeredAtMs,
            })
          : null,
      registeredAtMs,
      ...(registrationAttempt
        ? {
            registrationAttempt: {
              ...registrationAttempt,
              outcome: (host: { id: number; probeId: string }) =>
                Buffer.from(
                  RegistrationResponse.encode(
                    RegistrationResponse.create({
                      initialConfiguration: defaultProbeConfiguration,
                      enrollmentId: registrationAttempt.enrollmentId,
                      hostId: String(host.id),
                      probeId: host.probeId,
                      serverTimeMs: registeredAtMs,
                    }),
                  ).finish(),
                ),
            },
          }
        : {}),
      tokenHash,
      verificationDeadlineAtMs: registeredAtMs + enrollmentVerificationTtlMs,
    });

    if (!registration) {
      return probeJsonError("invalid_enrollment_token", 401);
    }

    const body =
      registration.registrationOutcome ??
      RegistrationResponse.encode(
        RegistrationResponse.create({
          initialConfiguration: defaultProbeConfiguration,
          enrollmentId: registration.enrollment.enrollmentId,
          hostId: String(registration.enrollment.hostId),
          probeId: registration.host.probeId,
          serverTimeMs: registeredAtMs,
        }),
      ).finish();

    return context.body(toArrayBuffer(body), 200, {
      "cache-control": "no-store",
      "content-type": "application/x-protobuf",
    });
  });

  return routes;
}

function decodeRegistrationRequest(body: Uint8Array): any | null {
  try {
    return RegistrationRequest.decode(body);
  } catch {
    return null;
  }
}

function registrationInstallationRejection(
  request: ProtoMessage,
):
  | { code: string; existingProbeId: string | null; message: string }
  | "invalid"
  | null {
  const rejection = request.installationRejection;
  if (!rejection) {
    return null;
  }
  if (
    request.installationInspection ||
    request.probePublicKeyPem ||
    (request.snapshots ?? []).length > 0
  ) {
    return "invalid";
  }
  const code = typeof rejection.code === "string" ? rejection.code : "";
  const existingProbeId =
    code === "existing_probe_installation" &&
    validPublicProbeId(rejection.existingProbeId)
      ? rejection.existingProbeId
      : null;
  const message = installationRejectionMessages[code];
  if (
    !message ||
    code.length > maxEnrollmentRejectionCodeLength ||
    message.length > maxEnrollmentRejectionMessageLength
  ) {
    return "invalid";
  }
  return { code, existingProbeId, message };
}

function registrationInstallationInspection(
  request: ProtoMessage,
): "invalid" | { readonly kind: "inspection" } | null {
  if (!request.installationInspection) {
    return null;
  }
  if (
    request.installationRejection ||
    request.probePublicKeyPem ||
    (request.snapshots ?? []).length > 0
  ) {
    return "invalid";
  }
  return { kind: "inspection" };
}

function validPublicProbeId(value: unknown): value is string {
  return typeof value === "string" && /^probe_[A-Za-z0-9_-]{1,90}$/.test(value);
}

const installationRejectionMessages: Record<string, string> = {
  existing_probe_installation: "existing local Probe installation detected",
  probe_bound_to_different_hub:
    "local Probe installation is bound to a different Hub",
  probe_installation_metadata_invalid:
    "local Probe installation metadata is unsafe or incomplete",
};

function validRegistrationResponsibilities(request: ProtoMessage) {
  const snapshots = (request.snapshots ?? []) as ProtoMessage[];

  return (
    snapshots.length === 0 ||
    (snapshots.length === 1 &&
      snapshots[0]?.collectorId === hostProfileCollectorId &&
      Boolean(snapshots[0]?.hostProfile))
  );
}

function createProbeId() {
  return `probe_${randomBytes(16).toString("base64url")}`;
}

function createProbeSecret() {
  return `enk_probe_${randomBytes(32).toString("base64url")}`;
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

function fallbackDisplayName(probeId: string) {
  return probeId.slice(0, 14);
}

function toArrayBuffer(bytes: Uint8Array) {
  const output = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(output).set(bytes);
  return output;
}

function contentLengthExceeds(headers: Headers, maxBytes: number) {
  const contentLength = headers.get("content-length")?.trim();
  return (
    Boolean(contentLength && /^\d+$/.test(contentLength)) &&
    Number(contentLength) > maxBytes
  );
}
