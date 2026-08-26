import { createHash, randomBytes } from "node:crypto";

import type { EnrollmentResponse } from "@enoki/api-client";
import { Hono, type Context } from "hono";

import type { AuditRepository } from "../database/audit.js";
import type {
  EnrollmentRepository,
  EnrollmentTarget,
} from "../database/enrollments.js";
import type { HostStatusThresholds } from "../database/hosts.js";
import type { HostRepository } from "../database/hosts.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import { evaluateProbeUpgradeEligibility } from "../probe/asset-set.js";
import { manualProbeReinstallPolicy } from "../probe/manual-reinstall-policy.js";
import {
  readProbeReleaseContextFromDirectory,
  unavailableProbeReleaseContext,
} from "../probe/release-context.js";
import {
  createDefaultInstallationCommandConfig,
  type InstallationCommandConfig,
  renderInstallCommand,
} from "./install-command.js";
import { enrollmentStatusResponse, validEnrollmentId } from "./lifecycle.js";

const enrollmentTokenTtlMs = 1000 * 60 * 15;

export type EnrollmentRouteServices = {
  audit?: AuditRepository;
  enrollments: EnrollmentRepository;
  hostStatus?: HostStatusThresholds;
  hosts?: HostRepository;
  installation?: InstallationCommandConfig;
  now?: () => number;
  probeAssetDir?: string;
  probeDistributionRootPublicKeyPem?: Buffer | string;
  probeOperations?: ProbeOperationRepository;
};

export function createEnrollmentRoutes(services: EnrollmentRouteServices) {
  const routes = new Hono();
  const now = services.now ?? Date.now;
  const installation =
    services.installation ?? createDefaultInstallationCommandConfig();

  routes.post("/", async (context) => {
    const target = await enrollmentTargetFromRequest(context);
    if (!target) {
      return context.json({ error: "invalid_enrollment_target" }, 400);
    }
    return createOwnerEnrollment(context, services, installation, now, target);
  });

  routes.post("/manual-reinstall/:hostId", async (context) => {
    const hostId = positiveInteger(context.req.param("hostId"));
    if (!hostId || !services.hosts) {
      return context.json({ error: "manual_reinstall_unavailable" }, 409);
    }
    const host = services.hosts.findActiveById(hostId);
    if (!host) {
      return context.json({ error: "host_not_found" }, 404);
    }
    const releaseContext = services.probeAssetDir
      ? await readProbeReleaseContextFromDirectory({
          assetDir: services.probeAssetDir,
          trustedRootPublicKeyPem: services.probeDistributionRootPublicKeyPem,
        })
      : unavailableProbeReleaseContext();
    const policy = manualProbeReinstallPolicy({
      eligibility: evaluateProbeUpgradeEligibility({
        probeAssetSetVersion: releaseContext.assetSet.version,
        probeAssetSetVersionNonUpgradeableReason:
          releaseContext.assetSet.nonUpgradeableReason,
        probeVersion: host.probeVersion,
        releaseTransition: releaseContext.releaseTransition,
      }),
      hostLastReportAtMs: host.lastReportAtMs,
      hostProbeVersion: host.probeVersion,
      latestOperation:
        services.probeOperations?.findLatestForHost(hostId) ?? null,
      nowMs: now(),
      offlineAfterMs: services.hostStatus?.offlineAfterMs ?? 90_000,
      sourceProbeSha256:
        releaseContext.releaseTransition?.sourceProbeSha256 ?? [],
      targetAssetSetDigest: releaseContext.assetSet.targetAssetSetDigest,
      targetProbeVersion: releaseContext.assetSet.version,
    });
    if (!policy) {
      return context.json({ error: "manual_reinstall_not_required" }, 409);
    }
    const expectedHubOrigin = installation.probeApiOrigin;
    if (!expectedHubOrigin) {
      return context.json({ error: "manual_reinstall_unavailable" }, 409);
    }
    return createOwnerEnrollment(context, services, installation, now, {
      expectedHubOrigin,
      expectedProbeId: host.probeId,
      expectedProbeVersion: policy.sourceProbeVersion,
      hostId,
      kind: "manual_reinstall",
      sourceProbeSha256: policy.sourceProbeSha256,
      targetAssetSetDigest: policy.targetAssetSetDigest,
      targetProbeVersion: policy.targetProbeVersion,
    });
  });

  routes.get("/:enrollmentId", (context) => {
    const enrollmentId = context.req.param("enrollmentId");
    if (!validEnrollmentId(enrollmentId)) {
      return context.json({ error: "enrollment_not_found" }, 404);
    }

    const enrollment = services.enrollments.readStatus(enrollmentId, now());
    const status = enrollment && enrollmentStatusResponse(enrollment);
    if (!status) {
      return context.json({ error: "enrollment_not_found" }, 404);
    }

    return context.json(status);
  });

  return routes;
}

function createOwnerEnrollment(
  context: Context,
  services: EnrollmentRouteServices,
  installation: InstallationCommandConfig,
  now: () => number,
  target: EnrollmentTarget,
) {
  const createdAtMs = now();
  const expiresAtMs = createdAtMs + enrollmentTokenTtlMs;
  const enrollmentId = createEnrollmentId();
  const enrollmentToken = createEnrollmentToken();
  const creation = services.enrollments.createPending({
    createdAtMs,
    enrollmentId,
    expiresAtMs,
    offlineAfterMs: services.hostStatus?.offlineAfterMs,
    target,
    tokenHash: hashSecret(enrollmentToken),
  });
  if (creation.kind !== "created") {
    return context.json(
      {
        error:
          creation.kind === "existing_host_verifying"
            ? "existing_host_reenrollment_verifying"
            : target.kind === "existing_host"
              ? "existing_host_reenrollment_unavailable"
              : "enrollment_creation_conflict",
      },
      409,
    );
  }
  const row = creation.enrollment;

  services.audit?.record({
    action: "enrollment_token.create",
    actor: "owner",
    details: {
      enrollmentId,
      expiresAtMs,
      target,
    },
    occurredAtMs: createdAtMs,
    outcome: "success",
    subjectId: String(row.id),
    subjectType: "enrollment_token",
    userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
  });

  const status = enrollmentStatusResponse(row);
  if (!status) {
    throw new Error("New Enrollment did not satisfy the lifecycle boundary.");
  }

  const response = {
    ...status,
    enrollmentToken,
    ...renderInstallCommand(installation, {
      enrollmentToken,
      ...(target.kind === "manual_reinstall"
        ? {
            replacementMigration: {
              enrollmentId,
              expectedProbeId: target.expectedProbeId,
              sourceProbeSha256: target.sourceProbeSha256,
              sourceProbeVersion: target.expectedProbeVersion,
              targetAssetSetDigest: target.targetAssetSetDigest,
              targetHostId: String(target.hostId),
              targetProbeVersion: target.targetProbeVersion,
            },
          }
        : {}),
    }),
  } satisfies EnrollmentResponse;

  return context.json(response, 201);
}

async function enrollmentTargetFromRequest(
  context: Context,
): Promise<EnrollmentTarget | null> {
  if (!context.req.header("content-type")?.includes("application/json")) {
    return { kind: "new_host" };
  }
  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    return null;
  }
  const target = (body as { target?: unknown } | null)?.target;
  if (target === undefined) {
    return { kind: "new_host" };
  }
  if (
    typeof target === "object" &&
    target !== null &&
    (target as { kind?: unknown }).kind === "new_host"
  ) {
    return { kind: "new_host" };
  }
  if (
    typeof target === "object" &&
    target !== null &&
    (target as { kind?: unknown }).kind === "existing_host" &&
    Number.isInteger((target as { hostId?: unknown }).hostId) &&
    Number((target as { hostId: number }).hostId) > 0
  ) {
    return {
      hostId: Number((target as { hostId: number }).hostId),
      kind: "existing_host",
    };
  }
  return null;
}

export function hashSecret(secret: string) {
  return createHash("sha256").update(secret).digest("hex");
}

function createEnrollmentToken() {
  return `enk_enroll_${randomBytes(32).toString("base64url")}`;
}

function createEnrollmentId() {
  return `enr_${randomBytes(16).toString("base64url")}`;
}

function positiveInteger(value: string) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}
