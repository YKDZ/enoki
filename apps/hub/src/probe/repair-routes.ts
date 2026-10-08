import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";

import { Hono, type Context } from "hono";

import type { EnrollmentRepository } from "../database/enrollments.js";
import type { HostRepository } from "../database/hosts.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import type { TrustedProxyCidr } from "../network.js";
import { deriveLifecycleAuthorityKey } from "./lifecycle-authority.js";
import {
  createInstalledBundleRepairRequest,
  createProbeRepairRequest,
  type ProbeUpgradeRequest,
} from "./operation.js";
import { readProbeReleaseContextFromDirectory } from "./release-context.js";
import {
  authorizeInstalledBundleRepair,
  authorizeProbeRepair,
  verifyInstalledBundleFailureEvidence,
  verifyProbeRepairEvidence,
  type InstalledBundleFailureEvidence,
  type ProbeRepairEvidence,
} from "./repair-authority.js";
import {
  createMemoryRepairAuthorizationBudget,
  type RepairAuthorizationBudget,
} from "./repair-authorization-budget.js";
import {
  observedIpFromContext,
  parseProbeOperationId,
  probeJsonError,
  readCappedRequestBody,
} from "./route-http.js";

const maxProbeOperationPayloadBytes = 16 * 1024;
const probeRepairAuthorityTtlMs = 60 * 1000;

export type ProbeRepairAuthorizationRouteServices = {
  enrollments: EnrollmentRepository;
  hosts: HostRepository;
  probeOperations?: ProbeOperationRepository;
  now?: () => number;
  probeAssetDir?: string;
  probeDistributionRootPublicKeyPem?: Buffer | string;
  probeApiOrigin?: string;
  repairAuthorizationBudget?: RepairAuthorizationBudget;
  trustedProxyCidrs?: TrustedProxyCidr[];
};

export function createProbeRepairAuthorizationRoutes(
  services: ProbeRepairAuthorizationRouteServices,
) {
  const routes = new Hono();
  const now = services.now ?? Date.now;
  const budget =
    services.repairAuthorizationBudget ??
    createMemoryRepairAuthorizationBudget({ monotonicNow: now });
  const manualReinstallRequired = (context: Context) =>
    context.json({ disposition: "manual_reinstall_required" }, 409, {
      "cache-control": "no-store",
    });
  const anonymousLimit = (context: Context) => {
    const result = budget.consumeAnonymous(
      observedIpFromContext(context, services.trustedProxyCidrs) ?? "unknown",
    );
    return result.accepted
      ? null
      : probeJsonError("probe_repair_rate_limited", 429, {
          "retry-after": String(result.retryAfterSeconds),
        });
  };
  const verifiedHostLimit = (hostId: number) => {
    const result = budget.consumeVerifiedHost(String(hostId));
    return result.accepted
      ? null
      : probeJsonError("probe_repair_rate_limited", 429, {
          "retry-after": String(result.retryAfterSeconds),
        });
  };
  const repairHostBoundary = (probeId: string) => {
    const host = services.hosts.findByProbeId(probeId);
    const hubOrigin = services.probeApiOrigin ?? "";
    const tokenHash = host
      ? services.enrollments.lifecycleAuthorityTokenHashForHost(host.id)
      : null;
    if (!host || !tokenHash || !/^[0-9a-f]{64}$/.test(tokenHash) || !hubOrigin)
      return null;
    return {
      host,
      hubOrigin,
      installKey: deriveLifecycleAuthorityKey(
        Buffer.from(tokenHash, "hex"),
        hubOrigin,
      ),
    };
  };
  const findOrCreateRepair = (
    evidenceSha256: string,
    candidate: ProbeUpgradeRequest | null,
    operationNowMs: number,
  ) => {
    let repair =
      services.probeOperations?.findByRepairEvidenceSha256(evidenceSha256);
    if (repair || !candidate) return repair;
    try {
      repair = services.probeOperations?.renewOrCreateProbeRepairRequest(
        candidate,
        operationNowMs,
      );
    } catch {
      repair =
        services.probeOperations?.findByRepairEvidenceSha256(evidenceSha256);
    }
    return repair;
  };

  routes.post(
    "/runtime-failures/:generation/repair-authorize",
    async (context) => {
      const limited = anonymousLimit(context);
      if (limited) return limited;
      const requestBody = await readCappedRequestBody(
        context.req.raw,
        maxProbeOperationPayloadBytes,
      );
      const body = requestBody
        ? readInstalledBundleRepairAuthorizationBody(requestBody)
        : null;
      const generation = context.req.param("generation");
      const boundary = body ? repairHostBoundary(body.evidence.probeId) : null;
      const host = boundary?.host ?? null;
      if (
        !body ||
        !boundary ||
        !host ||
        !host.probeVersion ||
        generation !== body.evidence.generation
      )
        return manualReinstallRequired(context);

      const { hubOrigin, installKey } = boundary;
      const operationNowMs = now();
      const verified = verifyInstalledBundleFailureEvidence({
        evidence: body.evidence,
        evidenceSignature: body.evidenceSignature,
        expectedBundleVersion: host.probeVersion,
        expectedHubOrigin: hubOrigin,
        expectedHostId: String(host.id),
        expectedProbeId: host.probeId,
        installKey,
        nowMs: operationNowMs,
      });
      if (!verified) return manualReinstallRequired(context);
      if (
        !services.probeAssetDir ||
        !services.probeDistributionRootPublicKeyPem
      )
        return manualReinstallRequired(context);

      const release = await readProbeReleaseContextFromDirectory({
        assetDir: services.probeAssetDir,
        trustedRootPublicKeyPem: services.probeDistributionRootPublicKeyPem,
      });
      const targetAssetSetDigest = release.assetSet.targetAssetSetDigest;
      const transition = release.releaseTransition;
      if (
        release.assetSet.version !== body.evidence.bundleVersion ||
        !targetAssetSetDigest ||
        transition?.targetProbeVersion !== body.evidence.bundleVersion ||
        transition.targetAssetSetDigest !== targetAssetSetDigest ||
        !transition.targetBundles?.some(
          (bundle) =>
            bundle.bundleManifestSha256 === body.evidence.manifestSha256,
        )
      )
        return manualReinstallRequired(context);

      const hostLimited = verifiedHostLimit(host.id);
      if (hostLimited) return hostLimited;
      const repair = findOrCreateRepair(
        verified.repairEvidenceSha256,
        createInstalledBundleRepairRequest({
          authorityExpiresAtMs: operationNowMs + probeRepairAuthorityTtlMs,
          bundleVersion: body.evidence.bundleVersion,
          evidenceSha256: verified.repairEvidenceSha256,
          failureGeneration: body.evidence.generation,
          hostId: host.id,
          manifestSha256: body.evidence.manifestSha256,
          targetAssetSetDigest,
          nonce: randomBytes(16).toString("hex"),
          nowMs: operationNowMs,
        }),
        operationNowMs,
      );
      if (
        !repair ||
        repair.kind !== "probe_repair" ||
        repair.state !== "accepted" ||
        repair.hostId !== host.id ||
        repair.repairEligibilityKind !== "installed_bundle_failure" ||
        repair.repairFailedOperationId != null ||
        repair.repairFailureGeneration !== body.evidence.generation ||
        repair.repairEvidenceSha256 !== verified.repairEvidenceSha256 ||
        !repair.repairNonce ||
        repair.targetAssetSetDigest !== targetAssetSetDigest ||
        !repair.repairAuthorityExpiresAtMs ||
        repair.repairAuthorityExpiresAtMs <= operationNowMs
      )
        return manualReinstallRequired(context);

      const decision = authorizeInstalledBundleRepair({
        authorityExpiresAtMs: repair.repairAuthorityExpiresAtMs,
        evidence: body.evidence,
        evidenceSignature: body.evidenceSignature,
        expectedBundleVersion: host.probeVersion,
        expectedHubOrigin: hubOrigin,
        expectedHostId: String(host.id),
        expectedProbeId: host.probeId,
        installKey,
        nowMs: operationNowMs,
        repairNonce: repair.repairNonce,
        repairOperationId: String(repair.id),
        targetAssetSetDigest,
      });
      if (decision.disposition !== "probe_repair")
        return context.json(decision, 409, { "cache-control": "no-store" });
      return context.json(
        {
          authority: decision.authority,
          signature: decision.signature,
          targetAssetSetDigest,
        },
        200,
        { "cache-control": "no-store" },
      );
    },
  );

  routes.post("/operations/:operationId/repair-authorize", async (context) => {
    const limited = anonymousLimit(context);
    if (limited) return limited;
    const requestBody = await readCappedRequestBody(
      context.req.raw,
      maxProbeOperationPayloadBytes,
    );
    if (!requestBody) return probeJsonError("probe_report_too_large", 413);
    const failedOperationId = parseProbeOperationId(
      context.req.param("operationId"),
    );
    const failedUpgrade =
      failedOperationId === null
        ? null
        : (services.probeOperations?.findById(failedOperationId) ?? null);
    const body = readRepairAuthorizationBody(requestBody);
    const boundary = body ? repairHostBoundary(body.evidence.probeId) : null;
    const host = boundary?.host ?? null;
    if (
      !host ||
      !boundary ||
      String(host.id) !== body?.evidence.hostId ||
      !failedUpgrade ||
      failedUpgrade.hostId !== host.id ||
      failedUpgrade.kind !== "probe_upgrade" ||
      failedUpgrade.state !== "failed" ||
      !failedUpgrade.targetManifestSha256 ||
      !failedUpgrade.verifiedStageSha256 ||
      !failedUpgrade.upgradeAuthoritySha256 ||
      !body
    )
      return manualReinstallRequired(context);

    const { hubOrigin, installKey } = boundary;
    const operationNowMs = now();
    const verified = verifyProbeRepairEvidence({
      evidence: body.evidence,
      evidenceSignature: body.evidenceSignature,
      expectedHubOrigin: hubOrigin,
      expectedProbeId: host.probeId,
      failedUpgrade,
      installKey,
      nowMs: operationNowMs,
      targetManifestSha256: failedUpgrade.targetManifestSha256,
    });
    if (!verified) return manualReinstallRequired(context);
    const hostLimited = verifiedHostLimit(host.id);
    if (hostLimited) return hostLimited;

    const repair = findOrCreateRepair(
      verified.repairEvidenceSha256,
      createProbeRepairRequest({
        authorityExpiresAtMs: operationNowMs + probeRepairAuthorityTtlMs,
        evidenceSha256: verified.repairEvidenceSha256,
        failedOperation: failedUpgrade,
        nonce: randomBytes(16).toString("hex"),
        nowMs: operationNowMs,
        targetManifestSha256: failedUpgrade.targetManifestSha256,
        verifiedStageSha256: failedUpgrade.verifiedStageSha256,
      }),
      operationNowMs,
    );
    if (!repair) {
      const active = services.probeOperations?.findActiveForHost(host.id);
      if (
        active?.kind === "probe_repair" &&
        active.repairFailedOperationId === failedUpgrade.id
      )
        return probeJsonError("probe_repair_still_unresolved", 409);
    } else if (repair.state === "running") {
      return probeJsonError("probe_repair_still_unresolved", 409);
    } else if (repair.state !== "accepted") {
      return probeJsonError("probe_repair_operation_terminal", 409);
    }
    if (
      !repair ||
      repair.kind !== "probe_repair" ||
      repair.hostId !== host.id ||
      repair.repairFailedOperationId !== failedUpgrade.id ||
      repair.repairEvidenceSha256 !== verified.repairEvidenceSha256 ||
      !repair.repairNonce ||
      !repair.repairAuthorityExpiresAtMs ||
      repair.repairAuthorityExpiresAtMs <= operationNowMs ||
      !repair.targetManifestSha256 ||
      !repair.verifiedStageSha256
    )
      return manualReinstallRequired(context);

    const decision = authorizeProbeRepair({
      authorityExpiresAtMs: repair.repairAuthorityExpiresAtMs,
      evidence: body.evidence,
      evidenceSignature: body.evidenceSignature,
      expectedHubOrigin: hubOrigin,
      expectedProbeId: host.probeId,
      failedUpgrade,
      installKey,
      nowMs: operationNowMs,
      repairNonce: repair.repairNonce,
      repairOperationId: String(repair.id),
      targetManifestSha256: repair.targetManifestSha256,
    });
    if (decision.disposition !== "probe_repair")
      return context.json(decision, 409, { "cache-control": "no-store" });
    return context.json(
      { authority: decision.authority, signature: decision.signature },
      200,
      { "cache-control": "no-store" },
    );
  });

  return routes;
}

function readInstalledBundleRepairAuthorizationBody(requestBody: Uint8Array): {
  evidence: InstalledBundleFailureEvidence;
  evidenceSignature: string;
} | null {
  const envelope = readSignedEvidenceEnvelope(requestBody);
  if (!envelope) return null;
  try {
    const evidence = envelope.evidence;
    const stringKeys = [
      "bootId",
      "bundleVersion",
      "generation",
      "hubOrigin",
      "hostId",
      "identityReceiptSha256",
      "installStateSha256",
      "kind",
      "manifestSha256",
      "probeId",
      "requestNonce",
      "unit",
      "unitSha256",
    ];
    const keys = [...stringKeys, "expiresAtMs", "issuedAtMs", "schemaVersion"];
    if (
      Object.keys(evidence).sort().join("\0") !== keys.sort().join("\0") ||
      evidence.kind !== "installed_bundle_failure" ||
      evidence.schemaVersion !== 1 ||
      stringKeys.some((key) => typeof evidence[key] !== "string") ||
      !Number.isSafeInteger(evidence.issuedAtMs) ||
      !Number.isSafeInteger(evidence.expiresAtMs)
    )
      return null;
    return {
      evidence: evidence as InstalledBundleFailureEvidence,
      evidenceSignature: envelope.evidenceSignature,
    };
  } catch {
    return null;
  }
}

function readRepairAuthorizationBody(requestBody: Uint8Array): {
  evidence: ProbeRepairEvidence;
  evidenceSignature: string;
} | null {
  const envelope = readSignedEvidenceEnvelope(requestBody);
  if (!envelope) return null;
  try {
    const evidence = envelope.evidence;
    const stringKeys = [
      "failedAuthoritySha256",
      "failedOperationId",
      "hostId",
      "hubOrigin",
      "journalPhase",
      "journalSha256",
      "probeId",
      "requestNonce",
      "targetAssetSetDigest",
      "targetBundleVersion",
      "targetManifestSha256",
      "verifiedStageSha256",
    ];
    const evidenceKeys = [
      "activatedTargets",
      "finalizedTargets",
      "issuedAtMs",
      "expiresAtMs",
      ...stringKeys,
      "schemaVersion",
    ];
    if (
      Object.keys(evidence).sort().join("\0") !==
        evidenceKeys.sort().join("\0") ||
      evidence.schemaVersion !== 1 ||
      stringKeys.some((key) => typeof evidence[key] !== "string") ||
      !Number.isSafeInteger(evidence.activatedTargets) ||
      !Number.isSafeInteger(evidence.finalizedTargets) ||
      !Number.isSafeInteger(evidence.issuedAtMs) ||
      !Number.isSafeInteger(evidence.expiresAtMs)
    )
      return null;
    return {
      evidence: evidence as ProbeRepairEvidence,
      evidenceSignature: envelope.evidenceSignature,
    };
  } catch {
    return null;
  }
}

type SignedEvidenceEnvelope = {
  evidence: Record<string, unknown>;
  evidenceSignature: string;
};

function readSignedEvidenceEnvelope(
  requestBody: Uint8Array,
): SignedEvidenceEnvelope | null {
  try {
    const body = JSON.parse(new TextDecoder().decode(requestBody)) as Record<
      string,
      unknown
    >;
    if (
      Object.keys(body).sort().join("\0") !==
        ["evidence", "evidenceSignature"].sort().join("\0") ||
      typeof body.evidence !== "object" ||
      body.evidence === null ||
      typeof body.evidenceSignature !== "string" ||
      !/^[0-9a-f]{64}$/.test(body.evidenceSignature)
    )
      return null;
    return {
      evidence: body.evidence as Record<string, unknown>,
      evidenceSignature: body.evidenceSignature,
    };
  } catch {
    return null;
  }
}
