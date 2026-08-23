import { Buffer } from "node:buffer";
import {
  createHash,
  createPublicKey,
  createVerify,
  randomBytes,
} from "node:crypto";

import type { HostProfileSnapshot } from "@enoki/api-client/protocol";
import type { HostDetailSample } from "@enoki/api-client/websocket";
import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";
import { getConnInfo } from "@hono/node-server/conninfo";
import { Hono } from "hono";
import type { Context } from "hono";

import type { ProbeOperationConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { EnrollmentRepository } from "../database/enrollments.js";
import {
  hostProfilePersistenceValues,
  type SnapshotCollectorStorageRegistry,
  type SnapshotReplayRequestKey,
} from "../database/host-profiles.js";
import type {
  HostStatusThresholds,
  HostRepository,
} from "../database/hosts.js";
import type { ProbeReportTransaction } from "../database/index.js";
import type { MetricsRepository } from "../database/metrics.js";
import type { ProbeConfigurationRepository } from "../database/probe-configuration.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import {
  maxEnrollmentRejectionCodeLength,
  maxEnrollmentRejectionMessageLength,
} from "../enrollment/lifecycle.js";
import { hashSecret } from "../enrollment/routes.js";
import { broadcastHostSummaryHint } from "../hosts/live-summary.js";
import { defaultProbeOperationTimeouts } from "../hosts/probe-upgrade-timeout.js";
import {
  broadcastHostReadyHint,
  broadcastHostRemovedHint,
  type LiveUpdateBroadcaster,
} from "../live-updates.js";
import { deriveObservedIp, type TrustedProxyCidr } from "../network.js";
import { defaultProbeConfiguration } from "./configuration.js";
import {
  canonicalLifecycleUpgradeAuthority,
  deriveLifecycleAuthorityKey,
  signLifecycleUpgradeAuthority,
  type LifecycleUpgradeAuthority,
} from "./lifecycle-authority.js";
import {
  defaultProbeOperationTokenTtlMs,
  issueProbeOperationToken,
  validateProbeOperationToken,
} from "./operation-token.js";
import {
  acknowledgeProbeUpgradeRequest,
  createProbeRepairRequest,
  failReportedProbeUpgradeRequest,
  hasUnavailableProbeUpgradeTarget,
  succeedReportedProbeOperation,
  startProbeUpgradeRequest,
  succeedProbeUpgradeRequestFromHostProfile,
  type ProbeUpgradeRequest,
} from "./operation.js";
import { readProbeReleaseContextFromDirectory } from "./release-context.js";
import {
  authorizeProbeRepair,
  verifyProbeRepairEvidence,
  type ProbeRepairEvidence,
} from "./repair-authority.js";
import {
  createMemoryRepairAuthorizationBudget,
  type RepairAuthorizationBudget,
} from "./repair-authorization-budget.js";

const RegistrationRequest = enoki.v1.ProbeRegistrationRequest as any;
const RegistrationResponse = enoki.v1.ProbeRegistrationResponse as any;
const ReportRequest = enoki.v1.ProbeReportRequest as any;
const ReportResponse = enoki.v1.ProbeReportResponse as any;
const HostProfileSnapshotMessage = enoki.v1.HostProfileSnapshot as any;
const ConfigurationRequest = enoki.v1.ProbeConfigurationRequest as any;
const ConfigurationResponse = enoki.v1.ProbeConfigurationResponse as any;
const hostProfileCollectorId = "official.host-profile";
const maxProbeRegistrationPayloadBytes = 256 * 1024;
const maxProbeReportPayloadBytes = 1024 * 1024;
const maxProbeOperationPayloadBytes = 16 * 1024;
const maxReportObservationRange = 10_000;
const defaultClockSkewThresholdMs = 5 * 60 * 1000;
const enrollmentVerificationTtlMs = 60 * 1000;
const probeRepairAuthorityTtlMs = 60 * 1000;
const defaultProbeOperationTokenSecret = randomBytes(32).toString("base64url");

type ProtoMessage = Record<string, any>;

class ReportBusinessRejection extends Error {
  constructor(
    readonly code: string,
    readonly status: 400 | 409,
  ) {
    super(code);
  }
}

export type ProbeRouteServices = {
  audit?: AuditRepository;
  enrollments: EnrollmentRepository;
  hosts: HostRepository;
  metrics: MetricsRepository;
  probeConfigurations: ProbeConfigurationRepository;
  probeOperations?: ProbeOperationRepository;
  probeOperationTimeouts?: ProbeOperationConfig;
  reportTransaction: ProbeReportTransaction;
  snapshotCollectors?: SnapshotCollectorStorageRegistry;
  clockSkewThresholdMs?: number;
  hostStatus?: HostStatusThresholds;
  liveUpdates?: LiveUpdateBroadcaster | null;
  now?: () => number;
  probeOperationTokenSecret?: string;
  probeAssetDir?: string;
  probeDistributionRootPublicKeyPem?: Buffer | string;
  probeApiOrigin?: string;
  repairAuthorizationBudget?: RepairAuthorizationBudget;
  trustedProxyCidrs?: TrustedProxyCidr[];
};

export function createProbeRoutes(services: ProbeRouteServices) {
  const routes = new Hono();
  const now = services.now ?? Date.now;
  const repairAuthorizationBudget =
    services.repairAuthorizationBudget ??
    createMemoryRepairAuthorizationBudget({ monotonicNow: now });

  routes.use("*", async (context, next) => {
    if (!isIdentityContentEncoding(context.req.raw.headers)) {
      return probeJsonError("payload_compression_not_supported", 415);
    }

    return next();
  });

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
    const probeId = createProbeId();
    const probeSecretPlaceholder = createProbeSecret();
    const hostProfileHash = hostProfileSnapshot?.canonicalHash ?? null;
    const observedIp = observedIpFromContext(
      context,
      services.trustedProxyCidrs,
    );
    const displayName =
      hostProfile?.hostname?.trim() || fallbackDisplayName(probeId);
    const registration = services.enrollments.registerNewHost({
      host: {
        architecture: hostProfile?.architecture || null,
        clockSkewDetected: false,
        connectAddress:
          firstHostProfileAddress(hostProfile) ?? observedIp ?? "",
        createdAtMs: registeredAtMs,
        cpuCount: hostProfile?.cpuCount || null,
        cpuModel: hostProfile?.cpuModel?.trim() || null,
        displayName,
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
      tokenHash: hashSecret(request.enrollmentToken),
      verificationDeadlineAtMs: registeredAtMs + enrollmentVerificationTtlMs,
    });

    if (!registration) {
      return probeJsonError("invalid_enrollment_token", 401);
    }

    const body = RegistrationResponse.encode(
      RegistrationResponse.create({
        initialConfiguration: defaultProbeConfiguration,
        enrollmentId: registration.enrollment.enrollmentId,
        probeId,
        serverTimeMs: registeredAtMs,
      }),
    ).finish();

    return context.body(toArrayBuffer(body), 200, {
      "cache-control": "no-store",
      "content-type": "application/x-protobuf",
    });
  });

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

    const validatedReport = validateReportEnvelope(request);

    if (!validatedReport) {
      return probeJsonError("malformed_probe_report", 400);
    }

    if (!snapshotPayloadBranchesMatchCollectorIds(request)) {
      return probeJsonError("malformed_probe_report", 400);
    }
    if (!hostProfileOutcomeWindowIsCoherent(request)) {
      return probeJsonError("malformed_probe_report", 400);
    }

    const hostProfileSnapshot = hostProfileSnapshotFromReport(request);

    if (
      hostProfileSnapshot?.hostProfile &&
      hostProfileSnapshot.snapshotHash &&
      hostProfileSnapshot.snapshotHash !== hostProfileSnapshot.canonicalHash
    ) {
      return probeJsonError("malformed_probe_report", 400);
    }

    const reportResponsibility = reportResponsibilityFor({
      hostProfileSnapshot,
      report: validatedReport,
      request,
    });
    if (!reportResponsibility) {
      return probeJsonError("malformed_probe_report", 400);
    }

    const reportReceivedAtMs = now();
    const prevalidatedOperations = planProbeOperationReportApplication({
      acknowledgements: request.operationAcknowledgements ?? [],
      hostId: host.id,
      nowMs: reportReceivedAtMs,
      services,
      statuses: request.operationStatuses ?? [],
    });
    if (prevalidatedOperations.error) {
      return probeJsonError(prevalidatedOperations.error, 400);
    }

    const ingestReport = (reportServices: ProbeRouteServices) => {
      const services = reportServices;
      const transactionalHost = services.hosts.findActiveById(host.id);
      if (!transactionalHost) {
        throw new ReportBusinessRejection("probe_identity_required", 400);
      }
      const bootBundleVersion =
        reportResponsibility === "startup"
          ? nonemptyString(request.probeAssetBundleVersion)
          : null;
      const reportedBundleVersion = nonemptyString(
        hostProfileSnapshot?.hostProfile?.probeAssetBundleVersion,
      );
      const storedBootBundleVersion = nonemptyString(
        transactionalHost.probeAssetBundleVersion,
      );
      const currentBootBundleVersion =
        bootBundleVersion ?? storedBootBundleVersion;
      if (
        hostProfileSnapshot?.hostProfile &&
        currentBootBundleVersion &&
        reportedBundleVersion !== currentBootBundleVersion
      ) {
        throw new ReportBusinessRejection("probe_asset_bundle_incoherent", 409);
      }
      let snapshotReplayToFulfill: SnapshotReplayRequestKey | null = null;
      const replaySequenceAlreadyAccepted = services.metrics.hasObservation({
        bootId: request.bootId,
        probeId: request.probeId,
        sequence: validatedReport.sequenceStart,
      });
      const isSnapshotReplay =
        reportResponsibility === "snapshot_replay" ||
        (reportResponsibility === "startup" &&
          replaySequenceAlreadyAccepted &&
          hasSnapshotReplayOnlyContents(request));
      if (isSnapshotReplay) {
        const snapshotHash =
          hostProfileSnapshot?.snapshotHash ??
          hostProfileSnapshot?.canonicalHash;
        if (!snapshotHash) {
          throw new ReportBusinessRejection("malformed_probe_report", 400);
        }
        const replayRequest: SnapshotReplayRequestKey = {
          bootId: request.bootId,
          collectorId: hostProfileCollectorId,
          hostId: host.id,
          sequence: validatedReport.sequenceStart,
          snapshotHash,
        };
        const replayRequestStatus =
          services.snapshotCollectors?.snapshotReplayRequestStatus(
            replayRequest,
          ) ?? null;
        const snapshotAlreadyStored =
          services.snapshotCollectors
            ?.get(hostProfileCollectorId)
            ?.hasSnapshot(host.id, snapshotHash) ?? false;
        // Snapshot Replay must exactly match the tuple the Hub requested. Its
        // receipt already exists, while recordObservation is an idempotent no-op.
        // A fulfilled tuple accepts only its exact lost-response retry.
        // The no-registry path is explicit legacy compatibility for injected
        // route services predating Snapshot Replay request persistence.
        if (services.snapshotCollectors) {
          if (!replaySequenceAlreadyAccepted) {
            throw new ReportBusinessRejection("malformed_probe_report", 400);
          }
          if (replayRequestStatus === "pending") {
            snapshotReplayToFulfill = replayRequest;
          } else if (
            replayRequestStatus !== "fulfilled" ||
            !snapshotAlreadyStored
          ) {
            throw new ReportBusinessRejection("malformed_probe_report", 400);
          }
        }
      }
      const startupEnrollment =
        !isSnapshotReplay &&
        (isProbeStartupReport({
          report: validatedReport,
          reportedHostProfile: hostProfileSnapshot?.hostProfile ?? null,
          request,
        }) ||
          hasProducedHostProfile(request))
          ? services.enrollments.resolveStartupReport({
              enrollmentId: nonemptyString(request.enrollmentId),
              hostId: host.id,
              probeAssetBundleVersion: reportedBundleVersion,
              probeVersion: nonemptyString(
                hostProfileSnapshot?.hostProfile?.probeVersion,
              ),
              producedCurrentHostProfile:
                hasProducedHostProfile(request) &&
                Boolean(hostProfileSnapshot?.hostProfile),
              reportedAtMs: reportReceivedAtMs,
            })
          : null;

      if (startupEnrollment?.status === "rejected") {
        // Commit the Enrollment's terminal timeout by itself, then reject the
        // report after the transaction. This preserves the status transition
        // while guaranteeing that no report effects can accompany it.
        return {
          detailSamples: [] as HostDetailSample[],
          hostProfileUpdate: null,
          hostRemovedIds: [] as number[],
          readyEnrollment: null,
          reportReceivedAtMs,
          responseBody: new Uint8Array(),
          startupRejection: new ReportBusinessRejection(
            "probe_startup_timeout",
            409,
          ),
        };
      }

      const operationPlan = planProbeOperationReportApplication({
        acknowledgements: request.operationAcknowledgements ?? [],
        hostId: host.id,
        nowMs: reportReceivedAtMs,
        services,
        statuses: request.operationStatuses ?? [],
      });
      if (operationPlan.error) {
        throw new ReportBusinessRejection(operationPlan.error, 400);
      }
      const operationApplication = applyProbeOperationReports({
        hostId: host.id,
        nowMs: reportReceivedAtMs,
        operations: operationPlan.operations,
        services,
      });

      if (operationApplication.error) {
        throw new ReportBusinessRejection(operationApplication.error, 400);
      }

      const reportedHostProfile = hostProfileSnapshot?.hostProfile ?? null;
      const reportedHostProfileHash =
        hostProfileSnapshot?.canonicalHash ?? null;
      const reportedSnapshotHash = hostProfileSnapshot?.snapshotHash ?? null;
      const knownHostProfileSnapshot =
        services.snapshotCollectors
          ?.get(hostProfileCollectorId)
          ?.hasSnapshot(host.id, reportedSnapshotHash) ?? false;
      const snapshotReplayRequest =
        !reportedHostProfile &&
        !knownHostProfileSnapshot &&
        reportedSnapshotHash
          ? {
              bootId: request.bootId,
              collectorId: hostProfileCollectorId,
              hostId: host.id,
              requestedAtMs: reportReceivedAtMs,
              sequence: validatedReport.sequenceEnd,
              snapshotHash: reportedSnapshotHash,
            }
          : null;
      const requestedSnapshotCollectorIds = snapshotReplayRequest
        ? [hostProfileCollectorId]
        : [];
      if (snapshotReplayRequest) {
        services.snapshotCollectors?.requestSnapshotReplay({
          ...snapshotReplayRequest,
        });
      }
      const clockSkew = detectClockSkew(
        request.metrics ?? [],
        reportReceivedAtMs,
        services.clockSkewThresholdMs ?? defaultClockSkewThresholdMs,
      );

      const observedIp = observedIpFromContext(
        context,
        services.trustedProxyCidrs,
      );

      services.hosts.recordReport(host.id, {
        architecture: reportedHostProfile?.architecture || undefined,
        clockSkewDetected: clockSkew.detected,
        connectAddress: reportConnectAddress(
          reportedHostProfile,
          host,
          observedIp,
        ),
        cpuCount: reportedHostProfile
          ? reportedHostProfile.cpuCount || null
          : undefined,
        cpuModel: reportedHostProfile
          ? reportedHostProfile.cpuModel?.trim() || null
          : undefined,
        hostname: reportedHostProfile?.hostname || undefined,
        kernel: reportedHostProfile?.kernel || undefined,
        lastClockSkewMs: clockSkew.lastDeltaMs,
        lastReportAtMs: reportReceivedAtMs,
        memoryTotalBytes: reportedHostProfile
          ? unsignedNumber(reportedHostProfile.memoryTotalBytes) || null
          : undefined,
        observedIp,
        os: reportedHostProfile?.os || undefined,
        probeConfigurationVersion:
          request.probeConfigurationVersion || undefined,
        probeConfigurationError: request.probeConfigurationError
          ? {
              errorCode: request.probeConfigurationError.errorCode ?? "",
              failedVersion:
                request.probeConfigurationError.failedVersion ?? "",
              message: request.probeConfigurationError.message ?? "",
              reportedAtMs: reportReceivedAtMs,
            }
          : null,
        probeVersion: reportedHostProfile?.probeVersion || undefined,
        probeAssetBundleVersion: bootBundleVersion ?? undefined,
        probeAssetBundleBootId: bootBundleVersion ? request.bootId : undefined,
        probeAssetBundleProbeId: bootBundleVersion
          ? request.probeId
          : undefined,
      });
      if (
        snapshotReplayToFulfill &&
        !services.snapshotCollectors?.fulfillSnapshotReplay({
          ...snapshotReplayToFulfill,
          fulfilledAtMs: reportReceivedAtMs,
        })
      ) {
        throw new ReportBusinessRejection("malformed_probe_report", 400);
      }
      const samplesBySequence = new Map<number, ProtoMessage>(
        ((request.metrics ?? []) as ProtoMessage[]).map((sample) => [
          unsignedNumber(sample.sequence),
          sample,
        ]),
      );
      const observationWindowFailureReason =
        validatedReport.observationWindowFailureReason;
      const cpuResourceCollectionOutcomeReasons =
        validatedReport.cpuResourceCollectionOutcomeReasons;
      const detailSamples: HostDetailSample[] = [];

      for (
        let sequence = validatedReport.sequenceStart;
        sequence <= validatedReport.sequenceEnd;
        sequence += 1
      ) {
        const sample = samplesBySequence.get(sequence);

        if (sample) {
          const inserted = services.metrics.recordObservationSample({
            observation: {
              bootId: request.bootId,
              cpuResourceCollectionOutcomeReason:
                cpuResourceCollectionOutcomeReasons.get(sequence) ?? null,
              hostId: host.id,
              observationWindowFailureReason,
              probeId: host.probeId,
              receivedAtMs: reportReceivedAtMs,
              sequence,
            },
            sample: {
              bootId: request.bootId,
              collectedAtMs: signedNumber(sample.collectedAtMs),
              collectorOutcomes: validatedCollectorOutcomes(sample),
              cpuCores: ((sample.cpuCores ?? []) as ProtoMessage[]).map(
                (core) => ({
                  idle: unsignedNumber(core.idle),
                  iowait: unsignedNumber(core.iowait),
                  irq: unsignedNumber(core.irq),
                  name: core.name ?? "",
                  nice: unsignedNumber(core.nice),
                  softirq: unsignedNumber(core.softirq),
                  steal: unsignedNumber(core.steal),
                  system: unsignedNumber(core.system),
                  usagePercent: core.usagePercent ?? 0,
                  user: unsignedNumber(core.user),
                }),
              ),
              batteryPercent: metricUnsignedField(sample, "batteryPercent"),
              batteryState: hasMetricField(sample, "batteryState")
                ? sample.batteryState || null
                : null,
              cpuIdlePercent: metricField(sample, "cpuIdlePercent"),
              cpuIowaitPercent: metricField(sample, "cpuIowaitPercent"),
              cpuPercent: metricField(sample, "cpuPercent"),
              cpuStealPercent: metricField(sample, "cpuStealPercent"),
              cpuSystemPercent: metricField(sample, "cpuSystemPercent"),
              cpuUserPercent: metricField(sample, "cpuUserPercent"),
              disks: ((sample.disks ?? []) as ProtoMessage[]).map((disk) => ({
                availableBytes: unsignedNumber(disk.availableBytes),
                filesystemType: disk.filesystemType ?? "",
                ioUtilizationPercent: metricField(disk, "ioUtilizationPercent"),
                mountPoint: disk.mountPoint ?? "",
                readAwaitMs: metricField(disk, "readAwaitMs"),
                readBytesDelta: unsignedNumber(disk.readBytesDelta),
                totalBytes: unsignedNumber(disk.totalBytes),
                usedBytes: unsignedNumber(disk.usedBytes),
                weightedIoPercent: metricField(disk, "weightedIoPercent"),
                writeAwaitMs: metricField(disk, "writeAwaitMs"),
                writeBytesDelta: unsignedNumber(disk.writeBytesDelta),
              })),
              diskHealth: ((sample.diskHealth ?? []) as ProtoMessage[]).map(
                (disk) => ({
                  deviceName: disk.deviceName ?? "",
                  model: disk.model || null,
                  passed: Boolean(disk.passed),
                  powerOnHours: unsignedMetricField(disk, "powerOnHours"),
                  role: disk.role || null,
                  serialNumber: disk.serialNumber || null,
                  temperatureCelsius: metricField(disk, "temperatureCelsius"),
                  totalBytes: unsignedMetricField(disk, "totalBytes"),
                  usageMountPoint: disk.usageMountPoint || null,
                  usedBytes: unsignedMetricField(disk, "usedBytes"),
                }),
              ),
              diskTotalBytes: sample.disks?.length
                ? sumUnsigned(
                    sample.disks as ProtoMessage[],
                    (disk: ProtoMessage) => disk.totalBytes,
                  )
                : null,
              diskUsedBytes: sample.disks?.length
                ? sumUnsigned(
                    sample.disks as ProtoMessage[],
                    (disk: ProtoMessage) => disk.usedBytes,
                  )
                : null,
              load1: metricField(sample, "load_1"),
              load5: metricField(sample, "load_5"),
              load15: metricField(sample, "load_15"),
              hostId: host.id,
              memoryCacheBytes: metricUnsignedField(sample, "memoryCacheBytes"),
              memoryTotalBytes: metricUnsignedField(sample, "memoryTotalBytes"),
              memoryUsedBytes: metricUnsignedField(sample, "memoryUsedBytes"),
              networkInterfaces: (
                (sample.networkInterfaces ?? []) as ProtoMessage[]
              ).map((networkInterface) => ({
                name: networkInterface.name ?? "",
                rxBytes: unsignedNumber(networkInterface.rxBytes),
                rxBytesDelta: unsignedNumber(networkInterface.rxBytesDelta),
                txBytes: unsignedNumber(networkInterface.txBytes),
                txBytesDelta: unsignedNumber(networkInterface.txBytesDelta),
              })),
              networkRxBytesDelta: sample.networkInterfaces?.length
                ? sumUnsigned(
                    sample.networkInterfaces as ProtoMessage[],
                    (networkInterface: ProtoMessage) =>
                      networkInterface.rxBytesDelta,
                  )
                : null,
              networkTxBytesDelta: sample.networkInterfaces?.length
                ? sumUnsigned(
                    sample.networkInterfaces as ProtoMessage[],
                    (networkInterface: ProtoMessage) =>
                      networkInterface.txBytesDelta,
                  )
                : null,
              probeId: host.probeId,
              receivedAtMs: reportReceivedAtMs,
              sequence,
              swapTotalBytes: metricUnsignedField(sample, "swapTotalBytes"),
              swapUsedBytes: metricUnsignedField(sample, "swapUsedBytes"),
              temperatureCelsius: metricField(sample, "temperatureCelsius"),
              uptimeSeconds: metricUnsignedField(sample, "uptimeSeconds"),
            },
          });

          if (inserted) {
            detailSamples.push(
              liveDetailSampleFromMetricSample(
                host.id,
                sample,
                reportReceivedAtMs,
              ),
            );
          }
        } else {
          services.metrics.recordObservationSample({
            observation: {
              bootId: request.bootId,
              cpuResourceCollectionOutcomeReason:
                cpuResourceCollectionOutcomeReasons.get(sequence) ?? null,
              hostId: host.id,
              observationWindowFailureReason,
              probeId: host.probeId,
              receivedAtMs: reportReceivedAtMs,
              sequence,
            },
          });
        }
      }

      const hostProfileObservedAtMs = services.metrics.observationReceivedAtMs({
        bootId: request.bootId,
        probeId: host.probeId,
        sequence: validatedReport.sequenceEnd,
      });
      let hostProfileUpdate: HostProfileSnapshot | null = null;
      if (
        hostProfileObservedAtMs !== null &&
        reportedHostProfile &&
        reportedHostProfileHash
      ) {
        const result = services.snapshotCollectors?.write({
          collectorId: hostProfileCollectorId,
          hostId: host.id,
          observedIp,
          payload: reportedHostProfile,
          snapshotHash: reportedHostProfileHash,
          updatedAtMs: hostProfileObservedAtMs,
        });
        if (result?.changed) {
          hostProfileUpdate = result.view;
        }
      } else if (
        hostProfileObservedAtMs !== null &&
        knownHostProfileSnapshot &&
        reportedSnapshotHash
      ) {
        services.snapshotCollectors?.hostProfile.observe({
          hostId: host.id,
          observedAtMs: hostProfileObservedAtMs,
          snapshotHash: reportedSnapshotHash,
        });
      }
      markProbeUpgradeSucceededFromHostProfile({
        authenticatedProbeId: request.probeId,
        bootEvidenceBootId:
          bootBundleVersion !== null
            ? request.bootId
            : transactionalHost.probeAssetBundleBootId,
        bootEvidenceProbeId:
          bootBundleVersion !== null
            ? request.probeId
            : transactionalHost.probeAssetBundleProbeId,
        bootProbeAssetBundleVersion: currentBootBundleVersion,
        hostId: host.id,
        hostProfile: reportedHostProfile,
        nowMs: reportReceivedAtMs,
        profileReportBootId: request.bootId,
        services,
      });

      const readyEnrollment =
        startupEnrollment?.status === "ready"
          ? startupEnrollment.enrollment
          : null;

      const responseBody = ReportResponse.encode(
        ReportResponse.create({
          acceptedSequenceEnd: validatedReport.sequenceEnd,
          requestedSnapshotCollectorIds,
          currentProbeConfigurationVersion:
            services.probeConfigurations.getEffectiveForHost(host.id)
              .configuration.version,
          pendingOperation: pendingProbeOperationForHost(
            services,
            host.id,
            host.probeId,
            reportReceivedAtMs,
          ),
          serverTimeMs: reportReceivedAtMs,
        }),
      ).finish();

      return {
        detailSamples,
        hostProfileUpdate,
        hostRemovedIds: operationApplication.hostRemovedIds,
        readyEnrollment,
        reportReceivedAtMs,
        responseBody,
        startupRejection: null,
      };
    };

    let ingested: ReturnType<typeof ingestReport>;
    try {
      ingested = services.reportTransaction.run((transactionalServices) =>
        ingestReport({ ...services, ...transactionalServices }),
      );
    } catch (error) {
      if (error instanceof ReportBusinessRejection) {
        return probeJsonError(error.code, error.status);
      }
      throw error;
    }

    if (ingested.startupRejection) {
      return probeJsonError(
        ingested.startupRejection.code,
        ingested.startupRejection.status,
      );
    }

    broadcastHostSummaryHint(services, {
      hostId: host.id,
      nowMs: ingested.reportReceivedAtMs,
      timeouts:
        services.probeOperationTimeouts ?? defaultProbeOperationTimeouts,
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });
    if (ingested.hostProfileUpdate) {
      services.liveUpdates?.broadcastHostProfile(
        host.id,
        ingested.hostProfileUpdate,
      );
    }
    for (const sample of ingested.detailSamples) {
      services.liveUpdates?.broadcastDetailSample(sample);
    }
    if (ingested.readyEnrollment?.enrollmentId) {
      broadcastHostReadyHint(services.liveUpdates, {
        enrollmentId: ingested.readyEnrollment.enrollmentId,
        hostId: host.id,
      });
    }
    for (const removedHostId of ingested.hostRemovedIds) {
      broadcastHostRemovedHint(services.liveUpdates, removedHostId);
    }

    return context.body(toArrayBuffer(ingested.responseBody), 200, {
      "cache-control": "no-store",
      "content-type": "application/x-protobuf",
    });
  });

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

  routes.post("/operations/:operationId/repair-authorize", async (context) => {
    const anonymousBudget = repairAuthorizationBudget.consumeAnonymous(
      observedIpFromContext(context, services.trustedProxyCidrs) ?? "unknown",
    );
    if (!anonymousBudget.accepted) {
      return probeJsonError("probe_repair_rate_limited", 429, {
        "retry-after": String(anonymousBudget.retryAfterSeconds),
      });
    }
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
    const host = body
      ? services.hosts.findByProbeId(body.evidence.probeId)
      : null;
    if (
      !host ||
      String(host.id) !== body?.evidence.hostId ||
      !failedUpgrade ||
      failedUpgrade.hostId !== host.id ||
      failedUpgrade.kind !== "probe_upgrade" ||
      failedUpgrade.state !== "failed" ||
      !failedUpgrade.targetManifestSha256 ||
      !failedUpgrade.verifiedStageSha256 ||
      !failedUpgrade.upgradeAuthoritySha256 ||
      !body
    ) {
      return context.json({ disposition: "manual_reinstall_required" }, 409, {
        "cache-control": "no-store",
      });
    }
    const tokenHash = services.enrollments.lifecycleAuthorityTokenHashForHost(
      host.id,
    );
    const hubOrigin = services.probeApiOrigin ?? "";
    if (!tokenHash || !/^[0-9a-f]{64}$/.test(tokenHash) || !hubOrigin) {
      return context.json({ disposition: "manual_reinstall_required" }, 409, {
        "cache-control": "no-store",
      });
    }
    const installKey = deriveLifecycleAuthorityKey(
      Buffer.from(tokenHash, "hex"),
      hubOrigin,
    );
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
    if (!verified) {
      return context.json({ disposition: "manual_reinstall_required" }, 409, {
        "cache-control": "no-store",
      });
    }
    const hostBudget = repairAuthorizationBudget.consumeVerifiedHost(
      String(host.id),
    );
    if (!hostBudget.accepted) {
      return probeJsonError("probe_repair_rate_limited", 429, {
        "retry-after": String(hostBudget.retryAfterSeconds),
      });
    }

    let repair = services.probeOperations?.findByRepairEvidenceSha256(
      verified.repairEvidenceSha256,
    );
    if (!repair) {
      const candidate = createProbeRepairRequest({
        authorityExpiresAtMs: operationNowMs + probeRepairAuthorityTtlMs,
        evidenceSha256: verified.repairEvidenceSha256,
        failedOperation: failedUpgrade,
        nonce: randomBytes(16).toString("hex"),
        nowMs: operationNowMs,
        targetManifestSha256: failedUpgrade.targetManifestSha256,
        verifiedStageSha256: failedUpgrade.verifiedStageSha256,
      });
      if (!candidate) {
        return context.json({ disposition: "manual_reinstall_required" }, 409, {
          "cache-control": "no-store",
        });
      }
      try {
        repair = services.probeOperations?.renewOrCreateProbeRepairRequest(
          candidate,
          operationNowMs,
        );
      } catch {
        repair = services.probeOperations?.findByRepairEvidenceSha256(
          verified.repairEvidenceSha256,
        );
      }
    }
    if (!repair) {
      const active = services.probeOperations?.findActiveForHost(host.id);
      if (
        active?.kind === "probe_repair" &&
        active.repairFailedOperationId === failedUpgrade.id
      ) {
        return probeJsonError("probe_repair_still_unresolved", 409);
      }
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
    ) {
      return context.json({ disposition: "manual_reinstall_required" }, 409, {
        "cache-control": "no-store",
      });
    }
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
    if (decision.disposition !== "probe_repair") {
      return context.json(decision, 409, { "cache-control": "no-store" });
    }
    return context.json(
      { authority: decision.authority, signature: decision.signature },
      200,
      { "cache-control": "no-store" },
    );
  });

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

    const statusResult =
      body.status === "succeeded"
        ? succeedReportedProbeOperation({
            nowMs: now(),
            operation,
          })
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

function isProbeStartupReport(input: {
  report: { sequenceEnd: number; sequenceStart: number };
  reportedHostProfile: ProtoMessage | null;
  request: ProtoMessage;
}) {
  return (
    input.report.sequenceStart === 1 &&
    input.report.sequenceEnd === 1 &&
    input.reportedHostProfile !== null &&
    (input.request.metrics ?? []).length === 0
  );
}

function isStartupReportShape(
  report: { sequenceEnd: number; sequenceStart: number },
  request: ProtoMessage,
) {
  return (
    report.sequenceStart === 1 &&
    report.sequenceEnd === 1 &&
    (request.metrics ?? []).length === 0 &&
    !request.observationWindowFailure
  );
}

function hasProducedHostProfile(request: ProtoMessage) {
  return ((request.metrics ?? []) as ProtoMessage[]).some((sample) =>
    ((sample.collectorOutcomes ?? []) as ProtoMessage[]).some(
      (outcome) =>
        outcome.collectorId === hostProfileCollectorId &&
        Number(outcome.state) === 1 &&
        !outcome.failure,
    ),
  );
}

function nonemptyString(value: unknown) {
  return typeof value === "string" && value.trim() ? value : null;
}

function pendingProbeOperationForHost(
  services: ProbeRouteServices,
  hostId: number,
  probeId: string,
  nowMs: number,
): ProtoMessage | null {
  const operation = services.probeOperations?.findActiveForHost(hostId);

  if (!operation || operation.state !== "pending") {
    return null;
  }
  if (operation.kind === "probe_upgrade" && !operation.targetAssetSetDigest) {
    return null;
  }

  return probeUpgradeOperationMessage(operation, {
    expiresAtMs: nowMs + defaultProbeOperationTokenTtlMs,
    probeId,
    secret: probeOperationTokenSecret(services),
  });
}

function probeUpgradeOperationMessage(
  operation: ProbeUpgradeRequest,
  tokenInput: {
    expiresAtMs: number;
    probeId: string;
    secret: string;
  },
): ProtoMessage {
  if (operation.kind === "probe_uninstall") {
    return {
      id: String(operation.id),
      probeUninstall: {
        operationToken: issueProbeOperationToken({
          expiresAtMs: tokenInput.expiresAtMs,
          operation,
          probeId: tokenInput.probeId,
          secret: tokenInput.secret,
        }),
      },
    };
  }

  return {
    id: String(operation.id),
    probeUpgrade: {
      currentProbeVersion: operation.currentProbeVersion ?? "",
      hostId: String(operation.hostId),
      operationToken: issueProbeOperationToken({
        expiresAtMs: tokenInput.expiresAtMs,
        operation,
        probeId: tokenInput.probeId,
        secret: tokenInput.secret,
      }),
      targetAssetSetDigest: operation.targetAssetSetDigest ?? "",
      targetManifestSha256: "",
      targetProbeVersion: operation.targetProbeVersion,
    },
  };
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

function readRepairAuthorizationBody(requestBody: Uint8Array): {
  evidence: ProbeRepairEvidence;
  evidenceSignature: string;
} | null {
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
    ) {
      return null;
    }
    const evidence = body.evidence as Record<string, unknown>;
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
    ) {
      return null;
    }
    return {
      evidence: evidence as ProbeRepairEvidence,
      evidenceSignature: body.evidenceSignature,
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

function applyProbeOperationReports(input: {
  hostId: number;
  nowMs: number;
  operations: ProbeUpgradeRequest[];
  services: ProbeRouteServices;
}): { error: string | null; hostRemovedIds: number[] } {
  const hostRemovedIds: number[] = [];
  for (const operation of input.operations) {
    const updated =
      input.services.probeOperations?.updateProbeUpgradeRequest(operation) ??
      operation;
    const removed = completeProbeUninstallIfSucceeded({
      nowMs: input.nowMs,
      operation: updated,
      services: input.services,
    });
    if (removed !== null) {
      hostRemovedIds.push(removed);
    }
  }

  return { error: null, hostRemovedIds };
}

function planProbeOperationReportApplication(input: {
  acknowledgements: ProtoMessage[];
  hostId: number;
  nowMs: number;
  services: ProbeRouteServices;
  statuses: ProtoMessage[];
}):
  | { error: string; operations: [] }
  | {
      error: null;
      operations: ProbeUpgradeRequest[];
    } {
  if (
    !input.services.probeOperations &&
    (input.acknowledgements.length > 0 || input.statuses.length > 0)
  ) {
    return {
      error: "malformed_probe_operation_acknowledgement",
      operations: [],
    };
  }

  const stagedOperations = new Map<number, ProbeUpgradeRequest>();
  const operationsToUpdate = new Map<number, ProbeUpgradeRequest>();

  for (const acknowledgement of input.acknowledgements) {
    const operation = findReportableProbeOperation(
      input.services,
      input.hostId,
      acknowledgement.operationId,
      stagedOperations,
    );

    if (!operation) {
      return {
        error: "malformed_probe_operation_acknowledgement",
        operations: [],
      };
    }

    if (isClosedProbeOperation(operation)) {
      continue;
    }

    const result = acknowledgeProbeUpgradeRequest({
      nowMs: input.nowMs,
      operation,
    });

    if (result.error) {
      return {
        error: "malformed_probe_operation_acknowledgement",
        operations: [],
      };
    }

    if (result.acknowledged !== operation) {
      stageProbeOperationUpdate(
        result.acknowledged,
        stagedOperations,
        operationsToUpdate,
      );
    }
  }

  for (const status of input.statuses) {
    const operation = findReportableProbeOperation(
      input.services,
      input.hostId,
      status.operationId,
      stagedOperations,
    );

    if (!operation) {
      return {
        error: "malformed_probe_operation_status",
        operations: [],
      };
    }

    if (isClosedProbeOperation(operation)) {
      continue;
    }

    const result = applyProbeOperationStatus(status, operation, input.nowMs);

    if (result.error) {
      return {
        error: "malformed_probe_operation_status",
        operations: [],
      };
    }

    if (result.operation !== operation) {
      stageProbeOperationUpdate(
        result.operation,
        stagedOperations,
        operationsToUpdate,
      );
    }
  }

  return {
    error: null,
    operations: [...operationsToUpdate.values()],
  };
}

function stageProbeOperationUpdate(
  operation: ProbeUpgradeRequest,
  stagedOperations: Map<number, ProbeUpgradeRequest>,
  operationsToUpdate: Map<number, ProbeUpgradeRequest>,
) {
  if (operation.id === null) {
    return;
  }

  stagedOperations.set(operation.id, operation);
  operationsToUpdate.set(operation.id, operation);
}

function isClosedProbeOperation(operation: ProbeUpgradeRequest) {
  return ["canceled", "failed", "succeeded", "superseded"].includes(
    operation.state,
  );
}

function findReportableProbeOperation(
  services: ProbeRouteServices,
  hostId: number,
  operationId: string | null | undefined,
  stagedOperations?: Map<number, ProbeUpgradeRequest>,
) {
  const id = parseProbeOperationId(operationId);

  if (id === null) {
    return null;
  }

  const stagedOperation = stagedOperations?.get(id);
  if (stagedOperation && !hasUnavailableProbeUpgradeTarget(stagedOperation)) {
    return stagedOperation;
  }

  const active = services.probeOperations?.findActiveForHost(hostId);
  if (active?.id === id && !hasUnavailableProbeUpgradeTarget(active)) {
    return active;
  }

  const operation = services.probeOperations?.findById(id);
  if (
    operation?.hostId === hostId &&
    !hasUnavailableProbeUpgradeTarget(operation) &&
    ["failed", "superseded", "canceled", "succeeded"].includes(operation.state)
  ) {
    return operation;
  }

  return null;
}

function applyProbeOperationStatus(
  status: ProtoMessage,
  operation: ProbeUpgradeRequest,
  nowMs: number,
) {
  if (status.running && !status.failed) {
    return startProbeUpgradeRequest({
      nowMs,
      operation,
    });
  }

  if (status.failed && !status.running && status.failed.errorCode) {
    return failReportedProbeUpgradeRequest({
      code: status.failed.errorCode,
      message: status.failed.message ?? "",
      nowMs,
      operation,
    });
  }

  if (status.succeeded && !status.running && !status.failed) {
    return succeedReportedProbeOperation({
      nowMs,
      operation,
    });
  }

  return {
    error: "probe_operation_status_invalid" as const,
    operation,
  };
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

function markProbeUpgradeSucceededFromHostProfile(input: {
  authenticatedProbeId: string;
  bootEvidenceBootId: string | null;
  bootEvidenceProbeId: string | null;
  bootProbeAssetBundleVersion: string | null;
  hostId: number;
  hostProfile: {
    probeAssetBundleVersion?: string | null;
    probeVersion?: string | null;
  } | null;
  nowMs: number;
  profileReportBootId: string;
  services: ProbeRouteServices;
}) {
  if (!input.hostProfile?.probeVersion) {
    return;
  }

  const active = input.services.probeOperations?.findActiveForHost(
    input.hostId,
  );
  if (!active) {
    return;
  }

  const succeeded = succeedProbeUpgradeRequestFromHostProfile({
    authenticatedProbeId: input.authenticatedProbeId,
    bootEvidenceBootId: input.bootEvidenceBootId,
    bootEvidenceProbeId: input.bootEvidenceProbeId,
    bootProbeAssetBundleVersion: input.bootProbeAssetBundleVersion,
    hostProfile: input.hostProfile,
    nowMs: input.nowMs,
    operation: active,
    profileReportBootId: input.profileReportBootId,
  });

  if (succeeded) {
    input.services.probeOperations?.updateProbeUpgradeRequest(succeeded);
  }
}

function parseProbeOperationId(operationId: string | null | undefined) {
  if (!operationId || !/^[1-9]\d*$/.test(operationId)) {
    return null;
  }

  return Number(operationId);
}

function liveDetailSampleFromMetricSample(
  hostId: number,
  sample: ProtoMessage,
  receivedAtMs: number,
): HostDetailSample {
  return {
    collectedAtMs: signedNumber(sample.collectedAtMs),
    cpuCores: ((sample.cpuCores ?? []) as ProtoMessage[]).map((core) => ({
      name: core.name ?? "",
      usagePercent: core.usagePercent ?? 0,
    })),
    batteryPercent: metricUnsignedField(sample, "batteryPercent"),
    batteryState: hasMetricField(sample, "batteryState")
      ? sample.batteryState || null
      : null,
    cpuIdlePercent: metricField(sample, "cpuIdlePercent"),
    cpuIowaitPercent: metricField(sample, "cpuIowaitPercent"),
    cpuPercent: metricField(sample, "cpuPercent"),
    cpuStealPercent: metricField(sample, "cpuStealPercent"),
    cpuSystemPercent: metricField(sample, "cpuSystemPercent"),
    cpuUserPercent: metricField(sample, "cpuUserPercent"),
    disks: ((sample.disks ?? []) as ProtoMessage[]).map((disk) => ({
      availableBytes: unsignedNumber(disk.availableBytes),
      filesystemType: disk.filesystemType ?? "",
      ioUtilizationPercent: metricField(disk, "ioUtilizationPercent"),
      mountPoint: disk.mountPoint ?? "",
      readAwaitMs: metricField(disk, "readAwaitMs"),
      readBytesDelta: unsignedNumber(disk.readBytesDelta),
      totalBytes: unsignedNumber(disk.totalBytes),
      usedBytes: unsignedNumber(disk.usedBytes),
      weightedIoPercent: metricField(disk, "weightedIoPercent"),
      writeAwaitMs: metricField(disk, "writeAwaitMs"),
      writeBytesDelta: unsignedNumber(disk.writeBytesDelta),
    })),
    ...(((sample.diskHealth ?? []) as ProtoMessage[]).length
      ? {
          diskHealth: ((sample.diskHealth ?? []) as ProtoMessage[]).map(
            (disk) => ({
              deviceName: disk.deviceName ?? "",
              model: disk.model || null,
              passed: Boolean(disk.passed),
              powerOnHours: unsignedMetricField(disk, "powerOnHours"),
              role: disk.role || null,
              serialNumber: disk.serialNumber || null,
              temperatureCelsius: metricField(disk, "temperatureCelsius"),
              totalBytes: unsignedMetricField(disk, "totalBytes"),
              usageMountPoint: disk.usageMountPoint || null,
              usedBytes: unsignedMetricField(disk, "usedBytes"),
            }),
          ),
        }
      : {}),
    hostId,
    memoryCacheBytes: metricUnsignedField(sample, "memoryCacheBytes"),
    memoryTotalBytes: metricUnsignedField(sample, "memoryTotalBytes"),
    memoryUsedBytes: metricUnsignedField(sample, "memoryUsedBytes"),
    networkInterfaces: ((sample.networkInterfaces ?? []) as ProtoMessage[]).map(
      (networkInterface) => ({
        name: networkInterface.name ?? "",
        rxBytesDelta: unsignedNumber(networkInterface.rxBytesDelta),
        txBytesDelta: unsignedNumber(networkInterface.txBytesDelta),
      }),
    ),
    receivedAtMs,
    sequence: unsignedNumber(sample.sequence),
    swapTotalBytes: metricUnsignedField(sample, "swapTotalBytes"),
    swapUsedBytes: metricUnsignedField(sample, "swapUsedBytes"),
    temperatureCelsius: metricField(sample, "temperatureCelsius"),
    uptimeSeconds: metricUnsignedField(sample, "uptimeSeconds"),
  };
}

function decodeRegistrationRequest(body: Uint8Array): any | null {
  try {
    return RegistrationRequest.decode(body);
  } catch {
    return null;
  }
}

function decodeReportRequest(body: Uint8Array): ProtoMessage | null {
  try {
    return ReportRequest.decode(body) as ProtoMessage;
  } catch {
    return null;
  }
}

function decodeConfigurationRequest(body: Uint8Array): any | null {
  try {
    return ConfigurationRequest.decode(body);
  } catch {
    return null;
  }
}

function hostProfileSnapshotFromRegistration(request: ProtoMessage) {
  const snapshot = ((request.snapshots ?? []) as ProtoMessage[]).find(
    (snapshot) =>
      snapshot.collectorId === hostProfileCollectorId && snapshot.hostProfile,
  );

  if (!snapshot?.hostProfile) {
    return null;
  }

  const snapshotHash =
    typeof snapshot.snapshotHash === "string" && snapshot.snapshotHash.trim()
      ? snapshot.snapshotHash
      : null;

  return {
    canonicalHash: hashHostProfile(snapshot.hostProfile),
    hostProfile: snapshot.hostProfile,
    snapshotHash,
  };
}

function validRegistrationResponsibilities(request: ProtoMessage) {
  const snapshots = (request.snapshots ?? []) as ProtoMessage[];

  return (
    snapshots.length === 0 ||
    (snapshots.length === 1 &&
      snapshots[0]?.collectorId === hostProfileCollectorId &&
      Boolean(snapshots[0]?.hostProfile))
  );
}

function hostProfileSnapshotFromReport(request: ProtoMessage) {
  const snapshot = ((request.snapshots ?? []) as ProtoMessage[]).find(
    (snapshot) => snapshot.collectorId === hostProfileCollectorId,
  );

  if (!snapshot) {
    return null;
  }

  const snapshotHash =
    typeof snapshot.snapshotHash === "string" && snapshot.snapshotHash.trim()
      ? snapshot.snapshotHash
      : null;
  const hostProfile = snapshot.hostProfile ?? null;

  return {
    canonicalHash: hostProfile ? hashHostProfile(hostProfile) : null,
    hostProfile,
    snapshotHash,
  };
}

function snapshotPayloadBranchesMatchCollectorIds(request: ProtoMessage) {
  return ((request.snapshots ?? []) as ProtoMessage[]).every((snapshot) => {
    if (snapshot.hostProfile) {
      return snapshot.collectorId === hostProfileCollectorId;
    }

    return true;
  });
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

function verifyProbeRequestSignature(
  publicKeyPem: string,
  payload: string,
  signature: string,
) {
  try {
    const verifier = createVerify("RSA-SHA256");
    verifier.update(payload);
    verifier.end();
    return verifier.verify(publicKeyPem, Buffer.from(signature, "hex"));
  } catch {
    return false;
  }
}

function validProbePublicKeyPem(publicKeyPem: string | null | undefined) {
  if (!publicKeyPem) {
    return false;
  }

  try {
    const publicKey = createPublicKey(publicKeyPem);
    return (
      publicKey.asymmetricKeyType === "rsa" &&
      (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048
    );
  } catch {
    return false;
  }
}

function isIdentityContentEncoding(headers: Headers) {
  const contentEncoding = headers.get("content-encoding");

  return (
    contentEncoding === null ||
    contentEncoding.trim() === "" ||
    contentEncoding.toLowerCase() === "identity"
  );
}

function contentLengthExceeds(headers: Headers, maxBytes: number) {
  const contentLength = headers.get("content-length")?.trim();

  if (!contentLength || !/^\d+$/.test(contentLength)) {
    return false;
  }

  return Number(contentLength) > maxBytes;
}

async function readCappedRequestBody(request: Request, maxBytes: number) {
  if (!request.body) {
    return new Uint8Array();
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) {
        break;
      }

      totalBytes += value.byteLength;

      if (totalBytes > maxBytes) {
        await reader.cancel();
        return null;
      }

      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;

  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return body;
}

function probeJsonError(
  error: string,
  status: 400 | 401 | 403 | 404 | 409 | 413 | 415 | 429 | 503,
  headers: Record<string, string> = {},
) {
  return new Response(JSON.stringify({ error }), {
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json",
      ...headers,
    },
    status,
  });
}

function createProbeId() {
  return `probe_${randomBytes(16).toString("base64url")}`;
}

function createProbeSecret() {
  return `enk_probe_${randomBytes(32).toString("base64url")}`;
}

function hashHostProfile(hostProfile: ProtoMessage) {
  const bytes = HostProfileSnapshotMessage.encode(
    HostProfileSnapshotMessage.create(stableHostProfile(hostProfile)),
  ).finish();

  return createHash("sha256").update(bytes).digest("hex");
}

function stableHostProfile(hostProfile: ProtoMessage): ProtoMessage {
  const { probeAssetBundleVersion: _bundleVersion, ...stable } = hostProfile;
  return {
    ...stable,
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
  };
}

function compareProtoStrings(left: unknown, right: unknown) {
  return Buffer.compare(
    Buffer.from(String(left ?? ""), "utf8"),
    Buffer.from(String(right ?? ""), "utf8"),
  );
}

function validateReportEnvelope(request: ProtoMessage) {
  const sequenceStart = unsignedNumber(request.sequenceStart);
  const sequenceEnd = unsignedNumber(request.sequenceEnd);

  if (
    !request.bootId ||
    sequenceStart < 1 ||
    sequenceEnd < sequenceStart ||
    sequenceEnd - sequenceStart + 1 > maxReportObservationRange
  ) {
    return null;
  }

  const samples = request.metrics ?? [];
  const observationWindowFailureReason = observationWindowFailureReasonFor(
    request.observationWindowFailure,
  );
  const cpuResourceCollectionOutcomeReasons = new Map<number, number>();
  const cpuResourceCollectionOutcomes =
    (request.cpuResourceCollectionOutcomes as ProtoMessage[] | undefined) ?? [];
  const sequenceCount = sequenceEnd - sequenceStart + 1;

  if (
    request.observationWindowFailure != null &&
    observationWindowFailureReason === null
  ) {
    return null;
  }
  if (
    observationWindowFailureReason !== null &&
    cpuResourceCollectionOutcomes.length > 0
  ) {
    return null;
  }

  if (observationWindowFailureReason !== null && samples.length !== 0) {
    return null;
  }

  if (
    samples.length === 0 &&
    sequenceCount !== 1 &&
    observationWindowFailureReason === null &&
    cpuResourceCollectionOutcomes.length === 0
  ) {
    return null;
  }

  if (samples.length > 0 && samples.length !== sequenceCount) {
    return null;
  }

  const sampleSequences = new Set<number>();

  for (const outcome of cpuResourceCollectionOutcomes) {
    const sequence = unsignedNumber(outcome.sequence);
    const reason = cpuResourceCollectionOutcomeReasonFor(outcome);
    if (
      sequence < sequenceStart ||
      sequence > sequenceEnd ||
      reason === null ||
      cpuResourceCollectionOutcomeReasons.has(sequence)
    ) {
      return null;
    }
    cpuResourceCollectionOutcomeReasons.set(sequence, reason);
  }
  if (
    samples.length === 0 &&
    observationWindowFailureReason === null &&
    cpuResourceCollectionOutcomes.length > 0 &&
    cpuResourceCollectionOutcomeReasons.size !== sequenceCount
  ) {
    return null;
  }

  for (const sample of samples) {
    const sequence = unsignedNumber(sample.sequence);
    const collectedAtMs = signedNumber(sample.collectedAtMs);

    if (
      sequence < sequenceStart ||
      sequence > sequenceEnd ||
      collectedAtMs < 1 ||
      (hasMetricField(sample, "cpuPercent") &&
        !Number.isFinite(sample.cpuPercent))
    ) {
      return null;
    }

    if (sampleSequences.has(sequence)) {
      return null;
    }

    sampleSequences.add(sequence);
  }

  for (
    let sequence = sequenceStart;
    samples.length > 0 && sequence <= sequenceEnd;
    sequence += 1
  ) {
    if (!sampleSequences.has(sequence)) {
      return null;
    }
  }

  return {
    cpuResourceCollectionOutcomeReasons,
    observationWindowFailureReason,
    sequenceEnd,
    sequenceStart,
  };
}

function cpuResourceCollectionOutcomeReasonFor(
  outcome: unknown,
): number | null {
  if (!outcome || typeof outcome !== "object") {
    return null;
  }
  const reason = unsignedNumber((outcome as ProtoMessage).reason);
  return reason >= 1 && reason <= 3 ? reason : null;
}

function observationWindowFailureReasonFor(failure: unknown): number | null {
  if (!failure || typeof failure !== "object") {
    return null;
  }

  const reason = unsignedNumber((failure as ProtoMessage).reason);
  return reason >= 1 && reason <= 3 ? reason : null;
}

function reportResponsibilityFor(input: {
  hostProfileSnapshot: ReturnType<typeof hostProfileSnapshotFromReport>;
  report: { sequenceEnd: number; sequenceStart: number };
  request: ProtoMessage;
}):
  | "legacy_observation"
  | "observation"
  | "snapshot_replay"
  | "startup"
  | null {
  const snapshots = (input.request.snapshots ?? []) as ProtoMessage[];
  const snapshot = input.hostProfileSnapshot;

  // Older Probes predate compact snapshot references. Keep their ordinary
  // Observation Batches compatible, including a legacy sequence-one metrics
  // batch that was never a Probe Startup Report, while requiring current
  // Probes to use the typed constructor shape below.
  if (snapshots.length === 0) {
    return isStartupReportShape(input.report, input.request) &&
      nonemptyString(input.request.probeAssetBundleVersion)
      ? "startup"
      : "legacy_observation";
  }

  if (
    snapshots.length !== 1 ||
    !snapshot ||
    snapshots[0]?.collectorId !== hostProfileCollectorId
  ) {
    return null;
  }

  if (snapshot.hostProfile === null && !snapshot.snapshotHash) {
    return null;
  }

  const isStartup =
    input.report.sequenceStart === 1 && input.report.sequenceEnd === 1;
  if (isStartup) {
    return snapshot.hostProfile !== null &&
      (input.request.metrics ?? []).length === 0 &&
      typeof input.request.probeConfigurationVersion === "string" &&
      input.request.probeConfigurationVersion.length > 0 &&
      !input.request.probeConfigurationError &&
      !input.request.observationWindowFailure
      ? "startup"
      : null;
  }

  if (snapshot.hostProfile !== null) {
    if (hasProducedHostProfile(input.request)) {
      return "observation";
    }
    return hasSnapshotReplayOnlyContents(input.request)
      ? "snapshot_replay"
      : null;
  }

  return "observation";
}

function hasSnapshotReplayOnlyContents(request: ProtoMessage) {
  return (
    (request.metrics ?? []).length === 0 &&
    !request.observationWindowFailure &&
    !request.probeConfigurationError &&
    (request.operationAcknowledgements ?? []).length === 0 &&
    (request.operationStatuses ?? []).length === 0
  );
}

function detectClockSkew(
  samples: ProtoMessage[],
  receivedAtMs: number,
  thresholdMs: number,
) {
  const deltas = samples.map((sample) =>
    Math.abs(receivedAtMs - signedNumber(sample.collectedAtMs)),
  );
  const lastDeltaMs = deltas.length > 0 ? Math.max(...deltas) : null;

  return {
    detected: lastDeltaMs !== null && lastDeltaMs >= thresholdMs,
    lastDeltaMs,
  };
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

const officialOutcomeCollectors = new Set([
  "official.cpu",
  "official.load",
  "official.memory",
  "official.uptime",
  "official.network",
  "official.disk",
  "official.temperature",
  "official.battery",
  "official.disk-health",
  "official.host-profile",
]);

function validatedCollectorOutcomes(sample: ProtoMessage) {
  const seen = new Set<string>();
  return ((sample.collectorOutcomes ?? []) as ProtoMessage[]).map((outcome) => {
    const collectorId = outcome.collectorId ?? "";
    const state = Number(outcome.state ?? 0);
    const failure = outcome.failure as ProtoMessage | null | undefined;
    const failurePhase = failure ? Number(failure.phase ?? 0) : null;
    const encodedFailureCode = failure ? String(failure.code ?? "") : null;
    const legacyFailureCode = failure ? Number(failure.legacyCode ?? 0) : 0;
    const normalizedLegacyFailureCode = legacyCollectorFailureCode(
      collectorId,
      failurePhase,
      legacyFailureCode,
    );
    const failureCode = encodedFailureCode
      ? encodedFailureCode
      : normalizedLegacyFailureCode;
    if (
      !officialOutcomeCollectors.has(collectorId) ||
      seen.has(collectorId) ||
      ![1, 2, 3].includes(state) ||
      (state === 3
        ? ![1, 2].includes(failurePhase ?? 0) ||
          !validCollectorFailureCode(failureCode) ||
          !failureCode?.startsWith(`${collectorId}.`) ||
          (legacyFailureCode !== 0 &&
            normalizedLegacyFailureCode !== failureCode)
        : failure !== null && failure !== undefined)
    ) {
      throw new ReportBusinessRejection("malformed_probe_report", 400);
    }
    seen.add(collectorId);
    return {
      collectorId,
      failureCode,
      failurePhase: failurePhase as 1 | 2 | null,
      state: state as 1 | 2 | 3,
    };
  });
}

function legacyCollectorFailureCode(
  collectorId: string,
  phase: number | null,
  code: number,
): string | null {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10].includes(code)) return null;
  if (code === 1) return `${collectorId}.resource-unavailable`;
  if (code === 2) return `${collectorId}.resource-malformed`;
  if (code === 3) return `${collectorId}.activation-budget-exhausted`;
  if (code === 4 && collectorId === "official.cpu")
    return "official.cpu.counters-malformed";
  if (code === 5 && collectorId === "official.load")
    return "official.load.facts-malformed";
  if (code === 6 && collectorId === "official.memory")
    return "official.memory.facts-malformed";
  if (code === 7 && collectorId === "official.uptime")
    return "official.uptime.facts-malformed";
  if (code === 8 && collectorId === "official.host-profile") {
    return phase === 1
      ? "official.host-profile.resource-malformed"
      : "official.host-profile.facts-malformed";
  }
  if (code === 9 && collectorId === "official.host-profile")
    return "official.host-profile.resource-unavailable";
  if (code === 10 && collectorId === "official.host-profile")
    return "official.host-profile.activation-budget-exhausted";
  return null;
}

function validCollectorFailureCode(code: string | null): code is string {
  return (
    code !== null &&
    code.length >= 3 &&
    code.length <= 96 &&
    /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/.test(code)
  );
}

function hostProfileOutcomeWindowIsCoherent(request: ProtoMessage) {
  const samples = (request.metrics ?? []) as ProtoMessage[];
  const snapshots = ((request.snapshots ?? []) as ProtoMessage[]).filter(
    (snapshot) => snapshot.collectorId === hostProfileCollectorId,
  );
  let outcome: ProtoMessage | undefined;
  for (const [index, sample] of samples.entries()) {
    const matches = ((sample.collectorOutcomes ?? []) as ProtoMessage[]).filter(
      (candidate) => candidate.collectorId === hostProfileCollectorId,
    );
    if (matches.length > 1 || (matches.length === 1 && index !== 0))
      return false;
    outcome ??= matches[0];
  }
  if (!outcome) return true;
  if (Number(outcome.state) === 1 && !outcome.failure) {
    return (
      snapshots.length === 1 &&
      Boolean(snapshots[0]?.snapshotHash) &&
      Boolean(snapshots[0]?.hostProfile) &&
      Boolean(
        nonemptyString(snapshots[0]?.hostProfile?.probeAssetBundleVersion),
      )
    );
  }
  return snapshots.length === 0 && [2, 3].includes(Number(outcome.state));
}

function reportConnectAddress(
  hostProfile: ProtoMessage | null | undefined,
  host: {
    connectAddress: string;
    observedIp: string | null;
  },
  observedIp: string | null,
) {
  const hostProfileAddress = firstHostProfileAddress(hostProfile);
  if (hostProfileAddress) {
    return hostProfileAddress;
  }

  if (!host.connectAddress || host.connectAddress === host.observedIp) {
    return observedIp;
  }

  return undefined;
}

function unsignedNumber(
  value: number | { toNumber: () => number } | null | undefined,
) {
  if (value === null || value === undefined) {
    return 0;
  }

  return typeof value === "number" ? value : value.toNumber();
}

function signedNumber(
  value: number | { toNumber: () => number } | null | undefined,
) {
  return unsignedNumber(value);
}

function metricField(
  sample: object,
  field:
    | "cpuPercent"
    | "cpuUserPercent"
    | "cpuSystemPercent"
    | "cpuIowaitPercent"
    | "cpuStealPercent"
    | "cpuIdlePercent"
    | "ioUtilizationPercent"
    | "load_1"
    | "load_5"
    | "load_15"
    | "readAwaitMs"
    | "temperatureCelsius"
    | "weightedIoPercent"
    | "writeAwaitMs",
) {
  const value = (sample as Record<string, unknown>)[field];

  return hasMetricField(sample, field) && typeof value === "number"
    ? value
    : null;
}

function metricUnsignedField(
  sample: object,
  field:
    | "batteryPercent"
    | "memoryCacheBytes"
    | "memoryTotalBytes"
    | "memoryUsedBytes"
    | "swapTotalBytes"
    | "swapUsedBytes"
    | "uptimeSeconds",
) {
  return hasMetricField(sample, field)
    ? unsignedNumber(
        (sample as Record<string, unknown>)[field] as
          | number
          | { toNumber: () => number }
          | null
          | undefined,
      )
    : null;
}

function unsignedMetricField(sample: object, field: string) {
  return hasMetricField(sample, field)
    ? unsignedNumber(
        (sample as Record<string, unknown>)[field] as
          | number
          | { toNumber: () => number }
          | null
          | undefined,
      )
    : null;
}

function hasMetricField(sample: object, field: string) {
  return Object.prototype.hasOwnProperty.call(sample, field);
}

function sumUnsigned<T>(
  values: T[],
  select: (value: T) => number | { toNumber: () => number } | null | undefined,
) {
  return values.reduce((sum, value) => sum + unsignedNumber(select(value)), 0);
}

function fallbackDisplayName(probeId: string) {
  return probeId.slice(0, 14);
}

function observedIpFromContext(
  context: Context,
  trustedProxyCidrs: TrustedProxyCidr[] | undefined,
) {
  const request = context.req.raw;
  return deriveObservedIp({
    directPeer: directRemoteAddress(context),
    trustedProxyCidrs: trustedProxyCidrs ?? [],
    xForwardedFor: request.headers.get("x-forwarded-for"),
  });
}

function directRemoteAddress(context: Context) {
  try {
    return normalizeRemoteAddress(getConnInfo(context).remote.address);
  } catch {
    return null;
  }
}

function normalizeRemoteAddress(address: string | undefined) {
  if (!address) {
    return null;
  }

  return address.startsWith("::ffff:") ? address.slice(7) : address;
}

function toArrayBuffer(bytes: Uint8Array) {
  const output = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(output).set(bytes);
  return output;
}
