import { createHash } from "node:crypto";

import type { HostProfileSnapshot } from "@enoki/api-client/protocol";
import type { HostDetailSample } from "@enoki/api-client/websocket";
import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";
import { Hono } from "hono";

import {
  type SnapshotReplayReceiptWireShape,
  type SnapshotReplayRequestKey,
} from "../database/host-profiles.js";
import type { HostRepository } from "../database/hosts.js";
import { broadcastHostSummaryHint } from "../hosts/live-summary.js";
import { defaultProbeOperationTimeouts } from "../hosts/probe-upgrade-timeout.js";
import {
  broadcastHostReadyHint,
  broadcastHostRemovedHint,
} from "../live-updates.js";
import { permitsLegacyFullHostProfileObservation } from "./legacy-report-compatibility.js";
import { verifyProbeRequestSignature } from "./probe-identity.js";
import {
  markProbeUpgradeSucceededFromHostProfile,
  pendingProbeOperationForHost,
  reconcileAuthenticatedOperationEvidence,
} from "./report-operation-reconciliation.js";
import {
  ReportBusinessRejection,
  admitProbeReport,
  decodeReportRequest,
  detectClockSkew,
  hasMetricField,
  hasProducedHostProfile,
  hasSnapshotReplayOnlyContents,
  hostProfileCollectorId,
  isProbeStartupReport,
  liveDetailSampleFromMetricSample,
  metricField,
  metricUnsignedField,
  nonemptyString,
  reportConnectAddress,
  signedNumber,
  sumUnsigned,
  unsignedMetricField,
  unsignedNumber,
  validatedCollectorOutcomes,
} from "./report-validation.js";
import {
  observedIpFromContext,
  probeJsonError,
  readCappedRequestBody,
} from "./route-http.js";
import type { ProbeRouteServices } from "./route-services.js";
const ReportResponse = enoki.v1.ProbeReportResponse as any;
const maxProbeReportPayloadBytes = 1024 * 1024;
const defaultClockSkewThresholdMs = 5 * 60 * 1000;

type ProtoMessage = Record<string, any>;

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
    const { hostProfileSnapshot, reportResponsibility, validatedReport } =
      admission;

    const reportReceivedAtMs = now();
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
      let snapshotReplayWireShape: SnapshotReplayReceiptWireShape | null = null;
      const replaySequenceAlreadyAccepted = services.metrics.hasObservation({
        bootId: request.bootId,
        probeId: request.probeId,
        sequence: validatedReport.sequenceStart,
      });
      const bootStartAlreadyAccepted = services.metrics.hasObservation({
        bootId: request.bootId,
        probeId: request.probeId,
        sequence: 1,
      });
      const hasCurrentReplayOnlyContents =
        hasSnapshotReplayOnlyContents(request);
      const isFullHostProfileReport =
        reportResponsibility === "full_host_profile" ||
        (reportResponsibility === "startup" &&
          replaySequenceAlreadyAccepted &&
          hasCurrentReplayOnlyContents);
      let isSnapshotReplay = false;
      if (isFullHostProfileReport) {
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
        const hasPendingSnapshotReplayRequest =
          services.snapshotCollectors?.hasPendingSnapshotReplayRequest({
            bootId: request.bootId,
            collectorId: hostProfileCollectorId,
            hostId: host.id,
          }) ?? false;
        const pendingLegacyReplayRequest =
          services.snapshotCollectors?.pendingLegacySnapshotReplayRequest(
            replayRequest,
          ) ?? null;
        const replayReceipt =
          services.snapshotCollectors?.snapshotReplayReceipt(replayRequest) ??
          null;
        const hasNoMetrics = (request.metrics ?? []).length === 0;
        const permitsLegacyFullObservation =
          reportResponsibility === "full_host_profile" &&
          permitsLegacyFullHostProfileObservation({
            reportedProbeVersion:
              hostProfileSnapshot?.hostProfile?.probeVersion,
            storedProbeVersion: host.probeVersion,
          });
        // Snapshot Replay must exactly match the tuple the Hub requested. Its
        // receipt already exists, while recordObservation is an idempotent no-op.
        // A fulfilled tuple accepts only its exact lost-response retry.
        if (!services.snapshotCollectors) {
          if (!permitsLegacyFullObservation) {
            throw new ReportBusinessRejection("malformed_probe_report", 400);
          }
        } else if (
          replaySequenceAlreadyAccepted &&
          hasCurrentReplayOnlyContents &&
          replayRequestStatus === "pending"
        ) {
          snapshotReplayToFulfill = replayRequest;
          snapshotReplayWireShape = "current_sequence";
          isSnapshotReplay = true;
        } else if (
          replaySequenceAlreadyAccepted &&
          hasCurrentReplayOnlyContents &&
          replayReceipt?.wireShape === "current_sequence" &&
          replayReceipt.acceptedSnapshotHash === snapshotHash &&
          replayReceipt.key.sequence === replayRequest.sequence
        ) {
          isSnapshotReplay = true;
        } else if (
          replaySequenceAlreadyAccepted &&
          hasNoMetrics &&
          replayReceipt?.wireShape === "legacy_successor" &&
          replayReceipt.acceptedSnapshotHash === snapshotHash &&
          replayReceipt.key.sequence + 1 === replayRequest.sequence &&
          permitsLegacyFullObservation
        ) {
          isSnapshotReplay = true;
        } else if (
          !replaySequenceAlreadyAccepted &&
          hasNoMetrics &&
          pendingLegacyReplayRequest &&
          permitsLegacyFullObservation
        ) {
          snapshotReplayToFulfill = pendingLegacyReplayRequest;
          snapshotReplayWireShape = "legacy_successor";
          isSnapshotReplay = true;
        } else if (
          permitsLegacyFullObservation &&
          bootStartAlreadyAccepted &&
          replayRequestStatus === null &&
          !hasPendingSnapshotReplayRequest &&
          !pendingLegacyReplayRequest &&
          !replayReceipt
        ) {
          // v0.1.72 emitted ordinary full Host Profile Observations after its
          // boot began. The exact allowlist admits them only when no replay
          // receipt or pending request can classify the payload as a replay.
        } else {
          throw new ReportBusinessRejection("malformed_probe_report", 400);
        }
      }
      const reportedEnrollmentId = nonemptyString(request.enrollmentId);
      const reportedEnrollment = reportedEnrollmentId
        ? services.enrollments.readStatus(
            reportedEnrollmentId,
            reportReceivedAtMs,
          )
        : null;
      if (
        reportedEnrollmentId &&
        (!reportedEnrollment || reportedEnrollment.hostId !== host.id)
      ) {
        throw new ReportBusinessRejection("malformed_probe_report", 400);
      }
      if (
        hasProducedHostProfile(request) &&
        !hostProfileSnapshot?.hostProfile &&
        reportedEnrollment?.targetKind === "manual_reinstall" &&
        reportedEnrollment.status === "verifying"
      ) {
        throw new ReportBusinessRejection("malformed_probe_report", 400);
      }
      const startupEnrollment =
        !isSnapshotReplay &&
        (isProbeStartupReport({
          report: validatedReport,
          reportedHostProfile: hostProfileSnapshot?.hostProfile ?? null,
          request,
        }) ||
          (hasProducedHostProfile(request) &&
            Boolean(hostProfileSnapshot?.hostProfile)))
          ? services.enrollments.resolveStartupReport({
              enrollmentId: null,
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

      if (
        reportedEnrollmentId &&
        startupEnrollment &&
        startupEnrollment.enrollment.enrollmentId !== reportedEnrollmentId
      ) {
        throw new ReportBusinessRejection("malformed_probe_report", 400);
      }

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

      if (
        hasProducedHostProfile(request) &&
        !hostProfileSnapshot?.hostProfile &&
        startupEnrollment?.status === "verifying"
      ) {
        throw new ReportBusinessRejection("malformed_probe_report", 400);
      }

      const operationApplication = reconcileAuthenticatedOperationEvidence({
        acknowledgements: request.operationAcknowledgements ?? [],
        hostId: host.id,
        nowMs: reportReceivedAtMs,
        probeId: host.probeId,
        services,
        statuses: request.operationStatuses ?? [],
      });
      if (operationApplication.error) {
        throw new ReportBusinessRejection(operationApplication.error, 400);
      }

      const reportedHostProfile = hostProfileSnapshot?.hostProfile ?? null;
      const reportedHostProfileHash =
        hostProfileSnapshot?.canonicalHash ?? null;
      const reportedSnapshotHash = hostProfileSnapshot?.snapshotHash ?? null;
      const latestForwardOperation =
        services.probeOperations?.findLatestForHost(host.id) ?? null;
      const hostProfileForwardEvidence =
        latestForwardOperation?.kind === "probe_upgrade" &&
        latestForwardOperation.state === "failed" &&
        latestForwardOperation.id !== null
          ? {
              operationId: latestForwardOperation.id,
              reportBootId: request.bootId,
              reportProbeId: request.probeId,
            }
          : null;
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
        (!snapshotReplayWireShape ||
          !reportedHostProfileHash ||
          !services.snapshotCollectors?.fulfillSnapshotReplay({
            ...snapshotReplayToFulfill,
            acceptedSnapshotHash: reportedHostProfileHash,
            acceptedSequence: validatedReport.sequenceStart,
            fulfilledAtMs: reportReceivedAtMs,
            wireShape: snapshotReplayWireShape,
          }))
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
          forwardEvidence: hostProfileForwardEvidence,
          hostId: host.id,
          observedIp,
          payload: reportedHostProfile,
          profileProbeAssetBundleVersion: reportedBundleVersion,
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
          forwardEvidence: hostProfileForwardEvidence,
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

  return routes;
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

function contentLengthExceeds(headers: Headers, maxBytes: number) {
  const contentLength = headers.get("content-length")?.trim();

  if (!contentLength || !/^\d+$/.test(contentLength)) {
    return false;
  }

  return Number(contentLength) > maxBytes;
}

function toArrayBuffer(bytes: Uint8Array) {
  const output = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(output).set(bytes);
  return output;
}
