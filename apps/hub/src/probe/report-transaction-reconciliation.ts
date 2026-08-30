import type { HostProfileSnapshot } from "@enoki/api-client/protocol";
import type { HostDetailSample } from "@enoki/api-client/websocket";
import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";

import {
  type SnapshotReplayReceiptWireShape,
  type SnapshotReplayRequestKey,
} from "../database/host-profiles.js";
import { permitsLegacyFullHostProfileObservation } from "./legacy-report-compatibility.js";
import {
  markProbeUpgradeSucceededFromHostProfile,
  pendingProbeOperationForHost,
  reconcileAuthenticatedOperationEvidence,
} from "./report-operation-reconciliation.js";
import {
  ReportBusinessRejection,
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
import type { ProbeRouteServices } from "./route-services.js";
const ReportResponse = enoki.v1.ProbeReportResponse as any;
const defaultClockSkewThresholdMs = 5 * 60 * 1000;

type ProtoMessage = Record<string, any>;

export type ProbeReportTransactionInput = {
  admission: {
    hostProfileSnapshot: {
      canonicalHash: string | null;
      hostProfile: ProtoMessage | null;
      snapshotHash: string | null;
    } | null;
    reportResponsibility:
      | "full_host_profile"
      | "legacy_observation"
      | "observation"
      | "startup";
    validatedReport: {
      cpuResourceCollectionOutcomeReasons: Map<number, number>;
      observationWindowFailureReason: number | null;
      sequenceEnd: number;
      sequenceStart: number;
    };
  };
  host: NonNullable<ReturnType<ProbeRouteServices["hosts"]["findByProbeId"]>>;
  observedIp: string | null;
  reportReceivedAtMs: number;
  request: ProtoMessage;
};

export type ProbeReportTransactionOutcome = {
  detailSamples: HostDetailSample[];
  hostProfileUpdate: HostProfileSnapshot | null;
  hostRemovedIds: number[];
  readyEnrollment: { enrollmentId: string | null } | null;
  reportReceivedAtMs: number;
  responseBody: Uint8Array;
  startupRejection: ReportBusinessRejection | null;
};

export function reconcileProbeReportTransaction(
  input: ProbeReportTransactionInput,
  services: ProbeRouteServices,
): ProbeReportTransactionOutcome {
  const { admission, host, reportReceivedAtMs, request } = input;
  const { hostProfileSnapshot, reportResponsibility, validatedReport } =
    admission;
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
    const hasCurrentReplayOnlyContents = hasSnapshotReplayOnlyContents(request);
    const isFullHostProfileReport =
      reportResponsibility === "full_host_profile" ||
      (reportResponsibility === "startup" &&
        replaySequenceAlreadyAccepted &&
        hasCurrentReplayOnlyContents);
    let isSnapshotReplay = false;
    if (isFullHostProfileReport) {
      const snapshotHash =
        hostProfileSnapshot?.snapshotHash ?? hostProfileSnapshot?.canonicalHash;
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
          reportedProbeVersion: hostProfileSnapshot?.hostProfile?.probeVersion,
          storedProbeVersion: host.probeVersion,
        });
      // Snapshot Replay 必须精确匹配 Hub 请求的 tuple。其 receipt 已存在，
      // 而 recordObservation 是幂等空操作。已完成的 tuple 只接受精确的响应丢失重试。
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
        // v0.1.72 在 boot 开始后发送普通完整 Host Profile Observation。
        // 只有不存在 replay receipt 或 pending request 可将 payload 归类为
        // replay 时，精确 allowlist 才允许该请求。
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
      // 单独提交 Enrollment 的终止 timeout，再在 transaction 后拒绝 report。
      // 这样既保留状态转换，也保证它不会携带任何 report effect。
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
    const reportedHostProfileHash = hostProfileSnapshot?.canonicalHash ?? null;
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
      !reportedHostProfile && !knownHostProfileSnapshot && reportedSnapshotHash
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

    const observedIp = input.observedIp;

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
      probeConfigurationVersion: request.probeConfigurationVersion || undefined,
      probeConfigurationError: request.probeConfigurationError
        ? {
            errorCode: request.probeConfigurationError.errorCode ?? "",
            failedVersion: request.probeConfigurationError.failedVersion ?? "",
            message: request.probeConfigurationError.message ?? "",
            reportedAtMs: reportReceivedAtMs,
          }
        : null,
      probeVersion: reportedHostProfile?.probeVersion || undefined,
      probeAssetBundleVersion: bootBundleVersion ?? undefined,
      probeAssetBundleBootId: bootBundleVersion ? request.bootId : undefined,
      probeAssetBundleProbeId: bootBundleVersion ? request.probeId : undefined,
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

  return services.reportTransaction.run((transactionalServices) =>
    ingestReport({ ...services, ...transactionalServices }),
  );
}
