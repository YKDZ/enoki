import {
  createHash,
  createPublicKey,
  createVerify,
  randomBytes,
} from "node:crypto";

import type { HostDetailSample } from "@enoki/api-client/websocket";
import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";
import { getConnInfo } from "@hono/node-server/conninfo";
import { Hono } from "hono";
import type { Context } from "hono";

import type { EnrollmentRepository } from "../database/enrollments.js";
import type {
  HostStatusThresholds,
  HostRepository,
} from "../database/hosts.js";
import type { MetricsRepository } from "../database/metrics.js";
import type { ProbeConfigurationRepository } from "../database/probe-configuration.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import { hashSecret } from "../enrollment/routes.js";
import {
  liveSummaryFromHost,
  type LiveUpdateBroadcaster,
} from "../live-updates.js";
import { defaultProbeConfiguration } from "./configuration.js";
import {
  defaultProbeOperationTokenTtlMs,
  issueProbeOperationToken,
  validateProbeOperationToken,
} from "./operation-token.js";
import {
  acknowledgeProbeUpgradeRequest,
  failReportedProbeUpgradeRequest,
  succeedReportedProbeOperation,
  startProbeUpgradeRequest,
  succeedProbeUpgradeRequestFromInventory,
  type ProbeUpgradeRequest,
} from "./operation.js";

const RegistrationRequest = enoki.v1.ProbeRegistrationRequest as any;
const RegistrationResponse = enoki.v1.ProbeRegistrationResponse as any;
const ReportRequest = enoki.v1.ProbeReportRequest as any;
const ReportResponse = enoki.v1.ProbeReportResponse as any;
const InventoryMessage = enoki.v1.Inventory as any;
const ConfigurationRequest = enoki.v1.ProbeConfigurationRequest as any;
const ConfigurationResponse = enoki.v1.ProbeConfigurationResponse as any;
const maxProbeReportPayloadBytes = 1024 * 1024;
const maxProbeOperationPayloadBytes = 16 * 1024;
const maxReportObservationRange = 10_000;
const defaultClockSkewThresholdMs = 5 * 60 * 1000;
const defaultProbeOperationTokenSecret = randomBytes(32).toString("base64url");

type ProtoMessage = Record<string, any>;

export type ProbeRouteServices = {
  enrollments: EnrollmentRepository;
  hosts: HostRepository;
  metrics: MetricsRepository;
  probeConfigurations: ProbeConfigurationRepository;
  probeOperations?: ProbeOperationRepository;
  clockSkewThresholdMs?: number;
  hostStatus?: HostStatusThresholds;
  liveUpdates?: LiveUpdateBroadcaster | null;
  now?: () => number;
  probeOperationTokenSecret?: string;
  trustForwardedHeaders?: boolean;
};

export function createProbeRoutes(services: ProbeRouteServices) {
  const routes = new Hono();
  const now = services.now ?? Date.now;

  routes.use("*", async (context, next) => {
    if (!isIdentityContentEncoding(context.req.raw.headers)) {
      return probeJsonError("payload_compression_not_supported", 415);
    }

    return next();
  });

  routes.post("/register", async (context) => {
    const request = decodeRegistrationRequest(
      new Uint8Array(await context.req.arrayBuffer()),
    );

    if (!request?.enrollmentToken) {
      return probeJsonError("invalid_enrollment_token", 401);
    }

    if (!validProbePublicKeyPem(request.probePublicKeyPem)) {
      return probeJsonError("probe_public_key_required", 400);
    }

    const registeredAtMs = now();
    const enrollment = services.enrollments.consume(
      hashSecret(request.enrollmentToken),
      registeredAtMs,
    );

    if (!enrollment) {
      return probeJsonError("invalid_enrollment_token", 401);
    }

    const probeId = createProbeId();
    const probeSecretPlaceholder = createProbeSecret();
    const inventory = request.inventory;
    const inventoryJson = inventory ? serializeInventory(inventory) : null;
    const inventoryHash = inventory ? hashInventory(inventory) : null;
    const observedIp = observedIpFromContext(
      context,
      services.trustForwardedHeaders,
    );
    const displayName =
      inventory?.hostname?.trim() || fallbackDisplayName(probeId);

    services.hosts.create({
      architecture: inventory?.architecture || null,
      clockSkewDetected: false,
      connectAddress: firstInventoryAddress(inventory) ?? observedIp ?? "",
      createdAtMs: registeredAtMs,
      cpuCount: inventory?.cpuCount || null,
      cpuModel: inventory?.cpuModel?.trim() || null,
      displayName,
      displayNameEdited: false,
      hostname: inventory?.hostname || null,
      inventoryHash,
      inventoryJson,
      kernel: inventory?.kernel || null,
      lastClockSkewMs: null,
      lastReportAtMs: null,
      memoryTotalBytes: inventory?.memoryTotalBytes
        ? Number(inventory.memoryTotalBytes)
        : null,
      observedIp,
      probePublicKeyPem: request.probePublicKeyPem,
      os: inventory?.os || null,
      probeConfigurationVersion: defaultProbeConfiguration.version,
      probeId,
      probeSecretHash: hashSecret(probeSecretPlaceholder),
      probeVersion: inventory?.probeVersion || null,
    });

    const body = RegistrationResponse.encode(
      RegistrationResponse.create({
        initialConfiguration: defaultProbeConfiguration,
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

    const suppliedInventoryHash = request.inventory
      ? hashInventory(request.inventory)
      : null;

    if (
      request.inventory &&
      request.inventoryHash &&
      request.inventoryHash !== suppliedInventoryHash
    ) {
      return probeJsonError("malformed_probe_report", 400);
    }

    const reportReceivedAtMs = now();
    const operationReportError = applyProbeOperationReports({
      acknowledgements: request.operationAcknowledgements ?? [],
      hostId: host.id,
      nowMs: reportReceivedAtMs,
      services,
      statuses: request.operationStatuses ?? [],
    });

    if (operationReportError) {
      return probeJsonError(operationReportError, 400);
    }

    const inventoryJson = request.inventory
      ? serializeInventory(request.inventory)
      : host.inventoryJson;
    const inventoryHash = suppliedInventoryHash ?? host.inventoryHash;
    const inventoryNeeded =
      !request.inventory &&
      (!request.inventoryHash || request.inventoryHash !== host.inventoryHash);
    const clockSkew = detectClockSkew(
      request.metrics ?? [],
      reportReceivedAtMs,
      services.clockSkewThresholdMs ?? defaultClockSkewThresholdMs,
    );

    const observedIp = observedIpFromContext(
      context,
      services.trustForwardedHeaders,
    );

    services.hosts.recordReport(host.id, {
      architecture: request.inventory?.architecture || undefined,
      clockSkewDetected: clockSkew.detected,
      connectAddress: reportConnectAddress(request.inventory, host, observedIp),
      cpuCount: request.inventory
        ? request.inventory.cpuCount || null
        : undefined,
      cpuModel: request.inventory
        ? request.inventory.cpuModel?.trim() || null
        : undefined,
      hostname: request.inventory?.hostname || undefined,
      inventoryHash,
      inventoryJson,
      kernel: request.inventory?.kernel || undefined,
      lastClockSkewMs: clockSkew.lastDeltaMs,
      lastReportAtMs: reportReceivedAtMs,
      memoryTotalBytes: request.inventory
        ? unsignedNumber(request.inventory.memoryTotalBytes) || null
        : undefined,
      observedIp,
      os: request.inventory?.os || undefined,
      probeConfigurationError: request.probeConfigurationError
        ? {
            errorCode: request.probeConfigurationError.errorCode ?? "",
            failedVersion: request.probeConfigurationError.failedVersion ?? "",
            message: request.probeConfigurationError.message ?? "",
            reportedAtMs: reportReceivedAtMs,
          }
        : null,
      probeVersion: request.inventory?.probeVersion || undefined,
    });
    markProbeUpgradeSucceededFromInventory({
      hostId: host.id,
      nowMs: reportReceivedAtMs,
      probeVersion: request.inventory?.probeVersion,
      services,
    });

    const samplesBySequence = new Map<number, ProtoMessage>(
      ((request.metrics ?? []) as ProtoMessage[]).map((sample) => [
        unsignedNumber(sample.sequence),
        sample,
      ]),
    );
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
            hostId: host.id,
            probeId: host.probeId,
            receivedAtMs: reportReceivedAtMs,
            sequence,
          },
          sample: {
            bootId: request.bootId,
            collectedAtMs: signedNumber(sample.collectedAtMs),
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
                serialNumber: disk.serialNumber || null,
                temperatureCelsius: metricField(disk, "temperatureCelsius"),
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
            hostId: host.id,
            probeId: host.probeId,
            receivedAtMs: reportReceivedAtMs,
            sequence,
          },
        });
      }
    }

    broadcastHostSummary(services, host.id, reportReceivedAtMs);
    for (const sample of detailSamples) {
      services.liveUpdates?.broadcastDetailSample(sample);
    }

    const responseBody = ReportResponse.encode(
      ReportResponse.create({
        acceptedSequenceEnd: validatedReport.sequenceEnd,
        inventoryNeeded,
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

    return context.body(toArrayBuffer(responseBody), 200, {
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

    const result = validateProbeOperationToken({
      nowMs: now(),
      operation,
      probeId: host.probeId,
      secret: probeOperationTokenSecret(services),
      targetProbeVersion: body.targetProbeVersion ?? "",
      token: body.token,
    });

    if (result.error) {
      return probeJsonError(result.error, 403);
    }

    return context.json({ valid: true }, 200, {
      "cache-control": "no-store",
    });
  });

  routes.post("/operations/:operationId/status", async (context) => {
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

    const body = readOperationStatusBody(requestBody);
    if (!body) {
      return probeJsonError("malformed_probe_operation_status", 400);
    }

    const tokenResult = validateProbeOperationToken({
      nowMs: now(),
      operation,
      probeId: host.probeId,
      secret: probeOperationTokenSecret(services),
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
    completeProbeUninstallIfSucceeded({
      nowMs: now(),
      operation: updated,
      services,
    });

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
      operationToken: issueProbeOperationToken({
        expiresAtMs: tokenInput.expiresAtMs,
        operation,
        probeId: tokenInput.probeId,
        secret: tokenInput.secret,
      }),
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
      targetProbeVersion?: unknown;
      token?: unknown;
    };

    if (
      typeof body.token !== "string" ||
      body.token.length === 0 ||
      (Object.hasOwn(body, "targetProbeVersion") &&
        typeof body.targetProbeVersion !== "string")
    ) {
      return null;
    }

    return {
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

function readOperationStatusBody(requestBody: Uint8Array) {
  try {
    const body = JSON.parse(new TextDecoder().decode(requestBody)) as {
      errorCode?: unknown;
      message?: unknown;
      status?: unknown;
      targetProbeVersion?: unknown;
      token?: unknown;
    };

    if (
      typeof body.token !== "string" ||
      body.token.length === 0 ||
      (body.status !== "succeeded" && body.status !== "failed") ||
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
  acknowledgements: ProtoMessage[];
  hostId: number;
  nowMs: number;
  services: ProbeRouteServices;
  statuses: ProtoMessage[];
}): string | null {
  const plan = planProbeOperationReportApplication(input);

  if (plan.error) {
    return plan.error;
  }

  for (const operation of plan.operations) {
    const updated =
      input.services.probeOperations?.updateProbeUpgradeRequest(operation) ??
      operation;
    completeProbeUninstallIfSucceeded({
      nowMs: input.nowMs,
      operation: updated,
      services: input.services,
    });
  }

  return null;
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
  if (stagedOperation) {
    return stagedOperation;
  }

  const active = services.probeOperations?.findActiveForHost(hostId);
  if (active?.id === id) {
    return active;
  }

  const operation = services.probeOperations?.findById(id);
  if (
    operation?.hostId === hostId &&
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
    return;
  }

  input.services.hosts.softDelete(input.operation.hostId, input.nowMs);
}

function markProbeUpgradeSucceededFromInventory(input: {
  hostId: number;
  nowMs: number;
  probeVersion: string | null | undefined;
  services: ProbeRouteServices;
}) {
  if (!input.probeVersion) {
    return;
  }

  const active = input.services.probeOperations?.findActiveForHost(
    input.hostId,
  );
  if (!active) {
    return;
  }

  const succeeded = succeedProbeUpgradeRequestFromInventory({
    nowMs: input.nowMs,
    operation: active,
    probeVersion: input.probeVersion,
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

function broadcastHostSummary(
  services: ProbeRouteServices,
  hostId: number,
  nowMs: number,
) {
  if (!services.liveUpdates) {
    return;
  }

  const hostSummary = services.hosts
    .listSummaries({
      latestMetricForHost: (hostId) =>
        services.metrics.findLatestSample(hostId),
      nowMs,
      probeConfigurationForHost: (hostId) => {
        const effective =
          services.probeConfigurations.getEffectiveForHost(hostId);

        return {
          mode: effective.mode,
          version: effective.configuration.version,
        };
      },
      thresholds: services.hostStatus,
    })
    .find((summary) => summary.id === hostId);

  if (hostSummary) {
    const effectiveConfiguration =
      services.probeConfigurations.getEffectiveForHost(hostId);

    services.liveUpdates.broadcastHostSummary(
      liveSummaryFromHost(hostSummary, {
        metricsCollectionIntervalSeconds:
          effectiveConfiguration.configuration.metricsCollectionIntervalSeconds,
      }),
    );
  }
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
              serialNumber: disk.serialNumber || null,
              temperatureCelsius: metricField(disk, "temperatureCelsius"),
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
) {
  const signedAuthentication = authenticateSignedProbeRequest(
    hosts,
    request,
    body,
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

  const host = hosts.findByProbeId(probeId);
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

  const url = new URL(request.url);
  const payload = probeRequestSignaturePayload({
    bodySha256,
    method: request.method,
    nonce,
    pathAndQuery: `${url.pathname}${url.search}`,
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
  method: string;
  nonce: string;
  pathAndQuery: string;
  timestampMs: string;
}) {
  return [
    input.method.toUpperCase(),
    input.pathAndQuery,
    input.timestampMs,
    input.nonce,
    input.bodySha256,
  ].join("\n");
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
  status: 400 | 401 | 403 | 404 | 413 | 415,
) {
  return new Response(JSON.stringify({ error }), {
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json",
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

function hashInventory(inventory: ProtoMessage) {
  const bytes = InventoryMessage.encode(
    InventoryMessage.create(stableInventory(inventory)),
  ).finish();

  return createHash("sha256").update(bytes).digest("hex");
}

function serializeInventory(inventory: ProtoMessage) {
  return JSON.stringify(
    InventoryMessage.toObject(
      InventoryMessage.create(stableInventory(inventory)),
      {
        longs: String,
      },
    ),
  );
}

function stableInventory(inventory: ProtoMessage): ProtoMessage {
  return {
    ...inventory,
    filesystems: [...(inventory.filesystems ?? [])].sort(
      (left, right) =>
        String(left.mountPoint ?? "").localeCompare(
          String(right.mountPoint ?? ""),
        ) ||
        String(left.filesystemType ?? "").localeCompare(
          String(right.filesystemType ?? ""),
        ),
    ),
    networkInterfaces: [...(inventory.networkInterfaces ?? [])]
      .map((networkInterface) => ({
        ...networkInterface,
        addresses: [...new Set(networkInterface.addresses ?? [])].sort(),
      }))
      .sort((left, right) =>
        String(left.name ?? "").localeCompare(String(right.name ?? "")),
      ),
  };
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
  const sequenceCount = sequenceEnd - sequenceStart + 1;

  if (samples.length === 0 && sequenceCount !== 1) {
    return null;
  }

  if (samples.length > 0 && samples.length !== sequenceCount) {
    return null;
  }

  const sampleSequences = new Set<number>();

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

  return { sequenceEnd, sequenceStart };
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

function firstInventoryAddress(inventory: ProtoMessage | null | undefined) {
  for (const networkInterface of (inventory?.networkInterfaces ??
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

function reportConnectAddress(
  inventory: ProtoMessage | null | undefined,
  host: {
    connectAddress: string;
    observedIp: string | null;
  },
  observedIp: string | null,
) {
  const inventoryAddress = firstInventoryAddress(inventory);
  if (inventoryAddress) {
    return inventoryAddress;
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
  trustForwardedHeaders = false,
) {
  const request = context.req.raw;

  const forwardedAddress = trustForwardedHeaders
    ? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      request.headers.get("x-real-ip")?.trim() ||
      null
    : null;

  return forwardedAddress || directRemoteAddress(context);
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
