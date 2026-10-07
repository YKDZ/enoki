import { createHash } from "node:crypto";
import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  request,
  type Server,
  type ServerResponse,
} from "node:http";

import { enoki } from "../packages/proto/src/generated/ts/enoki_pb.js";
import {
  hostProfileCollectorId,
  type RepairClosureCapture,
} from "./release-repair-closure-evidence.ts";

const ReportRequest = enoki.v1.ProbeReportRequest;
const ReportResponse = enoki.v1.ProbeReportResponse;
const maxProbeReportPayloadBytes = 1024 * 1024;
const reportPath = "/api/probe/report";
// 正式 CLI 通过既有修复授权响应取得非秘密的 Repair Operation 绑定；这里只缓冲同一
// 请求与真实 Hub 响应，不记录响应里的授权秘密。
const repairAuthorizationPath =
  /^\/api\/probe\/runtime-failures\/([0-9a-f]{64})\/repair-authorize$/;
const maxRepairAuthorizationPayloadBytes = 16 * 1024;
// Hub 判定 Produced 当前主机概况的既有产品条件：official.host-profile 的 Collector
// Outcome 处于 Produced 状态且没有失败。验收层只按同一形状观测，不复制结案算法。
const producedCollectorOutcomeState = 1;
const probeBundleVersionPattern =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const reportedIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;

type NumericLike =
  | number
  | string
  | bigint
  | { toString(): string }
  | null
  | undefined;

type ProbeReportRequestMessage = InstanceType<typeof ReportRequest>;
type ProbeReportResponseMessage = InstanceType<typeof ReportResponse>;

type CanonicalReportProjection = {
  body: Buffer;
  bootId: string;
  bytes: number;
  collectionOutcomeCount: number;
  enrollmentId: string;
  failureReason: number;
  hostProfile: HostProfileProjection | null;
  metricsCount: number;
  payloadSha256: string;
  probeAssetBundleVersion: string;
  probeConfigurationVersion: string;
  probeId: string;
  producedHostProfile: boolean;
  sequenceEnd: number;
  sequenceStart: number;
};

type HostProfileProjection = {
  architecture: string;
  cpuCount: number;
  hostname: string;
  kernel: string;
  os: string;
  probeAssetBundleVersion: string;
  probeVersion: string;
  snapshotHash: string;
};

type ClosureObservation =
  | { kind: "final-boot"; projected: CanonicalReportProjection }
  | { kind: "produced-profile"; projected: CanonicalReportProjection }
  | null;

type ArmedRepairClosure = {
  authorization: RepairClosureCapture["repairAuthorization"];
  expectedProbeId: string;
  failedWindows: RepairClosureCapture["failedWindows"];
  finalBoot: RepairClosureCapture["finalBoot"];
  producedProfile: RepairClosureCapture["producedProfile"];
};

type BootResponseEvidence = {
  acceptedSequenceEnd: number;
  currentConfigurationVersion: string;
  pendingOperation: "absent" | "present";
  requestedSnapshotCollectorIdsCount: number;
  responseSha256: string;
};

type FailureResponseEvidence = {
  acceptedSequenceEnd: number;
  responseSha256: string;
  upstreamStatus: number;
};

type ArmedCanonicalReport = {
  boot: CanonicalReportProjection | null;
  bootResponse: BootResponseEvidence | null;
  expectedProbeId: string | undefined;
  failure: CanonicalReportProjection | null;
  firstFailureResponse?: FailureResponseEvidence | null;
};

export type CanonicalReportEvidence = {
  bootId: string;
  bootReport: {
    acceptedSequenceEnd: number;
    bytes: number;
    payloadSha256: string;
    reconciliation: {
      currentProbeConfigurationVersion: string;
      pendingOperation: string;
      requestedSnapshotCollectorIdsCount: number;
    };
    responseDelivered: true;
    responseSha256: string;
    sequence: number;
    upstreamStatus: number;
  };
  failureReport: {
    attempts: {
      acceptedSequenceEnd: number;
      response: string;
      responseSha256: string;
      upstreamStatus: number;
    }[];
    bytes: number;
    collectionOutcomeCount: number;
    metricsCount: number;
    payloadSha256: string;
    probeConfigurationVersion: string;
    reason: string;
    retryPayloadSha256: string;
    sequence: number;
  };
  kind: string;
  receiptConvergence: {
    contract: string;
    key: { bootId: string; probeId: string; sequence: number };
    requestAttemptCount: number;
    uniquePayloadCount: number;
  };
  probeId: string;
  schemaVersion: number;
};

type Observation =
  | { kind: "invalid" }
  | {
      kind: "boot" | "first-failure" | "retry";
      projected: CanonicalReportProjection;
    }
  | null;

type CodedError = Error & { code?: string };

export function createCanonicalReportEvidenceTransport({
  fetch: fetch_ = globalThis.fetch,
  listenUrl,
  upstreamUrl,
}: {
  fetch?: typeof globalThis.fetch;
  listenUrl: string;
  upstreamUrl: string;
}) {
  const listen = validatedHttpOrigin(listenUrl, "listen");
  const upstream = validatedHttpOrigin(upstreamUrl, "upstream");
  if (listen.origin === upstream.origin && listen.port !== "0") {
    throw new Error(
      "canonical report evidence transport requires distinct listen and upstream origins",
    );
  }
  let armed: ArmedCanonicalReport | null = null;
  let completedEvidence: CanonicalReportEvidence | null = null;
  let failure: CodedError | null = null;
  let closure: ArmedRepairClosure | null = null;
  let completedClosure: RepairClosureCapture | null = null;
  let closureFailure: CodedError | null = null;
  let server: Server | null = null;
  let reportRequestCount = 0;
  let lastUpstreamStatus: number | null = null;
  const waiters = new Set<() => void>();

  function notify() {
    for (const waiter of waiters) waiter();
    waiters.clear();
  }

  async function handle(incoming: IncomingMessage, outgoing: ServerResponse) {
    try {
      const target = new URL(incoming.url ?? "/", upstream);
      const isReport =
        incoming.method === "POST" && target.pathname === reportPath;
      const authorization =
        incoming.method === "POST"
          ? repairAuthorizationPath.exec(target.pathname)
          : null;
      if (!isReport && !authorization) {
        streamTransparent(incoming, outgoing, target);
        return;
      }
      const maxPayloadBytes = isReport
        ? maxProbeReportPayloadBytes
        : maxRepairAuthorizationPayloadBytes;
      if (contentLengthExceeds(incoming.headers, maxPayloadBytes)) {
        if (isReport) rejectOversizedReport(incoming, outgoing);
        else rejectOversizedAuthorization(incoming, outgoing);
        return;
      }
      const body = await readCappedBody(incoming, maxPayloadBytes);
      if (!body) {
        if (isReport) rejectOversizedReport(incoming, outgoing);
        else rejectOversizedAuthorization(incoming, outgoing);
        return;
      }
      const headers = forwardedHeaders(incoming.headers, body.byteLength);
      const activeArmed =
        isReport && !completedEvidence && !failure ? armed : null;
      const activeClosure =
        !completedClosure && !closureFailure ? closure : null;
      const projected =
        isReport && (activeArmed !== null || activeClosure !== null)
          ? decodeReport(body, activeArmed !== null)
          : null;
      const observation =
        activeArmed && projected
          ? observeReport(activeArmed, body, projected)
          : null;
      const closureObservation =
        isReport && activeClosure && projected
          ? observeClosureReport(activeClosure, projected)
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
      if (!isReport && authorization && activeClosure) {
        recordRepairAuthorization(
          activeClosure,
          authorization[1] ?? "",
          body,
          response.status,
          responseBody,
        );
      }
      if (!isReport) {
        writeResponse(outgoing, response, responseBody);
        return;
      }
      if (activeClosure && closureObservation) {
        acceptClosureObservation(
          activeClosure,
          closureObservation,
          response.status,
          responseBody,
        );
      }
      const disposition =
        activeArmed && observation
          ? acceptUpstreamObservation(
              activeArmed,
              observation,
              response.status,
              responseBody,
            )
          : "deliver";
      if (disposition === "drop") {
        outgoing.destroy();
        return;
      }
      writeResponse(outgoing, response, responseBody);
    } catch (error) {
      if (!outgoing.destroyed)
        outgoing.destroy(
          error instanceof Error ? error : new Error(String(error)),
        );
    }
  }

  function decodeReport(
    body: Buffer,
    reportIsArmed: boolean,
  ): CanonicalReportProjection | null {
    try {
      return projectReport(ReportRequest.decode(body), body);
    } catch (error) {
      const message = `canonical report payload could not be decoded: ${errorText(error)}`;
      if (reportIsArmed) fail(message);
      else closureFail(message);
      return null;
    }
  }

  function observeReport(
    armed: ArmedCanonicalReport,
    body: Buffer,
    projected: CanonicalReportProjection,
  ): Observation {
    if (projected.probeId !== armed.expectedProbeId) return null;

    if (!armed.boot) {
      if (projected.sequenceStart !== 1 || projected.sequenceEnd !== 1) {
        return null;
      }
      const invalidBoot =
        projected.metricsCount !== 0 ||
        projected.collectionOutcomeCount !== 0 ||
        projected.failureReason !== 0 ||
        !probeBundleVersionPattern.test(projected.probeAssetBundleVersion);
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

  function acceptUpstreamObservation(
    armed: ArmedCanonicalReport,
    observation: NonNullable<Observation>,
    status: number,
    responseBody: Buffer,
  ): "deliver" | "drop" {
    if (!observation || observation.kind === "invalid") return "deliver";
    if (status !== 200) {
      fail(
        `canonical ${observationLabel(observation.kind)} upstream returned ${status}`,
      );
      return "deliver";
    }
    let response: ProbeReportResponseMessage;
    try {
      response = ReportResponse.decode(responseBody);
    } catch (error) {
      fail(`canonical Hub response could not be decoded: ${errorText(error)}`);
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

  function rejectOversizedReport(
    incoming: IncomingMessage,
    outgoing: ServerResponse,
  ) {
    fail(
      "canonical report payload exceeded the production 1 MiB limit",
      "canonical_report_payload_too_large",
    );
    incoming.destroy();
    if (!outgoing.destroyed) outgoing.destroy();
  }

  function rejectOversizedAuthorization(
    incoming: IncomingMessage,
    outgoing: ServerResponse,
  ) {
    closureFail(
      "repair closure authority payload exceeded the production 16 KiB limit",
      "repair_closure_payload_too_large",
    );
    incoming.destroy();
    if (!outgoing.destroyed) outgoing.destroy();
  }

  function observeClosureReport(
    armed: ArmedRepairClosure,
    projected: CanonicalReportProjection,
  ): ClosureObservation {
    if (projected.probeId !== armed.expectedProbeId) return null;
    if (projected.failureReason !== 0) {
      recordFailedWindow(armed, projected);
      return null;
    }
    const isFinalBoot =
      armed.authorization !== null &&
      armed.finalBoot === null &&
      projected.sequenceStart === 1 &&
      projected.sequenceEnd === 1 &&
      projected.metricsCount === 0 &&
      projected.collectionOutcomeCount === 0 &&
      probeBundleVersionPattern.test(projected.probeAssetBundleVersion);
    if (isFinalBoot) return { kind: "final-boot", projected };
    const isProducedProfile =
      armed.finalBoot !== null &&
      armed.producedProfile === null &&
      projected.bootId === armed.finalBoot.bootId &&
      projected.hostProfile !== null &&
      projected.producedHostProfile;
    if (isProducedProfile) return { kind: "produced-profile", projected };
    return null;
  }

  function recordFailedWindow(
    armed: ArmedRepairClosure,
    projected: CanonicalReportProjection,
  ) {
    if (
      armed.failedWindows.some(
        ({ payloadSha256 }) => payloadSha256 === projected.payloadSha256,
      )
    ) {
      return;
    }
    armed.failedWindows.push({
      bootId: projected.bootId,
      payloadSha256: projected.payloadSha256,
      sequence: projected.sequenceEnd,
    });
  }

  function acceptClosureObservation(
    armed: ArmedRepairClosure,
    observation: NonNullable<ClosureObservation>,
    status: number,
    responseBody: Buffer,
  ) {
    const projected = observation.projected;
    const acceptedSequenceEnd = acceptedSequenceEndOf(responseBody);
    const responseSha256 = sha256(responseBody);
    if (observation.kind === "final-boot") {
      armed.finalBoot = {
        acceptedSequenceEnd,
        ackObservedAtMs: Date.now(),
        bootId: projected.bootId,
        bytes: projected.bytes,
        payloadSha256: projected.payloadSha256,
        probeAssetBundleVersion: projected.probeAssetBundleVersion,
        probeId: projected.probeId,
        responseSha256,
        sequence: projected.sequenceEnd,
        upstreamStatus: status,
      };
    } else {
      const hostProfile = projected.hostProfile;
      if (hostProfile === null) return;
      armed.producedProfile = {
        acceptedSequenceEnd,
        architecture: hostProfile.architecture,
        bootId: projected.bootId,
        bytes: projected.bytes,
        collectorId: hostProfileCollectorId,
        cpuCount: hostProfile.cpuCount,
        hostname: hostProfile.hostname,
        kernel: hostProfile.kernel,
        os: hostProfile.os,
        payloadSha256: projected.payloadSha256,
        probeAssetBundleVersion: hostProfile.probeAssetBundleVersion,
        probeId: projected.probeId,
        probeVersion: hostProfile.probeVersion,
        responseSha256,
        sequence: projected.sequenceEnd,
        snapshotHash: hostProfile.snapshotHash,
        upstreamStatus: status,
      };
    }
    completeClosureCapture(armed);
    notify();
  }

  function recordRepairAuthorization(
    armed: ArmedRepairClosure,
    generation: string,
    requestBody: Buffer,
    status: number,
    responseBody: Buffer,
  ) {
    if (armed.authorization) return;
    const evidence = jsonObjectValue(jsonObject(requestBody)?.evidence);
    const authority = jsonObjectValue(jsonObject(responseBody)?.authority);
    armed.authorization = {
      bootId: textField(evidence?.bootId),
      bundleVersion: textField(evidence?.bundleVersion),
      epochGeneration: generation,
      hostId: textField(evidence?.hostId),
      operationId: textField(authority?.repairOperationId),
      probeId: textField(evidence?.probeId),
      requestPayloadSha256: sha256(requestBody),
      responseSha256: sha256(responseBody),
      upstreamStatus: status,
    };
    completeClosureCapture(armed);
    notify();
  }

  function closureCapture(armed: ArmedRepairClosure): RepairClosureCapture {
    return {
      bootId: armed.finalBoot?.bootId ?? "",
      failedWindows: structuredClone(armed.failedWindows),
      finalBoot: armed.finalBoot ? structuredClone(armed.finalBoot) : null,
      kind: "installed-bundle-repair-closure-capture",
      probeId: armed.expectedProbeId,
      producedProfile: armed.producedProfile
        ? structuredClone(armed.producedProfile)
        : null,
      repairAuthorization: armed.authorization
        ? structuredClone(armed.authorization)
        : null,
      schemaVersion: 1,
    };
  }

  function completeClosureCapture(armed: ArmedRepairClosure) {
    if (
      !armed.authorization ||
      !armed.finalBoot ||
      !armed.producedProfile ||
      completedClosure
    ) {
      return;
    }
    completedClosure = closureCapture(armed);
  }

  function closureFail(
    message: string,
    code = "repair_closure_evidence_invalid",
  ): void {
    if (!closureFailure) {
      closureFailure = new Error(message);
      closureFailure.code = code;
      notify();
    }
  }

  async function waitForState(
    deadline: number,
    done: () => boolean,
    getFailure: () => CodedError | null,
  ) {
    while (!done() && !getFailure() && Date.now() < deadline) {
      await new Promise<void>((resolve) => {
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
  }

  function fail(
    message: string,
    code = "canonical_report_evidence_invalid",
  ): void {
    if (!failure) {
      failure = new Error(message);
      failure.code = code;
      notify();
    }
  }

  return {
    arm({ expectedProbeId }: { expectedProbeId?: string }) {
      if (!reportedIdPattern.test(expectedProbeId ?? "")) {
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

    armRepairClosure({ expectedProbeId }: { expectedProbeId: string }) {
      if (!reportedIdPattern.test(expectedProbeId)) {
        throw new Error("repair closure evidence Probe ID is invalid");
      }
      if (closure || completedClosure || closureFailure) {
        throw new Error(
          "repair closure evidence transport can be armed only once",
        );
      }
      closure = {
        authorization: null,
        expectedProbeId,
        failedWindows: [],
        finalBoot: null,
        producedProfile: null,
      };
    },

    async close() {
      if (!server) return { clean: true, skipped: "not_started" };
      const closing = server;
      server = null;
      await new Promise<void>((resolve, reject) =>
        closing.close((error) => (error ? reject(error) : resolve())),
      );
      return { clean: true };
    },

    diagnostics() {
      return {
        armed: Boolean(armed),
        bootReportObserved: Boolean(armed?.boot),
        completed: Boolean(completedEvidence),
        closure: {
          armed: Boolean(closure),
          repairAuthorityObserved: Boolean(closure?.authorization),
          completed: Boolean(completedClosure),
          failedWindowCount: closure?.failedWindows.length ?? 0,
          failure: closureFailure
            ? { code: closureFailure.code, message: closureFailure.message }
            : null,
          finalBootObserved: Boolean(closure?.finalBoot),
          producedProfileObserved: Boolean(closure?.producedProfile),
        },
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
      const listening = createServer((incoming, outgoing) => {
        handle(incoming, outgoing);
      });
      server = listening;
      await new Promise<void>((resolve, reject) => {
        listening.once("error", reject);
        listening.listen(Number(listen.port), listen.hostname, resolve);
      });
      const address = listening.address();
      if (address === null || typeof address === "string") {
        throw new Error(
          "canonical report evidence transport did not bind a port",
        );
      }
      const origin = `${listen.protocol}//${listen.hostname}:${address.port}`;
      return { origin };
    },

    async waitForEvidence({ timeoutMs }: { timeoutMs: number }) {
      if (!armed)
        throw new Error("canonical report evidence transport is not armed");
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
        throw new Error("canonical report evidence timeout is invalid");
      }
      const deadline = Date.now() + timeoutMs;
      await waitForState(
        deadline,
        () => Boolean(completedEvidence),
        () => failure,
      );
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
      const error: CodedError = new Error(
        `canonical report evidence timed out: ${missing}`,
      );
      error.code = "canonical_report_evidence_timeout";
      throw error;
    },

    async waitForRepairClosureEvidence({ timeoutMs }: { timeoutMs: number }) {
      if (!closure)
        throw new Error("repair closure evidence transport is not armed");
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
        throw new Error("repair closure evidence timeout is invalid");
      }
      const deadline = Date.now() + timeoutMs;
      await waitForState(
        deadline,
        () => Boolean(completedClosure),
        () => closureFailure,
      );
      if (closureFailure) throw closureFailure;
      // 未完成时返回已观测到的部分事实，缺失项保持 null，由共享结案判据给出拒绝理由；
      // 传输层不自行断言修复是否完成。
      return closureCapture(closure);
    },
  };
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function hasProducedHostProfileOutcome(
  report: ProbeReportRequestMessage,
): boolean {
  return (report.metrics ?? []).some((sample) =>
    (sample?.collectorOutcomes ?? []).some(
      (outcome) =>
        outcome?.collectorId === hostProfileCollectorId &&
        Number(outcome?.state) === producedCollectorOutcomeState &&
        !outcome?.failure,
    ),
  );
}

function acceptedSequenceEndOf(responseBody: Buffer): number {
  try {
    return unsignedNumber(
      ReportResponse.decode(responseBody).acceptedSequenceEnd,
    );
  } catch {
    return -1;
  }
}

function jsonObject(value: Buffer): Record<string, unknown> | null {
  return jsonObjectValue(parseJson(value));
}

function parseJson(value: Buffer): unknown {
  try {
    return JSON.parse(value.toString("utf8"));
  } catch {
    return null;
  }
}

function jsonObjectValue(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function textField(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") {
    return String(value);
  }
  return "";
}

function streamTransparent(
  incoming: IncomingMessage,
  outgoing: ServerResponse,
  target: URL,
) {
  let upstreamResponse: IncomingMessage | null = null;
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
      response.once("error", (error: Error) => outgoing.destroy(error));
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
  upstreamRequest.once("error", (error: Error) => {
    if (!outgoing.destroyed) outgoing.destroy(error);
  });
  incoming.pipe(upstreamRequest);
}

function buildEvidence({
  armed,
  retryResponseSha256,
}: {
  armed: ArmedCanonicalReport;
  retryResponseSha256: string;
}): CanonicalReportEvidence {
  const boot = armed.boot;
  const failure = armed.failure;
  const bootResponse = armed.bootResponse;
  const firstFailureResponse = armed.firstFailureResponse;
  if (!boot || !failure || !bootResponse || !firstFailureResponse) {
    throw new Error("canonical report evidence is incomplete");
  }
  return {
    bootId: boot.bootId,
    bootReport: {
      acceptedSequenceEnd: bootResponse.acceptedSequenceEnd,
      bytes: boot.bytes,
      payloadSha256: boot.payloadSha256,
      reconciliation: {
        currentProbeConfigurationVersion:
          bootResponse.currentConfigurationVersion,
        pendingOperation: bootResponse.pendingOperation,
        requestedSnapshotCollectorIdsCount:
          bootResponse.requestedSnapshotCollectorIdsCount,
      },
      responseDelivered: true,
      responseSha256: bootResponse.responseSha256,
      sequence: 1,
      upstreamStatus: 200,
    },
    failureReport: {
      attempts: [
        {
          acceptedSequenceEnd: 2,
          response: "dropped",
          responseSha256: firstFailureResponse.responseSha256,
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

function projectReport(
  report: ProbeReportRequestMessage,
  body: Buffer,
): CanonicalReportProjection {
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
    hostProfile: projectHostProfile(report),
    metricsCount: report.metrics?.length ?? 0,
    payloadSha256: sha256(body),
    probeAssetBundleVersion: report.probeAssetBundleVersion ?? "",
    probeConfigurationVersion: report.probeConfigurationVersion ?? "",
    probeId: report.probeId ?? "",
    producedHostProfile: hasProducedHostProfileOutcome(report),
    sequenceEnd: unsignedNumber(report.sequenceEnd),
    sequenceStart: unsignedNumber(report.sequenceStart),
  };
}

function projectHostProfile(
  report: ProbeReportRequestMessage,
): HostProfileProjection | null {
  for (const snapshot of report.snapshots ?? []) {
    const hostProfile = snapshot?.hostProfile;
    if (
      !hostProfile ||
      snapshot?.collectorId !== hostProfileCollectorId ||
      !snapshot?.snapshotHash
    ) {
      continue;
    }
    return {
      architecture: textField(hostProfile.architecture),
      cpuCount: unsignedNumber(hostProfile.cpuCount),
      hostname: textField(hostProfile.hostname),
      kernel: textField(hostProfile.kernel),
      os: textField(hostProfile.os),
      probeAssetBundleVersion: textField(hostProfile.probeAssetBundleVersion),
      probeVersion: textField(hostProfile.probeVersion),
      snapshotHash: textField(snapshot.snapshotHash),
    };
  }
  return null;
}

function observationLabel(kind: "boot" | "first-failure" | "retry"): string {
  return kind === "boot" ? "Boot Report" : "ObservationWindowFailure";
}

function unsignedNumber(value: NumericLike): number {
  const number =
    typeof value === "number" ? value : Number(value?.toString() ?? value);
  return Number.isSafeInteger(number) && number >= 0 ? number : -1;
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function validatedHttpOrigin(value: string, label: string): URL {
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

function forwardedHeaders(
  source: IncomingHttpHeaders,
  length: number,
): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(source)) {
    if (
      value !== undefined &&
      !new Set([
        "connection",
        "content-length",
        "host",
        "transfer-encoding",
      ]).has(name.toLowerCase())
    ) {
      headers.set(name, Array.isArray(value) ? value.join(", ") : value);
    }
  }
  headers.set("content-length", String(length));
  return headers;
}

function transparentHeaders(source: IncomingHttpHeaders): OutgoingHttpHeaders {
  const headers: OutgoingHttpHeaders = {};
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

function contentLengthExceeds(
  headers: IncomingHttpHeaders,
  maxBytes: number,
): boolean {
  const value = headers["content-length"];
  const contentLength = Array.isArray(value)
    ? value[0]?.trim()
    : typeof value === "string"
      ? value.trim()
      : undefined;
  return Boolean(
    contentLength &&
    /^\d+$/.test(contentLength) &&
    Number(contentLength) > maxBytes,
  );
}

function writeResponse(
  outgoing: ServerResponse,
  response: Response,
  body: Buffer,
) {
  const headers: OutgoingHttpHeaders = {};
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

async function readCappedBody(
  incoming: IncomingMessage,
  maxBytes: number,
): Promise<Buffer<ArrayBuffer> | null> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of incoming) {
    totalBytes += chunk.byteLength;
    if (totalBytes > maxBytes) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, totalBytes);
}
