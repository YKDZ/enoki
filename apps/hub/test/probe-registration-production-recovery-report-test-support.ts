import { Buffer } from "node:buffer";
import type { AddressInfo } from "node:net";
import net from "node:net";
import type { DatabaseSync } from "node:sqlite";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { expect } from "vitest";

export async function startResponseLossProxy(hostname = "127.0.0.1") {
  let upstreamPort = 0;
  let responseLossMatcher: ((target: string, body: Buffer) => boolean) | null =
    null;
  const requestBodies: Buffer[] = [];
  const requestTargets: string[] = [];
  const reportExchanges: Array<Record<string, unknown>> = [];
  const server = net.createServer((client) => {
    const requestChunks: Buffer[] = [];
    let forwarded = false;
    client.on("data", (chunk) => {
      if (forwarded) return;
      requestChunks.push(Buffer.from(chunk));
      const request = Buffer.concat(requestChunks);
      const body = completeHttpBody(request);
      if (!body) return;
      forwarded = true;
      const target =
        request
          .subarray(0, request.indexOf("\r\n"))
          .toString("latin1")
          .split(" ")[1] ?? "";
      requestBodies.push(body);
      requestTargets.push(target);
      const reportExchange =
        target === "/api/probe/report" ? summarizeReport(body) : null;
      if (reportExchange) reportExchanges.push(reportExchange);
      const loseResponse = responseLossMatcher?.(target, body) ?? false;
      if (loseResponse) responseLossMatcher = null;
      const upstream = net.connect({ host: "127.0.0.1", port: upstreamPort });
      upstream.on("connect", () => upstream.write(request));
      const responseChunks: Buffer[] = [];
      upstream.on("data", (responseChunk) => {
        responseChunks.push(Buffer.from(responseChunk));
        if (!reportExchange) return;
        const response = Buffer.concat(responseChunks);
        const responseBody = completeHttpBody(response);
        if (!responseBody) return;
        reportExchange.status = Number(
          /^HTTP\/1\.1 (\d{3})/m.exec(response.toString("latin1"))?.[1],
        );
        if (reportExchange.status === 200) {
          try {
            const decodedResponse =
              root.enoki.v1.ProbeReportResponse.decode(responseBody);
            reportExchange.probeReportResponseDecoded = true;
            reportExchange.currentProbeConfigurationVersion =
              decodedResponse.currentProbeConfigurationVersion;
            reportExchange.requestedSnapshotCollectorIds = [
              ...decodedResponse.requestedSnapshotCollectorIds,
            ];
          } catch {
            reportExchange.probeReportResponseDecoded = false;
            reportExchange.currentProbeConfigurationVersion =
              "unparseable_response";
            reportExchange.requestedSnapshotCollectorIds = [
              "unparseable_response",
            ];
          }
        } else {
          try {
            reportExchange.errorCode = JSON.parse(
              responseBody.toString("utf8"),
            ).error;
          } catch {
            reportExchange.errorCode = "unparseable_error";
          }
        }
      });
      if (!loseResponse) {
        upstream.pipe(client);
        return;
      }
      upstream.on("data", () => {
        if (completeHttpBody(Buffer.concat(responseChunks))) {
          client.destroy();
          upstream.destroy();
        }
      });
    });
  });
  server.listen(0, hostname);
  await listening(server);
  return {
    close: () => closeServer(server),
    loseNextResponse: () => {
      responseLossMatcher = () => true;
    },
    loseNextResponseWhen: (
      matcher: (target: string, body: Buffer) => boolean,
    ) => {
      responseLossMatcher = matcher;
    },
    port: (server.address() as AddressInfo).port,
    reportExchanges,
    requestBodies,
    requestTargets,
    setUpstream: (port: number) => {
      upstreamPort = port;
    },
  };
}

function summarizeReport(body: Buffer): Record<string, unknown> | null {
  try {
    const report = root.enoki.v1.ProbeReportRequest.decode(body);
    return {
      bootId: report.bootId,
      metricCount: report.metrics.length,
      metricSequences: report.metrics.map((metric) => Number(metric.sequence)),
      observationWindowFailure: report.observationWindowFailure != null,
      probeId: report.probeId,
      sequenceEnd: Number(report.sequenceEnd),
      sequenceStart: Number(report.sequenceStart),
      snapshots: report.snapshots.map((snapshot) => ({
        hasPayload: snapshot.hostProfile != null,
        snapshotHash: snapshot.snapshotHash,
      })),
    };
  } catch {
    return null;
  }
}

type ReportIdentity = {
  bootId: string;
  probeId: string;
  sequence: number;
};

export function reportObservationIdentities(
  exchanges: Array<Record<string, unknown>>,
): ReportIdentity[] {
  return exchanges.flatMap((exchange) => {
    const identities: ReportIdentity[] = [];
    for (
      let sequence = Number(exchange.sequenceStart);
      sequence <= Number(exchange.sequenceEnd);
      sequence += 1
    ) {
      identities.push({
        bootId: String(exchange.bootId),
        probeId: String(exchange.probeId),
        sequence,
      });
    }
    return identities;
  });
}

export function reportMetricIdentities(
  exchanges: Array<Record<string, unknown>>,
): ReportIdentity[] {
  return exchanges.flatMap((exchange) =>
    ((exchange.metricSequences as number[] | undefined) ?? []).map(
      (sequence) => ({
        bootId: String(exchange.bootId),
        probeId: String(exchange.probeId),
        sequence,
      }),
    ),
  );
}

export function reportIdentityKey(identity: ReportIdentity) {
  return JSON.stringify([identity.probeId, identity.bootId, identity.sequence]);
}

function compareReportIdentities(left: ReportIdentity, right: ReportIdentity) {
  return (
    left.probeId.localeCompare(right.probeId) ||
    left.bootId.localeCompare(right.bootId) ||
    left.sequence - right.sequence
  );
}

export function expectPersistedReportIdentitiesExactlyOnce(
  sqlite: DatabaseSync,
  table: "metric_samples" | "report_observations",
  capturedIdentities: ReportIdentity[],
) {
  const identities = [
    ...new Map(
      capturedIdentities.map((identity) => [
        reportIdentityKey(identity),
        identity,
      ]),
    ).values(),
  ];
  expect(identities.length).toBeGreaterThan(0);
  const values = identities.map(() => "(?, ?, ?)").join(", ");
  const parameters = identities.flatMap(({ bootId, probeId, sequence }) => [
    probeId,
    bootId,
    sequence,
  ]);
  const persisted = sqlite
    .prepare(
      `with expected(probe_id, boot_id, sequence) as (values ${values})
       select
         expected.probe_id as probeId,
         expected.boot_id as bootId,
         expected.sequence as sequence,
         count(actual.id) as persistedCount
       from expected
       left join ${table} actual
         on actual.probe_id = expected.probe_id
        and actual.boot_id = expected.boot_id
        and actual.sequence = expected.sequence
       group by expected.probe_id, expected.boot_id, expected.sequence
       order by expected.probe_id, expected.boot_id, expected.sequence`,
    )
    .all(...parameters)
    .map((row) => ({
      bootId: String(row.bootId),
      persistedCount: Number(row.persistedCount),
      probeId: String(row.probeId),
      sequence: Number(row.sequence),
    }))
    .sort(compareReportIdentities);
  expect(persisted).toEqual(
    identities
      .map(({ bootId, probeId, sequence }) => ({
        bootId,
        persistedCount: 1,
        probeId,
        sequence,
      }))
      .sort(compareReportIdentities),
  );
}

export function hasFullThenTwoCompactReplays(
  exchanges: Array<Record<string, unknown>>,
) {
  const accepted = exchanges.filter((exchange) => exchange.status === 200);
  const firstFull = accepted.find(
    (exchange) =>
      Number(exchange.metricCount) > 0 &&
      reportSnapshot(exchange)?.hasPayload === true,
  );
  const firstFullHash = firstFull
    ? reportSnapshot(firstFull)?.snapshotHash
    : null;
  if (!firstFullHash) return false;

  const replayedHashes = new Set<string>();
  for (const compact of accepted) {
    const compactSnapshot = reportSnapshot(compact);
    if (
      Number(compact.metricCount) === 0 ||
      compactSnapshot?.hasPayload !== false ||
      !compactSnapshot.snapshotHash ||
      compactSnapshot.snapshotHash === firstFullHash ||
      !(
        compact.requestedSnapshotCollectorIds as string[] | undefined
      )?.includes("official.host-profile")
    ) {
      continue;
    }
    const replay = accepted.find(
      (exchange) =>
        Number(exchange.metricCount) === 0 &&
        Number(exchange.sequenceStart) === Number(compact.sequenceEnd) &&
        Number(exchange.sequenceEnd) === Number(compact.sequenceEnd) &&
        reportSnapshot(exchange)?.hasPayload === true &&
        reportSnapshot(exchange)?.snapshotHash === compactSnapshot.snapshotHash,
    );
    if (replay) replayedHashes.add(compactSnapshot.snapshotHash);
  }
  return replayedHashes.size >= 2;
}

function reportSnapshot(exchange: Record<string, unknown>) {
  const snapshots = exchange.snapshots as
    | Array<{ hasPayload?: boolean; snapshotHash?: string }>
    | undefined;
  return snapshots?.length === 1 ? snapshots[0] : null;
}

export function redactedReportExchangeSummary(
  exchanges: Array<Record<string, unknown>>,
) {
  const bootReferences = new Map<string, string>();
  const configurationReferences = new Map<string, string>();
  const snapshotReferences = new Map<string, string>();
  const reference = (
    references: Map<string, string>,
    value: unknown,
    prefix: string,
  ) => {
    const key = String(value ?? "");
    if (!references.has(key)) {
      references.set(key, `${prefix}-${references.size + 1}`);
    }
    return references.get(key);
  };

  return exchanges.map((exchange) => {
    const snapshot = reportSnapshot(exchange);
    const sequenceStart = Number(exchange.sequenceStart);
    const sequenceEnd = Number(exchange.sequenceEnd);
    const metricCount = Number(exchange.metricCount);
    const snapshotKind = snapshot
      ? snapshot.hasPayload === true
        ? "full"
        : "compact"
      : "none";
    return {
      boot: reference(bootReferences, exchange.bootId, "boot"),
      configuration:
        typeof exchange.currentProbeConfigurationVersion === "string"
          ? reference(
              configurationReferences,
              exchange.currentProbeConfigurationVersion,
              "configuration",
            )
          : null,
      error: exchange.errorCode ?? null,
      metricCount,
      observationWindowFailure: exchange.observationWindowFailure === true,
      requestedHostProfile:
        (
          exchange.requestedSnapshotCollectorIds as string[] | undefined
        )?.includes("official.host-profile") ?? false,
      responseDecoded: exchange.probeReportResponseDecoded === true,
      sameSequenceReplay:
        sequenceStart === sequenceEnd &&
        metricCount === 0 &&
        snapshotKind === "full",
      sequenceEnd,
      sequenceStart,
      snapshot: snapshot
        ? {
            kind: snapshotKind,
            ref: reference(
              snapshotReferences,
              snapshot.snapshotHash,
              "snapshot",
            ),
          }
        : null,
      status: exchange.status ?? null,
    };
  });
}

function completeHttpBody(message: Buffer) {
  const headerEnd = message.indexOf("\r\n\r\n");
  if (headerEnd < 0) return null;
  const header = message.subarray(0, headerEnd).toString("latin1");
  const length = Number(/\r\ncontent-length: (\d+)/i.exec(header)?.[1]);
  if (!Number.isSafeInteger(length) || length < 0) return null;
  const bodyStart = headerEnd + 4;
  return message.length >= bodyStart + length
    ? message.subarray(bodyStart, bodyStart + length)
    : null;
}

export function listening(server: net.Server) {
  return new Promise<void>((resolve) => server.once("listening", resolve));
}

export async function waitFor(
  predicate: () => boolean,
  timeoutMs: number,
  failureMessage?: () => string,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  expect(predicate(), failureMessage?.()).toBe(true);
}

export function closeServer(server: net.Server) {
  return new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
