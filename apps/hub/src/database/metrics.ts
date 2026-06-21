import { and, asc, desc, eq, gte, inArray, lte } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";

import {
  metricCpuCores,
  metricDisks,
  metricNetworkInterfaces,
  metricSamples,
  type MetricSampleRow,
  reportObservations,
} from "./schema.js";

type MetricsDatabase = BetterSQLite3Database<typeof import("./schema.js")>;

export type RawMetricSampleInput = {
  bootId: string;
  collectedAtMs: number;
  cpuCores?: Array<{
    idle: number;
    iowait: number;
    irq: number;
    name: string;
    nice: number;
    softirq: number;
    steal: number;
    system: number;
    usagePercent: number;
    user: number;
  }>;
  cpuPercent?: number | null;
  cpuUserPercent?: number | null;
  cpuSystemPercent?: number | null;
  cpuIowaitPercent?: number | null;
  cpuStealPercent?: number | null;
  cpuIdlePercent?: number | null;
  disks?: Array<{
    availableBytes: number;
    filesystemType: string;
    ioUtilizationPercent?: number | null;
    mountPoint: string;
    readAwaitMs?: number | null;
    readBytesDelta: number;
    totalBytes: number;
    usedBytes: number;
    weightedIoPercent?: number | null;
    writeAwaitMs?: number | null;
    writeBytesDelta: number;
  }>;
  diskTotalBytes?: number | null;
  diskUsedBytes?: number | null;
  load1?: number | null;
  load5?: number | null;
  load15?: number | null;
  hostId: number;
  batteryPercent?: number | null;
  batteryState?: string | null;
  memoryCacheBytes?: number | null;
  memoryTotalBytes?: number | null;
  memoryUsedBytes?: number | null;
  networkInterfaces?: Array<{
    name: string;
    rxBytes: number;
    rxBytesDelta: number;
    txBytes: number;
    txBytesDelta: number;
  }>;
  networkRxBytesDelta?: number | null;
  networkTxBytesDelta?: number | null;
  probeId: string;
  receivedAtMs: number;
  sequence: number;
  swapTotalBytes?: number | null;
  swapUsedBytes?: number | null;
  temperatureCelsius?: number | null;
  uptimeSeconds?: number | null;
};

export type ReportObservationInput = {
  bootId: string;
  hostId: number;
  probeId: string;
  receivedAtMs: number;
  sequence: number;
};

export type MetricHistorySample = MetricSampleRow & {
  cpuCores: Array<{
    name: string;
    usagePercent: number;
  }>;
  disks: Array<{
    availableBytes: number;
    filesystemType: string;
    ioUtilizationPercent: number | null;
    mountPoint: string;
    readAwaitMs: number | null;
    readBytesDelta: number;
    totalBytes: number;
    usedBytes: number;
    weightedIoPercent: number | null;
    writeAwaitMs: number | null;
    writeBytesDelta: number;
  }>;
  networkInterfaces: Array<{
    name: string;
    rxBytesDelta: number;
    txBytesDelta: number;
  }>;
};

export type MetricsRepository = {
  findLatestSample: (hostId: number) => MetricSampleRow | null;
  findSamplesForHost: (input: {
    fromCollectedAtMs: number;
    hostId: number;
    toCollectedAtMs: number;
  }) => MetricHistorySample[];
  recordObservation: (input: ReportObservationInput) => boolean;
  recordSample: (input: RawMetricSampleInput) => void;
};

export function createMetricsRepository(
  database: MetricsDatabase,
): MetricsRepository {
  return {
    findLatestSample(hostId) {
      return (
        database
          .select()
          .from(metricSamples)
          .where(eq(metricSamples.hostId, hostId))
          .orderBy(
            desc(metricSamples.receivedAtMs),
            desc(metricSamples.sequence),
          )
          .limit(1)
          .get() ?? null
      );
    },
    findSamplesForHost(input) {
      const samples = database
        .select()
        .from(metricSamples)
        .where(
          and(
            eq(metricSamples.hostId, input.hostId),
            gte(metricSamples.collectedAtMs, input.fromCollectedAtMs),
            lte(metricSamples.collectedAtMs, input.toCollectedAtMs),
          ),
        )
        .orderBy(asc(metricSamples.collectedAtMs), asc(metricSamples.sequence))
        .all();

      if (samples.length === 0) {
        return [];
      }

      const sampleIds = samples.map((sample) => sample.id);
      const coresBySample = new Map<
        number,
        Array<{ name: string; usagePercent: number }>
      >();
      const disksBySample = new Map<
        number,
        Array<{
          availableBytes: number;
          filesystemType: string;
          ioUtilizationPercent: number | null;
          mountPoint: string;
          readAwaitMs: number | null;
          readBytesDelta: number;
          totalBytes: number;
          usedBytes: number;
          weightedIoPercent: number | null;
          writeAwaitMs: number | null;
          writeBytesDelta: number;
        }>
      >();
      const interfacesBySample = new Map<
        number,
        Array<{
          name: string;
          rxBytesDelta: number;
          txBytesDelta: number;
        }>
      >();

      for (const core of database
        .select()
        .from(metricCpuCores)
        .where(inArray(metricCpuCores.metricSampleId, sampleIds))
        .orderBy(asc(metricCpuCores.name))
        .all()) {
        const cores = coresBySample.get(core.metricSampleId) ?? [];
        cores.push({
          name: core.name,
          usagePercent: core.usagePercent,
        });
        coresBySample.set(core.metricSampleId, cores);
      }

      for (const disk of database
        .select()
        .from(metricDisks)
        .where(inArray(metricDisks.metricSampleId, sampleIds))
        .orderBy(asc(metricDisks.mountPoint))
        .all()) {
        const disks = disksBySample.get(disk.metricSampleId) ?? [];
        disks.push({
          availableBytes: disk.availableBytes,
          filesystemType: disk.filesystemType,
          ioUtilizationPercent: disk.ioUtilizationPercent,
          mountPoint: disk.mountPoint,
          readAwaitMs: disk.readAwaitMs,
          readBytesDelta: disk.readBytesDelta,
          totalBytes: disk.totalBytes,
          usedBytes: disk.usedBytes,
          weightedIoPercent: disk.weightedIoPercent,
          writeAwaitMs: disk.writeAwaitMs,
          writeBytesDelta: disk.writeBytesDelta,
        });
        disksBySample.set(disk.metricSampleId, disks);
      }

      for (const networkInterface of database
        .select()
        .from(metricNetworkInterfaces)
        .where(inArray(metricNetworkInterfaces.metricSampleId, sampleIds))
        .orderBy(asc(metricNetworkInterfaces.name))
        .all()) {
        const networkInterfaces =
          interfacesBySample.get(networkInterface.metricSampleId) ?? [];
        networkInterfaces.push({
          name: networkInterface.name,
          rxBytesDelta: networkInterface.rxBytesDelta,
          txBytesDelta: networkInterface.txBytesDelta,
        });
        interfacesBySample.set(
          networkInterface.metricSampleId,
          networkInterfaces,
        );
      }

      return samples.map((sample) => ({
        ...sample,
        cpuCores: coresBySample.get(sample.id) ?? [],
        disks: disksBySample.get(sample.id) ?? [],
        networkInterfaces: interfacesBySample.get(sample.id) ?? [],
      }));
    },
    recordObservation(input) {
      const row = database
        .insert(reportObservations)
        .values({
          bootId: input.bootId,
          hostId: input.hostId,
          probeId: input.probeId,
          receivedAtMs: input.receivedAtMs,
          sequence: input.sequence,
        })
        .onConflictDoNothing({
          target: [
            reportObservations.probeId,
            reportObservations.bootId,
            reportObservations.sequence,
          ],
        })
        .returning()
        .get();

      return Boolean(row);
    },
    recordSample(input) {
      const sample = database
        .insert(metricSamples)
        .values({
          bootId: input.bootId,
          collectedAtMs: input.collectedAtMs,
          batteryPercent: input.batteryPercent ?? null,
          batteryState: input.batteryState ?? null,
          cpuIdlePercent: input.cpuIdlePercent ?? null,
          cpuIowaitPercent: input.cpuIowaitPercent ?? null,
          cpuPercent: input.cpuPercent ?? null,
          cpuStealPercent: input.cpuStealPercent ?? null,
          cpuSystemPercent: input.cpuSystemPercent ?? null,
          cpuUserPercent: input.cpuUserPercent ?? null,
          diskTotalBytes: input.diskTotalBytes ?? null,
          diskUsedBytes: input.diskUsedBytes ?? null,
          load1: input.load1 ?? null,
          load5: input.load5 ?? null,
          load15: input.load15 ?? null,
          hostId: input.hostId,
          memoryCacheBytes: input.memoryCacheBytes ?? null,
          memoryTotalBytes: input.memoryTotalBytes ?? null,
          memoryUsedBytes: input.memoryUsedBytes ?? null,
          networkRxBytesDelta: input.networkRxBytesDelta ?? null,
          networkTxBytesDelta: input.networkTxBytesDelta ?? null,
          probeId: input.probeId,
          receivedAtMs: input.receivedAtMs,
          sequence: input.sequence,
          swapTotalBytes: input.swapTotalBytes ?? null,
          swapUsedBytes: input.swapUsedBytes ?? null,
          temperatureCelsius: input.temperatureCelsius ?? null,
          uptimeSeconds: input.uptimeSeconds ?? null,
        })
        .onConflictDoNothing({
          target: [
            metricSamples.probeId,
            metricSamples.bootId,
            metricSamples.sequence,
          ],
        })
        .returning()
        .get();

      if (!sample) {
        return;
      }

      if (input.cpuCores?.length) {
        database
          .insert(metricCpuCores)
          .values(
            input.cpuCores.map((core) => ({
              idle: core.idle,
              iowait: core.iowait,
              irq: core.irq,
              metricSampleId: sample.id,
              name: core.name,
              nice: core.nice,
              softirq: core.softirq,
              steal: core.steal,
              system: core.system,
              usagePercent: core.usagePercent,
              user: core.user,
            })),
          )
          .run();
      }

      if (input.disks?.length) {
        database
          .insert(metricDisks)
          .values(
            input.disks.map((disk) => ({
              availableBytes: disk.availableBytes,
              filesystemType: disk.filesystemType,
              ioUtilizationPercent: disk.ioUtilizationPercent ?? null,
              metricSampleId: sample.id,
              mountPoint: disk.mountPoint,
              readAwaitMs: disk.readAwaitMs ?? null,
              readBytesDelta: disk.readBytesDelta,
              totalBytes: disk.totalBytes,
              usedBytes: disk.usedBytes,
              weightedIoPercent: disk.weightedIoPercent ?? null,
              writeAwaitMs: disk.writeAwaitMs ?? null,
              writeBytesDelta: disk.writeBytesDelta,
            })),
          )
          .run();
      }

      if (input.networkInterfaces?.length) {
        database
          .insert(metricNetworkInterfaces)
          .values(
            input.networkInterfaces.map((networkInterface) => ({
              metricSampleId: sample.id,
              name: networkInterface.name,
              rxBytes: networkInterface.rxBytes,
              rxBytesDelta: networkInterface.rxBytesDelta,
              txBytes: networkInterface.txBytes,
              txBytesDelta: networkInterface.txBytesDelta,
            })),
          )
          .run();
      }
    },
  };
}
