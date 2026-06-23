import { and, asc, desc, eq, gte, inArray, lte } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";

import {
  metricCpuCores,
  metricDisks,
  metricNetworkInterfaces,
  metricSamples,
  type MetricSampleRow,
  officialMetricCpu,
  officialMetricDiskSummary,
  officialMetricLoad,
  officialMetricMemory,
  officialMetricNetworkSummary,
  officialMetricThermalPower,
  officialMetricUptime,
  reportObservations,
} from "./schema.js";

type MetricsDatabase = NodeSQLiteDatabase<typeof import("./schema.js")>;
type MetricsWriteDatabase = Pick<MetricsDatabase, "insert">;

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
  recordObservationSample: (input: {
    observation: ReportObservationInput;
    sample?: RawMetricSampleInput;
  }) => boolean;
  recordSample: (input: RawMetricSampleInput) => void;
};

export function createMetricsRepository(
  database: MetricsDatabase,
): MetricsRepository {
  return {
    findLatestSample(hostId) {
      const sample =
        database
          .select()
          .from(metricSamples)
          .where(eq(metricSamples.hostId, hostId))
          .orderBy(
            desc(metricSamples.receivedAtMs),
            desc(metricSamples.sequence),
          )
          .limit(1)
          .get() ?? null;
      return sample ? (hydrateSamples(database, [sample]).at(0) ?? null) : null;
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

      const hydratedSamples = hydrateSamples(database, samples);
      return hydratedSamples.map((sample) => ({
        ...sample,
        cpuCores: coresBySample.get(sample.id) ?? [],
        disks: disksBySample.get(sample.id) ?? [],
        networkInterfaces: interfacesBySample.get(sample.id) ?? [],
      }));
    },
    recordObservation(input) {
      return insertReportObservation(database, input);
    },
    recordObservationSample(input) {
      return database.transaction((transaction) => {
        const inserted = insertReportObservation(
          transaction,
          input.observation,
        );
        if (!inserted) {
          return false;
        }

        if (input.sample) {
          insertMetricSample(transaction, input.sample);
        }

        return true;
      });
    },
    recordSample(input) {
      database.transaction((transaction) => {
        insertMetricSample(transaction, input);
      });
    },
  };
}

function insertReportObservation(
  database: MetricsWriteDatabase,
  input: ReportObservationInput,
) {
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
}

function insertMetricSample(
  database: MetricsWriteDatabase,
  input: RawMetricSampleInput,
) {
  const sample = database
    .insert(metricSamples)
    .values({
      bootId: input.bootId,
      collectedAtMs: input.collectedAtMs,
      hostId: input.hostId,
      probeId: input.probeId,
      receivedAtMs: input.receivedAtMs,
      sequence: input.sequence,
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

  if (
    hasAnyValue(
      input.cpuPercent,
      input.cpuUserPercent,
      input.cpuSystemPercent,
      input.cpuIowaitPercent,
      input.cpuStealPercent,
      input.cpuIdlePercent,
    )
  ) {
    database
      .insert(officialMetricCpu)
      .values({
        cpuIdlePercent: input.cpuIdlePercent ?? null,
        cpuIowaitPercent: input.cpuIowaitPercent ?? null,
        cpuPercent: input.cpuPercent ?? null,
        cpuStealPercent: input.cpuStealPercent ?? null,
        cpuSystemPercent: input.cpuSystemPercent ?? null,
        cpuUserPercent: input.cpuUserPercent ?? null,
        metricSampleId: sample.id,
      })
      .run();
  }

  if (
    hasAnyValue(
      input.memoryUsedBytes,
      input.memoryTotalBytes,
      input.memoryCacheBytes,
      input.swapTotalBytes,
      input.swapUsedBytes,
    )
  ) {
    database
      .insert(officialMetricMemory)
      .values({
        memoryCacheBytes: input.memoryCacheBytes ?? null,
        memoryTotalBytes: input.memoryTotalBytes ?? null,
        memoryUsedBytes: input.memoryUsedBytes ?? null,
        metricSampleId: sample.id,
        swapTotalBytes: input.swapTotalBytes ?? null,
        swapUsedBytes: input.swapUsedBytes ?? null,
      })
      .run();
  }

  if (hasAnyValue(input.load1, input.load5, input.load15)) {
    database
      .insert(officialMetricLoad)
      .values({
        load1: input.load1 ?? null,
        load5: input.load5 ?? null,
        load15: input.load15 ?? null,
        metricSampleId: sample.id,
      })
      .run();
  }

  if (hasAnyValue(input.uptimeSeconds)) {
    database
      .insert(officialMetricUptime)
      .values({
        metricSampleId: sample.id,
        uptimeSeconds: input.uptimeSeconds ?? null,
      })
      .run();
  }

  if (
    hasAnyValue(
      input.temperatureCelsius,
      input.batteryPercent,
      input.batteryState,
    )
  ) {
    database
      .insert(officialMetricThermalPower)
      .values({
        batteryPercent: input.batteryPercent ?? null,
        batteryState: input.batteryState ?? null,
        metricSampleId: sample.id,
        temperatureCelsius: input.temperatureCelsius ?? null,
      })
      .run();
  }

  if (hasAnyValue(input.diskUsedBytes, input.diskTotalBytes)) {
    database
      .insert(officialMetricDiskSummary)
      .values({
        diskTotalBytes: input.diskTotalBytes ?? null,
        diskUsedBytes: input.diskUsedBytes ?? null,
        metricSampleId: sample.id,
      })
      .run();
  }

  if (hasAnyValue(input.networkRxBytesDelta, input.networkTxBytesDelta)) {
    database
      .insert(officialMetricNetworkSummary)
      .values({
        metricSampleId: sample.id,
        networkRxBytesDelta: input.networkRxBytesDelta ?? null,
        networkTxBytesDelta: input.networkTxBytesDelta ?? null,
      })
      .run();
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
}

function hydrateSamples(
  database: MetricsDatabase,
  samples: MetricSampleRow[],
): MetricSampleRow[] {
  if (samples.length === 0) {
    return [];
  }

  const sampleIds = samples.map((sample) => sample.id);
  const cpuBySample = rowsBySampleId(
    database
      .select()
      .from(officialMetricCpu)
      .where(inArray(officialMetricCpu.metricSampleId, sampleIds))
      .all(),
  );
  const memoryBySample = rowsBySampleId(
    database
      .select()
      .from(officialMetricMemory)
      .where(inArray(officialMetricMemory.metricSampleId, sampleIds))
      .all(),
  );
  const loadBySample = rowsBySampleId(
    database
      .select()
      .from(officialMetricLoad)
      .where(inArray(officialMetricLoad.metricSampleId, sampleIds))
      .all(),
  );
  const uptimeBySample = rowsBySampleId(
    database
      .select()
      .from(officialMetricUptime)
      .where(inArray(officialMetricUptime.metricSampleId, sampleIds))
      .all(),
  );
  const thermalPowerBySample = rowsBySampleId(
    database
      .select()
      .from(officialMetricThermalPower)
      .where(inArray(officialMetricThermalPower.metricSampleId, sampleIds))
      .all(),
  );
  const diskSummaryBySample = rowsBySampleId(
    database
      .select()
      .from(officialMetricDiskSummary)
      .where(inArray(officialMetricDiskSummary.metricSampleId, sampleIds))
      .all(),
  );
  const networkSummaryBySample = rowsBySampleId(
    database
      .select()
      .from(officialMetricNetworkSummary)
      .where(inArray(officialMetricNetworkSummary.metricSampleId, sampleIds))
      .all(),
  );

  return samples.map((sample) => ({
    ...sample,
    ...cpuBySample.get(sample.id),
    ...memoryBySample.get(sample.id),
    ...loadBySample.get(sample.id),
    ...uptimeBySample.get(sample.id),
    ...thermalPowerBySample.get(sample.id),
    ...diskSummaryBySample.get(sample.id),
    ...networkSummaryBySample.get(sample.id),
  }));
}

function rowsBySampleId<T extends { id: number; metricSampleId: number }>(
  rows: T[],
) {
  return new Map(rows.map((row) => [row.metricSampleId, domainValues(row)]));
}

function domainValues<T extends { id: number; metricSampleId: number }>(
  row: T,
) {
  const { id: _id, metricSampleId: _metricSampleId, ...values } = row;
  return values;
}

function hasAnyValue(...values: unknown[]) {
  return values.some((value) => value !== null && value !== undefined);
}
