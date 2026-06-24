import * as v from "valibot";

import type {
  CollectorCapabilities,
  CpuCoreMetric,
  DiskHealthMetric,
  DiskUsageMetric,
  HostProfileSnapshot,
  NetworkInterfaceDeltaMetric,
} from "./protocol.js";

type HostStatus = "online" | "stale" | "offline";

export type WebSocketClientMessage =
  | {
      hostId: number;
      type: "subscribe_host_detail";
    }
  | {
      hostId: number;
      type: "unsubscribe_host_detail";
    };

export type HostLiveSummaryMetricSample = {
  batteryPercent?: number | null;
  batteryState?: string | null;
  collectedAtMs: number;
  cpuIdlePercent?: number | null;
  cpuIowaitPercent?: number | null;
  cpuPercent: number | null;
  cpuStealPercent?: number | null;
  cpuSystemPercent?: number | null;
  cpuUserPercent?: number | null;
  diskHealth?: DiskHealthMetric[];
  diskTotalBytes: number | null;
  diskUsedBytes: number | null;
  memoryCacheBytes?: number | null;
  memoryTotalBytes: number | null;
  memoryUsedBytes: number | null;
  networkRxBitsPerSecond: number | null;
  networkRxBytesDelta: number | null;
  networkTxBitsPerSecond: number | null;
  networkTxBytesDelta: number | null;
  receivedAtMs: number;
  swapTotalBytes?: number | null;
  swapUsedBytes?: number | null;
  temperatureCelsius?: number | null;
  uptimeSeconds: number | null;
};

export type HostLiveSummary = {
  collectorCapabilities?: CollectorCapabilities | null;
  id: number;
  lastSeenAtMs: number | null;
  latestMetrics: HostLiveSummaryMetricSample | null;
  status: HostStatus;
  warningFlags: {
    clockSkew: boolean;
    probeConfigurationError: boolean;
  };
};

export type HostDetailSample = {
  batteryPercent?: number | null;
  batteryState?: string | null;
  collectedAtMs: number;
  cpuCores: CpuCoreMetric[];
  cpuIdlePercent?: number | null;
  cpuIowaitPercent?: number | null;
  cpuPercent: number | null;
  cpuStealPercent?: number | null;
  cpuSystemPercent?: number | null;
  cpuUserPercent?: number | null;
  diskHealth?: DiskHealthMetric[];
  disks: DiskUsageMetric[];
  hostId: number;
  memoryCacheBytes?: number | null;
  memoryTotalBytes: number | null;
  memoryUsedBytes: number | null;
  networkInterfaces: NetworkInterfaceDeltaMetric[];
  receivedAtMs: number;
  sequence: number;
  swapTotalBytes?: number | null;
  swapUsedBytes?: number | null;
  temperatureCelsius?: number | null;
  uptimeSeconds: number | null;
};

export type WebSocketServerMessage =
  | {
      host: HostLiveSummary;
      type: "host_summary";
    }
  | {
      hostId: number;
      hostProfile: HostProfileSnapshot;
      type: "host_profile";
    }
  | {
      hostId: number;
      sample: HostDetailSample;
      type: "host_detail_sample";
    };

const hostIdSchema = v.pipe(v.number(), v.integer(), v.minValue(1));
const nullableNumberSchema = v.nullable(v.number());
const timestampMsSchema = v.pipe(v.number(), v.integer(), v.minValue(0));
const collectorAvailabilitySchema = v.object({
  available: v.boolean(),
});
const collectorCapabilitiesSchema = v.nullable(
  v.object({
    official: v.optional(
      v.object({
        battery: v.optional(collectorAvailabilitySchema),
        cpu: v.optional(collectorAvailabilitySchema),
        disk: v.optional(collectorAvailabilitySchema),
        diskHealth: v.optional(collectorAvailabilitySchema),
        hostProfile: v.optional(collectorAvailabilitySchema),
        load: v.optional(collectorAvailabilitySchema),
        memory: v.optional(collectorAvailabilitySchema),
        network: v.optional(collectorAvailabilitySchema),
        temperature: v.optional(collectorAvailabilitySchema),
        uptime: v.optional(collectorAvailabilitySchema),
      }),
    ),
  }),
);
const diskHealthMetricSchema = v.object({
  deviceName: v.string(),
  model: v.nullable(v.string()),
  passed: v.boolean(),
  powerOnHours: nullableNumberSchema,
  role: v.nullable(v.string()),
  serialNumber: v.nullable(v.string()),
  temperatureCelsius: nullableNumberSchema,
  totalBytes: nullableNumberSchema,
  usageMountPoint: v.nullable(v.string()),
  usedBytes: nullableNumberSchema,
});
const hostProfileSchema = v.object({
  architecture: v.string(),
  collectorCapabilities: v.optional(collectorCapabilitiesSchema),
  cpuBaseFrequencyMhz: v.optional(nullableNumberSchema),
  cpuCacheL3Bytes: v.optional(nullableNumberSchema),
  cpuCount: v.pipe(v.number(), v.integer(), v.minValue(0)),
  cpuModel: v.optional(v.nullable(v.string())),
  cpuPhysicalCount: v.optional(nullableNumberSchema),
  cpuSocketCount: v.optional(nullableNumberSchema),
  filesystems: v.array(
    v.object({
      availableBytes: v.pipe(v.number(), v.integer(), v.minValue(0)),
      filesystemType: v.string(),
      mountPoint: v.string(),
      totalBytes: v.pipe(v.number(), v.integer(), v.minValue(0)),
    }),
  ),
  hostname: v.string(),
  kernel: v.string(),
  memoryTotalBytes: v.pipe(v.number(), v.integer(), v.minValue(0)),
  networkInterfaces: v.array(
    v.object({
      addresses: v.array(v.string()),
      name: v.string(),
    }),
  ),
  os: v.string(),
  probeVersion: v.string(),
  processCount: v.optional(nullableNumberSchema),
  threadCount: v.optional(nullableNumberSchema),
});

export const webSocketClientMessageSchema = v.variant("type", [
  v.object({
    hostId: hostIdSchema,
    type: v.literal("subscribe_host_detail"),
  }),
  v.object({
    hostId: hostIdSchema,
    type: v.literal("unsubscribe_host_detail"),
  }),
]);

export const hostLiveSummarySchema = v.object({
  collectorCapabilities: v.optional(collectorCapabilitiesSchema),
  id: hostIdSchema,
  lastSeenAtMs: v.nullable(timestampMsSchema),
  latestMetrics: v.nullable(
    v.object({
      collectedAtMs: timestampMsSchema,
      batteryPercent: v.optional(nullableNumberSchema),
      batteryState: v.optional(v.nullable(v.string())),
      cpuIdlePercent: v.optional(nullableNumberSchema),
      cpuIowaitPercent: v.optional(nullableNumberSchema),
      cpuPercent: nullableNumberSchema,
      cpuStealPercent: v.optional(nullableNumberSchema),
      cpuSystemPercent: v.optional(nullableNumberSchema),
      cpuUserPercent: v.optional(nullableNumberSchema),
      diskHealth: v.optional(v.array(diskHealthMetricSchema)),
      diskTotalBytes: nullableNumberSchema,
      diskUsedBytes: nullableNumberSchema,
      memoryCacheBytes: v.optional(nullableNumberSchema),
      memoryTotalBytes: nullableNumberSchema,
      memoryUsedBytes: nullableNumberSchema,
      networkRxBitsPerSecond: nullableNumberSchema,
      networkRxBytesDelta: nullableNumberSchema,
      networkTxBitsPerSecond: nullableNumberSchema,
      networkTxBytesDelta: nullableNumberSchema,
      receivedAtMs: timestampMsSchema,
      swapTotalBytes: v.optional(nullableNumberSchema),
      swapUsedBytes: v.optional(nullableNumberSchema),
      temperatureCelsius: v.optional(nullableNumberSchema),
      uptimeSeconds: nullableNumberSchema,
    }),
  ),
  status: v.picklist(["online", "stale", "offline"]),
  warningFlags: v.object({
    clockSkew: v.boolean(),
    probeConfigurationError: v.boolean(),
  }),
});

export const hostDetailSampleSchema = v.object({
  collectedAtMs: timestampMsSchema,
  cpuCores: v.array(
    v.object({
      name: v.string(),
      usagePercent: v.number(),
    }),
  ),
  batteryPercent: v.optional(nullableNumberSchema),
  batteryState: v.optional(v.nullable(v.string())),
  cpuIdlePercent: v.optional(nullableNumberSchema),
  cpuIowaitPercent: v.optional(nullableNumberSchema),
  cpuPercent: nullableNumberSchema,
  cpuStealPercent: v.optional(nullableNumberSchema),
  cpuSystemPercent: v.optional(nullableNumberSchema),
  cpuUserPercent: v.optional(nullableNumberSchema),
  diskHealth: v.optional(v.array(diskHealthMetricSchema)),
  disks: v.array(
    v.object({
      availableBytes: v.pipe(v.number(), v.integer(), v.minValue(0)),
      filesystemType: v.string(),
      ioUtilizationPercent: v.optional(nullableNumberSchema),
      mountPoint: v.string(),
      readAwaitMs: v.optional(nullableNumberSchema),
      readBytesDelta: v.optional(
        v.pipe(v.number(), v.integer(), v.minValue(0)),
      ),
      totalBytes: v.pipe(v.number(), v.integer(), v.minValue(0)),
      usedBytes: v.pipe(v.number(), v.integer(), v.minValue(0)),
      weightedIoPercent: v.optional(nullableNumberSchema),
      writeAwaitMs: v.optional(nullableNumberSchema),
      writeBytesDelta: v.optional(
        v.pipe(v.number(), v.integer(), v.minValue(0)),
      ),
    }),
  ),
  hostId: hostIdSchema,
  memoryCacheBytes: v.optional(nullableNumberSchema),
  memoryTotalBytes: nullableNumberSchema,
  memoryUsedBytes: nullableNumberSchema,
  networkInterfaces: v.array(
    v.object({
      name: v.string(),
      rxBytesDelta: v.pipe(v.number(), v.integer(), v.minValue(0)),
      txBytesDelta: v.pipe(v.number(), v.integer(), v.minValue(0)),
    }),
  ),
  receivedAtMs: timestampMsSchema,
  sequence: v.pipe(v.number(), v.integer(), v.minValue(1)),
  swapTotalBytes: v.optional(nullableNumberSchema),
  swapUsedBytes: v.optional(nullableNumberSchema),
  temperatureCelsius: v.optional(nullableNumberSchema),
  uptimeSeconds: nullableNumberSchema,
});

export const webSocketServerMessageSchema = v.variant("type", [
  v.object({
    host: hostLiveSummarySchema,
    type: v.literal("host_summary"),
  }),
  v.object({
    hostId: hostIdSchema,
    hostProfile: hostProfileSchema,
    type: v.literal("host_profile"),
  }),
  v.object({
    hostId: hostIdSchema,
    sample: hostDetailSampleSchema,
    type: v.literal("host_detail_sample"),
  }),
]);

type SchemaOutputMatchesContract<SchemaOutput, Contract> =
  SchemaOutput extends Contract
    ? Contract extends SchemaOutput
      ? true
      : never
    : never;

type AssertTrue<Value extends true> = Value;

type _WebSocketClientMessageSchemaMatchesContract = AssertTrue<
  SchemaOutputMatchesContract<
    v.InferOutput<typeof webSocketClientMessageSchema>,
    WebSocketClientMessage
  >
>;

type _WebSocketServerMessageSchemaMatchesContract = AssertTrue<
  SchemaOutputMatchesContract<
    v.InferOutput<typeof webSocketServerMessageSchema>,
    WebSocketServerMessage
  >
>;

export function parseWebSocketClientMessage(
  message: unknown,
): WebSocketClientMessage | null {
  const result = v.safeParse(webSocketClientMessageSchema, message);

  return result.success ? (result.output as WebSocketClientMessage) : null;
}

export function parseWebSocketServerMessage(
  message: unknown,
): WebSocketServerMessage | null {
  const result = v.safeParse(webSocketServerMessageSchema, message);

  return result.success ? (result.output as WebSocketServerMessage) : null;
}
