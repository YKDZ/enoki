import * as v from "valibot";

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
        load: v.optional(collectorAvailabilitySchema),
        memory: v.optional(collectorAvailabilitySchema),
        network: v.optional(collectorAvailabilitySchema),
        temperature: v.optional(collectorAvailabilitySchema),
        uptime: v.optional(collectorAvailabilitySchema),
      }),
    ),
  }),
);

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

export type WebSocketClientMessage = v.InferOutput<
  typeof webSocketClientMessageSchema
>;

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
      diskHealth: v.optional(
        v.array(
          v.object({
            deviceName: v.string(),
            model: v.nullable(v.string()),
            passed: v.boolean(),
            powerOnHours: nullableNumberSchema,
            serialNumber: v.nullable(v.string()),
            temperatureCelsius: nullableNumberSchema,
          }),
        ),
      ),
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

export type HostLiveSummary = v.InferOutput<typeof hostLiveSummarySchema>;

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
  diskHealth: v.optional(
    v.array(
      v.object({
        deviceName: v.string(),
        model: v.nullable(v.string()),
        passed: v.boolean(),
        powerOnHours: nullableNumberSchema,
        serialNumber: v.nullable(v.string()),
        temperatureCelsius: nullableNumberSchema,
      }),
    ),
  ),
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

export type HostDetailSample = v.InferOutput<typeof hostDetailSampleSchema>;

export const webSocketServerMessageSchema = v.variant("type", [
  v.object({
    host: hostLiveSummarySchema,
    type: v.literal("host_summary"),
  }),
  v.object({
    hostId: hostIdSchema,
    sample: hostDetailSampleSchema,
    type: v.literal("host_detail_sample"),
  }),
]);

export type WebSocketServerMessage = v.InferOutput<
  typeof webSocketServerMessageSchema
>;

export function parseWebSocketClientMessage(
  message: unknown,
): WebSocketClientMessage | null {
  const result = v.safeParse(webSocketClientMessageSchema, message);

  return result.success ? result.output : null;
}

export function parseWebSocketServerMessage(
  message: unknown,
): WebSocketServerMessage | null {
  const result = v.safeParse(webSocketServerMessageSchema, message);

  return result.success ? result.output : null;
}
