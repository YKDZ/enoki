import * as v from "valibot";

const managedHostIdSchema = v.pipe(v.number(), v.integer(), v.minValue(1));
const nullableNumberSchema = v.nullable(v.number());
const timestampMsSchema = v.pipe(v.number(), v.integer(), v.minValue(0));

export const webSocketClientMessageSchema = v.variant("type", [
  v.object({
    managedHostId: managedHostIdSchema,
    type: v.literal("subscribe_managed_host_detail"),
  }),
  v.object({
    managedHostId: managedHostIdSchema,
    type: v.literal("unsubscribe_managed_host_detail"),
  }),
]);

export type WebSocketClientMessage = v.InferOutput<
  typeof webSocketClientMessageSchema
>;

export const managedHostLiveSummarySchema = v.object({
  id: managedHostIdSchema,
  lastSeenAtMs: v.nullable(timestampMsSchema),
  latestMetrics: v.nullable(
    v.object({
      collectedAtMs: timestampMsSchema,
      cpuPercent: nullableNumberSchema,
      diskTotalBytes: nullableNumberSchema,
      diskUsedBytes: nullableNumberSchema,
      memoryTotalBytes: nullableNumberSchema,
      memoryUsedBytes: nullableNumberSchema,
      networkRxBitsPerSecond: nullableNumberSchema,
      networkRxBytesDelta: nullableNumberSchema,
      networkTxBitsPerSecond: nullableNumberSchema,
      networkTxBytesDelta: nullableNumberSchema,
      receivedAtMs: timestampMsSchema,
      uptimeSeconds: nullableNumberSchema,
    }),
  ),
  status: v.picklist(["online", "stale", "offline"]),
  warningFlags: v.object({
    clockSkew: v.boolean(),
    probeConfigurationError: v.boolean(),
  }),
});

export type ManagedHostLiveSummary = v.InferOutput<
  typeof managedHostLiveSummarySchema
>;

export const managedHostDetailSampleSchema = v.object({
  collectedAtMs: timestampMsSchema,
  cpuCores: v.array(
    v.object({
      name: v.string(),
      usagePercent: v.number(),
    }),
  ),
  cpuPercent: nullableNumberSchema,
  disks: v.array(
    v.object({
      availableBytes: v.pipe(v.number(), v.integer(), v.minValue(0)),
      filesystemType: v.string(),
      mountPoint: v.string(),
      totalBytes: v.pipe(v.number(), v.integer(), v.minValue(0)),
      usedBytes: v.pipe(v.number(), v.integer(), v.minValue(0)),
    }),
  ),
  managedHostId: managedHostIdSchema,
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
  uptimeSeconds: nullableNumberSchema,
});

export type ManagedHostDetailSample = v.InferOutput<
  typeof managedHostDetailSampleSchema
>;

export const webSocketServerMessageSchema = v.variant("type", [
  v.object({
    host: managedHostLiveSummarySchema,
    type: v.literal("managed_host_summary"),
  }),
  v.object({
    managedHostId: managedHostIdSchema,
    sample: managedHostDetailSampleSchema,
    type: v.literal("managed_host_detail_sample"),
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
