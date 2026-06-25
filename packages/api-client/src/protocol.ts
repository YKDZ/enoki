import type { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";

type JsonScalar<T> =
  NonNullable<T> extends { toNumber(): number } ? number : NonNullable<T>;

type RequiredJsonFields<T, Key extends keyof T> = {
  [Field in Key]-?: JsonScalar<T[Field]>;
};

type OptionalJsonFields<T, Key extends keyof T> = {
  [Field in Key]?: JsonScalar<T[Field]> | null;
};

type RepeatedItem<T> = NonNullable<T> extends Array<infer Item> ? Item : never;

type ProtoMetricSample = enoki.v1.IMetricSample;
type ProtoHostProfileSnapshot = enoki.v1.IHostProfileSnapshot;
type ProtoFilesystemProfile = RepeatedItem<
  ProtoHostProfileSnapshot["filesystems"]
>;
type ProtoNetworkInterfaceProfile = RepeatedItem<
  ProtoHostProfileSnapshot["networkInterfaces"]
>;
type ProtoCpuCoreMetric = RepeatedItem<ProtoMetricSample["cpuCores"]>;
type ProtoDiskUsageMetric = RepeatedItem<ProtoMetricSample["disks"]>;
type ProtoDiskHealthMetric = RepeatedItem<ProtoMetricSample["diskHealth"]>;
type ProtoNetworkInterfaceMetric = RepeatedItem<
  ProtoMetricSample["networkInterfaces"]
>;

export type DiskHealthCollectorCapability = RequiredJsonFields<
  enoki.v1.IDiskHealthCollectorCapability,
  "status" | "diagnostic"
>;

export type OfficialCollectorCapabilities = {
  diskHealth?: DiskHealthCollectorCapability;
};

export type CollectorCapabilities = {
  official?: OfficialCollectorCapabilities;
};

export type FilesystemProfile = RequiredJsonFields<
  ProtoFilesystemProfile,
  "availableBytes" | "filesystemType" | "mountPoint" | "totalBytes"
>;

export type NetworkInterfaceProfile = RequiredJsonFields<
  ProtoNetworkInterfaceProfile,
  "name"
> & {
  addresses: string[];
};

export type HostProfileSnapshot = RequiredJsonFields<
  ProtoHostProfileSnapshot,
  | "architecture"
  | "cpuCount"
  | "hostname"
  | "kernel"
  | "memoryTotalBytes"
  | "os"
  | "probeVersion"
> &
  OptionalJsonFields<
    ProtoHostProfileSnapshot,
    | "cpuBaseFrequencyMhz"
    | "cpuCacheL3Bytes"
    | "cpuModel"
    | "cpuPhysicalCount"
    | "cpuSocketCount"
    | "processCount"
    | "threadCount"
  > & {
    collectorCapabilities?: CollectorCapabilities | null;
    filesystems: FilesystemProfile[];
    networkInterfaces: NetworkInterfaceProfile[];
  };

export type CpuCoreMetric = RequiredJsonFields<
  ProtoCpuCoreMetric,
  "name" | "usagePercent"
>;

export type DiskUsageMetric = RequiredJsonFields<
  ProtoDiskUsageMetric,
  | "availableBytes"
  | "filesystemType"
  | "mountPoint"
  | "totalBytes"
  | "usedBytes"
> &
  OptionalJsonFields<
    ProtoDiskUsageMetric,
    | "ioUtilizationPercent"
    | "readAwaitMs"
    | "readBytesDelta"
    | "weightedIoPercent"
    | "writeAwaitMs"
    | "writeBytesDelta"
  >;

export type DiskHealthMetric = {
  deviceName: JsonScalar<ProtoDiskHealthMetric["deviceName"]>;
  model: JsonScalar<ProtoDiskHealthMetric["model"]> | null;
  passed: JsonScalar<ProtoDiskHealthMetric["passed"]>;
  powerOnHours: JsonScalar<ProtoDiskHealthMetric["powerOnHours"]> | null;
  role: JsonScalar<ProtoDiskHealthMetric["role"]> | null;
  serialNumber: JsonScalar<ProtoDiskHealthMetric["serialNumber"]> | null;
  temperatureCelsius: JsonScalar<
    ProtoDiskHealthMetric["temperatureCelsius"]
  > | null;
  totalBytes: JsonScalar<ProtoDiskHealthMetric["totalBytes"]> | null;
  usageMountPoint: JsonScalar<ProtoDiskHealthMetric["usageMountPoint"]> | null;
  usedBytes: JsonScalar<ProtoDiskHealthMetric["usedBytes"]> | null;
};

export type NetworkInterfaceDeltaMetric = RequiredJsonFields<
  ProtoNetworkInterfaceMetric,
  "name" | "rxBytesDelta" | "txBytesDelta"
>;
