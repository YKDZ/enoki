import type {
  CollectorCapabilities,
  DiskHealthCollectorCapability,
  HostProfileSnapshot,
} from "@enoki/api-client/protocol";
import { enoki } from "@enoki/proto/generated/ts/enoki_pb.js";
import { eq } from "drizzle-orm";
import type { NodeSQLiteDatabase } from "drizzle-orm/node-sqlite";

import { hosts, officialHostProfiles } from "./schema.js";

type HostProfileDatabase = NodeSQLiteDatabase<typeof import("./schema.js")>;
type ProtoHostProfileSnapshot = enoki.v1.IHostProfileSnapshot;

const hostProfileCollectorId = "official.host-profile";

export type SnapshotCollectorStorageAdapter<Payload, View> = {
  collectorId: string;
  hasSnapshot: (
    hostId: number,
    snapshotHash: string | null | undefined,
  ) => boolean;
  read: (hostId: number) => View | null;
  write: (input: {
    hostId: number;
    observedIp?: string | null;
    payload: Payload;
    snapshotHash: string;
    updatedAtMs: number;
  }) => { changed: boolean; view: View };
};

export type HostProfileSnapshotWrite = {
  collectorId: typeof hostProfileCollectorId;
  hostId: number;
  observedIp?: string | null;
  payload: ProtoHostProfileSnapshot;
  snapshotHash: string;
  updatedAtMs: number;
};

export type SnapshotCollectorSnapshotWrite = HostProfileSnapshotWrite;

type RegisteredSnapshotCollectorStorageAdapter = Pick<
  SnapshotCollectorStorageAdapter<unknown, unknown>,
  "collectorId" | "hasSnapshot" | "read"
>;

export type SnapshotCollectorStorageRegistry = {
  hostProfile: SnapshotCollectorStorageAdapter<
    ProtoHostProfileSnapshot,
    HostProfileSnapshot
  >;
  get: (
    collectorId: string,
  ) => RegisteredSnapshotCollectorStorageAdapter | null;
  write: (
    input: SnapshotCollectorSnapshotWrite,
  ) => { changed: boolean; view: HostProfileSnapshot } | null;
};

export function createSnapshotCollectorStorageRegistry(
  database: HostProfileDatabase,
): SnapshotCollectorStorageRegistry {
  const hostProfile = createHostProfileStorageAdapter(database);
  const adapters = new Map<string, RegisteredSnapshotCollectorStorageAdapter>([
    [hostProfile.collectorId, hostProfile],
  ]);

  return {
    get(collectorId) {
      return adapters.get(collectorId) ?? null;
    },
    hostProfile,
    write(input) {
      if (input.collectorId === hostProfile.collectorId) {
        return hostProfile.write(input);
      }

      return null;
    },
  };
}

export function createHostProfileStorageAdapter(
  database: HostProfileDatabase,
): SnapshotCollectorStorageAdapter<
  ProtoHostProfileSnapshot,
  HostProfileSnapshot
> {
  return {
    collectorId: hostProfileCollectorId,
    hasSnapshot(hostId, snapshotHash) {
      if (!snapshotHash) {
        return false;
      }

      const row = database
        .select({ snapshotHash: officialHostProfiles.snapshotHash })
        .from(officialHostProfiles)
        .where(eq(officialHostProfiles.hostId, hostId))
        .get();

      return row?.snapshotHash === snapshotHash;
    },
    read(hostId) {
      const row =
        database
          .select()
          .from(officialHostProfiles)
          .where(eq(officialHostProfiles.hostId, hostId))
          .get() ?? null;

      return row ? viewFromRow(row) : null;
    },
    write(input) {
      const view = normalizeHostProfile(input.payload);
      return database.transaction((transaction) => {
        const existing =
          transaction
            .select()
            .from(officialHostProfiles)
            .where(eq(officialHostProfiles.hostId, input.hostId))
            .get() ?? null;

        if (existing?.snapshotHash === input.snapshotHash) {
          return { changed: false, view: viewFromRow(existing) };
        }

        const currentHost =
          transaction
            .select({
              id: hosts.id,
            })
            .from(hosts)
            .where(eq(hosts.id, input.hostId))
            .get() ?? null;

        if (!currentHost) {
          throw new Error("Failed to update Host Profile projection.");
        }

        const values = {
          architecture: view.architecture,
          collectorCapabilitiesJson: view.collectorCapabilities
            ? JSON.stringify(view.collectorCapabilities)
            : null,
          cpuCount: view.cpuCount,
          cpuModel: view.cpuModel,
          filesystemsJson: JSON.stringify(view.filesystems),
          hostname: view.hostname,
          hostId: input.hostId,
          kernel: view.kernel,
          memoryTotalBytes: view.memoryTotalBytes,
          networkInterfacesJson: JSON.stringify(view.networkInterfaces),
          os: view.os,
          payloadJson: JSON.stringify(view),
          probeVersion: view.probeVersion,
          snapshotHash: input.snapshotHash,
          updatedAtMs: input.updatedAtMs,
        };

        if (existing) {
          transaction
            .update(officialHostProfiles)
            .set(values)
            .where(eq(officialHostProfiles.hostId, input.hostId))
            .run();
        } else {
          transaction.insert(officialHostProfiles).values(values).run();
        }

        transaction
          .update(hosts)
          .set({
            architecture: view.architecture,
            cpuCount: view.cpuCount,
            cpuModel: view.cpuModel?.trim() || null,
            hostname: view.hostname,
            kernel: view.kernel,
            memoryTotalBytes: view.memoryTotalBytes,
            os: view.os,
            probeVersion: view.probeVersion,
          })
          .where(eq(hosts.id, input.hostId))
          .run();

        return { changed: true, view };
      });
    },
  };
}

function viewFromRow(
  row: typeof officialHostProfiles.$inferSelect,
): HostProfileSnapshot {
  const payload = parseJson<HostProfileSnapshot | null>(row.payloadJson, null);
  if (payload) {
    return payload;
  }

  return {
    architecture: row.architecture,
    collectorCapabilities: parseJson<CollectorCapabilities | null>(
      row.collectorCapabilitiesJson,
      null,
    ),
    cpuCount: row.cpuCount,
    cpuModel: row.cpuModel,
    filesystems: parseJson(row.filesystemsJson, []),
    hostname: row.hostname,
    kernel: row.kernel,
    memoryTotalBytes: row.memoryTotalBytes,
    networkInterfaces: parseJson(row.networkInterfacesJson, []),
    os: row.os,
    probeVersion: row.probeVersion,
  };
}

function normalizeHostProfile(
  hostProfile: ProtoHostProfileSnapshot,
): HostProfileSnapshot {
  return {
    architecture: stringField(hostProfile.architecture),
    collectorCapabilities: normalizeCollectorCapabilities(
      hostProfile.collectorCapabilities,
    ),
    cpuBaseFrequencyMhz: nullableNumberField(hostProfile.cpuBaseFrequencyMhz),
    cpuCacheL3Bytes: nullableNumberField(hostProfile.cpuCacheL3Bytes),
    cpuCount: numberField(hostProfile.cpuCount),
    cpuModel: nullableStringField(hostProfile.cpuModel),
    cpuPhysicalCount: nullableNumberField(hostProfile.cpuPhysicalCount),
    cpuSocketCount: nullableNumberField(hostProfile.cpuSocketCount),
    filesystems: (hostProfile.filesystems ?? []).map((filesystem) => ({
      availableBytes: numberField(filesystem.availableBytes),
      filesystemType: stringField(filesystem.filesystemType),
      mountPoint: stringField(filesystem.mountPoint),
      totalBytes: numberField(filesystem.totalBytes),
    })),
    hostname: stringField(hostProfile.hostname),
    kernel: stringField(hostProfile.kernel),
    memoryTotalBytes: numberField(hostProfile.memoryTotalBytes),
    networkInterfaces: (hostProfile.networkInterfaces ?? []).map(
      (networkInterface) => ({
        addresses: [...(networkInterface.addresses ?? [])],
        name: stringField(networkInterface.name),
      }),
    ),
    os: stringField(hostProfile.os),
    probeVersion: stringField(hostProfile.probeVersion),
    processCount: nullableNumberField(hostProfile.processCount),
    threadCount: nullableNumberField(hostProfile.threadCount),
  };
}

function parseJson<T>(json: string | null, fallback: T): T {
  if (!json) {
    return fallback;
  }

  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

function normalizeCollectorCapabilities(
  capabilities: ProtoHostProfileSnapshot["collectorCapabilities"],
) {
  if (!capabilities?.official) {
    return null;
  }

  const official = Object.fromEntries(
    [
      [
        "diskHealth",
        normalizeDiskHealthCollectorCapability(
          capabilities.official.diskHealth,
        ),
      ],
    ].filter((entry): entry is [string, DiskHealthCollectorCapability] =>
      Boolean(entry[1]),
    ),
  ) as CollectorCapabilities["official"];

  return official && Object.keys(official).length > 0 ? { official } : null;
}

function normalizeDiskHealthCollectorCapability(
  capability:
    | { diagnostic?: string | null; status?: number | null }
    | null
    | undefined,
) {
  if (capability === null || capability === undefined) {
    return null;
  }

  return {
    diagnostic: stringField(capability.diagnostic),
    status:
      typeof capability.status === "number" &&
      Number.isFinite(capability.status)
        ? capability.status
        : 0,
  };
}

function stringField(value: unknown) {
  return typeof value === "string" ? value : "";
}

function nullableStringField(value: unknown) {
  return typeof value === "string" && value.trim() ? value : null;
}

function nullableNumberField(
  value: number | { toNumber: () => number } | null | undefined,
) {
  if (value === null || value === undefined) {
    return null;
  }

  const number = typeof value === "number" ? value : value.toNumber();
  return Number.isFinite(number) ? number : null;
}

function numberField(
  value: number | { toNumber: () => number } | null | undefined,
) {
  return nullableNumberField(value) ?? 0;
}
