import type { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";

import type { ProbeOperationConfig } from "../config.js";
import type { AuditRepository } from "../database/audit.js";
import type { EnrollmentRepository } from "../database/enrollments.js";
import type { SnapshotCollectorStorageRegistry } from "../database/host-profiles.js";
import type {
  HostRepository,
  HostStatusThresholds,
} from "../database/hosts.js";
import type { ProbeReportTransaction } from "../database/index.js";
import type { MetricsRepository } from "../database/metrics.js";
import type { ProbeConfigurationRepository } from "../database/probe-configuration.js";
import type { ProbeOperationRepository } from "../database/probe-operations.js";
import type { LiveUpdateBroadcaster } from "../live-updates.js";
import type { TrustedProxyCidr } from "../network.js";
import type { ForwardTransitions } from "./forward-transitions.js";
import type { RepairAuthorizationBudget } from "./repair-authorization-budget.js";

export type ProbeRouteServices = {
  audit?: AuditRepository;
  enrollments: EnrollmentRepository;
  hosts: HostRepository;
  metrics: MetricsRepository;
  probeConfigurations: ProbeConfigurationRepository;
  probeOperations?: ProbeOperationRepository;
  forwardTransitions?: ForwardTransitions;
  probeOperationTimeouts?: ProbeOperationConfig;
  reportTransaction: ProbeReportTransaction;
  snapshotCollectors?: SnapshotCollectorStorageRegistry;
  clockSkewThresholdMs?: number;
  hostStatus?: HostStatusThresholds;
  liveUpdates?: LiveUpdateBroadcaster | null;
  now?: () => number;
  probeOperationTokenSecret?: string;
  probeAssetDir?: string;
  probeDistributionRootPublicKeyPem?: Buffer | string;
  probeApiOrigin?: string;
  repairAuthorizationBudget?: RepairAuthorizationBudget;
  trustedProxyCidrs?: TrustedProxyCidr[];
};

export const defaultProbeOperationTokenSecret =
  randomBytes(32).toString("base64url");
