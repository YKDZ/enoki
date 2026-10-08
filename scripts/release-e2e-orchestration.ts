import { createHash } from "node:crypto";

import { probeTargets } from "@enoki/probe-release";

import { validateReleaseCatalogSnapshot } from "./release-baseline-verification.ts";
import type { ReleaseCatalogSnapshot } from "./release-baseline-verification.ts";
import type { CanonicalReportEvidence } from "./release-canonical-report-evidence.ts";
import {
  hasAdvancingPortableMetrics,
  isCandidateHostReady,
  isPortableMetricSample,
} from "./release-evidence-judgments.ts";
import type { PortableMetricSample } from "./release-evidence-judgments.ts";
import {
  assertEnrollmentInstallContract,
  assertExactObjectKeys,
  assertHostInventoryEvidence,
  assertInstallCommand,
  assertProbeOperation,
  assertRunId,
  assertionError,
  createProbeHostHarness,
  inventoryResidue,
  parseJson,
  parseKeyValues,
  probeOperationStateRank,
  renderReleaseE2EResourceFingerprint,
  serializedError,
} from "./release-host-harness.ts";
import type {
  CommandEvidence,
  Enrollment,
  ProbeOperation,
  ProbeOperationExpectation,
  ProbeOperationState,
  SerializedError,
} from "./release-host-harness.ts";
import { proveInstalledBundleFailureRepair } from "./release-installed-bundle-failure-repair.ts";
import {
  isPositiveSafeInteger,
  isSafeInteger,
  isUnknownArray,
  isUnknownRecord,
  objectView,
  regexInput,
} from "./release-json-guards.ts";
import type { UnknownRecord } from "./release-json-guards.ts";
import type {
  HubHostProfileReading,
  HubRepairOperationReading,
  RepairClosureCapture,
} from "./release-repair-closure-evidence.ts";
import { probeRepairLocalCompletionOutput } from "./release-repair-closure-evidence.ts";

export { createProbeHostHarness, renderReleaseE2EResourceFingerprint };

type ProbeHost = ReturnType<typeof createProbeHostHarness>;
type HubLifecycleClient = ReturnType<typeof createHubLifecycleClient>;
type ReleaseTestHostEvidence = Awaited<
  ReturnType<ProbeHost["assertReleaseTestHost"]>
>;

type SleepFunction = (milliseconds: number) => Promise<void>;

type ReleaseScenarioTiming = {
  canonicalReportTimeoutMs?: number;
  intervalMs?: number;
  offlineTimeoutMs?: number;
  sleep?: SleepFunction;
  timeoutMs?: number;
};

type PollTiming = {
  intervalMs: number;
  sleep: SleepFunction;
  timeoutMs: number;
};

type EvidenceSink = {
  write(evidence: unknown): unknown;
};

type CandidateFileEntry = { file: string; sha256: string; size: number };
type LegacyCandidateFileEntry = { name: string; sha256: string; size: number };

type BaselineHubDescriptor = {
  archive: string;
  archiveSha256: string;
  digest: string;
  image: string;
  imageDigest: string;
  mediaType: string;
  platform: { architecture: string; os: string };
  size: number;
  sourceManifest: string;
  sourceManifestSha256: string;
  sourceManifestSize: number;
};

type BaselineGithubReleaseDescriptor = {
  id: number;
  peeledCommitSha: string;
  repository: string;
  tagRefSha: string;
  targetCommitish: string;
};

type BaselineSigningIdentityDescriptor = {
  algorithm: string;
  publicKeyFile: string;
  publicKeySha256: string;
};

type OrdinaryReleaseBaselineDescriptor = {
  catalogSnapshot: ReleaseCatalogSnapshot;
  githubRelease: BaselineGithubReleaseDescriptor;
  hub: BaselineHubDescriptor;
  kind: "enoki-release-baseline";
  probeAssetSet: {
    directory: string;
    files: CandidateFileEntry[];
    signingIdentity: BaselineSigningIdentityDescriptor;
    trustRoot: { publicKeySha256: string };
    version: string;
  };
  schemaVersion: number;
  tag: string;
};

type MigrationReleaseBaselineDescriptor = {
  authorization: {
    file: string;
    legacyReleaseSha256: string;
    sha256: string;
    signatureFile: string;
    signatureSha256: string;
  };
  catalogSnapshot: ReleaseCatalogSnapshot;
  githubRelease: BaselineGithubReleaseDescriptor & { tag: string };
  hub: BaselineHubDescriptor;
  kind: "enoki-trust-epoch-migration-baseline";
  legacyProbeAssets: { directory: string; files: LegacyCandidateFileEntry[] };
  schemaVersion: number;
  tag: string;
  transition: string;
};

type ReleaseBaselineDescriptor =
  | OrdinaryReleaseBaselineDescriptor
  | MigrationReleaseBaselineDescriptor;

type CandidateManifestHubDescriptor = {
  archive: string;
  archiveSha256: string;
  digest: string;
  embeddedProbeVersion: string;
  size: number;
};

type BootstrapRecipeDescriptor = {
  bundleVersion: string;
  distribution: string;
  file: string;
  kind: string;
  recordFile: string;
  recordSha256: string;
  recordSize: number;
  rootFingerprint: string;
  schemaVersion: number;
  sha256: string;
  size: number;
  targets: unknown;
  version: string;
};

export type ReleaseE2ECandidateManifest = {
  bootstrapRecipe: BootstrapRecipeDescriptor;
  candidate: { commit: string; version: string };
  hub: CandidateManifestHubDescriptor;
  kind: string;
  probeAssetSet: {
    directory: string;
    files: CandidateFileEntry[];
    signingIdentity: BaselineSigningIdentityDescriptor;
    version: string;
  };
  releaseBaseline: ReleaseBaselineDescriptor;
  schemaVersion: number;
};

type HubHostProfile = {
  architecture: string;
  collectorCapabilities?: unknown;
  cpuCacheL3Bytes?: number | null;
  cpuCount?: number;
  cpuModel?: string | null;
  cpuPhysicalCount?: number | null;
  cpuSocketCount?: number | null;
  filesystems: {
    availableBytes?: number;
    filesystemType: string;
    mountPoint: string;
    totalBytes: number;
  }[];
  hostname: string;
  kernel: string;
  memoryTotalBytes: number;
  networkInterfaces: { addresses?: string[]; name: string }[];
  os: string;
  probeVersion: string;
};

type HubHostSummary = {
  hostMetadata?: UnknownRecord;
  hostProfile: HubHostProfile;
  id: number;
  probeUpgradeStatus?: unknown;
  reportedProbeConfigurationVersion?: string | null;
  status?: string;
  warnings?: { code?: string }[];
};

type HubMetricsWindow = "10m" | "1h" | "1m" | "24h" | "3d" | "6h" | "7d";

type HubApiErrorDetails = {
  body: unknown;
  method: string;
  pathname: string;
  response: Response;
};

type HubEnrollmentTarget = {
  hostId?: number;
  kind: string;
};

type HubEnrollmentStatus =
  | "expired"
  | "pending"
  | "ready"
  | "rejected"
  | "verifying";

type HubEnrollmentEvidence = {
  bootstrapRecipe?: unknown;
  enrollmentId?: string;
  enrollmentToken?: string;
  hostId?: number | null;
  hubUrl?: string;
  installCommand?: string;
  rejection?: { code: string; message: string | null } | null;
  status?: HubEnrollmentStatus;
  target?: HubEnrollmentTarget;
};

type HubDeletedHostEvidence = {
  deletedAtMs: number;
  id: number;
};

type HubProbeConfiguration = {
  configuration: {
    enabledCollectorIds: unknown[];
    metricsCollectionIntervalSeconds: number;
    version: string;
  };
  mode: "inherit" | "override";
};

type HubProbeConfigurationUpdate = {
  configuration: {
    enabledCollectorIds: unknown[];
    metricsCollectionIntervalSeconds: number;
  };
  mode: string;
};

type HubEnrollmentTrackingRecord = {
  enrollmentId: string;
  hostId?: unknown;
  readError?: SerializedError | null;
  rejection?: unknown;
  status?: unknown;
  target?: unknown;
};

type HubApiRequestTimelineEntry = {
  error: unknown;
  method: string;
  pathname: string;
  status: number;
};

type HubCollectedEvidence = {
  apiTimeline: HubApiRequestTimelineEntry[];
  enrollments: HubEnrollmentTrackingRecord[];
};

const candidateManifestKeys = [
  "bootstrapRecipe",
  "candidate",
  "hub",
  "kind",
  "probeAssetSet",
  "releaseBaseline",
  "schemaVersion",
] as const;

function isReleaseE2ECandidateManifest(
  value: unknown,
): value is ReleaseE2ECandidateManifest {
  return (
    isUnknownRecord(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...candidateManifestKeys].sort())
  );
}

export type HubStateSnapshotRoot = {
  id: string;
  included?: boolean;
  path: string;
};

export type HubStateSnapshotEvidence = {
  baselineImageDigest: string;
  baselineVersion: string;
  hotDataFileCount: number;
  hotDataFiles: string[];
  manifestDigest: string;
  recoveryTime: string;
  roots: HubStateSnapshotRoot[];
  tool: string;
  version: string;
};

export type HubStateRestoreEvidence = {
  image: {
    activeManifestDigest: string;
    expectedManifestDigest: string;
  };
  restore: { manifestDigest: string; status: string };
  verify: { manifestDigest: string; status: string };
};

type CanonicalReportEvidenceTransport = {
  arm(input: { expectedProbeId: string }): void;
  armRepairClosure(input: { expectedProbeId: string }): void;
  diagnostics(): unknown;
  waitForEvidence(input: {
    timeoutMs: number;
  }): Promise<CanonicalReportEvidence>;
  waitForRepairClosureEvidence(input: {
    timeoutMs: number;
  }): Promise<RepairClosureCapture>;
};

type ScenarioHub = HubLifecycleClient & {
  captureBaselineStateSnapshot(input: {
    baselineImageDigest: string;
    baselineVersion: string;
  }): Promise<HubStateSnapshotEvidence>;
  restoreBaselineStateSnapshot(input: {
    baselineImageDigest: string;
    baselineVersion: string;
    expectedManifestDigest: string;
    recoveryTime: string;
  }): Promise<HubStateRestoreEvidence>;
  switchToCandidate(): Promise<{ activeHub: string }>;
};

type ReleaseScenarioContext = {
  canonicalReports?: CanonicalReportEvidenceTransport | null;
  host: ProbeHost;
  hub: ScenarioHub;
  infrastructure: unknown;
  releaseTestHost: ReleaseTestHostEvidence | null;
};

// Environment Seam 的公开 Module Interface：start 返回的参与者形状即本模块数据 Interface，
// 运行时仍由下方各 assert*ScenarioParticipants 逐场景复核方法清单，失败文本保持原实现。
type ReleaseScenarioEnvironment = {
  cleanup(input: {
    resources: ReleaseScenarioContext | null;
    runId: string;
  }): Promise<unknown>;
  start(input: {
    candidateManifest: ReleaseE2ECandidateManifest;
    hubMode?: string;
    runId: string;
    scenario?: string;
  }): Promise<ReleaseScenarioContext>;
};

type ReleaseScenarioOptions = {
  candidateManifest: unknown;
  environment: ReleaseScenarioEnvironment;
  evidenceSink: EvidenceSink;
  ownerPassword: string;
  runId: string;
  scenario: string;
  timing?: ReleaseScenarioTiming;
};

type UpgradeTransitionClassification = "compatible" | "replacement-required";

type ForwardLifecycleScenarioOptions = ReleaseScenarioOptions & {
  transitionClassification: UpgradeTransitionClassification;
};

type ScenarioError = Error & { code?: string };
type ScenarioFailureError = ScenarioError & {
  evidence?: unknown;
  evidenceWriteError?: SerializedError;
};
type TimelineCarryingError = ScenarioError & { timeline: ProbeOperation[] };
type OperationObservationError = ScenarioError & { timeline?: unknown[] };
type ObservationTimeoutError = ScenarioError & { lastValue?: unknown };

// 边界判据：抛出的观察错误携带 timeline 时，原实现只做 Array.isArray 结构复核。
// 这里沿用同一判据，元素类型取自本模块统一的 ProbeOperation 数据 Interface。
function isTimelineCarryingError(
  value: unknown,
): value is TimelineCarryingError {
  return isUnknownRecord(value) && Array.isArray(value.timeline);
}

type MetricHistoryAnchor = ReturnType<typeof compactMetricAnchor>;

type ProbeUpgradeTimelineOperation = ProbeOperation;

type AuditLogEvent = {
  action: string;
  actor?: string;
  details?: {
    code?: string;
    hostId?: number;
    mode?: string;
    newProbeId?: string;
    oldProbeId?: string;
    probeOperationId?: number;
    sourceProbeSha256?: unknown;
    target?: { hostId?: number; kind?: string };
    targetAssetSetDigest?: unknown;
    targetProbeVersion?: unknown;
  };
  id: number;
  occurredAtMs: number;
  outcome?: string;
  subjectId: string;
  subjectType: string;
};

const terminalProbeOperationStates = new Set<ProbeOperationState>([
  "succeeded",
  "failed",
  "superseded",
  "canceled",
]);

const hubHostOfflineAfterLocalUninstallMs = 90_000;
const localUninstallOfflineObservationHeadroomMs = 30_000;
const defaultLocalUninstallOfflineObservationTimeoutMs =
  hubHostOfflineAfterLocalUninstallMs +
  localUninstallOfflineObservationHeadroomMs;

export const releaseE2EScenarioRegistry = Object.freeze({
  "compatible-upgrade-uninstall": runCompatibleUpgradeUninstallScenario,
  "fresh-install-uninstall": runFreshInstallUninstallScenario,
  "hub-restore-compatibility-window": runHubRestoreCompatibilityWindowScenario,
  "post-replacement-repair-uninstall":
    runPostReplacementRepairUninstallScenario,
  "replacement-migration-uninstall": runReplacementMigrationUninstallScenario,
} satisfies Record<
  string,
  (options: ReleaseScenarioOptions) => Promise<unknown>
>);

export async function runReleaseE2EScenario(
  options: ReleaseScenarioOptions,
): Promise<unknown> {
  const scenario = options?.scenario;
  const runner = Object.entries(releaseE2EScenarioRegistry).find(
    ([name]) => name === scenario,
  )?.[1];
  if (!runner) {
    throw new Error(`unsupported Release E2E scenario: ${scenario}`);
  }
  return runner(options);
}

type ProbeIdentity = Awaited<ReturnType<ProbeHost["readProbeIdentity"]>>;
type HostProfileProjection = ReturnType<typeof stableHostProfileEvidence>;
type UninstallCompletionEvidence = Awaited<
  ReturnType<ProbeHost["verifyUninstallCompletion"]>
>;
type InstalledBundleRepairEvidence = Awaited<
  ReturnType<typeof proveInstalledBundleFailureRepair>
>;

type ScenarioResultEvidence = {
  error?: SerializedError;
  status: string;
};

type ScenarioCleanupEvidence = {
  environment?: unknown;
  host?: unknown;
};

type SerializedScenarioError = { error: SerializedError };

type ProbeConfigurationRoundTripEvidence = Awaited<
  ReturnType<typeof proveProbeConfigurationRoundTrip>
>;

type HubRestoreScenarioEvidence = {
  auditLog: unknown;
  baselineInstall: Awaited<ReturnType<ProbeHost["install"]>> | null;
  candidate: ReleaseE2ECandidateManifest["candidate"];
  cleanup: ScenarioCleanupEvidence | null;
  failureBoundary: unknown;
  hostEvidence:
    | Awaited<ReturnType<ProbeHost["collectEvidence"]>>
    | SerializedScenarioError
    | null;
  hubEvidence:
    | Awaited<ReturnType<HubLifecycleClient["collectEvidence"]>>
    | SerializedScenarioError
    | null;
  hostProfileContinuity: {
    allowedChanges: string[];
    candidateBeforeRestore: HostProfileProjection | null;
    restoredBaseline: HostProfileProjection | null;
  };
  identity: {
    afterRestore: ProbeIdentity | null;
    afterUpgrade: ProbeIdentity | null;
    beforeUpgrade: ProbeIdentity;
    hostId: number;
  } | null;
  image: {
    candidateDigest: string;
    expectedBaselineDigest: string;
    restoredBaselineDigest: string | null;
    snapshotVerify: HubStateRestoreEvidence["verify"] | null;
    stateRestore: HubStateRestoreEvidence["restore"] | null;
  };
  infrastructure: unknown;
  migration: {
    candidateProbeVersion: string;
    operationTimeline: ProbeOperation[];
    status: string;
  };
  migrationRetention: unknown;
  phase: string;
  protocol: {
    baselineProbeToCandidateHub: string;
    candidateProbeToBaselineHub: string;
  };
  probeConfiguration: { beforeReplacement: unknown; retained: unknown };
  releaseBaseline: ReturnType<typeof releaseBaselineEvidence>;
  releaseTestHost: ReleaseTestHostEvidence | null;
  reporting: {
    candidateHub: unknown;
    postReplacementCandidateHub: unknown;
    restoredBaselineHub: unknown;
  };
  result: ScenarioResultEvidence;
  runId: string;
  scenario: string;
  schemaVersion: number;
  snapshot: HubStateSnapshotEvidence | null;
  uninstall: {
    hostCompletion: UninstallCompletionEvidence | null;
    hubSoftDeleted: boolean;
    operationTimeline: ProbeOperation[];
    status: string;
  };
};

type RepairRunEvidence = Awaited<ReturnType<ProbeHost["repair"]>>;
type InstalledBundleBoundaryEvidence = Awaited<
  ReturnType<ProbeHost["assertInstalled"]>
>;

// post-replacement 失败边界载荷由 Host Harness 观察到的 JSON 提供，字段全部可选；
// 只有观察判据逐项复核通过才结束等待，hubFailureCode 稍后由失败 Upgrade 操作补写。
// post-replacement 失败观察载荷直接来自 Harness 输出的 JSON，字段判据只由边界校验器负责。
type PostReplacementUpgradeFailureEvidence = UnknownRecord;

type ProbeIdentityContinuityEvidence = {
  after: ProbeIdentity;
  before: ProbeIdentity;
  hostId: number;
};

type HubRuntimeHistoryEntry = {
  configDigest?: string;
  hub?: string;
  manifestDigest?: string;
  volume?: string;
};

type HubRuntimeEvidence = {
  activeHub?: string;
  activeManifestDigest?: string;
  baselineManifestDigest?: string;
  candidateManifestDigest?: string;
  containerConfigDigest?: string;
  containerInspect?: string;
  identityVerified?: boolean;
  imageInspect?: string;
  runtimeHistory?: HubRuntimeHistoryEntry[];
};

// 采集类证据字段：正常路径写入 Harness / Hub Client 的采集结果，采集失败时只写入序列化错误。
type HostEvidenceField = Partial<
  Awaited<ReturnType<ProbeHost["collectEvidence"]>>
> & { error?: SerializedError };

type HubEvidenceField = Partial<
  Awaited<ReturnType<HubLifecycleClient["collectEvidence"]>>
> & { error?: SerializedError; runtime?: HubRuntimeEvidence };

type BoundaryEvidenceValidation = {
  boundary?: unknown;
  error?: SerializedError;
  status: string;
};

// 边界校验器要求命令成功完成时证据必须满足的形状。
type SuccessfulCommandEvidence = {
  code: number;
  stderr: string;
  stdout: string;
};

type RepairBoundaryError = Error & {
  boundary?: string;
  cause?: unknown;
  code: string;
};

// Repair 边界校验器读取的证据载荷来自 Hub 与 Harness，属于外部输入。
type RepairBoundaryValidator = (
  source: UnknownRecord,
  candidateManifest: ReleaseE2ECandidateManifest,
) => void;

type PostReplacementRepairScenarioEvidence = {
  auditLog: AuditLogEvent[] | null;
  baselineInstall: Awaited<ReturnType<ProbeHost["install"]>> | null;
  boundaryEvidence?: ReturnType<typeof createRepairBoundaryEvidence>;
  boundaryEvidenceValidation: BoundaryEvidenceValidation | null;
  candidate: ReleaseE2ECandidateManifest["candidate"];
  cleanup: ScenarioCleanupEvidence | null;
  failureBoundary: PostReplacementUpgradeFailureEvidence | null;
  hostEvidence: HostEvidenceField | null;
  hubEvidence: HubEvidenceField | null;
  identityContinuity: ProbeIdentityContinuityEvidence | null;
  infrastructure: unknown;
  metrics: {
    afterRepair: ReturnType<typeof compactMetricsEvidence> | null;
    beforeUpgrade: ReturnType<typeof compactMetricsEvidence> | null;
  };
  operationTimeline: ProbeOperation[];
  phase: string;
  probeConfiguration: {
    afterRepair: ProbeConfigurationRoundTripEvidence | null;
    beforeUpgrade: ProbeConfigurationRoundTripEvidence | null;
  };
  releaseBaseline: ReturnType<typeof releaseBaselineEvidence>;
  releaseTestHost: ReleaseTestHostEvidence | null;
  repair: RepairRunEvidence | null;
  repairHostBoundary: InstalledBundleBoundaryEvidence | null;
  repairedHost: ReturnType<typeof compactHostEvidence> | null;
  result: ScenarioResultEvidence;
  runId: string;
  scenario: string;
  schemaVersion: number;
  uninstall: {
    hostCompletion: UninstallCompletionEvidence | null;
    hubSoftDeleted: boolean;
    operationTimeline: ProbeOperation[];
    status: string;
  };
  uninstallCompletion: UninstallCompletionEvidence | null;
  uninstallOperationTimeline: ProbeOperation[];
};

type ForwardLifecycleScenarioEvidence = {
  auditLog: AuditLogEvent[] | null;
  baselineInstall: Awaited<ReturnType<ProbeHost["install"]>> | null;
  candidate: ReleaseE2ECandidateManifest["candidate"];
  candidateHost: ReturnType<typeof compactHostEvidence> | null;
  cleanup: ScenarioCleanupEvidence | null;
  compatibility: {
    host: ReturnType<typeof compactHostEvidence>;
    status: string;
  } | null;
  hostBoundary: Awaited<ReturnType<ProbeHost["assertInstalled"]>> | null;
  hostEvidence: HostEvidenceField | null;
  hubEvidence: HubEvidenceField | null;
  identityContinuity: ProbeIdentityContinuityEvidence | null;
  infrastructure: unknown;
  manualRecovery: unknown;
  metrics: {
    afterUpgrade: ReturnType<typeof compactMetricsEvidence> | null;
    beforeUpgrade: ReturnType<typeof compactMetricsEvidence> | null;
  };
  migrationRetention: {
    configuration: unknown;
    hostAfter: unknown;
    hostBefore: unknown;
    metricHistory: unknown;
    postMetricHistory: unknown;
  } | null;
  operationTimeline: ProbeOperation[];
  phase: string;
  probeConfiguration: {
    afterUpgrade: ProbeConfigurationRoundTripEvidence | null;
    beforeUpgrade: ProbeConfigurationRoundTripEvidence | null;
  };
  releaseBaseline: ReturnType<typeof releaseBaselineEvidence>;
  releaseTestHost: ReleaseTestHostEvidence | null;
  result: ScenarioResultEvidence;
  runId: string;
  scenario: string;
  schemaVersion: number;
  uninstall: {
    hostCompletion: UninstallCompletionEvidence | null;
    hubSoftDeleted: boolean;
    operationTimeline: ProbeOperation[];
    status: string;
  };
  upgradeOperationTimeline: ProbeOperation[];
};

type FreshInstallScenarioEvidence = {
  auditLog: AuditLogEvent[] | null;
  candidate: ReleaseE2ECandidateManifest["candidate"];
  candidateIdentities: {
    hubDigest: string;
    probeAssetSetVersion: string;
  };
  canonicalRuntimeUnavailableReporting: {
    host:
      | Awaited<
          ReturnType<
            ProbeHost["restartCanonicalProbeWithoutObservationRuntime"]
          >
        >
      | undefined;
    ownerProjection: {
      host: ReturnType<typeof compactHostEvidence>;
      metricsUnchanged: boolean;
      reportedProbeConfigurationVersion?: string | null;
    };
    reporting: CanonicalReportEvidence | undefined;
  } | null;
  cleanup: ScenarioCleanupEvidence | null;
  diagnostics: UnknownRecord | null;
  finalLocalUninstall: Awaited<ReturnType<ProbeHost["localUninstall"]>> | null;
  host: ReturnType<typeof compactHostEvidence> | null;
  hostBoundary: Awaited<ReturnType<ProbeHost["assertInstalled"]>> | null;
  hostEvidence: HostEvidenceField | null;
  hubEvidence: HubEvidenceField | null;
  hubOnlyDeletion: {
    deletedHost: HubDeletedHostEvidence;
    permanentReportRejection: Awaited<
      ReturnType<ProbeHost["awaitPermanentReportRejection"]>
    >;
  } | null;
  initialInstall: Awaited<ReturnType<ProbeHost["install"]>> | null;
  infrastructure: unknown;
  installedBundleFailureRepair: Awaited<
    ReturnType<typeof proveInstalledBundleFailureRepair>
  > | null;
  localUninstall: {
    activeHost: ReturnType<typeof compactHostEvidence>;
    completion: Awaited<ReturnType<ProbeHost["localUninstall"]>>["completion"];
    offlineHost: ReturnType<typeof compactHostEvidence>;
    output: Awaited<ReturnType<ProbeHost["localUninstall"]>>["output"];
  } | null;
  metrics: ReturnType<typeof compactMetricsEvidence> | null;
  metricsHistory: ReturnType<typeof metricsHistoryEvidence> | null;
  phase: string;
  probeConfiguration: ProbeConfigurationRoundTripEvidence | null;
  reEnrollment: {
    enrollment: ReturnType<typeof compactEnrollmentEvidence>;
    host: ReturnType<typeof compactHostEvidence>;
    hostBoundary: Awaited<ReturnType<ProbeHost["assertInstalled"]>>;
    hostId: number;
    identity: {
      after: ProbeIdentity;
      before: ProbeIdentity;
    };
    installer: Awaited<ReturnType<ProbeHost["install"]>>;
    metrics: ReturnType<typeof compactMetricsEvidence>;
    metricsHistory: ReturnType<typeof metricsHistoryEvidence>;
    probeConfiguration: HubProbeConfiguration;
  } | null;
  repeatedAdd: {
    enrollment: ReturnType<typeof compactEnrollmentEvidence>;
    enrollmentStatus: ReturnType<typeof compactEnrollmentStatusEvidence>;
    hostAfter: ReturnType<typeof stableHubHostProjection>;
    hostBefore: ReturnType<typeof stableHubHostProjection>;
    rejection: Awaited<ReturnType<ProbeHost["rejectRepeatedInstall"]>>;
    stateAfter: Awaited<ReturnType<ProbeHost["captureInstallationState"]>>;
    stateBefore: Awaited<ReturnType<ProbeHost["captureInstallationState"]>>;
  } | null;
  releaseBaseline: ReturnType<typeof releaseBaselineEvidence>;
  releaseTestHost: ReleaseTestHostEvidence | null;
  result: ScenarioResultEvidence;
  runId: string;
  scenario: string;
  schemaVersion: number;
};

async function runHubRestoreCompatibilityWindowScenario({
  candidateManifest,
  environment,
  evidenceSink,
  ownerPassword,
  runId,
  scenario,
  timing = {},
}: ReleaseScenarioOptions) {
  assertRunId(runId);
  assertCandidateManifest(candidateManifest);
  if (!environment?.start || !environment?.cleanup || !evidenceSink?.write) {
    throw new Error("Release E2E environment and evidence sink are required");
  }
  const baseline = candidateManifest.releaseBaseline;

  const poll = normalizedPollTiming(timing);
  const evidence: HubRestoreScenarioEvidence = {
    auditLog: null,
    baselineInstall: null,
    candidate: candidateManifest.candidate,
    cleanup: null,
    failureBoundary: null,
    hostEvidence: null,
    hubEvidence: null,
    hostProfileContinuity: {
      allowedChanges: [
        "collection and observation timestamps",
        "cpuBaseFrequencyMhz",
        "filesystems[].availableBytes",
        "networkInterfaces with veth names",
        "processCount",
        "threadCount",
      ],
      candidateBeforeRestore: null,
      restoredBaseline: null,
    },
    identity: null,
    image: {
      candidateDigest: candidateManifest.hub.digest,
      expectedBaselineDigest: baseline.hub.imageDigest,
      restoredBaselineDigest: null,
      snapshotVerify: null,
      stateRestore: null,
    },
    infrastructure: null,
    migration: {
      candidateProbeVersion: candidateManifest.probeAssetSet.version,
      operationTimeline: [],
      status: "pending",
    },
    migrationRetention: null,
    phase: "scenario-running",
    protocol: {
      baselineProbeToCandidateHub: "pending",
      candidateProbeToBaselineHub: "pending",
    },
    probeConfiguration: { beforeReplacement: null, retained: null },
    releaseBaseline: releaseBaselineEvidence(baseline),
    releaseTestHost: null,
    reporting: {
      candidateHub: null,
      postReplacementCandidateHub: null,
      restoredBaselineHub: null,
    },
    result: { status: "running" },
    runId,
    scenario,
    schemaVersion: 2,
    snapshot: null,
    uninstall: {
      hostCompletion: null,
      hubSoftDeleted: false,
      operationTimeline: [],
      status: "pending",
    },
  };
  let activeBoundary = "infrastructure";
  let resources: ReleaseScenarioContext | null = null;
  let primaryError: unknown = null;
  let evidenceWriteError: unknown = null;
  let finalEvidence: unknown = evidence;

  try {
    resources = await environment.start({
      candidateManifest,
      hubMode: "baseline",
      runId,
      scenario,
    });
    const { host, hub } = resources;
    assertHubRestoreScenarioParticipants(host, hub);
    evidence.infrastructure = resources.infrastructure ?? null;
    evidence.releaseTestHost = resources.releaseTestHost ?? null;

    await host.assertDisposable(runId);
    await hub.authenticate(ownerPassword);
    const initialHosts = await hub.listHosts();
    if (!Array.isArray(initialHosts) || initialHosts.length !== 0) {
      throw assertionError(
        "restore_baseline_hub_not_empty",
        "Hub Restore scenario requires new Release Baseline Hub state",
      );
    }
    const enrollment = await hub.createEnrollment();
    if (!enrollment?.installCommand) {
      throw assertionError(
        "enrollment_command_missing",
        "Release Baseline Hub did not return its official Probe install command",
      );
    }
    evidence.baselineInstall = await host.install(enrollment, runId);
    await assertReleaseBaselineInstalled(host, baseline, runId);
    const hostSummary = await waitForObservation({
      code: "restore_probe_enrollment_timeout",
      label: "Release Baseline Probe enrollment before Hub State Snapshot",
      observe: async () => {
        const hosts = await hub.listHosts();
        return Array.isArray(hosts) && hosts.length === 1 ? hosts[0] : null;
      },
      poll,
      ready: (value) =>
        value !== null &&
        value !== undefined &&
        Number.isSafeInteger(value.id) &&
        value.id > 0,
    });
    const hostId = hostSummary.id;
    const baselineIdentity = await host.readProbeIdentity(runId);
    evidence.identity = {
      afterRestore: null,
      afterUpgrade: null,
      beforeUpgrade: baselineIdentity,
      hostId,
    };
    await waitForObservation({
      code: "restore_baseline_reporting_timeout",
      label: "Release Baseline core reporting before Hub State Snapshot",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
    });
    await waitForObservation({
      code: "restore_baseline_metrics_timeout",
      label: "Release Baseline portable Metrics before Hub State Snapshot",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: hasAdvancingPortableMetrics,
    });
    activeBoundary = "snapshot";
    evidence.snapshot = await hub.captureBaselineStateSnapshot({
      baselineImageDigest: baseline.hub.imageDigest,
      baselineVersion: baseline.tag,
    });
    assertLiveHubStateSnapshotEvidence(evidence.snapshot, baseline);

    activeBoundary = "migration";
    await hub.switchToCandidate();
    await hub.authenticate(ownerPassword);
    await waitForObservation({
      code: "restore_baseline_probe_candidate_hub_timeout",
      label: "Release Baseline Probe reporting to Candidate Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
    });
    evidence.protocol.baselineProbeToCandidateHub = "succeeded";
    const probeBeforeRestoreVersion = candidateManifest.probeAssetSet.version;
    await host.beginUpgradeOwnershipTransition(
      runId,
      candidateManifest.probeAssetSet.version,
    );
    const requestedUpgrade = await hub.requestProbeUpgrade(hostId);
    if (
      requestedUpgrade.targetProbeVersion !==
      candidateManifest.probeAssetSet.version
    ) {
      throw assertionError(
        "probe_upgrade_target_mismatch",
        "Hub Restore scenario Upgrade did not target the Candidate Probe",
      );
    }
    evidence.migration.operationTimeline = [requestedUpgrade];
    await host.bindUpgradeOwnershipTransition(runId, requestedUpgrade);
    const restoredUpgradeTimeline = await hub.waitForProbeOperation(
      requestedUpgrade,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    evidence.migration.operationTimeline = restoredUpgradeTimeline;
    validateSuccessfulProbeUpgradeTimeline(
      evidence.migration.operationTimeline,
    );
    // 上一条判定已保证 timeline 至少含 request 与 terminal 两项，这里只是把该事实交给类型系统。
    const restoredTerminalUpgrade = restoredUpgradeTimeline.at(-1);
    if (!restoredTerminalUpgrade) {
      throw assertionError(
        "probe_upgrade_timeline_incomplete",
        "Probe Upgrade did not record its request and terminal operation evidence",
      );
    }
    await host.completeUpgradeOwnershipTransition(
      runId,
      restoredTerminalUpgrade,
    );
    await host.assertInstalled(runId, probeBeforeRestoreVersion);
    activeBoundary = "identity";
    const upgradedIdentity = await host.readProbeIdentity(runId);
    assertSameProbeIdentity(baselineIdentity, upgradedIdentity, "Upgrade");
    evidence.identity.afterUpgrade = upgradedIdentity;
    activeBoundary = "reporting";
    const candidateHost = await waitForObservation({
      code: "restore_candidate_probe_reporting_timeout",
      label: "Candidate Probe core reporting to Candidate Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, probeBeforeRestoreVersion),
    });
    const candidateMetrics = await waitForObservation({
      code: "restore_candidate_metrics_timeout",
      label: "Candidate Probe portable Metrics before Hub Restore",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: hasAdvancingPortableMetrics,
    });
    const metricCheckpoint = latestPortableMetric(candidateMetrics);
    if (!metricCheckpoint) {
      throw assertionError(
        "restore_metrics_checkpoint_missing",
        "Hub Restore scenario has no Candidate Probe Metrics checkpoint",
      );
    }
    evidence.reporting.candidateHub = {
      host: compactHostEvidence(candidateHost),
      metrics: compactMetricsEvidence(candidateMetrics),
    };
    evidence.hostProfileContinuity.candidateBeforeRestore =
      stableHostProfileEvidence(candidateHost.hostProfile);
    evidence.migration.status = "succeeded";

    activeBoundary = "image";
    const restored = await hub.restoreBaselineStateSnapshot({
      baselineImageDigest: baseline.hub.imageDigest,
      baselineVersion: baseline.tag,
      expectedManifestDigest: evidence.snapshot.manifestDigest,
      recoveryTime: evidence.snapshot.recoveryTime,
    });
    assertLiveHubRestoreEvidence(
      restored,
      evidence.snapshot.manifestDigest,
      baseline.hub.imageDigest,
    );
    evidence.image.restoredBaselineDigest = restored.image.activeManifestDigest;
    evidence.image.snapshotVerify = restored.verify;
    evidence.image.stateRestore = restored.restore;

    activeBoundary = "protocol";
    await hub.authenticate(ownerPassword);
    const restoredHosts = await hub.listHosts();
    if (
      !Array.isArray(restoredHosts) ||
      restoredHosts.length !== 1 ||
      restoredHosts[0]?.id !== hostId
    ) {
      throw assertionError(
        "restored_host_state_mismatch",
        "Hub Restore did not recover the original Host",
      );
    }
    const restoredHost = await waitForObservation({
      code: "candidate_probe_baseline_hub_compatibility_timeout",
      label: "Candidate Probe reporting to restored Release Baseline Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, probeBeforeRestoreVersion),
    });
    evidence.hostProfileContinuity.restoredBaseline = stableHostProfileEvidence(
      restoredHost.hostProfile,
    );
    assertStableHostProfileContinuity(
      evidence.hostProfileContinuity.candidateBeforeRestore,
      evidence.hostProfileContinuity.restoredBaseline,
    );
    await host.assertInstalled(runId, probeBeforeRestoreVersion);
    activeBoundary = "identity";
    const restoredIdentity = await host.readProbeIdentity(runId);
    assertSameProbeIdentity(baselineIdentity, restoredIdentity, "Hub Restore");
    evidence.identity.afterRestore = restoredIdentity;
    activeBoundary = "reporting";
    const restoredMetrics = await waitForObservation({
      code: "candidate_probe_restored_metrics_timeout",
      label: "Candidate Probe portable Metrics after Hub Restore",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: (samples) =>
        hasAdvancingPortableMetrics(samples) &&
        isUnknownArray(samples) &&
        metricsAdvanceBeyond(samples, metricCheckpoint),
    });
    evidence.protocol.candidateProbeToBaselineHub = "succeeded";
    evidence.reporting.restoredBaselineHub = {
      host: compactHostEvidence(restoredHost),
      metrics: compactMetricsEvidence(restoredMetrics),
    };

    activeBoundary = "uninstall";
    await hub.switchToCandidate();
    await hub.authenticate(ownerPassword);
    await waitForObservation({
      code: "candidate_probe_post_restore_hub_timeout",
      label: "Candidate Probe reporting after returning to Candidate Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version),
    });
    const requestedUninstall = await hub.requestProbeUninstall(hostId);
    evidence.uninstall.operationTimeline = [requestedUninstall];
    evidence.uninstall.operationTimeline = await hub.waitForProbeOperation(
      requestedUninstall,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    const finalUninstall = evidence.uninstall.operationTimeline.at(-1);
    if (finalUninstall?.state !== "succeeded" || finalUninstall.failure) {
      throw assertionError(
        "probe_uninstall_failed",
        `Probe Uninstall after Hub Restore did not succeed: ${JSON.stringify(finalUninstall)}`,
      );
    }
    evidence.uninstall.hubSoftDeleted = await hub.isHostSoftDeleted(hostId);
    if (!evidence.uninstall.hubSoftDeleted) {
      throw assertionError(
        "host_not_soft_deleted",
        "Probe Uninstall after Hub Restore succeeded but the Host remains active",
      );
    }
    evidence.uninstall.hostCompletion =
      await host.verifyUninstallCompletion(runId);
    if (
      evidence.uninstall.hostCompletion?.clean !== true ||
      evidence.uninstall.hostCompletion?.journaldRetained !== true ||
      evidence.uninstall.hostCompletion?.sharedDependenciesRetained !== true
    ) {
      throw assertionError(
        "probe_uninstall_residue",
        `Host did not satisfy Probe Uninstall Completion after Hub Restore: ${JSON.stringify(evidence.uninstall.hostCompletion)}`,
      );
    }
    evidence.uninstall.status = "succeeded";
    evidence.result = { status: "succeeded" };
    evidence.phase = "succeeded";
  } catch (error) {
    primaryError = error;
    evidence.failureBoundary = activeBoundary;
    if (isTimelineCarryingError(error)) {
      if (error.timeline[0]?.kind === "probe_uninstall") {
        evidence.uninstall.operationTimeline = error.timeline;
      } else {
        evidence.migration.operationTimeline = error.timeline;
      }
    }
    evidence.result = { error: serializedError(error), status: "failed" };
    evidence.phase = "failed";
  } finally {
    if (resources?.hub?.collectEvidence) {
      try {
        evidence.hubEvidence = await resources.hub.collectEvidence();
      } catch (error) {
        evidence.hubEvidence = { error: serializedError(error) };
      }
    }
    if (resources?.host?.collectEvidence) {
      try {
        evidence.hostEvidence = await resources.host.collectEvidence(runId);
      } catch (error) {
        evidence.hostEvidence = { error: serializedError(error) };
      }
    }
    const cleanup: ScenarioCleanupEvidence = {};
    if (resources?.host?.cleanup) {
      try {
        cleanup.host = await resources.host.cleanup(runId);
      } catch (error) {
        cleanup.host = { error: serializedError(error) };
      }
    }
    try {
      cleanup.environment = await environment.cleanup({ resources, runId });
    } catch (error) {
      cleanup.environment = { error: serializedError(error) };
    }
    evidence.cleanup = cleanup;
    if (!primaryError && cleanupDidNotSucceed(cleanup)) {
      primaryError = assertionError(
        "release_e2e_cleanup_failed",
        "Release E2E cleanup did not remove all run-owned state",
      );
      evidence.failureBoundary = "cleanup";
      evidence.result = {
        error: serializedError(primaryError),
        status: "failed",
      };
      evidence.phase = "failed";
    }
    finalEvidence = redactReleaseE2EEvidence(evidence, {
      candidateManifest,
      secrets: [ownerPassword],
    });
    try {
      await evidenceSink.write(finalEvidence);
    } catch (error) {
      evidenceWriteError = error;
      if (!primaryError) {
        primaryError = assertionError(
          "release_e2e_evidence_write_failed",
          `Release E2E evidence could not be written: ${String(objectView(error).message)}`,
        );
      }
    }
  }

  if (primaryError) {
    const failure: ScenarioFailureError = new Error(
      `Release E2E ${scenario} failed at ${evidence.failureBoundary}: ${redactSensitiveText(objectView(primaryError).message, [ownerPassword])}`,
    );
    const primaryCode = objectView(primaryError).code;
    failure.code =
      typeof primaryCode === "string" ? primaryCode : "release_e2e_failed";
    failure.evidence = finalEvidence;
    if (evidenceWriteError) {
      failure.evidenceWriteError = serializedError(evidenceWriteError);
    }
    throw failure;
  }
  return evidence.result;
}

async function runPostReplacementRepairUninstallScenario({
  candidateManifest,
  environment,
  evidenceSink,
  ownerPassword,
  runId,
  scenario,
  timing = {},
}: ReleaseScenarioOptions) {
  assertRunId(runId);
  assertCandidateManifest(candidateManifest);
  if (!environment?.start || !environment?.cleanup || !evidenceSink?.write) {
    throw new Error("Release E2E environment and evidence sink are required");
  }
  const baseline = candidateManifest.releaseBaseline;

  const poll = normalizedPollTiming(timing);
  const evidence: PostReplacementRepairScenarioEvidence = {
    auditLog: null,
    baselineInstall: null,
    boundaryEvidenceValidation: null,
    candidate: candidateManifest.candidate,
    cleanup: null,
    failureBoundary: null,
    hostEvidence: null,
    hubEvidence: null,
    identityContinuity: null,
    infrastructure: null,
    metrics: { afterRepair: null, beforeUpgrade: null },
    operationTimeline: [],
    phase: "scenario-running",
    probeConfiguration: { afterRepair: null, beforeUpgrade: null },
    releaseBaseline: releaseBaselineEvidence(baseline),
    releaseTestHost: null,
    repair: null,
    repairHostBoundary: null,
    repairedHost: null,
    result: { status: "running" },
    runId,
    scenario,
    schemaVersion: 2,
    uninstallOperationTimeline: [],
    uninstallCompletion: null,
    uninstall: {
      hostCompletion: null,
      hubSoftDeleted: false,
      operationTimeline: [],
      status: "pending",
    },
  };
  let resources: ReleaseScenarioContext | null = null;
  let primaryError: unknown = null;
  let evidenceWriteError: unknown = null;
  let finalEvidence: unknown = evidence;

  try {
    resources = await environment.start({
      candidateManifest,
      hubMode: "baseline",
      runId,
      scenario,
    });
    const { host, hub } = resources;
    assertRepairScenarioParticipants(host, hub);
    evidence.infrastructure = resources.infrastructure ?? null;
    evidence.releaseTestHost = resources.releaseTestHost ?? null;

    await host.assertDisposable(runId);
    await hub.authenticate(ownerPassword);
    const initialHosts = await hub.listHosts();
    if (!Array.isArray(initialHosts) || initialHosts.length !== 0) {
      throw assertionError(
        "repair_baseline_hub_not_empty",
        "Probe Repair scenario requires new Release Baseline Hub state",
      );
    }
    const enrollment = await hub.createEnrollment();
    if (!enrollment?.installCommand) {
      throw assertionError(
        "enrollment_command_missing",
        "Release Baseline Hub did not return its official Probe install command",
      );
    }
    evidence.baselineInstall = await host.install(enrollment, runId);
    await assertReleaseBaselineInstalled(host, baseline, runId);
    const hostSummary = await waitForObservation({
      code: "repair_probe_enrollment_timeout",
      label: "Release Baseline Probe enrollment for Repair",
      observe: async () => {
        const hosts = await hub.listHosts();
        return Array.isArray(hosts) && hosts.length === 1 ? hosts[0] : null;
      },
      poll,
      ready: (value) =>
        value !== null &&
        value !== undefined &&
        Number.isSafeInteger(value.id) &&
        value.id > 0,
    });
    const hostId = hostSummary.id;
    const baselineIdentity = await host.readProbeIdentity(runId);
    await waitForObservation({
      code: "repair_baseline_reporting_timeout",
      label: "Release Baseline Probe reporting before Repair scenario Upgrade",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
    });
    evidence.metrics.beforeUpgrade = compactMetricsEvidence(
      await waitForObservation({
        code: "repair_baseline_metrics_timeout",
        label: "Release Baseline portable Metrics before Repair",
        observe: () => hub.getHostMetrics(hostId),
        poll,
        ready: hasAdvancingPortableMetrics,
      }),
    );
    const metricCheckpoint = latestPortableMetric(
      await hub.getHostMetrics(hostId),
    );
    if (!metricCheckpoint) {
      throw assertionError(
        "repair_metrics_checkpoint_missing",
        "Repair scenario has no pre-Upgrade portable Metrics checkpoint",
      );
    }
    await hub.switchToCandidate();
    await hub.authenticate(ownerPassword);
    await waitForObservation({
      code: "repair_baseline_probe_candidate_hub_compatibility_timeout",
      label: "Release Baseline Probe reporting to Candidate Hub before Repair",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
    });
    evidence.probeConfiguration.beforeUpgrade =
      await proveProbeConfigurationRoundTrip({ hostId, hub, poll });

    const candidateProbeVersion = candidateManifest.probeAssetSet.version;
    const repairIdentity = baselineIdentity;
    await host.beginUpgradeOwnershipTransition(runId, candidateProbeVersion);
    await host.armPostReplacementRestartFault(runId, candidateProbeVersion);
    const requestedUpgrade = await hub.requestProbeUpgrade(hostId);
    if (requestedUpgrade.targetProbeVersion !== candidateProbeVersion) {
      throw assertionError(
        "probe_upgrade_target_mismatch",
        "Probe Repair scenario Upgrade did not target the Candidate Probe",
      );
    }
    await host.bindUpgradeOwnershipTransition(runId, requestedUpgrade);
    evidence.operationTimeline = [requestedUpgrade];
    evidence.failureBoundary = await waitForObservation({
      code: "post_replacement_upgrade_failure_timeout",
      label: "local post-replacement Upgrade failure before Repair",
      observe: async () =>
        objectView(
          await host.assertPostReplacementUpgradeFailure(
            runId,
            requestedUpgrade,
            candidateProbeVersion,
          ),
        ),
      poll,
      ready: (value) =>
        value?.localFailureCode === "post_replacement_restart_failure" &&
        value.operationId === requestedUpgrade.id &&
        value.probeVersion === candidateProbeVersion,
    });
    await host.removePostReplacementRestartFault(runId);
    evidence.repair = await host.repair(runId);
    evidence.repairHostBoundary = await host.assertInstalled(
      runId,
      candidateProbeVersion,
    );
    if (evidence.repairHostBoundary?.probeVersion !== candidateProbeVersion) {
      throw assertionError(
        "probe_repair_target_mismatch",
        "Probe Repair did not restore the already-installed Candidate Probe version",
      );
    }
    const repairedIdentity = await host.readProbeIdentity(runId);
    if (
      repairedIdentity.probeId !== repairIdentity.probeId ||
      repairedIdentity.identitySha256 !== repairIdentity.identitySha256
    ) {
      throw assertionError(
        "probe_identity_changed",
        "Probe Repair changed the Probe Identity",
      );
    }
    evidence.identityContinuity = {
      after: repairedIdentity,
      before: repairIdentity,
      hostId,
    };
    evidence.operationTimeline = await hub.waitForProbeOperation(
      requestedUpgrade,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    const failedUpgrade = evidence.operationTimeline.at(-1);
    if (failedUpgrade?.state !== "failed" || !failedUpgrade.failure) {
      throw assertionError(
        "post_replacement_upgrade_not_failed",
        `Probe Upgrade did not retain a failed operation after Repair: ${JSON.stringify(failedUpgrade)}`,
      );
    }
    evidence.failureBoundary.hubFailureCode = failedUpgrade.failure.code;
    await host.completeRepairOwnershipTransition(runId, failedUpgrade);

    const preservedFailure = await hub.getProbeOperation(failedUpgrade);
    assertStableTerminalOperation(failedUpgrade, preservedFailure);
    if (preservedFailure.state !== "failed") {
      throw assertionError(
        "repair_rewrote_failed_upgrade",
        "Probe Repair rewrote the failed Probe Upgrade operation",
      );
    }
    const repairedHost = await waitForObservation({
      code: "candidate_probe_repair_reporting_timeout",
      label: "Candidate Probe core reporting after Repair",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateProbeVersion),
    });
    evidence.repairedHost = compactHostEvidence(repairedHost);
    evidence.metrics.afterRepair = compactMetricsEvidence(
      await waitForObservation({
        code: "candidate_probe_repair_metrics_timeout",
        label: "Candidate Probe portable Metrics progression after Repair",
        observe: () => hub.getHostMetrics(hostId),
        poll,
        ready: (samples) =>
          hasAdvancingPortableMetrics(samples) &&
          isUnknownArray(samples) &&
          metricsAdvanceBeyond(samples, metricCheckpoint),
      }),
    );
    evidence.probeConfiguration.afterRepair =
      await proveProbeConfigurationRoundTrip({ hostId, hub, poll });

    const requestedUninstall = await hub.requestProbeUninstall(hostId);
    evidence.uninstallOperationTimeline = [requestedUninstall];
    evidence.uninstallOperationTimeline = await hub.waitForProbeOperation(
      requestedUninstall,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    evidence.uninstall.operationTimeline = evidence.uninstallOperationTimeline;
    const finalUninstall = evidence.uninstallOperationTimeline.at(-1);
    if (finalUninstall?.state !== "succeeded" || finalUninstall.failure) {
      throw assertionError(
        "probe_uninstall_failed",
        `Probe Uninstall after Repair failed: ${JSON.stringify(finalUninstall)}`,
      );
    }
    evidence.uninstall.hubSoftDeleted = await hub.isHostSoftDeleted(hostId);
    if (!evidence.uninstall.hubSoftDeleted) {
      throw assertionError(
        "host_not_soft_deleted",
        "Probe Uninstall after Repair did not soft-delete the Host",
      );
    }
    const auditLog = await hub.getAuditLog();
    evidence.auditLog = assertBaselineUpgradeAuditLog(
      auditLog,
      hostId,
      requestedUpgrade.id,
      requestedUninstall.id,
      candidateProbeVersion,
    );
    evidence.uninstallCompletion = await host.verifyUninstallCompletion(runId);
    evidence.uninstall.hostCompletion = evidence.uninstallCompletion;
    if (
      evidence.uninstallCompletion?.clean !== true ||
      evidence.uninstallCompletion?.journaldRetained !== true ||
      evidence.uninstallCompletion?.sharedDependenciesRetained !== true
    ) {
      throw assertionError(
        "probe_uninstall_residue",
        `Host did not satisfy Probe Uninstall Completion after Repair: ${JSON.stringify(evidence.uninstallCompletion)}`,
      );
    }
    evidence.uninstall.status = "succeeded";
    evidence.result = { status: "succeeded" };
    evidence.phase = "succeeded";
  } catch (error) {
    primaryError = error;
    if (isTimelineCarryingError(error)) {
      if (
        error.timeline.some(
          (operation) => operation?.kind === "probe_uninstall",
        )
      ) {
        evidence.uninstallOperationTimeline = error.timeline;
        evidence.uninstall.operationTimeline = error.timeline;
      } else {
        evidence.operationTimeline = error.timeline;
      }
    }
    evidence.result = { error: serializedError(error), status: "failed" };
    evidence.phase = "failed";
  } finally {
    if (resources?.hub?.collectEvidence) {
      try {
        evidence.hubEvidence = await resources.hub.collectEvidence();
      } catch (error) {
        evidence.hubEvidence = { error: serializedError(error) };
      }
    }
    if (resources?.host?.collectEvidence) {
      try {
        evidence.hostEvidence = await resources.host.collectEvidence(runId);
      } catch (error) {
        evidence.hostEvidence = { error: serializedError(error) };
      }
    }
    const cleanup: ScenarioCleanupEvidence = {};
    if (resources?.host?.cleanup) {
      try {
        cleanup.host = await resources.host.cleanup(runId);
      } catch (error) {
        cleanup.host = { error: serializedError(error) };
      }
    }
    try {
      cleanup.environment = await environment.cleanup({ resources, runId });
    } catch (error) {
      cleanup.environment = { error: serializedError(error) };
    }
    evidence.cleanup = cleanup;
    evidence.boundaryEvidence = createRepairBoundaryEvidence(evidence);
    if (!primaryError && evidence.phase === "succeeded") {
      try {
        validateSuccessfulRepairBoundaryEvidence(evidence, candidateManifest);
        evidence.boundaryEvidenceValidation = { status: "succeeded" };
      } catch (error) {
        primaryError = error;
        evidence.boundaryEvidenceValidation = {
          boundary: objectView(error).boundary ?? null,
          error: serializedError(error),
          status: "failed",
        };
        evidence.result = {
          error: serializedError(error),
          status: "failed",
        };
        evidence.phase = "failed";
      }
    } else if (!primaryError && cleanupDidNotSucceed(cleanup)) {
      primaryError = assertionError(
        "release_e2e_cleanup_failed",
        "Release E2E cleanup did not remove all run-owned state",
      );
    }
    finalEvidence = redactReleaseE2EEvidence(evidence, {
      candidateManifest,
      secrets: [ownerPassword],
    });
    try {
      await evidenceSink.write(finalEvidence);
    } catch (error) {
      evidenceWriteError = error;
      if (!primaryError) {
        primaryError = assertionError(
          "release_e2e_evidence_write_failed",
          `Release E2E evidence could not be written: ${String(objectView(error).message)}`,
        );
      }
    }
  }

  if (primaryError) {
    const failure: ScenarioFailureError = new Error(
      `Release E2E ${scenario} failed: ${redactSensitiveText(objectView(primaryError).message, [ownerPassword])}`,
    );
    const primaryCode = objectView(primaryError).code;
    failure.code =
      typeof primaryCode === "string" ? primaryCode : "release_e2e_failed";
    failure.evidence = finalEvidence;
    if (evidenceWriteError) {
      failure.evidenceWriteError = serializedError(evidenceWriteError);
    }
    throw failure;
  }
  return evidence.result;
}

// 未信任证据中的列表读取：非数组按空列表处理，与原 optional chain 取下标得到 undefined 一致。
function observationList(value: unknown): readonly unknown[] {
  return isUnknownArray(value) ? value : [];
}

function createRepairBoundaryEvidence(evidence: unknown) {
  const source = objectView(evidence);
  const hostEvidence = objectView(source.hostEvidence);
  const hubEvidence = objectView(source.hubEvidence);
  const repairHostBoundary = objectView(source.repairHostBoundary);
  return {
    cleanup: {
      orchestrator: source.cleanup ?? null,
      uninstallCompletion: source.uninstallCompletion ?? null,
    },
    filesystem: {
      afterRepair: repairHostBoundary.inventory ?? null,
      postUninstall: hostEvidence.inventory ?? null,
    },
    hubApi: {
      apiTimeline: hubEvidence.apiTimeline ?? null,
      auditLog: source.auditLog ?? null,
      repairedHost: source.repairedHost ?? null,
      runtime: hubEvidence.runtime ?? null,
    },
    identity: source.identityContinuity ?? null,
    privilege: {
      afterRepair: repairHostBoundary.sudoers ?? null,
      postUninstall: hostEvidence.sudoers ?? null,
    },
    probeOperation: {
      uninstall: source.uninstallOperationTimeline ?? [],
      upgrade: source.operationTimeline ?? [],
    },
    systemd: {
      afterRepair: repairHostBoundary.service ?? null,
      journald: hostEvidence.journald ?? null,
      postUninstall: hostEvidence.systemd ?? null,
    },
  };
}

export function validateSuccessfulRepairBoundaryEvidence(
  evidence: unknown,
  candidateManifest: unknown,
): unknown {
  assertCandidateManifest(candidateManifest);
  if (objectView(objectView(evidence).hostEvidence).error) {
    throw repairBoundaryEvidenceError(
      "filesystem",
      new Error("Host evidence collection failed"),
    );
  }
  const validators: readonly [
    boundary: string,
    validate: RepairBoundaryValidator,
  ][] = [
    ["hub-api", validateRepairHubApiEvidence],
    ["probe-operation", validateRepairOperationEvidence],
    ["systemd", validateRepairSystemdEvidence],
    ["privilege", validateRepairPrivilegeEvidence],
    ["filesystem", validateRepairFilesystemEvidence],
    ["identity", validateRepairIdentityEvidence],
    ["cleanup", validateRepairCleanupEvidence],
  ];
  const source = objectView(evidence);
  for (const [boundary, validate] of validators) {
    try {
      validate(source, candidateManifest);
    } catch (cause) {
      throw repairBoundaryEvidenceError(boundary, cause);
    }
  }
  return evidence;
}

function repairBoundaryEvidenceError(
  boundary: string,
  cause: unknown,
): RepairBoundaryError {
  const error: RepairBoundaryError = assertionError(
    "repair_boundary_evidence_invalid",
    `Probe Repair ${boundary} evidence is invalid: ${String(objectView(cause).message)}`,
  );
  error.boundary = boundary;
  error.cause = cause;
  return error;
}

function validateRepairHubApiEvidence(
  source: UnknownRecord,
  candidateManifest: ReleaseE2ECandidateManifest,
): void {
  const hostEvidence = objectView(source.hostEvidence);
  if (hostEvidence.error) {
    throw new Error("Hub evidence collection failed");
  }
  const hubEvidence = objectView(source.hubEvidence);
  const identityContinuity = objectView(source.identityContinuity);
  const hostId = identityContinuity.hostId;
  assertPositiveInteger(hostId, "Repair Host ID");
  const upgrade = objectView(observationList(source.operationTimeline)[0]);
  const uninstall = objectView(
    observationList(source.uninstallOperationTimeline)[0],
  );
  const upgradeOperationId = upgrade.id;
  const uninstallOperationId = uninstall.id;
  assertPositiveInteger(upgradeOperationId, "Probe Upgrade operation ID");
  assertPositiveInteger(uninstallOperationId, "Probe Uninstall operation ID");
  if (!isAuditLogEventList(source.auditLog)) {
    throw new Error("Hub Audit Log evidence is not a list");
  }
  assertBaselineUpgradeAuditLog(
    source.auditLog,
    hostId,
    upgradeOperationId,
    uninstallOperationId,
    candidateManifest.probeAssetSet.version,
  );

  const apiTimelineValue = hubEvidence.apiTimeline;
  if (
    !isUnknownArray(apiTimelineValue) ||
    apiTimelineValue.length === 0 ||
    apiTimelineValue.some((value) => {
      const entry = objectView(value);
      const expectedDeletedHostObservation =
        entry.method === "GET" &&
        entry.pathname === `/api/web/hosts/${hostId}` &&
        entry.status === 404 &&
        typeof entry.error === "string" &&
        entry.error.length > 0;
      const status = entry.status;
      return (
        !isUnknownRecord(value) ||
        !/^(?:DELETE|GET|POST|PUT)$/.test(regexInput(entry.method)) ||
        typeof entry.pathname !== "string" ||
        !entry.pathname.startsWith("/api/") ||
        !Number.isInteger(status) ||
        (!expectedDeletedHostObservation &&
          ((typeof status === "number" && status < 200) ||
            (typeof status === "number" && status >= 300) ||
            entry.error !== null))
      );
    })
  ) {
    throw new Error("Hub API timeline is missing or contains a failed request");
  }
  const apiTimeline = apiTimelineValue;
  const expectedRequests: readonly [
    method: string,
    pathname: string,
    status?: number,
  ][] = [
    ["POST", "/api/web/auth/login"],
    ["POST", `/api/web/hosts/${hostId}/probe-upgrade-requests`],
    ["DELETE", `/api/web/hosts/${hostId}`],
    ["GET", `/api/web/hosts/${hostId}`, 404],
    ["GET", "/api/web/audit-log?limit=200"],
  ];
  for (const expected of expectedRequests) {
    if (
      !apiTimeline.some((value) => {
        const entry = objectView(value);
        return (
          entry.method === expected[0] &&
          entry.pathname === expected[1] &&
          (expected[2] === undefined || entry.status === expected[2])
        );
      })
    ) {
      throw new Error(`Hub API timeline is missing ${expected.join(" ")}`);
    }
  }

  const runtime = objectView(hubEvidence.runtime);
  const baselineDigest = candidateManifest.releaseBaseline.hub.imageDigest;
  const candidateDigest = candidateManifest.hub.digest;
  if (
    runtime.identityVerified !== true ||
    runtime.activeHub !== "candidate" ||
    runtime.activeManifestDigest !== candidateDigest ||
    runtime.candidateManifestDigest !== candidateDigest ||
    runtime.baselineManifestDigest !== baselineDigest ||
    !/^sha256:[0-9a-f]{64}$/.test(regexInput(runtime.containerConfigDigest)) ||
    typeof runtime.containerInspect !== "string" ||
    runtime.containerInspect.trim().length === 0 ||
    typeof runtime.imageInspect !== "string" ||
    runtime.imageInspect.trim().length === 0
  ) {
    throw new Error(
      "running Hub identity does not match the Candidate Manifest",
    );
  }
  const runtimeHistory = runtime.runtimeHistory;
  if (!isUnknownArray(runtimeHistory) || runtimeHistory.length < 2) {
    throw new Error("Hub runtime history does not prove Baseline to Candidate");
  }
  const baselineEntry = runtimeHistory.find((value) => {
    const entry = objectView(value);
    return entry.hub === "baseline" && entry.manifestDigest === baselineDigest;
  });
  const candidateEntry = runtimeHistory.find((value) => {
    const entry = objectView(value);
    return (
      entry.hub === "candidate" && entry.manifestDigest === candidateDigest
    );
  });
  const baseline = objectView(baselineEntry);
  const candidate = objectView(candidateEntry);
  if (
    !isUnknownRecord(baselineEntry) ||
    !isUnknownRecord(candidateEntry) ||
    typeof baseline.volume !== "string" ||
    baseline.volume.length === 0 ||
    candidate.volume !== baseline.volume ||
    !/^sha256:[0-9a-f]{64}$/.test(regexInput(baseline.configDigest)) ||
    !/^sha256:[0-9a-f]{64}$/.test(regexInput(candidate.configDigest))
  ) {
    throw new Error("Hub runtime history identities are incomplete");
  }
  const repairedHost = source.repairedHost;
  const probeConfiguration = objectView(source.probeConfiguration);
  const afterRepairConfiguration = objectView(probeConfiguration.afterRepair);
  if (
    objectView(repairedHost).id !== hostId ||
    !isCandidateHostReady(
      repairedHost,
      candidateManifest.probeAssetSet.version,
    ) ||
    !hasAdvancingPortableMetrics(objectView(source.metrics).afterRepair) ||
    afterRepairConfiguration.mode !== "override" ||
    typeof afterRepairConfiguration.version !== "string" ||
    afterRepairConfiguration.reportedVersion !==
      afterRepairConfiguration.version
  ) {
    throw new Error("Candidate Probe core reporting evidence is incomplete");
  }
}

function validateRepairOperationEvidence(
  source: UnknownRecord,
  candidateManifest: ReleaseE2ECandidateManifest,
): void {
  const hostId = objectView(source.identityContinuity).hostId;
  // hub-api 边界已对同一个 hostId 做过同样断言，这里只是把已成立的事实交给类型系统。
  assertPositiveInteger(hostId, "Repair Host ID");
  const targetProbeVersion = candidateManifest.probeAssetSet.version;
  validateTerminalRepairOperationTimeline(
    observationList(source.operationTimeline),
    {
      hostId,
      kind: "probe_upgrade",
      state: "failed",
      targetProbeVersion,
    },
  );
  validateTerminalRepairOperationTimeline(
    observationList(source.uninstallOperationTimeline),
    {
      hostId,
      kind: "probe_uninstall",
      state: "succeeded",
    },
  );
  const failedUpgrade = objectView(
    observationList(source.operationTimeline).at(-1),
  );
  const failureBoundary = objectView(source.failureBoundary);
  if (
    failureBoundary.operationId !== failedUpgrade.id ||
    failureBoundary.probeVersion !== targetProbeVersion ||
    failureBoundary.hubFailureCode !== objectView(failedUpgrade.failure).code ||
    failureBoundary.localFailureCode !== "post_replacement_restart_failure"
  ) {
    throw new Error(
      "post-replacement failure evidence is not bound to the failed Upgrade",
    );
  }
}

function validateTerminalRepairOperationTimeline(
  timeline: readonly unknown[],
  expected: {
    hostId: number;
    kind: string;
    state: ProbeOperationState;
    targetProbeVersion?: string;
  },
): void {
  if (timeline.length < 3) {
    throw new Error(`${expected.kind} timeline is incomplete`);
  }
  const requested = objectView(timeline[0]);
  const requestedId = requested.id;
  if (
    requested.state !== "pending" ||
    requested.acceptedAtMs !== null ||
    requested.runningAtMs !== null ||
    requested.completedAtMs !== null ||
    !isSafeInteger(requestedId) ||
    requestedId <= 0
  ) {
    throw new Error(
      `${expected.kind} request identity or timestamps are invalid`,
    );
  }
  let previous: ProbeOperation | null = null;
  let terminal: ProbeOperation | null = null;
  for (const value of timeline) {
    if (!isHubProbeOperation(value)) {
      throw new Error("Hub returned an invalid Probe Operation");
    }
    const operation = value;
    assertProbeOperation(operation, {
      hostId: expected.hostId,
      id: requestedId,
      kind: expected.kind,
      ...(expected.targetProbeVersion
        ? { targetProbeVersion: expected.targetProbeVersion }
        : {}),
    });
    if (previous) assertProbeOperationProgress(previous, operation);
    if (terminal) assertStableTerminalOperation(terminal, operation);
    if (!terminal && terminalProbeOperationStates.has(operation.state)) {
      terminal = operation;
    }
    previous = operation;
  }
  const finalValue = timeline.at(-1);
  const precedingValue = timeline.at(-2);
  if (
    !isHubProbeOperation(finalValue) ||
    !isHubProbeOperation(precedingValue)
  ) {
    throw new Error(
      `${expected.kind} does not retain confirmed ${expected.state} terminal timestamps`,
    );
  }
  const final = finalValue;
  const preceding = precedingValue;
  if (
    final.state !== expected.state ||
    final.acceptedAtMs === null ||
    final.runningAtMs === null ||
    final.completedAtMs === null ||
    preceding.state !== expected.state
  ) {
    throw new Error(
      `${expected.kind} does not retain confirmed ${expected.state} terminal timestamps`,
    );
  }
  assertStableTerminalOperation(preceding, final);
  if (
    (expected.state === "failed" &&
      (typeof final.failure?.code !== "string" ||
        final.failure.code.length === 0 ||
        typeof final.failure.message !== "string" ||
        final.failure.message.length === 0)) ||
    (expected.state === "succeeded" && final.failure !== null)
  ) {
    throw new Error(`${expected.kind} terminal failure contract is invalid`);
  }
}

function validateRepairSystemdEvidence(source: UnknownRecord): void {
  const hostEvidence = objectView(source.hostEvidence);
  const systemd = hostEvidence.systemd;
  assertSuccessfulCommandEvidence(systemd, "systemd");
  const service = parseKeyValues(systemd.stdout);
  if (
    service.stage !== "post-uninstall" ||
    service.LoadState !== "not-found" ||
    service.ActiveState !== "inactive" ||
    service.unitCount !== "0" ||
    service.failedUnitCount !== "0"
  ) {
    throw new Error("systemd state does not prove post-Uninstall absence");
  }
  const journald = hostEvidence.journald;
  assertSuccessfulCommandEvidence(journald, "journald");
  const journal = journald.stdout.trim();
  if (!journal || journal.includes("-- No entries --")) {
    throw new Error("journald history was not retained");
  }
  const repairedService = objectView(
    objectView(source.repairHostBoundary).service,
  );
  if (
    repairedService.LoadState !== "loaded" ||
    repairedService.ActiveState !== "active" ||
    repairedService.SubState !== "running" ||
    repairedService.User !== "enoki-probe" ||
    repairedService.Group !== "enoki-probe" ||
    repairedService.FragmentPath !== "/etc/systemd/system/enoki-probe.service"
  ) {
    throw new Error("Repair did not capture a running systemd service");
  }
}

function validateRepairPrivilegeEvidence(source: UnknownRecord): void {
  const sudoers = objectView(source.hostEvidence).sudoers;
  assertSuccessfulCommandEvidence(sudoers, "sudoers");
  const privilegeState = parseKeyValues(sudoers.stdout);
  if (
    privilegeState.stage !== "post-uninstall" ||
    privilegeState.managedSudoersCount !== "0"
  ) {
    throw new Error("post-Uninstall sudoers observation is invalid");
  }
  const repairedSudoers = objectView(source.repairHostBoundary).sudoers;
  if (repairedSudoers !== "") {
    throw new Error("Repair did not capture the authorized privilege boundary");
  }
}

function validateRepairFilesystemEvidence(
  source: UnknownRecord,
  candidateManifest: ReleaseE2ECandidateManifest,
): void {
  const hostEvidence = objectView(source.hostEvidence);
  if (hostEvidence.error) {
    throw new Error("Host evidence collection failed");
  }
  if (hostEvidence.runClaimed !== true) {
    throw new Error("Host evidence was not collected from the run-owned state");
  }
  assertHostInventoryEvidence(hostEvidence.inventory);
  if (inventoryResidue(hostEvidence.inventory).length > 0) {
    throw new Error("post-Uninstall filesystem inventory contains residue");
  }
  const installed = objectView(source.repairHostBoundary);
  assertHostInventoryEvidence(installed.inventory);
  const installedResidue = inventoryResidue(installed.inventory);
  const required = [
    "user:enoki-probe",
    "group:enoki-probe",
    "/usr/local/bin/enoki-probe",
    "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
    "/var/lib/enoki-probe-bootstrap",
    "/etc/enoki/probe-install.toml",
    "/etc/systemd/system/enoki-probe.service",
    "/var/lib/enoki-probe",
    "enoki-probe.service",
  ];
  if (
    installed.probeVersion !== candidateManifest.probeAssetSet.version ||
    installedResidue.some((entry) =>
      entry.startsWith("/etc/sudoers.d/enoki-probe"),
    ) ||
    required.some((entry) => !installedResidue.includes(entry))
  ) {
    throw new Error("post-Repair filesystem inventory is incomplete");
  }
}

function validateRepairIdentityEvidence(
  source: UnknownRecord,
  candidateManifest: ReleaseE2ECandidateManifest,
): void {
  const continuity = objectView(source.identityContinuity);
  assertPositiveInteger(continuity.hostId, "Repair Host ID");
  for (const value of [continuity.before, continuity.after]) {
    const identity = objectView(value);
    if (
      !isUnknownRecord(value) ||
      Object.keys(identity).sort().join(",") !== "identitySha256,probeId" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(
        regexInput(identity.probeId),
      ) ||
      !/^[0-9a-f]{64}$/.test(regexInput(identity.identitySha256))
    ) {
      throw new Error("Probe Identity evidence is incomplete");
    }
  }
  const before = objectView(continuity.before);
  const after = objectView(continuity.after);
  const repair = objectView(source.repair);
  if (
    before.probeId !== after.probeId ||
    before.identitySha256 !== after.identitySha256 ||
    repair.output !== probeRepairLocalCompletionOutput ||
    objectView(source.repairHostBoundary).probeVersion !==
      candidateManifest.probeAssetSet.version ||
    objectView(source.repairedHost).id !== continuity.hostId
  ) {
    throw new Error("Probe Identity is inconsistent across Repair boundaries");
  }
}

function validateRepairCleanupEvidence(source: UnknownRecord): void {
  const completion = objectView(source.uninstallCompletion);
  assertHostInventoryEvidence(completion.inventory);
  if (
    completion.clean !== true ||
    completion.journaldRetained !== true ||
    completion.sharedDependenciesRetained !== true ||
    typeof completion.journald !== "string" ||
    completion.journald.trim().length === 0 ||
    typeof completion.sharedDependencies !== "string" ||
    completion.sharedDependencies.trim().length === 0 ||
    inventoryResidue(completion.inventory).length > 0
  ) {
    throw new Error("Probe Uninstall Completion evidence is invalid");
  }
  const cleanup = objectView(source.cleanup);
  if (cleanupDidNotSucceed(cleanup)) {
    throw new Error("scenario cleanup did not complete cleanly");
  }
  if (!cleanup.host || !cleanup.environment) {
    throw new Error("scenario cleanup observations are incomplete");
  }
  assertCleanEvidenceTree(cleanup.host, "Host cleanup");
  assertCleanEvidenceTree(cleanup.environment, "environment cleanup");
}

function assertSuccessfulCommandEvidence(
  value: unknown,
  label: string,
): asserts value is SuccessfulCommandEvidence {
  if (
    !value ||
    objectView(value).error ||
    objectView(value).code !== 0 ||
    typeof objectView(value).stdout !== "string" ||
    typeof objectView(value).stderr !== "string"
  ) {
    throw new Error(`${label} evidence command did not complete successfully`);
  }
}

function assertCleanEvidenceTree(value: unknown, label: string): void {
  const view = objectView(value);
  if (
    !value ||
    typeof value !== "object" ||
    view.error ||
    view.clean !== true
  ) {
    throw new Error(`${label} did not report clean completion`);
  }
  for (const [key, nested] of Object.entries(view)) {
    if (key === "clean" || key === "skipped" || typeof nested !== "object") {
      continue;
    }
    assertCleanEvidenceTree(nested, `${label}.${key}`);
  }
}

async function runCompatibleUpgradeUninstallScenario(
  options: ReleaseScenarioOptions,
) {
  return runForwardLifecycleScenario({
    ...options,
    transitionClassification: "compatible",
  });
}

async function runReplacementMigrationUninstallScenario(
  options: ReleaseScenarioOptions,
) {
  return runForwardLifecycleScenario({
    ...options,
    transitionClassification: "replacement-required",
  });
}

async function runForwardLifecycleScenario({
  candidateManifest,
  environment,
  evidenceSink,
  ownerPassword,
  runId,
  scenario,
  timing = {},
  transitionClassification,
}: ForwardLifecycleScenarioOptions) {
  assertRunId(runId);
  assertCandidateManifest(candidateManifest);
  if (!environment?.start || !environment?.cleanup || !evidenceSink?.write) {
    throw new Error("Release E2E environment and evidence sink are required");
  }

  const baseline = candidateManifest.releaseBaseline;

  const poll = normalizedPollTiming(timing);
  const evidence: ForwardLifecycleScenarioEvidence = {
    auditLog: null,
    baselineInstall: null,
    candidate: candidateManifest.candidate,
    candidateHost: null,
    cleanup: null,
    compatibility: null,
    hostBoundary: null,
    hostEvidence: null,
    hubEvidence: null,
    identityContinuity: null,
    infrastructure: null,
    metrics: { afterUpgrade: null, beforeUpgrade: null },
    manualRecovery: null,
    migrationRetention: null,
    operationTimeline: [],
    phase: "scenario-running",
    probeConfiguration: { afterUpgrade: null, beforeUpgrade: null },
    releaseBaseline: releaseBaselineEvidence(baseline),
    releaseTestHost: null,
    result: { status: "running" },
    runId,
    scenario,
    schemaVersion: 2,
    uninstall: {
      hostCompletion: null,
      hubSoftDeleted: false,
      operationTimeline: [],
      status: "pending",
    },
    upgradeOperationTimeline: [],
  };
  let resources: ReleaseScenarioContext | null = null;
  let primaryError: unknown = null;
  let evidenceWriteError: unknown = null;
  let finalEvidence: unknown = evidence;

  try {
    resources = await environment.start({
      candidateManifest,
      hubMode: "baseline",
      runId,
    });
    const { host, hub } = resources;
    assertBaselineScenarioParticipants(host, hub, transitionClassification);
    evidence.infrastructure = resources.infrastructure ?? null;
    evidence.releaseTestHost = resources.releaseTestHost ?? null;

    await host.assertDisposable(runId);
    await hub.authenticate(ownerPassword);
    const initialHosts = await hub.listHosts();
    if (!Array.isArray(initialHosts) || initialHosts.length !== 0) {
      throw assertionError(
        "baseline_hub_not_empty",
        "Release Baseline scenario requires a new persisted Hub state with no Hosts",
      );
    }
    const enrollment = await hub.createEnrollment();
    if (!enrollment?.installCommand) {
      throw assertionError(
        "enrollment_command_missing",
        "Release Baseline Hub did not return its official Probe install command",
      );
    }
    evidence.baselineInstall = await host.install(enrollment, runId);
    await assertReleaseBaselineInstalled(host, baseline, runId);

    const hostSummary = await waitForObservation({
      code: "probe_enrollment_timeout",
      label: "Release Baseline Host enrollment",
      observe: async () => {
        const hosts = await hub.listHosts();
        return Array.isArray(hosts) && hosts.length === 1 ? hosts[0] : null;
      },
      poll,
      ready: (value) =>
        value !== null &&
        value !== undefined &&
        Number.isSafeInteger(value.id) &&
        value.id > 0,
    });
    const hostId = hostSummary.id;
    const baselineIdentity = await host.readProbeIdentity(runId);
    await waitForObservation({
      code: "baseline_host_core_reporting_timeout",
      label: "Release Baseline Probe reporting to the Release Baseline Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
    });

    await hub.switchToCandidate();
    await hub.authenticate(ownerPassword);
    const persistedHosts = await hub.listHosts();
    if (
      !Array.isArray(persistedHosts) ||
      persistedHosts.length !== 1 ||
      persistedHosts[0]?.id !== hostId
    ) {
      throw assertionError(
        "baseline_hub_state_not_persisted",
        "Candidate Hub did not retain the Release Baseline Host state",
      );
    }
    const compatibleHost = await waitForObservation({
      code: "baseline_probe_candidate_hub_compatibility_timeout",
      label: "Release Baseline Probe reporting to the Candidate Hub",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)),
    });
    if (compatibleHost.probeUpgradeStatus !== null) {
      throw assertionError(
        "unattended_probe_upgrade_detected",
        "A Probe Upgrade operation existed before Owner authorization",
      );
    }
    const beforeMetrics = await waitForObservation({
      code: "baseline_probe_metrics_progression_timeout",
      label: "Release Baseline Probe portable Metrics on the Candidate Hub",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: hasAdvancingPortableMetrics,
    });
    evidence.metrics.beforeUpgrade = compactMetricsEvidence(beforeMetrics);
    const beforeUpgradeConfiguration = await proveProbeConfigurationRoundTrip({
      hostId,
      hub,
      poll,
    });
    evidence.probeConfiguration.beforeUpgrade = beforeUpgradeConfiguration;
    const configuredCompatibleHost = await waitForObservation({
      code: "baseline_probe_configuration_projection_timeout",
      label: "Release Baseline Probe Configuration reporting projection",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, releaseBaselineProbeVersion(baseline)) &&
        value.reportedProbeConfigurationVersion ===
          beforeUpgradeConfiguration.reportedVersion,
    });
    const baselineHostProjection = stableHubHostProjection(
      configuredCompatibleHost,
    );
    const baselineMetricHistory = metricsHistoryEvidence(beforeMetrics);
    evidence.compatibility = {
      host: compactHostEvidence(configuredCompatibleHost),
      status: "succeeded",
    };

    const replacementRequired =
      transitionClassification === "replacement-required";
    let requestedUpgrade: ProbeOperation | null = null;
    let finalUpgrade: ProbeOperation | undefined;
    if (replacementRequired) {
      const replacementEnrollment =
        await hub.createManualReinstallEnrollment(hostId);
      if (!replacementEnrollment?.installCommand) {
        throw assertionError(
          "manual_reinstall_enrollment_command_missing",
          "Candidate Hub did not return the production manual Probe reinstall command",
        );
      }
      evidence.manualRecovery = {
        enrollmentId: replacementEnrollment.enrollmentId,
        hostId,
        kind: "trust_epoch_manual_reinstall",
        result: await host.manualReinstall(replacementEnrollment, runId),
      };
    } else {
      await host.beginUpgradeOwnershipTransition(
        runId,
        candidateManifest.probeAssetSet.version,
      );
      requestedUpgrade = await hub.requestProbeUpgrade(hostId);
      if (
        requestedUpgrade.targetProbeVersion !==
        candidateManifest.probeAssetSet.version
      ) {
        throw assertionError(
          "probe_upgrade_target_mismatch",
          `Probe Upgrade targets ${requestedUpgrade.targetProbeVersion ?? "unknown"} instead of Candidate ${candidateManifest.probeAssetSet.version}`,
        );
      }
      evidence.upgradeOperationTimeline = [requestedUpgrade];
      await host.bindUpgradeOwnershipTransition(runId, requestedUpgrade);
      evidence.upgradeOperationTimeline = await hub.waitForProbeOperation(
        requestedUpgrade,
        { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
      );
      finalUpgrade = evidence.upgradeOperationTimeline.at(-1);
      if (finalUpgrade?.state === "failed") {
        validateInsufficientPrivilegeProbeUpgradeTimeline(
          evidence.upgradeOperationTimeline,
        );
        throw assertionError(
          "compatible_probe_upgrade_failed",
          `Compatible Probe Upgrade failed without fallback: ${JSON.stringify(finalUpgrade)}`,
        );
      } else {
        validateSuccessfulProbeUpgradeTimeline(
          evidence.upgradeOperationTimeline,
        );
      }
    }

    const candidateHost = await waitForObservation({
      code: replacementRequired
        ? "candidate_probe_configuration_retention_timeout"
        : "candidate_probe_reporting_timeout",
      label: replacementRequired
        ? "Candidate Probe retained Configuration after manual reinstall"
        : "Candidate Probe Host Profile after Upgrade",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version) &&
        (!replacementRequired ||
          (value.reportedProbeConfigurationVersion ===
            beforeUpgradeConfiguration.reportedVersion &&
            !value.warnings?.some(
              (warning) => warning.code === "probe_configuration_error",
            ))),
    });
    evidence.candidateHost = compactHostEvidence(candidateHost);
    evidence.hostBoundary = await host.assertInstalled(
      runId,
      candidateManifest.probeAssetSet.version,
    );
    const candidateIdentity = await host.readProbeIdentity(runId);
    if (
      replacementRequired
        ? candidateIdentity.probeId === baselineIdentity.probeId ||
          candidateIdentity.identitySha256 === baselineIdentity.identitySha256
        : candidateIdentity.probeId !== baselineIdentity.probeId ||
          candidateIdentity.identitySha256 !== baselineIdentity.identitySha256
    ) {
      throw assertionError(
        "probe_identity_epoch_mismatch",
        replacementRequired
          ? "Trust Epoch manual reinstall did not replace Probe identity and credentials"
          : "Probe Upgrade changed the Probe identity or credentials",
      );
    }
    evidence.identityContinuity = {
      after: candidateIdentity,
      before: baselineIdentity,
      hostId,
    };
    let migrationRetention: ForwardLifecycleScenarioEvidence["migrationRetention"] =
      null;
    if (replacementRequired) {
      const retainedConfiguration = await hub.getHostProbeConfiguration(hostId);
      if (
        !sameEffectiveProbeConfiguration(
          retainedConfiguration,
          beforeUpgradeConfiguration,
        )
      ) {
        throw assertionError(
          "manual_reinstall_configuration_not_retained",
          "Trust Epoch manual reinstall did not retain the Host Probe Configuration",
        );
      }
      const candidateHostProjection = stableHubHostProjection(candidateHost);
      if (
        candidateHostProjection.id !== baselineHostProjection.id ||
        JSON.stringify(candidateHostProjection.hostMetadata) !==
          JSON.stringify(baselineHostProjection.hostMetadata)
      ) {
        throw assertionError(
          "manual_reinstall_host_metadata_not_retained",
          "Trust Epoch manual reinstall did not retain Host identity and metadata",
        );
      }
      migrationRetention = {
        configuration: effectiveProbeConfigurationEvidence(
          retainedConfiguration,
        ),
        hostAfter: candidateHostProjection,
        hostBefore: baselineHostProjection,
        metricHistory: baselineMetricHistory,
        postMetricHistory: null,
      };
      evidence.migrationRetention = migrationRetention;
    }
    if (!replacementRequired && finalUpgrade) {
      await host.completeUpgradeOwnershipTransition(runId, finalUpgrade);
    }

    const candidateMetricCheckpoint = latestPortableMetric(
      await hub.getHostMetrics(hostId),
    );
    if (!candidateMetricCheckpoint) {
      throw assertionError(
        "candidate_probe_metrics_checkpoint_missing",
        "Candidate Probe Host Profile was observed without a portable Metrics checkpoint",
      );
    }
    const afterMetrics = await waitForObservation({
      code: "candidate_probe_metrics_progression_timeout",
      label: "Candidate Probe portable Metrics after Upgrade",
      observe: () => hub.getHostMetrics(hostId),
      poll,
      ready: (samples) =>
        hasAdvancingPortableMetrics(samples) &&
        isUnknownArray(samples) &&
        metricsAdvanceBeyond(samples, candidateMetricCheckpoint),
    });
    evidence.metrics.afterUpgrade = compactMetricsEvidence(afterMetrics);
    if (
      replacementRequired &&
      !retainsMetricHistoryAnchors(afterMetrics, baselineMetricHistory.anchors)
    ) {
      throw assertionError(
        "manual_reinstall_metric_history_not_retained",
        "Trust Epoch manual reinstall did not retain pre-replacement Metrics history",
      );
    }
    if (replacementRequired && migrationRetention) {
      migrationRetention.postMetricHistory = metricsHistoryEvidence(
        afterMetrics,
        { retain: baselineMetricHistory.anchors },
      );
    }
    evidence.probeConfiguration.afterUpgrade =
      await proveProbeConfigurationRoundTrip({ hostId, hub, poll });

    const requestedUninstall = await hub.requestProbeUninstall(hostId);
    evidence.operationTimeline = [requestedUninstall];
    evidence.operationTimeline = await hub.waitForProbeOperation(
      requestedUninstall,
      { intervalMs: poll.intervalMs, timeoutMs: poll.timeoutMs },
    );
    evidence.uninstall.operationTimeline = evidence.operationTimeline;
    const finalUninstall = evidence.operationTimeline.at(-1);
    if (finalUninstall?.state !== "succeeded" || finalUninstall.failure) {
      throw assertionError(
        "probe_uninstall_failed",
        `Probe Uninstall did not succeed: ${JSON.stringify(finalUninstall)}`,
      );
    }
    evidence.uninstall.hubSoftDeleted = await hub.isHostSoftDeleted(hostId);
    if (!evidence.uninstall.hubSoftDeleted) {
      throw assertionError(
        "host_not_soft_deleted",
        "Probe Uninstall succeeded but the Host remains active",
      );
    }
    const auditLog = await hub.getAuditLog();
    // requestedUpgrade 只在 compatible 分支赋值，与原 replacementRequired 判据在此处互补，
    // 用它分支可让类型收窄成立且保持两侧结果不变。
    evidence.auditLog = requestedUpgrade
      ? assertBaselineUpgradeAuditLog(
          auditLog,
          hostId,
          requestedUpgrade.id,
          requestedUninstall.id,
          candidateManifest.probeAssetSet.version,
        )
      : assertMigrationLifecycleAuditLog(
          auditLog,
          hostId,
          requestedUninstall.id,
          baselineIdentity,
          candidateIdentity,
        );
    const completion = await host.verifyUninstallCompletion(runId);
    evidence.uninstall.hostCompletion = completion;
    if (
      completion?.clean !== true ||
      completion?.journaldRetained !== true ||
      completion?.sharedDependenciesRetained !== true
    ) {
      throw assertionError(
        "probe_uninstall_residue",
        `Host did not satisfy Probe Uninstall Completion: ${JSON.stringify(completion)}`,
      );
    }
    evidence.uninstall.status = "succeeded";
    evidence.result = { status: "succeeded" };
    evidence.phase = "succeeded";
  } catch (error) {
    primaryError = error;
    if (isTimelineCarryingError(error)) {
      if (error.timeline[0]?.kind === "probe_upgrade") {
        evidence.upgradeOperationTimeline = error.timeline;
      } else {
        evidence.operationTimeline = error.timeline;
      }
    }
    evidence.result = { error: serializedError(error), status: "failed" };
    evidence.phase = "failed";
  } finally {
    if (resources?.hub?.collectEvidence) {
      try {
        evidence.hubEvidence = await resources.hub.collectEvidence();
      } catch (error) {
        evidence.hubEvidence = { error: serializedError(error) };
      }
    }
    if (resources?.host?.collectEvidence) {
      try {
        evidence.hostEvidence = await resources.host.collectEvidence(runId);
      } catch (error) {
        evidence.hostEvidence = { error: serializedError(error) };
      }
    }
    const cleanup: ScenarioCleanupEvidence = {};
    if (resources?.host?.cleanup) {
      try {
        cleanup.host = await resources.host.cleanup(runId);
      } catch (error) {
        cleanup.host = { error: serializedError(error) };
      }
    }
    try {
      cleanup.environment = await environment.cleanup({ resources, runId });
    } catch (error) {
      cleanup.environment = { error: serializedError(error) };
    }
    evidence.cleanup = cleanup;
    if (!primaryError && cleanupDidNotSucceed(cleanup)) {
      primaryError = assertionError(
        "release_e2e_cleanup_failed",
        "Release E2E cleanup did not remove all run-owned state",
      );
      evidence.result = {
        error: serializedError(primaryError),
        status: "failed",
      };
      evidence.phase = "failed";
    }
    finalEvidence = redactReleaseE2EEvidence(evidence, {
      candidateManifest,
      secrets: [ownerPassword],
    });
    try {
      await evidenceSink.write(finalEvidence);
    } catch (error) {
      evidenceWriteError = error;
      if (!primaryError) {
        primaryError = assertionError(
          "release_e2e_evidence_write_failed",
          `Release E2E evidence could not be written: ${String(objectView(error).message)}`,
        );
      }
    }
  }

  if (primaryError) {
    const failure: ScenarioFailureError = new Error(
      `Release E2E ${scenario} failed: ${redactSensitiveText(objectView(primaryError).message, [ownerPassword])}`,
    );
    const primaryCode = objectView(primaryError).code;
    failure.code =
      typeof primaryCode === "string" ? primaryCode : "release_e2e_failed";
    failure.evidence = finalEvidence;
    if (evidenceWriteError) {
      failure.evidenceWriteError = serializedError(evidenceWriteError);
    }
    throw failure;
  }
  return evidence.result;
}

async function runFreshInstallUninstallScenario({
  candidateManifest,
  environment,
  evidenceSink,
  ownerPassword,
  runId,
  scenario,
  timing = {},
}: ReleaseScenarioOptions) {
  assertRunId(runId);
  assertCandidateManifest(candidateManifest);
  if (!environment?.start || !environment?.cleanup || !evidenceSink?.write) {
    throw new Error("Release E2E environment and evidence sink are required");
  }

  const poll = normalizedPollTiming(timing);
  const offlinePoll = localUninstallOfflineObservationPoll(timing, poll);
  const evidence: FreshInstallScenarioEvidence = {
    auditLog: null,
    candidate: candidateManifest.candidate,
    candidateIdentities: {
      hubDigest: candidateManifest.hub.digest,
      probeAssetSetVersion: candidateManifest.probeAssetSet.version,
    },
    cleanup: null,
    canonicalRuntimeUnavailableReporting: null,
    diagnostics: null,
    finalLocalUninstall: null,
    host: null,
    hostBoundary: null,
    hostEvidence: null,
    hubOnlyDeletion: null,
    hubEvidence: null,
    initialInstall: null,
    infrastructure: null,
    installedBundleFailureRepair: null,
    localUninstall: null,
    metrics: null,
    metricsHistory: null,
    phase: "scenario-running",
    probeConfiguration: null,
    reEnrollment: null,
    releaseBaseline: releaseBaselineEvidence(candidateManifest.releaseBaseline),
    releaseTestHost: null,
    repeatedAdd: null,
    result: { status: "running" },
    runId,
    scenario,
    schemaVersion: 2,
  };
  let resources: ReleaseScenarioContext | null = null;
  let primaryError: unknown = null;
  let evidenceWriteError: unknown = null;
  let finalEvidence: unknown = evidence;

  try {
    resources = await environment.start({ candidateManifest, runId });
    const { host, hub } = resources;
    assertFreshInstallScenarioParticipants(host, hub);
    evidence.infrastructure = resources.infrastructure ?? null;
    evidence.releaseTestHost = resources.releaseTestHost ?? null;

    await host.assertDisposable(runId);
    await hub.authenticate(ownerPassword);
    const initialHosts = await hub.listHosts();
    if (!Array.isArray(initialHosts) || initialHosts.length !== 0) {
      throw assertionError(
        "fresh_hub_not_empty",
        "Fresh-install scenario requires a candidate Hub with no Hosts",
      );
    }

    const newHostTarget = { kind: "new_host" };
    const enrollment = await hub.createEnrollment(newHostTarget);
    assertCreatedEnrollment(enrollment, newHostTarget);
    const initialInstall = await host.install(enrollment, runId);
    evidence.initialInstall = initialInstall;
    evidence.hostBoundary = await host.assertInstalled(
      runId,
      candidateManifest.probeAssetSet.version,
    );

    const hostSummary = await waitForObservation({
      code: "probe_enrollment_timeout",
      label: "newly enrolled Host",
      observe: async () => {
        const hosts = await hub.listHosts();
        return Array.isArray(hosts) && hosts.length === 1 ? hosts[0] : null;
      },
      poll,
      ready: (value) =>
        value !== null &&
        value !== undefined &&
        Number.isSafeInteger(value.id) &&
        value.id > 0,
    });
    const hostId = hostSummary.id;
    const ready = await waitForObservation({
      code: "host_core_reporting_timeout",
      label: "online Host with a typed Host Profile",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version),
    });
    evidence.host = compactHostEvidence(ready);
    const initialIdentity = await host.readProbeIdentity(runId);

    const samples = await waitForObservation({
      code: "metrics_progression_timeout",
      label: "two advancing portable Metrics samples",
      observe: () => hub.getHostMetrics(hostId, { window: "24h" }),
      poll,
      ready: hasAdvancingPortableMetrics,
    });
    evidence.metrics = compactMetricsEvidence(samples);
    const metricsHistory = metricsHistoryEvidence(samples);
    evidence.metricsHistory = metricsHistory;

    const probeConfiguration = await proveProbeConfigurationRoundTrip({
      hostId,
      hub,
      poll,
    });
    evidence.probeConfiguration = probeConfiguration;

    const reportTransport = resources?.canonicalReports;
    if (
      !reportTransport ||
      typeof reportTransport.armRepairClosure !== "function" ||
      typeof reportTransport.waitForRepairClosureEvidence !== "function"
    ) {
      throw assertionError(
        "canonical_report_evidence_unavailable",
        "Release E2E environment lacks Installed Bundle Failure Repair closure evidence",
      );
    }
    reportTransport.armRepairClosure({
      expectedProbeId: initialIdentity.probeId,
    });
    evidence.installedBundleFailureRepair =
      await proveInstalledBundleFailureRepair({
        expectedBundleVersion: candidateManifest.probeAssetSet.version,
        host,
        hostId,
        identityBefore: initialIdentity,
        readClosureCapture: () =>
          reportTransport.waitForRepairClosureEvidence({
            timeoutMs: timing.canonicalReportTimeoutMs ?? 90_000,
          }),
        readHubHostProfile: async (): Promise<HubHostProfileReading | null> => {
          const profile = objectView((await hub.getHost(hostId)).hostProfile);
          return isHubHostProfile(profile)
            ? {
                architecture: profile.architecture,
                cpuCount: profile.cpuCount,
                hostname: profile.hostname,
                kernel: profile.kernel,
                os: profile.os,
                probeVersion: profile.probeVersion,
              }
            : null;
        },
        readHubRepairOperation: (operationId) =>
          hub.getProbeRepairOperation(operationId),
        runId,
      });

    const repeatedEnrollment = await hub.createEnrollment(newHostTarget);
    assertCreatedEnrollment(repeatedEnrollment, newHostTarget);
    const hostBeforeRepeatedAdd = stableHubHostProjection(
      await hub.getHost(hostId),
    );
    const stateBeforeRepeatedAdd = await host.captureInstallationState(runId);
    const rejection = await host.rejectRepeatedInstall(
      repeatedEnrollment,
      runId,
    );
    const stateAfterRepeatedAdd = await host.captureInstallationState(runId);
    if (
      JSON.stringify(stateAfterRepeatedAdd) !==
      JSON.stringify(stateBeforeRepeatedAdd)
    ) {
      throw assertionError(
        "repeated_add_mutated_installation",
        "Ordinary repeated Add changed the installed Probe boundary",
      );
    }
    const hostAfterRepeatedAdd = stableHubHostProjection(
      await hub.getHost(hostId),
    );
    if (
      JSON.stringify(hostAfterRepeatedAdd) !==
      JSON.stringify(hostBeforeRepeatedAdd)
    ) {
      throw assertionError(
        "repeated_add_mutated_hub_host",
        "Ordinary repeated Add changed the stable Hub Host projection",
      );
    }
    const rejectedEnrollment = await waitForObservation({
      code: "repeated_add_rejection_timeout",
      label: "terminal repeated Add rejection",
      observe: () => hub.getEnrollment(repeatedEnrollment.enrollmentId),
      poll,
      ready: (value) =>
        value?.status === "rejected" &&
        value?.rejection?.code === "existing_probe_installation",
    });
    evidence.repeatedAdd = {
      enrollment: compactEnrollmentEvidence(repeatedEnrollment),
      enrollmentStatus: compactEnrollmentStatusEvidence(rejectedEnrollment),
      rejection,
      hostAfter: hostAfterRepeatedAdd,
      hostBefore: hostBeforeRepeatedAdd,
      stateAfter: stateAfterRepeatedAdd,
      stateBefore: stateBeforeRepeatedAdd,
    };

    const localUninstall = await host.localUninstall(runId);
    assertLocalUninstallCompletion(localUninstall?.completion);
    const hostAfterLocalUninstall = await hub.getHost(hostId);
    if (
      hostAfterLocalUninstall?.id !== hostId ||
      hostAfterLocalUninstall?.status === "offline"
    ) {
      throw assertionError(
        "local_uninstall_host_not_active",
        "Local Probe Uninstall did not leave an active non-offline Hub Host before bounded offline observation",
      );
    }
    const offlineHost = await waitForObservation({
      code: "host_offline_after_local_uninstall_timeout",
      label: "active Host becoming offline after Local Probe Uninstall",
      observe: () => hub.getHost(hostId),
      poll: offlinePoll,
      ready: (value) => value?.id === hostId && value?.status === "offline",
    });
    evidence.localUninstall = {
      activeHost: compactHostEvidence(hostAfterLocalUninstall),
      completion: localUninstall.completion,
      offlineHost: compactHostEvidence(offlineHost),
      output: localUninstall.output,
    };

    const existingHostTarget = { hostId, kind: "existing_host" };
    const reEnrollment = await hub.createEnrollment(existingHostTarget);
    assertCreatedEnrollment(reEnrollment, existingHostTarget);
    const reEnrollmentInstall = await host.install(reEnrollment, runId);
    const reEnrollmentBoundary = await host.assertInstalled(
      runId,
      candidateManifest.probeAssetSet.version,
    );
    const reEnrollmentIdentity = await host.readProbeIdentity(runId);
    if (
      reEnrollmentIdentity.probeId === initialIdentity.probeId ||
      reEnrollmentIdentity.identitySha256 === initialIdentity.identitySha256
    ) {
      throw assertionError(
        "reenrollment_identity_not_replaced",
        "Host Re-enrollment did not replace the Probe Identity",
      );
    }
    const renewed = await waitForObservation({
      code: "host_reenrollment_timeout",
      label: "re-enrolled Host with renewed readiness",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        isCandidateHostReady(value, candidateManifest.probeAssetSet.version),
    });
    const reEnrollmentMetrics = await waitForObservation({
      code: "reenrollment_metrics_progression_timeout",
      label: "new portable Metrics after Host Re-enrollment",
      observe: () => hub.getHostMetrics(hostId, { window: "24h" }),
      poll,
      ready: (value) =>
        hasAdvancingPortableMetrics(value) &&
        hasPortableMetricsAfter(value, samples) &&
        retainsInitialMetricSample(value, samples) &&
        isUnknownArray(value) &&
        retainsMetricHistoryAnchors(value, metricsHistory.anchors),
    });
    const reEnrollmentConfiguration =
      await hub.getHostProbeConfiguration(hostId);
    if (
      !sameEffectiveProbeConfiguration(
        reEnrollmentConfiguration,
        probeConfiguration,
      )
    ) {
      throw assertionError(
        "reenrollment_configuration_not_preserved",
        "Host Re-enrollment did not preserve Owner Probe Configuration",
      );
    }
    evidence.reEnrollment = {
      enrollment: compactEnrollmentEvidence(reEnrollment),
      host: compactHostEvidence(renewed),
      hostBoundary: reEnrollmentBoundary,
      hostId,
      identity: { after: reEnrollmentIdentity, before: initialIdentity },
      installer: reEnrollmentInstall,
      metrics: compactMetricsEvidence(reEnrollmentMetrics),
      metricsHistory: metricsHistoryEvidence(reEnrollmentMetrics, {
        retain: metricsHistory.anchors,
      }),
      probeConfiguration: reEnrollmentConfiguration,
    };

    const canonicalReports = resources?.canonicalReports;
    if (
      !canonicalReports ||
      typeof canonicalReports.arm !== "function" ||
      typeof canonicalReports.waitForEvidence !== "function" ||
      typeof canonicalReports.diagnostics !== "function" ||
      typeof host.restartCanonicalProbeWithoutObservationRuntime !==
        "function" ||
      typeof host.restoreObservationRuntime !== "function"
    ) {
      throw assertionError(
        "canonical_report_evidence_unavailable",
        "Release E2E environment lacks canonical report response-loss evidence",
      );
    }
    canonicalReports.arm({ expectedProbeId: reEnrollmentIdentity.probeId });
    let canonicalHostEvidence:
      | Awaited<
          ReturnType<
            ProbeHost["restartCanonicalProbeWithoutObservationRuntime"]
          >
        >
      | undefined;
    let canonicalReporting: CanonicalReportEvidence | undefined;
    let metricsAfterCanonicalFailure: readonly unknown[] | undefined;
    let restoreError: unknown = null;
    try {
      canonicalHostEvidence =
        await host.restartCanonicalProbeWithoutObservationRuntime(
          runId,
          reEnrollmentIdentity.probeId,
        );
      canonicalReporting = await canonicalReports.waitForEvidence({
        timeoutMs: timing.canonicalReportTimeoutMs ?? 90_000,
      });
      metricsAfterCanonicalFailure = await hub.getHostMetrics(hostId, {
        window: "24h",
      });
      if (
        JSON.stringify(
          portableMetricIdentities(metricsAfterCanonicalFailure),
        ) !== JSON.stringify(portableMetricIdentities(reEnrollmentMetrics))
      ) {
        throw assertionError(
          "canonical_runtime_unavailable_created_metrics",
          "Accepted ObservationWindowFailure created or changed Metrics",
        );
      }
    } finally {
      try {
        await host.restoreObservationRuntime(runId);
      } catch (error) {
        restoreError = error;
      }
    }
    if (restoreError) throw restoreError;
    // try/finally 正常完成后 reporting 必然已赋值；用只读局部保留同一对象供回调读取。
    const acceptedCanonicalReporting = canonicalReporting;
    const canonicalOwnerHost = await waitForObservation({
      code: "canonical_runtime_unavailable_owner_projection_timeout",
      label: "canonical Probe online after accepted Runtime-unavailable report",
      observe: () => hub.getHost(hostId),
      poll,
      ready: (value) =>
        value?.id === hostId &&
        value?.status === "online" &&
        value?.reportedProbeConfigurationVersion ===
          acceptedCanonicalReporting.bootReport.reconciliation
            .currentProbeConfigurationVersion,
    });
    evidence.canonicalRuntimeUnavailableReporting = {
      host: canonicalHostEvidence,
      ownerProjection: {
        host: compactHostEvidence(canonicalOwnerHost),
        metricsUnchanged: true,
        reportedProbeConfigurationVersion:
          canonicalOwnerHost.reportedProbeConfigurationVersion,
      },
      reporting: canonicalReporting,
    };

    const deletedHost = await hub.deleteHostHubOnly(hostId);
    const deleted = await waitForObservation({
      code: "hub_only_host_deletion_timeout",
      label: "Hub-only Host removal",
      observe: () => hub.isHostSoftDeleted(hostId),
      poll,
      ready: (value) => value === true,
    });
    if (deleted !== true || deletedHost?.id !== hostId) {
      throw assertionError(
        "hub_only_host_deletion_invalid",
        "Hub-only deletion did not remove the expected Host",
      );
    }
    const permanentReportRejection =
      await host.awaitPermanentReportRejection(runId);
    evidence.diagnostics = {
      host: await host.collectDiagnostics(runId),
      hub: await hub.collectEvidence(),
    };
    evidence.hubOnlyDeletion = {
      deletedHost,
      permanentReportRejection,
    };

    const finalLocalUninstall = await host.localUninstall(runId);
    assertLocalUninstallCompletion(finalLocalUninstall?.completion);
    evidence.finalLocalUninstall = finalLocalUninstall;
    evidence.auditLog = assertFreshLifecycleAuditLog(
      await hub.getAuditLog(),
      hostId,
    );
    evidence.result = { status: "succeeded" };
    evidence.phase = "succeeded";
  } catch (error) {
    primaryError = error;
    evidence.result = { error: serializedError(error), status: "failed" };
    evidence.phase = "failed";
  } finally {
    if (resources?.hub?.collectEvidence) {
      try {
        evidence.hubEvidence = await resources.hub.collectEvidence();
      } catch (error) {
        evidence.hubEvidence = { error: serializedError(error) };
      }
    }
    if (resources?.host?.collectEvidence) {
      try {
        evidence.hostEvidence = await resources.host.collectEvidence(runId);
      } catch (error) {
        evidence.hostEvidence = { error: serializedError(error) };
      }
    }
    if (evidence.diagnostics === null && resources?.host?.collectDiagnostics) {
      try {
        evidence.diagnostics = {
          host: await resources.host.collectDiagnostics(runId),
          hub: resources?.hub?.collectEvidence
            ? await resources.hub.collectEvidence()
            : null,
        };
      } catch (error) {
        evidence.diagnostics = { error: serializedError(error) };
      }
    }
    if (resources?.canonicalReports?.diagnostics) {
      const transport = resources.canonicalReports.diagnostics();
      evidence.diagnostics = {
        ...(evidence.diagnostics && typeof evidence.diagnostics === "object"
          ? evidence.diagnostics
          : {}),
        transport,
      };
    }

    const cleanup: ScenarioCleanupEvidence = {};
    if (resources?.host?.cleanup) {
      try {
        cleanup.host = await resources.host.cleanup(runId);
      } catch (error) {
        cleanup.host = { error: serializedError(error) };
      }
    }
    try {
      cleanup.environment = await environment.cleanup({ resources, runId });
    } catch (error) {
      cleanup.environment = { error: serializedError(error) };
    }
    evidence.cleanup = cleanup;
    if (!primaryError && cleanupDidNotSucceed(cleanup)) {
      primaryError = assertionError(
        "release_e2e_cleanup_failed",
        "Release E2E cleanup did not remove all run-owned state",
      );
      evidence.result = {
        error: serializedError(primaryError),
        status: "failed",
      };
      evidence.phase = "failed";
    }
    finalEvidence = redactReleaseE2EEvidence(evidence, {
      candidateManifest,
      secrets: [ownerPassword],
    });
    try {
      await evidenceSink.write(finalEvidence);
    } catch (error) {
      evidenceWriteError = error;
      if (!primaryError) {
        primaryError = assertionError(
          "release_e2e_evidence_write_failed",
          `Release E2E evidence could not be written: ${String(objectView(error).message)}`,
        );
      }
    }
  }

  if (primaryError) {
    const failure: ScenarioFailureError = new Error(
      `Release E2E ${scenario} failed: ${redactSensitiveText(objectView(primaryError).message, [ownerPassword])}`,
    );
    const primaryCode = objectView(primaryError).code;
    failure.code =
      typeof primaryCode === "string" ? primaryCode : "release_e2e_failed";
    failure.evidence = finalEvidence;
    if (evidenceWriteError) {
      failure.evidenceWriteError = serializedError(evidenceWriteError);
    }
    throw failure;
  }
  return evidence.result;
}

export function createHubLifecycleClient({
  baseUrl,
  fetch: fetch_ = globalThis.fetch,
  sleep = defaultSleep,
}: {
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
  sleep?: SleepFunction;
}) {
  const normalizedBaseUrl = new URL(baseUrl);
  const apiTimeline: HubApiRequestTimelineEntry[] = [];
  const enrollments = new Map<string, HubEnrollmentTrackingRecord>();
  let ownerCookie = "";

  async function request(
    pathname: string,
    init: RequestInit = {},
    allowedStatuses: readonly number[] = [],
  ) {
    const headers = new Headers(init.headers);
    headers.set("accept", "application/json");
    if (ownerCookie) headers.set("cookie", ownerCookie);
    if (init.body !== undefined)
      headers.set("content-type", "application/json");
    const response = await fetch_(new URL(pathname, normalizedBaseUrl), {
      ...init,
      headers,
    });
    const text = await response.text();
    const body = text ? parseJson(text, `Hub response for ${pathname}`) : null;
    apiTimeline.push({
      error: objectView(body).error ?? null,
      method: init.method ?? "GET",
      pathname,
      status: response.status,
    });
    if (!response.ok && !allowedStatuses.includes(response.status)) {
      throw new HubApiError({
        body,
        method: init.method ?? "GET",
        pathname,
        response,
      });
    }
    return { body, response };
  }

  async function readTrackedEnrollment(enrollmentId: string) {
    const { body } = await request(`/api/web/enrollments/${enrollmentId}`);
    assertEnrollmentStatus(body, enrollmentId);
    recordEnrollmentEvidence(enrollments, body);
    return body;
  }

  async function refreshTrackedEnrollment(enrollmentId: string) {
    try {
      await readTrackedEnrollment(enrollmentId);
    } catch (error) {
      const previous = enrollments.get(enrollmentId);
      enrollments.set(enrollmentId, {
        ...previous,
        enrollmentId,
        readError: serializedError(error),
      });
    }
  }

  return {
    async authenticate(password: string) {
      if (!password) throw new Error("Owner password is required");
      const { body, response } = await request("/api/web/auth/login", {
        body: JSON.stringify({ password }),
        method: "POST",
      });
      if (objectView(body).authenticated !== true) {
        throw new Error("Hub did not authenticate the Owner");
      }
      const setCookie = response.headers.get("set-cookie");
      ownerCookie = setCookie?.split(";", 1)[0] ?? "";
      return body;
    },

    async collectEvidence(): Promise<HubCollectedEvidence> {
      await Promise.all(
        [...enrollments.keys()].map((enrollmentId) =>
          refreshTrackedEnrollment(enrollmentId),
        ),
      );
      return {
        apiTimeline: [...apiTimeline],
        enrollments: [...enrollments.values()],
      };
    },

    async createEnrollment(target?: unknown): Promise<HubEnrollmentEvidence> {
      if (target !== undefined) assertEnrollmentTarget(target);
      const { body } = await request("/api/web/enrollments", {
        ...(target === undefined ? {} : { body: JSON.stringify({ target }) }),
        method: "POST",
      });
      if (!isHubEnrollmentEvidence(body)) {
        throw new Error("Hub returned an invalid Enrollment response");
      }
      assertEnrollmentInstallContract(body);
      recordEnrollmentEvidence(enrollments, body);
      return body;
    },

    async createManualReinstallEnrollment(
      hostId: number,
    ): Promise<HubEnrollmentEvidence> {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(
        `/api/web/enrollments/manual-reinstall/${hostId}`,
        { method: "POST" },
      );
      if (!isHubEnrollmentEvidence(body)) {
        throw new Error(
          "Hub returned an invalid manual Probe reinstall Enrollment response",
        );
      }
      assertEnrollmentInstallContract(body);
      const reinstallTarget = body.target;
      assertEnrollmentTarget(reinstallTarget);
      if (
        reinstallTarget.kind !== "manual_reinstall" ||
        reinstallTarget.hostId !== hostId
      ) {
        throw new Error("Hub manual Probe reinstall Enrollment target changed");
      }
      recordEnrollmentEvidence(enrollments, body);
      return body;
    },

    async deleteHostHubOnly(hostId: number): Promise<HubDeletedHostEvidence> {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(`/api/web/hosts/${hostId}?mode=hub-only`, {
        method: "DELETE",
      });
      const deleted = objectView(body).deletedHost;
      const deletedAtMs = objectView(deleted).deletedAtMs;
      if (
        !isHubDeletedHostEvidence(deleted) ||
        deleted.id !== hostId ||
        !isSafeInteger(deletedAtMs) ||
        deletedAtMs < 0
      ) {
        throw new Error("Hub returned an invalid Hub-only Host deletion");
      }
      return deleted;
    },

    async getHost(hostId: number): Promise<HubHostSummary> {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(`/api/web/hosts/${hostId}`);
      const host = objectView(body).host;
      if (!isHubHostSummary(host) || host.id !== hostId) {
        throw new Error("Hub returned an invalid Host detail response");
      }
      return host;
    },

    async getAuditLog(): Promise<AuditLogEvent[]> {
      const { body } = await request("/api/web/audit-log?limit=200");
      const auditLog = objectView(body).auditLog;
      if (!isAuditLogEventList(auditLog)) {
        throw new Error("Hub returned an invalid Audit Log response");
      }
      return auditLog;
    },

    async getEnrollment(enrollmentId: string) {
      assertEnrollmentId(enrollmentId);
      return readTrackedEnrollment(enrollmentId);
    },

    async getHostMetrics(
      hostId: number,
      { window = "1m" }: { window?: HubMetricsWindow } = {},
    ): Promise<readonly unknown[]> {
      assertPositiveInteger(hostId, "Host ID");
      assertMetricsWindow(window);
      const { body } = await request(
        `/api/web/hosts/${hostId}/metrics?window=${window}`,
      );
      const samples = objectView(objectView(body).metrics).samples;
      if (!isUnknownArray(samples)) {
        throw new Error("Hub returned an invalid Metrics response");
      }
      return samples;
    },

    async getHostProbeConfiguration(
      hostId: number,
    ): Promise<HubProbeConfiguration> {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(
        `/api/web/hosts/${hostId}/probe-configuration`,
      );
      assertHostProbeConfiguration(body);
      return body;
    },

    async getProbeOperation(
      expectedOperation: ProbeOperation,
    ): Promise<ProbeOperation> {
      assertProbeOperation(expectedOperation, {
        hostId: expectedOperation?.hostId,
        id: expectedOperation?.id,
        kind: expectedOperation?.kind,
        targetProbeVersion: expectedOperation?.targetProbeVersion,
      });
      const { body } = await request(
        `/api/web/probe-operations/${expectedOperation.id}`,
      );
      const operation = objectView(body).probeOperation;
      if (!isHubProbeOperation(operation)) {
        throw new Error("Hub returned an invalid Probe Operation");
      }
      assertProbeOperation(operation, {
        hostId: expectedOperation.hostId,
        id: expectedOperation.id,
        kind: expectedOperation.kind,
        targetProbeVersion: expectedOperation.targetProbeVersion,
      });
      return operation;
    },

    // 普通 Owner 读数：修复授权响应里绑定的独立 Probe Repair Operation 只按公开
    // /api/web/probe-operations/:id 的形状读取并回显，结案与否由共享判据决定。
    async getProbeRepairOperation(
      operationId: string,
    ): Promise<HubRepairOperationReading | null> {
      if (!/^[1-9]\d*$/.test(operationId)) return null;
      const { response, body } = await request(
        `/api/web/probe-operations/${operationId}`,
        {},
        [404],
      );
      if (response.status !== 200) return null;
      const operation = objectView(body).probeOperation;
      if (!isHubProbeOperation(operation)) return null;
      assertProbeOperation(operation, { id: Number(operationId) });
      if (!isPositiveSafeInteger(operation.hostId) || !operation.kind) {
        throw assertionError(
          "probe_operation_host_unbound",
          `Hub returned Probe Operation ${operationId} without a Host binding`,
        );
      }
      return {
        hostId: operation.hostId,
        id: String(operation.id),
        kind: operation.kind,
        source: "owner-probe-operation-read",
        state: operation.state,
        targetProbeVersion: operation.targetProbeVersion,
      };
    },

    async isHostSoftDeleted(hostId: number) {
      assertPositiveInteger(hostId, "Host ID");
      const hosts = await this.listHosts();
      const { response } = await request(`/api/web/hosts/${hostId}`, {}, [404]);
      return (
        !hosts.some((host) => host.id === hostId) && response.status === 404
      );
    },

    async listHosts(): Promise<HubHostSummary[]> {
      const { body } = await request("/api/web/hosts");
      const hosts = objectView(body).hosts;
      if (!isHubHostSummaryList(hosts)) {
        throw new Error("Hub returned an invalid Host list response");
      }
      return hosts;
    },

    async requestProbeUninstall(hostId: number): Promise<ProbeOperation> {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(`/api/web/hosts/${hostId}`, {
        method: "DELETE",
      });
      const operation = objectView(body).probeUninstallRequest;
      if (!isHubProbeOperation(operation)) {
        throw new Error("Hub returned an invalid Probe Operation");
      }
      const boundOperation = {
        ...normalizeProbeUninstallOperation(operation),
        hostId,
        kind: "probe_uninstall",
      };
      assertProbeOperation(boundOperation, {
        hostId,
        kind: "probe_uninstall",
      });
      return boundOperation;
    },

    async requestProbeUpgrade(hostId: number): Promise<ProbeOperation> {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(
        `/api/web/hosts/${hostId}/probe-upgrade-requests`,
        { method: "POST" },
      );
      const operation = objectView(body).probeUpgradeRequest;
      if (!isHubProbeOperation(operation)) {
        throw new Error("Hub returned an invalid Probe Operation");
      }
      const boundOperation = {
        ...operation,
        hostId,
        kind: "probe_upgrade",
      };
      assertProbeOperation(boundOperation, {
        hostId,
        kind: "probe_upgrade",
      });
      if (
        !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
          boundOperation.targetProbeVersion ?? "",
        )
      ) {
        throw new Error("Hub returned an invalid Probe Upgrade target version");
      }
      return boundOperation;
    },

    async updateHostProbeConfiguration(
      hostId: number,
      configuration: HubProbeConfigurationUpdate,
    ): Promise<HubProbeConfiguration> {
      assertPositiveInteger(hostId, "Host ID");
      const { body } = await request(
        `/api/web/hosts/${hostId}/probe-configuration`,
        { body: JSON.stringify(configuration), method: "PUT" },
      );
      assertHostProbeConfiguration(body);
      return body;
    },

    async waitForProbeOperation(
      expectedOperation: ProbeOperation,
      options?: { intervalMs?: number; timeoutMs?: number },
    ): Promise<ProbeOperation[]> {
      assertProbeOperation(expectedOperation, {
        hostId: expectedOperation?.hostId,
        id: expectedOperation?.id,
        kind: expectedOperation?.kind,
        targetProbeVersion: expectedOperation?.targetProbeVersion,
      });
      const operationId = expectedOperation.id;
      const intervalMs = positiveDuration(options?.intervalMs, "poll interval");
      const timeoutMs = positiveDuration(options?.timeoutMs, "poll timeout");
      const maximumObservations = Math.floor(timeoutMs / intervalMs) + 1;
      const timeline = [{ ...expectedOperation }];
      let previous = expectedOperation;
      let terminalObservation: ProbeOperation | null = null;

      for (let attempt = 0; attempt < maximumObservations; attempt += 1) {
        try {
          const { body } = await request(
            `/api/web/probe-operations/${operationId}`,
          );
          const payload = objectView(body).probeOperation;
          if (!isHubProbeOperation(payload)) {
            throw new Error("Hub returned an invalid Probe Operation");
          }
          const operation =
            expectedOperation.kind === "probe_uninstall"
              ? normalizeProbeUninstallOperation(payload)
              : payload;
          assertProbeOperation(operation, {
            hostId: expectedOperation.hostId,
            id: operationId,
            kind: expectedOperation.kind,
            targetProbeVersion: expectedOperation.targetProbeVersion,
          });
          assertProbeOperationProgress(previous, operation);
          timeline.push(operation);
          if (terminalObservation) {
            assertStableTerminalOperation(terminalObservation, operation);
            return timeline;
          }
          if (terminalProbeOperationStates.has(operation.state)) {
            terminalObservation = operation;
          } else if (attempt + 1 < maximumObservations) {
            await sleep(intervalMs);
          }
          previous = operation;
        } catch (error) {
          attachObservationTimeline(error, timeline);
          throw error;
        }
      }

      const error: OperationObservationError = new Error(
        `Probe Operation ${operationId} did not complete within ${timeoutMs}ms`,
      );
      error.code = "probe_operation_timeout";
      error.timeline = timeline;
      throw error;
    },
  };
}

class HubApiError extends Error {
  body: unknown;
  code: unknown;
  status: number;

  constructor({ body, method, pathname, response }: HubApiErrorDetails) {
    super(
      `Hub API ${method} ${pathname} failed with ${response.status}: ${
        objectView(body).error ?? response.statusText
      }`,
    );
    this.body = body;
    this.code = objectView(body).error ?? "hub_api_error";
    this.status = response.status;
  }
}

function normalizeProbeUninstallOperation(
  operation: ProbeOperation,
): ProbeOperation {
  return {
    ...operation,
    targetProbeVersion: operation.targetProbeVersion ?? "",
  };
}

// 边界判据：Hub JSON 载荷的字段形状由本模块数据 Interface 声明，这里只复核原实现已有的
// 结构性判据（对象或数组；Enrollment 额外复核 token 与 installCommand 两个字符串字段），
// 不新增校验。判据不成立时抛出的错误文本与原实现一致，完整校验仍由 H 与本地断言执行。
function isAuditLogEventList(value: unknown): value is AuditLogEvent[] {
  return isUnknownArray(value);
}

function isHubDeletedHostEvidence(
  value: unknown,
): value is HubDeletedHostEvidence {
  return isUnknownRecord(value);
}

function isHubEnrollmentEvidence(
  value: unknown,
): value is HubEnrollmentEvidence {
  return (
    isUnknownRecord(value) &&
    typeof value.enrollmentToken === "string" &&
    typeof value.installCommand === "string"
  );
}

function isHubHostSummary(value: unknown): value is HubHostSummary {
  return isUnknownRecord(value);
}

function isHubHostSummaryList(value: unknown): value is HubHostSummary[] {
  return isUnknownArray(value);
}

function isHubProbeOperation(value: unknown): value is ProbeOperation {
  return isUnknownRecord(value);
}

function isHubHostProfile(
  value: UnknownRecord,
): value is UnknownRecord & HubHostProfileReading {
  return (
    typeof value.architecture === "string" &&
    isSafeInteger(value.cpuCount) &&
    typeof value.hostname === "string" &&
    typeof value.kernel === "string" &&
    typeof value.os === "string" &&
    typeof value.probeVersion === "string"
  );
}

function isHubProbeConfiguration(
  value: unknown,
): value is HubProbeConfiguration {
  const mode = objectView(value).mode;
  const configuration = objectView(objectView(value).configuration);
  return (
    isUnknownRecord(value) &&
    (mode === "inherit" || mode === "override") &&
    isUnknownArray(configuration.enabledCollectorIds) &&
    isSafeInteger(configuration.metricsCollectionIntervalSeconds) &&
    typeof configuration.version === "string"
  );
}

function isEnrollmentStatus(value: unknown): value is HubEnrollmentStatus {
  return (
    typeof value === "string" &&
    ["expired", "pending", "ready", "rejected", "verifying"].includes(value)
  );
}

function attachObservationTimeline(
  error: unknown,
  timeline: readonly ProbeOperation[],
): void {
  if (isUnknownRecord(error)) error.timeline = timeline;
}

function assertProbeOperationProgress(
  previous: ProbeOperation,
  operation: ProbeOperation,
): void {
  for (const field of [
    "createdAtMs",
    "acceptedAtMs",
    "runningAtMs",
    "completedAtMs",
  ] as const) {
    if (
      (field === "createdAtMs" && operation[field] !== previous[field]) ||
      (previous[field] !== null && operation[field] !== previous[field])
    ) {
      throw assertionError(
        "probe_operation_timestamp_changed",
        `Probe Operation ${field} changed from ${previous[field]} to ${operation[field]}`,
      );
    }
  }
  if (terminalProbeOperationStates.has(previous.state)) return;
  const allowedAfter: Partial<
    Record<ProbeOperationState, ReadonlySet<string>>
  > = {
    accepted: new Set(["accepted", "failed", "running", "succeeded"]),
    pending: new Set(Object.keys(probeOperationStateRank)),
    running: new Set(["failed", "running", "succeeded"]),
  };
  if (
    !allowedAfter[previous.state]?.has(operation.state) ||
    operation.updatedAtMs < previous.updatedAtMs
  ) {
    throw assertionError(
      "probe_operation_state_regressed",
      `Probe Operation regressed from ${previous.state}@${previous.updatedAtMs} to ${operation.state}@${operation.updatedAtMs}`,
    );
  }
}

function assertStableTerminalOperation(
  previous: ProbeOperation,
  operation: ProbeOperation,
): void {
  if (
    previous.state !== operation.state ||
    JSON.stringify(previous.failure) !== JSON.stringify(operation.failure)
  ) {
    throw assertionError(
      "probe_operation_terminal_changed",
      "Probe Operation terminal state or failure changed while being confirmed",
    );
  }
}

function assertHostProbeConfiguration(
  value: unknown,
): asserts value is HubProbeConfiguration {
  if (!isHubProbeConfiguration(value)) {
    throw new Error("Hub returned an invalid Host Probe Configuration");
  }
}

function assertPositiveInteger(
  value: unknown,
  label: string,
): asserts value is number {
  if (!isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
}

function assertEnrollmentTarget(
  target: unknown,
): asserts target is HubEnrollmentTarget {
  const view = objectView(target);
  if (view.kind === "new_host" && Object.keys(view).length === 1) {
    return;
  }
  const hostId = view.hostId;
  if (
    (view.kind === "existing_host" || view.kind === "manual_reinstall") &&
    Object.keys(view).sort().join(",") === "hostId,kind" &&
    isSafeInteger(hostId) &&
    hostId > 0
  ) {
    return;
  }
  throw new Error("Enrollment target is invalid");
}

function assertEnrollmentId(value: unknown): void {
  if (!/^enr_[A-Za-z0-9_-]{16,}$/.test(regexInput(value))) {
    throw new Error("Enrollment ID is invalid");
  }
}

function assertEnrollmentStatus(
  value: unknown,
  enrollmentId: string,
): asserts value is HubEnrollmentEvidence {
  const view = objectView(value);
  const rejection = view.rejection;
  const rejectionFields = objectView(rejection);
  const code = rejectionFields.code;
  const message = rejectionFields.message;
  const validRejection =
    rejection === null ||
    (typeof code === "string" &&
      code.length > 0 &&
      code.length <= 64 &&
      (message === null ||
        (typeof message === "string" &&
          message.length > 0 &&
          message.length <= 512)));
  const hostId = view.hostId;
  if (
    view.enrollmentId !== enrollmentId ||
    !isEnrollmentStatus(view.status) ||
    (hostId !== null && (!isSafeInteger(hostId) || hostId < 1)) ||
    !validRejection
  ) {
    throw new Error("Hub returned an invalid Enrollment status");
  }
  assertEnrollmentTarget(view.target);
}

function positiveDuration(value: unknown, label: string): number {
  if (!isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function defaultSleep(milliseconds: number): Promise<void> {
  return new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

export function assertCandidateManifest(
  manifest: unknown,
): asserts manifest is ReleaseE2ECandidateManifest {
  assertExactObjectKeys(manifest, candidateManifestKeys);
  // 边界判据：上面的断言已保证这是含这七个字段的对象，这里按同一条件把载荷提升到本模块
  // 数据 Interface，随后的逐项校验与原实现完全一致。
  if (!isReleaseE2ECandidateManifest(manifest)) {
    throw new Error("Candidate Manifest is invalid or internally inconsistent");
  }
  assertExactObjectKeys(manifest.candidate, ["commit", "version"]);
  assertExactObjectKeys(manifest.hub, [
    "archive",
    "archiveSha256",
    "digest",
    "embeddedProbeVersion",
    "size",
  ]);
  assertExactObjectKeys(manifest.probeAssetSet, [
    "directory",
    "files",
    "signingIdentity",
    "version",
  ]);
  assertExactObjectKeys(manifest.probeAssetSet.signingIdentity, [
    "algorithm",
    "publicKeyFile",
    "publicKeySha256",
  ]);
  const bootstrapRecipe = manifest.bootstrapRecipe;
  assertExactObjectKeys(bootstrapRecipe, [
    "bundleVersion",
    "distribution",
    "file",
    "kind",
    "recordFile",
    "recordSha256",
    "recordSize",
    "rootFingerprint",
    "schemaVersion",
    "sha256",
    "size",
    "targets",
    "version",
  ]);
  const candidateVersion = manifest.candidate.version;
  const probeVersion = manifest.probeAssetSet.version;
  const releaseBaseline = assertReleaseBaselineDescriptor(
    manifest.releaseBaseline,
  );
  if (
    manifest.schemaVersion !== 4 ||
    manifest.kind !== "enoki-release-candidate" ||
    !/^[0-9a-f]{40}$/.test(manifest.candidate.commit ?? "") ||
    !/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      candidateVersion ?? "",
    ) ||
    !/^sha256:[0-9a-f]{64}$/.test(manifest.hub.digest ?? "") ||
    !/^[0-9a-f]{64}$/.test(manifest.hub.archiveSha256 ?? "") ||
    manifest.hub.archive !== `hub/enoki-hub-${candidateVersion}.oci.tar` ||
    !isPositiveSafeInteger(manifest.hub.size) ||
    manifest.hub.embeddedProbeVersion !== probeVersion ||
    probeVersion !== candidateVersion.slice(1) ||
    manifest.probeAssetSet.directory !== "probe-assets" ||
    !isCandidateFileList(manifest.probeAssetSet.files) ||
    manifest.probeAssetSet.signingIdentity.algorithm !== "rsa-sha256" ||
    manifest.probeAssetSet.signingIdentity.publicKeyFile !==
      "signing-key.pem" ||
    !/^[0-9a-f]{64}$/.test(
      manifest.probeAssetSet.signingIdentity.publicKeySha256 ?? "",
    ) ||
    bootstrapRecipe.bundleVersion !== probeVersion ||
    bootstrapRecipe.distribution !== "enoki" ||
    bootstrapRecipe.file !== "enoki-probe-bootstrap.py" ||
    bootstrapRecipe.kind !== "enoki-probe-bootstrap-recipe-record" ||
    bootstrapRecipe.recordFile !== "enoki-probe-bootstrap-recipe.json" ||
    !/^[0-9a-f]{64}$/.test(bootstrapRecipe.recordSha256 ?? "") ||
    !isPositiveSafeInteger(bootstrapRecipe.recordSize) ||
    !/^[0-9a-f]{64}$/.test(bootstrapRecipe.rootFingerprint ?? "") ||
    bootstrapRecipe.schemaVersion !== 1 ||
    !/^[0-9a-f]{64}$/.test(bootstrapRecipe.sha256 ?? "") ||
    !isPositiveSafeInteger(bootstrapRecipe.size) ||
    JSON.stringify(bootstrapRecipe.targets) !== JSON.stringify(probeTargets) ||
    bootstrapRecipe.version !== "v1" ||
    releaseBaseline.tag === candidateVersion
  ) {
    throw new Error("Candidate Manifest is invalid or internally inconsistent");
  }
}

function assertReleaseBaselineDescriptor(
  baseline: ReleaseBaselineDescriptor,
): ReleaseBaselineDescriptor {
  const ordinary = baseline.kind === "enoki-release-baseline";
  const migration = baseline.kind === "enoki-trust-epoch-migration-baseline";
  assertExactObjectKeys(
    baseline,
    ordinary
      ? [
          "catalogSnapshot",
          "githubRelease",
          "hub",
          "kind",
          "probeAssetSet",
          "schemaVersion",
          "tag",
        ]
      : migration
        ? [
            "authorization",
            "catalogSnapshot",
            "githubRelease",
            "hub",
            "kind",
            "legacyProbeAssets",
            "schemaVersion",
            "tag",
            "transition",
          ]
        : [],
  );
  assertExactObjectKeys(baseline.hub, [
    "archive",
    "archiveSha256",
    "digest",
    "image",
    "imageDigest",
    "mediaType",
    "platform",
    "size",
    "sourceManifest",
    "sourceManifestSha256",
    "sourceManifestSize",
  ]);
  assertExactObjectKeys(baseline.hub.platform, ["architecture", "os"]);
  // 迁移基线的生产形状多带一个 tag：它与已签授权里被 legacyReleaseSha256 钉住的
  // githubRelease 同源，前面的候选验证已按根信任复核过该授权与描述符的字节一致性。
  assertExactObjectKeys(
    baseline.githubRelease,
    ordinary
      ? ["id", "peeledCommitSha", "repository", "tagRefSha", "targetCommitish"]
      : [
          "id",
          "peeledCommitSha",
          "repository",
          "tag",
          "tagRefSha",
          "targetCommitish",
        ],
  );
  assertExactObjectKeys(baseline.catalogSnapshot, ["entries", "sha256"]);
  validateReleaseCatalogSnapshot(baseline.catalogSnapshot);
  const snapshotRelease = baseline.catalogSnapshot.entries.find(
    (entry) =>
      entry?.id === baseline.githubRelease.id && entry.tag === baseline.tag,
  );
  if (
    !/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      baseline.tag ?? "",
    ) ||
    baseline.hub.archive !== `hub/enoki-hub-${baseline.tag}.oci.tar` ||
    !/^[0-9a-f]{64}$/.test(baseline.hub.archiveSha256 ?? "") ||
    !/^sha256:[0-9a-f]{64}$/.test(baseline.hub.digest ?? "") ||
    baseline.hub.image !== "ghcr.io/ykdz/enoki-hub" ||
    !new Set([
      "application/vnd.docker.distribution.manifest.list.v2+json",
      "application/vnd.docker.distribution.manifest.v2+json",
      "application/vnd.oci.image.index.v1+json",
      "application/vnd.oci.image.manifest.v1+json",
    ]).has(baseline.hub.mediaType) ||
    !/^sha256:[0-9a-f]{64}$/.test(baseline.hub.imageDigest ?? "") ||
    !isPositiveSafeInteger(baseline.hub.size) ||
    baseline.hub.sourceManifest !== "hub-source-manifest.json" ||
    !/^[0-9a-f]{64}$/.test(baseline.hub.sourceManifestSha256 ?? "") ||
    !isPositiveSafeInteger(baseline.hub.sourceManifestSize) ||
    baseline.hub.platform.architecture !== "amd64" ||
    baseline.hub.platform.os !== "linux" ||
    !Number.isSafeInteger(baseline.githubRelease.id) ||
    baseline.githubRelease.id < 1 ||
    baseline.githubRelease.repository !== "YKDZ/enoki" ||
    !/^[0-9a-f]{40}$/.test(baseline.githubRelease.peeledCommitSha ?? "") ||
    !/^[0-9a-f]{40}$/.test(baseline.githubRelease.tagRefSha ?? "") ||
    typeof baseline.githubRelease.targetCommitish !== "string" ||
    baseline.githubRelease.targetCommitish.length === 0 ||
    !snapshotRelease ||
    snapshotRelease.targetCommitish !==
      baseline.githubRelease.targetCommitish ||
    baseline.hub.digest !== `sha256:${baseline.hub.sourceManifestSha256}`
  ) {
    throw new Error("Candidate Manifest Release Baseline is invalid");
  }
  if (ordinary) {
    assertExactObjectKeys(baseline.probeAssetSet, [
      "directory",
      "files",
      "signingIdentity",
      "trustRoot",
      "version",
    ]);
    assertExactObjectKeys(baseline.probeAssetSet.signingIdentity, [
      "algorithm",
      "publicKeyFile",
      "publicKeySha256",
    ]);
    assertExactObjectKeys(baseline.probeAssetSet.trustRoot, [
      "publicKeySha256",
    ]);
    if (
      baseline.schemaVersion !== 2 ||
      baseline.probeAssetSet.directory !== "probe-assets" ||
      baseline.probeAssetSet.version !== baseline.tag.slice(1) ||
      !isCandidateFileList(baseline.probeAssetSet.files) ||
      baseline.probeAssetSet.signingIdentity.algorithm !== "rsa-sha256" ||
      baseline.probeAssetSet.signingIdentity.publicKeyFile !==
        "signing-key.pem" ||
      !/^[0-9a-f]{64}$/.test(
        baseline.probeAssetSet.signingIdentity.publicKeySha256 ?? "",
      ) ||
      !/^[0-9a-f]{64}$/.test(
        baseline.probeAssetSet.trustRoot.publicKeySha256 ?? "",
      )
    ) {
      throw new Error("Candidate Manifest rooted Release Baseline is invalid");
    }
    return baseline;
  }
  assertExactObjectKeys(baseline.authorization, [
    "file",
    "legacyReleaseSha256",
    "sha256",
    "signatureFile",
    "signatureSha256",
  ]);
  assertExactObjectKeys(baseline.legacyProbeAssets, ["directory", "files"]);
  if (
    baseline.schemaVersion !== 1 ||
    baseline.tag !== "v0.1.74" ||
    baseline.transition !== "replacement-required" ||
    baseline.authorization.file !==
      "trust-epoch-migration-authorization.json" ||
    baseline.authorization.signatureFile !==
      "trust-epoch-migration-authorization.json.sig" ||
    !/^[0-9a-f]{64}$/.test(baseline.authorization.legacyReleaseSha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(baseline.authorization.sha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(baseline.authorization.signatureSha256 ?? "") ||
    baseline.legacyProbeAssets.directory !== "probe-assets" ||
    !isLegacyCandidateFileList(baseline.legacyProbeAssets.files)
  ) {
    throw new Error(
      "Candidate Manifest Trust Epoch Migration Baseline is invalid",
    );
  }
  return baseline;
}

function isTrustEpochMigrationBaseline(
  baseline: ReleaseBaselineDescriptor,
): baseline is MigrationReleaseBaselineDescriptor {
  return baseline.kind === "enoki-trust-epoch-migration-baseline";
}

function releaseBaselineProbeVersion(
  baseline: ReleaseBaselineDescriptor,
): string {
  assertReleaseBaselineDescriptor(baseline);
  return isTrustEpochMigrationBaseline(baseline)
    ? baseline.tag.slice(1)
    : baseline.probeAssetSet.version;
}

// 基线安装消费该已验证 Release Baseline 类型对应的安装边界：Trust Epoch 迁移基线按旧发布
// 边界验证，其余基线沿用候选 schema 2 边界。两类转换共用同一 Harness 与 execute 接缝。
async function assertReleaseBaselineInstalled(
  host: ProbeHost,
  baseline: ReleaseBaselineDescriptor,
  runId: string,
) {
  const expectedProbeVersion = releaseBaselineProbeVersion(baseline);
  return isTrustEpochMigrationBaseline(baseline)
    ? host.assertLegacyReleaseBaselineInstalled(runId, expectedProbeVersion)
    : host.assertInstalled(runId, expectedProbeVersion);
}

function releaseBaselineEvidence(baseline: ReleaseBaselineDescriptor) {
  assertReleaseBaselineDescriptor(baseline);
  const migration = isTrustEpochMigrationBaseline(baseline);
  return {
    authority: migration
      ? {
          authorizationSha256: baseline.authorization.sha256,
          githubReleaseId: baseline.githubRelease.id,
          legacyReleaseSha256: baseline.authorization.legacyReleaseSha256,
          peeledCommitSha: baseline.githubRelease.peeledCommitSha,
        }
      : {
          githubReleaseId: baseline.githubRelease.id,
          peeledCommitSha: baseline.githubRelease.peeledCommitSha,
          signingPublicKeySha256:
            baseline.probeAssetSet.signingIdentity.publicKeySha256,
          trustRootPublicKeySha256:
            baseline.probeAssetSet.trustRoot.publicKeySha256,
        },
    descriptorSha256: createHash("sha256")
      .update(JSON.stringify(baseline))
      .digest("hex"),
    hubDigest: baseline.hub.imageDigest,
    kind: baseline.kind,
    probeVersion: releaseBaselineProbeVersion(baseline),
    tag: baseline.tag,
  };
}

// 边界判据：assertExactObjectKeys 已经保证条目是含这三个字段的对象，这里按同一条件把它
// 提升到本模块数据 Interface；判据不成立时沿用原实现在该处的结果（该条目不算合法清单）。
function isCandidateFileEntryShape(
  value: unknown,
): value is CandidateFileEntry {
  return isUnknownRecord(value);
}

function isLegacyCandidateFileEntryShape(
  value: unknown,
): value is LegacyCandidateFileEntry {
  return isUnknownRecord(value);
}

function isCandidateFileList(files: unknown): boolean {
  return (
    isUnknownArray(files) &&
    files.length > 0 &&
    files.every((file) => {
      try {
        assertExactObjectKeys(file, ["file", "sha256", "size"]);
      } catch {
        return false;
      }
      if (!isCandidateFileEntryShape(file)) return false;
      return (
        /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(file.file ?? "") &&
        !file.file.includes("..") &&
        /^[0-9a-f]{64}$/.test(file.sha256 ?? "") &&
        isPositiveSafeInteger(file.size)
      );
    })
  );
}

function isLegacyCandidateFileList(files: unknown): boolean {
  return (
    isUnknownArray(files) &&
    files.length > 0 &&
    files.every((file) => {
      try {
        assertExactObjectKeys(file, ["name", "sha256", "size"]);
      } catch {
        return false;
      }
      if (!isLegacyCandidateFileEntryShape(file)) return false;
      return (
        /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(file.name ?? "") &&
        !file.name.includes("..") &&
        /^[0-9a-f]{64}$/.test(file.sha256 ?? "") &&
        isPositiveSafeInteger(file.size)
      );
    })
  );
}

// 边界判据：与原实现一致，只复核参与者对象上这些方法存在；非对象或数组载荷经 objectView
// 得到空对象，判据同样不成立，失败文本保持原样。
function hasAllMethods(value: unknown, methods: readonly string[]): boolean {
  const view = objectView(value);
  return methods.every((method) => typeof view[method] === "function");
}

function assertScenarioParticipants(host: unknown, hub: unknown): void {
  const hostMethods = [
    "assertDisposable",
    "assertInstalled",
    "cleanup",
    "collectEvidence",
    "install",
    "verifyUninstallCompletion",
  ];
  const hubMethods = [
    "authenticate",
    "createEnrollment",
    "getHost",
    "getHostMetrics",
    "isHostSoftDeleted",
    "listHosts",
    "requestProbeUninstall",
    "waitForProbeOperation",
  ];
  if (!hasAllMethods(host, hostMethods) || !hasAllMethods(hub, hubMethods)) {
    throw new Error("Release E2E environment returned invalid participants");
  }
}

function assertFreshInstallScenarioParticipants(
  host: unknown,
  hub: unknown,
): void {
  const hostMethods = [
    "assertDisposable",
    "assertInstalled",
    "awaitPermanentReportRejection",
    "captureInstallationState",
    "cleanup",
    "collectDiagnostics",
    "collectEvidence",
    "install",
    "localUninstall",
    "readProbeIdentity",
    "rejectRepeatedInstall",
    "repairInstalledBundleFailure",
  ];
  const hubMethods = [
    "authenticate",
    "collectEvidence",
    "createEnrollment",
    "deleteHostHubOnly",
    "getAuditLog",
    "getEnrollment",
    "getHost",
    "getHostMetrics",
    "getHostProbeConfiguration",
    "isHostSoftDeleted",
    "listHosts",
    "updateHostProbeConfiguration",
  ];
  if (!hasAllMethods(host, hostMethods) || !hasAllMethods(hub, hubMethods)) {
    throw new Error(
      "Release E2E environment returned invalid fresh-install participants",
    );
  }
}

function assertCreatedEnrollment(
  enrollment: HubEnrollmentEvidence,
  expectedTarget: unknown,
): asserts enrollment is HubEnrollmentEvidence & { enrollmentId: string } {
  if (
    !enrollment?.installCommand ||
    enrollment?.status !== "pending" ||
    JSON.stringify(enrollment.target) !== JSON.stringify(expectedTarget)
  ) {
    throw assertionError(
      "enrollment_command_missing",
      "Hub did not return an official pending Enrollment for the expected target",
    );
  }
  assertEnrollmentId(enrollment.enrollmentId);
  assertInstallCommand(enrollment.installCommand);
}

function compactEnrollmentEvidence(enrollment: HubEnrollmentEvidence): {
  enrollmentId?: string;
  status?: HubEnrollmentStatus;
  target?: HubEnrollmentTarget;
} {
  return {
    enrollmentId: enrollment.enrollmentId,
    status: enrollment.status,
    target: enrollment.target,
  };
}

function compactEnrollmentStatusEvidence(enrollment: HubEnrollmentEvidence): {
  enrollmentId?: string;
  hostId?: number | null;
  rejection?: { code: string; message: string | null } | null;
  status?: HubEnrollmentStatus;
  target?: HubEnrollmentTarget;
} {
  return {
    enrollmentId: enrollment.enrollmentId,
    hostId: enrollment.hostId,
    rejection: enrollment.rejection,
    status: enrollment.status,
    target: enrollment.target,
  };
}

function recordEnrollmentEvidence(
  enrollments: Map<string, HubEnrollmentTrackingRecord>,
  enrollment: unknown,
): void {
  const view = objectView(enrollment);
  if (typeof view.enrollmentId !== "string") return;
  enrollments.set(view.enrollmentId, {
    enrollmentId: view.enrollmentId,
    hostId: view.hostId ?? null,
    rejection: view.rejection ?? null,
    readError: null,
    status: view.status ?? null,
    target: view.target ?? null,
  });
}

function assertMetricsWindow(
  window: unknown,
): asserts window is HubMetricsWindow {
  if (
    !new Set(["1m", "10m", "1h", "6h", "24h", "3d", "7d"]).has(
      regexInput(window),
    )
  ) {
    throw new Error("Hub Metrics window is invalid");
  }
}

function assertLocalUninstallCompletion(completion: unknown): void {
  const view = objectView(completion);
  if (
    view.clean !== true ||
    view.journaldRetained !== true ||
    view.sharedDependenciesRetained !== true
  ) {
    throw assertionError(
      "local_probe_uninstall_residue",
      "Local Probe Uninstall did not satisfy the shared no-residue boundary",
    );
  }
  assertHostInventoryEvidence(view.inventory);
  if (inventoryResidue(view.inventory).length > 0) {
    throw assertionError(
      "local_probe_uninstall_residue",
      "Local Probe Uninstall left Enoki-managed residue",
    );
  }
}

function hasPortableMetricsAfter(
  samples: readonly unknown[] | null | undefined,
  previousSamples: readonly unknown[],
): boolean {
  const previous = latestPortableMetric(previousSamples);
  if (!previous || !isUnknownArray(samples)) return false;
  return samples.some(
    (sample) =>
      isPortableMetricSample(sample) &&
      sample.collectedAtMs > previous.collectedAtMs,
  );
}

function retainsInitialMetricSample(
  samples: readonly unknown[] | null | undefined,
  initialSamples: readonly unknown[],
): boolean {
  const initial = compactMetricsEvidence(initialSamples)[0];
  if (!initial || !isUnknownArray(samples)) return false;
  return samples.some(
    (sample) =>
      isPortableMetricSample(sample) &&
      sample.sequence === initial.sequence &&
      sample.collectedAtMs === initial.collectedAtMs,
  );
}

function retainsMetricHistoryAnchors(
  samples: readonly unknown[],
  anchors: readonly MetricHistoryAnchor[],
): boolean {
  return (
    Array.isArray(anchors) &&
    anchors.length > 0 &&
    anchors.every((anchor) =>
      samples.some(
        (sample) =>
          isPortableMetricSample(sample) &&
          JSON.stringify(compactMetricAnchor(sample)) ===
            JSON.stringify(anchor),
      ),
    )
  );
}

function assertFreshLifecycleAuditLog(
  auditLog: AuditLogEvent[],
  hostId: number,
): AuditLogEvent[] {
  const required: {
    action: string;
    matches: (event: AuditLogEvent) => boolean;
  }[] = [
    {
      action: "enrollment_token.create",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.details?.target?.kind === "new_host",
    },
    {
      action: "enrollment.installation_rejected",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "system" &&
        event.outcome === "success" &&
        event.details?.code === "existing_probe_installation",
    },
    {
      action: "enrollment_token.create",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.details?.target?.kind === "existing_host" &&
        event.details.target.hostId === hostId,
    },
    {
      action: "probe_configuration.host.override",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.subjectId === String(hostId),
    },
    {
      action: "host.delete",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.subjectId === String(hostId) &&
        event.subjectType === "host" &&
        event.details?.hostId === hostId &&
        event.details?.mode === "hub-only",
    },
  ];
  const selected = required.map(({ action, matches }) =>
    auditLog.find((event) => event?.action === action && matches(event)),
  );
  const missing = required
    .filter((_, index) => !selected[index])
    .map(({ action }) => action);
  if (missing.length > 0) {
    throw assertionError(
      "fresh_lifecycle_audit_log_missing",
      `Hub Audit Log is missing fresh lifecycle evidence: ${missing.join(", ")}`,
    );
  }
  return selected.filter(
    (event): event is AuditLogEvent => event !== undefined,
  );
}

function assertBaselineScenarioParticipants(
  host: unknown,
  hub: unknown,
  transitionClassification: UpgradeTransitionClassification,
): void {
  assertScenarioParticipants(host, hub);
  const hostMethods = ["readProbeIdentity"];
  const hubMethods = ["switchToCandidate"];
  if (transitionClassification === "replacement-required") {
    hostMethods.push("assertLegacyReleaseBaselineInstalled", "manualReinstall");
    hubMethods.push(
      "createManualReinstallEnrollment",
      "getAuditLog",
      "getHostProbeConfiguration",
      "updateHostProbeConfiguration",
    );
  } else {
    hostMethods.push(
      "beginUpgradeOwnershipTransition",
      "bindUpgradeOwnershipTransition",
      "completeUpgradeOwnershipTransition",
    );
    hubMethods.push("requestProbeUpgrade");
  }
  if (!hasAllMethods(host, hostMethods) || !hasAllMethods(hub, hubMethods)) {
    throw new Error(
      "Release E2E environment returned invalid baseline-upgrade participants",
    );
  }
}

function assertHubRestoreScenarioParticipants(
  host: unknown,
  hub: unknown,
): void {
  const hostMethods = [
    "assertDisposable",
    "assertInstalled",
    "cleanup",
    "collectEvidence",
    "install",
    "readProbeIdentity",
    "verifyUninstallCompletion",
  ];
  const hubMethods = [
    "authenticate",
    "captureBaselineStateSnapshot",
    "createEnrollment",
    "getHost",
    "getHostMetrics",
    "listHosts",
    "isHostSoftDeleted",
    "requestProbeUninstall",
    "restoreBaselineStateSnapshot",
    "switchToCandidate",
    "waitForProbeOperation",
  ];
  hostMethods.push(
    "beginUpgradeOwnershipTransition",
    "bindUpgradeOwnershipTransition",
    "completeUpgradeOwnershipTransition",
  );
  hubMethods.push("requestProbeUpgrade");
  if (!hasAllMethods(host, hostMethods) || !hasAllMethods(hub, hubMethods)) {
    throw new Error(
      "Release E2E environment returned invalid Hub Restore participants",
    );
  }
}

function assertLiveHubStateSnapshotEvidence(
  snapshot: HubStateSnapshotEvidence | null | undefined,
  baseline: ReleaseBaselineDescriptor,
): void {
  if (
    snapshot?.tool !== "enoki-hub-state" ||
    snapshot.version !== "v1" ||
    snapshot.baselineImageDigest !== baseline.hub.imageDigest ||
    snapshot.baselineVersion !== baseline.tag ||
    !/^sha256:[0-9a-f]{64}$/.test(snapshot.manifestDigest ?? "") ||
    !Number.isFinite(Date.parse(snapshot.recoveryTime ?? "")) ||
    !Number.isSafeInteger(snapshot.hotDataFileCount) ||
    snapshot.hotDataFileCount < 1 ||
    !Array.isArray(snapshot.hotDataFiles) ||
    !snapshot.hotDataFiles.includes("data-root/enoki.db") ||
    !Array.isArray(snapshot.roots) ||
    !snapshot.roots.some(
      (root) => root?.id === "data-root" && root.path === "/data",
    ) ||
    !snapshot.roots.some(
      (root) =>
        root?.id === "metrics-archive" &&
        root.path === "/data/metrics-archive" &&
        root.included === true,
    )
  ) {
    throw assertionError(
      "hub_state_snapshot_evidence_invalid",
      "Hub State Snapshot does not prove hot data and the configured Metrics Archive boundary",
    );
  }
}

function assertLiveHubRestoreEvidence(
  restored: HubStateRestoreEvidence | null | undefined,
  expectedManifestDigest: string,
  expectedBaselineImageDigest: string,
): void {
  if (
    restored?.verify?.status !== "succeeded" ||
    restored.verify.manifestDigest !== expectedManifestDigest ||
    restored?.restore?.status !== "succeeded" ||
    restored.restore.manifestDigest !== expectedManifestDigest ||
    restored?.image?.expectedManifestDigest !== expectedBaselineImageDigest ||
    restored.image.activeManifestDigest !== expectedBaselineImageDigest
  ) {
    throw assertionError(
      "hub_state_restore_evidence_invalid",
      "Hub Restore did not verify and restore the snapshot before starting the exact Release Baseline image",
    );
  }
}

function assertSameProbeIdentity(
  before: ProbeIdentity | null | undefined,
  after: ProbeIdentity | null | undefined,
  boundary: string,
): void {
  if (
    !before ||
    !after ||
    before.probeId !== after.probeId ||
    before.identitySha256 !== after.identitySha256
  ) {
    throw assertionError(
      "probe_identity_changed",
      `${boundary} changed the Probe Identity`,
    );
  }
}

function assertRepairScenarioParticipants(host: unknown, hub: unknown): void {
  assertBaselineScenarioParticipants(host, hub, "compatible");
  const hostMethods = [
    "armPostReplacementRestartFault",
    "assertPostReplacementUpgradeFailure",
    "completeRepairOwnershipTransition",
    "removePostReplacementRestartFault",
    "repair",
  ];
  if (
    !hasAllMethods(host, hostMethods) ||
    typeof objectView(hub).getProbeOperation !== "function"
  ) {
    throw new Error(
      "Release E2E environment returned invalid post-replacement Repair participants",
    );
  }
}

function assertLifecycleAuditLog(
  auditLog: readonly AuditLogEvent[],
  hostId: number,
  operationId: number,
): AuditLogEvent[] {
  const required: {
    action: string;
    matches: (event: AuditLogEvent) => boolean;
  }[] = [
    {
      action: "enrollment_token.create",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.subjectType === "enrollment_token",
    },
    {
      action: "probe_configuration.host.override",
      matches: (event) =>
        isValidLifecycleAuditEvent(event) &&
        event.actor === "owner" &&
        event.outcome === "success" &&
        event.subjectId === String(hostId),
    },
    {
      action: "host.delete",
      matches: (event) => {
        const details = event.details;
        return (
          isValidLifecycleAuditEvent(event) &&
          event.actor === "owner" &&
          event.outcome === "success" &&
          event.subjectId === String(hostId) &&
          event.subjectType === "host" &&
          details?.hostId === hostId &&
          details?.probeOperationId === operationId
        );
      },
    },
  ];
  const selected = required.map(({ action, matches }) =>
    auditLog.find((event) => event?.action === action && matches(event)),
  );
  const missing = required
    .filter((_, index) => !selected[index])
    .map(({ action }) => action);
  if (missing.length > 0) {
    throw assertionError(
      "lifecycle_audit_log_missing",
      `Hub Audit Log is missing lifecycle evidence: ${missing.join(", ")}`,
    );
  }
  // 上一项判定已保证每个 action 都命中，这里只是把该事实交给类型系统。
  return selected.filter(
    (event): event is AuditLogEvent => event !== undefined,
  );
}

function assertMigrationLifecycleAuditLog(
  auditLog: readonly AuditLogEvent[],
  hostId: number,
  operationId: number,
  oldIdentity: ProbeIdentity,
  newIdentity: ProbeIdentity,
): AuditLogEvent[] {
  const selected = assertLifecycleAuditLog(auditLog, hostId, operationId);
  return [
    ...selected,
    ...assertManualReinstallAuditEvent(
      auditLog,
      hostId,
      oldIdentity,
      newIdentity,
    ),
  ];
}

function assertManualReinstallAuditEvent(
  auditLog: readonly AuditLogEvent[],
  hostId: number,
  oldIdentity: ProbeIdentity,
  newIdentity: ProbeIdentity,
): AuditLogEvent[] {
  const replacement = auditLog.find((event) => {
    const details = event?.details;
    const sourceProbeSha256 = details?.sourceProbeSha256;
    return (
      event?.action === "probe.manual_reinstall_identity_replaced" &&
      isValidLifecycleAuditEvent(event) &&
      event.actor === "system" &&
      event.outcome === "success" &&
      event.subjectId === String(hostId) &&
      event.subjectType === "host" &&
      details?.oldProbeId === oldIdentity.probeId &&
      details?.newProbeId === newIdentity.probeId &&
      Array.isArray(sourceProbeSha256) &&
      sourceProbeSha256.length > 0 &&
      /^sha256:[0-9a-f]{64}$/.test(regexInput(details?.targetAssetSetDigest)) &&
      /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
        regexInput(details?.targetProbeVersion),
      )
    );
  });
  if (!replacement) {
    throw assertionError(
      "manual_reinstall_audit_log_missing",
      "Hub Audit Log is missing the production manual reinstall identity replacement event",
    );
  }
  return [replacement];
}

function assertBaselineUpgradeAuditLog(
  auditLog: readonly AuditLogEvent[],
  hostId: number,
  upgradeOperationId: number,
  uninstallOperationId: number,
  targetProbeVersion: string,
): AuditLogEvent[] {
  const lifecycle = assertLifecycleAuditLog(
    auditLog,
    hostId,
    uninstallOperationId,
  );
  const upgrade = auditLog.find(
    (event) =>
      event?.action === "probe_upgrade_request.create" &&
      isValidLifecycleAuditEvent(event) &&
      event.actor === "owner" &&
      event.outcome === "success" &&
      event.subjectId === String(upgradeOperationId) &&
      event.subjectType === "probe_upgrade_request" &&
      event.details?.hostId === hostId &&
      event.details?.targetProbeVersion === targetProbeVersion,
  );
  if (!upgrade) {
    throw assertionError(
      "lifecycle_audit_log_missing",
      "Hub Audit Log is missing the Owner-authorized Probe Upgrade",
    );
  }
  return [...lifecycle, upgrade];
}

function isValidLifecycleAuditEvent(event: unknown): boolean {
  const view = objectView(event);
  const id = view.id;
  const occurredAtMs = view.occurredAtMs;
  const action = view.action;
  const subjectId = view.subjectId;
  const subjectType = view.subjectType;
  return (
    typeof id === "number" &&
    Number.isSafeInteger(id) &&
    id > 0 &&
    typeof occurredAtMs === "number" &&
    Number.isSafeInteger(occurredAtMs) &&
    occurredAtMs > 0 &&
    typeof action === "string" &&
    action.length > 0 &&
    typeof subjectId === "string" &&
    subjectId.length > 0 &&
    typeof subjectType === "string" &&
    subjectType.length > 0
  );
}

export function validateSuccessfulProbeUpgradeTimeline(
  timeline: readonly ProbeOperation[],
): void {
  if (!Array.isArray(timeline) || timeline.length < 2) {
    throw assertionError(
      "probe_upgrade_timeline_incomplete",
      "Probe Upgrade did not record its request and terminal operation evidence",
    );
  }
  const requested = timeline[0];
  if (
    requested?.state !== "pending" ||
    requested.acceptedAtMs !== null ||
    requested.runningAtMs !== null ||
    requested.completedAtMs !== null
  ) {
    throw assertionError(
      "probe_upgrade_request_invalid",
      "Probe Upgrade request did not begin as a pending operation",
    );
  }
  let previous: ProbeOperation | null = null;
  let terminal: ProbeOperation | null = null;
  for (const operation of timeline) {
    assertProbeOperation(operation, {
      hostId: requested.hostId,
      id: requested.id,
      kind: "probe_upgrade",
      targetProbeVersion: requested.targetProbeVersion,
    });
    if (previous) assertProbeOperationProgress(previous, operation);
    if (terminal) assertStableTerminalOperation(terminal, operation);
    if (!terminal && terminalProbeOperationStates.has(operation.state)) {
      terminal = operation;
    }
    previous = operation;
  }
  const finalOperation = timeline.at(-1);
  if (
    finalOperation?.acceptedAtMs === null ||
    finalOperation?.acceptedAtMs === undefined ||
    finalOperation?.runningAtMs === null ||
    finalOperation?.runningAtMs === undefined ||
    finalOperation?.completedAtMs === null ||
    finalOperation?.completedAtMs === undefined ||
    finalOperation?.state !== "succeeded" ||
    finalOperation.failure
  ) {
    throw assertionError(
      "probe_upgrade_timeline_incomplete",
      `Probe Upgrade did not preserve accepted, running, and succeeded transition evidence: ${JSON.stringify(timeline)}`,
    );
  }
}

function validateInsufficientPrivilegeProbeUpgradeTimeline(
  timeline: readonly ProbeOperation[],
): void {
  if (!Array.isArray(timeline) || timeline.length < 3) {
    throw assertionError(
      "probe_upgrade_timeline_incomplete",
      "Probe Upgrade permission failure did not retain bounded terminal evidence",
    );
  }
  const requested = timeline[0];
  let previous: ProbeOperation | null = null;
  for (const operation of timeline) {
    assertProbeOperation(operation, {
      hostId: requested?.hostId,
      id: requested?.id,
      kind: "probe_upgrade",
      targetProbeVersion: requested?.targetProbeVersion,
    });
    if (previous) assertProbeOperationProgress(previous, operation);
    previous = operation;
  }
  const finalOperation = timeline.at(-1);
  const confirmedOperation = timeline.at(-2);
  if (
    requested?.state !== "pending" ||
    requested.acceptedAtMs !== null ||
    requested.runningAtMs !== null ||
    requested.completedAtMs !== null ||
    finalOperation?.state !== "failed" ||
    finalOperation.failure?.code !== "insufficient_privilege" ||
    !Number.isSafeInteger(finalOperation.acceptedAtMs) ||
    !Number.isSafeInteger(finalOperation.completedAtMs)
  ) {
    throw assertionError(
      "probe_upgrade_permission_failure_invalid",
      `Probe Upgrade did not preserve a terminal insufficient-privilege failure: ${JSON.stringify(timeline)}`,
    );
  }
  // 顶部长度判定已保证 timeline 至少三项，这里只是把该事实交给类型系统。
  if (!confirmedOperation) {
    throw assertionError(
      "probe_upgrade_timeline_incomplete",
      "Probe Upgrade permission failure did not retain bounded terminal evidence",
    );
  }
  assertStableTerminalOperation(confirmedOperation, finalOperation);
}

async function proveProbeConfigurationRoundTrip({
  hostId,
  hub,
  poll,
}: {
  hostId: number;
  hub: ScenarioHub;
  poll: PollTiming;
}) {
  const existing = await hub.getHostProbeConfiguration(hostId);
  const values = existing?.configuration;
  if (
    !values ||
    !Array.isArray(values.enabledCollectorIds) ||
    !Number.isSafeInteger(values.metricsCollectionIntervalSeconds) ||
    !values.enabledCollectorIds.includes("official.cpu") ||
    !values.enabledCollectorIds.includes("official.memory")
  ) {
    throw assertionError(
      "probe_configuration_invalid",
      "Hub returned an invalid Probe Configuration",
    );
  }
  const updated = await hub.updateHostProbeConfiguration(hostId, {
    configuration: {
      enabledCollectorIds: values.enabledCollectorIds,
      metricsCollectionIntervalSeconds:
        values.metricsCollectionIntervalSeconds === 2 ? 3 : 2,
    },
    mode: "override",
  });
  const version = updated?.configuration?.version;
  if (!version) {
    throw assertionError(
      "probe_configuration_version_missing",
      "Hub did not version the updated Probe Configuration",
    );
  }
  const reported = await waitForObservation({
    code: "probe_configuration_round_trip_timeout",
    label: `Probe Configuration ${version}`,
    observe: () => hub.getHost(hostId),
    poll,
    ready: (value) => {
      if (value === null || value === undefined) return false;
      return (
        value.reportedProbeConfigurationVersion === version &&
        !value.warnings?.some(
          (warning) => warning.code === "probe_configuration_error",
        )
      );
    },
  });
  return {
    configuration: canonicalSemanticValue(updated.configuration),
    mode: updated.mode,
    reportedVersion: reported.reportedProbeConfigurationVersion,
    version,
  };
}

function sameEffectiveProbeConfiguration(
  current: unknown,
  expected: unknown,
): boolean {
  const currentView = objectView(current);
  const expectedView = objectView(expected);
  return (
    currentView.mode === expectedView.mode &&
    JSON.stringify(canonicalSemanticValue(currentView.configuration)) ===
      JSON.stringify(expectedView.configuration)
  );
}

function effectiveProbeConfigurationEvidence(value: unknown) {
  const view = objectView(value);
  return {
    configuration: canonicalSemanticValue(view.configuration),
    mode: view.mode,
  };
}

function metricsAdvanceBeyond(
  samples: readonly unknown[],
  previous: PortableMetricSample | null,
): boolean {
  const compact = compactMetricsEvidence(samples);
  const latest = compact.at(-1);
  const latestSequence = latest?.sequence;
  const latestCollectedAtMs = latest?.collectedAtMs;
  const previousSequence = previous?.sequence;
  const previousCollectedAtMs = previous?.collectedAtMs;
  // 原实现依赖 NaN 比较恒为 false 的语义；这里的 typeof 判定只把同一事实交给类型系统。
  return (
    typeof latestSequence === "number" &&
    typeof previousSequence === "number" &&
    latestSequence > previousSequence &&
    typeof latestCollectedAtMs === "number" &&
    typeof previousCollectedAtMs === "number" &&
    latestCollectedAtMs > previousCollectedAtMs
  );
}

function normalizedPollTiming(timing: ReleaseScenarioTiming): PollTiming {
  return {
    intervalMs: timing.intervalMs ?? 2_000,
    sleep: timing.sleep ?? defaultSleep,
    timeoutMs: timing.timeoutMs ?? 120_000,
  };
}

function localUninstallOfflineObservationPoll(
  timing: ReleaseScenarioTiming,
  poll: PollTiming,
): PollTiming {
  return {
    ...poll,
    timeoutMs: Math.max(
      timing.offlineTimeoutMs ?? poll.timeoutMs,
      defaultLocalUninstallOfflineObservationTimeoutMs,
    ),
  };
}

async function waitForObservation<T>({
  code,
  label,
  observe,
  poll,
  ready,
}: {
  code: string;
  label: string;
  observe: () => Promise<T | null | undefined>;
  poll: PollTiming;
  ready: (value: T | null | undefined) => boolean;
}): Promise<NonNullable<T>> {
  const intervalMs = positiveDuration(poll.intervalMs, "poll interval");
  const timeoutMs = positiveDuration(poll.timeoutMs, "poll timeout");
  const maximumObservations = Math.floor(timeoutMs / intervalMs) + 1;
  let lastValue: T | null | undefined = null;
  let lastError: unknown = null;

  for (let attempt = 0; attempt < maximumObservations; attempt += 1) {
    try {
      lastValue = await observe();
      lastError = null;
      // 判据为真的载荷必然存在，这里只是把该事实交给类型系统。
      if (ready(lastValue) && lastValue !== null && lastValue !== undefined) {
        return lastValue;
      }
    } catch (error) {
      lastError = error;
    }
    if (attempt + 1 < maximumObservations) await poll.sleep(intervalMs);
  }

  const error: ObservationTimeoutError = assertionError(
    code,
    `${label} was not observed within ${timeoutMs}ms${
      lastError ? `: ${String(objectView(lastError).message)}` : ""
    }`,
  );
  error.lastValue = lastValue;
  throw error;
}

function stableHostProfileEvidence(profile: HubHostProfile) {
  const projection = {
    architecture: profile.architecture,
    collectorCapabilities: canonicalSemanticValue(
      profile.collectorCapabilities ?? null,
    ),
    cpu: {
      cacheL3Bytes: profile.cpuCacheL3Bytes ?? null,
      count: profile.cpuCount,
      model: profile.cpuModel ?? null,
      physicalCount: profile.cpuPhysicalCount ?? null,
      socketCount: profile.cpuSocketCount ?? null,
    },
    filesystems: profile.filesystems
      .map((filesystem) => ({
        filesystemType: filesystem.filesystemType,
        mountPoint: filesystem.mountPoint,
        totalBytes: filesystem.totalBytes,
      }))
      .sort((left, right) =>
        `${left.mountPoint}\0${left.filesystemType}`.localeCompare(
          `${right.mountPoint}\0${right.filesystemType}`,
        ),
      ),
    hostname: profile.hostname,
    kernel: profile.kernel,
    memoryTotalBytes: profile.memoryTotalBytes,
    networkInterfaces: profile.networkInterfaces
      .filter((networkInterface) =>
        isStableHostNetworkInterface(networkInterface),
      )
      .map((networkInterface) => ({
        addresses: [...new Set(networkInterface.addresses ?? [])].sort(),
        name: networkInterface.name,
      }))
      .sort((left, right) => left.name.localeCompare(right.name)),
    os: profile.os,
    probeVersion: profile.probeVersion,
  };
  const serialized = JSON.stringify(projection);
  return {
    projection,
    sha256: createHash("sha256").update(serialized).digest("hex"),
  };
}

function isStableHostNetworkInterface(
  networkInterface: HubHostProfile["networkInterfaces"][number],
): boolean {
  return (
    typeof networkInterface?.name === "string" &&
    networkInterface.name.length > 0 &&
    !networkInterface.name.startsWith("veth")
  );
}

function assertStableHostProfileContinuity(
  candidate: HostProfileProjection | null | undefined,
  restored: HostProfileProjection | null | undefined,
): void {
  if (
    !candidate ||
    !restored ||
    candidate.sha256 !== restored.sha256 ||
    JSON.stringify(candidate.projection) !== JSON.stringify(restored.projection)
  ) {
    throw assertionError(
      "host_profile_stable_projection_changed",
      "Hub Restore changed the Candidate Probe Host Profile stable semantic projection",
    );
  }
}

function canonicalSemanticValue(value: unknown): unknown {
  if (isUnknownArray(value)) {
    return value.map(canonicalSemanticValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, entryValue]) => entryValue !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entryValue]) => [key, canonicalSemanticValue(entryValue)]),
    );
  }
  return value;
}

function compactHostEvidence(host: HubHostSummary) {
  return {
    hostProfile: host.hostProfile,
    id: host.id,
    status: host.status,
  };
}

function stableHubHostProjection(host: unknown) {
  const view = objectView(host);
  return {
    hostMetadata: canonicalHostMetadata(view.hostMetadata),
    hostProfile: canonicalSemanticValue(view.hostProfile),
    id: view.id,
    reportedProbeConfigurationVersion:
      view.reportedProbeConfigurationVersion ?? null,
  };
}

function canonicalHostMetadata(metadata: unknown) {
  const view = objectView(metadata);
  return {
    connectAddress: view.connectAddress ?? null,
    description: view.description ?? null,
    displayName: view.displayName ?? null,
    observedIp: view.observedIp ?? null,
  };
}

function compactMetricsEvidence(samples: readonly unknown[]) {
  const ordered = samples
    .filter(isPortableMetricSample)
    .sort((a, b) => a.sequence - b.sequence);
  return [ordered[0], ordered.at(-1)].map((sample) => ({
    collectedAtMs: sample?.collectedAtMs,
    cpuPercent: sample?.cpuPercent,
    memoryTotalBytes: sample?.memoryTotalBytes,
    memoryUsedBytes: sample?.memoryUsedBytes,
    sequence: sample?.sequence,
    uptimeSeconds: sample?.uptimeSeconds,
  }));
}

function portableMetricIdentities(samples: readonly unknown[]) {
  return samples
    .filter(isPortableMetricSample)
    .map((sample) => ({
      collectedAtMs: sample.collectedAtMs,
      sequence: sample.sequence,
    }))
    .sort(
      (left, right) =>
        left.sequence - right.sequence ||
        left.collectedAtMs - right.collectedAtMs,
    );
}

function metricsHistoryEvidence(
  samples: readonly unknown[],
  { retain = [] }: { retain?: readonly MetricHistoryAnchor[] } = {},
) {
  const ordered = samples
    .filter(isPortableMetricSample)
    .sort((left, right) => left.sequence - right.sequence)
    .map(compactMetricAnchor);
  const selected = [
    ordered[0],
    ordered[Math.floor((ordered.length - 1) / 2)],
    ordered.at(-1),
    ...retain.filter((anchor) =>
      ordered.some(
        (sample) => JSON.stringify(sample) === JSON.stringify(anchor),
      ),
    ),
  ].filter((anchor): anchor is MetricHistoryAnchor => Boolean(anchor));
  const anchors = [
    ...new Map(selected.map((anchor) => [anchor.sequence, anchor])).values(),
  ].sort((left, right) => left.sequence - right.sequence);
  return {
    anchors,
    sha256: createHash("sha256").update(JSON.stringify(anchors)).digest("hex"),
  };
}

function compactMetricAnchor(sample: PortableMetricSample) {
  return {
    collectedAtMs: sample.collectedAtMs,
    cpuPercent: sample.cpuPercent,
    memoryTotalBytes: sample.memoryTotalBytes,
    memoryUsedBytes: sample.memoryUsedBytes,
    sequence: sample.sequence,
    uptimeSeconds: sample.uptimeSeconds,
  };
}

function latestPortableMetric(samples: unknown): PortableMetricSample | null {
  if (!isUnknownArray(samples)) return null;
  return (
    samples
      .filter(isPortableMetricSample)
      .sort((left, right) => left.sequence - right.sequence)
      .at(-1) ?? null
  );
}

const releaseBaselineAuthorizationEvidencePath = Object.freeze([
  "releaseBaseline",
  "authority",
  "authorizationSha256",
]);

// 结案记录里的修复授权事实只含 epoch 绑定摘要、上游状态与 Operation ID；
// 授权签名与令牌从不写入，因此这些字段要按原样保留，供 summary 用共享判据重新判定。
const repairClosureAuthorizationEvidencePath = Object.freeze([
  "installedBundleFailureRepair",
  "closure",
  "capture",
  "repairAuthorization",
]);

export function redactReleaseE2EEvidence(
  value: unknown,
  {
    candidateManifest,
    secrets = [],
  }: { candidateManifest?: unknown; secrets?: readonly string[] } = {},
): unknown {
  assertCandidateManifest(candidateManifest);
  const baseline = candidateManifest.releaseBaseline;
  return redactSensitiveEvidence(value, secrets, [], {
    expectedReleaseBaselineAuthorizationSha256: isTrustEpochMigrationBaseline(
      baseline,
    )
      ? baseline.authorization.sha256
      : null,
  });
}

function isRepairClosureAuthorizationFacts(path: readonly string[]): boolean {
  return (
    path.length === repairClosureAuthorizationEvidencePath.length &&
    repairClosureAuthorizationEvidencePath.every(
      (segment, index) => segment === path[index],
    )
  );
}

function isValidatedReleaseBaselineAuthorizationSummary(
  path: readonly string[],
  value: unknown,
  expected: unknown,
): boolean {
  return (
    path.length === releaseBaselineAuthorizationEvidencePath.length &&
    path.every(
      (segment, index) =>
        segment === releaseBaselineAuthorizationEvidencePath[index],
    ) &&
    typeof expected === "string" &&
    /^[0-9a-f]{64}$/.test(expected) &&
    value === expected
  );
}

function redactSensitiveEvidence(
  value: unknown,
  secrets: readonly string[],
  path: readonly string[],
  context: { expectedReleaseBaselineAuthorizationSha256: unknown },
): unknown {
  const key = path.at(-1) ?? "";
  if (
    key &&
    !isRepairClosureAuthorizationFacts(path) &&
    !isValidatedReleaseBaselineAuthorizationSummary(
      path,
      value,
      context.expectedReleaseBaselineAuthorizationSha256,
    ) &&
    /(?:authorization|cookie|enrollment.?token|headers?|owner.?password|private.?key|signing.?secret|install.?command)/i.test(
      key,
    )
  ) {
    return "[REDACTED]";
  }
  if (typeof value === "string") {
    return redactSensitiveText(value, secrets);
  }
  if (Array.isArray(value)) {
    return value.map((item, index) =>
      redactSensitiveEvidence(item, secrets, [...path, String(index)], context),
    );
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, child]) => [
        childKey,
        redactSensitiveEvidence(child, secrets, [...path, childKey], context),
      ]),
    );
  }
  return value;
}

function redactSensitiveText(
  value: unknown,
  secrets: readonly string[],
): string {
  let redacted = String(value ?? "");
  for (const secret of secrets) {
    if (secret) redacted = redacted.replaceAll(secret, "[REDACTED]");
  }
  redacted = redacted.replace(
    /printf '%s\\n' 'enk_enroll_[A-Za-z0-9_-]+' \| python3 -- \.\/enoki-probe-bootstrap\.py --hub-origin 'https?:\/\/[^'\s]+'|curl -fsSL 'https?:\/\/[^'\s]+\/api\/probe\/install\.sh' \| sudo env ENOKI_HUB_URL='https?:\/\/[^'\s]+' ENOKI_ENROLLMENT_TOKEN='enk_enroll_[A-Za-z0-9_-]+' bash/g,
    "[REDACTED_INSTALLER_COMMAND]",
  );
  return redacted
    .replace(/enk_enroll_[A-Za-z0-9_-]+/g, "[REDACTED_ENROLLMENT_TOKEN]")
    .replace(
      /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z]+)? PRIVATE KEY-----/g,
      "[REDACTED_PRIVATE_KEY]",
    )
    .replace(
      /(authorization\s*[:=]\s*)(?:Bearer\s+)?[^\s,;]+/gi,
      "$1[REDACTED]",
    )
    .replace(/(cookie\s*[:=]\s*)[^\s,;]+/gi, "$1[REDACTED]")
    .replace(
      /(ENOKI_ENROLLMENT_TOKEN\s*=\s*)('[^']*'|"[^"]*"|[^\s]+)/g,
      "$1[REDACTED]",
    );
}

function cleanupDidNotSucceed(cleanup: ScenarioCleanupEvidence): boolean {
  return Object.values(cleanup).some((result) => {
    const view = objectView(result);
    return Boolean(view.error) || view.clean !== true;
  });
}
