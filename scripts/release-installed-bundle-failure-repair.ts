// 已安装包故障修复的 Host driver 与本机直接证明：在受支持主机上耗尽 Observation
// Runtime 恢复预算、读取 durable epoch/latch，再调用正式 CLI 完成本机修复。结案
// 所需的本机事实、报告事实与 Hub 读数在这里分开采集，是否结案只由共享判据决定。

import { objectView, regexInput, stringValue } from "./release-json-guards.ts";
import type {
  HubHostProfileReading,
  HubRepairOperationReading,
  RepairClosureCapture,
  RepairClosureExpectation,
} from "./release-repair-closure-evidence.ts";
import {
  judgeInstalledBundleRepairClosure,
  probeRepairLocalCompletionOutput,
} from "./release-repair-closure-evidence.ts";

export type CommandResult = {
  code: number;
  stderr: string;
  stdout: string;
};

export type CommandOptions = {
  root?: boolean;
  sensitive?: boolean;
};

export type CommandExecutor = (
  script: string,
  options?: CommandOptions,
) => Promise<CommandResult>;

export type OwnedRunAssertion = (runId: string) => void;

export type FailureEvidence = {
  activeState: string;
  bundle: {
    installStateSha256: string;
    manifestSha256: string;
    runtimeFaultSha256: string;
    runtimeSha256: string;
    version: string;
  };
  epochResult: string;
  failureEpoch: {
    bootId: string;
    generation: string;
    hostId: string;
    identityReceiptSha256: string;
    links: number;
    mode: string;
    ownerUid: number;
    probeId: string;
  };
  latch: {
    generation: string;
    links: number;
    mode: string;
    ownerUid: number;
  };
  recoveryBudget: {
    observedStarts: number;
    startLimitBurst: number;
    startLimitIntervalSeconds: number;
  };
  result: string;
  role: string;
  status: string;
  unit: string;
  unitSha256: string;
};

export type RepairEvidence = {
  failureEpochRemoved: boolean;
  faultRemoved: boolean;
  latchRemoved: boolean;
  output: string;
  runtimeSha256: string;
  sameBundle: boolean;
  unit: string;
};

export type ProbeIdentityEvidence = {
  identitySha256: string;
  probeId: string;
};

export type InstalledBundleFailureRepair = {
  failure: FailureEvidence;
  repair: RepairEvidence;
};

export type InstalledBundleFailureRepairDriver = {
  cleanup(runId: string): Promise<{ clean: true }>;
  repair(
    runId: string,
    expectedBundleVersion: string,
  ): Promise<InstalledBundleFailureRepair>;
};

const observationRuntimeUnit = "enoki-observation-runtime.service";
const observationRuntimeRole = "observation_runtime";

// 07 已接受合同：受支持主机上 Runtime 预算耗尽的真实终态 Result 由 durable epoch
// 绑定；`start-limit-hit` 在受支持主机从未出现，不构成耗尽资格。
const exhaustedRuntimeResults: readonly string[] = Object.freeze([
  "exit-code",
  "signal",
  "core-dump",
  "watchdog",
  "timeout",
  "protocol",
  "resources",
  "oom-kill",
]);

export function isExhaustedRuntimeResult(value: unknown): boolean {
  return typeof value === "string" && exhaustedRuntimeResults.includes(value);
}

export function createInstalledBundleFailureRepairHostDriver({
  assertOwnedRun,
  execute,
  ownershipToken,
}: {
  assertOwnedRun: OwnedRunAssertion;
  execute: CommandExecutor;
  ownershipToken: string;
}): InstalledBundleFailureRepairDriver {
  if (
    typeof assertOwnedRun !== "function" ||
    typeof execute !== "function" ||
    !/^[0-9a-f-]{36}$/.test(ownershipToken ?? "")
  ) {
    throw new Error("Installed Bundle Failure Repair Host driver is invalid");
  }
  let faultMayBeActive = false;

  return Object.freeze({
    async cleanup(runId: string): Promise<{ clean: true }> {
      assertOwnedRun(runId);
      const result = await execute(
        cleanupObservationRuntimeFailureScript(runId, ownershipToken),
        { root: true },
      );
      if (result.code !== 0 || result.stdout.trim() !== "cleaned") {
        throw new Error(
          `Observation Runtime failure cleanup failed: ${result.stderr || result.stdout}`,
        );
      }
      faultMayBeActive = false;
      return { clean: true };
    },

    async repair(
      runId: string,
      expectedBundleVersion: string,
    ): Promise<InstalledBundleFailureRepair> {
      assertOwnedRun(runId);
      assertProbeVersion(expectedBundleVersion);
      if (faultMayBeActive) {
        throw new Error("Observation Runtime failure is already active");
      }
      faultMayBeActive = true;
      const exhausted = await execute(
        exhaustObservationRuntimeBudgetScript(
          runId,
          ownershipToken,
          expectedBundleVersion,
        ),
        { root: true },
      );
      if (exhausted.code !== 0) {
        throw new Error(
          `Installed Bundle Failure lacks durable Observation Runtime failure eligibility: ${exhausted.stderr || exhausted.stdout}`,
        );
      }
      const failure = parseFailureEvidence(
        exhausted.stdout,
        expectedBundleVersion,
      );
      const repaired = await execute(
        repairObservationRuntimeFailureScript(
          runId,
          ownershipToken,
          expectedBundleVersion,
        ),
        { root: true },
      );
      if (repaired.code !== 0) {
        throw new Error(
          `Installed Bundle Failure Repair failed (${repaired.code}): ${repaired.stderr || repaired.stdout}`,
        );
      }
      const repair = parseRepairEvidence(
        repaired.stdout,
        expectedBundleVersion,
        failure.bundle.runtimeSha256,
      );
      faultMayBeActive = false;
      return { failure, repair };
    },
  });
}

export type InstalledBundleFailureRepairHost = {
  assertInstalled(
    runId: string,
    expectedProbeVersion: string,
  ): Promise<unknown>;
  readProbeIdentity(runId: string): Promise<ProbeIdentityEvidence>;
  repairInstalledBundleFailure(
    runId: string,
    expectedBundleVersion: string,
  ): Promise<InstalledBundleFailureRepair>;
};

export async function proveInstalledBundleFailureRepair({
  expectedBundleVersion,
  host,
  hostId,
  identityBefore,
  readClosureCapture,
  readHubHostProfile,
  readHubRepairOperation,
  runId,
}: {
  expectedBundleVersion: string;
  host: InstalledBundleFailureRepairHost;
  hostId: number;
  identityBefore: ProbeIdentityEvidence | null;
  readClosureCapture: () => Promise<RepairClosureCapture | null>;
  readHubHostProfile: () => Promise<HubHostProfileReading | null>;
  readHubRepairOperation: (
    operationId: string,
  ) => Promise<HubRepairOperationReading | null>;
  runId: string;
}) {
  if (
    !Number.isSafeInteger(hostId) ||
    hostId <= 0 ||
    typeof host?.repairInstalledBundleFailure !== "function" ||
    typeof host.assertInstalled !== "function" ||
    typeof host.readProbeIdentity !== "function" ||
    typeof readClosureCapture !== "function" ||
    typeof readHubHostProfile !== "function" ||
    typeof readHubRepairOperation !== "function"
  ) {
    throw new Error(
      "Installed Bundle Failure Repair capability port is invalid",
    );
  }
  const { failure, repair } = await host.repairInstalledBundleFailure(
    runId,
    expectedBundleVersion,
  );
  if (
    failure?.failureEpoch?.hostId !== String(hostId) ||
    failure.failureEpoch.probeId !== identityBefore?.probeId
  ) {
    throw new Error(
      "Installed Bundle Failure epoch changed the Host or Probe Identity binding",
    );
  }
  const hostBoundary = await host.assertInstalled(runId, expectedBundleVersion);
  const identityAfter = await host.readProbeIdentity(runId);
  if (
    identityAfter?.probeId !== identityBefore?.probeId ||
    identityAfter?.identitySha256 !== identityBefore?.identitySha256
  ) {
    throw new Error(
      "Installed Bundle Failure Repair changed the Probe Identity",
    );
  }
  // 本机 CLI 只证明本机恢复与最终普通 Probe 已启动；目标版本与身份保持分别取自
  // 修复后的已安装包边界与身份读数，Hub 结案事实由协调参与者的普通读数独立采集。
  const localCompletion = {
    completedAtMs: Date.now(),
    identitySha256: identityAfter.identitySha256,
    output: repair.output,
    probeId: identityAfter.probeId,
    repairedVersion: stringValue(objectView(hostBoundary).probeVersion),
  };
  const capture = await readClosureCapture();
  const operationId = capture?.repairAuthorization?.operationId ?? "";
  const hubOperation = /^[1-9]\d*$/.test(operationId)
    ? await readHubRepairOperation(operationId)
    : null;
  const hubHostProfile = await readHubHostProfile();
  const expectation: RepairClosureExpectation = {
    failureEpochBootId: failure.failureEpoch.bootId,
    failureEpochGeneration: failure.failureEpoch.generation,
    hostId,
    identitySha256: identityAfter.identitySha256,
    probeId: identityAfter.probeId,
    targetProbeVersion: expectedBundleVersion,
  };
  const judgment = judgeInstalledBundleRepairClosure({
    capture,
    expectation,
    hubHostProfile,
    hubOperation,
    localCompletion,
  });
  if (!judgment.accepted) {
    throw new Error(
      `Installed Bundle Failure Repair is not closed by the collected report facts and the Hub Repair Operation: ${judgment.reasons.join(",")}`,
    );
  }
  return {
    closure: {
      capture,
      expectation,
      hubHostProfile,
      hubOperation,
      localCompletion,
    },
    failure,
    hostBoundary,
    identity: { after: identityAfter, before: identityBefore },
    repair,
  };
}

function parseFailureEvidence(
  stdout: string,
  expectedBundleVersion: string,
): FailureEvidence {
  let values;
  try {
    values = exactKeyValues(stdout, [
      "activeState",
      "bootId",
      "bundleVersion",
      "epochGeneration",
      "epochLinks",
      "epochMode",
      "epochOwner",
      "epochResult",
      "hostId",
      "identityReceiptSha256",
      "installStateSha256",
      "latchGeneration",
      "latchLinks",
      "latchMode",
      "latchOwner",
      "manifestSha256",
      "probeId",
      "result",
      "restartCount",
      "role",
      "runtimeFaultSha256",
      "runtimeSha256",
      "startLimitBurst",
      "startLimitIntervalSec",
      "unit",
      "unitSha256",
    ]);
  } catch (error) {
    throw new Error(
      "Installed Bundle Failure lacks durable Observation Runtime failure eligibility",
      { cause: error },
    );
  }
  const restartCount = Number(values.restartCount);
  const startLimitBurst = Number(values.startLimitBurst);
  if (
    values.role !== observationRuntimeRole ||
    values.unit !== observationRuntimeUnit ||
    values.activeState !== "failed" ||
    !isExhaustedRuntimeResult(values.result) ||
    values.epochResult !== values.result ||
    values.bundleVersion !== expectedBundleVersion ||
    values.startLimitIntervalSec !== "60" ||
    startLimitBurst !== 3 ||
    !Number.isSafeInteger(restartCount) ||
    restartCount !== startLimitBurst ||
    values.epochGeneration !== values.latchGeneration ||
    values.epochOwner !== "0" ||
    values.epochMode !== "600" ||
    values.epochLinks !== "1" ||
    values.latchOwner !== "0" ||
    values.latchMode !== "600" ||
    values.latchLinks !== "1" ||
    values.runtimeSha256 === values.runtimeFaultSha256 ||
    !/^[1-9]\d*$/.test(values.hostId ?? "") ||
    !validIdentifier(values.probeId) ||
    !validIdentifier(values.bootId) ||
    ![
      values.epochGeneration,
      values.identityReceiptSha256,
      values.installStateSha256,
      values.manifestSha256,
      values.runtimeFaultSha256,
      values.runtimeSha256,
      values.unitSha256,
    ].every(isSha256)
  ) {
    throw new Error(
      "Installed Bundle Failure lacks durable Observation Runtime failure eligibility",
    );
  }
  return {
    activeState: stringValue(values.activeState),
    bundle: {
      installStateSha256: stringValue(values.installStateSha256),
      manifestSha256: stringValue(values.manifestSha256),
      runtimeFaultSha256: stringValue(values.runtimeFaultSha256),
      runtimeSha256: stringValue(values.runtimeSha256),
      version: values.bundleVersion,
    },
    failureEpoch: {
      bootId: stringValue(values.bootId),
      generation: stringValue(values.epochGeneration),
      hostId: stringValue(values.hostId),
      identityReceiptSha256: stringValue(values.identityReceiptSha256),
      links: 1,
      mode: "0600",
      ownerUid: 0,
      probeId: stringValue(values.probeId),
    },
    latch: {
      generation: stringValue(values.latchGeneration),
      links: 1,
      mode: "0600",
      ownerUid: 0,
    },
    recoveryBudget: {
      observedStarts: restartCount,
      startLimitBurst,
      startLimitIntervalSeconds: 60,
    },
    result: stringValue(values.result),
    epochResult: stringValue(values.epochResult),
    role: values.role,
    status: "latched",
    unit: values.unit,
    unitSha256: stringValue(values.unitSha256),
  };
}

function parseRepairEvidence(
  stdout: string,
  expectedBundleVersion: string,
  originalRuntimeSha256: string,
): RepairEvidence {
  let values;
  try {
    values = exactKeyValues(stdout, [
      "bundleVersion",
      "epochExists",
      "faultBackupExists",
      "latchExists",
      "repairOutput",
      "runtimeSha256",
      "unit",
    ]);
  } catch (error) {
    throw new Error("Installed Bundle Failure Repair evidence is invalid", {
      cause: error,
    });
  }
  if (
    values.bundleVersion !== expectedBundleVersion ||
    values.unit !== observationRuntimeUnit ||
    values.repairOutput !== probeRepairLocalCompletionOutput ||
    values.runtimeSha256 !== originalRuntimeSha256 ||
    values.epochExists !== "0" ||
    values.latchExists !== "0" ||
    values.faultBackupExists !== "0"
  ) {
    throw new Error("Installed Bundle Failure Repair evidence is invalid");
  }
  return {
    failureEpochRemoved: true,
    faultRemoved: true,
    latchRemoved: true,
    output: stringValue(values.repairOutput),
    runtimeSha256: stringValue(values.runtimeSha256),
    sameBundle: true,
    unit: stringValue(values.unit),
  };
}

function exactKeyValues(
  stdout: string,
  expectedKeys: readonly string[],
): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of stdout.split("\n")) {
    if (!line) continue;
    const separator = line.indexOf("=");
    if (separator < 1) throw new Error("evidence line is malformed");
    const key = line.slice(0, separator);
    if (Object.hasOwn(values, key))
      throw new Error("evidence key is duplicated");
    values[key] = line.slice(separator + 1);
  }
  if (
    JSON.stringify(Object.keys(values).sort()) !==
    JSON.stringify([...expectedKeys].sort())
  ) {
    throw new Error("evidence keys are incomplete");
  }
  return values;
}

function exhaustObservationRuntimeBudgetScript(
  runId: string,
  ownershipToken: string,
  expectedBundleVersion: string,
): string {
  return `# enoki-release-e2e:exhaust-observation-runtime-budget
set -eu
claim=/var/lib/enoki-release-e2e/claim
runtime=/usr/local/bin/enoki-observation-runtime
backup="$claim/observation-runtime-original"
unit_file=/etc/systemd/system/enoki-observation-runtime.service
epoch=/var/lib/enoki-probe/runtime-failure/epoch.toml
latch=/var/lib/enoki-probe/runtime-failure/latch
unit=${shellSingleQuote(observationRuntimeUnit)}
fail() { printf '%s\n' "$1" >&2; exit 79; }
[ -d "$claim" ] || fail 'release E2E ownership claim is missing'
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ] || fail 'release E2E run claim changed'
[ "$(cat "$claim/token")" = ${shellSingleQuote(ownershipToken)} ] || fail 'release E2E ownership token changed'
[ -f "$runtime" ] && [ ! -L "$runtime" ] || fail 'Observation Runtime binary boundary is invalid'
[ "$(stat -c '%u:%a:%h' "$runtime")" = 0:755:1 ] || fail 'Observation Runtime binary ownership is invalid'
[ -f "$unit_file" ] && [ ! -L "$unit_file" ] || fail 'Observation Runtime unit boundary is invalid'
[ "$(stat -c '%u:%a:%h' "$unit_file")" = 0:644:1 ] || fail 'Observation Runtime unit ownership is invalid'
[ "$(systemctl show "$unit" --property=FragmentPath --value)" = "$unit_file" ] || fail 'Observation Runtime unit path is not canonical'
[ ! -e "$backup" ] && [ ! -e "$epoch" ] && [ ! -e "$latch" ] || fail 'Observation Runtime failure state is not fresh'
[ -z "$(systemctl show "$unit" --property=DropInPaths --value)" ] || fail 'Observation Runtime has an unexpected drop-in'
version_output=$(/usr/local/bin/enoki-probe --version)
bundle_version=\${version_output#"enoki-probe "}
bundle_version=\${bundle_version#v}
[ "$bundle_version" = ${shellSingleQuote(expectedBundleVersion)} ] || fail 'installed bundle version changed'
start_limit_burst=$(sed -n 's/^StartLimitBurst=//p' "$unit_file")
start_limit_interval=$(sed -n 's/^StartLimitIntervalSec=//p' "$unit_file")
[ "$start_limit_burst" = 3 ] && [ "$start_limit_interval" = 60s ] || fail 'Observation Runtime recovery budget is not build-fixed'
cp --preserve=mode,ownership,timestamps -- "$runtime" "$backup"
runtime_sha256=$(sha256sum "$backup" | cut -d ' ' -f 1)
temporary=$(mktemp /usr/local/bin/.enoki-observation-runtime.release-e2e.XXXXXX)
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
printf '#!/bin/sh\nexit 70\n' > "$temporary"
chown 0:0 "$temporary"
chmod 0755 "$temporary"
systemctl stop enoki-observation-runtime.socket "$unit" enoki-observation-runtime-failure.service >/dev/null 2>&1 || true
systemctl reset-failed "$unit" enoki-observation-runtime-failure.service
mv -- "$temporary" "$runtime"
trap - EXIT HUP INT TERM
runtime_fault_sha256=$(sha256sum "$runtime" | cut -d ' ' -f 1)
[ "$runtime_fault_sha256" != "$runtime_sha256" ] || fail 'Observation Runtime fault was not installed'
systemctl start "$unit" >/dev/null 2>&1 || true
remaining=60
while [ "$remaining" -gt 0 ] && { [ ! -f "$epoch" ] || [ ! -f "$latch" ]; }; do
  sleep 1
  remaining=$((remaining - 1))
done
[ -f "$epoch" ] && [ ! -L "$epoch" ] && [ -f "$latch" ] && [ ! -L "$latch" ] || fail 'root-owned failure epoch and latch were not persisted'
epoch_value() { sed -n "s/^$1 = \\"\\([^\\"]*\\)\\"$/\\1/p" "$epoch"; }
epoch_number() { sed -n "s/^$1 = \\([0-9][0-9]*\\)$/\\1/p" "$epoch"; }
[ "$(epoch_number schema_version)" = 1 ] || fail 'failure epoch schema is invalid'
epoch_generation=$(epoch_value generation)
epoch_boot_id=$(epoch_value boot_id)
epoch_unit=$(epoch_value unit)
epoch_unit_sha256=$(epoch_value unit_sha256)
epoch_host_id=$(epoch_value host_id)
epoch_probe_id=$(epoch_value probe_id)
epoch_identity_sha256=$(epoch_value identity_receipt_sha256)
epoch_install_sha256=$(epoch_value install_state_sha256)
epoch_manifest_sha256=$(epoch_value manifest_sha256)
epoch_bundle_version=$(epoch_value bundle_version)
epoch_result=$(epoch_value result)
latch_generation=$(cat "$latch")
[ "$epoch_generation" = "$latch_generation" ] || fail 'failure latch does not bind the epoch'
[ "$epoch_unit" = "$unit" ] || fail 'failure epoch does not bind the Observation Runtime unit'
case "$epoch_result" in
  exit-code|signal|core-dump|watchdog|timeout|protocol|resources|oom-kill) ;;
  *) fail 'failure epoch does not bind a real terminal Runtime Result' ;;
esac
active_state=$(systemctl show "$unit" --property=ActiveState --value)
live_result=$(systemctl show "$unit" --property=Result --value)
[ "$active_state" = failed ] || fail 'Observation Runtime is not in the durable failed state'
[ "$live_result" = "$epoch_result" ] || fail 'live Runtime Result diverged from the durable failure epoch'
[ "$epoch_bundle_version" = "$bundle_version" ] || fail 'failure epoch bundle binding changed'
[ "$epoch_unit_sha256" = "$(sha256sum "$unit_file" | cut -d ' ' -f 1)" ] || fail 'failure epoch unit binding changed'
restart_count=$(systemctl show "$unit" --property=NRestarts --value)
[ "$restart_count" = "$start_limit_burst" ] || fail 'Observation Runtime did not exhaust its recovery budget'
printf 'activeState=%s\nbootId=%s\nbundleVersion=%s\nepochGeneration=%s\nepochLinks=%s\nepochMode=%s\nepochOwner=%s\nepochResult=%s\nhostId=%s\nidentityReceiptSha256=%s\ninstallStateSha256=%s\nlatchGeneration=%s\nlatchLinks=%s\nlatchMode=%s\nlatchOwner=%s\nmanifestSha256=%s\nprobeId=%s\nresult=%s\nrestartCount=%s\nrole=%s\nruntimeFaultSha256=%s\nruntimeSha256=%s\nstartLimitBurst=%s\nstartLimitIntervalSec=60\nunit=%s\nunitSha256=%s\n' \\
  "$active_state" "$epoch_boot_id" "$epoch_bundle_version" "$epoch_generation" "$(stat -c '%h' "$epoch")" "$(stat -c '%a' "$epoch")" "$(stat -c '%u' "$epoch")" "$epoch_result" "$epoch_host_id" "$epoch_identity_sha256" "$epoch_install_sha256" "$latch_generation" "$(stat -c '%h' "$latch")" "$(stat -c '%a' "$latch")" "$(stat -c '%u' "$latch")" "$epoch_manifest_sha256" "$epoch_probe_id" "$live_result" "$restart_count" ${shellSingleQuote(observationRuntimeRole)} "$runtime_fault_sha256" "$runtime_sha256" "$start_limit_burst" "$unit" "$epoch_unit_sha256"
`;
}

function repairObservationRuntimeFailureScript(
  runId: string,
  ownershipToken: string,
  expectedBundleVersion: string,
): string {
  return `# enoki-release-e2e:repair-observation-runtime-failure
set -eu
claim=/var/lib/enoki-release-e2e/claim
runtime=/usr/local/bin/enoki-observation-runtime
backup="$claim/observation-runtime-original"
epoch=/var/lib/enoki-probe/runtime-failure/epoch.toml
latch=/var/lib/enoki-probe/runtime-failure/latch
unit=${shellSingleQuote(observationRuntimeUnit)}
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(ownershipToken)} ]
[ -f "$backup" ] && [ -f "$epoch" ] && [ -f "$latch" ]
runtime_sha256=$(sha256sum "$backup" | cut -d ' ' -f 1)
repair_output=$(/usr/local/bin/enoki-probe repair)
[ "$repair_output" = ${shellSingleQuote(probeRepairLocalCompletionOutput)} ]
[ ! -e "$epoch" ] && [ ! -e "$latch" ]
[ "$(sha256sum "$runtime" | cut -d ' ' -f 1)" = "$runtime_sha256" ]
rm -- "$backup"
version_output=$(/usr/local/bin/enoki-probe --version)
bundle_version=\${version_output#"enoki-probe "}
bundle_version=\${bundle_version#v}
[ "$bundle_version" = ${shellSingleQuote(expectedBundleVersion)} ]
printf 'bundleVersion=%s\nepochExists=0\nfaultBackupExists=0\nlatchExists=0\nrepairOutput=%s\nruntimeSha256=%s\nunit=%s\n' \\
  "$bundle_version" "$repair_output" "$runtime_sha256" "$unit"
`;
}

function cleanupObservationRuntimeFailureScript(
  runId: string,
  ownershipToken: string,
): string {
  return `# enoki-release-e2e:cleanup-observation-runtime-failure
set -eu
claim=/var/lib/enoki-release-e2e/claim
runtime=/usr/local/bin/enoki-observation-runtime
backup="$claim/observation-runtime-original"
epoch=/var/lib/enoki-probe/runtime-failure/epoch.toml
latch=/var/lib/enoki-probe/runtime-failure/latch
unit=${shellSingleQuote(observationRuntimeUnit)}
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(ownershipToken)} ]
if [ -f "$backup" ] && [ ! -L "$backup" ]; then
  systemctl stop enoki-observation-runtime.socket "$unit" >/dev/null 2>&1 || true
  mv -- "$backup" "$runtime"
  if [ -f "$epoch" ] || [ -f "$latch" ]; then
    [ -f "$epoch" ] && [ -f "$latch" ]
    /usr/local/bin/enoki-probe-lifecycle-companion retry-runtime
  else
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  fi
  systemctl start enoki-observation-runtime.socket
elif [ -e "$epoch" ] || [ -e "$latch" ]; then
  printf 'failure state exists without the run-owned Runtime backup\n' >&2
  exit 79
fi
[ ! -e "$backup" ] && [ ! -e "$epoch" ] && [ ! -e "$latch" ]
printf 'cleaned\n'
`;
}

function assertProbeVersion(version: string): void {
  if (!/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(version ?? "")) {
    throw new Error("Installed Bundle Failure Repair version is invalid");
  }
}

function isSha256(value: unknown): boolean {
  return /^[0-9a-f]{64}$/.test(regexInput(value));
}

function validIdentifier(value: unknown): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(regexInput(value));
}

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}
