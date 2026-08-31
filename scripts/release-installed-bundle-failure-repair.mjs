const observationRuntimeUnit = "enoki-observation-runtime.service";
const observationRuntimeRole = "observation_runtime";

export function createInstalledBundleFailureRepairHostDriver({
  assertOwnedRun,
  execute,
  ownershipToken,
}) {
  if (
    typeof assertOwnedRun !== "function" ||
    typeof execute !== "function" ||
    !/^[0-9a-f-]{36}$/.test(ownershipToken ?? "")
  ) {
    throw new Error("Installed Bundle Failure Repair Host driver is invalid");
  }
  let faultMayBeActive = false;

  return Object.freeze({
    async inspectCustody(runId) {
      assertOwnedRun(runId);
      const result = await execute(
        inspectObservationRuntimeCustodyScript(runId, ownershipToken),
        { root: true },
      );
      const state = result.stdout.trim();
      if (result.code !== 0 || (state !== "present" && state !== "absent")) {
        throw new Error(
          `Observation Runtime failure custody inspection failed: ${result.stderr || result.stdout}`,
        );
      }
      return { present: state === "present" };
    },

    async retireCustody(runId) {
      assertOwnedRun(runId);
      const result = await execute(
        retireObservationRuntimeCustodyScript(runId, ownershipToken),
        { root: true },
      );
      if (result.code !== 0 || result.stdout.trim() !== "retired") {
        throw new Error(
          `Observation Runtime failure custody retirement failed: ${result.stderr || result.stdout}`,
        );
      }
      return { retired: true };
    },

    async cleanup(runId) {
      assertOwnedRun(runId);
      const result = await execute(
        cleanupObservationRuntimeFailureScript(runId, ownershipToken),
        { root: true },
      );
      if (result.code !== 0 || result.stdout.trim() !== "cleaned") {
        const recovered = result.stdout.trim().match(/^recovered=(.+)$/);
        if (result.code !== 0 || !recovered) {
          throw new Error(
            `Observation Runtime failure cleanup failed: ${result.stderr || result.stdout}`,
          );
        }
        assertProbeVersion(recovered[1]);
        faultMayBeActive = false;
        return { clean: true, recoveredBundleVersion: recovered[1] };
      }
      faultMayBeActive = false;
      return { clean: true };
    },

    async repair(runId, expectedBundleVersion) {
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

export async function proveInstalledBundleFailureRepair({
  expectedBundleVersion,
  host,
  hostId,
  identityBefore,
  observeReadyHost,
  runId,
}) {
  if (
    !Number.isSafeInteger(hostId) ||
    hostId <= 0 ||
    typeof host?.repairInstalledBundleFailure !== "function" ||
    typeof host.assertInstalled !== "function" ||
    typeof host.readProbeIdentity !== "function" ||
    typeof observeReadyHost !== "function"
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
  const readyHost = await observeReadyHost();
  if (readyHost?.id !== hostId) {
    throw new Error("Installed Bundle Failure Repair changed the Hub Host");
  }
  return {
    failure,
    host: readyHost,
    hostBoundary,
    identity: { after: identityAfter, before: identityBefore },
    repair: {
      failureEpochRemoved: repair.failureEpochRemoved,
      faultRemoved: true,
      latchRemoved: repair.latchRemoved,
      output: repair.output,
      probeId: identityAfter.probeId,
      repairedVersion: expectedBundleVersion,
      runtimeSha256: repair.runtimeSha256,
      sameBundle: repair.sameBundle,
      unit: repair.unit,
    },
  };
}

function parseFailureEvidence(stdout, expectedBundleVersion) {
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
    values.result !== "start-limit-hit" ||
    values.bundleVersion !== expectedBundleVersion ||
    values.startLimitIntervalSec !== "60" ||
    startLimitBurst !== 3 ||
    !Number.isSafeInteger(restartCount) ||
    restartCount + 1 < startLimitBurst ||
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
    activeState: values.activeState,
    bundle: {
      installStateSha256: values.installStateSha256,
      manifestSha256: values.manifestSha256,
      runtimeFaultSha256: values.runtimeFaultSha256,
      runtimeSha256: values.runtimeSha256,
      version: values.bundleVersion,
    },
    failureEpoch: {
      bootId: values.bootId,
      generation: values.epochGeneration,
      hostId: values.hostId,
      identityReceiptSha256: values.identityReceiptSha256,
      links: 1,
      mode: "0600",
      ownerUid: 0,
      probeId: values.probeId,
    },
    latch: {
      generation: values.latchGeneration,
      links: 1,
      mode: "0600",
      ownerUid: 0,
    },
    recoveryBudget: {
      observedStarts: restartCount + 1,
      startLimitBurst,
      startLimitIntervalSeconds: 60,
    },
    result: values.result,
    role: values.role,
    status: "latched",
    unit: values.unit,
    unitSha256: values.unitSha256,
  };
}

function parseRepairEvidence(
  stdout,
  expectedBundleVersion,
  originalRuntimeSha256,
) {
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
    values.repairOutput !== "Probe repair completed." ||
    values.runtimeSha256 !== originalRuntimeSha256 ||
    values.epochExists !== "0" ||
    values.latchExists !== "0" ||
    values.faultBackupExists !== "1"
  ) {
    throw new Error("Installed Bundle Failure Repair evidence is invalid");
  }
  return {
    failureEpochRemoved: true,
    custodyRetained: true,
    latchRemoved: true,
    output: values.repairOutput,
    runtimeSha256: values.runtimeSha256,
    sameBundle: true,
    unit: values.unit,
  };
}

function exactKeyValues(stdout, expectedKeys) {
  const values = {};
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
  runId,
  ownershipToken,
  expectedBundleVersion,
) {
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
${systemdUnitStateFunctions()}
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
stop_unit enoki-probe.service
stop_unit enoki-observation-runtime.socket
stop_unit "$unit"
stop_unit enoki-observation-runtime-failure.service
require_stopped_unit enoki-probe.service
require_stopped_unit enoki-observation-runtime.socket
require_stopped_unit "$unit"
require_stopped_unit enoki-observation-runtime-failure.service
systemctl reset-failed "$unit" >/dev/null 2>&1 || fail 'could not reset Observation Runtime failure state'
systemctl reset-failed enoki-observation-runtime-failure.service >/dev/null 2>&1 || fail 'could not reset Runtime recorder failure state'
cp --preserve=mode,ownership -- "$temporary" "$runtime"
rm -- "$temporary"
trap - EXIT HUP INT TERM
runtime_fault_sha256=$(sha256sum "$runtime" | cut -d ' ' -f 1)
[ "$runtime_fault_sha256" != "$runtime_sha256" ] || fail 'Observation Runtime fault was not installed'
systemctl start "$unit" >/dev/null 2>&1 || true
active_state=
result=
remaining=50
while [ "$remaining" -gt 0 ]; do
  active_state=$(systemctl show "$unit" --property=ActiveState --value)
  result=$(systemctl show "$unit" --property=Result --value)
  if [ "$active_state" = failed ] && [ "$result" = start-limit-hit ]; then break; fi
  sleep 1
  remaining=$((remaining - 1))
done
[ "$active_state" = failed ] && [ "$result" = start-limit-hit ] || fail 'Observation Runtime did not exhaust its recovery budget'
remaining=20
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
[ "$epoch_unit" = "$unit" ] && [ "$epoch_result" = start-limit-hit ] || fail 'failure epoch does not bind terminal Runtime exhaustion'
[ "$epoch_bundle_version" = "$bundle_version" ] || fail 'failure epoch bundle binding changed'
[ "$epoch_unit_sha256" = "$(sha256sum "$unit_file" | cut -d ' ' -f 1)" ] || fail 'failure epoch unit binding changed'
restart_count=$(systemctl show "$unit" --property=NRestarts --value)
printf 'activeState=%s\nbootId=%s\nbundleVersion=%s\nepochGeneration=%s\nepochLinks=%s\nepochMode=%s\nepochOwner=%s\nhostId=%s\nidentityReceiptSha256=%s\ninstallStateSha256=%s\nlatchGeneration=%s\nlatchLinks=%s\nlatchMode=%s\nlatchOwner=%s\nmanifestSha256=%s\nprobeId=%s\nresult=%s\nrestartCount=%s\nrole=%s\nruntimeFaultSha256=%s\nruntimeSha256=%s\nstartLimitBurst=%s\nstartLimitIntervalSec=60\nunit=%s\nunitSha256=%s\n' \\
  "$active_state" "$epoch_boot_id" "$epoch_bundle_version" "$epoch_generation" "$(stat -c '%h' "$epoch")" "$(stat -c '%a' "$epoch")" "$(stat -c '%u' "$epoch")" "$epoch_host_id" "$epoch_identity_sha256" "$epoch_install_sha256" "$latch_generation" "$(stat -c '%h' "$latch")" "$(stat -c '%a' "$latch")" "$(stat -c '%u' "$latch")" "$epoch_manifest_sha256" "$epoch_probe_id" "$result" "$restart_count" ${shellSingleQuote(observationRuntimeRole)} "$runtime_fault_sha256" "$runtime_sha256" "$start_limit_burst" "$unit" "$epoch_unit_sha256"
`;
}

function repairObservationRuntimeFailureScript(
  runId,
  ownershipToken,
  expectedBundleVersion,
) {
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
[ "$repair_output" = 'Probe repair completed.' ]
[ ! -e "$epoch" ] && [ ! -e "$latch" ]
[ "$(sha256sum "$runtime" | cut -d ' ' -f 1)" = "$runtime_sha256" ]
version_output=$(/usr/local/bin/enoki-probe --version)
bundle_version=\${version_output#"enoki-probe "}
bundle_version=\${bundle_version#v}
[ "$bundle_version" = ${shellSingleQuote(expectedBundleVersion)} ]
printf 'bundleVersion=%s\nepochExists=0\nfaultBackupExists=1\nlatchExists=0\nrepairOutput=%s\nruntimeSha256=%s\nunit=%s\n' \\
  "$bundle_version" "$repair_output" "$runtime_sha256" "$unit"
`;
}

function cleanupObservationRuntimeFailureScript(runId, ownershipToken) {
  return `# enoki-release-e2e:cleanup-observation-runtime-failure
set -eu
claim=/var/lib/enoki-release-e2e/claim
runtime=/usr/local/bin/enoki-observation-runtime
backup="$claim/observation-runtime-original"
epoch=/var/lib/enoki-probe/runtime-failure/epoch.toml
latch=/var/lib/enoki-probe/runtime-failure/latch
companion=/usr/local/bin/enoki-probe-lifecycle-companion
unit=${shellSingleQuote(observationRuntimeUnit)}
fail() { printf '%s\n' "$1" >&2; exit 79; }
${systemdUnitStateFunctions()}
path_exists() { [ -e "$1" ] || [ -L "$1" ]; }
recovered_bundle_version=
[ -d "$claim" ]
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ]
[ "$(cat "$claim/token")" = ${shellSingleQuote(ownershipToken)} ]
if [ -f "$backup" ] && [ ! -L "$backup" ]; then
  [ "$(stat -c '%u:%a:%h' "$backup")" = 0:755:1 ] || fail 'run-owned Runtime backup boundary is invalid'
  backup_sha256=$(sha256sum "$backup" | cut -d ' ' -f 1) || fail 'could not read run-owned Runtime backup'
  stop_unit enoki-probe.service
  stop_unit enoki-observation-runtime.socket
  require_stopped_unit enoki-probe.service
  require_stopped_unit enoki-observation-runtime.socket
  if path_exists "$epoch" && ! path_exists "$latch"; then
    "$companion" record-runtime-failure || fail 'could not complete partial Runtime failure pair'
  fi
  stop_unit "$unit"
  stop_unit enoki-observation-runtime-failure.service
  require_stopped_unit "$unit"
  require_stopped_unit enoki-observation-runtime-failure.service
  cp --preserve=mode,ownership,timestamps -- "$backup" "$runtime"
  [ "$(stat -c '%u:%a:%h' "$runtime")" = 0:755:1 ] || fail 'restored Observation Runtime boundary is invalid'
  [ "$(sha256sum "$runtime" | cut -d ' ' -f 1)" = "$backup_sha256" ] || fail 'restored Observation Runtime digest changed'
  if path_exists "$epoch" || path_exists "$latch"; then
    "$companion" retry-runtime || fail 'could not consume Runtime failure pair'
  else
    systemctl reset-failed "$unit" >/dev/null 2>&1 || fail 'could not reset Observation Runtime failure state'
    systemctl reset-failed enoki-observation-runtime-failure.service >/dev/null 2>&1 || fail 'could not reset Runtime recorder failure state'
  fi
  systemctl start enoki-observation-runtime.socket >/dev/null 2>&1 || fail 'could not restart Observation Runtime socket'
  systemctl start enoki-probe.service >/dev/null 2>&1 || fail 'could not restart canonical Probe'
  wait_for_unit_state enoki-observation-runtime.socket active listening
  wait_for_unit_state enoki-probe.service active running
  wait_for_unit_state "$unit" active running
  require_stopped_unit enoki-observation-runtime-failure.service
  [ ! -e "$epoch" ] && [ ! -e "$latch" ] || fail 'Runtime failure state remained after recovery'
  [ "$(sha256sum "$runtime" | cut -d ' ' -f 1)" = "$backup_sha256" ] || fail 'recovered Observation Runtime digest changed'
  version_output=$(/usr/local/bin/enoki-probe --version) || fail 'could not read recovered Probe version'
  recovered_bundle_version=\${version_output#"enoki-probe "}
  recovered_bundle_version=\${recovered_bundle_version#v}
  printf '%s\n' "$recovered_bundle_version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || fail 'recovered Probe version is invalid'
elif path_exists "$backup"; then
  fail 'run-owned Runtime backup boundary is invalid'
elif path_exists "$epoch" || path_exists "$latch"; then
  printf 'failure state exists without the run-owned Runtime backup\n' >&2
  exit 79
fi
[ -f "$backup" ] || { [ ! -e "$epoch" ] && [ ! -e "$latch" ]; }
if [ -n "$recovered_bundle_version" ]; then
  printf 'recovered=%s\n' "$recovered_bundle_version"
else
  printf 'cleaned\n'
fi
`;
}

function inspectObservationRuntimeCustodyScript(runId, ownershipToken) {
  return runtimeCustodyScript({
    header: "inspect-runtime-failure-custody",
    ownershipToken,
    retire: false,
    runId,
  });
}

function retireObservationRuntimeCustodyScript(runId, ownershipToken) {
  return runtimeCustodyScript({
    header: "retire-runtime-failure-custody",
    ownershipToken,
    retire: true,
    runId,
  });
}

function runtimeCustodyScript({ header, ownershipToken, retire, runId }) {
  return `# enoki-release-e2e:${header}
set -eu
claim=/var/lib/enoki-release-e2e/claim
runtime=/usr/local/bin/enoki-observation-runtime
backup="$claim/observation-runtime-original"
fail() { printf '%s\n' "$1" >&2; exit 79; }
[ -d "$claim" ] || fail 'release E2E ownership claim is missing'
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ] || fail 'release E2E run claim changed'
[ "$(cat "$claim/token")" = ${shellSingleQuote(ownershipToken)} ] || fail 'release E2E ownership token changed'
if [ ! -e "$backup" ] && [ ! -L "$backup" ]; then
  printf '${retire ? "retired" : "absent"}\n'
  exit 0
fi
[ -f "$backup" ] && [ ! -L "$backup" ] || fail 'run-owned Runtime backup boundary is invalid'
[ "$(stat -c '%u:%a:%h' "$backup")" = 0:755:1 ] || fail 'run-owned Runtime backup ownership is invalid'
[ -f "$runtime" ] && [ ! -L "$runtime" ] || fail 'Observation Runtime binary boundary is invalid'
[ "$(stat -c '%u:%a:%h' "$runtime")" = 0:755:1 ] || fail 'Observation Runtime binary ownership is invalid'
[ "$(sha256sum "$runtime" | cut -d ' ' -f 1)" = "$(sha256sum "$backup" | cut -d ' ' -f 1)" ] || fail 'Observation Runtime differs from run-owned custody'
${retire ? "rm -- \"$backup\"\nprintf 'retired\\n'" : "printf 'present\\n'"}
`;
}

function systemdUnitStateFunctions() {
  return `read_unit_state() {
  target=$1
  properties=$(systemctl show "$target" --no-pager --property=LoadState --property=ActiveState --property=SubState) || return 1
  property_count=$(printf '%s\n' "$properties" | awk 'NF { count += 1 } END { print count + 0 }') || return 1
  load_count=$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" { count += 1 } END { print count + 0 }') || return 1
  active_count=$(printf '%s\n' "$properties" | awk -F= '$1 == "ActiveState" { count += 1 } END { print count + 0 }') || return 1
  sub_count=$(printf '%s\n' "$properties" | awk -F= '$1 == "SubState" { count += 1 } END { print count + 0 }') || return 1
  [ "$property_count" -eq 3 ] && [ "$load_count" -eq 1 ] && [ "$active_count" -eq 1 ] && [ "$sub_count" -eq 1 ] || return 1
  load_state=$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" { print substr($0, index($0, "=") + 1) }') || return 1
  active_state=$(printf '%s\n' "$properties" | awk -F= '$1 == "ActiveState" { print substr($0, index($0, "=") + 1) }') || return 1
  sub_state=$(printf '%s\n' "$properties" | awk -F= '$1 == "SubState" { print substr($0, index($0, "=") + 1) }') || return 1
  printf '%s %s %s\n' "$load_state" "$active_state" "$sub_state"
}
stop_unit() {
  systemctl stop "$1" >/dev/null 2>&1 || fail "could not stop $1"
}
require_stopped_unit() {
  expected_target=$1
  observed_state=$(read_unit_state "$expected_target") || fail "could not query $expected_target state"
  [ "$observed_state" = 'loaded inactive dead' ] || fail "$expected_target did not reach loaded/inactive/dead"
}
wait_for_unit_state() {
  expected_target=$1
  expected_active=$2
  expected_sub=$3
  state_remaining=20
  while [ "$state_remaining" -gt 0 ]; do
    observed_state=$(read_unit_state "$expected_target") || fail "could not query $expected_target state"
    [ "$observed_state" = "loaded $expected_active $expected_sub" ] && return 0
    sleep 1
    state_remaining=$((state_remaining - 1))
  done
  fail "$expected_target did not reach loaded/$expected_active/$expected_sub"
}`;
}

function assertProbeVersion(version) {
  if (!/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(version ?? "")) {
    throw new Error("Installed Bundle Failure Repair version is invalid");
  }
}

function isSha256(value) {
  return /^[0-9a-f]{64}$/.test(value ?? "");
}

function validIdentifier(value) {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(value ?? "");
}

function shellSingleQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}
