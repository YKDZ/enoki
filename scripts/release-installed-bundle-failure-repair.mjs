const observationRuntimeUnit = "enoki-observation-runtime.service";

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
          throw commandResultFailure(
            `Observation Runtime failure cleanup failed: ${result.stderr || result.stdout}`,
            "cleanup",
            result,
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
        throw commandResultFailure(
          `Installed Bundle Failure lacks durable Observation Runtime failure eligibility: ${exhausted.stderr || exhausted.stdout}`,
          "exhaust",
          exhausted,
        );
      }
      if (exhausted.stdout.trim() !== "recorded") {
        throw new Error(
          "Installed Bundle Failure recorder did not publish the product failure pair",
        );
      }
      const repaired = await execute(
        repairObservationRuntimeFailureScript(
          runId,
          ownershipToken,
          expectedBundleVersion,
        ),
        { root: true },
      );
      if (repaired.code !== 0) {
        throw commandResultFailure(
          `Installed Bundle Failure Repair failed (${repaired.code}): ${repaired.stderr || repaired.stdout}`,
          "repair",
          repaired,
        );
      }
      let repair;
      try {
        repair = parseRepairEvidence(repaired.stdout, expectedBundleVersion);
      } catch (error) {
        error.failureDetail = boundedCommandResult("repair", repaired);
        throw error;
      }
      faultMayBeActive = false;
      return {
        failure: { status: "recorded" },
        repair,
        repairCommand: repaired,
      };
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
      faultRemoved: true,
      output: repair.output,
      probeId: identityAfter.probeId,
      repairedVersion: expectedBundleVersion,
      runtimeSha256: repair.runtimeSha256,
      sameBundle: repair.sameBundle,
      unit: repair.unit,
    },
  };
}

function parseRepairEvidence(stdout, expectedBundleVersion) {
  let values;
  try {
    values = exactKeyValues(stdout, [
      "bundleVersion",
      "faultBackupExists",
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
    values.repairOutput !==
      "本机恢复与最终探针启动已完成；修复最终结果以 Hub 为准" ||
    values.faultBackupExists !== "1"
  ) {
    throw new Error("Installed Bundle Failure Repair evidence is invalid");
  }
  return {
    custodyRetained: true,
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
backup_tmp="$claim/observation-runtime-original.next"
restore_tmp=/usr/local/bin/.enoki-observation-runtime.release-e2e.restore
unit_file=/etc/systemd/system/enoki-observation-runtime.service
epoch=/var/lib/enoki-probe/runtime-failure/epoch.toml
latch=/var/lib/enoki-probe/runtime-failure/latch
unit=${shellSingleQuote(observationRuntimeUnit)}
${runtimeClaimLockPrelude()}
fail() { printf '%s\n' "$1" >&2; exit 79; }
${systemdUnitStateFunctions()}
${runtimeClaimPreflight(runId, ownershipToken)}
[ -f "$runtime" ] && [ ! -L "$runtime" ] || fail 'Observation Runtime binary boundary is invalid'
[ "$(stat -c '%u:%a:%h' "$runtime")" = 0:755:1 ] || fail 'Observation Runtime binary ownership is invalid'
[ -f "$unit_file" ] && [ ! -L "$unit_file" ] || fail 'Observation Runtime unit boundary is invalid'
[ "$(stat -c '%u:%a:%h' "$unit_file")" = 0:644:1 ] || fail 'Observation Runtime unit ownership is invalid'
[ "$(systemctl show "$unit" --property=FragmentPath --value)" = "$unit_file" ] || fail 'Observation Runtime unit path is not canonical'
[ ! -e "$backup" ] && [ ! -L "$backup" ] && [ ! -e "$backup_tmp" ] && [ ! -L "$backup_tmp" ] && [ ! -e "$epoch" ] && [ ! -e "$latch" ] || fail 'Observation Runtime failure state is not fresh'
[ -z "$(systemctl show "$unit" --property=DropInPaths --value)" ] || fail 'Observation Runtime has an unexpected drop-in'
version_output=$(/usr/local/bin/enoki-probe --version)
bundle_version=\${version_output#"enoki-probe "}
bundle_version=\${bundle_version#v}
[ "$bundle_version" = ${shellSingleQuote(expectedBundleVersion)} ] || fail 'installed bundle version changed'
runtime_sha256=$(sha256sum "$runtime" | cut -d ' ' -f 1)
cp --preserve=mode,ownership,timestamps -- "$runtime" "$backup_tmp"
[ "$(stat -c '%u:%a:%h' "$backup_tmp")" = 0:755:1 ] || fail 'Runtime backup temporary boundary is invalid'
[ "$(sha256sum "$backup_tmp" | cut -d ' ' -f 1)" = "$runtime_sha256" ] || fail 'Runtime backup temporary digest changed'
sync -f "$backup_tmp" || fail 'could not persist Runtime backup temporary'
mv -- "$backup_tmp" "$backup"
sync -f "$claim" || fail 'could not persist Runtime backup publication'
[ "$(stat -c '%u:%a:%h' "$backup")" = 0:755:1 ] || fail 'Runtime backup custody is invalid'
[ "$(sha256sum "$backup" | cut -d ' ' -f 1)" = "$runtime_sha256" ] || fail 'Runtime backup custody digest changed'
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
remaining=30
while [ "$remaining" -gt 0 ] && { [ ! -f "$epoch" ] || [ ! -f "$latch" ]; }; do
  sleep 1
  remaining=$((remaining - 1))
done
[ -f "$epoch" ] && [ -f "$latch" ] || fail 'product Runtime recorder did not publish its failure pair'
printf 'recorded\n'
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
unit=${shellSingleQuote(observationRuntimeUnit)}
${runtimeClaimLockPrelude()}
fail() { printf '%s\n' "$1" >&2; exit 79; }
${runtimeClaimPreflight(runId, ownershipToken)}
[ -f "$backup" ]
runtime_sha256=$(sha256sum "$backup" | cut -d ' ' -f 1)
repair_output=$(/usr/local/bin/enoki-probe repair)
[ "$repair_output" = '本机恢复与最终探针启动已完成；修复最终结果以 Hub 为准' ]
[ "$(sha256sum "$runtime" | cut -d ' ' -f 1)" = "$runtime_sha256" ]
version_output=$(/usr/local/bin/enoki-probe --version)
bundle_version=\${version_output#"enoki-probe "}
bundle_version=\${bundle_version#v}
[ "$bundle_version" = ${shellSingleQuote(expectedBundleVersion)} ]
printf 'bundleVersion=%s\nfaultBackupExists=1\nrepairOutput=%s\nruntimeSha256=%s\nunit=%s\n' \\
  "$bundle_version" "$repair_output" "$runtime_sha256" "$unit"
`;
}

function cleanupObservationRuntimeFailureScript(runId, ownershipToken) {
  return `# enoki-release-e2e:cleanup-observation-runtime-failure
set -eu
claim=/var/lib/enoki-release-e2e/claim
runtime=/usr/local/bin/enoki-observation-runtime
backup="$claim/observation-runtime-original"
restore_tmp=/usr/local/bin/.enoki-observation-runtime.release-e2e.restore
lock_root=/run/enoki-release-e2e
lock_path="$lock_root/claim.lock"
lock_parent=$(dirname -- "$lock_root")
[ -d "$lock_parent" ] || mkdir -p "$lock_parent"
[ ! -e "$lock_root" ] && [ ! -L "$lock_root" ] && { mkdir -m 0700 "$lock_root" && sync -f "$lock_parent"; }
[ -d "$lock_root" ] && [ ! -L "$lock_root" ] && [ "$(stat -c '%u:%a:%h' "$lock_root")" = 0:700:2 ] || { printf 'release E2E lock directory custody is invalid\n' >&2; exit 79; }
[ ! -e "$lock_path" ] && [ ! -L "$lock_path" ] && ( umask 077; : > "$lock_path"; sync -f "$lock_path"; sync -f "$lock_root"; )
[ -f "$lock_path" ] && [ ! -L "$lock_path" ] && [ "$(stat -c '%u:%a:%h' "$lock_path")" = 0:600:1 ] || { printf 'release E2E lock custody is invalid\n' >&2; exit 79; }
exec 9<>"$lock_path"
flock -x 9
[ -d "$lock_root" ] && [ ! -L "$lock_root" ] && [ "$(stat -c '%u:%a:%h' "$lock_root")" = 0:700:2 ] || { printf 'release E2E lock directory changed\n' >&2; exit 79; }
[ -f "$lock_path" ] && [ ! -L "$lock_path" ] && [ "$(stat -c '%u:%a:%h' "$lock_path")" = 0:600:1 ] || { printf 'release E2E lock custody changed\n' >&2; exit 79; }
[ "$(stat -Lc '%d:%i' "$lock_path")" = "$(stat -Lc '%d:%i' "/proc/$$/fd/9")" ] || { printf 'release E2E lock inode changed\n' >&2; exit 79; }
companion=/usr/local/bin/enoki-probe-lifecycle-companion
unit=${shellSingleQuote(observationRuntimeUnit)}
fail() { printf '%s\n' "$1" >&2; exit 79; }
${systemdUnitStateFunctions()}
recovered_bundle_version=
${runtimeClaimPreflight(runId, ownershipToken)}
if [ -f "$backup" ] && [ ! -L "$backup" ]; then
  [ "$(stat -c '%u:%a:%h' "$backup")" = 0:755:1 ] || fail 'run-owned Runtime backup boundary is invalid'
  backup_sha256=$(sha256sum "$backup" | cut -d ' ' -f 1) || fail 'could not read run-owned Runtime backup'
  if [ -e "$restore_tmp" ] || [ -L "$restore_tmp" ]; then
    [ -f "$restore_tmp" ] && [ ! -L "$restore_tmp" ] && [ "$(stat -c '%u:%a:%h' "$restore_tmp")" = 0:755:1 ] || fail 'Runtime restore temporary residue is invalid'
    rm -- "$restore_tmp"
    sync -f /usr/local/bin || fail 'could not persist Runtime restore temporary cleanup'
  fi
  stop_unit enoki-probe.service
  stop_unit enoki-observation-runtime.socket
  require_stopped_unit enoki-probe.service
  require_stopped_unit enoki-observation-runtime.socket
  stop_unit "$unit"
  stop_unit enoki-observation-runtime-failure.service
  reset_quiescent_failed_unit "$unit"
  require_stopped_unit "$unit"
  require_stopped_unit enoki-observation-runtime-failure.service
  [ ! -e "$restore_tmp" ] && [ ! -L "$restore_tmp" ] || fail 'Runtime restore temporary residue is invalid'
  cp --preserve=mode,ownership,timestamps -- "$backup" "$restore_tmp"
  [ "$(stat -c '%u:%a:%h' "$restore_tmp")" = 0:755:1 ] || fail 'Runtime restore temporary boundary is invalid'
  [ "$(sha256sum "$restore_tmp" | cut -d ' ' -f 1)" = "$backup_sha256" ] || fail 'Runtime restore temporary digest changed'
  sync -f "$restore_tmp" || fail 'could not persist Runtime restore temporary'
  mv -- "$restore_tmp" "$runtime"
  sync -f /usr/local/bin || fail 'could not persist Runtime restore'
  [ "$(stat -c '%u:%a:%h' "$runtime")" = 0:755:1 ] || fail 'restored Observation Runtime boundary is invalid'
  [ "$(sha256sum "$runtime" | cut -d ' ' -f 1)" = "$backup_sha256" ] || fail 'restored Observation Runtime digest changed'
  systemctl start enoki-observation-runtime.socket >/dev/null 2>&1 || fail 'could not restart Observation Runtime socket'
  "$companion" retry-runtime || fail 'could not reconcile and retry fixed Runtime'
  systemctl start enoki-probe.service >/dev/null 2>&1 || fail 'could not restart canonical Probe'
  wait_for_unit_state enoki-observation-runtime.socket active listening
  wait_for_unit_state enoki-probe.service active running
  wait_for_unit_state "$unit" active running
  require_stopped_unit enoki-observation-runtime-failure.service
  [ "$(sha256sum "$runtime" | cut -d ' ' -f 1)" = "$backup_sha256" ] || fail 'recovered Observation Runtime digest changed'
  version_output=$(/usr/local/bin/enoki-probe --version) || fail 'could not read recovered Probe version'
  recovered_bundle_version=\${version_output#"enoki-probe "}
  recovered_bundle_version=\${recovered_bundle_version#v}
  printf '%s\n' "$recovered_bundle_version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || fail 'recovered Probe version is invalid'
elif [ -e "$backup" ] || [ -L "$backup" ]; then
  fail 'run-owned Runtime backup boundary is invalid'
fi
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
${runtimeClaimLockPrelude()}
fail() { printf '%s\n' "$1" >&2; exit 79; }
${runtimeClaimPreflight(runId, ownershipToken)}
if [ ! -e "$backup" ] && [ ! -L "$backup" ]; then
  printf '${retire ? "retired" : "absent"}\n'
  exit 0
fi
[ -f "$backup" ] && [ ! -L "$backup" ] || fail 'run-owned Runtime backup boundary is invalid'
[ "$(stat -c '%u:%a:%h' "$backup")" = 0:755:1 ] || fail 'run-owned Runtime backup ownership is invalid'
[ -f "$runtime" ] && [ ! -L "$runtime" ] || fail 'Observation Runtime binary boundary is invalid'
[ "$(stat -c '%u:%a:%h' "$runtime")" = 0:755:1 ] || fail 'Observation Runtime binary ownership is invalid'
[ "$(sha256sum "$runtime" | cut -d ' ' -f 1)" = "$(sha256sum "$backup" | cut -d ' ' -f 1)" ] || fail 'Observation Runtime differs from run-owned custody'
${retire ? "rm -- \"$backup\"\nsync -f \"$claim\" || fail 'could not persist Runtime custody retirement'\nprintf 'retired\\n'" : "printf 'present\\n'"}
`;
}

function runtimeClaimLockPrelude() {
  return String.raw`lock_root=/run/enoki-release-e2e
lock_path="$lock_root/claim.lock"
lock_parent=$(dirname -- "$lock_root")
[ -d "$lock_parent" ] || mkdir -p "$lock_parent"
[ ! -e "$lock_root" ] && [ ! -L "$lock_root" ] && { mkdir -m 0700 "$lock_root" && sync -f "$lock_parent"; }
[ -d "$lock_root" ] && [ ! -L "$lock_root" ] && [ "$(stat -c '%u:%a:%h' "$lock_root")" = 0:700:2 ] || { printf 'release E2E lock directory custody is invalid\n' >&2; exit 79; }
[ ! -e "$lock_path" ] && [ ! -L "$lock_path" ] && ( umask 077; : > "$lock_path"; sync -f "$lock_path"; sync -f "$lock_root"; )
[ -f "$lock_path" ] && [ ! -L "$lock_path" ] && [ "$(stat -c '%u:%a:%h' "$lock_path")" = 0:600:1 ] || { printf 'release E2E lock custody is invalid\n' >&2; exit 79; }
exec 9<>"$lock_path"
flock -x 9
[ -d "$lock_root" ] && [ ! -L "$lock_root" ] && [ "$(stat -c '%u:%a:%h' "$lock_root")" = 0:700:2 ] || { printf 'release E2E lock directory changed\n' >&2; exit 79; }
[ -f "$lock_path" ] && [ ! -L "$lock_path" ] && [ "$(stat -c '%u:%a:%h' "$lock_path")" = 0:600:1 ] || { printf 'release E2E lock custody changed\n' >&2; exit 79; }
[ "$(stat -Lc '%d:%i' "$lock_path")" = "$(stat -Lc '%d:%i' "/proc/$$/fd/9")" ] || { printf 'release E2E lock inode changed\n' >&2; exit 79; }
`;
}

function runtimeClaimPreflight(runId, ownershipToken) {
  return `claim_root=/var/lib/enoki-release-e2e
[ -d "$claim_root" ] && [ ! -L "$claim_root" ] && [ "$(stat -c '%u:%a' "$claim_root")" = 0:700 ] || fail 'release E2E claim root custody is invalid'
[ -d "$claim" ] && [ ! -L "$claim" ] && [ "$(stat -c '%u:%a:%h' "$claim")" = 0:700:2 ] || fail 'release E2E ownership claim is invalid'
[ -f "$claim/run-id" ] && [ ! -L "$claim/run-id" ] && [ "$(stat -c '%u:%a:%h' "$claim/run-id")" = 0:600:1 ] || fail 'release E2E run claim is invalid'
[ -f "$claim/token" ] && [ ! -L "$claim/token" ] && [ "$(stat -c '%u:%a:%h' "$claim/token")" = 0:600:1 ] || fail 'release E2E ownership token is invalid'
[ "$(cat "$claim/run-id")" = ${shellSingleQuote(runId)} ] || fail 'release E2E run claim changed'
[ "$(cat "$claim/token")" = ${shellSingleQuote(ownershipToken)} ] || fail 'release E2E ownership token changed'
[ -f "$claim/resources" ] && [ ! -L "$claim/resources" ] && [ "$(stat -c '%u:%a:%h' "$claim/resources")" = 0:600:1 ] || fail 'release E2E resource custody is invalid'
resources_next=
recovered_backup_tmp=
for member in "$claim"/* "$claim"/.[!.]* "$claim"/..?*; do
  [ -e "$member" ] || [ -L "$member" ] || continue
  [ -f "$member" ] && [ ! -L "$member" ] || fail 'release E2E claim member is invalid'
  case "$(basename -- "$member")" in
    resources.next) [ "$(stat -c '%u:%a:%h' "$member")" = 0:600:1 ] || fail 'release E2E resource recovery is invalid'; resources_next=$member ;;
    observation-runtime-original.next) [ "$(stat -c '%u:%a:%h' "$member")" = 0:755:1 ] || fail 'Runtime backup temporary boundary is invalid'; recovered_backup_tmp=$member ;;
    observation-runtime-original) [ "$(stat -c '%u:%a:%h' "$member")" = 0:755:1 ] || fail 'run-owned Runtime backup boundary is invalid' ;;
    run-id|token|resources) ;;
    *) fail 'release E2E claim has an unknown member' ;;
  esac
done
if [ -n "$resources_next" ] || [ -n "$recovered_backup_tmp" ]; then
  [ -z "$resources_next" ] || rm -- "$resources_next"
  [ -z "$recovered_backup_tmp" ] || rm -- "$recovered_backup_tmp"
  sync -f "$claim" || fail 'could not persist release E2E claim recovery'
fi`;
}

function systemdUnitStateFunctions() {
  return `state_monotonic_ms() {
  awk '{ printf "%.0f", $1 * 1000 }' /proc/uptime 2>/dev/null
}
read_unit_state() {
  closed_unit_state_stdout() {
    closed_load=$(printf '%s\n' "$1" | awk -F= '$1 == "LoadState" { print $2 }') || return 1
    closed_active=$(printf '%s\n' "$1" | awk -F= '$1 == "ActiveState" { print $2 }') || return 1
    closed_sub=$(printf '%s\n' "$1" | awk -F= '$1 == "SubState" { print $2 }') || return 1
    [ "$(printf '%s\n' "$1" | awk 'NF { count += 1 } END { print count + 0 }')" -eq 3 ] || return 1
    case "$closed_load:$closed_active:$closed_sub" in
      loaded:active:running|loaded:active:listening|loaded:inactive:dead|loaded:failed:failed) return 0 ;;
    esac
    return 1
  }
  record_unit_state() {
    record_target=$1
    record_code=$2
    record_stdout=$3
    record_bytes=unavailable
    record_hex=unavailable
    if record_count=$(printf '%s' "$record_stdout" | wc -c | tr -d ' '); then
      record_bytes=$record_count
    fi
    if [ "$record_bytes" != unavailable ] && [ "$record_bytes" -le 3800 ] && closed_unit_state_stdout "$record_stdout"; then
      if record_od=$(printf '%s' "$record_stdout" | od -An -tx1); then
        record_hex=$(printf '%s' "$record_od" | tr -d ' \\n') || record_hex=unavailable
      fi
    fi
    ( printf 'enoki.lifecycle.diagnostic role=host phase=%s operation=read_unit_state unit=%s poll=%s code=%s stdout_bytes=%s stdout_hex=%s wait_seconds=%s elapsed_ms=%s sleep_ms=%s\\n' "\${state_phase:-runtime_cleanup}" "$record_target" "\${state_poll_index:-direct}" "$record_code" "$record_bytes" "$record_hex" "\${state_remaining:-direct}" "\${state_elapsed_ms:-unavailable}" "\${state_sleep_ms:-unavailable}" >&2 ) || :
    return 0
  }
  target=$1
  if properties=$(systemctl show "$target" --no-pager --property=LoadState --property=ActiveState --property=SubState); then
    record_unit_state "$target" 0 "$properties" || :
  else
    state_code=$?
    record_unit_state "$target" "$state_code" "$properties" || :
    return 1
  fi
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
reset_quiescent_failed_unit() {
  expected_target=$1
  properties=$(systemctl show "$expected_target" --no-pager --property=LoadState --property=ActiveState --property=SubState --property=MainPID --property=ControlPID --property=Job) || fail "could not query $expected_target quiescence"
  property_count=$(printf '%s\n' "$properties" | awk 'NF { count += 1 } END { print count + 0 }') || fail "could not query $expected_target quiescence"
  load_count=$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" { count += 1 } END { print count + 0 }') || fail "could not query $expected_target quiescence"
  active_count=$(printf '%s\n' "$properties" | awk -F= '$1 == "ActiveState" { count += 1 } END { print count + 0 }') || fail "could not query $expected_target quiescence"
  sub_count=$(printf '%s\n' "$properties" | awk -F= '$1 == "SubState" { count += 1 } END { print count + 0 }') || fail "could not query $expected_target quiescence"
  main_pid_count=$(printf '%s\n' "$properties" | awk -F= '$1 == "MainPID" { count += 1 } END { print count + 0 }') || fail "could not query $expected_target quiescence"
  control_pid_count=$(printf '%s\n' "$properties" | awk -F= '$1 == "ControlPID" { count += 1 } END { print count + 0 }') || fail "could not query $expected_target quiescence"
  job_count=$(printf '%s\n' "$properties" | awk -F= '$1 == "Job" { count += 1 } END { print count + 0 }') || fail "could not query $expected_target quiescence"
  [ "$property_count" -eq 6 ] && [ "$load_count" -eq 1 ] && [ "$active_count" -eq 1 ] && [ "$sub_count" -eq 1 ] && [ "$main_pid_count" -eq 1 ] && [ "$control_pid_count" -eq 1 ] && [ "$job_count" -eq 1 ] || fail "$expected_target quiescence is invalid"
  load_state=$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" { print substr($0, index($0, "=") + 1) }') || fail "could not query $expected_target quiescence"
  active_state=$(printf '%s\n' "$properties" | awk -F= '$1 == "ActiveState" { print substr($0, index($0, "=") + 1) }') || fail "could not query $expected_target quiescence"
  sub_state=$(printf '%s\n' "$properties" | awk -F= '$1 == "SubState" { print substr($0, index($0, "=") + 1) }') || fail "could not query $expected_target quiescence"
  main_pid=$(printf '%s\n' "$properties" | awk -F= '$1 == "MainPID" { print substr($0, index($0, "=") + 1) }') || fail "could not query $expected_target quiescence"
  control_pid=$(printf '%s\n' "$properties" | awk -F= '$1 == "ControlPID" { print substr($0, index($0, "=") + 1) }') || fail "could not query $expected_target quiescence"
  job=$(printf '%s\n' "$properties" | awk -F= '$1 == "Job" { print substr($0, index($0, "=") + 1) }') || fail "could not query $expected_target quiescence"
  [ "$load_state" = loaded ] && [ "$active_state" = failed ] && [ "$sub_state" = failed ] || return 0
  [ "$main_pid" = 0 ] && [ "$control_pid" = 0 ] && [ -z "$job" ] || fail "$expected_target failed state is not quiescent"
  systemctl reset-failed "$expected_target" >/dev/null 2>&1 || fail "could not reset $expected_target failure state"
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
  state_phase=runtime_custody_recovery
  state_started_ms=$(state_monotonic_ms) || state_started_ms=unavailable
  state_remaining=20
  while [ "$state_remaining" -gt 0 ]; do
    state_poll_index=$((20 - state_remaining + 1))
    state_now_ms=$(state_monotonic_ms) || state_now_ms=unavailable
    if [ "$state_started_ms" != unavailable ] && [ "$state_now_ms" != unavailable ]; then
      state_elapsed_ms=$((state_now_ms - state_started_ms))
    else
      state_elapsed_ms=unavailable
    fi
    state_sleep_ms=unavailable
    observed_state=$(read_unit_state "$expected_target") || fail "could not query $expected_target state"
    [ "$observed_state" = "loaded $expected_active $expected_sub" ] && return 0
    state_sleep_started_ms=$(state_monotonic_ms) || state_sleep_started_ms=unavailable
    sleep 1
    state_sleep_finished_ms=$(state_monotonic_ms) || state_sleep_finished_ms=unavailable
    if [ "$state_sleep_started_ms" != unavailable ] && [ "$state_sleep_finished_ms" != unavailable ]; then
      state_sleep_ms=$((state_sleep_finished_ms - state_sleep_started_ms))
    else
      state_sleep_ms=unavailable
    fi
    ( printf 'enoki.lifecycle.diagnostic role=host phase=%s operation=wait_unit_sleep unit=%s poll=%s sleep_ms=%s\\n' "$state_phase" "$expected_target" "$state_poll_index" "$state_sleep_ms" >&2 ) || :
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

function commandResultFailure(message, phase, result) {
  const failureDetail = boundedCommandResult(phase, result);
  const error = new Error(
    failureDetail.replayReady === false
      ? `Installed Bundle Failure ${phase} command failed; detail unavailable`
      : message,
  );
  error.failureDetail = failureDetail;
  return error;
}

function boundedCommandResult(phase, result) {
  const detail = {
    kind: "installed_bundle_failure_repair",
    phase,
    result: {
      code: Number.isInteger(result?.code) ? result.code : null,
      stderr: typeof result?.stderr === "string" ? result.stderr : "",
      stdout: typeof result?.stdout === "string" ? result.stdout : "",
    },
    executionTiming:
      Number.isSafeInteger(result?.executionTiming?.elapsedMs) &&
      Number.isSafeInteger(result?.executionTiming?.timeoutMs) &&
      typeof result?.executionTiming?.timedOut === "boolean"
        ? {
            elapsedMs: result.executionTiming.elapsedMs,
            timeoutMs: result.executionTiming.timeoutMs,
            timedOut: result.executionTiming.timedOut,
          }
        : { unavailable: true },
  };
  const encoded = JSON.stringify(detail);
  if (
    /(?:enrollment.?token|password|private.?key|signing.?secret|enk_enroll_)/i.test(
      `${detail.result.stderr}\n${detail.result.stdout}`,
    ) ||
    Buffer.byteLength(encoded, "utf8") > 8 * 1024
  ) {
    return {
      kind: detail.kind,
      phase,
      replayReady: false,
      unavailable: "unsafe_or_oversize_result",
    };
  }
  return detail;
}

function shellSingleQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}
