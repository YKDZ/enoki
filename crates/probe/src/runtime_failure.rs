//! Observation Runtime 启动预算耗尽的固定 recorder 与终止性 latch。

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use enoki_probe_bootstrap::lifecycle::{
    InstalledBundleFailureEvidenceV1, InstalledBundleRepairAuthorityV1,
};

use crate::secure_file::{atomic_write, ensure_directory, remove_regular_file};

const RUNTIME_UNIT: &str = "enoki-observation-runtime.service";
const RECORDER_UNIT: &str = "enoki-observation-runtime-failure.service";
const METADATA_PATH: &str = "/etc/enoki/probe-install.toml";
/// public 身份文件固定路径；生产 identity 由 concrete 状态根派生（见 IDENTITY_SUFFIX），
/// 此常量仅供测试夹具写入普通布局的身份文件。
#[cfg(test)]
const IDENTITY_PATH: &str = "/var/lib/enoki-probe/identity/probe-bootstrap.toml";
const UNIT_PATH: &str = "/etc/systemd/system/enoki-observation-runtime.service";
const RECORDER_UNIT_PATH: &str = "/etc/systemd/system/enoki-observation-runtime-failure.service";
/// recorder 命名空间内由固定 unit bind 出来的当前 boot alias 来源（宿主 proc 隐藏时的入口）。
const BOOT_ID_PATH: &str = "/run/enoki-probe/runtime-failure-boot-id";
/// manager／Local Retry 上下文可见的宿主 boot 来源。
const HOST_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
/// 专用 bounded reader 单次读取上限：boot ID 远小于此，超过即拒绝。
const BOOT_ID_READ_LIMIT: usize = 64;
const STATE_ROOT_PUBLIC: &str = "/var/lib/enoki-probe";
/// DynamicUser 安装：public 是指向固定 private 根的单链接 symlink。
const CANONICAL_PRIVATE_STATE_ROOT: &str = "/var/lib/private/enoki-probe";
const CANONICAL_PUBLIC_SYMLINK_TARGET: &[u8] = b"private/enoki-probe";
/// 既有安装入口建立并验证的 root 管理 bootstrap 持久根（root:root 0700）。
const BOOTSTRAP_STATE_ROOT: &str = "/var/lib/enoki-probe-bootstrap";
/// 故障 pair 与 Repair intent 的唯一固定保管 child：root bootstrap 根下的 `runtime-failure`。
/// 普通 Probe 对该 parent 没有写权限，因此无法移动或清除固定 latch／intent。
const FAILURE_DIR_NAME: &str = "runtime-failure";
const EPOCH_NAME: &str = "epoch.toml";
const LATCH_NAME: &str = "latch";
const REPAIR_INTENT_NAME: &str = "repair-intent.json";
/// 上述固定根内文件的绝对路径镜像，仅供测试夹具断言实际位置。
#[cfg(test)]
const EPOCH_PATH: &str = "/var/lib/enoki-probe-bootstrap/runtime-failure/epoch.toml";
#[cfg(test)]
const LATCH_PATH: &str = "/var/lib/enoki-probe-bootstrap/runtime-failure/latch";

/// manager 必须实际加载的固定恢复预算：`Restart=on-failure`、`RestartSec=5s`、`3 次/60s`。
const FIXED_RESTART: &str = "on-failure";
const FIXED_RESTART_USEC: &str = "5s";
const FIXED_START_LIMIT_BURST: &str = "3";
const FIXED_START_LIMIT_INTERVAL_USEC: &str = "1min";
const FIXED_RESTART_INTERVAL_MONOTONIC_USEC: u64 = 5_000_000;
const FIXED_START_LIMIT_INTERVAL_MONOTONIC_USEC: u64 = 60_000_000;

const RECORDER_PROPERTIES: [&str; 6] = [
    "InvocationID",
    "MainPID",
    "FragmentPath",
    "DropInPaths",
    "NeedDaemonReload",
    "RefuseManualStart",
];
const RUNTIME_PROPERTIES: [&str; 20] = [
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "NRestarts",
    "MainPID",
    "ControlPID",
    "Job",
    "InvocationID",
    "StateChangeTimestampMonotonic",
    "ExecMainStartTimestampMonotonic",
    "ExecMainExitTimestampMonotonic",
    "FragmentPath",
    "DropInPaths",
    "NeedDaemonReload",
    "Restart",
    "RestartUSec",
    "StartLimitBurst",
    "StartLimitIntervalUSec",
    "OnFailure",
];

mod installed_bundle_repair;
use installed_bundle_repair::write_installed_bundle_repair_status;
#[cfg(test)]
use installed_bundle_repair::*;
#[cfg(test)]
use installed_bundle_repair::{
    InstalledBundleRepairDriveError, InstalledBundleRepairEffects, drive_installed_bundle_repair,
};
pub use installed_bundle_repair::{
    InstalledBundleRepairError, InstalledBundleRepairGrant, installed_bundle_failure_is_current,
};
pub(crate) use installed_bundle_repair::{
    InstalledBundleRepairOutcome, LiveInstalledBundleRepairError, begin_installed_bundle_repair,
    drive_live_installed_bundle_repair, resume_installed_bundle_repair,
};

/// manager 交出的一份 recorder 完整 property closure。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecorderUnitSnapshot {
    invocation_id: String,
    main_pid: String,
    fragment_path: String,
    drop_in_paths: String,
    need_daemon_reload: String,
    refuse_manual_start: String,
}

/// manager 交出的一份 Runtime 完整 property closure。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeUnitSnapshot {
    load_state: String,
    active_state: String,
    sub_state: String,
    result: String,
    restart_count: String,
    main_pid: String,
    control_pid: String,
    job: String,
    invocation_id: String,
    state_change_monotonic: String,
    exec_start_monotonic: String,
    exec_exit_monotonic: String,
    fragment_path: String,
    drop_in_paths: String,
    need_daemon_reload: String,
    restart: String,
    restart_usec: String,
    start_limit_burst: String,
    start_limit_interval_usec: String,
    on_failure: String,
}

/// 同一轮观察：两份完整 closure 加上观察时刻。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeFailureSnapshot {
    recorder: RecorderUnitSnapshot,
    runtime: RuntimeUnitSnapshot,
    observed_monotonic_usec: u64,
}

/// 资格只在本次调用内存活：不可序列化、字段私有，调用方与测试都无法构造。
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ConfirmedFixedRuntimeBudgetExhaustion {
    result: String,
}

/// raw observation seam：只交出 `systemctl show` 原始文本与观察时刻；解析、固定闭包、
/// 终态形状与跨 horizon 判定全部留在本模块，fake 无法直接交出结论。
pub(crate) trait RuntimeFailureSystemd {
    fn recorder_unit_show(&mut self) -> std::io::Result<String>;
    fn runtime_unit_show(&mut self) -> std::io::Result<String>;
    fn observe_monotonic_usec(&mut self) -> std::io::Result<u64>;

    fn wait_for_fixed_restart_interval(&mut self) -> std::io::Result<()> {
        thread::sleep(Duration::from_micros(FIXED_RESTART_INTERVAL_MONOTONIC_USEC));
        Ok(())
    }
}

pub struct SystemRuntimeFailureSystemd;

impl RuntimeFailureSystemd for SystemRuntimeFailureSystemd {
    fn recorder_unit_show(&mut self) -> std::io::Result<String> {
        systemctl_show(RECORDER_UNIT, &RECORDER_PROPERTIES)
    }

    fn runtime_unit_show(&mut self) -> std::io::Result<String> {
        systemctl_show(RUNTIME_UNIT, &RUNTIME_PROPERTIES)
    }

    fn observe_monotonic_usec(&mut self) -> std::io::Result<u64> {
        monotonic_usec()
    }
}

fn systemctl_show(unit: &str, properties: &[&str]) -> std::io::Result<String> {
    let mut arguments = vec!["show", unit];
    for property in properties {
        arguments.push("--property");
        arguments.push(property);
    }
    let output = Command::new("/usr/bin/systemctl")
        .args(arguments)
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(std::io::Error::other("systemd state unavailable"));
    }
    String::from_utf8(output.stdout).map_err(|_| std::io::Error::other("systemd state invalid"))
}

fn fixed_snapshot(
    systemd: &mut impl RuntimeFailureSystemd,
) -> std::io::Result<RuntimeFailureSnapshot> {
    let recorder = parse_recorder_unit_snapshot(&systemd.recorder_unit_show()?)?;
    let runtime = parse_runtime_unit_snapshot(&systemd.runtime_unit_show()?)?;
    Ok(RuntimeFailureSnapshot {
        recorder,
        runtime,
        observed_monotonic_usec: systemd.observe_monotonic_usec()?,
    })
}

/// 完整 property closure 的逐 key 解析；缺、重、额外 key 或无法拆分的行都 fail closed。
fn exact_systemd_properties<'a>(
    text: &'a str,
    expected: &[&str],
) -> std::io::Result<BTreeMap<&'a str, &'a str>> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| std::io::Error::other("systemd state invalid"))?;
        if !expected.contains(&key) || values.insert(key, value).is_some() {
            return Err(std::io::Error::other("systemd state invalid"));
        }
    }
    if values.len() != expected.len() {
        return Err(std::io::Error::other("systemd state invalid"));
    }
    Ok(values)
}

fn property(values: &BTreeMap<&str, &str>, name: &str) -> std::io::Result<String> {
    values
        .get(name)
        .map(|value| (*value).to_owned())
        .ok_or_else(|| std::io::Error::other("systemd state invalid"))
}

fn parse_recorder_unit_snapshot(text: &str) -> std::io::Result<RecorderUnitSnapshot> {
    let values = exact_systemd_properties(text, &RECORDER_PROPERTIES)?;
    Ok(RecorderUnitSnapshot {
        invocation_id: property(&values, "InvocationID")?,
        main_pid: property(&values, "MainPID")?,
        fragment_path: property(&values, "FragmentPath")?,
        drop_in_paths: property(&values, "DropInPaths")?,
        need_daemon_reload: property(&values, "NeedDaemonReload")?,
        refuse_manual_start: property(&values, "RefuseManualStart")?,
    })
}

fn parse_runtime_unit_snapshot(text: &str) -> std::io::Result<RuntimeUnitSnapshot> {
    let values = exact_systemd_properties(text, &RUNTIME_PROPERTIES)?;
    Ok(RuntimeUnitSnapshot {
        load_state: property(&values, "LoadState")?,
        active_state: property(&values, "ActiveState")?,
        sub_state: property(&values, "SubState")?,
        result: property(&values, "Result")?,
        restart_count: property(&values, "NRestarts")?,
        main_pid: property(&values, "MainPID")?,
        control_pid: property(&values, "ControlPID")?,
        job: property(&values, "Job")?,
        invocation_id: property(&values, "InvocationID")?,
        state_change_monotonic: property(&values, "StateChangeTimestampMonotonic")?,
        exec_start_monotonic: property(&values, "ExecMainStartTimestampMonotonic")?,
        exec_exit_monotonic: property(&values, "ExecMainExitTimestampMonotonic")?,
        fragment_path: property(&values, "FragmentPath")?,
        drop_in_paths: property(&values, "DropInPaths")?,
        need_daemon_reload: property(&values, "NeedDaemonReload")?,
        restart: property(&values, "Restart")?,
        restart_usec: property(&values, "RestartUSec")?,
        start_limit_burst: property(&values, "StartLimitBurst")?,
        start_limit_interval_usec: property(&values, "StartLimitIntervalUSec")?,
        on_failure: property(&values, "OnFailure")?,
    })
}

fn monotonic_usec() -> std::io::Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    u64::try_from(value.tv_sec)
        .ok()
        .and_then(|seconds| {
            u64::try_from(value.tv_nsec)
                .ok()
                .map(|nanos| seconds * 1_000_000 + nanos / 1_000)
        })
        .ok_or_else(|| std::io::Error::other("monotonic clock invalid"))
}

/// OBS-0002：受支持主机在 `3/60/5` 上的真实终态 Result 是 `exit-code`；
/// `start-limit-hit` 从未出现，与 `success`、`exec-condition` 一样不构成耗尽资格。
fn restart_eligible_result(value: &str) -> bool {
    matches!(
        value,
        "exit-code"
            | "signal"
            | "core-dump"
            | "watchdog"
            | "timeout"
            | "protocol"
            | "resources"
            | "oom-kill"
    )
}

fn canonical_u64(value: &str) -> Option<u64> {
    if value == "0"
        || (!value.is_empty()
            && !value.starts_with('0')
            && value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        value.parse().ok()
    } else {
        None
    }
}

fn canonical_invocation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn fixed_runtime_unit_bytes() -> std::io::Result<Vec<u8>> {
    enoki_probe_bootstrap::install::fixed_execution_role_units()
        .into_iter()
        .find_map(|(role, bytes)| (role == "observation-runtime-v4").then_some(bytes))
        .ok_or_else(|| std::io::Error::other("fixed runtime unit unavailable"))
}

fn fixed_recorder_unit_bytes() -> std::io::Result<Vec<u8>> {
    enoki_probe_bootstrap::install::fixed_observation_unit_contents()
        .into_iter()
        .find(|unit| {
            unit.starts_with(b"[Unit]\nDescription=Enoki Observation Runtime failure recorder\n")
        })
        .ok_or_else(|| std::io::Error::other("fixed recorder unit unavailable"))
}

/// manager 实际加载的固定 unit 与配置闭包，并且磁盘 fragment 逐 byte 等于本 build 渲染值。
fn valid_fixed_unit_closure(
    root: &Path,
    expected_uid: u32,
    snapshot: &RuntimeFailureSnapshot,
) -> std::io::Result<()> {
    if snapshot.recorder.fragment_path != RECORDER_UNIT_PATH
        || !snapshot.recorder.drop_in_paths.is_empty()
        || snapshot.recorder.need_daemon_reload != "no"
        || snapshot.recorder.refuse_manual_start != "yes"
        || snapshot.runtime.fragment_path != UNIT_PATH
        || !snapshot.runtime.drop_in_paths.is_empty()
        || snapshot.runtime.need_daemon_reload != "no"
        || snapshot.runtime.load_state != "loaded"
        || snapshot.runtime.restart != FIXED_RESTART
        || snapshot.runtime.restart_usec != FIXED_RESTART_USEC
        || snapshot.runtime.start_limit_burst != FIXED_START_LIMIT_BURST
        || snapshot.runtime.start_limit_interval_usec != FIXED_START_LIMIT_INTERVAL_USEC
        || snapshot.runtime.on_failure != RECORDER_UNIT
    {
        return Err(std::io::Error::other("fixed systemd closure invalid"));
    }
    if trusted_file(&rooted(root, UNIT_PATH), expected_uid, 0o644)? != fixed_runtime_unit_bytes()?
        || trusted_file(&rooted(root, RECORDER_UNIT_PATH), expected_uid, 0o644)?
            != fixed_recorder_unit_bytes()?
    {
        return Err(std::io::Error::other("fixed systemd unit binding invalid"));
    }
    Ok(())
}

/// 一份 snapshot 的终态形状与 freshness；时间戳非法仍 fail closed。
fn valid_fixed_terminal_snapshot(
    root: &Path,
    expected_uid: u32,
    snapshot: &RuntimeFailureSnapshot,
) -> std::io::Result<bool> {
    valid_fixed_unit_closure(root, expected_uid, snapshot)?;
    let runtime = &snapshot.runtime;
    let state_change = canonical_u64(&runtime.state_change_monotonic)
        .filter(|value| *value > 0)
        .ok_or_else(|| std::io::Error::other("runtime timestamp invalid"))?;
    for timestamp in [&runtime.exec_start_monotonic, &runtime.exec_exit_monotonic] {
        if canonical_u64(timestamp)
            .filter(|value| *value > 0)
            .is_none()
        {
            return Err(std::io::Error::other("runtime timestamp invalid"));
        }
    }
    if snapshot.observed_monotonic_usec < state_change
        || snapshot.observed_monotonic_usec - state_change
            >= FIXED_START_LIMIT_INTERVAL_MONOTONIC_USEC
        || runtime.active_state != "failed"
        || runtime.sub_state != "failed"
        || runtime.main_pid != "0"
        || runtime.control_pid != "0"
        || !runtime.job.is_empty()
        || runtime.restart_count != FIXED_START_LIMIT_BURST
        || !restart_eligible_result(&runtime.result)
        || !canonical_invocation_id(&runtime.invocation_id)
    {
        return Ok(false);
    }
    Ok(true)
}

/// 唯一的复合资格判定：来源自证、固定闭包、终态形状、freshness 与跨 RestartSec 稳定。
fn confirm_fixed_runtime_budget_exhaustion(
    root: &Path,
    expected_uid: u32,
    systemd: &mut impl RuntimeFailureSystemd,
    recorder_invocation_id: &str,
    recorder_pid: u32,
) -> std::io::Result<Option<ConfirmedFixedRuntimeBudgetExhaustion>> {
    if !canonical_invocation_id(recorder_invocation_id) {
        return Ok(None);
    }
    let first = fixed_snapshot(systemd)?;
    if !valid_fixed_terminal_snapshot(root, expected_uid, &first)? {
        return Ok(None);
    }
    if first.recorder.invocation_id != recorder_invocation_id
        || first.recorder.main_pid != recorder_pid.to_string()
        || !canonical_invocation_id(&first.recorder.invocation_id)
    {
        return Ok(None);
    }
    systemd.wait_for_fixed_restart_interval()?;
    let second = fixed_snapshot(systemd)?;
    if !valid_fixed_terminal_snapshot(root, expected_uid, &second)? {
        return Ok(None);
    }
    if second.recorder != first.recorder
        || second.runtime != first.runtime
        || second.observed_monotonic_usec < first.observed_monotonic_usec
        || second.observed_monotonic_usec - first.observed_monotonic_usec
            < FIXED_RESTART_INTERVAL_MONOTONIC_USEC
    {
        return Ok(None);
    }
    Ok(Some(ConfirmedFixedRuntimeBudgetExhaustion {
        result: second.runtime.result,
    }))
}

/// 消费端只做当前性复核：固定闭包、failed 无 PID 无 job、Result 与 durable epoch 一致。
fn valid_current_failure_evidence_snapshot(
    root: &Path,
    expected_uid: u32,
    systemd: &mut impl RuntimeFailureSystemd,
    epoch_result: &str,
) -> std::io::Result<()> {
    let snapshot = fixed_snapshot(systemd)?;
    valid_fixed_unit_closure(root, expected_uid, &snapshot)?;
    let runtime = &snapshot.runtime;
    if runtime.active_state != "failed"
        || runtime.sub_state != "failed"
        || runtime.main_pid != "0"
        || runtime.control_pid != "0"
        || !runtime.job.is_empty()
        || runtime.result != epoch_result
        || !restart_eligible_result(&runtime.result)
    {
        return Err(std::io::Error::other("failure epoch is no longer current"));
    }
    Ok(())
}

/// OnFailure recorder 只能由 manager 自己拉起的 invocation 调用。
fn recorder_caller_identity() -> std::io::Result<(String, u32)> {
    let invocation_id = std::env::var("INVOCATION_ID")
        .map_err(|_| std::io::Error::other("recorder invocation unavailable"))?;
    if !canonical_invocation_id(&invocation_id) {
        return Err(std::io::Error::other("recorder invocation invalid"));
    }
    Ok((invocation_id, std::process::id()))
}

pub trait RuntimeRetrySystemd {
    fn retry_fixed_runtime(&mut self) -> std::io::Result<()>;
}

impl RuntimeRetrySystemd for SystemRuntimeFailureSystemd {
    fn retry_fixed_runtime(&mut self) -> std::io::Result<()> {
        for arguments in [
            &["reset-failed", RUNTIME_UNIT][..],
            &["start", RUNTIME_UNIT][..],
            &["is-active", "--quiet", RUNTIME_UNIT][..],
        ] {
            let status = Command::new("/usr/bin/systemctl")
                .args(arguments)
                .status()?;
            if !status.success() {
                return Err(std::io::Error::other("fixed Runtime retry failed"));
            }
        }
        Ok(())
    }
}

pub trait FailureGenerationSource {
    fn fill_generation(&mut self, bytes: &mut [u8; 32]) -> std::io::Result<()>;
}

pub struct KernelFailureGenerationSource;

impl FailureGenerationSource for KernelFailureGenerationSource {
    fn fill_generation(&mut self, bytes: &mut [u8; 32]) -> std::io::Result<()> {
        let read = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        if read == bytes.len() as isize {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFailureRecordOutcome {
    Ignored,
    Latched,
    AlreadyLatched,
}

#[derive(Debug, Deserialize, Serialize)]
struct RuntimeFailureEpoch {
    schema_version: u16,
    generation: String,
    boot_id: String,
    unit: String,
    unit_sha256: String,
    hub_origin: String,
    host_id: String,
    probe_id: String,
    identity_receipt_sha256: String,
    install_state_sha256: String,
    manifest_sha256: String,
    bundle_version: String,
    result: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SignedInstalledBundleFailureEvidence {
    pub evidence: InstalledBundleFailureEvidenceV1,
    pub signature: String,
}

pub fn issue_installed_bundle_failure_evidence(
    issued_at_ms: u64,
    expires_at_ms: u64,
    request_nonce: &str,
) -> std::io::Result<SignedInstalledBundleFailureEvidence> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "root required",
        ));
    }
    issue_installed_bundle_failure_evidence_at(
        Path::new("/"),
        0,
        &mut SystemRuntimeFailureSystemd,
        issued_at_ms,
        expires_at_ms,
        request_nonce,
    )
}

pub fn validate_installed_bundle_repair_authority(
    signed: &SignedInstalledBundleFailureEvidence,
    authority: &InstalledBundleRepairAuthorityV1,
    authority_signature: &str,
    now_ms: u64,
) -> Result<InstalledBundleRepairGrant, InstalledBundleRepairError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(InstalledBundleRepairError::InvalidBoundary);
    }
    validate_installed_bundle_repair_authority_at(
        Path::new("/"),
        0,
        &mut SystemRuntimeFailureSystemd,
        signed,
        authority,
        authority_signature,
        now_ms,
    )
}

/// 固定生产入口；无参数、无 stdin、无网络 transport。
pub fn record_runtime_failure() -> std::io::Result<RuntimeFailureRecordOutcome> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "root required",
        ));
    }
    let (recorder_invocation_id, recorder_pid) = recorder_caller_identity()?;
    record_runtime_failure_at(
        Path::new("/"),
        0,
        &mut SystemRuntimeFailureSystemd,
        &mut KernelFailureGenerationSource,
        &recorder_invocation_id,
        recorder_pid,
    )
}

/// 本机管理员的固定诊断动作。清除 latch 即使启动失败也会使旧 epoch 失效；
/// 新一轮预算耗尽只能产生一个新 generation。
pub fn retry_runtime() -> std::io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "root required",
        ));
    }
    retry_runtime_at(Path::new("/"), 0, &mut SystemRuntimeFailureSystemd)
}

fn retry_runtime_at(
    root: &Path,
    expected_uid: u32,
    systemd: &mut impl RuntimeRetrySystemd,
) -> std::io::Result<()> {
    let paths = runtime_failure_paths(root, expected_uid)?;
    let epoch_bytes = trusted_file(&paths.epoch, expected_uid, 0o600)?;
    let epoch: RuntimeFailureEpoch = toml::from_str(
        std::str::from_utf8(&epoch_bytes)
            .map_err(|_| std::io::Error::other("failure epoch invalid"))?,
    )
    .map_err(|_| std::io::Error::other("failure epoch invalid"))?;
    let latch = trusted_file(&paths.latch, expected_uid, 0o600)?;
    if latch != epoch.generation.as_bytes()
        || epoch.boot_id != trusted_fixed_boot_id(root, expected_uid, FixedBootIdSource::HostProc)?
    {
        return Err(std::io::Error::other("failure epoch binding invalid"));
    }
    fs::remove_file(&paths.latch)?;
    fs::remove_file(&paths.epoch)?;
    File::open(&paths.failure_dir)?.sync_all()?;
    systemd.retry_fixed_runtime()
}

fn issue_installed_bundle_failure_evidence_at(
    root: &Path,
    expected_uid: u32,
    systemd: &mut impl RuntimeFailureSystemd,
    issued_at_ms: u64,
    expires_at_ms: u64,
    request_nonce: &str,
) -> std::io::Result<SignedInstalledBundleFailureEvidence> {
    if expires_at_ms <= issued_at_ms
        || expires_at_ms - issued_at_ms > 120_000
        || !valid_identifier(request_nonce)
    {
        return Err(std::io::Error::other("failure evidence lifetime invalid"));
    }
    let (epoch, metadata) = current_epoch_at(root, expected_uid)?;
    valid_current_failure_evidence_snapshot(root, expected_uid, systemd, &epoch.result)?;
    let install_key = metadata_string(&metadata, "lifecycle_authority_install_key")
        .and_then(|value| decode_lower_hex_32(&value))
        .ok_or_else(|| std::io::Error::other("install authority unavailable"))?;
    let evidence = InstalledBundleFailureEvidenceV1 {
        kind: "installed_bundle_failure".to_owned(),
        schema_version: 1,
        hub_origin: epoch.hub_origin,
        host_id: epoch.host_id,
        probe_id: epoch.probe_id,
        generation: epoch.generation,
        boot_id: epoch.boot_id,
        unit: epoch.unit,
        unit_sha256: epoch.unit_sha256,
        identity_receipt_sha256: epoch.identity_receipt_sha256,
        install_state_sha256: epoch.install_state_sha256,
        manifest_sha256: epoch.manifest_sha256,
        bundle_version: epoch.bundle_version,
        issued_at_ms,
        expires_at_ms,
        request_nonce: request_nonce.to_owned(),
    };
    Ok(SignedInstalledBundleFailureEvidence {
        signature: evidence.sign(&install_key),
        evidence,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_installed_bundle_repair_authority_at(
    root: &Path,
    expected_uid: u32,
    systemd: &mut impl RuntimeFailureSystemd,
    signed: &SignedInstalledBundleFailureEvidence,
    authority: &InstalledBundleRepairAuthorityV1,
    authority_signature: &str,
    now_ms: u64,
) -> Result<InstalledBundleRepairGrant, InstalledBundleRepairError> {
    let current = issue_installed_bundle_failure_evidence_at(
        root,
        expected_uid,
        systemd,
        signed.evidence.issued_at_ms,
        signed.evidence.expires_at_ms,
        &signed.evidence.request_nonce,
    )
    .map_err(|_| InstalledBundleRepairError::InvalidBoundary)?;
    let (_, metadata) = current_epoch_at(root, expected_uid)
        .map_err(|_| InstalledBundleRepairError::InvalidBoundary)?;
    let install_key = metadata_string(&metadata, "lifecycle_authority_install_key")
        .and_then(|value| decode_lower_hex_32(&value))
        .ok_or(InstalledBundleRepairError::InvalidBoundary)?;
    if current != *signed
        || signed.evidence.expires_at_ms <= now_ms
        || authority.kind != "installed_bundle_failure"
        || authority.schema_version != 1
        || authority.expires_at_ms <= now_ms
        || !authority.verify(&install_key, authority_signature)
        || !authority.matches_evidence(&signed.evidence)
        || !valid_identifier(&authority.host_id)
        || !valid_identifier(&authority.repair_operation_id)
        || !valid_identifier(&authority.repair_nonce)
    {
        return Err(InstalledBundleRepairError::InvalidBoundary);
    }
    write_installed_bundle_repair_status(root, authority, "running", None)
        .map_err(|_| InstalledBundleRepairError::InvalidBoundary)?;
    Ok(InstalledBundleRepairGrant {
        authority: authority.clone(),
        authority_signature: authority_signature.to_owned(),
        signed_evidence: signed.clone(),
        root: root.to_path_buf(),
        expected_uid,
    })
}

fn current_epoch_at(
    root: &Path,
    expected_uid: u32,
) -> std::io::Result<(RuntimeFailureEpoch, toml::Value)> {
    let paths = runtime_failure_paths(root, expected_uid)?;
    let epoch_bytes = trusted_file(&paths.epoch, expected_uid, 0o600)?;
    let epoch: RuntimeFailureEpoch = toml::from_str(
        std::str::from_utf8(&epoch_bytes)
            .map_err(|_| std::io::Error::other("failure epoch invalid"))?,
    )
    .map_err(|_| std::io::Error::other("failure epoch invalid"))?;
    let latch = trusted_file(&paths.latch, expected_uid, 0o600)?;
    let metadata_bytes = trusted_file(&rooted(root, METADATA_PATH), expected_uid, 0o600)?;
    let identity = trusted_identity_file(&paths.identity)?;
    let unit = trusted_file(&rooted(root, UNIT_PATH), expected_uid, 0o644)?;
    let boot_id = trusted_fixed_boot_id(root, expected_uid, FixedBootIdSource::NamespaceAlias)?;
    let metadata: toml::Value = toml::from_str(
        std::str::from_utf8(&metadata_bytes)
            .map_err(|_| std::io::Error::other("install receipt invalid"))?,
    )
    .map_err(|_| std::io::Error::other("install receipt invalid"))?;
    let identity_value: toml::Value = toml::from_str(
        std::str::from_utf8(&identity)
            .map_err(|_| std::io::Error::other("identity receipt invalid"))?,
    )
    .map_err(|_| std::io::Error::other("identity receipt invalid"))?;
    if epoch.schema_version != 1
        || !restart_eligible_result(&epoch.result)
        || epoch.unit != RUNTIME_UNIT
        || latch != epoch.generation.as_bytes()
        || epoch.boot_id != boot_id.trim()
        || epoch.unit_sha256 != sha256(&unit)
        || epoch.identity_receipt_sha256 != sha256(&identity)
        || epoch.hub_origin != metadata_string(&metadata, "hub_url").unwrap_or_default()
        || epoch.hub_origin != metadata_string(&identity_value, "hub_url").unwrap_or_default()
        || epoch.host_id != metadata_string(&identity_value, "host_id").unwrap_or_default()
        || epoch.probe_id != metadata_string(&identity_value, "probe_id").unwrap_or_default()
        || epoch.install_state_sha256
            != metadata_string(&metadata, "install_state_sha256").unwrap_or_default()
        || epoch.manifest_sha256
            != metadata_string(&metadata, "target_manifest_sha256").unwrap_or_default()
        || epoch.bundle_version != metadata_string(&metadata, "bundle_version").unwrap_or_default()
    {
        return Err(std::io::Error::other("failure epoch binding invalid"));
    }
    Ok((epoch, metadata))
}

fn record_runtime_failure_at(
    root: &Path,
    expected_uid: u32,
    systemd: &mut impl RuntimeFailureSystemd,
    generations: &mut impl FailureGenerationSource,
    recorder_invocation_id: &str,
    recorder_pid: u32,
) -> std::io::Result<RuntimeFailureRecordOutcome> {
    let paths = runtime_failure_paths(root, expected_uid)?;
    let failure_dir = paths.failure_dir.clone();
    let epoch_path = paths.epoch.clone();
    let latch_path = paths.latch.clone();
    if epoch_path.exists() || latch_path.exists() {
        current_epoch_at(root, expected_uid)?;
        return Ok(RuntimeFailureRecordOutcome::AlreadyLatched);
    }
    let Some(exhaustion) = confirm_fixed_runtime_budget_exhaustion(
        root,
        expected_uid,
        systemd,
        recorder_invocation_id,
        recorder_pid,
    )?
    else {
        return Ok(RuntimeFailureRecordOutcome::Ignored);
    };

    if failure_dir.exists() {
        trusted_directory(&failure_dir, expected_uid, 0o700)?;
    } else {
        ensure_directory(&failure_dir, 0o700, Some((expected_uid, expected_uid)))?;
        trusted_directory(&failure_dir, expected_uid, 0o700)?;
    }
    let metadata = trusted_file(&rooted(root, METADATA_PATH), expected_uid, 0o600)?;
    let identity = trusted_identity_file(&paths.identity)?;
    let unit = trusted_file(&rooted(root, UNIT_PATH), expected_uid, 0o644)?;
    let expected_unit = enoki_probe_bootstrap::install::fixed_execution_role_units()
        .into_iter()
        .find_map(|(role, bytes)| (role == "observation-runtime-v4").then_some(bytes))
        .ok_or_else(|| std::io::Error::other("fixed runtime unit unavailable"))?;
    if unit != expected_unit {
        return Err(std::io::Error::other("runtime unit binding mismatch"));
    }
    let boot_id = trusted_fixed_boot_id(root, expected_uid, FixedBootIdSource::NamespaceAlias)?;
    let metadata: toml::Value = toml::from_str(
        std::str::from_utf8(&metadata)
            .map_err(|_| std::io::Error::other("install receipt invalid"))?,
    )
    .map_err(|_| std::io::Error::other("install receipt invalid"))?;
    let identity_value: toml::Value = toml::from_str(
        std::str::from_utf8(&identity)
            .map_err(|_| std::io::Error::other("identity receipt invalid"))?,
    )
    .map_err(|_| std::io::Error::other("identity receipt invalid"))?;
    let string = |value: &toml::Value, key: &str| {
        value
            .get(key)
            .and_then(toml::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| std::io::Error::other("failure binding missing"))
    };
    let hub_origin = string(&metadata, "hub_url")?;
    if string(&identity_value, "hub_url")? != hub_origin {
        return Err(std::io::Error::other("identity binding mismatch"));
    }
    let mut generation = [0_u8; 32];
    generations.fill_generation(&mut generation)?;
    let epoch = RuntimeFailureEpoch {
        schema_version: 1,
        generation: hex(&generation),
        boot_id: boot_id.trim().to_owned(),
        unit: RUNTIME_UNIT.to_owned(),
        unit_sha256: sha256(&unit),
        hub_origin,
        host_id: string(&identity_value, "host_id")?,
        probe_id: string(&identity_value, "probe_id")?,
        identity_receipt_sha256: sha256(&identity),
        install_state_sha256: string(&metadata, "install_state_sha256")?,
        manifest_sha256: string(&metadata, "target_manifest_sha256")?,
        bundle_version: string(&metadata, "bundle_version")?,
        result: exhaustion.result,
    };
    let encoded =
        toml::to_string(&epoch).map_err(|_| std::io::Error::other("failure epoch invalid"))?;
    atomic_write(
        &epoch_path,
        encoded.as_bytes(),
        0o600,
        Some((expected_uid, expected_uid)),
    )?;
    atomic_write(
        &latch_path,
        epoch.generation.as_bytes(),
        0o600,
        Some((expected_uid, expected_uid)),
    )?;
    Ok(RuntimeFailureRecordOutcome::Latched)
}

fn rooted(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

/// concrete 状态根下的相对后缀（去掉 public 前缀），供两种布局共用。
const IDENTITY_SUFFIX: &str = "identity/probe-bootstrap.toml";

/// 固定的当前 boot 来源；命名空间 alias 与宿主 proc 共用同一专用 bounded reader。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixedBootIdSource {
    /// recorder 单元 bind 出的固定 alias（宿主 proc 在受限命名空间不可见时的入口）。
    NamespaceAlias,
    /// manager／Local Retry 上下文直接可见的宿主 proc。
    HostProc,
}

impl FixedBootIdSource {
    fn path(self) -> &'static str {
        match self {
            Self::NamespaceAlias => BOOT_ID_PATH,
            Self::HostProc => HOST_BOOT_ID_PATH,
        }
    }
}

/// 当前 boot 绑定的专用 bounded reader：读取固定来源至多 `BOOT_ID_READ_LIMIT` 字节，
/// 不比较 st_size（proc 伪文件恒报 0），拒绝缺失／symlink／非 root 文件／超长／空白／控制字符。
/// 通用 `trusted_file` 的磁盘文件语义不受影响；来源固定，不新增公开 caller path／source 参数。
fn trusted_fixed_boot_id(
    root: &Path,
    expected_uid: u32,
    source: FixedBootIdSource,
) -> std::io::Result<String> {
    let path = rooted(root, source.path());
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| std::io::Error::other("boot binding invalid"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o444
    {
        return Err(std::io::Error::other("boot binding invalid"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| std::io::Error::other("boot binding invalid"))?;
    let mut buffer = [0_u8; 65];
    let read = file
        .take(65)
        .read(&mut buffer)
        .map_err(|_| std::io::Error::other("boot binding invalid"))?;
    if read == 0 || read > BOOT_ID_READ_LIMIT {
        return Err(std::io::Error::other("boot binding invalid"));
    }
    let value = std::str::from_utf8(&buffer[..read])
        .map_err(|_| std::io::Error::other("boot binding invalid"))?;
    let boot_id = value.trim_end_matches(['\n', '\r']);
    if boot_id.is_empty() || boot_id.chars().any(char::is_control) {
        return Err(std::io::Error::other("boot binding invalid"));
    }
    Ok(boot_id.to_owned())
}

/// RuntimeFailurePair 的固定路径：identity 仍按 concrete 状态根投影，
/// 故障 epoch／latch 只存在于 root 管理的固定 bootstrap child。
struct RuntimeFailurePaths {
    failure_dir: PathBuf,
    epoch: PathBuf,
    latch: PathBuf,
    identity: PathBuf,
}

/// 把 public 绝对状态路径投影到 concrete 状态根；仅用于 Probe 自己的 operation status，
/// 让普通／canonical 两种布局的消费者复用同一 concrete 根，无需放宽全局 no-follow。
/// 非状态根路径（／etc、／run、／proc、bootstrap 根）原样返回。
fn state_child(root: &Path, public_absolute: &str) -> std::io::Result<PathBuf> {
    match public_absolute.strip_prefix(STATE_ROOT_PUBLIC) {
        Some(relative) => Ok(concrete_state_root(root)?.join(relative.trim_start_matches('/'))),
        None => Ok(rooted(root, public_absolute)),
    }
}

/// 固定的故障保管根：root 管理的 bootstrap 根下唯一 child，caller 不能选择目录、形态、
/// mode 或 owner。关闭 F51-1 的因果是 parent 的归属与写入权：parent 必须是 root 管理的
/// 真实目录且组／其他无写位（安装入口已把它固定为 root:root 0700），因此普通 Probe
/// 既不能在其中创建 symlink，也不能 rename 走故障 child；Probe-owned parent、symlink、
/// 组／其他可写或不可达路径一律拒绝。child 自身继续按 recorder 的 0700 精确复核。
/// child 缺失只表示尚无故障事实，由 recorder 按原前置建立，不在此补建 bootstrap parent。
fn fixed_failure_dir(root: &Path, expected_uid: u32) -> std::io::Result<PathBuf> {
    let bootstrap_root = rooted(root, BOOTSTRAP_STATE_ROOT);
    let failure_dir = bootstrap_root.join(FAILURE_DIR_NAME);
    trusted_lifecycle_parent(&bootstrap_root, expected_uid)?;
    if failure_dir.exists() {
        trusted_directory(&failure_dir, expected_uid, 0o700)?;
    }
    Ok(failure_dir)
}

/// 固定的故障保管文件（epoch／latch／Repair intent）路径。
fn fixed_failure_child(root: &Path, expected_uid: u32, name: &str) -> std::io::Result<PathBuf> {
    Ok(fixed_failure_dir(root, expected_uid)?.join(name))
}

/// 解析当前安装的 concrete 状态根，供 producer／consumer／Repair 复用；
/// unknown target、错误 symlink 目标、不可达 child 均在查询／写入前拒绝。
/// ordinary：public 是真实目录（owner／mode 由现有 `trusted_state_directory` 复核）。
/// canonical：public 必须是 root 拥有的单链接 symlink → 固定 private 根；recorder 不补建／chown 该父目录。
fn concrete_state_root(root: &Path) -> std::io::Result<PathBuf> {
    let public = rooted(root, STATE_ROOT_PUBLIC);
    let metadata = fs::symlink_metadata(&public)
        .map_err(|_| std::io::Error::other("state root unavailable"))?;
    if metadata.file_type().is_symlink() {
        if metadata.uid() != 0 {
            return Err(std::io::Error::other("state root symlink invalid"));
        }
        let link = fs::read_link(&public)
            .map_err(|_| std::io::Error::other("state root symlink invalid"))?;
        if link.as_os_str().as_bytes() != CANONICAL_PUBLIC_SYMLINK_TARGET {
            return Err(std::io::Error::other("state root symlink target unknown"));
        }
        let private = rooted(root, CANONICAL_PRIVATE_STATE_ROOT);
        let child = fs::symlink_metadata(&private)
            .map_err(|_| std::io::Error::other("state child unreachable"))?;
        if !child.is_dir() || child.file_type().is_symlink() {
            return Err(std::io::Error::other("state child unreachable"));
        }
        return Ok(private);
    }
    if metadata.is_dir() {
        return Ok(public);
    }
    Err(std::io::Error::other("state root target unknown"))
}

/// 计算 identity 的 concrete 投影与固定故障根，并在查询／写入前复核两类布局边界
/// （真实 0750 状态根 + 合法 identity 文件；root 管理 0700 bootstrap parent + child）。
fn runtime_failure_paths(root: &Path, expected_uid: u32) -> std::io::Result<RuntimeFailurePaths> {
    let state_root = concrete_state_root(root)?;
    let identity = state_root.join(IDENTITY_SUFFIX);
    trusted_state_directory(&state_root, &identity)?;
    let failure_dir = fixed_failure_dir(root, expected_uid)?;
    Ok(RuntimeFailurePaths {
        epoch: failure_dir.join(EPOCH_NAME),
        latch: failure_dir.join(LATCH_NAME),
        failure_dir,
        identity,
    })
}

fn trusted_file(path: &Path, uid: u32, mode: u32) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
        || metadata.len() > 64 * 1024
    {
        return Err(std::io::Error::other("trusted file boundary invalid"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(std::io::Error::other("trusted file changed"));
    }
    Ok(bytes)
}

fn trusted_identity_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > 64 * 1024
    {
        return Err(std::io::Error::other("identity receipt boundary invalid"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != metadata.uid()
    {
        return Err(std::io::Error::other("identity receipt changed"));
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(std::io::Error::other("identity receipt changed"));
    }
    Ok(bytes)
}

fn trusted_directory(path: &Path, uid: u32, mode: u32) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() < 2
    {
        return Err(std::io::Error::other("trusted directory boundary invalid"));
    }
    Ok(())
}

/// 耐久保管 parent 的归属判据：真实目录（非 symlink）、归 expected_uid 管理、
/// 组／其他无写位。这里不复用 `trusted_directory` 的精确 mode 断言，因为 parent 的
/// 具体权限由安装入口固定并可整体只读，F51-1 的因果仅在“谁能在其中改名”。
fn trusted_lifecycle_parent(path: &Path, uid: u32) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() < 2
    {
        return Err(std::io::Error::other("lifecycle parent boundary invalid"));
    }
    Ok(())
}

fn trusted_state_directory(path: &Path, identity_path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let identity = fs::symlink_metadata(identity_path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o7777 != 0o750
        || !identity.is_file()
        || identity.file_type().is_symlink()
        || identity.mode() & 0o7777 != 0o600
        || metadata.uid() != identity.uid()
        || metadata.gid() != identity.gid()
        || metadata.nlink() < 2
    {
        return Err(std::io::Error::other("state directory boundary invalid"));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn metadata_string(value: &toml::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn decode_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        output[index] = ((high << 4) | low) as u8;
    }
    Some(output)
}

fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::{collections::VecDeque, os::unix::fs::PermissionsExt};

    const RECORDER_INVOCATION: &str = "0123456789abcdef0123456789abcdef";
    const RUNTIME_INVOCATION: &str = "fedcba9876543210fedcba9876543210";
    const TERMINAL_STATE_CHANGE_USEC: u64 = 7_000_000_000;
    const TERMINAL_OBSERVED_USEC: u64 = 7_000_200_000;

    fn show(properties: &[(&str, &str)]) -> String {
        properties
            .iter()
            .map(|(key, value)| format!("{key}={value}\n"))
            .collect()
    }

    /// 固定 recorder 的 manager property closure。
    #[derive(Clone, Debug)]
    struct RecorderView {
        invocation_id: String,
        main_pid: String,
        fragment_path: String,
        drop_in_paths: String,
        need_daemon_reload: String,
        refuse_manual_start: String,
    }

    impl RecorderView {
        fn terminal() -> Self {
            Self {
                invocation_id: RECORDER_INVOCATION.to_owned(),
                main_pid: std::process::id().to_string(),
                fragment_path: RECORDER_UNIT_PATH.to_owned(),
                drop_in_paths: String::new(),
                need_daemon_reload: "no".to_owned(),
                refuse_manual_start: "yes".to_owned(),
            }
        }

        fn show(&self) -> String {
            show(&[
                ("InvocationID", self.invocation_id.as_str()),
                ("MainPID", self.main_pid.as_str()),
                ("FragmentPath", self.fragment_path.as_str()),
                ("DropInPaths", self.drop_in_paths.as_str()),
                ("NeedDaemonReload", self.need_daemon_reload.as_str()),
                ("RefuseManualStart", self.refuse_manual_start.as_str()),
            ])
        }
    }

    /// Runtime 的 manager property closure。
    #[derive(Clone, Debug)]
    struct RuntimeView {
        load_state: String,
        active_state: String,
        sub_state: String,
        result: String,
        restart_count: String,
        main_pid: String,
        control_pid: String,
        job: String,
        invocation_id: String,
        state_change_monotonic: String,
        exec_start_monotonic: String,
        exec_exit_monotonic: String,
        fragment_path: String,
        drop_in_paths: String,
        need_daemon_reload: String,
        restart: String,
        restart_usec: String,
        start_limit_burst: String,
        start_limit_interval_usec: String,
        on_failure: String,
    }

    impl RuntimeView {
        fn terminal() -> Self {
            Self {
                load_state: "loaded".to_owned(),
                active_state: "failed".to_owned(),
                sub_state: "failed".to_owned(),
                result: "exit-code".to_owned(),
                restart_count: FIXED_START_LIMIT_BURST.to_owned(),
                main_pid: "0".to_owned(),
                control_pid: "0".to_owned(),
                job: String::new(),
                invocation_id: RUNTIME_INVOCATION.to_owned(),
                state_change_monotonic: TERMINAL_STATE_CHANGE_USEC.to_string(),
                exec_start_monotonic: (TERMINAL_STATE_CHANGE_USEC - 2_000_000).to_string(),
                exec_exit_monotonic: (TERMINAL_STATE_CHANGE_USEC - 1_000_000).to_string(),
                fragment_path: UNIT_PATH.to_owned(),
                drop_in_paths: String::new(),
                need_daemon_reload: "no".to_owned(),
                restart: FIXED_RESTART.to_owned(),
                restart_usec: FIXED_RESTART_USEC.to_owned(),
                start_limit_burst: FIXED_START_LIMIT_BURST.to_owned(),
                start_limit_interval_usec: FIXED_START_LIMIT_INTERVAL_USEC.to_owned(),
                on_failure: RECORDER_UNIT.to_owned(),
            }
        }

        fn show(&self) -> String {
            show(&[
                ("LoadState", self.load_state.as_str()),
                ("ActiveState", self.active_state.as_str()),
                ("SubState", self.sub_state.as_str()),
                ("Result", self.result.as_str()),
                ("NRestarts", self.restart_count.as_str()),
                ("MainPID", self.main_pid.as_str()),
                ("ControlPID", self.control_pid.as_str()),
                ("Job", self.job.as_str()),
                ("InvocationID", self.invocation_id.as_str()),
                (
                    "StateChangeTimestampMonotonic",
                    self.state_change_monotonic.as_str(),
                ),
                (
                    "ExecMainStartTimestampMonotonic",
                    self.exec_start_monotonic.as_str(),
                ),
                (
                    "ExecMainExitTimestampMonotonic",
                    self.exec_exit_monotonic.as_str(),
                ),
                ("FragmentPath", self.fragment_path.as_str()),
                ("DropInPaths", self.drop_in_paths.as_str()),
                ("NeedDaemonReload", self.need_daemon_reload.as_str()),
                ("Restart", self.restart.as_str()),
                ("RestartUSec", self.restart_usec.as_str()),
                ("StartLimitBurst", self.start_limit_burst.as_str()),
                (
                    "StartLimitIntervalUSec",
                    self.start_limit_interval_usec.as_str(),
                ),
                ("OnFailure", self.on_failure.as_str()),
            ])
        }
    }

    /// 一份完整观察：两份 closure 加上观察时刻。
    #[derive(Clone, Debug)]
    struct Observation {
        recorder: RecorderView,
        runtime: RuntimeView,
        observed_usec: u64,
    }

    impl Observation {
        fn terminal() -> Self {
            Self {
                recorder: RecorderView::terminal(),
                runtime: RuntimeView::terminal(),
                observed_usec: TERMINAL_OBSERVED_USEC,
            }
        }

        /// 第 `index` 份稳定观察：与第一份相隔 `index * RestartSec`，其余逐字段相同。
        fn stable(index: usize) -> Self {
            Self {
                observed_usec: TERMINAL_OBSERVED_USEC
                    + index as u64 * FIXED_RESTART_INTERVAL_MONOTONIC_USEC,
                ..Self::terminal()
            }
        }
    }

    /// 按顺序交出预置 raw 观察的替身；一轮观察在交出观察时刻后结束。
    struct Snapshots {
        rounds: VecDeque<(String, String, u64)>,
        waits: usize,
    }

    impl Snapshots {
        fn observations(observations: impl IntoIterator<Item = Observation>) -> Self {
            Self {
                rounds: observations
                    .into_iter()
                    .map(|observation| {
                        (
                            observation.recorder.show(),
                            observation.runtime.show(),
                            observation.observed_usec,
                        )
                    })
                    .collect(),
                waits: 0,
            }
        }

        fn terminal(count: usize) -> Self {
            Self::observations((0..count).map(Observation::stable))
        }

        fn raw(rounds: impl IntoIterator<Item = (String, String)>) -> Self {
            Self {
                rounds: rounds
                    .into_iter()
                    .map(|(recorder, runtime)| (recorder, runtime, TERMINAL_OBSERVED_USEC))
                    .collect(),
                waits: 0,
            }
        }
    }

    impl RuntimeFailureSystemd for Snapshots {
        fn recorder_unit_show(&mut self) -> std::io::Result<String> {
            self.rounds
                .front()
                .map(|(recorder, ..)| recorder.clone())
                .ok_or_else(|| std::io::Error::other("snapshot unavailable"))
        }

        fn runtime_unit_show(&mut self) -> std::io::Result<String> {
            self.rounds
                .front()
                .map(|(_, runtime, _)| runtime.clone())
                .ok_or_else(|| std::io::Error::other("snapshot unavailable"))
        }

        fn observe_monotonic_usec(&mut self) -> std::io::Result<u64> {
            self.rounds
                .pop_front()
                .map(|(_, _, observed)| observed)
                .ok_or_else(|| std::io::Error::other("snapshot unavailable"))
        }

        fn wait_for_fixed_restart_interval(&mut self) -> std::io::Result<()> {
            self.waits += 1;
            Ok(())
        }
    }

    /// 消费端替身：持续交出同一份当前观察；`retry_fails` 保留 Repair 被拒绝的行为。
    #[derive(Clone, Debug)]
    struct ObservationFake {
        recorder: RecorderView,
        runtime: RuntimeView,
        retry_fails: bool,
        retry_calls: usize,
    }

    impl ObservationFake {
        fn terminal() -> Self {
            let observation = Observation::terminal();
            Self {
                recorder: observation.recorder,
                runtime: observation.runtime,
                retry_fails: false,
                retry_calls: 0,
            }
        }

        fn repair_rejected() -> Self {
            Self {
                retry_fails: true,
                ..Self::terminal()
            }
        }
    }

    impl RuntimeFailureSystemd for ObservationFake {
        fn recorder_unit_show(&mut self) -> std::io::Result<String> {
            Ok(self.recorder.show())
        }

        fn runtime_unit_show(&mut self) -> std::io::Result<String> {
            Ok(self.runtime.show())
        }

        fn observe_monotonic_usec(&mut self) -> std::io::Result<u64> {
            Ok(TERMINAL_OBSERVED_USEC)
        }
    }

    impl RuntimeRetrySystemd for ObservationFake {
        fn retry_fixed_runtime(&mut self) -> std::io::Result<()> {
            self.retry_calls += 1;
            if self.retry_fails {
                return Err(std::io::Error::other("完整 Bundle 恢复失败"));
            }
            Ok(())
        }
    }

    struct Generation(u8);
    impl FailureGenerationSource for Generation {
        fn fill_generation(&mut self, bytes: &mut [u8; 32]) -> std::io::Result<()> {
            bytes.fill(self.0);
            Ok(())
        }
    }
    #[derive(Default)]
    struct RetrySystemd(usize);
    impl RuntimeRetrySystemd for RetrySystemd {
        fn retry_fixed_runtime(&mut self) -> std::io::Result<()> {
            self.0 += 1;
            Ok(())
        }
    }

    /// 正式 record 入口：固定 recorder 身份加两份跨 RestartSec 的稳定观察。
    fn record_terminal(
        root: &Path,
        generation_byte: u8,
    ) -> std::io::Result<RuntimeFailureRecordOutcome> {
        record_runtime_failure_at(
            root,
            unsafe { libc::geteuid() },
            &mut Snapshots::terminal(2),
            &mut Generation(generation_byte),
            RECORDER_INVOCATION,
            std::process::id(),
        )
    }

    fn record_with(
        root: &Path,
        observations: impl IntoIterator<Item = Observation>,
        generation_byte: u8,
    ) -> std::io::Result<RuntimeFailureRecordOutcome> {
        record_runtime_failure_at(
            root,
            unsafe { libc::geteuid() },
            &mut Snapshots::observations(observations),
            &mut Generation(generation_byte),
            RECORDER_INVOCATION,
            std::process::id(),
        )
    }

    fn record_latched(root: &Path, generation_byte: u8) {
        assert_eq!(
            record_terminal(root, generation_byte).unwrap(),
            RuntimeFailureRecordOutcome::Latched
        );
    }

    pub(super) fn repair_test_bundle() -> enoki_probe_bootstrap::verifier::VerifiedBundle {
        enoki_probe_bootstrap::verifier::VerifiedBundle::deterministic_complete_for_test(
            "1.2.3",
            "x86_64-unknown-linux-gnu",
            &"b".repeat(64),
            &"a".repeat(64),
            b"probe",
        )
    }

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for directory in [
            "etc/enoki",
            "var/lib/enoki-probe/identity",
            "var/lib/enoki-probe-bootstrap",
            "etc/systemd/system",
            "run/enoki-probe",
            "proc/sys/kernel/random",
        ] {
            fs::create_dir_all(root.path().join(directory)).unwrap();
        }
        fs::set_permissions(
            root.path().join("var/lib/enoki-probe"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        fs::set_permissions(
            root.path().join("var/lib/enoki-probe-bootstrap"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let metadata = format!(
            "schema_version = 5\nhub_url = \"https://hub.example\"\ninstall_state_sha256 = \"{}\"\ntarget_manifest_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\nbundle_version = \"1.2.3\"\nlifecycle_authority_install_key = \"1111111111111111111111111111111111111111111111111111111111111111\"\n",
            repair_test_bundle().install_state_sha256()
        );
        let identity = format!(
            "hub_url = \"https://hub.example\"\nhost_id = \"7\"\nprobe_id = \"probe_01\"\ninstall_state_sha256 = \"{}\"\ntarget_manifest_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\nbundle_version = \"1.2.3\"\n",
            repair_test_bundle().install_state_sha256()
        );
        write_fixture(root.path(), METADATA_PATH, metadata.as_bytes(), 0o600);
        write_fixture(root.path(), IDENTITY_PATH, identity.as_bytes(), 0o600);
        write_fixture(
            root.path(),
            UNIT_PATH,
            &fixed_runtime_unit_bytes().unwrap(),
            0o644,
        );
        write_fixture(
            root.path(),
            RECORDER_UNIT_PATH,
            &fixed_recorder_unit_bytes().unwrap(),
            0o644,
        );
        write_fixture(root.path(), BOOT_ID_PATH, b"boot-01\n", 0o444);
        write_fixture(root.path(), HOST_BOOT_ID_PATH, b"boot-01\n", 0o444);
        root
    }

    fn write_fixture(root: &Path, path: &str, bytes: &[u8], mode: u32) {
        let path = rooted(root, path);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn systemd_249_intermediate_on_failure_does_not_write_an_epoch() {
        let root = fixture();
        // 中间态 OnFailure 通知：预算尚未耗尽，普通通知不产生 durable authority。
        let mut intermediate = RuntimeView::terminal();
        intermediate.active_state = "activating".into();
        intermediate.sub_state = "start".into();
        intermediate.main_pid = "4242".into();
        intermediate.job = "12 enoki-observation-runtime.service/start".into();
        intermediate.restart_count = "1".into();
        assert_eq!(
            record_with(
                root.path(),
                [Observation {
                    runtime: intermediate,
                    ..Observation::terminal()
                }],
                1,
            )
            .unwrap(),
            RuntimeFailureRecordOutcome::Ignored
        );
        assert!(!rooted(root.path(), EPOCH_PATH).exists());
        assert!(!rooted(root.path(), LATCH_PATH).exists());
    }

    #[test]
    fn legacy_identity_without_authenticated_host_id_cannot_create_failure_evidence() {
        let root = fixture();
        write_fixture(
            root.path(),
            IDENTITY_PATH,
            b"hub_url = \"https://hub.example\"\nprobe_id = \"probe_01\"\n",
            0o600,
        );
        assert!(record_terminal(root.path(), 2).is_err());
        assert!(!rooted(root.path(), EPOCH_PATH).exists());
        assert!(!rooted(root.path(), LATCH_PATH).exists());
    }

    #[test]
    fn failure_epoch_rejects_a_later_identity_with_a_different_host_id() {
        let root = fixture();
        record_latched(root.path(), 3);
        write_fixture(
            root.path(),
            IDENTITY_PATH,
            b"hub_url = \"https://hub.example\"\nhost_id = \"8\"\nprobe_id = \"probe_01\"\n",
            0o600,
        );
        assert!(
            issue_installed_bundle_failure_evidence_at(
                root.path(),
                unsafe { libc::geteuid() },
                &mut ObservationFake::terminal(),
                100,
                60_100,
                "request_nonce_wrong_host",
            )
            .is_err()
        );
    }

    type RuntimeDeviation = (&'static str, fn(&mut RuntimeView));
    type ClosureDeviation = (&'static str, fn(&mut RecorderView, &mut RuntimeView));

    fn assert_no_pair(root: &Path) {
        assert!(!rooted(root, EPOCH_PATH).exists());
        assert!(!rooted(root, LATCH_PATH).exists());
    }

    #[test]
    fn two_stable_terminal_observations_with_the_real_result_latch_the_exact_pair() {
        let root = fixture();
        assert_eq!(
            record_terminal(root.path(), 1).unwrap(),
            RuntimeFailureRecordOutcome::Latched
        );
        let epoch = fs::read_to_string(rooted(root.path(), EPOCH_PATH)).unwrap();
        assert!(
            epoch.contains("result = \"exit-code\""),
            "epoch 必须记录 manager 交出的真实 Result：{epoch}"
        );
        assert_eq!(
            fs::read_to_string(rooted(root.path(), LATCH_PATH)).unwrap(),
            "01".repeat(32)
        );
    }

    #[test]
    fn eligibility_consumes_two_observations_one_restart_interval_apart() {
        let root = fixture();
        let mut systemd = Snapshots::terminal(2);
        assert_eq!(
            record_runtime_failure_at(
                root.path(),
                unsafe { libc::geteuid() },
                &mut systemd,
                &mut Generation(1),
                RECORDER_INVOCATION,
                std::process::id(),
            )
            .unwrap(),
            RuntimeFailureRecordOutcome::Latched
        );
        assert_eq!(systemd.waits, 1, "两份观察之间必须等待一个 RestartSec");
        assert!(systemd.rounds.is_empty(), "两份完整观察都要被消费");
    }

    #[test]
    fn a_single_terminal_notification_does_not_establish_eligibility() {
        let root = fixture();
        // 第二份观察时预算仍在推进：单次通知跨不过 RestartSec。
        let mut advancing = Observation::stable(1);
        advancing.runtime.restart_count = "2".into();
        assert_eq!(
            record_with(root.path(), [Observation::terminal(), advancing], 1).unwrap(),
            RuntimeFailureRecordOutcome::Ignored
        );
        assert_no_pair(root.path());
    }

    #[test]
    fn observations_closer_than_the_restart_interval_are_not_eligible() {
        let root = fixture();
        let mut too_close = Observation::terminal();
        too_close.observed_usec = TERMINAL_OBSERVED_USEC + 1_000_000;
        assert_eq!(
            record_with(root.path(), [Observation::terminal(), too_close], 1).unwrap(),
            RuntimeFailureRecordOutcome::Ignored
        );
        assert_no_pair(root.path());
    }

    #[test]
    fn a_single_property_deviation_never_establishes_eligibility() {
        let deviations: [RuntimeDeviation; 9] = [
            ("start-limit-hit 从未在受支持主机出现", |runtime| {
                runtime.result = "start-limit-hit".into()
            }),
            ("成功结束", |runtime| runtime.result = "success".into()),
            ("ExecCondition 拒绝", |runtime| {
                runtime.result = "exec-condition".into()
            }),
            ("预算未用满", |runtime| {
                runtime.restart_count = "2".into()
            }),
            ("仍有主进程", |runtime| {
                runtime.main_pid = "4242".into()
            }),
            ("仍有控制进程", |runtime| {
                runtime.control_pid = "4243".into()
            }),
            ("仍有排队 job", |runtime| {
                runtime.job = "21 enoki-observation-runtime.service/start".into()
            }),
            ("终态观察已过期", |runtime| {
                runtime.state_change_monotonic = (TERMINAL_OBSERVED_USEC
                    - FIXED_START_LIMIT_INTERVAL_MONOTONIC_USEC)
                    .to_string();
            }),
            ("invocation 非 canonical", |runtime| {
                runtime.invocation_id = "nope".into()
            }),
        ];
        for (case, mutate) in deviations {
            let root = fixture();
            let mut first = Observation::terminal();
            mutate(&mut first.runtime);
            let mut second = first.clone();
            second.observed_usec += FIXED_RESTART_INTERVAL_MONOTONIC_USEC;
            assert_eq!(
                record_with(root.path(), [first, second], 1).unwrap(),
                RuntimeFailureRecordOutcome::Ignored,
                "{case}"
            );
            assert_no_pair(root.path());
        }
    }

    #[test]
    fn a_caller_that_is_not_the_managers_recorder_is_not_eligible() {
        let root = fixture();
        let cases: [(&str, &str, u32); 3] = [
            (
                "invocation 与 manager 不同",
                "99999999999999999999999999999999",
                std::process::id(),
            ),
            ("invocation 缺失", "", std::process::id()),
            (
                "pid 与 recorder 主进程不同",
                RECORDER_INVOCATION,
                std::process::id() + 1,
            ),
        ];
        for (case, invocation_id, pid) in cases {
            assert_eq!(
                record_runtime_failure_at(
                    root.path(),
                    unsafe { libc::geteuid() },
                    &mut Snapshots::terminal(2),
                    &mut Generation(1),
                    invocation_id,
                    pid,
                )
                .unwrap(),
                RuntimeFailureRecordOutcome::Ignored,
                "{case}"
            );
        }
        assert_no_pair(root.path());
    }

    #[test]
    fn a_deviated_manager_closure_or_stale_fragment_fails_closed() {
        let deviations: [ClosureDeviation; 11] = [
            ("Runtime 有 drop-in", |_, runtime| {
                runtime.drop_in_paths =
                    "/etc/systemd/system/enoki-observation-runtime.service.d/override.conf".into();
            }),
            ("Runtime 未加载", |_, runtime| {
                runtime.load_state = "masked".into()
            }),
            ("Restart 被改", |_, runtime| {
                runtime.restart = "always".into()
            }),
            ("RestartSec 被改", |_, runtime| {
                runtime.restart_usec = "10s".into()
            }),
            ("burst 被改", |_, runtime| {
                runtime.start_limit_burst = "10".into()
            }),
            ("interval 被改", |_, runtime| {
                runtime.start_limit_interval_usec = "2min".into()
            }),
            ("OnFailure 被改", |_, runtime| {
                runtime.on_failure = "other.service".into()
            }),
            ("fragment 等待 reload", |_, runtime| {
                runtime.need_daemon_reload = "yes".into()
            }),
            ("Runtime fragment 路径被换", |_, runtime| {
                runtime.fragment_path = "/run/other.service".into()
            }),
            ("recorder 允许手工启动", |recorder, _| {
                recorder.refuse_manual_start = "no".into()
            }),
            ("recorder 有 drop-in", |recorder, _| {
                recorder.drop_in_paths =
                    "/etc/systemd/system/enoki-observation-runtime-failure.service.d/override.conf"
                        .into();
            }),
        ];
        for (case, mutate) in deviations {
            let root = fixture();
            let mut first = Observation::terminal();
            mutate(&mut first.recorder, &mut first.runtime);
            let mut second = first.clone();
            second.observed_usec += FIXED_RESTART_INTERVAL_MONOTONIC_USEC;
            assert!(
                record_with(root.path(), [first, second], 1).is_err(),
                "{case} 必须 fail closed"
            );
            assert_no_pair(root.path());
        }
        let root = fixture();
        write_fixture(
            root.path(),
            RECORDER_UNIT_PATH,
            b"[Unit]\nDescription=stale recorder\n\n[Service]\n",
            0o644,
        );
        assert!(record_terminal(root.path(), 1).is_err());
        assert_no_pair(root.path());
    }

    #[test]
    fn malformed_property_closures_fail_closed() {
        let recorder = RecorderView::terminal().show();
        let runtime = RuntimeView::terminal().show();
        let anomalies: [(&str, String, String); 5] = [
            (
                "缺少 Result",
                recorder.clone(),
                runtime.replace("Result=exit-code\n", ""),
            ),
            (
                "重复 ActiveState",
                recorder.clone(),
                runtime.replace("Job=\n", "Job=\nActiveState=failed\n"),
            ),
            ("额外 key", recorder.clone(), format!("{runtime}Foo=bar\n")),
            (
                "无法拆分的行",
                recorder.clone(),
                "no-separator\n".to_owned(),
            ),
            (
                "recorder 缺 RefuseManualStart",
                recorder.replace("RefuseManualStart=yes\n", ""),
                runtime,
            ),
        ];
        for (case, recorder_text, runtime_text) in anomalies {
            let root = fixture();
            let rounds = vec![
                (recorder_text.clone(), runtime_text.clone()),
                (recorder_text, runtime_text),
            ];
            assert!(
                record_runtime_failure_at(
                    root.path(),
                    unsafe { libc::geteuid() },
                    &mut Snapshots::raw(rounds),
                    &mut Generation(1),
                    RECORDER_INVOCATION,
                    std::process::id(),
                )
                .is_err(),
                "{case} 必须 fail closed"
            );
            assert_no_pair(root.path());
        }
    }

    #[test]
    fn a_repeat_notification_after_latching_keeps_the_exact_pair_unconfirmed() {
        let root = fixture();
        record_latched(root.path(), 1);
        let epoch_before = fs::read(rooted(root.path(), EPOCH_PATH)).unwrap();
        let latch_before = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();
        // 60s 窗口过期或 reset-failed 后计数归零：latch 仍在，record 不重跑确认、不产生新 generation。
        let mut expired = RuntimeView::terminal();
        expired.restart_count = "0".into();
        let mut systemd = Snapshots::observations([Observation {
            runtime: expired,
            ..Observation::terminal()
        }]);
        assert_eq!(
            record_runtime_failure_at(
                root.path(),
                unsafe { libc::geteuid() },
                &mut systemd,
                &mut Generation(9),
                RECORDER_INVOCATION,
                std::process::id(),
            )
            .unwrap(),
            RuntimeFailureRecordOutcome::AlreadyLatched
        );
        assert_eq!(systemd.waits, 0);
        assert_eq!(
            systemd.rounds.len(),
            1,
            "已有精确 pair 时不得再次查询 manager"
        );
        assert_eq!(
            fs::read(rooted(root.path(), EPOCH_PATH)).unwrap(),
            epoch_before
        );
        assert_eq!(
            fs::read(rooted(root.path(), LATCH_PATH)).unwrap(),
            latch_before
        );
    }

    #[test]
    fn an_interrupted_publication_is_not_authority() {
        for (case, missing) in [("缺 latch", LATCH_PATH), ("缺 epoch", EPOCH_PATH)] {
            let root = fixture();
            record_latched(root.path(), 2);
            let epoch_before = fs::read(rooted(root.path(), EPOCH_PATH)).unwrap();
            let latch_before = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();
            fs::remove_file(rooted(root.path(), missing)).unwrap();
            let remaining = if missing == LATCH_PATH {
                EPOCH_PATH
            } else {
                LATCH_PATH
            };
            assert!(
                record_terminal(root.path(), 3).is_err(),
                "{case} 的半途状态必须被拒绝"
            );
            assert!(
                !rooted(root.path(), missing).exists(),
                "{case} 不得被补全或产生新 authority"
            );
            let remaining_bytes = fs::read(rooted(root.path(), remaining)).unwrap();
            if missing == LATCH_PATH {
                assert_eq!(remaining_bytes, epoch_before);
            } else {
                assert_eq!(remaining_bytes, latch_before);
            }
            assert!(
                issue_installed_bundle_failure_evidence_at(
                    root.path(),
                    unsafe { libc::geteuid() },
                    &mut ObservationFake::terminal(),
                    100,
                    60_100,
                    "request_nonce_partial",
                )
                .is_err(),
                "{case} 不能签发 Evidence"
            );
            assert!(
                !installed_bundle_failure_is_current_at(
                    root.path(),
                    unsafe { libc::geteuid() },
                    &mut ObservationFake::terminal(),
                ),
                "{case} 不能授权 Repair"
            );
            let mut retry = RetrySystemd::default();
            assert!(
                retry_runtime_at(root.path(), unsafe { libc::geteuid() }, &mut retry).is_err(),
                "{case} 的 Local Retry 必须 fail closed"
            );
            assert_eq!(retry.0, 0, "{case} 不得触发任何 systemd 动作");
        }
    }

    #[test]
    fn a_changed_install_receipt_invalidates_the_latched_pair() {
        let root = fixture();
        record_latched(root.path(), 4);
        let metadata = fs::read_to_string(rooted(root.path(), METADATA_PATH))
            .unwrap()
            .replace("bundle_version = \"1.2.3\"", "bundle_version = \"9.9.9\"");
        write_fixture(root.path(), METADATA_PATH, metadata.as_bytes(), 0o600);
        assert!(
            issue_installed_bundle_failure_evidence_at(
                root.path(),
                unsafe { libc::geteuid() },
                &mut ObservationFake::terminal(),
                100,
                60_100,
                "request_nonce_reinstall",
            )
            .is_err()
        );
        assert!(!installed_bundle_failure_is_current_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut ObservationFake::terminal(),
        ));
        assert!(record_terminal(root.path(), 5).is_err());
    }

    #[test]
    fn evidence_issuance_revalidates_the_current_shape_instead_of_historical_counts() {
        let root = fixture();
        record_latched(root.path(), 5);
        let mut systemd = ObservationFake::terminal();
        let signed = issue_installed_bundle_failure_evidence_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            100,
            60_100,
            "request_nonce_current",
        )
        .unwrap();
        assert_eq!(signed.evidence.generation, "05".repeat(32));
        // 60s 窗口过期后计数归零：同一终态形状的 durable authority 保持。
        let mut expired = ObservationFake::terminal();
        expired.runtime.restart_count = "0".into();
        assert!(
            issue_installed_bundle_failure_evidence_at(
                root.path(),
                unsafe { libc::geteuid() },
                &mut expired,
                100,
                60_100,
                "request_nonce_expired",
            )
            .is_ok()
        );
        // 签发只做当前性复核：不重演跨 RestartSec 的两份观察。
        let mut single = Snapshots::terminal(1);
        assert!(
            issue_installed_bundle_failure_evidence_at(
                root.path(),
                unsafe { libc::geteuid() },
                &mut single,
                100,
                60_100,
                "request_nonce_single",
            )
            .is_ok()
        );
        assert_eq!(single.waits, 0);
        assert!(single.rounds.is_empty());
        let non_current: [RuntimeDeviation; 3] = [
            ("Runtime 已成功启动", |runtime| {
                runtime.active_state = "active".into();
                runtime.sub_state = "running".into();
                runtime.main_pid = "4242".into();
            }),
            ("reset-failed 清除了 Result", |runtime| {
                runtime.result = "success".into();
                runtime.restart_count = "0".into();
            }),
            ("仍有排队 job", |runtime| {
                runtime.job = "21 enoki-observation-runtime.service/start".into()
            }),
        ];
        for (case, mutate) in non_current {
            let mut stale = ObservationFake::terminal();
            mutate(&mut stale.runtime);
            assert!(
                issue_installed_bundle_failure_evidence_at(
                    root.path(),
                    unsafe { libc::geteuid() },
                    &mut stale,
                    100,
                    60_100,
                    "request_nonce_stale",
                )
                .is_err(),
                "{case} 时旧资格不可用"
            );
            assert!(
                !installed_bundle_failure_is_current_at(
                    root.path(),
                    unsafe { libc::geteuid() },
                    &mut stale,
                ),
                "{case} 时 Repair 不得认为资格当前"
            );
        }
    }

    #[test]
    fn local_retry_invalidates_the_generation_and_a_later_failure_starts_over() {
        let root = fixture();
        record_latched(root.path(), 6);
        let mut systemd = ObservationFake::terminal();
        let signed = issue_installed_bundle_failure_evidence_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            100,
            60_100,
            "request_nonce_before",
        )
        .unwrap();
        let authority = installed_authority(&signed, "46");
        let signature = test_hmac(
            &[0x11; 32],
            b"enoki/installed-bundle-repair-authority/hmac-sha256/v1\0",
            &authority.canonical_bytes(),
        );
        let mut retry = RetrySystemd::default();
        retry_runtime_at(root.path(), unsafe { libc::geteuid() }, &mut retry).unwrap();
        assert_eq!(retry.0, 1);
        assert!(!installed_bundle_failure_is_current_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
        ));
        assert!(matches!(
            validate_installed_bundle_repair_authority_at(
                root.path(),
                unsafe { libc::geteuid() },
                &mut systemd,
                &signed,
                &authority,
                &signature,
                101,
            ),
            Err(InstalledBundleRepairError::InvalidBoundary)
        ));
        // 清除后的一次启动失败不会复活旧 generation：必须重新走完整确认。
        let mut partial = Observation::terminal();
        partial.runtime.restart_count = "1".into();
        assert_eq!(
            record_with(root.path(), [partial, Observation::stable(1)], 7).unwrap(),
            RuntimeFailureRecordOutcome::Ignored
        );
        assert!(
            issue_installed_bundle_failure_evidence_at(
                root.path(),
                unsafe { libc::geteuid() },
                &mut systemd,
                100,
                60_100,
                "request_nonce_after",
            )
            .is_err()
        );
        record_latched(root.path(), 8);
        let reissued = issue_installed_bundle_failure_evidence_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            100,
            60_100,
            "request_nonce_new",
        )
        .unwrap();
        assert_eq!(reissued.evidence.generation, "08".repeat(32));
        assert_ne!(reissued.evidence.generation, signed.evidence.generation);
    }

    #[test]
    fn typed_local_retry_consumes_the_latch_before_one_fixed_retry() {
        let root = fixture();
        record_latched(root.path(), 4);
        let mut systemd = RetrySystemd::default();
        retry_runtime_at(root.path(), unsafe { libc::geteuid() }, &mut systemd).unwrap();
        assert_eq!(systemd.0, 1);
        assert!(!rooted(root.path(), EPOCH_PATH).exists());
        assert!(!rooted(root.path(), LATCH_PATH).exists());
    }

    #[test]
    fn signed_installed_bundle_authority_consumes_only_the_current_generation() {
        let root = fixture();
        record_latched(root.path(), 5);
        let mut systemd = ObservationFake::terminal();
        let signed = issue_installed_bundle_failure_evidence_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            100,
            60_100,
            "request_nonce_01",
        )
        .unwrap();
        let authority = InstalledBundleRepairAuthorityV1 {
            kind: signed.evidence.kind.clone(),
            schema_version: 1,
            hub_origin: signed.evidence.hub_origin.clone(),
            host_id: "7".into(),
            probe_id: signed.evidence.probe_id.clone(),
            generation: signed.evidence.generation.clone(),
            boot_id: signed.evidence.boot_id.clone(),
            unit: signed.evidence.unit.clone(),
            unit_sha256: signed.evidence.unit_sha256.clone(),
            identity_receipt_sha256: signed.evidence.identity_receipt_sha256.clone(),
            install_state_sha256: signed.evidence.install_state_sha256.clone(),
            manifest_sha256: signed.evidence.manifest_sha256.clone(),
            bundle_version: signed.evidence.bundle_version.clone(),
            target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
            repair_operation_id: "42".into(),
            repair_nonce: "repair_nonce_01".into(),
            repair_evidence_sha256: signed.evidence.sha256(),
            expires_at_ms: 60_100,
        };
        let signature = test_hmac(
            &[0x11; 32],
            b"enoki/installed-bundle-repair-authority/hmac-sha256/v1\0",
            &authority.canonical_bytes(),
        );
        let grant = validate_installed_bundle_repair_authority_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            &signed,
            &authority,
            &signature,
            101,
        )
        .unwrap();
        write_installed_bundle_repair_intent(
            root.path(),
            &InstalledBundleRepairIntent {
                schema_version: 2,
                state: InstalledBundleRepairProgress::TemporaryRuntimeHealthy,
                last_error_code: None,
                stage_owner_uid: unsafe { libc::geteuid() },
                stage_receipt: enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt {
                    operation_id: authority.repair_operation_id.clone(),
                    target_asset_set_digest: authority.target_asset_set_digest.clone(),
                    target_manifest_sha256: authority.manifest_sha256.clone(),
                    target_version: authority.bundle_version.clone(),
                    verified_stage_sha256: "b".repeat(64),
                },
                signed_evidence: signed,
                authority: authority.clone(),
                authority_signature: signature,
            },
        )
        .unwrap();
        assert_eq!(
            invalidate_installed_bundle_failure_at(
                root.path(),
                unsafe { libc::geteuid() },
                grant.authority(),
            ),
            Err(InstalledBundleRepairError::RecoveryPending)
        );
        assert!(
            !fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH))
                .unwrap()
                .contains("status = \"succeeded\"")
        );
        let mut intent: InstalledBundleRepairIntent =
            serde_json::from_slice(&fs::read(rooted(root.path(), REPAIR_INTENT_PATH)).unwrap())
                .unwrap();
        intent.state = InstalledBundleRepairProgress::ProbeActive;
        write_installed_bundle_repair_intent(root.path(), &intent).unwrap();
        invalidate_installed_bundle_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            grant.authority(),
        )
        .unwrap();
        let mut intent: InstalledBundleRepairIntent =
            serde_json::from_slice(&fs::read(rooted(root.path(), REPAIR_INTENT_PATH)).unwrap())
                .unwrap();
        assert_eq!(intent.state, InstalledBundleRepairProgress::LatchRemoved);
        assert!(
            !fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH))
                .unwrap()
                .contains("status = \"succeeded\"")
        );
        intent.state = InstalledBundleRepairProgress::CanonicalRuntimeHealthy;
        write_installed_bundle_repair_intent(root.path(), &intent).unwrap();
        let identity = publish_installed_bundle_repair_success_at(
            root.path(),
            unsafe { libc::geteuid() },
            grant.authority(),
        )
        .unwrap();
        assert_eq!(identity, ("probe_01".into(), "1.2.3".into()));
        finish_installed_bundle_repair_success_at(
            root.path(),
            unsafe { libc::geteuid() },
            grant.authority(),
        )
        .unwrap();
        assert_eq!(systemd.retry_calls, 0, "成功恢复链路不得再触发固定 Retry");
        assert!(!rooted(root.path(), LATCH_PATH).exists());
        assert_eq!(
            fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH)).unwrap(),
            "operation_id = \"42\"\ntarget_probe_version = \"1.2.3\"\nstatus = \"succeeded\"\n"
        );
    }

    #[test]
    fn failed_installed_bundle_repair_keeps_the_exact_epoch_latched_and_unresolved() {
        let root = fixture();
        record_latched(root.path(), 6);
        let epoch_before = fs::read(rooted(root.path(), EPOCH_PATH)).unwrap();
        let latch_before = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();
        let mut systemd = ObservationFake::repair_rejected();
        let signed = issue_installed_bundle_failure_evidence_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            100,
            60_100,
            "request_nonce_02",
        )
        .unwrap();
        let authority = installed_authority(&signed, "43");
        let signature = test_hmac(
            &[0x11; 32],
            b"enoki/installed-bundle-repair-authority/hmac-sha256/v1\0",
            &authority.canonical_bytes(),
        );

        let grant = validate_installed_bundle_repair_authority_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            &signed,
            &authority,
            &signature,
            101,
        )
        .unwrap();
        write_installed_bundle_repair_status(
            root.path(),
            grant.authority(),
            "failed",
            Some("lifecycle.repair_unresolved"),
        )
        .unwrap();
        assert_eq!(
            fs::read(rooted(root.path(), EPOCH_PATH)).unwrap(),
            epoch_before
        );
        assert_eq!(
            fs::read(rooted(root.path(), LATCH_PATH)).unwrap(),
            latch_before
        );
        let status = fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH)).unwrap();
        assert!(status.contains("status = \"failed\""));
        assert!(status.contains("error_code = \"lifecycle.repair_unresolved\""));
    }

    #[test]
    fn admitted_installed_bundle_repair_resumes_without_new_authority() {
        let root = fixture();
        record_latched(root.path(), 7);
        let mut systemd = ObservationFake::terminal();
        let signed = issue_installed_bundle_failure_evidence_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            100,
            60_100,
            "request_nonce_03",
        )
        .unwrap();
        let authority = installed_authority(&signed, "44");
        let signature = test_hmac(
            &[0x11; 32],
            b"enoki/installed-bundle-repair-authority/hmac-sha256/v1\0",
            &authority.canonical_bytes(),
        );
        let receipt = enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt {
            operation_id: authority.repair_operation_id.clone(),
            target_asset_set_digest: authority.target_asset_set_digest.clone(),
            target_manifest_sha256: authority.manifest_sha256.clone(),
            target_version: authority.bundle_version.clone(),
            verified_stage_sha256: "b".repeat(64),
        };
        write_installed_bundle_repair_intent(
            root.path(),
            &InstalledBundleRepairIntent {
                schema_version: 2,
                state: InstalledBundleRepairProgress::ValidationPending,
                last_error_code: None,
                stage_owner_uid: unsafe { libc::geteuid() },
                stage_receipt: receipt.clone(),
                signed_evidence: signed,
                authority: authority.clone(),
                authority_signature: signature,
            },
        )
        .unwrap();

        let resumed = resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() })
            .unwrap()
            .unwrap();
        assert_eq!(
            resumed.progress,
            InstalledBundleRepairProgress::ValidationPending
        );
        assert_eq!(resumed.stage_receipt, receipt);
        assert_eq!(resumed.grant.authority(), &authority);
        assert!(rooted(root.path(), LATCH_PATH).exists());

        let bytes = trusted_file(
            &rooted(root.path(), REPAIR_INTENT_PATH),
            unsafe { libc::geteuid() },
            0o600,
        )
        .unwrap();
        let mut healthy: InstalledBundleRepairIntent = serde_json::from_slice(&bytes).unwrap();
        healthy.state = InstalledBundleRepairProgress::TemporaryRuntimeHealthy;
        write_installed_bundle_repair_intent(root.path(), &healthy).unwrap();
        assert_eq!(
            resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() })
                .unwrap()
                .unwrap()
                .progress,
            InstalledBundleRepairProgress::TemporaryRuntimeHealthy
        );
        fs::remove_file(rooted(root.path(), EPOCH_PATH)).unwrap();
        assert_eq!(
            resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() })
                .unwrap()
                .unwrap()
                .progress,
            InstalledBundleRepairProgress::TemporaryRuntimeHealthy
        );
        healthy.stage_receipt.target_asset_set_digest = format!("sha256:{}", "c".repeat(64));
        write_installed_bundle_repair_intent(root.path(), &healthy).unwrap();
        assert!(matches!(
            resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() }),
            Err(InstalledBundleRepairError::RecoveryPending)
        ));
    }

    #[test]
    fn forward_only_repair_completion_resumes_each_invalidation_window() {
        for (index, progress) in [
            InstalledBundleRepairProgress::InvalidationCommitted,
            InstalledBundleRepairProgress::EpochRemoved,
            InstalledBundleRepairProgress::LatchRemoved,
            InstalledBundleRepairProgress::StatusPublished,
        ]
        .into_iter()
        .enumerate()
        {
            let (root, authority) = repair_completion_fixture(progress, (index + 20) as u8);
            if matches!(
                progress,
                InstalledBundleRepairProgress::EpochRemoved
                    | InstalledBundleRepairProgress::LatchRemoved
                    | InstalledBundleRepairProgress::StatusPublished
            ) {
                fs::remove_file(rooted(root.path(), EPOCH_PATH)).unwrap();
            }
            if matches!(
                progress,
                InstalledBundleRepairProgress::LatchRemoved
                    | InstalledBundleRepairProgress::StatusPublished
            ) {
                fs::remove_file(rooted(root.path(), LATCH_PATH)).unwrap();
            }
            if progress == InstalledBundleRepairProgress::StatusPublished {
                write_installed_bundle_repair_status(root.path(), &authority, "succeeded", None)
                    .unwrap();
            }
            let published_status_inode =
                (progress == InstalledBundleRepairProgress::StatusPublished).then(|| {
                    fs::metadata(rooted(root.path(), OPERATION_STATUS_PATH))
                        .unwrap()
                        .ino()
                });

            assert_eq!(
                if progress == InstalledBundleRepairProgress::StatusPublished {
                    publish_installed_bundle_repair_success_at(
                        root.path(),
                        unsafe { libc::geteuid() },
                        &authority,
                    )
                    .unwrap()
                } else {
                    invalidate_installed_bundle_failure_at(
                        root.path(),
                        unsafe { libc::geteuid() },
                        &authority,
                    )
                    .unwrap();
                    let mut intent: InstalledBundleRepairIntent = serde_json::from_slice(
                        &fs::read(rooted(root.path(), REPAIR_INTENT_PATH)).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(intent.state, InstalledBundleRepairProgress::LatchRemoved);
                    intent.state = InstalledBundleRepairProgress::CanonicalRuntimeHealthy;
                    write_installed_bundle_repair_intent(root.path(), &intent).unwrap();
                    publish_installed_bundle_repair_success_at(
                        root.path(),
                        unsafe { libc::geteuid() },
                        &authority,
                    )
                    .unwrap()
                },
                ("probe_01".into(), "1.2.3".into())
            );
            finish_installed_bundle_repair_success_at(
                root.path(),
                unsafe { libc::geteuid() },
                &authority,
            )
            .unwrap();
            assert!(!rooted(root.path(), EPOCH_PATH).exists());
            assert!(!rooted(root.path(), LATCH_PATH).exists());
            assert!(!rooted(root.path(), REPAIR_INTENT_PATH).exists());
            assert_eq!(
                fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH)).unwrap(),
                "operation_id = \"50\"\ntarget_probe_version = \"1.2.3\"\nstatus = \"succeeded\"\n"
            );
            if let Some(inode) = published_status_inode {
                assert_eq!(
                    fs::metadata(rooted(root.path(), OPERATION_STATUS_PATH))
                        .unwrap()
                        .ino(),
                    inode,
                    "status 已发布的 resume 只清理 intent，不重复执行副作用"
                );
            }
        }
    }

    #[derive(Default)]
    struct RepairEffects {
        restored: usize,
        temporary_validations: usize,
        canonical_normalizations: usize,
        canonical_activations: usize,
        canonical_validations: usize,
        final_ordinary_activations: usize,
        fail_canonical: bool,
        fail_verify: bool,
    }

    #[derive(Debug)]
    struct RepairEffectError(&'static str);

    impl InstalledBundleRepairEffects for RepairEffects {
        type Error = RepairEffectError;

        fn restore_bundle(
            &mut self,
            _: &enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
            _: u32,
            _: &InstalledBundleRepairAuthorityV1,
        ) -> Result<(), Self::Error> {
            self.restored += 1;
            Ok(())
        }

        fn validate_temporary_runtime(&mut self) -> Result<(), Self::Error> {
            self.temporary_validations += 1;
            Ok(())
        }

        fn normalize_canonical_runtime(&mut self) -> Result<(), Self::Error> {
            self.canonical_normalizations += 1;
            Ok(())
        }

        fn activate_probe_on_canonical_gate(&mut self) -> Result<(), Self::Error> {
            self.canonical_activations += 1;
            self.normalize_canonical_runtime()?;
            Ok(())
        }

        fn validate_canonical_runtime(&mut self) -> Result<(), Self::Error> {
            self.canonical_validations += 1;
            if self.fail_canonical {
                Err(RepairEffectError(
                    "probe_repair_canonical_runtime_validation_failed",
                ))
            } else {
                Ok(())
            }
        }

        fn activate_final_ordinary_probe(&mut self) -> Result<(), Self::Error> {
            self.final_ordinary_activations += 1;
            Ok(())
        }

        fn quiesce_status_published(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn recover_preboundary_reporting(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn verify_bundle_restore_complete(
            &mut self,
            _: &enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
            _: u32,
            _: &InstalledBundleRepairAuthorityV1,
        ) -> Result<(), Self::Error> {
            if self.fail_verify {
                Err(RepairEffectError("probe_repair_bundle_verification_failed"))
            } else {
                Ok(())
            }
        }

        fn retire_bundle_restore(
            &mut self,
            _: &enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
            _: u32,
            _: &InstalledBundleRepairAuthorityV1,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn remove_stage(&mut self, _: &str, _: u32) -> Result<(), Self::Error> {
            Ok(())
        }

        fn error_code<'a>(&self, error: &'a Self::Error) -> &'a str {
            error.0
        }
    }

    #[test]
    fn repair_module_resumes_every_persisted_checkpoint_through_its_interface() {
        for (index, progress) in [
            InstalledBundleRepairProgress::Admitted,
            InstalledBundleRepairProgress::ValidationPending,
            InstalledBundleRepairProgress::TemporaryRuntimeHealthy,
            InstalledBundleRepairProgress::ProbeActive,
            InstalledBundleRepairProgress::InvalidationCommitted,
            InstalledBundleRepairProgress::EpochRemoved,
            InstalledBundleRepairProgress::LatchRemoved,
            InstalledBundleRepairProgress::CanonicalRuntimeHealthy,
            InstalledBundleRepairProgress::StatusPublished,
        ]
        .into_iter()
        .enumerate()
        {
            let (root, authority) = repair_completion_fixture(progress, (index + 40) as u8);
            if matches!(
                progress,
                InstalledBundleRepairProgress::EpochRemoved
                    | InstalledBundleRepairProgress::LatchRemoved
                    | InstalledBundleRepairProgress::CanonicalRuntimeHealthy
                    | InstalledBundleRepairProgress::StatusPublished
            ) {
                fs::remove_file(rooted(root.path(), EPOCH_PATH)).unwrap();
            }
            if matches!(
                progress,
                InstalledBundleRepairProgress::LatchRemoved
                    | InstalledBundleRepairProgress::CanonicalRuntimeHealthy
                    | InstalledBundleRepairProgress::StatusPublished
            ) {
                fs::remove_file(rooted(root.path(), LATCH_PATH)).unwrap();
            }
            if progress == InstalledBundleRepairProgress::StatusPublished {
                write_installed_bundle_repair_status(root.path(), &authority, "succeeded", None)
                    .unwrap();
            }
            let session =
                resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() })
                    .unwrap()
                    .unwrap();
            let mut effects = RepairEffects::default();
            let outcome = drive_installed_bundle_repair(session, &mut effects).unwrap();

            assert_eq!(outcome.probe_id, authority.probe_id);
            assert_eq!(outcome.repaired_version, authority.bundle_version);
            assert!(!rooted(root.path(), REPAIR_INTENT_PATH).exists());
            assert!(
                fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH))
                    .unwrap()
                    .contains("status = \"succeeded\"")
            );
            assert_eq!(
                effects.canonical_validations,
                usize::from(matches!(
                    progress,
                    InstalledBundleRepairProgress::Admitted
                        | InstalledBundleRepairProgress::ValidationPending
                        | InstalledBundleRepairProgress::TemporaryRuntimeHealthy
                        | InstalledBundleRepairProgress::ProbeActive
                        | InstalledBundleRepairProgress::InvalidationCommitted
                        | InstalledBundleRepairProgress::EpochRemoved
                        | InstalledBundleRepairProgress::LatchRemoved
                )),
                "成功只能由 latch 移除后的 canonical Runtime 验证产生"
            );
            assert_eq!(
                effects.canonical_normalizations,
                usize::from(matches!(
                    progress,
                    InstalledBundleRepairProgress::Admitted
                        | InstalledBundleRepairProgress::ValidationPending
                        | InstalledBundleRepairProgress::TemporaryRuntimeHealthy
                        | InstalledBundleRepairProgress::ProbeActive
                        | InstalledBundleRepairProgress::InvalidationCommitted
                        | InstalledBundleRepairProgress::EpochRemoved
                        | InstalledBundleRepairProgress::LatchRemoved
                )),
                "进入 forward-only 前或后均先恢复 canonical-validation shape"
            );
            assert_eq!(
                effects.final_ordinary_activations, 1,
                "intent 退休前必须完成最终 ordinary Probe 激活"
            );
        }
    }

    #[test]
    fn upgrader_adapter_cannot_observe_or_drive_private_repair_checkpoints() {
        let upgrader = include_str!("upgrader.rs");
        assert!(upgrader.contains("drive_live_installed_bundle_repair"));
        for private_detail in [
            "InstalledBundleRepairProgress",
            "mark_validation_pending",
            "mark_temporary_runtime_healthy",
            "mark_probe_active",
            "mark_canonical_runtime_healthy",
            "invalidate_failure_evidence",
            "publish_success",
        ] {
            assert!(
                !upgrader.contains(private_detail),
                "upgrader Adapter 不得观察 Repair 私有 checkpoint：{private_detail}"
            );
        }
    }

    #[test]
    fn canonical_runtime_failure_after_latch_removal_stays_forward_only_and_resumes() {
        let (root, _authority) =
            repair_completion_fixture(InstalledBundleRepairProgress::LatchRemoved, 61);
        fs::remove_file(rooted(root.path(), EPOCH_PATH)).unwrap();
        fs::remove_file(rooted(root.path(), LATCH_PATH)).unwrap();
        let session = resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() })
            .unwrap()
            .unwrap();
        let mut failed = RepairEffects {
            fail_canonical: true,
            ..RepairEffects::default()
        };
        assert!(matches!(
            drive_installed_bundle_repair(session, &mut failed),
            Err(InstalledBundleRepairDriveError::Effect(RepairEffectError(
                "probe_repair_canonical_runtime_validation_failed"
            )))
        ));
        let intent: InstalledBundleRepairIntent =
            serde_json::from_slice(&fs::read(rooted(root.path(), REPAIR_INTENT_PATH)).unwrap())
                .unwrap();
        assert_eq!(intent.state, InstalledBundleRepairProgress::LatchRemoved);
        assert_eq!(
            intent.last_error_code.as_deref(),
            Some("probe_repair_canonical_runtime_validation_failed")
        );
        assert!(
            !fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH))
                .is_ok_and(|status| status.contains("status = \"succeeded\""))
        );

        let resumed = resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() })
            .unwrap()
            .unwrap();
        drive_installed_bundle_repair(resumed, &mut RepairEffects::default()).unwrap();
        assert!(!rooted(root.path(), REPAIR_INTENT_PATH).exists());
        assert!(
            fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH))
                .unwrap()
                .contains("status = \"succeeded\"")
        );
    }

    #[test]
    fn exact_bundle_verification_failure_never_publishes_succeeded() {
        let (root, _) =
            repair_completion_fixture(InstalledBundleRepairProgress::CanonicalRuntimeHealthy, 63);
        fs::remove_file(rooted(root.path(), EPOCH_PATH)).unwrap();
        fs::remove_file(rooted(root.path(), LATCH_PATH)).unwrap();
        let session = resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() })
            .unwrap()
            .unwrap();
        assert!(matches!(
            drive_installed_bundle_repair(
                session,
                &mut RepairEffects {
                    fail_verify: true,
                    ..RepairEffects::default()
                }
            ),
            Err(InstalledBundleRepairDriveError::Effect(RepairEffectError(
                "probe_repair_bundle_verification_failed"
            )))
        ));
        assert!(rooted(root.path(), REPAIR_INTENT_PATH).exists());
        assert!(
            !fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH))
                .is_ok_and(|status| status.contains("status = \"succeeded\""))
        );
    }

    #[test]
    fn postcommit_invalidation_error_persists_exact_error_without_publishing_failed() {
        let (root, _authority) =
            repair_completion_fixture(InstalledBundleRepairProgress::ProbeActive, 62);
        let epoch_path = rooted(root.path(), EPOCH_PATH);
        let epoch_bytes = fs::read(&epoch_path).unwrap();
        let session = resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() })
            .unwrap()
            .unwrap();
        let mut epoch: RuntimeFailureEpoch =
            toml::from_str(std::str::from_utf8(&epoch_bytes).unwrap()).unwrap();
        epoch.generation = "f".repeat(64);
        write_fixture(
            root.path(),
            EPOCH_PATH,
            toml::to_string(&epoch).unwrap().as_bytes(),
            0o600,
        );

        assert!(matches!(
            drive_installed_bundle_repair(session, &mut RepairEffects::default()),
            Err(InstalledBundleRepairDriveError::RecoveryPending(
                "probe_repair_completion_persist_failed"
            ))
        ));
        let intent: InstalledBundleRepairIntent =
            serde_json::from_slice(&fs::read(rooted(root.path(), REPAIR_INTENT_PATH)).unwrap())
                .unwrap();
        assert_eq!(
            intent.state,
            InstalledBundleRepairProgress::InvalidationCommitted
        );
        assert_eq!(
            intent.last_error_code.as_deref(),
            Some("probe_repair_completion_persist_failed")
        );
        assert!(
            !fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH))
                .is_ok_and(|status| status.contains("status = \"failed\""))
        );

        write_fixture(root.path(), EPOCH_PATH, &epoch_bytes, 0o600);
        let resumed = resume_installed_bundle_repair_at(root.path(), unsafe { libc::geteuid() })
            .unwrap()
            .unwrap();
        drive_installed_bundle_repair(resumed, &mut RepairEffects::default()).unwrap();
        assert!(!rooted(root.path(), REPAIR_INTENT_PATH).exists());
    }

    pub(super) fn repair_completion_fixture(
        progress: InstalledBundleRepairProgress,
        generation_byte: u8,
    ) -> (tempfile::TempDir, InstalledBundleRepairAuthorityV1) {
        let root = fixture();
        record_latched(root.path(), generation_byte);
        let signed = issue_installed_bundle_failure_evidence_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut ObservationFake::terminal(),
            100,
            60_100,
            "request_nonce_04",
        )
        .unwrap();
        let authority = installed_authority(&signed, "50");
        let signature = test_hmac(
            &[0x11; 32],
            b"enoki/installed-bundle-repair-authority/hmac-sha256/v1\0",
            &authority.canonical_bytes(),
        );
        write_installed_bundle_repair_intent(
            root.path(),
            &InstalledBundleRepairIntent {
                schema_version: 2,
                state: progress,
                last_error_code: None,
                stage_owner_uid: unsafe { libc::geteuid() },
                stage_receipt: enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt {
                    operation_id: authority.repair_operation_id.clone(),
                    target_asset_set_digest: authority.target_asset_set_digest.clone(),
                    target_manifest_sha256: authority.manifest_sha256.clone(),
                    target_version: authority.bundle_version.clone(),
                    verified_stage_sha256: "b".repeat(64),
                },
                signed_evidence: signed,
                authority: authority.clone(),
                authority_signature: signature,
            },
        )
        .unwrap();
        (root, authority)
    }

    /// R51-3 唯一切点的初始化：在正式 DynamicUser（public 精确 symlink 到 private）布局上，
    /// 沿 recorder→Evidence→Authority→begin 链取得 intent。intent 只可能由 begin 落盘，
    /// 因此该载体同时证明保管位置、签名 authority 与 Admitted checkpoint 同源。
    pub(super) fn formal_begin_installed_bundle_repair_at_canonical_layout(
        generation_byte: u8,
        operation_id: &str,
    ) -> tempfile::TempDir {
        let root = canonical_dynamic_user_fixture();
        record_latched(root.path(), generation_byte);
        let mut systemd = ObservationFake::terminal();
        let signed = issue_installed_bundle_failure_evidence_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            100,
            60_100,
            "request_nonce_05",
        )
        .unwrap();
        let authority = installed_authority(&signed, operation_id);
        let signature = test_hmac(
            &[0x11; 32],
            b"enoki/installed-bundle-repair-authority/hmac-sha256/v1\0",
            &authority.canonical_bytes(),
        );
        let grant = validate_installed_bundle_repair_authority_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            &signed,
            &authority,
            &signature,
            101,
        )
        .unwrap();
        let stage_receipt = enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt {
            operation_id: authority.repair_operation_id.clone(),
            target_asset_set_digest: authority.target_asset_set_digest.clone(),
            target_manifest_sha256: authority.manifest_sha256.clone(),
            target_version: authority.bundle_version.clone(),
            verified_stage_sha256: "b".repeat(64),
        };
        begin_installed_bundle_repair(grant, stage_receipt, unsafe { libc::geteuid() }).unwrap();
        root
    }

    fn installed_authority(
        signed: &SignedInstalledBundleFailureEvidence,
        operation_id: &str,
    ) -> InstalledBundleRepairAuthorityV1 {
        InstalledBundleRepairAuthorityV1 {
            kind: signed.evidence.kind.clone(),
            schema_version: 1,
            hub_origin: signed.evidence.hub_origin.clone(),
            host_id: "7".into(),
            probe_id: signed.evidence.probe_id.clone(),
            generation: signed.evidence.generation.clone(),
            boot_id: signed.evidence.boot_id.clone(),
            unit: signed.evidence.unit.clone(),
            unit_sha256: signed.evidence.unit_sha256.clone(),
            identity_receipt_sha256: signed.evidence.identity_receipt_sha256.clone(),
            install_state_sha256: signed.evidence.install_state_sha256.clone(),
            manifest_sha256: signed.evidence.manifest_sha256.clone(),
            bundle_version: signed.evidence.bundle_version.clone(),
            target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
            repair_operation_id: operation_id.into(),
            repair_nonce: "repair_nonce_01".into(),
            repair_evidence_sha256: signed.evidence.sha256(),
            expires_at_ms: 60_100,
        }
    }

    fn test_hmac(key: &[u8; 32], domain: &[u8], canonical: &[u8]) -> String {
        let mut inner_pad = [0x36_u8; 64];
        let mut outer_pad = [0x5c_u8; 64];
        for (index, byte) in key.iter().enumerate() {
            inner_pad[index] ^= byte;
            outer_pad[index] ^= byte;
        }
        let inner = Sha256::new()
            .chain_update(inner_pad)
            .chain_update(domain)
            .chain_update(canonical)
            .finalize();
        hex(&Sha256::new()
            .chain_update(outer_pad)
            .chain_update(inner)
            .finalize())
    }

    /// 正式 DynamicUser 安装布局：public 是 root 单链接 symlink，状态与 child 都在固定 private 根。
    fn canonical_dynamic_user_fixture() -> tempfile::TempDir {
        let root = fixture();
        let public = rooted(root.path(), "/var/lib/enoki-probe");
        let private = rooted(root.path(), "/var/lib/private/enoki-probe");
        fs::create_dir_all(private.join("identity")).unwrap();
        fs::rename(public.join("identity"), private.join("identity")).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o750)).unwrap();
        fs::remove_dir(&public).unwrap();
        std::os::unix::fs::symlink("private/enoki-probe", &public).unwrap();
        root
    }

    #[test]
    fn canonical_dynamic_user_layout_publishes_and_consumes_the_private_exact_pair() {
        let root = canonical_dynamic_user_fixture();
        assert_eq!(
            concrete_state_root(root.path()).unwrap(),
            rooted(root.path(), "/var/lib/private/enoki-probe"),
            "canonical 单链接 symlink 必须解析到固定 private 根"
        );
        record_latched(root.path(), 3);
        assert!(
            rooted(root.path(), EPOCH_PATH).is_file(),
            "canonical 布局的 recorder 必须把 exact pair 发布在固定 root failure child"
        );
        assert!(
            rooted(root.path(), LATCH_PATH).is_file(),
            "latch 与 epoch 共用同一固定 failure 根"
        );
        assert!(
            !private_failure_pair_present(root.path()),
            "canonical 布局不再把故障 pair 放在 Probe private 状态根 child"
        );
        let mut retry = RetrySystemd::default();
        retry_runtime_at(root.path(), unsafe { libc::geteuid() }, &mut retry).unwrap();
        assert_eq!(retry.0, 1);
    }

    fn private_failure_pair_present(root: &Path) -> bool {
        let private = rooted(root, CANONICAL_PRIVATE_STATE_ROOT).join(FAILURE_DIR_NAME);
        private.join(EPOCH_NAME).is_file() || private.join(LATCH_NAME).is_file()
    }

    #[test]
    fn canonical_dynamic_user_rejects_an_unknown_symlink_target_before_any_query_or_write() {
        let root = canonical_dynamic_user_fixture();
        let public = rooted(root.path(), "/var/lib/enoki-probe");
        fs::remove_file(&public).unwrap();
        std::os::unix::fs::symlink("private/enoki-probe-evil", &public).unwrap();
        record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut Snapshots::terminal(2),
            &mut Generation(4),
            RECORDER_INVOCATION,
            std::process::id(),
        )
        .expect_err("unknown canonical symlink target 必须在查询／写入前拒绝");
    }

    /// R51-2 正项：D9 的每个 producer／consumer 入口都必须解析到同一个 root 保管
    /// failure 位置，而 identity／operation status 继续走各自 concrete 状态根投影；
    /// ordinary 与 canonical 两种布局复用同一结论，不各自另立路径。
    #[test]
    fn every_custody_entrypoint_resolves_to_the_root_failure_location_in_both_layouts() {
        let uid = unsafe { libc::geteuid() };
        let ordinary = fixture();
        let canonical = canonical_dynamic_user_fixture();
        for root in [ordinary.path(), canonical.path()] {
            let fixed = rooted(root, BOOTSTRAP_STATE_ROOT).join(FAILURE_DIR_NAME);
            let paths = runtime_failure_paths(root, uid).unwrap();
            assert_eq!(
                paths.failure_dir, fixed,
                "failure 根必须是 bootstrap 根下唯一 child"
            );
            assert_eq!(paths.epoch, fixed.join(EPOCH_NAME));
            assert_eq!(paths.latch, fixed.join(LATCH_NAME));
            for name in [EPOCH_NAME, LATCH_NAME, REPAIR_INTENT_NAME] {
                assert_eq!(
                    fixed_failure_child(root, uid, name).unwrap(),
                    fixed.join(name),
                    "producer／consumer 共用同一固定 child"
                );
            }
            assert_eq!(rooted(root, EPOCH_PATH), fixed.join(EPOCH_NAME));
            assert_eq!(rooted(root, LATCH_PATH), fixed.join(LATCH_NAME));
            assert_eq!(
                rooted(root, REPAIR_INTENT_PATH),
                fixed.join(REPAIR_INTENT_NAME)
            );
            assert!(
                !paths.identity.starts_with(&fixed),
                "identity 不得随故障保管一起搬进 root failure 根"
            );
            assert!(
                !state_child(root, OPERATION_STATUS_PATH)
                    .unwrap()
                    .starts_with(&fixed),
                "Probe operation status 不得搬进 root failure 根"
            );
            assert!(
                !rooted(root, STATE_ROOT_PUBLIC)
                    .join(FAILURE_DIR_NAME)
                    .exists()
                    && !rooted(root, CANONICAL_PRIVATE_STATE_ROOT)
                        .join(FAILURE_DIR_NAME)
                        .exists(),
                "两种布局都不再在 Probe 状态根内保管故障 child"
            );
        }
        // ordinary：identity／status 留在 public 本体；canonical：两者留在固定 private 根。
        let ordinary_paths = runtime_failure_paths(ordinary.path(), uid).unwrap();
        assert_eq!(
            ordinary_paths.identity,
            rooted(ordinary.path(), IDENTITY_PATH)
        );
        assert_eq!(
            state_child(ordinary.path(), OPERATION_STATUS_PATH).unwrap(),
            rooted(ordinary.path(), OPERATION_STATUS_PATH)
        );
        let canonical_paths = runtime_failure_paths(canonical.path(), uid).unwrap();
        let private = rooted(canonical.path(), CANONICAL_PRIVATE_STATE_ROOT);
        assert_eq!(canonical_paths.identity, private.join(IDENTITY_SUFFIX));
        assert_eq!(
            state_child(canonical.path(), OPERATION_STATUS_PATH).unwrap(),
            private.join("probe-operation-status.toml")
        );
        assert_eq!(
            canonical_paths.failure_dir,
            rooted(canonical.path(), BOOTSTRAP_STATE_ROOT).join(FAILURE_DIR_NAME),
            "canonical 布局的故障保管不跟随 private 投影"
        );
    }

    /// R51-2 负项（单一聚合）：root 保管位置的归属或形态一旦被破坏，全部入口必须在任何
    /// systemd 查询与任何写入之前拒绝，并且不得回退到 Probe 状态根另建故障数据。
    #[test]
    fn a_misplaced_root_custody_is_rejected_by_every_entrypoint_without_fallback_writes() {
        enum Deviation {
            ForeignParentOwner,
            GroupWritableParent,
            WorldWritableParent,
            ParentReplacedBySymlink,
            ChildModeTooPermissive,
            ChildReplacedBySymlink,
        }
        let uid = unsafe { libc::geteuid() };
        for deviation in [
            Deviation::ForeignParentOwner,
            Deviation::GroupWritableParent,
            Deviation::WorldWritableParent,
            Deviation::ParentReplacedBySymlink,
            Deviation::ChildModeTooPermissive,
            Deviation::ChildReplacedBySymlink,
        ] {
            let root = fixture();
            let parent = rooted(root.path(), BOOTSTRAP_STATE_ROOT);
            let child = parent.join(FAILURE_DIR_NAME);
            match deviation {
                Deviation::ForeignParentOwner => chown_fixture(&parent, 65_534, 65_534),
                Deviation::GroupWritableParent => {
                    fs::set_permissions(&parent, fs::Permissions::from_mode(0o720)).unwrap();
                }
                Deviation::WorldWritableParent => {
                    fs::set_permissions(&parent, fs::Permissions::from_mode(0o707)).unwrap();
                }
                Deviation::ParentReplacedBySymlink => {
                    let real = parent.clone();
                    let target = rooted(root.path(), "/var/lib/bootstrap-relocation");
                    fs::create_dir_all(&target).unwrap();
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
                    fs::remove_dir(&real).unwrap();
                    std::os::unix::fs::symlink("../bootstrap-relocation", &real).unwrap();
                }
                Deviation::ChildModeTooPermissive => {
                    fs::create_dir(&child).unwrap();
                    fs::set_permissions(&child, fs::Permissions::from_mode(0o755)).unwrap();
                }
                Deviation::ChildReplacedBySymlink => {
                    let target = rooted(root.path(), "/var/lib/enoki-probe/runtime-failure");
                    fs::create_dir(&target).unwrap();
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
                    std::os::unix::fs::symlink("../enoki-probe/runtime-failure", child.as_path())
                        .unwrap();
                }
            }

            assert!(
                record_runtime_failure_at(
                    root.path(),
                    uid,
                    &mut Snapshots::terminal(2),
                    &mut Generation(1),
                    RECORDER_INVOCATION,
                    std::process::id(),
                )
                .is_err(),
                "错误保管根下 recorder 必须拒绝"
            );
            assert!(
                current_epoch_at(root.path(), uid).is_err(),
                "错误保管根下 consumer 必须拒绝"
            );
            assert!(
                fixed_failure_child(root.path(), uid, REPAIR_INTENT_NAME).is_err(),
                "错误保管根下 Repair intent 必须拒绝"
            );
            assert!(
                retry_runtime_at(root.path(), uid, &mut RetrySystemd::default()).is_err(),
                "错误保管根下 Local Retry 必须拒绝"
            );
            assert!(matches!(
                resume_installed_bundle_repair_at(root.path(), uid),
                Err(InstalledBundleRepairError::RecoveryPending)
            ));
            assert_no_pair(root.path());
            // 拒绝不得以“换个地方另建数据”为代价：Probe 状态根内即使存在 child 也必须为空。
            for candidate in [
                rooted(root.path(), STATE_ROOT_PUBLIC).join(FAILURE_DIR_NAME),
                rooted(root.path(), CANONICAL_PRIVATE_STATE_ROOT).join(FAILURE_DIR_NAME),
            ] {
                if let Ok(mut children) = fs::read_dir(&candidate) {
                    assert!(
                        children.next().is_none(),
                        "被拒的保管根不得留下回退数据：{}",
                        candidate.display()
                    );
                }
            }
        }
    }

    fn chown_fixture(path: &Path, uid: u32, gid: u32) {
        let target = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(target.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) },
            0,
            "夹具 chown 必须成功"
        );
    }

    #[test]
    fn current_boot_reader_keeps_size_zero_pseudo_file_readable_although_trusted_file_stays_disk() {
        let host = Path::new(HOST_BOOT_ID_PATH);
        let metadata = fs::symlink_metadata(host).unwrap();
        assert!(
            metadata.is_file() && metadata.len() == 0,
            "宿主 boot 输入必须仍是报告 size=0 的伪文件"
        );
        // 通用 trusted_file 保持原磁盘文件语义：以 st_size 相等为准，size-0 伪文件被拒绝。
        assert!(
            trusted_file(host, 0, 0o444).is_err(),
            "trusted_file 不得被放宽以迁就伪文件"
        );
        // 专用 bounded reader 不比较 st_size：同一固定 host 来源必须可读且非空。
        let boot_id =
            trusted_fixed_boot_id(Path::new("/"), 0, FixedBootIdSource::HostProc).unwrap();
        assert!(
            !boot_id.is_empty(),
            "固定的当前 boot 输入必须可读出合法 boot id"
        );
    }
}
