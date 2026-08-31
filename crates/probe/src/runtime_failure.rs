//! Observation Runtime 启动预算耗尽的固定 recorder 与终止性 latch。

use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use enoki_probe_bootstrap::lifecycle::{
    InstalledBundleFailureEvidenceV1, InstalledBundleRepairAuthorityV1,
};

use crate::secure_file::{atomic_write, ensure_directory, remove_regular_file};

const RUNTIME_UNIT: &str = "enoki-observation-runtime.service";
const METADATA_PATH: &str = "/etc/enoki/probe-install.toml";
const IDENTITY_PATH: &str = "/var/lib/enoki-probe/identity/probe-bootstrap.toml";
const UNIT_PATH: &str = "/etc/systemd/system/enoki-observation-runtime.service";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const FAILURE_DIR: &str = "/var/lib/enoki-probe/runtime-failure";
const EPOCH_PATH: &str = "/var/lib/enoki-probe/runtime-failure/epoch.toml";
const LATCH_PATH: &str = "/var/lib/enoki-probe/runtime-failure/latch";
const PAIR_LOCK_PATH: &str = "/run/enoki-probe/runtime-failure-pair.lock";
const LOCAL_RETRY_RECEIPT_PATH: &str =
    "/var/lib/enoki-probe/runtime-failure/local-retry-receipt.json";
const UPGRADE_ATTEMPT_PATH: &str = "/var/lib/enoki-probe-bootstrap/probe-upgrade-attempt.toml";

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeUnitState {
    pub active_state: String,
    pub result: String,
}

pub trait RuntimeFailureSystemd {
    fn fixed_runtime_state(&mut self) -> std::io::Result<RuntimeUnitState>;
}

pub struct SystemRuntimeFailureSystemd;

impl RuntimeFailureSystemd for SystemRuntimeFailureSystemd {
    fn fixed_runtime_state(&mut self) -> std::io::Result<RuntimeUnitState> {
        let output = Command::new("/usr/bin/systemctl")
            .args(["show", RUNTIME_UNIT, "--property=ActiveState,Result"])
            .output()?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(std::io::Error::other("systemd state unavailable"));
        }
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| std::io::Error::other("systemd state invalid"))?;
        let mut active_state = None;
        let mut result = None;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("ActiveState=") {
                active_state = Some(value.to_owned());
            } else if let Some(value) = line.strip_prefix("Result=") {
                result = Some(value.to_owned());
            } else {
                return Err(std::io::Error::other("systemd state invalid"));
            }
        }
        let active_state = active_state
            .filter(|value| !value.is_empty())
            .ok_or_else(|| std::io::Error::other("systemd state invalid"))?;
        let result = result
            .filter(|value| !value.is_empty())
            .ok_or_else(|| std::io::Error::other("systemd state invalid"))?;
        Ok(RuntimeUnitState {
            active_state,
            result,
        })
    }
}

pub trait RuntimeRetrySystemd: RuntimeFailureSystemd {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum LocalRetryProgress {
    Committed,
    EpochRemoved,
    LatchRemoved,
    RetryInvoked,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalRetryReceipt {
    schema_version: u16,
    generation: String,
    epoch_sha256: String,
    progress: LocalRetryProgress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpgradeRuntimeFailureProgress {
    None,
    NoneConsumed,
    Bound,
    EpochRemoved,
    LatchRemoved,
}

#[derive(Debug)]
struct UpgradeRuntimeFailureIntent {
    phase: String,
    progress: Option<UpgradeRuntimeFailureProgress>,
    generation: Option<String>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalRetryCrashPoint {
    ReceiptCommitted,
    EpochUnlinked,
    EpochRemovedReceipt,
    LatchUnlinked,
    LatchRemovedReceipt,
    SystemdInvoked,
}

#[cfg(test)]
thread_local! {
    static LOCAL_RETRY_CRASH_POINT: std::cell::Cell<Option<LocalRetryCrashPoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn fail_local_retry_after(point: LocalRetryCrashPoint) {
    LOCAL_RETRY_CRASH_POINT.set(Some(point));
}

#[cfg(test)]
fn local_retry_crash_after(point: LocalRetryCrashPoint) -> std::io::Result<()> {
    if LOCAL_RETRY_CRASH_POINT.get() == Some(point) {
        LOCAL_RETRY_CRASH_POINT.set(None);
        return Err(std::io::Error::other("injected abrupt local retry exit"));
    }
    Ok(())
}

/// The OS releases this guard after an abrupt process exit.  Recovery never
/// interprets the lock as a durable fact; it only serializes one short pair
/// transition against recorder, evidence, and typed consumers.
pub(crate) struct RuntimeFailurePairLock {
    _file: File,
}

pub(crate) fn acquire_runtime_failure_pair_lock_for_state(
    state_dir: &Path,
    expected_uid: u32,
) -> std::io::Result<RuntimeFailurePairLock> {
    let path = runtime_failure_pair_lock_path_for_state(state_dir)?;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("runtime failure lock path invalid"))?;
    ensure_directory(parent, 0o700, Some((expected_uid, expected_uid)))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != expected_uid
        || parent_metadata.mode() & 0o7777 != 0o700
    {
        return Err(std::io::Error::other("runtime failure lock parent invalid"));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.uid() != expected_uid
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
    {
        return Err(std::io::Error::other(
            "runtime failure lock boundary invalid",
        ));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(RuntimeFailurePairLock { _file: file })
}

pub(crate) fn acquire_runtime_failure_pair_cleanup_lock_for_state(
    state_dir: &Path,
    expected_uid: u32,
) -> std::io::Result<RuntimeFailurePairLock> {
    let lock = acquire_runtime_failure_pair_lock_for_state(state_dir, expected_uid)?;
    let failure_dir = state_dir.join("runtime-failure");
    let metadata = match fs::symlink_metadata(&failure_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(lock),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(std::io::Error::other(
            "runtime failure cleanup boundary invalid",
        ));
    }
    let directory = File::open(&failure_dir)?;
    for name in ["epoch.toml", "latch"] {
        match fs::remove_file(failure_dir.join(name)) {
            Ok(()) => directory.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(lock)
}

pub(crate) fn runtime_failure_pair_lock_path_for_state(
    state_dir: &Path,
) -> std::io::Result<PathBuf> {
    let root = if state_dir.ends_with("var/lib/enoki-probe") {
        state_dir
            .ancestors()
            .nth(3)
            .ok_or_else(|| std::io::Error::other("Probe state path invalid"))?
    } else {
        state_dir
            .parent()
            .ok_or_else(|| std::io::Error::other("Probe state path invalid"))?
    };
    Ok(root.join(PAIR_LOCK_PATH.trim_start_matches('/')))
}

fn acquire_runtime_failure_pair_lock_at(
    root: &Path,
    expected_uid: u32,
) -> std::io::Result<RuntimeFailurePairLock> {
    debug_assert_eq!(
        rooted(root, PAIR_LOCK_PATH),
        runtime_failure_pair_lock_path_for_state(&rooted(root, "/var/lib/enoki-probe"))?
    );
    acquire_runtime_failure_pair_lock_for_state(&rooted(root, "/var/lib/enoki-probe"), expected_uid)
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
    record_runtime_failure_at(
        Path::new("/"),
        0,
        &mut SystemRuntimeFailureSystemd,
        &mut KernelFailureGenerationSource,
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
    let _lock = acquire_runtime_failure_pair_lock_at(root, expected_uid)?;
    let epoch_path = rooted(root, EPOCH_PATH);
    let latch_path = rooted(root, LATCH_PATH);
    let receipt_path = rooted(root, LOCAL_RETRY_RECEIPT_PATH);
    let epoch_present = path_present(&epoch_path)?;
    let latch_present = path_present(&latch_path)?;
    let mut receipt = if path_present(&receipt_path)? {
        let bytes = trusted_file(&receipt_path, expected_uid, 0o600)?;
        parse_local_retry_receipt(&bytes)?
    } else {
        if !epoch_present && !latch_present {
            if runtime_failure_creation_reserved_at(root, expected_uid)? {
                return Err(std::io::Error::other("failure pair creation reserved"));
            }
            return systemd.retry_fixed_runtime();
        }
        let state = systemd.fixed_runtime_state()?;
        if state.active_state != "failed" || state.result != "start-limit-hit" {
            return Err(std::io::Error::other("failure pair is not terminal"));
        }
        match (epoch_present, latch_present) {
            (true, false) => {
                let (epoch, _, _) = current_epoch_binding_at(root, expected_uid)?;
                if runtime_failure_consumption_pending_at(root, expected_uid, &epoch.generation)?
                    || runtime_failure_creation_reserved_at(root, expected_uid)?
                {
                    return Err(std::io::Error::other("failure pair consumption pending"));
                }
                atomic_write(
                    &latch_path,
                    epoch.generation.as_bytes(),
                    0o600,
                    Some((expected_uid, expected_uid)),
                )?;
            }
            (false, true) => {
                let latch = trusted_file(&latch_path, expected_uid, 0o600)?;
                let generation = std::str::from_utf8(&latch)
                    .ok()
                    .filter(|value| decode_lower_hex_32(value).is_some())
                    .ok_or_else(|| std::io::Error::other("failure latch invalid"))?;
                if runtime_failure_consumption_pending_at(root, expected_uid, generation)?
                    || runtime_failure_creation_reserved_at(root, expected_uid)?
                {
                    return Err(std::io::Error::other("failure pair consumption pending"));
                }
                let epoch = build_current_epoch(root, expected_uid, &state, generation)?;
                let encoded = toml::to_string(&epoch)
                    .map_err(|_| std::io::Error::other("failure epoch invalid"))?;
                atomic_write(
                    &epoch_path,
                    encoded.as_bytes(),
                    0o600,
                    Some((expected_uid, expected_uid)),
                )?;
            }
            (true, true) => {}
            (false, false) => unreachable!(),
        }
        let (epoch, _, epoch_bytes) = current_epoch_at_locked(root, expected_uid)?;
        if runtime_failure_consumption_pending_at(root, expected_uid, &epoch.generation)?
            || runtime_failure_creation_reserved_at(root, expected_uid)?
        {
            return Err(std::io::Error::other("failure pair consumption pending"));
        }
        let receipt = LocalRetryReceipt {
            schema_version: 1,
            generation: epoch.generation,
            epoch_sha256: sha256(&epoch_bytes),
            progress: LocalRetryProgress::Committed,
        };
        write_local_retry_receipt(root, expected_uid, &receipt)?;
        #[cfg(test)]
        local_retry_crash_after(LocalRetryCrashPoint::ReceiptCommitted)?;
        receipt
    };

    if receipt.progress == LocalRetryProgress::RetryInvoked {
        if path_present(&epoch_path)? || path_present(&latch_path)? {
            return Err(std::io::Error::other("local retry receipt binding invalid"));
        }
        return systemd.retry_fixed_runtime();
    }

    if receipt.progress == LocalRetryProgress::Committed {
        let epoch_present = path_present(&epoch_path)?;
        let latch_present = path_present(&latch_path)?;
        if epoch_present {
            let (epoch, _, epoch_bytes) = current_epoch_binding_at(root, expected_uid)?;
            if !latch_present {
                return Err(std::io::Error::other("local retry receipt binding invalid"));
            }
            let latch = trusted_file(&latch_path, expected_uid, 0o600)?;
            if epoch.generation != receipt.generation
                || sha256(&epoch_bytes) != receipt.epoch_sha256
                || latch != receipt.generation.as_bytes()
            {
                return Err(std::io::Error::other("local retry receipt binding invalid"));
            }
            remove_regular_file(&epoch_path, 0o600, Some((expected_uid, expected_uid)))?;
            #[cfg(test)]
            local_retry_crash_after(LocalRetryCrashPoint::EpochUnlinked)?;
        } else if latch_present {
            let latch = trusted_file(&latch_path, expected_uid, 0o600)?;
            if latch != receipt.generation.as_bytes() {
                return Err(std::io::Error::other("local retry receipt binding invalid"));
            }
        }
        receipt.progress = LocalRetryProgress::EpochRemoved;
        write_local_retry_receipt(root, expected_uid, &receipt)?;
        #[cfg(test)]
        local_retry_crash_after(LocalRetryCrashPoint::EpochRemovedReceipt)?;
    }

    if receipt.progress == LocalRetryProgress::EpochRemoved {
        if path_present(&epoch_path)? {
            return Err(std::io::Error::other("local retry receipt binding invalid"));
        }
        match trusted_file(&latch_path, expected_uid, 0o600) {
            Ok(latch) if latch == receipt.generation.as_bytes() => {
                remove_regular_file(&latch_path, 0o600, Some((expected_uid, expected_uid)))?;
                #[cfg(test)]
                local_retry_crash_after(LocalRetryCrashPoint::LatchUnlinked)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(std::io::Error::other("local retry receipt binding invalid")),
        }
        receipt.progress = LocalRetryProgress::LatchRemoved;
        write_local_retry_receipt(root, expected_uid, &receipt)?;
        #[cfg(test)]
        local_retry_crash_after(LocalRetryCrashPoint::LatchRemovedReceipt)?;
    }

    if receipt.progress != LocalRetryProgress::LatchRemoved {
        return Err(std::io::Error::other("local retry recovery invalid"));
    }
    let retry_result = systemd.retry_fixed_runtime();
    #[cfg(test)]
    local_retry_crash_after(LocalRetryCrashPoint::SystemdInvoked)?;
    receipt.progress = LocalRetryProgress::RetryInvoked;
    write_local_retry_receipt(root, expected_uid, &receipt)?;
    retry_result
}

fn path_present(path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn write_local_retry_receipt(
    root: &Path,
    expected_uid: u32,
    receipt: &LocalRetryReceipt,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(receipt)
        .map_err(|_| std::io::Error::other("local retry receipt invalid"))?;
    atomic_write(
        &rooted(root, LOCAL_RETRY_RECEIPT_PATH),
        &bytes,
        0o600,
        Some((expected_uid, expected_uid)),
    )
}

fn issue_installed_bundle_failure_evidence_at(
    root: &Path,
    expected_uid: u32,
    systemd: &mut impl RuntimeFailureSystemd,
    issued_at_ms: u64,
    expires_at_ms: u64,
    request_nonce: &str,
) -> std::io::Result<SignedInstalledBundleFailureEvidence> {
    let _lock = acquire_runtime_failure_pair_lock_at(root, expected_uid)?;
    issue_installed_bundle_failure_evidence_at_locked(
        root,
        expected_uid,
        systemd,
        issued_at_ms,
        expires_at_ms,
        request_nonce,
    )
}

fn issue_installed_bundle_failure_evidence_at_locked(
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
    let state = systemd.fixed_runtime_state()?;
    if state.active_state != "failed" || state.result != "start-limit-hit" {
        return Err(std::io::Error::other("failure epoch is no longer current"));
    }
    let (epoch, metadata, _) = current_epoch_at_locked(root, expected_uid)?;
    if runtime_failure_consumption_pending_at(root, expected_uid, &epoch.generation)?
        || runtime_failure_creation_reserved_at(root, expected_uid)?
    {
        return Err(std::io::Error::other("failure pair consumption pending"));
    }
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
    let _lock = acquire_runtime_failure_pair_lock_at(root, expected_uid)
        .map_err(|_| InstalledBundleRepairError::InvalidBoundary)?;
    let current = issue_installed_bundle_failure_evidence_at_locked(
        root,
        expected_uid,
        systemd,
        signed.evidence.issued_at_ms,
        signed.evidence.expires_at_ms,
        &signed.evidence.request_nonce,
    )
    .map_err(|_| InstalledBundleRepairError::InvalidBoundary)?;
    let (_, metadata, _) = current_epoch_at_locked(root, expected_uid)
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

fn current_epoch_at_locked(
    root: &Path,
    expected_uid: u32,
) -> std::io::Result<(RuntimeFailureEpoch, toml::Value, Vec<u8>)> {
    let (epoch, metadata, epoch_bytes) = current_epoch_binding_at(root, expected_uid)?;
    let latch = trusted_file(&rooted(root, LATCH_PATH), expected_uid, 0o600)?;
    if latch != epoch.generation.as_bytes() {
        return Err(std::io::Error::other("failure epoch binding invalid"));
    }
    Ok((epoch, metadata, epoch_bytes))
}

fn current_epoch_binding_at(
    root: &Path,
    expected_uid: u32,
) -> std::io::Result<(RuntimeFailureEpoch, toml::Value, Vec<u8>)> {
    trusted_state_directory(
        &rooted(root, "/var/lib/enoki-probe"),
        &rooted(root, IDENTITY_PATH),
    )?;
    let epoch_bytes = trusted_file(&rooted(root, EPOCH_PATH), expected_uid, 0o600)?;
    let epoch: RuntimeFailureEpoch = toml::from_str(
        std::str::from_utf8(&epoch_bytes)
            .map_err(|_| std::io::Error::other("failure epoch invalid"))?,
    )
    .map_err(|_| std::io::Error::other("failure epoch invalid"))?;
    let metadata_bytes = trusted_file(&rooted(root, METADATA_PATH), expected_uid, 0o600)?;
    let identity = trusted_identity_file(&rooted(root, IDENTITY_PATH))?;
    let unit = trusted_file(&rooted(root, UNIT_PATH), expected_uid, 0o644)?;
    let boot_id = String::from_utf8(trusted_file(
        &rooted(root, BOOT_ID_PATH),
        expected_uid,
        0o444,
    )?)
    .map_err(|_| std::io::Error::other("boot binding invalid"))?;
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
        || epoch.result != "start-limit-hit"
        || epoch.unit != RUNTIME_UNIT
        || decode_lower_hex_32(&epoch.generation).is_none()
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
    Ok((epoch, metadata, epoch_bytes))
}

fn record_runtime_failure_at(
    root: &Path,
    expected_uid: u32,
    systemd: &mut impl RuntimeFailureSystemd,
    generations: &mut impl FailureGenerationSource,
) -> std::io::Result<RuntimeFailureRecordOutcome> {
    let _lock = acquire_runtime_failure_pair_lock_at(root, expected_uid)?;
    let state = systemd.fixed_runtime_state()?;
    if state.active_state != "failed" || state.result != "start-limit-hit" {
        return Ok(RuntimeFailureRecordOutcome::Ignored);
    }
    let failure_dir = rooted(root, FAILURE_DIR);
    let epoch_path = rooted(root, EPOCH_PATH);
    let latch_path = rooted(root, LATCH_PATH);
    trusted_state_directory(
        &rooted(root, "/var/lib/enoki-probe"),
        &rooted(root, IDENTITY_PATH),
    )?;
    let creation_reserved = runtime_failure_creation_reserved_at(root, expected_uid)?;
    match (path_present(&epoch_path)?, path_present(&latch_path)?) {
        (true, true) => {
            let (epoch, _, _) = current_epoch_at_locked(root, expected_uid)?;
            if creation_reserved
                || runtime_failure_consumption_pending_at(root, expected_uid, &epoch.generation)?
            {
                return Err(std::io::Error::other("failure pair consumption pending"));
            }
            return Ok(RuntimeFailureRecordOutcome::AlreadyLatched);
        }
        (true, false) => {
            let (epoch, _, _) = current_epoch_binding_at(root, expected_uid)?;
            if creation_reserved
                || runtime_failure_consumption_pending_at(root, expected_uid, &epoch.generation)?
            {
                return Err(std::io::Error::other("failure pair consumption pending"));
            }
            atomic_write(
                &latch_path,
                epoch.generation.as_bytes(),
                0o600,
                Some((expected_uid, expected_uid)),
            )?;
            return Ok(RuntimeFailureRecordOutcome::Latched);
        }
        (false, true) => {
            let latch = trusted_file(&latch_path, expected_uid, 0o600)?;
            let generation = std::str::from_utf8(&latch)
                .ok()
                .filter(|value| decode_lower_hex_32(value).is_some())
                .ok_or_else(|| std::io::Error::other("failure latch invalid"))?;
            if creation_reserved
                || runtime_failure_consumption_pending_at(root, expected_uid, generation)?
            {
                return Err(std::io::Error::other("failure pair consumption pending"));
            }
            let epoch = build_current_epoch(root, expected_uid, &state, generation)?;
            let encoded = toml::to_string(&epoch)
                .map_err(|_| std::io::Error::other("failure epoch invalid"))?;
            atomic_write(
                &epoch_path,
                encoded.as_bytes(),
                0o600,
                Some((expected_uid, expected_uid)),
            )?;
            return Ok(RuntimeFailureRecordOutcome::Latched);
        }
        (false, false) => {}
    }

    if creation_reserved {
        return Err(std::io::Error::other("failure pair creation reserved"));
    }

    let retry_receipt = rooted(root, LOCAL_RETRY_RECEIPT_PATH);
    if path_present(&retry_receipt)? {
        let bytes = trusted_file(&retry_receipt, expected_uid, 0o600)?;
        let receipt = parse_local_retry_receipt(&bytes)?;
        if receipt.progress != LocalRetryProgress::RetryInvoked {
            return Err(std::io::Error::other("local retry recovery pending"));
        }
        remove_regular_file(&retry_receipt, 0o600, Some((expected_uid, expected_uid)))?;
    }

    if path_present(&failure_dir)? {
        trusted_directory(&failure_dir, expected_uid, 0o700)?;
    } else {
        ensure_directory(&failure_dir, 0o700, Some((expected_uid, expected_uid)))?;
        trusted_directory(&failure_dir, expected_uid, 0o700)?;
    }
    let mut generation = [0_u8; 32];
    generations.fill_generation(&mut generation)?;
    let epoch = build_current_epoch(root, expected_uid, &state, &hex(&generation))?;
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

fn runtime_failure_consumption_pending_at(
    root: &Path,
    expected_uid: u32,
    generation: &str,
) -> std::io::Result<bool> {
    if let Some(bytes) =
        trusted_optional_file(&rooted(root, LOCAL_RETRY_RECEIPT_PATH), expected_uid, 0o600)?
    {
        let receipt = parse_local_retry_receipt(&bytes)?;
        if receipt.generation != generation {
            return Err(std::io::Error::other("local retry receipt binding invalid"));
        }
        if receipt.progress != LocalRetryProgress::RetryInvoked {
            return Ok(true);
        }
        return Err(std::io::Error::other(
            "completed local retry retained a latch",
        ));
    }

    if let Some(_bytes) = trusted_optional_file(
        &rooted(root, installed_bundle_repair::REPAIR_INTENT_PATH),
        expected_uid,
        0o600,
    )? {
        let intent = installed_bundle_repair::load_validated_installed_bundle_repair_intent_at(
            root,
            expected_uid,
        )
        .map_err(|_| std::io::Error::other("repair intent invalid"))?
        .ok_or_else(|| std::io::Error::other("repair intent invalid"))?;
        let state = intent.state;
        if matches!(
            state,
            installed_bundle_repair::InstalledBundleRepairProgress::Admitted
                | installed_bundle_repair::InstalledBundleRepairProgress::ValidationPending
                | installed_bundle_repair::InstalledBundleRepairProgress::TemporaryRuntimeHealthy
                | installed_bundle_repair::InstalledBundleRepairProgress::ProbeActive
                | installed_bundle_repair::InstalledBundleRepairProgress::InvalidationCommitted
                | installed_bundle_repair::InstalledBundleRepairProgress::EpochRemoved
        ) {
            if intent.authority.generation != generation {
                return Err(std::io::Error::other("repair intent binding invalid"));
            }
            return Ok(true);
        }
        if matches!(
            state,
            installed_bundle_repair::InstalledBundleRepairProgress::LatchRemoved
                | installed_bundle_repair::InstalledBundleRepairProgress::CanonicalRuntimeHealthy
                | installed_bundle_repair::InstalledBundleRepairProgress::StatusPublished
        ) && intent.authority.generation == generation
        {
            return Err(std::io::Error::other(
                "completed repair retained a failure pair",
            ));
        }
    }

    if let Some(bytes) =
        trusted_optional_file(&rooted(root, UPGRADE_ATTEMPT_PATH), expected_uid, 0o600)?
    {
        let intent = parse_upgrade_runtime_failure_intent(&bytes)?;
        if intent.phase == "aborted" {
            return Ok(false);
        }
        let Some(progress) = intent.progress else {
            return Ok(true);
        };
        match progress {
            UpgradeRuntimeFailureProgress::Bound | UpgradeRuntimeFailureProgress::EpochRemoved => {
                if intent.generation.as_deref() != Some(generation) {
                    return Err(std::io::Error::other("upgrade intent binding invalid"));
                }
                return Ok(true);
            }
            UpgradeRuntimeFailureProgress::LatchRemoved => {
                if intent.generation.as_deref() == Some(generation) {
                    return Err(std::io::Error::other(
                        "completed upgrade retained a failure pair",
                    ));
                }
            }
            UpgradeRuntimeFailureProgress::None => {
                return Err(std::io::Error::other(
                    "absent-pair upgrade intent retained a failure pair",
                ));
            }
            UpgradeRuntimeFailureProgress::NoneConsumed => return Ok(intent.phase != "activated"),
        }
    }
    Ok(false)
}

fn runtime_failure_creation_reserved_at(root: &Path, expected_uid: u32) -> std::io::Result<bool> {
    if let Some(_bytes) = trusted_optional_file(
        &rooted(root, installed_bundle_repair::REPAIR_INTENT_PATH),
        expected_uid,
        0o600,
    )? {
        let intent = installed_bundle_repair::load_validated_installed_bundle_repair_intent_at(
            root,
            expected_uid,
        )
        .map_err(|_| std::io::Error::other("repair intent invalid"))?
        .ok_or_else(|| std::io::Error::other("repair intent invalid"))?;
        // validated Repair intent 在其 durable retirement 删除文件前始终独占消费权。
        // progress 不是释放信号：pair-none Local Retry 不能在此窗口启动 Runtime。
        let _ = intent;
        return Ok(true);
    }
    let Some(bytes) =
        trusted_optional_file(&rooted(root, UPGRADE_ATTEMPT_PATH), expected_uid, 0o600)?
    else {
        return Ok(false);
    };
    let intent = parse_upgrade_runtime_failure_intent(&bytes)?;
    if intent.phase == "aborted" {
        return Ok(false);
    }
    Ok(!matches!(
        (&intent.phase, intent.progress),
        (phase, Some(UpgradeRuntimeFailureProgress::NoneConsumed))
            | (phase, Some(UpgradeRuntimeFailureProgress::LatchRemoved))
            if phase == "activated"
    ))
}

fn parse_local_retry_receipt(bytes: &[u8]) -> std::io::Result<LocalRetryReceipt> {
    let receipt: LocalRetryReceipt = serde_json::from_slice(bytes)
        .map_err(|_| std::io::Error::other("local retry receipt invalid"))?;
    if receipt.schema_version != 1
        || decode_lower_hex_32(&receipt.generation).is_none()
        || decode_lower_hex_32(&receipt.epoch_sha256).is_none()
    {
        return Err(std::io::Error::other("local retry receipt invalid"));
    }
    Ok(receipt)
}

fn parse_upgrade_runtime_failure_intent(
    bytes: &[u8],
) -> std::io::Result<UpgradeRuntimeFailureIntent> {
    let journal =
        std::str::from_utf8(bytes).map_err(|_| std::io::Error::other("upgrade intent invalid"))?;
    let value: toml::Value =
        toml::from_str(journal).map_err(|_| std::io::Error::other("upgrade intent invalid"))?;
    let schema = value
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        .filter(|schema| (1..=4).contains(schema))
        .and_then(|schema| u16::try_from(schema).ok())
        .ok_or_else(|| std::io::Error::other("upgrade intent schema invalid"))?;
    let operation_id = upgrade_journal_string(&value, "operation_id")?;
    let _stage_owner_uid: u32 = upgrade_journal_usize(&value, "stage_owner_uid")?
        .try_into()
        .map_err(|_| std::io::Error::other("upgrade intent binding invalid"))?;
    let authority_sha256 = upgrade_journal_string(&value, "authority_sha256")?;
    let source_probe_id = upgrade_journal_string(&value, "source_probe_id")?;
    let source_bundle_version = upgrade_journal_string(&value, "source_bundle_version")?;
    let source_install_state_sha256 =
        upgrade_journal_string(&value, "source_install_state_sha256")?;
    let source_manifest_sha256 = upgrade_journal_string(&value, "source_manifest_sha256")?;
    let target_bundle_version = upgrade_journal_string(&value, "target_bundle_version")?;
    let target_install_state_present = value.get("target_install_state_sha256").is_some();
    let target_install_state_sha256 = metadata_string(&value, "target_install_state_sha256");
    let target_manifest_sha256 = upgrade_journal_string(&value, "target_manifest_sha256")?;
    if !valid_upgrade_identifier(&operation_id)
        || !valid_upgrade_identifier(&source_probe_id)
        || decode_lower_hex_32(&authority_sha256).is_none()
        || !valid_upgrade_version(&source_bundle_version)
        || !valid_upgrade_version(&target_bundle_version)
        || decode_lower_hex_32(&source_install_state_sha256).is_none()
        || decode_lower_hex_32(&source_manifest_sha256).is_none()
        || (target_install_state_present
            && target_install_state_sha256
                .as_deref()
                .and_then(decode_lower_hex_32)
                .is_none())
        || decode_lower_hex_32(&target_manifest_sha256).is_none()
    {
        return Err(std::io::Error::other("upgrade intent binding invalid"));
    }
    let has_authority_scope = [
        "hub_origin",
        "host_id",
        "target_asset_set_digest",
        "verified_stage_sha256",
    ]
    .iter()
    .any(|key| value.get(*key).is_some());
    if has_authority_scope {
        let hub_origin = upgrade_journal_string(&value, "hub_origin")?;
        let host_id = upgrade_journal_string(&value, "host_id")?;
        let target_asset_set_digest = upgrade_journal_string(&value, "target_asset_set_digest")?;
        let verified_stage_sha256 = upgrade_journal_string(&value, "verified_stage_sha256")?;
        if hub_origin.is_empty()
            || !valid_upgrade_identifier(&host_id)
            || target_asset_set_digest
                .strip_prefix("sha256:")
                .and_then(decode_lower_hex_32)
                .is_none()
            || decode_lower_hex_32(&verified_stage_sha256).is_none()
        {
            return Err(std::io::Error::other("upgrade intent authority invalid"));
        }
    } else {
        if schema == 2 {
            return Err(std::io::Error::other("upgrade intent authority missing"));
        }
        if target_install_state_sha256.is_none() {
            return Err(std::io::Error::other(
                "upgrade intent target binding missing",
            ));
        }
    }
    let phase = upgrade_journal_string(&value, "phase")?;
    let activated_targets = upgrade_journal_usize(&value, "activated_targets")?;
    let finalized_targets = upgrade_journal_usize(&value, "finalized_targets")?;
    let activation_started = match schema {
        3 | 4 => value
            .get("activation_started")
            .and_then(toml::Value::as_bool)
            .ok_or_else(|| std::io::Error::other("upgrade intent activation marker invalid"))?,
        2 => match value.get("activation_started") {
            Some(value) => value
                .as_bool()
                .ok_or_else(|| std::io::Error::other("upgrade intent activation marker invalid"))?,
            None => infer_upgrade_activation_started(&phase, activated_targets, finalized_targets)?,
        },
        1 => infer_upgrade_activation_started(&phase, activated_targets, finalized_targets)?,
        _ => unreachable!(),
    };
    validate_upgrade_attempt_tuple(
        &phase,
        activation_started,
        activated_targets,
        finalized_targets,
    )?;
    let progress = metadata_string(&value, "runtime_failure_consumption");
    let generation = metadata_string(&value, "runtime_failure_generation");
    let epoch_sha256 = metadata_string(&value, "runtime_failure_epoch_sha256");
    if schema != 4 {
        if value.get("runtime_failure_consumption").is_some()
            || value.get("runtime_failure_generation").is_some()
            || value.get("runtime_failure_epoch_sha256").is_some()
        {
            return Err(std::io::Error::other("legacy upgrade intent invalid"));
        }
        return Ok(UpgradeRuntimeFailureIntent {
            phase,
            progress: None,
            generation: None,
        });
    }
    let generation_present = value.get("runtime_failure_generation").is_some();
    let epoch_sha256_present = value.get("runtime_failure_epoch_sha256").is_some();
    let (progress, generation) = match (progress.as_deref(), generation, epoch_sha256) {
        (Some("none"), None, None) if !generation_present && !epoch_sha256_present => {
            (UpgradeRuntimeFailureProgress::None, None)
        }
        (Some("none-consumed"), None, None) if !generation_present && !epoch_sha256_present => {
            (UpgradeRuntimeFailureProgress::NoneConsumed, None)
        }
        (Some("bound"), Some(generation), Some(digest))
            if decode_lower_hex_32(&generation).is_some()
                && decode_lower_hex_32(&digest).is_some() =>
        {
            (UpgradeRuntimeFailureProgress::Bound, Some(generation))
        }
        (Some("epoch-removed"), Some(generation), Some(digest))
            if decode_lower_hex_32(&generation).is_some()
                && decode_lower_hex_32(&digest).is_some() =>
        {
            (
                UpgradeRuntimeFailureProgress::EpochRemoved,
                Some(generation),
            )
        }
        (Some("latch-removed"), Some(generation), Some(digest))
            if decode_lower_hex_32(&generation).is_some()
                && decode_lower_hex_32(&digest).is_some() =>
        {
            (
                UpgradeRuntimeFailureProgress::LatchRemoved,
                Some(generation),
            )
        }
        _ => return Err(std::io::Error::other("upgrade intent progress invalid")),
    };
    if !upgrade_runtime_failure_progress_matches_phase(progress, &phase) {
        return Err(std::io::Error::other("upgrade intent progress incoherent"));
    }
    Ok(UpgradeRuntimeFailureIntent {
        phase,
        progress: Some(progress),
        generation,
    })
}

fn upgrade_runtime_failure_progress_matches_phase(
    progress: UpgradeRuntimeFailureProgress,
    phase: &str,
) -> bool {
    match progress {
        UpgradeRuntimeFailureProgress::None | UpgradeRuntimeFailureProgress::Bound => matches!(
            phase,
            "consumed"
                | "admitted"
                | "prepared"
                | "aborted"
                | "activation-started"
                | "repair-required"
                | "finalizing"
                | "stage-cleanup-required"
        ),
        UpgradeRuntimeFailureProgress::EpochRemoved => matches!(
            phase,
            "activation-started" | "repair-required" | "finalizing" | "stage-cleanup-required"
        ),
        UpgradeRuntimeFailureProgress::NoneConsumed
        | UpgradeRuntimeFailureProgress::LatchRemoved => matches!(
            phase,
            "activation-started"
                | "repair-required"
                | "finalizing"
                | "stage-cleanup-required"
                | "activated"
        ),
    }
}

fn infer_upgrade_activation_started(
    phase: &str,
    activated: usize,
    finalized: usize,
) -> std::io::Result<bool> {
    match phase {
        "consumed" | "admitted" | "prepared" | "aborted" => Ok(false),
        "activation-started" | "finalizing" | "stage-cleanup-required" | "activated" => Ok(true),
        "repair-required" if activated > 0 || finalized > 0 => Ok(true),
        _ => Err(std::io::Error::other("upgrade intent phase invalid")),
    }
}

fn validate_upgrade_attempt_tuple(
    phase: &str,
    activation_started: bool,
    activated: usize,
    finalized: usize,
) -> std::io::Result<()> {
    const UPGRADE_TARGET_COUNT: usize = 21;

    if finalized > activated || activated > UPGRADE_TARGET_COUNT {
        return Err(std::io::Error::other(
            "upgrade intent progress tuple invalid",
        ));
    }
    let valid = match phase {
        "consumed" | "admitted" | "prepared" | "aborted" => {
            !activation_started && activated == 0 && finalized == 0
        }
        "activation-started" => activation_started && finalized == 0,
        "repair-required" => activation_started,
        "finalizing" => activation_started && activated == UPGRADE_TARGET_COUNT,
        "stage-cleanup-required" | "activated" => {
            activation_started
                && activated == UPGRADE_TARGET_COUNT
                && finalized == UPGRADE_TARGET_COUNT
        }
        _ => false,
    };
    valid
        .then_some(())
        .ok_or_else(|| std::io::Error::other("upgrade intent progress tuple invalid"))
}

fn upgrade_journal_string(value: &toml::Value, key: &str) -> std::io::Result<String> {
    metadata_string(value, key).ok_or_else(|| std::io::Error::other("upgrade intent field invalid"))
}

fn upgrade_journal_usize(value: &toml::Value, key: &str) -> std::io::Result<usize> {
    value
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| std::io::Error::other("upgrade intent field invalid"))
}

fn valid_upgrade_identifier(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_upgrade_version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_whitespace)
}

fn trusted_optional_file(path: &Path, uid: u32, mode: u32) -> std::io::Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => trusted_file(path, uid, mode).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn build_current_epoch(
    root: &Path,
    expected_uid: u32,
    state: &RuntimeUnitState,
    generation: &str,
) -> std::io::Result<RuntimeFailureEpoch> {
    if decode_lower_hex_32(generation).is_none() {
        return Err(std::io::Error::other("failure generation invalid"));
    }
    if state.active_state != "failed" || state.result != "start-limit-hit" {
        return Err(std::io::Error::other("Runtime failure is not terminal"));
    }
    let metadata = trusted_file(&rooted(root, METADATA_PATH), expected_uid, 0o600)?;
    let identity = trusted_identity_file(&rooted(root, IDENTITY_PATH))?;
    let unit = trusted_file(&rooted(root, UNIT_PATH), expected_uid, 0o644)?;
    let expected_unit = enoki_probe_bootstrap::install::fixed_execution_role_units()
        .into_iter()
        .find_map(|(role, bytes)| (role == "observation-runtime-v4").then_some(bytes))
        .ok_or_else(|| std::io::Error::other("fixed runtime unit unavailable"))?;
    if unit != expected_unit {
        return Err(std::io::Error::other("runtime unit binding mismatch"));
    }
    let boot_id = String::from_utf8(trusted_file(
        &rooted(root, BOOT_ID_PATH),
        expected_uid,
        0o444,
    )?)
    .map_err(|_| std::io::Error::other("boot binding invalid"))?;
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
    Ok(RuntimeFailureEpoch {
        schema_version: 1,
        generation: generation.to_owned(),
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
        result: state.result.clone(),
    })
}

fn rooted(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
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
    use std::os::unix::fs::PermissionsExt;

    struct State(RuntimeUnitState);
    impl RuntimeFailureSystemd for State {
        fn fixed_runtime_state(&mut self) -> std::io::Result<RuntimeUnitState> {
            Ok(self.0.clone())
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
    impl RuntimeFailureSystemd for RetrySystemd {
        fn fixed_runtime_state(&mut self) -> std::io::Result<RuntimeUnitState> {
            Ok(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            })
        }
    }
    impl RuntimeRetrySystemd for RetrySystemd {
        fn retry_fixed_runtime(&mut self) -> std::io::Result<()> {
            self.0 += 1;
            Ok(())
        }
    }
    struct FailedRuntime(usize);
    impl RuntimeFailureSystemd for FailedRuntime {
        fn fixed_runtime_state(&mut self) -> std::io::Result<RuntimeUnitState> {
            Ok(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            })
        }
    }
    impl RuntimeRetrySystemd for FailedRuntime {
        fn retry_fixed_runtime(&mut self) -> std::io::Result<()> {
            self.0 += 1;
            Ok(())
        }
    }
    struct RejectedRepair;
    impl RuntimeFailureSystemd for RejectedRepair {
        fn fixed_runtime_state(&mut self) -> std::io::Result<RuntimeUnitState> {
            Ok(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            })
        }
    }
    impl RuntimeRetrySystemd for RejectedRepair {
        fn retry_fixed_runtime(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("完整 Bundle 恢复失败"))
        }
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
            "etc/systemd/system",
            "proc/sys/kernel/random",
            "run/enoki-probe",
        ] {
            fs::create_dir_all(root.path().join(directory)).unwrap();
        }
        fs::set_permissions(
            root.path().join("var/lib/enoki-probe"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        fs::set_permissions(
            root.path().join("run/enoki-probe"),
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
        let unit = enoki_probe_bootstrap::install::fixed_execution_role_units()
            .into_iter()
            .find(|(role, _)| *role == "observation-runtime-v4")
            .unwrap()
            .1;
        write_fixture(root.path(), UNIT_PATH, &unit, 0o644);
        write_fixture(root.path(), BOOT_ID_PATH, b"boot-01\n", 0o444);
        root
    }

    fn write_fixture(root: &Path, path: &str, bytes: &[u8], mode: u32) {
        let path = rooted(root, path);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn upgrade_journal_fixture(
        phase: &str,
        activation_started: bool,
        activated_targets: usize,
        finalized_targets: usize,
        progress: &str,
        binding: Option<(&str, &str)>,
    ) -> String {
        let mut journal = format!(
            "schema_version = 4\noperation_id = \"runtime-failure-test\"\nstage_owner_uid = {}\nauthority_sha256 = {:?}\nhub_origin = \"https://hub.example\"\nhost_id = \"host_01\"\nsource_probe_id = \"probe_01\"\nsource_bundle_version = \"1.2.3\"\nsource_install_state_sha256 = {:?}\nsource_manifest_sha256 = {:?}\ntarget_bundle_version = \"1.2.4\"\ntarget_asset_set_digest = {:?}\ntarget_manifest_sha256 = {:?}\nverified_stage_sha256 = {:?}\nphase = {phase:?}\nactivation_started = {activation_started}\nactivated_targets = {activated_targets}\nfinalized_targets = {finalized_targets}\nruntime_failure_consumption = {progress:?}\n",
            unsafe { libc::geteuid() },
            "1a".repeat(32),
            "2b".repeat(32),
            "3c".repeat(32),
            format!("sha256:{}", "4d".repeat(32)),
            "5e".repeat(32),
            "6f".repeat(32),
        );
        if let Some((generation, epoch_sha256)) = binding {
            journal.push_str(&format!(
                "runtime_failure_generation = {generation:?}\nruntime_failure_epoch_sha256 = {epoch_sha256:?}\n"
            ));
        }
        journal
    }

    fn scope_less_upgrade_journal_fixture(
        journal: &str,
        target_install_state: Option<&str>,
    ) -> String {
        let mut output = String::new();
        for line in journal.lines() {
            if [
                "hub_origin = ",
                "host_id = ",
                "target_asset_set_digest = ",
                "verified_stage_sha256 = ",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
            {
                continue;
            }
            if line.starts_with("target_manifest_sha256 = ")
                && let Some(digest) = target_install_state
            {
                output.push_str(&format!("target_install_state_sha256 = {digest:?}\n"));
            }
            output.push_str(line);
            output.push('\n');
        }
        output
    }

    #[test]
    fn systemd_249_intermediate_on_failure_does_not_write_an_epoch() {
        let root = fixture();
        let outcome = record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "activating".into(),
                result: "exit-code".into(),
            }),
            &mut Generation(1),
        )
        .unwrap();
        assert_eq!(outcome, RuntimeFailureRecordOutcome::Ignored);
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
        assert!(
            record_runtime_failure_at(
                root.path(),
                unsafe { libc::geteuid() },
                &mut State(RuntimeUnitState {
                    active_state: "failed".into(),
                    result: "start-limit-hit".into(),
                }),
                &mut Generation(2),
            )
            .is_err()
        );
        assert!(!rooted(root.path(), EPOCH_PATH).exists());
        assert!(!rooted(root.path(), LATCH_PATH).exists());
    }

    #[test]
    fn failure_epoch_rejects_a_later_identity_with_a_different_host_id() {
        let root = fixture();
        record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            }),
            &mut Generation(3),
        )
        .unwrap();
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
                &mut FailedRuntime(0),
                100,
                60_100,
                "request_nonce_wrong_host",
            )
            .is_err()
        );
    }

    #[test]
    fn failure_evidence_accepts_only_the_current_exact_epoch_latch_pair() {
        let uid = unsafe { libc::geteuid() };
        let issue = |root: &Path| {
            issue_installed_bundle_failure_evidence_at(
                root,
                uid,
                &mut FailedRuntime(0),
                100,
                60_100,
                "request_nonce_pair_classification",
            )
        };

        let none = fixture();
        assert!(issue(none.path()).is_err());

        let epoch_only = fixture();
        record_runtime_failure_at(
            epoch_only.path(),
            uid,
            &mut FailedRuntime(0),
            &mut Generation(4),
        )
        .unwrap();
        remove_regular_file(
            &rooted(epoch_only.path(), LATCH_PATH),
            0o600,
            Some((uid, uid)),
        )
        .unwrap();
        assert!(issue(epoch_only.path()).is_err());

        let latch_only = fixture();
        record_runtime_failure_at(
            latch_only.path(),
            uid,
            &mut FailedRuntime(0),
            &mut Generation(5),
        )
        .unwrap();
        remove_regular_file(
            &rooted(latch_only.path(), EPOCH_PATH),
            0o600,
            Some((uid, uid)),
        )
        .unwrap();
        assert!(issue(latch_only.path()).is_err());

        let exact = fixture();
        record_runtime_failure_at(exact.path(), uid, &mut FailedRuntime(0), &mut Generation(6))
            .unwrap();
        assert!(issue(exact.path()).is_ok());

        let mismatch = fixture();
        record_runtime_failure_at(
            mismatch.path(),
            uid,
            &mut FailedRuntime(0),
            &mut Generation(7),
        )
        .unwrap();
        write_fixture(mismatch.path(), LATCH_PATH, &b"aa".repeat(32), 0o600);
        assert!(issue(mismatch.path()).is_err());
        assert!(rooted(mismatch.path(), LATCH_PATH).exists());

        let corrupt = fixture();
        record_runtime_failure_at(
            corrupt.path(),
            uid,
            &mut FailedRuntime(0),
            &mut Generation(8),
        )
        .unwrap();
        write_fixture(corrupt.path(), EPOCH_PATH, b"not toml", 0o600);
        assert!(issue(corrupt.path()).is_err());
        assert!(rooted(corrupt.path(), LATCH_PATH).exists());
    }

    #[test]
    fn systemd_255_only_latches_the_terminal_start_limit_hit() {
        let root = fixture();
        let ignored = record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "failed".into(),
                result: "exit-code".into(),
            }),
            &mut Generation(1),
        )
        .unwrap();
        assert_eq!(ignored, RuntimeFailureRecordOutcome::Ignored);
        let latched = record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            }),
            &mut Generation(2),
        )
        .unwrap();
        assert_eq!(latched, RuntimeFailureRecordOutcome::Latched);
        assert!(rooted(root.path(), EPOCH_PATH).exists());
        assert_eq!(
            fs::read_to_string(rooted(root.path(), LATCH_PATH)).unwrap(),
            "02".repeat(32)
        );
        let before = fs::read(rooted(root.path(), EPOCH_PATH)).unwrap();
        let repeated = record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            }),
            &mut Generation(3),
        )
        .unwrap();
        assert_eq!(repeated, RuntimeFailureRecordOutcome::AlreadyLatched);
        assert_eq!(fs::read(rooted(root.path(), EPOCH_PATH)).unwrap(), before);
    }

    #[test]
    fn typed_local_retry_invalidates_epoch_before_one_fixed_retry() {
        let root = fixture();
        record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            }),
            &mut Generation(4),
        )
        .unwrap();
        let mut systemd = RetrySystemd::default();
        retry_runtime_at(root.path(), unsafe { libc::geteuid() }, &mut systemd).unwrap();
        assert_eq!(systemd.0, 1);
        assert!(!rooted(root.path(), EPOCH_PATH).exists());
        assert!(!rooted(root.path(), LATCH_PATH).exists());
        let receipt: LocalRetryReceipt = serde_json::from_slice(
            &fs::read(rooted(root.path(), LOCAL_RETRY_RECEIPT_PATH)).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.progress, LocalRetryProgress::RetryInvoked);
    }

    #[test]
    fn fixed_retry_reconciles_clean_and_legal_partial_pair_states() {
        let uid = unsafe { libc::geteuid() };

        let clean = fixture();
        let mut clean_systemd = FailedRuntime(0);
        retry_runtime_at(clean.path(), uid, &mut clean_systemd).unwrap();
        assert_eq!(clean_systemd.0, 1);

        for missing in [EPOCH_PATH, LATCH_PATH] {
            let root = fixture();
            record_runtime_failure_at(root.path(), uid, &mut FailedRuntime(0), &mut Generation(19))
                .unwrap();
            remove_regular_file(&rooted(root.path(), missing), 0o600, Some((uid, uid))).unwrap();

            let mut restarted_systemd = FailedRuntime(0);
            retry_runtime_at(root.path(), uid, &mut restarted_systemd).unwrap();
            assert_eq!(restarted_systemd.0, 1, "missing {missing}");
            assert!(
                issue_installed_bundle_failure_evidence_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    100,
                    60_100,
                    "request_nonce_partial_retry",
                )
                .is_err(),
                "missing {missing}",
            );
        }
    }

    #[test]
    fn recorder_reconciles_exact_single_file_publish_windows_and_rejects_corrupt_latch() {
        let root = fixture();
        let uid = unsafe { libc::geteuid() };
        let mut terminal = State(RuntimeUnitState {
            active_state: "failed".into(),
            result: "start-limit-hit".into(),
        });
        record_runtime_failure_at(root.path(), uid, &mut terminal, &mut Generation(20)).unwrap();
        let generation = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();

        remove_regular_file(&rooted(root.path(), LATCH_PATH), 0o600, Some((uid, uid))).unwrap();
        assert_eq!(
            record_runtime_failure_at(root.path(), uid, &mut terminal, &mut Generation(21))
                .unwrap(),
            RuntimeFailureRecordOutcome::Latched
        );
        assert_eq!(
            fs::read(rooted(root.path(), LATCH_PATH)).unwrap(),
            generation
        );

        remove_regular_file(&rooted(root.path(), EPOCH_PATH), 0o600, Some((uid, uid))).unwrap();
        assert_eq!(
            record_runtime_failure_at(root.path(), uid, &mut terminal, &mut Generation(22))
                .unwrap(),
            RuntimeFailureRecordOutcome::Latched
        );
        assert!(current_epoch_at_locked(root.path(), uid).is_ok());

        remove_regular_file(&rooted(root.path(), EPOCH_PATH), 0o600, Some((uid, uid))).unwrap();
        write_fixture(root.path(), LATCH_PATH, b"not-a-generation", 0o600);
        assert!(
            record_runtime_failure_at(root.path(), uid, &mut terminal, &mut Generation(23))
                .is_err()
        );
        assert_eq!(
            fs::read(rooted(root.path(), LATCH_PATH)).unwrap(),
            b"not-a-generation"
        );
        assert!(!rooted(root.path(), EPOCH_PATH).exists());
    }

    #[test]
    fn explicit_local_retry_resumes_every_effect_receipt_crash_from_fresh_durable_facts() {
        let uid = unsafe { libc::geteuid() };
        for (index, crash) in [
            LocalRetryCrashPoint::ReceiptCommitted,
            LocalRetryCrashPoint::EpochUnlinked,
            LocalRetryCrashPoint::EpochRemovedReceipt,
            LocalRetryCrashPoint::LatchUnlinked,
            LocalRetryCrashPoint::LatchRemovedReceipt,
            LocalRetryCrashPoint::SystemdInvoked,
        ]
        .into_iter()
        .enumerate()
        {
            let root = fixture();
            record_runtime_failure_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                &mut Generation(24 + index as u8),
            )
            .unwrap();
            fail_local_retry_after(crash);
            assert!(
                retry_runtime_at(root.path(), uid, &mut RetrySystemd::default()).is_err(),
                "{crash:?} must interrupt the production retry entrypoint",
            );

            assert!(
                record_runtime_failure_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    &mut Generation(40),
                )
                .is_err(),
                "{crash:?} must not let recorder revive or replace consumed authority",
            );
            assert!(
                issue_installed_bundle_failure_evidence_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    100,
                    60_100,
                    "request_nonce_retry_crash",
                )
                .is_err(),
                "{crash:?} must not expose authority after typed consumption",
            );

            let mut restarted_systemd = RetrySystemd::default();
            retry_runtime_at(root.path(), uid, &mut restarted_systemd).unwrap();
            assert_eq!(restarted_systemd.0, 1);
            assert!(!rooted(root.path(), EPOCH_PATH).exists());
            assert!(!rooted(root.path(), LATCH_PATH).exists());
            let completed: LocalRetryReceipt = serde_json::from_slice(
                &fs::read(rooted(root.path(), LOCAL_RETRY_RECEIPT_PATH)).unwrap(),
            )
            .unwrap();
            assert_eq!(completed.progress, LocalRetryProgress::RetryInvoked);
        }
    }

    #[test]
    fn local_retry_systemd_failure_is_durable_and_only_a_new_recorder_generation_returns() {
        let root = fixture();
        let uid = unsafe { libc::geteuid() };
        record_runtime_failure_at(root.path(), uid, &mut FailedRuntime(0), &mut Generation(50))
            .unwrap();
        let old_generation = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();

        assert!(retry_runtime_at(root.path(), uid, &mut RejectedRepair).is_err());
        let attempted: LocalRetryReceipt = serde_json::from_slice(
            &fs::read(rooted(root.path(), LOCAL_RETRY_RECEIPT_PATH)).unwrap(),
        )
        .unwrap();
        assert_eq!(attempted.progress, LocalRetryProgress::RetryInvoked);

        assert_eq!(
            record_runtime_failure_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                &mut Generation(51),
            )
            .unwrap(),
            RuntimeFailureRecordOutcome::Latched,
        );
        assert_ne!(
            fs::read(rooted(root.path(), LATCH_PATH)).unwrap(),
            old_generation
        );
        assert!(!rooted(root.path(), LOCAL_RETRY_RECEIPT_PATH).exists());
    }

    #[test]
    fn recorder_never_revives_latch_only_pair_owned_by_repair_or_upgrade_intent() {
        for (path, contents) in [
            (
                installed_bundle_repair::REPAIR_INTENT_PATH,
                serde_json::json!({
                    "state": "epoch-removed",
                    "authority": { "generation": "1b".repeat(32) }
                })
                .to_string(),
            ),
            (
                UPGRADE_ATTEMPT_PATH,
                upgrade_journal_fixture(
                    "activation-started",
                    true,
                    21,
                    0,
                    "epoch-removed",
                    Some((&"1b".repeat(32), &"2c".repeat(32))),
                ),
            ),
        ] {
            let root = fixture();
            let uid = unsafe { libc::geteuid() };
            record_runtime_failure_at(root.path(), uid, &mut FailedRuntime(0), &mut Generation(27))
                .unwrap();
            remove_regular_file(&rooted(root.path(), EPOCH_PATH), 0o600, Some((uid, uid))).unwrap();
            let intent = rooted(root.path(), path);
            fs::create_dir_all(intent.parent().unwrap()).unwrap();
            write_fixture(root.path(), path, contents.as_bytes(), 0o600);

            assert!(
                record_runtime_failure_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    &mut Generation(28),
                )
                .is_err()
            );
            assert!(!rooted(root.path(), EPOCH_PATH).exists());
            assert_eq!(
                fs::read(rooted(root.path(), LATCH_PATH)).unwrap(),
                b"1b".repeat(32)
            );
            assert_eq!(fs::read(intent).unwrap(), contents.as_bytes());

            remove_regular_file(&rooted(root.path(), LATCH_PATH), 0o600, Some((uid, uid))).unwrap();
            assert!(
                record_runtime_failure_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    &mut Generation(29),
                )
                .is_err(),
                "typed consumer must close the latch-unlink-before-receipt window",
            );
            assert!(!rooted(root.path(), EPOCH_PATH).exists());
            assert!(!rooted(root.path(), LATCH_PATH).exists());
        }
    }

    #[test]
    fn recorder_cannot_race_an_upgrade_that_reserved_an_absent_pair() {
        let root = fixture();
        let uid = unsafe { libc::geteuid() };
        let journal_path = rooted(root.path(), UPGRADE_ATTEMPT_PATH);
        fs::create_dir_all(journal_path.parent().unwrap()).unwrap();
        write_fixture(
            root.path(),
            UPGRADE_ATTEMPT_PATH,
            upgrade_journal_fixture("prepared", false, 0, 0, "none", None).as_bytes(),
            0o600,
        );

        assert!(
            record_runtime_failure_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                &mut Generation(60),
            )
            .is_err()
        );
        assert!(!rooted(root.path(), EPOCH_PATH).exists());
        assert!(!rooted(root.path(), LATCH_PATH).exists());

        write_fixture(
            root.path(),
            UPGRADE_ATTEMPT_PATH,
            upgrade_journal_fixture("activation-started", true, 0, 0, "none-consumed", None)
                .as_bytes(),
            0o600,
        );
        assert!(
            record_runtime_failure_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                &mut Generation(61),
            )
            .is_err(),
            "none-consumed cannot release a non-terminal Upgrade reservation",
        );

        write_fixture(
            root.path(),
            UPGRADE_ATTEMPT_PATH,
            upgrade_journal_fixture("activated", true, 21, 21, "none-consumed", None).as_bytes(),
            0o600,
        );
        record_runtime_failure_at(root.path(), uid, &mut FailedRuntime(0), &mut Generation(62))
            .unwrap();

        write_fixture(
            root.path(),
            UPGRADE_ATTEMPT_PATH,
            upgrade_journal_fixture(
                "prepared",
                false,
                0,
                0,
                "bound",
                Some((&"3d".repeat(32), &"4e".repeat(32))),
            )
            .as_bytes(),
            0o600,
        );
        assert!(retry_runtime_at(root.path(), uid, &mut RetrySystemd::default()).is_err());
        assert!(
            issue_installed_bundle_failure_evidence_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                100,
                60_100,
                "request_nonce_upgrade_custody",
            )
            .is_err()
        );
        assert!(!rooted(root.path(), LOCAL_RETRY_RECEIPT_PATH).exists());
        assert!(current_epoch_at_locked(root.path(), uid).is_ok());
    }

    #[test]
    fn unknown_typed_consumer_state_retains_pair_and_exposes_no_authority_or_effect() {
        for (path, contents) in [
            (
                LOCAL_RETRY_RECEIPT_PATH,
                serde_json::json!({
                    "schemaVersion": 1,
                    "generation": "6a".repeat(32),
                    "epochSha256": "7b".repeat(32),
                    "progress": "future-retry-state",
                })
                .to_string(),
            ),
            (
                installed_bundle_repair::REPAIR_INTENT_PATH,
                serde_json::json!({
                    "schemaVersion": 2,
                    "state": "future-repair-state",
                })
                .to_string(),
            ),
            (
                UPGRADE_ATTEMPT_PATH,
                "schema_version = 4\nphase = \"activation-started\"\nruntime_failure_consumption = \"future-upgrade-state\"\n"
                    .to_owned(),
            ),
            (
                UPGRADE_ATTEMPT_PATH,
                format!(
                    "schema_version = 4\nphase = \"prepared\"\nruntime_failure_consumption = \"latch-removed\"\nruntime_failure_generation = {:?}\nruntime_failure_epoch_sha256 = {:?}\n",
                    "8c".repeat(32),
                    "9d".repeat(32),
                ),
            ),
        ] {
            let root = fixture();
            let uid = unsafe { libc::geteuid() };
            record_runtime_failure_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                &mut Generation(0x6a),
            )
            .unwrap();
            let epoch_before = fs::read(rooted(root.path(), EPOCH_PATH)).unwrap();
            let latch_before = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();
            fs::create_dir_all(rooted(root.path(), path).parent().unwrap()).unwrap();
            write_fixture(root.path(), path, contents.as_bytes(), 0o600);

            assert!(
                record_runtime_failure_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    &mut Generation(0x6b),
                )
                .is_err(),
                "unknown typed state at {path} must fail closed",
            );
            assert!(
                issue_installed_bundle_failure_evidence_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    100,
                    60_100,
                    "request_nonce_unknown_typed_state",
                )
                .is_err(),
            );
            let mut retry = RetrySystemd::default();
            assert!(retry_runtime_at(root.path(), uid, &mut retry).is_err());
            assert_eq!(retry.0, 0);
            assert_eq!(fs::read(rooted(root.path(), EPOCH_PATH)).unwrap(), epoch_before);
            assert_eq!(fs::read(rooted(root.path(), LATCH_PATH)).unwrap(), latch_before);
            assert_eq!(fs::read(rooted(root.path(), path)).unwrap(), contents.as_bytes());
        }
    }

    #[test]
    fn incoherent_full_upgrade_journal_retains_pair_and_blocks_all_runtime_effects() {
        let completed_generation = "a7".repeat(32);
        let completed_digest = "b8".repeat(32);
        let valid = upgrade_journal_fixture(
            "activated",
            true,
            21,
            21,
            "latch-removed",
            Some((&completed_generation, &completed_digest)),
        );
        let invalid = [
            upgrade_journal_fixture(
                "activated",
                false,
                0,
                0,
                "latch-removed",
                Some((&completed_generation, &completed_digest)),
            ),
            upgrade_journal_fixture(
                "finalizing",
                true,
                20,
                7,
                "latch-removed",
                Some((&completed_generation, &completed_digest)),
            ),
            upgrade_journal_fixture(
                "activation-started",
                true,
                21,
                1,
                "latch-removed",
                Some((&completed_generation, &completed_digest)),
            ),
            valid.replacen("operation_id = \"runtime-failure-test\"\n", "", 1),
            valid.replacen(
                &format!("authority_sha256 = {:?}", "1a".repeat(32)),
                "authority_sha256 = \"invalid\"",
                1,
            ),
            valid.replacen("activation_started = true\n", "", 1),
        ];
        for (index, journal) in invalid.into_iter().enumerate() {
            let root = fixture();
            let uid = unsafe { libc::geteuid() };
            record_runtime_failure_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                &mut Generation(0x76),
            )
            .unwrap();
            let epoch_before = fs::read(rooted(root.path(), EPOCH_PATH)).unwrap();
            let latch_before = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();
            fs::create_dir_all(rooted(root.path(), UPGRADE_ATTEMPT_PATH).parent().unwrap())
                .unwrap();
            write_fixture(root.path(), UPGRADE_ATTEMPT_PATH, journal.as_bytes(), 0o600);

            assert!(
                record_runtime_failure_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    &mut Generation(0x77),
                )
                .is_err(),
                "invalid full upgrade journal case {index} must block the recorder",
            );
            assert!(
                issue_installed_bundle_failure_evidence_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    100,
                    60_100,
                    "request_nonce_incoherent_upgrade",
                )
                .is_err(),
                "invalid full upgrade journal case {index} must expose no Evidence",
            );
            let mut retry = RetrySystemd::default();
            assert!(retry_runtime_at(root.path(), uid, &mut retry).is_err());
            assert_eq!(retry.0, 0);
            assert_eq!(
                fs::read(rooted(root.path(), EPOCH_PATH)).unwrap(),
                epoch_before
            );
            assert_eq!(
                fs::read(rooted(root.path(), LATCH_PATH)).unwrap(),
                latch_before
            );
            assert_eq!(
                fs::read(rooted(root.path(), UPGRADE_ATTEMPT_PATH)).unwrap(),
                journal.as_bytes(),
            );
        }
    }

    #[test]
    fn scope_less_upgrade_journal_requires_a_valid_target_install_binding() {
        let scoped = upgrade_journal_fixture("aborted", false, 0, 0, "none-consumed", None)
            .replacen("schema_version = 4", "schema_version = 3", 1)
            .replacen("runtime_failure_consumption = \"none-consumed\"\n", "", 1);
        for journal in [
            scope_less_upgrade_journal_fixture(&scoped, None),
            scope_less_upgrade_journal_fixture(&scoped, Some("invalid")),
        ] {
            let root = fixture();
            let uid = unsafe { libc::geteuid() };
            record_runtime_failure_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                &mut Generation(0x78),
            )
            .unwrap();
            let epoch_before = fs::read(rooted(root.path(), EPOCH_PATH)).unwrap();
            let latch_before = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();
            fs::create_dir_all(rooted(root.path(), UPGRADE_ATTEMPT_PATH).parent().unwrap())
                .unwrap();
            write_fixture(root.path(), UPGRADE_ATTEMPT_PATH, journal.as_bytes(), 0o600);

            assert!(
                record_runtime_failure_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    &mut Generation(0x79),
                )
                .is_err()
            );
            assert!(
                issue_installed_bundle_failure_evidence_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    100,
                    60_100,
                    "request_nonce_scope_less_target_binding",
                )
                .is_err()
            );
            let mut retry = RetrySystemd::default();
            assert!(retry_runtime_at(root.path(), uid, &mut retry).is_err());
            assert_eq!(retry.0, 0);
            assert_eq!(
                fs::read(rooted(root.path(), EPOCH_PATH)).unwrap(),
                epoch_before
            );
            assert_eq!(
                fs::read(rooted(root.path(), LATCH_PATH)).unwrap(),
                latch_before
            );
            assert_eq!(
                fs::read(rooted(root.path(), UPGRADE_ATTEMPT_PATH)).unwrap(),
                journal.as_bytes(),
            );
        }

        let root = fixture();
        let uid = unsafe { libc::geteuid() };
        fs::create_dir_all(rooted(root.path(), UPGRADE_ATTEMPT_PATH).parent().unwrap()).unwrap();
        let journal = scope_less_upgrade_journal_fixture(&scoped, Some(&"ca".repeat(32)));
        write_fixture(root.path(), UPGRADE_ATTEMPT_PATH, journal.as_bytes(), 0o600);
        assert_eq!(
            record_runtime_failure_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                &mut Generation(0x7a),
            )
            .unwrap(),
            RuntimeFailureRecordOutcome::Latched,
        );
        issue_installed_bundle_failure_evidence_at(
            root.path(),
            uid,
            &mut FailedRuntime(0),
            100,
            60_100,
            "request_nonce_valid_scope_less_target_binding",
        )
        .unwrap();
        let mut retry = RetrySystemd::default();
        retry_runtime_at(root.path(), uid, &mut retry).unwrap();
        assert_eq!(retry.0, 1);
    }

    #[test]
    fn strictly_completed_upgrade_journal_allows_a_later_runtime_failure_generation() {
        for (progress, binding) in [
            ("none-consumed", None),
            ("latch-removed", Some(("c9".repeat(32), "da".repeat(32)))),
        ] {
            let root = fixture();
            let uid = unsafe { libc::geteuid() };
            fs::create_dir_all(rooted(root.path(), UPGRADE_ATTEMPT_PATH).parent().unwrap())
                .unwrap();
            let journal = upgrade_journal_fixture(
                "activated",
                true,
                21,
                21,
                progress,
                binding
                    .as_ref()
                    .map(|(generation, digest)| (generation.as_str(), digest.as_str())),
            );
            write_fixture(root.path(), UPGRADE_ATTEMPT_PATH, journal.as_bytes(), 0o600);

            assert_eq!(
                record_runtime_failure_at(
                    root.path(),
                    uid,
                    &mut FailedRuntime(0),
                    &mut Generation(0xeb),
                )
                .unwrap(),
                RuntimeFailureRecordOutcome::Latched,
            );
            issue_installed_bundle_failure_evidence_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                100,
                60_100,
                "request_nonce_completed_upgrade",
            )
            .unwrap();
            let mut retry = RetrySystemd::default();
            retry_runtime_at(root.path(), uid, &mut retry).unwrap();
            assert_eq!(retry.0, 1);
            assert!(!rooted(root.path(), EPOCH_PATH).exists());
            assert!(!rooted(root.path(), LATCH_PATH).exists());
        }
    }

    #[test]
    fn legacy_activated_upgrade_without_typed_completion_blocks_a_new_generation() {
        let typed = upgrade_journal_fixture("activated", true, 21, 21, "none-consumed", None);
        let legacy = typed
            .replacen("schema_version = 4", "schema_version = 3", 1)
            .replacen("runtime_failure_consumption = \"none-consumed\"\n", "", 1);
        let root = fixture();
        let uid = unsafe { libc::geteuid() };
        fs::create_dir_all(rooted(root.path(), UPGRADE_ATTEMPT_PATH).parent().unwrap()).unwrap();
        write_fixture(root.path(), UPGRADE_ATTEMPT_PATH, legacy.as_bytes(), 0o600);

        assert!(
            record_runtime_failure_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                &mut Generation(0xec),
            )
            .is_err(),
        );
        assert!(!rooted(root.path(), EPOCH_PATH).exists());
        assert!(!rooted(root.path(), LATCH_PATH).exists());

        let root = fixture();
        record_runtime_failure_at(
            root.path(),
            uid,
            &mut FailedRuntime(0),
            &mut Generation(0xed),
        )
        .unwrap();
        let epoch_before = fs::read(rooted(root.path(), EPOCH_PATH)).unwrap();
        let latch_before = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();
        fs::create_dir_all(rooted(root.path(), UPGRADE_ATTEMPT_PATH).parent().unwrap()).unwrap();
        write_fixture(root.path(), UPGRADE_ATTEMPT_PATH, legacy.as_bytes(), 0o600);
        assert!(
            issue_installed_bundle_failure_evidence_at(
                root.path(),
                uid,
                &mut FailedRuntime(0),
                100,
                60_100,
                "request_nonce_legacy_upgrade",
            )
            .is_err(),
        );
        let mut retry = RetrySystemd::default();
        assert!(retry_runtime_at(root.path(), uid, &mut retry).is_err());
        assert_eq!(retry.0, 0);
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
    fn concurrent_recorders_publish_one_exact_pair() {
        let root = fixture();
        let uid = unsafe { libc::geteuid() };
        let path = root.path().to_path_buf();
        let outcomes = std::thread::scope(|scope| {
            let first_path = path.clone();
            let first = scope.spawn(move || {
                record_runtime_failure_at(
                    &first_path,
                    uid,
                    &mut FailedRuntime(0),
                    &mut Generation(25),
                )
                .unwrap()
            });
            let second = scope.spawn(move || {
                record_runtime_failure_at(&path, uid, &mut FailedRuntime(0), &mut Generation(26))
                    .unwrap()
            });
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert!(outcomes.contains(&RuntimeFailureRecordOutcome::Latched));
        assert!(outcomes.contains(&RuntimeFailureRecordOutcome::AlreadyLatched));
        assert!(current_epoch_at_locked(root.path(), uid).is_ok());
    }

    #[test]
    fn signed_installed_bundle_authority_consumes_only_the_current_generation() {
        let root = fixture();
        record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            }),
            &mut Generation(5),
        )
        .unwrap();
        let mut systemd = FailedRuntime(0);
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
        assert_eq!(systemd.0, 0);
        assert!(!rooted(root.path(), LATCH_PATH).exists());
        assert_eq!(
            fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH)).unwrap(),
            "operation_id = \"42\"\ntarget_probe_version = \"1.2.3\"\nstatus = \"succeeded\"\n"
        );
    }

    #[test]
    fn failed_installed_bundle_repair_keeps_the_exact_epoch_latched_and_unresolved() {
        let root = fixture();
        record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            }),
            &mut Generation(6),
        )
        .unwrap();
        let epoch_before = fs::read(rooted(root.path(), EPOCH_PATH)).unwrap();
        let latch_before = fs::read(rooted(root.path(), LATCH_PATH)).unwrap();
        let mut systemd = RejectedRepair;
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
        record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            }),
            &mut Generation(7),
        )
        .unwrap();
        let mut systemd = FailedRuntime(0);
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

    #[test]
    fn repair_reentry_removes_only_the_exact_bound_latch_and_converges_if_already_absent() {
        for (index, progress) in [
            InstalledBundleRepairProgress::InvalidationCommitted,
            InstalledBundleRepairProgress::EpochRemoved,
        ]
        .into_iter()
        .enumerate()
        {
            for latch in [b"ff".repeat(32), b"corrupt-generation".to_vec()] {
                let (root, authority) = repair_completion_fixture(progress, (0x70 + index) as u8);
                if progress == InstalledBundleRepairProgress::EpochRemoved {
                    fs::remove_file(rooted(root.path(), EPOCH_PATH)).unwrap();
                }
                write_fixture(root.path(), LATCH_PATH, &latch, 0o600);

                assert_eq!(
                    invalidate_installed_bundle_failure_at(
                        root.path(),
                        unsafe { libc::geteuid() },
                        &authority,
                    ),
                    Err(InstalledBundleRepairError::RecoveryPending),
                );
                assert_eq!(fs::read(rooted(root.path(), LATCH_PATH)).unwrap(), latch);
                let intent: InstalledBundleRepairIntent = serde_json::from_slice(
                    &fs::read(rooted(root.path(), REPAIR_INTENT_PATH)).unwrap(),
                )
                .unwrap();
                assert_eq!(intent.state, progress);
            }
        }

        let (root, authority) =
            repair_completion_fixture(InstalledBundleRepairProgress::EpochRemoved, 0x72);
        fs::remove_file(rooted(root.path(), EPOCH_PATH)).unwrap();
        fs::remove_file(rooted(root.path(), LATCH_PATH)).unwrap();
        invalidate_installed_bundle_failure_at(root.path(), unsafe { libc::geteuid() }, &authority)
            .unwrap();
        let intent: InstalledBundleRepairIntent =
            serde_json::from_slice(&fs::read(rooted(root.path(), REPAIR_INTENT_PATH)).unwrap())
                .unwrap();
        assert_eq!(intent.state, InstalledBundleRepairProgress::LatchRemoved);
    }

    #[derive(Default)]
    struct RepairEffects {
        restored: usize,
        temporary_validations: usize,
        canonical_activations: usize,
        canonical_validations: usize,
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

        fn activate_probe_on_canonical_gate(&mut self) -> Result<(), Self::Error> {
            self.canonical_activations += 1;
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
        }
    }

    #[test]
    fn upgrader_adapter_cannot_observe_or_drive_private_repair_checkpoints() {
        let upgrader = include_str!("upgrader.rs");
        let coordinator = include_str!("upgrader/repair.rs");
        assert!(coordinator.contains("drive_live_installed_bundle_repair"));
        assert!(!upgrader.contains("drive_live_installed_bundle_repair"));
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
                !upgrader.contains(private_detail) && !coordinator.contains(private_detail),
                "Repair coordinator Interface 不得观察私有 checkpoint：{private_detail}"
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
        record_runtime_failure_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut State(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            }),
            &mut Generation(generation_byte),
        )
        .unwrap();
        let signed = issue_installed_bundle_failure_evidence_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut FailedRuntime(0),
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
}
