//! Observation Runtime 启动预算耗尽的固定 recorder 与终止性 latch。

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use enoki_probe_bootstrap::lifecycle::{
    InstalledBundleFailureEvidenceV1, InstalledBundleRepairAuthorityV1,
};

const RUNTIME_UNIT: &str = "enoki-observation-runtime.service";
const METADATA_PATH: &str = "/etc/enoki/probe-install.toml";
const IDENTITY_PATH: &str = "/var/lib/enoki-probe/identity/probe-bootstrap.toml";
const UNIT_PATH: &str = "/etc/systemd/system/enoki-observation-runtime.service";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const FAILURE_DIR: &str = "/var/lib/enoki-probe/runtime-failure";
const EPOCH_PATH: &str = "/var/lib/enoki-probe/runtime-failure/epoch.toml";
const LATCH_PATH: &str = "/var/lib/enoki-probe/runtime-failure/latch";
const OPERATION_STATUS_PATH: &str = "/var/lib/enoki-probe/probe-operation-status.toml";

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
    probe_id: String,
    identity_receipt_sha256: String,
    install_state_sha256: String,
    manifest_sha256: String,
    bundle_version: String,
    result: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedInstalledBundleFailureEvidence {
    pub evidence: InstalledBundleFailureEvidenceV1,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledBundleRepairError {
    InvalidBoundary,
    RuntimeRestartFailed,
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

pub fn consume_installed_bundle_repair_authority(
    signed: &SignedInstalledBundleFailureEvidence,
    authority: &InstalledBundleRepairAuthorityV1,
    authority_signature: &str,
    now_ms: u64,
) -> Result<(String, String), InstalledBundleRepairError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(InstalledBundleRepairError::InvalidBoundary);
    }
    consume_installed_bundle_repair_authority_at(
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
    let epoch_path = rooted(root, EPOCH_PATH);
    let latch_path = rooted(root, LATCH_PATH);
    let epoch_bytes = trusted_file(&epoch_path, expected_uid, 0o600)?;
    let epoch: RuntimeFailureEpoch = toml::from_str(
        std::str::from_utf8(&epoch_bytes)
            .map_err(|_| std::io::Error::other("failure epoch invalid"))?,
    )
    .map_err(|_| std::io::Error::other("failure epoch invalid"))?;
    let latch = trusted_file(&latch_path, expected_uid, 0o600)?;
    if latch != epoch.generation.as_bytes()
        || epoch.boot_id
            != String::from_utf8(trusted_file(
                &rooted(root, BOOT_ID_PATH),
                expected_uid,
                0o444,
            )?)
            .map_err(|_| std::io::Error::other("boot binding invalid"))?
            .trim()
    {
        return Err(std::io::Error::other("failure epoch binding invalid"));
    }
    fs::remove_file(&latch_path)?;
    fs::remove_file(&epoch_path)?;
    File::open(rooted(root, FAILURE_DIR))?.sync_all()?;
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
    let state = systemd.fixed_runtime_state()?;
    if state.active_state != "failed" || state.result != "start-limit-hit" {
        return Err(std::io::Error::other("failure epoch is no longer current"));
    }
    let (epoch, metadata) = current_epoch_at(root, expected_uid)?;
    let install_key = metadata_string(&metadata, "lifecycle_authority_install_key")
        .and_then(|value| decode_lower_hex_32(&value))
        .ok_or_else(|| std::io::Error::other("install authority unavailable"))?;
    let evidence = InstalledBundleFailureEvidenceV1 {
        kind: "installed_bundle_failure".to_owned(),
        schema_version: 1,
        hub_origin: epoch.hub_origin,
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
fn consume_installed_bundle_repair_authority_at<T>(
    root: &Path,
    expected_uid: u32,
    systemd: &mut T,
    signed: &SignedInstalledBundleFailureEvidence,
    authority: &InstalledBundleRepairAuthorityV1,
    authority_signature: &str,
    now_ms: u64,
) -> Result<(String, String), InstalledBundleRepairError>
where
    T: RuntimeFailureSystemd + RuntimeRetrySystemd,
{
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
        || authority.hub_origin != signed.evidence.hub_origin
        || authority.probe_id != signed.evidence.probe_id
        || authority.generation != signed.evidence.generation
        || authority.boot_id != signed.evidence.boot_id
        || authority.unit != signed.evidence.unit
        || authority.unit_sha256 != signed.evidence.unit_sha256
        || authority.identity_receipt_sha256 != signed.evidence.identity_receipt_sha256
        || authority.install_state_sha256 != signed.evidence.install_state_sha256
        || authority.manifest_sha256 != signed.evidence.manifest_sha256
        || authority.bundle_version != signed.evidence.bundle_version
        || authority.repair_evidence_sha256 != signed.evidence.sha256()
        || !valid_identifier(&authority.host_id)
        || !valid_identifier(&authority.repair_operation_id)
        || !valid_identifier(&authority.repair_nonce)
    {
        return Err(InstalledBundleRepairError::InvalidBoundary);
    }
    write_installed_bundle_repair_status(root, authority, "running", None)
        .map_err(|_| InstalledBundleRepairError::InvalidBoundary)?;
    if retry_runtime_at(root, expected_uid, systemd).is_err() {
        let _ = write_installed_bundle_repair_status(
            root,
            authority,
            "failed",
            Some("lifecycle.repair_unresolved"),
        );
        return Err(InstalledBundleRepairError::RuntimeRestartFailed);
    }
    write_installed_bundle_repair_status(root, authority, "succeeded", None)
        .map_err(|_| InstalledBundleRepairError::RuntimeRestartFailed)?;
    Ok((authority.probe_id.clone(), authority.bundle_version.clone()))
}

fn write_installed_bundle_repair_status(
    root: &Path,
    authority: &InstalledBundleRepairAuthorityV1,
    status: &str,
    error_code: Option<&str>,
) -> std::io::Result<()> {
    if !matches!(status, "running" | "succeeded" | "failed") {
        return Err(std::io::Error::other("repair status invalid"));
    }
    let mut contents = format!(
        "operation_id = {:?}\ntarget_probe_version = {:?}\nstatus = {:?}\n",
        authority.repair_operation_id, authority.bundle_version, status,
    );
    if let Some(error_code) = error_code {
        contents.push_str(&format!("error_code = {error_code:?}\nmessage = \"\"\n"));
    }
    atomic_write(
        &rooted(root, OPERATION_STATUS_PATH),
        contents.as_bytes(),
        0o644,
    )
}

fn current_epoch_at(
    root: &Path,
    expected_uid: u32,
) -> std::io::Result<(RuntimeFailureEpoch, toml::Value)> {
    trusted_state_directory(&rooted(root, "/var/lib/enoki-probe"))?;
    let epoch_bytes = trusted_file(&rooted(root, EPOCH_PATH), expected_uid, 0o600)?;
    let epoch: RuntimeFailureEpoch = toml::from_str(
        std::str::from_utf8(&epoch_bytes)
            .map_err(|_| std::io::Error::other("failure epoch invalid"))?,
    )
    .map_err(|_| std::io::Error::other("failure epoch invalid"))?;
    let latch = trusted_file(&rooted(root, LATCH_PATH), expected_uid, 0o600)?;
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
        || latch != epoch.generation.as_bytes()
        || epoch.boot_id != boot_id.trim()
        || epoch.unit_sha256 != sha256(&unit)
        || epoch.identity_receipt_sha256 != sha256(&identity)
        || epoch.hub_origin != metadata_string(&metadata, "hub_url").unwrap_or_default()
        || epoch.hub_origin != metadata_string(&identity_value, "hub_url").unwrap_or_default()
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
) -> std::io::Result<RuntimeFailureRecordOutcome> {
    let state = systemd.fixed_runtime_state()?;
    if state.active_state != "failed" || state.result != "start-limit-hit" {
        return Ok(RuntimeFailureRecordOutcome::Ignored);
    }
    let failure_dir = rooted(root, FAILURE_DIR);
    let epoch_path = rooted(root, EPOCH_PATH);
    let latch_path = rooted(root, LATCH_PATH);
    trusted_state_directory(&rooted(root, "/var/lib/enoki-probe"))?;
    if epoch_path.exists() || latch_path.exists() {
        current_epoch_at(root, expected_uid)?;
        return Ok(RuntimeFailureRecordOutcome::AlreadyLatched);
    }

    if failure_dir.exists() {
        trusted_directory(&failure_dir, expected_uid, 0o700)?;
    } else {
        fs::DirBuilder::new().mode(0o700).create(&failure_dir)?;
        trusted_directory(&failure_dir, expected_uid, 0o700)?;
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
    let mut generation = [0_u8; 32];
    generations.fill_generation(&mut generation)?;
    let epoch = RuntimeFailureEpoch {
        schema_version: 1,
        generation: hex(&generation),
        boot_id: boot_id.trim().to_owned(),
        unit: RUNTIME_UNIT.to_owned(),
        unit_sha256: sha256(&unit),
        hub_origin,
        probe_id: string(&identity_value, "probe_id")?,
        identity_receipt_sha256: sha256(&identity),
        install_state_sha256: string(&metadata, "install_state_sha256")?,
        manifest_sha256: string(&metadata, "target_manifest_sha256")?,
        bundle_version: string(&metadata, "bundle_version")?,
        result: state.result,
    };
    let encoded =
        toml::to_string(&epoch).map_err(|_| std::io::Error::other("failure epoch invalid"))?;
    atomic_write(&epoch_path, encoded.as_bytes(), 0o600)?;
    atomic_write(&latch_path, epoch.generation.as_bytes(), 0o600)?;
    Ok(RuntimeFailureRecordOutcome::Latched)
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

fn trusted_state_directory(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o7777 != 0o700
        || metadata.nlink() < 2
    {
        return Err(std::io::Error::other("state directory boundary invalid"));
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let temporary = path.with_extension("enoki-new");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(
        path.parent()
            .ok_or_else(|| std::io::Error::other("no parent"))?,
    )?
    .sync_all()
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
mod tests {
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

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for directory in [
            "etc/enoki",
            "var/lib/enoki-probe/identity",
            "etc/systemd/system",
            "proc/sys/kernel/random",
        ] {
            fs::create_dir_all(root.path().join(directory)).unwrap();
        }
        fs::set_permissions(
            root.path().join("var/lib/enoki-probe"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let metadata = "hub_url = \"https://hub.example\"\ninstall_state_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\ntarget_manifest_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\nbundle_version = \"1.2.3\"\nlifecycle_authority_install_key = \"1111111111111111111111111111111111111111111111111111111111111111\"\n";
        let identity = "hub_url = \"https://hub.example\"\nprobe_id = \"probe_01\"\n";
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
    fn typed_local_retry_consumes_the_latch_before_one_fixed_retry() {
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
        let identity = consume_installed_bundle_repair_authority_at(
            root.path(),
            unsafe { libc::geteuid() },
            &mut systemd,
            &signed,
            &authority,
            &signature,
            101,
        )
        .unwrap();
        assert_eq!(identity, ("probe_01".into(), "1.2.3".into()));
        assert_eq!(systemd.0, 1);
        assert!(!rooted(root.path(), LATCH_PATH).exists());
        assert_eq!(
            fs::read_to_string(rooted(root.path(), OPERATION_STATUS_PATH)).unwrap(),
            "operation_id = \"42\"\ntarget_probe_version = \"1.2.3\"\nstatus = \"succeeded\"\n"
        );
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
