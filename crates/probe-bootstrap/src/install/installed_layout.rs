use super::{FixedInstallPaths, InstallError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(super) const TARGET_COUNT: usize = 21;
const MAX_TEXT_BYTES: u64 = 256 * 1024;
const MAX_TARGET_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub(super) enum TargetKind {
    Bundle(&'static str),
    Unit(fn() -> String),
    Identity,
    Metadata,
}

#[derive(Clone, Debug)]
pub(super) struct Target {
    pub(super) id: &'static str,
    pub(super) destination: PathBuf,
    pub(super) kind: TargetKind,
    pub(super) mode: u32,
}

pub(super) fn registry(paths: &FixedInstallPaths) -> Vec<Target> {
    vec![
        target("probe", paths.binary(), TargetKind::Bundle("probe"), 0o755),
        target(
            "observation-runtime",
            paths.observation_runtime_binary(),
            TargetKind::Bundle("observation-runtime"),
            0o755,
        ),
        target(
            "system-state-provider",
            paths.cpu_provider_binary(),
            TargetKind::Bundle("system-state-provider"),
            0o755,
        ),
        target(
            "disk-health-provider",
            paths.disk_health_provider_binary(),
            TargetKind::Bundle("disk-health-provider"),
            0o755,
        ),
        target(
            "lifecycle-companion",
            paths.lifecycle_companion_binary(),
            TargetKind::Bundle("lifecycle-companion"),
            0o755,
        ),
        target(
            "bootstrap-acquirer",
            paths.bootstrap_acquirer(),
            TargetKind::Bundle("bootstrap-acquirer"),
            0o755,
        ),
        target(
            "bootstrap-activator",
            paths.bootstrap_activator(),
            TargetKind::Bundle("bootstrap-activator"),
            0o755,
        ),
        target(
            "probe-unit",
            paths.unit(),
            TargetKind::Unit(super::service_unit),
            0o644,
        ),
        target(
            "runtime-unit",
            paths.observation_runtime_unit(),
            TargetKind::Unit(super::observation_runtime_unit),
            0o644,
        ),
        target(
            "runtime-socket",
            paths.observation_runtime_socket_unit(),
            TargetKind::Unit(runtime_socket),
            0o644,
        ),
        target(
            "cpu-unit",
            paths.cpu_provider_unit(),
            TargetKind::Unit(super::cpu_provider_unit),
            0o644,
        ),
        target(
            "cpu-socket",
            paths.cpu_provider_socket_unit(),
            TargetKind::Unit(cpu_socket),
            0o644,
        ),
        target(
            "disk-unit",
            paths.disk_health_provider_unit(),
            TargetKind::Unit(super::disk_health_provider_unit),
            0o644,
        ),
        target(
            "disk-socket",
            paths.disk_health_provider_socket_unit(),
            TargetKind::Unit(disk_socket),
            0o644,
        ),
        target(
            "lifecycle-unit",
            paths.lifecycle_companion_unit(),
            TargetKind::Unit(super::lifecycle_companion_unit),
            0o644,
        ),
        target(
            "lifecycle-socket",
            paths.lifecycle_companion_socket_unit(),
            TargetKind::Unit(lifecycle_socket),
            0o644,
        ),
        target(
            "upgrade-unit",
            paths.lifecycle_upgrade_unit(),
            TargetKind::Unit(super::lifecycle_upgrade_unit),
            0o644,
        ),
        target(
            "upgrade-socket",
            paths.lifecycle_upgrade_socket_unit(),
            TargetKind::Unit(upgrade_socket),
            0o644,
        ),
        target("identity", paths.identity(), TargetKind::Identity, 0o600),
        target("metadata", paths.metadata(), TargetKind::Metadata, 0o600),
        target(
            "runtime-failure-recorder-unit",
            paths.observation_runtime_failure_recorder_unit(),
            TargetKind::Unit(super::observation_runtime_failure_recorder_unit),
            0o644,
        ),
    ]
}

fn target(id: &'static str, destination: PathBuf, kind: TargetKind, mode: u32) -> Target {
    Target {
        id,
        destination,
        kind,
        mode,
    }
}

fn runtime_socket() -> String {
    super::observation_runtime_socket_unit().to_owned()
}
fn cpu_socket() -> String {
    super::cpu_provider_socket_unit().to_owned()
}
fn disk_socket() -> String {
    super::disk_health_provider_socket_unit().to_owned()
}
fn lifecycle_socket() -> String {
    super::lifecycle_companion_socket_unit().to_owned()
}
fn upgrade_socket() -> String {
    super::lifecycle_upgrade_socket_unit().to_owned()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Fingerprint {
    pub(super) length: u64,
    pub(super) sha256: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mode: u32,
}

pub(super) fn fingerprint(path: &Path) -> Result<Fingerprint, InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    if metadata.len() > MAX_TARGET_BYTES {
        return Err(InstallError::ExistingResidue);
    }
    fingerprint_bounded(path, metadata.len())
}

pub(super) fn verify_fingerprint(path: &Path, expected: &Fingerprint) -> Result<(), InstallError> {
    (fingerprint_bounded(path, expected.length)? == *expected)
        .then_some(())
        .ok_or(InstallError::ExistingResidue)
}

fn fingerprint_bounded(path: &Path, max_length: u64) -> Result<Fingerprint, InstallError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| InstallError::ExistingResidue)?;
    let opened = file.metadata().map_err(|_| InstallError::ExistingResidue)?;
    if path_metadata.file_type().is_symlink()
        || !opened.is_file()
        || path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
        || opened.nlink() != 1
        || opened.len() > max_length
    {
        return Err(InstallError::ExistingResidue);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_length.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| InstallError::Io)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > max_length {
        return Err(InstallError::ExistingResidue);
    }
    Ok(Fingerprint {
        length: opened.len(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        uid: opened.uid(),
        gid: opened.gid(),
        mode: opened.mode() & 0o7777,
    })
}

pub(super) fn trusted_text(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<String, InstallError> {
    let mut file = trusted_file(path, uid, gid, mode, MAX_TEXT_BYTES)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_TEXT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallError::Io)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_TEXT_BYTES {
        return Err(InstallError::ExistingResidue);
    }
    String::from_utf8(bytes).map_err(|_| InstallError::ExistingResidue)
}

pub(super) fn trusted_file(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    max_length: u64,
) -> Result<File, InstallError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| InstallError::ExistingResidue)?;
    let opened = file.metadata().map_err(|_| InstallError::ExistingResidue)?;
    if path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
        || path_metadata.file_type().is_symlink()
        || !opened.is_file()
        || opened.uid() != uid
        || opened.gid() != gid
        || opened.mode() & 0o7777 != mode
        || opened.nlink() != 1
        || opened.len() > max_length
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(file)
}
