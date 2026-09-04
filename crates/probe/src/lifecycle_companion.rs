//! Companion 的完整进程入口；binary 不解释任何 lifecycle 输入。

use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::{FromRawFd, RawFd},
        unix::fs::MetadataExt,
    },
    process::ExitCode,
};

use enoki_probe_bootstrap::lifecycle::{
    LifecycleRequest, LifecycleRequestAuthority, LifecycleResponse, LifecycleTransition,
    MAX_LIFECYCLE_REQUEST_BYTES,
};

use crate::upgrader::{
    HttpProbeUpgraderValidationTransport, resume_lifecycle_companion,
    run_adopted_replacement_child, run_lifecycle_companion_from_peer,
    run_upgrade_lifecycle_companion_from_peer,
};

const LEASE_MARKER: &str = "ENOKI_LIFECYCLE_LEASE_FD";
const LEASE_FD: RawFd = 9;
const STABLE_LOCK: &str = "/run/lock/enoki-probe-lifecycle.lock";

/// 唯一 production Companion process interface。
#[doc(hidden)]
pub fn run_lifecycle_companion_process() -> ExitCode {
    let source = match inherited_source() {
        Ok(source) => source,
        Err(()) => return write_response(LifecycleResponse::failed("lifecycle.invalid_authority")),
    };
    run(source, classify_argv())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CompanionMode {
    General,
    Upgrade,
    RecordRuntimeFailure,
    RetryRuntime,
    Invalid,
}

/// 只能由完整 fd 9 admission 构造；fd 本身持有至进程退出。
enum CompanionSource {
    NoInheritedMarker,
    AdoptedReplacementChild(AdoptedReplacementChild),
}
struct AdoptedReplacementChild {
    fd: RawFd,
}

fn classify_argv() -> CompanionMode {
    match std::env::args_os().skip(1).collect::<Vec<_>>().as_slice() {
        [] => CompanionMode::General,
        [argument] if argument == "--upgrade" => CompanionMode::Upgrade,
        [argument] if argument == "record-runtime-failure" => CompanionMode::RecordRuntimeFailure,
        [argument] if argument == "retry-runtime" => CompanionMode::RetryRuntime,
        _ => CompanionMode::Invalid,
    }
}

fn inherited_source() -> Result<CompanionSource, ()> {
    let Some(marker) = marker_value()? else {
        return Ok(CompanionSource::NoInheritedMarker);
    };
    if marker != "9" {
        return Err(());
    }
    adopt_replacement_child().map(CompanionSource::AdoptedReplacementChild)
}

/// `/proc/self/environ` 用于拒绝 duplicate/non-UTF8 marker；这不是 durable
/// product state，读失败或歧义同样 fail closed。
fn marker_value() -> Result<Option<String>, ()> {
    let bytes = fs::read("/proc/self/environ").map_err(|_| ())?;
    let prefix = format!("{LEASE_MARKER}=").into_bytes();
    let mut values = bytes
        .split(|byte| *byte == 0)
        .filter_map(|entry| entry.strip_prefix(prefix.as_slice()));
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    first
        .map(|value| String::from_utf8(value.to_vec()).map_err(|_| ()))
        .transpose()
}

fn adopt_replacement_child() -> Result<AdoptedReplacementChild, ()> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return Err(());
    }
    let flags = unsafe { libc::fcntl(LEASE_FD, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC != 0 {
        return Err(());
    }
    validate_stable_lock(LEASE_FD)?;
    validate_fdinfo(LEASE_FD)?;
    if unsafe { libc::fcntl(LEASE_FD, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
        return Err(());
    }
    Ok(AdoptedReplacementChild { fd: LEASE_FD })
}

fn validate_stable_lock(fd: RawFd) -> Result<(), ()> {
    let parent = fs::symlink_metadata("/run/lock").map_err(|_| ())?;
    if !parent.is_dir() || parent.file_type().is_symlink() || parent.uid() != 0 || parent.gid() != 0
    {
        return Err(());
    }
    let path = fs::symlink_metadata(STABLE_LOCK).map_err(|_| ())?;
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate < 0 {
        return Err(());
    }
    let file = unsafe { fs::File::from_raw_fd(duplicate) };
    let held = file.metadata().map_err(|_| ())?;
    if !canonical_lock(&path)
        || !canonical_lock(&held)
        || path.file_type().is_symlink()
        || path.dev() != held.dev()
        || path.ino() != held.ino()
    {
        return Err(());
    }
    Ok(())
}

fn canonical_lock(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.nlink() == 1
        && metadata.len() == 0
        && metadata.mode() & 0o7777 == 0o600
}

fn validate_fdinfo(fd: RawFd) -> Result<(), ()> {
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate < 0 {
        return Err(());
    }
    let file = unsafe { fs::File::from_raw_fd(duplicate) };
    let inode = file.metadata().map_err(|_| ())?.ino().to_string();
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).map_err(|_| ())?;
    let valid = fdinfo
        .lines()
        .filter(|line| line.starts_with("lock:"))
        .filter(|line| {
            line.contains("FLOCK ADVISORY WRITE")
                && line.ends_with(" 0 EOF")
                && line.split_whitespace().any(|word| word.ends_with(&inode))
        })
        .count();
    (valid == 1).then_some(()).ok_or(())
}

fn run(source: CompanionSource, mode: CompanionMode) -> ExitCode {
    match (&source, mode) {
        (CompanionSource::AdoptedReplacementChild(_), CompanionMode::General) => {}
        (CompanionSource::AdoptedReplacementChild(_), _) => return invalid_authority(),
        (CompanionSource::NoInheritedMarker, CompanionMode::Invalid) => return ExitCode::from(2),
        (CompanionSource::NoInheritedMarker, CompanionMode::RecordRuntimeFailure) => {
            return runtime_exit(crate::runtime_failure::record_runtime_failure());
        }
        (CompanionSource::NoInheritedMarker, CompanionMode::RetryRuntime) => {
            return runtime_exit(crate::runtime_failure::retry_runtime());
        }
        (CompanionSource::NoInheritedMarker, CompanionMode::Upgrade)
            if unsafe { libc::getuid() } != 0 =>
        {
            return ExitCode::from(2);
        }
        (CompanionSource::NoInheritedMarker, _) => {}
    }

    let mut bytes = Vec::new();
    if std::io::stdin()
        .take(MAX_LIFECYCLE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES
    {
        return write_response(LifecycleResponse::failed("lifecycle.invalid_request"));
    }
    let peer_uid = stdin_peer_uid();
    let process_uid = unsafe { libc::getuid() };
    if bytes.is_empty() {
        return match source {
            CompanionSource::AdoptedReplacementChild(_) => invalid_authority(),
            CompanionSource::NoInheritedMarker
                if mode == CompanionMode::Upgrade || peer_uid.is_some() || process_uid != 0 =>
            {
                invalid_authority()
            }
            CompanionSource::NoInheritedMarker => {
                let mut transport = HttpProbeUpgraderValidationTransport;
                write_terminal_response(resume_lifecycle_companion(&mut transport))
            }
        };
    }
    let request = match LifecycleRequest::decode(&bytes) {
        Ok(request) => request,
        Err(_) => return write_response(LifecycleResponse::failed("lifecycle.invalid_request")),
    };
    match source {
        CompanionSource::AdoptedReplacementChild(lease) => {
            let _held_lease_fd = lease.fd;
            if mode != CompanionMode::General
                || request.transition() != LifecycleTransition::ReplacementMigration
                || !caller_is_authorized(request.authority(), peer_uid, process_uid)
            {
                return invalid_authority();
            }
            write_response(run_adopted_replacement_child(&request))
        }
        CompanionSource::NoInheritedMarker => {
            if request.transition() == LifecycleTransition::ReplacementMigration {
                return invalid_authority();
            }
            if !mode_accepts(mode, request.transition()) {
                return write_response(LifecycleResponse::not_enabled());
            }
            if !caller_is_authorized(request.authority(), peer_uid, process_uid) {
                return invalid_authority();
            }
            if mode == CompanionMode::Upgrade {
                write_response(run_upgrade_lifecycle_companion_from_peer(
                    &request, peer_uid,
                ))
            } else {
                let mut transport = HttpProbeUpgraderValidationTransport;
                let response =
                    run_lifecycle_companion_from_peer(&request, &mut transport, peer_uid);
                if request.transition() == LifecycleTransition::Uninstall {
                    write_terminal_response(response)
                } else {
                    write_response(response)
                }
            }
        }
    }
}

fn invalid_authority() -> ExitCode {
    write_response(LifecycleResponse::failed("lifecycle.invalid_authority"))
}
fn runtime_exit<T>(result: Result<T, impl Sized>) -> ExitCode {
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
fn mode_accepts(mode: CompanionMode, transition: LifecycleTransition) -> bool {
    (mode == CompanionMode::Upgrade) == (transition == LifecycleTransition::Upgrade)
}

fn caller_is_authorized(
    authority: &LifecycleRequestAuthority,
    peer_uid: Option<u32>,
    process_uid: u32,
) -> bool {
    match authority {
        LifecycleRequestAuthority::HubUpgrade { .. }
        | LifecycleRequestAuthority::HubOperation { .. } => peer_uid.is_some(),
        LifecycleRequestAuthority::LocalRoot { .. }
        | LifecycleRequestAuthority::LocalRepair { .. }
        | LifecycleRequestAuthority::ReplacementEnrollment { .. } => {
            peer_uid.map_or(process_uid == 0, |uid| uid == 0)
        }
    }
}

fn stdin_peer_uid() -> Option<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            libc::STDIN_FILENO,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of::<libc::ucred>())
        .then_some(credentials.uid)
}

fn write_response(response: LifecycleResponse) -> ExitCode {
    let mut stdout = std::io::stdout();
    if stdout
        .write_all(&response.encode())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::from(1);
    }
    match response.status() {
        enoki_probe_bootstrap::lifecycle::LifecycleResultStatus::Succeeded => ExitCode::SUCCESS,
        enoki_probe_bootstrap::lifecycle::LifecycleResultStatus::Failed
        | enoki_probe_bootstrap::lifecycle::LifecycleResultStatus::NotEnabled => ExitCode::from(1),
    }
}

/// 只有已完成本机 no-residue proof 的 terminal response 才能在 canonical
/// frame flush 后自删除；失败时追加协议外字节，调用方不会接受该 success。
fn write_terminal_response(response: LifecycleResponse) -> ExitCode {
    if response != LifecycleResponse::succeeded() {
        return write_response(response);
    }
    let frame = response.encode();
    let mut stdout = std::io::stdout();
    if stdout
        .write_all(&frame)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::from(1);
    }
    if crate::upgrader::finalize_lifecycle_companion_binary() {
        return ExitCode::SUCCESS;
    }
    let _ = stdout.write_all(b"\n").and_then(|()| stdout.flush());
    ExitCode::from(1)
}
