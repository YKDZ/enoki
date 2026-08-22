use super::transaction::OWNERSHIP_MARKER;
use super::*;
pub(super) fn ensure_fixed_metadata_directory(
    path: &Path,
    journal: &mut TransactionJournal,
) -> Result<bool, InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_existing_metadata_directory(path)?;
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(
                path,
                0o755,
                ServiceIdentity { uid: 0, gid: 0 },
                journal,
                RollbackStep::RemoveMetadataDirectory,
            )?;
            Ok(true)
        }
        Err(_) => Err(InstallError::Io),
    }
}

pub(super) fn preflight_fixed_metadata_directory(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_existing_metadata_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError::Io),
    }
}

pub(super) fn validate_existing_metadata_directory(path: &Path) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o755
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

pub(super) fn remove_created_path(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|_| InstallError::Io)?;
            sync_parent_directory(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(InstallError::Io),
    }
}

pub(super) fn remove_created_directory(path: &Path) -> Result<(), InstallError> {
    let marker = path.join(OWNERSHIP_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(&marker).map_err(|_| InstallError::Io)?;
            File::open(path)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| InstallError::Io)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Err(InstallError::ExistingResidue),
    }
    match fs::remove_dir(path) {
        Ok(()) => sync_parent_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError::Io),
    }
}

fn sync_parent_directory(path: &Path) -> Result<(), InstallError> {
    File::open(path.parent().ok_or(InstallError::Io)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InstallError::Io)
}

pub(super) fn validate_component(
    component: &mut File,
    expected_len: u64,
) -> Result<(), InstallError> {
    let metadata = component.metadata().map_err(|_| InstallError::Io)?;
    if !metadata.is_file() || metadata.len() != expected_len {
        return Err(InstallError::InvalidVerifiedComponent);
    }
    component
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallError::Io)?;
    Ok(())
}

pub(super) fn preflight_files(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    for path in [
        paths.binary(),
        paths.state(),
        paths.identity_dir(),
        paths.identity(),
        paths.metadata(),
        paths.unit(),
        paths.map(OPERATION_SUDOERS),
        paths.map(COLLECTOR_SUDOERS),
        paths.map(LEGACY_SUDOERS),
        paths.map("/etc/enoki/probe-bootstrap.toml"),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(InstallError::ExistingResidue),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(InstallError::Io),
        }
    }
    Ok(())
}

pub(super) fn preflight_parent_chains(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    for path in [
        paths.binary(),
        paths.state(),
        paths.etc_enoki(),
        paths.unit(),
        paths.map(OPERATION_SUDOERS),
        paths.bootstrap_acquirer(),
    ] {
        ensure_safe_parent_chain(path.parent().ok_or(InstallError::Io)?)?;
    }
    Ok(())
}

/// 两个 Bootstrap role 早于本事务安装，仅在 schema-2 metadata 原子落盘后才归 Probe
/// 管理；在此之前，激活失败必须保留它们。
pub(super) fn validate_bootstrap_role(path: &Path) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o755
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

pub(super) fn create_private_directory(
    path: &Path,
    mode: u32,
    identity: ServiceIdentity,
    journal: &mut TransactionJournal,
    step: RollbackStep,
) -> Result<(), InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    let temporary = exclusive_temp_directory(parent)?;
    let configured = (|| {
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
            .map_err(|_| InstallError::Io)?;
        let directory = File::open(&temporary).map_err(|_| InstallError::Io)?;
        chown_file(&directory, identity)?;
        let marker = temporary.join(OWNERSHIP_MARKER);
        let mut marker_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&marker)
            .map_err(|_| InstallError::Io)?;
        marker_file
            .write_all(journal.transaction_id().as_bytes())
            .map_err(|_| InstallError::Io)?;
        marker_file.sync_all().map_err(|_| InstallError::Io)?;
        chown_file(&marker_file, identity)?;
        verify_directory(&temporary, mode, identity)?;
        directory.sync_all().map_err(|_| InstallError::Io)
    })();
    if let Err(error) = configured {
        return Err(cleanup_partial_directory(&temporary, error));
    }
    let owned = OwnedPath::planned_from(&temporary, path, true, step)?;
    if let Err(error) = journal.record_path(owned) {
        return Err(cleanup_partial_directory(&temporary, error));
    }
    rename_directory_new(&temporary, path)
}

pub(super) fn cleanup_partial_directory(path: &Path, cause: InstallError) -> InstallError {
    match fs::remove_dir(path) {
        Ok(()) => match sync_parent_directory(path) {
            Ok(()) => cause,
            Err(error) => error,
        },
        Err(_) => InstallError::Rollback {
            cause: cause.kind(),
            failures: vec![RollbackFailure::new(
                RollbackStep::RemovePartiallyInstalledPath,
                InstallErrorKind::Io,
            )],
        },
    }
}

pub(super) fn ensure_safe_parent_chain(path: &Path) -> Result<(), InstallError> {
    let mut current = Some(path);
    while let Some(directory) = current {
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            }
            _ => return Err(InstallError::Io),
        }
        current = directory.parent();
    }
    Ok(())
}

pub(super) fn verify_directory(
    path: &Path,
    mode: u32,
    identity: ServiceIdentity,
) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.mode() & 0o777 != mode
        || metadata.uid() != identity.uid
        || metadata.gid() != identity.gid
    {
        return Err(InstallError::Io);
    }
    Ok(())
}

pub(super) fn install_binary(
    component: &mut File,
    destination: &Path,
    journal: &mut TransactionJournal,
    step: RollbackStep,
) -> Result<(), InstallError> {
    let parent = destination.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    component
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallError::Io)?;
    let mut output = exclusive_temp(parent, 0o755)?;
    let staged = (|| {
        std::io::copy(component, &mut output.0).map_err(|_| InstallError::Io)?;
        output.0.sync_all().map_err(|_| InstallError::Io)?;
        chown_file(&output.0, ServiceIdentity { uid: 0, gid: 0 })
    })();
    if let Err(error) = staged {
        return Err(cleanup_temporary_file(&output.1, error));
    }
    let owned = OwnedPath::planned_from(&output.1, destination, false, step)?;
    if let Err(error) = journal.record_path(owned) {
        return Err(cleanup_temporary_file(&output.1, error));
    }
    rename_new(output.1, destination)
}

pub(super) fn atomic_write_owned(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: ServiceIdentity,
    journal: &mut TransactionJournal,
    step: RollbackStep,
) -> Result<(), InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    let (mut file, temporary) = exclusive_temp(parent, mode)?;
    let staged = (|| {
        file.write_all(contents).map_err(|_| InstallError::Io)?;
        file.sync_all().map_err(|_| InstallError::Io)?;
        chown_file(&file, owner)
    })();
    if let Err(error) = staged {
        return Err(cleanup_temporary_file(&temporary, error));
    }
    let owned = OwnedPath::planned_from(&temporary, path, false, step)?;
    if let Err(error) = journal.record_path(owned) {
        return Err(cleanup_temporary_file(&temporary, error));
    }
    rename_new(temporary, path)
}

fn exclusive_temp_directory(parent: &Path) -> Result<PathBuf, InstallError> {
    for suffix in 0..32 {
        let path = parent.join(format!(".enoki-probe-bootstrap-directory-{suffix}"));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(InstallError::Io),
        }
    }
    Err(InstallError::Io)
}

fn rename_directory_new(from: &Path, destination: &Path) -> Result<(), InstallError> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let from_c = CString::new(from.as_os_str().as_bytes()).map_err(|_| InstallError::Io)?;
    let destination_c =
        CString::new(destination.as_os_str().as_bytes()).map_err(|_| InstallError::Io)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from_c.as_ptr(),
            libc::AT_FDCWD,
            destination_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            cleanup_partial_directory(from, InstallError::ExistingResidue)
        } else {
            cleanup_partial_directory(from, InstallError::Io)
        });
    }
    File::open(destination.parent().ok_or(InstallError::Io)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InstallError::Io)
}

pub(super) fn exclusive_temp(parent: &Path, mode: u32) -> Result<(File, PathBuf), InstallError> {
    for suffix in 0..32 {
        let path = parent.join(format!(".enoki-probe-bootstrap-{suffix}"));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path);
        match opened {
            Ok(file) => {
                // 创建时的 `mode` 会受调用者 umask 影响；在链接进 layout 前，
                // 必须在已打开 descriptor 上恢复精确权限。
                if file
                    .set_permissions(fs::Permissions::from_mode(mode))
                    .is_err()
                {
                    return Err(cleanup_temporary_file(&path, InstallError::Io));
                }
                return Ok((file, path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(InstallError::Io),
        }
    }
    Err(InstallError::Io)
}

pub(super) fn rename_new(from: PathBuf, destination: &Path) -> Result<(), InstallError> {
    match fs::hard_link(&from, destination) {
        Ok(()) => {
            let committed = fs::remove_file(&from)
                .and_then(|()| {
                    File::open(
                        destination
                            .parent()
                            .ok_or(std::io::Error::other("no parent"))?,
                    )
                })
                .and_then(|directory| directory.sync_all())
                .map_err(|_| InstallError::Io);
            if let Err(error) = committed {
                let mut failures = Vec::new();
                record_io_cleanup(
                    &mut failures,
                    RollbackStep::RemovePartiallyInstalledPath,
                    remove_file_durable_io(destination),
                );
                record_io_cleanup(
                    &mut failures,
                    RollbackStep::RemoveTemporary,
                    remove_file_durable_io(&from),
                );
                return if failures.is_empty() {
                    Err(error)
                } else {
                    Err(InstallError::Rollback {
                        cause: error.kind(),
                        failures,
                    })
                };
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(cleanup_temporary_file(&from, InstallError::ExistingResidue))
        }
        Err(_) => Err(cleanup_temporary_file(&from, InstallError::Io)),
    }
}

pub(super) fn cleanup_temporary_file(path: &Path, cause: InstallError) -> InstallError {
    match fs::remove_file(path) {
        Ok(()) => match sync_parent_directory(path) {
            Ok(()) => cause,
            Err(error) => error,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => cause,
        Err(_) => InstallError::Rollback {
            cause: cause.kind(),
            failures: vec![RollbackFailure::new(
                RollbackStep::RemoveTemporary,
                InstallErrorKind::Io,
            )],
        },
    }
}

fn remove_file_durable_io(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)?;
    File::open(
        path.parent()
            .ok_or_else(|| std::io::Error::other("no parent"))?,
    )?
    .sync_all()
}

pub(super) fn record_io_cleanup(
    failures: &mut Vec<RollbackFailure>,
    step: RollbackStep,
    result: std::io::Result<()>,
) {
    if let Err(error) = result
        && error.kind() != std::io::ErrorKind::NotFound
    {
        failures.push(RollbackFailure::new(step, InstallErrorKind::Io));
    }
}

pub(super) fn chown_file(file: &File, identity: ServiceIdentity) -> Result<(), InstallError> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::fchown(file.as_raw_fd(), identity.uid, identity.gid) } != 0 {
        return Err(InstallError::Io);
    }
    Ok(())
}
