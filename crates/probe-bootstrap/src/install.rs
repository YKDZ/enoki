//! The fixed fresh-install adapter for the current Probe component.
//!
//! This is intentionally a small closed boundary: a verified component can
//! become only the current Probe service at the paths below.  It has no
//! archive, network, command-line interpolation, or candidate-code surface.

use crate::{
    handoff::Enrollment,
    trust::{BootstrapRole, BuildTrust},
    verifier::VerifiedBundle,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

const SERVICE_NAME: &str = "enoki-probe";
const SERVICE_USER: &str = "enoki-probe";
const SERVICE_GROUP: &str = "enoki-probe";
const BINARY: &str = "/usr/local/bin/enoki-probe";
const STATE: &str = "/var/lib/enoki-probe";
const IDENTITY_DIR: &str = "/var/lib/enoki-probe/identity";
const IDENTITY: &str = "/var/lib/enoki-probe/identity/probe-bootstrap.toml";
const INSTALL_METADATA: &str = "/etc/enoki/probe-install.toml";
const UNIT: &str = "/etc/systemd/system/enoki-probe.service";
const BOOTSTRAP_ACQUIRER: &str = "/usr/local/bin/enoki-probe-bootstrap-acquire";
const BOOTSTRAP_ACTIVATOR: &str = "/usr/local/bin/enoki-probe-bootstrap-activate";
const BOOTSTRAP_STATE: &str = "/var/lib/enoki-probe-bootstrap";
const OPERATION_SUDOERS: &str = "/etc/sudoers.d/enoki-probe-operations";
const COLLECTOR_SUDOERS: &str = "/etc/sudoers.d/enoki-probe-collector-helpers";
const LEGACY_SUDOERS: &str = "/etc/sudoers.d/enoki-probe-upgrader";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ServiceIdentity {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InstallErrorKind {
    ExistingResidue,
    InvalidVerifiedComponent,
    Account,
    Systemd,
    Io,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RollbackStep {
    StopService,
    DisableService,
    RemoveUnit,
    RemoveInstallMetadata,
    RemoveIdentity,
    RemoveBinary,
    RemoveIdentityDirectory,
    RemoveStateDirectory,
    RemoveMetadataDirectory,
    ReloadSystemd,
    RemoveServiceIdentity,
    RemoveServiceUser,
    RemoveServiceGroup,
    RemoveTemporary,
    RemovePartiallyInstalledPath,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RollbackFailure {
    pub step: RollbackStep,
    pub error: InstallErrorKind,
}

impl RollbackFailure {
    pub const fn new(step: RollbackStep, error: InstallErrorKind) -> Self {
        Self { step, error }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InstallError {
    ExistingResidue,
    InvalidVerifiedComponent,
    Account,
    Systemd,
    Io,
    Rollback {
        cause: InstallErrorKind,
        failures: Vec<RollbackFailure>,
    },
}

impl InstallError {
    fn kind(&self) -> InstallErrorKind {
        match self {
            Self::ExistingResidue => InstallErrorKind::ExistingResidue,
            Self::InvalidVerifiedComponent => InstallErrorKind::InvalidVerifiedComponent,
            Self::Account => InstallErrorKind::Account,
            Self::Systemd => InstallErrorKind::Systemd,
            Self::Io => InstallErrorKind::Io,
            Self::Rollback { cause, .. } => *cause,
        }
    }
}

/// Accounts are deliberately separate from systemd so tests can prove the
/// exact authority requests without executing host management commands.
pub trait AccountPort {
    fn require_absent(&mut self) -> Result<(), InstallError>;
    fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError>;
    fn remove_static_service_identity(&mut self) -> Result<(), InstallError>;
}

/// The only service-manager actions this adapter may request.
pub trait SystemdPort {
    fn require_absent(&mut self) -> Result<(), InstallError>;
    fn daemon_reload(&mut self) -> Result<(), InstallError>;
    fn enable(&mut self) -> Result<(), InstallError>;
    fn start(&mut self) -> Result<(), InstallError>;
    fn wait_ready(&mut self) -> Result<(), InstallError>;
    fn stop(&mut self) -> Result<(), InstallError>;
    fn disable(&mut self) -> Result<(), InstallError>;
}

trait InstallFilePort {
    fn ensure_metadata_directory(&mut self, path: &Path) -> Result<bool, InstallError>;
    fn create_directory(
        &mut self,
        path: &Path,
        mode: u32,
        identity: ServiceIdentity,
    ) -> Result<(), InstallError>;
    fn install_binary(&mut self, component: &mut File, path: &Path) -> Result<(), InstallError>;
    fn write_owned(
        &mut self,
        path: &Path,
        contents: &[u8],
        mode: u32,
        owner: ServiceIdentity,
    ) -> Result<(), InstallError>;
    fn remove_path(&mut self, path: &Path) -> Result<(), InstallError>;
    fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError>;
}

struct SystemInstallFiles;

#[derive(Clone, Copy)]
enum CreatedPathKind {
    File,
    Directory,
}

struct CreatedPath {
    path: PathBuf,
    step: RollbackStep,
    kind: CreatedPathKind,
}

struct InstallPorts<'a, A, S, F> {
    accounts: &'a mut A,
    systemd: &'a mut S,
    files: &'a mut F,
}

impl InstallFilePort for SystemInstallFiles {
    fn ensure_metadata_directory(&mut self, path: &Path) -> Result<bool, InstallError> {
        ensure_fixed_metadata_directory(path)
    }

    fn create_directory(
        &mut self,
        path: &Path,
        mode: u32,
        identity: ServiceIdentity,
    ) -> Result<(), InstallError> {
        create_private_directory(path, mode, identity)
    }

    fn install_binary(&mut self, component: &mut File, path: &Path) -> Result<(), InstallError> {
        install_binary(component, path)
    }

    fn write_owned(
        &mut self,
        path: &Path,
        contents: &[u8],
        mode: u32,
        owner: ServiceIdentity,
    ) -> Result<(), InstallError> {
        atomic_write_owned(path, contents, mode, owner)
    }

    fn remove_path(&mut self, path: &Path) -> Result<(), InstallError> {
        remove_created_path(path)
    }

    fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError> {
        remove_created_directory(path)
    }
}

#[derive(Clone, Debug)]
pub struct FixedInstallPaths {
    root: PathBuf,
}

impl FixedInstallPaths {
    pub fn production() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    #[cfg(test)]
    fn under(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn map(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    fn binary(&self) -> PathBuf {
        self.map(BINARY)
    }
    fn state(&self) -> PathBuf {
        self.map(STATE)
    }
    fn identity_dir(&self) -> PathBuf {
        self.map(IDENTITY_DIR)
    }
    fn identity(&self) -> PathBuf {
        self.map(IDENTITY)
    }
    fn metadata(&self) -> PathBuf {
        self.map(INSTALL_METADATA)
    }
    fn etc_enoki(&self) -> PathBuf {
        self.map("/etc/enoki")
    }
    fn unit(&self) -> PathBuf {
        self.map(UNIT)
    }
    fn bootstrap_acquirer(&self) -> PathBuf {
        self.map(BOOTSTRAP_ACQUIRER)
    }
    fn bootstrap_activator(&self) -> PathBuf {
        self.map(BOOTSTRAP_ACTIVATOR)
    }
}

/// Activates precisely the verified current `probe` component.  It is a
/// fresh-install-only operation: any previously managed evidence is a closed
/// failure, rather than an implicit upgrade, repair, or reinstall.
pub fn activate_current_probe(
    component: &mut File,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    paths: &FixedInstallPaths,
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
) -> Result<(), InstallError> {
    let mut files = SystemInstallFiles;
    activate_current_probe_with_files(
        component,
        enrollment,
        bundle,
        trust,
        paths,
        &mut InstallPorts {
            accounts,
            systemd,
            files: &mut files,
        },
    )
}

fn activate_current_probe_with_files(
    component: &mut File,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    paths: &FixedInstallPaths,
    ports: &mut InstallPorts<'_, impl AccountPort, impl SystemdPort, impl InstallFilePort>,
) -> Result<(), InstallError> {
    let trust_version = trust.version.strip_prefix('v').unwrap_or(trust.version);
    if !trust.is_for(BootstrapRole::Activator)
        || bundle.target != trust.target
        || bundle.version != trust_version
        || bundle.component_len == 0
    {
        return Err(InstallError::InvalidVerifiedComponent);
    }
    validate_component(component, bundle.component_len)?;
    preflight_parent_chains(paths)?;
    preflight_files(paths)?;
    preflight_fixed_metadata_directory(&paths.etc_enoki())?;
    validate_bootstrap_role(&paths.bootstrap_acquirer())?;
    validate_bootstrap_role(&paths.bootstrap_activator())?;
    ports.accounts.require_absent()?;
    ports.systemd.require_absent()?;

    let identity = ports.accounts.create_static_service_identity()?;
    let mut created_paths = Vec::new();
    let mut enabled = false;
    let mut started = false;
    let result = (|| {
        if ports.files.ensure_metadata_directory(&paths.etc_enoki())? {
            created_paths.push(CreatedPath {
                path: paths.etc_enoki(),
                step: RollbackStep::RemoveMetadataDirectory,
                kind: CreatedPathKind::Directory,
            });
        }
        ports
            .files
            .create_directory(&paths.state(), 0o750, identity)?;
        created_paths.push(CreatedPath {
            path: paths.state(),
            step: RollbackStep::RemoveStateDirectory,
            kind: CreatedPathKind::Directory,
        });
        ports
            .files
            .create_directory(&paths.identity_dir(), 0o700, identity)?;
        created_paths.push(CreatedPath {
            path: paths.identity_dir(),
            step: RollbackStep::RemoveIdentityDirectory,
            kind: CreatedPathKind::Directory,
        });
        ports.files.install_binary(component, &paths.binary())?;
        created_paths.push(CreatedPath {
            path: paths.binary(),
            step: RollbackStep::RemoveBinary,
            kind: CreatedPathKind::File,
        });
        ports.files.write_owned(
            &paths.identity(),
            bootstrap_config(enrollment, trust).as_bytes(),
            0o600,
            identity,
        )?;
        created_paths.push(CreatedPath {
            path: paths.identity(),
            step: RollbackStep::RemoveIdentity,
            kind: CreatedPathKind::File,
        });
        ports.files.write_owned(
            &paths.metadata(),
            install_metadata(enrollment, trust).as_bytes(),
            0o600,
            ServiceIdentity { uid: 0, gid: 0 },
        )?;
        created_paths.push(CreatedPath {
            path: paths.metadata(),
            step: RollbackStep::RemoveInstallMetadata,
            kind: CreatedPathKind::File,
        });
        ports.files.write_owned(
            &paths.unit(),
            service_unit().as_bytes(),
            0o644,
            ServiceIdentity { uid: 0, gid: 0 },
        )?;
        created_paths.push(CreatedPath {
            path: paths.unit(),
            step: RollbackStep::RemoveUnit,
            kind: CreatedPathKind::File,
        });
        ports.systemd.daemon_reload()?;
        enabled = true;
        ports.systemd.enable()?;
        started = true;
        ports.systemd.start()?;
        ports.systemd.wait_ready()?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(install_error) => {
            let mut failures = Vec::new();
            if started {
                record_rollback(
                    &mut failures,
                    RollbackStep::StopService,
                    ports.systemd.stop(),
                );
            }
            if enabled {
                record_rollback(
                    &mut failures,
                    RollbackStep::DisableService,
                    ports.systemd.disable(),
                );
            }
            // No metadata is retained after failure, so every path below was
            // created by this invocation and may be removed. The bootstrap
            // roles predate ownership transfer and are intentionally excluded.
            cleanup_failed_install(
                ports.accounts,
                ports.systemd,
                ports.files,
                &created_paths,
                &mut failures,
            );
            if failures.is_empty() {
                Err(install_error)
            } else {
                Err(InstallError::Rollback {
                    cause: install_error.kind(),
                    failures,
                })
            }
        }
    }
}

fn cleanup_failed_install(
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
    files: &mut impl InstallFilePort,
    created_paths: &[CreatedPath],
    failures: &mut Vec<RollbackFailure>,
) {
    for created in created_paths.iter().rev() {
        let result = match created.kind {
            CreatedPathKind::File => files.remove_path(&created.path),
            CreatedPathKind::Directory => files.remove_directory(&created.path),
        };
        record_rollback(failures, created.step, result);
    }
    // Systemd must forget the removed unit before another fresh install is
    // allowed to consult its absence state.
    record_rollback(
        failures,
        RollbackStep::ReloadSystemd,
        systemd.daemon_reload(),
    );
    record_rollback(
        failures,
        RollbackStep::RemoveServiceIdentity,
        accounts.remove_static_service_identity(),
    );
}

fn record_rollback(
    failures: &mut Vec<RollbackFailure>,
    step: RollbackStep,
    result: Result<(), InstallError>,
) {
    if let Err(error) = result {
        match error {
            InstallError::Rollback {
                failures: nested, ..
            } => failures.extend(nested),
            error => failures.push(RollbackFailure::new(step, error.kind())),
        }
    }
}

fn ensure_fixed_metadata_directory(path: &Path) -> Result<bool, InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    match fs::create_dir(path) {
        Ok(()) => {
            let configured = (|| {
                fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                    .map_err(|_| InstallError::Io)?;
                let dir = File::open(path).map_err(|_| InstallError::Io)?;
                chown_file(&dir, ServiceIdentity { uid: 0, gid: 0 })?;
                verify_directory(path, 0o755, ServiceIdentity { uid: 0, gid: 0 })
            })();
            if let Err(error) = configured {
                return Err(cleanup_partial_directory(path, error));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_existing_metadata_directory(path)?;
            Ok(false)
        }
        Err(_) => Err(InstallError::Io),
    }
}

fn preflight_fixed_metadata_directory(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_existing_metadata_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError::Io),
    }
}

fn validate_existing_metadata_directory(path: &Path) -> Result<(), InstallError> {
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

fn remove_created_path(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|_| InstallError::Io)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(InstallError::Io),
    }
}

fn remove_created_directory(path: &Path) -> Result<(), InstallError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError::Io),
    }
}

fn validate_component(component: &mut File, expected_len: u64) -> Result<(), InstallError> {
    let metadata = component.metadata().map_err(|_| InstallError::Io)?;
    if !metadata.is_file() || metadata.len() != expected_len {
        return Err(InstallError::InvalidVerifiedComponent);
    }
    component
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallError::Io)?;
    Ok(())
}

fn preflight_files(paths: &FixedInstallPaths) -> Result<(), InstallError> {
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

fn preflight_parent_chains(paths: &FixedInstallPaths) -> Result<(), InstallError> {
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

/// The two bootstrap roles were installed before this transaction.  They only
/// become Probe-owned after the schema-2 metadata is atomically persisted.
/// Until then a failed activation deliberately leaves them untouched.
fn validate_bootstrap_role(path: &Path) -> Result<(), InstallError> {
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

fn create_private_directory(
    path: &Path,
    mode: u32,
    identity: ServiceIdentity,
) -> Result<(), InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    fs::create_dir(path).map_err(|_| InstallError::Io)?;
    let configured = (|| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| InstallError::Io)?;
        let directory = File::open(path).map_err(|_| InstallError::Io)?;
        chown_file(&directory, identity)?;
        verify_directory(path, mode, identity)
    })();
    configured.map_err(|error| cleanup_partial_directory(path, error))
}

fn cleanup_partial_directory(path: &Path, cause: InstallError) -> InstallError {
    match fs::remove_dir(path) {
        Ok(()) => cause,
        Err(_) => InstallError::Rollback {
            cause: cause.kind(),
            failures: vec![RollbackFailure::new(
                RollbackStep::RemovePartiallyInstalledPath,
                InstallErrorKind::Io,
            )],
        },
    }
}

fn ensure_safe_parent_chain(path: &Path) -> Result<(), InstallError> {
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

fn verify_directory(path: &Path, mode: u32, identity: ServiceIdentity) -> Result<(), InstallError> {
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

fn install_binary(component: &mut File, destination: &Path) -> Result<(), InstallError> {
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
    rename_new(output.1, destination)
}

fn atomic_write_owned(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: ServiceIdentity,
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
    rename_new(temporary, path)
}

fn exclusive_temp(parent: &Path, mode: u32) -> Result<(File, PathBuf), InstallError> {
    for suffix in 0..32 {
        let path = parent.join(format!(".enoki-probe-bootstrap-{suffix}"));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path);
        match opened {
            Ok(file) => {
                // `mode` on create is filtered by the caller's umask. These
                // are security contracts, so restore the exact mode on the
                // opened descriptor before it can be linked into the layout.
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

fn rename_new(from: PathBuf, destination: &Path) -> Result<(), InstallError> {
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
                    fs::remove_file(destination),
                );
                record_io_cleanup(
                    &mut failures,
                    RollbackStep::RemoveTemporary,
                    fs::remove_file(&from),
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

fn cleanup_temporary_file(path: &Path, cause: InstallError) -> InstallError {
    match fs::remove_file(path) {
        Ok(()) => cause,
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

fn record_io_cleanup(
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

fn chown_file(file: &File, identity: ServiceIdentity) -> Result<(), InstallError> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::fchown(file.as_raw_fd(), identity.uid, identity.gid) } != 0 {
        return Err(InstallError::Io);
    }
    Ok(())
}

fn bootstrap_config(enrollment: &Enrollment, trust: &BuildTrust) -> String {
    format!(
        "hub_url = {:?}\nenrollment_token = {:?}\nstate_dir = {:?}\noperation_status_path = {:?}\ninstall_path = {:?}\nservice_name = {:?}\nservice_user = {:?}\nprobe_distribution_root_sha256 = {:?}\nlog_level = \"info\"\n",
        enrollment.hub_origin(),
        enrollment.enrollment_token(),
        STATE,
        "/var/lib/enoki-probe/probe-operation-status.toml",
        BINARY,
        SERVICE_NAME,
        SERVICE_USER,
        trust.root_fingerprint,
    )
}

fn install_metadata(enrollment: &Enrollment, trust: &BuildTrust) -> String {
    format!(
        "schema_version = 2\nhub_url = {:?}\nidentity_path = {:?}\ninstall_path = {:?}\noperation_status_path = {:?}\nstate_dir = {:?}\nprobe_distribution_root_sha256 = {:?}\nbootstrap_state_dir = {:?}\nbootstrap_acquirer_path = {:?}\nbootstrap_activator_path = {:?}\nservice_name = {:?}\nservice_user = {:?}\nservice_group = {:?}\nservice_unit_path = {:?}\n",
        enrollment.hub_origin(),
        IDENTITY,
        BINARY,
        "/var/lib/enoki-probe/probe-operation-status.toml",
        STATE,
        trust.root_fingerprint,
        BOOTSTRAP_STATE,
        BOOTSTRAP_ACQUIRER,
        BOOTSTRAP_ACTIVATOR,
        SERVICE_NAME,
        SERVICE_USER,
        SERVICE_GROUP,
        UNIT,
    )
}

fn service_unit() -> &'static str {
    "[Unit]\nDescription=Enoki Probe\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=notify\nNotifyAccess=main\nUser=enoki-probe\nGroup=enoki-probe\nExecStart=/usr/local/bin/enoki-probe run --config /var/lib/enoki-probe/identity/probe-bootstrap.toml\nRestart=on-failure\nRestartPreventExitStatus=78\nRestartSec=5s\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\nProtectControlGroups=true\nReadWritePaths=/var/lib/enoki-probe /var/lib/enoki-probe/identity\n\n[Install]\nWantedBy=multi-user.target\n"
}

/// Production account implementation. Every executable and argument is fixed;
/// the process environment is discarded before invoking it.
pub struct SystemAccounts;
impl AccountPort for SystemAccounts {
    fn require_absent(&mut self) -> Result<(), InstallError> {
        let group = command_presence("/usr/bin/getent", &["group", SERVICE_GROUP], 2)?;
        let user = command_presence("/usr/bin/id", &["-u", SERVICE_USER], 1)?;
        if group || user {
            Err(InstallError::ExistingResidue)
        } else {
            Ok(())
        }
    }
    fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
        create_static_service_identity_with_commands(
            &mut |program, arguments| require_success(program, arguments, InstallError::Account),
            &mut numeric_id,
        )
    }
    fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
        remove_static_service_identity_with_commands(&mut |program, arguments| {
            require_success(program, arguments, InstallError::Account)
        })
    }
}

/// The account transaction has no durable metadata until identity discovery
/// completes.  Therefore every failure after `groupadd` removes exactly the
/// identities this attempt created, leaving a later fresh install possible.
fn create_static_service_identity_with_commands(
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
    lookup_id: &mut impl FnMut(&str) -> Result<u32, InstallError>,
) -> Result<ServiceIdentity, InstallError> {
    if let Err(error) = execute("/usr/sbin/groupadd", &["--system", SERVICE_GROUP]) {
        return rollback_account_creation(error, rollback_created_group(execute));
    }
    if let Err(error) = execute(
        "/usr/sbin/useradd",
        &[
            "--system",
            "--gid",
            SERVICE_GROUP,
            "--home-dir",
            STATE,
            "--shell",
            "/usr/sbin/nologin",
            SERVICE_USER,
        ],
    ) {
        return rollback_account_creation(error, rollback_created_identity(execute));
    }
    let uid = match lookup_id("-u") {
        Ok(uid) => uid,
        Err(error) => {
            return rollback_account_creation(error, rollback_created_identity(execute));
        }
    };
    let gid = match lookup_id("-g") {
        Ok(gid) => gid,
        Err(error) => {
            return rollback_account_creation(error, rollback_created_identity(execute));
        }
    };
    Ok(ServiceIdentity { uid, gid })
}

fn rollback_account_creation(
    cause: InstallError,
    failures: Vec<RollbackFailure>,
) -> Result<ServiceIdentity, InstallError> {
    if failures.is_empty() {
        Err(cause)
    } else {
        Err(InstallError::Rollback {
            cause: cause.kind(),
            failures,
        })
    }
}

fn rollback_created_group(
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
) -> Vec<RollbackFailure> {
    let first = execute("/usr/sbin/groupdel", &[SERVICE_GROUP]);
    let final_result = if first.is_err() {
        execute("/usr/sbin/groupdel", &[SERVICE_GROUP])
    } else {
        first
    };
    final_result.err().map_or_else(Vec::new, |error| {
        vec![RollbackFailure::new(
            RollbackStep::RemoveServiceGroup,
            error.kind(),
        )]
    })
}

fn rollback_created_identity(
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
) -> Vec<RollbackFailure> {
    remove_static_service_identity_with_commands(execute)
        .err()
        .and_then(|error| match error {
            InstallError::Rollback { failures, .. } => Some(failures),
            _ => None,
        })
        .unwrap_or_default()
}

fn remove_static_service_identity_with_commands(
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
) -> Result<(), InstallError> {
    let first_user = execute("/usr/sbin/userdel", &[SERVICE_USER]);
    let first_group = execute("/usr/sbin/groupdel", &[SERVICE_GROUP]);
    let final_user = if first_user.is_err() {
        execute("/usr/sbin/userdel", &[SERVICE_USER])
    } else {
        first_user
    };
    let final_group = if first_group.is_err() {
        execute("/usr/sbin/groupdel", &[SERVICE_GROUP])
    } else {
        first_group
    };
    let mut failures = Vec::new();
    record_rollback(&mut failures, RollbackStep::RemoveServiceUser, final_user);
    record_rollback(&mut failures, RollbackStep::RemoveServiceGroup, final_group);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(InstallError::Rollback {
            cause: InstallErrorKind::Account,
            failures,
        })
    }
}

/// Production systemd implementation. Its only dynamic data is absent: all
/// unit names and paths are compiled constants.
pub struct SystemSystemd;
impl SystemdPort for SystemSystemd {
    fn require_absent(&mut self) -> Result<(), InstallError> {
        let enabled = Command::new("/usr/bin/systemctl")
            .args(["is-enabled", "--full", "--no-pager", "enoki-probe.service"])
            .env_clear()
            .env("LANG", "C")
            .output()
            .map_err(|_| InstallError::Systemd)?;
        let enabled_value = single_systemd_value(&enabled.stdout)?;
        if enabled_value != "not-found" || !matches!(enabled.status.code(), Some(1) | Some(4)) {
            return Err(InstallError::ExistingResidue);
        }
        let loaded = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "--property=LoadState",
                "--value",
                "enoki-probe.service",
            ])
            .env_clear()
            .env("LANG", "C")
            .output()
            .map_err(|_| InstallError::Systemd)?;
        if !loaded.status.success() || single_systemd_value(&loaded.stdout)? != "not-found" {
            return Err(InstallError::ExistingResidue);
        }
        Ok(())
    }
    fn daemon_reload(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["daemon-reload"],
            InstallError::Systemd,
        )
    }
    fn enable(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["enable", "enoki-probe.service"],
            InstallError::Systemd,
        )
    }
    fn start(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["start", "--no-block", "enoki-probe.service"],
            InstallError::Systemd,
        )
    }
    fn wait_ready(&mut self) -> Result<(), InstallError> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if require_success(
                "/usr/bin/systemctl",
                &["is-active", "--quiet", "enoki-probe.service"],
                InstallError::Systemd,
            )
            .is_ok()
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(InstallError::Systemd);
            }
            thread::sleep(Duration::from_millis(250));
        }
    }
    fn stop(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["stop", "enoki-probe.service"],
            InstallError::Systemd,
        )
    }
    fn disable(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["disable", "enoki-probe.service"],
            InstallError::Systemd,
        )
    }
}

fn command_presence(
    program: &str,
    arguments: &[&str],
    absent_status: i32,
) -> Result<bool, InstallError> {
    let status = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .status()
        .map_err(|_| InstallError::Account)?;
    match status.code() {
        Some(0) => Ok(true),
        Some(code) if code == absent_status => Ok(false),
        _ => Err(InstallError::Account),
    }
}
fn require_success(
    program: &str,
    arguments: &[&str],
    error: InstallError,
) -> Result<(), InstallError> {
    let status = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .status()
        .map_err(|_| error.clone())?;
    status.success().then_some(()).ok_or(error)
}
fn numeric_id(flag: &str) -> Result<u32, InstallError> {
    let output = Command::new("/usr/bin/id")
        .args([flag, SERVICE_USER])
        .env_clear()
        .env("LANG", "C")
        .output()
        .map_err(|_| InstallError::Account)?;
    if !output.status.success() {
        return Err(InstallError::Account);
    }
    std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or(InstallError::Account)
}

fn single_systemd_value(bytes: &[u8]) -> Result<&str, InstallError> {
    let value = std::str::from_utf8(bytes).map_err(|_| InstallError::Systemd)?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(InstallError::Systemd);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handoff::Enrollment;
    use crate::trust::BootstrapRole;
    use tempfile::tempdir;

    #[derive(Default)]
    struct Accounts {
        calls: Vec<&'static str>,
        reject: bool,
    }
    impl AccountPort for Accounts {
        fn require_absent(&mut self) -> Result<(), InstallError> {
            self.calls.push("absent");
            (!self.reject)
                .then_some(())
                .ok_or(InstallError::ExistingResidue)
        }
        fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
            self.calls.push("create");
            Ok(ServiceIdentity {
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            })
        }
        fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
            self.calls.push("remove");
            Ok(())
        }
    }
    #[derive(Default)]
    struct Systemd {
        calls: Vec<&'static str>,
        fail_start: bool,
        residue: bool,
    }
    impl SystemdPort for Systemd {
        fn require_absent(&mut self) -> Result<(), InstallError> {
            self.calls.push("absent");
            (!self.residue)
                .then_some(())
                .ok_or(InstallError::ExistingResidue)
        }
        fn daemon_reload(&mut self) -> Result<(), InstallError> {
            self.calls.push("reload");
            Ok(())
        }
        fn enable(&mut self) -> Result<(), InstallError> {
            self.calls.push("enable");
            Ok(())
        }
        fn start(&mut self) -> Result<(), InstallError> {
            self.calls.push("start");
            (!self.fail_start)
                .then_some(())
                .ok_or(InstallError::Systemd)
        }
        fn wait_ready(&mut self) -> Result<(), InstallError> {
            self.calls.push("ready");
            Ok(())
        }
        fn stop(&mut self) -> Result<(), InstallError> {
            self.calls.push("stop");
            Ok(())
        }
        fn disable(&mut self) -> Result<(), InstallError> {
            self.calls.push("disable");
            Ok(())
        }
    }
    fn trust() -> BuildTrust {
        BuildTrust {
            distribution: "enoki",
            role: BootstrapRole::Activator,
            root_pem: "",
            root_fingerprint: "a".repeat(64).leak(),
            root_key_id: "",
            target: "x86_64-unknown-linux-gnu",
            version: "v1.2.3",
        }
    }
    fn bundle() -> VerifiedBundle {
        VerifiedBundle {
            version: "1.2.3".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            delegation_generation: 1,
            component_len: 5,
        }
    }
    fn component() -> File {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), b"probe").unwrap();
        temp.reopen().unwrap()
    }

    #[test]
    fn account_identity_lookup_failure_rolls_back_created_user_and_group() {
        use std::cell::RefCell;

        for failed_lookup in ["-u", "-g"] {
            let calls = RefCell::new(Vec::new());
            let mut execute = |program: &str, _arguments: &[&str]| {
                calls.borrow_mut().push(program.to_string());
                Ok(())
            };
            let mut lookup = |flag: &str| {
                calls.borrow_mut().push(format!("id {flag}"));
                if flag == failed_lookup {
                    Err(InstallError::Account)
                } else {
                    Ok(123)
                }
            };

            let error = create_static_service_identity_with_commands(&mut execute, &mut lookup)
                .expect_err("failed numeric identity lookup rolls back");

            assert_eq!(error, InstallError::Account);
            let mut expected = vec![
                "/usr/sbin/groupadd".to_string(),
                "/usr/sbin/useradd".to_string(),
                "id -u".to_string(),
            ];
            if failed_lookup == "-g" {
                expected.push("id -g".to_string());
            }
            expected.extend([
                "/usr/sbin/userdel".to_string(),
                "/usr/sbin/groupdel".to_string(),
            ]);
            assert_eq!(*calls.borrow(), expected);
        }
    }

    #[test]
    fn account_mutation_failure_exhausts_and_stably_reports_identity_compensations() {
        let mut calls = Vec::new();
        let error = create_static_service_identity_with_commands(
            &mut |program, _arguments| {
                calls.push(program.to_string());
                match program {
                    "/usr/sbin/groupadd" => Ok(()),
                    _ => Err(InstallError::Account),
                }
            },
            &mut |_flag| Ok(123),
        )
        .expect_err("useradd failure with failed cleanup must report all residue");

        assert_eq!(
            error,
            InstallError::Rollback {
                cause: InstallErrorKind::Account,
                failures: vec![
                    RollbackFailure::new(
                        RollbackStep::RemoveServiceUser,
                        InstallErrorKind::Account,
                    ),
                    RollbackFailure::new(
                        RollbackStep::RemoveServiceGroup,
                        InstallErrorKind::Account,
                    ),
                ],
            }
        );
        assert_eq!(
            calls,
            [
                "/usr/sbin/groupadd",
                "/usr/sbin/useradd",
                "/usr/sbin/userdel",
                "/usr/sbin/groupdel",
                "/usr/sbin/userdel",
                "/usr/sbin/groupdel",
            ]
        );
    }

    #[test]
    fn transient_account_compensation_failure_still_allows_fresh_retry() {
        use std::cell::Cell;

        let group_exists = Cell::new(false);
        let user_exists = Cell::new(false);
        let fail_useradd = Cell::new(true);
        let fail_first_userdel = Cell::new(true);
        let fail_first_groupdel = Cell::new(true);
        let mut execute = |program: &str, _arguments: &[&str]| match program {
            "/usr/sbin/groupadd" if !group_exists.replace(true) => Ok(()),
            "/usr/sbin/useradd" if fail_useradd.replace(false) => {
                user_exists.set(true);
                Err(InstallError::Account)
            }
            "/usr/sbin/useradd" if group_exists.get() && !user_exists.replace(true) => Ok(()),
            "/usr/sbin/userdel" if user_exists.get() && fail_first_userdel.replace(false) => {
                Err(InstallError::Account)
            }
            "/usr/sbin/userdel" if user_exists.replace(false) => Ok(()),
            "/usr/sbin/groupdel" if group_exists.get() && fail_first_groupdel.replace(false) => {
                Err(InstallError::Account)
            }
            "/usr/sbin/groupdel" if !user_exists.get() && group_exists.replace(false) => Ok(()),
            _ => Err(InstallError::Account),
        };
        let mut lookup = |_flag: &str| Ok(123);

        assert_eq!(
            create_static_service_identity_with_commands(&mut execute, &mut lookup),
            Err(InstallError::Account)
        );
        assert!(!user_exists.get());
        assert!(!group_exists.get());
        assert_eq!(
            create_static_service_identity_with_commands(&mut execute, &mut lookup),
            Ok(ServiceIdentity { uid: 123, gid: 123 })
        );
    }

    #[test]
    fn fresh_verified_probe_becomes_only_the_fixed_current_service() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap();
        let binary = temporary.path().join("usr/local/bin/enoki-probe");
        assert_eq!(fs::read(binary).unwrap(), b"probe");
        let config = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        )
        .unwrap();
        assert!(config.contains("hub_url = \"https://hub.example\""));
        assert!(config.contains("probe_distribution_root_sha256"));
        assert!(!config.contains("probe_asset_public_key_sha256"));
        let metadata =
            fs::read_to_string(temporary.path().join("etc/enoki/probe-install.toml")).unwrap();
        assert!(metadata.contains("schema_version = 2"));
        assert!(metadata.contains("bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\""));
        assert_eq!(
            fs::metadata(temporary.path().join("etc/enoki"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        assert!(!metadata.contains("sudoers_path"));
        assert!(!metadata.contains("probe_asset_public_key_sha256"));
        assert_eq!(
            fs::metadata(temporary.path().join("usr/local/bin/enoki-probe"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(
                temporary
                    .path()
                    .join("var/lib/enoki-probe/identity/probe-bootstrap.toml")
            )
            .unwrap()
            .mode()
                & 0o777,
            0o600
        );
        assert_eq!(accounts.calls, ["absent", "create"]);
        assert_eq!(
            systemd.calls,
            ["absent", "reload", "enable", "start", "ready"]
        );
    }

    #[test]
    fn existing_or_symlinked_enoki_residue_fails_before_any_host_authority() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            "/not-a-probe",
            temporary.path().join("usr/local/bin/enoki-probe"),
        )
        .unwrap();
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap_err();
        assert_eq!(error, InstallError::ExistingResidue);
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
        assert!(!format!("{error:?}").contains("enk_enroll_secret"));
    }

    #[test]
    fn unsafe_existing_metadata_directory_fails_before_any_host_authority() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        fs::set_permissions(
            temporary.path().join("etc/enoki"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect_err("unsafe metadata directory fails closed");

        assert_eq!(error, InstallError::ExistingResidue);
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_metadata_directory_fails_before_any_host_authority() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let target = temporary.path().join("outside");
        fs::create_dir(&target).unwrap();
        symlink(&target, temporary.path().join("etc/enoki")).unwrap();
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect_err("symlinked metadata directory fails closed");

        assert_eq!(error, InstallError::ExistingResidue);
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn start_failure_rolls_back_only_this_attempt_and_allows_a_fresh_retry() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            calls: Vec::new(),
            fail_start: true,
            residue: false,
        };
        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap_err();
        assert_eq!(error, InstallError::Systemd);
        assert_eq!(
            systemd.calls,
            [
                "absent", "reload", "enable", "start", "stop", "disable", "reload"
            ]
        );
        assert_eq!(accounts.calls, ["absent", "create", "remove"]);
        assert!(!temporary.path().join("usr/local/bin/enoki-probe").exists());
        assert!(!temporary.path().join("var/lib/enoki-probe").exists());
        assert!(
            !temporary
                .path()
                .join("etc/enoki/probe-install.toml")
                .exists()
        );
        assert!(
            !temporary
                .path()
                .join("etc/systemd/system/enoki-probe.service")
                .exists()
        );
        assert!(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-acquire")
                .exists()
        );
        assert!(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-activate")
                .exists()
        );
        systemd.fail_start = false;
        activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect("a transient start failure leaves a retryable fresh install");
        assert!(temporary.path().join("usr/local/bin/enoki-probe").exists());
        assert!(
            temporary
                .path()
                .join("etc/enoki/probe-install.toml")
                .exists()
        );
    }

    #[test]
    fn rollback_attempts_every_compensation_and_reports_failures_in_stable_order() {
        struct FailingAccounts {
            calls: Vec<&'static str>,
        }
        impl AccountPort for FailingAccounts {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                self.calls.push("absent");
                Ok(())
            }
            fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
                self.calls.push("create");
                Ok(ServiceIdentity {
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                })
            }
            fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
                self.calls.push("remove");
                Err(InstallError::Account)
            }
        }
        struct FailingSystemd {
            calls: Vec<&'static str>,
            unit: PathBuf,
            reloads: usize,
        }
        impl SystemdPort for FailingSystemd {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                self.calls.push("absent");
                Ok(())
            }
            fn daemon_reload(&mut self) -> Result<(), InstallError> {
                self.calls.push("reload");
                self.reloads += 1;
                if self.reloads == 2 {
                    Err(InstallError::Systemd)
                } else {
                    Ok(())
                }
            }
            fn enable(&mut self) -> Result<(), InstallError> {
                self.calls.push("enable");
                Ok(())
            }
            fn start(&mut self) -> Result<(), InstallError> {
                self.calls.push("start");
                fs::remove_file(&self.unit).unwrap();
                fs::create_dir(&self.unit).unwrap();
                Err(InstallError::Systemd)
            }
            fn wait_ready(&mut self) -> Result<(), InstallError> {
                unreachable!()
            }
            fn stop(&mut self) -> Result<(), InstallError> {
                self.calls.push("stop");
                Err(InstallError::Systemd)
            }
            fn disable(&mut self) -> Result<(), InstallError> {
                self.calls.push("disable");
                Err(InstallError::Systemd)
            }
        }

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = FailingAccounts { calls: Vec::new() };
        let unit = temporary
            .path()
            .join("etc/systemd/system/enoki-probe.service");
        let mut systemd = FailingSystemd {
            calls: Vec::new(),
            unit,
            reloads: 0,
        };

        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect_err("start and rollback failures must remain observable");

        assert_eq!(
            error,
            InstallError::Rollback {
                cause: InstallErrorKind::Systemd,
                failures: vec![
                    RollbackFailure::new(RollbackStep::StopService, InstallErrorKind::Systemd),
                    RollbackFailure::new(RollbackStep::DisableService, InstallErrorKind::Systemd),
                    RollbackFailure::new(RollbackStep::RemoveUnit, InstallErrorKind::Io),
                    RollbackFailure::new(RollbackStep::ReloadSystemd, InstallErrorKind::Systemd),
                    RollbackFailure::new(
                        RollbackStep::RemoveServiceIdentity,
                        InstallErrorKind::Account,
                    ),
                ],
            }
        );
        assert_eq!(
            systemd.calls,
            [
                "absent", "reload", "enable", "start", "stop", "disable", "reload"
            ]
        );
        assert_eq!(accounts.calls, ["absent", "create", "remove"]);
        assert!(
            !temporary.path().join("var/lib/enoki-probe").exists(),
            "a unit cleanup failure must not stop later filesystem compensations"
        );
        assert!(
            !temporary
                .path()
                .join("etc/enoki/probe-install.toml")
                .exists()
        );
    }

    #[test]
    fn every_filesystem_mutation_failure_rolls_back_to_a_retryable_fresh_state() {
        struct FaultFiles {
            inner: SystemInstallFiles,
            fail_at: usize,
            mutation: usize,
        }
        impl FaultFiles {
            fn before_mutation(&mut self) -> Result<(), InstallError> {
                let current = self.mutation;
                self.mutation += 1;
                if current == self.fail_at {
                    Err(InstallError::Io)
                } else {
                    Ok(())
                }
            }
        }
        impl InstallFilePort for FaultFiles {
            fn ensure_metadata_directory(&mut self, path: &Path) -> Result<bool, InstallError> {
                self.before_mutation()?;
                self.inner.ensure_metadata_directory(path)
            }
            fn create_directory(
                &mut self,
                path: &Path,
                mode: u32,
                identity: ServiceIdentity,
            ) -> Result<(), InstallError> {
                self.before_mutation()?;
                self.inner.create_directory(path, mode, identity)
            }
            fn install_binary(
                &mut self,
                component: &mut File,
                path: &Path,
            ) -> Result<(), InstallError> {
                self.before_mutation()?;
                self.inner.install_binary(component, path)
            }
            fn write_owned(
                &mut self,
                path: &Path,
                contents: &[u8],
                mode: u32,
                owner: ServiceIdentity,
            ) -> Result<(), InstallError> {
                self.before_mutation()?;
                self.inner.write_owned(path, contents, mode, owner)
            }
            fn remove_path(&mut self, path: &Path) -> Result<(), InstallError> {
                self.inner.remove_path(path)
            }
            fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError> {
                self.inner.remove_directory(path)
            }
        }

        for fail_at in 0..7 {
            let temporary = tempdir().unwrap();
            for parent in [
                "usr/local/bin",
                "var/lib",
                "etc",
                "etc/systemd/system",
                "etc/sudoers.d",
            ] {
                fs::create_dir_all(temporary.path().join(parent)).unwrap();
            }
            write_bootstrap_roles(temporary.path());
            let paths = FixedInstallPaths::under(temporary.path());
            let mut component = component();
            let mut accounts = Accounts::default();
            let mut systemd = Systemd::default();
            let mut files = FaultFiles {
                inner: SystemInstallFiles,
                fail_at,
                mutation: 0,
            };

            assert_eq!(
                activate_current_probe_with_files(
                    &mut component,
                    &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                    &bundle(),
                    &trust(),
                    &paths,
                    &mut InstallPorts {
                        accounts: &mut accounts,
                        systemd: &mut systemd,
                        files: &mut files,
                    },
                ),
                Err(InstallError::Io),
                "filesystem mutation {fail_at} must preserve the initiating failure"
            );
            for residue in [
                "usr/local/bin/enoki-probe",
                "var/lib/enoki-probe",
                "etc/enoki",
                "etc/systemd/system/enoki-probe.service",
            ] {
                assert!(
                    !temporary.path().join(residue).exists(),
                    "filesystem mutation {fail_at} left {residue}"
                );
            }
            assert!(paths.bootstrap_acquirer().exists());
            assert!(paths.bootstrap_activator().exists());

            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut Accounts::default(),
                &mut Systemd::default(),
            )
            .expect("rollback must permit a fresh retry");
        }
    }

    #[test]
    fn rollback_never_removes_state_not_created_by_this_transaction() {
        struct RacingFiles {
            inner: SystemInstallFiles,
        }
        impl InstallFilePort for RacingFiles {
            fn ensure_metadata_directory(&mut self, path: &Path) -> Result<bool, InstallError> {
                self.inner.ensure_metadata_directory(path)
            }
            fn create_directory(
                &mut self,
                path: &Path,
                mode: u32,
                identity: ServiceIdentity,
            ) -> Result<(), InstallError> {
                self.inner.create_directory(path, mode, identity)
            }
            fn install_binary(
                &mut self,
                _component: &mut File,
                path: &Path,
            ) -> Result<(), InstallError> {
                fs::write(path, b"preexisting-race").unwrap();
                Err(InstallError::ExistingResidue)
            }
            fn write_owned(
                &mut self,
                path: &Path,
                contents: &[u8],
                mode: u32,
                owner: ServiceIdentity,
            ) -> Result<(), InstallError> {
                self.inner.write_owned(path, contents, mode, owner)
            }
            fn remove_path(&mut self, path: &Path) -> Result<(), InstallError> {
                self.inner.remove_path(path)
            }
            fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError> {
                self.inner.remove_directory(path)
            }
        }

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let paths = FixedInstallPaths::under(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let mut files = RacingFiles {
            inner: SystemInstallFiles,
        };

        assert_eq!(
            activate_current_probe_with_files(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut InstallPorts {
                    accounts: &mut accounts,
                    systemd: &mut systemd,
                    files: &mut files,
                },
            ),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(fs::read(paths.binary()).unwrap(), b"preexisting-race");
        assert!(!paths.state().exists());
        assert!(!paths.metadata().exists());
        assert!(!paths.unit().exists());

        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut Accounts::default(),
                &mut Systemd::default(),
            ),
            Err(InstallError::ExistingResidue),
            "retry must preserve and report the authoritative pre-existing state"
        );
        assert_eq!(fs::read(paths.binary()).unwrap(), b"preexisting-race");
    }

    #[test]
    fn every_systemd_mutation_failure_compensates_uncertain_partial_state() {
        struct FailOnceSystemd {
            calls: Vec<&'static str>,
            fail_on: &'static str,
            failed: bool,
        }
        impl FailOnceSystemd {
            fn call(&mut self, action: &'static str) -> Result<(), InstallError> {
                self.calls.push(action);
                if action == self.fail_on && !self.failed {
                    self.failed = true;
                    Err(InstallError::Systemd)
                } else {
                    Ok(())
                }
            }
        }
        impl SystemdPort for FailOnceSystemd {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                self.call("absent")
            }
            fn daemon_reload(&mut self) -> Result<(), InstallError> {
                self.call("reload")
            }
            fn enable(&mut self) -> Result<(), InstallError> {
                self.call("enable")
            }
            fn start(&mut self) -> Result<(), InstallError> {
                self.call("start")
            }
            fn wait_ready(&mut self) -> Result<(), InstallError> {
                self.call("ready")
            }
            fn stop(&mut self) -> Result<(), InstallError> {
                self.call("stop")
            }
            fn disable(&mut self) -> Result<(), InstallError> {
                self.call("disable")
            }
        }

        for fail_on in ["reload", "enable", "start", "ready"] {
            let temporary = tempdir().unwrap();
            for parent in [
                "usr/local/bin",
                "var/lib",
                "etc",
                "etc/systemd/system",
                "etc/sudoers.d",
            ] {
                fs::create_dir_all(temporary.path().join(parent)).unwrap();
            }
            write_bootstrap_roles(temporary.path());
            let paths = FixedInstallPaths::under(temporary.path());
            let mut component = component();
            let mut accounts = Accounts::default();
            let mut systemd = FailOnceSystemd {
                calls: Vec::new(),
                fail_on,
                failed: false,
            };

            assert_eq!(
                activate_current_probe(
                    &mut component,
                    &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                    &bundle(),
                    &trust(),
                    &paths,
                    &mut accounts,
                    &mut systemd,
                ),
                Err(InstallError::Systemd)
            );
            if fail_on == "enable" {
                assert!(
                    systemd.calls.contains(&"disable"),
                    "a failed mutating enable has uncertain partial state and must be disabled"
                );
            }
            if matches!(fail_on, "start" | "ready") {
                assert!(systemd.calls.contains(&"stop"));
                assert!(systemd.calls.contains(&"disable"));
            }
            assert_eq!(accounts.calls, ["absent", "create", "remove"]);
            assert!(!paths.binary().exists());
            assert!(!paths.state().exists());
            assert!(!paths.metadata().exists());
            assert!(!paths.unit().exists());

            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut Accounts::default(),
                &mut Systemd::default(),
            )
            .expect("systemd compensation must permit a fresh retry");
        }
    }

    #[test]
    fn loaded_systemd_residue_fails_before_creating_the_service_account_or_files() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            calls: Vec::new(),
            fail_start: false,
            residue: true,
        };
        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd
            ),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(accounts.calls, ["absent"]);
        assert_eq!(systemd.calls, ["absent"]);
        assert!(!temporary.path().join("var/lib/enoki-probe").exists());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_roles_must_be_root_owned_regular_0755_files_and_are_never_cleaned_on_failure() {
        use std::os::unix::fs::symlink;
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let acquirer = temporary
            .path()
            .join("usr/local/bin/enoki-probe-bootstrap-acquire");
        symlink("/untrusted", &acquirer).unwrap();
        fs::write(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-activate"),
            "role",
        )
        .unwrap();
        fs::set_permissions(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-activate"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd
            ),
            Err(InstallError::ExistingResidue)
        );
        assert!(
            fs::symlink_metadata(acquirer)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn missing_bootstrap_role_fails_before_creating_the_metadata_directory() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::ExistingResidue)
        );
        assert!(
            !temporary.path().join("etc/enoki").exists(),
            "preflight rejection must leave the Host filesystem unchanged"
        );
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn acquirer_trust_cannot_enter_the_fixed_activation_transaction() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut wrong_role = trust();
        wrong_role.role = BootstrapRole::Acquirer;
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &wrong_role,
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::InvalidVerifiedComponent)
        );
        assert!(!temporary.path().join("etc/enoki").exists());
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_destination_parent_fails_before_creating_identity_or_metadata() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
            "outside",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        symlink(
            temporary.path().join("outside"),
            temporary.path().join("var/lib"),
        )
        .unwrap();
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::Io)
        );
        assert!(!temporary.path().join("etc/enoki").exists());
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    fn write_bootstrap_roles(root: &Path) {
        for role in [
            "enoki-probe-bootstrap-acquire",
            "enoki-probe-bootstrap-activate",
        ] {
            let path = root.join("usr/local/bin").join(role);
            fs::write(&path, "bootstrap role").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}
