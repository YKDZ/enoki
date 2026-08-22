//! The fixed fresh-install adapter for the current Probe component.
//!
//! This is intentionally a small closed boundary: a verified component can
//! become only the current Probe service at the paths below.  It has no
//! archive, network, command-line interpolation, or candidate-code surface.

mod account;
mod command;
mod filesystem;
mod systemd;
mod transaction;

use crate::{
    handoff::Enrollment,
    trust::{BootstrapRole, BuildTrust},
    verifier::VerifiedBundle,
};
use command::run_bounded;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use transaction::{ActivationLock, OwnedPath, TransactionJournal};

const INSTALL_COMMAND_BUDGET: Duration = Duration::from_secs(90);
const ROLLBACK_COMMAND_BUDGET: Duration = Duration::from_secs(30);
const COMMAND_STEP_BUDGET: Duration = Duration::from_secs(15);

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

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
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
    const fn kind(&self) -> InstallErrorKind {
        match self {
            Self::ExistingResidue => InstallErrorKind::ExistingResidue,
            Self::InvalidVerifiedComponent => InstallErrorKind::InvalidVerifiedComponent,
            Self::Account => InstallErrorKind::Account,
            Self::Systemd => InstallErrorKind::Systemd,
            Self::Io => InstallErrorKind::Io,
            Self::Rollback { cause, .. } => *cause,
        }
    }

    /// 稳定且不含秘密的生产诊断；回滚失败保持事务顺序，便于核对 journald 证据。
    pub fn diagnostic(&self) -> String {
        let mut value = format!("install={}", self.kind().code());
        if let Self::Rollback { failures, .. } = self {
            value.push_str(" rollback=");
            for (index, failure) in failures.iter().enumerate() {
                if index > 0 {
                    value.push(',');
                }
                value.push_str(failure.step.code());
                value.push(':');
                value.push_str(failure.error.code());
            }
        }
        value
    }

    pub const fn exit_code(&self) -> u8 {
        match self.kind() {
            InstallErrorKind::ExistingResidue => 20,
            InstallErrorKind::InvalidVerifiedComponent => 21,
            InstallErrorKind::Account => 22,
            InstallErrorKind::Systemd => 23,
            InstallErrorKind::Io => 24,
        }
    }
}

impl InstallErrorKind {
    const fn code(self) -> &'static str {
        match self {
            Self::ExistingResidue => "existing_residue",
            Self::InvalidVerifiedComponent => "invalid_verified_component",
            Self::Account => "account",
            Self::Systemd => "systemd",
            Self::Io => "io",
        }
    }
}

impl RollbackStep {
    const fn code(self) -> &'static str {
        match self {
            Self::StopService => "stop_service",
            Self::DisableService => "disable_service",
            Self::RemoveUnit => "remove_unit",
            Self::RemoveInstallMetadata => "remove_install_metadata",
            Self::RemoveIdentity => "remove_identity",
            Self::RemoveBinary => "remove_binary",
            Self::RemoveIdentityDirectory => "remove_identity_directory",
            Self::RemoveStateDirectory => "remove_state_directory",
            Self::RemoveMetadataDirectory => "remove_metadata_directory",
            Self::ReloadSystemd => "reload_systemd",
            Self::RemoveServiceIdentity => "remove_service_identity",
            Self::RemoveServiceUser => "remove_service_user",
            Self::RemoveServiceGroup => "remove_service_group",
            Self::RemoveTemporary => "remove_temporary",
            Self::RemovePartiallyInstalledPath => "remove_partial_path",
        }
    }
}

/// Accounts are deliberately separate from systemd so tests can prove the
/// exact authority requests without executing host management commands.
pub trait AccountPort {
    fn set_command_deadline(&mut self, _deadline: Instant) {}
    fn require_absent(&mut self) -> Result<(), InstallError>;
    fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError>;
    fn remove_static_service_identity(&mut self) -> Result<(), InstallError>;
    fn owns_static_service_identity(
        &mut self,
        _identity: ServiceIdentity,
    ) -> Result<bool, InstallError> {
        Ok(false)
    }
    fn create_transaction_identity(
        &mut self,
        _transaction_id: &str,
    ) -> Result<ServiceIdentity, InstallError> {
        self.create_static_service_identity()
    }
    fn remove_transaction_identity(
        &mut self,
        _transaction_id: &str,
        _identity: Option<ServiceIdentity>,
    ) -> Result<(), InstallError> {
        self.remove_static_service_identity()
    }
    fn owns_transaction_identity(
        &mut self,
        _transaction_id: &str,
        identity: Option<ServiceIdentity>,
    ) -> Result<bool, InstallError> {
        match identity {
            Some(identity) => self.owns_static_service_identity(identity),
            None => Ok(false),
        }
    }
}

/// The only service-manager actions this adapter may request.
pub trait SystemdPort {
    fn set_command_deadline(&mut self, _deadline: Instant) {}
    fn require_absent(&mut self) -> Result<(), InstallError>;
    fn daemon_reload(&mut self) -> Result<(), InstallError>;
    fn enable(&mut self) -> Result<(), InstallError>;
    fn start(&mut self) -> Result<(), InstallError>;
    /// 只确认本机 unit 已激活；Hub 的安装就绪证据不属于 root activator。
    fn wait_local_activated(&mut self) -> Result<(), InstallError>;
    fn stop(&mut self) -> Result<(), InstallError>;
    fn disable(&mut self) -> Result<(), InstallError>;
}

trait InstallFilePort {
    fn ensure_metadata_directory(
        &mut self,
        path: &Path,
        journal: &mut TransactionJournal,
    ) -> Result<bool, InstallError>;
    fn create_directory(
        &mut self,
        path: &Path,
        mode: u32,
        identity: ServiceIdentity,
        journal: &mut TransactionJournal,
        step: RollbackStep,
    ) -> Result<(), InstallError>;
    fn install_binary(
        &mut self,
        component: &mut File,
        path: &Path,
        journal: &mut TransactionJournal,
        step: RollbackStep,
    ) -> Result<(), InstallError>;
    fn write_owned(
        &mut self,
        path: &Path,
        contents: &[u8],
        mode: u32,
        owner: ServiceIdentity,
        journal: &mut TransactionJournal,
        step: RollbackStep,
    ) -> Result<(), InstallError>;
    fn remove_path(&mut self, path: &Path) -> Result<(), InstallError>;
    fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError>;
}

struct SystemInstallFiles;

struct StagedLayout {
    binary: PathBuf,
    identity: PathBuf,
    metadata: PathBuf,
    unit: PathBuf,
}

struct InstallPorts<'a, A, S, F> {
    accounts: &'a mut A,
    systemd: &'a mut S,
    files: &'a mut F,
}

impl InstallFilePort for SystemInstallFiles {
    fn ensure_metadata_directory(
        &mut self,
        path: &Path,
        journal: &mut TransactionJournal,
    ) -> Result<bool, InstallError> {
        ensure_fixed_metadata_directory(path, journal)
    }

    fn create_directory(
        &mut self,
        path: &Path,
        mode: u32,
        identity: ServiceIdentity,
        journal: &mut TransactionJournal,
        step: RollbackStep,
    ) -> Result<(), InstallError> {
        create_private_directory(path, mode, identity, journal, step)
    }

    fn install_binary(
        &mut self,
        component: &mut File,
        path: &Path,
        journal: &mut TransactionJournal,
        step: RollbackStep,
    ) -> Result<(), InstallError> {
        install_binary(component, path, journal, step)
    }

    fn write_owned(
        &mut self,
        path: &Path,
        contents: &[u8],
        mode: u32,
        owner: ServiceIdentity,
        journal: &mut TransactionJournal,
        step: RollbackStep,
    ) -> Result<(), InstallError> {
        atomic_write_owned(path, contents, mode, owner, journal, step)
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
    fn bootstrap_state(&self) -> PathBuf {
        self.map(BOOTSTRAP_STATE)
    }

    fn expected_root_uid(&self) -> u32 {
        if self.root == Path::new("/") {
            0
        } else {
            unsafe { libc::geteuid() }
        }
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

/// Fresh-machine adapter: publishes only the two verified Bootstrap receipts,
/// then enters the existing closed Probe transaction. On failure it removes
/// only the exact inodes created by this attempt.
pub struct VerifiedFreshComponents<'a> {
    pub probe: &'a mut File,
    pub bootstrap_acquirer: &'a mut File,
    pub bootstrap_activator: &'a mut File,
}

pub fn activate_fresh_current_probe(
    components: VerifiedFreshComponents<'_>,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    paths: &FixedInstallPaths,
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
) -> Result<(), InstallError> {
    preflight_parent_chains(paths)?;
    let acquirer =
        publish_bootstrap_receipt(components.bootstrap_acquirer, &paths.bootstrap_acquirer())?;
    let activator = match publish_bootstrap_receipt(
        components.bootstrap_activator,
        &paths.bootstrap_activator(),
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            remove_published_bootstrap(&acquirer);
            return Err(error);
        }
    };
    let result = activate_current_probe(
        components.probe,
        enrollment,
        bundle,
        trust,
        paths,
        accounts,
        systemd,
    );
    if result.is_err() {
        remove_published_bootstrap(&activator);
        remove_published_bootstrap(&acquirer);
    }
    result
}

struct PublishedBootstrap {
    device: u64,
    inode: u64,
    path: PathBuf,
}

fn publish_bootstrap_receipt(
    source: &mut File,
    destination: &Path,
) -> Result<PublishedBootstrap, InstallError> {
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(InstallError::ExistingResidue),
        Err(_) => return Err(InstallError::Io),
    }
    let parent = destination.parent().ok_or(InstallError::Io)?;
    let temporary = parent.join(format!(
        ".enoki-bootstrap-role-{}-{}",
        std::process::id(),
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(InstallError::Io)?
    ));
    let _ = fs::remove_file(&temporary);
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| InstallError::Io)?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| InstallError::Io)?;
        std::io::copy(source, &mut output).map_err(|_| InstallError::Io)?;
        output.sync_all().map_err(|_| InstallError::Io)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))
            .map_err(|_| InstallError::Io)?;
        fs::hard_link(&temporary, destination).map_err(|_| InstallError::ExistingResidue)?;
        let metadata = fs::symlink_metadata(destination).map_err(|_| InstallError::Io)?;
        fs::remove_file(&temporary).map_err(|_| InstallError::Io)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| InstallError::Io)?;
        Ok(PublishedBootstrap {
            device: metadata.dev(),
            inode: metadata.ino(),
            path: destination.to_owned(),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_published_bootstrap(receipt: &PublishedBootstrap) {
    if let Ok(metadata) = fs::symlink_metadata(&receipt.path)
        && metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.dev() == receipt.device
        && metadata.ino() == receipt.inode
    {
        let _ = fs::remove_file(&receipt.path);
        if let Some(parent) = receipt.path.parent() {
            let _ = File::open(parent).and_then(|directory| directory.sync_all());
        }
    }
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
    let _activation_lock = ActivationLock::acquire(
        &paths.bootstrap_state(),
        paths.expected_root_uid(),
        Instant::now() + INSTALL_COMMAND_BUDGET,
    )?;
    recover_interrupted_install(paths, ports)?;
    preflight_parent_chains(paths)?;
    preflight_files(paths)?;
    preflight_fixed_metadata_directory(&paths.etc_enoki())?;
    validate_bootstrap_role(&paths.bootstrap_acquirer())?;
    validate_bootstrap_role(&paths.bootstrap_activator())?;
    let install_deadline = Instant::now() + INSTALL_COMMAND_BUDGET;
    ports.accounts.set_command_deadline(install_deadline);
    ports.systemd.set_command_deadline(install_deadline);
    ports.accounts.require_absent()?;
    ports.systemd.require_absent()?;

    let mut journal = TransactionJournal::begin(&paths.bootstrap_state())?;
    let identity = match ports
        .accounts
        .create_transaction_identity(journal.transaction_id())
    {
        Ok(identity) => identity,
        Err(error) => {
            return Err(abort_prepared_install(error, &journal, ports.accounts));
        }
    };
    if let Err(error) = journal.record_identity(identity.uid, identity.gid) {
        return Err(abort_prepared_install(error, &journal, ports.accounts));
    }
    let staged =
        match stage_complete_layout(component, enrollment, trust, journal.staging_directory()) {
            Ok(staged) => staged,
            Err(error) => {
                return Err(abort_prepared_install(error, &journal, ports.accounts));
            }
        };
    let mut enabled = false;
    let mut started = false;
    let result = (|| {
        ports
            .files
            .ensure_metadata_directory(&paths.etc_enoki(), &mut journal)?;
        ports.files.create_directory(
            &paths.state(),
            0o750,
            identity,
            &mut journal,
            RollbackStep::RemoveStateDirectory,
        )?;
        ports.files.create_directory(
            &paths.identity_dir(),
            0o700,
            identity,
            &mut journal,
            RollbackStep::RemoveIdentityDirectory,
        )?;
        let mut staged_binary = File::open(&staged.binary).map_err(|_| InstallError::Io)?;
        ports.files.install_binary(
            &mut staged_binary,
            &paths.binary(),
            &mut journal,
            RollbackStep::RemoveBinary,
        )?;
        ports.files.write_owned(
            &paths.identity(),
            &fs::read(&staged.identity).map_err(|_| InstallError::Io)?,
            0o600,
            identity,
            &mut journal,
            RollbackStep::RemoveIdentity,
        )?;
        ports.files.write_owned(
            &paths.metadata(),
            &fs::read(&staged.metadata).map_err(|_| InstallError::Io)?,
            0o600,
            ServiceIdentity { uid: 0, gid: 0 },
            &mut journal,
            RollbackStep::RemoveInstallMetadata,
        )?;
        ports.files.write_owned(
            &paths.unit(),
            &fs::read(&staged.unit).map_err(|_| InstallError::Io)?,
            0o644,
            ServiceIdentity { uid: 0, gid: 0 },
            &mut journal,
            RollbackStep::RemoveUnit,
        )?;
        ports.systemd.daemon_reload()?;
        journal.record_enabled_intent()?;
        enabled = true;
        ports.systemd.enable()?;
        journal.record_started_intent()?;
        started = true;
        ports.systemd.start()?;
        ports.systemd.wait_local_activated()?;
        Ok(())
    })();
    match result {
        Ok(()) => journal.commit_layout(&paths.bootstrap_state(), &bundle.version),
        Err(install_error) => {
            let rollback_deadline = Instant::now() + ROLLBACK_COMMAND_BUDGET;
            ports.accounts.set_command_deadline(rollback_deadline);
            ports.systemd.set_command_deadline(rollback_deadline);
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
                &journal,
                &mut failures,
            );
            if failures.is_empty() {
                record_rollback(
                    &mut failures,
                    RollbackStep::RemoveTemporary,
                    journal.remove_staging_if_owned(),
                );
            }
            if failures.is_empty() {
                record_rollback(
                    &mut failures,
                    RollbackStep::RemoveTemporary,
                    journal.remove(),
                );
            }
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

fn abort_prepared_install(
    cause: InstallError,
    journal: &TransactionJournal,
    accounts: &mut impl AccountPort,
) -> InstallError {
    accounts.set_command_deadline(Instant::now() + ROLLBACK_COMMAND_BUDGET);
    let mut failures = Vec::new();
    record_rollback(
        &mut failures,
        RollbackStep::RemoveServiceIdentity,
        accounts.remove_transaction_identity(
            journal.transaction_id(),
            journal
                .identity()
                .map(|(uid, gid)| ServiceIdentity { uid, gid }),
        ),
    );
    record_rollback(
        &mut failures,
        RollbackStep::RemoveTemporary,
        journal.remove_staging_if_owned(),
    );
    if failures.is_empty() {
        record_rollback(
            &mut failures,
            RollbackStep::RemoveTemporary,
            journal.remove(),
        );
    }
    if failures.is_empty() {
        cause
    } else {
        InstallError::Rollback {
            cause: cause.kind(),
            failures,
        }
    }
}

fn cleanup_failed_install(
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
    files: &mut impl InstallFilePort,
    journal: &TransactionJournal,
    failures: &mut Vec<RollbackFailure>,
) {
    for owned in journal.paths().iter().rev() {
        let result = if owned.still_owned() {
            if owned.directory() {
                files.remove_directory(owned.path())
            } else {
                files.remove_path(owned.path())
            }
        } else if owned.path().exists() {
            Err(InstallError::ExistingResidue)
        } else {
            Ok(())
        };
        record_rollback(failures, owned.step(), result);
        record_rollback(
            failures,
            RollbackStep::RemoveTemporary,
            owned.remove_owned_staging(),
        );
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
        accounts.remove_transaction_identity(
            journal.transaction_id(),
            journal
                .identity()
                .map(|(uid, gid)| ServiceIdentity { uid, gid }),
        ),
    );
}

fn recover_interrupted_install(
    paths: &FixedInstallPaths,
    ports: &mut InstallPorts<'_, impl AccountPort, impl SystemdPort, impl InstallFilePort>,
) -> Result<(), InstallError> {
    let Some(journal) = TransactionJournal::load(&paths.bootstrap_state())? else {
        return Ok(());
    };
    if TransactionJournal::layout_is_committed(&paths.bootstrap_state())? {
        journal.remove_staging_if_owned()?;
        journal.remove()?;
        return Err(InstallError::ExistingResidue);
    }
    let deadline = Instant::now() + ROLLBACK_COMMAND_BUDGET;
    ports.accounts.set_command_deadline(deadline);
    ports.systemd.set_command_deadline(deadline);
    let mut failures = Vec::new();
    if journal.started_may_exist() {
        record_rollback(
            &mut failures,
            RollbackStep::StopService,
            ports.systemd.stop(),
        );
    }
    if journal.enabled_may_exist() {
        record_rollback(
            &mut failures,
            RollbackStep::DisableService,
            ports.systemd.disable(),
        );
    }
    for owned in journal.paths().iter().rev() {
        if owned.still_owned() {
            let result = if owned.directory() {
                ports.files.remove_directory(owned.path())
            } else {
                ports.files.remove_path(owned.path())
            };
            record_rollback(&mut failures, owned.step(), result);
        } else if owned.path().exists() {
            failures.push(RollbackFailure::new(
                owned.step(),
                InstallErrorKind::ExistingResidue,
            ));
        }
        record_rollback(
            &mut failures,
            RollbackStep::RemoveTemporary,
            owned.remove_owned_staging(),
        );
    }
    record_rollback(
        &mut failures,
        RollbackStep::RemoveTemporary,
        journal.remove_staging_if_owned(),
    );
    record_rollback(
        &mut failures,
        RollbackStep::ReloadSystemd,
        ports.systemd.daemon_reload(),
    );
    {
        let identity = journal
            .identity()
            .map(|(uid, gid)| ServiceIdentity { uid, gid });
        match ports
            .accounts
            .owns_transaction_identity(journal.transaction_id(), identity)
        {
            Ok(true) => record_rollback(
                &mut failures,
                RollbackStep::RemoveServiceIdentity,
                ports
                    .accounts
                    .remove_transaction_identity(journal.transaction_id(), identity),
            ),
            Ok(false) if identity.is_some() => failures.push(RollbackFailure::new(
                RollbackStep::RemoveServiceIdentity,
                InstallErrorKind::ExistingResidue,
            )),
            Ok(false) => {}
            Err(error) => record_rollback(
                &mut failures,
                RollbackStep::RemoveServiceIdentity,
                Err(error),
            ),
        }
    }
    if failures.is_empty() {
        journal.remove()
    } else {
        Err(InstallError::Rollback {
            cause: InstallErrorKind::Io,
            failures,
        })
    }
}

fn stage_complete_layout(
    component: &mut File,
    enrollment: &Enrollment,
    trust: &BuildTrust,
    staging: &Path,
) -> Result<StagedLayout, InstallError> {
    let binary = staging.join("enoki-probe");
    component
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallError::Io)?;
    let mut staged_binary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&binary)
        .map_err(|_| InstallError::Io)?;
    std::io::copy(component, &mut staged_binary).map_err(|_| InstallError::Io)?;
    staged_binary.sync_all().map_err(|_| InstallError::Io)?;
    let identity = staging.join("probe-bootstrap.toml");
    let metadata = staging.join("probe-install.toml");
    let unit = staging.join("enoki-probe.service");
    for (path, contents) in [
        (&identity, bootstrap_config(enrollment, trust)),
        (&metadata, install_metadata(enrollment, trust)),
        (&unit, service_unit().to_owned()),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| InstallError::Io)?;
        file.write_all(contents.as_bytes())
            .map_err(|_| InstallError::Io)?;
        file.sync_all().map_err(|_| InstallError::Io)?;
    }
    File::open(staging)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InstallError::Io)?;
    Ok(StagedLayout {
        binary,
        identity,
        metadata,
        unit,
    })
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

fn command_presence(
    program: &str,
    arguments: &[&str],
    absent_status: i32,
    deadline: Instant,
) -> Result<bool, InstallError> {
    let output = run_bounded(
        program,
        arguments,
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(code) if code == absent_status => Ok(false),
        _ => Err(InstallError::Account),
    }
}
fn require_success(
    program: &str,
    arguments: &[&str],
    error: InstallError,
    deadline: Instant,
) -> Result<(), InstallError> {
    let output = run_bounded(
        program,
        arguments,
        error.clone(),
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    output.status.success().then_some(()).ok_or(error)
}
fn numeric_id(flag: &str, deadline: Instant) -> Result<u32, InstallError> {
    let output = run_bounded(
        "/usr/bin/id",
        &[flag, SERVICE_USER],
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
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

pub use account::SystemAccounts;
#[cfg(test)]
use account::create_static_service_identity_with_commands;
use filesystem::*;
pub use systemd::SystemSystemd;

include!("install/tests.rs");
