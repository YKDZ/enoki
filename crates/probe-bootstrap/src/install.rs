//! The fixed fresh-install adapter for the current Probe component.
//!
//! This is intentionally a small closed boundary: a verified component can
//! become only the current Probe service at the paths below.  It has no
//! archive, network, command-line interpolation, or candidate-code surface.

mod account;
mod bundle_restore;
mod command;
#[cfg(feature = "acquirer")]
mod compatible_upgrade;
mod filesystem;
mod installed_layout;
mod replacement_finalize;
mod replacement_registration;
mod systemd;
mod transaction;
#[cfg_attr(not(feature = "acquirer"), allow(dead_code))]
mod upgrade;

use crate::replacement::{
    FileReplacementCommitStore, ReplacementCommitFact, ReplacementCommitStore,
    ReplacementRegistrationBinding, ReplacementResumeBinding,
};
use crate::{
    bundle_role::{
        DISK_HEALTH_PERMISSION_PROFILE, LIFECYCLE_COMPANION_PERMISSION_PROFILE,
        OBSERVATION_RUNTIME_PERMISSION_PROFILE, PROBE_PERMISSION_PROFILE,
        SYSTEM_STATE_PERMISSION_PROFILE,
    },
    handoff::Enrollment,
    lifecycle::derive_lifecycle_authority_install_key,
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

pub(crate) use replacement_registration::retire_attempt_source as retire_replacement_registration_attempt_source;

const INSTALL_COMMAND_BUDGET: Duration = Duration::from_secs(90);
const ROLLBACK_COMMAND_BUDGET: Duration = Duration::from_secs(30);
const COMMAND_STEP_BUDGET: Duration = Duration::from_secs(15);

const SERVICE_NAME: &str = "enoki-probe";
const SERVICE_USER: &str = "enoki-probe";
const SERVICE_GROUP: &str = "enoki-probe";
const PROBE_IPC_GROUP: &str = "enoki-probe-ipc";
const OBSERVATION_IPC_GROUP: &str = "enoki-observation-ipc";
const BINARY: &str = "/usr/local/bin/enoki-probe";
const OBSERVATION_RUNTIME_BINARY: &str = "/usr/local/bin/enoki-observation-runtime";
const CPU_PROVIDER_BINARY: &str = "/usr/local/bin/enoki-cpu-resource-provider";
const DISK_HEALTH_PROVIDER_BINARY: &str = "/usr/local/bin/enoki-disk-health-resource-provider";
const LIFECYCLE_COMPANION_BINARY: &str = "/usr/local/bin/enoki-probe-lifecycle-companion";
const STATE: &str = "/var/lib/enoki-probe";
const RUNTIME_FAILURE_EPOCH: &str = "/var/lib/enoki-probe/runtime-failure/epoch.toml";
const RUNTIME_FAILURE_LATCH: &str = "/var/lib/enoki-probe/runtime-failure/latch";
const RUNTIME_FAILURE_DIR: &str = "/var/lib/enoki-probe/runtime-failure";
// Volatile synchronization only. This path deliberately lives outside every
// durable Runtime-failure state directory so cleanup can never unlink the
// inode while another recorder or typed consumer is waiting on it.
const RUNTIME_FAILURE_LOCK: &str = "/run/enoki-probe/runtime-failure-pair.lock";
const BOOT_ID: &str = "/run/enoki-probe/runtime-failure-boot-id";
const IDENTITY_DIR: &str = "/var/lib/enoki-probe/identity";
const IDENTITY: &str = "/var/lib/enoki-probe/identity/probe-bootstrap.toml";
const INSTALL_METADATA: &str = "/etc/enoki/probe-install.toml";
const UNIT: &str = "/etc/systemd/system/enoki-probe.service";
const OBSERVATION_RUNTIME_UNIT: &str = "/etc/systemd/system/enoki-observation-runtime.service";
const OBSERVATION_RUNTIME_SOCKET_UNIT: &str =
    "/etc/systemd/system/enoki-observation-runtime.socket";
const OBSERVATION_RUNTIME_FAILURE_RECORDER_UNIT: &str =
    "/etc/systemd/system/enoki-observation-runtime-failure.service";
const CPU_PROVIDER_UNIT: &str = "/etc/systemd/system/enoki-cpu-resource-provider@.service";
const CPU_PROVIDER_SOCKET_UNIT: &str = "/etc/systemd/system/enoki-cpu-resource-provider.socket";
const DISK_HEALTH_PROVIDER_UNIT: &str =
    "/etc/systemd/system/enoki-disk-health-resource-provider@.service";
const DISK_HEALTH_PROVIDER_SOCKET_UNIT: &str =
    "/etc/systemd/system/enoki-disk-health-resource-provider.socket";
const LIFECYCLE_COMPANION_UNIT: &str =
    "/etc/systemd/system/enoki-probe-lifecycle-companion@.service";
const LIFECYCLE_COMPANION_SOCKET_UNIT: &str =
    "/etc/systemd/system/enoki-probe-lifecycle-companion.socket";
const LIFECYCLE_UPGRADE_UNIT: &str = "/etc/systemd/system/enoki-probe-lifecycle-upgrade@.service";
const LIFECYCLE_UPGRADE_SOCKET_UNIT: &str =
    "/etc/systemd/system/enoki-probe-lifecycle-upgrade.socket";
const BOOTSTRAP_ACQUIRER: &str = "/usr/local/bin/enoki-probe-bootstrap-acquire";
const BOOTSTRAP_ACTIVATOR: &str = "/usr/local/bin/enoki-probe-bootstrap-activate";
const BOOTSTRAP_STATE: &str = "/var/lib/enoki-probe-bootstrap";
// 仅用于拒绝/清理旧安装残留；新安装绝不创建此路径。
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
    RemoveBootstrapAcquirer,
    RemoveBootstrapActivator,
    RemoveIdentityDirectory,
    RemoveStateDirectory,
    RemoveMetadataDirectory,
    ReloadSystemd,
    RemoveServiceIdentity,
    RemoveServiceUser,
    RemoveServiceGroup,
    RemoveObservationIpcGroup,
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
            Self::RemoveBootstrapAcquirer => "remove_bootstrap_acquirer",
            Self::RemoveBootstrapActivator => "remove_bootstrap_activator",
            Self::RemoveIdentityDirectory => "remove_identity_directory",
            Self::RemoveStateDirectory => "remove_state_directory",
            Self::RemoveMetadataDirectory => "remove_metadata_directory",
            Self::ReloadSystemd => "reload_systemd",
            Self::RemoveServiceIdentity => "remove_service_identity",
            Self::RemoveServiceUser => "remove_service_user",
            Self::RemoveServiceGroup => "remove_service_group",
            Self::RemoveObservationIpcGroup => "remove_observation_ipc_group",
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
    fn create_transaction_identity(
        &mut self,
        _transaction_id: &str,
    ) -> Result<ServiceIdentity, InstallError>;
    fn remove_transaction_identity(
        &mut self,
        _transaction_id: &str,
        _identity: Option<ServiceIdentity>,
    ) -> Result<(), InstallError>;
    fn owns_transaction_identity(
        &mut self,
        _transaction_id: &str,
        _identity: Option<ServiceIdentity>,
    ) -> Result<bool, InstallError> {
        Ok(false)
    }
    fn owns_observation_ipc_group(&mut self, _transaction_id: &str) -> Result<bool, InstallError> {
        Ok(false)
    }
    fn create_observation_ipc_group(&mut self, _transaction_id: &str) -> Result<(), InstallError> {
        Ok(())
    }
    fn remove_observation_ipc_group(&mut self, _transaction_id: &str) -> Result<(), InstallError> {
        Ok(())
    }
}

/// The only service-manager actions this adapter may request.
pub trait SystemdPort {
    fn set_command_deadline(&mut self, _deadline: Instant) {}
    fn require_absent(&mut self) -> Result<(), InstallError>;
    fn daemon_reload(&mut self) -> Result<(), InstallError>;
    fn enable(&mut self) -> Result<(), InstallError>;
    fn start(&mut self) -> Result<(), InstallError>;
    /// 只重启 canonical Probe unit，并在无 registration credential 的新 invocation
    /// 已激活后返回；不得复用广义 rollback stop。
    fn restart_canonical(&mut self) -> Result<(), InstallError> {
        Err(InstallError::Systemd)
    }
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
    #[cfg(test)]
    test_identity_owner_mapping: Option<(ServiceIdentity, ServiceIdentity)>,
}

impl FixedInstallPaths {
    pub fn production() -> Self {
        Self {
            root: PathBuf::from("/"),
            #[cfg(test)]
            test_identity_owner_mapping: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn under(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            test_identity_owner_mapping: Some((
                ServiceIdentity {
                    uid: 2_000_000_001,
                    gid: 2_000_000_002,
                },
                ServiceIdentity {
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                },
            )),
        }
    }

    #[cfg(feature = "deterministic-test-seams")]
    #[doc(hidden)]
    pub fn under_test_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            #[cfg(test)]
            test_identity_owner_mapping: None,
        }
    }

    fn map(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    fn binary(&self) -> PathBuf {
        self.map(BINARY)
    }
    fn observation_runtime_binary(&self) -> PathBuf {
        self.map(OBSERVATION_RUNTIME_BINARY)
    }
    fn cpu_provider_binary(&self) -> PathBuf {
        self.map(CPU_PROVIDER_BINARY)
    }
    fn disk_health_provider_binary(&self) -> PathBuf {
        self.map(DISK_HEALTH_PROVIDER_BINARY)
    }
    fn lifecycle_companion_binary(&self) -> PathBuf {
        self.map(LIFECYCLE_COMPANION_BINARY)
    }
    fn state(&self) -> PathBuf {
        self.map(STATE)
    }
    fn runtime_failure_epoch(&self) -> PathBuf {
        self.map(RUNTIME_FAILURE_EPOCH)
    }
    fn runtime_failure_dir(&self) -> PathBuf {
        self.map(RUNTIME_FAILURE_DIR)
    }
    fn runtime_failure_latch(&self) -> PathBuf {
        self.map(RUNTIME_FAILURE_LATCH)
    }
    fn runtime_failure_lock(&self) -> PathBuf {
        self.map(RUNTIME_FAILURE_LOCK)
    }
    fn boot_id(&self) -> PathBuf {
        self.map(BOOT_ID)
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
    fn observation_runtime_unit(&self) -> PathBuf {
        self.map(OBSERVATION_RUNTIME_UNIT)
    }
    fn observation_runtime_socket_unit(&self) -> PathBuf {
        self.map(OBSERVATION_RUNTIME_SOCKET_UNIT)
    }
    fn observation_runtime_failure_recorder_unit(&self) -> PathBuf {
        self.map(OBSERVATION_RUNTIME_FAILURE_RECORDER_UNIT)
    }
    fn cpu_provider_unit(&self) -> PathBuf {
        self.map(CPU_PROVIDER_UNIT)
    }
    fn cpu_provider_socket_unit(&self) -> PathBuf {
        self.map(CPU_PROVIDER_SOCKET_UNIT)
    }
    fn disk_health_provider_unit(&self) -> PathBuf {
        self.map(DISK_HEALTH_PROVIDER_UNIT)
    }
    fn disk_health_provider_socket_unit(&self) -> PathBuf {
        self.map(DISK_HEALTH_PROVIDER_SOCKET_UNIT)
    }
    fn lifecycle_companion_unit(&self) -> PathBuf {
        self.map(LIFECYCLE_COMPANION_UNIT)
    }
    fn lifecycle_companion_socket_unit(&self) -> PathBuf {
        self.map(LIFECYCLE_COMPANION_SOCKET_UNIT)
    }
    fn lifecycle_upgrade_unit(&self) -> PathBuf {
        self.map(LIFECYCLE_UPGRADE_UNIT)
    }
    fn lifecycle_upgrade_socket_unit(&self) -> PathBuf {
        self.map(LIFECYCLE_UPGRADE_SOCKET_UNIT)
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

    fn expected_root_gid(&self) -> u32 {
        if self.root == Path::new("/") {
            0
        } else {
            unsafe { libc::getegid() }
        }
    }

    fn observed_identity_owner(&self, receipt: ServiceIdentity) -> ServiceIdentity {
        #[cfg(test)]
        if let Some((logical, observed)) = self.test_identity_owner_mapping
            && receipt == logical
        {
            return observed;
        }
        receipt
    }

    #[cfg(test)]
    fn map_identity_owner_for_test(&mut self, logical: ServiceIdentity, observed: ServiceIdentity) {
        self.test_identity_owner_mapping = Some((logical, observed));
    }

    fn identity_owner_receipt(&self, observed: ServiceIdentity) -> ServiceIdentity {
        #[cfg(test)]
        if let Some((logical, mapped_observed)) = self.test_identity_owner_mapping
            && observed == mapped_observed
        {
            return logical;
        }
        observed
    }
}

#[cfg(feature = "deterministic-test-seams")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledBundleRepairCrashPoint {
    JournalPublish,
    Prepare(usize),
    Backup(usize),
    Stop,
    Publish(usize),
    Reload,
    Cleanup(usize),
    Complete,
    JournalCleanup,
}

#[cfg(feature = "deterministic-test-seams")]
#[doc(hidden)]
pub fn set_installed_bundle_repair_crash_for_test(
    point: InstalledBundleRepairCrashPoint,
) -> Result<(), InstallError> {
    let point = match point {
        InstalledBundleRepairCrashPoint::JournalPublish => "journal-publish".to_owned(),
        InstalledBundleRepairCrashPoint::Prepare(index) if index < 21 => {
            format!("prepare:{index}")
        }
        InstalledBundleRepairCrashPoint::Backup(index) if index < 21 => {
            format!("backup:{index}")
        }
        InstalledBundleRepairCrashPoint::Stop => "stop".to_owned(),
        InstalledBundleRepairCrashPoint::Publish(index) if index < 21 => {
            format!("publish:{index}")
        }
        InstalledBundleRepairCrashPoint::Reload => "reload".to_owned(),
        InstalledBundleRepairCrashPoint::Cleanup(index) if index < 21 => {
            format!("cleanup:{index}")
        }
        InstalledBundleRepairCrashPoint::Complete => "complete".to_owned(),
        InstalledBundleRepairCrashPoint::JournalCleanup => "journal-cleanup".to_owned(),
        _ => return Err(InstallError::ExistingResidue),
    };
    bundle_restore::set_crash(&point);
    Ok(())
}

pub(crate) struct VerifiedCompleteFreshComponents<'a> {
    pub probe: &'a mut File,
    pub observation_runtime: &'a mut File,
    pub cpu_provider: &'a mut File,
    pub disk_health_provider: &'a mut File,
    pub lifecycle_companion: &'a mut File,
    pub bootstrap_acquirer: &'a mut File,
    pub bootstrap_activator: &'a mut File,
}

#[derive(Clone, Copy)]
struct FreshInstallAuthority<'a> {
    enrollment: &'a Enrollment,
}

impl<'a> FreshInstallAuthority<'a> {
    fn classify(enrollment: &'a Enrollment) -> Result<Self, InstallError> {
        if enrollment.replacement_migration().is_some() {
            return Err(InstallError::InvalidVerifiedComponent);
        }
        Ok(Self { enrollment })
    }
}

struct VerifiedFreshInstall<'a> {
    components: VerifiedCompleteFreshComponents<'a>,
    authority: FreshInstallAuthority<'a>,
    bundle: &'a VerifiedBundle,
    trust: &'a BuildTrust,
}

#[derive(Clone, Copy)]
enum InstallFailureSemantics<'a> {
    FreshRollback,
    #[cfg_attr(not(test), allow(dead_code))]
    CommittedReplacement(&'a ReplacementResumeBinding),
    CommittedReplacementWithRegistration {
        registration: &'a ReplacementRegistrationBinding,
        resume: &'a ReplacementResumeBinding,
    },
}

impl<'a> InstallFailureSemantics<'a> {
    fn committed_replacement_binding(self) -> Option<&'a ReplacementResumeBinding> {
        match self {
            Self::FreshRollback => None,
            Self::CommittedReplacement(binding) => Some(binding),
            Self::CommittedReplacementWithRegistration { resume, .. } => Some(resume),
        }
    }

    fn registration_binding(self) -> Option<&'a ReplacementRegistrationBinding> {
        match self {
            Self::CommittedReplacementWithRegistration { registration, .. } => Some(registration),
            Self::FreshRollback | Self::CommittedReplacement(_) => None,
        }
    }

    fn is_committed_replacement(self) -> bool {
        !matches!(self, Self::FreshRollback)
    }
}

enum InterruptedInstall {
    Fresh,
    ResumeCommitted(Box<TransactionJournal>),
    Complete,
}

/// Classifies only whether the exact committed candidate transaction already
/// owns local publication. Source metadata must never be retired once this
/// journal exists, even before the candidate-layout receipt is persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommittedReplacementLocalCustody {
    SourceMetadata,
    SourceMetadataRetired,
    CandidateTransaction,
}

pub(crate) fn classify_committed_replacement_local_custody(
    paths: &FixedInstallPaths,
    resume_binding: &ReplacementResumeBinding,
) -> Result<CommittedReplacementLocalCustody, InstallError> {
    if let Some(journal) = TransactionJournal::load(&paths.bootstrap_state())? {
        if !journal.matches_resume_binding(resume_binding.as_str()) {
            return Err(InstallError::ExistingResidue);
        }
        return Ok(CommittedReplacementLocalCustody::CandidateTransaction);
    }
    if paths
        .metadata()
        .try_exists()
        .map_err(|_| InstallError::Io)?
    {
        Ok(CommittedReplacementLocalCustody::SourceMetadata)
    } else {
        Ok(CommittedReplacementLocalCustody::SourceMetadataRetired)
    }
}

/// Fresh 专属 coordinator：只接受普通新 Host Enrollment 与完整已验证角色集合。
/// Replacement authority 在构造任何 account/filesystem/systemd effect 前关闭。
pub(crate) fn coordinate_fresh_install(
    components: VerifiedCompleteFreshComponents<'_>,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
) -> Result<(), InstallError> {
    let verified = verify_fresh_install(components, enrollment, bundle, trust)?;
    let paths = FixedInstallPaths::production();
    let mut accounts = SystemAccounts::default();
    let mut systemd = SystemSystemd::default();
    let mut files = SystemInstallFiles;
    activate_verified_fresh_install(
        verified.components.probe,
        Some((
            verified.components.observation_runtime,
            verified.components.cpu_provider,
            verified.components.disk_health_provider,
            verified.components.lifecycle_companion,
        )),
        Some((
            verified.components.bootstrap_acquirer,
            verified.components.bootstrap_activator,
        )),
        verified.authority.enrollment,
        verified.bundle,
        verified.trust,
        &paths,
        &mut InstallPorts {
            accounts: &mut accounts,
            systemd: &mut systemd,
            files: &mut files,
        },
        InstallFailureSemantics::FreshRollback,
    )
}

fn verify_fresh_install<'a>(
    components: VerifiedCompleteFreshComponents<'a>,
    enrollment: &'a Enrollment,
    bundle: &'a VerifiedBundle,
    trust: &'a BuildTrust,
) -> Result<VerifiedFreshInstall<'a>, InstallError> {
    let authority = FreshInstallAuthority::classify(enrollment)?;
    verify_fresh_install_inputs(
        components.probe,
        Some(&mut (
            &mut *components.observation_runtime,
            &mut *components.cpu_provider,
            &mut *components.disk_health_provider,
            &mut *components.lifecycle_companion,
        )),
        bundle,
        trust,
    )?;
    Ok(VerifiedFreshInstall {
        components,
        authority,
        bundle,
        trust,
    })
}

/// 仅用于 Replacement；调用者已持久化精确的 Replacement Migration commit fact，
/// 因此候选激活失败时保留 durable journal，绝不调用普通 fresh-install rollback。
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn activate_complete_replacement_current_probe(
    components: VerifiedCompleteFreshComponents<'_>,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    paths: &FixedInstallPaths,
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
    resume_binding: &ReplacementResumeBinding,
) -> Result<(), InstallError> {
    activate_complete_replacement_current_probe_with_semantics(
        components,
        enrollment,
        bundle,
        trust,
        paths,
        accounts,
        systemd,
        InstallFailureSemantics::CommittedReplacement(resume_binding),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_complete_replacement_current_probe_with_registration(
    components: VerifiedCompleteFreshComponents<'_>,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    paths: &FixedInstallPaths,
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
    resume_binding: &ReplacementResumeBinding,
    registration_binding: &ReplacementRegistrationBinding,
) -> Result<(), InstallError> {
    activate_complete_replacement_current_probe_with_semantics(
        components,
        enrollment,
        bundle,
        trust,
        paths,
        accounts,
        systemd,
        InstallFailureSemantics::CommittedReplacementWithRegistration {
            registration: registration_binding,
            resume: resume_binding,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn activate_complete_replacement_current_probe_with_semantics<'a>(
    components: VerifiedCompleteFreshComponents<'_>,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    paths: &FixedInstallPaths,
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
    semantics: InstallFailureSemantics<'a>,
) -> Result<(), InstallError> {
    let mut files = SystemInstallFiles;
    activate_verified_install_layout(
        components.probe,
        Some((
            components.observation_runtime,
            components.cpu_provider,
            components.disk_health_provider,
            components.lifecycle_companion,
        )),
        Some((
            components.bootstrap_acquirer,
            components.bootstrap_activator,
        )),
        enrollment,
        bundle,
        trust,
        paths,
        &mut InstallPorts {
            accounts,
            systemd,
            files: &mut files,
        },
        semantics,
    )
}

/// Replacement coordinator 在 candidate-layout receipt 持久化后调用；只有完全相同
/// 的不透明绑定可以释放 activation journal custody。
pub(crate) fn finalize_complete_replacement_current_probe(
    paths: &FixedInstallPaths,
    resume_binding: &ReplacementResumeBinding,
    bundle: &VerifiedBundle,
    commit: &ReplacementCommitFact,
) -> Result<(), InstallError> {
    if !commit.has_valid_binding() || commit.resume_binding() != *resume_binding {
        return Err(InstallError::ExistingResidue);
    }
    let journal = TransactionJournal::load(&paths.bootstrap_state())?;
    if let Some(journal) = journal.as_ref()
        && !journal.matches_resume_binding(resume_binding.as_str())
    {
        return Err(InstallError::ExistingResidue);
    }
    replacement_finalize::verify_exact_layout(paths, bundle, commit, journal.as_ref())?;
    if let Some(journal) = journal {
        journal.remove_staging_if_owned()?;
        journal.remove()?;
    }
    Ok(())
}

/// Root finalizer 的完整 Replacement retirement 边界。只有 exact layout 与注册结果
/// 均已 durable，才按 registration attempt、commit fact 的顺序释放恢复 custody。
pub(crate) fn finalize_and_retire_complete_replacement_current_probe(
    paths: &FixedInstallPaths,
    resume_binding: &ReplacementResumeBinding,
    bundle: &VerifiedBundle,
    commit: &ReplacementCommitFact,
    commit_store: &mut FileReplacementCommitStore,
    systemd: &mut impl SystemdPort,
) -> Result<(), InstallError> {
    if !commit.has_valid_binding()
        || commit.resume_binding() != *resume_binding
        || commit_store
            .load()
            .map_err(|_| InstallError::ExistingResidue)?
            .as_ref()
            != Some(commit)
    {
        return Err(InstallError::ExistingResidue);
    }
    let registration_binding = commit
        .registration_binding()
        .ok_or(InstallError::ExistingResidue)?;
    let mut retained_commit = commit.clone();
    replacement_registration::converge_registered_identity_to_canonical(
        paths,
        &registration_binding,
    )?;
    replacement_registration::require_canonical_restart_ready(paths, &registration_binding)?;
    let identity_sha256 = replacement_registration::canonical_identity_sha256(
        paths,
        &registration_binding,
        retained_commit.canonical_identity_sha256().is_none(),
    )?;
    retained_commit
        .bind_canonical_identity_sha256(identity_sha256.clone())
        .map_err(|()| InstallError::ExistingResidue)?;
    if retained_commit != *commit {
        commit_store
            .persist_identity_binding_exact(commit, &retained_commit)
            .map_err(|_| InstallError::ExistingResidue)?;
    }
    if commit_store
        .load()
        .map_err(|_| InstallError::ExistingResidue)?
        .as_ref()
        != Some(&retained_commit)
        || replacement_registration::canonical_identity_sha256(paths, &registration_binding, false)?
            != identity_sha256
    {
        return Err(InstallError::ExistingResidue);
    }
    replacement_registration::require_canonical_restart_ready(paths, &registration_binding)?;
    finalize_complete_replacement_current_probe(paths, resume_binding, bundle, &retained_commit)?;
    retire_replacement_registration_attempt_source(paths)?;
    if replacement_registration::canonical_identity_sha256(paths, &registration_binding, false)?
        != identity_sha256
    {
        return Err(InstallError::ExistingResidue);
    }
    replacement_registration::require_canonical_restart_ready(paths, &registration_binding)?;
    systemd.restart_canonical()?;
    commit_store
        .retire_exact(&retained_commit)
        .map_err(|_| InstallError::ExistingResidue)
}

/// Read-only predecessor/successor correlation at the root finalizer boundary.
/// A retained commit is not authority for a different Enrollment: only the
/// terminal-recovery Enrollment bound to the canonical Probe identity produced
/// by that commit may retire it before beginning its own activation.
pub(crate) fn completed_replacement_predecessor_matches_current_enrollment(
    paths: &FixedInstallPaths,
    predecessor: &ReplacementRegistrationBinding,
    enrollment: &crate::handoff::Enrollment,
    bundle: &VerifiedBundle,
) -> bool {
    replacement_registration::completed_predecessor_matches_current_enrollment(
        paths,
        predecessor,
        enrollment,
        bundle,
    )
}

struct BootstrapRolePath {
    path: PathBuf,
    rollback: RollbackStep,
}

fn bootstrap_role_registry(paths: &FixedInstallPaths) -> [BootstrapRolePath; 2] {
    [
        BootstrapRolePath {
            path: paths.bootstrap_acquirer(),
            rollback: RollbackStep::RemoveBootstrapAcquirer,
        },
        BootstrapRolePath {
            path: paths.bootstrap_activator(),
            rollback: RollbackStep::RemoveBootstrapActivator,
        },
    ]
}

fn require_bootstrap_roles_absent(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    for role in bootstrap_role_registry(paths) {
        match fs::symlink_metadata(role.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(InstallError::ExistingResidue),
            Err(_) => return Err(InstallError::Io),
        }
    }
    Ok(())
}

fn validate_bootstrap_roles(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    for role in bootstrap_role_registry(paths) {
        validate_bootstrap_role(&role.path)?;
    }
    Ok(())
}

// The closed activation boundary makes every authority-bearing dependency
// explicit; none of these values are caller-selected role collections.
#[allow(clippy::too_many_arguments)]
fn activate_verified_install_layout(
    component: &mut File,
    observation_components: Option<(&mut File, &mut File, &mut File, &mut File)>,
    bootstrap_components: Option<(&mut File, &mut File)>,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    paths: &FixedInstallPaths,
    ports: &mut InstallPorts<'_, impl AccountPort, impl SystemdPort, impl InstallFilePort>,
    failure_semantics: InstallFailureSemantics<'_>,
) -> Result<(), InstallError> {
    let mut observation_components = observation_components;
    verify_fresh_install_inputs(component, observation_components.as_mut(), bundle, trust)?;
    activate_verified_fresh_install(
        component,
        observation_components,
        bootstrap_components,
        enrollment,
        bundle,
        trust,
        paths,
        ports,
        failure_semantics,
    )
}

fn verify_fresh_install_inputs(
    component: &mut File,
    observation_components: Option<&mut (&mut File, &mut File, &mut File, &mut File)>,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
) -> Result<(), InstallError> {
    let trust_version = trust.version.strip_prefix('v').unwrap_or(trust.version);
    let runtime_receipt = bundle.component_receipt("observation-runtime");
    let cpu_provider_receipt = bundle.component_receipt("system-state-provider");
    let disk_health_provider_receipt = bundle.component_receipt("disk-health-provider");
    let lifecycle_companion_receipt = bundle.component_receipt("lifecycle-companion");
    if !trust.is_for(BootstrapRole::Activator)
        || bundle.target != trust.target
        || bundle.version != trust_version
        || bundle.component_len == 0
        || (observation_components.is_some()
            && (runtime_receipt.is_none()
                || cpu_provider_receipt.is_none()
                || disk_health_provider_receipt.is_none()
                || lifecycle_companion_receipt.is_none()))
    {
        return Err(InstallError::InvalidVerifiedComponent);
    }
    validate_component(component, bundle.component_len)?;
    if let Some((runtime, cpu_provider, disk_health_provider, lifecycle_companion)) =
        observation_components
    {
        validate_component(runtime, runtime_receipt.expect("checked").1)?;
        validate_component(cpu_provider, cpu_provider_receipt.expect("checked").1)?;
        validate_component(
            disk_health_provider,
            disk_health_provider_receipt.expect("checked").1,
        )?;
        validate_component(
            lifecycle_companion,
            lifecycle_companion_receipt.expect("checked").1,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn activate_verified_fresh_install(
    component: &mut File,
    observation_components: Option<(&mut File, &mut File, &mut File, &mut File)>,
    bootstrap_components: Option<(&mut File, &mut File)>,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    paths: &FixedInstallPaths,
    ports: &mut InstallPorts<'_, impl AccountPort, impl SystemdPort, impl InstallFilePort>,
    failure_semantics: InstallFailureSemantics<'_>,
) -> Result<(), InstallError> {
    let install_observation = observation_components.is_some();
    let _activation_lock = ActivationLock::acquire(
        &paths.bootstrap_state(),
        paths.expected_root_uid(),
        Instant::now() + INSTALL_COMMAND_BUDGET,
    )?;
    let resumed_journal = match recover_interrupted_install(paths, ports, failure_semantics)? {
        InterruptedInstall::Fresh => None,
        InterruptedInstall::ResumeCommitted(journal) => Some(*journal),
        InterruptedInstall::Complete => return Ok(()),
    };
    let is_committed_resume = resumed_journal.is_some();
    if !is_committed_resume {
        preflight_parent_chains(paths)?;
        preflight_files(paths)?;
        preflight_fixed_metadata_directory(&paths.etc_enoki())?;
        if bootstrap_components.is_some() {
            require_bootstrap_roles_absent(paths)?;
        } else {
            validate_bootstrap_roles(paths)?;
        }
    }
    let install_deadline = Instant::now() + INSTALL_COMMAND_BUDGET;
    ports.accounts.set_command_deadline(install_deadline);
    ports.systemd.set_command_deadline(install_deadline);
    if !is_committed_resume {
        ports.accounts.require_absent()?;
        ports.systemd.require_absent()?;
    }

    let mut journal = match resumed_journal {
        Some(journal) => journal,
        None => TransactionJournal::begin_with_binding(
            &paths.bootstrap_state(),
            failure_semantics
                .committed_replacement_binding()
                .map(ReplacementResumeBinding::as_str),
        )?,
    };
    if let Some((acquirer, activator)) = bootstrap_components {
        let role_sources = [acquirer, activator];
        for (source, role) in role_sources.into_iter().zip(bootstrap_role_registry(paths)) {
            if journal.owns_published_path(&role.path)? {
                continue;
            }
            if let Err(error) =
                ports
                    .files
                    .install_binary(source, &role.path, &mut journal, role.rollback)
            {
                return Err(handle_prepared_install_failure(
                    error,
                    &journal,
                    ports.accounts,
                    ports.files,
                    failure_semantics,
                ));
            }
        }
    }
    let identity = if let Some((uid, gid)) = journal.identity() {
        ServiceIdentity { uid, gid }
    } else if is_committed_resume
        && ports
            .accounts
            .owns_transaction_identity(journal.transaction_id(), None)?
    {
        let identity = ServiceIdentity { uid: 0, gid: 0 };
        journal.record_identity(identity.uid, identity.gid)?;
        identity
    } else {
        let identity = match ports
            .accounts
            .create_transaction_identity(journal.transaction_id())
        {
            Ok(identity) => identity,
            Err(error) => {
                return Err(handle_prepared_install_failure(
                    error,
                    &journal,
                    ports.accounts,
                    ports.files,
                    failure_semantics,
                ));
            }
        };
        if let Err(error) = journal.record_identity(identity.uid, identity.gid) {
            return Err(handle_prepared_install_failure(
                error,
                &journal,
                ports.accounts,
                ports.files,
                failure_semantics,
            ));
        }
        identity
    };
    if install_observation {
        if !journal.observation_ipc_group_may_exist()
            && let Err(error) = journal.record_observation_ipc_group_intent()
        {
            return Err(handle_prepared_install_failure(
                error,
                &journal,
                ports.accounts,
                ports.files,
                failure_semantics,
            ));
        }
        let already_owned = is_committed_resume
            && ports
                .accounts
                .owns_observation_ipc_group(journal.transaction_id())?;
        if !already_owned
            && let Err(error) = ports
                .accounts
                .create_observation_ipc_group(journal.transaction_id())
        {
            return Err(handle_prepared_install_failure(
                error,
                &journal,
                ports.accounts,
                ports.files,
                failure_semantics,
            ));
        }
    }
    if is_committed_resume {
        for staged_name in [
            "enoki-probe",
            "probe-bootstrap.toml",
            "probe-install.toml",
            "enoki-probe.service",
        ] {
            match fs::remove_file(journal.staging_directory().join(staged_name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(InstallError::Io),
            }
        }
    }
    let staged = match stage_complete_layout(
        component,
        enrollment,
        bundle,
        trust,
        journal.staging_directory(),
        install_observation,
        journal.transaction_id(),
        failure_semantics.registration_binding(),
    ) {
        Ok(staged) => staged,
        Err(error) => {
            return Err(handle_prepared_install_failure(
                error,
                &journal,
                ports.accounts,
                ports.files,
                failure_semantics,
            ));
        }
    };
    let mut enabled = false;
    let mut started = false;
    let result = (|| {
        if !journal.owns_published_path(&paths.etc_enoki())? {
            ports
                .files
                .ensure_metadata_directory(&paths.etc_enoki(), &mut journal)?;
        }
        if !journal.owns_published_path(&paths.state())? {
            ports.files.create_directory(
                &paths.state(),
                0o750,
                identity,
                &mut journal,
                RollbackStep::RemoveStateDirectory,
            )?;
        }
        if !journal.owns_published_path(&paths.identity_dir())? {
            ports.files.create_directory(
                &paths.identity_dir(),
                0o700,
                identity,
                &mut journal,
                RollbackStep::RemoveIdentityDirectory,
            )?;
        }
        let mut staged_binary = File::open(&staged.binary).map_err(|_| InstallError::Io)?;
        if !journal.owns_published_path(&paths.binary())? {
            ports.files.install_binary(
                &mut staged_binary,
                &paths.binary(),
                &mut journal,
                RollbackStep::RemoveBinary,
            )?;
        }
        if let Some((runtime, cpu_provider, disk_health_provider, lifecycle_companion)) =
            observation_components
        {
            for (source, destination) in [
                (runtime, paths.observation_runtime_binary()),
                (disk_health_provider, paths.disk_health_provider_binary()),
                (cpu_provider, paths.cpu_provider_binary()),
                (lifecycle_companion, paths.lifecycle_companion_binary()),
            ] {
                if !journal.owns_published_path(&destination)? {
                    ports.files.install_binary(
                        source,
                        &destination,
                        &mut journal,
                        RollbackStep::RemoveBinary,
                    )?;
                }
            }
        }
        let registered_identity_is_owned =
            failure_semantics
                .registration_binding()
                .is_some_and(|binding| {
                    journal.published_path_is_recorded(&paths.identity())
                        && replacement_registration::registered_identity_matches(paths, binding)
                });
        if !registered_identity_is_owned && !journal.owns_published_path(&paths.identity())? {
            ports.files.write_owned(
                &paths.identity(),
                &fs::read(&staged.identity).map_err(|_| InstallError::Io)?,
                0o600,
                identity,
                &mut journal,
                RollbackStep::RemoveIdentity,
            )?;
        }
        if !journal.owns_published_path(&paths.metadata())? {
            ports.files.write_owned(
                &paths.metadata(),
                &fs::read(&staged.metadata).map_err(|_| InstallError::Io)?,
                0o600,
                ServiceIdentity { uid: 0, gid: 0 },
                &mut journal,
                RollbackStep::RemoveInstallMetadata,
            )?;
        }
        if !journal.owns_published_path(&paths.unit())? {
            ports.files.write_owned(
                &paths.unit(),
                &fs::read(&staged.unit).map_err(|_| InstallError::Io)?,
                0o644,
                ServiceIdentity { uid: 0, gid: 0 },
                &mut journal,
                RollbackStep::RemoveUnit,
            )?;
        }
        for (path, contents) in install_observation
            .then_some([
                (paths.observation_runtime_unit(), observation_runtime_unit()),
                (
                    paths.observation_runtime_socket_unit(),
                    observation_runtime_socket_unit().to_owned(),
                ),
                (
                    paths.observation_runtime_failure_recorder_unit(),
                    observation_runtime_failure_recorder_unit(),
                ),
                (paths.cpu_provider_unit(), cpu_provider_unit()),
                (
                    paths.cpu_provider_socket_unit(),
                    cpu_provider_socket_unit().to_owned(),
                ),
                (
                    paths.disk_health_provider_unit(),
                    disk_health_provider_unit(),
                ),
                (
                    paths.disk_health_provider_socket_unit(),
                    disk_health_provider_socket_unit().to_owned(),
                ),
                (paths.lifecycle_companion_unit(), lifecycle_companion_unit()),
                (
                    paths.lifecycle_companion_socket_unit(),
                    lifecycle_companion_socket_unit().to_owned(),
                ),
                (paths.lifecycle_upgrade_unit(), lifecycle_upgrade_unit()),
                (
                    paths.lifecycle_upgrade_socket_unit(),
                    lifecycle_upgrade_socket_unit().to_owned(),
                ),
            ])
            .into_iter()
            .flatten()
        {
            if !journal.owns_published_path(&path)? {
                ports.files.write_owned(
                    &path,
                    contents.as_bytes(),
                    0o644,
                    ServiceIdentity { uid: 0, gid: 0 },
                    &mut journal,
                    RollbackStep::RemoveUnit,
                )?;
            }
        }
        if failure_semantics.registration_binding().is_some() {
            replacement_registration::publish_drop_in(paths)?;
        }
        ports.systemd.daemon_reload()?;
        if !journal.enabled_may_exist() {
            journal.record_enabled_intent()?;
        }
        enabled = true;
        ports.systemd.enable()?;
        if !journal.started_may_exist() {
            journal.record_started_intent()?;
        }
        started = true;
        ports.systemd.start()?;
        ports.systemd.wait_local_activated()?;
        if failure_semantics.registration_binding().is_some() {
            replacement_registration::retire_drop_in(paths)?;
            ports.systemd.daemon_reload()?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            journal.commit_layout(
                paths,
                &bundle.version,
                failure_semantics.is_committed_replacement(),
            )?;
            Ok(())
        }
        Err(install_error) => {
            if failure_semantics.is_committed_replacement() {
                // journal 与所有由 receipt 持有的候选路径继续作为恢复事实源；后续精确
                // 候选调用只向前修复或重新暂存，绝不恢复 P0。
                return Err(install_error);
            }
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
            // No metadata is retained after failure, so every journal-owned
            // path below, including fresh Bootstrap roles, is compensated.
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
    files: &mut impl InstallFilePort,
) -> InstallError {
    accounts.set_command_deadline(Instant::now() + ROLLBACK_COMMAND_BUDGET);
    let mut failures = Vec::new();
    cleanup_owned_paths(files, journal, &mut failures);
    record_rollback(
        &mut failures,
        RollbackStep::RemoveObservationIpcGroup,
        accounts.remove_observation_ipc_group(journal.transaction_id()),
    );
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

fn handle_prepared_install_failure(
    cause: InstallError,
    journal: &TransactionJournal,
    accounts: &mut impl AccountPort,
    files: &mut impl InstallFilePort,
    failure_semantics: InstallFailureSemantics<'_>,
) -> InstallError {
    if failure_semantics.is_committed_replacement() {
        cause
    } else {
        abort_prepared_install(cause, journal, accounts, files)
    }
}

fn cleanup_owned_paths(
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
}

fn cleanup_failed_install(
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
    files: &mut impl InstallFilePort,
    journal: &TransactionJournal,
    failures: &mut Vec<RollbackFailure>,
) {
    cleanup_owned_paths(files, journal, failures);
    // Systemd must forget the removed unit before another fresh install is
    // allowed to consult its absence state.
    record_rollback(
        failures,
        RollbackStep::ReloadSystemd,
        systemd.daemon_reload(),
    );
    record_rollback(
        failures,
        RollbackStep::RemoveObservationIpcGroup,
        accounts.remove_observation_ipc_group(journal.transaction_id()),
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
    failure_semantics: InstallFailureSemantics<'_>,
) -> Result<InterruptedInstall, InstallError> {
    let Some(journal) = TransactionJournal::load(&paths.bootstrap_state())? else {
        return Ok(InterruptedInstall::Fresh);
    };
    if journal.has_resume_binding() && failure_semantics.committed_replacement_binding().is_none() {
        return Err(InstallError::ExistingResidue);
    }
    if let Some(binding) = failure_semantics.committed_replacement_binding()
        && !journal.matches_resume_binding(binding.as_str())
    {
        return Err(InstallError::ExistingResidue);
    }
    if TransactionJournal::layout_is_committed(&paths.bootstrap_state())? {
        journal.remove_staging_if_owned()?;
        return if failure_semantics.is_committed_replacement() {
            Ok(InterruptedInstall::Complete)
        } else {
            journal.remove()?;
            Err(InstallError::ExistingResidue)
        };
    }
    if failure_semantics.is_committed_replacement() {
        let published_paths_are_owned = match failure_semantics.registration_binding() {
            Some(binding) => {
                journal.all_published_paths_except_are_owned(&paths.identity())
                    && (journal.published_path_is_owned(&paths.identity())
                        || replacement_registration::registered_identity_matches(paths, binding))
            }
            None => journal.all_published_paths_are_owned(),
        };
        if !published_paths_are_owned {
            return Err(InstallError::ExistingResidue);
        }
        if let Some((uid, gid)) = journal.identity()
            && !ports.accounts.owns_transaction_identity(
                journal.transaction_id(),
                Some(ServiceIdentity { uid, gid }),
            )?
        {
            return Err(InstallError::ExistingResidue);
        }
        return Ok(InterruptedInstall::ResumeCommitted(Box::new(journal)));
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
    record_rollback(
        &mut failures,
        RollbackStep::RemoveObservationIpcGroup,
        ports
            .accounts
            .remove_observation_ipc_group(journal.transaction_id()),
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
        journal.remove().map(|()| InterruptedInstall::Fresh)
    } else {
        Err(InstallError::Rollback {
            cause: InstallErrorKind::Io,
            failures,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_complete_layout(
    component: &mut File,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    staging: &Path,
    install_observation: bool,
    transaction_id: &str,
    registration_binding: Option<&ReplacementRegistrationBinding>,
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
    let metadata_contents = install_metadata(
        enrollment,
        bundle,
        trust,
        install_observation,
        transaction_id,
    )?;
    for (path, contents) in [
        (
            &identity,
            bootstrap_config(enrollment, bundle, trust, registration_binding),
        ),
        (&metadata, metadata_contents),
        (&unit, service_unit()),
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

fn bootstrap_config(
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    registration_binding: Option<&ReplacementRegistrationBinding>,
) -> String {
    let mut config = format!(
        "hub_url = {:?}\nenrollment_token = {:?}\nstate_dir = {:?}\noperation_status_path = {:?}\ninstall_path = {:?}\nservice_name = {:?}\nservice_user = {:?}\nprobe_distribution_root_sha256 = {:?}\ninstall_state_sha256 = {:?}\ntarget_manifest_sha256 = {:?}\nbundle_version = {:?}\nlog_level = \"info\"\n",
        enrollment.hub_origin(),
        enrollment.enrollment_token(),
        STATE,
        "/var/lib/enoki-probe/probe-operation-status.toml",
        BINARY,
        SERVICE_NAME,
        SERVICE_USER,
        trust.root_fingerprint,
        bundle.install_state_sha256(),
        bundle.manifest_sha256,
        bundle.version,
    );
    if let Some(binding) = registration_binding {
        replacement_registration::append_bootstrap_config(&mut config, binding);
    }
    config
}

fn install_metadata(
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    install_observation: bool,
    transaction_id: &str,
) -> Result<String, InstallError> {
    if !install_observation {
        return Ok(format!(
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
        ));
    }
    let lifecycle_authority_install_key = derive_lifecycle_authority_install_key(
        enrollment.enrollment_token(),
        enrollment.hub_origin(),
    );
    Ok(format!(
        "schema_version = 5\nhub_url = {:?}\nidentity_path = {:?}\ninstall_path = {:?}\nobservation_runtime_path = {:?}\ncpu_provider_path = {:?}\ndisk_health_provider_path = {:?}\nlifecycle_companion_path = {:?}\nprobe_ipc_group = {:?}\nprobe_ipc_group_ownership = {:?}\nobservation_ipc_group = {:?}\noperation_status_path = {:?}\nstate_dir = {:?}\nprobe_distribution_root_sha256 = {:?}\nlifecycle_authority_install_key = {:?}\ninstall_state_sha256 = {:?}\ntarget_manifest_sha256 = {:?}\nbundle_version = {:?}\nbootstrap_state_dir = {:?}\nbootstrap_acquirer_path = {:?}\nbootstrap_activator_path = {:?}\nservice_name = {:?}\nservice_user = {:?}\nservice_group = {:?}\nservice_unit_path = {:?}\nobservation_runtime_service_unit_path = {:?}\nobservation_runtime_socket_unit_path = {:?}\nobservation_runtime_failure_recorder_unit_path = {:?}\ncpu_provider_service_unit_path = {:?}\ncpu_provider_socket_unit_path = {:?}\ndisk_health_provider_service_unit_path = {:?}\ndisk_health_provider_socket_unit_path = {:?}\nlifecycle_companion_service_unit_path = {:?}\nlifecycle_companion_socket_unit_path = {:?}\nlifecycle_upgrade_service_unit_path = {:?}\nlifecycle_upgrade_socket_unit_path = {:?}\ncollector_helper_sudoers_path = {:?}\n",
        enrollment.hub_origin(),
        IDENTITY,
        BINARY,
        OBSERVATION_RUNTIME_BINARY,
        CPU_PROVIDER_BINARY,
        DISK_HEALTH_PROVIDER_BINARY,
        LIFECYCLE_COMPANION_BINARY,
        PROBE_IPC_GROUP,
        account::group_account_marker(transaction_id),
        OBSERVATION_IPC_GROUP,
        "/var/lib/enoki-probe/probe-operation-status.toml",
        STATE,
        trust.root_fingerprint,
        lifecycle_authority_install_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        bundle.install_state_sha256(),
        bundle.manifest_sha256,
        bundle.version,
        BOOTSTRAP_STATE,
        BOOTSTRAP_ACQUIRER,
        BOOTSTRAP_ACTIVATOR,
        SERVICE_NAME,
        SERVICE_USER,
        SERVICE_GROUP,
        UNIT,
        OBSERVATION_RUNTIME_UNIT,
        OBSERVATION_RUNTIME_SOCKET_UNIT,
        OBSERVATION_RUNTIME_FAILURE_RECORDER_UNIT,
        CPU_PROVIDER_UNIT,
        CPU_PROVIDER_SOCKET_UNIT,
        DISK_HEALTH_PROVIDER_UNIT,
        DISK_HEALTH_PROVIDER_SOCKET_UNIT,
        LIFECYCLE_COMPANION_UNIT,
        LIFECYCLE_COMPANION_SOCKET_UNIT,
        LIFECYCLE_UPGRADE_UNIT,
        LIFECYCLE_UPGRADE_SOCKET_UNIT,
        COLLECTOR_SUDOERS,
    ))
}

// 所有执行角色先继承同一拒绝优先下限，再声明各自确需的资源面。
const DENY_FIRST_EXECUTION_POLICY: &str = "NoNewPrivileges=true\nAmbientCapabilities=\nPrivateTmp=true\nProtectSystem=strict\nProtectControlGroups=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectKernelLogs=true\nProtectClock=true\nRestrictSUIDSGID=true\nRestrictRealtime=true\nRestrictNamespaces=true\nLockPersonality=true\nMemoryDenyWriteExecute=true\nKeyringMode=private\nSystemCallArchitectures=native\nSystemCallFilter=@system-service\nTasksMax=64\nUMask=0077\n";

fn service_unit() -> String {
    format!(
        "[Unit]\nDescription=Enoki Probe\nAfter=network-online.target enoki-observation-runtime.socket\nAfter=enoki-probe-lifecycle-companion.socket enoki-probe-lifecycle-upgrade.socket\nWants=network-online.target enoki-observation-runtime.socket\nWants=enoki-probe-lifecycle-companion.socket enoki-probe-lifecycle-upgrade.socket\n\n[Service]\nType=notify\nNotifyAccess=main\nUser=enoki-probe\nGroup=enoki-probe\nDynamicUser=true\nSupplementaryGroups=enoki-probe-ipc\nStateDirectory=enoki-probe\nStateDirectoryMode=0750\nExecStart=/usr/local/bin/enoki-probe run --config /var/lib/enoki-probe/identity/probe-bootstrap.toml\nRestart=on-failure\nRestartPreventExitStatus=78\nRestartSec=5s\n{DENY_FIRST_EXECUTION_POLICY}CapabilityBoundingSet=\nPrivateDevices=true\nProtectHome=true\nProtectHostname=true\nProtectProc=invisible\nProcSubset=pid\nMemoryMax=256M\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nSocketBindDeny=ipv4:any\nSocketBindDeny=ipv6:any\nInaccessiblePaths=-/proc/stat -/proc/loadavg -/proc/meminfo -/proc/uptime -/proc/cpuinfo -/proc/mounts -/proc/net/dev -/proc/net/route -/proc/net/ipv6_route -/proc/diskstats -/proc/sys/kernel/hostname -/proc/sys/kernel/osrelease /sys/devices/system/cpu /sys/class/hwmon /sys/class/power_supply /sys/class/block /etc/os-release /usr/lib/os-release -/run/systemd/private -/run/systemd/system -/run/dbus/system_bus_socket -/run/enoki-cpu-resource-provider.sock -/run/enoki-disk-health-resource-provider.sock\nReadWritePaths=/var/lib/enoki-probe /var/lib/enoki-probe/identity\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

fn lifecycle_companion_socket_unit() -> &'static str {
    "[Unit]\nDescription=Enoki Probe Lifecycle Companion Socket\n\n[Socket]\nListenStream=/run/enoki-probe-lifecycle-companion.sock\nSocketMode=0660\nSocketUser=root\nSocketGroup=enoki-probe-ipc\nAccept=yes\nMaxConnections=1\nMaxConnectionsPerSource=1\nExecStopPost=/usr/bin/rm -rf -- /run/systemd/system/enoki-observation-runtime.service.d\n\n[Install]\nWantedBy=sockets.target\n"
}

fn lifecycle_companion_unit() -> String {
    format!(
        "[Unit]\nDescription=Enoki Probe Lifecycle Companion\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nUser=root\nGroup=root\nStandardInput=socket\nStandardOutput=socket\nStandardError=journal\nExecStart=/usr/local/bin/enoki-probe-lifecycle-companion\nTimeoutStartSec=90s\nRuntimeDirectory=enoki-probe systemd/system/enoki-observation-runtime.service.d\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n{DENY_FIRST_EXECUTION_POLICY}CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID\nPrivateDevices=true\nProtectHome=true\nProtectHostname=true\nProtectProc=invisible\nProcSubset=pid\nReadOnlyPaths=/run/systemd/system\nBindPaths=/run/systemd/system/enoki-observation-runtime.service.d:/run/systemd/system/enoki-observation-runtime.service.d\nBindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/enoki-probe/runtime-failure-boot-id\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nSocketBindDeny=ipv4:any\nSocketBindDeny=ipv6:any\nMemoryMax=256M\nReadWritePaths=/etc/enoki /etc/systemd/system /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers.d /usr/local/bin /var/lib/enoki-probe /var/lib/enoki-probe-bootstrap /var/lib/enoki-probe-registration /run/enoki-probe\n"
    )
}

fn lifecycle_upgrade_socket_unit() -> &'static str {
    "[Unit]\nDescription=Enoki Probe Upgrade Companion Socket\n\n[Socket]\nListenStream=/run/enoki-probe-lifecycle-upgrade.sock\nSocketMode=0660\nSocketUser=root\nSocketGroup=enoki-probe-ipc\nAccept=yes\nMaxConnections=1\nMaxConnectionsPerSource=1\n\n[Install]\nWantedBy=sockets.target\n"
}

fn lifecycle_upgrade_unit() -> String {
    format!(
        "[Unit]\nDescription=Enoki Probe Upgrade Companion\n\n[Service]\nType=oneshot\nUser=root\nGroup=root\nStandardInput=socket\nStandardOutput=socket\nStandardError=journal\nExecStart=/usr/local/bin/enoki-probe-lifecycle-companion --upgrade\nTimeoutStartSec=90s\nRuntimeDirectory=enoki-probe\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n{DENY_FIRST_EXECUTION_POLICY}CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER\nPrivateDevices=true\nPrivateNetwork=true\nProtectHome=true\nProtectHostname=true\nProtectProc=invisible\nProcSubset=pid\nBindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/enoki-probe/runtime-failure-boot-id\nRestrictAddressFamilies=AF_UNIX\nIPAddressDeny=any\nSocketBindDeny=any\nMemoryMax=256M\nReadWritePaths=/etc/enoki /etc/systemd/system /usr/local/bin /var/lib/enoki-probe /var/lib/enoki-probe-bootstrap /run/enoki-probe\n"
    )
}

fn observation_runtime_socket_unit() -> &'static str {
    "[Unit]\nDescription=Enoki Observation Runtime socket\n\n[Socket]\nListenStream=/run/enoki-observation-runtime.sock\nSocketMode=0660\nSocketUser=root\nSocketGroup=enoki-probe-ipc\nRemoveOnStop=true\n\n[Install]\nWantedBy=sockets.target\n"
}

fn observation_runtime_unit() -> String {
    format!(
        "[Unit]\nDescription=Enoki Observation Runtime\nRequires=enoki-cpu-resource-provider.socket enoki-disk-health-resource-provider.socket\nAfter=enoki-cpu-resource-provider.socket enoki-disk-health-resource-provider.socket\nOnFailure=enoki-observation-runtime-failure.service\nConditionPathExists=!/var/lib/enoki-probe/runtime-failure/latch\nStartLimitIntervalSec=60s\nStartLimitBurst=3\n\n[Service]\nType=notify\nNotifyAccess=main\nUser=enoki-observation-runtime\nGroup=enoki-observation-runtime\nDynamicUser=true\nSupplementaryGroups=enoki-observation-ipc\nExecStart=/usr/local/bin/enoki-observation-runtime\nRestart=on-failure\nRestartSec=5s\nWatchdogSec=30s\nKillMode=control-group\n{DENY_FIRST_EXECUTION_POLICY}CapabilityBoundingSet=\nPrivateDevices=true\nPrivateNetwork=true\nProtectHome=true\nProtectHostname=true\nProtectProc=invisible\nProcSubset=pid\nMemoryMax=256M\nRestrictAddressFamilies=AF_UNIX\nIPAddressDeny=any\nSocketBindDeny=any\nInaccessiblePaths=-/proc/stat -/proc/loadavg -/proc/meminfo -/proc/uptime -/proc/cpuinfo -/proc/mounts -/proc/net/dev -/proc/net/route -/proc/net/ipv6_route -/proc/diskstats -/proc/sys/kernel/hostname -/proc/sys/kernel/osrelease /sys/devices/system/cpu /sys/class/hwmon /sys/class/power_supply /sys/class/block /etc/os-release /usr/lib/os-release /var/lib/enoki-probe/identity -/run/systemd/private -/run/systemd/system -/run/dbus/system_bus_socket\n"
    )
}

fn observation_runtime_failure_recorder_unit() -> String {
    format!(
        "[Unit]\nDescription=Enoki Observation Runtime failure recorder\nRefuseManualStart=yes\n\n[Service]\nType=oneshot\nUser=root\nGroup=root\nExecStart=/usr/local/bin/enoki-probe-lifecycle-companion record-runtime-failure\nTimeoutStartSec=15s\nStateDirectory=enoki-probe/runtime-failure\nStateDirectoryMode=0700\nRuntimeDirectory=enoki-probe\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n{DENY_FIRST_EXECUTION_POLICY}CapabilityBoundingSet=CAP_DAC_READ_SEARCH\nPrivateDevices=true\nPrivateNetwork=true\nProtectHome=true\nProtectHostname=true\nProtectProc=invisible\nProcSubset=pid\nMemoryMax=64M\nRestrictAddressFamilies=AF_UNIX\nIPAddressDeny=any\nSocketBindDeny=any\nReadOnlyPaths=/etc/enoki/probe-install.toml /var/lib/enoki-probe/identity/probe-bootstrap.toml /etc/systemd/system/enoki-observation-runtime.service /etc/systemd/system/enoki-observation-runtime-failure.service\nBindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/enoki-probe/runtime-failure-boot-id\nReadWritePaths=/var/lib/enoki-probe/runtime-failure /run/enoki-probe\n"
    )
}

fn cpu_provider_socket_unit() -> &'static str {
    "[Unit]\nDescription=Enoki CPU Resource Provider socket\n\n[Socket]\nListenStream=/run/enoki-cpu-resource-provider.sock\nAccept=true\nService=enoki-cpu-resource-provider@.service\nSocketMode=0660\nSocketUser=root\nSocketGroup=enoki-observation-ipc\nBacklog=1\nMaxConnections=1\nMaxConnectionsPerSource=1\nTriggerLimitIntervalSec=10s\nTriggerLimitBurst=12\nRemoveOnStop=true\n\n[Install]\nWantedBy=sockets.target\n"
}

fn cpu_provider_unit() -> String {
    format!(
        "[Unit]\nDescription=Enoki one-shot System State Resource Provider\nCollectMode=inactive-or-failed\n\n[Service]\nType=exec\nExecStart=/usr/local/bin/enoki-cpu-resource-provider\nStandardInput=socket\nStandardOutput=socket\nUser=root\nGroup=root\nRuntimeMaxSec=3s\nTimeoutStartSec=3s\nTimeoutStopSec=1s\nKillMode=control-group\nSendSIGKILL=yes\nOOMPolicy=kill\n{DENY_FIRST_EXECUTION_POLICY}SystemCallFilter=landlock_create_ruleset landlock_add_rule landlock_restrict_self\nCapabilityBoundingSet=\nPrivateDevices=true\nProtectHome=read-only\nProtectProc=ptraceable\nMemoryMax=256M\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\nIPAddressDeny=any\nSocketBindDeny=ipv4:any\nSocketBindDeny=ipv6:any\nBindReadOnlyPaths=/etc/os-release /usr/lib/os-release /sys/devices/system/cpu /sys/class/hwmon /sys/class/power_supply /sys/class/block\nReadOnlyPaths=/proc/net\nReadOnlyPaths=/proc/stat /proc/loadavg /proc/meminfo /proc/uptime /proc/cpuinfo /proc/mounts /proc/diskstats /proc/sys/kernel/hostname /proc/sys/kernel/osrelease\n"
    )
}

fn disk_health_provider_socket_unit() -> &'static str {
    "[Unit]\nDescription=Enoki Disk Health Resource Provider socket\n\n[Socket]\nListenStream=/run/enoki-disk-health-resource-provider.sock\nAccept=true\nService=enoki-disk-health-resource-provider@.service\nSocketMode=0660\nSocketUser=root\nSocketGroup=enoki-observation-ipc\nBacklog=1\nMaxConnections=1\nMaxConnectionsPerSource=1\nTriggerLimitIntervalSec=60s\nTriggerLimitBurst=2\nRemoveOnStop=true\n\n[Install]\nWantedBy=sockets.target\n"
}

fn disk_health_provider_unit() -> String {
    format!(
        "[Unit]\nDescription=Enoki one-shot Disk Health Resource Provider\nCollectMode=inactive-or-failed\n\n[Service]\nType=exec\nExecStart=/usr/local/bin/enoki-disk-health-resource-provider\nStandardInput=socket\nStandardOutput=socket\nUser=root\nGroup=root\nRuntimeMaxSec=10s\nTimeoutStartSec=10s\nTimeoutStopSec=1s\nKillMode=control-group\nSendSIGKILL=yes\nOOMPolicy=kill\n{DENY_FIRST_EXECUTION_POLICY}SystemCallFilter=landlock_create_ruleset landlock_add_rule landlock_restrict_self\nCapabilityBoundingSet=CAP_SYS_RAWIO\nDevicePolicy=closed\nDeviceAllow=block-* rw\nPrivateNetwork=true\nProtectHome=true\nProtectHostname=true\nProtectProc=invisible\nProcSubset=pid\nMemoryMax=128M\nRestrictAddressFamilies=AF_UNIX\nIPAddressDeny=any\nSocketBindDeny=any\nInaccessiblePaths=/boot /home /media /mnt /opt /root /srv\nBindReadOnlyPaths=-/usr/sbin/smartctl -/usr/bin/smartctl -/var/local/emhttp/disks.ini\n"
    )
}

/// 签名 permission profile 到 canonical execution unit 的构建期固定映射。
pub fn fixed_execution_role_units() -> [(&'static str, Vec<u8>); 5] {
    [
        (PROBE_PERMISSION_PROFILE, service_unit().into_bytes()),
        (
            OBSERVATION_RUNTIME_PERMISSION_PROFILE,
            observation_runtime_unit().into_bytes(),
        ),
        (
            SYSTEM_STATE_PERMISSION_PROFILE,
            cpu_provider_unit().into_bytes(),
        ),
        (
            DISK_HEALTH_PERMISSION_PROFILE,
            disk_health_provider_unit().into_bytes(),
        ),
        (
            LIFECYCLE_COMPANION_PERMISSION_PROFILE,
            lifecycle_companion_unit().into_bytes(),
        ),
    ]
}

/// Upgrader 与首次安装共享的固定 systemd integration assets。
pub fn fixed_observation_unit_contents() -> [Vec<u8>; 9] {
    [
        observation_runtime_unit().into_bytes(),
        observation_runtime_socket_unit().as_bytes().to_vec(),
        cpu_provider_unit().into_bytes(),
        cpu_provider_socket_unit().as_bytes().to_vec(),
        disk_health_provider_unit().into_bytes(),
        disk_health_provider_socket_unit().as_bytes().to_vec(),
        lifecycle_companion_unit().into_bytes(),
        lifecycle_companion_socket_unit().as_bytes().to_vec(),
        observation_runtime_failure_recorder_unit().into_bytes(),
    ]
}

/// 目标 Activator 的无输入固定协议；函数名保留 v1 是为了旧 CLI 调用点的窄兼容。
/// 返回内容以自描述 v2 magic 封闭新增的 Lifecycle Companion 资产。
pub fn render_observation_integration_v1() -> Vec<u8> {
    let mut output = b"enoki.observation-integration.v2\n".to_vec();
    for unit in fixed_observation_unit_contents() {
        output.extend_from_slice(unit.len().to_string().as_bytes());
        output.push(b'\n');
        output.extend_from_slice(&unit);
    }
    output
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
#[cfg(feature = "acquirer")]
pub use compatible_upgrade::run_compatible_upgrade;
use filesystem::*;
pub use systemd::SystemSystemd;
#[cfg(feature = "acquirer")]
pub(crate) use upgrade::{
    ConsumeBeforeOuterError, UpgradeAttempt, UpgradeAuthorityConsumption, UpgradeOperationFailure,
    abort_consumed_probe_upgrade_authority, consume_signed_before_upgrade_outer_checks,
    upgrade_current_probe_for_operation,
};
#[cfg(all(test, not(feature = "acquirer")))]
use upgrade::{
    ConsumeBeforeOuterError, UpgradeAttempt, UpgradeAuthorityConsumption, UpgradeOperationFailure,
    abort_consumed_probe_upgrade_authority, consume_signed_before_upgrade_outer_checks,
    upgrade_current_probe_for_operation,
};
pub use upgrade::{
    ConsumedRepairAuthority, InstalledBundleRepairBinding, InstalledUpgradeBinding,
    RepairIntentState, SignedRepairEligibility, SignedRepairEvidence, UpgradeRecoveryReceipt,
    VerifiedUpgradeComponents, cleanup_installed_bundle_repair, complete_authorized_probe_repair,
    consume_probe_repair_authority, execute_authorized_probe_repair,
    finalize_probe_upgrade_stage_cleanup, inspect_installed_probe_for_upgrade,
    issue_probe_repair_eligibility, issue_probe_repair_evidence, mark_probe_repair_unresolved,
    persist_probe_repair_execution_failure, recover_incomplete_probe_upgrade,
    restore_installed_bundle_for_repair, resume_probe_repair_intent,
    verify_installed_bundle_repair_complete,
};
#[cfg(test)]
use upgrade::{consume_before_upgrade_outer_checks, consume_probe_upgrade_authority};

include!("install/tests.rs");
