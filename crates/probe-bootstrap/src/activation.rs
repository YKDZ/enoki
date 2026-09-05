//! Root-only component receiver. It deliberately imports neither archive nor
//! network code: unprivileged acquisition owns gzip/tar/HTTP parsing.
use crate::{
    generation::{DelegationGenerationLease, GenerationStateError, acquire_delegation_generation},
    handoff::{Enrollment, Handoff, HandoffError},
    install::{
        CommittedReplacementLocalCustody, FixedInstallPaths, InstallError, SystemAccounts,
        SystemSystemd, VerifiedCompleteFreshComponents,
        activate_complete_replacement_current_probe_with_registration_and_admission,
        coordinate_fresh_install_with_admission, transaction::ActivationLock,
    },
    lifecycle::{LifecycleRequest, LifecycleResponse},
    replacement::{
        FileReplacementCommitStore, ReplacementCommitStore, record_replacement_candidate_layout,
    },
    trust::{BootstrapRole, embedded_production_trust_for},
    verifier::{
        VerificationPolicy, VerifiedBundle, verify_acquirer_receipt, verify_activator_receipt,
        verify_component, verify_metadata, verify_role_component,
    },
};
use sha2::{Digest, Sha256};
#[cfg(not(test))]
use std::sync::OnceLock;
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::process::CommandExt,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    process::{Command, ExitCode, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

const INBOX_DIRECTORY: &str = "inbox";
const INSTALL_METADATA: &str = "/etc/enoki/probe-install.toml";
const REPLACEMENT_COMMIT: &str = "/var/lib/enoki-probe-bootstrap/replacement-migration.json";
const REPLACEMENT_COMPANION_BUDGET: Duration = Duration::from_secs(90);
const REPLACEMENT_COMPANION_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STABLE_LIFECYCLE_LOCK_NAME: &[u8] = b"enoki-probe-lifecycle.lock\0";
const RUN_LOCK_DIRECTORY: &[u8] = b"/run/lock\0";
const ACTIVATION_LOCK_BUDGET: Duration = Duration::from_secs(90);
const ORPHAN_COMPANION: &str = "/usr/local/bin/enoki-probe-lifecycle-companion";
static COMPONENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Eq, PartialEq)]
pub enum ActivationError {
    BuildTrustUnavailable,
    Generation(GenerationStateError),
    Handoff(HandoffError),
    NotRoot,
    Verification,
    Io,
    Install(InstallError),
    Replacement,
}

/// 唯一 production Bootstrap activation process interface。binary 不保留
/// handoff、generation 或安装 transaction 的第二入口。
#[doc(hidden)]
pub fn run_bootstrap_activate_process() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--render-observation-integration-v1") {
        return match std::io::stdout()
            .lock()
            .write_all(&crate::install::render_observation_integration_v1())
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    let result = if std::env::args().nth(1).as_deref() == Some("--fd-handoff") {
        // SAFETY: acquisition 只跨 exec 转交固定 receipt/socket descriptors。
        let mut receipt = unsafe { File::from_raw_fd(libc::STDIN_FILENO) };
        let mut input = unsafe { std::os::unix::net::UnixStream::from_raw_fd(libc::STDOUT_FILENO) };
        activate_from_socket(&mut input, &mut receipt)
    } else {
        activate_from_stdin(&mut std::io::stdin().lock())
    };
    match result {
        Ok(verified) => match verified.activate_fixed_current_probe() {
            Ok(()) => ExitCode::SUCCESS,
            Err(ActivationError::Install(error)) => {
                eprintln!("Probe Bootstrap activation failed ({})", error.diagnostic());
                ExitCode::from(error.exit_code())
            }
            Err(_) => {
                eprintln!("Probe Bootstrap activation failed");
                ExitCode::from(1)
            }
        },
        Err(ActivationError::NotRoot) => {
            eprintln!("Probe Bootstrap activation must run as root");
            ExitCode::from(2)
        }
        Err(_) => {
            eprintln!("Probe Bootstrap activation failed");
            ExitCode::from(1)
        }
    }
}

/// Bootstrap 进程唯一的 lifecycle owner。legacy 在 stable 之前取得，两个
/// descriptor 都只由 kernel 在进程退出时释放，不能由 child 重新取得。
struct BootstrapLifecycleOwner {
    _legacy: Option<ActivationLock>,
    stable: StableLifecycleLock,
}

struct StableLifecycleLock {
    parent: File,
    file: File,
    #[cfg(test)]
    validate: bool,
}

impl StableLifecycleLock {
    fn try_clone(&self) -> Result<Self, io::Error> {
        Ok(Self {
            parent: self.parent.try_clone()?,
            file: self.file.try_clone()?,
            #[cfg(test)]
            validate: self.validate,
        })
    }

    fn validate(&self) -> Result<(), ActivationError> {
        #[cfg(test)]
        if !self.validate {
            return Ok(());
        }
        if !stable_lock_parent_is_current(&self.parent)?
            || !stable_lock_matches_parent_entry(&self.parent, &self.file)?
        {
            return Err(ActivationError::Io);
        }
        Ok(())
    }
}

impl std::ops::Deref for StableLifecycleLock {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

#[cfg(not(test))]
static PROCESS_LIFETIME_BOOTSTRAP_LEGACY: OnceLock<Option<ActivationLock>> = OnceLock::new();
#[cfg(not(test))]
static PROCESS_LIFETIME_BOOTSTRAP_STABLE: OnceLock<StableLifecycleLock> = OnceLock::new();

/// 只可由 Bootstrap process owner 的私有字段构造。installer 可消费此类型，
/// 但无法以任意 File、Option 或 flag 伪造它。
pub(crate) struct BootstrapInstallAdmission<'a> {
    source: BootstrapInstallAdmissionSource<'a>,
}

enum BootstrapInstallAdmissionSource<'a> {
    Owner {
        owner: &'a BootstrapLifecycleOwner,
        generation: Option<&'a DelegationGenerationLease>,
    },
    #[cfg(test)]
    Independent,
}

#[allow(dead_code)]
pub(crate) struct BootstrapInstallLease<'a> {
    _owner: Option<&'a BootstrapLifecycleOwner>,
    _independent: Option<ActivationLock>,
}

impl BootstrapLifecycleOwner {
    fn acquire() -> Result<Self, ActivationError> {
        let state = std::path::Path::new("/var/lib/enoki-probe-bootstrap");
        loop {
            match fs::symlink_metadata(state) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    let deadline = Instant::now() + ACTIVATION_LOCK_BUDGET;
                    let legacy = ActivationLock::acquire(state, 0, deadline)
                        .map_err(ActivationError::Install)?;
                    let stable = open_stable_lifecycle_lock(deadline)?;
                    return Ok(Self {
                        _legacy: Some(legacy),
                        stable,
                    });
                }
                Ok(_) => return Err(ActivationError::Io),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let stable =
                        open_stable_lifecycle_lock(Instant::now() + ACTIVATION_LOCK_BUDGET)?;
                    // 没有 legacy 时只可在 stable 内复验 absence。并发创建则
                    // 释放 stable，从唯一的 legacy -> stable 顺序重新开始。
                    match fs::symlink_metadata(state) {
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            return Ok(Self {
                                _legacy: None,
                                stable,
                            });
                        }
                        Ok(_) => drop(stable),
                        Err(_) => return Err(ActivationError::Io),
                    }
                }
                Err(_) => return Err(ActivationError::Io),
            }
        }
    }

    fn install_admission<'a>(
        &'a self,
        generation: Option<&'a DelegationGenerationLease>,
    ) -> BootstrapInstallAdmission<'a> {
        BootstrapInstallAdmission {
            source: BootstrapInstallAdmissionSource::Owner {
                owner: self,
                generation,
            },
        }
    }

    fn validate_stable(&self) -> Result<(), ActivationError> {
        self.stable.validate()
    }

    #[cfg(not(test))]
    fn retain_to_process_exit(&self) -> Result<(), ActivationError> {
        if PROCESS_LIFETIME_BOOTSTRAP_STABLE.get().is_some() {
            return Ok(());
        }
        let legacy = self
            ._legacy
            .as_ref()
            .map(ActivationLock::try_clone)
            .transpose()
            .map_err(ActivationError::Install)?;
        let stable = self.stable.try_clone().map_err(|_| ActivationError::Io)?;
        PROCESS_LIFETIME_BOOTSTRAP_LEGACY
            .set(legacy)
            .map_err(|_| ActivationError::Io)?;
        PROCESS_LIFETIME_BOOTSTRAP_STABLE
            .set(stable)
            .map_err(|_| ActivationError::Io)
    }

    #[cfg(test)]
    fn retain_to_process_exit(&self) -> Result<(), ActivationError> {
        Ok(())
    }
}

impl<'a> BootstrapInstallAdmission<'a> {
    #[cfg(test)]
    pub(crate) fn independent_for_test() -> Self {
        Self {
            source: BootstrapInstallAdmissionSource::Independent,
        }
    }

    #[allow(irrefutable_let_patterns)]
    pub(crate) fn enter(
        self,
        state: &std::path::Path,
        expected_uid: u32,
    ) -> Result<BootstrapInstallLease<'a>, InstallError> {
        let BootstrapInstallAdmissionSource::Owner { owner, generation } = self.source else {
            return ActivationLock::acquire(
                state,
                expected_uid,
                Instant::now() + ACTIVATION_LOCK_BUDGET,
            )
            .map(|lock| BootstrapInstallLease {
                _owner: None,
                _independent: Some(lock),
            });
        };
        if let Some(legacy) = owner._legacy.as_ref() {
            legacy.matches_canonical_state(state, expected_uid)?;
        } else {
            let Some(generation) = generation else {
                return Err(InstallError::ExistingResidue);
            };
            matches_generation_owned_state(state, expected_uid, generation)?;
            if owner.stable.metadata().map_err(|_| InstallError::Io)?.len() != 0 {
                return Err(InstallError::ExistingResidue);
            }
            ActivationLock::establish_state_without_legacy_lock(state, expected_uid)?;
        }
        Ok(BootstrapInstallLease {
            _owner: Some(owner),
            _independent: None,
        })
    }
}

fn matches_generation_owned_state(
    state: &std::path::Path,
    expected_uid: u32,
    generation: &DelegationGenerationLease,
) -> Result<(), InstallError> {
    let path = fs::symlink_metadata(state).map_err(|_| InstallError::ExistingResidue)?;
    let held = generation
        .state_directory()
        .metadata()
        .map_err(|_| InstallError::Io)?;
    if path.file_type().is_symlink()
        || !path.is_dir()
        || path.uid() != expected_uid
        || path.gid() != expected_uid
        || path.mode() & 0o7777 != 0o700
        || path.dev() != held.dev()
        || path.ino() != held.ino()
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

/// R1 只收敛前一次 terminal self-unlink 失败留下的 exact Companion。它在
/// source/state/handoff 读取前运行；任何额外 inventory 都拒绝，绝不读取 B。
fn reconcile_exact_orphan_companion() -> Result<(), ActivationError> {
    reconcile_exact_orphan_companion_at(
        std::path::Path::new(INSTALL_METADATA),
        std::path::Path::new(ORPHAN_COMPANION),
        &[
            "/var/lib/enoki-probe-bootstrap",
            "/var/lib/enoki-probe",
            "/etc/enoki",
            "/usr/local/bin/enoki-probe",
            "/usr/local/bin/enoki-observation-runtime",
            "/usr/local/bin/enoki-cpu-resource-provider",
            "/usr/local/bin/enoki-disk-health-resource-provider",
            "/usr/local/bin/enoki-probe-bootstrap-acquire",
            "/usr/local/bin/enoki-probe-bootstrap-activate",
            "/etc/systemd/system/enoki-probe.service",
            "/etc/systemd/system/enoki-observation-runtime.service",
            "/etc/systemd/system/enoki-observation-runtime.socket",
            "/etc/systemd/system/enoki-observation-runtime-failure.service",
            "/etc/systemd/system/enoki-cpu-resource-provider@.service",
            "/etc/systemd/system/enoki-cpu-resource-provider.socket",
            "/etc/systemd/system/enoki-disk-health-resource-provider@.service",
            "/etc/systemd/system/enoki-disk-health-resource-provider.socket",
            "/etc/systemd/system/enoki-probe-lifecycle-companion@.service",
            "/etc/systemd/system/enoki-probe-lifecycle-companion.socket",
            "/etc/systemd/system/enoki-probe-lifecycle-upgrade@.service",
            "/etc/systemd/system/enoki-probe-lifecycle-upgrade.socket",
            "/etc/sudoers.d/enoki-probe-operations",
            "/etc/sudoers.d/enoki-probe-collector-helpers",
            "/etc/sudoers.d/enoki-probe-upgrader",
        ],
    )
}

fn reconcile_exact_orphan_companion_at(
    install_metadata: &std::path::Path,
    companion: &std::path::Path,
    forbidden_inventory: &[&str],
) -> Result<(), ActivationError> {
    match fs::symlink_metadata(install_metadata) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(ActivationError::Io),
    }
    let metadata = match fs::symlink_metadata(companion) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ActivationError::Io),
    };
    for path in forbidden_inventory {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(ActivationError::Io),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(ActivationError::Io),
        }
    }
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o755
    {
        return Err(ActivationError::Io);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(companion)
        .map_err(|_| ActivationError::Io)?;
    let held = file.metadata().map_err(|_| ActivationError::Io)?;
    if held.dev() != metadata.dev() || held.ino() != metadata.ino() {
        return Err(ActivationError::Io);
    }
    let parent_path = companion.parent().ok_or(ActivationError::Io)?;
    let parent_fd = unsafe {
        libc::open(
            std::ffi::CString::new(parent_path.as_os_str().as_encoded_bytes())
                .map_err(|_| ActivationError::Io)?
                .as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if parent_fd < 0 {
        return Err(ActivationError::Io);
    }
    let parent = unsafe { File::from_raw_fd(parent_fd) };
    let name = std::ffi::CString::new(
        companion
            .file_name()
            .ok_or(ActivationError::Io)?
            .as_encoded_bytes(),
    )
    .map_err(|_| ActivationError::Io)?;
    let mut current: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut current,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || current.st_dev != held.dev()
        || current.st_ino != held.ino()
        || unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0
        || parent.sync_all().is_err()
    {
        return Err(ActivationError::Io);
    }
    let mut absent: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut absent,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
        || io::Error::last_os_error().kind() != io::ErrorKind::NotFound
    {
        return Err(ActivationError::Io);
    }
    for path in forbidden_inventory {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(ActivationError::Io),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(ActivationError::Io),
        }
    }
    Ok(())
}

fn open_stable_lifecycle_lock(deadline: Instant) -> Result<StableLifecycleLock, ActivationError> {
    let parent_fd = unsafe {
        libc::open(
            RUN_LOCK_DIRECTORY.as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if parent_fd < 0 {
        return Err(ActivationError::Io);
    }
    // SAFETY: a successful directory open transfers exactly one descriptor.
    let parent = unsafe { File::from_raw_fd(parent_fd) };
    if !stable_lock_parent_is_current(&parent)? {
        return Err(ActivationError::Io);
    }
    let create_flags =
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let file = match unsafe {
        libc::openat(
            parent.as_raw_fd(),
            STABLE_LIFECYCLE_LOCK_NAME.as_ptr().cast(),
            create_flags,
            0o600,
        )
    } {
        descriptor if descriptor >= 0 => {
            // SAFETY: a successful openat transfers exactly one descriptor.
            let file = unsafe { File::from_raw_fd(descriptor) };
            file.sync_all().map_err(|_| ActivationError::Io)?;
            parent.sync_all().map_err(|_| ActivationError::Io)?;
            file
        }
        _ if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists => {
            let descriptor = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    STABLE_LIFECYCLE_LOCK_NAME.as_ptr().cast(),
                    libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(ActivationError::Io);
            }
            // SAFETY: a successful openat transfers exactly one descriptor.
            unsafe { File::from_raw_fd(descriptor) }
        }
        _ => return Err(ActivationError::Io),
    };
    if !stable_lock_matches_parent_entry(&parent, &file)? {
        return Err(ActivationError::Io);
    }
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        if Instant::now() >= deadline {
            return Err(ActivationError::Io);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !stable_lock_parent_is_current(&parent)?
        || !stable_lock_matches_parent_entry(&parent, &file)?
    {
        return Err(ActivationError::Io);
    }
    Ok(StableLifecycleLock {
        parent,
        file,
        #[cfg(test)]
        validate: true,
    })
}

/// `openat` 固定住目录 fd；每次采用 stable entry 前仍确认绝对 parent
/// pathname 没有被替换为另一代目录。
fn stable_lock_parent_is_current(parent: &File) -> Result<bool, ActivationError> {
    let held = parent.metadata().map_err(|_| ActivationError::Io)?;
    let current = fs::symlink_metadata("/run/lock").map_err(|_| ActivationError::Io)?;
    Ok(held.is_dir()
        && held.uid() == 0
        && held.gid() == 0
        && !current.file_type().is_symlink()
        && current.is_dir()
        && current.uid() == 0
        && current.gid() == 0
        && held.dev() == current.dev()
        && held.ino() == current.ino())
}

fn stable_lock_matches_parent_entry(parent: &File, file: &File) -> Result<bool, ActivationError> {
    let metadata = file.metadata().map_err(|_| ActivationError::Io)?;
    let mut entry: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            STABLE_LIFECYCLE_LOCK_NAME.as_ptr().cast(),
            &mut entry,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(ActivationError::Io);
    }
    Ok(canonical_stable_lock(&metadata)
        && entry.st_mode & libc::S_IFMT == libc::S_IFREG
        && entry.st_uid == 0
        && entry.st_gid == 0
        && entry.st_nlink == 1
        && entry.st_size == 0
        && entry.st_mode & 0o7777 == 0o600
        && metadata.dev() == entry.st_dev
        && metadata.ino() == entry.st_ino)
}

fn canonical_stable_lock(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.nlink() == 1
        && metadata.len() == 0
        && metadata.mode() & 0o7777 == 0o600
}

impl From<HandoffError> for ActivationError {
    fn from(error: HandoffError) -> Self {
        Self::Handoff(error)
    }
}

impl From<GenerationStateError> for ActivationError {
    fn from(error: GenerationStateError) -> Self {
        Self::Generation(error)
    }
}

/// An unlinked root-private verified component and the exclusive delegation
/// generation lease that authorized it. The lease remains held until this
/// value is dropped after activation completes.
struct ReceivedRootHandoff {
    pub bundle: VerifiedBundle,
    component: File,
    runtime: File,
    cpu_provider: File,
    disk_health_provider: File,
    lifecycle_companion: File,
    acquirer: Option<File>,
    activator: Option<File>,
    enrollment: Enrollment,
    _generation_lease: DelegationGenerationLease,
    _lifecycle_owner: Option<BootstrapLifecycleOwner>,
}

impl ReceivedRootHandoff {
    /// The only consumption boundary for a verified candidate. It keeps the
    /// component descriptor, enrollment capability, and generation lease in
    /// one owner until the fixed local lifecycle adapter returns.
    #[cfg(test)]
    fn activate_with<T>(
        mut self,
        adapter: impl FnOnce(&mut File, &Enrollment, &VerifiedBundle) -> Result<T, ActivationError>,
    ) -> Result<T, ActivationError> {
        self.component()?;
        validate_received_role(&mut self.runtime, &self.bundle, "observation-runtime")?;
        validate_received_role(
            &mut self.cpu_provider,
            &self.bundle,
            "system-state-provider",
        )?;
        validate_received_role(
            &mut self.disk_health_provider,
            &self.bundle,
            "disk-health-provider",
        )?;
        validate_received_role(
            &mut self.lifecycle_companion,
            &self.bundle,
            "lifecycle-companion",
        )?;
        adapter(&mut self.component, &self.enrollment, &self.bundle)
    }

    /// Production's closed activation route. It owns the generation lease
    /// through the complete filesystem and systemd transaction; neither stdin
    /// nor a candidate component selects an installer command or path.
    fn activate_fixed_current_probe(mut self) -> Result<(), ActivationError> {
        let trust = embedded_production_trust_for(BootstrapRole::Activator)
            .ok_or(ActivationError::BuildTrustUnavailable)?;
        let mut accounts = SystemAccounts::default();
        let mut systemd = SystemSystemd::default();
        self.component()?;
        let acquirer = self
            .acquirer
            .as_mut()
            .ok_or(ActivationError::Verification)?;
        let activator = self
            .activator
            .as_mut()
            .ok_or(ActivationError::Verification)?;
        let owner = self._lifecycle_owner.as_ref().ok_or(ActivationError::Io)?;
        owner.validate_stable()?;
        let stable = owner.stable.try_clone().map_err(|_| ActivationError::Io)?;
        let mut replacement_activation = prepare_replacement_migration(
            &self.enrollment,
            &self.bundle,
            &mut self.lifecycle_companion,
            &stable,
        )?;
        if let ReplacementActivation::CompletePredecessor(commit) = &replacement_activation {
            let paths = FixedInstallPaths::production();
            let resume_binding = commit.resume_binding();
            let registration_binding = commit
                .registration_binding()
                .ok_or(ActivationError::Replacement)?;
            if !crate::install::completed_replacement_predecessor_matches_current_enrollment(
                &paths,
                &registration_binding,
                &self.enrollment,
                &self.bundle,
            ) {
                return Err(ActivationError::Replacement);
            }
            let mut store = FileReplacementCommitStore::at(REPLACEMENT_COMMIT, 0);
            crate::install::finalize_and_retire_complete_replacement_current_probe(
                &paths,
                &resume_binding,
                &self.bundle,
                commit,
                &mut store,
                &mut systemd,
            )
            .map_err(ActivationError::Install)?;
            replacement_activation = prepare_replacement_migration(
                &self.enrollment,
                &self.bundle,
                &mut self.lifecycle_companion,
                &stable,
            )?;
        }
        if let ReplacementActivation::Complete(commit) = &replacement_activation {
            let paths = FixedInstallPaths::production();
            let resume_binding = commit.resume_binding();
            let mut store = FileReplacementCommitStore::at(REPLACEMENT_COMMIT, 0);
            crate::install::finalize_and_retire_complete_replacement_current_probe(
                &paths,
                &resume_binding,
                &self.bundle,
                commit,
                &mut store,
                &mut systemd,
            )
            .map_err(ActivationError::Install)?;
            return Ok(());
        }
        let components = VerifiedCompleteFreshComponents {
            probe: &mut self.component,
            observation_runtime: &mut self.runtime,
            cpu_provider: &mut self.cpu_provider,
            disk_health_provider: &mut self.disk_health_provider,
            lifecycle_companion: &mut self.lifecycle_companion,
            bootstrap_acquirer: acquirer,
            bootstrap_activator: activator,
        };
        let paths = FixedInstallPaths::production();
        let result = if let ReplacementActivation::Resume(commit) = &replacement_activation {
            let resume_binding = commit.resume_binding();
            let registration_binding = commit
                .registration_binding()
                .ok_or(ActivationError::Replacement)?;
            activate_complete_replacement_current_probe_with_registration_and_admission(
                components,
                &self.enrollment,
                &self.bundle,
                &trust,
                &paths,
                &mut accounts,
                &mut systemd,
                &resume_binding,
                &registration_binding,
                owner.install_admission(Some(&self._generation_lease)),
            )
        } else {
            coordinate_fresh_install_with_admission(
                components,
                &self.enrollment,
                &self.bundle,
                &trust,
                owner.install_admission(Some(&self._generation_lease)),
            )
        };
        result.map_err(ActivationError::Install)?;
        if let ReplacementActivation::Resume(commit) = replacement_activation {
            let resume_binding = commit.resume_binding();
            let mut store = FileReplacementCommitStore::at(REPLACEMENT_COMMIT, 0);
            record_replacement_candidate_layout(&mut store, resume_binding.as_str())
                .map_err(|_| ActivationError::Replacement)?;
            let completed = store
                .load()
                .map_err(|_| ActivationError::Replacement)?
                .ok_or(ActivationError::Replacement)?;
            crate::install::finalize_and_retire_complete_replacement_current_probe(
                &paths,
                &resume_binding,
                &self.bundle,
                &completed,
                &mut store,
                &mut systemd,
            )
            .map_err(ActivationError::Install)?;
        }
        Ok(())
    }
    fn component(&mut self) -> Result<&mut File, ActivationError> {
        validate_regular_file(&self.component, 0, 0o600)?;
        let metadata = self.component.metadata().map_err(|_| ActivationError::Io)?;
        if metadata.len() != self.bundle.component_len {
            return Err(ActivationError::Io);
        }
        self.component
            .seek(SeekFrom::Start(0))
            .map_err(|_| ActivationError::Io)?;
        Ok(&mut self.component)
    }
}

fn prepare_replacement_migration(
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    companion: &mut File,
    stable: &StableLifecycleLock,
) -> Result<ReplacementActivation, ActivationError> {
    let has_installed_metadata = std::path::Path::new(INSTALL_METADATA)
        .try_exists()
        .map_err(|_| ActivationError::Io)?;
    let mut store = FileReplacementCommitStore::at(REPLACEMENT_COMMIT, 0);
    prepare_replacement_migration_in(
        enrollment,
        bundle,
        &mut store,
        has_installed_metadata,
        |fact| {
            crate::install::classify_committed_replacement_local_custody(
                &FixedInstallPaths::production(),
                &fact.resume_binding(),
            )
            .map_err(ActivationError::Install)
        },
        |request| {
            invoke_replacement_companion(request, companion, bundle, &stable.file)?;
            // child 只有在 canonical response frame、EOF 与成功退出全部成立后
            // 才会返回；parent 必须在采用 child 产生的 commit/custody 前复验
            // 同一 held stable generation。
            stable.validate()?;
            Ok(())
        },
    )
}

enum ReplacementActivation {
    Fresh,
    Resume(crate::replacement::ReplacementCommitFact),
    Complete(crate::replacement::ReplacementCommitFact),
    CompletePredecessor(crate::replacement::ReplacementCommitFact),
}

enum MatchingReplacementCommit {
    CleanupRequired(Box<crate::replacement::ReplacementCommitFact>),
    Ready(Box<crate::replacement::ReplacementCommitFact>),
    CompletePredecessor(Box<crate::replacement::ReplacementCommitFact>),
}

fn prepare_replacement_migration_in<S: crate::replacement::ReplacementCommitStore>(
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    store: &mut S,
    has_installed_metadata: bool,
    mut classify_local_custody: impl FnMut(
        &crate::replacement::ReplacementCommitFact,
    )
        -> Result<CommittedReplacementLocalCustody, ActivationError>,
    mut invoke: impl FnMut(&LifecycleRequest) -> Result<(), ActivationError>,
) -> Result<ReplacementActivation, ActivationError> {
    if let Some(commit) = matching_replacement_commit_in(store, enrollment, bundle)? {
        match commit {
            MatchingReplacementCommit::CleanupRequired(fact) => {
                if classify_local_custody(&fact)?
                    != CommittedReplacementLocalCustody::SourceMetadata
                {
                    return Err(ActivationError::Replacement);
                }
                let request = replacement_request_for_installed_state(true, enrollment, bundle)?
                    .ok_or(ActivationError::Replacement)?;
                invoke(&request)?;
            }
            MatchingReplacementCommit::Ready(fact) => {
                if !fact.candidate_layout_complete
                    && classify_local_custody(&fact)?
                        == CommittedReplacementLocalCustody::SourceMetadata
                {
                    let request =
                        replacement_request_for_installed_state(true, enrollment, bundle)?
                            .ok_or(ActivationError::Replacement)?;
                    invoke(&request)?;
                    return Ok(ReplacementActivation::Resume(*fact));
                }
                return Ok(if fact.candidate_layout_complete {
                    ReplacementActivation::Complete(*fact)
                } else {
                    ReplacementActivation::Resume(*fact)
                });
            }
            MatchingReplacementCommit::CompletePredecessor(fact) => {
                return Ok(ReplacementActivation::CompletePredecessor(*fact));
            }
        }
    } else {
        let Some(request) =
            replacement_request_for_installed_state(has_installed_metadata, enrollment, bundle)?
        else {
            return Ok(ReplacementActivation::Fresh);
        };
        invoke(&request)?;
    }
    let Some(MatchingReplacementCommit::Ready(fact)) =
        matching_replacement_commit_in(store, enrollment, bundle)?
    else {
        return Err(ActivationError::Replacement);
    };
    Ok(if fact.candidate_layout_complete {
        ReplacementActivation::Complete(*fact)
    } else {
        ReplacementActivation::Resume(*fact)
    })
}

fn matching_replacement_commit_in<S: crate::replacement::ReplacementCommitStore>(
    store: &mut S,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
) -> Result<Option<MatchingReplacementCommit>, ActivationError> {
    let Some(fact) = store.load().map_err(|_| ActivationError::Replacement)? else {
        return Ok(None);
    };
    let token_sha256 = format!(
        "{:x}",
        Sha256::digest(enrollment.enrollment_token().as_bytes())
    );
    let replacement = enrollment.replacement_migration();
    let exact_request = fact.has_valid_binding()
        && fact.intent.enrollment_token_sha256 == token_sha256
        && fact.intent.hub_origin == enrollment.hub_origin()
        && replacement.is_some_and(|replacement| {
            fact.intent.enrollment_id == replacement.enrollment_id()
                && fact.intent.host_id == replacement.target_host_id()
                && fact.intent.old_probe_id == replacement.expected_probe_id()
                && fact.intent.source_probe_version == replacement.source_probe_version()
                && replacement
                    .source_probe_sha256()
                    .contains(&fact.intent.source_probe_sha256)
                && fact.intent.target_probe_version == replacement.target_probe_version()
                && fact.intent.target_asset_set_digest == replacement.target_asset_set_digest()
        })
        && fact.intent.target_bundle_target == bundle.target
        && fact.intent.target_probe_version == bundle.version
        && fact.intent.target_asset_set_digest
            == format!("sha256:{}", bundle.asset_set_manifest_sha256)
        && fact.intent.target_manifest_sha256 == bundle.manifest_sha256;
    if exact_request {
        return Ok(Some(if fact.cleanup_complete {
            MatchingReplacementCommit::Ready(Box::new(fact))
        } else {
            MatchingReplacementCommit::CleanupRequired(Box::new(fact))
        }));
    }
    if !fact.candidate_layout_complete {
        return Err(ActivationError::Replacement);
    }
    if !fact.cleanup_complete || fact.intent.hub_origin != enrollment.hub_origin() {
        return Err(ActivationError::Replacement);
    }
    if !complete_predecessor_current_enrollment_matches(&fact, enrollment, bundle) {
        return Err(ActivationError::Replacement);
    }
    Ok(Some(MatchingReplacementCommit::CompletePredecessor(
        Box::new(fact),
    )))
}

/// A completed retained commit can only be retired ahead of a new activation
/// when the incoming authority is the terminal-recovery successor of its
/// already-installed target. The canonical Probe identity itself is checked
/// at the fixed-path finalizer boundary immediately before retirement.
fn complete_predecessor_current_enrollment_matches(
    predecessor: &crate::replacement::ReplacementCommitFact,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
) -> bool {
    let Some(current) = enrollment.replacement_migration() else {
        return false;
    };
    let Some((current_probe_sha256, _)) = bundle.component_receipt("probe") else {
        return false;
    };
    predecessor.has_valid_binding()
        && enrollment.hub_origin() == predecessor.intent.hub_origin
        && current.target_host_id() == predecessor.intent.host_id
        && current.expected_probe_id() != predecessor.intent.old_probe_id
        && current.source_probe_version() == predecessor.intent.target_probe_version
        && current
            .source_probe_sha256()
            .iter()
            .any(|digest| digest == current_probe_sha256)
        && current.target_probe_version() == predecessor.intent.target_probe_version
        && current.target_asset_set_digest() == predecessor.intent.target_asset_set_digest
        && bundle.target == predecessor.intent.target_bundle_target
        && bundle.version == predecessor.intent.target_probe_version
        && format!("sha256:{}", bundle.asset_set_manifest_sha256)
            == predecessor.intent.target_asset_set_digest
        && bundle.manifest_sha256 == predecessor.intent.target_manifest_sha256
}

fn replacement_request_for_installed_state(
    has_installed_metadata: bool,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
) -> Result<Option<LifecycleRequest>, ActivationError> {
    if !has_installed_metadata {
        return if enrollment.replacement_migration().is_some() {
            Err(ActivationError::Replacement)
        } else {
            Ok(None)
        };
    }
    LifecycleRequest::replacement_migration(
        enrollment,
        &format!("sha256:{}", bundle.asset_set_manifest_sha256),
        &bundle.target,
        &bundle.manifest_sha256,
        &bundle.version,
    )
    .map(Some)
    .map_err(|_| ActivationError::Replacement)
}

fn invoke_replacement_companion(
    request: &LifecycleRequest,
    source: &mut File,
    bundle: &VerifiedBundle,
    stable: &File,
) -> Result<(), ActivationError> {
    let _standard_descriptors = reserve_closed_standard_descriptors()?;
    let executable = sealed_lifecycle_companion(source, bundle)?;
    let executable_path = format!("/proc/self/fd/{}", executable.as_raw_fd());
    let mut command = Command::new(executable_path);
    command
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("ENOKI_LIFECYCLE_LEASE_FD", "9")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // 候选角色可能创建子进程；超时清理整个固定进程组并回收主进程。
    let stable_fd = stable.as_raw_fd();
    if (libc::STDIN_FILENO..=libc::STDERR_FILENO).contains(&stable_fd)
        || executable.as_raw_fd() == 9
    {
        return Err(ActivationError::Replacement);
    }
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if stable_fd == 9 {
                let flags = libc::fcntl(9, libc::F_GETFD);
                if flags < 0 || libc::fcntl(9, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::dup3(stable_fd, 9, 0) != 9 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| ActivationError::Replacement)?;
    let Some(mut stdin) = child.stdin.take() else {
        terminate_and_reap(&mut child);
        return Err(ActivationError::Replacement);
    };
    let encoded = request.encode().map_err(|_| ActivationError::Replacement)?;
    if stdin
        .write_all(&encoded)
        .and_then(|()| stdin.flush())
        .is_err()
    {
        terminate_and_reap(&mut child);
        return Err(ActivationError::Replacement);
    }
    drop(stdin);
    let Some(mut stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        return Err(ActivationError::Replacement);
    };
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
    {
        terminate_and_reap(&mut child);
        return Err(ActivationError::Replacement);
    }
    let deadline = Instant::now() + REPLACEMENT_COMPANION_BUDGET;
    let mut response = Vec::new();
    let mut status = None;
    loop {
        let mut chunk = [0_u8; 512];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) if status.is_some() => {
                    let succeeded = status
                        .is_some_and(|status: std::process::ExitStatus| status.success())
                        && LifecycleResponse::decode(&response)
                            == Ok(LifecycleResponse::succeeded());
                    return succeeded.then_some(()).ok_or(ActivationError::Replacement);
                }
                Ok(0) => break,
                Ok(read) => {
                    response.extend_from_slice(&chunk[..read]);
                    if response.len() > crate::lifecycle::MAX_LIFECYCLE_REQUEST_BYTES {
                        terminate_and_reap(&mut child);
                        return Err(ActivationError::Replacement);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    terminate_and_reap(&mut child);
                    return Err(ActivationError::Replacement);
                }
            }
        }
        if Instant::now() >= deadline {
            terminate_and_reap(&mut child);
            return Err(ActivationError::Replacement);
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(next) => status = next,
                Err(_) => {
                    terminate_and_reap(&mut child);
                    return Err(ActivationError::Replacement);
                }
            }
        }
        std::thread::sleep(REPLACEMENT_COMPANION_POLL_INTERVAL);
    }
}

fn reserve_closed_standard_descriptors() -> Result<Vec<File>, ActivationError> {
    let mut reserved = Vec::new();
    for descriptor in libc::STDIN_FILENO..=libc::STDERR_FILENO {
        if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0 {
            continue;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
            return Err(ActivationError::Replacement);
        }
        let opened = unsafe {
            libc::open(
                c"/dev/null".as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if opened != descriptor {
            if opened >= 0 {
                unsafe { libc::close(opened) };
            }
            return Err(ActivationError::Replacement);
        }
        reserved.push(unsafe { File::from_raw_fd(opened) });
    }
    Ok(reserved)
}

fn sealed_lifecycle_companion(
    source: &mut File,
    bundle: &VerifiedBundle,
) -> Result<File, ActivationError> {
    source.rewind().map_err(|_| ActivationError::Io)?;
    let name = CString::new("enoki-probe-lifecycle-companion")
        .map_err(|_| ActivationError::Replacement)?;
    let descriptor =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(ActivationError::Replacement);
    }
    let mut sealed = unsafe { File::from_raw_fd(descriptor) };
    let copied = io::copy(source, &mut sealed).map_err(|_| ActivationError::Replacement)?;
    let (_, expected_size) = bundle
        .component_receipt("lifecycle-companion")
        .ok_or(ActivationError::Verification)?;
    if copied != expected_size {
        return Err(ActivationError::Verification);
    }
    sealed
        .sync_all()
        .map_err(|_| ActivationError::Replacement)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(descriptor, libc::F_ADD_SEALS, seals) } != 0
        || unsafe { libc::fcntl(descriptor, libc::F_GET_SEALS) } != seals
    {
        return Err(ActivationError::Replacement);
    }
    verify_role_component(&mut sealed, bundle, "lifecycle-companion")
        .map_err(|_| ActivationError::Verification)?;
    Ok(sealed)
}

fn terminate_and_reap(child: &mut std::process::Child) {
    let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
    let _ = child.kill();
    let _ = child.wait();
}

impl Drop for ReceivedRootHandoff {
    fn drop(&mut self) {
        self.enrollment.zeroize();
    }
}

#[cfg(test)]
fn validate_received_role(
    component: &mut File,
    bundle: &VerifiedBundle,
    role: &str,
) -> Result<(), ActivationError> {
    validate_regular_file(component, 0, 0o600)?;
    verify_role_component(component, bundle, role).map_err(|_| ActivationError::Verification)
}

/// Root orchestration boundary. The caller must construct `policy` only from
/// build-fixed distribution trust; no rollback floor is accepted from stdin.
#[allow(dead_code)]
fn receive_root_handoff_with_policy(
    input: &mut impl Read,
    policy: &VerificationPolicy<'_>,
) -> Result<ReceivedRootHandoff, ActivationError> {
    receive_root_handoff(
        input,
        policy,
        0,
        |candidate| acquire_delegation_generation(candidate).map_err(ActivationError::from),
        None,
    )
}

/// Root-only production receiver. It has no arguments other than stdin and
/// obtains every trust value from the compiled Bootstrap identity.
fn activate_from_stdin(input: &mut impl Read) -> Result<ReceivedRootHandoff, ActivationError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ActivationError::NotRoot);
    }
    let owner = BootstrapLifecycleOwner::acquire()?;
    owner.retain_to_process_exit()?;
    owner.validate_stable()?;
    reconcile_exact_orphan_companion()?;
    owner.validate_stable()?;
    let trust = embedded_production_trust_for(BootstrapRole::Activator)
        .ok_or(ActivationError::BuildTrustUnavailable)?;
    receive_root_handoff_with_policy(
        input,
        &VerificationPolicy {
            distribution: trust.distribution,
            expected_target: trust.target,
            highest_accepted_delegation_generation: 0,
            external_root_fingerprint: trust.root_fingerprint.to_owned(),
            external_root_pem: Some(trust.root_pem.as_bytes()),
        },
    )
    .map(|mut handoff| {
        handoff._lifecycle_owner = Some(owner);
        handoff
    })
}

/// 私有 socket 只承载 metadata/component handoff；fd 0 保留为 sudo 实际
/// 执行的 sealed activator receipt，并在任何 Host mutation 前复验。
fn activate_from_socket(
    input: &mut impl Read,
    activator_receipt: &mut File,
) -> Result<ReceivedRootHandoff, ActivationError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ActivationError::NotRoot);
    }
    let owner = BootstrapLifecycleOwner::acquire()?;
    owner.retain_to_process_exit()?;
    owner.validate_stable()?;
    reconcile_exact_orphan_companion()?;
    owner.validate_stable()?;
    let trust = embedded_production_trust_for(BootstrapRole::Activator)
        .ok_or(ActivationError::BuildTrustUnavailable)?;
    let policy = VerificationPolicy {
        distribution: trust.distribution,
        expected_target: trust.target,
        highest_accepted_delegation_generation: 0,
        external_root_fingerprint: trust.root_fingerprint.to_owned(),
        external_root_pem: Some(trust.root_pem.as_bytes()),
    };
    receive_root_handoff_with_receipt(input, &policy, activator_receipt).map(|mut handoff| {
        handoff._lifecycle_owner = Some(owner);
        handoff
    })
}

fn receive_root_handoff_with_receipt(
    input: &mut impl Read,
    policy: &VerificationPolicy<'_>,
    activator_receipt: &mut File,
) -> Result<ReceivedRootHandoff, ActivationError> {
    receive_root_handoff(
        input,
        policy,
        0,
        |candidate| acquire_delegation_generation(candidate).map_err(ActivationError::from),
        Some(activator_receipt),
    )
}

fn receive_root_handoff(
    input: &mut impl Read,
    policy: &VerificationPolicy<'_>,
    expected_uid: u32,
    acquire_generation: impl FnOnce(u64) -> Result<DelegationGenerationLease, ActivationError>,
    mut activator_receipt: Option<&mut File>,
) -> Result<ReceivedRootHandoff, ActivationError> {
    let handoff = Handoff::read_metadata(input)?;

    // The first pass authenticates the root-signed candidate generation. It
    // deliberately ignores any caller-supplied floor; installed state is the
    // sole rollback authority.
    let initial_policy = VerificationPolicy {
        highest_accepted_delegation_generation: 0,
        ..policy.clone()
    };
    let initial =
        verify_metadata(&handoff, &initial_policy).map_err(|_| ActivationError::Verification)?;
    let mut generation_lease = acquire_generation(initial.bundle().delegation_generation)?;

    // Re-authenticate all metadata while holding the exclusive state lease and
    // using its root-owned rollback floor.
    let installed_policy = VerificationPolicy {
        highest_accepted_delegation_generation: generation_lease.current(),
        ..policy.clone()
    };
    let metadata =
        verify_metadata(&handoff, &installed_policy).map_err(|_| ActivationError::Verification)?;
    if let Some(receipt) = activator_receipt.as_deref_mut() {
        verify_activator_receipt(receipt, metadata.bundle())
            .map_err(|_| ActivationError::Verification)?;
    }
    // The enrollment capability is neither signed nor an authority to select
    // assets. It is consumed only after all signed metadata is authoritative.
    // A root-private component sink is staging only, never installed Host
    // state, so the generation floor must not advance until its exact content
    // has also been verified.
    let enrollment = Handoff::read_enrollment(input)?;

    let inbox = ensure_private_directory_at(
        generation_lease.state_directory().as_raw_fd(),
        INBOX_DIRECTORY,
        expected_uid,
    )?;
    let (temporary_name, mut component) = create_exclusive_component(&inbox, expected_uid)?;
    let (runtime_name, mut runtime) = create_exclusive_component(&inbox, expected_uid)?;
    let (cpu_provider_name, mut cpu_provider) = create_exclusive_component(&inbox, expected_uid)?;
    let (disk_health_provider_name, mut disk_health_provider) =
        create_exclusive_component(&inbox, expected_uid)?;
    let (lifecycle_companion_name, mut lifecycle_companion) =
        create_exclusive_component(&inbox, expected_uid)?;
    let (acquirer_name, mut acquirer) = create_exclusive_component(&inbox, expected_uid)?;
    let (activator_name, mut activator) = create_exclusive_component(&inbox, expected_uid)?;
    let has_bootstrap_receipts = activator_receipt.is_some();
    let result = (|| {
        Handoff::read_component_into(input, &mut component, metadata.bundle().component_len)?;
        component.sync_all().map_err(|_| ActivationError::Io)?;
        verify_component(&mut component, &handoff, metadata.bundle())
            .map_err(|_| ActivationError::Verification)?;
        let (_, runtime_len) = metadata
            .bundle()
            .component_receipt("observation-runtime")
            .ok_or(ActivationError::Verification)?;
        Handoff::read_runtime_into(input, &mut runtime, runtime_len)?;
        runtime.sync_all().map_err(|_| ActivationError::Io)?;
        verify_role_component(&mut runtime, metadata.bundle(), "observation-runtime")
            .map_err(|_| ActivationError::Verification)?;
        let (_, cpu_provider_len) = metadata
            .bundle()
            .component_receipt("system-state-provider")
            .ok_or(ActivationError::Verification)?;
        Handoff::read_cpu_provider_into(input, &mut cpu_provider, cpu_provider_len)?;
        cpu_provider.sync_all().map_err(|_| ActivationError::Io)?;
        verify_role_component(
            &mut cpu_provider,
            metadata.bundle(),
            "system-state-provider",
        )
        .map_err(|_| ActivationError::Verification)?;
        let (_, disk_health_provider_len) = metadata
            .bundle()
            .component_receipt("disk-health-provider")
            .ok_or(ActivationError::Verification)?;
        Handoff::read_disk_health_provider_into(
            input,
            &mut disk_health_provider,
            disk_health_provider_len,
        )?;
        disk_health_provider
            .sync_all()
            .map_err(|_| ActivationError::Io)?;
        verify_role_component(
            &mut disk_health_provider,
            metadata.bundle(),
            "disk-health-provider",
        )
        .map_err(|_| ActivationError::Verification)?;
        let (_, lifecycle_companion_len) = metadata
            .bundle()
            .component_receipt("lifecycle-companion")
            .ok_or(ActivationError::Verification)?;
        Handoff::read_lifecycle_companion_into(
            input,
            &mut lifecycle_companion,
            lifecycle_companion_len,
        )?;
        lifecycle_companion
            .sync_all()
            .map_err(|_| ActivationError::Io)?;
        verify_role_component(
            &mut lifecycle_companion,
            metadata.bundle(),
            "lifecycle-companion",
        )
        .map_err(|_| ActivationError::Verification)?;
        if let Some(receipt) = activator_receipt {
            let (_, acquirer_len) = metadata
                .bundle()
                .acquirer_receipt()
                .ok_or(ActivationError::Verification)?;
            Handoff::read_acquirer_into(input, &mut acquirer, acquirer_len)?;
            acquirer.sync_all().map_err(|_| ActivationError::Io)?;
            verify_acquirer_receipt(&mut acquirer, metadata.bundle())
                .map_err(|_| ActivationError::Verification)?;
            receipt
                .seek(SeekFrom::Start(0))
                .map_err(|_| ActivationError::Io)?;
            let copied = std::io::copy(receipt, &mut activator).map_err(|_| ActivationError::Io)?;
            let (_, activator_len) = metadata
                .bundle()
                .activator_receipt()
                .ok_or(ActivationError::Verification)?;
            if copied != activator_len {
                return Err(ActivationError::Verification);
            }
            activator.sync_all().map_err(|_| ActivationError::Io)?;
            verify_activator_receipt(&mut activator, metadata.bundle())
                .map_err(|_| ActivationError::Verification)?;
        }
        component
            .seek(SeekFrom::Start(0))
            .map_err(|_| ActivationError::Io)?;
        unlink_at(inbox.as_raw_fd(), &temporary_name)?;
        unlink_at(inbox.as_raw_fd(), &runtime_name)?;
        unlink_at(inbox.as_raw_fd(), &cpu_provider_name)?;
        unlink_at(inbox.as_raw_fd(), &disk_health_provider_name)?;
        unlink_at(inbox.as_raw_fd(), &lifecycle_companion_name)?;
        unlink_at(inbox.as_raw_fd(), &acquirer_name)?;
        unlink_at(inbox.as_raw_fd(), &activator_name)?;
        // The candidate has now passed every coherence, enrollment, exact
        // byte, digest, and EOF check. Persist immediately before returning
        // the sole object that can invoke a Host-mutating activation adapter.
        generation_lease.persist_before_mutation()?;
        Ok(ReceivedRootHandoff {
            bundle: metadata.bundle().clone(),
            component,
            runtime,
            cpu_provider,
            disk_health_provider,
            lifecycle_companion,
            acquirer: has_bootstrap_receipts.then_some(acquirer),
            activator: has_bootstrap_receipts.then_some(activator),
            enrollment,
            _generation_lease: generation_lease,
            _lifecycle_owner: None,
        })
    })();
    if result.is_err() {
        let _ = unlink_at(inbox.as_raw_fd(), &temporary_name);
        let _ = unlink_at(inbox.as_raw_fd(), &runtime_name);
        let _ = unlink_at(inbox.as_raw_fd(), &cpu_provider_name);
        let _ = unlink_at(inbox.as_raw_fd(), &disk_health_provider_name);
        let _ = unlink_at(inbox.as_raw_fd(), &lifecycle_companion_name);
        let _ = unlink_at(inbox.as_raw_fd(), &acquirer_name);
        let _ = unlink_at(inbox.as_raw_fd(), &activator_name);
    }
    result
}

fn ensure_private_directory_at(
    parent: RawFd,
    name: &str,
    expected_uid: u32,
) -> Result<File, ActivationError> {
    let name = c_string(name)?;
    let created = unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) } == 0;
    if !created {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(ActivationError::Io);
        }
    }
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let directory = file_from_descriptor(descriptor)?;
    if created && unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(ActivationError::Io);
    }
    validate_directory(&directory, expected_uid, 0o700)?;
    if created && unsafe { libc::fsync(parent) } != 0 {
        return Err(ActivationError::Io);
    }
    Ok(directory)
}

fn create_exclusive_component(
    inbox: &File,
    expected_uid: u32,
) -> Result<(CString, File), ActivationError> {
    for _ in 0..32 {
        let sequence = COMPONENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = c_string(&format!("component-{}-{sequence}", std::process::id()))?;
        let descriptor = unsafe {
            libc::openat(
                inbox.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor >= 0 {
            let file = file_from_descriptor(descriptor)?;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                return Err(ActivationError::Io);
            }
            validate_regular_file(&file, expected_uid, 0o600)?;
            return Ok((name, file));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(ActivationError::Io);
        }
    }
    Err(ActivationError::Io)
}

fn validate_directory(
    file: &File,
    expected_uid: u32,
    mode: libc::mode_t,
) -> Result<(), ActivationError> {
    validate_file(file, expected_uid, libc::S_IFDIR, mode)
}

fn validate_regular_file(
    file: &File,
    expected_uid: u32,
    mode: libc::mode_t,
) -> Result<(), ActivationError> {
    validate_file(file, expected_uid, libc::S_IFREG, mode)
}

fn validate_file(
    file: &File,
    expected_uid: u32,
    expected_type: libc::mode_t,
    expected_mode: libc::mode_t,
) -> Result<(), ActivationError> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(ActivationError::Io);
    }
    let status = unsafe { status.assume_init() };
    if status.st_uid != expected_uid
        || status.st_mode & libc::S_IFMT != expected_type
        || status.st_mode & 0o7777 != expected_mode
    {
        return Err(ActivationError::Io);
    }
    Ok(())
}

fn unlink_at(directory: RawFd, name: &CString) -> Result<(), ActivationError> {
    if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } != 0 {
        return Err(ActivationError::Io);
    }
    Ok(())
}

fn file_from_descriptor(descriptor: RawFd) -> Result<File, ActivationError> {
    if descriptor < 0 {
        return Err(ActivationError::Io);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn c_string(value: &str) -> Result<CString, ActivationError> {
    CString::new(value).map_err(|_| ActivationError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generation::acquire_delegation_generation_for_test,
        handoff::{MAGIC, SCHEMA_VERSION},
    };
    use rsa::{
        RsaPrivateKey,
        pkcs1v15::SigningKey,
        pkcs8::{EncodePublicKey, LineEnding},
        rand_core::OsRng,
        signature::{RandomizedSigner, SignatureEncoding},
    };
    use sha2::{Digest, Sha256};
    use std::{fs, io::Cursor, os::unix::fs::PermissionsExt, sync::mpsc, thread, time::Duration};
    use tempfile::tempdir;

    struct TestStableLock {
        file: File,
        path: std::path::PathBuf,
    }

    impl Drop for TestStableLock {
        fn drop(&mut self) {
            let held = self.file.metadata().ok();
            let current = fs::symlink_metadata(&self.path).ok();
            if held.is_some_and(|held| {
                current.is_some_and(|current| {
                    held.dev() == current.dev() && held.ino() == current.ino()
                })
            }) {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    fn hold_test_stable_lock() -> Option<TestStableLock> {
        let path = std::path::PathBuf::from("/run/lock/enoki-probe-lifecycle.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .ok()?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .expect("canonical stable mode");
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) }, 0);
        Some(TestStableLock { file, path })
    }

    fn test_stable_owner() -> StableLifecycleLock {
        StableLifecycleLock {
            parent: tempfile::tempfile().unwrap(),
            file: tempfile::tempfile().unwrap(),
            validate: false,
        }
    }

    #[test]
    fn bootstrap_stable_owner_wait_is_bounded() {
        let Some(stable) = hold_test_stable_lock() else {
            return;
        };
        assert!(open_stable_lifecycle_lock(Instant::now() + Duration::from_millis(30)).is_err());
        drop(stable);
    }

    #[test]
    fn process_owner_admission_borrows_legacy_for_the_actual_install_transaction_gate() {
        let root = tempdir().unwrap();
        let state = root.path().join("bootstrap-state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let legacy = ActivationLock::acquire(
            &state,
            unsafe { libc::geteuid() },
            Instant::now() + ACTIVATION_LOCK_BUDGET,
        )
        .unwrap();
        let owner = BootstrapLifecycleOwner {
            _legacy: Some(legacy),
            stable: test_stable_owner(),
        };

        owner
            .install_admission(None)
            .enter(&state, unsafe { libc::geteuid() })
            .expect("actual install transaction gate borrows held legacy instead of re-flocking");
    }

    #[test]
    fn received_fresh_handoff_generation_enters_the_actual_install_transaction_gate() {
        let root = tempdir().unwrap();
        let state = root.path().join("bootstrap-state");
        let fixture = fixture(1);
        let mut received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &state,
            &fixture.policy(),
        )
        .expect("真实 handoff 已创建并持有 generation state");
        received._lifecycle_owner = Some(BootstrapLifecycleOwner {
            _legacy: None,
            stable: test_stable_owner(),
        });
        received
            ._lifecycle_owner
            .as_ref()
            .expect("同一 process owner")
            .install_admission(Some(&received._generation_lease))
            .enter(&state, unsafe { libc::geteuid() })
            .expect("同一 owner 的 generation state 可进入实际 Fresh transaction gate 并建立 legacy inventory");
    }

    #[test]
    fn rejects_invalid_metadata_before_creating_a_root_component() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut bytes = Vec::new();
        bytes.extend(MAGIC);
        bytes.extend(2u16.to_be_bytes());
        bytes.extend([7, 0]);
        let policy = invalid_policy();
        assert!(receive_for_test(&mut Cursor::new(bytes), &state_root, &policy).is_err());
        assert!(!state_root.join("inbox").exists());
    }

    #[test]
    fn inbox_symlink_fails_closed() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(temporary.path().join("outside"), state_root.join("inbox"))
            .unwrap();
        let state = File::open(&state_root).unwrap();
        assert!(
            ensure_private_directory_at(state.as_raw_fd(), INBOX_DIRECTORY, unsafe {
                libc::geteuid()
            })
            .is_err()
        );
    }

    #[test]
    fn rollback_is_rejected_before_a_component_sink_exists() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut installed = acquire_delegation_generation_for_test(&state_root, 2).unwrap();
        installed.persist_before_mutation().unwrap();
        drop(installed);
        let fixture = fixture(1);

        assert_eq!(
            receive_for_test(
                &mut Cursor::new(fixture.stream.as_slice()),
                &state_root,
                &fixture.policy()
            )
            .err(),
            Some(ActivationError::Generation(GenerationStateError::Rollback))
        );
        assert!(!state_root.join("inbox").exists());
    }

    #[test]
    fn same_generation_is_accepted_and_the_component_is_unlinked() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut installed = acquire_delegation_generation_for_test(&state_root, 3).unwrap();
        installed.persist_before_mutation().unwrap();
        drop(installed);
        let fixture = fixture(3);

        let mut received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &state_root,
            &fixture.policy(),
        )
        .unwrap();
        let mut bytes = Vec::new();
        received
            .component()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"probe");
        assert!(
            fs::read_dir(state_root.join("inbox"))
                .map(|entries| entries.count() == 0)
                .unwrap_or(true)
        );
    }

    #[test]
    fn truncated_component_does_not_advance_the_generation_floor() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut fixture = fixture(4);
        let component = fixture
            .stream
            .windows(b"probe".len())
            .position(|bytes| bytes == b"probe")
            .unwrap();
        fixture.stream.remove(component + b"probe".len() - 1);

        assert!(
            receive_for_test(
                &mut Cursor::new(fixture.stream.as_slice()),
                &state_root,
                &fixture.policy()
            )
            .is_err()
        );
        let floor = acquire_delegation_generation_for_test(&state_root, 4).unwrap();
        assert_eq!(floor.current(), 0);
        assert!(
            fs::read_dir(state_root.join("inbox"))
                .map(|entries| entries.count() == 0)
                .unwrap_or(true)
        );
    }

    #[test]
    fn invalid_enrollment_does_not_advance_the_generation_floor() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut fixture = fixture(4);
        let token = b"enk_enroll_test";
        let offset = fixture
            .stream
            .windows(token.len())
            .position(|bytes| bytes == token)
            .unwrap();
        fixture.stream[offset] = b'!';

        assert!(
            receive_for_test(
                &mut Cursor::new(fixture.stream.as_slice()),
                &state_root,
                &fixture.policy()
            )
            .is_err()
        );
        let floor = acquire_delegation_generation_for_test(&state_root, 4).unwrap();
        assert_eq!(floor.current(), 0);
    }

    #[test]
    fn invalid_component_does_not_advance_the_generation_floor() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut fixture = fixture(4);
        let component = fixture
            .stream
            .windows(b"probe".len())
            .position(|bytes| bytes == b"probe")
            .unwrap();
        fixture.stream[component] ^= 1;

        assert!(
            receive_for_test(
                &mut Cursor::new(fixture.stream.as_slice()),
                &state_root,
                &fixture.policy()
            )
            .is_err()
        );
        let floor = acquire_delegation_generation_for_test(&state_root, 4).unwrap();
        assert_eq!(floor.current(), 0);
    }

    #[test]
    fn valid_handoff_persists_the_generation_floor_before_activation() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let fixture = fixture(4);
        let received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &state_root,
            &fixture.policy(),
        )
        .unwrap();

        received
            .activate_with(|_, _, _| {
                assert_eq!(
                    fs::read_to_string(state_root.join("trust/delegation-generation")).unwrap(),
                    "4\n"
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn installed_state_maps_the_verified_candidate_to_one_replacement_request() {
        let temporary = tempdir().unwrap();
        let fixture = fixture(4);
        let received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &temporary.path().join("state"),
            &fixture.policy(),
        )
        .unwrap();

        let enrollment_input = format!(
            "{{\"hubOrigin\":\"https://hub.example\",\"enrollmentToken\":\"enk_enroll_test\",\"replacementMigration\":{{\"enrollmentId\":\"enr_0123456789abcdef\",\"expectedProbeId\":\"probe_old_01\",\"sourceProbeSha256\":[\"{}\"],\"sourceProbeVersion\":\"1.2.2\",\"targetAssetSetDigest\":\"sha256:{}\",\"targetHostId\":\"7\",\"targetProbeVersion\":\"1.2.3\"}},\"schemaVersion\":1}}",
            "c".repeat(64),
            received.bundle.asset_set_manifest_sha256,
        );
        let enrollment = crate::handoff::Enrollment::from_install_input(
            "https://hub.example",
            enrollment_input.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            replacement_request_for_installed_state(false, &enrollment, &received.bundle),
            Err(ActivationError::Replacement),
            "Replacement authority 缺少旧 install metadata 时必须在任何 Host effect 前关闭",
        );
        assert_eq!(
            replacement_request_for_installed_state(true, &received.enrollment, &received.bundle,),
            Err(ActivationError::Replacement),
            "raw-token Enrollment不得误触 Replacement",
        );
        let request = replacement_request_for_installed_state(true, &enrollment, &received.bundle)
            .unwrap()
            .unwrap();
        assert_eq!(
            request.transition(),
            crate::lifecycle::LifecycleTransition::ReplacementMigration
        );
        assert_eq!(
            request.authority(),
            &crate::lifecycle::LifecycleRequestAuthority::ReplacementEnrollment {
                enrollment_token: "enk_enroll_test".to_string(),
                enrollment_id: "enr_0123456789abcdef".to_string(),
                hub_origin: "https://hub.example".to_string(),
                host_id: "7".to_string(),
                expected_probe_id: "probe_old_01".to_string(),
                source_probe_version: "1.2.2".to_string(),
                source_probe_sha256: vec!["c".repeat(64)],
                target_asset_set_digest: format!(
                    "sha256:{}",
                    received.bundle.asset_set_manifest_sha256
                ),
                target_bundle_target: received.bundle.target.clone(),
                target_manifest_sha256: received.bundle.manifest_sha256.clone(),
                bundle_version: "1.2.3".to_string(),
            }
        );
    }

    #[test]
    fn completed_predecessor_requires_a_terminal_recovery_successor_before_retirement() {
        struct Store(Option<crate::replacement::ReplacementCommitFact>);
        impl crate::replacement::ReplacementCommitStore for Store {
            type Error = ();

            fn load(
                &mut self,
            ) -> Result<Option<crate::replacement::ReplacementCommitFact>, Self::Error>
            {
                Ok(self.0.clone())
            }

            fn persist(
                &mut self,
                _: &crate::replacement::ReplacementCommitFact,
            ) -> Result<(), Self::Error> {
                unreachable!()
            }
        }

        let temporary = tempdir().unwrap();
        let fixture = fixture(4);
        let received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &temporary.path().join("state"),
            &fixture.policy(),
        )
        .unwrap();
        let token_sha256 = format!(
            "{:x}",
            Sha256::digest(received.enrollment.enrollment_token().as_bytes())
        );
        let fact = crate::replacement::ReplacementCommitFact::for_test(
            crate::replacement::ReplacementIntent {
                enrollment_id: "enr_0123456789abcdef".to_owned(),
                enrollment_token_sha256: token_sha256,
                host_id: "7".to_owned(),
                hub_origin: received.enrollment.hub_origin().to_owned(),
                old_probe_id: "probe-old".to_owned(),
                source_probe_version: "1.2.2".to_owned(),
                source_probe_sha256: "a".repeat(64),
                target_bundle_target: received.bundle.target.clone(),
                target_probe_version: received.bundle.version.clone(),
                target_asset_set_digest: format!(
                    "sha256:{}",
                    received.bundle.asset_set_manifest_sha256
                ),
                target_manifest_sha256: received.bundle.manifest_sha256.clone(),
            },
            true,
            true,
        );
        let enrollment_input = format!(
            "{{\"hubOrigin\":\"https://hub.example\",\"enrollmentToken\":\"{}\",\"replacementMigration\":{{\"enrollmentId\":\"enr_0123456789abcdef\",\"expectedProbeId\":\"probe-old\",\"sourceProbeSha256\":[\"{}\"],\"sourceProbeVersion\":\"1.2.2\",\"targetAssetSetDigest\":\"sha256:{}\",\"targetHostId\":\"7\",\"targetProbeVersion\":\"{}\"}},\"schemaVersion\":1}}",
            received.enrollment.enrollment_token(),
            "a".repeat(64),
            received.bundle.asset_set_manifest_sha256,
            received.bundle.version,
        );
        let exact_enrollment = Enrollment::from_install_input(
            received.enrollment.hub_origin(),
            enrollment_input.as_bytes(),
        )
        .unwrap();
        let exact = matching_replacement_commit_in(
            &mut Store(Some(fact.clone())),
            &exact_enrollment,
            &received.bundle,
        )
        .unwrap()
        .unwrap();
        let MatchingReplacementCommit::Ready(exact) = exact else {
            panic!("completed exact commit must be ready")
        };
        assert_eq!(*exact, fact);

        let other_enrollment =
            Enrollment::new(received.enrollment.hub_origin(), "enk_enroll_other").unwrap();
        assert!(matches!(
            matching_replacement_commit_in(
                &mut Store(Some(fact.clone())),
                &other_enrollment,
                &received.bundle,
            ),
            Err(ActivationError::Replacement)
        ));

        let current_probe_sha256 = received.bundle.component_receipt("probe").unwrap().0;
        let successor_input = format!(
            "{{\"hubOrigin\":\"https://hub.example\",\"enrollmentToken\":\"enk_enroll_other\",\"replacementMigration\":{{\"enrollmentId\":\"enr_fedcba9876543210\",\"expectedProbeId\":\"probe-current\",\"sourceProbeSha256\":[\"{}\"],\"sourceProbeVersion\":\"{}\",\"targetAssetSetDigest\":\"sha256:{}\",\"targetHostId\":\"7\",\"targetProbeVersion\":\"{}\"}},\"schemaVersion\":1}}",
            current_probe_sha256,
            received.bundle.version,
            received.bundle.asset_set_manifest_sha256,
            received.bundle.version,
        );
        let terminal_recovery = Enrollment::from_install_input(
            received.enrollment.hub_origin(),
            successor_input.as_bytes(),
        )
        .unwrap();
        let predecessor = matching_replacement_commit_in(
            &mut Store(Some(fact.clone())),
            &terminal_recovery,
            &received.bundle,
        )
        .unwrap()
        .unwrap();
        let MatchingReplacementCommit::CompletePredecessor(predecessor) = predecessor else {
            panic!("only a terminal-recovery successor may retire a complete predecessor")
        };
        assert_eq!(*predecessor, fact);
        let mut incomplete = fact;
        incomplete.candidate_layout_complete = false;
        assert!(matches!(
            matching_replacement_commit_in(
                &mut Store(Some(incomplete)),
                &terminal_recovery,
                &received.bundle,
            ),
            Err(ActivationError::Replacement)
        ));
    }

    #[test]
    fn fresh_invocation_recognizes_the_exact_incomplete_replacement_commit() {
        use std::{cell::RefCell, rc::Rc};

        struct Store(Rc<RefCell<Option<crate::replacement::ReplacementCommitFact>>>);
        impl crate::replacement::ReplacementCommitStore for Store {
            type Error = ();

            fn load(
                &mut self,
            ) -> Result<Option<crate::replacement::ReplacementCommitFact>, Self::Error>
            {
                Ok(self.0.borrow().clone())
            }

            fn persist(
                &mut self,
                fact: &crate::replacement::ReplacementCommitFact,
            ) -> Result<(), Self::Error> {
                *self.0.borrow_mut() = Some(fact.clone());
                Ok(())
            }
        }

        let temporary = tempdir().unwrap();
        let fixture = fixture(4);
        let received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &temporary.path().join("state"),
            &fixture.policy(),
        )
        .unwrap();
        let enrollment_input = format!(
            "{{\"hubOrigin\":\"https://hub.example\",\"enrollmentToken\":\"enk_enroll_test\",\"replacementMigration\":{{\"enrollmentId\":\"enr_0123456789abcdef\",\"expectedProbeId\":\"probe_old_01\",\"sourceProbeSha256\":[\"{}\"],\"sourceProbeVersion\":\"1.2.2\",\"targetAssetSetDigest\":\"sha256:{}\",\"targetHostId\":\"7\",\"targetProbeVersion\":\"1.2.3\"}},\"schemaVersion\":1}}",
            "c".repeat(64),
            received.bundle.asset_set_manifest_sha256,
        );
        let enrollment =
            Enrollment::from_install_input("https://hub.example", enrollment_input.as_bytes())
                .unwrap();
        let intent = crate::replacement::ReplacementIntent {
            enrollment_id: "enr_0123456789abcdef".to_owned(),
            enrollment_token_sha256: format!(
                "{:x}",
                Sha256::digest(enrollment.enrollment_token().as_bytes())
            ),
            host_id: "7".to_owned(),
            hub_origin: "https://hub.example".to_owned(),
            old_probe_id: "probe_old_01".to_owned(),
            source_probe_version: "1.2.2".to_owned(),
            source_probe_sha256: "c".repeat(64),
            target_bundle_target: received.bundle.target.clone(),
            target_probe_version: received.bundle.version.clone(),
            target_asset_set_digest: format!(
                "sha256:{}",
                received.bundle.asset_set_manifest_sha256
            ),
            target_manifest_sha256: received.bundle.manifest_sha256.clone(),
        };
        let fact = crate::replacement::ReplacementCommitFact::for_test(intent, false, false);
        let shared = Rc::new(RefCell::new(Some(fact)));
        let invoked = Rc::new(RefCell::new(Vec::new()));
        let invoked_from_fresh_instance = Rc::clone(&invoked);
        let committed_by_companion = Rc::clone(&shared);

        let activation = prepare_replacement_migration_in(
            &enrollment,
            &received.bundle,
            &mut Store(Rc::clone(&shared)),
            false,
            |_| Ok(CommittedReplacementLocalCustody::SourceMetadata),
            move |request| {
                invoked_from_fresh_instance
                    .borrow_mut()
                    .push(request.clone());
                let mut completed = committed_by_companion
                    .borrow()
                    .clone()
                    .expect("durable commit");
                completed.cleanup_complete = true;
                *committed_by_companion.borrow_mut() = Some(completed);
                Ok(())
            },
        )
        .expect("fresh activation resumes exact incomplete commit");

        assert!(
            matches!(activation, ReplacementActivation::Resume(_)),
            "cleanup 后必须继续 committed candidate activation"
        );
        let invoked = invoked.borrow();
        assert_eq!(
            invoked.len(),
            1,
            "fresh instance invokes one candidate Companion"
        );
        assert_eq!(
            invoked[0].transition(),
            crate::lifecycle::LifecycleTransition::ReplacementMigration
        );

        let retirement_invocations = Rc::new(RefCell::new(0));
        let observed_retirement_invocations = Rc::clone(&retirement_invocations);
        let source_custody = tempdir().unwrap();
        let source_metadata = source_custody.path().join("etc/enoki/probe-install.toml");
        fs::create_dir_all(source_metadata.parent().unwrap()).unwrap();
        fs::write(
            &source_metadata,
            "source metadata under durable commit custody",
        )
        .unwrap();
        let source_state = source_custody.path().join("var/lib/enoki-probe-bootstrap");
        fs::create_dir_all(&source_state).unwrap();
        fs::set_permissions(&source_state, fs::Permissions::from_mode(0o700)).unwrap();
        let source_paths = FixedInstallPaths::under(source_custody.path());
        let activation = prepare_replacement_migration_in(
            &enrollment,
            &received.bundle,
            &mut Store(Rc::clone(&shared)),
            true,
            |fact| {
                crate::install::classify_committed_replacement_local_custody(
                    &source_paths,
                    &fact.resume_binding(),
                )
                .map_err(ActivationError::Install)
            },
            move |_| {
                *observed_retirement_invocations.borrow_mut() += 1;
                Ok(())
            },
        )
        .expect("fresh activation retires source metadata after cleanup receipt");
        assert!(matches!(activation, ReplacementActivation::Resume(_)));
        assert_eq!(
            *retirement_invocations.borrow(),
            1,
            "cleanup receipt with source metadata must reenter the sealed Companion"
        );

        let candidate_invocations = Rc::new(RefCell::new(0));
        let observed_candidate_invocations = Rc::clone(&candidate_invocations);
        let activation = prepare_replacement_migration_in(
            &enrollment,
            &received.bundle,
            &mut Store(Rc::clone(&shared)),
            true,
            |_| Ok(CommittedReplacementLocalCustody::CandidateTransaction),
            move |_| {
                *observed_candidate_invocations.borrow_mut() += 1;
                Ok(())
            },
        )
        .expect("fresh activation resumes candidate transaction without retiring its metadata");
        assert!(matches!(activation, ReplacementActivation::Resume(_)));
        assert_eq!(
            *candidate_invocations.borrow(),
            0,
            "candidate transaction custody must bypass source metadata retirement"
        );

        let wrong = Enrollment::new("https://hub.example", "enk_enroll_wrong").unwrap();
        let wrong_invocations = Rc::new(RefCell::new(0));
        let observed_wrong_invocations = Rc::clone(&wrong_invocations);
        assert!(matches!(
            prepare_replacement_migration_in(
                &wrong,
                &received.bundle,
                &mut Store(Rc::clone(&shared)),
                false,
                |_| Ok(CommittedReplacementLocalCustody::SourceMetadataRetired),
                move |_| {
                    *observed_wrong_invocations.borrow_mut() += 1;
                    Ok(())
                },
            ),
            Err(ActivationError::Replacement)
        ));
        assert_eq!(
            *wrong_invocations.borrow(),
            0,
            "wrong token has zero effects"
        );

        let mut wrong_bundle = received.bundle.clone();
        wrong_bundle.manifest_sha256 = "f".repeat(64);
        let wrong_bundle_invocations = Rc::new(RefCell::new(0));
        let observed_wrong_bundle = Rc::clone(&wrong_bundle_invocations);
        assert!(matches!(
            prepare_replacement_migration_in(
                &enrollment,
                &wrong_bundle,
                &mut Store(Rc::clone(&shared)),
                false,
                |_| Ok(CommittedReplacementLocalCustody::SourceMetadataRetired),
                move |_| {
                    *observed_wrong_bundle.borrow_mut() += 1;
                    Ok(())
                },
            ),
            Err(ActivationError::Replacement)
        ));
        assert_eq!(
            *wrong_bundle_invocations.borrow(),
            0,
            "wrong verified bundle binding has zero effects"
        );

        let mut wrong_target_bundle = received.bundle.clone();
        wrong_target_bundle.target = "aarch64-unknown-linux-gnu".to_owned();
        let wrong_target_invocations = Rc::new(RefCell::new(0));
        let observed_wrong_target = Rc::clone(&wrong_target_invocations);
        assert!(matches!(
            prepare_replacement_migration_in(
                &enrollment,
                &wrong_target_bundle,
                &mut Store(Rc::clone(&shared)),
                false,
                |_| Ok(CommittedReplacementLocalCustody::SourceMetadataRetired),
                move |_| {
                    *observed_wrong_target.borrow_mut() += 1;
                    Ok(())
                },
            ),
            Err(ActivationError::Replacement)
        ));
        assert_eq!(
            *wrong_target_invocations.borrow(),
            0,
            "wrong target has zero Companion effects"
        );

        let wrong_intent_input =
            enrollment_input.replace("\"targetHostId\":\"7\"", "\"targetHostId\":\"8\"");
        let wrong_intent =
            Enrollment::from_install_input("https://hub.example", wrong_intent_input.as_bytes())
                .unwrap();
        let wrong_intent_invocations = Rc::new(RefCell::new(0));
        let observed_wrong_intent = Rc::clone(&wrong_intent_invocations);
        assert!(matches!(
            prepare_replacement_migration_in(
                &wrong_intent,
                &received.bundle,
                &mut Store(shared),
                false,
                |_| Ok(CommittedReplacementLocalCustody::SourceMetadataRetired),
                move |_| {
                    *observed_wrong_intent.borrow_mut() += 1;
                    Ok(())
                },
            ),
            Err(ActivationError::Replacement)
        ));
        assert_eq!(
            *wrong_intent_invocations.borrow(),
            0,
            "wrong Replacement intent has zero effects"
        );
    }

    #[test]
    fn replacement_companion_execution_fd_is_the_exact_sealed_candidate_role() {
        let temporary = tempdir().unwrap();
        let fixture = fixture(4);
        let mut received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &temporary.path().join("state"),
            &fixture.policy(),
        )
        .unwrap();

        let mut sealed =
            sealed_lifecycle_companion(&mut received.lifecycle_companion, &received.bundle)
                .unwrap();
        let mut bytes = Vec::new();
        sealed.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"lifecycle-companion");
        assert_eq!(
            unsafe { libc::fcntl(sealed.as_raw_fd(), libc::F_GET_SEALS) },
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL
        );
    }

    #[test]
    fn received_handoff_holds_the_generation_lock_until_drop() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let fixture = fixture(5);
        let received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &state_root,
            &fixture.policy(),
        )
        .unwrap();
        let worker_root = state_root.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let lease = acquire_delegation_generation_for_test(&worker_root, 5);
            sender.send(lease.is_ok()).unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        drop(received);
        assert!(receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        worker.join().unwrap();
    }

    #[test]
    fn root_module_never_gains_archive_or_network_dependencies() {
        let source = include_str!("activation.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            ["flat", "e2"].concat(),
            ["ta", "r::"].concat(),
            ["ur", "eq"].concat(),
            ["req", "west"].concat(),
            ["Gz", "Decoder"].concat(),
        ] {
            assert!(!production.contains(&forbidden), "{forbidden}")
        }
    }

    fn receive_for_test(
        input: &mut impl Read,
        state_root: &std::path::Path,
        policy: &VerificationPolicy<'_>,
    ) -> Result<ReceivedRootHandoff, ActivationError> {
        receive_root_handoff(
            input,
            policy,
            unsafe { libc::geteuid() },
            |candidate| {
                acquire_delegation_generation_for_test(state_root, candidate)
                    .map_err(ActivationError::from)
            },
            None,
        )
    }

    fn invalid_policy() -> VerificationPolicy<'static> {
        VerificationPolicy {
            distribution: "enoki",
            expected_target: "x86_64-unknown-linux-gnu",
            highest_accepted_delegation_generation: u64::MAX,
            external_root_fingerprint: "a".repeat(64),
            external_root_pem: None,
        }
    }

    struct Fixture {
        root: Vec<u8>,
        root_fingerprint: String,
        stream: Vec<u8>,
    }

    impl Fixture {
        fn policy(&self) -> VerificationPolicy<'_> {
            VerificationPolicy {
                distribution: "enoki",
                expected_target: "x86_64-unknown-linux-gnu",
                highest_accepted_delegation_generation: u64::MAX,
                external_root_fingerprint: self.root_fingerprint.clone(),
                external_root_pem: Some(&self.root),
            }
        }
    }

    fn fixture(generation: u64) -> Fixture {
        let mut rng = OsRng;
        let root = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let daily = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let root_pem = root
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .into_bytes();
        let daily_pem = daily
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .into_bytes();
        let root_id = sha256(&root_pem);
        let daily_id = sha256(&daily_pem);
        let component = b"probe";
        let bundle = format!(
            "{{\"bootstrapAssets\":[{{\"path\":\"bootstrap/enoki-probe-bootstrap-acquire\",\"permissionProfile\":\"bootstrap-acquirer-v1\",\"role\":\"bootstrap-acquirer\",\"sha256\":\"{}\",\"size\":1,\"version\":\"1.2.3\"}},{{\"path\":\"bootstrap/enoki-probe-bootstrap-activate\",\"permissionProfile\":\"bootstrap-activator-v1\",\"role\":\"bootstrap-activator\",\"sha256\":\"{}\",\"size\":1,\"version\":\"1.2.3\"}}],\"components\":[{{\"path\":\"enoki-probe\",\"permissionProfile\":\"probe-v5\",\"resourceContract\":\"hub-reporting-v1\",\"role\":\"probe\",\"sha256\":\"{}\",\"size\":5,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-observation-runtime\",\"permissionProfile\":\"observation-runtime-v4\",\"resourceContract\":\"official-observation-v2\",\"role\":\"observation-runtime\",\"sha256\":\"{}\",\"size\":7,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-cpu-resource-provider\",\"permissionProfile\":\"system-state-provider-v5\",\"resourceContract\":\"system-state-v3\",\"role\":\"system-state-provider\",\"sha256\":\"{}\",\"size\":21,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-disk-health-resource-provider\",\"permissionProfile\":\"disk-health-provider-v3\",\"resourceContract\":\"disk-health-v1\",\"role\":\"disk-health-provider\",\"sha256\":\"{}\",\"size\":20,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-probe-lifecycle-companion\",\"permissionProfile\":\"lifecycle-companion-v3\",\"resourceContract\":\"local-lifecycle-v1\",\"role\":\"lifecycle-companion\",\"sha256\":\"{}\",\"size\":19,\"version\":\"1.2.3\"}}],\"kind\":\"enoki-probe-bundle\",\"target\":\"x86_64-unknown-linux-gnu\",\"version\":\"1.2.3\"}}\n",
            sha256(b"a"),
            sha256(b"b"),
            sha256(component),
            sha256(b"runtime"),
            sha256(b"system-state-provider"),
            sha256(b"disk-health-provider"),
            sha256(b"lifecycle-companion"),
        )
        .into_bytes();
        let delegation = format!(
            "{{\"distribution\":\"enoki\",\"generation\":{generation},\"kind\":\"enoki-probe-trust-delegation\",\"purpose\":\"probe-asset-signing\",\"rootKeyId\":\"{root_id}\",\"schemaVersion\":1,\"signingIdentity\":{{\"algorithm\":\"rsa-sha256\",\"keyId\":\"{daily_id}\",\"publicKeyPem\":{}}}}}\n",
            serde_json::to_string(std::str::from_utf8(&daily_pem).unwrap()).unwrap()
        )
        .into_bytes();
        let mut delegation_input = b"enoki/probe-trust-delegation/v1\0".to_vec();
        delegation_input.extend_from_slice(&delegation);
        let delegation_signature = SigningKey::<Sha256>::new(root)
            .sign_with_rng(&mut rng, &delegation_input)
            .to_vec();
        let manifest = format!(
            "{{\"assets\":[{{\"bundleManifestSha256\":\"{}\",\"file\":\"enoki-probe-x86_64-unknown-linux-gnu.tar.gz\",\"sha256\":\"{}\",\"size\":1,\"target\":\"x86_64-unknown-linux-gnu\"}}],\"kind\":\"enoki-probe-assets\",\"signature\":{{\"algorithm\":\"rsa-sha256\",\"delegationGeneration\":{generation},\"delegationKeyId\":\"{daily_id}\",\"file\":\"manifest.json.sig\",\"publicKey\":\"signing-key.pem\"}},\"version\":\"1.2.3\"}}\n",
            sha256(&bundle),
            "0".repeat(64)
        )
        .into_bytes();
        let manifest_signature = SigningKey::<Sha256>::new(daily)
            .sign_with_rng(&mut rng, &manifest)
            .to_vec();
        let handoff = Handoff {
            delegation,
            delegation_signature,
            manifest,
            manifest_signature,
            signing_key: daily_pem,
            bundle_manifest: bundle,
        };
        let mut stream = Vec::new();
        handoff
            .write_from(
                &crate::handoff::Enrollment::new("https://hub.example", "enk_enroll_test").unwrap(),
                &mut Cursor::new(component),
                component.len() as u64,
                &mut Cursor::new(b"runtime"),
                7,
                &mut Cursor::new(b"system-state-provider"),
                21,
                &mut Cursor::new(b"disk-health-provider"),
                20,
                &mut Cursor::new(b"lifecycle-companion"),
                19,
                &mut Cursor::new(b"a"),
                1,
                &mut stream,
            )
            .unwrap();
        assert_eq!(&stream[..8], &MAGIC);
        assert_eq!(&stream[8..10], &SCHEMA_VERSION.to_be_bytes());
        Fixture {
            root: root_pem,
            root_fingerprint: root_id,
            stream,
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
}
