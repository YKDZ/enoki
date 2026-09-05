use super::{InstallError, RollbackStep};
use crate::secure_file::{
    HeldDirectoryFacts, SystemdProbeDirectory, SystemdProbeStateProjection,
    open_systemd_probe_state_projection_for_finalization,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const LOCK_NAME: &str = "activation.lock";
const JOURNAL_NAME: &str = "activation-journal.json";
const LAYOUT_NAME: &str = "current-layout";
const STAGING_NAME: &str = "activation-stage";
pub(super) const OWNERSHIP_MARKER: &str = ".enoki-bootstrap-transaction";

pub(crate) struct ActivationLock {
    file: File,
}

impl ActivationLock {
    pub(crate) fn acquire(
        state: &Path,
        expected_uid: u32,
        deadline: Instant,
    ) -> Result<Self, InstallError> {
        ensure_private_state(state, expected_uid)?;
        let path = state.join(LOCK_NAME);
        let (file, created) = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => (file, true),
            Err(open_error) if open_error.kind() == std::io::ErrorKind::AlreadyExists => {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)
                    .map_err(|_| InstallError::ExistingResidue)?;
                (file, false)
            }
            Err(_) => return Err(InstallError::Io),
        };
        if created {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| InstallError::Io)?;
            file.sync_all().map_err(|_| InstallError::Io)?;
            sync_parent(&path)?;
        }
        let metadata = file.metadata().map_err(|_| InstallError::Io)?;
        if !metadata.is_file()
            || metadata.uid() != expected_uid
            || metadata.gid() != expected_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(InstallError::ExistingResidue);
        }
        loop {
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                let path_metadata =
                    fs::symlink_metadata(&path).map_err(|_| InstallError::ExistingResidue)?;
                let locked_metadata = file.metadata().map_err(|_| InstallError::Io)?;
                if path_metadata.file_type().is_symlink()
                    || !path_metadata.is_file()
                    || path_metadata.uid() != expected_uid
                    || path_metadata.gid() != expected_uid
                    || path_metadata.mode() & 0o7777 != 0o600
                    || path_metadata.dev() != locked_metadata.dev()
                    || path_metadata.ino() != locked_metadata.ino()
                    || path_metadata.nlink() != 1
                    || !locked_metadata.is_file()
                    || locked_metadata.uid() != expected_uid
                    || locked_metadata.gid() != expected_uid
                    || locked_metadata.mode() & 0o7777 != 0o600
                    || locked_metadata.nlink() != 1
                {
                    return Err(InstallError::ExistingResidue);
                }
                return Ok(Self { file });
            }
            if Instant::now() >= deadline {
                return Err(InstallError::Io);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn matches_canonical_state(
        &self,
        state: &Path,
        expected_uid: u32,
    ) -> Result<(), InstallError> {
        let path = state.join(LOCK_NAME);
        let path_metadata =
            fs::symlink_metadata(&path).map_err(|_| InstallError::ExistingResidue)?;
        let held_metadata = self.file.metadata().map_err(|_| InstallError::Io)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.uid() != expected_uid
            || path_metadata.gid() != expected_uid
            || path_metadata.mode() & 0o7777 != 0o600
            || path_metadata.nlink() != 1
            || path_metadata.dev() != held_metadata.dev()
            || path_metadata.ino() != held_metadata.ino()
        {
            return Err(InstallError::ExistingResidue);
        }
        Ok(())
    }

    /// 只供已持有 stable lifecycle owner 的 legacy-absent admission 使用。
    /// 它建立/复验 private state，但绝不打开或 flock 新 legacy OFD。
    pub(crate) fn establish_state_without_legacy_lock(
        state: &Path,
        expected_uid: u32,
    ) -> Result<(), InstallError> {
        ensure_private_state(state, expected_uid)
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn try_clone(&self) -> Result<Self, InstallError> {
        self.file
            .try_clone()
            .map(|file| Self { file })
            .map_err(|_| InstallError::Io)
    }
}

impl Drop for ActivationLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

use std::os::fd::AsRawFd;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct OwnedPath {
    path: PathBuf,
    staged: Option<PathBuf>,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    digest: Option<String>,
    transaction_marker: Option<String>,
    marker_may_be_absent: bool,
    directory: bool,
    step: RollbackStep,
}

impl OwnedPath {
    pub fn capture(path: &Path, directory: bool, step: RollbackStep) -> Result<Self, InstallError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::Io)?;
        if metadata.file_type().is_symlink() || metadata.is_dir() != directory {
            return Err(InstallError::Io);
        }
        Ok(Self {
            path: path.to_owned(),
            staged: None,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
            size: metadata.len(),
            digest: (!directory).then(|| digest_file(path)).transpose()?,
            transaction_marker: if directory {
                fs::read_to_string(path.join(OWNERSHIP_MARKER)).ok()
            } else {
                None
            },
            marker_may_be_absent: false,
            directory,
            step,
        })
    }

    pub fn planned_from(
        staged: &Path,
        destination: &Path,
        directory: bool,
        step: RollbackStep,
    ) -> Result<Self, InstallError> {
        let metadata = fs::symlink_metadata(staged).map_err(|_| InstallError::Io)?;
        if metadata.file_type().is_symlink() || metadata.is_dir() != directory {
            return Err(InstallError::Io);
        }
        Ok(Self {
            path: destination.to_owned(),
            staged: Some(staged.to_owned()),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
            size: metadata.len(),
            digest: (!directory).then(|| digest_file(staged)).transpose()?,
            transaction_marker: directory
                .then(|| fs::read_to_string(staged.join(OWNERSHIP_MARKER)))
                .transpose()
                .map_err(|_| InstallError::Io)?,
            marker_may_be_absent: false,
            directory,
            step,
        })
    }

    pub fn still_owned(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            if self.device == 0 {
                return !metadata.file_type().is_symlink()
                    && metadata.is_dir()
                    && metadata.mode() & 0o777 == 0o700;
            }
            !metadata.file_type().is_symlink()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.is_dir() == self.directory
                && metadata.uid() == self.uid
                && metadata.gid() == self.gid
                && metadata.mode() & 0o7777 == self.mode
                && (self.directory || metadata.len() == self.size)
                && self
                    .digest
                    .as_ref()
                    .is_none_or(|expected| digest_file(&self.path).as_ref() == Ok(expected))
                && self.marker_matches(&self.path)
        })
    }

    fn matches_systemd_projection(
        &self,
        projection: &SystemdProbeStateProjection,
        directory: SystemdProbeDirectory,
    ) -> bool {
        let Ok(facts) = projection.facts(directory) else {
            return false;
        };
        self.projected_directory_facts_match(facts)
            && self.transaction_marker.as_ref().is_none_or(|expected| {
                match projection.read_file(directory, std::ffi::OsStr::new(OWNERSHIP_MARKER)) {
                    Ok(actual) => actual == expected.as_bytes(),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        self.marker_may_be_absent
                    }
                    Err(_) => false,
                }
            })
    }

    fn projected_directory_facts_match(&self, facts: HeldDirectoryFacts) -> bool {
        self.directory
            && facts.device == self.device
            && facts.inode == self.inode
            && facts.mode == self.mode
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn directory(&self) -> bool {
        self.directory
    }

    pub fn step(&self) -> RollbackStep {
        self.step
    }

    fn marker_matches(&self, directory: &Path) -> bool {
        self.transaction_marker.as_ref().is_none_or(|expected| {
            match fs::read_to_string(directory.join(OWNERSHIP_MARKER)) {
                Ok(actual) => actual == *expected,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.marker_may_be_absent
                }
                Err(_) => false,
            }
        })
    }

    pub fn remove_owned_staging(&self) -> Result<(), InstallError> {
        let Some(path) = &self.staged else {
            return Ok(());
        };
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(InstallError::Io),
        };
        let receipt_matches = !metadata.file_type().is_symlink()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.is_dir() == self.directory
            && metadata.uid() == self.uid
            && metadata.gid() == self.gid
            && metadata.mode() & 0o7777 == self.mode
            && (self.directory || metadata.len() == self.size)
            && self
                .digest
                .as_ref()
                .is_none_or(|expected| digest_file(path).as_ref() == Ok(expected))
            && self.marker_matches(path);
        if !receipt_matches {
            return Err(InstallError::ExistingResidue);
        }
        if self.directory {
            remove_tree_durable(path)
        } else {
            fs::remove_file(path).map_err(|_| InstallError::Io)?;
            sync_parent(path)
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct JournalState {
    schema_version: u8,
    transaction_id: String,
    #[serde(default)]
    resume_binding: Option<String>,
    identity: Option<(u32, u32)>,
    #[serde(default)]
    observation_ipc_group_may_exist: bool,
    enabled_may_exist: bool,
    started_may_exist: bool,
    staging: OwnedPath,
    paths: Vec<OwnedPath>,
}

pub(super) struct TransactionJournal {
    path: PathBuf,
    state: JournalState,
}

impl TransactionJournal {
    #[cfg(test)]
    pub fn begin(state_directory: &Path) -> Result<Self, InstallError> {
        Self::begin_with_binding(state_directory, None)
    }

    pub fn begin_with_binding(
        state_directory: &Path,
        resume_binding: Option<&str>,
    ) -> Result<Self, InstallError> {
        Self::begin_with_stage(state_directory, resume_binding, |path| fs::create_dir(path))
    }

    fn begin_with_stage(
        state_directory: &Path,
        resume_binding: Option<&str>,
        mut create_stage: impl FnMut(&Path) -> std::io::Result<()>,
    ) -> Result<Self, InstallError> {
        if state_directory.join(LAYOUT_NAME).exists() {
            return Err(InstallError::ExistingResidue);
        }
        let transaction_id = transaction_id()?;
        let staging_path = state_directory.join(format!("{STAGING_NAME}-{transaction_id}"));
        let journal = Self {
            path: state_directory.join(JOURNAL_NAME),
            state: JournalState {
                schema_version: 3,
                transaction_id,
                resume_binding: resume_binding.map(ToOwned::to_owned),
                identity: None,
                observation_ipc_group_may_exist: false,
                enabled_may_exist: false,
                started_may_exist: false,
                // 先持久化唯一路径 intent；它是事务开始后的首份可恢复证据。
                staging: OwnedPath {
                    path: staging_path.clone(),
                    staged: None,
                    device: 0,
                    inode: 0,
                    uid: 0,
                    gid: 0,
                    mode: 0,
                    size: 0,
                    digest: None,
                    transaction_marker: None,
                    marker_may_be_absent: false,
                    directory: true,
                    step: RollbackStep::RemoveTemporary,
                },
                paths: Vec::new(),
            },
        };
        match fs::symlink_metadata(&journal.path) {
            Ok(_) => return Err(InstallError::ExistingResidue),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(InstallError::Io),
        }
        journal.persist()?;
        if let Err(error) = create_stage(&staging_path) {
            let _ = journal.remove();
            return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                InstallError::ExistingResidue
            } else {
                InstallError::Io
            });
        }
        fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700))
            .map_err(|_| InstallError::Io)
            .and_then(|()| sync_parent(&staging_path))?;
        let staging = OwnedPath::capture(&staging_path, true, RollbackStep::RemoveTemporary)?;
        let journal = Self {
            state: JournalState {
                staging,
                ..journal.state
            },
            ..journal
        };
        journal.persist()?;
        Ok(journal)
    }

    pub fn load(state_directory: &Path) -> Result<Option<Self>, InstallError> {
        remove_unpublished_journal_candidates(state_directory)?;
        let path = state_directory.join(JOURNAL_NAME);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(InstallError::Io),
            Ok(_) => {}
        }
        let state_metadata = fs::symlink_metadata(state_directory).map_err(|_| InstallError::Io)?;
        let contents = super::installed_layout::trusted_text(
            &path,
            state_metadata.uid(),
            state_metadata.gid(),
            0o600,
        )?;
        let state: JournalState = serde_json::from_str(&contents).map_err(|_| InstallError::Io)?;
        let valid_transaction_id = state.transaction_id.len() == 32
            && state
                .transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if !matches!(state.schema_version, 2 | 3)
            || !valid_transaction_id
            || state.staging.path
                != state_directory.join(format!("{STAGING_NAME}-{}", state.transaction_id))
        {
            return Err(InstallError::ExistingResidue);
        }
        Ok(Some(Self { path, state }))
    }

    pub fn layout_is_committed(state_directory: &Path) -> Result<bool, InstallError> {
        let path = state_directory.join(LAYOUT_NAME);
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
            Ok(_) => Err(InstallError::ExistingResidue),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(InstallError::Io),
        }
    }

    pub fn record_identity(&mut self, uid: u32, gid: u32) -> Result<(), InstallError> {
        self.state.identity = Some((uid, gid));
        self.persist()
    }

    pub fn record_observation_ipc_group_intent(&mut self) -> Result<(), InstallError> {
        self.state.observation_ipc_group_may_exist = true;
        self.persist()
    }

    pub fn observation_ipc_group_may_exist(&self) -> bool {
        self.state.observation_ipc_group_may_exist
    }

    pub fn transaction_id(&self) -> &str {
        &self.state.transaction_id
    }

    pub fn matches_resume_binding(&self, expected: &str) -> bool {
        self.state.schema_version == 3 && self.state.resume_binding.as_deref() == Some(expected)
    }

    pub fn has_resume_binding(&self) -> bool {
        self.state.resume_binding.is_some()
    }

    pub fn record_path(&mut self, path: OwnedPath) -> Result<(), InstallError> {
        self.state.paths.push(path);
        self.persist()
    }

    pub fn record_enabled_intent(&mut self) -> Result<(), InstallError> {
        self.state.enabled_may_exist = true;
        self.persist()
    }

    pub fn record_started_intent(&mut self) -> Result<(), InstallError> {
        self.state.started_may_exist = true;
        self.persist()
    }

    pub fn identity(&self) -> Option<(u32, u32)> {
        self.state.identity
    }

    pub fn paths(&self) -> &[OwnedPath] {
        &self.state.paths
    }

    pub fn all_published_paths_are_owned(&self) -> bool {
        self.state.paths.iter().all(OwnedPath::still_owned)
    }

    pub fn all_published_paths_except_are_owned(&self, mutable: &Path) -> bool {
        self.state
            .paths
            .iter()
            .filter(|owned| owned.path() != mutable)
            .all(OwnedPath::still_owned)
    }

    pub fn published_path_is_owned(&self, path: &Path) -> bool {
        self.state
            .paths
            .iter()
            .find(|owned| owned.path() == path)
            .is_some_and(OwnedPath::still_owned)
    }

    pub fn published_path_is_recorded(&self, path: &Path) -> bool {
        self.state.paths.iter().any(|owned| owned.path() == path)
    }

    pub fn owns_published_path(&self, path: &Path) -> Result<bool, InstallError> {
        match self.state.paths.iter().find(|owned| owned.path() == path) {
            Some(owned) if owned.still_owned() => Ok(true),
            Some(_) => Err(InstallError::ExistingResidue),
            None => Ok(false),
        }
    }

    pub fn staging_directory(&self) -> &Path {
        self.state.staging.path()
    }

    pub fn remove_staging_if_owned(&self) -> Result<(), InstallError> {
        if !self.state.staging.still_owned() {
            return if self.state.staging.path().exists() {
                Err(InstallError::ExistingResidue)
            } else {
                Ok(())
            };
        }
        remove_tree_durable(self.state.staging.path())
    }

    pub fn enabled_may_exist(&self) -> bool {
        self.state.enabled_may_exist
    }

    pub fn started_may_exist(&self) -> bool {
        self.state.started_may_exist
    }

    pub fn commit_layout(
        &mut self,
        paths: &super::FixedInstallPaths,
        version: &str,
        retain_journal: bool,
    ) -> Result<(), InstallError> {
        self.remove_staging_if_owned()?;
        self.retire_directory_markers(paths)?;
        let layout = paths.bootstrap_state().join(LAYOUT_NAME);
        atomic_replace(
            &layout,
            format!("schema_version=1\nversion={version}\n").as_bytes(),
        )?;
        // `current-layout` 是成功的唯一提交点；其后 journal 清理失败由下次启动完成。
        if !retain_journal {
            let _ = self.remove();
        }
        Ok(())
    }

    fn retire_directory_markers(
        &mut self,
        paths: &super::FixedInstallPaths,
    ) -> Result<(), InstallError> {
        let projection = self.systemd_state_projection(paths)?;
        for index in 0..self.state.paths.len() {
            if self.state.paths[index].transaction_marker.is_none() {
                continue;
            }
            let projected_directory = projection.as_ref().and_then(|projection| {
                if self.state.paths[index].path == paths.state() {
                    Some((projection, SystemdProbeDirectory::State))
                } else if self.state.paths[index].path == paths.identity_dir() {
                    Some((projection, SystemdProbeDirectory::Identity))
                } else {
                    None
                }
            });
            let owned = match projected_directory {
                Some((projection, directory)) => {
                    self.state.paths[index].matches_systemd_projection(projection, directory)
                }
                None => self.state.paths[index].still_owned(),
            };
            if !owned {
                return Err(InstallError::ExistingResidue);
            }
            // 先持久化“marker 可已删除”的 intent；任一点重启都仍能认领同一 receipt。
            self.state.paths[index].marker_may_be_absent = true;
            self.persist()?;
            let removal = match projected_directory {
                Some((projection, directory)) => {
                    projection.remove_file(directory, std::ffi::OsStr::new(OWNERSHIP_MARKER))
                }
                None => {
                    let marker = self.state.paths[index].path.join(OWNERSHIP_MARKER);
                    fs::remove_file(&marker).and_then(|()| {
                        File::open(&self.state.paths[index].path)
                            .and_then(|directory| directory.sync_all())
                    })
                }
            };
            match removal {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(InstallError::Io),
            }
        }
        Ok(())
    }

    fn systemd_state_projection(
        &self,
        paths: &super::FixedInstallPaths,
    ) -> Result<Option<SystemdProbeStateProjection>, InstallError> {
        let metadata = fs::symlink_metadata(paths.state()).map_err(|_| InstallError::Io)?;
        if !metadata.file_type().is_symlink() {
            return Ok(None);
        }
        let projection = open_systemd_probe_state_projection_for_finalization(
            &paths.state(),
            (paths.expected_root_uid(), paths.expected_root_gid()),
        )
        .map_err(|_| InstallError::ExistingResidue)?;
        let observed = projection.owner();
        let receipt = paths.identity_owner_receipt(super::ServiceIdentity {
            uid: observed.0,
            gid: observed.1,
        });
        if receipt.uid == paths.expected_root_uid() || receipt.gid == paths.expected_root_gid() {
            return Err(InstallError::ExistingResidue);
        }
        let original_owner = self.state.identity.ok_or(InstallError::ExistingResidue)?;
        for (path, directory) in [
            (paths.state(), SystemdProbeDirectory::State),
            (paths.identity_dir(), SystemdProbeDirectory::Identity),
        ] {
            let mut receipts = self.state.paths.iter().filter(|owned| owned.path == path);
            let owned = receipts.next().ok_or(InstallError::ExistingResidue)?;
            if receipts.next().is_some()
                || !owned.directory
                || (owned.uid, owned.gid) != original_owner
                || !owned.matches_systemd_projection(&projection, directory)
            {
                return Err(InstallError::ExistingResidue);
            }
        }
        Ok(Some(projection))
    }

    pub fn remove(&self) -> Result<(), InstallError> {
        match fs::remove_file(&self.path) {
            Ok(()) => sync_parent(&self.path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(InstallError::Io),
        }
    }

    fn persist(&self) -> Result<(), InstallError> {
        let bytes = serde_json::to_vec(&self.state).map_err(|_| InstallError::Io)?;
        atomic_replace(&self.path, &bytes)
    }
}

fn digest_file(path: &Path) -> Result<String, InstallError> {
    let bytes = fs::read(path).map_err(|_| InstallError::Io)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn transaction_id() -> Result<String, InstallError> {
    let mut bytes = [0_u8; 16];
    let read = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if read != bytes.len() as isize {
        return Err(InstallError::Io);
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn ensure_private_state(path: &Path, expected_uid: u32) -> Result<(), InstallError> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| InstallError::Io)?;
            sync_parent(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(InstallError::Io),
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), InstallError> {
    crate::secure_file::atomic_write(path, bytes, 0o600, None).map_err(|_| InstallError::Io)
}

fn remove_unpublished_journal_candidates(state: &Path) -> Result<(), InstallError> {
    let prefix = format!(".{JOURNAL_NAME}-");
    for entry in fs::read_dir(state).map_err(|_| InstallError::Io)? {
        let entry = entry.map_err(|_| InstallError::Io)?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(&prefix) {
            let suffix = name.to_string_lossy()[prefix.len()..].to_owned();
            if suffix.len() != 32
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(InstallError::ExistingResidue);
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| InstallError::Io)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(InstallError::ExistingResidue);
            }
            fs::remove_file(entry.path()).map_err(|_| InstallError::Io)?;
            File::open(state)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| InstallError::Io)?;
        }
    }
    Ok(())
}

fn remove_tree_durable(path: &Path) -> Result<(), InstallError> {
    for entry in fs::read_dir(path).map_err(|_| InstallError::Io)? {
        let entry = entry.map_err(|_| InstallError::Io)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| InstallError::Io)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            remove_tree_durable(&entry.path())?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            fs::remove_file(entry.path()).map_err(|_| InstallError::Io)?;
            File::open(path)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| InstallError::Io)?;
        } else {
            return Err(InstallError::ExistingResidue);
        }
    }
    fs::remove_dir(path).map_err(|_| InstallError::Io)?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), InstallError> {
    File::open(path.parent().ok_or(InstallError::Io)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InstallError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::symlink, sync::mpsc};
    use tempfile::tempdir;

    struct ProjectedJournalFixture {
        _root: tempfile::TempDir,
        paths: super::super::FixedInstallPaths,
        private_state: PathBuf,
        journal: TransactionJournal,
    }

    fn projected_journal_fixture() -> ProjectedJournalFixture {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        for parent in ["var/lib", "var/lib/enoki-probe-bootstrap"] {
            fs::create_dir_all(root.path().join(parent)).unwrap();
            fs::set_permissions(
                root.path().join(parent),
                fs::Permissions::from_mode(if parent.ends_with("bootstrap") {
                    0o700
                } else {
                    0o755
                }),
            )
            .unwrap();
        }
        let paths = super::super::FixedInstallPaths::under(root.path());
        fs::create_dir(paths.state()).unwrap();
        fs::set_permissions(paths.state(), fs::Permissions::from_mode(0o750)).unwrap();
        fs::create_dir(paths.identity_dir()).unwrap();
        fs::set_permissions(paths.identity_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal = TransactionJournal::begin(&paths.bootstrap_state()).unwrap();
        journal
            .record_identity(unsafe { libc::geteuid() }, unsafe { libc::getegid() })
            .unwrap();
        for (path, step) in [
            (paths.state(), RollbackStep::RemoveStateDirectory),
            (paths.identity_dir(), RollbackStep::RemoveIdentityDirectory),
        ] {
            let marker = path.join(OWNERSHIP_MARKER);
            fs::write(&marker, journal.transaction_id()).unwrap();
            fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
            journal
                .record_path(OwnedPath::capture(&path, true, step).unwrap())
                .unwrap();
        }
        let private = root.path().join("var/lib/private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let private_state = private.join("enoki-probe");
        fs::rename(paths.state(), &private_state).unwrap();
        symlink("private/enoki-probe", paths.state()).unwrap();
        ProjectedJournalFixture {
            _root: root,
            paths,
            private_state,
            journal,
        }
    }

    fn ordinary_pre_existing_metadata_fixture() -> (
        tempfile::TempDir,
        super::super::FixedInstallPaths,
        TransactionJournal,
    ) {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        for (path, mode) in [
            ("var", 0o755),
            ("var/lib", 0o755),
            ("var/lib/enoki-probe-bootstrap", 0o700),
            ("etc", 0o755),
            ("etc/enoki", 0o755),
        ] {
            fs::create_dir(root.path().join(path)).unwrap();
            fs::set_permissions(root.path().join(path), fs::Permissions::from_mode(mode)).unwrap();
        }
        let paths = super::super::FixedInstallPaths::under(root.path());
        if unsafe { libc::geteuid() } == 0 {
            std::os::unix::fs::chown(paths.etc_enoki(), None, Some(1)).unwrap();
        }
        let mut journal = TransactionJournal::begin(&paths.bootstrap_state()).unwrap();
        assert!(
            !super::super::filesystem::ensure_fixed_metadata_directory(
                &paths.etc_enoki(),
                &mut journal,
            )
            .unwrap()
        );
        (root, paths, journal)
    }

    #[test]
    fn ordinary_transaction_does_not_persist_or_own_a_pre_existing_metadata_directory() {
        let (_root, paths, journal) = ordinary_pre_existing_metadata_fixture();
        let encoded: serde_json::Value =
            serde_json::from_slice(&fs::read(paths.bootstrap_state().join(JOURNAL_NAME)).unwrap())
                .unwrap();
        assert!(encoded["paths"].as_array().unwrap().is_empty());
        assert!(encoded.get("pre_existing_paths").is_none());
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(fs::symlink_metadata(paths.etc_enoki()).unwrap().gid(), 1);
        }
        drop(journal);

        let recovered = TransactionJournal::load(&paths.bootstrap_state())
            .unwrap()
            .unwrap();
        recovered.remove_staging_if_owned().unwrap();
        recovered.remove().unwrap();

        assert!(paths.etc_enoki().is_dir());
    }

    #[test]
    fn rollback_removes_only_owned_children_of_pre_existing_metadata_directory() {
        let (_root, paths, mut journal) = ordinary_pre_existing_metadata_fixture();
        let child = paths.etc_enoki().join("probe-install.toml");
        fs::write(&child, b"candidate").unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o600)).unwrap();
        journal
            .record_path(
                OwnedPath::capture(&child, false, RollbackStep::RemoveInstallMetadata).unwrap(),
            )
            .unwrap();
        let mut failures = Vec::new();
        super::super::cleanup_owned_paths(
            &mut super::super::SystemInstallFiles,
            &journal,
            &mut failures,
        );

        assert!(failures.is_empty());
        assert!(!child.exists());
        assert!(paths.etc_enoki().is_dir());
    }

    #[test]
    fn transaction_created_metadata_directory_remains_owned_by_rollback() {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        for (path, mode) in [
            ("var", 0o755),
            ("var/lib", 0o755),
            ("var/lib/enoki-probe-bootstrap", 0o700),
            ("etc", 0o755),
        ] {
            fs::create_dir(root.path().join(path)).unwrap();
            fs::set_permissions(root.path().join(path), fs::Permissions::from_mode(mode)).unwrap();
        }
        let paths = super::super::FixedInstallPaths::under(root.path());
        let mut journal = TransactionJournal::begin(&paths.bootstrap_state()).unwrap();
        assert!(
            super::super::filesystem::ensure_fixed_metadata_directory(
                &paths.etc_enoki(),
                &mut journal,
            )
            .unwrap()
        );
        assert!(journal.published_path_is_recorded(&paths.etc_enoki()));
        let mut failures = Vec::new();
        super::super::cleanup_owned_paths(
            &mut super::super::SystemInstallFiles,
            &journal,
            &mut failures,
        );

        assert!(failures.is_empty());
        assert!(!paths.etc_enoki().exists());
    }

    #[test]
    fn commit_retires_exact_systemd_state_projection_markers() {
        let mut fixture = projected_journal_fixture();

        fixture
            .journal
            .commit_layout(&fixture.paths, "1.2.3", true)
            .unwrap();

        assert!(!fixture.private_state.join(OWNERSHIP_MARKER).exists());
        assert!(
            !fixture
                .private_state
                .join("identity")
                .join(OWNERSHIP_MARKER)
                .exists()
        );
        assert_eq!(
            fs::read_to_string(fixture.paths.bootstrap_state().join(LAYOUT_NAME)).unwrap(),
            "schema_version=1\nversion=1.2.3\n"
        );
    }

    #[test]
    fn projected_marker_retirement_resumes_before_and_after_unlink() {
        for marker_was_removed in [false, true] {
            let mut fixture = projected_journal_fixture();
            for owned in &mut fixture.journal.state.paths {
                owned.marker_may_be_absent = true;
            }
            fixture.journal.persist().unwrap();
            if marker_was_removed {
                fs::remove_file(fixture.private_state.join(OWNERSHIP_MARKER)).unwrap();
                fs::remove_file(
                    fixture
                        .private_state
                        .join("identity")
                        .join(OWNERSHIP_MARKER),
                )
                .unwrap();
            }
            drop(fixture.journal);
            let mut recovered = TransactionJournal::load(&fixture.paths.bootstrap_state())
                .unwrap()
                .unwrap();

            recovered
                .commit_layout(&fixture.paths, "1.2.3", true)
                .unwrap();

            assert!(fixture.paths.bootstrap_state().join(LAYOUT_NAME).exists());
        }
    }

    #[test]
    fn projected_marker_retirement_rejects_custody_tamper_without_deleting_markers() {
        for tamper in ["link", "private", "state", "identity", "marker"] {
            let mut fixture = projected_journal_fixture();
            match tamper {
                "link" => {
                    fs::remove_file(fixture.paths.state()).unwrap();
                    symlink("private/../private/enoki-probe", fixture.paths.state()).unwrap();
                }
                "private" => fs::set_permissions(
                    fixture.private_state.parent().unwrap(),
                    fs::Permissions::from_mode(0o777),
                )
                .unwrap(),
                "state" => {
                    fs::set_permissions(&fixture.private_state, fs::Permissions::from_mode(0o770))
                        .unwrap()
                }
                "identity" => fs::set_permissions(
                    fixture.private_state.join("identity"),
                    fs::Permissions::from_mode(0o770),
                )
                .unwrap(),
                "marker" => fs::write(
                    fixture.private_state.join(OWNERSHIP_MARKER),
                    "another-transaction",
                )
                .unwrap(),
                _ => unreachable!(),
            }

            assert_eq!(
                fixture.journal.commit_layout(&fixture.paths, "1.2.3", true),
                Err(InstallError::ExistingResidue),
                "tamper {tamper} must fail closed"
            );
            assert!(!fixture.paths.bootstrap_state().join(LAYOUT_NAME).exists());
            assert!(
                fixture
                    .private_state
                    .join("identity")
                    .join(OWNERSHIP_MARKER)
                    .exists()
            );
        }
    }

    #[test]
    fn fresh_activation_lock_serializes_ordinary_concurrent_attempts() {
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let first = ActivationLock::acquire(
            &state,
            unsafe { libc::geteuid() },
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let (sent, received) = mpsc::channel();
        let worker_state = state.clone();
        let worker = std::thread::spawn(move || {
            let second = ActivationLock::acquire(
                &worker_state,
                unsafe { libc::geteuid() },
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            sent.send(()).unwrap();
            drop(second);
        });
        assert!(received.recv_timeout(Duration::from_millis(40)).is_err());
        drop(first);
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn activation_lock_rejects_a_symlink_without_changing_its_target() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.path().join("target");
        fs::write(&target, "unchanged").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, state.join(LOCK_NAME)).unwrap();

        assert_eq!(
            ActivationLock::acquire(
                &state,
                unsafe { libc::geteuid() },
                Instant::now() + Duration::from_millis(20),
            )
            .map(|_| ()),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn journal_loader_rejects_a_symlink_as_closed_residue() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.path().join("journal-target");
        fs::write(&target, "external").unwrap();
        symlink(&target, state.join(JOURNAL_NAME)).unwrap();

        assert!(matches!(
            TransactionJournal::load(&state),
            Err(InstallError::ExistingResidue)
        ));
        assert_eq!(fs::read_to_string(target).unwrap(), "external");
    }

    #[test]
    fn journal_round_trip_preserves_typed_ownership_for_restart_recovery() {
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let owned = root.path().join("owned");
        fs::write(&owned, "owned").unwrap();
        let mut journal = TransactionJournal::begin(&state).unwrap();
        journal
            .record_path(OwnedPath::capture(&owned, false, RollbackStep::RemoveBinary).unwrap())
            .unwrap();
        drop(journal);

        let recovered = TransactionJournal::load(&state).unwrap().unwrap();
        assert!(recovered.paths()[0].still_owned());
        let replacement = root.path().join("replacement");
        fs::write(&replacement, "replacement").unwrap();
        fs::rename(&replacement, &owned).unwrap();
        assert!(!recovered.paths()[0].still_owned());
    }

    #[test]
    fn content_change_invalidates_a_path_receipt_even_when_identity_is_unchanged() {
        let root = tempdir().unwrap();
        let owned = root.path().join("owned");
        fs::write(&owned, "first").unwrap();
        let receipt = OwnedPath::capture(&owned, false, RollbackStep::RemoveBinary).unwrap();

        fs::write(&owned, "other").unwrap();

        assert!(!receipt.still_owned());
    }

    #[test]
    fn restart_cleans_a_predeclared_stage_that_was_not_published() {
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let staged = root.path().join("staged");
        let destination = root.path().join("destination");
        fs::write(&staged, "staged").unwrap();
        let mut journal = TransactionJournal::begin(&state).unwrap();
        journal
            .record_path(
                OwnedPath::planned_from(&staged, &destination, false, RollbackStep::RemoveBinary)
                    .unwrap(),
            )
            .unwrap();
        drop(journal);

        let recovered = TransactionJournal::load(&state).unwrap().unwrap();
        assert!(!recovered.paths()[0].still_owned());
        recovered.paths()[0].remove_owned_staging().unwrap();
        assert!(!staged.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn journal_intent_is_durable_before_the_stage_becomes_visible() {
        let root = tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = state.join(JOURNAL_NAME);

        let journal = TransactionJournal::begin_with_stage(&state, None, |stage| {
            assert!(journal_path.is_file());
            let bytes = fs::read(&journal_path).unwrap();
            let persisted: JournalState = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(persisted.schema_version, 3);
            assert_eq!(persisted.staging.path(), stage);
            fs::create_dir(stage)
        })
        .unwrap();

        journal.remove_staging_if_owned().unwrap();
        journal.remove().unwrap();
    }
}
