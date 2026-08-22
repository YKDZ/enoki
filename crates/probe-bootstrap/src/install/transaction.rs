use super::{InstallError, RollbackStep};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const LOCK_NAME: &str = "activation.lock";
const JOURNAL_NAME: &str = "activation-journal.json";
const LAYOUT_NAME: &str = "current-layout";
const STAGING_NAME: &str = "activation-stage";

pub(super) struct ActivationLock {
    file: File,
}

impl ActivationLock {
    pub fn acquire(
        state: &Path,
        expected_uid: u32,
        deadline: Instant,
    ) -> Result<Self, InstallError> {
        ensure_private_state(state, expected_uid)?;
        let path = state.join(LOCK_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|_| InstallError::Io)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| InstallError::Io)?;
        let metadata = file.metadata().map_err(|_| InstallError::Io)?;
        if !metadata.is_file() || metadata.uid() != expected_uid || metadata.mode() & 0o777 != 0o600
        {
            return Err(InstallError::Io);
        }
        loop {
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                return Ok(Self { file });
            }
            if Instant::now() >= deadline {
                return Err(InstallError::Io);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
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
            directory,
            step,
        })
    }

    pub fn still_owned(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            !metadata.file_type().is_symlink()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.is_dir() == self.directory
        })
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

    pub fn remove_owned_staging(&self) -> Result<(), InstallError> {
        let Some(path) = &self.staged else {
            return Ok(());
        };
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(InstallError::Io),
        };
        if metadata.file_type().is_symlink()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.is_dir() != self.directory
        {
            return Err(InstallError::ExistingResidue);
        }
        if self.directory {
            fs::remove_dir(path).map_err(|_| InstallError::Io)
        } else {
            fs::remove_file(path).map_err(|_| InstallError::Io)
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct JournalState {
    schema_version: u8,
    identity: Option<(u32, u32)>,
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
    pub fn begin(state_directory: &Path) -> Result<Self, InstallError> {
        if state_directory.join(LAYOUT_NAME).exists() {
            return Err(InstallError::ExistingResidue);
        }
        let staging_path = state_directory.join(STAGING_NAME);
        fs::create_dir(&staging_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                InstallError::ExistingResidue
            } else {
                InstallError::Io
            }
        })?;
        fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700))
            .map_err(|_| InstallError::Io)?;
        sync_parent(&staging_path)?;
        let staging = OwnedPath::capture(&staging_path, true, RollbackStep::RemoveTemporary)?;
        let journal = Self {
            path: state_directory.join(JOURNAL_NAME),
            state: JournalState {
                schema_version: 1,
                identity: None,
                enabled_may_exist: false,
                started_may_exist: false,
                staging,
                paths: Vec::new(),
            },
        };
        if journal.path.exists() {
            return Err(InstallError::ExistingResidue);
        }
        journal.persist()?;
        Ok(journal)
    }

    pub fn load(state_directory: &Path) -> Result<Option<Self>, InstallError> {
        let path = state_directory.join(JOURNAL_NAME);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(InstallError::Io),
        };
        let state: JournalState = serde_json::from_slice(&bytes).map_err(|_| InstallError::Io)?;
        if state.schema_version != 1 {
            return Err(InstallError::Io);
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
        fs::remove_dir_all(self.state.staging.path()).map_err(|_| InstallError::Io)?;
        sync_parent(self.state.staging.path())
    }

    pub fn enabled_may_exist(&self) -> bool {
        self.state.enabled_may_exist
    }

    pub fn started_may_exist(&self) -> bool {
        self.state.started_may_exist
    }

    pub fn commit_layout(&self, state_directory: &Path, version: &str) -> Result<(), InstallError> {
        self.remove_staging_if_owned()?;
        let layout = state_directory.join(LAYOUT_NAME);
        atomic_replace(
            &layout,
            format!("schema_version=1\nversion={version}\n").as_bytes(),
        )?;
        // `current-layout` 是成功的唯一提交点；其后 journal 清理失败由下次启动完成。
        let _ = self.remove();
        Ok(())
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
        return Err(InstallError::Io);
    }
    Ok(())
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    let temporary = parent.join(format!(".{}-{}", JOURNAL_NAME, std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| InstallError::Io)?;
    let result = (|| {
        file.write_all(bytes).map_err(|_| InstallError::Io)?;
        file.sync_all().map_err(|_| InstallError::Io)?;
        fs::rename(&temporary, path).map_err(|_| InstallError::Io)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn sync_parent(path: &Path) -> Result<(), InstallError> {
    File::open(path.parent().ok_or(InstallError::Io)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InstallError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tempfile::tempdir;

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
}
