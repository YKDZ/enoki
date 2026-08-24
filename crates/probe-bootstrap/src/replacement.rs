use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_COMMIT_FACT_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplacementIntent {
    pub enrollment_id: String,
    pub enrollment_token_sha256: String,
    pub host_id: String,
    pub hub_origin: String,
    pub old_probe_id: String,
    pub source_probe_version: String,
    pub source_probe_sha256: String,
    pub target_probe_version: String,
    pub target_asset_set_digest: String,
    pub target_manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplacementCommitFact {
    pub schema_version: u8,
    pub canonical_intent_sha256: String,
    pub intent: ReplacementIntent,
    pub cleanup_complete: bool,
    pub candidate_layout_complete: bool,
}

pub trait ReplacementCommitStore {
    type Error;

    fn load(&mut self) -> Result<Option<ReplacementCommitFact>, Self::Error>;
    fn persist(&mut self, fact: &ReplacementCommitFact) -> Result<(), Self::Error>;
}

pub trait ReplacementCleanup {
    type Error;

    fn cleanup_old_installation(&mut self) -> Result<(), Self::Error>;
}

impl<F, E> ReplacementCleanup for F
where
    F: FnMut() -> Result<(), E>,
{
    type Error = E;
    fn cleanup_old_installation(&mut self) -> Result<(), Self::Error> {
        self()
    }
}

pub struct FileReplacementCommitStore {
    path: PathBuf,
    expected_owner_uid: u32,
}

impl FileReplacementCommitStore {
    pub fn at(path: impl Into<PathBuf>, expected_owner_uid: u32) -> Self {
        Self {
            path: path.into(),
            expected_owner_uid,
        }
    }
}

impl ReplacementCommitStore for FileReplacementCommitStore {
    type Error = std::io::Error;

    fn load(&mut self) -> Result<Option<ReplacementCommitFact>, Self::Error> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.expected_owner_uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > MAX_COMMIT_FACT_BYTES
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid replacement commit fact",
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_COMMIT_FACT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_COMMIT_FACT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "replacement commit fact is too large",
            ));
        }
        let fact: ReplacementCommitFact = serde_json::from_slice(&bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid replacement commit fact",
            )
        })?;
        if fact.schema_version != 1
            || canonical_intent_sha256(&fact.intent).ok().as_deref()
                != Some(&fact.canonical_intent_sha256)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid replacement commit binding",
            ));
        }
        Ok(Some(fact))
    }

    fn persist(&mut self, fact: &ReplacementCommitFact) -> Result<(), Self::Error> {
        let parent = self.path.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing commit parent")
        })?;
        validate_private_parent(parent, self.expected_owner_uid)?;
        let bytes = serde_json::to_vec(fact).map_err(std::io::Error::other)?;
        if bytes.len() as u64 > MAX_COMMIT_FACT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "replacement commit fact is too large",
            ));
        }
        crate::secure_file::atomic_write(&self.path, &bytes, 0o600, None)
    }
}

fn validate_private_parent(path: &Path, expected_owner_uid: u32) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "replacement commit parent is not root-private",
        ));
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub enum ReplacementCommitError<StoreError, EffectError> {
    Store(StoreError),
    Effect(EffectError),
    ConflictingCommit,
}

pub fn commit_and_cleanup_replacement<S, E>(
    intent: ReplacementIntent,
    store: &mut S,
    cleanup: &mut E,
) -> Result<ReplacementCommitFact, ReplacementCommitError<S::Error, E::Error>>
where
    S: ReplacementCommitStore,
    E: ReplacementCleanup,
{
    let digest =
        canonical_intent_sha256(&intent).map_err(|_| ReplacementCommitError::ConflictingCommit)?;
    let mut fact = match store.load().map_err(ReplacementCommitError::Store)? {
        Some(existing)
            if existing.schema_version == 1
                && existing.canonical_intent_sha256 == digest
                && existing.intent == intent =>
        {
            existing
        }
        Some(existing) if existing.candidate_layout_complete => {
            let committed = ReplacementCommitFact {
                schema_version: 1,
                canonical_intent_sha256: digest,
                intent,
                cleanup_complete: false,
                candidate_layout_complete: false,
            };
            store
                .persist(&committed)
                .map_err(ReplacementCommitError::Store)?;
            committed
        }
        Some(_) => return Err(ReplacementCommitError::ConflictingCommit),
        None => {
            let committed = ReplacementCommitFact {
                schema_version: 1,
                canonical_intent_sha256: digest,
                intent,
                cleanup_complete: false,
                candidate_layout_complete: false,
            };
            store
                .persist(&committed)
                .map_err(ReplacementCommitError::Store)?;
            committed
        }
    };
    if !fact.cleanup_complete {
        cleanup
            .cleanup_old_installation()
            .map_err(ReplacementCommitError::Effect)?;
        fact.cleanup_complete = true;
        store
            .persist(&fact)
            .map_err(ReplacementCommitError::Store)?;
    }
    Ok(fact)
}

pub fn record_replacement_candidate_layout<S: ReplacementCommitStore>(
    store: &mut S,
    expected_intent_sha256: &str,
) -> Result<ReplacementCommitFact, ReplacementCommitError<S::Error, std::convert::Infallible>> {
    let Some(mut fact) = store.load().map_err(ReplacementCommitError::Store)? else {
        return Err(ReplacementCommitError::ConflictingCommit);
    };
    if fact.canonical_intent_sha256 != expected_intent_sha256 || !fact.cleanup_complete {
        return Err(ReplacementCommitError::ConflictingCommit);
    }
    if !fact.candidate_layout_complete {
        fact.candidate_layout_complete = true;
        store
            .persist(&fact)
            .map_err(ReplacementCommitError::Store)?;
    }
    Ok(fact)
}

fn canonical_intent_sha256(intent: &ReplacementIntent) -> Result<String, serde_json::Error> {
    serde_json::to_vec(intent).map(|bytes| format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[derive(Default)]
    struct Store {
        fact: Option<ReplacementCommitFact>,
        fail_persist: bool,
        writes: usize,
    }

    impl ReplacementCommitStore for Store {
        type Error = &'static str;
        fn load(&mut self) -> Result<Option<ReplacementCommitFact>, Self::Error> {
            Ok(self.fact.clone())
        }
        fn persist(&mut self, fact: &ReplacementCommitFact) -> Result<(), Self::Error> {
            self.writes += 1;
            if self.fail_persist {
                return Err("persist failed");
            }
            self.fact = Some(fact.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct Cleanup {
        calls: usize,
        fail: bool,
    }

    impl ReplacementCleanup for Cleanup {
        type Error = &'static str;
        fn cleanup_old_installation(&mut self) -> Result<(), Self::Error> {
            self.calls += 1;
            (!self.fail).then_some(()).ok_or("cleanup failed")
        }
    }

    fn intent() -> ReplacementIntent {
        ReplacementIntent {
            enrollment_id: "enr_0123456789abcdef".to_owned(),
            enrollment_token_sha256: "d".repeat(64),
            host_id: "7".to_owned(),
            hub_origin: "https://hub.example".to_owned(),
            old_probe_id: "probe_old_01".to_owned(),
            source_probe_version: "1.2.2".to_owned(),
            source_probe_sha256: "a".repeat(64),
            target_probe_version: "1.2.3".to_owned(),
            target_asset_set_digest: format!("sha256:{}", "b".repeat(64)),
            target_manifest_sha256: "c".repeat(64),
        }
    }

    #[test]
    fn owner_commit_is_durable_before_the_first_cleanup_effect() {
        let mut store = Store {
            fail_persist: true,
            ..Store::default()
        };
        let mut cleanup = Cleanup::default();
        assert_eq!(
            commit_and_cleanup_replacement(intent(), &mut store, &mut cleanup),
            Err(ReplacementCommitError::Store("persist failed"))
        );
        assert_eq!(cleanup.calls, 0);
    }

    #[test]
    fn committed_cleanup_failure_resumes_forward_without_recommitting_or_recleaning() {
        let mut store = Store::default();
        let mut first = Cleanup {
            fail: true,
            ..Cleanup::default()
        };
        assert_eq!(
            commit_and_cleanup_replacement(intent(), &mut store, &mut first),
            Err(ReplacementCommitError::Effect("cleanup failed"))
        );
        assert_eq!(store.writes, 1);
        assert!(!store.fact.as_ref().unwrap().cleanup_complete);

        let mut resumed = Cleanup::default();
        let completed = commit_and_cleanup_replacement(intent(), &mut store, &mut resumed).unwrap();
        assert!(completed.cleanup_complete);
        assert_eq!(resumed.calls, 1);
        assert_eq!(store.writes, 2);

        let layout =
            record_replacement_candidate_layout(&mut store, &completed.canonical_intent_sha256)
                .unwrap();
        assert!(layout.candidate_layout_complete);

        let mut replay = Cleanup::default();
        commit_and_cleanup_replacement(intent(), &mut store, &mut replay).unwrap();
        assert_eq!(replay.calls, 0);
        assert_eq!(store.writes, 3);
    }

    #[test]
    fn filesystem_store_publishes_one_private_canonical_commit_fact() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temporary.path().join("replacement-migration.json");
        let mut store = FileReplacementCommitStore::at(&path, unsafe { libc::geteuid() });
        let mut cleanup = Cleanup::default();

        let fact = commit_and_cleanup_replacement(intent(), &mut store, &mut cleanup).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(store.load().unwrap(), Some(fact));
        assert_eq!(cleanup.calls, 1);
        assert_eq!(
            fs::read_dir(temporary.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            [std::ffi::OsString::from("replacement-migration.json")]
        );
    }
}
