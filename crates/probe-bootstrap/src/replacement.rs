use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::secure_file::PrivateAtomicFileCustody;

mod registration_attempt;
#[cfg(test)]
pub(crate) use registration_attempt::mutate_signed_replacement_capsule_for_test;
#[cfg(test)]
pub(crate) use registration_attempt::signed_replacement_registration_attempt_capsule_for_test;
pub use registration_attempt::{
    ReplacementRegistrationAttemptError, validate_replacement_registration_attempt_capsule,
};
pub(crate) use registration_attempt::{
    ReplacementRegistrationAttemptProof, prove_replacement_registration_attempt_capsule,
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
    pub target_bundle_target: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_identity_sha256: Option<String>,
}

/// Probe Local Lifecycle kernel 只持有这个不透明绑定；Enrollment、身份与候选语义
/// 仍由 Replacement coordinator 在生成 commit fact 时封闭验证。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementResumeBinding(String);

/// 将已提交的 Replacement 事实以只读投影送入候选注册边界，
/// 且不引入新的生命周期状态。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementRegistrationBinding {
    pub committed_source_probe_sha256: String,
    pub enrollment_id: String,
    pub host_id: String,
    pub hub_origin: String,
    pub old_probe_id: String,
    pub replacement_commit_sha256: String,
    pub source_probe_version: String,
    pub target_asset_set_digest: String,
    pub target_bundle_target: String,
    pub target_manifest_sha256: String,
    pub target_probe_version: String,
}

impl ReplacementIntent {
    pub fn canonical_sha256(&self) -> Option<String> {
        canonical_intent_sha256(self).ok()
    }

    #[must_use]
    pub fn registration_binding(&self) -> Option<ReplacementRegistrationBinding> {
        Some(ReplacementRegistrationBinding {
            committed_source_probe_sha256: self.source_probe_sha256.clone(),
            enrollment_id: self.enrollment_id.clone(),
            host_id: self.host_id.clone(),
            hub_origin: self.hub_origin.clone(),
            old_probe_id: self.old_probe_id.clone(),
            replacement_commit_sha256: self.canonical_sha256()?,
            source_probe_version: self.source_probe_version.clone(),
            target_asset_set_digest: self.target_asset_set_digest.clone(),
            target_bundle_target: self.target_bundle_target.clone(),
            target_manifest_sha256: self.target_manifest_sha256.clone(),
            target_probe_version: self.target_probe_version.clone(),
        })
    }
}

impl ReplacementCommitFact {
    #[cfg(feature = "activator")]
    #[must_use]
    pub fn resume_binding(&self) -> ReplacementResumeBinding {
        ReplacementResumeBinding(self.canonical_intent_sha256.clone())
    }

    #[cfg(feature = "activator")]
    #[must_use]
    pub fn registration_binding(&self) -> Option<ReplacementRegistrationBinding> {
        self.has_valid_binding()
            .then(|| ReplacementRegistrationBinding {
                committed_source_probe_sha256: self.intent.source_probe_sha256.clone(),
                enrollment_id: self.intent.enrollment_id.clone(),
                host_id: self.intent.host_id.clone(),
                hub_origin: self.intent.hub_origin.clone(),
                old_probe_id: self.intent.old_probe_id.clone(),
                replacement_commit_sha256: self.canonical_intent_sha256.clone(),
                source_probe_version: self.intent.source_probe_version.clone(),
                target_asset_set_digest: self.intent.target_asset_set_digest.clone(),
                target_bundle_target: self.intent.target_bundle_target.clone(),
                target_manifest_sha256: self.intent.target_manifest_sha256.clone(),
                target_probe_version: self.intent.target_probe_version.clone(),
            })
    }

    pub(crate) fn has_valid_binding(&self) -> bool {
        (matches!(
            (
                self.schema_version,
                self.canonical_identity_sha256.as_deref()
            ),
            (1, None)
        ) || matches!(
            (self.schema_version, self.canonical_identity_sha256.as_deref()),
            (2, Some(digest)) if valid_lower_sha256(digest)
        )) && canonical_intent_sha256(&self.intent).ok().as_deref()
            == Some(self.canonical_intent_sha256.as_str())
    }

    #[cfg(feature = "activator")]
    pub(crate) fn canonical_identity_sha256(&self) -> Option<&str> {
        self.canonical_identity_sha256.as_deref()
    }

    #[cfg(feature = "activator")]
    pub(crate) fn bind_canonical_identity_sha256(&mut self, digest: String) -> Result<(), ()> {
        if !self.has_valid_binding()
            || !valid_lower_sha256(&digest)
            || self
                .canonical_identity_sha256
                .as_ref()
                .is_some_and(|existing| existing != &digest)
        {
            return Err(());
        }
        self.schema_version = 2;
        self.canonical_identity_sha256 = Some(digest);
        Ok(())
    }

    #[cfg(all(test, feature = "activator"))]
    pub(crate) fn for_test(
        intent: ReplacementIntent,
        cleanup_complete: bool,
        candidate_layout_complete: bool,
    ) -> Self {
        Self {
            schema_version: 1,
            canonical_intent_sha256: canonical_intent_sha256(&intent).expect("canonical intent"),
            intent,
            cleanup_complete,
            candidate_layout_complete,
            canonical_identity_sha256: None,
        }
    }
}

impl ReplacementResumeBinding {
    #[cfg(feature = "activator")]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(all(test, feature = "activator"))]
    pub(crate) fn for_test(value: &str) -> Self {
        Self(value.to_owned())
    }
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
    custody: Option<PrivateAtomicFileCustody>,
    path: PathBuf,
    expected_owner_gid: u32,
    expected_owner_uid: u32,
}

impl FileReplacementCommitStore {
    pub fn at(path: impl Into<PathBuf>, expected_owner_uid: u32) -> Self {
        Self {
            custody: None,
            path: path.into(),
            expected_owner_gid: unsafe { libc::getegid() },
            expected_owner_uid,
        }
    }

    /// 只有已完成且与 finalizer 手中 receipt 完全相同的 commit fact 才能退休。
    /// 删除与目录 fsync 之间的中断可由相同 finalizer 幂等重放。
    #[cfg(feature = "activator")]
    pub(crate) fn retire_exact(&mut self, expected: &ReplacementCommitFact) -> std::io::Result<()> {
        let custody = self.custody()?;
        let actual = load_commit_fact(custody)?;
        match actual {
            Some(actual)
                if actual == *expected
                    && actual.cleanup_complete
                    && actual.candidate_layout_complete => {}
            None => {
                return Ok(());
            }
            Some(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "replacement commit fact does not match finalizer receipt",
                ));
            }
        }

        custody.remove()
    }

    /// Deepens only the exact retained commit; a caller cannot overwrite a
    /// different replacement fact while establishing identity custody.
    #[cfg(feature = "activator")]
    pub(crate) fn persist_identity_binding_exact(
        &mut self,
        expected: &ReplacementCommitFact,
        bound: &ReplacementCommitFact,
    ) -> std::io::Result<()> {
        let custody = self.custody()?;
        if load_commit_fact(custody)?.as_ref() != Some(expected)
            || expected.schema_version != 1
            || expected.canonical_identity_sha256.is_some()
            || !expected.has_valid_binding()
            || !bound.has_valid_binding()
            || bound.schema_version != 2
            || bound.canonical_identity_sha256.is_none()
            || bound.intent != expected.intent
            || bound.canonical_intent_sha256 != expected.canonical_intent_sha256
            || bound.cleanup_complete != expected.cleanup_complete
            || bound.candidate_layout_complete != expected.candidate_layout_complete
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "replacement commit changed before identity custody persisted",
            ));
        }
        persist_commit_fact(custody, bound)
    }

    fn custody(&mut self) -> std::io::Result<&PrivateAtomicFileCustody> {
        if self.custody.is_none() {
            self.custody = Some(PrivateAtomicFileCustody::open(
                &self.path,
                0o600,
                (self.expected_owner_uid, self.expected_owner_gid),
                self.expected_owner_uid,
            )?);
        }
        Ok(self.custody.as_ref().expect("commit custody initialized"))
    }
}

impl ReplacementCommitStore for FileReplacementCommitStore {
    type Error = std::io::Error;

    fn load(&mut self) -> Result<Option<ReplacementCommitFact>, Self::Error> {
        load_commit_fact(self.custody()?)
    }

    fn persist(&mut self, fact: &ReplacementCommitFact) -> Result<(), Self::Error> {
        persist_commit_fact(self.custody()?, fact)
    }
}

fn load_commit_fact(
    custody: &PrivateAtomicFileCustody,
) -> std::io::Result<Option<ReplacementCommitFact>> {
    let Some(bytes) = custody.read_bounded(MAX_COMMIT_FACT_BYTES as usize)? else {
        return Ok(None);
    };
    let fact: ReplacementCommitFact = serde_json::from_slice(&bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid replacement commit fact",
        )
    })?;
    if !fact.has_valid_binding() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid replacement commit binding",
        ));
    }
    Ok(Some(fact))
}

fn persist_commit_fact(
    custody: &PrivateAtomicFileCustody,
    fact: &ReplacementCommitFact,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(fact).map_err(std::io::Error::other)?;
    if bytes.len() as u64 > MAX_COMMIT_FACT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "replacement commit fact is too large",
        ));
    }
    custody.publish(&bytes)
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
            if existing.has_valid_binding()
                && existing.canonical_intent_sha256 == digest
                && existing.intent == intent =>
        {
            existing
        }
        Some(_) => return Err(ReplacementCommitError::ConflictingCommit),
        None => {
            let committed = ReplacementCommitFact {
                schema_version: 1,
                canonical_intent_sha256: digest,
                intent,
                cleanup_complete: false,
                candidate_layout_complete: false,
                canonical_identity_sha256: None,
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

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };

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
            target_bundle_target: "x86_64-unknown-linux-gnu".to_owned(),
            target_probe_version: "1.2.3".to_owned(),
            target_asset_set_digest: format!("sha256:{}", "b".repeat(64)),
            target_manifest_sha256: "c".repeat(64),
        }
    }

    #[test]
    fn resume_binding_covers_every_canonical_replacement_fact() {
        let original = intent();
        let expected = canonical_intent_sha256(&original).unwrap();
        let mutations: [fn(&mut ReplacementIntent); 11] = [
            |intent| intent.enrollment_id.push_str("_other"),
            |intent| intent.enrollment_token_sha256.replace_range(..1, "e"),
            |intent| intent.host_id.push('8'),
            |intent| intent.hub_origin.push_str("/other"),
            |intent| intent.old_probe_id.push_str("_other"),
            |intent| intent.source_probe_version.push_str("+other"),
            |intent| intent.source_probe_sha256.replace_range(..1, "f"),
            |intent| intent.target_bundle_target.push_str("-other"),
            |intent| intent.target_probe_version.push_str("+other"),
            |intent| intent.target_asset_set_digest.replace_range(7..8, "e"),
            |intent| intent.target_manifest_sha256.replace_range(..1, "f"),
        ];

        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(canonical_intent_sha256(&changed).unwrap(), expected);
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
    fn completed_layout_does_not_authorize_a_different_replacement_commit() {
        let mut store = Store::default();
        let mut cleanup = Cleanup::default();
        let committed = commit_and_cleanup_replacement(intent(), &mut store, &mut cleanup).unwrap();
        record_replacement_candidate_layout(&mut store, &committed.canonical_intent_sha256)
            .unwrap();
        let mut different = intent();
        different.enrollment_id.push_str("_new");
        let mut replacement_cleanup = Cleanup::default();

        assert_eq!(
            commit_and_cleanup_replacement(different, &mut store, &mut replacement_cleanup),
            Err(ReplacementCommitError::ConflictingCommit)
        );
        assert_eq!(replacement_cleanup.calls, 0);
        assert_eq!(
            store.load().unwrap().unwrap().canonical_intent_sha256,
            committed.canonical_intent_sha256
        );
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
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("\"targetBundleTarget\":\"x86_64-unknown-linux-gnu\"")
        );
        assert_eq!(cleanup.calls, 1);
        assert_eq!(
            fs::read_dir(temporary.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            [std::ffi::OsString::from("replacement-migration.json")]
        );
    }

    #[cfg(feature = "activator")]
    #[test]
    fn commit_residue_never_authorizes_publish_or_cleanup() {
        for residue in ["exact", "different", "malformed", "wrong-mode", "symlink"] {
            let temporary = tempfile::tempdir().unwrap();
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let path = temporary.path().join("replacement-migration.json");
            let residue_path = temporary
                .path()
                .join(".replacement-migration.json-enoki-write-123-1");
            let expected = ReplacementCommitFact::for_test(intent(), false, false);
            let residue_bytes = match residue {
                "exact" => serde_json::to_vec(&expected).unwrap(),
                "different" => serde_json::to_vec(&ReplacementCommitFact::for_test(
                    {
                        let mut intent = intent();
                        intent.enrollment_id.push_str("_other");
                        intent
                    },
                    false,
                    false,
                ))
                .unwrap(),
                "malformed" | "wrong-mode" => b"not a commit fact".to_vec(),
                "symlink" => Vec::new(),
                _ => unreachable!(),
            };
            if residue == "symlink" {
                symlink(&path, &residue_path).unwrap();
            } else {
                fs::write(&residue_path, &residue_bytes).unwrap();
                fs::set_permissions(
                    &residue_path,
                    fs::Permissions::from_mode(if residue == "wrong-mode" {
                        0o644
                    } else {
                        0o600
                    }),
                )
                .unwrap();
            }
            let mut store = FileReplacementCommitStore::at(&path, unsafe { libc::geteuid() });
            let mut cleanup = Cleanup::default();

            assert!(
                matches!(
                    commit_and_cleanup_replacement(intent(), &mut store, &mut cleanup),
                    Err(ReplacementCommitError::Store(_))
                ),
                "{residue} residue must fail before commit or cleanup"
            );
            assert_eq!(cleanup.calls, 0, "{residue} has zero cleanup effect");
            assert!(!path.exists(), "{residue} cannot publish a commit");
            if residue != "symlink" {
                assert_eq!(fs::read(&residue_path).unwrap(), residue_bytes);
            }
        }
    }

    #[cfg(feature = "activator")]
    #[test]
    fn identity_custody_schema_only_upgrades_legacy_facts_with_a_valid_digest() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temporary.path().join("replacement-migration.json");
        let mut store = FileReplacementCommitStore::at(&path, unsafe { libc::geteuid() });
        let mut legacy = ReplacementCommitFact::for_test(intent(), true, true);
        store.persist(&legacy).unwrap();
        assert_eq!(store.load().unwrap(), Some(legacy.clone()));

        let mut upgraded = legacy.clone();
        upgraded
            .bind_canonical_identity_sha256("d".repeat(64))
            .unwrap();
        store.persist(&upgraded).unwrap();
        assert_eq!(store.load().unwrap(), Some(upgraded));

        let mut different_intent = intent();
        different_intent.enrollment_id.push_str("_other");
        let different = ReplacementCommitFact::for_test(different_intent, true, true);
        store.persist(&different).unwrap();
        let mut attempted_overwrite = legacy.clone();
        attempted_overwrite
            .bind_canonical_identity_sha256("d".repeat(64))
            .unwrap();
        assert!(
            store
                .persist_identity_binding_exact(&legacy, &attempted_overwrite)
                .is_err()
        );
        assert_eq!(store.load().unwrap(), Some(different));

        legacy.canonical_identity_sha256 = Some("d".repeat(64));
        store.persist(&legacy).unwrap();
        assert!(
            store.load().is_err(),
            "schema 1 cannot claim identity custody"
        );

        let mut malformed = ReplacementCommitFact::for_test(intent(), true, true);
        malformed.schema_version = 2;
        malformed.canonical_identity_sha256 = Some("not-a-digest".into());
        store.persist(&malformed).unwrap();
        assert!(
            store.load().is_err(),
            "malformed schema 2 custody fails closed"
        );

        let mut missing = ReplacementCommitFact::for_test(intent(), true, true);
        missing.schema_version = 2;
        store.persist(&missing).unwrap();
        assert!(
            store.load().is_err(),
            "schema 2 requires durable identity custody"
        );
    }

    #[cfg(feature = "activator")]
    #[test]
    fn filesystem_store_retires_only_the_exact_complete_replacement_fact() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temporary.path().join("replacement-migration.json");
        let mut store = FileReplacementCommitStore::at(&path, unsafe { libc::geteuid() });
        let mut cleanup = Cleanup::default();
        let committed = commit_and_cleanup_replacement(intent(), &mut store, &mut cleanup).unwrap();
        let complete =
            record_replacement_candidate_layout(&mut store, &committed.canonical_intent_sha256)
                .unwrap();
        let mut wrong = complete.clone();
        wrong.candidate_layout_complete = false;

        assert!(store.retire_exact(&wrong).is_err());
        assert_eq!(store.load().unwrap(), Some(complete.clone()));

        store.persist(&wrong).unwrap();
        assert!(store.retire_exact(&wrong).is_err());
        assert_eq!(store.load().unwrap(), Some(wrong));

        let mut tampered = complete.clone();
        tampered.intent.host_id = "wrong-host".to_owned();
        store.persist(&tampered).unwrap();
        assert!(store.retire_exact(&tampered).is_err());
        assert!(path.exists());

        store.persist(&complete).unwrap();
        store.retire_exact(&complete).unwrap();
        assert_eq!(store.load().unwrap(), None);
        store.retire_exact(&complete).unwrap();
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
    }
}
