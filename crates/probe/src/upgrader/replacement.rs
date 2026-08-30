//! Probe Replacement Migration 的封闭 coordinator Module。
//!
//! 本 Module 独占 preflight authority、durable commit、exact replay 与
//! post-commit forward-only recovery。外部 Interface 只接受完整 request。

use super::uninstall::commit_replacement_and_cleanup_install_with_systemd;
use super::{
    MAX_INSTALLED_PROBE_BYTES, PRODUCTION_INSTALL_METADATA_PATH, PRODUCTION_PROBE_BINARY_PATH,
    PRODUCTION_REPLACEMENT_COMMIT_PATH, PRODUCTION_REPLACEMENT_REGISTRATION_ATTEMPT_PATH,
    SystemProbeUpgraderSystemdRunner, TrustedProbeInstallMetadata, TrustedProbeInstallPreflight,
    preflight_rooted_path, read_trusted_probe_install_metadata,
    read_trusted_probe_install_preflight,
};
use enoki_probe_bootstrap::{
    lifecycle::{LifecycleRequest, LifecycleRequestAuthority, LifecycleResponse},
    replacement::{
        FileReplacementCommitStore, ReplacementCommitError, ReplacementCommitFact,
        ReplacementCommitStore, ReplacementIntent,
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const REPLACEMENT_COORDINATOR_LOCK_PATH: &str = "/var/lib/enoki-probe-bootstrap/activation.lock";
const REPLACEMENT_COORDINATOR_LOCK_BUDGET: Duration = Duration::from_secs(90);

pub(super) fn coordinate(request: &LifecycleRequest) -> LifecycleResponse {
    let production_root = match production_root() {
        Ok(root) => root,
        Err(()) => return LifecycleResponse::failed("lifecycle.invalid_authority"),
    };
    {
        let Ok(_guard) = ReplacementCoordinatorGuard::acquire(production_root.as_deref()) else {
            return LifecycleResponse::failed("lifecycle.replacement_commit_failed");
        };
        if let Some(response) =
            resume_committed_from_exact_request(request, production_root.as_deref())
        {
            return response;
        }
    }
    let metadata_path =
        production_path(PRODUCTION_INSTALL_METADATA_PATH, production_root.as_deref());
    let metadata = match read_trusted_probe_install_metadata(&metadata_path, None) {
        Ok(metadata) => metadata,
        Err(_) => return LifecycleResponse::failed("lifecycle.install_state_invalid"),
    };
    let identity =
        match read_trusted_probe_install_preflight(&metadata_path, production_root.as_deref()) {
            Ok(identity) => identity,
            Err(_) => return LifecycleResponse::failed("lifecycle.identity_invalid"),
        };
    run(request, &metadata, &identity, production_root.as_deref())
}

fn run(
    request: &LifecycleRequest,
    metadata: &TrustedProbeInstallMetadata,
    identity: &TrustedProbeInstallPreflight,
    production_root: Option<&Path>,
) -> LifecycleResponse {
    let LifecycleRequestAuthority::ReplacementEnrollment {
        enrollment_token,
        enrollment_id,
        hub_origin,
        host_id,
        expected_probe_id,
        source_probe_version,
        source_probe_sha256,
        target_asset_set_digest,
        target_bundle_target,
        target_manifest_sha256,
        bundle_version,
    } = request.authority()
    else {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    };
    let installed_probe_sha256 =
        match fixed_installed_probe_sha256(&metadata.install_path, production_root) {
            Ok(digest) => digest,
            Err(_) => return LifecycleResponse::failed("lifecycle.authority_invalid"),
        };
    let claimed_authority = crate::registration::ProbeReplacementAuthorization {
        enrollment_id: enrollment_id.clone(),
        host_id: host_id.clone(),
        expected_hub_origin: hub_origin.clone(),
        expected_probe_id: expected_probe_id.clone(),
        source_probe_version: source_probe_version.clone(),
        source_probe_sha256: source_probe_sha256.clone(),
        target_asset_set_digest: target_asset_set_digest.clone(),
        target_probe_version: bundle_version.clone(),
    };
    let authority_match = authority_matches(
        hub_origin,
        target_asset_set_digest,
        bundle_version,
        &claimed_authority,
        metadata,
        identity,
        &installed_probe_sha256,
    );
    if authority_match != AuthorityMatch::Matches {
        return LifecycleResponse::failed(match authority_match {
            AuthorityMatch::UnprovableSource => "lifecycle.authority_invalid",
            AuthorityMatch::Mismatch => "lifecycle.authority_mismatch",
            AuthorityMatch::Matches => unreachable!(),
        });
    }
    let intent = ReplacementIntent {
        enrollment_id: enrollment_id.clone(),
        enrollment_token_sha256: format!("{:x}", Sha256::digest(enrollment_token.as_bytes())),
        host_id: host_id.clone(),
        hub_origin: hub_origin.clone(),
        old_probe_id: expected_probe_id.clone(),
        source_probe_version: source_probe_version.clone(),
        source_probe_sha256: installed_probe_sha256,
        target_bundle_target: target_bundle_target.clone(),
        target_probe_version: bundle_version.clone(),
        target_asset_set_digest: target_asset_set_digest.clone(),
        target_manifest_sha256: target_manifest_sha256.clone(),
    };
    let Some(registration_binding) = intent.registration_binding() else {
        return LifecycleResponse::failed("lifecycle.authority_invalid");
    };
    let enrollment_token = enrollment_token.clone();
    let mut registration = crate::registration::HttpRegistrationTransport;
    let inspected = crate::registration::inspect_probe_installation(
        crate::registration::ProbeInstallationInspectionInput {
            enrollment_token: enrollment_token.clone(),
            hub_url: hub_origin.clone(),
        },
        &mut registration,
    );
    let Ok(crate::registration::ProbeInstallationTarget::ManualReinstall(authority)) = inspected
    else {
        return LifecycleResponse::failed("lifecycle.authority_rejected");
    };
    if authority != claimed_authority {
        return LifecycleResponse::failed("lifecycle.authority_mismatch");
    }
    coordinate_inspected_replacement(
        request,
        &claimed_authority,
        intent,
        registration_binding,
        production_root,
    )
}

fn coordinate_inspected_replacement(
    request: &LifecycleRequest,
    claimed_authority: &crate::registration::ProbeReplacementAuthorization,
    intent: ReplacementIntent,
    registration_binding: enoki_probe_bootstrap::replacement::ReplacementRegistrationBinding,
    production_root: Option<&Path>,
) -> LifecycleResponse {
    let LifecycleRequestAuthority::ReplacementEnrollment {
        enrollment_token,
        hub_origin,
        target_asset_set_digest,
        bundle_version,
        ..
    } = request.authority()
    else {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    };
    let Ok(_guard) = ReplacementCoordinatorGuard::acquire(production_root) else {
        return LifecycleResponse::failed("lifecycle.replacement_commit_failed");
    };
    if let Some(response) = resume_committed_from_exact_request(request, production_root) {
        return response;
    }
    let metadata_path = production_path(PRODUCTION_INSTALL_METADATA_PATH, production_root);
    let current_metadata = match read_trusted_probe_install_metadata(&metadata_path, None) {
        Ok(metadata) => metadata,
        Err(_) => return LifecycleResponse::failed("lifecycle.install_state_invalid"),
    };
    let current_identity =
        match read_trusted_probe_install_preflight(&metadata_path, production_root) {
            Ok(identity) => identity,
            Err(_) => return LifecycleResponse::failed("lifecycle.identity_invalid"),
        };
    let current_probe_sha256 =
        match fixed_installed_probe_sha256(&current_metadata.install_path, production_root) {
            Ok(digest) => digest,
            Err(_) => return LifecycleResponse::failed("lifecycle.authority_invalid"),
        };
    if !post_inspection_source_remains_exact(
        &intent,
        hub_origin,
        target_asset_set_digest,
        bundle_version,
        claimed_authority,
        &current_metadata,
        &current_identity,
        &current_probe_sha256,
    ) {
        return LifecycleResponse::failed("lifecycle.authority_mismatch");
    }
    let mut store = FileReplacementCommitStore::at(
        production_path(PRODUCTION_REPLACEMENT_COMMIT_PATH, production_root),
        0,
    );
    match store.load() {
        Ok(None) => {}
        Ok(Some(_)) => return LifecycleResponse::failed("lifecycle.replacement_commit_conflict"),
        Err(_) => return LifecycleResponse::failed("lifecycle.replacement_commit_failed"),
    }
    let attempt_path = production_path(
        PRODUCTION_REPLACEMENT_REGISTRATION_ATTEMPT_PATH,
        production_root,
    );
    let attempt_input = crate::registration::RootReplacementRegistrationAttemptInput {
        enrollment_token: enrollment_token.clone(),
        binding: registration_binding,
    };
    if crate::registration::prepare_root_replacement_registration_attempt(
        &attempt_path,
        attempt_input.clone(),
    )
    .or_else(|_| {
        crate::registration::replace_stale_root_replacement_registration_attempt(
            &attempt_path,
            attempt_input,
        )
    })
    .is_err()
    {
        return LifecycleResponse::failed("lifecycle.registration_attempt_failed");
    }
    let mut systemd = SystemProbeUpgraderSystemdRunner;
    commit_and_cleanup_response(commit_replacement_and_cleanup_install_with_systemd(
        intent,
        &mut store,
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        production_root,
        &mut systemd,
    ))
}

#[allow(clippy::too_many_arguments)]
fn post_inspection_source_remains_exact(
    intent: &ReplacementIntent,
    hub_origin: &str,
    target_asset_set_digest: &str,
    bundle_version: &str,
    claimed_authority: &crate::registration::ProbeReplacementAuthorization,
    current_metadata: &TrustedProbeInstallMetadata,
    current_identity: &TrustedProbeInstallPreflight,
    current_probe_sha256: &str,
) -> bool {
    current_probe_sha256 == intent.source_probe_sha256
        && authority_matches(
            hub_origin,
            target_asset_set_digest,
            bundle_version,
            claimed_authority,
            current_metadata,
            current_identity,
            current_probe_sha256,
        ) == AuthorityMatch::Matches
}

/// Serializes the post-inspection proof, capsule publication, and Replacement
/// commit with every production activation process. The lock is intentionally
/// not authority: a fresh holder always re-reads every durable fact.
struct ReplacementCoordinatorGuard {
    file: File,
}

impl ReplacementCoordinatorGuard {
    fn acquire(production_root: Option<&Path>) -> Result<Self, std::io::Error> {
        let path = production_path(REPLACEMENT_COORDINATOR_LOCK_PATH, production_root);
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing lock parent")
        })?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.uid() != 0
            || parent_metadata.mode() & 0o077 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "replacement coordinator lock parent is not root-private",
            ));
        }
        let (file, created) = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)?,
                false,
            ),
            Err(error) => return Err(error),
        };
        if created {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.sync_all()?;
            File::open(parent)?.sync_all()?;
        }
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "replacement coordinator lock is not root-private",
            ));
        }
        let deadline = Instant::now() + REPLACEMENT_COORDINATOR_LOCK_BUDGET;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { file });
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "replacement coordinator lock timed out",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ReplacementCoordinatorGuard {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub(super) fn resume_committed_from_exact_request(
    request: &LifecycleRequest,
    production_root: Option<&Path>,
) -> Option<LifecycleResponse> {
    resume_committed_from_exact_request_with(request, production_root, |fact, store| {
        let metadata_path = production_path(PRODUCTION_INSTALL_METADATA_PATH, production_root);
        if !fact.cleanup_complete && !metadata_path.exists() {
            // exact request 是 authority binding，不是 effect receipt。没有仍受 commit
            // custody 的 metadata 就无法证明旧 inventory 已完整清理，必须零效果关闭。
            return LifecycleResponse::failed("lifecycle.replacement_cleanup_failed");
        }
        let mut systemd = SystemProbeUpgraderSystemdRunner;
        commit_and_cleanup_response(commit_replacement_and_cleanup_install_with_systemd(
            fact.intent,
            store,
            Path::new(PRODUCTION_INSTALL_METADATA_PATH),
            production_root,
            &mut systemd,
        ))
    })
}

fn resume_committed_from_exact_request_with(
    request: &LifecycleRequest,
    production_root: Option<&Path>,
    resume: impl FnOnce(ReplacementCommitFact, &mut FileReplacementCommitStore) -> LifecycleResponse,
) -> Option<LifecycleResponse> {
    let mut store = FileReplacementCommitStore::at(
        production_path(PRODUCTION_REPLACEMENT_COMMIT_PATH, production_root),
        0,
    );
    let fact = match store.load() {
        Ok(Some(fact)) => fact,
        Ok(None) => return None,
        Err(_) => {
            return Some(LifecycleResponse::failed(
                "lifecycle.replacement_commit_failed",
            ));
        }
    };
    if !request_matches_committed_fact(request, &fact) {
        return Some(LifecycleResponse::failed(
            "lifecycle.replacement_commit_conflict",
        ));
    }
    let LifecycleRequestAuthority::ReplacementEnrollment {
        enrollment_token, ..
    } = request.authority()
    else {
        return Some(LifecycleResponse::failed("lifecycle.invalid_authority"));
    };
    let Some(binding) = fact.intent.registration_binding() else {
        return Some(LifecycleResponse::failed(
            "lifecycle.replacement_commit_conflict",
        ));
    };
    if crate::registration::validate_root_replacement_registration_attempt(
        &production_path(
            PRODUCTION_REPLACEMENT_REGISTRATION_ATTEMPT_PATH,
            production_root,
        ),
        crate::registration::RootReplacementRegistrationAttemptInput {
            enrollment_token: enrollment_token.clone(),
            binding,
        },
    )
    .is_err()
    {
        return Some(LifecycleResponse::failed(
            "lifecycle.registration_attempt_failed",
        ));
    }
    Some(resume(fact, &mut store))
}

fn commit_and_cleanup_response<E>(
    result: Result<ReplacementCommitFact, ReplacementCommitError<E, super::ProbeUpgraderRunError>>,
) -> LifecycleResponse {
    match result {
        Ok(_) => LifecycleResponse::succeeded(),
        Err(ReplacementCommitError::Effect(_)) => {
            LifecycleResponse::failed("lifecycle.replacement_cleanup_failed")
        }
        Err(ReplacementCommitError::Store(_)) => {
            LifecycleResponse::failed("lifecycle.replacement_commit_failed")
        }
        Err(ReplacementCommitError::ConflictingCommit) => {
            LifecycleResponse::failed("lifecycle.replacement_commit_conflict")
        }
    }
}

fn request_matches_committed_fact(
    request: &LifecycleRequest,
    fact: &ReplacementCommitFact,
) -> bool {
    let LifecycleRequestAuthority::ReplacementEnrollment {
        enrollment_token,
        enrollment_id,
        hub_origin,
        host_id,
        expected_probe_id,
        source_probe_version,
        source_probe_sha256,
        target_asset_set_digest,
        target_bundle_target,
        target_manifest_sha256,
        bundle_version,
        ..
    } = request.authority()
    else {
        return false;
    };
    fact.intent.canonical_sha256().as_deref() == Some(&fact.canonical_intent_sha256)
        && fact.intent.enrollment_token_sha256
            == format!("{:x}", Sha256::digest(enrollment_token.as_bytes()))
        && fact.intent.enrollment_id == *enrollment_id
        && fact.intent.hub_origin == *hub_origin
        && fact.intent.host_id == *host_id
        && fact.intent.old_probe_id == *expected_probe_id
        && fact.intent.source_probe_version == *source_probe_version
        && source_probe_sha256.contains(&fact.intent.source_probe_sha256)
        && fact.intent.target_asset_set_digest == *target_asset_set_digest
        && fact.intent.target_bundle_target == *target_bundle_target
        && fact.intent.target_manifest_sha256 == *target_manifest_sha256
        && fact.intent.target_probe_version == *bundle_version
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InstalledProbeBinaryFacts {
    device: u64,
    inode: u64,
    is_regular_file: bool,
    is_symlink: bool,
    length: u64,
    link_count: u64,
    mode: u32,
    owner_uid: u32,
}

pub(super) fn fixed_installed_probe_sha256(
    path: &Path,
    production_root: Option<&Path>,
) -> Result<String, std::io::Error> {
    if path != Path::new(PRODUCTION_PROBE_BINARY_PATH) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "installed Probe path is not the fixed production path",
        ));
    }
    let opened_path = preflight_rooted_path(production_root, path);
    let path_facts = installed_probe_binary_facts(&fs::symlink_metadata(&opened_path)?);
    validate_installed_probe_binary_facts(path_facts)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(opened_path)?;
    let opened_facts = installed_probe_binary_facts(&file.metadata()?);
    validate_installed_probe_binary_facts(opened_facts)?;
    if path_facts != opened_facts {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed Probe path and opened file do not match",
        ));
    }
    let digest = installed_probe_sha256_from_reader(&mut file, opened_facts)?;
    if installed_probe_binary_facts(&file.metadata()?) != opened_facts {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed Probe changed while it was hashed",
        ));
    }
    Ok(digest)
}

#[cfg(feature = "deterministic-test-seams")]
fn production_root() -> Result<Option<PathBuf>, ()> {
    let Some(value) = std::env::var_os("ENOKI_TEST_REPLACEMENT_PRODUCTION_ROOT") else {
        return Ok(None);
    };
    let root = PathBuf::from(value);
    if !root.is_absolute() || root == Path::new("/") {
        return Err(());
    }
    Ok(Some(root))
}

#[cfg(not(feature = "deterministic-test-seams"))]
fn production_root() -> Result<Option<PathBuf>, ()> {
    Ok(None)
}

pub(super) fn production_path(absolute: &str, root: Option<&Path>) -> PathBuf {
    root.map_or_else(
        || PathBuf::from(absolute),
        |root| root.join(absolute.trim_start_matches('/')),
    )
}

fn installed_probe_binary_facts(metadata: &fs::Metadata) -> InstalledProbeBinaryFacts {
    InstalledProbeBinaryFacts {
        device: metadata.dev(),
        inode: metadata.ino(),
        is_regular_file: metadata.file_type().is_file(),
        is_symlink: metadata.file_type().is_symlink(),
        length: metadata.len(),
        link_count: metadata.nlink(),
        mode: metadata.mode() & 0o7777,
        owner_uid: metadata.uid(),
    }
}

fn validate_installed_probe_binary_facts(
    facts: InstalledProbeBinaryFacts,
) -> Result<(), std::io::Error> {
    if facts.is_symlink
        || !facts.is_regular_file
        || facts.owner_uid != 0
        || facts.mode != 0o755
        || facts.link_count != 1
        || facts.length == 0
        || facts.length > MAX_INSTALLED_PROBE_BYTES
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed Probe file facts are invalid",
        ));
    }
    Ok(())
}

fn installed_probe_sha256_from_reader(
    mut reader: impl Read,
    facts: InstalledProbeBinaryFacts,
) -> Result<String, std::io::Error> {
    validate_installed_probe_binary_facts(facts)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "installed Probe size exceeded its bound",
            )
        })?;
        if total > facts.length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "installed Probe size changed while it was hashed",
            ));
        }
        digest.update(&buffer[..read]);
    }
    if total != facts.length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed Probe size changed while it was hashed",
        ));
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityMatch {
    Matches,
    Mismatch,
    UnprovableSource,
}

fn authority_matches(
    hub_origin: &str,
    target_asset_set_digest: &str,
    bundle_version: &str,
    authority: &crate::registration::ProbeReplacementAuthorization,
    metadata: &TrustedProbeInstallMetadata,
    identity: &TrustedProbeInstallPreflight,
    installed_probe_sha256: &str,
) -> AuthorityMatch {
    if authority.source_probe_sha256.is_empty() {
        return AuthorityMatch::UnprovableSource;
    }
    if !authority
        .source_probe_sha256
        .iter()
        .any(|expected| expected == installed_probe_sha256)
    {
        return AuthorityMatch::Mismatch;
    }
    if metadata
        .bundle_version
        .as_deref()
        .is_some_and(|installed| installed != authority.source_probe_version)
    {
        return AuthorityMatch::Mismatch;
    }
    if authority.expected_hub_origin == hub_origin
        && identity.hub_url == hub_origin
        && metadata.hub_url == hub_origin
        && authority.expected_probe_id == identity.probe_id
        && authority.target_asset_set_digest == target_asset_set_digest
        && authority.target_probe_version == bundle_version
    {
        AuthorityMatch::Matches
    } else {
        AuthorityMatch::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enoki_probe_bootstrap::handoff::Enrollment;
    use std::{cell::Cell, sync::mpsc, time::Duration};

    fn replacement_intent(enrollment_id: &str, token: &str) -> ReplacementIntent {
        ReplacementIntent {
            enrollment_id: enrollment_id.to_owned(),
            enrollment_token_sha256: format!("{:x}", Sha256::digest(token.as_bytes())),
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

    fn replacement_request(intent: &ReplacementIntent, token: &str) -> LifecycleRequest {
        let input = format!(
            "{{\"hubOrigin\":\"https://hub.example\",\"enrollmentToken\":\"{token}\",\"replacementMigration\":{{\"enrollmentId\":\"{}\",\"expectedProbeId\":\"probe_old_01\",\"sourceProbeSha256\":[\"{}\"],\"sourceProbeVersion\":\"1.2.2\",\"targetAssetSetDigest\":\"{}\",\"targetHostId\":\"7\",\"targetProbeVersion\":\"1.2.3\"}},\"schemaVersion\":1}}",
            intent.enrollment_id, intent.source_probe_sha256, intent.target_asset_set_digest,
        );
        let enrollment = Enrollment::from_install_input("https://hub.example", input.as_bytes())
            .expect("canonical replacement enrollment");
        LifecycleRequest::replacement_migration(
            &enrollment,
            &intent.target_asset_set_digest,
            &intent.target_bundle_target,
            &intent.target_manifest_sha256,
            &intent.target_probe_version,
        )
        .expect("replacement request")
    }

    fn replacement_authority(
        intent: &ReplacementIntent,
    ) -> crate::registration::ProbeReplacementAuthorization {
        crate::registration::ProbeReplacementAuthorization {
            enrollment_id: intent.enrollment_id.clone(),
            host_id: intent.host_id.clone(),
            expected_hub_origin: intent.hub_origin.clone(),
            expected_probe_id: intent.old_probe_id.clone(),
            source_probe_version: intent.source_probe_version.clone(),
            source_probe_sha256: vec![intent.source_probe_sha256.clone()],
            target_asset_set_digest: intent.target_asset_set_digest.clone(),
            target_probe_version: intent.target_probe_version.clone(),
        }
    }

    #[test]
    fn migration_requires_one_exact_hub_identity_and_source_authority() {
        let temporary = tempfile::tempdir().unwrap();
        let status = temporary.path().join("probe-operation-status.toml");
        let mut metadata = metadata_for_hub(
            "https://hub.example",
            &temporary.path().join("enoki-probe"),
            &status,
        );
        metadata.schema_version = 4;
        metadata.bundle_version = Some("1.2.2".to_owned());
        let identity = TrustedProbeInstallPreflight {
            hub_url: "https://hub.example".to_owned(),
            probe_id: "probe_old_01".to_owned(),
        };
        let authority = crate::registration::ProbeReplacementAuthorization {
            enrollment_id: "enr_0123456789abcdef".to_owned(),
            host_id: "7".to_owned(),
            expected_hub_origin: "https://hub.example".to_owned(),
            expected_probe_id: "probe_old_01".to_owned(),
            source_probe_version: "1.2.2".to_owned(),
            source_probe_sha256: vec!["c".repeat(64)],
            target_asset_set_digest: format!("sha256:{}", "b".repeat(64)),
            target_probe_version: "1.2.3".to_owned(),
        };

        assert_eq!(
            authority_matches(
                "https://hub.example",
                &format!("sha256:{}", "b".repeat(64)),
                "1.2.3",
                &authority,
                &metadata,
                &identity,
                &"c".repeat(64),
            ),
            AuthorityMatch::Matches
        );
        metadata.bundle_version = Some("1.2.1".to_owned());
        assert_eq!(
            authority_matches(
                "https://hub.example",
                &format!("sha256:{}", "b".repeat(64)),
                "1.2.3",
                &authority,
                &metadata,
                &identity,
                &"c".repeat(64),
            ),
            AuthorityMatch::Mismatch
        );
        metadata.schema_version = 3;
        metadata.bundle_version = None;
        let mut unprovable = authority.clone();
        unprovable.source_probe_sha256.clear();
        assert_eq!(
            authority_matches(
                "https://hub.example",
                &format!("sha256:{}", "b".repeat(64)),
                "1.2.3",
                &unprovable,
                &metadata,
                &identity,
                &"c".repeat(64),
            ),
            AuthorityMatch::UnprovableSource
        );
    }

    #[test]
    fn post_inspection_metadata_identity_and_probe_changes_are_rejected_before_precommit() {
        let temporary = tempfile::tempdir().unwrap();
        let status = temporary.path().join("probe-operation-status.toml");
        let mut metadata = metadata_for_hub(
            "https://hub.example",
            Path::new(PRODUCTION_PROBE_BINARY_PATH),
            &status,
        );
        metadata.schema_version = 4;
        metadata.bundle_version = Some("1.2.2".to_owned());
        let identity = TrustedProbeInstallPreflight {
            hub_url: "https://hub.example".to_owned(),
            probe_id: "probe_old_01".to_owned(),
        };
        let intent = replacement_intent("enr_0123456789abcdef", "enk_enroll_old");
        let authority = replacement_authority(&intent);
        let exact = |metadata: &TrustedProbeInstallMetadata,
                     identity: &TrustedProbeInstallPreflight,
                     digest: &str| {
            post_inspection_source_remains_exact(
                &intent,
                "https://hub.example",
                &intent.target_asset_set_digest,
                &intent.target_probe_version,
                &authority,
                metadata,
                identity,
                digest,
            )
        };

        assert!(exact(&metadata, &identity, &intent.source_probe_sha256));

        let mut changed_metadata = metadata.clone();
        changed_metadata.bundle_version = Some("1.2.1".to_owned());
        assert!(!exact(
            &changed_metadata,
            &identity,
            &intent.source_probe_sha256
        ));

        let mut changed_identity = identity.clone();
        changed_identity.probe_id = "probe_other".to_owned();
        assert!(!exact(
            &metadata,
            &changed_identity,
            &intent.source_probe_sha256
        ));

        assert!(!exact(&metadata, &identity, &"f".repeat(64)));
    }

    #[test]
    fn root_owned_binary_facts_prove_one_bounded_legacy_component() {
        let facts = InstalledProbeBinaryFacts {
            device: 11,
            inode: 22,
            is_regular_file: true,
            is_symlink: false,
            length: 22,
            link_count: 1,
            mode: 0o755,
            owner_uid: 0,
        };
        validate_installed_probe_binary_facts(facts).expect("接受 canonical facts");
        let digest = installed_probe_sha256_from_reader(
            std::io::Cursor::new(b"legacy probe component"),
            facts,
        )
        .expect("计算有界组件摘要");
        assert_eq!(
            digest,
            "d7f57fc65a2c73a675a0952208f072d22e3c9e65995b07753e53946e2638966e"
        );
    }

    #[test]
    fn concurrent_commit_cannot_split_a_stale_capsule_from_its_commit() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "test requires root custody");
        let temporary = tempfile::tempdir().unwrap();
        let bootstrap_state =
            production_path("/var/lib/enoki-probe-bootstrap", Some(temporary.path()));
        let registration_state =
            production_path("/var/lib/enoki-probe-registration", Some(temporary.path()));
        fs::create_dir_all(&bootstrap_state).unwrap();
        fs::create_dir_all(&registration_state).unwrap();
        fs::set_permissions(&bootstrap_state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&registration_state, fs::Permissions::from_mode(0o700)).unwrap();

        let old_token = "enk_enroll_old";
        let old_intent = replacement_intent("enr_0123456789abcdef", old_token);
        let attempt_path = production_path(
            PRODUCTION_REPLACEMENT_REGISTRATION_ATTEMPT_PATH,
            Some(temporary.path()),
        );
        crate::registration::prepare_root_replacement_registration_attempt(
            &attempt_path,
            crate::registration::RootReplacementRegistrationAttemptInput {
                enrollment_token: old_token.to_owned(),
                binding: old_intent.registration_binding().unwrap(),
            },
        )
        .unwrap();
        let original_capsule = fs::read(&attempt_path).unwrap();

        let guard = ReplacementCoordinatorGuard::acquire(Some(temporary.path())).unwrap();
        let new_token = "enk_enroll_new";
        let new_intent = replacement_intent("enr_abcdef0123456789", new_token);
        let request = replacement_request(&new_intent, new_token);
        let authority = replacement_authority(&new_intent);
        let binding = new_intent.registration_binding().unwrap();
        let root = temporary.path().to_path_buf();
        let (started_tx, started_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            coordinate_inspected_replacement(&request, &authority, new_intent, binding, Some(&root))
        });
        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(30));

        let commit = ReplacementCommitFact {
            schema_version: 1,
            canonical_intent_sha256: old_intent.canonical_sha256().unwrap(),
            intent: old_intent,
            cleanup_complete: false,
            candidate_layout_complete: false,
            canonical_identity_sha256: None,
        };
        let mut store = FileReplacementCommitStore::at(
            production_path(PRODUCTION_REPLACEMENT_COMMIT_PATH, Some(temporary.path())),
            0,
        );
        store.persist(&commit).unwrap();
        drop(guard);

        assert_eq!(
            worker.join().unwrap(),
            LifecycleResponse::failed("lifecycle.replacement_commit_conflict")
        );
        assert_eq!(fs::read(&attempt_path).unwrap(), original_capsule);
        assert_eq!(store.load().unwrap(), Some(commit));
    }

    #[test]
    fn committed_resume_requires_the_exact_durable_registration_capsule_in_both_seams() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "test requires root custody");
        let temporary = tempfile::tempdir().unwrap();
        for directory in [
            "/var/lib/enoki-probe-bootstrap",
            "/var/lib/enoki-probe-registration",
            "/etc/enoki",
        ] {
            let path = production_path(directory, Some(temporary.path()));
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let metadata_path =
            production_path(PRODUCTION_INSTALL_METADATA_PATH, Some(temporary.path()));
        fs::write(&metadata_path, b"retained old installation metadata").unwrap();
        fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o600)).unwrap();

        let capsule_token = "enk_enroll_capsule_a";
        let capsule_intent = replacement_intent("enr_0123456789abcdef", capsule_token);
        let attempt_path = production_path(
            PRODUCTION_REPLACEMENT_REGISTRATION_ATTEMPT_PATH,
            Some(temporary.path()),
        );
        crate::registration::prepare_root_replacement_registration_attempt(
            &attempt_path,
            crate::registration::RootReplacementRegistrationAttemptInput {
                enrollment_token: capsule_token.to_owned(),
                binding: capsule_intent.registration_binding().unwrap(),
            },
        )
        .unwrap();

        let committed_token = "enk_enroll_commit_b";
        let committed_intent = replacement_intent("enr_abcdef0123456789", committed_token);
        let request = replacement_request(&committed_intent, committed_token);
        let commit = ReplacementCommitFact {
            schema_version: 1,
            canonical_intent_sha256: committed_intent.canonical_sha256().unwrap(),
            intent: committed_intent.clone(),
            cleanup_complete: false,
            candidate_layout_complete: false,
            canonical_identity_sha256: None,
        };
        let commit_path =
            production_path(PRODUCTION_REPLACEMENT_COMMIT_PATH, Some(temporary.path()));
        let mut store = FileReplacementCommitStore::at(&commit_path, 0);
        store.persist(&commit).unwrap();
        let original_capsule = fs::read(&attempt_path).unwrap();
        let original_commit = fs::read(&commit_path).unwrap();

        let effects = Cell::new(0);
        assert_eq!(
            resume_committed_from_exact_request_with(&request, Some(temporary.path()), |_, _| {
                effects.set(effects.get() + 1);
                LifecycleResponse::succeeded()
            },),
            Some(LifecycleResponse::failed(
                "lifecycle.registration_attempt_failed"
            ))
        );
        assert_eq!(effects.get(), 0);
        assert_eq!(fs::read(&attempt_path).unwrap(), original_capsule);
        assert_eq!(fs::read(&commit_path).unwrap(), original_commit);
        assert_eq!(
            fs::read(&metadata_path).unwrap(),
            b"retained old installation metadata"
        );

        let post_inspection = coordinate_inspected_replacement(
            &request,
            &replacement_authority(&committed_intent),
            committed_intent.clone(),
            committed_intent.registration_binding().unwrap(),
            Some(temporary.path()),
        );
        assert_eq!(
            post_inspection,
            LifecycleResponse::failed("lifecycle.registration_attempt_failed")
        );
        assert_eq!(fs::read(&attempt_path).unwrap(), original_capsule);
        assert_eq!(fs::read(&commit_path).unwrap(), original_commit);
        assert_eq!(
            fs::read(&metadata_path).unwrap(),
            b"retained old installation metadata"
        );

        fs::remove_file(&attempt_path).unwrap();
        let missing_capsule_effects = Cell::new(0);
        assert_eq!(
            resume_committed_from_exact_request_with(&request, Some(temporary.path()), |_, _| {
                missing_capsule_effects.set(missing_capsule_effects.get() + 1);
                LifecycleResponse::succeeded()
            },),
            Some(LifecycleResponse::failed(
                "lifecycle.registration_attempt_failed"
            ))
        );
        assert_eq!(missing_capsule_effects.get(), 0);
        assert_eq!(fs::read(&commit_path).unwrap(), original_commit);
        assert_eq!(
            fs::read(&metadata_path).unwrap(),
            b"retained old installation metadata"
        );

        let exact_root = tempfile::tempdir().unwrap();
        for directory in [
            "/var/lib/enoki-probe-bootstrap",
            "/var/lib/enoki-probe-registration",
        ] {
            let path = production_path(directory, Some(exact_root.path()));
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let exact_attempt_path = production_path(
            PRODUCTION_REPLACEMENT_REGISTRATION_ATTEMPT_PATH,
            Some(exact_root.path()),
        );
        crate::registration::prepare_root_replacement_registration_attempt(
            &exact_attempt_path,
            crate::registration::RootReplacementRegistrationAttemptInput {
                enrollment_token: committed_token.to_owned(),
                binding: committed_intent.registration_binding().unwrap(),
            },
        )
        .unwrap();
        let exact_commit_path =
            production_path(PRODUCTION_REPLACEMENT_COMMIT_PATH, Some(exact_root.path()));
        FileReplacementCommitStore::at(&exact_commit_path, 0)
            .persist(&commit)
            .unwrap();
        let exact_effects = Cell::new(0);
        assert_eq!(
            resume_committed_from_exact_request_with(
                &request,
                Some(exact_root.path()),
                |resumed, _| {
                    exact_effects.set(exact_effects.get() + 1);
                    assert_eq!(resumed, commit);
                    LifecycleResponse::succeeded()
                },
            ),
            Some(LifecycleResponse::succeeded())
        );
        assert_eq!(exact_effects.get(), 1);
    }

    fn metadata_for_hub(
        hub_url: &str,
        install_path: &Path,
        operation_status_path: &Path,
    ) -> TrustedProbeInstallMetadata {
        TrustedProbeInstallMetadata {
            schema_version: 0,
            hub_url: crate::hub_url::normalized_base(hub_url).expect("有效 Hub URL"),
            identity_path: operation_status_path
                .parent()
                .unwrap()
                .join("probe-bootstrap.toml"),
            install_path: install_path.to_path_buf(),
            operation_status_path: operation_status_path.to_path_buf(),
            probe_asset_public_key_sha256: "a".repeat(64),
            probe_distribution_root_sha256: None,
            bootstrap_acquirer_path: None,
            bootstrap_activator_path: None,
            bootstrap_state_dir: None,
            service_name: "enoki-probe".to_owned(),
            service_group: "enoki-probe".to_owned(),
            service_unit_path: operation_status_path
                .parent()
                .unwrap()
                .join("enoki-probe.service"),
            service_user: "enoki-probe".to_owned(),
            state_dir: operation_status_path.parent().unwrap().to_path_buf(),
            operation_sudoers_path: None,
            collector_helper_sudoers_path: None,
            old_sudoers_paths: Vec::new(),
            observation_runtime_path: None,
            cpu_provider_path: None,
            disk_health_provider_path: None,
            lifecycle_companion_path: None,
            observation_unit_paths: Vec::new(),
            probe_ipc_group: None,
            probe_ipc_group_ownership: None,
            observation_ipc_group: None,
            install_state_sha256: None,
            target_manifest_sha256: None,
            bundle_version: None,
            lifecycle_authority_install_key: None,
        }
    }
}
