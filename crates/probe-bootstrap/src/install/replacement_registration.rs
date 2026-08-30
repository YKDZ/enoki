use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::OsStr,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::secure_file::{
    SystemdProbeDirectory, open_systemd_probe_state_projection_for_finalization,
};
use crate::{
    handoff::Enrollment, replacement::ReplacementRegistrationBinding, verifier::VerifiedBundle,
};

use super::{FixedInstallPaths, InstallError, installed_layout, upgrade};

const ATTEMPT_SOURCE: &str = "/var/lib/enoki-probe-registration/attempt.json";
const ATTEMPT_CREDENTIAL: &str = "/run/credentials/enoki-probe.service/registration-attempt";
const DELIVERY_DROP_IN: &str =
    "/run/systemd/system/enoki-probe.service.d/10-enoki-replacement-registration.conf";
const REGISTRATION_IDENTITY_KEYS: [&str; 13] = [
    "registration_attempt_credential_path",
    "registration_committed_source_probe_sha256",
    "registration_enrollment_id",
    "registration_host_id",
    "registration_hub_origin",
    "registration_old_probe_id",
    "registration_replacement_commit_sha256",
    "registration_signed_attempt_sha256",
    "registration_source_probe_version",
    "registration_target_asset_set_digest",
    "registration_target_bundle_target",
    "registration_target_manifest_sha256",
    "registration_target_probe_version",
];

#[derive(Clone, Copy, Eq, PartialEq)]
enum RegistrationIdentityShape {
    Transitional,
    Canonical,
}

impl FixedInstallPaths {
    pub(super) fn replacement_registration_drop_in(&self) -> PathBuf {
        if self.root == Path::new("/") {
            self.map(DELIVERY_DROP_IN)
        } else {
            self.map(
                "/etc/systemd/system/enoki-probe.service.d/10-enoki-replacement-registration.conf",
            )
        }
    }

    pub(super) fn replacement_registration_attempt_source(&self) -> PathBuf {
        self.map(ATTEMPT_SOURCE)
    }
}

pub(super) fn publish_drop_in(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    let path = paths.replacement_registration_drop_in();
    let directory = path.parent().ok_or(InstallError::Io)?;
    match fs::create_dir(directory) {
        Ok(()) => fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| InstallError::Io)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(InstallError::Io),
    }
    let metadata = fs::symlink_metadata(directory).map_err(|_| InstallError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != paths.expected_root_uid()
        || metadata.gid() != paths.expected_root_gid()
    {
        return Err(InstallError::ExistingResidue);
    }
    let contents = format!("[Service]\nLoadCredential=registration-attempt:{ATTEMPT_SOURCE}\n");
    crate::secure_file::atomic_write(
        &path,
        contents.as_bytes(),
        0o600,
        Some((paths.expected_root_uid(), paths.expected_root_gid())),
    )
    .map_err(|_| InstallError::Io)
}

pub(super) fn retire_drop_in(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    retire_private_file(
        &paths.replacement_registration_drop_in(),
        paths.expected_root_uid(),
        paths.expected_root_gid(),
    )
}

pub(crate) fn retire_attempt_source(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    retire_private_file(
        &paths.replacement_registration_attempt_source(),
        paths.expected_root_uid(),
        paths.expected_root_gid(),
    )
}

pub(super) fn require_canonical_restart_ready(
    paths: &FixedInstallPaths,
    binding: &ReplacementRegistrationBinding,
) -> Result<(), InstallError> {
    match fs::symlink_metadata(paths.replacement_registration_drop_in()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Err(InstallError::ExistingResidue),
    }
    canonical_identity_matches(paths, binding)
        .then_some(())
        .ok_or(InstallError::ExistingResidue)
}

pub(super) fn converge_registered_identity_to_canonical(
    paths: &FixedInstallPaths,
    binding: &ReplacementRegistrationBinding,
) -> Result<(), InstallError> {
    let (identity, owner) = read_identity(paths)?;
    match registration_identity_shape(&identity)? {
        RegistrationIdentityShape::Transitional => {
            if !registered_identity_matches(paths, binding) {
                return Err(InstallError::ExistingResidue);
            }
            let canonical = render_canonical_identity(&identity)?;
            write_identity(paths, &canonical, owner)?;
        }
        RegistrationIdentityShape::Canonical => {}
    }
    canonical_identity_matches(paths, binding)
        .then_some(())
        .ok_or(InstallError::ExistingResidue)
}

/// Returns an exact digest of the already-canonical identity.  A legacy
/// commit may establish this custody only while its root-private attempt
/// capsule is still present; a bound commit can later prove the same bytes
/// after the capsule has been retired.
pub(super) fn canonical_identity_sha256(
    paths: &FixedInstallPaths,
    binding: &ReplacementRegistrationBinding,
    require_attempt_capsule: bool,
) -> Result<String, InstallError> {
    let (identity, _) = read_identity(paths)?;
    if !canonical_identity_matches_contents(paths, &identity, binding)
        || (require_attempt_capsule && !matches!(read_attempt_receipt(paths), Ok(Some(_))))
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(format!("{:x}", Sha256::digest(identity.as_bytes())))
}

/// Projects only the already-canonical registered identity and correlates it
/// with the independent terminal-recovery Enrollment. This is intentionally a
/// read-only guard: the caller must reject before finalizer cleanup can retire
/// the predecessor's commit or attempt capsule.
pub(super) fn completed_predecessor_matches_current_enrollment(
    paths: &FixedInstallPaths,
    predecessor: &ReplacementRegistrationBinding,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
) -> bool {
    let Some(current) = enrollment.replacement_migration() else {
        return false;
    };
    let Some((current_probe_sha256, _)) = bundle.component_receipt("probe") else {
        return false;
    };
    if enrollment.hub_origin() != predecessor.hub_origin
        || current.target_host_id() != predecessor.host_id
        || current.source_probe_version() != predecessor.target_probe_version
        || !current
            .source_probe_sha256()
            .iter()
            .any(|digest| digest == current_probe_sha256)
        || current.target_probe_version() != predecessor.target_probe_version
        || current.target_asset_set_digest() != predecessor.target_asset_set_digest
        || bundle.target != predecessor.target_bundle_target
        || bundle.version != predecessor.target_probe_version
        || format!("sha256:{}", bundle.asset_set_manifest_sha256)
            != predecessor.target_asset_set_digest
        || bundle.manifest_sha256 != predecessor.target_manifest_sha256
    {
        return false;
    }
    let Ok((identity, _)) = read_identity(paths) else {
        return false;
    };
    if !canonical_identity_matches_contents(paths, &identity, predecessor) {
        return false;
    }
    upgrade::metadata_string(&identity, "probe_id").as_deref() == Some(current.expected_probe_id())
}

pub(super) fn registered_identity_matches(
    paths: &FixedInstallPaths,
    binding: &ReplacementRegistrationBinding,
) -> bool {
    let Ok(directory) = fs::symlink_metadata(paths.identity_dir()) else {
        return false;
    };
    let Ok(metadata) = fs::symlink_metadata(paths.identity()) else {
        return false;
    };
    if directory.file_type().is_symlink()
        || !directory.is_dir()
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != directory.uid()
        || metadata.gid() != directory.gid()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return false;
    }
    let Ok(identity) =
        installed_layout::trusted_text(&paths.identity(), metadata.uid(), metadata.gid(), 0o600)
    else {
        return false;
    };
    let Ok(capsule) = installed_layout::trusted_text(
        &paths.replacement_registration_attempt_source(),
        paths.expected_root_uid(),
        paths.expected_root_gid(),
        0o600,
    )
    .and_then(|contents| {
        serde_json::from_str::<ReplacementRegistrationAttemptReceipt>(&contents)
            .map_err(|_| InstallError::ExistingResidue)
    }) else {
        return false;
    };
    let value = |key| upgrade::metadata_string(&identity, key);
    let private_key = value("probe_private_key_pem");
    capsule.schema_version == 1
        && capsule.hub_origin.trim_end_matches('/') == binding.hub_origin.trim_end_matches('/')
        && capsule.local_clock_reference_ms > 0
        && valid_lower_sha256(&capsule.enrollment_token_sha256)
        && valid_lower_sha256(&capsule.signed_attempt_sha256)
        && !capsule.request_hex.is_empty()
        && capsule
            .request_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value("enrollment_token").is_none()
        && value("hub_url")
            .as_deref()
            .map(|hub| hub.trim_end_matches('/'))
            == Some(binding.hub_origin.trim_end_matches('/'))
        && value("enrollment_id").as_deref() == Some(binding.enrollment_id.as_str())
        && value("host_id").as_deref() == Some(binding.host_id.as_str())
        && value("probe_id")
            .is_some_and(|probe_id| !probe_id.is_empty() && probe_id != binding.old_probe_id)
        && private_key.as_deref().is_some_and(|pem| {
            pem == capsule.candidate_private_key_pem && RsaPrivateKey::from_pkcs8_pem(pem).is_ok()
        })
        && value("registration_attempt_credential_path").as_deref() == Some(ATTEMPT_CREDENTIAL)
        && value("registration_committed_source_probe_sha256").as_deref()
            == Some(binding.committed_source_probe_sha256.as_str())
        && value("registration_enrollment_id").as_deref() == Some(binding.enrollment_id.as_str())
        && value("registration_host_id").as_deref() == Some(binding.host_id.as_str())
        && value("registration_hub_origin").as_deref() == Some(binding.hub_origin.as_str())
        && value("registration_old_probe_id").as_deref() == Some(binding.old_probe_id.as_str())
        && value("registration_replacement_commit_sha256").as_deref()
            == Some(binding.replacement_commit_sha256.as_str())
        && value("registration_source_probe_version").as_deref()
            == Some(binding.source_probe_version.as_str())
        && value("registration_signed_attempt_sha256").as_deref()
            == Some(capsule.signed_attempt_sha256.as_str())
        && value("registration_target_asset_set_digest").as_deref()
            == Some(binding.target_asset_set_digest.as_str())
        && value("registration_target_bundle_target").as_deref()
            == Some(binding.target_bundle_target.as_str())
        && value("registration_target_manifest_sha256").as_deref()
            == Some(binding.target_manifest_sha256.as_str())
        && value("registration_target_probe_version").as_deref()
            == Some(binding.target_probe_version.as_str())
}

fn canonical_identity_matches(
    paths: &FixedInstallPaths,
    binding: &ReplacementRegistrationBinding,
) -> bool {
    let Ok((identity, _)) = read_identity(paths) else {
        return false;
    };
    canonical_identity_matches_contents(paths, &identity, binding)
}

fn canonical_identity_matches_contents(
    paths: &FixedInstallPaths,
    identity: &str,
    binding: &ReplacementRegistrationBinding,
) -> bool {
    if registration_identity_shape(identity) != Ok(RegistrationIdentityShape::Canonical) {
        return false;
    }
    let value = |key| upgrade::metadata_string(identity, key);
    let Some(private_key) = value("probe_private_key_pem") else {
        return false;
    };
    if value("enrollment_token").is_some()
        || value("hub_url")
            .as_deref()
            .map(|hub| hub.trim_end_matches('/'))
            != Some(binding.hub_origin.trim_end_matches('/'))
        || value("enrollment_id").as_deref() != Some(binding.enrollment_id.as_str())
        || value("host_id").as_deref() != Some(binding.host_id.as_str())
        || value("probe_id")
            .is_none_or(|probe_id| probe_id.is_empty() || probe_id == binding.old_probe_id)
        || RsaPrivateKey::from_pkcs8_pem(&private_key).is_err()
    {
        return false;
    }

    match read_attempt_receipt(paths) {
        Ok(Some(capsule)) => private_key == capsule.candidate_private_key_pem,
        Ok(None) => true,
        Err(()) => false,
    }
}

fn read_identity(paths: &FixedInstallPaths) -> Result<(String, (u32, u32)), InstallError> {
    let state = fs::symlink_metadata(paths.state()).map_err(|_| InstallError::ExistingResidue)?;
    if state.file_type().is_symlink() {
        let projection = open_systemd_probe_state_projection_for_finalization(
            &paths.state(),
            (paths.expected_root_uid(), paths.expected_root_gid()),
        )
        .map_err(|_| InstallError::ExistingResidue)?;
        let owner = projection.owner();
        let bytes = projection
            .read_file(
                SystemdProbeDirectory::Identity,
                OsStr::new("probe-bootstrap.toml"),
            )
            .map_err(|_| InstallError::ExistingResidue)?;
        let identity = String::from_utf8(bytes).map_err(|_| InstallError::ExistingResidue)?;
        return Ok((identity, owner));
    }
    let directory =
        fs::symlink_metadata(paths.identity_dir()).map_err(|_| InstallError::ExistingResidue)?;
    let metadata =
        fs::symlink_metadata(paths.identity()).map_err(|_| InstallError::ExistingResidue)?;
    if directory.file_type().is_symlink()
        || !directory.is_dir()
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != directory.uid()
        || metadata.gid() != directory.gid()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(InstallError::ExistingResidue);
    }
    installed_layout::trusted_text(&paths.identity(), metadata.uid(), metadata.gid(), 0o600)
        .map(|identity| (identity, (metadata.uid(), metadata.gid())))
}

fn write_identity(
    paths: &FixedInstallPaths,
    canonical: &str,
    owner: (u32, u32),
) -> Result<(), InstallError> {
    let state = fs::symlink_metadata(paths.state()).map_err(|_| InstallError::ExistingResidue)?;
    if state.file_type().is_symlink() {
        return open_systemd_probe_state_projection_for_finalization(
            &paths.state(),
            (paths.expected_root_uid(), paths.expected_root_gid()),
        )
        .and_then(|projection| {
            (projection.owner() == owner).then_some(()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Probe identity owner changed before canonical rewrite",
                )
            })?;
            projection.write_probe_bootstrap_config(&paths.identity(), canonical.as_bytes())
        })
        .map_err(|_| InstallError::ExistingResidue);
    }
    crate::secure_file::atomic_write(&paths.identity(), canonical.as_bytes(), 0o600, Some(owner))
        .map_err(|_| InstallError::ExistingResidue)
}

fn read_attempt_receipt(
    paths: &FixedInstallPaths,
) -> Result<Option<ReplacementRegistrationAttemptReceipt>, ()> {
    match fs::symlink_metadata(paths.replacement_registration_attempt_source()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
        Ok(_) => installed_layout::trusted_text(
            &paths.replacement_registration_attempt_source(),
            paths.expected_root_uid(),
            paths.expected_root_gid(),
            0o600,
        )
        .and_then(|contents| {
            serde_json::from_str::<ReplacementRegistrationAttemptReceipt>(&contents)
                .map_err(|_| InstallError::ExistingResidue)
        })
        .map(Some)
        .map_err(|_| ()),
    }
}

fn registration_identity_shape(identity: &str) -> Result<RegistrationIdentityShape, InstallError> {
    if !identity.ends_with('\n') {
        return Err(InstallError::ExistingResidue);
    }
    let mut seen = HashSet::new();
    let mut registration_keys = HashSet::new();
    for line in identity.lines() {
        let (key, _) = line.split_once('=').ok_or(InstallError::ExistingResidue)?;
        let key = key.trim();
        if key.is_empty() || !seen.insert(key) {
            return Err(InstallError::ExistingResidue);
        }
        if key.starts_with("registration_") {
            if !REGISTRATION_IDENTITY_KEYS.contains(&key) {
                return Err(InstallError::ExistingResidue);
            }
            registration_keys.insert(key);
        }
    }
    if registration_keys.is_empty() {
        Ok(RegistrationIdentityShape::Canonical)
    } else if registration_keys.len() == REGISTRATION_IDENTITY_KEYS.len() {
        Ok(RegistrationIdentityShape::Transitional)
    } else {
        Err(InstallError::ExistingResidue)
    }
}

fn render_canonical_identity(identity: &str) -> Result<String, InstallError> {
    if registration_identity_shape(identity)? != RegistrationIdentityShape::Transitional {
        return Err(InstallError::ExistingResidue);
    }
    let mut canonical = String::with_capacity(identity.len());
    for line in identity.lines() {
        let (key, _) = line.split_once('=').ok_or(InstallError::ExistingResidue)?;
        if !key.trim().starts_with("registration_") {
            canonical.push_str(line);
            canonical.push('\n');
        }
    }
    Ok(canonical)
}

pub(super) fn append_bootstrap_config(
    config: &mut String,
    binding: &ReplacementRegistrationBinding,
) {
    config.push_str(&format!(
        "registration_attempt_credential_path = {:?}\nregistration_enrollment_id = {:?}\nregistration_host_id = {:?}\nregistration_hub_origin = {:?}\nregistration_old_probe_id = {:?}\nregistration_source_probe_version = {:?}\nregistration_committed_source_probe_sha256 = {:?}\nregistration_target_probe_version = {:?}\nregistration_target_bundle_target = {:?}\nregistration_target_asset_set_digest = {:?}\nregistration_target_manifest_sha256 = {:?}\nregistration_replacement_commit_sha256 = {:?}\n",
        ATTEMPT_CREDENTIAL,
        binding.enrollment_id,
        binding.host_id,
        binding.hub_origin,
        binding.old_probe_id,
        binding.source_probe_version,
        binding.committed_source_probe_sha256,
        binding.target_probe_version,
        binding.target_bundle_target,
        binding.target_asset_set_digest,
        binding.target_manifest_sha256,
        binding.replacement_commit_sha256,
    ));
}

fn retire_private_file(path: &Path, uid: u32, gid: u32) -> Result<(), InstallError> {
    match crate::secure_file::remove_private_regular_file(path, 0o600, (uid, gid)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(InstallError::ExistingResidue),
    }
    match crate::secure_file::retire_replacement_atomic_write_residue(path, 0o600, (uid, gid)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(InstallError::ExistingResidue),
    }
    match fs::remove_dir(path.parent().ok_or(InstallError::Io)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError::ExistingResidue),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplacementRegistrationAttemptReceipt {
    candidate_private_key_pem: String,
    enrollment_token_sha256: String,
    hub_origin: String,
    local_clock_reference_ms: u64,
    request_hex: String,
    schema_version: u8,
    signed_attempt_sha256: String,
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
