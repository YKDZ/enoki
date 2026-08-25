use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use serde::Deserialize;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::replacement::ReplacementRegistrationBinding;

use super::{FixedInstallPaths, InstallError, installed_layout, upgrade};

const ATTEMPT_SOURCE: &str = "/var/lib/enoki-probe-registration/attempt.json";
const ATTEMPT_CREDENTIAL: &str = "/run/credentials/enoki-probe.service/registration-attempt";
const DELIVERY_DROP_IN: &str =
    "/run/systemd/system/enoki-probe.service.d/10-enoki-replacement-registration.conf";

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
    crate::secure_file::retire_replacement_atomic_write_residue(path, 0o600, (uid, gid))
        .map_err(|_| InstallError::ExistingResidue)?;
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
