use super::{
    FixedInstallPaths, InstallError, ServiceIdentity,
    installed_layout::{self, Fingerprint, TargetKind},
    transaction::TransactionJournal,
};
use crate::secure_file::{
    SystemdProbeDirectory, SystemdProbeStateProjection,
    open_systemd_probe_state_projection_for_finalization,
};
use crate::{replacement::ReplacementCommitFact, verifier::VerifiedBundle};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

const MAX_METADATA_BYTES: u64 = 256 * 1024;

struct IdentityCustody {
    owner_receipt: ServiceIdentity,
    projection: Option<SystemdProbeStateProjection>,
}

pub(super) fn verify_exact_layout(
    paths: &FixedInstallPaths,
    bundle: &VerifiedBundle,
    commit: &ReplacementCommitFact,
    journal: Option<&TransactionJournal>,
) -> Result<(), InstallError> {
    let held_metadata_directory = hold_fixed_metadata_directory(paths)?;
    if let Some(journal) = journal {
        verify_exact_journal_layout(paths, journal)?;
    }
    let identity_custody = identity_custody(paths)?;
    let identity_owner_receipt = identity_custody.owner_receipt;
    let identity_owner = paths.observed_identity_owner(identity_owner_receipt);
    if !commit.has_valid_binding()
        || !commit.cleanup_complete
        || !commit.candidate_layout_complete
        || commit.intent.target_probe_version != bundle.version
        || commit.intent.target_bundle_target != bundle.target
        || commit.intent.target_manifest_sha256 != bundle.manifest_sha256
        || commit.intent.target_asset_set_digest
            != format!("sha256:{}", bundle.asset_set_manifest_sha256)
    {
        return Err(InstallError::ExistingResidue);
    }

    let root_uid = paths.expected_root_uid();
    let root_gid = paths.expected_root_gid();
    let current_layout = installed_layout::trusted_text(
        &paths.bootstrap_state().join("current-layout"),
        root_uid,
        root_gid,
        0o600,
    )?;
    if current_layout != format!("schema_version=1\nversion={}\n", bundle.version) {
        return Err(InstallError::ExistingResidue);
    }
    if identity_custody.projection.is_none() {
        verify_identity_directory(paths, identity_owner)?;
    }

    let registry = installed_layout::registry(paths);
    if registry.len() != installed_layout::TARGET_COUNT {
        return Err(InstallError::ExistingResidue);
    }
    for target in registry {
        match target.kind {
            TargetKind::Bundle(role) => {
                let (sha256, length) = bundle
                    .component_receipt(role)
                    .ok_or(InstallError::InvalidVerifiedComponent)?;
                installed_layout::verify_fingerprint(
                    &target.destination,
                    &Fingerprint {
                        length,
                        sha256: sha256.to_owned(),
                        uid: root_uid,
                        gid: root_gid,
                        mode: target.mode,
                    },
                )?;
            }
            TargetKind::Unit(generate) => {
                let contents = generate();
                installed_layout::verify_fingerprint(
                    &target.destination,
                    &Fingerprint {
                        length: contents.len() as u64,
                        sha256: format!("{:x}", Sha256::digest(contents.as_bytes())),
                        uid: root_uid,
                        gid: root_gid,
                        mode: target.mode,
                    },
                )?;
            }
            TargetKind::Metadata => {
                verify_metadata(paths, bundle, commit, &held_metadata_directory)?
            }
            TargetKind::Identity => verify_identity(
                paths,
                bundle,
                commit,
                identity_owner,
                identity_custody.projection.as_ref(),
            )?,
        }
    }
    recheck_fixed_metadata_directory(paths, &held_metadata_directory)?;
    drop(held_metadata_directory);
    Ok(())
}

fn hold_fixed_metadata_directory(paths: &FixedInstallPaths) -> Result<File, InstallError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(paths.etc_enoki())
        .map_err(|_| InstallError::ExistingResidue)?;
    let metadata = directory
        .metadata()
        .map_err(|_| InstallError::ExistingResidue)?;
    if !metadata.is_dir()
        || metadata.uid() != paths.expected_root_uid()
        || metadata.gid() != paths.expected_root_gid()
        || metadata.mode() & 0o7777 != 0o755
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(directory)
}

fn recheck_fixed_metadata_directory(
    paths: &FixedInstallPaths,
    held: &File,
) -> Result<(), InstallError> {
    let path_metadata =
        std::fs::symlink_metadata(paths.etc_enoki()).map_err(|_| InstallError::ExistingResidue)?;
    let held_metadata = held.metadata().map_err(|_| InstallError::ExistingResidue)?;
    (!path_metadata.file_type().is_symlink()
        && path_metadata.is_dir()
        && path_metadata.dev() == held_metadata.dev()
        && path_metadata.ino() == held_metadata.ino()
        && path_metadata.uid() == held_metadata.uid()
        && path_metadata.gid() == held_metadata.gid()
        && path_metadata.mode() & 0o7777 == held_metadata.mode() & 0o7777
        && held_metadata.uid() == paths.expected_root_uid()
        && held_metadata.gid() == paths.expected_root_gid()
        && held_metadata.mode() & 0o7777 == 0o755)
        .then_some(())
        .ok_or(InstallError::ExistingResidue)
}

fn verify_exact_journal_layout(
    paths: &FixedInstallPaths,
    journal: &TransactionJournal,
) -> Result<(), InstallError> {
    if journal.identity().is_none() {
        return Err(InstallError::ExistingResidue);
    }
    let registry = installed_layout::registry(paths);
    let expected_count = registry.len() + 3;
    let mut expected = registry
        .into_iter()
        .map(|target| target.destination)
        .collect::<BTreeSet<_>>();
    expected.extend([paths.etc_enoki(), paths.state(), paths.identity_dir()]);
    if expected.len() != expected_count {
        return Err(InstallError::ExistingResidue);
    }

    let mut actual = journal
        .paths()
        .iter()
        .map(|owned| owned.path().to_owned())
        .collect::<BTreeSet<_>>();
    if actual.len() != journal.paths().len() {
        return Err(InstallError::ExistingResidue);
    }
    let metadata_directory_receipts = journal
        .paths()
        .iter()
        .filter(|owned| owned.path() == paths.etc_enoki())
        .collect::<Vec<_>>();
    match metadata_directory_receipts.as_slice() {
        [] => {
            actual.insert(paths.etc_enoki());
        }
        [owned] if owned.directory() && owned.still_owned() => {}
        _ => return Err(InstallError::ExistingResidue),
    }
    if actual != expected
        || !journal
            .paths()
            .iter()
            .filter(|owned| {
                ![paths.state(), paths.identity_dir(), paths.identity()]
                    .iter()
                    .any(|mutable| owned.path() == mutable)
            })
            .all(|owned| owned.still_owned())
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

fn identity_custody(paths: &FixedInstallPaths) -> Result<IdentityCustody, InstallError> {
    let state =
        std::fs::symlink_metadata(paths.state()).map_err(|_| InstallError::ExistingResidue)?;
    if state.file_type().is_symlink() {
        let projection = open_systemd_probe_state_projection_for_finalization(
            &paths.state(),
            (paths.expected_root_uid(), paths.expected_root_gid()),
        )
        .map_err(|_| InstallError::ExistingResidue)?;
        let observed = projection.owner();
        let owner_receipt = paths.identity_owner_receipt(ServiceIdentity {
            uid: observed.0,
            gid: observed.1,
        });
        if owner_receipt.uid == paths.expected_root_uid()
            || owner_receipt.gid == paths.expected_root_gid()
        {
            return Err(InstallError::ExistingResidue);
        }
        return Ok(IdentityCustody {
            owner_receipt,
            projection: Some(projection),
        });
    }
    let identity = std::fs::symlink_metadata(paths.identity_dir())
        .map_err(|_| InstallError::ExistingResidue)?;
    if identity.file_type().is_symlink()
        || !state.is_dir()
        || !identity.is_dir()
        || state.uid() != identity.uid()
        || state.gid() != identity.gid()
        || state.mode() & 0o7777 != 0o750
        || identity.mode() & 0o7777 != 0o700
    {
        return Err(InstallError::ExistingResidue);
    }
    let receipt = paths.identity_owner_receipt(ServiceIdentity {
        uid: identity.uid(),
        gid: identity.gid(),
    });
    if receipt.uid == paths.expected_root_uid() || receipt.gid == paths.expected_root_gid() {
        return Err(InstallError::ExistingResidue);
    }
    Ok(IdentityCustody {
        owner_receipt: receipt,
        projection: None,
    })
}

fn verify_identity_directory(
    paths: &FixedInstallPaths,
    expected: ServiceIdentity,
) -> Result<(), InstallError> {
    let metadata = std::fs::symlink_metadata(paths.identity_dir())
        .map_err(|_| InstallError::ExistingResidue)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected.uid
        || metadata.gid() != expected.gid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

fn verify_metadata(
    paths: &FixedInstallPaths,
    bundle: &VerifiedBundle,
    commit: &ReplacementCommitFact,
    metadata_directory: &File,
) -> Result<(), InstallError> {
    let root_uid = paths.expected_root_uid();
    let descriptor = unsafe {
        libc::openat(
            metadata_directory.as_raw_fd(),
            c"probe-install.toml".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(InstallError::ExistingResidue);
    }
    let mut metadata_file = unsafe { File::from_raw_fd(descriptor) };
    let opened = metadata_file
        .metadata()
        .map_err(|_| InstallError::ExistingResidue)?;
    if !opened.is_file()
        || opened.uid() != root_uid
        || opened.gid() != paths.expected_root_gid()
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.len() == 0
        || opened.len() > MAX_METADATA_BYTES
    {
        return Err(InstallError::ExistingResidue);
    }
    let mut bytes = Vec::new();
    metadata_file
        .by_ref()
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallError::Io)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(InstallError::ExistingResidue);
    }
    let metadata = String::from_utf8(bytes).map_err(|_| InstallError::ExistingResidue)?;
    if super::upgrade::metadata_scalar(&metadata, "schema_version").as_deref() != Some("5")
        || super::upgrade::metadata_string(&metadata, "bundle_version").as_deref()
            != Some(bundle.version.as_str())
        || super::upgrade::metadata_string(&metadata, "target_manifest_sha256").as_deref()
            != Some(bundle.manifest_sha256.as_str())
        || super::upgrade::metadata_string(&metadata, "install_state_sha256").as_deref()
            != Some(bundle.install_state_sha256().as_str())
        || super::upgrade::metadata_string(&metadata, "hub_url")
            .as_deref()
            .map(|value| value.trim_end_matches('/'))
            != Some(commit.intent.hub_origin.trim_end_matches('/'))
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

fn verify_identity(
    paths: &FixedInstallPaths,
    bundle: &VerifiedBundle,
    commit: &ReplacementCommitFact,
    owner: ServiceIdentity,
    projection: Option<&SystemdProbeStateProjection>,
) -> Result<(), InstallError> {
    let identity = match projection {
        Some(projection) => String::from_utf8(
            projection
                .read_file(
                    SystemdProbeDirectory::Identity,
                    OsStr::new("probe-bootstrap.toml"),
                )
                .map_err(|_| InstallError::ExistingResidue)?,
        )
        .map_err(|_| InstallError::ExistingResidue)?,
        None => installed_layout::trusted_text(&paths.identity(), owner.uid, owner.gid, 0o600)?,
    };
    let private_key = super::upgrade::metadata_string(&identity, "probe_private_key_pem")
        .ok_or(InstallError::ExistingResidue)?;
    if RsaPrivateKey::from_pkcs8_pem(&private_key).is_err()
        || super::upgrade::metadata_string(&identity, "hub_url")
            .as_deref()
            .map(|value| value.trim_end_matches('/'))
            != Some(commit.intent.hub_origin.trim_end_matches('/'))
        || super::upgrade::metadata_string(&identity, "host_id").as_deref()
            != Some(commit.intent.host_id.as_str())
        || super::upgrade::metadata_string(&identity, "enrollment_id").as_deref()
            != Some(commit.intent.enrollment_id.as_str())
        || super::upgrade::metadata_string(&identity, "probe_id")
            .is_none_or(|probe_id| probe_id.is_empty() || probe_id == commit.intent.old_probe_id)
        || super::upgrade::metadata_string(&identity, "bundle_version").as_deref()
            != Some(bundle.version.as_str())
        || super::upgrade::metadata_string(&identity, "target_manifest_sha256").as_deref()
            != Some(bundle.manifest_sha256.as_str())
        || super::upgrade::metadata_string(&identity, "install_state_sha256").as_deref()
            != Some(bundle.install_state_sha256().as_str())
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use tempfile::tempdir;

    #[test]
    fn held_metadata_directory_recheck_rejects_a_legal_path_swap() {
        let temporary = tempdir().unwrap();
        fs::create_dir_all(temporary.path().join("etc/enoki")).unwrap();
        fs::set_permissions(
            temporary.path().join("etc/enoki"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let paths = FixedInstallPaths::under(temporary.path());
        let held = hold_fixed_metadata_directory(&paths).unwrap();
        fs::rename(
            paths.etc_enoki(),
            temporary.path().join("etc/enoki-before-swap"),
        )
        .unwrap();
        fs::create_dir(paths.etc_enoki()).unwrap();
        fs::set_permissions(paths.etc_enoki(), fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            recheck_fixed_metadata_directory(&paths, &held),
            Err(InstallError::ExistingResidue)
        );
    }

    #[test]
    fn held_metadata_directory_recheck_rejects_a_mode_change_on_the_same_inode() {
        let temporary = tempdir().unwrap();
        fs::create_dir_all(temporary.path().join("etc/enoki")).unwrap();
        fs::set_permissions(
            temporary.path().join("etc/enoki"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let paths = FixedInstallPaths::under(temporary.path());
        let held = hold_fixed_metadata_directory(&paths).unwrap();

        fs::set_permissions(paths.etc_enoki(), fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(
            recheck_fixed_metadata_directory(&paths, &held),
            Err(InstallError::ExistingResidue)
        );
    }
}
