use super::{
    FixedInstallPaths, InstallError, SystemdPort, VerifiedUpgradeComponents,
    upgrade::{
        InstalledBundleRepairBinding, InstalledUpgradeBinding, updated_metadata,
        updated_receipt_projection,
    },
};
use crate::replacement::ReplacementCommitFact;
use crate::verifier::VerifiedBundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::Instant,
};

const JOURNAL_NAME: &str = "installed-bundle-repair.json";
const MAX_JOURNAL_BYTES: u64 = 256 * 1024;
const TARGET_COUNT: usize = 21;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BundleRestoreReceipt {
    pub(super) binding_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fingerprint {
    length: u64,
    sha256: String,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Debug)]
struct PlannedTarget {
    id: &'static str,
    destination: PathBuf,
    bytes: Vec<u8>,
    fingerprint: Fingerprint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetJournal {
    id: String,
    new: Fingerprint,
    old: Option<Fingerprint>,
    prepared: bool,
    backed_up: bool,
    published: bool,
    cleaned: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    schema_version: u16,
    transaction_id: String,
    binding_sha256: String,
    retirement_binding_sha256: String,
    spec_sha256: String,
    targets: Vec<TargetJournal>,
    mutation_intent: bool,
    stopped: bool,
    reloaded: bool,
    full_payload_verified: bool,
    complete: bool,
}

pub(super) fn restore(
    mut components: VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    installed: &InstalledUpgradeBinding,
    repair: &InstalledBundleRepairBinding,
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<BundleRestoreReceipt, InstallError> {
    let binding_sha256 = repair.binding_sha256(installed, bundle, paths)?;
    let retirement_binding_sha256 = repair.retirement_binding_sha256()?;
    let planned = planned_targets(&mut components, bundle, installed, paths)?;
    if planned.len() != TARGET_COUNT {
        return Err(InstallError::ExistingResidue);
    }
    let journal_path = paths.bootstrap_state().join(JOURNAL_NAME);
    let mut journal = match load_journal(&journal_path, paths.expected_root_uid())? {
        Some(journal) => {
            validate_journal(
                &journal,
                &binding_sha256,
                &retirement_binding_sha256,
                &planned,
            )?;
            journal
        }
        None => {
            if super::upgrade::inspect_installed_probe_for_upgrade(paths)? != *installed {
                return Err(InstallError::ExistingResidue);
            }
            begin_journal(
                &journal_path,
                &binding_sha256,
                &retirement_binding_sha256,
                &planned,
                paths,
            )?
        }
    };

    for index in 0..planned.len() {
        prepare_target(index, &planned, &mut journal, &journal_path, paths)?;
    }
    for index in 0..planned.len() {
        backup_target(index, &planned, &mut journal, &journal_path, paths)?;
    }
    if !journal.mutation_intent {
        journal.mutation_intent = true;
        persist_journal(&journal_path, &journal)?;
    }
    if !journal.stopped {
        systemd.set_command_deadline(Instant::now() + super::INSTALL_COMMAND_BUDGET);
        systemd.stop()?;
        crash("stop")?;
        journal.stopped = true;
        persist_journal(&journal_path, &journal)?;
    }
    for index in 0..planned.len() {
        publish_target(index, &planned, &mut journal, &journal_path)?;
    }
    if !journal.reloaded {
        systemd.daemon_reload()?;
        crash("reload")?;
        journal.reloaded = true;
        persist_journal(&journal_path, &journal)?;
    }
    verify_targets(&planned)?;
    if !journal.full_payload_verified {
        journal.full_payload_verified = true;
        persist_journal(&journal_path, &journal)?;
    }
    for index in 0..planned.len() {
        cleanup_target(index, &planned, &mut journal, &journal_path)?;
    }
    if !journal.complete {
        journal.complete = true;
        persist_journal(&journal_path, &journal)?;
        crash("complete")?;
    }
    Ok(BundleRestoreReceipt { binding_sha256 })
}

pub(super) fn verify_complete(
    installed: &InstalledUpgradeBinding,
    bundle: &VerifiedBundle,
    repair: &InstalledBundleRepairBinding,
    paths: &FixedInstallPaths,
) -> Result<(), InstallError> {
    let binding_sha256 = repair.binding_sha256(installed, bundle, paths)?;
    let journal_path = paths.bootstrap_state().join(JOURNAL_NAME);
    let journal = load_journal(&journal_path, paths.expected_root_uid())?
        .ok_or(InstallError::ExistingResidue)?;
    if journal.schema_version != 1
        || journal.binding_sha256 != binding_sha256
        || journal.spec_sha256 != spec_sha256(&journal)?
        || journal.targets.len() != TARGET_COUNT
        || !journal.complete
        || journal.targets.iter().any(|target| !target.cleaned)
    {
        return Err(InstallError::ExistingResidue);
    }
    verify_journal_destinations(&journal, paths)?;
    Ok(())
}

pub(super) fn retire_complete(
    repair: &InstalledBundleRepairBinding,
    paths: &FixedInstallPaths,
) -> Result<(), InstallError> {
    let retirement_binding_sha256 = repair.retirement_binding_sha256()?;
    let journal_path = paths.bootstrap_state().join(JOURNAL_NAME);
    let Some(journal) = load_journal(&journal_path, paths.expected_root_uid())? else {
        return Ok(());
    };
    if journal.schema_version != 1
        || journal.retirement_binding_sha256 != retirement_binding_sha256
        || journal.spec_sha256 != spec_sha256(&journal)?
        || !journal.complete
        || journal.targets.len() != TARGET_COUNT
        || journal.targets.iter().any(|target| !target.cleaned)
    {
        return Err(InstallError::ExistingResidue);
    }
    fs::remove_file(&journal_path).map_err(|_| InstallError::Io)?;
    sync_parent(&journal_path)?;
    crash("journal-cleanup")
}

pub(super) fn verify_exact_replacement_layout(
    paths: &FixedInstallPaths,
    bundle: &VerifiedBundle,
    commit: &ReplacementCommitFact,
) -> Result<(), InstallError> {
    if commit.schema_version != 1
        || !commit.cleanup_complete
        || !commit.candidate_layout_complete
        || commit.intent.target_probe_version != bundle.version
        || commit.intent.target_manifest_sha256 != bundle.manifest_sha256
        || commit.intent.target_asset_set_digest
            != format!("sha256:{}", bundle.asset_set_manifest_sha256)
        || !super::transaction::TransactionJournal::committed_layout_matches(
            &paths.bootstrap_state(),
            &bundle.version,
        )?
    {
        return Err(InstallError::ExistingResidue);
    }
    let root_uid = paths.expected_root_uid();
    for (path, role) in [
        (paths.binary(), "probe"),
        (paths.observation_runtime_binary(), "observation-runtime"),
        (paths.cpu_provider_binary(), "system-state-provider"),
        (paths.disk_health_provider_binary(), "disk-health-provider"),
        (paths.lifecycle_companion_binary(), "lifecycle-companion"),
        (paths.bootstrap_acquirer(), "bootstrap-acquirer"),
        (paths.bootstrap_activator(), "bootstrap-activator"),
    ] {
        let (sha256, length) = bundle
            .component_receipt(role)
            .ok_or(InstallError::InvalidVerifiedComponent)?;
        verify_fingerprint(
            &path,
            &Fingerprint {
                length,
                sha256: sha256.to_owned(),
                uid: root_uid,
                gid: root_uid,
                mode: 0o755,
            },
        )?;
        require_single_link(&path)?;
    }
    for (path, contents) in canonical_unit_registry(paths) {
        verify_fingerprint(
            &path,
            &Fingerprint {
                length: contents.len() as u64,
                sha256: sha256(contents.as_bytes()),
                uid: root_uid,
                gid: root_uid,
                mode: 0o644,
            },
        )?;
        require_single_link(&path)?;
    }
    let metadata_path = paths.metadata();
    let metadata = fs::read_to_string(&metadata_path).map_err(|_| InstallError::Io)?;
    let metadata_fingerprint = fingerprint(&metadata_path)?;
    if metadata_fingerprint.uid != root_uid
        || metadata_fingerprint.gid != root_uid
        || metadata_fingerprint.mode != 0o600
        || super::upgrade::metadata_scalar(&metadata, "schema_version").as_deref() != Some("5")
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
    require_single_link(&metadata_path)?;

    let identity_path = paths.identity();
    let identity = fs::read_to_string(&identity_path).map_err(|_| InstallError::Io)?;
    let identity_fingerprint = fingerprint(&identity_path)?;
    if identity_fingerprint.uid != root_uid
        || identity_fingerprint.gid != root_uid
        || identity_fingerprint.mode != 0o600
        || super::upgrade::metadata_string(&identity, "hub_url")
            .as_deref()
            .map(|value| value.trim_end_matches('/'))
            != Some(commit.intent.hub_origin.trim_end_matches('/'))
        || super::upgrade::metadata_string(&identity, "host_id").as_deref()
            != Some(commit.intent.host_id.as_str())
        || super::upgrade::metadata_string(&identity, "probe_id")
            .is_none_or(|probe_id| probe_id.is_empty() || probe_id == commit.intent.old_probe_id)
        || super::upgrade::metadata_string(&identity, "probe_private_key_pem")
            .is_none_or(|key| key.is_empty())
        || super::upgrade::metadata_string(&identity, "bundle_version").as_deref()
            != Some(bundle.version.as_str())
        || super::upgrade::metadata_string(&identity, "target_manifest_sha256").as_deref()
            != Some(bundle.manifest_sha256.as_str())
        || super::upgrade::metadata_string(&identity, "install_state_sha256").as_deref()
            != Some(bundle.install_state_sha256().as_str())
    {
        return Err(InstallError::ExistingResidue);
    }
    require_single_link(&identity_path)
}

fn canonical_unit_registry(paths: &FixedInstallPaths) -> Vec<(PathBuf, String)> {
    vec![
        (paths.unit(), super::service_unit()),
        (
            paths.observation_runtime_unit(),
            super::observation_runtime_unit(),
        ),
        (
            paths.observation_runtime_socket_unit(),
            super::observation_runtime_socket_unit().to_owned(),
        ),
        (paths.cpu_provider_unit(), super::cpu_provider_unit()),
        (
            paths.cpu_provider_socket_unit(),
            super::cpu_provider_socket_unit().to_owned(),
        ),
        (
            paths.disk_health_provider_unit(),
            super::disk_health_provider_unit(),
        ),
        (
            paths.disk_health_provider_socket_unit(),
            super::disk_health_provider_socket_unit().to_owned(),
        ),
        (
            paths.lifecycle_companion_unit(),
            super::lifecycle_companion_unit(),
        ),
        (
            paths.lifecycle_companion_socket_unit(),
            super::lifecycle_companion_socket_unit().to_owned(),
        ),
        (
            paths.lifecycle_upgrade_unit(),
            super::lifecycle_upgrade_unit(),
        ),
        (
            paths.lifecycle_upgrade_socket_unit(),
            super::lifecycle_upgrade_socket_unit().to_owned(),
        ),
        (
            paths.observation_runtime_failure_recorder_unit(),
            super::observation_runtime_failure_recorder_unit(),
        ),
    ]
}

fn begin_journal(
    path: &Path,
    binding_sha256: &str,
    retirement_binding_sha256: &str,
    planned: &[PlannedTarget],
    paths: &FixedInstallPaths,
) -> Result<Journal, InstallError> {
    for target in planned {
        require_absent(&staged_path(&target.destination))?;
        require_absent(&backup_path(&target.destination))?;
    }
    let targets = planned
        .iter()
        .map(|target| {
            Ok(TargetJournal {
                id: target.id.to_owned(),
                new: target.fingerprint.clone(),
                old: fingerprint_if_present(&target.destination)?,
                prepared: false,
                backed_up: false,
                published: false,
                cleaned: false,
            })
        })
        .collect::<Result<Vec<_>, InstallError>>()?;
    let mut journal = Journal {
        schema_version: 1,
        transaction_id: transaction_id()?,
        binding_sha256: binding_sha256.to_owned(),
        retirement_binding_sha256: retirement_binding_sha256.to_owned(),
        spec_sha256: String::new(),
        targets,
        mutation_intent: false,
        stopped: false,
        reloaded: false,
        full_payload_verified: false,
        complete: false,
    };
    journal.spec_sha256 = spec_sha256(&journal)?;
    if paths
        .bootstrap_state()
        .metadata()
        .map_err(|_| InstallError::Io)?
        .mode()
        & 0o777
        != 0o700
    {
        return Err(InstallError::ExistingResidue);
    }
    persist_journal(path, &journal)?;
    crash("journal-publish")?;
    Ok(journal)
}

fn validate_journal(
    journal: &Journal,
    binding_sha256: &str,
    retirement_binding_sha256: &str,
    planned: &[PlannedTarget],
) -> Result<(), InstallError> {
    if journal.schema_version != 1
        || journal.transaction_id.len() != 32
        || !is_lower_hex(&journal.transaction_id)
        || journal.binding_sha256 != binding_sha256
        || journal.retirement_binding_sha256 != retirement_binding_sha256
        || journal.targets.len() != TARGET_COUNT
        || journal.spec_sha256 != spec_sha256(journal)?
    {
        return Err(InstallError::ExistingResidue);
    }
    for (stored, expected) in journal.targets.iter().zip(planned) {
        if stored.id != expected.id || stored.new != expected.fingerprint {
            return Err(InstallError::ExistingResidue);
        }
    }
    Ok(())
}

fn prepare_target(
    index: usize,
    planned: &[PlannedTarget],
    journal: &mut Journal,
    journal_path: &Path,
    paths: &FixedInstallPaths,
) -> Result<(), InstallError> {
    let target = &planned[index];
    let staged = staged_path(&target.destination);
    if journal.targets[index].published {
        require_absent(&staged)?;
        verify_fingerprint(&target.destination, &target.fingerprint)?;
        return Ok(());
    }
    if journal.targets[index].prepared {
        if staged.try_exists().map_err(|_| InstallError::Io)? {
            verify_fingerprint(&staged, &target.fingerprint)?;
        } else if journal.mutation_intent {
            verify_fingerprint(&target.destination, &target.fingerprint)?;
        } else {
            return Err(InstallError::ExistingResidue);
        }
        return Ok(());
    }
    match fs::symlink_metadata(&staged) {
        Ok(_) => verify_fingerprint(&staged, &target.fingerprint)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_staged(&staged, &target.bytes, &target.fingerprint)?;
            sync_parent(&staged)?;
            crash(&format!("prepare:{index}"))?;
        }
        Err(_) => return Err(InstallError::Io),
    }
    verify_fingerprint(&staged, &target.fingerprint)?;
    journal.targets[index].prepared = true;
    persist_journal(journal_path, journal)?;
    let _ = paths;
    Ok(())
}

fn backup_target(
    index: usize,
    planned: &[PlannedTarget],
    journal: &mut Journal,
    journal_path: &Path,
    _paths: &FixedInstallPaths,
) -> Result<(), InstallError> {
    let target = &planned[index];
    let backup = backup_path(&target.destination);
    if journal.targets[index].cleaned {
        require_absent(&backup)?;
        verify_fingerprint(&target.destination, &target.fingerprint)?;
        return Ok(());
    }
    if journal.targets[index].backed_up {
        if backup.try_exists().map_err(|_| InstallError::Io)? {
            verify_backup(
                &backup,
                journal.targets[index].old.as_ref(),
                &target.fingerprint,
            )?;
        } else if journal.full_payload_verified {
            verify_fingerprint(&target.destination, &target.fingerprint)?;
        } else {
            return Err(InstallError::ExistingResidue);
        }
        return Ok(());
    }
    match fs::symlink_metadata(&backup) {
        Ok(_) => verify_backup(
            &backup,
            journal.targets[index].old.as_ref(),
            &target.fingerprint,
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(old) = journal.targets[index].old.as_ref() {
                verify_fingerprint(&target.destination, old)?;
                let bytes = fs::read(&target.destination).map_err(|_| InstallError::Io)?;
                write_staged(&backup, &bytes, old)?;
            } else {
                write_staged(
                    &backup,
                    &[],
                    &Fingerprint {
                        length: 0,
                        sha256: sha256(&[]),
                        uid: target.fingerprint.uid,
                        gid: target.fingerprint.gid,
                        mode: 0o600,
                    },
                )?;
            }
            sync_parent(&backup)?;
            crash(&format!("backup:{index}"))?;
        }
        Err(_) => return Err(InstallError::Io),
    }
    verify_backup(
        &backup,
        journal.targets[index].old.as_ref(),
        &target.fingerprint,
    )?;
    journal.targets[index].backed_up = true;
    persist_journal(journal_path, journal)
}

fn publish_target(
    index: usize,
    planned: &[PlannedTarget],
    journal: &mut Journal,
    journal_path: &Path,
) -> Result<(), InstallError> {
    let target = &planned[index];
    let staged = staged_path(&target.destination);
    let backup = backup_path(&target.destination);
    if journal.targets[index].published {
        require_absent(&staged)?;
        verify_fingerprint(&target.destination, &target.fingerprint)?;
        if journal.targets[index].cleaned {
            require_absent(&backup)?;
        } else if journal.full_payload_verified
            && !backup.try_exists().map_err(|_| InstallError::Io)?
        {
            // cleanup effect 已完成但 receipt 尚未持久化；由 cleanup_target 补写。
        } else {
            verify_backup(
                &backup,
                journal.targets[index].old.as_ref(),
                &target.fingerprint,
            )?;
        }
        return Ok(());
    }
    verify_backup(
        &backup,
        journal.targets[index].old.as_ref(),
        &target.fingerprint,
    )?;
    let staged_exists = staged.try_exists().map_err(|_| InstallError::Io)?;
    if staged_exists {
        verify_fingerprint(&staged, &target.fingerprint)?;
        match journal.targets[index].old.as_ref() {
            Some(old) => verify_fingerprint(&target.destination, old)?,
            None => require_absent(&target.destination)?,
        }
        fs::rename(&staged, &target.destination).map_err(|_| InstallError::Io)?;
        sync_parent(&target.destination)?;
        crash(&format!("publish:{index}"))?;
    } else {
        verify_fingerprint(&target.destination, &target.fingerprint)?;
    }
    require_absent(&staged)?;
    verify_fingerprint(&target.destination, &target.fingerprint)?;
    journal.targets[index].published = true;
    persist_journal(journal_path, journal)
}

fn cleanup_target(
    index: usize,
    planned: &[PlannedTarget],
    journal: &mut Journal,
    journal_path: &Path,
) -> Result<(), InstallError> {
    let target = &planned[index];
    let backup = backup_path(&target.destination);
    verify_fingerprint(&target.destination, &target.fingerprint)?;
    if journal.targets[index].cleaned {
        require_absent(&backup)?;
        return Ok(());
    }
    match fs::symlink_metadata(&backup) {
        Ok(_) => {
            verify_backup(
                &backup,
                journal.targets[index].old.as_ref(),
                &target.fingerprint,
            )?;
            fs::remove_file(&backup).map_err(|_| InstallError::Io)?;
            sync_parent(&backup)?;
            crash(&format!("cleanup:{index}"))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(InstallError::Io),
    }
    journal.targets[index].cleaned = true;
    persist_journal(journal_path, journal)
}

fn planned_targets(
    components: &mut VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    installed: &InstalledUpgradeBinding,
    paths: &FixedInstallPaths,
) -> Result<Vec<PlannedTarget>, InstallError> {
    let root_uid = paths.expected_root_uid();
    let mut targets = Vec::with_capacity(TARGET_COUNT);
    for (id, source, destination, role) in [
        ("probe", &mut *components.probe, paths.binary(), "probe"),
        (
            "observation-runtime",
            &mut *components.observation_runtime,
            paths.observation_runtime_binary(),
            "observation-runtime",
        ),
        (
            "system-state-provider",
            &mut *components.system_state_provider,
            paths.cpu_provider_binary(),
            "system-state-provider",
        ),
        (
            "disk-health-provider",
            &mut *components.disk_health_provider,
            paths.disk_health_provider_binary(),
            "disk-health-provider",
        ),
        (
            "lifecycle-companion",
            &mut *components.lifecycle_companion,
            paths.lifecycle_companion_binary(),
            "lifecycle-companion",
        ),
        (
            "bootstrap-acquirer",
            &mut *components.bootstrap_acquirer,
            paths.bootstrap_acquirer(),
            "bootstrap-acquirer",
        ),
        (
            "bootstrap-activator",
            &mut *components.bootstrap_activator,
            paths.bootstrap_activator(),
            "bootstrap-activator",
        ),
    ] {
        let bytes = read_component(source)?;
        let (expected_sha256, expected_length) = bundle
            .component_receipt(role)
            .ok_or(InstallError::InvalidVerifiedComponent)?;
        if bytes.len() as u64 != expected_length || sha256(&bytes) != expected_sha256 {
            return Err(InstallError::InvalidVerifiedComponent);
        }
        targets.push(planned(id, destination, bytes, root_uid, root_uid, 0o755));
    }
    for (id, destination, contents) in [
        ("probe-unit", paths.unit(), super::service_unit()),
        (
            "runtime-unit",
            paths.observation_runtime_unit(),
            super::observation_runtime_unit(),
        ),
        (
            "runtime-socket",
            paths.observation_runtime_socket_unit(),
            super::observation_runtime_socket_unit().to_owned(),
        ),
        (
            "cpu-unit",
            paths.cpu_provider_unit(),
            super::cpu_provider_unit(),
        ),
        (
            "cpu-socket",
            paths.cpu_provider_socket_unit(),
            super::cpu_provider_socket_unit().to_owned(),
        ),
        (
            "disk-unit",
            paths.disk_health_provider_unit(),
            super::disk_health_provider_unit(),
        ),
        (
            "disk-socket",
            paths.disk_health_provider_socket_unit(),
            super::disk_health_provider_socket_unit().to_owned(),
        ),
        (
            "lifecycle-unit",
            paths.lifecycle_companion_unit(),
            super::lifecycle_companion_unit(),
        ),
        (
            "lifecycle-socket",
            paths.lifecycle_companion_socket_unit(),
            super::lifecycle_companion_socket_unit().to_owned(),
        ),
        (
            "upgrade-unit",
            paths.lifecycle_upgrade_unit(),
            super::lifecycle_upgrade_unit(),
        ),
        (
            "upgrade-socket",
            paths.lifecycle_upgrade_socket_unit(),
            super::lifecycle_upgrade_socket_unit().to_owned(),
        ),
    ] {
        targets.push(planned(
            id,
            destination,
            contents.into_bytes(),
            root_uid,
            root_uid,
            0o644,
        ));
    }
    let identity_metadata = fs::metadata(paths.identity()).map_err(|_| InstallError::Io)?;
    let current_identity = fs::read_to_string(paths.identity()).map_err(|_| InstallError::Io)?;
    targets.push(planned(
        "identity",
        paths.identity(),
        updated_receipt_projection(&current_identity, bundle, installed)?.into_bytes(),
        identity_metadata.uid(),
        identity_metadata.gid(),
        0o600,
    ));
    let current_metadata = fs::read_to_string(paths.metadata()).map_err(|_| InstallError::Io)?;
    targets.push(planned(
        "metadata",
        paths.metadata(),
        updated_metadata(&current_metadata, bundle, installed)?.into_bytes(),
        root_uid,
        root_uid,
        0o600,
    ));
    targets.push(planned(
        "runtime-failure-recorder-unit",
        paths.observation_runtime_failure_recorder_unit(),
        super::observation_runtime_failure_recorder_unit().into_bytes(),
        root_uid,
        root_uid,
        0o644,
    ));
    Ok(targets)
}

fn planned(
    id: &'static str,
    destination: PathBuf,
    bytes: Vec<u8>,
    uid: u32,
    gid: u32,
    mode: u32,
) -> PlannedTarget {
    PlannedTarget {
        id,
        destination,
        fingerprint: Fingerprint {
            length: bytes.len() as u64,
            sha256: sha256(&bytes),
            uid,
            gid,
            mode,
        },
        bytes,
    }
}

fn verify_targets(targets: &[PlannedTarget]) -> Result<(), InstallError> {
    for target in targets {
        verify_fingerprint(&target.destination, &target.fingerprint)?;
        require_absent(&staged_path(&target.destination))?;
    }
    Ok(())
}

fn verify_journal_destinations(
    journal: &Journal,
    paths: &FixedInstallPaths,
) -> Result<(), InstallError> {
    let destinations = super::upgrade::upgrade_destinations(paths);
    if destinations.len() != journal.targets.len() {
        return Err(InstallError::ExistingResidue);
    }
    for (target, destination) in journal.targets.iter().zip(destinations) {
        verify_fingerprint(&destination, &target.new)?;
        require_absent(&staged_path(&destination))?;
        require_absent(&backup_path(&destination))?;
    }
    Ok(())
}

fn read_component(file: &mut File) -> Result<Vec<u8>, InstallError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| InstallError::Io)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| InstallError::Io)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| InstallError::Io)?;
    Ok(bytes)
}

fn fingerprint_if_present(path: &Path) -> Result<Option<Fingerprint>, InstallError> {
    match fs::symlink_metadata(path) {
        Ok(_) => fingerprint(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(InstallError::Io),
    }
}

fn fingerprint(path: &Path) -> Result<Fingerprint, InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| InstallError::ExistingResidue)?;
    let opened = file.metadata().map_err(|_| InstallError::ExistingResidue)?;
    if metadata.file_type().is_symlink()
        || !opened.is_file()
        || metadata.dev() != opened.dev()
        || metadata.ino() != opened.ino()
    {
        return Err(InstallError::ExistingResidue);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| InstallError::Io)?;
    Ok(Fingerprint {
        length: bytes.len() as u64,
        sha256: sha256(&bytes),
        uid: opened.uid(),
        gid: opened.gid(),
        mode: opened.mode() & 0o777,
    })
}

fn verify_fingerprint(path: &Path, expected: &Fingerprint) -> Result<(), InstallError> {
    (fingerprint(path)? == *expected)
        .then_some(())
        .ok_or(InstallError::ExistingResidue)
}

fn require_single_link(path: &Path) -> Result<(), InstallError> {
    (fs::symlink_metadata(path)
        .map_err(|_| InstallError::ExistingResidue)?
        .nlink()
        == 1)
        .then_some(())
        .ok_or(InstallError::ExistingResidue)
}

fn verify_backup(
    path: &Path,
    old: Option<&Fingerprint>,
    new: &Fingerprint,
) -> Result<(), InstallError> {
    if let Some(old) = old {
        verify_fingerprint(path, old)?;
        require_single_link(path)
    } else {
        let actual = fingerprint(path)?;
        if actual.length == 0
            && actual.sha256 == sha256(&[])
            && actual.uid == new.uid
            && actual.gid == new.gid
            && actual.mode == 0o600
            && fs::symlink_metadata(path)
                .map_err(|_| InstallError::ExistingResidue)?
                .nlink()
                == 1
        {
            Ok(())
        } else {
            Err(InstallError::ExistingResidue)
        }
    }
}

fn write_staged(path: &Path, bytes: &[u8], expected: &Fingerprint) -> Result<(), InstallError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(expected.mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                InstallError::ExistingResidue
            } else {
                InstallError::Io
            }
        })?;
    file.write_all(bytes).map_err(|_| InstallError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(expected.mode))
        .map_err(|_| InstallError::Io)?;
    if unsafe { libc::fchown(file.as_raw_fd(), expected.uid, expected.gid) } != 0 {
        return Err(InstallError::Io);
    }
    file.sync_all().map_err(|_| InstallError::Io)
}

fn load_journal(path: &Path, expected_uid: u32) -> Result<Option<Journal>, InstallError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(InstallError::ExistingResidue),
    };
    let metadata = file.metadata().map_err(|_| InstallError::ExistingResidue)?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(InstallError::ExistingResidue);
    }
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallError::Io)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(InstallError::ExistingResidue);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| InstallError::ExistingResidue)
}

fn persist_journal(path: &Path, journal: &Journal) -> Result<(), InstallError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| InstallError::Io)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(InstallError::Io);
    }
    crate::secure_file::atomic_write(path, &bytes, 0o600, None).map_err(|_| InstallError::Io)
}

fn spec_sha256(journal: &Journal) -> Result<String, InstallError> {
    #[derive(Serialize)]
    struct Spec<'a> {
        schema_version: u16,
        transaction_id: &'a str,
        binding_sha256: &'a str,
        retirement_binding_sha256: &'a str,
        targets: &'a [TargetJournal],
    }
    let immutable = journal
        .targets
        .iter()
        .cloned()
        .map(|mut target| {
            target.prepared = false;
            target.backed_up = false;
            target.published = false;
            target.cleaned = false;
            target
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&Spec {
        schema_version: journal.schema_version,
        transaction_id: &journal.transaction_id,
        binding_sha256: &journal.binding_sha256,
        retirement_binding_sha256: &journal.retirement_binding_sha256,
        targets: &immutable,
    })
    .map(|bytes| sha256(&bytes))
    .map_err(|_| InstallError::Io)
}

fn transaction_id() -> Result<String, InstallError> {
    let mut bytes = [0_u8; 16];
    let read = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if read != bytes.len() as isize {
        return Err(InstallError::Io);
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn staged_path(destination: &Path) -> PathBuf {
    sibling(destination, "enoki-repair-new")
}

fn backup_path(destination: &Path) -> PathBuf {
    sibling(destination, "enoki-repair-old")
}

fn sibling(destination: &Path, suffix: &str) -> PathBuf {
    let name = destination
        .file_name()
        .expect("fixed installed-layout target has a name")
        .to_string_lossy();
    destination.with_file_name(format!(".{name}.{suffix}"))
}

fn require_absent(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(InstallError::ExistingResidue),
        Err(_) => Err(InstallError::Io),
    }
}

fn sync_parent(path: &Path) -> Result<(), InstallError> {
    File::open(path.parent().ok_or(InstallError::Io)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InstallError::Io)
}

#[cfg(any(test, feature = "deterministic-test-seams"))]
thread_local! {
    static CRASH_POINT: std::cell::RefCell<Option<String>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(any(test, feature = "deterministic-test-seams"))]
pub(super) fn set_crash(point: &str) {
    CRASH_POINT.with(|configured| *configured.borrow_mut() = Some(point.to_owned()));
}

fn crash(point: &str) -> Result<(), InstallError> {
    #[cfg(any(test, feature = "deterministic-test-seams"))]
    if CRASH_POINT.with(|configured| {
        let mut configured = configured.borrow_mut();
        if configured.as_deref() == Some(point) {
            configured.take();
            true
        } else {
            false
        }
    }) {
        return Err(InstallError::Io);
    }
    let _ = point;
    Ok(())
}
