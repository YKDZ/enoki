use super::{
    FixedInstallPaths, InstallError, SystemdPort, VerifiedUpgradeComponents,
    upgrade::{
        InstalledBundleRepairBinding, InstalledUpgradeBinding, updated_metadata,
        updated_receipt_projection,
    },
};
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
const TARGET_COUNT: usize = installed_layout::TARGET_COUNT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BundleRestoreReceipt {
    pub(super) binding_sha256: String,
}

use super::installed_layout::{self, Fingerprint, TargetKind};

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
    verify_journal_destinations(&journal, paths)?;
    fs::remove_file(&journal_path).map_err(|_| InstallError::Io)?;
    sync_parent(&journal_path)?;
    crash("journal-cleanup")
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
        & 0o7777
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
    for target in installed_layout::registry(paths) {
        let (bytes, uid, gid) = match target.kind {
            TargetKind::Bundle(role) => {
                let source = match role {
                    "probe" => &mut *components.probe,
                    "observation-runtime" => &mut *components.observation_runtime,
                    "system-state-provider" => &mut *components.system_state_provider,
                    "disk-health-provider" => &mut *components.disk_health_provider,
                    "lifecycle-companion" => &mut *components.lifecycle_companion,
                    "bootstrap-acquirer" => &mut *components.bootstrap_acquirer,
                    "bootstrap-activator" => &mut *components.bootstrap_activator,
                    _ => return Err(InstallError::InvalidVerifiedComponent),
                };
                let bytes = read_component(source)?;
                let (expected_sha256, expected_length) = bundle
                    .component_receipt(role)
                    .ok_or(InstallError::InvalidVerifiedComponent)?;
                if bytes.len() as u64 != expected_length || sha256(&bytes) != expected_sha256 {
                    return Err(InstallError::InvalidVerifiedComponent);
                }
                (bytes, root_uid, root_uid)
            }
            TargetKind::Unit(generate) => (generate().into_bytes(), root_uid, root_uid),
            TargetKind::Identity => {
                let metadata = fs::symlink_metadata(&target.destination)
                    .map_err(|_| InstallError::ExistingResidue)?;
                let current = installed_layout::trusted_text(
                    &target.destination,
                    metadata.uid(),
                    metadata.gid(),
                    target.mode,
                )?;
                (
                    updated_receipt_projection(&current, bundle, installed)?.into_bytes(),
                    metadata.uid(),
                    metadata.gid(),
                )
            }
            TargetKind::Metadata => {
                let current = installed_layout::trusted_text(
                    &target.destination,
                    root_uid,
                    root_uid,
                    target.mode,
                )?;
                (
                    updated_metadata(&current, bundle, installed)?.into_bytes(),
                    root_uid,
                    root_uid,
                )
            }
        };
        targets.push(planned(
            target.id,
            target.destination,
            bytes,
            uid,
            gid,
            target.mode,
        ));
    }
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
    let destinations = installed_layout::registry(paths)
        .into_iter()
        .map(|target| target.destination)
        .collect::<Vec<_>>();
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
    installed_layout::fingerprint(path)
}

fn verify_fingerprint(path: &Path, expected: &Fingerprint) -> Result<(), InstallError> {
    installed_layout::verify_fingerprint(path, expected)
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
        || metadata.mode() & 0o7777 != 0o600
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
