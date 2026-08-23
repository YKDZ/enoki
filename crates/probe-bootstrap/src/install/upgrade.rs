use super::*;
use crate::lifecycle::{
    UpgradeCompletion, UpgradeLifecycleEffects, execute_upgrade_lifecycle,
    verify_lifecycle_upgrade_authority_signature,
};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::fd::AsRawFd;

const UPGRADE_ATTEMPT_FILE: &str = "probe-upgrade-attempt.toml";
const OPERATION_STATUS_FILE: &str = "probe-operation-status.toml";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAttempt {
    pub operation_id: String,
    pub stage_owner_uid: u32,
    pub authority_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAuthorityConsumption {
    pub operation_id: String,
    pub stage_owner_uid: u32,
    pub hub_origin: String,
    pub probe_id: String,
    pub source_bundle_version: String,
    pub source_install_state_sha256: String,
    pub source_manifest_sha256: String,
    pub target_bundle_version: String,
    pub target_asset_set_digest: String,
    pub target_manifest_sha256: String,
    pub verified_stage_sha256: String,
}

#[derive(Debug)]
pub enum ConsumeBeforeOuterError<E> {
    Consume(InstallError),
    Outer { consumed: UpgradeAttempt, error: E },
}

pub fn consume_before_upgrade_outer_checks<T, E>(
    paths: &FixedInstallPaths,
    authority: &UpgradeAuthorityConsumption,
    outer_checks: impl FnOnce(&UpgradeAttempt) -> Result<T, E>,
) -> Result<(UpgradeAttempt, T), ConsumeBeforeOuterError<E>> {
    let consumed = consume_probe_upgrade_authority(paths, authority)
        .map_err(ConsumeBeforeOuterError::Consume)?;
    match outer_checks(&consumed) {
        Ok(output) => Ok((consumed, output)),
        Err(error) => Err(ConsumeBeforeOuterError::Outer { consumed, error }),
    }
}

pub fn consume_signed_before_upgrade_outer_checks<T, E>(
    paths: &FixedInstallPaths,
    authority: &UpgradeAuthorityConsumption,
    canonical_authority: &[u8],
    signature_hex: &str,
    outer_checks: impl FnOnce(&UpgradeAttempt) -> Result<T, E>,
) -> Result<(UpgradeAttempt, T), ConsumeBeforeOuterError<E>> {
    let consumed = consume_signed_probe_upgrade_authority(
        paths,
        authority,
        canonical_authority,
        signature_hex,
    )
    .map_err(ConsumeBeforeOuterError::Consume)?;
    match outer_checks(&consumed) {
        Ok(output) => Ok((consumed, output)),
        Err(error) => Err(ConsumeBeforeOuterError::Outer { consumed, error }),
    }
}

fn consume_signed_probe_upgrade_authority(
    paths: &FixedInstallPaths,
    authority: &UpgradeAuthorityConsumption,
    canonical_authority: &[u8],
    signature_hex: &str,
) -> Result<UpgradeAttempt, InstallError> {
    let metadata = trusted_text(&paths.metadata(), paths.expected_root_uid(), 0o600)?;
    let key_hex = metadata_string(&metadata, "lifecycle_authority_install_key")
        .ok_or(InstallError::ExistingResidue)?;
    let install_key = decode_lower_sha256(&key_hex).ok_or(InstallError::ExistingResidue)?;
    if !verify_lifecycle_upgrade_authority_signature(
        &install_key,
        canonical_authority,
        signature_hex,
    ) {
        return Err(InstallError::ExistingResidue);
    }
    consume_probe_upgrade_authority(paths, authority)
}

fn decode_lower_sha256(value: &str) -> Option<[u8; 32]> {
    if !valid_sha256(value) {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        bytes[index] = ((high << 4) | low) as u8;
    }
    Some(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeRecoveryReceipt {
    pub operation_id: String,
    pub probe_id: String,
    pub stage_owner_uid: u32,
    pub source_bundle_version: String,
    pub target_bundle_version: String,
    pub activated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledUpgradeBinding {
    pub hub_origin: String,
    pub probe_id: String,
    pub source_bundle_version: String,
    pub source_install_state_sha256: String,
    pub source_manifest_sha256: String,
}

pub struct VerifiedUpgradeComponents<'a> {
    pub probe: &'a mut File,
    pub observation_runtime: &'a mut File,
    pub system_state_provider: &'a mut File,
    pub disk_health_provider: &'a mut File,
    pub lifecycle_companion: &'a mut File,
    pub bootstrap_acquirer: &'a mut File,
    pub bootstrap_activator: &'a mut File,
}

pub fn inspect_installed_probe_for_upgrade(
    paths: &FixedInstallPaths,
) -> Result<InstalledUpgradeBinding, InstallError> {
    let metadata = trusted_text(&paths.metadata(), paths.expected_root_uid(), 0o600)?;
    if metadata_scalar(&metadata, "schema_version").as_deref() != Some("5") {
        return Err(InstallError::ExistingResidue);
    }
    for (path, mode) in [
        (paths.binary(), 0o755),
        (paths.observation_runtime_binary(), 0o755),
        (paths.cpu_provider_binary(), 0o755),
        (paths.disk_health_provider_binary(), 0o755),
        (paths.lifecycle_companion_binary(), 0o755),
        (paths.bootstrap_acquirer(), 0o755),
        (paths.bootstrap_activator(), 0o755),
        (paths.unit(), 0o644),
        (paths.observation_runtime_unit(), 0o644),
        (paths.observation_runtime_socket_unit(), 0o644),
        (paths.cpu_provider_unit(), 0o644),
        (paths.cpu_provider_socket_unit(), 0o644),
        (paths.disk_health_provider_unit(), 0o644),
        (paths.disk_health_provider_socket_unit(), 0o644),
        (paths.lifecycle_companion_unit(), 0o644),
        (paths.lifecycle_companion_socket_unit(), 0o644),
        (paths.lifecycle_upgrade_unit(), 0o644),
        (paths.lifecycle_upgrade_socket_unit(), 0o644),
    ] {
        trusted_file(&path, paths.expected_root_uid(), mode)?;
    }
    let identity_uid = fs::symlink_metadata(paths.identity())
        .map_err(|_| InstallError::ExistingResidue)?
        .uid();
    let identity = trusted_text(&paths.identity(), identity_uid, 0o600)?;
    let field = |name: &str| {
        metadata_string(&metadata, name)
            .filter(|value| !value.is_empty())
            .ok_or(InstallError::ExistingResidue)
    };
    let hub_origin = field("hub_url")?;
    if metadata_string(&identity, "hub_url")
        .as_deref()
        .map(|value| value.trim_end_matches('/'))
        != Some(hub_origin.trim_end_matches('/'))
    {
        return Err(InstallError::ExistingResidue);
    }
    let probe_id = metadata_string(&identity, "probe_id")
        .filter(|value| !value.is_empty())
        .ok_or(InstallError::ExistingResidue)?
        .to_owned();
    Ok(InstalledUpgradeBinding {
        hub_origin,
        probe_id,
        source_bundle_version: field("bundle_version")?,
        source_install_state_sha256: sha256_field(&metadata, "install_state_sha256")?,
        source_manifest_sha256: sha256_field(&metadata, "target_manifest_sha256")?,
    })
}

fn metadata_scalar(contents: &str, key: &str) -> Option<String> {
    let mut values = contents.lines().filter_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate.trim() == key).then(|| value.trim().to_owned())
    });
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn metadata_string(contents: &str, key: &str) -> Option<String> {
    serde_json::from_str(&metadata_scalar(contents, key)?).ok()
}

fn sha256_field(contents: &str, name: &str) -> Result<String, InstallError> {
    let value = metadata_string(contents, name).ok_or(InstallError::ExistingResidue)?;
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(value)
        .ok_or(InstallError::ExistingResidue)
}

fn trusted_text(path: &Path, uid: u32, mode: u32) -> Result<String, InstallError> {
    let mut file = trusted_file(path, uid, mode)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| InstallError::Io)?;
    if bytes.is_empty() || bytes.len() > 256 * 1024 {
        return Err(InstallError::ExistingResidue);
    }
    String::from_utf8(bytes).map_err(|_| InstallError::ExistingResidue)
}

fn trusted_file(path: &Path, uid: u32, mode: u32) -> Result<File, InstallError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| InstallError::ExistingResidue)?;
    let opened = file.metadata().map_err(|_| InstallError::ExistingResidue)?;
    if path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
        || path_metadata.file_type().is_symlink()
        || !opened.is_file()
        || opened.uid() != uid
        || opened.mode() & 0o777 != mode
        || opened.nlink() != 1
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(file)
}

pub fn upgrade_current_probe(
    components: VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    expected_source: &InstalledUpgradeBinding,
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<UpgradeCompletion, InstallError> {
    upgrade_current_probe_inner(components, bundle, expected_source, None, paths, systemd)
}

pub fn upgrade_current_probe_for_operation(
    components: VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    expected_source: &InstalledUpgradeBinding,
    attempt: &UpgradeAttempt,
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<UpgradeCompletion, InstallError> {
    if attempt.operation_id.is_empty()
        || attempt.operation_id.len() > 96
        || !attempt
            .operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(InstallError::ExistingResidue);
    }
    upgrade_current_probe_inner(
        components,
        bundle,
        expected_source,
        Some(attempt),
        paths,
        systemd,
    )
}

fn upgrade_current_probe_inner(
    components: VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    expected_source: &InstalledUpgradeBinding,
    attempt: Option<&UpgradeAttempt>,
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<UpgradeCompletion, InstallError> {
    let mut effects = UpgradeEffects {
        components: Some(components),
        bundle,
        expected_source,
        attempt,
        paths,
        systemd,
        prepared: None,
    };
    execute_upgrade_lifecycle(&mut effects)
}

struct UpgradeEffects<'a, S> {
    components: Option<VerifiedUpgradeComponents<'a>>,
    bundle: &'a VerifiedBundle,
    expected_source: &'a InstalledUpgradeBinding,
    attempt: Option<&'a UpgradeAttempt>,
    paths: &'a FixedInstallPaths,
    systemd: &'a mut S,
    prepared: Option<PreparedUpgrade>,
}

impl<S: SystemdPort> UpgradeLifecycleEffects for UpgradeEffects<'_, S> {
    type Error = InstallError;

    fn verify_and_prepare(&mut self) -> Result<(), Self::Error> {
        if let Some(attempt) = self.attempt {
            begin_upgrade_attempt(self.paths, attempt, self.expected_source, self.bundle)?;
        }
        let actual = inspect_installed_probe_for_upgrade(self.paths)?;
        if &actual != self.expected_source
            || self.bundle.version == actual.source_bundle_version
            || !version_is_newer(&self.bundle.version, &actual.source_bundle_version)
        {
            return Err(InstallError::ExistingResidue);
        }
        let components = self
            .components
            .as_mut()
            .ok_or(InstallError::InvalidVerifiedComponent)?;
        verify_component_lengths(components, self.bundle)?;
        let prepared = prepare_upgrade(components, self.bundle, self.paths, &actual);
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Err(error),
        };
        if let Some(attempt) = self.attempt
            && write_upgrade_attempt(
                self.paths,
                attempt,
                self.expected_source,
                self.bundle,
                "prepared",
                0,
                0,
            )
            .is_err()
        {
            return Err(InstallError::Io);
        }
        self.prepared = Some(prepared);
        Ok(())
    }

    fn activate_complete_bundle(&mut self) -> Result<(), Self::Error> {
        let mut prepared = self.prepared.take().ok_or(InstallError::Io)?;
        prepared.retain_for_repair = true;
        let activated = (|| {
            if let Some(attempt) = self.attempt {
                write_upgrade_attempt(
                    self.paths,
                    attempt,
                    self.expected_source,
                    self.bundle,
                    "activation-started",
                    0,
                    0,
                )?;
                write_operation_status(self.paths, attempt, &self.bundle.version, "running", None)?;
            }
            self.systemd
                .set_command_deadline(Instant::now() + INSTALL_COMMAND_BUDGET);
            self.systemd.stop()?;
            for (index, (temporary, destination)) in prepared
                .staged
                .iter()
                .zip(&prepared.destinations)
                .enumerate()
            {
                fs::rename(temporary, destination).map_err(|_| InstallError::Io)?;
                sync_directory(destination.parent().ok_or(InstallError::Io)?)?;
                if let Some(attempt) = self.attempt {
                    write_upgrade_attempt(
                        self.paths,
                        attempt,
                        self.expected_source,
                        self.bundle,
                        "activation-started",
                        index + 1,
                        0,
                    )?;
                }
            }
            self.systemd.daemon_reload()?;
            self.systemd.start()?;
            self.systemd.wait_local_activated()?;
            if let Some(attempt) = self.attempt {
                write_upgrade_attempt(
                    self.paths,
                    attempt,
                    self.expected_source,
                    self.bundle,
                    "finalizing",
                    prepared.destinations.len(),
                    0,
                )?;
            }
            for (index, backup) in prepared.backups.iter().enumerate() {
                fs::remove_file(backup).map_err(|_| InstallError::Io)?;
                sync_directory(backup.parent().ok_or(InstallError::Io)?)?;
                if let Some(attempt) = self.attempt {
                    write_upgrade_attempt(
                        self.paths,
                        attempt,
                        self.expected_source,
                        self.bundle,
                        "finalizing",
                        prepared.destinations.len(),
                        index + 1,
                    )?;
                }
            }
            if let Some(attempt) = self.attempt {
                write_upgrade_attempt(
                    self.paths,
                    attempt,
                    self.expected_source,
                    self.bundle,
                    "stage-cleanup-required",
                    prepared.destinations.len(),
                    prepared.backups.len(),
                )?;
                write_operation_status(
                    self.paths,
                    attempt,
                    &self.bundle.version,
                    "failed",
                    Some("lifecycle.upgrade_repair_required"),
                )?;
            }
            prepared.retain_for_repair = false;
            Ok(())
        })();
        if activated.is_err()
            && let Some(attempt) = self.attempt
        {
            let _ = write_operation_status(
                self.paths,
                attempt,
                &self.bundle.version,
                "failed",
                Some("lifecycle.upgrade_repair_required"),
            );
            let _ = mark_upgrade_attempt_phase(self.paths, "repair-required");
        }
        activated
    }
}

fn mark_upgrade_attempt_phase(paths: &FixedInstallPaths, phase: &str) -> Result<(), InstallError> {
    let journal = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    let contents = fs::read_to_string(&journal).map_err(|_| InstallError::Io)?;
    let mut replacements = 0_u8;
    let mut updated = String::new();
    for line in contents.lines() {
        if line.starts_with("phase = ") {
            replacements += 1;
            updated.push_str(&format!("phase = {phase:?}\n"));
        } else {
            updated.push_str(line);
            updated.push('\n');
        }
    }
    if replacements != 1 {
        return Err(InstallError::ExistingResidue);
    }
    atomic_durable_write(&journal, updated.as_bytes(), 0o600)
}

fn verify_component_lengths(
    components: &mut VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
) -> Result<(), InstallError> {
    validate_component(components.probe, bundle.component_len)?;
    for (file, role) in [
        (&mut *components.observation_runtime, "observation-runtime"),
        (
            &mut *components.system_state_provider,
            "system-state-provider",
        ),
        (
            &mut *components.disk_health_provider,
            "disk-health-provider",
        ),
        (&mut *components.lifecycle_companion, "lifecycle-companion"),
    ] {
        let (_, length) = bundle
            .component_receipt(role)
            .ok_or(InstallError::InvalidVerifiedComponent)?;
        validate_component(file, length)?;
    }
    validate_bootstrap_role_file(components.bootstrap_acquirer, bundle, true)?;
    validate_bootstrap_role_file(components.bootstrap_activator, bundle, false)
}

fn validate_bootstrap_role_file(
    file: &mut File,
    bundle: &VerifiedBundle,
    acquirer: bool,
) -> Result<(), InstallError> {
    let receipt = if acquirer {
        bundle.acquirer_receipt()
    } else {
        bundle.activator_receipt()
    }
    .ok_or(InstallError::InvalidVerifiedComponent)?;
    validate_component(file, receipt.1)
}

struct PreparedUpgrade {
    staged: Vec<PathBuf>,
    destinations: Vec<PathBuf>,
    backups: Vec<PathBuf>,
    retain_for_repair: bool,
}

impl Drop for PreparedUpgrade {
    fn drop(&mut self) {
        if self.retain_for_repair {
            return;
        }
        for path in self.staged.iter().chain(&self.backups) {
            let _ = fs::remove_file(path);
        }
    }
}

fn prepare_upgrade(
    components: &mut VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    paths: &FixedInstallPaths,
    source: &InstalledUpgradeBinding,
) -> Result<PreparedUpgrade, InstallError> {
    let destinations = vec![
        paths.binary(),
        paths.observation_runtime_binary(),
        paths.cpu_provider_binary(),
        paths.disk_health_provider_binary(),
        paths.lifecycle_companion_binary(),
        paths.bootstrap_acquirer(),
        paths.bootstrap_activator(),
        paths.unit(),
        paths.observation_runtime_unit(),
        paths.observation_runtime_socket_unit(),
        paths.cpu_provider_unit(),
        paths.cpu_provider_socket_unit(),
        paths.disk_health_provider_unit(),
        paths.disk_health_provider_socket_unit(),
        paths.lifecycle_companion_unit(),
        paths.lifecycle_companion_socket_unit(),
        paths.lifecycle_upgrade_unit(),
        paths.lifecycle_upgrade_socket_unit(),
        paths.identity(),
        paths.metadata(),
    ];
    let mut prepared = PreparedUpgrade {
        staged: Vec::new(),
        destinations,
        backups: Vec::new(),
        retain_for_repair: false,
    };
    for (source, destination) in [
        (&mut *components.probe, &prepared.destinations[0]),
        (
            &mut *components.observation_runtime,
            &prepared.destinations[1],
        ),
        (
            &mut *components.system_state_provider,
            &prepared.destinations[2],
        ),
        (
            &mut *components.disk_health_provider,
            &prepared.destinations[3],
        ),
        (
            &mut *components.lifecycle_companion,
            &prepared.destinations[4],
        ),
        (
            &mut *components.bootstrap_acquirer,
            &prepared.destinations[5],
        ),
        (
            &mut *components.bootstrap_activator,
            &prepared.destinations[6],
        ),
    ] {
        prepared
            .staged
            .push(stage_reader(source, destination, 0o755)?);
    }
    for (contents, destination) in [
        (service_unit(), &prepared.destinations[7]),
        (observation_runtime_unit(), &prepared.destinations[8]),
        (
            observation_runtime_socket_unit().to_owned(),
            &prepared.destinations[9],
        ),
        (cpu_provider_unit(), &prepared.destinations[10]),
        (
            cpu_provider_socket_unit().to_owned(),
            &prepared.destinations[11],
        ),
        (disk_health_provider_unit(), &prepared.destinations[12]),
        (
            disk_health_provider_socket_unit().to_owned(),
            &prepared.destinations[13],
        ),
        (lifecycle_companion_unit(), &prepared.destinations[14]),
        (
            lifecycle_companion_socket_unit().to_owned(),
            &prepared.destinations[15],
        ),
        (lifecycle_upgrade_unit(), &prepared.destinations[16]),
        (
            lifecycle_upgrade_socket_unit().to_owned(),
            &prepared.destinations[17],
        ),
    ] {
        prepared
            .staged
            .push(stage_bytes(contents.as_bytes(), destination, 0o644)?);
    }
    let current_identity = fs::read_to_string(paths.identity()).map_err(|_| InstallError::Io)?;
    let identity_metadata = fs::metadata(paths.identity()).map_err(|_| InstallError::Io)?;
    let updated_identity = updated_receipt_projection(&current_identity, bundle, source)?;
    prepared.staged.push(stage_bytes_owned(
        updated_identity.as_bytes(),
        &prepared.destinations[18],
        0o600,
        identity_metadata.uid(),
        identity_metadata.gid(),
    )?);
    let current_metadata = fs::read_to_string(paths.metadata()).map_err(|_| InstallError::Io)?;
    let updated = updated_metadata(&current_metadata, bundle, source)?;
    prepared.staged.push(stage_bytes(
        updated.as_bytes(),
        &prepared.destinations[19],
        0o600,
    )?);
    for destination in &prepared.destinations {
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(InstallError::Io)?;
        let backup = destination.with_file_name(format!(".{name}.enoki-upgrade-old"));
        if fs::symlink_metadata(&backup).is_ok() {
            return Err(InstallError::ExistingResidue);
        }
        fs::hard_link(destination, &backup).map_err(|_| InstallError::Io)?;
        prepared.backups.push(backup);
    }
    Ok(prepared)
}

fn stage_reader(source: &mut File, destination: &Path, mode: u32) -> Result<PathBuf, InstallError> {
    source.rewind().map_err(|_| InstallError::Io)?;
    let parent = destination.parent().ok_or(InstallError::Io)?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InstallError::Io)?;
    let path = parent.join(format!(".{name}.enoki-upgrade-new"));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&path)
        .map_err(|_| InstallError::ExistingResidue)?;
    std::io::copy(source, &mut output).map_err(|_| InstallError::Io)?;
    output
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| InstallError::Io)?;
    output.sync_all().map_err(|_| InstallError::Io)?;
    Ok(path)
}

fn stage_bytes(bytes: &[u8], destination: &Path, mode: u32) -> Result<PathBuf, InstallError> {
    let temporary = destination.with_file_name(format!(
        ".{}.enoki-upgrade-new",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(InstallError::Io)?
    ));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|_| InstallError::ExistingResidue)?;
    output.write_all(bytes).map_err(|_| InstallError::Io)?;
    output
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| InstallError::Io)?;
    output.sync_all().map_err(|_| InstallError::Io)?;
    Ok(temporary)
}

fn stage_bytes_owned(
    bytes: &[u8],
    destination: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<PathBuf, InstallError> {
    let path = stage_bytes(bytes, destination, mode)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| InstallError::Io)?;
    // SAFETY：descriptor 指向刚创建的普通暂存文件；uid/gid 来自已信任的
    // 当前 Probe Identity inode。
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        let _ = fs::remove_file(&path);
        return Err(InstallError::Io);
    }
    file.sync_all().map_err(|_| InstallError::Io)?;
    Ok(path)
}

fn updated_metadata(
    current: &str,
    bundle: &VerifiedBundle,
    source: &InstalledUpgradeBinding,
) -> Result<String, InstallError> {
    let replacements = [
        ("install_state_sha256", bundle.install_state_sha256()),
        ("target_manifest_sha256", bundle.manifest_sha256.clone()),
        ("bundle_version", bundle.version.clone()),
    ];
    let mut counts = [0_u8; 3];
    let mut output = String::new();
    for line in current.lines() {
        if let Some((index, (key, value))) = replacements
            .iter()
            .enumerate()
            .find(|(_, (key, _))| line.starts_with(&format!("{key} = ")))
        {
            counts[index] += 1;
            output.push_str(&format!("{key} = {value:?}\n"));
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if counts != [1, 1, 1]
        || !current.contains(&format!(
            "bundle_version = {:?}",
            source.source_bundle_version
        ))
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(output)
}

fn updated_receipt_projection(
    current: &str,
    bundle: &VerifiedBundle,
    source: &InstalledUpgradeBinding,
) -> Result<String, InstallError> {
    updated_metadata(current, bundle, source)
}

fn begin_upgrade_attempt(
    paths: &FixedInstallPaths,
    attempt: &UpgradeAttempt,
    source: &InstalledUpgradeBinding,
    bundle: &VerifiedBundle,
) -> Result<(), InstallError> {
    if let Some(authority_sha256) = attempt.authority_sha256.as_deref() {
        return confirm_consumed_upgrade_authority(
            paths,
            attempt,
            authority_sha256,
            source,
            bundle,
        );
    }
    let journal = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    if let Ok(contents) = fs::read_to_string(&journal) {
        let prior_operation = journal_string(&contents, "operation_id")?;
        let phase = journal_string(&contents, "phase")?;
        if prior_operation == attempt.operation_id
            || matches!(
                phase,
                "activation-started" | "repair-required" | "finalizing" | "stage-cleanup-required"
            )
        {
            return Err(InstallError::ExistingResidue);
        }
        if !matches!(phase, "activated" | "aborted") {
            return Err(InstallError::ExistingResidue);
        }
        cleanup_pre_activation_residue(paths)?;
    } else if journal.exists() {
        return Err(InstallError::ExistingResidue);
    }
    write_upgrade_attempt(paths, attempt, source, bundle, "admitted", 0, 0)
}

pub fn consume_probe_upgrade_authority(
    paths: &FixedInstallPaths,
    authority: &UpgradeAuthorityConsumption,
) -> Result<UpgradeAttempt, InstallError> {
    if !valid_upgrade_identifier(&authority.operation_id)
        || !valid_upgrade_identifier(&authority.probe_id)
        || authority.hub_origin.is_empty()
        || !valid_upgrade_version(&authority.source_bundle_version)
        || !valid_upgrade_version(&authority.target_bundle_version)
        || !valid_sha256(&authority.source_install_state_sha256)
        || !valid_sha256(&authority.source_manifest_sha256)
        || !valid_sha256(&authority.target_manifest_sha256)
        || authority
            .target_asset_set_digest
            .strip_prefix("sha256:")
            .is_none_or(|digest| !valid_sha256(digest))
        || !valid_sha256(&authority.verified_stage_sha256)
    {
        return Err(InstallError::ExistingResidue);
    }
    let journal = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    if journal.exists() {
        let contents = trusted_text(&journal, paths.expected_root_uid(), 0o600)?;
        let prior_operation = journal_string(&contents, "operation_id")?;
        let phase = journal_string(&contents, "phase")?;
        if prior_operation == authority.operation_id || !matches!(phase, "aborted" | "activated") {
            return Err(InstallError::ExistingResidue);
        }
        cleanup_pre_activation_residue(paths)?;
    }
    let authority_sha256 = consumed_authority_sha256(authority);
    let contents = format!(
        "schema_version = 2\noperation_id = {:?}\nstage_owner_uid = {}\nauthority_sha256 = {:?}\nsource_probe_id = {:?}\nsource_bundle_version = {:?}\nsource_install_state_sha256 = {:?}\nsource_manifest_sha256 = {:?}\ntarget_bundle_version = {:?}\ntarget_asset_set_digest = {:?}\ntarget_manifest_sha256 = {:?}\nverified_stage_sha256 = {:?}\nphase = \"consumed\"\nactivated_targets = 0\nfinalized_targets = 0\n",
        authority.operation_id,
        authority.stage_owner_uid,
        authority_sha256,
        authority.probe_id,
        authority.source_bundle_version,
        authority.source_install_state_sha256,
        authority.source_manifest_sha256,
        authority.target_bundle_version,
        authority.target_asset_set_digest,
        authority.target_manifest_sha256,
        authority.verified_stage_sha256,
    );
    atomic_durable_write(&journal, contents.as_bytes(), 0o600)?;
    Ok(UpgradeAttempt {
        operation_id: authority.operation_id.clone(),
        stage_owner_uid: authority.stage_owner_uid,
        authority_sha256: Some(authority_sha256),
    })
}

pub fn abort_consumed_probe_upgrade_authority(
    paths: &FixedInstallPaths,
    consumed: &UpgradeAttempt,
) -> Result<(), InstallError> {
    let contents = trusted_text(
        &paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
        paths.expected_root_uid(),
        0o600,
    )?;
    if journal_string(&contents, "operation_id")? != consumed.operation_id
        || journal_string(&contents, "phase")? != "consumed"
        || Some(journal_string(&contents, "authority_sha256")?)
            != consumed.authority_sha256.as_deref()
    {
        return Err(InstallError::ExistingResidue);
    }
    mark_upgrade_attempt_phase(paths, "aborted")
}

fn confirm_consumed_upgrade_authority(
    paths: &FixedInstallPaths,
    attempt: &UpgradeAttempt,
    authority_sha256: &str,
    source: &InstalledUpgradeBinding,
    bundle: &VerifiedBundle,
) -> Result<(), InstallError> {
    let contents = trusted_text(
        &paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
        paths.expected_root_uid(),
        0o600,
    )?;
    if journal_string(&contents, "operation_id")? != attempt.operation_id
        || journal_usize(&contents, "stage_owner_uid")? != attempt.stage_owner_uid as usize
        || journal_string(&contents, "authority_sha256")? != authority_sha256
        || journal_string(&contents, "phase")? != "consumed"
        || journal_string(&contents, "source_probe_id")? != source.probe_id
        || journal_string(&contents, "source_bundle_version")? != source.source_bundle_version
        || journal_string(&contents, "source_install_state_sha256")?
            != source.source_install_state_sha256
        || journal_string(&contents, "source_manifest_sha256")? != source.source_manifest_sha256
        || journal_string(&contents, "target_bundle_version")? != bundle.version
        || journal_string(&contents, "target_manifest_sha256")? != bundle.manifest_sha256
    {
        return Err(InstallError::ExistingResidue);
    }
    write_upgrade_attempt(paths, attempt, source, bundle, "admitted", 0, 0)
}

fn valid_upgrade_identifier(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_upgrade_version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_whitespace)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn consumed_authority_sha256(authority: &UpgradeAuthorityConsumption) -> String {
    let canonical = format!(
        "enoki/lifecycle-upgrade-consumption/v2\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        authority.operation_id,
        authority.hub_origin,
        authority.probe_id,
        authority.source_bundle_version,
        authority.source_install_state_sha256,
        authority.source_manifest_sha256,
        authority.target_bundle_version,
        authority.target_asset_set_digest,
        authority.target_manifest_sha256,
        authority.verified_stage_sha256,
    );
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

fn journal_string<'a>(contents: &'a str, key: &str) -> Result<&'a str, InstallError> {
    let prefix = format!("{key} = \"");
    let mut values = contents.lines().filter_map(|line| {
        line.strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix('"'))
    });
    let value = values.next().ok_or(InstallError::ExistingResidue)?;
    if value.is_empty() || values.next().is_some() {
        return Err(InstallError::ExistingResidue);
    }
    Ok(value)
}

fn cleanup_pre_activation_residue(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    let destinations = upgrade_destinations(paths);
    let mut changed = Vec::new();
    for destination in &destinations {
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(InstallError::Io)?;
        for residue in [
            destination.with_file_name(format!(".{name}.enoki-upgrade-new")),
            destination.with_file_name(format!(".{name}.enoki-upgrade-old")),
        ] {
            match fs::remove_file(&residue) {
                Ok(()) => changed.push(destination.clone()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(InstallError::Io),
            }
        }
    }
    sync_destination_directories(&changed)
}

fn journal_usize(contents: &str, key: &str) -> Result<usize, InstallError> {
    let prefix = format!("{key} = ");
    let mut values = contents
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(str::parse::<usize>);
    let value = values
        .next()
        .ok_or(InstallError::ExistingResidue)?
        .map_err(|_| InstallError::ExistingResidue)?;
    if values.next().is_some() {
        return Err(InstallError::ExistingResidue);
    }
    Ok(value)
}

pub fn recover_incomplete_probe_upgrade(
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<Option<UpgradeRecoveryReceipt>, InstallError> {
    let journal_path = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    if !journal_path.exists() {
        return Ok(None);
    }
    let contents = trusted_text(&journal_path, paths.expected_root_uid(), 0o600)?;
    if !matches!(
        metadata_scalar(&contents, "schema_version").as_deref(),
        Some("1" | "2")
    ) {
        return Err(InstallError::ExistingResidue);
    }
    let operation_id = journal_string(&contents, "operation_id")?.to_owned();
    let probe_id = journal_string(&contents, "source_probe_id")?.to_owned();
    let target_bundle_version = journal_string(&contents, "target_bundle_version")?.to_owned();
    let source_bundle_version = journal_string(&contents, "source_bundle_version")?.to_owned();
    let stage_owner_uid = journal_usize(&contents, "stage_owner_uid")?
        .try_into()
        .map_err(|_| InstallError::ExistingResidue)?;
    let phase = journal_string(&contents, "phase")?;
    let destinations = upgrade_destinations(paths);
    let activated_targets = journal_usize(&contents, "activated_targets")?;
    let finalized_targets = journal_usize(&contents, "finalized_targets")?;
    if activated_targets > destinations.len() || finalized_targets > destinations.len() {
        return Err(InstallError::ExistingResidue);
    }
    let receipt = UpgradeRecoveryReceipt {
        operation_id: operation_id.clone(),
        probe_id,
        stage_owner_uid,
        source_bundle_version,
        target_bundle_version: target_bundle_version.clone(),
        activated: !matches!(phase, "consumed" | "admitted" | "prepared" | "aborted"),
    };
    let attempt = UpgradeAttempt {
        operation_id,
        stage_owner_uid,
        authority_sha256: Some(journal_string(&contents, "authority_sha256")?.to_owned()),
    };

    let recovered = (|| {
        match phase {
            "consumed" | "admitted" | "prepared" => {
                cleanup_pre_activation_residue(paths)?;
                mark_upgrade_attempt_phase(paths, "aborted")?;
                write_operation_status(
                    paths,
                    &attempt,
                    &target_bundle_version,
                    "failed",
                    Some("lifecycle.upgrade_repair_required"),
                )?;
            }
            "aborted" => {}
            "activation-started" | "repair-required" | "finalizing" => {
                systemd.set_command_deadline(Instant::now() + INSTALL_COMMAND_BUDGET);
                systemd.stop()?;
                for (index, destination) in destinations.iter().enumerate() {
                    let name = destination
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or(InstallError::Io)?;
                    let staged = destination.with_file_name(format!(".{name}.enoki-upgrade-new"));
                    if staged.exists() {
                        fs::rename(&staged, destination).map_err(|_| InstallError::Io)?;
                        sync_directory(destination.parent().ok_or(InstallError::Io)?)?;
                    } else if !destination.exists() {
                        return Err(InstallError::ExistingResidue);
                    }
                    write_upgrade_attempt_from_journal(
                        paths,
                        &contents,
                        "activation-started",
                        index + 1,
                        finalized_targets,
                    )?;
                }
                systemd.daemon_reload()?;
                systemd.start()?;
                systemd.wait_local_activated()?;
                write_upgrade_attempt_from_journal(
                    paths,
                    &contents,
                    "finalizing",
                    destinations.len(),
                    finalized_targets,
                )?;
                for (index, destination) in destinations.iter().enumerate() {
                    let name = destination
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or(InstallError::Io)?;
                    let backup = destination.with_file_name(format!(".{name}.enoki-upgrade-old"));
                    match fs::remove_file(&backup) {
                        Ok(()) => sync_directory(backup.parent().ok_or(InstallError::Io)?)?,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => return Err(InstallError::Io),
                    }
                    write_upgrade_attempt_from_journal(
                        paths,
                        &contents,
                        "finalizing",
                        destinations.len(),
                        index + 1,
                    )?;
                }
                write_upgrade_attempt_from_journal(
                    paths,
                    &contents,
                    "stage-cleanup-required",
                    destinations.len(),
                    destinations.len(),
                )?;
                write_operation_status(
                    paths,
                    &attempt,
                    &target_bundle_version,
                    "failed",
                    Some("lifecycle.upgrade_repair_required"),
                )?;
            }
            "stage-cleanup-required" => {}
            "activated" => return Ok(None),
            _ => return Err(InstallError::ExistingResidue),
        }
        Ok(Some(receipt))
    })();
    if recovered.is_err() && !matches!(phase, "admitted" | "prepared" | "aborted") {
        let _ = mark_upgrade_attempt_phase(paths, "repair-required");
        let _ = write_operation_status(
            paths,
            &attempt,
            &target_bundle_version,
            "failed",
            Some("lifecycle.upgrade_repair_required"),
        );
    }
    recovered
}

pub fn finalize_probe_upgrade_stage_cleanup(
    paths: &FixedInstallPaths,
    receipt: &UpgradeRecoveryReceipt,
) -> Result<(), InstallError> {
    let journal_path = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    let contents = trusted_text(&journal_path, paths.expected_root_uid(), 0o600)?;
    if journal_string(&contents, "operation_id")? != receipt.operation_id
        || journal_usize(&contents, "stage_owner_uid")? != receipt.stage_owner_uid as usize
        || journal_string(&contents, "target_bundle_version")? != receipt.target_bundle_version
    {
        return Err(InstallError::ExistingResidue);
    }
    let phase = journal_string(&contents, "phase")?;
    if receipt.activated {
        if phase != "stage-cleanup-required" {
            return Err(InstallError::ExistingResidue);
        }
        mark_upgrade_attempt_phase(paths, "activated")?;
        write_operation_status(
            paths,
            &UpgradeAttempt {
                operation_id: receipt.operation_id.clone(),
                stage_owner_uid: receipt.stage_owner_uid,
                authority_sha256: None,
            },
            &receipt.target_bundle_version,
            "running",
            None,
        )
    } else {
        if phase != "aborted" {
            return Err(InstallError::ExistingResidue);
        }
        write_operation_status(
            paths,
            &UpgradeAttempt {
                operation_id: receipt.operation_id.clone(),
                stage_owner_uid: receipt.stage_owner_uid,
                authority_sha256: None,
            },
            &receipt.target_bundle_version,
            "failed",
            Some("lifecycle.upgrade_failed_before_activation"),
        )
    }
}

fn write_upgrade_attempt_from_journal(
    paths: &FixedInstallPaths,
    prior: &str,
    phase: &str,
    activated_targets: usize,
    finalized_targets: usize,
) -> Result<(), InstallError> {
    let mut counts = [0_u8; 3];
    let mut output = String::new();
    for line in prior.lines() {
        if line.starts_with("phase = ") {
            counts[0] += 1;
            output.push_str(&format!("phase = {phase:?}\n"));
        } else if line.starts_with("activated_targets = ") {
            counts[1] += 1;
            output.push_str(&format!("activated_targets = {activated_targets}\n"));
        } else if line.starts_with("finalized_targets = ") {
            counts[2] += 1;
            output.push_str(&format!("finalized_targets = {finalized_targets}\n"));
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if counts != [1, 1, 1] {
        return Err(InstallError::ExistingResidue);
    }
    atomic_durable_write(
        &paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
        output.as_bytes(),
        0o600,
    )
}

fn write_upgrade_attempt(
    paths: &FixedInstallPaths,
    attempt: &UpgradeAttempt,
    source: &InstalledUpgradeBinding,
    bundle: &VerifiedBundle,
    phase: &str,
    activated_targets: usize,
    finalized_targets: usize,
) -> Result<(), InstallError> {
    let authority_sha256 = attempt
        .authority_sha256
        .clone()
        .unwrap_or_else(|| upgrade_authority_sha256(attempt, source, bundle));
    let contents = format!(
        "schema_version = 1\noperation_id = {:?}\nstage_owner_uid = {}\nauthority_sha256 = {:?}\nsource_probe_id = {:?}\nsource_bundle_version = {:?}\nsource_install_state_sha256 = {:?}\nsource_manifest_sha256 = {:?}\ntarget_bundle_version = {:?}\ntarget_install_state_sha256 = {:?}\ntarget_manifest_sha256 = {:?}\nphase = {:?}\nactivated_targets = {activated_targets}\nfinalized_targets = {finalized_targets}\n",
        attempt.operation_id,
        attempt.stage_owner_uid,
        authority_sha256,
        source.probe_id,
        source.source_bundle_version,
        source.source_install_state_sha256,
        source.source_manifest_sha256,
        bundle.version,
        bundle.install_state_sha256(),
        bundle.manifest_sha256,
        phase,
    );
    atomic_durable_write(
        &paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
        contents.as_bytes(),
        0o600,
    )
}

fn upgrade_authority_sha256(
    attempt: &UpgradeAttempt,
    source: &InstalledUpgradeBinding,
    bundle: &VerifiedBundle,
) -> String {
    let canonical = format!(
        "enoki/lifecycle-upgrade-consumption/v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        attempt.operation_id,
        source.hub_origin,
        source.probe_id,
        source.source_bundle_version,
        source.source_install_state_sha256,
        bundle.version,
        bundle.manifest_sha256,
    );
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

fn write_operation_status(
    paths: &FixedInstallPaths,
    attempt: &UpgradeAttempt,
    target_version: &str,
    status: &str,
    error_code: Option<&str>,
) -> Result<(), InstallError> {
    let mut contents = format!(
        "operation_id = {:?}\ntarget_probe_version = {:?}\nstatus = {:?}\n",
        attempt.operation_id, target_version, status,
    );
    if let Some(code) = error_code {
        contents.push_str(&format!("error_code = {:?}\nmessage = \"\"\n", code));
    }
    atomic_durable_write(
        &paths.state().join(OPERATION_STATUS_FILE),
        contents.as_bytes(),
        0o644,
    )
}

fn atomic_durable_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| InstallError::Io)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(InstallError::ExistingResidue);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InstallError::Io)?;
    let temporary = parent.join(format!(".{name}.enoki-write"));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| InstallError::Io)?;
    file.write_all(bytes).map_err(|_| InstallError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| InstallError::Io)?;
    file.sync_all().map_err(|_| InstallError::Io)?;
    fs::rename(&temporary, path).map_err(|_| InstallError::Io)?;
    sync_directory(parent)
}

fn sync_destination_directories(paths: &[PathBuf]) -> Result<(), InstallError> {
    let mut parents = std::collections::BTreeSet::new();
    for path in paths {
        parents.insert(path.parent().ok_or(InstallError::Io)?.to_path_buf());
    }
    for parent in parents {
        sync_directory(&parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), InstallError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InstallError::Io)
}

pub(super) fn upgrade_destinations(paths: &FixedInstallPaths) -> Vec<PathBuf> {
    vec![
        paths.binary(),
        paths.observation_runtime_binary(),
        paths.cpu_provider_binary(),
        paths.disk_health_provider_binary(),
        paths.lifecycle_companion_binary(),
        paths.bootstrap_acquirer(),
        paths.bootstrap_activator(),
        paths.unit(),
        paths.observation_runtime_unit(),
        paths.observation_runtime_socket_unit(),
        paths.cpu_provider_unit(),
        paths.cpu_provider_socket_unit(),
        paths.disk_health_provider_unit(),
        paths.disk_health_provider_socket_unit(),
        paths.lifecycle_companion_unit(),
        paths.lifecycle_companion_socket_unit(),
        paths.lifecycle_upgrade_unit(),
        paths.lifecycle_upgrade_socket_unit(),
        paths.identity(),
        paths.metadata(),
    ]
}

fn version_is_newer(target: &str, source: &str) -> bool {
    fn parse(value: &str) -> Option<[u64; 3]> {
        let values = value.strip_prefix('v').unwrap_or(value);
        let mut parts = values.split('.');
        let parsed = [
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        ];
        parts.next().is_none().then_some(parsed)
    }
    parse(target)
        .zip(parse(source))
        .is_some_and(|(target, source)| target > source)
}
