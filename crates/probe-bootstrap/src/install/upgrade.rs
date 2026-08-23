use super::*;
use crate::lifecycle::{UpgradeCompletion, UpgradeLifecycleEffects, execute_upgrade_lifecycle};
use std::io::Read;

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
    let mut effects = UpgradeEffects {
        components: Some(components),
        bundle,
        expected_source,
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
    paths: &'a FixedInstallPaths,
    systemd: &'a mut S,
    prepared: Option<PreparedUpgrade>,
}

impl<S: SystemdPort> UpgradeLifecycleEffects for UpgradeEffects<'_, S> {
    type Error = InstallError;

    fn verify_and_prepare(&mut self) -> Result<(), Self::Error> {
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
        self.prepared = Some(prepare_upgrade(
            components,
            self.bundle,
            self.paths,
            &actual,
        )?);
        Ok(())
    }

    fn activate_complete_bundle(&mut self) -> Result<(), Self::Error> {
        let mut prepared = self.prepared.take().ok_or(InstallError::Io)?;
        prepared.retain_for_repair = true;
        self.systemd
            .set_command_deadline(Instant::now() + INSTALL_COMMAND_BUDGET);
        self.systemd.stop()?;
        for (temporary, destination) in prepared.staged.iter().zip(&prepared.destinations) {
            fs::rename(temporary, destination).map_err(|_| InstallError::Io)?;
        }
        self.systemd.daemon_reload()?;
        self.systemd.start()?;
        self.systemd.wait_local_activated()?;
        for backup in &prepared.backups {
            fs::remove_file(backup).map_err(|_| InstallError::Io)?;
        }
        prepared.retain_for_repair = false;
        Ok(())
    }
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
    let current_metadata = fs::read_to_string(paths.metadata()).map_err(|_| InstallError::Io)?;
    let updated = updated_metadata(&current_metadata, bundle, source)?;
    prepared.staged.push(stage_bytes(
        updated.as_bytes(),
        &prepared.destinations[18],
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
    output.sync_all().map_err(|_| InstallError::Io)?;
    Ok(temporary)
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
