//! The fixed fresh-install adapter for the current Probe component.
//!
//! This is intentionally a small closed boundary: a verified component can
//! become only the current Probe service at the paths below.  It has no
//! archive, network, command-line interpolation, or candidate-code surface.

use crate::{handoff::Enrollment, trust::BuildTrust, verifier::VerifiedBundle};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

const SERVICE_NAME: &str = "enoki-probe";
const SERVICE_USER: &str = "enoki-probe";
const SERVICE_GROUP: &str = "enoki-probe";
const BINARY: &str = "/usr/local/bin/enoki-probe";
const STATE: &str = "/var/lib/enoki-probe";
const IDENTITY_DIR: &str = "/var/lib/enoki-probe/identity";
const IDENTITY: &str = "/var/lib/enoki-probe/identity/probe-bootstrap.toml";
const INSTALL_METADATA: &str = "/etc/enoki/probe-install.toml";
const UNIT: &str = "/etc/systemd/system/enoki-probe.service";
const BOOTSTRAP_ACQUIRER: &str = "/usr/local/bin/enoki-probe-bootstrap-acquire";
const BOOTSTRAP_ACTIVATOR: &str = "/usr/local/bin/enoki-probe-bootstrap-activate";
const BOOTSTRAP_STATE: &str = "/var/lib/enoki-probe-bootstrap";
const OPERATION_SUDOERS: &str = "/etc/sudoers.d/enoki-probe-operations";
const COLLECTOR_SUDOERS: &str = "/etc/sudoers.d/enoki-probe-collector-helpers";
const LEGACY_SUDOERS: &str = "/etc/sudoers.d/enoki-probe-upgrader";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ServiceIdentity {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InstallError {
    ExistingResidue,
    InvalidVerifiedComponent,
    Account,
    Systemd,
    Io,
}

/// Accounts are deliberately separate from systemd so tests can prove the
/// exact authority requests without executing host management commands.
pub trait AccountPort {
    fn require_absent(&mut self) -> Result<(), InstallError>;
    fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError>;
    fn remove_static_service_identity(&mut self) -> Result<(), InstallError>;
}

/// The only service-manager actions this adapter may request.
pub trait SystemdPort {
    fn require_absent(&mut self) -> Result<(), InstallError>;
    fn daemon_reload(&mut self) -> Result<(), InstallError>;
    fn enable(&mut self) -> Result<(), InstallError>;
    fn start(&mut self) -> Result<(), InstallError>;
    fn wait_ready(&mut self) -> Result<(), InstallError>;
    fn stop(&mut self) -> Result<(), InstallError>;
    fn disable(&mut self) -> Result<(), InstallError>;
}

#[derive(Clone, Debug)]
pub struct FixedInstallPaths {
    root: PathBuf,
}

impl FixedInstallPaths {
    pub fn production() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    #[cfg(test)]
    fn under(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn map(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    fn binary(&self) -> PathBuf {
        self.map(BINARY)
    }
    fn state(&self) -> PathBuf {
        self.map(STATE)
    }
    fn identity_dir(&self) -> PathBuf {
        self.map(IDENTITY_DIR)
    }
    fn identity(&self) -> PathBuf {
        self.map(IDENTITY)
    }
    fn metadata(&self) -> PathBuf {
        self.map(INSTALL_METADATA)
    }
    fn etc_enoki(&self) -> PathBuf {
        self.map("/etc/enoki")
    }
    fn unit(&self) -> PathBuf {
        self.map(UNIT)
    }
    fn bootstrap_acquirer(&self) -> PathBuf {
        self.map(BOOTSTRAP_ACQUIRER)
    }
    fn bootstrap_activator(&self) -> PathBuf {
        self.map(BOOTSTRAP_ACTIVATOR)
    }
}

/// Activates precisely the verified current `probe` component.  It is a
/// fresh-install-only operation: any previously managed evidence is a closed
/// failure, rather than an implicit upgrade, repair, or reinstall.
pub fn activate_current_probe(
    component: &mut File,
    enrollment: &Enrollment,
    bundle: &VerifiedBundle,
    trust: &BuildTrust,
    paths: &FixedInstallPaths,
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
) -> Result<(), InstallError> {
    let trust_version = trust.version.strip_prefix('v').unwrap_or(trust.version);
    if bundle.target != trust.target || bundle.version != trust_version || bundle.component_len == 0
    {
        return Err(InstallError::InvalidVerifiedComponent);
    }
    validate_component(component, bundle.component_len)?;
    preflight_files(paths)?;
    let created_etc_enoki = ensure_fixed_metadata_directory(&paths.etc_enoki())?;
    validate_bootstrap_role(&paths.bootstrap_acquirer())?;
    validate_bootstrap_role(&paths.bootstrap_activator())?;
    accounts.require_absent()?;
    systemd.require_absent()?;

    let identity = accounts.create_static_service_identity()?;
    let mut enabled = false;
    let mut started = false;
    let result = (|| {
        create_private_directory(&paths.state(), 0o750, identity)?;
        create_private_directory(&paths.identity_dir(), 0o700, identity)?;
        install_binary(component, &paths.binary())?;
        atomic_write_owned(
            &paths.identity(),
            bootstrap_config(enrollment, trust).as_bytes(),
            0o600,
            identity,
        )?;
        atomic_write_owned(
            &paths.metadata(),
            install_metadata(enrollment, trust).as_bytes(),
            0o600,
            ServiceIdentity { uid: 0, gid: 0 },
        )?;
        atomic_write_owned(
            &paths.unit(),
            service_unit().as_bytes(),
            0o644,
            ServiceIdentity { uid: 0, gid: 0 },
        )?;
        systemd.daemon_reload()?;
        systemd.enable()?;
        enabled = true;
        started = true;
        systemd.start()?;
        systemd.wait_ready()?;
        Ok(())
    })();
    if result.is_err() {
        if started {
            let _ = systemd.stop();
        }
        if enabled {
            let _ = systemd.disable();
        }
        // No metadata is retained after failure, so every path below was
        // created by this invocation and may be removed.  The bootstrap
        // roles predate ownership transfer and are intentionally excluded.
        let cleanup = cleanup_failed_install(paths, accounts, systemd, created_etc_enoki);
        if cleanup.is_err() {
            return Err(InstallError::Io);
        }
    }
    result
}

fn cleanup_failed_install(
    paths: &FixedInstallPaths,
    accounts: &mut impl AccountPort,
    systemd: &mut impl SystemdPort,
    created_etc_enoki: bool,
) -> Result<(), InstallError> {
    for path in [
        paths.unit(),
        paths.metadata(),
        paths.identity(),
        paths.binary(),
    ] {
        remove_created_path(&path)?;
    }
    remove_created_directory(&paths.identity_dir())?;
    remove_created_directory(&paths.state())?;
    if created_etc_enoki {
        remove_created_directory(&paths.etc_enoki())?;
    }
    // Systemd must forget the removed unit before another fresh install is
    // allowed to consult its absence state.
    systemd.daemon_reload()?;
    accounts.remove_static_service_identity()
}

fn ensure_fixed_metadata_directory(path: &Path) -> Result<bool, InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .map_err(|_| InstallError::Io)?;
            let dir = File::open(path).map_err(|_| InstallError::Io)?;
            chown_file(&dir, ServiceIdentity { uid: 0, gid: 0 })?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::Io)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o755
            {
                return Err(InstallError::ExistingResidue);
            }
            Ok(false)
        }
        Err(_) => Err(InstallError::Io),
    }
}

fn remove_created_path(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|_| InstallError::Io)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(InstallError::Io),
    }
}

fn remove_created_directory(path: &Path) -> Result<(), InstallError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError::Io),
    }
}

fn validate_component(component: &mut File, expected_len: u64) -> Result<(), InstallError> {
    let metadata = component.metadata().map_err(|_| InstallError::Io)?;
    if !metadata.is_file() || metadata.len() != expected_len {
        return Err(InstallError::InvalidVerifiedComponent);
    }
    component
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallError::Io)?;
    Ok(())
}

fn preflight_files(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    for path in [
        paths.binary(),
        paths.state(),
        paths.identity_dir(),
        paths.identity(),
        paths.metadata(),
        paths.unit(),
        paths.map(OPERATION_SUDOERS),
        paths.map(COLLECTOR_SUDOERS),
        paths.map(LEGACY_SUDOERS),
        paths.map("/etc/enoki/probe-bootstrap.toml"),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(InstallError::ExistingResidue),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(InstallError::Io),
        }
    }
    Ok(())
}

/// The two bootstrap roles were installed before this transaction.  They only
/// become Probe-owned after the schema-2 metadata is atomically persisted.
/// Until then a failed activation deliberately leaves them untouched.
fn validate_bootstrap_role(path: &Path) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o755
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

fn create_private_directory(
    path: &Path,
    mode: u32,
    identity: ServiceIdentity,
) -> Result<(), InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    fs::create_dir(path).map_err(|_| InstallError::Io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|_| InstallError::Io)?;
    let directory = File::open(path).map_err(|_| InstallError::Io)?;
    chown_file(&directory, identity)?;
    verify_directory(path, mode, identity)
}

fn ensure_safe_parent_chain(path: &Path) -> Result<(), InstallError> {
    let mut current = Some(path);
    while let Some(directory) = current {
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            }
            _ => return Err(InstallError::Io),
        }
        current = directory.parent();
    }
    Ok(())
}

fn verify_directory(path: &Path, mode: u32, identity: ServiceIdentity) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.mode() & 0o777 != mode
        || metadata.uid() != identity.uid
        || metadata.gid() != identity.gid
    {
        return Err(InstallError::Io);
    }
    Ok(())
}

fn install_binary(component: &mut File, destination: &Path) -> Result<(), InstallError> {
    let parent = destination.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    component
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallError::Io)?;
    let mut output = exclusive_temp(parent, 0o755)?;
    std::io::copy(component, &mut output.0).map_err(|_| InstallError::Io)?;
    output.0.sync_all().map_err(|_| InstallError::Io)?;
    chown_file(&output.0, ServiceIdentity { uid: 0, gid: 0 })?;
    rename_new(output.1, destination)
}

fn atomic_write_owned(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: ServiceIdentity,
) -> Result<(), InstallError> {
    let parent = path.parent().ok_or(InstallError::Io)?;
    ensure_safe_parent_chain(parent)?;
    let (mut file, temporary) = exclusive_temp(parent, mode)?;
    file.write_all(contents).map_err(|_| InstallError::Io)?;
    file.sync_all().map_err(|_| InstallError::Io)?;
    chown_file(&file, owner)?;
    rename_new(temporary, path)
}

fn exclusive_temp(parent: &Path, mode: u32) -> Result<(File, PathBuf), InstallError> {
    for suffix in 0..32 {
        let path = parent.join(format!(".enoki-probe-bootstrap-{suffix}"));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path);
        match opened {
            Ok(file) => {
                // `mode` on create is filtered by the caller's umask. These
                // are security contracts, so restore the exact mode on the
                // opened descriptor before it can be linked into the layout.
                file.set_permissions(fs::Permissions::from_mode(mode))
                    .map_err(|_| InstallError::Io)?;
                return Ok((file, path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(InstallError::Io),
        }
    }
    Err(InstallError::Io)
}

fn rename_new(from: PathBuf, destination: &Path) -> Result<(), InstallError> {
    match fs::hard_link(&from, destination) {
        Ok(()) => {
            fs::remove_file(from).map_err(|_| InstallError::Io)?;
            File::open(destination.parent().ok_or(InstallError::Io)?)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| InstallError::Io)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(InstallError::ExistingResidue)
        }
        Err(_) => Err(InstallError::Io),
    }
}

fn chown_file(file: &File, identity: ServiceIdentity) -> Result<(), InstallError> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::fchown(file.as_raw_fd(), identity.uid, identity.gid) } != 0 {
        return Err(InstallError::Io);
    }
    Ok(())
}

fn bootstrap_config(enrollment: &Enrollment, trust: &BuildTrust) -> String {
    format!(
        "hub_url = {:?}\nenrollment_token = {:?}\nstate_dir = {:?}\noperation_status_path = {:?}\ninstall_path = {:?}\nservice_name = {:?}\nservice_user = {:?}\nprobe_distribution_root_sha256 = {:?}\nlog_level = \"info\"\n",
        enrollment.hub_origin(),
        enrollment.enrollment_token(),
        STATE,
        "/var/lib/enoki-probe/probe-operation-status.toml",
        BINARY,
        SERVICE_NAME,
        SERVICE_USER,
        trust.root_fingerprint,
    )
}

fn install_metadata(enrollment: &Enrollment, trust: &BuildTrust) -> String {
    format!(
        "schema_version = 2\nhub_url = {:?}\nidentity_path = {:?}\ninstall_path = {:?}\noperation_status_path = {:?}\nstate_dir = {:?}\nprobe_distribution_root_sha256 = {:?}\nbootstrap_state_dir = {:?}\nbootstrap_acquirer_path = {:?}\nbootstrap_activator_path = {:?}\nservice_name = {:?}\nservice_user = {:?}\nservice_group = {:?}\nservice_unit_path = {:?}\n",
        enrollment.hub_origin(),
        IDENTITY,
        BINARY,
        "/var/lib/enoki-probe/probe-operation-status.toml",
        STATE,
        trust.root_fingerprint,
        BOOTSTRAP_STATE,
        BOOTSTRAP_ACQUIRER,
        BOOTSTRAP_ACTIVATOR,
        SERVICE_NAME,
        SERVICE_USER,
        SERVICE_GROUP,
        UNIT,
    )
}

fn service_unit() -> &'static str {
    "[Unit]\nDescription=Enoki Probe\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=notify\nNotifyAccess=main\nUser=enoki-probe\nGroup=enoki-probe\nExecStart=/usr/local/bin/enoki-probe run --config /var/lib/enoki-probe/identity/probe-bootstrap.toml\nRestart=on-failure\nRestartPreventExitStatus=78\nRestartSec=5s\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\nProtectControlGroups=true\nReadWritePaths=/var/lib/enoki-probe /var/lib/enoki-probe/identity\n\n[Install]\nWantedBy=multi-user.target\n"
}

/// Production account implementation. Every executable and argument is fixed;
/// the process environment is discarded before invoking it.
pub struct SystemAccounts;
impl AccountPort for SystemAccounts {
    fn require_absent(&mut self) -> Result<(), InstallError> {
        let group = command_presence("/usr/bin/getent", &["group", SERVICE_GROUP], 2)?;
        let user = command_presence("/usr/bin/id", &["-u", SERVICE_USER], 1)?;
        if group || user {
            Err(InstallError::ExistingResidue)
        } else {
            Ok(())
        }
    }
    fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
        create_static_service_identity_with_commands(
            &mut |program, arguments| require_success(program, arguments, InstallError::Account),
            &mut numeric_id,
        )
    }
    fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
        require_success("/usr/sbin/userdel", &[SERVICE_USER], InstallError::Account)?;
        require_success(
            "/usr/sbin/groupdel",
            &[SERVICE_GROUP],
            InstallError::Account,
        )
    }
}

/// The account transaction has no durable metadata until identity discovery
/// completes.  Therefore every failure after `groupadd` removes exactly the
/// identities this attempt created, leaving a later fresh install possible.
fn create_static_service_identity_with_commands(
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
    lookup_id: &mut impl FnMut(&str) -> Result<u32, InstallError>,
) -> Result<ServiceIdentity, InstallError> {
    execute("/usr/sbin/groupadd", &["--system", SERVICE_GROUP])?;
    if let Err(error) = execute(
        "/usr/sbin/useradd",
        &[
            "--system",
            "--gid",
            SERVICE_GROUP,
            "--home-dir",
            STATE,
            "--shell",
            "/usr/sbin/nologin",
            SERVICE_USER,
        ],
    ) {
        rollback_created_group(execute);
        return Err(error);
    }
    let uid = match lookup_id("-u") {
        Ok(uid) => uid,
        Err(error) => {
            rollback_created_identity(execute);
            return Err(error);
        }
    };
    let gid = match lookup_id("-g") {
        Ok(gid) => gid,
        Err(error) => {
            rollback_created_identity(execute);
            return Err(error);
        }
    };
    Ok(ServiceIdentity { uid, gid })
}

fn rollback_created_group(execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>) {
    let _ = execute("/usr/sbin/groupdel", &[SERVICE_GROUP]);
}

fn rollback_created_identity(execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>) {
    let _ = execute("/usr/sbin/userdel", &[SERVICE_USER]);
    rollback_created_group(execute);
}

/// Production systemd implementation. Its only dynamic data is absent: all
/// unit names and paths are compiled constants.
pub struct SystemSystemd;
impl SystemdPort for SystemSystemd {
    fn require_absent(&mut self) -> Result<(), InstallError> {
        let enabled = Command::new("/usr/bin/systemctl")
            .args(["is-enabled", "--full", "--no-pager", "enoki-probe.service"])
            .env_clear()
            .env("LANG", "C")
            .output()
            .map_err(|_| InstallError::Systemd)?;
        let enabled_value = single_systemd_value(&enabled.stdout)?;
        if enabled_value != "not-found" || !matches!(enabled.status.code(), Some(1) | Some(4)) {
            return Err(InstallError::ExistingResidue);
        }
        let loaded = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "--property=LoadState",
                "--value",
                "enoki-probe.service",
            ])
            .env_clear()
            .env("LANG", "C")
            .output()
            .map_err(|_| InstallError::Systemd)?;
        if !loaded.status.success() || single_systemd_value(&loaded.stdout)? != "not-found" {
            return Err(InstallError::ExistingResidue);
        }
        Ok(())
    }
    fn daemon_reload(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["daemon-reload"],
            InstallError::Systemd,
        )
    }
    fn enable(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["enable", "enoki-probe.service"],
            InstallError::Systemd,
        )
    }
    fn start(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["start", "--no-block", "enoki-probe.service"],
            InstallError::Systemd,
        )
    }
    fn wait_ready(&mut self) -> Result<(), InstallError> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if require_success(
                "/usr/bin/systemctl",
                &["is-active", "--quiet", "enoki-probe.service"],
                InstallError::Systemd,
            )
            .is_ok()
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(InstallError::Systemd);
            }
            thread::sleep(Duration::from_millis(250));
        }
    }
    fn stop(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["stop", "enoki-probe.service"],
            InstallError::Systemd,
        )
    }
    fn disable(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["disable", "enoki-probe.service"],
            InstallError::Systemd,
        )
    }
}

fn command_presence(
    program: &str,
    arguments: &[&str],
    absent_status: i32,
) -> Result<bool, InstallError> {
    let status = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .status()
        .map_err(|_| InstallError::Account)?;
    match status.code() {
        Some(0) => Ok(true),
        Some(code) if code == absent_status => Ok(false),
        _ => Err(InstallError::Account),
    }
}
fn require_success(
    program: &str,
    arguments: &[&str],
    error: InstallError,
) -> Result<(), InstallError> {
    let status = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .status()
        .map_err(|_| error)?;
    status.success().then_some(()).ok_or(error)
}
fn numeric_id(flag: &str) -> Result<u32, InstallError> {
    let output = Command::new("/usr/bin/id")
        .args([flag, SERVICE_USER])
        .env_clear()
        .env("LANG", "C")
        .output()
        .map_err(|_| InstallError::Account)?;
    if !output.status.success() {
        return Err(InstallError::Account);
    }
    std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or(InstallError::Account)
}

fn single_systemd_value(bytes: &[u8]) -> Result<&str, InstallError> {
    let value = std::str::from_utf8(bytes).map_err(|_| InstallError::Systemd)?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(InstallError::Systemd);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handoff::Enrollment;
    use crate::trust::BootstrapRole;
    use tempfile::tempdir;

    #[derive(Default)]
    struct Accounts {
        calls: Vec<&'static str>,
        reject: bool,
    }
    impl AccountPort for Accounts {
        fn require_absent(&mut self) -> Result<(), InstallError> {
            self.calls.push("absent");
            (!self.reject)
                .then_some(())
                .ok_or(InstallError::ExistingResidue)
        }
        fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
            self.calls.push("create");
            Ok(ServiceIdentity {
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            })
        }
        fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
            self.calls.push("remove");
            Ok(())
        }
    }
    #[derive(Default)]
    struct Systemd {
        calls: Vec<&'static str>,
        fail_start: bool,
        residue: bool,
    }
    impl SystemdPort for Systemd {
        fn require_absent(&mut self) -> Result<(), InstallError> {
            self.calls.push("absent");
            (!self.residue)
                .then_some(())
                .ok_or(InstallError::ExistingResidue)
        }
        fn daemon_reload(&mut self) -> Result<(), InstallError> {
            self.calls.push("reload");
            Ok(())
        }
        fn enable(&mut self) -> Result<(), InstallError> {
            self.calls.push("enable");
            Ok(())
        }
        fn start(&mut self) -> Result<(), InstallError> {
            self.calls.push("start");
            (!self.fail_start)
                .then_some(())
                .ok_or(InstallError::Systemd)
        }
        fn wait_ready(&mut self) -> Result<(), InstallError> {
            self.calls.push("ready");
            Ok(())
        }
        fn stop(&mut self) -> Result<(), InstallError> {
            self.calls.push("stop");
            Ok(())
        }
        fn disable(&mut self) -> Result<(), InstallError> {
            self.calls.push("disable");
            Ok(())
        }
    }
    fn trust() -> BuildTrust {
        BuildTrust {
            distribution: "enoki",
            role: BootstrapRole::Activator,
            root_pem: "",
            root_fingerprint: "a".repeat(64).leak(),
            root_key_id: "",
            target: "x86_64-unknown-linux-gnu",
            version: "v1.2.3",
        }
    }
    fn bundle() -> VerifiedBundle {
        VerifiedBundle {
            version: "1.2.3".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            delegation_generation: 1,
            component_len: 5,
        }
    }
    fn component() -> File {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), b"probe").unwrap();
        temp.reopen().unwrap()
    }

    #[test]
    fn account_identity_lookup_failure_rolls_back_created_user_and_group() {
        use std::cell::RefCell;

        for failed_lookup in ["-u", "-g"] {
            let calls = RefCell::new(Vec::new());
            let mut execute = |program: &str, _arguments: &[&str]| {
                calls.borrow_mut().push(program.to_string());
                Ok(())
            };
            let mut lookup = |flag: &str| {
                calls.borrow_mut().push(format!("id {flag}"));
                if flag == failed_lookup {
                    Err(InstallError::Account)
                } else {
                    Ok(123)
                }
            };

            let error = create_static_service_identity_with_commands(&mut execute, &mut lookup)
                .expect_err("failed numeric identity lookup rolls back");

            assert_eq!(error, InstallError::Account);
            let mut expected = vec![
                "/usr/sbin/groupadd".to_string(),
                "/usr/sbin/useradd".to_string(),
                "id -u".to_string(),
            ];
            if failed_lookup == "-g" {
                expected.push("id -g".to_string());
            }
            expected.extend([
                "/usr/sbin/userdel".to_string(),
                "/usr/sbin/groupdel".to_string(),
            ]);
            assert_eq!(*calls.borrow(), expected);
        }
    }

    #[test]
    fn fresh_verified_probe_becomes_only_the_fixed_current_service() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap();
        let binary = temporary.path().join("usr/local/bin/enoki-probe");
        assert_eq!(fs::read(binary).unwrap(), b"probe");
        let config = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        )
        .unwrap();
        assert!(config.contains("hub_url = \"https://hub.example\""));
        assert!(config.contains("probe_distribution_root_sha256"));
        assert!(!config.contains("probe_asset_public_key_sha256"));
        let metadata =
            fs::read_to_string(temporary.path().join("etc/enoki/probe-install.toml")).unwrap();
        assert!(metadata.contains("schema_version = 2"));
        assert!(metadata.contains("bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\""));
        assert_eq!(
            fs::metadata(temporary.path().join("etc/enoki"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        assert!(!metadata.contains("sudoers_path"));
        assert!(!metadata.contains("probe_asset_public_key_sha256"));
        assert_eq!(
            fs::metadata(temporary.path().join("usr/local/bin/enoki-probe"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(
                temporary
                    .path()
                    .join("var/lib/enoki-probe/identity/probe-bootstrap.toml")
            )
            .unwrap()
            .mode()
                & 0o777,
            0o600
        );
        assert_eq!(accounts.calls, ["absent", "create"]);
        assert_eq!(
            systemd.calls,
            ["absent", "reload", "enable", "start", "ready"]
        );
    }

    #[test]
    fn existing_or_symlinked_enoki_residue_fails_before_any_host_authority() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            "/not-a-probe",
            temporary.path().join("usr/local/bin/enoki-probe"),
        )
        .unwrap();
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap_err();
        assert_eq!(error, InstallError::ExistingResidue);
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
        assert!(!format!("{error:?}").contains("enk_enroll_secret"));
    }

    #[test]
    fn unsafe_existing_metadata_directory_fails_before_any_host_authority() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        fs::set_permissions(
            temporary.path().join("etc/enoki"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect_err("unsafe metadata directory fails closed");

        assert_eq!(error, InstallError::ExistingResidue);
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_metadata_directory_fails_before_any_host_authority() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let target = temporary.path().join("outside");
        fs::create_dir(&target).unwrap();
        symlink(&target, temporary.path().join("etc/enoki")).unwrap();
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect_err("symlinked metadata directory fails closed");

        assert_eq!(error, InstallError::ExistingResidue);
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn start_failure_rolls_back_only_this_attempt_and_allows_a_fresh_retry() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            calls: Vec::new(),
            fail_start: true,
            residue: false,
        };
        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap_err();
        assert_eq!(error, InstallError::Systemd);
        assert_eq!(
            systemd.calls,
            [
                "absent", "reload", "enable", "start", "stop", "disable", "reload"
            ]
        );
        assert_eq!(accounts.calls, ["absent", "create", "remove"]);
        assert!(!temporary.path().join("usr/local/bin/enoki-probe").exists());
        assert!(!temporary.path().join("var/lib/enoki-probe").exists());
        assert!(
            !temporary
                .path()
                .join("etc/enoki/probe-install.toml")
                .exists()
        );
        assert!(
            !temporary
                .path()
                .join("etc/systemd/system/enoki-probe.service")
                .exists()
        );
        assert!(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-acquire")
                .exists()
        );
        assert!(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-activate")
                .exists()
        );
        systemd.fail_start = false;
        activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect("a transient start failure leaves a retryable fresh install");
        assert!(temporary.path().join("usr/local/bin/enoki-probe").exists());
        assert!(
            temporary
                .path()
                .join("etc/enoki/probe-install.toml")
                .exists()
        );
    }

    #[test]
    fn loaded_systemd_residue_fails_before_creating_the_service_account_or_files() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            calls: Vec::new(),
            fail_start: false,
            residue: true,
        };
        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd
            ),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(accounts.calls, ["absent"]);
        assert_eq!(systemd.calls, ["absent"]);
        assert!(!temporary.path().join("var/lib/enoki-probe").exists());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_roles_must_be_root_owned_regular_0755_files_and_are_never_cleaned_on_failure() {
        use std::os::unix::fs::symlink;
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let acquirer = temporary
            .path()
            .join("usr/local/bin/enoki-probe-bootstrap-acquire");
        symlink("/untrusted", &acquirer).unwrap();
        fs::write(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-activate"),
            "role",
        )
        .unwrap();
        fs::set_permissions(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-activate"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd
            ),
            Err(InstallError::ExistingResidue)
        );
        assert!(
            fs::symlink_metadata(acquirer)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    fn write_bootstrap_roles(root: &Path) {
        for role in [
            "enoki-probe-bootstrap-acquire",
            "enoki-probe-bootstrap-activate",
        ] {
            let path = root.join("usr/local/bin").join(role);
            fs::write(&path, "bootstrap role").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}
