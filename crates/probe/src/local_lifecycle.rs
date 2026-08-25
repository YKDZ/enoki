use std::{
    env,
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::{
    hub_url,
    registration::{
        HttpRegistrationTransport, ProbeInstallationInspectionInput,
        ProbeInstallationRejectionInput, ProbeInstallationTarget, RegistrationError,
        RegistrationTransport, inspect_probe_installation, prepare_probe_installation_rejection,
        submit_prepared_installation_rejection,
    },
    secure_file::{atomic_write, ensure_directory, managed_path_exists},
    upgrader::{
        cleanup_trusted_probe_install_for_reenrollment, read_trusted_probe_install_preflight,
    },
};

pub const LOCAL_LIFECYCLE_COMPLETE_MARKER: &str = "ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE";
const LEGACY_UPGRADER_SUDOERS_PATH: &str = "/etc/sudoers.d/enoki-probe-upgrader";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallationRejectionRetryPolicy {
    pub deadline: Duration,
    pub max_attempts: usize,
    pub retry_delay: Duration,
}

const DEFAULT_INSTALLATION_REJECTION_RETRY_POLICY: InstallationRejectionRetryPolicy =
    InstallationRejectionRetryPolicy {
        deadline: Duration::from_secs(5),
        max_attempts: 3,
        retry_delay: Duration::from_secs(1),
    };

pub trait InstallationRejectionClock {
    fn now(&self) -> Duration;
}

pub trait InstallationRejectionSleeper {
    fn sleep(&mut self, duration: Duration);
}

struct MonotonicInstallationRejectionClock {
    started_at: Instant,
}

impl MonotonicInstallationRejectionClock {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
}

impl InstallationRejectionClock for MonotonicInstallationRejectionClock {
    fn now(&self) -> Duration {
        self.started_at.elapsed()
    }
}

struct ThreadInstallationRejectionSleeper;

impl InstallationRejectionSleeper for ThreadInstallationRejectionSleeper {
    fn sleep(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
}

#[derive(Debug)]
pub struct InstallationRejectionConfirmationError {
    error: RegistrationError,
}

impl fmt::Display for InstallationRejectionConfirmationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Hub未确认 installation rejection: {}",
            self.error
        )
    }
}

impl Error for InstallationRejectionConfirmationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

pub fn probe_local_install_input_from_environment(
    candidate_binary: PathBuf,
) -> Result<ProbeLocalInstallInput, ProbeLocalLifecycleError> {
    let value = |name: &str, default: &str| match env::var(name) {
        Ok(value) => value,
        Err(_) => default.to_string(),
    };
    let required = |name: &'static str| {
        env::var(name)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or(ProbeLocalLifecycleError::InvalidInput(name))
    };
    let readiness_timeout = env::var("ENOKI_READINESS_TIMEOUT_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| ProbeLocalLifecycleError::InvalidInput("invalid readiness timeout"))?
        .unwrap_or(60);
    Ok(ProbeLocalInstallInput {
        candidate_binary,
        collector_helper_sudoers_path: PathBuf::from(value(
            "ENOKI_COLLECTOR_HELPER_SUDOERS_PATH",
            "/etc/sudoers.d/enoki-probe-collector-helpers",
        )),
        enrollment_token: required("ENOKI_ENROLLMENT_TOKEN is required")?,
        hub_url: required("ENOKI_HUB_URL is required")?,
        identity_path: PathBuf::from(value(
            "ENOKI_CONFIG_PATH",
            "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
        )),
        install_metadata_path: PathBuf::from(value(
            "ENOKI_INSTALL_METADATA_PATH",
            "/etc/enoki/probe-install.toml",
        )),
        install_path: PathBuf::from(value("ENOKI_INSTALL_PATH", "/usr/local/bin/enoki-probe")),
        log_level: value("ENOKI_LOG_LEVEL", "info"),
        operation_sudoers_path: PathBuf::from(value(
            "ENOKI_OPERATION_SUDOERS_PATH",
            "/etc/sudoers.d/enoki-probe-operations",
        )),
        readiness_timeout: Duration::from_secs(readiness_timeout.max(1)),
        service_group: value("ENOKI_SERVICE_GROUP", "enoki-probe"),
        service_name: "enoki-probe".to_string(),
        service_unit_path: PathBuf::from(value(
            "ENOKI_SERVICE_UNIT_PATH",
            "/etc/systemd/system/enoki-probe.service",
        )),
        service_user: value("ENOKI_SERVICE_USER", "enoki-probe"),
        state_dir: PathBuf::from(value("ENOKI_STATE_DIR", "/var/lib/enoki-probe")),
        test_root: env::var_os("ENOKI_TEST_ROOT").map(PathBuf::from),
        trusted_asset_public_key_sha256: required(
            "ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256 is required",
        )?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeLocalInstallInput {
    pub candidate_binary: PathBuf,
    pub collector_helper_sudoers_path: PathBuf,
    pub enrollment_token: String,
    pub hub_url: String,
    pub identity_path: PathBuf,
    pub install_metadata_path: PathBuf,
    pub install_path: PathBuf,
    pub log_level: String,
    pub operation_sudoers_path: PathBuf,
    pub readiness_timeout: Duration,
    pub service_group: String,
    pub service_name: String,
    pub service_unit_path: PathBuf,
    pub service_user: String,
    pub state_dir: PathBuf,
    pub test_root: Option<PathBuf>,
    pub trusted_asset_public_key_sha256: String,
}

#[derive(Debug)]
pub enum ProbeLocalLifecycleError {
    ExistingInstallation,
    ExistingInstallationWithProbeId(String),
    ExistingInstallationBoundToDifferentHub,
    ExistingInstallationCleanup(String),
    InstallationInspection(String),
    InvalidExistingInstallation,
    InvalidInput(&'static str),
    Io(std::io::Error),
    ReadinessTimeout,
    ServiceCommand(String),
}

impl fmt::Display for ProbeLocalLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExistingInstallation => write!(
                formatter,
                "a pre-existing Enoki Probe installation or residue was found; use Local Probe Uninstall or Host Re-enrollment"
            ),
            Self::ExistingInstallationWithProbeId(_) => write!(
                formatter,
                "a pre-existing Enoki Probe installation was found; use Local Probe Uninstall or Host Re-enrollment"
            ),
            Self::ExistingInstallationBoundToDifferentHub => write!(
                formatter,
                "a pre-existing Enoki Probe installation is bound to a different Hub; use Local Probe Uninstall before re-enrollment"
            ),
            Self::ExistingInstallationCleanup(message) => write!(
                formatter,
                "same-Hub Probe re-enrollment cleanup failed: {message}"
            ),
            Self::InstallationInspection(message) => {
                write!(formatter, "Probe installation inspection failed: {message}")
            }
            Self::InvalidExistingInstallation => write!(
                formatter,
                "pre-existing Enoki Probe installation metadata is unsafe or incomplete; use Local Probe Uninstall before re-enrollment"
            ),
            Self::InvalidInput(message) => {
                write!(formatter, "invalid Probe Local Lifecycle input: {message}")
            }
            Self::Io(error) => write!(
                formatter,
                "Probe Local Lifecycle filesystem failure: {error}"
            ),
            Self::ReadinessTimeout => write!(
                formatter,
                "Probe Installation Readiness was not confirmed before the installation deadline"
            ),
            Self::ServiceCommand(message) => write!(
                formatter,
                "Probe Local Lifecycle systemd failure: {message}"
            ),
        }
    }
}

impl Error for ProbeLocalLifecycleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::ExistingInstallation
            | Self::ExistingInstallationWithProbeId(_)
            | Self::ExistingInstallationBoundToDifferentHub
            | Self::ExistingInstallationCleanup(_)
            | Self::InstallationInspection(_)
            | Self::InvalidExistingInstallation
            | Self::InvalidInput(_)
            | Self::ReadinessTimeout
            | Self::ServiceCommand(_) => None,
        }
    }
}

impl ProbeLocalLifecycleError {
    #[must_use]
    pub fn installation_rejection(&self) -> Option<(&'static str, String)> {
        match self {
            Self::ExistingInstallation => Some(("existing_probe_installation", String::new())),
            Self::ExistingInstallationWithProbeId(probe_id) => {
                Some(("existing_probe_installation", probe_id.clone()))
            }
            Self::ExistingInstallationBoundToDifferentHub => Some((
                "probe_bound_to_different_hub",
                "local Probe installation is bound to a different Hub".to_string(),
            )),
            Self::InvalidExistingInstallation => Some((
                "probe_installation_metadata_invalid",
                "local Probe installation metadata is unsafe or incomplete".to_string(),
            )),
            Self::InvalidInput(_)
            | Self::Io(_)
            | Self::ReadinessTimeout
            | Self::ServiceCommand(_)
            | Self::ExistingInstallationCleanup(_)
            | Self::InstallationInspection(_) => None,
        }
    }
}

#[must_use]
pub fn format_probe_local_lifecycle_failure(error: &ProbeLocalLifecycleError) -> String {
    match error.installation_rejection() {
        Some((code, _)) => {
            format!("Probe Local Lifecycle failed: code={code} message={error}")
        }
        None => format!("Probe Local Lifecycle failed: {error}"),
    }
}

impl From<std::io::Error> for ProbeLocalLifecycleError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reports a known Probe Local Lifecycle rejection before the staged installer
/// exits. A lost 204 response is retried with the exact same protobuf body so
/// the Hub can confirm the terminal Enrollment idempotently.
pub fn confirm_probe_local_install_failure(
    input: &ProbeLocalInstallInput,
    error: &ProbeLocalLifecycleError,
) -> Result<(), InstallationRejectionConfirmationError> {
    let mut transport = HttpRegistrationTransport;
    let clock = MonotonicInstallationRejectionClock::new();
    let mut sleeper = ThreadInstallationRejectionSleeper;
    confirm_probe_local_install_failure_with_retry(
        input,
        error,
        &mut transport,
        &clock,
        &mut sleeper,
        DEFAULT_INSTALLATION_REJECTION_RETRY_POLICY,
    )
}

pub fn confirm_probe_local_install_failure_with_retry(
    input: &ProbeLocalInstallInput,
    lifecycle_error: &ProbeLocalLifecycleError,
    transport: &mut impl RegistrationTransport,
    clock: &impl InstallationRejectionClock,
    sleeper: &mut impl InstallationRejectionSleeper,
    policy: InstallationRejectionRetryPolicy,
) -> Result<(), InstallationRejectionConfirmationError> {
    let Some((code, message)) = lifecycle_error.installation_rejection() else {
        return Ok(());
    };
    let request = prepare_probe_installation_rejection(ProbeInstallationRejectionInput {
        code: code.to_string(),
        existing_probe_id: if code == "existing_probe_installation" {
            message.clone()
        } else {
            String::new()
        },
        enrollment_token: input.enrollment_token.clone(),
        hub_url: input.hub_url.clone(),
        message: if code == "existing_probe_installation" {
            String::new()
        } else {
            message
        },
    })
    .map_err(|error| InstallationRejectionConfirmationError { error })?;
    let deadline = clock.now().saturating_add(policy.deadline);
    let max_attempts = policy.max_attempts.max(1);

    for attempt in 0..max_attempts {
        match submit_prepared_installation_rejection(&request, transport) {
            Ok(()) => return Ok(()),
            Err(error) if error.is_transient() && attempt + 1 < max_attempts => {
                let now = clock.now();
                if now >= deadline {
                    return Err(InstallationRejectionConfirmationError { error });
                }
                sleeper.sleep(policy.retry_delay.min(deadline.saturating_sub(now)));
            }
            Err(error) => return Err(InstallationRejectionConfirmationError { error }),
        }
    }

    unreachable!("at least one installation rejection attempt is always made")
}

pub fn run_probe_local_install(
    input: &ProbeLocalInstallInput,
) -> Result<(), ProbeLocalLifecycleError> {
    let mut transport = HttpRegistrationTransport;
    run_probe_local_install_with_registration_transport(input, &mut transport)
}

pub fn run_probe_local_install_with_registration_transport(
    input: &ProbeLocalInstallInput,
    transport: &mut impl RegistrationTransport,
) -> Result<(), ProbeLocalLifecycleError> {
    validate_input(input)?;
    let target = inspect_probe_installation(
        ProbeInstallationInspectionInput {
            enrollment_token: input.enrollment_token.clone(),
            hub_url: input.hub_url.clone(),
        },
        transport,
    )
    .map_err(|error| ProbeLocalLifecycleError::InstallationInspection(error.to_string()))?;
    let existing_host_cleanup = preflight_for_installation_target(input, target)?;
    require_root(input)?;
    validate_root_managed_ancestry(input)?;
    ensure_systemd()?;

    if existing_host_cleanup {
        cleanup_trusted_probe_install_for_reenrollment(
            &input.install_metadata_path,
            input.test_root.as_deref(),
        )
        .map_err(|error| {
            ProbeLocalLifecycleError::ExistingInstallationCleanup(error.to_string())
        })?;
        preflight_fresh_installation(input)?;
    }

    let mut service_enabled = false;
    let mut service_started = false;
    let result = (|| {
        let service_identity = ensure_service_account(input)?;
        install_candidate_binary(input)?;
        write_bootstrap_config(input, service_identity)?;
        assign_service_ownership(input, service_identity)?;
        write_install_metadata(input)?;
        write_systemd_service(input)?;
        write_operation_sudoers(input)?;
        run_systemctl(&["daemon-reload"])?;
        run_systemctl(&["enable", &unit_name(input)])?;
        service_enabled = true;
        let start_arguments = lifecycle_start_arguments(&unit_name(input));
        let start_argument_references = start_arguments
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        run_systemctl(&start_argument_references)?;
        service_started = true;
        wait_for_readiness(input)
    })();

    if let Err(error) = result {
        // A failed fresh installation must leave its installed evidence intact,
        // but it must not leave a restart loop running in the background.
        if service_started {
            let _ = run_systemctl(&["stop", &unit_name(input)]);
        }
        if service_enabled {
            let _ = run_systemctl(&["disable", &unit_name(input)]);
        }
        return Err(error);
    }

    Ok(())
}

fn preflight_for_installation_target(
    input: &ProbeLocalInstallInput,
    target: ProbeInstallationTarget,
) -> Result<bool, ProbeLocalLifecycleError> {
    match target {
        ProbeInstallationTarget::NewHost => preflight_fresh_installation(input).map(|()| false),
        ProbeInstallationTarget::ExistingHost => preflight_existing_host_reenrollment(input),
        ProbeInstallationTarget::ManualReinstall(_) => Err(ProbeLocalLifecycleError::InvalidInput(
            "manual reinstall requires Lifecycle Companion",
        )),
    }
}

fn preflight_existing_host_reenrollment(
    input: &ProbeLocalInstallInput,
) -> Result<bool, ProbeLocalLifecycleError> {
    let path = rooted_path(input, &input.install_metadata_path);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            preflight_fresh_installation(input).map(|()| false)
        }
        Err(error) => Err(ProbeLocalLifecycleError::Io(error)),
        Ok(_) => {
            let trusted = read_trusted_probe_install_preflight(&path, input.test_root.as_deref())
                .map_err(|_| ProbeLocalLifecycleError::InvalidExistingInstallation)?;
            let candidate_hub = hub_url::normalized_base(&input.hub_url)
                .map_err(|_| ProbeLocalLifecycleError::InvalidInput("invalid Hub URL"))?;
            if trusted.hub_url != candidate_hub {
                Err(ProbeLocalLifecycleError::ExistingInstallationBoundToDifferentHub)
            } else {
                Ok(true)
            }
        }
    }
}

pub fn render_probe_systemd_service(input: &ProbeLocalInstallInput) -> String {
    format!(
        "[Unit]\nDescription=Enoki Probe\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=notify\nNotifyAccess=main\nUser={}\nGroup={}\nExecStart={} run --config {}\nRestart=on-failure\nRestartPreventExitStatus=78\nRestartSec=5s\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\nProtectControlGroups=true\nReadWritePaths={} {}\n\n[Install]\nWantedBy=multi-user.target\n",
        input.service_user,
        input.service_group,
        input.install_path.display(),
        input.identity_path.display(),
        input.state_dir.display(),
        input
            .identity_path
            .parent()
            .unwrap_or(&input.state_dir)
            .display(),
    )
}

fn validate_input(input: &ProbeLocalInstallInput) -> Result<(), ProbeLocalLifecycleError> {
    if input.enrollment_token.is_empty() {
        return Err(ProbeLocalLifecycleError::InvalidInput(
            "missing Enrollment Token",
        ));
    }
    if hub_url::normalized_base(&input.hub_url).is_err() {
        return Err(ProbeLocalLifecycleError::InvalidInput("invalid Hub URL"));
    }
    if input.service_name != "enoki-probe"
        || !safe_account_name(&input.service_user)
        || !safe_account_name(&input.service_group)
    {
        return Err(ProbeLocalLifecycleError::InvalidInput(
            "unsafe service identity",
        ));
    }
    if !sha256_hex(&input.trusted_asset_public_key_sha256) {
        return Err(ProbeLocalLifecycleError::InvalidInput(
            "invalid trusted Probe asset signing key fingerprint",
        ));
    }
    if input.identity_path != service_identity_path(input) {
        return Err(ProbeLocalLifecycleError::InvalidInput(
            "Probe identity must use the service-owned private identity directory",
        ));
    }
    for path in [
        &input.identity_path,
        &input.install_metadata_path,
        &input.install_path,
        &input.operation_sudoers_path,
        &input.collector_helper_sudoers_path,
        &input.service_unit_path,
        &input.state_dir,
    ] {
        safe_absolute_path(path)?;
    }
    let candidate_metadata = fs::symlink_metadata(&input.candidate_binary)?;
    if candidate_metadata.file_type().is_symlink() || !candidate_metadata.file_type().is_file() {
        return Err(ProbeLocalLifecycleError::InvalidInput(
            "staged Probe candidate is not a regular file",
        ));
    }
    Ok(())
}

fn preflight_fresh_installation(
    input: &ProbeLocalInstallInput,
) -> Result<(), ProbeLocalLifecycleError> {
    preflight_existing_install_metadata(input)?;
    for path in [
        &input.identity_path,
        &input.install_path,
        &input.operation_sudoers_path,
        &input.collector_helper_sudoers_path,
        &input.service_unit_path,
        &input.state_dir,
        Path::new(LEGACY_UPGRADER_SUDOERS_PATH),
    ] {
        let managed_path = rooted_path(input, path);
        if managed_path_exists(&managed_path)? {
            return Err(ProbeLocalLifecycleError::InvalidExistingInstallation);
        }
    }
    if command_succeeds("getent", &["group", &input.service_group])
        || command_succeeds("id", &["-u", &input.service_user])
    {
        return Err(ProbeLocalLifecycleError::InvalidExistingInstallation);
    }
    preflight_systemd_residue(input)?;
    Ok(())
}

fn preflight_existing_install_metadata(
    input: &ProbeLocalInstallInput,
) -> Result<(), ProbeLocalLifecycleError> {
    let path = rooted_path(input, &input.install_metadata_path);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ProbeLocalLifecycleError::Io(error)),
    };
    let trusted = read_trusted_probe_install_preflight(&path, input.test_root.as_deref())
        .map_err(|_| ProbeLocalLifecycleError::InvalidExistingInstallation)?;
    let existing_hub = trusted.hub_url;
    let candidate_hub = hub_url::normalized_base(&input.hub_url)
        .map_err(|_| ProbeLocalLifecycleError::InvalidInput("invalid Hub URL"))?;
    if existing_hub == candidate_hub {
        Err(ProbeLocalLifecycleError::ExistingInstallationWithProbeId(
            trusted.probe_id,
        ))
    } else {
        Err(ProbeLocalLifecycleError::ExistingInstallationBoundToDifferentHub)
    }
}

fn preflight_systemd_residue(
    input: &ProbeLocalInstallInput,
) -> Result<(), ProbeLocalLifecycleError> {
    let unit = unit_name(input);
    let enabled = systemd_enabled_state(&unit)
        .map_err(|_| ProbeLocalLifecycleError::InvalidExistingInstallation)?;
    let load_state = systemd_load_state(&unit)
        .map_err(|_| ProbeLocalLifecycleError::InvalidExistingInstallation)?;
    if systemd_preflight_is_clean(Ok(enabled), Ok(load_state)) {
        Ok(())
    } else {
        Err(ProbeLocalLifecycleError::InvalidExistingInstallation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SystemdEnabledState {
    Disabled,
    NotFound,
    Enabled,
}

fn systemd_enabled_state(unit: &str) -> Result<SystemdEnabledState, ProbeLocalLifecycleError> {
    let output = Command::new("systemctl")
        .args(["is-enabled", "--full", "--no-pager", unit])
        .output()
        .map_err(ProbeLocalLifecycleError::Io)?;
    parse_systemd_enabled_state(output.status.code(), &output.stdout).map_err(|_| {
        ProbeLocalLifecycleError::ServiceCommand(format!(
            "systemctl is-enabled did not return an explicit enabled, disabled, or not-found state for {unit}"
        ))
    })
}

fn systemd_load_state(unit: &str) -> Result<String, ProbeLocalLifecycleError> {
    let output = Command::new("systemctl")
        .args(["show", "--property=LoadState", "--value", unit])
        .output()
        .map_err(ProbeLocalLifecycleError::Io)?;
    if !output.status.success() {
        return Err(ProbeLocalLifecycleError::ServiceCommand(format!(
            "systemctl show failed for {unit}"
        )));
    }
    systemd_stdout_value(&output.stdout)
        .map(str::to_string)
        .map_err(|_| {
            ProbeLocalLifecycleError::ServiceCommand(format!(
                "systemctl show did not return a single LoadState value for {unit}"
            ))
        })
}

fn parse_systemd_enabled_state(
    status: Option<i32>,
    stdout: &[u8],
) -> Result<SystemdEnabledState, &'static str> {
    let state = systemd_stdout_value(stdout)?;
    match (status, state) {
        (Some(1), "disabled") => Ok(SystemdEnabledState::Disabled),
        // Ubuntu 24.04 returns exit 4 for an absent unit. Ubuntu 22.04-era
        // systemd can return exit 1, but only its exact `not-found` state is
        // accepted so a generic command failure can never look clean.
        (Some(4) | Some(1), "not-found") => Ok(SystemdEnabledState::NotFound),
        (Some(0), "enabled") => Ok(SystemdEnabledState::Enabled),
        _ => Err("unexpected systemctl is-enabled result"),
    }
}

#[cfg(test)]
fn parse_systemd_load_state(stdout: &[u8]) -> Result<&str, &'static str> {
    match systemd_stdout_value(stdout)? {
        "not-found" => Ok("not-found"),
        _ => Err("unexpected systemctl LoadState"),
    }
}

fn systemd_stdout_value(stdout: &[u8]) -> Result<&str, &'static str> {
    let value = std::str::from_utf8(stdout).map_err(|_| "non-UTF-8 systemctl stdout")?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err("malformed systemctl stdout");
    }
    Ok(value)
}

fn systemd_preflight_is_clean(
    enabled: Result<SystemdEnabledState, &str>,
    load_state: Result<String, &str>,
) -> bool {
    matches!(
        (enabled, load_state),
        (
            Ok(SystemdEnabledState::Disabled | SystemdEnabledState::NotFound),
            Ok(load_state),
        ) if load_state == "not-found"
    )
}

fn require_root(input: &ProbeLocalInstallInput) -> Result<(), ProbeLocalLifecycleError> {
    if input.test_root.is_some() || unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(ProbeLocalLifecycleError::InvalidInput(
            "Probe Local Lifecycle must run as root",
        ))
    }
}

fn validate_root_managed_ancestry(
    input: &ProbeLocalInstallInput,
) -> Result<(), ProbeLocalLifecycleError> {
    if input.test_root.is_some() {
        return Ok(());
    }
    for path in [
        &input.install_path,
        &input.install_metadata_path,
        &input.operation_sudoers_path,
        &input.collector_helper_sudoers_path,
        &input.service_unit_path,
        &input.state_dir,
    ] {
        let mut ancestor = path.parent();
        while let Some(directory) = ancestor {
            match fs::symlink_metadata(directory) {
                Ok(metadata) => validate_root_managed_directory_metadata(&metadata)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(ProbeLocalLifecycleError::Io(error)),
            }
            if directory == Path::new("/") {
                break;
            }
            ancestor = directory.parent();
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_root_managed_directory_metadata(
    metadata: &fs::Metadata,
) -> Result<(), ProbeLocalLifecycleError> {
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProbeLocalLifecycleError::InvalidInput(
            "root-managed directory ancestry ownership or mode is unsafe",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_root_managed_directory_metadata(
    _metadata: &fs::Metadata,
) -> Result<(), ProbeLocalLifecycleError> {
    Ok(())
}

fn ensure_systemd() -> Result<(), ProbeLocalLifecycleError> {
    run_systemctl(&["--version"])
}

fn ensure_service_account(
    input: &ProbeLocalInstallInput,
) -> Result<Option<(u32, u32)>, ProbeLocalLifecycleError> {
    if !command_succeeds("getent", &["group", &input.service_group]) {
        run_command("groupadd", &["--system", &input.service_group])?;
    }
    if !command_succeeds("id", &["-u", &input.service_user]) {
        run_command(
            "useradd",
            &[
                "--system",
                "--gid",
                &input.service_group,
                "--home-dir",
                input
                    .state_dir
                    .to_str()
                    .ok_or(ProbeLocalLifecycleError::InvalidInput(
                        "state path is not UTF-8",
                    ))?,
                "--shell",
                "/usr/sbin/nologin",
                &input.service_user,
            ],
        )?;
    }
    if input.test_root.is_some() {
        return Ok(None);
    }

    Ok(Some(service_identity(input)?))
}

fn install_candidate_binary(
    input: &ProbeLocalInstallInput,
) -> Result<(), ProbeLocalLifecycleError> {
    let install_path = rooted_path(input, &input.install_path);
    atomic_write(
        &install_path,
        &fs::read(&input.candidate_binary)?,
        0o755,
        root_owner(input),
    )
    .map_err(ProbeLocalLifecycleError::Io)
}

fn write_bootstrap_config(
    input: &ProbeLocalInstallInput,
    service_identity: Option<(u32, u32)>,
) -> Result<(), ProbeLocalLifecycleError> {
    let path = rooted_path(input, &input.identity_path);
    let state_dir = rooted_path(input, &input.state_dir);
    let identity_dir = rooted_path(input, &service_identity_directory(input));
    ensure_directory(&state_dir, 0o750, service_identity)?;
    ensure_directory(&identity_dir, 0o700, service_identity)?;
    let contents = [
        format!("hub_url = {}", toml_string(&input.hub_url)),
        format!(
            "enrollment_token = {}",
            toml_string(&input.enrollment_token)
        ),
        format!(
            "state_dir = {}",
            toml_string(&input.state_dir.display().to_string())
        ),
        format!(
            "operation_status_path = {}",
            toml_string(
                &input
                    .state_dir
                    .join("probe-operation-status.toml")
                    .display()
                    .to_string()
            )
        ),
        format!(
            "install_path = {}",
            toml_string(&input.install_path.display().to_string())
        ),
        format!("service_name = {}", toml_string(&input.service_name)),
        format!("service_user = {}", toml_string(&input.service_user)),
        format!(
            "operation_sudoers_path = {}",
            toml_string(&input.operation_sudoers_path.display().to_string())
        ),
        format!(
            "collector_helper_sudoers_path = {}",
            toml_string(&input.collector_helper_sudoers_path.display().to_string())
        ),
        format!(
            "probe_asset_public_key_sha256 = {}",
            toml_string(&input.trusted_asset_public_key_sha256)
        ),
        "upgrader_launch = \"systemd\"".to_string(),
        format!("log_level = {}", toml_string(&input.log_level)),
        String::new(),
    ]
    .join("\n");
    atomic_write(&path, contents.as_bytes(), 0o600, service_identity)?;
    Ok(())
}

fn assign_service_ownership(
    input: &ProbeLocalInstallInput,
    service_identity: Option<(u32, u32)>,
) -> Result<(), ProbeLocalLifecycleError> {
    let Some((uid, gid)) = service_identity else {
        return Ok(());
    };

    verify_service_owned_directory(&rooted_path(input, &input.state_dir), uid, gid)?;
    verify_private_service_identity_directory(
        &rooted_path(input, &service_identity_directory(input)),
        uid,
        gid,
    )
}

fn root_owner(input: &ProbeLocalInstallInput) -> Option<(u32, u32)> {
    input.test_root.is_none().then_some((0, 0))
}

fn service_identity(
    input: &ProbeLocalInstallInput,
) -> Result<(u32, u32), ProbeLocalLifecycleError> {
    Ok((
        service_identity_value("-u", &input.service_user)?,
        service_identity_value("-g", &input.service_user)?,
    ))
}

fn service_identity_value(flag: &str, service_user: &str) -> Result<u32, ProbeLocalLifecycleError> {
    let output = Command::new("id")
        .args([flag, service_user])
        .output()
        .map_err(ProbeLocalLifecycleError::Io)?;
    if !output.status.success() {
        return Err(ProbeLocalLifecycleError::ServiceCommand(
            "created service identity could not be resolved".to_string(),
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|_| {
            ProbeLocalLifecycleError::ServiceCommand(
                "created service identity has an invalid numeric id".to_string(),
            )
        })
}

fn verify_service_owned_directory(
    path: &Path,
    uid: u32,
    gid: u32,
) -> Result<(), ProbeLocalLifecycleError> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || metadata.mode() & 0o777 != 0o750
            || metadata.uid() != uid
            || metadata.gid() != gid
        {
            return Err(ProbeLocalLifecycleError::InvalidInput(
                "service state directory ownership or mode is unsafe",
            ));
        }
    }
    Ok(())
}

fn verify_private_service_identity_directory(
    path: &Path,
    uid: u32,
    gid: u32,
) -> Result<(), ProbeLocalLifecycleError> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || metadata.mode() & 0o777 != 0o700
            || metadata.uid() != uid
            || metadata.gid() != gid
        {
            return Err(ProbeLocalLifecycleError::InvalidInput(
                "service identity directory ownership or mode is unsafe",
            ));
        }
    }
    Ok(())
}

fn service_identity_directory(input: &ProbeLocalInstallInput) -> PathBuf {
    input.state_dir.join("identity")
}

fn service_identity_path(input: &ProbeLocalInstallInput) -> PathBuf {
    service_identity_directory(input).join("probe-bootstrap.toml")
}

fn write_install_metadata(input: &ProbeLocalInstallInput) -> Result<(), ProbeLocalLifecycleError> {
    let path = rooted_path(input, &input.install_metadata_path);
    let contents = [
        "schema_version = 1".to_string(),
        format!(
            "hub_url = {}",
            toml_string(&hub_url::normalized_base(&input.hub_url).expect("validated Hub URL"))
        ),
        format!(
            "install_path = {}",
            toml_string(&input.install_path.display().to_string())
        ),
        format!(
            "identity_path = {}",
            toml_string(&input.identity_path.display().to_string())
        ),
        format!(
            "state_dir = {}",
            toml_string(&input.state_dir.display().to_string())
        ),
        format!(
            "operation_status_path = {}",
            toml_string(
                &input
                    .state_dir
                    .join("probe-operation-status.toml")
                    .display()
                    .to_string()
            )
        ),
        format!("service_name = {}", toml_string(&input.service_name)),
        format!("service_user = {}", toml_string(&input.service_user)),
        format!("service_group = {}", toml_string(&input.service_group)),
        format!(
            "service_unit_path = {}",
            toml_string(&input.service_unit_path.display().to_string())
        ),
        format!(
            "operation_sudoers_path = {}",
            toml_string(&input.operation_sudoers_path.display().to_string())
        ),
        format!(
            "collector_helper_sudoers_path = {}",
            toml_string(&input.collector_helper_sudoers_path.display().to_string())
        ),
        format!(
            "probe_asset_public_key_sha256 = {}",
            toml_string(&input.trusted_asset_public_key_sha256)
        ),
        String::new(),
    ]
    .join("\n");
    atomic_write(&path, contents.as_bytes(), 0o600, root_owner(input))
        .map_err(ProbeLocalLifecycleError::Io)
}

fn write_systemd_service(input: &ProbeLocalInstallInput) -> Result<(), ProbeLocalLifecycleError> {
    let path = rooted_path(input, &input.service_unit_path);
    atomic_write(
        &path,
        render_probe_systemd_service(input).as_bytes(),
        0o644,
        root_owner(input),
    )
    .map_err(ProbeLocalLifecycleError::Io)
}

fn write_operation_sudoers(input: &ProbeLocalInstallInput) -> Result<(), ProbeLocalLifecycleError> {
    let path = rooted_path(input, &input.operation_sudoers_path);
    let contents = format!(
        "# Managed by Enoki Probe installer.\n{} ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit={}-upgrader --property=Type=exec -- {} internal-upgrader --config {}\n{} ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit={}-uninstaller --property=Type=exec -- {} internal-uninstaller --config {}\n",
        input.service_user,
        input.service_name,
        input.install_path.display(),
        input.identity_path.display(),
        input.service_user,
        input.service_name,
        input.install_path.display(),
        input.identity_path.display(),
    );
    atomic_write(&path, contents.as_bytes(), 0o440, root_owner(input))
        .map_err(ProbeLocalLifecycleError::Io)
}

fn wait_for_readiness(input: &ProbeLocalInstallInput) -> Result<(), ProbeLocalLifecycleError> {
    let deadline = Instant::now() + input.readiness_timeout;
    loop {
        if command_succeeds("systemctl", &["is-active", "--quiet", &unit_name(input)]) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ProbeLocalLifecycleError::ReadinessTimeout);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn lifecycle_start_arguments(unit_name: &str) -> [String; 3] {
    [
        "start".to_string(),
        "--no-block".to_string(),
        unit_name.to_string(),
    ]
}

fn unit_name(input: &ProbeLocalInstallInput) -> String {
    format!("{}.service", input.service_name)
}

fn run_systemctl(args: &[&str]) -> Result<(), ProbeLocalLifecycleError> {
    run_command("systemctl", args)
}

fn run_command(program: &str, args: &[&str]) -> Result<(), ProbeLocalLifecycleError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(ProbeLocalLifecycleError::Io)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(ProbeLocalLifecycleError::ServiceCommand(
        if stderr.is_empty() {
            format!("{program} exited with {}", output.status)
        } else {
            stderr
        },
    ))
}

fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .is_ok_and(|status| status.success())
}

fn rooted_path(input: &ProbeLocalInstallInput, path: &Path) -> PathBuf {
    input.test_root.as_ref().map_or_else(
        || path.to_path_buf(),
        |root| root.join(path.strip_prefix("/").expect("validated absolute path")),
    )
}

fn safe_absolute_path(path: &Path) -> Result<(), ProbeLocalLifecycleError> {
    let value = path
        .to_str()
        .ok_or(ProbeLocalLifecycleError::InvalidInput("path is not UTF-8"))?;
    if !path.is_absolute()
        || path == Path::new("/")
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(ProbeLocalLifecycleError::InvalidInput(
            "unsafe managed path",
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(ProbeLocalLifecycleError::InvalidInput(
            "unsafe managed path",
        ));
    }
    Ok(())
}

fn safe_account_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .chars()
            .enumerate()
            .all(|(index, character)| match index {
                0 => character.is_ascii_lowercase() || character == '_',
                _ => {
                    character.is_ascii_lowercase()
                        || character.is_ascii_digit()
                        || matches!(character, '_' | '-' | '$')
                }
            })
}

fn sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn toml_string(value: &str) -> String {
    let escaped = value
        .chars()
        .flat_map(|character| character.escape_default())
        .collect::<String>();
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::sync::Mutex;

    static PATH_MUTATION_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    #[derive(Debug, Eq, PartialEq)]
    struct PathFingerprint {
        gid: u32,
        link_target: Option<PathBuf>,
        mode: u32,
        mtime: i64,
        mtime_nsec: i64,
        contents: Option<Vec<u8>>,
        uid: u32,
    }

    fn input() -> ProbeLocalInstallInput {
        ProbeLocalInstallInput {
            candidate_binary: PathBuf::from("/tmp/enoki-probe-candidate"),
            collector_helper_sudoers_path: PathBuf::from(
                "/etc/sudoers.d/enoki-probe-collector-helpers",
            ),
            enrollment_token: "enk_enroll_test".to_string(),
            hub_url: "https://hub.example".to_string(),
            identity_path: PathBuf::from("/var/lib/enoki-probe/identity/probe-bootstrap.toml"),
            install_metadata_path: PathBuf::from("/etc/enoki/probe-install.toml"),
            install_path: PathBuf::from("/usr/local/bin/enoki-probe"),
            log_level: "info".to_string(),
            operation_sudoers_path: PathBuf::from("/etc/sudoers.d/enoki-probe-operations"),
            readiness_timeout: Duration::from_secs(60),
            service_group: "enoki-probe".to_string(),
            service_name: "enoki-probe".to_string(),
            service_unit_path: PathBuf::from("/etc/systemd/system/enoki-probe.service"),
            service_user: "enoki-probe".to_string(),
            state_dir: PathBuf::from("/var/lib/enoki-probe"),
            test_root: None,
            trusted_asset_public_key_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn known_installation_rejections_render_stable_codes_without_leaking_tokens() {
        let token = "enk_enroll_do_not_emit";
        let cases = [
            (
                ProbeLocalLifecycleError::ExistingInstallationWithProbeId(token.to_string()),
                "existing_probe_installation",
                "pre-existing Enoki Probe installation was found",
            ),
            (
                ProbeLocalLifecycleError::ExistingInstallationBoundToDifferentHub,
                "probe_bound_to_different_hub",
                "bound to a different Hub",
            ),
            (
                ProbeLocalLifecycleError::InvalidExistingInstallation,
                "probe_installation_metadata_invalid",
                "metadata is unsafe or incomplete",
            ),
        ];

        for (error, code, message) in cases {
            let output = format_probe_local_lifecycle_failure(&error);

            assert!(output.starts_with("Probe Local Lifecycle failed:"));
            assert!(output.contains(&format!("code={code}")));
            assert!(output.contains(message));
            assert!(!output.contains(token));
        }
    }

    #[test]
    fn local_lifecycle_renders_a_notify_service_without_a_finite_global_startup_timeout() {
        let unit = render_probe_systemd_service(&input());

        assert!(unit.contains("Type=notify"));
        assert!(unit.contains("NotifyAccess=main"));
        assert!(unit.contains("RestartPreventExitStatus=78"));
        assert!(!unit.contains("TimeoutStartSec="));
    }

    #[test]
    fn local_lifecycle_starts_the_notify_service_without_blocking_the_finite_readiness_poll() {
        assert_eq!(
            lifecycle_start_arguments("enoki-probe.service"),
            [
                "start".to_string(),
                "--no-block".to_string(),
                "enoki-probe.service".to_string(),
            ]
        );
    }

    #[test]
    fn fresh_installation_systemd_preflight_fails_closed_except_for_explicit_disabled_not_found() {
        assert!(systemd_preflight_is_clean(
            Ok(SystemdEnabledState::Disabled),
            Ok("not-found".to_string()),
        ));
        assert!(systemd_preflight_is_clean(
            Ok(SystemdEnabledState::NotFound),
            Ok("not-found".to_string()),
        ));
        assert!(!systemd_preflight_is_clean(
            Ok(SystemdEnabledState::Enabled),
            Ok("not-found".to_string()),
        ));
        assert!(!systemd_preflight_is_clean(
            Ok(SystemdEnabledState::Disabled),
            Ok("loaded".to_string()),
        ));
        assert!(!systemd_preflight_is_clean(
            Err("is-enabled failed"),
            Ok("not-found".to_string()),
        ));
        assert!(!systemd_preflight_is_clean(
            Ok(SystemdEnabledState::Disabled),
            Err("show failed"),
        ));
        assert!(!systemd_preflight_is_clean(
            Ok(SystemdEnabledState::Disabled),
            Ok("unexpected output".to_string()),
        ));
    }

    #[test]
    fn ubuntu_systemd_is_enabled_contract_accepts_only_documented_disabled_and_not_found_results() {
        // Ubuntu 22.04's systemd reports a disabled unit with exit 1, while
        // Ubuntu 24.04 reports an absent unit with exit 4. Older systemd
        // releases may use exit 1 for the latter, but only with the exact
        // `not-found` stdout state.
        assert_eq!(
            parse_systemd_enabled_state(Some(1), b"disabled\n"),
            Ok(SystemdEnabledState::Disabled),
        );
        assert_eq!(
            parse_systemd_enabled_state(Some(4), b"not-found\n"),
            Ok(SystemdEnabledState::NotFound),
        );
        assert_eq!(
            parse_systemd_enabled_state(Some(1), b"not-found\n"),
            Ok(SystemdEnabledState::NotFound),
        );

        for (status, output) in [
            (Some(0), b"disabled\n".as_slice()),
            (Some(1), b"".as_slice()),
            (Some(1), b"not-found\nunexpected\n".as_slice()),
            (Some(2), b"not-found\n".as_slice()),
            (None, b"not-found\n".as_slice()),
            (Some(4), b"disabled\n".as_slice()),
            (Some(4), &[0xff]),
        ] {
            assert!(
                parse_systemd_enabled_state(status, output).is_err(),
                "status={status:?}, output={output:?} must fail closed"
            );
        }
    }

    #[test]
    fn systemd_load_state_requires_an_exact_not_found_value() {
        assert_eq!(parse_systemd_load_state(b"not-found\n"), Ok("not-found"));
        for output in [
            b"".as_slice(),
            b"not-found\nloaded\n".as_slice(),
            b"not-found\0".as_slice(),
            &[0xff],
        ] {
            assert!(
                parse_systemd_load_state(output).is_err(),
                "output={output:?} must fail closed"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn root_managed_directory_validation_rejects_a_writable_ancestry_component() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().expect("tempdir");
        let root_managed = temporary.path().join("root-managed");
        fs::create_dir(&root_managed).expect("directory");
        fs::set_permissions(&root_managed, fs::Permissions::from_mode(0o755)).expect("safe mode");
        if unsafe { libc::geteuid() } == 0 {
            validate_root_managed_directory_metadata(
                &fs::symlink_metadata(&root_managed).expect("safe metadata"),
            )
            .expect("root-owned safe directory is accepted");
        }
        fs::set_permissions(&root_managed, fs::Permissions::from_mode(0o777)).expect("unsafe mode");

        assert!(matches!(
            validate_root_managed_directory_metadata(
                &fs::symlink_metadata(&root_managed).expect("metadata"),
            ),
            Err(ProbeLocalLifecycleError::InvalidInput(_))
        ));
    }

    #[test]
    fn local_lifecycle_writes_escaped_operator_log_configuration_to_its_bootstrap_file() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let mut input = input();
        input.candidate_binary = candidate;
        input.log_level = "info\"\nnext = \"unsafe".to_string();
        input.test_root = Some(temporary.path().to_path_buf());

        write_bootstrap_config(&input, None).expect("bootstrap config");

        let config = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        )
        .expect("bootstrap config");
        assert!(config.contains("log_level = \"info\\\"\\nnext = \\\"unsafe\""));
    }

    #[cfg(unix)]
    #[test]
    fn local_lifecycle_creates_a_private_service_owned_identity_directory_separate_from_metadata() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let mut input = input();
        input.candidate_binary = candidate;
        input.identity_path = PathBuf::from("/var/lib/enoki-probe/identity/probe-bootstrap.toml");
        input.test_root = Some(temporary.path().to_path_buf());

        write_bootstrap_config(&input, None).expect("bootstrap config");

        let state_dir = temporary.path().join("var/lib/enoki-probe");
        let identity_dir = state_dir.join("identity");
        assert_eq!(
            fs::metadata(&state_dir)
                .expect("state directory")
                .permissions()
                .mode()
                & 0o777,
            0o750,
        );
        assert_eq!(
            fs::metadata(&identity_dir)
                .expect("identity directory")
                .permissions()
                .mode()
                & 0o777,
            0o700,
        );
        assert!(identity_dir.join("probe-bootstrap.toml").is_file());
        assert!(
            !temporary
                .path()
                .join("etc/enoki/probe-bootstrap.toml")
                .exists(),
            "the mixed root metadata directory must not contain mutable identity",
        );
    }

    #[test]
    fn fresh_installation_preflight_rejects_existing_managed_metadata_before_mutation() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let metadata = temporary.path().join("etc/enoki/probe-install.toml");
        fs::create_dir_all(metadata.parent().expect("parent")).expect("parent");
        fs::write(&metadata, "existing").expect("metadata");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());

        assert!(matches!(
            preflight_fresh_installation(&input),
            Err(ProbeLocalLifecycleError::InvalidExistingInstallation)
        ));
    }

    #[test]
    fn existing_host_target_allows_a_machine_without_a_local_probe_installation() {
        let _path_lock = PATH_MUTATION_LOCK.lock().expect("PATH lock");
        let temporary = tempfile::tempdir().expect("tempdir");
        let fake_commands = temporary.path().join("fake-commands");
        fs::create_dir(&fake_commands).expect("fake command directory");
        write_test_command(
            &fake_commands.join("systemctl"),
            "#!/bin/sh\ncase \"${1:-}\" in\n  is-enabled) printf '%s\\n' disabled; exit 1 ;;\n  show) printf '%s\\n' not-found; exit 0 ;;\n  is-active) exit 0 ;;\nesac\nexit 0\n",
        );
        for command in ["getent", "id"] {
            write_test_command(&fake_commands.join(command), "#!/bin/sh\nexit 1\n");
        }
        for command in ["groupadd", "useradd", "chown"] {
            write_test_command(&fake_commands.join(command), "#!/bin/sh\nexit 0\n");
        }
        let candidate = temporary.path().join("candidate");
        write_test_command(
            &candidate,
            "#!/bin/sh\nif [ \"${1:-}\" = \"internal-render-collector-helper-sudoers\" ]; then\n  printf '# helper sudoers\\n'\n  exit 0\nfi\nexit 64\n",
        );
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());

        with_test_path(&fake_commands, || {
            run_with_inspected_target(&input, ProbeInstallationTarget::ExistingHost)
        })
        .expect("an ExistingHost target can install where no local Probe remains");
        assert!(rooted_path(&input, &input.install_path).exists());
    }

    #[test]
    fn existing_host_target_cleans_a_complete_same_hub_installation_with_the_staged_candidate() {
        let _path_lock = PATH_MUTATION_LOCK.lock().expect("PATH lock");
        let temporary = tempfile::tempdir().expect("tempdir");
        let fake_commands = temporary.path().join("fake-commands");
        fs::create_dir(&fake_commands).expect("fake command directory");
        let command_log = temporary.path().join("commands.log");
        write_test_command(
            &fake_commands.join("systemctl"),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"${{1:-}}\" in\n  is-enabled) printf '%s\\n' disabled; exit 1 ;;\n  show) printf '%s\\n' not-found; exit 0 ;;\n  is-active) exit 0 ;;\nesac\nexit 0\n",
                command_log.display(),
            ),
        );
        write_test_command(&fake_commands.join("getent"), "#!/bin/sh\nexit 2\n");
        write_test_command(&fake_commands.join("id"), "#!/bin/sh\nexit 1\n");
        for command in ["groupadd", "useradd", "chown", "userdel", "groupdel"] {
            write_test_command(&fake_commands.join(command), "#!/bin/sh\nexit 0\n");
        }
        let candidate = temporary.path().join("candidate");
        write_test_command(
            &candidate,
            "#!/bin/sh\nif [ \"${1:-}\" = \"internal-render-collector-helper-sudoers\" ]; then\n  printf '# helper sudoers\\n'\n  exit 0\nfi\nprintf 'candidate must not be run as the old Probe\\n' >&2\nexit 64\n",
        );
        let mut input = input();
        input.candidate_binary = candidate.clone();
        input.test_root = Some(temporary.path().to_path_buf());
        write_install_metadata(&input).expect("trusted install metadata");
        write_complete_probe_identity(&input, "probe_same_hub_01", &input.hub_url);
        let old_binary = rooted_path(&input, &input.install_path);
        fs::create_dir_all(old_binary.parent().expect("old binary parent"))
            .expect("old binary parent");
        write_test_command(
            &old_binary,
            &format!(
                "#!/bin/sh\nprintf 'old binary invoked\\n' >> '{}'\nexit 64\n",
                command_log.display(),
            ),
        );
        for path in [
            rooted_path(&input, &input.operation_sudoers_path),
            rooted_path(&input, &input.collector_helper_sudoers_path),
            rooted_path(&input, &input.service_unit_path),
        ] {
            fs::create_dir_all(path.parent().expect("managed parent")).expect("managed parent");
            fs::write(path, "old managed residue").expect("managed residue");
        }
        let stale_state = rooted_path(&input, &input.state_dir).join("old-state");
        fs::write(&stale_state, "old state").expect("old state");
        let legacy_sudoers = temporary.path().join("etc/sudoers.d/enoki-probe-upgrader");
        fs::write(&legacy_sudoers, "legacy sudoers").expect("legacy sudoers");

        with_test_path(&fake_commands, || {
            run_with_inspected_target(&input, ProbeInstallationTarget::ExistingHost)
        })
        .expect("same-Hub re-enrollment cleans and reinstalls with the candidate");

        assert_eq!(
            fs::read(rooted_path(&input, &input.install_path)).expect("installed candidate"),
            fs::read(candidate).expect("candidate"),
        );
        assert!(rooted_path(&input, &input.identity_path).exists());
        assert!(rooted_path(&input, &input.install_metadata_path).exists());
        assert!(!stale_state.exists());
        assert!(!legacy_sudoers.exists());
        for path in [
            rooted_path(&input, &input.operation_sudoers_path),
            rooted_path(&input, &input.service_unit_path),
        ] {
            assert_ne!(
                fs::read_to_string(path).expect("reinstalled managed file"),
                "old managed residue"
            );
        }
        assert!(!rooted_path(&input, &input.collector_helper_sudoers_path).exists());
        let command_log = fs::read_to_string(command_log).expect("command log");
        assert!(!command_log.contains("old binary invoked"));
        for cleanup_command in [
            "stop enoki-probe",
            "disable enoki-probe",
            "reset-failed enoki-probe",
        ] {
            assert!(command_log.contains(cleanup_command), "{cleanup_command}");
        }
    }

    #[test]
    fn existing_host_target_rejects_a_cross_hub_installation_before_mutating_it() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());
        input.hub_url = "https://other-hub.example".to_string();
        write_install_metadata(&input).expect("trusted install metadata");
        write_complete_probe_identity(&input, "probe_other_hub_01", &input.hub_url);
        input.hub_url = "https://hub.example".to_string();
        let metadata_path = rooted_path(&input, &input.install_metadata_path);
        let identity_path = rooted_path(&input, &input.identity_path);
        let metadata_before = path_fingerprint(&metadata_path);
        let identity_before = path_fingerprint(&identity_path);

        let error = run_with_inspected_target(&input, ProbeInstallationTarget::ExistingHost)
            .expect_err("cross-Hub local installation must reject re-enrollment");

        assert!(matches!(
            error,
            ProbeLocalLifecycleError::ExistingInstallationBoundToDifferentHub
        ));
        assert_eq!(
            error.installation_rejection().map(|(code, _)| code),
            Some("probe_bound_to_different_hub"),
        );
        assert_eq!(path_fingerprint(&metadata_path), metadata_before);
        assert_eq!(path_fingerprint(&identity_path), identity_before);
        assert!(!rooted_path(&input, &input.install_path).exists());
    }

    #[test]
    fn existing_host_target_rejects_invalid_local_metadata_before_mutating_it() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());
        let metadata_path = rooted_path(&input, &input.install_metadata_path);
        fs::create_dir_all(metadata_path.parent().expect("metadata parent"))
            .expect("metadata parent");
        fs::write(&metadata_path, "unsafe = [").expect("invalid metadata");
        let metadata_before = path_fingerprint(&metadata_path);

        let error = run_with_inspected_target(&input, ProbeInstallationTarget::ExistingHost)
            .expect_err("invalid local installation metadata must reject re-enrollment");

        assert!(matches!(
            error,
            ProbeLocalLifecycleError::InvalidExistingInstallation
        ));
        assert_eq!(
            error.installation_rejection().map(|(code, _)| code),
            Some("probe_installation_metadata_invalid"),
        );
        assert_eq!(path_fingerprint(&metadata_path), metadata_before);
        assert!(!rooted_path(&input, &input.install_path).exists());
    }

    #[test]
    fn existing_host_target_stops_before_installing_when_shared_cleanup_fails() {
        let _path_lock = PATH_MUTATION_LOCK.lock().expect("PATH lock");
        let temporary = tempfile::tempdir().expect("tempdir");
        let fake_commands = temporary.path().join("fake-commands");
        fs::create_dir(&fake_commands).expect("fake command directory");
        let command_log = temporary.path().join("commands.log");
        write_test_command(
            &fake_commands.join("systemctl"),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"${{1:-}}\" in\n  stop) exit 1 ;;\n  show) printf '%s\\n' loaded; exit 0 ;;\nesac\nexit 0\n",
                command_log.display(),
            ),
        );
        let candidate = temporary.path().join("candidate");
        write_test_command(
            &candidate,
            "#!/bin/sh\nprintf 'candidate invoked\\n' >&2\nexit 64\n",
        );
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());
        write_install_metadata(&input).expect("trusted install metadata");
        write_complete_probe_identity(&input, "probe_same_hub_01", &input.hub_url);
        let metadata_path = rooted_path(&input, &input.install_metadata_path);
        let identity_path = rooted_path(&input, &input.identity_path);
        let metadata_before = path_fingerprint(&metadata_path);
        let identity_before = path_fingerprint(&identity_path);

        let error = with_test_path(&fake_commands, || {
            run_with_inspected_target(&input, ProbeInstallationTarget::ExistingHost)
        })
        .expect_err("cleanup failure must stop re-enrollment before installation");

        assert!(matches!(
            error,
            ProbeLocalLifecycleError::ExistingInstallationCleanup(_)
        ));
        assert_eq!(error.installation_rejection(), None);
        assert_eq!(path_fingerprint(&metadata_path), metadata_before);
        assert_eq!(path_fingerprint(&identity_path), identity_before);
        assert!(!rooted_path(&input, &input.install_path).exists());
        let command_log = fs::read_to_string(command_log).expect("command log");
        assert!(command_log.contains("stop enoki-probe"));
        assert!(!command_log.contains("enable enoki-probe.service"));
    }

    #[test]
    fn new_host_inspection_never_cleans_a_same_hub_installation_from_an_environment_marker() {
        let _path_lock = PATH_MUTATION_LOCK.lock().expect("PATH lock");
        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());
        write_install_metadata(&input).expect("trusted install metadata");
        write_complete_probe_identity(&input, "probe_same_hub_01", &input.hub_url);
        let old_binary = rooted_path(&input, &input.install_path);
        fs::create_dir_all(old_binary.parent().expect("old binary parent"))
            .expect("old binary parent");
        fs::write(&old_binary, "old Probe binary").expect("old binary");
        let metadata_path = rooted_path(&input, &input.install_metadata_path);
        let metadata_before = path_fingerprint(&metadata_path);
        let old_binary_before = path_fingerprint(&old_binary);

        let previous = env::var_os("ENOKI_ENROLLMENT_TARGET");
        // SAFETY: this test serializes and restores its process-wide environment mutation.
        unsafe { env::set_var("ENOKI_ENROLLMENT_TARGET", "existing_host") };
        let result = run_with_inspected_target(&input, ProbeInstallationTarget::NewHost);
        // SAFETY: restores the process-wide environment changed for this serialized test.
        unsafe {
            if let Some(previous) = previous {
                env::set_var("ENOKI_ENROLLMENT_TARGET", previous);
            } else {
                env::remove_var("ENOKI_ENROLLMENT_TARGET");
            }
        }

        assert!(matches!(
            result,
            Err(ProbeLocalLifecycleError::ExistingInstallationWithProbeId(_))
        ));
        assert_eq!(path_fingerprint(&metadata_path), metadata_before);
        assert_eq!(path_fingerprint(&old_binary), old_binary_before);
    }

    #[test]
    fn inspection_network_failure_happens_before_any_local_installation_mutation() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());
        let mut transport = FailingInspectionTransport;

        let error = run_probe_local_install_with_registration_transport(&input, &mut transport)
            .expect_err("inspection network failure must stop before local mutation");

        assert!(matches!(
            error,
            ProbeLocalLifecycleError::InstallationInspection(_)
        ));
        for path in [
            input.install_path.as_path(),
            input.identity_path.as_path(),
            input.install_metadata_path.as_path(),
            input.state_dir.as_path(),
        ] {
            assert!(!rooted_path(&input, path).exists(), "{}", path.display());
        }
    }

    #[test]
    fn installation_rejection_retries_the_same_encoded_body_until_the_hub_confirms_it() {
        let input = input();
        let error = ProbeLocalLifecycleError::ExistingInstallationBoundToDifferentHub;
        let mut transport = RejectionRetryTransport {
            attempts: 0,
            bodies: Vec::new(),
        };
        let now = std::rc::Rc::new(std::cell::Cell::new(Duration::from_secs(10)));
        let clock = TestInstallationRejectionClock {
            now: std::rc::Rc::clone(&now),
        };
        let mut sleeper = TestInstallationRejectionSleeper {
            now,
            sleeps: Vec::new(),
        };

        confirm_probe_local_install_failure_with_retry(
            &input,
            &error,
            &mut transport,
            &clock,
            &mut sleeper,
            InstallationRejectionRetryPolicy {
                deadline: Duration::from_secs(5),
                max_attempts: 3,
                retry_delay: Duration::from_secs(1),
            },
        )
        .expect("a transient rejection response is retried until Hub confirmation");

        assert_eq!(transport.bodies.len(), 2);
        assert_eq!(transport.bodies[0], transport.bodies[1]);
        assert_eq!(sleeper.sleeps, vec![Duration::from_secs(1)]);
    }

    #[test]
    fn installation_rejection_stops_at_its_deadline_without_leaking_the_enrollment_token() {
        let input = input();
        let error = ProbeLocalLifecycleError::ExistingInstallation;
        let mut transport = AlwaysTransientRejectionTransport { attempts: 0 };
        let now = std::rc::Rc::new(std::cell::Cell::new(Duration::from_secs(10)));
        let clock = TestInstallationRejectionClock {
            now: std::rc::Rc::clone(&now),
        };
        let mut sleeper = TestInstallationRejectionSleeper {
            now,
            sleeps: Vec::new(),
        };

        let confirmation = confirm_probe_local_install_failure_with_retry(
            &input,
            &error,
            &mut transport,
            &clock,
            &mut sleeper,
            InstallationRejectionRetryPolicy {
                deadline: Duration::from_secs(1),
                max_attempts: 5,
                retry_delay: Duration::from_secs(1),
            },
        )
        .expect_err("an unconfirmed transient rejection remains an installation failure");

        assert_eq!(transport.attempts, 2);
        assert_eq!(sleeper.sleeps, vec![Duration::from_secs(1)]);
        assert!(confirmation.to_string().contains("Hub未确认"));
        assert!(!confirmation.to_string().contains(&input.enrollment_token));
    }

    #[test]
    fn fresh_installation_preflight_distinguishes_a_probe_bound_to_a_different_hub_before_mutation()
    {
        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());
        input.hub_url = "https://other-hub.example".to_string();
        write_install_metadata(&input).expect("trusted metadata");
        write_complete_probe_identity(&input, "probe_other_hub_01", &input.hub_url);
        input.hub_url = "https://hub.example".to_string();

        assert!(matches!(
            preflight_fresh_installation(&input),
            Err(ProbeLocalLifecycleError::ExistingInstallationBoundToDifferentHub)
        ));
        assert_eq!(
            ProbeLocalLifecycleError::ExistingInstallationBoundToDifferentHub
                .installation_rejection(),
            Some((
                "probe_bound_to_different_hub",
                "local Probe installation is bound to a different Hub".to_string(),
            )),
        );
    }

    #[test]
    fn same_hub_preflight_rejects_trusted_metadata_without_an_identity_as_invalid() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());
        write_install_metadata(&input).expect("trusted metadata");

        assert!(matches!(
            preflight_fresh_installation(&input),
            Err(ProbeLocalLifecycleError::InvalidExistingInstallation)
        ));
    }

    #[test]
    fn same_hub_preflight_reports_only_a_strict_existing_public_probe_id_context() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let identity = temporary
            .path()
            .join("var/lib/enoki-probe/identity/probe-bootstrap.toml");
        fs::create_dir_all(identity.parent().expect("identity parent")).expect("identity parent");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());
        write_install_metadata(&input).expect("trusted metadata");
        write_complete_probe_identity(&input, "probe_known_01", "https://hub.example");

        assert_eq!(
            preflight_fresh_installation(&input)
                .expect_err("existing installation is rejected")
                .installation_rejection(),
            Some(("existing_probe_installation", "probe_known_01".to_string())),
        );
    }

    #[cfg(unix)]
    #[test]
    fn same_hub_preflight_rejects_every_untrusted_identity_without_mutating_evidence() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        enum IdentityState {
            Missing,
            Symlink,
            Directory,
            WrongMode,
            InvalidToml,
            MissingProbeId,
            InvalidProbeId,
            HubMismatch,
        }

        for state in [
            IdentityState::Missing,
            IdentityState::Symlink,
            IdentityState::Directory,
            IdentityState::WrongMode,
            IdentityState::InvalidToml,
            IdentityState::MissingProbeId,
            IdentityState::InvalidProbeId,
            IdentityState::HubMismatch,
        ] {
            let temporary = tempfile::tempdir().expect("tempdir");
            let candidate = temporary.path().join("candidate");
            fs::write(&candidate, "candidate").expect("candidate");
            let mut input = input();
            input.candidate_binary = candidate;
            input.test_root = Some(temporary.path().to_path_buf());
            write_install_metadata(&input).expect("trusted metadata");
            write_complete_probe_identity(&input, "probe_known_01", "https://hub.example");
            let identity_path = rooted_path(&input, &input.identity_path);

            match state {
                IdentityState::Missing => fs::remove_file(&identity_path).expect("remove identity"),
                IdentityState::Symlink => {
                    fs::remove_file(&identity_path).expect("remove identity");
                    symlink("/not/a/real/identity", &identity_path).expect("identity symlink");
                }
                IdentityState::Directory => {
                    fs::remove_file(&identity_path).expect("remove identity");
                    fs::create_dir(&identity_path).expect("identity directory");
                }
                IdentityState::WrongMode => {
                    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o640))
                        .expect("identity mode");
                }
                IdentityState::InvalidToml => {
                    fs::write(&identity_path, "not = [valid").expect("invalid identity");
                    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
                        .expect("identity mode");
                }
                IdentityState::MissingProbeId => {
                    fs::write(
                        &identity_path,
                        "hub_url = \"https://hub.example\"\nprobe_private_key_pem = \"test-private-key\"\n",
                    )
                    .expect("identity without Probe ID");
                    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
                        .expect("identity mode");
                }
                IdentityState::InvalidProbeId => {
                    let identity = fs::read_to_string(&identity_path).expect("identity");
                    fs::write(&identity_path, identity.replace("probe_known_01", "probe_"))
                        .expect("invalid Probe ID");
                }
                IdentityState::HubMismatch => {
                    let identity = fs::read_to_string(&identity_path).expect("identity");
                    fs::write(
                        &identity_path,
                        identity.replace("https://hub.example", "https://other-hub.example"),
                    )
                    .expect("Hub mismatch");
                }
            }

            let metadata_path = rooted_path(&input, &input.install_metadata_path);
            let metadata_before = path_fingerprint(&metadata_path);
            let identity_before = path_fingerprint(&identity_path);
            let error = preflight_fresh_installation(&input)
                .expect_err("untrusted Identity rejects fresh installation");
            assert!(matches!(
                &error,
                ProbeLocalLifecycleError::InvalidExistingInstallation
            ));
            assert_eq!(
                error.installation_rejection().map(|(code, _)| code),
                Some("probe_installation_metadata_invalid")
            );
            assert_eq!(path_fingerprint(&metadata_path), metadata_before);
            assert_eq!(path_fingerprint(&identity_path), identity_before);
        }
    }

    #[cfg(unix)]
    #[test]
    fn fresh_installation_preflight_rejects_a_dangling_symlink_at_any_managed_target() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let install_path = temporary.path().join("usr/local/bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("parent")).expect("parent");
        symlink("/not/a/real/probe", &install_path).expect("dangling symlink");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());

        assert!(matches!(
            preflight_fresh_installation(&input),
            Err(ProbeLocalLifecycleError::InvalidExistingInstallation)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn metadata_absent_preflight_rejects_every_managed_residue_without_mutating_it() {
        for (managed_path, is_directory) in [
            ("var/lib/enoki-probe/identity/probe-bootstrap.toml", false),
            ("usr/local/bin/enoki-probe", false),
            ("etc/sudoers.d/enoki-probe-operations", false),
            ("etc/sudoers.d/enoki-probe-collector-helpers", false),
            ("etc/systemd/system/enoki-probe.service", false),
            ("var/lib/enoki-probe", true),
            ("etc/sudoers.d/enoki-probe-upgrader", false),
        ] {
            let temporary = tempfile::tempdir().expect("tempdir");
            let candidate = temporary.path().join("candidate");
            fs::write(&candidate, "candidate").expect("candidate");
            let residue = temporary.path().join(managed_path);
            fs::create_dir_all(residue.parent().expect("residue parent")).expect("residue parent");
            if is_directory {
                fs::create_dir(&residue).expect("residue directory");
            } else {
                fs::write(&residue, b"pre-existing Enoki residue").expect("residue");
            }
            let mut input = input();
            input.candidate_binary = candidate;
            input.test_root = Some(temporary.path().to_path_buf());

            let before = path_fingerprint(&residue);
            let error = preflight_fresh_installation(&input)
                .expect_err("residue rejects fresh installation");
            assert!(matches!(
                &error,
                ProbeLocalLifecycleError::InvalidExistingInstallation
            ));
            assert_eq!(
                error.installation_rejection().map(|(code, _)| code),
                Some("probe_installation_metadata_invalid")
            );
            assert_eq!(path_fingerprint(&residue), before, "{managed_path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn metadata_absent_preflight_classifies_loaded_systemd_as_invalid_with_test_commands() {
        let _path_lock = PATH_MUTATION_LOCK.lock().expect("PATH lock");
        let temporary = tempfile::tempdir().expect("tempdir");
        let fake_commands = temporary.path().join("fake-commands");
        fs::create_dir(&fake_commands).expect("fake command directory");
        write_test_command(
            &fake_commands.join("systemctl"),
            "#!/bin/sh\ncase \"${1:-}\" in\n  is-enabled) printf '%s\\n' disabled; exit 1 ;;\n  show) printf '%s\\n' loaded; exit 0 ;;\nesac\nexit 1\n",
        );
        for command in ["getent", "id"] {
            write_test_command(&fake_commands.join(command), "#!/bin/sh\nexit 1\n");
        }
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());

        let old_path = env::var_os("PATH");
        let test_path = format!(
            "{}:{}",
            fake_commands.display(),
            old_path
                .as_deref()
                .unwrap_or_else(|| std::ffi::OsStr::new(""))
                .to_string_lossy(),
        );
        // SAFETY: this test serializes its process-wide PATH mutation and restores
        // the original value before releasing the lock.
        unsafe { env::set_var("PATH", &test_path) };
        let result = preflight_fresh_installation(&input);
        // SAFETY: restores the process-wide PATH changed for this serialized test.
        unsafe {
            if let Some(old_path) = old_path {
                env::set_var("PATH", old_path);
            } else {
                env::remove_var("PATH");
            }
        }

        assert!(matches!(
            result,
            Err(ProbeLocalLifecycleError::InvalidExistingInstallation)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn metadata_absent_preflight_classifies_service_account_or_group_residue_as_invalid_with_test_commands()
     {
        let _path_lock = PATH_MUTATION_LOCK.lock().expect("PATH lock");

        for (getent_status, id_status) in [(0, 1), (1, 0)] {
            let temporary = tempfile::tempdir().expect("tempdir");
            let fake_commands = temporary.path().join("fake-commands");
            fs::create_dir(&fake_commands).expect("fake command directory");
            write_test_command(
                &fake_commands.join("getent"),
                &format!("#!/bin/sh\nexit {getent_status}\n"),
            );
            write_test_command(
                &fake_commands.join("id"),
                &format!("#!/bin/sh\nexit {id_status}\n"),
            );
            write_test_command(&fake_commands.join("systemctl"), "#!/bin/sh\nexit 99\n");
            let candidate = temporary.path().join("candidate");
            fs::write(&candidate, "candidate").expect("candidate");
            let mut input = input();
            input.candidate_binary = candidate;
            input.test_root = Some(temporary.path().to_path_buf());

            let old_path = env::var_os("PATH");
            let test_path = format!(
                "{}:{}",
                fake_commands.display(),
                old_path
                    .as_deref()
                    .unwrap_or_else(|| std::ffi::OsStr::new(""))
                    .to_string_lossy(),
            );
            // SAFETY: this test serializes its process-wide PATH mutation and restores
            // the original value before releasing the lock.
            unsafe { env::set_var("PATH", &test_path) };
            let result = preflight_fresh_installation(&input);
            // SAFETY: restores the process-wide PATH changed for this serialized test.
            unsafe {
                if let Some(old_path) = old_path {
                    env::set_var("PATH", old_path);
                } else {
                    env::remove_var("PATH");
                }
            }

            assert!(matches!(
                result,
                Err(ProbeLocalLifecycleError::InvalidExistingInstallation)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn fresh_installation_preflight_rejects_a_symlink_in_a_managed_parent() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("tempdir");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, "candidate").expect("candidate");
        let outside = temporary.path().join("outside");
        fs::create_dir(&outside).expect("outside");
        symlink(&outside, temporary.path().join("etc")).expect("parent symlink");
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());

        assert!(matches!(
            preflight_fresh_installation(&input),
            Err(ProbeLocalLifecycleError::Io(_))
        ));
    }

    #[test]
    fn failed_readiness_stops_and_disables_the_service_without_removing_installation_evidence() {
        let _path_lock = PATH_MUTATION_LOCK.lock().expect("PATH lock");
        let temporary = tempfile::tempdir().expect("tempdir");
        let fake_commands = temporary.path().join("fake-commands");
        fs::create_dir_all(&fake_commands).expect("fake command directory");
        let command_log = temporary.path().join("commands.log");
        write_test_command(
            &fake_commands.join("systemctl"),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"${{1:-}}\" in\n  is-active) exit 1 ;;\n  is-enabled) printf '%s\\n' disabled; exit 1 ;;\n  show) printf '%s\\n' not-found; exit 0 ;;\nesac\nexit 0\n",
                command_log.display()
            ),
        );
        for command in ["getent", "id"] {
            write_test_command(&fake_commands.join(command), "#!/bin/sh\nexit 1\n");
        }
        for command in ["groupadd", "useradd", "chown"] {
            write_test_command(&fake_commands.join(command), "#!/bin/sh\nexit 0\n");
        }

        let candidate = temporary.path().join("candidate");
        write_test_command(
            &candidate,
            "#!/bin/sh\nif [ \"${1:-}\" = \"internal-render-collector-helper-sudoers\" ]; then\n  printf '# helper sudoers\\n'\n  exit 0\nfi\nexit 64\n",
        );
        let mut input = input();
        input.candidate_binary = candidate;
        input.readiness_timeout = Duration::from_millis(1);
        input.test_root = Some(temporary.path().to_path_buf());

        let old_path = env::var_os("PATH");
        let test_path = format!(
            "{}:{}",
            fake_commands.display(),
            old_path
                .as_deref()
                .unwrap_or_else(|| std::ffi::OsStr::new(""))
                .to_string_lossy(),
        );
        // SAFETY: this test serializes its process-wide PATH mutation and restores
        // the original value before releasing the lock.
        unsafe { env::set_var("PATH", &test_path) };

        let result = run_with_inspected_target(&input, ProbeInstallationTarget::NewHost);

        // SAFETY: restores the process-wide PATH changed for this serialized test.
        unsafe {
            if let Some(old_path) = old_path {
                env::set_var("PATH", old_path);
            } else {
                env::remove_var("PATH");
            }
        }

        assert!(matches!(
            result,
            Err(ProbeLocalLifecycleError::ReadinessTimeout)
        ));
        for path in [
            "usr/local/bin/enoki-probe",
            "var/lib/enoki-probe/identity/probe-bootstrap.toml",
            "etc/enoki/probe-install.toml",
            "var/lib/enoki-probe",
        ] {
            assert!(temporary.path().join(path).exists(), "{path} remains");
        }
        let command_log = fs::read_to_string(command_log).expect("command log");
        assert!(command_log.contains("stop enoki-probe.service"));
        assert!(command_log.contains("disable enoki-probe.service"));
    }

    #[test]
    fn installation_failure_before_enable_never_stops_or_disables_a_service() {
        let _path_lock = PATH_MUTATION_LOCK.lock().expect("PATH lock");
        let temporary = tempfile::tempdir().expect("tempdir");
        let fake_commands = temporary.path().join("fake-commands");
        fs::create_dir_all(&fake_commands).expect("fake command directory");
        let command_log = temporary.path().join("commands.log");
        write_test_command(
            &fake_commands.join("systemctl"),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"${{1:-}}\" in\n  is-enabled) printf '%s\\n' disabled; exit 1 ;;\n  show) printf '%s\\n' not-found; exit 0 ;;\n  enable) exit 1 ;;\nesac\nexit 0\n",
                command_log.display()
            ),
        );
        for command in ["getent", "id"] {
            write_test_command(&fake_commands.join(command), "#!/bin/sh\nexit 1\n");
        }
        for command in ["groupadd", "useradd", "chown"] {
            write_test_command(&fake_commands.join(command), "#!/bin/sh\nexit 0\n");
        }

        let candidate = temporary.path().join("candidate");
        write_test_command(
            &candidate,
            "#!/bin/sh\nif [ \"${1:-}\" = \"internal-render-collector-helper-sudoers\" ]; then\n  printf '# helper sudoers\\n'\n  exit 0\nfi\nexit 64\n",
        );
        let mut input = input();
        input.candidate_binary = candidate;
        input.test_root = Some(temporary.path().to_path_buf());

        let old_path = env::var_os("PATH");
        let test_path = format!(
            "{}:{}",
            fake_commands.display(),
            old_path
                .as_deref()
                .unwrap_or_else(|| std::ffi::OsStr::new(""))
                .to_string_lossy(),
        );
        // SAFETY: this test serializes its process-wide PATH mutation and restores
        // the original value before releasing the lock.
        unsafe { env::set_var("PATH", &test_path) };

        let result = run_with_inspected_target(&input, ProbeInstallationTarget::NewHost);

        // SAFETY: restores the process-wide PATH changed for this serialized test.
        unsafe {
            if let Some(old_path) = old_path {
                env::set_var("PATH", old_path);
            } else {
                env::remove_var("PATH");
            }
        }

        assert!(matches!(
            result,
            Err(ProbeLocalLifecycleError::ServiceCommand(_))
        ));
        let command_log = fs::read_to_string(command_log).expect("command log");
        assert!(command_log.contains("enable enoki-probe.service"));
        assert!(!command_log.contains("stop enoki-probe.service"));
        assert!(!command_log.contains("disable enoki-probe.service"));
    }

    #[cfg(unix)]
    fn write_complete_probe_identity(
        input: &ProbeLocalInstallInput,
        probe_id: &str,
        hub_url: &str,
    ) {
        use std::os::unix::fs::PermissionsExt;

        let identity_path = rooted_path(input, &input.identity_path);
        fs::create_dir_all(identity_path.parent().expect("identity parent"))
            .expect("identity parent");
        fs::write(
            &identity_path,
            [
                format!("hub_url = {}", toml_string(hub_url)),
                format!("probe_id = {}", toml_string(probe_id)),
                "probe_private_key_pem = \"test-private-key\"".to_string(),
                format!(
                    "state_dir = {}",
                    toml_string(&input.state_dir.display().to_string())
                ),
                format!(
                    "operation_status_path = {}",
                    toml_string(
                        &input
                            .state_dir
                            .join("probe-operation-status.toml")
                            .display()
                            .to_string(),
                    )
                ),
                format!(
                    "install_path = {}",
                    toml_string(&input.install_path.display().to_string())
                ),
                format!("service_name = {}", toml_string(&input.service_name)),
                format!(
                    "probe_asset_public_key_sha256 = {}",
                    toml_string(&input.trusted_asset_public_key_sha256)
                ),
                String::new(),
            ]
            .join("\n"),
        )
        .expect("identity");
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
            .expect("identity mode");
    }

    #[cfg(unix)]
    fn path_fingerprint(path: &Path) -> Option<PathFingerprint> {
        let metadata = fs::symlink_metadata(path).ok()?;
        Some(PathFingerprint {
            gid: metadata.gid(),
            link_target: fs::read_link(path).ok(),
            mode: metadata.mode(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            contents: fs::read(path).ok(),
            uid: metadata.uid(),
        })
    }

    #[cfg(unix)]
    fn write_test_command(path: &Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, contents).expect("write test command");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("make test command executable");
    }

    fn with_test_path<T>(fake_commands: &Path, operation: impl FnOnce() -> T) -> T {
        let old_path = env::var_os("PATH");
        let test_path = format!(
            "{}:{}",
            fake_commands.display(),
            old_path
                .as_deref()
                .unwrap_or_else(|| std::ffi::OsStr::new(""))
                .to_string_lossy(),
        );
        // SAFETY: callers hold PATH_MUTATION_LOCK and this restores the value.
        unsafe { env::set_var("PATH", &test_path) };
        let result = operation();
        // SAFETY: restores the process-wide PATH changed for this serialized test.
        unsafe {
            if let Some(old_path) = old_path {
                env::set_var("PATH", old_path);
            } else {
                env::remove_var("PATH");
            }
        }
        result
    }

    struct InspectionTransport {
        target: ProbeInstallationTarget,
    }

    struct RejectionRetryTransport {
        attempts: usize,
        bodies: Vec<Vec<u8>>,
    }

    impl RegistrationTransport for RejectionRetryTransport {
        fn post_protobuf(
            &mut self,
            _url: &str,
            body: Vec<u8>,
        ) -> Result<Vec<u8>, crate::registration::RegistrationError> {
            self.bodies.push(body);
            self.attempts += 1;
            if self.attempts == 1 {
                return Err(crate::registration::RegistrationError::Attempt(
                    crate::transport::HttpAttemptError::Network(
                        "temporary Hub connection failure".to_string(),
                    ),
                ));
            }
            Ok(Vec::new())
        }
    }

    struct AlwaysTransientRejectionTransport {
        attempts: usize,
    }

    impl RegistrationTransport for AlwaysTransientRejectionTransport {
        fn post_protobuf(
            &mut self,
            _url: &str,
            _body: Vec<u8>,
        ) -> Result<Vec<u8>, crate::registration::RegistrationError> {
            self.attempts += 1;
            Err(crate::registration::RegistrationError::Attempt(
                crate::transport::HttpAttemptError::Network(
                    "temporary Hub connection failure".to_string(),
                ),
            ))
        }
    }

    struct TestInstallationRejectionClock {
        now: std::rc::Rc<std::cell::Cell<Duration>>,
    }

    impl InstallationRejectionClock for TestInstallationRejectionClock {
        fn now(&self) -> Duration {
            self.now.get()
        }
    }

    struct TestInstallationRejectionSleeper {
        now: std::rc::Rc<std::cell::Cell<Duration>>,
        sleeps: Vec<Duration>,
    }

    impl InstallationRejectionSleeper for TestInstallationRejectionSleeper {
        fn sleep(&mut self, duration: Duration) {
            self.sleeps.push(duration);
            self.now.set(self.now.get().saturating_add(duration));
        }
    }

    struct FailingInspectionTransport;

    impl RegistrationTransport for FailingInspectionTransport {
        fn post_protobuf(
            &mut self,
            _url: &str,
            _body: Vec<u8>,
        ) -> Result<Vec<u8>, crate::registration::RegistrationError> {
            Err(crate::registration::RegistrationError::Attempt(
                crate::transport::HttpAttemptError::Network("network unavailable".to_string()),
            ))
        }
    }

    impl RegistrationTransport for InspectionTransport {
        fn post_protobuf(
            &mut self,
            _url: &str,
            _body: Vec<u8>,
        ) -> Result<Vec<u8>, crate::registration::RegistrationError> {
            let target_kind = match &self.target {
                ProbeInstallationTarget::NewHost => {
                    crate::protocol::enoki::v1::ProbeEnrollmentTargetKind::NewHost
                }
                ProbeInstallationTarget::ExistingHost => {
                    crate::protocol::enoki::v1::ProbeEnrollmentTargetKind::ExistingHost
                }
                ProbeInstallationTarget::ManualReinstall(_) => {
                    crate::protocol::enoki::v1::ProbeEnrollmentTargetKind::ManualReinstall
                }
            };
            Ok(crate::protocol::enoki::v1::ProbeRegistrationResponse {
                enrollment_id: String::new(),
                host_id: String::new(),
                initial_configuration: None,
                installation_inspection: Some(
                    crate::protocol::enoki::v1::ProbeInstallationInspectionResponse {
                        target_kind: target_kind as i32,
                        ..Default::default()
                    },
                ),
                probe_id: String::new(),
                probe_secret: String::new(),
                server_time_ms: 0,
            }
            .encode_to_vec())
        }
    }

    fn run_with_inspected_target(
        input: &ProbeLocalInstallInput,
        target: ProbeInstallationTarget,
    ) -> Result<(), ProbeLocalLifecycleError> {
        let mut transport = InspectionTransport { target };
        run_probe_local_install_with_registration_transport(input, &mut transport)
    }
}
