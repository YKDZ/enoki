mod repair;
mod replacement;
mod uninstall;
use uninstall::resume_lifecycle_companion_at;

use std::{
    error::Error,
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
};

use enoki_probe_bootstrap::lifecycle::{LifecycleRequest, LifecycleResponse, LifecycleTransition};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    hub_url,
    probe_auth::{ProbeRequestAuth, signed_probe_request_headers},
    protocol::enoki::v1::ProbeConfigurationRequest,
};

const OBSERVATION_RUNTIME_BINARY_PATH: &str = "/usr/local/bin/enoki-observation-runtime";
const PRODUCTION_PROBE_BINARY_PATH: &str = "/usr/local/bin/enoki-probe";
const CPU_PROVIDER_BINARY_PATH: &str = "/usr/local/bin/enoki-cpu-resource-provider";
const DISK_HEALTH_PROVIDER_BINARY_PATH: &str = "/usr/local/bin/enoki-disk-health-resource-provider";
const LIFECYCLE_COMPANION_BINARY_PATH: &str = "/usr/local/bin/enoki-probe-lifecycle-companion";
const MAX_INSTALLED_PROBE_BYTES: u64 = 256 * 1024 * 1024;
const OBSERVATION_RUNTIME_SERVICE_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-observation-runtime.service";
const OBSERVATION_RUNTIME_SOCKET_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-observation-runtime.socket";
const OBSERVATION_RUNTIME_FAILURE_RECORDER_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-observation-runtime-failure.service";
const CPU_PROVIDER_SERVICE_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-cpu-resource-provider@.service";
const CPU_PROVIDER_SOCKET_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-cpu-resource-provider.socket";
const DISK_HEALTH_PROVIDER_SERVICE_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-disk-health-resource-provider@.service";
const DISK_HEALTH_PROVIDER_SOCKET_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-disk-health-resource-provider.socket";
const LIFECYCLE_COMPANION_SERVICE_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-probe-lifecycle-companion@.service";
const LIFECYCLE_COMPANION_SOCKET_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-probe-lifecycle-companion.socket";
const LIFECYCLE_UPGRADE_SERVICE_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-probe-lifecycle-upgrade@.service";
const LIFECYCLE_UPGRADE_SOCKET_UNIT_PATH: &str =
    "/etc/systemd/system/enoki-probe-lifecycle-upgrade.socket";
const PROBE_IPC_GROUP: &str = "enoki-probe-ipc";
const OBSERVATION_SERVICES_SCHEMA_THREE: [&str; 4] = [
    "enoki-observation-runtime.service",
    "enoki-observation-runtime.socket",
    "enoki-cpu-resource-provider.socket",
    "enoki-disk-health-resource-provider.socket",
];
const OBSERVATION_SERVICES_SCHEMA_FOUR: [&str; 7] = [
    "enoki-observation-runtime.service",
    "enoki-observation-runtime.socket",
    "enoki-cpu-resource-provider.socket",
    "enoki-disk-health-resource-provider.socket",
    "enoki-cpu-resource-provider@*.service",
    "enoki-disk-health-resource-provider@*.service",
    "enoki-probe-lifecycle-companion.socket",
];
const OBSERVATION_SERVICES_SCHEMA_FIVE: [&str; 9] = [
    "enoki-observation-runtime.service",
    "enoki-observation-runtime.socket",
    "enoki-cpu-resource-provider.socket",
    "enoki-disk-health-resource-provider.socket",
    "enoki-cpu-resource-provider@*.service",
    "enoki-disk-health-resource-provider@*.service",
    "enoki-probe-lifecycle-companion.socket",
    "enoki-probe-lifecycle-upgrade.socket",
    "enoki-probe-lifecycle-upgrade@*.service",
];

fn observation_services(schema_version: u32) -> &'static [&'static str] {
    if schema_version == 5 {
        &OBSERVATION_SERVICES_SCHEMA_FIVE
    } else if schema_version == 4 {
        &OBSERVATION_SERVICES_SCHEMA_FOUR
    } else {
        &OBSERVATION_SERVICES_SCHEMA_THREE
    }
}

fn is_lifecycle_companion_service(service: &str) -> bool {
    matches!(
        service,
        "enoki-probe-lifecycle-companion.socket" | "enoki-probe-lifecycle-upgrade.socket"
    )
}

fn is_lifecycle_companion_path(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            "enoki-probe-lifecycle-companion"
                | "enoki-probe-lifecycle-companion@.service"
                | "enoki-probe-lifecycle-companion.socket"
                | "enoki-probe-lifecycle-upgrade@.service"
                | "enoki-probe-lifecycle-upgrade.socket"
        )
    )
}
const OBSERVATION_IPC_GROUP: &str = "enoki-observation-ipc";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUninstallerRunInput {
    pub bootstrap_config_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeRepairResult {
    pub probe_id: String,
    pub repaired_version: String,
}

#[derive(Debug)]
pub enum ProbeRepairRunError {
    CandidateNotInstalled,
    DowngradeRejected,
    FailureMarkerInvalid,
    FailureMarkerMissing,
    FailureMarkerNotPostReplacement,
    HubTargetMismatch,
    IdentityHubMismatch,
    IdentityIncomplete,
    IdentityRejected(String),
    InstalledVersionInvalid,
    Installation(ProbeUpgraderRunError),
    RootRequired,
    ServiceReconstruction { code: &'static str, message: String },
}

impl ProbeRepairRunError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::CandidateNotInstalled => "probe_repair_candidate_not_installed",
            Self::DowngradeRejected => "probe_repair_downgrade_rejected",
            Self::FailureMarkerInvalid => "probe_repair_failure_marker_invalid",
            Self::FailureMarkerMissing => "probe_repair_failure_marker_missing",
            Self::FailureMarkerNotPostReplacement => {
                "probe_repair_failure_marker_not_post_replacement"
            }
            Self::HubTargetMismatch => "probe_repair_hub_target_mismatch",
            Self::IdentityHubMismatch => "probe_repair_identity_hub_mismatch",
            Self::IdentityIncomplete => "probe_repair_identity_incomplete",
            Self::IdentityRejected(_) => "probe_repair_identity_rejected",
            Self::InstalledVersionInvalid => "probe_repair_installed_version_invalid",
            Self::RootRequired => "probe_repair_root_required",
            Self::ServiceReconstruction { code, .. } => code,
            Self::Installation(error) => match error {
                ProbeUpgraderRunError::AssetMissing => "probe_repair_asset_missing",
                ProbeUpgraderRunError::ArchitectureMissing => "probe_repair_architecture_missing",
                ProbeUpgraderRunError::ChecksumFailure => "probe_repair_checksum_failure",
                ProbeUpgraderRunError::InvalidManifest(_) => "probe_repair_manifest_invalid",
                ProbeUpgraderRunError::SignatureFailure => "probe_repair_signature_failure",
                ProbeUpgraderRunError::SigningKeyUntrusted => "probe_repair_signing_key_untrusted",
                ProbeUpgraderRunError::UnsafeArchive(_) => "probe_repair_unsafe_archive",
                ProbeUpgraderRunError::UnsupportedArchitecture(_) => {
                    "probe_repair_unsupported_architecture"
                }
                ProbeUpgraderRunError::InvalidInstallMetadata("unsupported schema version") => {
                    "probe_repair_metadata_unsupported"
                }
                ProbeUpgraderRunError::InvalidInstallMetadata(_) => "probe_repair_metadata_invalid",
                ProbeUpgraderRunError::Io(error)
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    "probe_repair_installation_missing"
                }
                ProbeUpgraderRunError::InvalidConfig(_) => "probe_repair_installation_invalid",
                ProbeUpgraderRunError::ManualProbeReinstallRequired => {
                    "probe_manual_reinstall_required"
                }
                _ => "probe_repair_failed",
            },
        }
    }
}

impl fmt::Display for ProbeRepairRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CandidateNotInstalled => write!(
                formatter,
                "the installed Probe version does not match the failed Upgrade target"
            ),
            Self::DowngradeRejected => write!(
                formatter,
                "the bound Hub supplies an older Probe; use Hub Restore rather than Probe Repair"
            ),
            Self::FailureMarkerInvalid => {
                write!(
                    formatter,
                    "the local failed Probe Upgrade marker is invalid"
                )
            }
            Self::FailureMarkerMissing => {
                write!(formatter, "no local failed Probe Upgrade marker exists")
            }
            Self::FailureMarkerNotPostReplacement => write!(
                formatter,
                "the local Probe Upgrade did not fail after binary replacement"
            ),
            Self::HubTargetMismatch => write!(
                formatter,
                "the bound Hub Probe target does not match the failed Upgrade target"
            ),
            Self::IdentityHubMismatch => {
                write!(formatter, "the Probe Identity is bound to a different Hub")
            }
            Self::IdentityIncomplete => write!(
                formatter,
                "the recorded Probe Identity is absent or incomplete"
            ),
            Self::IdentityRejected(message) => {
                write!(
                    formatter,
                    "the bound Hub rejected the Probe Identity: {message}"
                )
            }
            Self::InstalledVersionInvalid => {
                write!(formatter, "the installed Probe version cannot be verified")
            }
            Self::Installation(error) => write!(formatter, "{error}"),
            Self::RootRequired => write!(formatter, "Probe Repair must run as root"),
            Self::ServiceReconstruction { message, .. } => {
                write!(formatter, "Probe service reconstruction failed: {message}")
            }
        }
    }
}

impl Error for ProbeRepairRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Installation(error) => Some(error),
            Self::CandidateNotInstalled
            | Self::DowngradeRejected
            | Self::FailureMarkerInvalid
            | Self::FailureMarkerMissing
            | Self::FailureMarkerNotPostReplacement
            | Self::HubTargetMismatch
            | Self::IdentityHubMismatch
            | Self::IdentityIncomplete
            | Self::IdentityRejected(_)
            | Self::InstalledVersionInvalid
            | Self::RootRequired
            | Self::ServiceReconstruction { .. } => None,
        }
    }
}

impl From<ProbeUpgraderRunError> for ProbeRepairRunError {
    fn from(error: ProbeUpgraderRunError) -> Self {
        Self::Installation(error)
    }
}

const PRODUCTION_INSTALL_METADATA_PATH: &str = "/etc/enoki/probe-install.toml";
const PRODUCTION_LEGACY_UPGRADER_SUDOERS_PATH: &str = "/etc/sudoers.d/enoki-probe-upgrader";
const PRODUCTION_OPERATION_SUDOERS_PATH: &str = "/etc/sudoers.d/enoki-probe-operations";
const PRODUCTION_COLLECTOR_HELPER_SUDOERS_PATH: &str =
    "/etc/sudoers.d/enoki-probe-collector-helpers";
const PRODUCTION_BOOTSTRAP_ACQUIRER_PATH: &str = "/usr/local/bin/enoki-probe-bootstrap-acquire";
const PRODUCTION_BOOTSTRAP_ACTIVATOR_PATH: &str = "/usr/local/bin/enoki-probe-bootstrap-activate";
const PRODUCTION_REPLACEMENT_COMMIT_PATH: &str =
    "/var/lib/enoki-probe-bootstrap/replacement-migration.json";
const PRODUCTION_REPLACEMENT_REGISTRATION_ATTEMPT_PATH: &str =
    "/var/lib/enoki-probe-registration/attempt.json";
const PRODUCTION_BOOTSTRAP_STATE_DIR: &str = "/var/lib/enoki-probe-bootstrap";
const PRODUCTION_INSTALL_STATE_DIR: &str = "/var/lib/enoki-probe";
#[derive(Debug)]
pub enum ProbeUpgraderRunError {
    ArchitectureMissing,
    AssetMissing,
    ChecksumFailure,
    InvalidConfig(&'static str),
    InvalidInstallMetadata(&'static str),
    InvalidManifest(&'static str),
    InvalidMetadata(&'static str),
    InvalidSigningKey(String),
    IdentityValidation(String),
    Io(std::io::Error),
    LocalUninstallRootRequired,
    MissingToken,
    ManualProbeReinstallRequired,
    PostReplacementRestartFailure(String),
    PostReplacementStatusWriteFailure(String),
    RestartFailure(String),
    SignatureFailure,
    SigningKeyUntrusted,
    DowngradeRejected,
    TargetMismatch,
    TokenValidation(String),
    UninstallCleanupFailure {
        action: &'static str,
        code: &'static str,
        message: String,
    },
    UninstallStatusReportFailure(String),
    UnsafeArchive(&'static str),
    UnsupportedArchitecture(String),
}

impl ProbeUpgraderRunError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::LocalUninstallRootRequired => "probe_uninstall_root_required",
            Self::InvalidInstallMetadata(_) => "probe_uninstall_metadata_invalid",
            Self::UninstallCleanupFailure { code, .. } => code,
            Self::ManualProbeReinstallRequired => "probe_manual_reinstall_required",
            _ => "probe_uninstall_failed",
        }
    }
}

impl fmt::Display for ProbeUpgraderRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchitectureMissing => write!(
                formatter,
                "Probe Asset Set does not contain an archive for this Host architecture"
            ),
            Self::AssetMissing => write!(formatter, "Probe Asset Set archive is missing"),
            Self::ChecksumFailure => write!(formatter, "Probe archive sha256 verification failed"),
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid Probe bootstrap config: {message}")
            }
            Self::InvalidInstallMetadata(message) => {
                write!(formatter, "invalid Probe install metadata: {message}")
            }
            Self::InvalidManifest(message) => {
                write!(formatter, "invalid Probe asset manifest: {message}")
            }
            Self::InvalidMetadata(message) => {
                write!(
                    formatter,
                    "invalid Probe Upgrader operation metadata: {message}"
                )
            }
            Self::InvalidSigningKey(message) => {
                write!(formatter, "invalid Probe signing key: {message}")
            }
            Self::IdentityValidation(message) => {
                write!(formatter, "Probe Identity validation failed: {message}")
            }
            Self::Io(_) => write!(formatter, "failed to read Probe bootstrap config"),
            Self::LocalUninstallRootRequired => {
                write!(formatter, "Local Probe Uninstall must run as root")
            }
            Self::MissingToken => write!(formatter, "missing Probe Operation Token on stdin"),
            Self::ManualProbeReinstallRequired => write!(
                formatter,
                "this Probe uses the signed Probe installation package; manually reinstall the Probe instead of using the legacy updater"
            ),
            Self::PostReplacementRestartFailure(message) => write!(
                formatter,
                "Probe binary was replaced, but restarting the Probe service failed: {message}"
            ),
            Self::PostReplacementStatusWriteFailure(message) => write!(
                formatter,
                "Probe binary was replaced, but writing Probe Upgrade status failed: {message}"
            ),
            Self::RestartFailure(message) => {
                write!(formatter, "failed to restart Probe service: {message}")
            }
            Self::SignatureFailure => write!(
                formatter,
                "Probe asset manifest signature verification failed"
            ),
            Self::SigningKeyUntrusted => write!(
                formatter,
                "Probe asset signing key fingerprint verification failed"
            ),
            Self::DowngradeRejected => write!(
                formatter,
                "Probe Upgrade target version is not newer than the installed Probe version"
            ),
            Self::TargetMismatch => write!(
                formatter,
                "Probe asset manifest target version does not match Probe Upgrade Request"
            ),
            Self::TokenValidation(message) => {
                write!(
                    formatter,
                    "Probe Operation Token validation failed: {message}"
                )
            }
            Self::UninstallCleanupFailure {
                action, message, ..
            } => write!(
                formatter,
                "Probe uninstall cleanup failed while {action}: {message}"
            ),
            Self::UninstallStatusReportFailure(message) => {
                write!(formatter, "Probe uninstall status report failed: {message}")
            }
            Self::UnsafeArchive(message) => write!(formatter, "unsafe Probe archive: {message}"),
            Self::UnsupportedArchitecture(architecture) => {
                write!(formatter, "unsupported Host architecture: {architecture}")
            }
        }
    }
}

impl Error for ProbeUpgraderRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidConfig(_)
            | Self::InvalidInstallMetadata(_)
            | Self::ArchitectureMissing
            | Self::AssetMissing
            | Self::ChecksumFailure
            | Self::InvalidManifest(_)
            | Self::InvalidMetadata(_)
            | Self::InvalidSigningKey(_)
            | Self::IdentityValidation(_)
            | Self::LocalUninstallRootRequired
            | Self::MissingToken
            | Self::ManualProbeReinstallRequired
            | Self::PostReplacementRestartFailure(_)
            | Self::PostReplacementStatusWriteFailure(_)
            | Self::RestartFailure(_)
            | Self::SignatureFailure
            | Self::SigningKeyUntrusted
            | Self::DowngradeRejected
            | Self::TargetMismatch
            | Self::TokenValidation(_)
            | Self::UninstallCleanupFailure { .. }
            | Self::UninstallStatusReportFailure(_)
            | Self::UnsafeArchive(_)
            | Self::UnsupportedArchitecture(_) => None,
        }
    }
}

impl From<std::io::Error> for ProbeUpgraderRunError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub trait ProbeUpgraderValidationTransport {
    fn get_asset(&mut self, url: &str) -> Result<Vec<u8>, ProbeUpgraderRunError>;

    fn post_token_validation(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError>;

    fn post_operation_status(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError>;

    fn validate_probe_identity(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
    ) -> Result<(), ProbeUpgraderRunError>;
}

pub struct HttpProbeUpgraderValidationTransport;

impl ProbeUpgraderValidationTransport for HttpProbeUpgraderValidationTransport {
    fn get_asset(&mut self, url: &str) -> Result<Vec<u8>, ProbeUpgraderRunError> {
        let response = ureq::get(url)
            .set("accept", "application/octet-stream")
            .call()
            .map_err(|_error| ProbeUpgraderRunError::AssetMissing)?;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut bytes)
            .map_err(ProbeUpgraderRunError::Io)?;

        Ok(bytes)
    }

    fn post_token_validation(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        let mut request = ureq::post(url)
            .set("accept", "application/json")
            .set("content-type", "application/json");
        for (name, value) in signed_probe_request_headers("POST", url, auth, body.as_bytes())
            .map_err(ProbeUpgraderRunError::InvalidSigningKey)?
        {
            request = request.set(name, &value);
        }
        request
            .send_string(body)
            .map_err(|error| ProbeUpgraderRunError::TokenValidation(error.to_string()))?;

        Ok(())
    }

    fn post_operation_status(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        let mut request = ureq::post(url)
            .set("accept", "application/json")
            .set("content-type", "application/json");
        for (name, value) in signed_probe_request_headers("POST", url, auth, body.as_bytes())
            .map_err(ProbeUpgraderRunError::InvalidSigningKey)?
        {
            request = request.set(name, &value);
        }
        request.send_string(body).map_err(|error| {
            ProbeUpgraderRunError::UninstallStatusReportFailure(error.to_string())
        })?;

        Ok(())
    }

    fn validate_probe_identity(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
    ) -> Result<(), ProbeUpgraderRunError> {
        let body = ProbeConfigurationRequest {
            current_version: String::new(),
            probe_id: auth.probe_id.to_string(),
        }
        .encode_to_vec();
        let mut request = ureq::post(url)
            .set("accept", "application/x-protobuf")
            .set("content-type", "application/x-protobuf");
        for (name, value) in signed_probe_request_headers("POST", url, auth, &body)
            .map_err(ProbeUpgraderRunError::InvalidSigningKey)?
        {
            request = request.set(name, &value);
        }
        request
            .send_bytes(&body)
            .map_err(|error| ProbeUpgraderRunError::IdentityValidation(error.to_string()))?;
        Ok(())
    }
}

pub trait ProbeUpgraderSystemdRunner {
    fn ensure_service_group(&mut self, _service_group: &str) -> Result<(), ProbeUpgraderRunError> {
        Ok(())
    }

    fn ensure_service_account(
        &mut self,
        _service_user: &str,
        _service_group: &str,
        _state_dir: &Path,
        _identity_path: &Path,
    ) -> Result<(), ProbeUpgraderRunError> {
        Ok(())
    }

    fn enable_service(&mut self, _service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        Ok(())
    }

    fn restart_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError>;

    fn stop_service(&mut self, _service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        Ok(())
    }

    fn disable_service(&mut self, _service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        Ok(())
    }

    fn daemon_reload(&mut self) -> Result<(), ProbeUpgraderRunError> {
        Ok(())
    }

    fn reset_failed(&mut self, _service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        Ok(())
    }

    fn verify_service_active(&mut self, _service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        Ok(())
    }

    fn verify_service_absent(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError>;

    fn remove_service_identity(
        &mut self,
        service_user: &str,
        service_group: &str,
    ) -> Result<(), ProbeUpgraderRunError>;

    fn remove_owned_ipc_group(
        &mut self,
        group: &str,
        ownership_marker: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        let _ = ownership_marker;
        self.remove_service_identity(group, group)
    }
}

pub struct SystemProbeUpgraderSystemdRunner;

impl ProbeUpgraderSystemdRunner for SystemProbeUpgraderSystemdRunner {
    fn ensure_service_group(&mut self, service_group: &str) -> Result<(), ProbeUpgraderRunError> {
        if !command_succeeds("getent", &["group", service_group]) {
            run_required_command("groupadd", &["--system", service_group])?;
        }
        Ok(())
    }

    fn ensure_service_account(
        &mut self,
        service_user: &str,
        service_group: &str,
        state_dir: &Path,
        identity_path: &Path,
    ) -> Result<(), ProbeUpgraderRunError> {
        if !command_succeeds("id", &["-u", service_user]) {
            run_required_command(
                "useradd",
                &[
                    "--system",
                    "--gid",
                    service_group,
                    "--home-dir",
                    state_dir
                        .to_str()
                        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
                            "state dir is not valid UTF-8",
                        ))?,
                    "--shell",
                    "/usr/sbin/nologin",
                    service_user,
                ],
            )?;
        }
        let ownership = format!("{service_user}:{service_group}");
        run_required_command(
            "chown",
            &[
                "-R",
                &ownership,
                state_dir
                    .to_str()
                    .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
                        "state dir is not valid UTF-8",
                    ))?,
            ],
        )?;
        run_required_command(
            "chown",
            &[
                &ownership,
                identity_path
                    .to_str()
                    .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
                        "identity path is not valid UTF-8",
                    ))?,
            ],
        )
    }

    fn enable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        run_required_command("systemctl", &["enable", service_name])
    }

    fn restart_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        let output = Command::new("systemctl")
            .args(["restart", service_name])
            .output()
            .map_err(|error| ProbeUpgraderRunError::RestartFailure(error.to_string()))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(ProbeUpgraderRunError::RestartFailure(
            if stderr.is_empty() {
                format!("systemctl restart exited with {}", output.status)
            } else {
                stderr
            },
        ))
    }

    fn stop_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        run_required_systemctl_cleanup(
            &["stop", service_name],
            service_name,
            "probe_uninstall_service_stop_failed",
            "stopping the service",
        )
    }

    fn disable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        run_required_systemctl_cleanup(
            &["disable", service_name],
            service_name,
            "probe_uninstall_service_disable_failed",
            "disabling the service",
        )
    }

    fn daemon_reload(&mut self) -> Result<(), ProbeUpgraderRunError> {
        run_required_cleanup_command(
            "systemctl",
            &["daemon-reload"],
            "probe_uninstall_daemon_reload_failed",
            "reloading systemd",
        )
    }

    fn reset_failed(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        run_required_systemctl_cleanup(
            &["reset-failed", service_name],
            service_name,
            "probe_uninstall_service_reset_failed",
            "resetting the failed service state",
        )
    }

    fn verify_service_active(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        run_required_command("systemctl", &["is-active", "--quiet", service_name])
    }

    fn verify_service_absent(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        verify_systemd_service_absent_with(service_name, &mut run_cleanup_command)
    }

    fn remove_service_identity(
        &mut self,
        service_user: &str,
        service_group: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        remove_service_identity_with(service_user, service_group, &mut run_cleanup_command)
    }

    fn remove_owned_ipc_group(
        &mut self,
        group: &str,
        ownership_marker: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        remove_owned_ipc_group_with(group, ownership_marker, &mut run_cleanup_command)
    }
}

struct CleanupCommandOutput {
    code: Option<i32>,
    stderr: String,
    stdout: String,
    successful: bool,
}

fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn run_required_command(program: &str, args: &[&str]) -> Result<(), ProbeUpgraderRunError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| ProbeUpgraderRunError::RestartFailure(error.to_string()))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(ProbeUpgraderRunError::RestartFailure(
        if stderr.is_empty() {
            format!("{program} exited with {}", output.status)
        } else {
            stderr
        },
    ))
}

fn run_required_systemctl_cleanup(
    args: &[&str],
    service_name: &str,
    code: &'static str,
    action: &'static str,
) -> Result<(), ProbeUpgraderRunError> {
    run_required_systemctl_cleanup_with(args, service_name, code, action, &mut run_cleanup_command)
}

fn run_required_systemctl_cleanup_with(
    args: &[&str],
    service_name: &str,
    code: &'static str,
    action: &'static str,
    run: &mut impl FnMut(&str, &[&str]) -> Result<CleanupCommandOutput, std::io::Error>,
) -> Result<(), ProbeUpgraderRunError> {
    let output = run("systemctl", args)
        .map_err(|error| uninstall_cleanup_failure(code, action, error.to_string()))?;
    if output.successful {
        return Ok(());
    }
    let load_state = run(
        "systemctl",
        &["show", "--property=LoadState", "--value", service_name],
    )
    .map_err(|error| uninstall_cleanup_failure(code, action, error.to_string()))?;
    if load_state.successful && load_state.stdout.trim() == "not-found" {
        return Ok(());
    }

    Err(uninstall_cleanup_failure(
        code,
        action,
        cleanup_command_failure_message(&output, "systemctl"),
    ))
}

fn verify_systemd_service_absent_with(
    service_name: &str,
    run: &mut impl FnMut(&str, &[&str]) -> Result<CleanupCommandOutput, std::io::Error>,
) -> Result<(), ProbeUpgraderRunError> {
    let action = "verifying the service is absent";
    let output = run(
        "systemctl",
        &["show", "--property=LoadState", "--value", service_name],
    )
    .map_err(|error| {
        uninstall_cleanup_failure(
            "probe_uninstall_service_verification_failed",
            action,
            error.to_string(),
        )
    })?;
    if output.successful && output.stdout.trim() == "not-found" {
        return Ok(());
    }
    if output.successful {
        return Err(uninstall_cleanup_failure(
            "probe_uninstall_service_residue",
            action,
            format!("systemd LoadState is {}", output.stdout.trim()),
        ));
    }
    Err(uninstall_cleanup_failure(
        "probe_uninstall_service_verification_failed",
        action,
        cleanup_command_failure_message(&output, "systemctl"),
    ))
}

fn remove_service_identity_with(
    service_user: &str,
    service_group: &str,
    run: &mut impl FnMut(&str, &[&str]) -> Result<CleanupCommandOutput, std::io::Error>,
) -> Result<(), ProbeUpgraderRunError> {
    remove_identity_entry_with(
        "passwd",
        service_user,
        "userdel",
        "probe_uninstall_service_account_remove_failed",
        "probe_uninstall_service_account_verification_failed",
        "probe_uninstall_service_account_residue",
        "removing the service account",
        "verifying the service account is absent",
        run,
    )?;
    remove_identity_entry_with(
        "group",
        service_group,
        "groupdel",
        "probe_uninstall_service_group_remove_failed",
        "probe_uninstall_service_group_verification_failed",
        "probe_uninstall_service_group_residue",
        "removing the service group",
        "verifying the service group is absent",
        run,
    )
}

fn remove_owned_ipc_group_with(
    group: &str,
    ownership_marker: &str,
    run: &mut impl FnMut(&str, &[&str]) -> Result<CleanupCommandOutput, std::io::Error>,
) -> Result<(), ProbeUpgraderRunError> {
    let action = "verifying the lifecycle IPC group ownership";
    let output = run("getent", &["gshadow", group]).map_err(|error| {
        uninstall_cleanup_failure(
            "probe_uninstall_service_group_verification_failed",
            action,
            error.to_string(),
        )
    })?;
    match output.code {
        Some(2) => return Ok(()),
        Some(0) if output.successful => {}
        _ => {
            return Err(uninstall_cleanup_failure(
                "probe_uninstall_service_group_verification_failed",
                action,
                cleanup_command_failure_message(&output, "getent"),
            ));
        }
    }
    let fields = output.stdout.trim_end().split(':').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != group || fields[1] != ownership_marker {
        return Err(uninstall_cleanup_failure(
            "probe_uninstall_service_group_residue",
            action,
            "lifecycle IPC group ownership receipt does not match".to_owned(),
        ));
    }
    remove_identity_entry_with(
        "group",
        group,
        "groupdel",
        "probe_uninstall_service_group_remove_failed",
        "probe_uninstall_service_group_verification_failed",
        "probe_uninstall_service_group_residue",
        "removing the lifecycle IPC group",
        "verifying the lifecycle IPC group is absent",
        run,
    )
}

#[allow(clippy::too_many_arguments)]
fn remove_identity_entry_with(
    database: &str,
    name: &str,
    delete_program: &str,
    remove_failure_code: &'static str,
    verification_failure_code: &'static str,
    residue_code: &'static str,
    remove_action: &'static str,
    verification_action: &'static str,
    run: &mut impl FnMut(&str, &[&str]) -> Result<CleanupCommandOutput, std::io::Error>,
) -> Result<(), ProbeUpgraderRunError> {
    let existed = identity_entry_exists_with(
        database,
        name,
        verification_failure_code,
        verification_action,
        run,
    )?;
    if !existed {
        return Ok(());
    }

    let output = run(delete_program, &[name]).map_err(|error| {
        uninstall_cleanup_failure(remove_failure_code, remove_action, error.to_string())
    })?;
    // shadow's userdel/groupdel use exit code 6 for an explicitly absent entry.
    if !output.successful && output.code != Some(6) {
        return Err(uninstall_cleanup_failure(
            remove_failure_code,
            remove_action,
            cleanup_command_failure_message(&output, delete_program),
        ));
    }

    if identity_entry_exists_with(
        database,
        name,
        verification_failure_code,
        verification_action,
        run,
    )? {
        return Err(uninstall_cleanup_failure(
            residue_code,
            verification_action,
            format!("{database} entry {name} still exists"),
        ));
    }
    Ok(())
}

fn identity_entry_exists_with(
    database: &str,
    name: &str,
    failure_code: &'static str,
    action: &'static str,
    run: &mut impl FnMut(&str, &[&str]) -> Result<CleanupCommandOutput, std::io::Error>,
) -> Result<bool, ProbeUpgraderRunError> {
    let output = run("getent", &[database, name])
        .map_err(|error| uninstall_cleanup_failure(failure_code, action, error.to_string()))?;
    if output.successful {
        return Ok(true);
    }
    // getent explicitly returns 2 when the requested key is absent.
    if output.code == Some(2) {
        return Ok(false);
    }
    Err(uninstall_cleanup_failure(
        failure_code,
        action,
        cleanup_command_failure_message(&output, "getent"),
    ))
}

fn run_required_cleanup_command(
    program: &str,
    args: &[&str],
    code: &'static str,
    action: &'static str,
) -> Result<(), ProbeUpgraderRunError> {
    let output = run_cleanup_command(program, args)
        .map_err(|error| uninstall_cleanup_failure(code, action, error.to_string()))?;
    if output.successful {
        return Ok(());
    }
    Err(uninstall_cleanup_failure(
        code,
        action,
        cleanup_command_failure_message(&output, program),
    ))
}

fn run_cleanup_command(
    program: &str,
    args: &[&str],
) -> Result<CleanupCommandOutput, std::io::Error> {
    let output = Command::new(program).args(args).output()?;
    Ok(CleanupCommandOutput {
        code: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        successful: output.status.success(),
    })
}

fn cleanup_command_failure_message(output: &CleanupCommandOutput, program: &str) -> String {
    if !output.stderr.is_empty() {
        return output.stderr.clone();
    }
    if !output.stdout.is_empty() {
        return output.stdout.clone();
    }
    match output.code {
        Some(code) => format!("{program} exited with code {code}"),
        None => format!("{program} terminated without an exit code"),
    }
}

fn uninstall_cleanup_failure(
    code: &'static str,
    action: &'static str,
    message: String,
) -> ProbeUpgraderRunError {
    ProbeUpgraderRunError::UninstallCleanupFailure {
        action,
        code,
        message,
    }
}

#[cfg(test)]
pub(crate) fn repair_acquirer_exit_lifecycle_response(
    code: Option<i32>,
) -> Option<LifecycleResponse> {
    repair::acquirer_exit_failure(code).map(|error| repair::response(Err(error)))
}

fn read_probe_repair_identity(
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<ProbeUpgraderBootstrapConfig, ProbeRepairRunError> {
    let metadata = fs::symlink_metadata(&install_metadata.identity_path)
        .map_err(|_| ProbeRepairRunError::IdentityIncomplete)?;
    read_probe_repair_identity_with_file_metadata(
        install_metadata,
        TrustedFileMetadata {
            is_regular_file: metadata.file_type().is_file(),
            is_symlink: metadata.file_type().is_symlink(),
            mode: metadata.permissions().mode() & 0o777,
            owner_uid: metadata.uid(),
        },
    )
}

fn read_probe_repair_identity_with_file_metadata(
    install_metadata: &TrustedProbeInstallMetadata,
    file_metadata: TrustedFileMetadata,
) -> Result<ProbeUpgraderBootstrapConfig, ProbeRepairRunError> {
    if file_metadata.is_symlink || !file_metadata.is_regular_file || file_metadata.mode != 0o600 {
        return Err(ProbeRepairRunError::IdentityIncomplete);
    }
    let identity = read_upgrader_bootstrap_config(&install_metadata.identity_path)
        .map_err(|_| ProbeRepairRunError::IdentityIncomplete)?;
    if identity.hub_url.as_deref().is_none_or(str::is_empty)
        || identity.probe_id.as_deref().is_none_or(str::is_empty)
        || identity
            .probe_private_key_pem
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(ProbeRepairRunError::IdentityIncomplete);
    }
    Ok(identity)
}

pub(crate) fn run_lifecycle_companion_from_peer(
    _owner: &replacement::StandaloneLifecycleOwner,
    request: &LifecycleRequest,
    transport: &mut impl ProbeUpgraderValidationTransport,
    peer_uid: Option<u32>,
) -> LifecycleResponse {
    run_lifecycle_companion_from_peer_with_effective_uid(
        request,
        transport,
        peer_uid,
        EffectiveUid::process(),
    )
}

pub(crate) fn acquire_standalone_lifecycle_owner()
-> Result<replacement::StandaloneLifecycleOwner, ()> {
    replacement::acquire_standalone_lifecycle_owner()
}

#[derive(Clone, Copy)]
struct EffectiveUid(u32);

impl EffectiveUid {
    fn process() -> Self {
        Self(unsafe { libc::geteuid() })
    }

    #[cfg(test)]
    const fn test(uid: u32) -> Self {
        Self(uid)
    }

    const fn is_root(self) -> bool {
        self.0 == 0
    }
}

fn run_lifecycle_companion_from_peer_with_effective_uid(
    request: &LifecycleRequest,
    transport: &mut impl ProbeUpgraderValidationTransport,
    peer_uid: Option<u32>,
    effective_uid: EffectiveUid,
) -> LifecycleResponse {
    if !effective_uid.is_root() {
        return LifecycleResponse::failed("lifecycle.root_required");
    }
    match request.transition() {
        LifecycleTransition::Upgrade => {
            enoki_probe_bootstrap::install::run_compatible_upgrade(request, peer_uid)
        }
        LifecycleTransition::Repair => repair::coordinate(request, peer_uid),
        // Replacement 有且只有 fd9 admission 构造的 adopted witness 入口；
        // 一般 lifecycle dispatch 绝不代为取得或伪造它。
        LifecycleTransition::ReplacementMigration => {
            LifecycleResponse::failed("lifecycle.invalid_authority")
        }
        LifecycleTransition::Uninstall => uninstall::coordinate(Some(request), transport),
        LifecycleTransition::FreshInstall => LifecycleResponse::not_enabled(),
    }
}

/// 仅供已完成 fd9 admission 的 Companion process invocation 使用。source
/// witness 不可跨此 crate 边界，因而没有第二个外部 Replacement 入口。
pub(crate) fn run_adopted_replacement_child(
    witness: crate::lifecycle_companion::AdoptedReplacementChild,
    request: &LifecycleRequest,
) -> LifecycleResponse {
    replacement::coordinate(witness, request)
}

/// 固定 `--upgrade` CLI Adapter 只接受 Compatible Upgrade，并与 socket
/// companion 入口进入同一个 Probe Bootstrap coordinator。
pub(crate) fn run_upgrade_lifecycle_companion_from_peer(
    _owner: &replacement::StandaloneLifecycleOwner,
    request: &LifecycleRequest,
    peer_uid: Option<u32>,
) -> LifecycleResponse {
    run_upgrade_lifecycle_companion_from_peer_with_effective_uid(
        request,
        peer_uid,
        EffectiveUid::process(),
    )
}

fn run_upgrade_lifecycle_companion_from_peer_with_effective_uid(
    request: &LifecycleRequest,
    peer_uid: Option<u32>,
    effective_uid: EffectiveUid,
) -> LifecycleResponse {
    if !effective_uid.is_root() {
        return LifecycleResponse::failed("lifecycle.root_required");
    }
    if request.transition() != LifecycleTransition::Upgrade {
        return LifecycleResponse::not_enabled();
    }
    enoki_probe_bootstrap::install::run_compatible_upgrade(request, peer_uid)
}

fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

/// 响应已经完整写出后，Companion binary unlink 是进程最后一个可失败动作。
pub(crate) fn finalize_lifecycle_companion_binary() -> bool {
    remove_path_if_exists(Path::new(LIFECYCLE_COMPANION_BINARY_PATH)).is_ok()
}

/// 固定恢复入口不接受运行时参数；它只消费安装目录中的 root-owned
/// canonical capsule。capsule 已提交删除时，唯一剩余动作是自删除固定
/// Companion binary。
pub(crate) fn resume_lifecycle_companion(
    _owner: &replacement::StandaloneLifecycleOwner,
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> LifecycleResponse {
    if unsafe { libc::geteuid() } != 0 {
        return LifecycleResponse::failed("lifecycle.root_required");
    }
    resume_lifecycle_companion_at(
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        Path::new(PRODUCTION_INSTALL_STATE_DIR),
        Path::new(PRODUCTION_BOOTSTRAP_STATE_DIR),
        Path::new(LIFECYCLE_COMPANION_BINARY_PATH),
        transport,
        &mut SystemProbeUpgraderSystemdRunner,
    )
}

fn rebase_trusted_install_metadata_paths(
    metadata: &mut TrustedProbeInstallMetadata,
    test_root: Option<&Path>,
) {
    for path in [
        &mut metadata.identity_path,
        &mut metadata.install_path,
        &mut metadata.operation_status_path,
        &mut metadata.service_unit_path,
        &mut metadata.state_dir,
    ] {
        *path = preflight_rooted_path(test_root, path);
    }
    for path in [
        &mut metadata.operation_sudoers_path,
        &mut metadata.collector_helper_sudoers_path,
        &mut metadata.bootstrap_acquirer_path,
        &mut metadata.bootstrap_activator_path,
        &mut metadata.bootstrap_state_dir,
    ]
    .into_iter()
    .flatten()
    {
        *path = preflight_rooted_path(test_root, path);
    }
    for path in &mut metadata.old_sudoers_paths {
        *path = preflight_rooted_path(test_root, path);
    }
    for path in [
        &mut metadata.observation_runtime_path,
        &mut metadata.cpu_provider_path,
        &mut metadata.disk_health_provider_path,
        &mut metadata.lifecycle_companion_path,
    ]
    .into_iter()
    .flatten()
    {
        *path = preflight_rooted_path(test_root, path);
    }
    for path in &mut metadata.observation_unit_paths {
        *path = preflight_rooted_path(test_root, path);
    }
}

fn remove_path_if_exists(path: &Path) -> Result<(), ProbeUpgraderRunError> {
    ensure_absolute_path(path)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ProbeUpgraderRunError::Io(error)),
    };

    if metadata.is_dir() {
        fs::remove_dir_all(path).map_err(ProbeUpgraderRunError::Io)
    } else {
        fs::remove_file(path).map_err(ProbeUpgraderRunError::Io)
    }
}

fn verify_path_absent(
    path: &Path,
    residue_code: &'static str,
    action: &'static str,
) -> Result<(), ProbeUpgraderRunError> {
    ensure_absolute_path(path)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(uninstall_cleanup_failure(
            "probe_uninstall_path_verification_failed",
            action,
            error.to_string(),
        )),
        Ok(_) => Err(uninstall_cleanup_failure(
            residue_code,
            action,
            format!("{} still exists", path.display()),
        )),
    }
}

fn remove_empty_parent_dir(path: &Path) -> Result<(), ProbeUpgraderRunError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent == Path::new("/") {
        return Ok(());
    }

    match fs::remove_dir(parent) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(ProbeUpgraderRunError::Io(error)),
    }
}

fn ensure_absolute_path(path: &Path) -> Result<(), ProbeUpgraderRunError> {
    if path.is_absolute() && path != Path::new("/") {
        return Ok(());
    }

    Err(ProbeUpgraderRunError::InvalidInstallMetadata(
        "paths must be absolute",
    ))
}

fn render_operation_status_body(token: &str, status: &str) -> String {
    format!(
        "{{\"status\":\"{}\",\"token\":\"{}\"}}",
        json_string_fragment(status),
        json_string_fragment(token),
    )
}

#[derive(Debug)]
struct ProbeUpgraderBootstrapConfig {
    hub_url: Option<String>,
    install_path: Option<String>,
    operation_status_path: Option<String>,
    probe_asset_public_key_sha256: Option<String>,
    probe_distribution_root_sha256: Option<String>,
    probe_id: Option<String>,
    probe_private_key_pem: Option<String>,
    server_time_offset_ms: Option<i64>,
    service_name: Option<String>,
    state_dir: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedProbeInstallMetadata {
    schema_version: u32,
    hub_url: String,
    identity_path: PathBuf,
    install_path: PathBuf,
    operation_status_path: PathBuf,
    probe_asset_public_key_sha256: String,
    probe_distribution_root_sha256: Option<String>,
    bootstrap_acquirer_path: Option<PathBuf>,
    bootstrap_activator_path: Option<PathBuf>,
    bootstrap_state_dir: Option<PathBuf>,
    service_name: String,
    service_group: String,
    service_unit_path: PathBuf,
    service_user: String,
    state_dir: PathBuf,
    operation_sudoers_path: Option<PathBuf>,
    collector_helper_sudoers_path: Option<PathBuf>,
    old_sudoers_paths: Vec<PathBuf>,
    observation_runtime_path: Option<PathBuf>,
    cpu_provider_path: Option<PathBuf>,
    disk_health_provider_path: Option<PathBuf>,
    lifecycle_companion_path: Option<PathBuf>,
    observation_unit_paths: Vec<PathBuf>,
    probe_ipc_group: Option<String>,
    probe_ipc_group_ownership: Option<String>,
    observation_ipc_group: Option<String>,
    install_state_sha256: Option<String>,
    target_manifest_sha256: Option<String>,
    bundle_version: Option<String>,
    lifecycle_authority_install_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedProbeInstallPreflight {
    pub hub_url: String,
    pub probe_id: String,
}

pub fn read_trusted_probe_install_preflight(
    path: &Path,
    test_root: Option<&Path>,
) -> Result<TrustedProbeInstallPreflight, ProbeUpgraderRunError> {
    let metadata = read_trusted_probe_install_metadata_read_only(path, None)?;
    let mut identity_metadata = metadata.clone();
    identity_metadata.identity_path = preflight_rooted_path(test_root, &metadata.identity_path);
    let identity = read_probe_repair_identity(&identity_metadata).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("Probe identity is incomplete or unsafe")
    })?;
    let identity_hub_url = identity
        .hub_url
        .as_deref()
        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe identity Hub URL is missing",
        ))
        .and_then(|hub_url| {
            hub_url::normalized_base(hub_url).map_err(|()| {
                ProbeUpgraderRunError::InvalidInstallMetadata("Probe identity Hub URL is invalid")
            })
        })?;
    if identity_hub_url != metadata.hub_url {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe identity Hub URL does not match install metadata",
        ));
    }
    let probe_id = identity
        .probe_id
        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe identity is missing a Probe ID",
        ))?;
    if !valid_public_probe_id(&probe_id) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe identity has an invalid Probe ID",
        ));
    }
    Ok(TrustedProbeInstallPreflight {
        hub_url: metadata.hub_url,
        probe_id,
    })
}

fn preflight_rooted_path(test_root: Option<&Path>, path: &Path) -> PathBuf {
    test_root.map_or_else(
        || path.to_path_buf(),
        |root| {
            root.join(
                path.strip_prefix("/")
                    .expect("trusted metadata paths are absolute"),
            )
        },
    )
}

fn valid_public_probe_id(value: &str) -> bool {
    value
        .strip_prefix("probe_")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.len() <= 90)
        && value["probe_".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrustedFileMetadata {
    is_regular_file: bool,
    is_symlink: bool,
    mode: u32,
    owner_uid: u32,
}

fn read_upgrader_bootstrap_config(
    path: &PathBuf,
) -> Result<ProbeUpgraderBootstrapConfig, ProbeUpgraderRunError> {
    let contents = fs::read_to_string(path).map_err(ProbeUpgraderRunError::Io)?;
    let value = contents
        .parse::<toml::Value>()
        .map_err(|_| ProbeUpgraderRunError::InvalidConfig("invalid TOML"))?;

    Ok(ProbeUpgraderBootstrapConfig {
        hub_url: string_value(&value, "hub_url")?,
        install_path: string_value(&value, "install_path")?,
        operation_status_path: string_value(&value, "operation_status_path")?,
        probe_asset_public_key_sha256: string_value(&value, "probe_asset_public_key_sha256")?,
        probe_distribution_root_sha256: string_value(&value, "probe_distribution_root_sha256")?,
        probe_id: string_value(&value, "probe_id")?,
        probe_private_key_pem: string_value(&value, "probe_private_key_pem")?,
        server_time_offset_ms: signed_integer_value(&value, "server_time_offset_ms")?,
        service_name: string_value(&value, "service_name")?,
        state_dir: string_value(&value, "state_dir")?,
    })
}

fn probe_request_auth_from_bootstrap_config(
    bootstrap_config: &ProbeUpgraderBootstrapConfig,
) -> Result<ProbeRequestAuth<'_>, ProbeUpgraderRunError> {
    Ok(ProbeRequestAuth {
        probe_id: bootstrap_config
            .probe_id
            .as_deref()
            .ok_or(ProbeUpgraderRunError::InvalidConfig("missing Probe ID"))?,
        probe_private_key_pem: bootstrap_config.probe_private_key_pem.as_deref().ok_or(
            ProbeUpgraderRunError::InvalidConfig("missing Probe signing key"),
        )?,
        server_time_offset_ms: bootstrap_config.server_time_offset_ms.unwrap_or(0),
    })
}

fn read_trusted_probe_install_metadata(
    path: &Path,
    legacy_identity_path: Option<&Path>,
) -> Result<TrustedProbeInstallMetadata, ProbeUpgraderRunError> {
    let mut trusted = read_trusted_probe_install_metadata_read_only(path, legacy_identity_path)?;
    if trusted.schema_version == 0 {
        write_trusted_probe_install_metadata(path, &trusted)?;
        trusted.schema_version = 1;
    }
    Ok(trusted)
}

fn read_trusted_probe_install_metadata_read_only(
    path: &Path,
    legacy_identity_path: Option<&Path>,
) -> Result<TrustedProbeInstallMetadata, ProbeUpgraderRunError> {
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    read_trusted_probe_install_metadata_read_only_with_file_metadata(
        path,
        legacy_identity_path,
        TrustedFileMetadata {
            is_regular_file: metadata.file_type().is_file(),
            is_symlink: metadata.file_type().is_symlink(),
            mode: metadata.mode() & 0o777,
            owner_uid: metadata.uid(),
        },
    )
}

fn read_trusted_probe_install_metadata_read_only_with_file_metadata(
    path: &Path,
    legacy_identity_path: Option<&Path>,
    file_metadata: TrustedFileMetadata,
) -> Result<TrustedProbeInstallMetadata, ProbeUpgraderRunError> {
    if file_metadata.is_symlink || !file_metadata.is_regular_file {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "metadata path must be a regular non-symlink file",
        ));
    }
    if file_metadata.owner_uid != 0 {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "metadata file is not owned by root",
        ));
    }

    let contents = fs::read_to_string(path).map_err(ProbeUpgraderRunError::Io)?;
    let metadata =
        parse_trusted_probe_install_metadata_with_legacy_identity(&contents, legacy_identity_path)?;
    if metadata.schema_version == 1 {
        if file_metadata.mode != 0o600 {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "schema v1 metadata mode must be 0600",
            ));
        }
    } else if matches!(metadata.schema_version, 2..=5) {
        if file_metadata.mode != 0o600 {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "schema v2 metadata mode must be 0600",
            ));
        }
    } else {
        if !matches!(file_metadata.mode, 0o600 | 0o644) {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "legacy metadata mode is not supported",
            ));
        }
    }
    Ok(metadata)
}

fn parse_trusted_probe_install_metadata_with_legacy_identity(
    contents: &str,
    legacy_identity_path: Option<&Path>,
) -> Result<TrustedProbeInstallMetadata, ProbeUpgraderRunError> {
    let value = contents
        .parse::<toml::Value>()
        .map_err(|_| ProbeUpgraderRunError::InvalidInstallMetadata("invalid TOML"))?;
    let schema_version = match value.get("schema_version") {
        None => 0,
        Some(toml::Value::Integer(1)) => 1,
        Some(toml::Value::Integer(2)) => 2,
        Some(toml::Value::Integer(3)) => 3,
        Some(toml::Value::Integer(4)) => 4,
        Some(toml::Value::Integer(5)) => 5,
        Some(toml::Value::Integer(_)) => {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "unsupported schema version",
            ));
        }
        Some(_) => {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "schema version must be an integer",
            ));
        }
    };
    let install_path = required_install_metadata_path(&value, "install_path")?;
    if matches!(schema_version, 3..=5) && install_path != Path::new(PRODUCTION_PROBE_BINARY_PATH) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "install_path does not match the fixed production path",
        ));
    }
    let hub_url = required_install_metadata_string(&value, "hub_url")?;
    let operation_status_path = required_install_metadata_path(&value, "operation_status_path")?;
    let state_dir = required_install_metadata_path(&value, "state_dir")?;
    if value.get("sudoers_path").is_some() {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "old sudoers_path metadata is not supported",
        ));
    }
    let (operation_sudoers_path, collector_helper_sudoers_path) = if schema_version == 2 {
        if value.get("operation_sudoers_path").is_some()
            || value.get("collector_helper_sudoers_path").is_some()
            || value.get("probe_asset_public_key_sha256").is_some()
        {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "signed package metadata must not carry legacy sudoers or daily signing trust",
            ));
        }
        (None, None)
    } else if matches!(schema_version, 3..=5) {
        (
            optional_fixed_install_metadata_path(
                &value,
                "operation_sudoers_path",
                PRODUCTION_OPERATION_SUDOERS_PATH,
            )?,
            required_fixed_install_metadata_path(
                &value,
                "collector_helper_sudoers_path",
                PRODUCTION_COLLECTOR_HELPER_SUDOERS_PATH,
            )?,
        )
    } else {
        (
            Some(required_install_metadata_path(
                &value,
                "operation_sudoers_path",
            )?),
            Some(required_install_metadata_path(
                &value,
                "collector_helper_sudoers_path",
            )?),
        )
    };
    let service_name = required_install_metadata_string(&value, "service_name")?;
    let service_user = optional_install_metadata_string(&value, "service_user")?
        .unwrap_or_else(|| "enoki-probe".to_string());
    let identity_path = if matches!(schema_version, 1..=5) {
        required_install_metadata_path(&value, "identity_path")?
    } else {
        legacy_identity_path
            .unwrap_or_else(|| Path::new("/etc/enoki/probe-bootstrap.toml"))
            .to_path_buf()
    };
    let service_group = if matches!(schema_version, 1..=5) {
        required_install_metadata_string(&value, "service_group")?
    } else {
        service_user.clone()
    };
    let service_unit_path = if matches!(schema_version, 1..=5) {
        required_install_metadata_path(&value, "service_unit_path")?
    } else {
        PathBuf::from("/etc/systemd/system/enoki-probe.service")
    };
    let (probe_asset_public_key_sha256, probe_distribution_root_sha256) =
        if matches!(schema_version, 2..=5) {
            let root = required_install_metadata_string(&value, "probe_distribution_root_sha256")?;
            if !is_sha256_hex(&root) {
                return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                    "Probe distribution root fingerprint is not a valid sha256 value",
                ));
            }
            // Legacy helpers retain a private field so their cleanup plan keeps
            // fixed paths. It is never serialized or used as daily signing trust.
            (root.clone(), Some(root))
        } else {
            (
                required_install_metadata_string(&value, "probe_asset_public_key_sha256")?,
                None,
            )
        };
    let (bootstrap_acquirer_path, bootstrap_activator_path, bootstrap_state_dir) =
        if matches!(schema_version, 2..=5) {
            (
                required_fixed_install_metadata_path(
                    &value,
                    "bootstrap_acquirer_path",
                    PRODUCTION_BOOTSTRAP_ACQUIRER_PATH,
                )?,
                required_fixed_install_metadata_path(
                    &value,
                    "bootstrap_activator_path",
                    PRODUCTION_BOOTSTRAP_ACTIVATOR_PATH,
                )?,
                required_fixed_install_metadata_path(
                    &value,
                    "bootstrap_state_dir",
                    PRODUCTION_BOOTSTRAP_STATE_DIR,
                )?,
            )
        } else {
            if value.get("bootstrap_acquirer_path").is_some()
                || value.get("bootstrap_activator_path").is_some()
                || value.get("bootstrap_state_dir").is_some()
            {
                return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                    "legacy metadata must not carry Probe Bootstrap ownership",
                ));
            }
            (None, None, None)
        };

    let (
        observation_runtime_path,
        cpu_provider_path,
        disk_health_provider_path,
        observation_unit_paths,
        observation_ipc_group,
        lifecycle_companion_path,
    ) = if matches!(schema_version, 3..=5) {
        let runtime = required_fixed_install_metadata_path(
            &value,
            "observation_runtime_path",
            OBSERVATION_RUNTIME_BINARY_PATH,
        )?;
        let provider = required_fixed_install_metadata_path(
            &value,
            "cpu_provider_path",
            CPU_PROVIDER_BINARY_PATH,
        )?;
        let has_disk_health_provider = value.get("disk_health_provider_path").is_some();
        let has_disk_health_units = value
            .get("disk_health_provider_service_unit_path")
            .is_some()
            && value.get("disk_health_provider_socket_unit_path").is_some();
        if has_disk_health_provider != has_disk_health_units {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "schema 3 Disk Health Provider inventory is partial",
            ));
        }
        let lifecycle_companion = if schema_version >= 4 {
            required_fixed_install_metadata_path(
                &value,
                "lifecycle_companion_path",
                LIFECYCLE_COMPANION_BINARY_PATH,
            )?
        } else {
            None
        };
        let disk_health_provider = if has_disk_health_provider {
            required_fixed_install_metadata_path(
                &value,
                "disk_health_provider_path",
                DISK_HEALTH_PROVIDER_BINARY_PATH,
            )?
        } else {
            None
        };
        let mut unit_specs = vec![
            (
                "observation_runtime_service_unit_path",
                OBSERVATION_RUNTIME_SERVICE_UNIT_PATH,
            ),
            (
                "observation_runtime_socket_unit_path",
                OBSERVATION_RUNTIME_SOCKET_UNIT_PATH,
            ),
            (
                "cpu_provider_service_unit_path",
                CPU_PROVIDER_SERVICE_UNIT_PATH,
            ),
            (
                "cpu_provider_socket_unit_path",
                CPU_PROVIDER_SOCKET_UNIT_PATH,
            ),
        ];
        if has_disk_health_provider {
            unit_specs.extend([
                (
                    "disk_health_provider_service_unit_path",
                    DISK_HEALTH_PROVIDER_SERVICE_UNIT_PATH,
                ),
                (
                    "disk_health_provider_socket_unit_path",
                    DISK_HEALTH_PROVIDER_SOCKET_UNIT_PATH,
                ),
            ]);
        }
        if schema_version >= 4 {
            unit_specs.extend([
                (
                    "lifecycle_companion_service_unit_path",
                    LIFECYCLE_COMPANION_SERVICE_UNIT_PATH,
                ),
                (
                    "lifecycle_companion_socket_unit_path",
                    LIFECYCLE_COMPANION_SOCKET_UNIT_PATH,
                ),
            ]);
        }
        if schema_version == 5 {
            unit_specs.extend([
                (
                    "lifecycle_upgrade_service_unit_path",
                    LIFECYCLE_UPGRADE_SERVICE_UNIT_PATH,
                ),
                (
                    "lifecycle_upgrade_socket_unit_path",
                    LIFECYCLE_UPGRADE_SOCKET_UNIT_PATH,
                ),
            ]);
            if value
                .get("observation_runtime_failure_recorder_unit_path")
                .is_some()
            {
                unit_specs.push((
                    "observation_runtime_failure_recorder_unit_path",
                    OBSERVATION_RUNTIME_FAILURE_RECORDER_UNIT_PATH,
                ));
            }
        }
        let units = unit_specs
            .into_iter()
            .map(|(key, expected)| required_fixed_install_metadata_path(&value, key, expected))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        let ipc_group = required_install_metadata_string(&value, "observation_ipc_group")?;
        if ipc_group != OBSERVATION_IPC_GROUP {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "observation IPC group must use the fixed installation identity",
            ));
        }
        (
            runtime,
            provider,
            disk_health_provider,
            units,
            Some(ipc_group),
            lifecycle_companion,
        )
    } else {
        (None, None, None, Vec::new(), None, None)
    };

    let (
        install_state_sha256,
        target_manifest_sha256,
        bundle_version,
        probe_ipc_group,
        probe_ipc_group_ownership,
    ) = if matches!(schema_version, 4 | 5) {
        let install_state = required_install_metadata_string(&value, "install_state_sha256")?;
        let manifest = required_install_metadata_string(&value, "target_manifest_sha256")?;
        let version = required_install_metadata_string(&value, "bundle_version")?;
        let ipc_group = required_install_metadata_string(&value, "probe_ipc_group")?;
        let ipc_group_ownership =
            required_install_metadata_string(&value, "probe_ipc_group_ownership")?;
        if !is_sha256_hex(&install_state)
            || !is_sha256_hex(&manifest)
            || version.is_empty()
            || version.len() > 64
            || ipc_group != PROBE_IPC_GROUP
            || !valid_probe_ipc_group_ownership(&ipc_group_ownership)
        {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "lifecycle receipt is invalid",
            ));
        }
        (
            Some(install_state),
            Some(manifest),
            Some(version),
            Some(ipc_group),
            Some(ipc_group_ownership),
        )
    } else {
        (None, None, None, None, None)
    };
    let lifecycle_authority_install_key =
        optional_install_metadata_string(&value, "lifecycle_authority_install_key")?;
    if (schema_version == 5 && lifecycle_authority_install_key.is_none())
        || (schema_version < 5 && lifecycle_authority_install_key.is_some())
        || lifecycle_authority_install_key
            .as_deref()
            .is_some_and(|key| decode_lower_hex(key).is_none_or(|bytes| bytes.len() != 32))
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "lifecycle authority install key is invalid",
        ));
    }

    if service_name != "enoki-probe" {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "service name must be enoki-probe",
        ));
    }
    if !is_safe_sudoers_token(&service_user) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "service user is not safe for sudoers",
        ));
    }
    if !is_safe_sudoers_token(&service_group) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "service group is not safe",
        ));
    }
    if !matches!(schema_version, 2..=5) && !is_sha256_hex(&probe_asset_public_key_sha256) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "trusted Probe asset signing key fingerprint is not a valid sha256 value",
        ));
    }
    let hub_url = hub_url::normalized_base(&hub_url).map_err(|()| {
        ProbeUpgraderRunError::InvalidInstallMetadata("trusted Hub URL is invalid")
    })?;

    Ok(TrustedProbeInstallMetadata {
        schema_version,
        hub_url,
        identity_path,
        install_path,
        operation_status_path,
        probe_asset_public_key_sha256,
        probe_distribution_root_sha256,
        bootstrap_acquirer_path,
        bootstrap_activator_path,
        bootstrap_state_dir,
        service_name,
        service_group,
        service_unit_path,
        service_user,
        state_dir,
        operation_sudoers_path,
        collector_helper_sudoers_path,
        old_sudoers_paths: if matches!(schema_version, 2..=5) {
            Vec::new()
        } else {
            vec![PathBuf::from(PRODUCTION_LEGACY_UPGRADER_SUDOERS_PATH)]
        },
        observation_runtime_path,
        cpu_provider_path,
        disk_health_provider_path,
        lifecycle_companion_path,
        observation_unit_paths,
        probe_ipc_group,
        probe_ipc_group_ownership,
        observation_ipc_group,
        install_state_sha256,
        target_manifest_sha256,
        bundle_version,
        lifecycle_authority_install_key,
    })
}

fn valid_probe_ipc_group_ownership(value: &str) -> bool {
    value
        .strip_prefix("!enoki-bootstrap-")
        .is_some_and(|transaction| {
            transaction.len() == 32
                && transaction
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn required_fixed_install_metadata_path(
    value: &toml::Value,
    key: &'static str,
    expected: &'static str,
) -> Result<Option<PathBuf>, ProbeUpgraderRunError> {
    let path = required_install_metadata_path(value, key)?;
    if path != Path::new(expected) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap role path is not the fixed production path",
        ));
    }
    Ok(Some(path))
}

fn optional_fixed_install_metadata_path(
    value: &toml::Value,
    key: &'static str,
    expected: &'static str,
) -> Result<Option<PathBuf>, ProbeUpgraderRunError> {
    if value.get(key).is_none() {
        return Ok(None);
    }
    required_fixed_install_metadata_path(value, key, expected)
}

fn validate_identity_path(
    supplied: &Path,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    if install_metadata.schema_version == 0 {
        return Ok(());
    }
    if supplied != install_metadata.identity_path {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "identity path does not match trusted install metadata",
        ));
    }
    Ok(())
}

fn write_trusted_probe_install_metadata(
    path: &Path,
    metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    let parent = path
        .parent()
        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "metadata path has no parent",
        ))?;
    let temporary = parent.join(format!(
        ".probe-install.toml.migrating-{}",
        std::process::id()
    ));
    let contents = [
        "schema_version = 1".to_string(),
        format!("hub_url = {}", toml_string(&metadata.hub_url)),
        format!(
            "install_path = {}",
            toml_string(&metadata.install_path.display().to_string())
        ),
        format!(
            "identity_path = {}",
            toml_string(&metadata.identity_path.display().to_string())
        ),
        format!(
            "state_dir = {}",
            toml_string(&metadata.state_dir.display().to_string())
        ),
        format!(
            "operation_status_path = {}",
            toml_string(&metadata.operation_status_path.display().to_string())
        ),
        format!("service_name = {}", toml_string(&metadata.service_name)),
        format!("service_user = {}", toml_string(&metadata.service_user)),
        format!("service_group = {}", toml_string(&metadata.service_group)),
        format!(
            "service_unit_path = {}",
            toml_string(&metadata.service_unit_path.display().to_string())
        ),
        format!(
            "operation_sudoers_path = {}",
            toml_string(
                &metadata
                    .operation_sudoers_path
                    .as_ref()
                    .expect("schema v0 migration has operation sudoers")
                    .display()
                    .to_string()
            )
        ),
        format!(
            "collector_helper_sudoers_path = {}",
            toml_string(
                &metadata
                    .collector_helper_sudoers_path
                    .as_ref()
                    .expect("schema v0 migration has collector sudoers")
                    .display()
                    .to_string()
            )
        ),
        format!(
            "probe_asset_public_key_sha256 = {}",
            toml_string(&metadata.probe_asset_public_key_sha256)
        ),
        String::new(),
    ]
    .join("\n");
    fs::write(&temporary, contents).map_err(ProbeUpgraderRunError::Io)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .map_err(ProbeUpgraderRunError::Io)?;
    fs::rename(&temporary, path).map_err(ProbeUpgraderRunError::Io)
}

fn required_install_metadata_path(
    value: &toml::Value,
    key: &'static str,
) -> Result<PathBuf, ProbeUpgraderRunError> {
    let path = PathBuf::from(required_install_metadata_string(value, key)?);
    if !path.is_absolute() {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "paths must be absolute",
        ));
    }
    if path == Path::new("/") {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "paths must not be filesystem root",
        ));
    }
    let Some(value) = path.to_str() else {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "paths must be UTF-8",
        ));
    };
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "paths contain unsafe components",
        ));
    }

    Ok(path)
}

fn required_install_metadata_string(
    value: &toml::Value,
    key: &'static str,
) -> Result<String, ProbeUpgraderRunError> {
    match value.get(key) {
        Some(toml::Value::String(string)) if !string.is_empty() => Ok(string.clone()),
        Some(toml::Value::String(_)) | None => Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "missing required field",
        )),
        Some(_) => Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "expected string values",
        )),
    }
}

fn optional_install_metadata_string(
    value: &toml::Value,
    key: &'static str,
) -> Result<Option<String>, ProbeUpgraderRunError> {
    match value.get(key) {
        Some(toml::Value::String(string)) => Ok(Some(string.clone())),
        Some(_) => Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "expected string values",
        )),
        None => Ok(None),
    }
}

fn string_value(
    value: &toml::Value,
    key: &'static str,
) -> Result<Option<String>, ProbeUpgraderRunError> {
    match value.get(key) {
        Some(toml::Value::String(string)) => Ok(Some(string.clone())),
        Some(_) => Err(ProbeUpgraderRunError::InvalidConfig(
            "expected string values",
        )),
        None => Ok(None),
    }
}

fn signed_integer_value(
    value: &toml::Value,
    key: &'static str,
) -> Result<Option<i64>, ProbeUpgraderRunError> {
    match value.get(key) {
        Some(toml::Value::Integer(integer)) => Ok(Some(*integer)),
        Some(_) => Err(ProbeUpgraderRunError::InvalidConfig(
            "expected integer values",
        )),
        None => Ok(None),
    }
}

fn json_string_fragment(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn write_new_synced_file(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), ProbeUpgraderRunError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(ProbeUpgraderRunError::Io)?;
    file.write_all(bytes).map_err(ProbeUpgraderRunError::Io)?;
    file.sync_all().map_err(ProbeUpgraderRunError::Io)
}

fn sync_directory(path: &Path) -> Result<(), ProbeUpgraderRunError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(ProbeUpgraderRunError::Io)
}

fn validate_bootstrap_config_matches_trusted_install_metadata(
    bootstrap_config: &ProbeUpgraderBootstrapConfig,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    let bootstrap_hub_url = bootstrap_config
        .hub_url
        .as_deref()
        .ok_or(ProbeUpgraderRunError::InvalidConfig("missing Hub URL"))?;
    let bootstrap_hub_url = hub_url::normalized_base(bootstrap_hub_url)
        .map_err(|()| ProbeUpgraderRunError::InvalidConfig("invalid Hub URL"))?;
    if bootstrap_hub_url != install_metadata.hub_url {
        return Err(ProbeUpgraderRunError::InvalidConfig(
            "Hub URL does not match trusted install metadata",
        ));
    }
    validate_optional_bootstrap_path(
        bootstrap_config.install_path.as_deref(),
        &install_metadata.install_path,
        "install path does not match trusted install metadata",
    )?;
    validate_optional_bootstrap_path(
        bootstrap_config.operation_status_path.as_deref(),
        &install_metadata.operation_status_path,
        "operation status path does not match trusted install metadata",
    )?;
    validate_optional_bootstrap_path(
        bootstrap_config.state_dir.as_deref(),
        &install_metadata.state_dir,
        "state dir does not match trusted install metadata",
    )?;
    if let Some(service_name) = bootstrap_config.service_name.as_deref()
        && service_name != install_metadata.service_name
    {
        return Err(ProbeUpgraderRunError::InvalidConfig(
            "service name does not match trusted install metadata",
        ));
    }
    if let Some(key_sha256) = bootstrap_config.probe_asset_public_key_sha256.as_deref()
        && !key_sha256.eq_ignore_ascii_case(&install_metadata.probe_asset_public_key_sha256)
    {
        return Err(ProbeUpgraderRunError::InvalidConfig(
            "trusted signing key does not match install metadata",
        ));
    }
    if install_metadata.schema_version == 2
        && bootstrap_config.probe_distribution_root_sha256.as_deref()
            != install_metadata.probe_distribution_root_sha256.as_deref()
    {
        return Err(ProbeUpgraderRunError::InvalidConfig(
            "Probe distribution root does not match install metadata",
        ));
    }

    Ok(())
}

fn validate_optional_bootstrap_path(
    value: Option<&str>,
    expected: &Path,
    message: &'static str,
) -> Result<(), ProbeUpgraderRunError> {
    if let Some(value) = value
        && Path::new(value) != expected
    {
        return Err(ProbeUpgraderRunError::InvalidConfig(message));
    }

    Ok(())
}

fn operation_token_validation_url(
    hub_url: &str,
    operation_id: &str,
) -> Result<String, ProbeUpgraderRunError> {
    hub_url::endpoint(
        hub_url,
        &format!("/api/probe/operations/{operation_id}/token/validate"),
    )
    .map_err(|()| ProbeUpgraderRunError::InvalidConfig("invalid Hub URL"))
}

fn operation_status_url(
    hub_url: &str,
    operation_id: &str,
) -> Result<String, ProbeUpgraderRunError> {
    hub_url::endpoint(
        hub_url,
        &format!("/api/probe/operations/{operation_id}/status"),
    )
    .map_err(|()| ProbeUpgraderRunError::InvalidConfig("invalid Hub URL"))
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn is_safe_sudoers_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn toml_string(value: &str) -> String {
    let escaped = value
        .chars()
        .flat_map(|character| character.escape_default())
        .collect::<String>();

    format!("\"{escaped}\"")
}

#[cfg(test)]
mod install_metadata_tests;
#[cfg(test)]
mod lifecycle_entry_tests;
