use std::{
    error::Error,
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

use flate2::read::GzDecoder;
use prost::Message;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    signature::Verifier,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::local_privilege_boundary::{
    CollectorHelperExposureEnvironment, CollectorHelperSudoersPlanInput,
    CollectorHelperSudoersPlanner,
};
use crate::{
    hub_url,
    probe_auth::{ProbeRequestAuth, signed_probe_request_headers},
    protocol::enoki::v1::ProbeConfigurationRequest,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderRunInput {
    pub bootstrap_config_path: PathBuf,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderResult {
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub operation_id: String,
    pub status: String,
}

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
    MissingToken,
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
            Self::MissingToken => write!(formatter, "missing Probe Operation Token on stdin"),
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
            | Self::MissingToken
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

    fn verify_service_absent(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError>;

    fn remove_service_identity(
        &mut self,
        service_user: &str,
        service_group: &str,
    ) -> Result<(), ProbeUpgraderRunError>;
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
}

struct CleanupCommandOutput {
    code: Option<i32>,
    stderr: String,
    stdout: String,
    successful: bool,
}

#[cfg(test)]
impl CleanupCommandOutput {
    fn success(stdout: &str) -> Self {
        Self {
            code: Some(0),
            stderr: String::new(),
            stdout: stdout.to_string(),
            successful: true,
        }
    }

    fn failure(code: Option<i32>, stdout: &str, stderr: &str) -> Self {
        Self {
            code,
            stderr: stderr.to_string(),
            stdout: stdout.to_string(),
            successful: false,
        }
    }
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

pub fn run_probe_upgrader(
    input: ProbeUpgraderRunInput,
    stdin: &str,
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> Result<ProbeUpgraderResult, ProbeUpgraderRunError> {
    let mut systemd = SystemProbeUpgraderSystemdRunner;
    run_probe_upgrader_with_systemd_runner(input, stdin, transport, &mut systemd)
}

pub fn run_probe_repair(
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> Result<ProbeRepairResult, ProbeRepairRunError> {
    // SAFETY: `geteuid` takes no arguments and only reads the process credentials.
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProbeRepairRunError::RootRequired);
    }
    let install_metadata =
        read_trusted_probe_install_metadata(Path::new(PRODUCTION_INSTALL_METADATA_PATH), None)?;
    let installed_version = read_installed_probe_version(&install_metadata.install_path)?;
    let mut systemd = SystemProbeUpgraderSystemdRunner;
    run_probe_repair_with_current_version_and_systemd_runner(
        &install_metadata,
        transport,
        &mut systemd,
        0,
        0,
        &installed_version,
    )
}

fn read_installed_probe_version(install_path: &Path) -> Result<String, ProbeRepairRunError> {
    const VERSION_MARKER: &[u8] = b"ENOKI_PROBE_VERSION=";
    let binary =
        fs::read(install_path).map_err(|_| ProbeRepairRunError::InstalledVersionInvalid)?;
    let versions = binary
        .windows(VERSION_MARKER.len())
        .enumerate()
        .filter_map(|(marker_index, candidate)| {
            if candidate != VERSION_MARKER {
                return None;
            }
            let value_start = marker_index + VERSION_MARKER.len();
            let tail = &binary[value_start..];
            let value_end = tail.iter().position(|byte| *byte == 0)?;
            let version = std::str::from_utf8(&tail[..value_end]).ok()?;
            parse_probe_semver(version)?;
            Some(normalized_probe_version(version).to_string())
        })
        .collect::<std::collections::BTreeSet<_>>();
    if versions.len() != 1 {
        return Err(ProbeRepairRunError::InstalledVersionInvalid);
    }
    versions
        .into_iter()
        .next()
        .ok_or(ProbeRepairRunError::InstalledVersionInvalid)
}

fn run_probe_repair_with_current_version_and_systemd_runner(
    install_metadata: &TrustedProbeInstallMetadata,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    effective_uid: u32,
    trusted_failure_marker_owner_uid: u32,
    current_probe_version: &str,
) -> Result<ProbeRepairResult, ProbeRepairRunError> {
    if effective_uid != 0 {
        return Err(ProbeRepairRunError::RootRequired);
    }
    let failed_upgrade = read_probe_repair_failure_marker_with_owner(
        install_metadata,
        trusted_failure_marker_owner_uid,
    )?;
    validate_repair_candidate_is_installed(&failed_upgrade, current_probe_version)?;
    let identity = read_probe_repair_identity(install_metadata)?;
    let identity_hub_url = identity
        .hub_url
        .as_deref()
        .ok_or(ProbeRepairRunError::IdentityIncomplete)
        .and_then(|value| {
            hub_url::normalized_base(value).map_err(|()| ProbeRepairRunError::IdentityIncomplete)
        })?;
    if identity_hub_url != install_metadata.hub_url {
        return Err(ProbeRepairRunError::IdentityHubMismatch);
    }
    validate_bootstrap_config_matches_trusted_install_metadata(&identity, install_metadata)
        .map_err(|_| ProbeRepairRunError::IdentityIncomplete)?;
    let request_auth = probe_request_auth_from_bootstrap_config(&identity)
        .map_err(|_| ProbeRepairRunError::IdentityIncomplete)?;
    transport
        .validate_probe_identity(
            &probe_identity_validation_url(&install_metadata.hub_url)?,
            &request_auth,
        )
        .map_err(|error| ProbeRepairRunError::IdentityRejected(error.to_string()))?;

    let manifest_bytes = download_hub_asset(transport, &install_metadata.hub_url, "manifest.json")?;
    let signature_bytes =
        download_hub_asset(transport, &install_metadata.hub_url, "manifest.json.sig")?;
    let public_key_bytes =
        download_hub_asset(transport, &install_metadata.hub_url, "signing-key.pem")?;
    verify_public_key_trust(
        &public_key_bytes,
        &install_metadata.probe_asset_public_key_sha256,
    )?;
    verify_manifest_signature(&manifest_bytes, &signature_bytes, &public_key_bytes)?;
    let manifest: ProbeAssetManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| ProbeUpgraderRunError::InvalidManifest("invalid JSON"))?;
    if parse_probe_semver(&manifest.version).is_none() {
        return Err(ProbeUpgraderRunError::InvalidManifest("version is not a valid SemVer").into());
    }
    validate_probe_repair_target(
        &manifest.version,
        current_probe_version,
        &failed_upgrade.target_probe_version,
    )?;
    if manifest.signature.algorithm != "rsa-sha256"
        || manifest.signature.file != "manifest.json.sig"
        || manifest.signature.public_key != "signing-key.pem"
    {
        return Err(
            ProbeUpgraderRunError::InvalidManifest("unsupported signature metadata").into(),
        );
    }
    let target = host_probe_asset_target()?;
    let asset = manifest
        .assets
        .iter()
        .find(|asset| asset.target == target)
        .ok_or(ProbeUpgraderRunError::ArchitectureMissing)?;
    validate_asset_metadata(asset)?;
    let archive = download_hub_asset(transport, &install_metadata.hub_url, &asset.file)?;
    verify_archive_sha256(&archive, &asset.sha256)?;

    fs::create_dir_all(&install_metadata.state_dir).map_err(ProbeUpgraderRunError::Io)?;
    let install_dir = install_metadata.install_path.parent().ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata("install path has no parent"),
    )?;
    fs::create_dir_all(install_dir).map_err(ProbeUpgraderRunError::Io)?;
    systemd
        .ensure_service_group(&install_metadata.service_group)
        .map_err(|error| {
            probe_repair_reconstruction_error("probe_repair_service_group_failed", error)
        })?;
    systemd
        .ensure_service_account(
            &install_metadata.service_user,
            &install_metadata.service_group,
            &install_metadata.state_dir,
            &install_metadata.identity_path,
        )
        .map_err(|error| {
            probe_repair_reconstruction_error("probe_repair_service_account_failed", error)
        })?;
    systemd
        .stop_service(&install_metadata.service_name)
        .map_err(|error| {
            probe_repair_reconstruction_error("probe_repair_service_stop_failed", error)
        })?;
    replace_installed_probe_binary(&archive, &install_metadata.install_path)?;
    write_probe_operation_sudoers(install_metadata, &install_metadata.identity_path)
        .map_err(|error| probe_repair_reconstruction_error("probe_repair_sudoers_failed", error))?;
    write_collector_helper_sudoers_from_installed_probe(install_metadata)
        .map_err(|error| probe_repair_reconstruction_error("probe_repair_sudoers_failed", error))?;
    remove_old_sudoers_paths(install_metadata)
        .map_err(|error| probe_repair_reconstruction_error("probe_repair_sudoers_failed", error))?;
    write_probe_systemd_service(install_metadata).map_err(|error| {
        probe_repair_reconstruction_error("probe_repair_service_unit_failed", error)
    })?;
    systemd.daemon_reload().map_err(|error| {
        probe_repair_reconstruction_error("probe_repair_daemon_reload_failed", error)
    })?;
    systemd
        .enable_service(&install_metadata.service_name)
        .map_err(|error| {
            probe_repair_reconstruction_error("probe_repair_service_enable_failed", error)
        })?;
    systemd
        .reset_failed(&install_metadata.service_name)
        .map_err(|error| {
            probe_repair_reconstruction_error("probe_repair_service_reset_failed", error)
        })?;
    systemd
        .restart_service(&install_metadata.service_name)
        .map_err(|error| {
            probe_repair_reconstruction_error("probe_repair_service_restart_failed", error)
        })?;

    Ok(ProbeRepairResult {
        probe_id: request_auth.probe_id.to_string(),
        repaired_version: normalized_probe_version(&manifest.version).to_string(),
    })
}

fn probe_repair_reconstruction_error(
    code: &'static str,
    error: ProbeUpgraderRunError,
) -> ProbeRepairRunError {
    ProbeRepairRunError::ServiceReconstruction {
        code,
        message: error.to_string(),
    }
}

fn probe_identity_validation_url(hub_url: &str) -> Result<String, ProbeUpgraderRunError> {
    hub_url::endpoint(hub_url, "/api/probe/config")
        .map_err(|()| ProbeUpgraderRunError::InvalidConfig("invalid Hub URL"))
}

fn write_probe_systemd_service(
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    for path in [
        &install_metadata.install_path,
        &install_metadata.identity_path,
        &install_metadata.state_dir,
        &install_metadata.service_unit_path,
    ] {
        ensure_absolute_path(path)?;
    }
    if !is_safe_sudoers_token(&install_metadata.service_user)
        || !is_safe_sudoers_token(&install_metadata.service_group)
        || !is_safe_sudoers_token(&install_metadata.service_name)
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "service identity is unsafe",
        ));
    }
    let config_dir = install_metadata.identity_path.parent().ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata("identity path has no parent"),
    )?;
    let contents = format!(
        "[Unit]\nDescription=Enoki Probe\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser={}\nGroup={}\nExecStart={} run --config {}\nRestart=always\nRestartSec=5s\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\nProtectControlGroups=true\nReadWritePaths={} {}\n\n[Install]\nWantedBy=multi-user.target\n",
        install_metadata.service_user,
        install_metadata.service_group,
        install_metadata.install_path.display(),
        install_metadata.identity_path.display(),
        install_metadata.state_dir.display(),
        config_dir.display(),
    );
    if let Some(parent) = install_metadata.service_unit_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }
    fs::write(&install_metadata.service_unit_path, contents).map_err(ProbeUpgraderRunError::Io)?;
    fs::set_permissions(
        &install_metadata.service_unit_path,
        fs::Permissions::from_mode(0o644),
    )
    .map_err(ProbeUpgraderRunError::Io)
}

#[derive(Debug)]
struct FailedProbeUpgradeMarker {
    target_probe_version: String,
}

fn read_probe_repair_failure_marker_with_owner(
    install_metadata: &TrustedProbeInstallMetadata,
    trusted_owner_uid: u32,
) -> Result<FailedProbeUpgradeMarker, ProbeRepairRunError> {
    let metadata = match fs::symlink_metadata(&install_metadata.operation_status_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProbeRepairRunError::FailureMarkerMissing);
        }
        Err(_) => return Err(ProbeRepairRunError::FailureMarkerInvalid),
    };
    read_probe_repair_failure_marker_with_file_metadata_and_owner(
        install_metadata,
        TrustedFileMetadata {
            is_regular_file: metadata.file_type().is_file(),
            is_symlink: metadata.file_type().is_symlink(),
            mode: metadata.mode() & 0o777,
            owner_uid: metadata.uid(),
        },
        trusted_owner_uid,
    )
}

#[cfg(test)]
fn read_probe_repair_failure_marker_with_file_metadata(
    install_metadata: &TrustedProbeInstallMetadata,
    file_metadata: TrustedFileMetadata,
) -> Result<FailedProbeUpgradeMarker, ProbeRepairRunError> {
    read_probe_repair_failure_marker_with_file_metadata_and_owner(
        install_metadata,
        file_metadata,
        0,
    )
}

fn read_probe_repair_failure_marker_with_file_metadata_and_owner(
    install_metadata: &TrustedProbeInstallMetadata,
    file_metadata: TrustedFileMetadata,
    trusted_owner_uid: u32,
) -> Result<FailedProbeUpgradeMarker, ProbeRepairRunError> {
    if file_metadata.is_symlink
        || !file_metadata.is_regular_file
        || file_metadata.owner_uid != trusted_owner_uid
        || file_metadata.mode != 0o644
    {
        return Err(ProbeRepairRunError::FailureMarkerInvalid);
    }
    let contents = fs::read_to_string(&install_metadata.operation_status_path)
        .map_err(|_| ProbeRepairRunError::FailureMarkerInvalid)?;
    parse_probe_repair_failure_marker(&contents)
}

fn parse_probe_repair_failure_marker(
    contents: &str,
) -> Result<FailedProbeUpgradeMarker, ProbeRepairRunError> {
    let value = contents
        .parse::<toml::Value>()
        .map_err(|_| ProbeRepairRunError::FailureMarkerInvalid)?;
    let operation_id = value
        .get("operation_id")
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ProbeRepairRunError::FailureMarkerInvalid)?;
    let target_probe_version = value
        .get("target_probe_version")
        .and_then(toml::Value::as_str)
        .filter(|value| parse_probe_semver(value).is_some())
        .ok_or(ProbeRepairRunError::FailureMarkerInvalid)?;
    let status = value
        .get("status")
        .and_then(toml::Value::as_str)
        .ok_or(ProbeRepairRunError::FailureMarkerInvalid)?;
    let error_code = value
        .get("error_code")
        .and_then(toml::Value::as_str)
        .ok_or(ProbeRepairRunError::FailureMarkerInvalid)?;
    if status != "failed"
        || !matches!(
            error_code,
            "post_replacement_restart_failure" | "post_replacement_status_write_failure"
        )
    {
        return Err(ProbeRepairRunError::FailureMarkerNotPostReplacement);
    }
    let _ = operation_id;
    Ok(FailedProbeUpgradeMarker {
        target_probe_version: normalized_probe_version(target_probe_version).to_string(),
    })
}

fn validate_repair_candidate_is_installed(
    marker: &FailedProbeUpgradeMarker,
    current_probe_version: &str,
) -> Result<(), ProbeRepairRunError> {
    let current = parse_probe_semver(current_probe_version)
        .ok_or(ProbeRepairRunError::InstalledVersionInvalid)?;
    let marked_target = parse_probe_semver(&marker.target_probe_version)
        .ok_or(ProbeRepairRunError::FailureMarkerInvalid)?;
    if marked_target != current {
        return Err(ProbeRepairRunError::CandidateNotInstalled);
    }
    Ok(())
}

fn validate_probe_repair_target(
    hub_target_version: &str,
    current_probe_version: &str,
    failed_target_version: &str,
) -> Result<(), ProbeRepairRunError> {
    let target =
        parse_probe_semver(hub_target_version).ok_or(ProbeRepairRunError::HubTargetMismatch)?;
    let current = parse_probe_semver(current_probe_version)
        .ok_or(ProbeRepairRunError::InstalledVersionInvalid)?;
    if target < current {
        return Err(ProbeRepairRunError::DowngradeRejected);
    }
    let failed_target = parse_probe_semver(failed_target_version)
        .ok_or(ProbeRepairRunError::FailureMarkerInvalid)?;
    if target != current || target != failed_target {
        return Err(ProbeRepairRunError::HubTargetMismatch);
    }
    Ok(())
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

pub fn run_probe_upgrader_with_systemd_runner(
    input: ProbeUpgraderRunInput,
    stdin: &str,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<ProbeUpgraderResult, ProbeUpgraderRunError> {
    let operation = read_operation_metadata(stdin)?;
    if operation.token.is_empty() {
        return Err(ProbeUpgraderRunError::MissingToken);
    }
    let install_metadata = read_trusted_probe_install_metadata(
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        Some(&input.bootstrap_config_path),
    )?;
    run_probe_upgrader_with_systemd_runner_and_install_metadata(
        input,
        stdin,
        transport,
        systemd,
        &install_metadata,
    )
}

fn run_probe_upgrader_with_systemd_runner_and_install_metadata(
    input: ProbeUpgraderRunInput,
    stdin: &str,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<ProbeUpgraderResult, ProbeUpgraderRunError> {
    let operation = read_operation_metadata(stdin)?;
    if operation.token.is_empty() {
        return Err(ProbeUpgraderRunError::MissingToken);
    }

    validate_identity_path(&input.bootstrap_config_path, install_metadata)?;
    let bootstrap_config = read_upgrader_bootstrap_config(&input.bootstrap_config_path)?;
    validate_bootstrap_config_matches_trusted_install_metadata(
        &bootstrap_config,
        install_metadata,
    )?;
    let hub_url = &install_metadata.hub_url;
    let request_auth = probe_request_auth_from_bootstrap_config(&bootstrap_config)?;
    let body = format!(
        "{{\"targetProbeVersion\":\"{}\",\"token\":\"{}\"}}",
        json_string_fragment(&operation.target_probe_version),
        json_string_fragment(&operation.token),
    );

    transport.post_token_validation(
        &operation_token_validation_url(hub_url, &operation.operation_id)?,
        &request_auth,
        &body,
    )?;

    if let Err(error) = execute_probe_upgrade(
        &operation,
        &bootstrap_config,
        &input.bootstrap_config_path,
        install_metadata,
        transport,
        systemd,
    ) {
        let failed = failed_probe_upgrader_result(&operation, &error);
        let _ = write_failed_local_operation_status(&operation, install_metadata, &failed);
        if let Ok(status_url) = operation_status_url(hub_url, &operation.operation_id) {
            let body = render_operation_status_body(&operation.token, "failed", Some(&failed));
            let _ = transport.post_operation_status(&status_url, &request_auth, &body);
        }
        return Ok(failed);
    }

    Ok(ProbeUpgraderResult {
        error_code: None,
        message: None,
        operation_id: operation.operation_id,
        status: "running".to_string(),
    })
}

pub fn run_probe_uninstaller(
    input: ProbeUninstallerRunInput,
    stdin: &str,
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> Result<ProbeUpgraderResult, ProbeUpgraderRunError> {
    let mut systemd = SystemProbeUpgraderSystemdRunner;
    run_probe_uninstaller_with_systemd_runner(input, stdin, transport, &mut systemd)
}

pub fn run_probe_uninstaller_with_systemd_runner(
    input: ProbeUninstallerRunInput,
    stdin: &str,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<ProbeUpgraderResult, ProbeUpgraderRunError> {
    let operation = read_uninstall_operation_metadata(stdin)?;
    if operation.token.is_empty() {
        return Err(ProbeUpgraderRunError::MissingToken);
    }
    let install_metadata = read_trusted_probe_install_metadata(
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        Some(&input.bootstrap_config_path),
    )?;
    run_probe_uninstaller_with_systemd_runner_and_install_metadata(
        input,
        stdin,
        transport,
        systemd,
        &install_metadata,
    )
}

fn run_probe_uninstaller_with_systemd_runner_and_install_metadata(
    input: ProbeUninstallerRunInput,
    stdin: &str,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<ProbeUpgraderResult, ProbeUpgraderRunError> {
    let operation = read_uninstall_operation_metadata(stdin)?;
    if operation.token.is_empty() {
        return Err(ProbeUpgraderRunError::MissingToken);
    }

    validate_identity_path(&input.bootstrap_config_path, install_metadata)?;
    let bootstrap_config = read_upgrader_bootstrap_config(&input.bootstrap_config_path)?;
    validate_bootstrap_config_matches_trusted_install_metadata(
        &bootstrap_config,
        install_metadata,
    )?;
    let hub_url = &install_metadata.hub_url;
    let request_auth = probe_request_auth_from_bootstrap_config(&bootstrap_config)?;

    let token_body = format!(
        "{{\"token\":\"{}\"}}",
        json_string_fragment(&operation.token)
    );
    transport.post_token_validation(
        &operation_token_validation_url(hub_url, &operation.operation_id)?,
        &request_auth,
        &token_body,
    )?;

    let status_url = operation_status_url(hub_url, &operation.operation_id)?;

    if let Err(error) = execute_probe_uninstall(&input, install_metadata, systemd) {
        let failed = failed_probe_uninstaller_result(&operation, &error);
        let body = render_operation_status_body(&operation.token, "failed", Some(&failed));
        let _ = transport.post_operation_status(&status_url, &request_auth, &body);
        return Ok(failed);
    }

    let body = render_operation_status_body(&operation.token, "succeeded", None);
    transport.post_operation_status(&status_url, &request_auth, &body)?;

    Ok(ProbeUpgraderResult {
        error_code: None,
        message: None,
        operation_id: operation.operation_id,
        status: "succeeded".to_string(),
    })
}

fn execute_probe_uninstall(
    input: &ProbeUninstallerRunInput,
    install_metadata: &TrustedProbeInstallMetadata,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    execute_probe_uninstall_with_install_metadata_path(
        input,
        install_metadata,
        systemd,
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
    )
}

fn execute_probe_uninstall_with_install_metadata_path(
    input: &ProbeUninstallerRunInput,
    install_metadata: &TrustedProbeInstallMetadata,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    install_metadata_path: &Path,
) -> Result<(), ProbeUpgraderRunError> {
    ensure_absolute_path(&input.bootstrap_config_path)?;
    systemd
        .stop_service(&install_metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_stop_failed",
                "stopping the service",
                error,
            )
        })?;
    systemd
        .disable_service(&install_metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_disable_failed",
                "disabling the service",
                error,
            )
        })?;
    remove_path_if_exists(&install_metadata.service_unit_path).map_err(|error| {
        probe_uninstall_cleanup_error(
            "probe_uninstall_service_unit_remove_failed",
            "removing the service unit",
            error,
        )
    })?;
    verify_path_absent(
        &install_metadata.service_unit_path,
        "probe_uninstall_service_unit_residue",
        "verifying the service unit is absent",
    )?;
    systemd.daemon_reload().map_err(|error| {
        probe_uninstall_cleanup_error(
            "probe_uninstall_daemon_reload_failed",
            "reloading systemd",
            error,
        )
    })?;
    systemd
        .reset_failed(&install_metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_reset_failed",
                "resetting the failed service state",
                error,
            )
        })?;
    systemd
        .verify_service_absent(&install_metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_verification_failed",
                "verifying the service is absent",
                error,
            )
        })?;
    remove_path_if_exists(&install_metadata.install_path)?;
    remove_path_if_exists(&install_metadata.operation_sudoers_path)?;
    remove_path_if_exists(&install_metadata.collector_helper_sudoers_path)?;
    for path in &install_metadata.old_sudoers_paths {
        remove_path_if_exists(path)?;
    }
    remove_path_if_exists(install_metadata_path)?;
    remove_path_if_exists(&input.bootstrap_config_path)?;
    remove_empty_parent_dir(&input.bootstrap_config_path)?;
    remove_path_if_exists(&install_metadata.state_dir)?;
    systemd
        .remove_service_identity(
            &install_metadata.service_user,
            &install_metadata.service_group,
        )
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_account_remove_failed",
                "removing the service account",
                error,
            )
        })?;

    Ok(())
}

fn probe_uninstall_cleanup_error(
    code: &'static str,
    action: &'static str,
    error: ProbeUpgraderRunError,
) -> ProbeUpgraderRunError {
    match error {
        ProbeUpgraderRunError::UninstallCleanupFailure { .. } => error,
        ProbeUpgraderRunError::RestartFailure(message) => {
            ProbeUpgraderRunError::UninstallCleanupFailure {
                action,
                code,
                message,
            }
        }
        _ => ProbeUpgraderRunError::UninstallCleanupFailure {
            action,
            code,
            message: error.to_string(),
        },
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

fn render_operation_status_body(
    token: &str,
    status: &str,
    failure: Option<&ProbeUpgraderResult>,
) -> String {
    if let Some(failure) = failure {
        return format!(
            "{{\"errorCode\":\"{}\",\"message\":\"{}\",\"status\":\"{}\",\"token\":\"{}\"}}",
            json_string_fragment(
                failure
                    .error_code
                    .as_deref()
                    .unwrap_or("probe_operation_failed")
            ),
            json_string_fragment(failure.message.as_deref().unwrap_or("")),
            json_string_fragment(status),
            json_string_fragment(token),
        );
    }

    format!(
        "{{\"status\":\"{}\",\"token\":\"{}\"}}",
        json_string_fragment(status),
        json_string_fragment(token),
    )
}

struct ProbeUpgraderOperationMetadata {
    operation_id: String,
    target_probe_version: String,
    token: String,
}

struct ProbeUninstallerOperationMetadata {
    operation_id: String,
    token: String,
}

fn read_operation_metadata(
    stdin: &str,
) -> Result<ProbeUpgraderOperationMetadata, ProbeUpgraderRunError> {
    if stdin.trim().is_empty() {
        return Err(ProbeUpgraderRunError::MissingToken);
    }

    let value = stdin
        .parse::<toml::Value>()
        .map_err(|_| ProbeUpgraderRunError::InvalidMetadata("invalid TOML"))?;
    let operation_id = required_metadata_string(&value, "operation_id")?;
    let target_probe_version = required_metadata_string(&value, "target_probe_version")?;
    let token = required_metadata_string(&value, "token")?;

    Ok(ProbeUpgraderOperationMetadata {
        operation_id,
        target_probe_version,
        token,
    })
}

fn read_uninstall_operation_metadata(
    stdin: &str,
) -> Result<ProbeUninstallerOperationMetadata, ProbeUpgraderRunError> {
    if stdin.trim().is_empty() {
        return Err(ProbeUpgraderRunError::MissingToken);
    }

    let value = stdin
        .parse::<toml::Value>()
        .map_err(|_| ProbeUpgraderRunError::InvalidMetadata("invalid TOML"))?;
    let operation_id = required_metadata_string(&value, "operation_id")?;
    let token = required_metadata_string(&value, "token")?;

    Ok(ProbeUninstallerOperationMetadata {
        operation_id,
        token,
    })
}

fn required_metadata_string(
    value: &toml::Value,
    key: &'static str,
) -> Result<String, ProbeUpgraderRunError> {
    match value.get(key) {
        Some(toml::Value::String(string)) => Ok(string.clone()),
        Some(_) => Err(ProbeUpgraderRunError::InvalidMetadata(
            "expected string values",
        )),
        None => Err(ProbeUpgraderRunError::InvalidMetadata("missing field")),
    }
}

#[derive(Debug)]
struct ProbeUpgraderBootstrapConfig {
    hub_url: Option<String>,
    install_path: Option<String>,
    operation_status_path: Option<String>,
    probe_asset_public_key_sha256: Option<String>,
    probe_id: Option<String>,
    probe_private_key_pem: Option<String>,
    server_time_offset_ms: Option<i64>,
    service_name: Option<String>,
    state_dir: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustedProbeInstallMetadata {
    schema_version: u32,
    hub_url: String,
    identity_path: PathBuf,
    install_path: PathBuf,
    operation_status_path: PathBuf,
    probe_asset_public_key_sha256: String,
    service_name: String,
    service_group: String,
    service_unit_path: PathBuf,
    service_user: String,
    state_dir: PathBuf,
    operation_sudoers_path: PathBuf,
    collector_helper_sudoers_path: PathBuf,
    old_sudoers_paths: Vec<PathBuf>,
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
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    read_trusted_probe_install_metadata_with_file_metadata(
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

fn read_trusted_probe_install_metadata_with_file_metadata(
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
    let mut metadata =
        parse_trusted_probe_install_metadata_with_legacy_identity(&contents, legacy_identity_path)?;
    if metadata.schema_version == 1 {
        if file_metadata.mode != 0o600 {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "schema v1 metadata mode must be 0600",
            ));
        }
    } else {
        if !matches!(file_metadata.mode, 0o600 | 0o644) {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "legacy metadata mode is not supported",
            ));
        }
        write_trusted_probe_install_metadata(path, &metadata)?;
        metadata.schema_version = 1;
    }
    Ok(metadata)
}

#[cfg(test)]
fn parse_trusted_probe_install_metadata(
    contents: &str,
) -> Result<TrustedProbeInstallMetadata, ProbeUpgraderRunError> {
    parse_trusted_probe_install_metadata_with_legacy_identity(contents, None)
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
    let hub_url = required_install_metadata_string(&value, "hub_url")?;
    let operation_status_path = required_install_metadata_path(&value, "operation_status_path")?;
    let state_dir = required_install_metadata_path(&value, "state_dir")?;
    if value.get("sudoers_path").is_some() {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "old sudoers_path metadata is not supported",
        ));
    }
    let operation_sudoers_path = required_install_metadata_path(&value, "operation_sudoers_path")?;
    let collector_helper_sudoers_path =
        required_install_metadata_path(&value, "collector_helper_sudoers_path")?;
    let service_name = required_install_metadata_string(&value, "service_name")?;
    let service_user = optional_install_metadata_string(&value, "service_user")?
        .unwrap_or_else(|| "enoki-probe".to_string());
    let identity_path = if schema_version == 1 {
        required_install_metadata_path(&value, "identity_path")?
    } else {
        legacy_identity_path
            .unwrap_or_else(|| Path::new("/etc/enoki/probe-bootstrap.toml"))
            .to_path_buf()
    };
    let service_group = if schema_version == 1 {
        required_install_metadata_string(&value, "service_group")?
    } else {
        service_user.clone()
    };
    let service_unit_path = if schema_version == 1 {
        required_install_metadata_path(&value, "service_unit_path")?
    } else {
        PathBuf::from("/etc/systemd/system/enoki-probe.service")
    };
    let probe_asset_public_key_sha256 =
        required_install_metadata_string(&value, "probe_asset_public_key_sha256")?;

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
    if !is_sha256_hex(&probe_asset_public_key_sha256) {
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
        service_name,
        service_group,
        service_unit_path,
        service_user,
        state_dir,
        operation_sudoers_path,
        collector_helper_sudoers_path,
        old_sudoers_paths: vec![PathBuf::from(PRODUCTION_LEGACY_UPGRADER_SUDOERS_PATH)],
    })
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
            toml_string(&metadata.operation_sudoers_path.display().to_string())
        ),
        format!(
            "collector_helper_sudoers_path = {}",
            toml_string(&metadata.collector_helper_sudoers_path.display().to_string())
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

#[derive(Deserialize)]
struct ProbeAssetManifest {
    assets: Vec<ProbeAssetManifestAsset>,
    signature: ProbeAssetManifestSignature,
    version: String,
}

#[derive(Deserialize)]
struct ProbeAssetManifestAsset {
    file: String,
    sha256: String,
    target: String,
}

#[derive(Deserialize)]
struct ProbeAssetManifestSignature {
    algorithm: String,
    file: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

fn execute_probe_upgrade(
    operation: &ProbeUpgraderOperationMetadata,
    bootstrap_config: &ProbeUpgraderBootstrapConfig,
    bootstrap_config_path: &Path,
    install_metadata: &TrustedProbeInstallMetadata,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    execute_probe_upgrade_with_current_version(
        operation,
        bootstrap_config,
        bootstrap_config_path,
        install_metadata,
        transport,
        systemd,
        crate::version::probe_version(),
    )
}

fn execute_probe_upgrade_with_current_version(
    operation: &ProbeUpgraderOperationMetadata,
    bootstrap_config: &ProbeUpgraderBootstrapConfig,
    bootstrap_config_path: &Path,
    install_metadata: &TrustedProbeInstallMetadata,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    current_probe_version: &str,
) -> Result<(), ProbeUpgraderRunError> {
    validate_bootstrap_config_matches_trusted_install_metadata(bootstrap_config, install_metadata)?;
    let hub_url = &install_metadata.hub_url;

    let manifest_bytes = download_hub_asset(transport, hub_url, "manifest.json")?;
    let signature_bytes = download_hub_asset(transport, hub_url, "manifest.json.sig")?;
    let public_key_bytes = download_hub_asset(transport, hub_url, "signing-key.pem")?;

    verify_public_key_trust(
        &public_key_bytes,
        &install_metadata.probe_asset_public_key_sha256,
    )?;
    verify_manifest_signature(&manifest_bytes, &signature_bytes, &public_key_bytes)?;

    let manifest: ProbeAssetManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| ProbeUpgraderRunError::InvalidManifest("invalid JSON"))?;
    if normalized_probe_version(&manifest.version)
        != normalized_probe_version(&operation.target_probe_version)
    {
        return Err(ProbeUpgraderRunError::TargetMismatch);
    }
    validate_probe_upgrade_target_is_newer(&manifest.version, current_probe_version)?;
    if manifest.signature.algorithm != "rsa-sha256"
        || manifest.signature.file != "manifest.json.sig"
        || manifest.signature.public_key != "signing-key.pem"
    {
        return Err(ProbeUpgraderRunError::InvalidManifest(
            "unsupported signature metadata",
        ));
    }

    let target = host_probe_asset_target()?;
    let asset = manifest
        .assets
        .iter()
        .find(|asset| asset.target == target)
        .ok_or(ProbeUpgraderRunError::ArchitectureMissing)?;
    validate_asset_metadata(asset)?;

    let archive = download_hub_asset(transport, hub_url, &asset.file)?;
    verify_archive_sha256(&archive, &asset.sha256)?;
    preflight_local_operation_status_writable(install_metadata)?;
    replace_installed_probe_binary(&archive, &install_metadata.install_path)?;
    write_probe_operation_sudoers(install_metadata, bootstrap_config_path)?;
    write_collector_helper_sudoers_from_installed_probe(install_metadata)?;
    remove_old_sudoers_paths(install_metadata)?;
    write_local_operation_status(operation, install_metadata).map_err(|error| {
        ProbeUpgraderRunError::PostReplacementStatusWriteFailure(error.to_string())
    })?;
    systemd
        .restart_service(&install_metadata.service_name)
        .map_err(|error| ProbeUpgraderRunError::PostReplacementRestartFailure(error.to_string()))?;

    Ok(())
}

fn write_probe_operation_sudoers(
    install_metadata: &TrustedProbeInstallMetadata,
    bootstrap_config_path: &Path,
) -> Result<(), ProbeUpgraderRunError> {
    ensure_absolute_path(bootstrap_config_path)?;
    let lines = render_probe_operation_sudoers_lines(install_metadata, bootstrap_config_path)?;

    let sudoers_path = &install_metadata.operation_sudoers_path;
    if let Some(parent) = sudoers_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }

    fs::write(sudoers_path, lines.join("\n")).map_err(ProbeUpgraderRunError::Io)?;
    fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o440))
        .map_err(ProbeUpgraderRunError::Io)
}

#[cfg(test)]
fn write_collector_helper_sudoers(
    install_metadata: &TrustedProbeInstallMetadata,
    collector_helper_environment: &dyn CollectorHelperExposureEnvironment,
) -> Result<(), ProbeUpgraderRunError> {
    let plan = CollectorHelperSudoersPlanner::new(collector_helper_environment).plan(
        CollectorHelperSudoersPlanInput {
            service_user: install_metadata.service_user.clone(),
            probe_binary: install_metadata.install_path.clone(),
        },
    );
    let sudoers_path = &install_metadata.collector_helper_sudoers_path;
    if let Some(parent) = sudoers_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }

    let Some(content) = plan.content else {
        return remove_path_if_exists(sudoers_path);
    };

    fs::write(sudoers_path, content).map_err(ProbeUpgraderRunError::Io)?;
    fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o440))
        .map_err(ProbeUpgraderRunError::Io)
}

fn write_collector_helper_sudoers_from_installed_probe(
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    let output = Command::new(&install_metadata.install_path)
        .arg("internal-render-collector-helper-sudoers")
        .arg("--service-user")
        .arg(&install_metadata.service_user)
        .arg("--probe-binary")
        .arg(&install_metadata.install_path)
        .output()
        .map_err(ProbeUpgraderRunError::Io)?;

    if !output.status.success() {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "collector-helper sudoers planner failed",
        ));
    }

    let content = String::from_utf8(output.stdout).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata(
            "collector-helper sudoers planner output is not UTF-8",
        )
    })?;
    let sudoers_path = &install_metadata.collector_helper_sudoers_path;
    if content.is_empty() {
        return remove_path_if_exists(sudoers_path);
    }

    if let Some(parent) = sudoers_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }

    fs::write(sudoers_path, content).map_err(ProbeUpgraderRunError::Io)?;
    fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o440))
        .map_err(ProbeUpgraderRunError::Io)
}

fn remove_old_sudoers_paths(
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    for path in &install_metadata.old_sudoers_paths {
        if path != &install_metadata.operation_sudoers_path
            && path != &install_metadata.collector_helper_sudoers_path
        {
            remove_path_if_exists(path)?;
        }
    }

    Ok(())
}

fn render_probe_operation_sudoers_lines(
    install_metadata: &TrustedProbeInstallMetadata,
    bootstrap_config_path: &Path,
) -> Result<Vec<String>, ProbeUpgraderRunError> {
    if !is_safe_sudoers_path(&install_metadata.install_path)
        || !is_safe_sudoers_path(bootstrap_config_path)
        || !is_safe_sudoers_token(&install_metadata.service_user)
        || !is_safe_sudoers_token(&install_metadata.service_name)
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "sudoers command contains unsafe values",
        ));
    }

    let mut lines = vec![
        "# Managed by Enoki Probe installer.".to_string(),
        format!(
            "{} ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit={}-upgrader --property=Type=exec -- {} internal-upgrader --config {}",
            install_metadata.service_user,
            install_metadata.service_name,
            install_metadata.install_path.display(),
            bootstrap_config_path.display(),
        ),
        format!(
            "{} ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit={}-uninstaller --property=Type=exec -- {} internal-uninstaller --config {}",
            install_metadata.service_user,
            install_metadata.service_name,
            install_metadata.install_path.display(),
            bootstrap_config_path.display(),
        ),
    ];
    lines.push(String::new());

    Ok(lines)
}

fn normalized_probe_version(value: &str) -> &str {
    value.strip_prefix('v').unwrap_or(value)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProbeSemVer {
    major: u64,
    minor: u64,
    patch: u64,
}

fn validate_probe_upgrade_target_is_newer(
    target_version: &str,
    current_probe_version: &str,
) -> Result<(), ProbeUpgraderRunError> {
    if current_probe_version == "dev" {
        return Ok(());
    }

    let target = parse_probe_semver(target_version).ok_or(
        ProbeUpgraderRunError::InvalidManifest("target version is not a valid SemVer"),
    )?;
    let current = parse_probe_semver(current_probe_version).ok_or(
        ProbeUpgraderRunError::InvalidConfig("current Probe version is not a valid SemVer"),
    )?;
    if target <= current {
        return Err(ProbeUpgraderRunError::DowngradeRejected);
    }

    Ok(())
}

fn parse_probe_semver(value: &str) -> Option<ProbeSemVer> {
    let mut parts = normalized_probe_version(value).split('.');
    let major = parse_semver_number(parts.next()?)?;
    let minor = parse_semver_number(parts.next()?)?;
    let patch = parse_semver_number(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }

    Some(ProbeSemVer {
        major,
        minor,
        patch,
    })
}

fn parse_semver_number(value: &str) -> Option<u64> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok()
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

fn download_hub_asset(
    transport: &mut impl ProbeUpgraderValidationTransport,
    hub_url: &str,
    file_name: &str,
) -> Result<Vec<u8>, ProbeUpgraderRunError> {
    if !is_safe_asset_file_name(file_name) {
        return Err(ProbeUpgraderRunError::AssetMissing);
    }

    transport.get_asset(&hub_asset_url(hub_url, file_name)?)
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

fn hub_asset_url(hub_url: &str, file_name: &str) -> Result<String, ProbeUpgraderRunError> {
    hub_url::endpoint(hub_url, &format!("/api/probe/assets/{file_name}"))
        .map_err(|()| ProbeUpgraderRunError::InvalidConfig("invalid Hub URL"))
}

fn verify_public_key_trust(public_key: &[u8], expected: &str) -> Result<(), ProbeUpgraderRunError> {
    if !is_sha256_hex(expected) {
        return Err(ProbeUpgraderRunError::InvalidConfig(
            "trusted Probe asset signing key fingerprint is not a valid sha256 value",
        ));
    }
    let actual = hex_sha256(public_key);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(ProbeUpgraderRunError::SigningKeyUntrusted);
    }

    Ok(())
}

fn verify_manifest_signature(
    manifest: &[u8],
    signature: &[u8],
    public_key_pem: &[u8],
) -> Result<(), ProbeUpgraderRunError> {
    let public_key_pem =
        std::str::from_utf8(public_key_pem).map_err(|_| ProbeUpgraderRunError::SignatureFailure)?;
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|_| ProbeUpgraderRunError::SignatureFailure)?;
    let signature = RsaPkcs1v15Signature::try_from(signature)
        .map_err(|_| ProbeUpgraderRunError::SignatureFailure)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    verifying_key
        .verify(manifest, &signature)
        .map_err(|_| ProbeUpgraderRunError::SignatureFailure)
}

fn validate_asset_metadata(asset: &ProbeAssetManifestAsset) -> Result<(), ProbeUpgraderRunError> {
    if !is_safe_asset_file_name(&asset.file) {
        return Err(ProbeUpgraderRunError::AssetMissing);
    }
    if !is_sha256_hex(&asset.sha256) {
        return Err(ProbeUpgraderRunError::InvalidManifest(
            "asset sha256 is not valid",
        ));
    }

    Ok(())
}

fn verify_archive_sha256(archive: &[u8], expected: &str) -> Result<(), ProbeUpgraderRunError> {
    if hex_sha256(archive).eq_ignore_ascii_case(expected) {
        return Ok(());
    }

    Err(ProbeUpgraderRunError::ChecksumFailure)
}

fn replace_installed_probe_binary(
    archive: &[u8],
    install_path: &Path,
) -> Result<(), ProbeUpgraderRunError> {
    let install_dir = install_path
        .parent()
        .ok_or(ProbeUpgraderRunError::InvalidConfig("invalid install path"))?;
    let work_dir = install_dir.join(".enoki-probe-upgrade");
    if work_dir.exists() {
        fs::remove_dir_all(&work_dir).map_err(ProbeUpgraderRunError::Io)?;
    }
    fs::create_dir_all(&work_dir).map_err(ProbeUpgraderRunError::Io)?;

    let decoder = GzDecoder::new(archive);
    let mut archive = tar::Archive::new(decoder);
    let staged_binary = work_dir.join("enoki-probe.new");
    extract_probe_binary_to_staged_path(&mut archive, &staged_binary)?;
    fs::set_permissions(&staged_binary, fs::Permissions::from_mode(0o755))
        .map_err(ProbeUpgraderRunError::Io)?;
    fs::rename(&staged_binary, install_path).map_err(ProbeUpgraderRunError::Io)?;
    fs::remove_dir_all(&work_dir).map_err(ProbeUpgraderRunError::Io)?;

    Ok(())
}

fn extract_probe_binary_to_staged_path(
    archive: &mut tar::Archive<GzDecoder<&[u8]>>,
    staged_binary: &Path,
) -> Result<(), ProbeUpgraderRunError> {
    let mut found = false;
    let entries = archive
        .entries()
        .map_err(|_| ProbeUpgraderRunError::AssetMissing)?;

    for entry in entries {
        let mut entry = entry.map_err(|_| ProbeUpgraderRunError::UnsafeArchive("invalid entry"))?;
        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() {
            return Err(ProbeUpgraderRunError::UnsafeArchive(
                "archive entries must be regular files",
            ));
        }
        let path = entry
            .path()
            .map_err(|_| ProbeUpgraderRunError::UnsafeArchive("invalid entry path"))?;
        if !is_expected_probe_archive_path(&path) {
            return Err(ProbeUpgraderRunError::UnsafeArchive(
                "archive may only contain enoki-probe at the archive root",
            ));
        }
        if found {
            return Err(ProbeUpgraderRunError::UnsafeArchive(
                "archive contains duplicate enoki-probe entries",
            ));
        }

        let mut output = fs::File::create(staged_binary).map_err(ProbeUpgraderRunError::Io)?;
        std::io::copy(&mut entry, &mut output).map_err(ProbeUpgraderRunError::Io)?;
        found = true;
    }

    if found {
        Ok(())
    } else {
        Err(ProbeUpgraderRunError::AssetMissing)
    }
}

fn is_expected_probe_archive_path(path: &Path) -> bool {
    let mut normal_components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => normal_components.push(value),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
        }
    }

    normal_components.as_slice() == [std::ffi::OsStr::new("enoki-probe")]
}

fn preflight_local_operation_status_writable(
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    let status_path = operation_status_path(install_metadata);
    prepare_local_operation_status_path(&status_path)?;
    open_local_operation_status_for_append(&status_path)?;
    set_operation_status_permissions(&status_path)?;

    Ok(())
}

fn write_local_operation_status(
    operation: &ProbeUpgraderOperationMetadata,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    let status_path = operation_status_path(install_metadata);
    write_local_operation_status_contents(
        &status_path,
        &[
            format!("operation_id = {}", toml_string(&operation.operation_id)),
            format!(
                "target_probe_version = {}",
                toml_string(&operation.target_probe_version),
            ),
            "status = \"running\"".to_string(),
            String::new(),
        ]
        .join("\n"),
    )?;
    set_operation_status_permissions(&status_path)
}

fn write_failed_local_operation_status(
    operation: &ProbeUpgraderOperationMetadata,
    install_metadata: &TrustedProbeInstallMetadata,
    result: &ProbeUpgraderResult,
) -> Result<(), ProbeUpgraderRunError> {
    let status_path = operation_status_path(install_metadata);
    write_local_operation_status_contents(
        &status_path,
        &[
            format!("operation_id = {}", toml_string(&operation.operation_id)),
            format!(
                "target_probe_version = {}",
                toml_string(&operation.target_probe_version),
            ),
            "status = \"failed\"".to_string(),
            format!(
                "error_code = {}",
                toml_string(
                    result
                        .error_code
                        .as_deref()
                        .unwrap_or("probe_upgrader_failed")
                ),
            ),
            format!(
                "message = {}",
                toml_string(result.message.as_deref().unwrap_or(""))
            ),
            String::new(),
        ]
        .join("\n"),
    )?;
    set_operation_status_permissions(&status_path)
}

fn prepare_local_operation_status_path(status_path: &Path) -> Result<(), ProbeUpgraderRunError> {
    if let Some(parent) = status_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
        validate_local_operation_status_parent(parent)?;
    }
    reject_local_operation_status_symlink(status_path)?;

    Ok(())
}

#[cfg(unix)]
fn validate_local_operation_status_parent(parent: &Path) -> Result<(), ProbeUpgraderRunError> {
    let metadata = fs::symlink_metadata(parent).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "operation status parent must be a directory",
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "operation status parent must not be writable by group or other",
        ));
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_local_operation_status_parent(_parent: &Path) -> Result<(), ProbeUpgraderRunError> {
    Ok(())
}

#[cfg(unix)]
fn reject_local_operation_status_symlink(status_path: &Path) -> Result<(), ProbeUpgraderRunError> {
    match fs::symlink_metadata(status_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "operation status path must not be a symlink",
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ProbeUpgraderRunError::Io(error)),
    }
}

#[cfg(not(unix))]
fn reject_local_operation_status_symlink(_status_path: &Path) -> Result<(), ProbeUpgraderRunError> {
    Ok(())
}

#[cfg(unix)]
fn open_local_operation_status_for_append(status_path: &Path) -> Result<(), ProbeUpgraderRunError> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(status_path)
        .map(|_| ())
        .map_err(ProbeUpgraderRunError::Io)
}

#[cfg(not(unix))]
fn open_local_operation_status_for_append(status_path: &Path) -> Result<(), ProbeUpgraderRunError> {
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(status_path)
        .map(|_| ())
        .map_err(ProbeUpgraderRunError::Io)
}

#[cfg(unix)]
fn write_local_operation_status_contents(
    status_path: &Path,
    contents: &str,
) -> Result<(), ProbeUpgraderRunError> {
    use std::os::unix::fs::OpenOptionsExt;

    prepare_local_operation_status_path(status_path)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(status_path)
        .map_err(ProbeUpgraderRunError::Io)?;
    file.write_all(contents.as_bytes())
        .map_err(ProbeUpgraderRunError::Io)
}

#[cfg(not(unix))]
fn write_local_operation_status_contents(
    status_path: &Path,
    contents: &str,
) -> Result<(), ProbeUpgraderRunError> {
    prepare_local_operation_status_path(status_path)?;
    fs::write(status_path, contents).map_err(ProbeUpgraderRunError::Io)
}

fn set_operation_status_permissions(status_path: &Path) -> Result<(), ProbeUpgraderRunError> {
    fs::set_permissions(status_path, fs::Permissions::from_mode(0o644))
        .map_err(ProbeUpgraderRunError::Io)
}

fn failed_probe_upgrader_result(
    operation: &ProbeUpgraderOperationMetadata,
    error: &ProbeUpgraderRunError,
) -> ProbeUpgraderResult {
    ProbeUpgraderResult {
        error_code: Some(probe_upgrader_error_code(error).to_string()),
        message: Some(error.to_string()),
        operation_id: operation.operation_id.clone(),
        status: "failed".to_string(),
    }
}

fn failed_probe_uninstaller_result(
    operation: &ProbeUninstallerOperationMetadata,
    error: &ProbeUpgraderRunError,
) -> ProbeUpgraderResult {
    ProbeUpgraderResult {
        error_code: Some(probe_upgrader_error_code(error).to_string()),
        message: Some(error.to_string()),
        operation_id: operation.operation_id.clone(),
        status: "failed".to_string(),
    }
}

fn probe_upgrader_error_code(error: &ProbeUpgraderRunError) -> &'static str {
    match error {
        ProbeUpgraderRunError::ArchitectureMissing => "architecture_missing",
        ProbeUpgraderRunError::AssetMissing => "asset_missing",
        ProbeUpgraderRunError::ChecksumFailure => "checksum_failure",
        ProbeUpgraderRunError::PostReplacementRestartFailure(_) => {
            "post_replacement_restart_failure"
        }
        ProbeUpgraderRunError::PostReplacementStatusWriteFailure(_) => {
            "post_replacement_status_write_failure"
        }
        ProbeUpgraderRunError::RestartFailure(_) => "restart_failure",
        ProbeUpgraderRunError::SignatureFailure => "signature_failure",
        ProbeUpgraderRunError::SigningKeyUntrusted => "signing_key_untrusted",
        ProbeUpgraderRunError::DowngradeRejected => "downgrade_rejected",
        ProbeUpgraderRunError::TargetMismatch => "target_mismatch",
        ProbeUpgraderRunError::UninstallCleanupFailure { code, .. } => code,
        ProbeUpgraderRunError::UninstallStatusReportFailure(_) => "uninstall_status_report_failure",
        ProbeUpgraderRunError::UnsafeArchive(_) => "unsafe_archive",
        ProbeUpgraderRunError::UnsupportedArchitecture(_) => "unsupported_architecture",
        ProbeUpgraderRunError::InvalidConfig(_)
        | ProbeUpgraderRunError::InvalidInstallMetadata(_)
        | ProbeUpgraderRunError::InvalidManifest(_)
        | ProbeUpgraderRunError::InvalidMetadata(_)
        | ProbeUpgraderRunError::InvalidSigningKey(_)
        | ProbeUpgraderRunError::IdentityValidation(_)
        | ProbeUpgraderRunError::Io(_)
        | ProbeUpgraderRunError::MissingToken
        | ProbeUpgraderRunError::TokenValidation(_) => "probe_upgrader_failed",
    }
}

fn operation_status_path(install_metadata: &TrustedProbeInstallMetadata) -> PathBuf {
    install_metadata.operation_status_path.clone()
}

fn host_probe_asset_target() -> Result<&'static str, ProbeUpgraderRunError> {
    probe_asset_target_for_arch_and_abi(std::env::consts::ARCH, detect_linux_abi())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxAbi {
    Gnu,
    Musl,
}

fn detect_linux_abi() -> LinuxAbi {
    if command_output_contains_success("getconf", &["GNU_LIBC_VERSION"], "") {
        return LinuxAbi::Gnu;
    }

    if command_output_contains_success("ldd", &["--version"], "musl") {
        return LinuxAbi::Musl;
    }

    if has_musl_loader("/lib") || has_musl_loader("/usr/lib") {
        return LinuxAbi::Musl;
    }

    LinuxAbi::Gnu
}

fn command_output_contains_success(command: &str, args: &[&str], needle: &str) -> bool {
    let Ok(output) = Command::new(command).args(args).output() else {
        return false;
    };

    if !output.status.success() {
        return false;
    }

    needle.is_empty()
        || String::from_utf8_lossy(&output.stdout)
            .to_ascii_lowercase()
            .contains(needle)
        || String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains(needle)
}

fn has_musl_loader(directory: &str) -> bool {
    let Ok(entries) = fs::read_dir(directory) else {
        return false;
    };

    entries.flatten().any(|entry| {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        file_name.starts_with("ld-musl-") && file_name.ends_with(".so.1")
    })
}

fn probe_asset_target_for_arch_and_abi(
    architecture: &str,
    abi: LinuxAbi,
) -> Result<&'static str, ProbeUpgraderRunError> {
    match (architecture, abi) {
        ("x86_64", LinuxAbi::Gnu) => Ok("x86_64-unknown-linux-gnu"),
        ("x86_64", LinuxAbi::Musl) => Ok("x86_64-unknown-linux-musl"),
        ("aarch64", LinuxAbi::Gnu) => Ok("aarch64-unknown-linux-gnu"),
        ("aarch64", LinuxAbi::Musl) => Ok("aarch64-unknown-linux-musl"),
        other => Err(ProbeUpgraderRunError::UnsupportedArchitecture(
            other.0.to_string(),
        )),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn is_safe_asset_file_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.contains('/')
        && !value.contains("..")
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn is_safe_sudoers_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn is_safe_sudoers_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && !path
            .display()
            .to_string()
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderLaunch {
    pub bootstrap_config_path: PathBuf,
    pub install_path: PathBuf,
    pub operation_id: String,
    pub target_probe_version: String,
    pub token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUninstallerLaunch {
    pub bootstrap_config_path: PathBuf,
    pub install_path: PathBuf,
    pub operation_id: String,
    pub token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderCommandOutput {
    pub stdout: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeUpgraderLaunchError {
    InsufficientPrivilege(String),
    UnsupportedInstallation(String),
}

pub trait ProbeUpgraderCommandRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
        stdin: &str,
    ) -> Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError>;
}

pub struct SystemProbeUpgraderCommandRunner;

impl ProbeUpgraderCommandRunner for SystemProbeUpgraderCommandRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
        stdin: &str,
    ) -> Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ProbeUpgraderLaunchError::UnsupportedInstallation(
                        "sudo is not available for Probe Upgrader launch".to_string(),
                    )
                } else {
                    ProbeUpgraderLaunchError::InsufficientPrivilege(error.to_string())
                }
            })?;

        let mut child_stdin = child.stdin.take().ok_or_else(|| {
            ProbeUpgraderLaunchError::UnsupportedInstallation(
                "Probe Upgrader stdin pipe is unavailable".to_string(),
            )
        })?;
        child_stdin
            .write_all(stdin.as_bytes())
            .map_err(|error| ProbeUpgraderLaunchError::InsufficientPrivilege(error.to_string()))?;
        drop(child_stdin);

        let output = child
            .wait_with_output()
            .map_err(|error| ProbeUpgraderLaunchError::InsufficientPrivilege(error.to_string()))?;

        if output.status.success() {
            return Ok(ProbeUpgraderCommandOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(ProbeUpgraderLaunchError::InsufficientPrivilege(
            if stderr.is_empty() {
                format!("Probe Upgrader launch exited with {}", output.status)
            } else {
                stderr
            },
        ))
    }
}

pub fn launch_systemd_probe_upgrader(
    input: ProbeUpgraderLaunch,
    runner: &mut impl ProbeUpgraderCommandRunner,
) -> Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError> {
    let args = vec![
        "/usr/bin/systemd-run".to_string(),
        "--collect".to_string(),
        "--pipe".to_string(),
        "--wait".to_string(),
        "--unit=enoki-probe-upgrader".to_string(),
        "--property=Type=exec".to_string(),
        "--".to_string(),
        input.install_path.display().to_string(),
        "internal-upgrader".to_string(),
        "--config".to_string(),
        input.bootstrap_config_path.display().to_string(),
    ];
    let stdin = render_probe_upgrader_stdin(&input);

    runner.run("sudo", &args, &stdin)
}

pub fn launch_systemd_probe_uninstaller(
    input: ProbeUninstallerLaunch,
    runner: &mut impl ProbeUpgraderCommandRunner,
) -> Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError> {
    let args = vec![
        "/usr/bin/systemd-run".to_string(),
        "--collect".to_string(),
        "--pipe".to_string(),
        "--wait".to_string(),
        "--unit=enoki-probe-uninstaller".to_string(),
        "--property=Type=exec".to_string(),
        "--".to_string(),
        input.install_path.display().to_string(),
        "internal-uninstaller".to_string(),
        "--config".to_string(),
        input.bootstrap_config_path.display().to_string(),
    ];
    let stdin = render_probe_uninstaller_stdin(&input);

    runner.run("sudo", &args, &stdin)
}

pub fn render_probe_upgrader_stdin(input: &ProbeUpgraderLaunch) -> String {
    [
        format!("operation_id = {}", toml_string(&input.operation_id)),
        format!(
            "target_probe_version = {}",
            toml_string(&input.target_probe_version),
        ),
        format!("token = {}", toml_string(&input.token)),
        String::new(),
    ]
    .join("\n")
}

pub fn render_probe_uninstaller_stdin(input: &ProbeUninstallerLaunch) -> String {
    [
        format!("operation_id = {}", toml_string(&input.operation_id)),
        format!("token = {}", toml_string(&input.token)),
        String::new(),
    ]
    .join("\n")
}

pub fn format_probe_upgrader_result(result: &ProbeUpgraderResult) -> String {
    let mut output = format!(
        "Probe Upgrader result: operation={} status={}",
        result.operation_id, result.status,
    );
    if let Some(error_code) = result.error_code.as_ref() {
        output.push_str(&format!(" error_code={}", output_token(error_code)));
    }
    if let Some(message) = result.message.as_ref() {
        output.push_str(&format!(" message={}", output_token(message)));
    }
    output
}

pub fn parse_probe_upgrader_result(output: &str) -> Option<ProbeUpgraderResult> {
    output.lines().find_map(|line| {
        let rest = line.strip_prefix("Probe Upgrader result: ")?;
        let mut error_code = None;
        let mut message = None;
        let mut operation_id = None;
        let mut status = None;

        for field in rest.split_whitespace() {
            if let Some(value) = field.strip_prefix("operation=") {
                operation_id = Some(value.to_string());
            } else if let Some(value) = field.strip_prefix("status=") {
                status = Some(value.to_string());
            } else if let Some(value) = field.strip_prefix("error_code=") {
                error_code = Some(input_token(value));
            } else if let Some(value) = field.strip_prefix("message=") {
                message = Some(input_token(value));
            }
        }

        Some(ProbeUpgraderResult {
            error_code,
            message,
            operation_id: operation_id?,
            status: status?,
        })
    })
}

fn toml_string(value: &str) -> String {
    let escaped = value
        .chars()
        .flat_map(|character| character.escape_default())
        .collect::<String>();

    format!("\"{escaped}\"")
}

fn output_token(value: &str) -> String {
    value.replace('\\', "\\\\").replace(' ', "\\s")
}

fn input_token(value: &str) -> String {
    let mut output = String::new();
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            output.push(match character {
                's' => ' ',
                other => other,
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            output.push(character);
        }
    }
    if escaped {
        output.push('\\');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use rsa::{
        RsaPrivateKey,
        pkcs1v15::SigningKey,
        pkcs8::EncodePublicKey,
        rand_core::OsRng,
        signature::{RandomizedSigner, SignatureEncoding},
    };
    use std::{collections::HashMap, fs};

    #[derive(Default)]
    struct RecordingCommandRunner {
        args: Vec<String>,
        program: String,
        stdin: String,
    }

    #[derive(Default)]
    struct RecordingValidationTransport {
        assets: HashMap<String, Vec<u8>>,
        body: String,
        downloads: Vec<String>,
        probe_id: String,
        status_body: String,
        status_url: String,
        url: String,
        validated_identity_url: String,
        identity_failure: Option<String>,
    }

    #[derive(Default)]
    struct RecordingSystemdRunner {
        calls: Vec<String>,
        failure: Option<String>,
        failure_step: Option<&'static str>,
        restarted: Vec<String>,
    }

    impl RecordingSystemdRunner {
        fn record_step(&mut self, step: &'static str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(step.to_string());
            if self.failure_step == Some(step) {
                return Err(ProbeUpgraderRunError::RestartFailure(format!(
                    "{step} failed"
                )));
            }
            Ok(())
        }
    }

    impl ProbeUpgraderValidationTransport for RecordingValidationTransport {
        fn get_asset(&mut self, url: &str) -> Result<Vec<u8>, ProbeUpgraderRunError> {
            self.downloads.push(url.to_string());
            self.assets
                .get(url)
                .cloned()
                .ok_or(ProbeUpgraderRunError::AssetMissing)
        }

        fn post_token_validation(
            &mut self,
            url: &str,
            auth: &ProbeRequestAuth<'_>,
            body: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.url = url.to_string();
            self.probe_id = auth.probe_id.to_string();
            self.body = body.to_string();

            Ok(())
        }

        fn post_operation_status(
            &mut self,
            url: &str,
            auth: &ProbeRequestAuth<'_>,
            body: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.status_url = url.to_string();
            self.probe_id = auth.probe_id.to_string();
            self.status_body = body.to_string();

            Ok(())
        }

        fn validate_probe_identity(
            &mut self,
            url: &str,
            auth: &ProbeRequestAuth<'_>,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.validated_identity_url = url.to_string();
            self.probe_id = auth.probe_id.to_string();
            if let Some(message) = self.identity_failure.take() {
                return Err(ProbeUpgraderRunError::IdentityValidation(message));
            }
            Ok(())
        }
    }

    impl ProbeUpgraderSystemdRunner for RecordingSystemdRunner {
        fn ensure_service_group(
            &mut self,
            _service_group: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.record_step("ensure-group")
        }

        fn ensure_service_account(
            &mut self,
            _service_user: &str,
            _service_group: &str,
            _state_dir: &Path,
            _identity_path: &Path,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.record_step("ensure-account")
        }

        fn enable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("enable {service_name}"));
            if self.failure_step == Some("enable") {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "enable failed".to_string(),
                ));
            }
            Ok(())
        }

        fn restart_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("restart {service_name}"));
            if self.failure_step == Some("restart") {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "restart failed".to_string(),
                ));
            }
            if let Some(failure) = self.failure.take() {
                return Err(ProbeUpgraderRunError::RestartFailure(failure));
            }
            self.restarted.push(service_name.to_string());
            Ok(())
        }

        fn stop_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("stop {service_name}"));
            if self.failure_step == Some("stop") {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "stop failed".to_string(),
                ));
            }
            Ok(())
        }

        fn disable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("disable {service_name}"));
            if self.failure_step == Some("disable") {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "disable failed".to_string(),
                ));
            }
            Ok(())
        }

        fn daemon_reload(&mut self) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push("daemon-reload".to_string());
            if self.failure_step == Some("daemon-reload") {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "daemon-reload failed".to_string(),
                ));
            }
            Ok(())
        }

        fn reset_failed(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("reset-failed {service_name}"));
            if self.failure_step == Some("reset-failed") {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "reset-failed failed".to_string(),
                ));
            }
            Ok(())
        }

        fn verify_service_absent(
            &mut self,
            service_name: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.calls
                .push(format!("verify-service-absent {service_name}"));
            if self.failure_step == Some("verify-service") {
                return Err(uninstall_cleanup_failure(
                    "probe_uninstall_service_residue",
                    "verifying the service is absent",
                    "systemd LoadState is loaded".to_string(),
                ));
            }
            Ok(())
        }

        fn remove_service_identity(
            &mut self,
            service_user: &str,
            service_group: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!(
                "remove-service-identity {service_user}:{service_group}"
            ));
            if self.failure_step == Some("remove-account") {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "service account removal failed".to_string(),
                ));
            }
            Ok(())
        }
    }

    impl ProbeUpgraderCommandRunner for RecordingCommandRunner {
        fn run(
            &mut self,
            program: &str,
            args: &[String],
            stdin: &str,
        ) -> Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError> {
            self.program = program.to_string();
            self.args = args.to_vec();
            self.stdin = stdin.to_string();

            Ok(ProbeUpgraderCommandOutput {
                stdout: String::new(),
            })
        }
    }

    #[test]
    fn systemd_probe_upgrader_launch_uses_typed_entrypoint_and_stdin_token() {
        let mut runner = RecordingCommandRunner::default();

        launch_systemd_probe_upgrader(
            ProbeUpgraderLaunch {
                bootstrap_config_path: PathBuf::from("/etc/enoki/probe-bootstrap.toml"),
                install_path: PathBuf::from("/usr/local/bin/enoki-probe"),
                operation_id: "42".to_string(),
                target_probe_version: "0.2.0".to_string(),
                token: "probe-operation-token".to_string(),
            },
            &mut runner,
        )
        .expect("launch succeeds");

        assert_eq!(runner.program, "sudo");
        assert_eq!(
            runner.args,
            vec![
                "/usr/bin/systemd-run",
                "--collect",
                "--pipe",
                "--wait",
                "--unit=enoki-probe-upgrader",
                "--property=Type=exec",
                "--",
                "/usr/local/bin/enoki-probe",
                "internal-upgrader",
                "--config",
                "/etc/enoki/probe-bootstrap.toml",
            ],
        );
        assert_eq!(
            runner.stdin,
            [
                "operation_id = \"42\"",
                "target_probe_version = \"0.2.0\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
        );
        assert!(!runner.args.iter().any(|arg| arg == "probe-operation-token"));
        assert!(!runner.args.iter().any(|arg| arg == "42"));
        assert!(!runner.args.iter().any(|arg| arg == "0.2.0"));
    }

    #[test]
    fn systemd_probe_uninstaller_launch_uses_typed_entrypoint_and_stdin_token() {
        let mut runner = RecordingCommandRunner::default();

        launch_systemd_probe_uninstaller(
            ProbeUninstallerLaunch {
                bootstrap_config_path: PathBuf::from("/etc/enoki/probe-bootstrap.toml"),
                install_path: PathBuf::from("/usr/local/bin/enoki-probe"),
                operation_id: "42".to_string(),
                token: "probe-operation-token".to_string(),
            },
            &mut runner,
        )
        .expect("launch succeeds");

        assert_eq!(runner.program, "sudo");
        assert_eq!(
            runner.args,
            vec![
                "/usr/bin/systemd-run",
                "--collect",
                "--pipe",
                "--wait",
                "--unit=enoki-probe-uninstaller",
                "--property=Type=exec",
                "--",
                "/usr/local/bin/enoki-probe",
                "internal-uninstaller",
                "--config",
                "/etc/enoki/probe-bootstrap.toml",
            ],
        );
        assert_eq!(
            runner.stdin,
            [
                "operation_id = \"42\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
        );
        assert!(!runner.args.iter().any(|arg| arg == "probe-operation-token"));
        assert!(!runner.args.iter().any(|arg| arg == "42"));
    }

    #[test]
    fn internal_probe_upgrader_rejects_missing_stdin_token() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "probe_private_key_pem = \"test-private-key\"",
                "",
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport::default();

        let error = run_probe_upgrader(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
            },
            "",
            &mut transport,
        )
        .expect_err("missing token fails");

        assert!(matches!(error, ProbeUpgraderRunError::MissingToken));
        assert_eq!(transport.url, "");
    }

    #[test]
    fn probe_repair_rejects_non_root_before_identity_or_network_access() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let error = run_probe_repair_with_current_version_and_systemd_runner(
            &install_metadata,
            &mut transport,
            &mut systemd,
            1000,
            test_process_uid(),
            "0.2.0",
        )
        .expect_err("non-root Repair fails closed");

        assert_eq!(error.code(), "probe_repair_root_required");
        assert!(transport.downloads.is_empty());
        assert!(systemd.calls.is_empty());
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn probe_repair_requires_a_local_post_replacement_failed_upgrade_marker() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let error = run_probe_repair_with_current_version_and_systemd_runner(
            &install_metadata,
            &mut transport,
            &mut systemd,
            0,
            test_process_uid(),
            "0.2.0",
        )
        .expect_err("Repair without a failed Upgrade marker fails closed");

        assert_eq!(error.code(), "probe_repair_failure_marker_missing");
        assert!(transport.downloads.is_empty());
        assert!(systemd.calls.is_empty());
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn probe_repair_failure_marker_must_be_a_trusted_root_written_file() {
        let temp = tempfile::tempdir().expect("temp dir");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata = trusted_install_metadata(
            &temp.path().join("bin/enoki-probe"),
            &status_path,
            assets_public_key_sha256(),
        );
        write_failed_upgrade_marker(&status_path, "0.2.0");

        for file_metadata in [
            TrustedFileMetadata {
                is_regular_file: true,
                is_symlink: true,
                mode: 0o644,
                owner_uid: 0,
            },
            TrustedFileMetadata {
                is_regular_file: true,
                is_symlink: false,
                mode: 0o640,
                owner_uid: 0,
            },
            TrustedFileMetadata {
                is_regular_file: true,
                is_symlink: false,
                mode: 0o644,
                owner_uid: 1000,
            },
        ] {
            let error = read_probe_repair_failure_marker_with_file_metadata(
                &install_metadata,
                file_metadata,
            )
            .expect_err("untrusted failed Upgrade marker is rejected");

            assert_eq!(error.code(), "probe_repair_failure_marker_invalid");
        }
    }

    #[test]
    fn probe_repair_failure_marker_requires_complete_post_replacement_evidence() {
        for contents in [
            "not TOML",
            "operation_id = \"operation_41\"\nstatus = \"failed\"\n",
            "operation_id = \"\"\ntarget_probe_version = \"0.2.0\"\nstatus = \"failed\"\nerror_code = \"post_replacement_restart_failure\"\n",
        ] {
            assert_eq!(
                parse_probe_repair_failure_marker(contents)
                    .expect_err("incomplete failed Upgrade marker is rejected")
                    .code(),
                "probe_repair_failure_marker_invalid",
            );
        }

        for (status, error_code) in [
            ("running", "post_replacement_restart_failure"),
            ("failed", "checksum_failure"),
        ] {
            let contents = format!(
                "operation_id = \"operation_41\"\ntarget_probe_version = \"0.2.0\"\nstatus = \"{status}\"\nerror_code = \"{error_code}\"\n"
            );
            assert_eq!(
                parse_probe_repair_failure_marker(&contents)
                    .expect_err("non-post-replacement failure cannot authorize Repair")
                    .code(),
                "probe_repair_failure_marker_not_post_replacement",
            );
        }
    }

    #[test]
    fn probe_repair_rejects_complete_identity_bound_to_another_hub() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let mut install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        install_metadata.identity_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &install_metadata.identity_path,
            [
                "hub_url = \"https://other-hub.example\"",
                "probe_id = \"probe_01\"",
                "probe_private_key_pem = \"complete-private-key\"",
                "",
            ]
            .join("\n"),
        )
        .expect("identity config");
        fs::set_permissions(
            &install_metadata.identity_path,
            fs::Permissions::from_mode(0o600),
        )
        .expect("identity permissions");
        write_failed_upgrade_marker(&status_path, "0.2.0");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let error = run_probe_repair_with_current_version_and_systemd_runner(
            &install_metadata,
            &mut transport,
            &mut systemd,
            0,
            test_process_uid(),
            "0.2.0",
        )
        .expect_err("cross-Hub identity fails closed");

        assert_eq!(error.code(), "probe_repair_identity_hub_mismatch");
        assert!(transport.downloads.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn probe_repair_identity_requires_exact_mode_0600() {
        let temp = tempfile::tempdir().expect("temp dir");
        let identity_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &identity_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "probe_private_key_pem = \"complete-private-key\"",
                "",
            ]
            .join("\n"),
        )
        .expect("identity");
        let mut install_metadata = trusted_install_metadata(
            &temp.path().join("bin/enoki-probe"),
            &temp.path().join("state/probe-operation-status.toml"),
            assets_public_key_sha256(),
        );
        install_metadata.identity_path = identity_path;

        for mode in [0o400, 0o640, 0o644] {
            let error = read_probe_repair_identity_with_file_metadata(
                &install_metadata,
                TrustedFileMetadata {
                    is_regular_file: true,
                    is_symlink: false,
                    mode,
                    owner_uid: 1000,
                },
            )
            .expect_err("non-0600 Probe Identity is rejected");

            assert_eq!(error.code(), "probe_repair_identity_incomplete");
        }
    }

    #[cfg(unix)]
    #[test]
    fn probe_repair_rejects_absent_incomplete_and_symlink_identities() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp dir");
        let identity_path = temp.path().join("probe-bootstrap.toml");
        let mut install_metadata = trusted_install_metadata(
            &temp.path().join("bin/enoki-probe"),
            &temp.path().join("state/probe-operation-status.toml"),
            assets_public_key_sha256(),
        );
        install_metadata.identity_path = identity_path.clone();

        assert_eq!(
            read_probe_repair_identity(&install_metadata)
                .expect_err("absent identity is rejected")
                .code(),
            "probe_repair_identity_incomplete",
        );

        fs::write(
            &identity_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "",
            ]
            .join("\n"),
        )
        .expect("incomplete identity");
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
            .expect("identity mode");
        assert_eq!(
            read_probe_repair_identity(&install_metadata)
                .expect_err("identity without signing key is rejected")
                .code(),
            "probe_repair_identity_incomplete",
        );

        let target = temp.path().join("identity-target.toml");
        fs::rename(&identity_path, &target).expect("move identity target");
        symlink(&target, &identity_path).expect("identity symlink");
        assert_eq!(
            read_probe_repair_identity(&install_metadata)
                .expect_err("identity symlink is rejected")
                .code(),
            "probe_repair_identity_incomplete",
        );
    }

    #[test]
    fn probe_repair_reinstalls_hub_supplied_probe_and_preserves_identity() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("usr/local/bin/enoki-probe");
        let status_path = temp
            .path()
            .join("var/lib/enoki-probe/probe-operation-status.toml");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "broken candidate").expect("broken candidate");
        let assets = signed_assets(
            "0.2.0",
            &replacement_probe_binary("repaired candidate"),
            None,
        );
        let mut install_metadata = trusted_install_metadata(
            &install_path,
            &status_path,
            assets.public_key_sha256.clone(),
        );
        install_metadata.identity_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
        install_metadata.service_unit_path =
            temp.path().join("etc/systemd/system/enoki-probe.service");
        fs::create_dir_all(
            install_metadata
                .identity_path
                .parent()
                .expect("identity dir"),
        )
        .expect("identity dir");
        let identity_contents = [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_private_key_pem = \"complete-private-key\"",
            "",
        ]
        .join("\n");
        fs::write(&install_metadata.identity_path, &identity_contents).expect("identity config");
        fs::set_permissions(
            &install_metadata.identity_path,
            fs::Permissions::from_mode(0o600),
        )
        .expect("identity permissions");
        write_failed_upgrade_marker(&status_path, "0.2.0");
        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        let result = run_probe_repair_with_current_version_and_systemd_runner(
            &install_metadata,
            &mut transport,
            &mut systemd,
            0,
            test_process_uid(),
            "0.2.0",
        )
        .expect("Repair succeeds");

        assert_eq!(result.probe_id, "probe_01");
        assert_eq!(result.repaired_version, "0.2.0");
        assert_eq!(
            fs::read_to_string(&install_metadata.identity_path).expect("identity remains"),
            identity_contents,
        );
        assert!(
            fs::read_to_string(&install_path)
                .expect("repaired binary")
                .contains("repaired candidate")
        );
        assert!(
            fs::read_to_string(&install_metadata.service_unit_path)
                .expect("service unit")
                .contains("ExecStart=")
        );
        assert_eq!(
            transport.validated_identity_url,
            "https://hub.example/api/probe/config",
        );
        assert_eq!(transport.probe_id, "probe_01");
        assert_eq!(systemd.restarted, vec!["enoki-probe"]);
        assert_eq!(
            systemd.calls,
            [
                "ensure-group",
                "ensure-account",
                "stop enoki-probe",
                "daemon-reload",
                "enable enoki-probe",
                "reset-failed enoki-probe",
                "restart enoki-probe",
            ],
        );
    }

    #[test]
    fn probe_repair_rejects_archive_checksum_failure_before_replacement() {
        let assets = signed_assets(
            "0.2.0",
            &replacement_probe_binary("tampered candidate"),
            Some("0".repeat(64)),
        );
        let pinned_key = assets.public_key_sha256.clone();
        let (result, install_path, _temp) = run_repair_with_assets(assets, pinned_key, None);

        let error = result.expect_err("checksum mismatch fails Repair");
        assert_eq!(error.code(), "probe_repair_checksum_failure");
        assert_eq!(
            fs::read_to_string(install_path).expect("old binary remains"),
            "broken candidate",
        );
    }

    #[test]
    fn probe_repair_rejects_untrusted_signing_key_before_replacement() {
        let assets = signed_assets(
            "0.2.0",
            &replacement_probe_binary("attacker candidate"),
            None,
        );
        let (result, install_path, _temp) = run_repair_with_assets(assets, "0".repeat(64), None);

        let error = result.expect_err("untrusted signing key fails Repair");
        assert_eq!(error.code(), "probe_repair_signing_key_untrusted");
        assert_eq!(
            fs::read_to_string(install_path).expect("old binary remains"),
            "broken candidate",
        );
    }

    #[test]
    fn probe_repair_rejects_manifest_signature_failure_before_replacement() {
        let mut assets = signed_assets(
            "0.2.0",
            &replacement_probe_binary("tampered candidate"),
            None,
        );
        assets.signature[0] ^= 0xff;
        let pinned_key = assets.public_key_sha256.clone();
        let (result, install_path, _temp) = run_repair_with_assets(assets, pinned_key, None);

        let error = result.expect_err("invalid signature fails Repair");
        assert_eq!(error.code(), "probe_repair_signature_failure");
        assert_eq!(
            fs::read_to_string(install_path).expect("old binary remains"),
            "broken candidate",
        );
    }

    #[test]
    fn probe_repair_requires_bound_hub_to_accept_existing_identity() {
        let assets = signed_assets("0.2.0", &replacement_probe_binary("candidate"), None);
        let pinned_key = assets.public_key_sha256.clone();
        let (result, install_path, _temp) = run_repair_with_assets(
            assets,
            pinned_key,
            Some("HTTP 401 probe_identity_required".to_string()),
        );

        let error = result.expect_err("Hub-rejected identity fails Repair");
        assert_eq!(error.code(), "probe_repair_identity_rejected");
        assert_eq!(
            fs::read_to_string(install_path).expect("old binary remains"),
            "broken candidate",
        );
    }

    #[test]
    fn probe_repair_rejects_release_baseline_hub_downgrade() {
        let assets = signed_assets(
            "0.1.0",
            &replacement_probe_binary("Release Baseline Probe"),
            None,
        );
        let pinned_key = assets.public_key_sha256.clone();
        let (result, install_path, _temp) =
            run_repair_with_assets_for_versions(assets, pinned_key, None, "0.2.0", "0.2.0");

        let error = result.expect_err("Hub Restore baseline cannot downgrade Probe Repair");
        assert_eq!(error.code(), "probe_repair_downgrade_rejected");
        assert_eq!(
            fs::read_to_string(install_path).expect("candidate binary remains"),
            "broken candidate",
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_repair_reads_and_validates_the_installed_probe_version() {
        let temp = tempfile::tempdir().expect("temp dir");
        let binary = temp.path().join("enoki-probe");
        fs::write(&binary, b"ELF\0ENOKI_PROBE_VERSION=0.2.0\0payload").expect("Probe binary");

        assert_eq!(
            read_installed_probe_version(&binary).expect("installed version"),
            "0.2.0",
        );

        fs::write(&binary, b"ELF\0no version marker\0").expect("invalid Probe binary");
        let error = read_installed_probe_version(&binary)
            .expect_err("unverifiable installed version is rejected");
        assert_eq!(error.code(), "probe_repair_installed_version_invalid");
    }

    #[test]
    fn probe_repair_rejects_a_newer_hub_target_as_a_general_reinstall() {
        let assets = signed_assets(
            "0.3.0",
            &replacement_probe_binary("unrelated newer Probe"),
            None,
        );
        let pinned_key = assets.public_key_sha256.clone();
        let (result, install_path, _temp) =
            run_repair_with_assets_for_versions(assets, pinned_key, None, "0.2.0", "0.2.0");

        let error = result.expect_err("Repair cannot become a forward Upgrade path");
        assert_eq!(error.code(), "probe_repair_hub_target_mismatch");
        assert_eq!(
            fs::read_to_string(install_path).expect("candidate binary remains"),
            "broken candidate",
        );
    }

    #[test]
    fn probe_repair_rejects_a_marker_for_a_candidate_not_currently_installed() {
        let assets = signed_assets("0.3.0", &replacement_probe_binary("marked Probe"), None);
        let pinned_key = assets.public_key_sha256.clone();
        let (result, install_path, _temp) =
            run_repair_with_assets_for_versions(assets, pinned_key, None, "0.2.0", "0.3.0");

        let error = result.expect_err("Repair requires the replaced candidate to be installed");
        assert_eq!(error.code(), "probe_repair_candidate_not_installed");
        assert_eq!(
            fs::read_to_string(install_path).expect("current binary remains"),
            "broken candidate",
        );
    }

    #[test]
    fn probe_repair_reports_stable_service_reconstruction_step_codes() {
        let assets = signed_assets(
            "0.2.0",
            &replacement_probe_binary("repaired candidate"),
            None,
        );

        for (failure_step, expected_code) in [
            ("ensure-group", "probe_repair_service_group_failed"),
            ("ensure-account", "probe_repair_service_account_failed"),
            ("daemon-reload", "probe_repair_daemon_reload_failed"),
            ("enable", "probe_repair_service_enable_failed"),
            ("restart", "probe_repair_service_restart_failed"),
        ] {
            let (result, calls, _temp) =
                run_repair_reconstruction_case(&assets, Some(failure_step), None);
            let error = result.expect_err("injected service reconstruction step fails");
            assert_eq!(error.code(), expected_code, "failure step {failure_step}");
            assert!(
                calls.iter().any(|call| call.contains(failure_step)),
                "runner must record the failing {failure_step} step",
            );
        }

        for (blocked_write, expected_code) in [
            ("sudoers", "probe_repair_sudoers_failed"),
            ("service-unit", "probe_repair_service_unit_failed"),
        ] {
            let (result, _calls, _temp) =
                run_repair_reconstruction_case(&assets, None, Some(blocked_write));
            let error = result.expect_err("blocked reconstruction write fails");
            assert_eq!(error.code(), expected_code, "blocked {blocked_write}");
        }
    }

    #[test]
    fn internal_probe_uninstaller_removes_owned_files_and_reports_success() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
        let install_path = temp.path().join("usr/local/bin/enoki-probe");
        let state_dir = temp.path().join("var/lib/enoki-probe");
        let status_path = state_dir.join("probe-operation-status.toml");
        fs::create_dir_all(bootstrap_config_path.parent().expect("config dir"))
            .expect("config dir");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::create_dir_all(&state_dir).expect("state dir");
        let sudoers_dir = temp.path().join("etc/sudoers.d");
        fs::create_dir_all(&sudoers_dir).expect("sudoers dir");
        let operation_sudoers_path = sudoers_dir.join("enoki-probe-operations");
        let collector_helper_sudoers_path = sudoers_dir.join("enoki-probe-collector-helpers");
        let legacy_sudoers_path = sudoers_dir.join("enoki-probe-upgrader");
        fs::write(&install_path, "probe binary").expect("install binary");
        fs::write(state_dir.join("state"), "state").expect("state");
        fs::write(&operation_sudoers_path, "operation sudoers").expect("operation sudoers");
        fs::write(&collector_helper_sudoers_path, "collector helper sudoers")
            .expect("collector helper sudoers");
        fs::write(&legacy_sudoers_path, "legacy sudoers").expect("legacy sudoers");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "probe_private_key_pem = \"test-private-key\"",
                &format!(
                    "install_path = {}",
                    toml_string(install_path.to_str().expect("install path")),
                ),
                &format!(
                    "operation_status_path = {}",
                    toml_string(status_path.to_str().expect("status path")),
                ),
                &format!(
                    "state_dir = {}",
                    toml_string(state_dir.to_str().expect("state dir")),
                ),
                "service_name = \"enoki-probe\"",
                &format!(
                    "probe_asset_public_key_sha256 = {}",
                    toml_string(&"a".repeat(64))
                ),
                "",
            ]
            .join("\n"),
        )
        .expect("bootstrap config");
        let mut install_metadata =
            trusted_install_metadata(&install_path, &status_path, "a".repeat(64));
        install_metadata.operation_sudoers_path = operation_sudoers_path.clone();
        install_metadata.collector_helper_sudoers_path = collector_helper_sudoers_path.clone();
        install_metadata.old_sudoers_paths = vec![legacy_sudoers_path.clone()];
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let result = run_probe_uninstaller_with_systemd_runner_and_install_metadata(
            ProbeUninstallerRunInput {
                bootstrap_config_path: bootstrap_config_path.clone(),
            },
            &[
                "operation_id = \"42\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("uninstall succeeds");

        assert_eq!(result.status, "succeeded");
        assert_eq!(
            systemd.calls,
            vec![
                "stop enoki-probe",
                "disable enoki-probe",
                "daemon-reload",
                "reset-failed enoki-probe",
                "verify-service-absent enoki-probe",
                "remove-service-identity enoki-probe:enoki-probe",
            ],
        );
        assert!(!install_path.exists());
        assert!(!bootstrap_config_path.exists());
        assert!(!state_dir.exists());
        assert!(!operation_sudoers_path.exists());
        assert!(!collector_helper_sudoers_path.exists());
        assert!(!legacy_sudoers_path.exists());
        assert_eq!(
            transport.url,
            "https://hub.example/api/probe/operations/42/token/validate",
        );
        assert_eq!(
            transport.status_url,
            "https://hub.example/api/probe/operations/42/status",
        );
        assert_eq!(
            transport.status_body,
            "{\"status\":\"succeeded\",\"token\":\"probe-operation-token\"}"
        );
    }

    #[test]
    fn internal_probe_uninstaller_reports_required_service_cleanup_failure() {
        let temp = tempfile::tempdir().expect("temp dir");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_path = temp.path().join("bin/enoki-probe");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        fs::create_dir_all(&install_metadata.state_dir).expect("state dir");
        write_test_bootstrap_config(&install_metadata.identity_path, &install_metadata)
            .expect("bootstrap config");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner {
            failure_step: Some("disable"),
            ..RecordingSystemdRunner::default()
        };

        let result = run_probe_uninstaller_with_systemd_runner_and_install_metadata(
            ProbeUninstallerRunInput {
                bootstrap_config_path: install_metadata.identity_path.clone(),
            },
            &[
                "operation_id = \"42\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("cleanup failure is reported to Hub");

        assert_eq!(result.status, "failed");
        assert_eq!(
            result.error_code.as_deref(),
            Some("probe_uninstall_service_disable_failed")
        );
        assert_eq!(
            transport.status_body,
            "{\"errorCode\":\"probe_uninstall_service_disable_failed\",\"message\":\"Probe uninstall cleanup failed while disabling the service: disable failed\",\"status\":\"failed\",\"token\":\"probe-operation-token\"}"
        );
        assert_eq!(systemd.calls, ["stop enoki-probe", "disable enoki-probe"]);
    }

    #[test]
    fn required_systemd_cleanup_rejects_failure_for_a_loaded_service() {
        let mut calls = Vec::new();
        let mut run = |program: &str, args: &[&str]| {
            calls.push(format!("{program} {}", args.join(" ")));
            Ok(match args.first().copied() {
                Some("disable") => CleanupCommandOutput::failure(
                    Some(1),
                    "",
                    "Failed to disable unit: access denied",
                ),
                Some("show") => CleanupCommandOutput::success("loaded\n"),
                _ => panic!("unexpected command: {program} {args:?}"),
            })
        };

        let error = run_required_systemctl_cleanup_with(
            &["disable", "enoki-probe"],
            "enoki-probe",
            "probe_uninstall_service_disable_failed",
            "disabling the service",
            &mut run,
        )
        .expect_err("a loaded unit cannot turn disable failure into success");

        assert_eq!(
            probe_upgrader_error_code(&error),
            "probe_uninstall_service_disable_failed"
        );
        assert!(error.to_string().contains("access denied"));
        assert_eq!(
            calls,
            [
                "systemctl disable enoki-probe",
                "systemctl show --property=LoadState --value enoki-probe",
            ]
        );
    }

    #[test]
    fn required_systemd_cleanup_allows_only_an_explicitly_missing_service() {
        let mut calls = Vec::new();
        let mut run = |program: &str, args: &[&str]| {
            calls.push(format!("{program} {}", args.join(" ")));
            Ok(match args.first().copied() {
                Some("disable") => {
                    CleanupCommandOutput::failure(Some(1), "", "unit does not exist")
                }
                Some("show") => CleanupCommandOutput::success("not-found\n"),
                _ => panic!("unexpected command: {program} {args:?}"),
            })
        };

        run_required_systemctl_cleanup_with(
            &["disable", "enoki-probe"],
            "enoki-probe",
            "probe_uninstall_service_disable_failed",
            "disabling the service",
            &mut run,
        )
        .expect("an explicit systemd not-found state is idempotent success");

        assert_eq!(
            calls,
            [
                "systemctl disable enoki-probe",
                "systemctl show --property=LoadState --value enoki-probe",
            ]
        );
    }

    #[test]
    fn systemd_service_absence_check_rejects_loaded_state_and_accepts_not_found() {
        let mut loaded =
            |_program: &str, _args: &[&str]| Ok(CleanupCommandOutput::success("loaded\n"));
        let error = verify_systemd_service_absent_with("enoki-probe", &mut loaded)
            .expect_err("a loaded service is uninstall residue");
        assert_eq!(
            probe_upgrader_error_code(&error),
            "probe_uninstall_service_residue"
        );

        let mut missing =
            |_program: &str, _args: &[&str]| Ok(CleanupCommandOutput::success("not-found\n"));
        verify_systemd_service_absent_with("enoki-probe", &mut missing)
            .expect("an explicit not-found LoadState is absent");
    }

    #[test]
    fn service_identity_cleanup_fails_closed_when_userdel_fails() {
        let mut calls = Vec::new();
        let mut run = |program: &str, args: &[&str]| {
            calls.push(format!("{program} {}", args.join(" ")));
            Ok(match program {
                "getent" => CleanupCommandOutput::success("enoki-probe:x:999:999"),
                "userdel" => CleanupCommandOutput::failure(Some(1), "", "account is in use"),
                _ => panic!("unexpected command: {program} {args:?}"),
            })
        };

        let error = remove_service_identity_with("enoki-probe", "enoki-probe", &mut run)
            .expect_err("an unexplained userdel failure is fatal");

        assert_eq!(
            probe_upgrader_error_code(&error),
            "probe_uninstall_service_account_remove_failed"
        );
        assert!(error.to_string().contains("account is in use"));
        assert_eq!(calls, ["getent passwd enoki-probe", "userdel enoki-probe"]);
    }

    #[test]
    fn service_identity_cleanup_verifies_account_and_group_are_absent() {
        let mut calls = Vec::new();
        let mut passwd_queries = 0;
        let mut group_queries = 0;
        let mut run = |program: &str, args: &[&str]| {
            calls.push(format!("{program} {}", args.join(" ")));
            Ok(match (program, args.first().copied()) {
                ("getent", Some("passwd")) => {
                    passwd_queries += 1;
                    if passwd_queries == 1 {
                        CleanupCommandOutput::success("enoki-probe:x:999:999")
                    } else {
                        CleanupCommandOutput::failure(Some(2), "", "")
                    }
                }
                ("getent", Some("group")) => {
                    group_queries += 1;
                    if group_queries == 1 {
                        CleanupCommandOutput::success("enoki-probe:x:999:")
                    } else {
                        CleanupCommandOutput::failure(Some(2), "", "")
                    }
                }
                ("userdel" | "groupdel", _) => CleanupCommandOutput::success(""),
                _ => panic!("unexpected command: {program} {args:?}"),
            })
        };

        remove_service_identity_with("enoki-probe", "enoki-probe", &mut run)
            .expect("both identity entries are deleted and verified absent");

        assert_eq!(
            calls,
            [
                "getent passwd enoki-probe",
                "userdel enoki-probe",
                "getent passwd enoki-probe",
                "getent group enoki-probe",
                "groupdel enoki-probe",
                "getent group enoki-probe",
            ]
        );
    }

    #[test]
    fn service_identity_cleanup_is_idempotent_only_for_explicitly_missing_entries() {
        let mut calls = Vec::new();
        let mut run = |program: &str, args: &[&str]| {
            calls.push(format!("{program} {}", args.join(" ")));
            Ok(CleanupCommandOutput::failure(Some(2), "", ""))
        };

        remove_service_identity_with("enoki-probe", "enoki-probe", &mut run)
            .expect("getent exit code 2 explicitly means the entries are absent");

        assert_eq!(
            calls,
            ["getent passwd enoki-probe", "getent group enoki-probe"]
        );
    }

    #[test]
    fn service_identity_cleanup_rejects_account_residue_after_userdel() {
        let mut run = |program: &str, _args: &[&str]| {
            Ok(match program {
                "getent" => CleanupCommandOutput::success("enoki-probe:x:999:999"),
                "userdel" => CleanupCommandOutput::success(""),
                _ => panic!("unexpected command: {program}"),
            })
        };

        let error = remove_service_identity_with("enoki-probe", "enoki-probe", &mut run)
            .expect_err("an account that remains after userdel is fatal");

        assert_eq!(
            probe_upgrader_error_code(&error),
            "probe_uninstall_service_account_residue"
        );
    }

    #[test]
    fn service_unit_absence_check_rejects_residue_and_accepts_not_found() {
        let temp = tempfile::tempdir().expect("temp dir");
        let service_unit_path = temp.path().join("enoki-probe.service");
        fs::write(&service_unit_path, "unit").expect("service unit");

        let error = verify_path_absent(
            &service_unit_path,
            "probe_uninstall_service_unit_residue",
            "verifying the service unit is absent",
        )
        .expect_err("a remaining unit file is fatal");
        assert_eq!(
            probe_upgrader_error_code(&error),
            "probe_uninstall_service_unit_residue"
        );

        fs::remove_file(&service_unit_path).expect("remove service unit");
        verify_path_absent(
            &service_unit_path,
            "probe_uninstall_service_unit_residue",
            "verifying the service unit is absent",
        )
        .expect("not-found is idempotent success");
    }

    #[test]
    fn internal_probe_uninstaller_reports_loaded_service_residue() {
        let temp = tempfile::tempdir().expect("temp dir");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_path = temp.path().join("bin/enoki-probe");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        fs::create_dir_all(&install_metadata.state_dir).expect("state dir");
        write_test_bootstrap_config(&install_metadata.identity_path, &install_metadata)
            .expect("bootstrap config");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner {
            failure_step: Some("verify-service"),
            ..RecordingSystemdRunner::default()
        };

        let result = run_probe_uninstaller_with_systemd_runner_and_install_metadata(
            ProbeUninstallerRunInput {
                bootstrap_config_path: install_metadata.identity_path.clone(),
            },
            &[
                "operation_id = \"42\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("service residue is reported to Hub");

        assert_eq!(result.status, "failed");
        assert_eq!(
            result.error_code.as_deref(),
            Some("probe_uninstall_service_residue")
        );
        assert!(transport.status_body.contains("\"status\":\"failed\""));
        assert!(!transport.status_body.contains("\"status\":\"succeeded\""));
    }

    #[test]
    fn internal_probe_uninstaller_reports_service_account_cleanup_failure() {
        let temp = tempfile::tempdir().expect("temp dir");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_path = temp.path().join("bin/enoki-probe");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        fs::create_dir_all(&install_metadata.state_dir).expect("state dir");
        write_test_bootstrap_config(&install_metadata.identity_path, &install_metadata)
            .expect("bootstrap config");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner {
            failure_step: Some("remove-account"),
            ..RecordingSystemdRunner::default()
        };

        let result = run_probe_uninstaller_with_systemd_runner_and_install_metadata(
            ProbeUninstallerRunInput {
                bootstrap_config_path: install_metadata.identity_path.clone(),
            },
            &[
                "operation_id = \"42\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("account cleanup failure is reported to Hub");

        assert_eq!(result.status, "failed");
        assert_eq!(
            result.error_code.as_deref(),
            Some("probe_uninstall_service_account_remove_failed")
        );
        assert!(transport.status_body.contains("\"status\":\"failed\""));
        assert!(!transport.status_body.contains("\"status\":\"succeeded\""));
    }

    #[test]
    fn probe_uninstaller_removes_install_metadata_and_local_installation_assets() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
        let install_metadata_path = temp.path().join("etc/enoki/probe-install.toml");
        let install_path = temp.path().join("usr/local/bin/enoki-probe");
        let state_dir = temp.path().join("var/lib/enoki-probe");
        let status_path = state_dir.join("probe-operation-status.toml");
        let operation_sudoers_path = temp.path().join("etc/sudoers.d/enoki-probe-operations");
        let collector_helper_sudoers_path = temp
            .path()
            .join("etc/sudoers.d/enoki-probe-collector-helpers");
        let old_sudoers_path = temp.path().join("etc/sudoers.d/enoki-probe-upgrader");
        for path in [
            &bootstrap_config_path,
            &install_metadata_path,
            &install_path,
            &operation_sudoers_path,
            &collector_helper_sudoers_path,
            &old_sudoers_path,
        ] {
            fs::create_dir_all(path.parent().expect("parent")).expect("parent");
            fs::write(path, "owned file").expect("owned file");
        }
        fs::create_dir_all(&state_dir).expect("state dir");
        fs::write(state_dir.join("state"), "state").expect("state");
        let mut install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        install_metadata.operation_sudoers_path = operation_sudoers_path.clone();
        install_metadata.collector_helper_sudoers_path = collector_helper_sudoers_path.clone();
        install_metadata.old_sudoers_paths = vec![old_sudoers_path.clone()];
        let mut systemd = RecordingSystemdRunner::default();

        execute_probe_uninstall_with_install_metadata_path(
            &ProbeUninstallerRunInput {
                bootstrap_config_path: bootstrap_config_path.clone(),
            },
            &install_metadata,
            &mut systemd,
            &install_metadata_path,
        )
        .expect("uninstall cleanup succeeds");

        for path in [
            &bootstrap_config_path,
            &install_metadata_path,
            &install_path,
            &operation_sudoers_path,
            &collector_helper_sudoers_path,
            &old_sudoers_path,
        ] {
            assert!(!path.exists(), "{} should be removed", path.display());
        }
        assert!(!state_dir.exists());
        assert_eq!(
            systemd.calls,
            vec![
                "stop enoki-probe",
                "disable enoki-probe",
                "daemon-reload",
                "reset-failed enoki-probe",
                "verify-service-absent enoki-probe",
                "remove-service-identity enoki-probe:enoki-probe",
            ],
        );
    }

    #[test]
    fn internal_probe_uninstaller_rejects_bootstrap_hub_url_mismatch_before_token_validation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://attacker.example\"".to_string(),
                "probe_id = \"probe_01\"".to_string(),
                "probe_private_key_pem = \"test-private-key\"".to_string(),
                String::new(),
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let error = run_probe_uninstaller_with_systemd_runner_and_install_metadata(
            ProbeUninstallerRunInput {
                bootstrap_config_path,
            },
            &[
                "operation_id = \"42\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect_err("Hub URL mismatch is rejected before network calls");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidConfig("Hub URL does not match trusted install metadata")
        ));
        assert_eq!(transport.url, "");
        assert_eq!(transport.status_url, "");
        assert!(transport.downloads.is_empty());
    }

    #[test]
    fn trusted_install_metadata_rejects_unsafe_service_user_for_sudoers() {
        let contents = [
            "hub_url = \"https://hub.example\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "operation_sudoers_path = \"/etc/sudoers.d/enoki-probe-operations\"",
            "collector_helper_sudoers_path = \"/etc/sudoers.d/enoki-probe-collector-helpers\"",
            "service_name = \"enoki-probe\"",
            "service_user = \"enoki-probe\\nALL=(root) NOPASSWD: ALL\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "",
        ]
        .join("\n");

        let error = parse_trusted_probe_install_metadata(&contents)
            .expect_err("unsafe service user is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata("service user is not safe for sudoers")
        ));
    }

    #[test]
    fn trusted_install_metadata_rejects_root_paths() {
        let contents = [
            "hub_url = \"https://hub.example\"",
            "install_path = \"/\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "service_name = \"enoki-probe\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "",
        ]
        .join("\n");

        let error =
            parse_trusted_probe_install_metadata(&contents).expect_err("root path is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata("paths must not be filesystem root")
        ));
    }

    #[test]
    fn trusted_install_metadata_uses_fresh_split_sudoers_paths() {
        let temp = tempfile::tempdir().expect("temp dir");
        let (contents, operation_sudoers_path, collector_helper_sudoers_path, legacy_sudoers_path) =
            fresh_split_install_metadata_contents(temp.path());

        let install_metadata =
            parse_trusted_probe_install_metadata(&contents).expect("fresh metadata parses");

        assert_eq!(
            install_metadata.operation_sudoers_path,
            operation_sudoers_path
        );
        assert_eq!(
            install_metadata.collector_helper_sudoers_path,
            collector_helper_sudoers_path
        );
        assert_ne!(install_metadata.operation_sudoers_path, legacy_sudoers_path);
    }

    #[test]
    fn supported_legacy_install_metadata_migrates_to_version_one_deterministically() {
        let temp = tempfile::tempdir().expect("temp dir");
        let (contents, _, _, _) = fresh_split_install_metadata_contents(temp.path());
        let metadata_path = temp.path().join("etc/enoki/probe-install.toml");
        let legacy_identity_path = temp.path().join("etc/enoki/custom-identity.toml");
        fs::create_dir_all(metadata_path.parent().expect("metadata dir")).expect("metadata dir");
        fs::write(&metadata_path, contents).expect("legacy metadata");
        fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o644))
            .expect("legacy permissions");

        let metadata = read_trusted_probe_install_metadata_with_file_metadata(
            &metadata_path,
            Some(&legacy_identity_path),
            TrustedFileMetadata {
                is_regular_file: true,
                is_symlink: false,
                mode: 0o644,
                owner_uid: 0,
            },
        )
        .expect("supported legacy metadata migrates");

        assert_eq!(metadata.schema_version, 1);
        assert_eq!(metadata.identity_path, legacy_identity_path);
        let migrated = fs::read_to_string(&metadata_path).expect("migrated metadata");
        assert!(migrated.starts_with("schema_version = 1\n"));
        assert!(migrated.contains(&format!(
            "identity_path = {}",
            toml_string(&legacy_identity_path.display().to_string()),
        )));
        assert!(migrated.contains("service_group = \"enoki-probe\""));
        assert!(
            migrated.contains("service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",)
        );
        assert_eq!(
            fs::metadata(&metadata_path)
                .expect("metadata stat")
                .permissions()
                .mode()
                & 0o777,
            0o600,
        );
    }

    #[test]
    fn version_one_install_metadata_requires_exact_mode_0600() {
        let temp = tempfile::tempdir().expect("temp dir");
        let metadata_path = temp.path().join("probe-install.toml");
        fs::write(
            &metadata_path,
            version_one_install_metadata_contents(temp.path()),
        )
        .expect("metadata");

        for mode in [0o644, 0o640] {
            let error = read_trusted_probe_install_metadata_with_file_metadata(
                &metadata_path,
                None,
                TrustedFileMetadata {
                    is_regular_file: true,
                    is_symlink: false,
                    mode,
                    owner_uid: 0,
                },
            )
            .expect_err("non-0600 v1 metadata is rejected");

            assert!(matches!(
                error,
                ProbeUpgraderRunError::InvalidInstallMetadata(
                    "schema v1 metadata mode must be 0600"
                )
            ));
        }
    }

    #[test]
    fn install_metadata_rejects_symlink_non_regular_and_non_root_files() {
        let temp = tempfile::tempdir().expect("temp dir");
        let metadata_path = temp.path().join("probe-install.toml");
        fs::write(
            &metadata_path,
            version_one_install_metadata_contents(temp.path()),
        )
        .expect("metadata");

        for (file_metadata, expected_message) in [
            (
                TrustedFileMetadata {
                    is_regular_file: true,
                    is_symlink: true,
                    mode: 0o600,
                    owner_uid: 0,
                },
                "metadata path must be a regular non-symlink file",
            ),
            (
                TrustedFileMetadata {
                    is_regular_file: false,
                    is_symlink: false,
                    mode: 0o600,
                    owner_uid: 0,
                },
                "metadata path must be a regular non-symlink file",
            ),
            (
                TrustedFileMetadata {
                    is_regular_file: true,
                    is_symlink: false,
                    mode: 0o600,
                    owner_uid: 1000,
                },
                "metadata file is not owned by root",
            ),
        ] {
            let error = read_trusted_probe_install_metadata_with_file_metadata(
                &metadata_path,
                None,
                file_metadata,
            )
            .expect_err("untrusted metadata file is rejected");

            assert!(matches!(
                &error,
                ProbeUpgraderRunError::InvalidInstallMetadata(message)
                    if *message == expected_message
            ));
            assert_eq!(
                ProbeRepairRunError::from(error).code(),
                "probe_repair_metadata_invalid",
            );
        }
    }

    #[test]
    fn legacy_install_metadata_rejects_modes_outside_the_compatibility_allowlist() {
        let temp = tempfile::tempdir().expect("temp dir");
        let metadata_path = temp.path().join("probe-install.toml");
        let (contents, _, _, _) = fresh_split_install_metadata_contents(temp.path());
        fs::write(&metadata_path, contents).expect("legacy metadata");

        let error = read_trusted_probe_install_metadata_with_file_metadata(
            &metadata_path,
            Some(&temp.path().join("probe-bootstrap.toml")),
            TrustedFileMetadata {
                is_regular_file: true,
                is_symlink: false,
                mode: 0o640,
                owner_uid: 0,
            },
        )
        .expect_err("unrecognized legacy metadata mode is rejected");

        assert!(matches!(
            &error,
            ProbeUpgraderRunError::InvalidInstallMetadata("legacy metadata mode is not supported")
        ));
        assert_eq!(
            ProbeRepairRunError::from(error).code(),
            "probe_repair_metadata_invalid",
        );
    }

    #[cfg(unix)]
    #[test]
    fn trusted_install_metadata_uses_lstat_and_rejects_a_symlink_path() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp dir");
        let target = temp.path().join("target.toml");
        let link = temp.path().join("probe-install.toml");
        fs::write(&target, version_one_install_metadata_contents(temp.path()))
            .expect("metadata target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("metadata mode");
        symlink(&target, &link).expect("metadata symlink");

        let error = read_trusted_probe_install_metadata(&link, None)
            .expect_err("metadata symlink is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "metadata path must be a regular non-symlink file"
            )
        ));
    }

    #[test]
    fn install_metadata_rejects_unsupported_schema_version_with_stable_repair_code() {
        let contents = [
            "schema_version = 2",
            "hub_url = \"https://hub.example\"",
            "",
        ]
        .join("\n");

        let error = parse_trusted_probe_install_metadata(&contents)
            .expect_err("future metadata fails closed");
        let repair_error = ProbeRepairRunError::from(error);

        assert_eq!(repair_error.code(), "probe_repair_metadata_unsupported");
    }

    #[test]
    fn trusted_install_metadata_rejects_old_single_sudoers_path_metadata() {
        let contents = [
            "hub_url = \"https://hub.example\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "sudoers_path = \"/etc/sudoers.d/enoki-probe-upgrader\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "service_name = \"enoki-probe\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "",
        ]
        .join("\n");

        let error =
            parse_trusted_probe_install_metadata(&contents).expect_err("old metadata is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "old sudoers_path metadata is not supported"
            )
        ));
    }

    #[test]
    fn trusted_install_metadata_requires_explicit_split_sudoers_paths() {
        let contents = [
            "hub_url = \"https://hub.example\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "service_name = \"enoki-probe\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "",
        ]
        .join("\n");

        let error = parse_trusted_probe_install_metadata(&contents)
            .expect_err("split sudoers paths are required");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata("missing required field")
        ));
    }

    #[test]
    fn probe_operation_sudoers_uses_fresh_operation_path_without_legacy_mixed_layout() {
        let temp = tempfile::tempdir().expect("temp dir");
        let (contents, operation_sudoers_path, collector_helper_sudoers_path, legacy_sudoers_path) =
            fresh_split_install_metadata_contents(temp.path());
        let install_metadata =
            parse_trusted_probe_install_metadata(&contents).expect("fresh metadata parses");
        let bootstrap_config_path = temp.path().join("etc/enoki/probe-bootstrap.toml");

        write_probe_operation_sudoers(&install_metadata, &bootstrap_config_path)
            .expect("operation sudoers are written");

        let sudoers = fs::read_to_string(&operation_sudoers_path).expect("operation sudoers");
        assert!(sudoers.contains("internal-upgrader --config"));
        assert!(sudoers.contains("internal-uninstaller --config"));
        assert!(!sudoers.contains("internal-privileged-collector-helper"));
        assert!(!sudoers.contains("disk-health.smartctl"));
        assert!(!legacy_sudoers_path.exists());
        assert!(!collector_helper_sudoers_path.exists());
    }

    #[test]
    fn probe_operation_sudoers_rejects_paths_unsafe_for_sudoers() {
        let temp = tempfile::tempdir().expect("temp dir");
        let unsafe_install_path = temp.path().join("bin/enoki probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata = trusted_install_metadata(
            &unsafe_install_path,
            &status_path,
            assets_public_key_sha256(),
        );
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");

        let error = write_probe_operation_sudoers(&install_metadata, &bootstrap_config_path)
            .expect_err("unsafe install path is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata("sudoers command contains unsafe values")
        ));
    }

    #[test]
    fn probe_operation_sudoers_rejects_bootstrap_path_unsafe_for_sudoers() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        let unsafe_bootstrap_config_path = temp.path().join("probe bootstrap.toml");

        let error = write_probe_operation_sudoers(&install_metadata, &unsafe_bootstrap_config_path)
            .expect_err("unsafe bootstrap path is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata("sudoers command contains unsafe values")
        ));
    }

    #[test]
    fn collector_helper_sudoers_includes_exposed_compiled_privileged_collector_helpers() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());

        write_collector_helper_sudoers(&install_metadata, &SmartctlCollectorHelperExposure)
            .expect("collector-helper sudoers render");

        let sudoers = fs::read_to_string(&install_metadata.collector_helper_sudoers_path)
            .expect("collector-helper sudoers");
        assert!(
            sudoers.contains("internal-privileged-collector-helper --helper disk-health.smartctl")
        );
        assert!(!sudoers.contains("internal-upgrader --config"));
        assert!(!sudoers.contains("internal-uninstaller --config"));
        assert!(!sudoers.contains("internal-privileged-collector --collector"));
        assert!(!sudoers.contains("--collector disk-health.smartctl"));
        assert!(sudoers.contains("--property=RuntimeMaxSec=10"));
        assert!(sudoers.contains("--property=PrivateNetwork=yes"));
        assert!(!sudoers.contains('*'));
        assert!(!sudoers.contains("--operation-id"));
        assert!(!sudoers.contains("--target-probe-version"));
    }

    #[test]
    fn collector_helper_sudoers_is_absent_when_no_helper_is_exposed() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        fs::create_dir_all(
            install_metadata
                .collector_helper_sudoers_path
                .parent()
                .expect("sudoers parent"),
        )
        .expect("sudoers parent");
        fs::write(
            &install_metadata.collector_helper_sudoers_path,
            "stale collector helper sudoers",
        )
        .expect("stale helper sudoers");

        write_collector_helper_sudoers(&install_metadata, &NoCollectorHelperExposure)
            .expect("collector-helper sudoers omitted");

        assert!(!install_metadata.collector_helper_sudoers_path.exists());
    }

    struct NoCollectorHelperExposure;

    impl CollectorHelperExposureEnvironment for NoCollectorHelperExposure {
        fn tool_exists(&self, _path: &Path) -> bool {
            false
        }
    }

    struct SmartctlCollectorHelperExposure;

    impl CollectorHelperExposureEnvironment for SmartctlCollectorHelperExposure {
        fn tool_exists(&self, path: &Path) -> bool {
            path == Path::new("/usr/sbin/smartctl")
        }
    }

    #[test]
    fn internal_probe_upgrader_validates_stdin_token_with_hub_before_noop_result() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "probe_private_key_pem = \"test-private-key\"",
                "",
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport::default();

        let mut systemd = RecordingSystemdRunner::default();
        let install_metadata = trusted_install_metadata(
            &temp.path().join("bin/enoki-probe"),
            &temp.path().join("state/probe-operation-status.toml"),
            assets_public_key_sha256(),
        );
        let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path: bootstrap_config_path.clone(),
            },
            &[
                "operation_id = \"42\"",
                "target_probe_version = \"0.2.0\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("missing assets are reported as operation failure");

        assert_eq!(
            transport.url,
            "https://hub.example/api/probe/operations/42/token/validate",
        );
        assert_eq!(transport.probe_id, "probe_01");
        assert_eq!(
            transport.body,
            "{\"targetProbeVersion\":\"0.2.0\",\"token\":\"probe-operation-token\"}",
        );
        assert_eq!(
            result,
            ProbeUpgraderResult {
                error_code: Some("asset_missing".to_string()),
                message: Some("Probe Asset Set archive is missing".to_string()),
                operation_id: "42".to_string(),
                status: "failed".to_string(),
            },
        );
        assert_eq!(
            transport.downloads,
            vec!["https://hub.example/api/probe/assets/manifest.json"],
        );
    }

    #[test]
    fn internal_probe_upgrader_rejects_unsafe_hub_url_before_token_validation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"http://hub.example\"".to_string(),
                "probe_id = \"probe_01\"".to_string(),
                "probe_private_key_pem = \"test-private-key\"".to_string(),
                String::new(),
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let error = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
            },
            &operation_stdin(),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect_err("unsafe Hub URL is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidConfig("invalid Hub URL")
        ));
        assert_eq!(transport.url, "");
        assert!(transport.downloads.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_rejects_bootstrap_hub_url_mismatch_before_token_validation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://attacker.example\"".to_string(),
                "probe_id = \"probe_01\"".to_string(),
                "probe_private_key_pem = \"test-private-key\"".to_string(),
                String::new(),
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let error = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
            },
            &operation_stdin(),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect_err("Hub URL mismatch is rejected before network calls");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidConfig("Hub URL does not match trusted install metadata")
        ));
        assert_eq!(transport.url, "");
        assert_eq!(transport.status_url, "");
        assert!(transport.downloads.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_allows_localhost_http_hub_for_development() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata = trusted_install_metadata_for_hub(
            "http://127.0.0.1:8787/base/",
            &install_path,
            &status_path,
            assets_public_key_sha256(),
        );
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"http://127.0.0.1:8787/base/\"".to_string(),
                "probe_id = \"probe_01\"".to_string(),
                "probe_private_key_pem = \"test-private-key\"".to_string(),
                String::new(),
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
            },
            &operation_stdin(),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("missing assets are reported as operation failure");

        assert_eq!(
            transport.url,
            "http://127.0.0.1:8787/base/api/probe/operations/42/token/validate",
        );
        assert_eq!(
            transport.downloads,
            vec!["http://127.0.0.1:8787/base/api/probe/assets/manifest.json"],
        );
        assert_eq!(result.error_code.as_deref(), Some("asset_missing"));
    }

    #[test]
    fn formats_probe_upgrader_running_result_for_probe_runtime() {
        let result = ProbeUpgraderResult {
            error_code: None,
            message: None,
            operation_id: "42".to_string(),
            status: "running".to_string(),
        };

        assert_eq!(
            parse_probe_upgrader_result(&format_probe_upgrader_result(&result)),
            Some(result),
        );
    }

    #[test]
    fn internal_probe_upgrader_verifies_assets_replaces_binary_writes_status_and_restarts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let state_dir = temp.path().join("state");
        let status_path = state_dir.join("probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
        let install_metadata = trusted_install_metadata_for_hub(
            "https://hub.example/base",
            &install_path,
            &status_path,
            assets.public_key_sha256.clone(),
        );
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example/base\"".to_string(),
                "probe_id = \"probe_01\"".to_string(),
                "probe_private_key_pem = \"test-private-key\"".to_string(),
                format!(
                    "state_dir = {}",
                    toml_string(state_dir.to_str().expect("state dir"))
                ),
                format!(
                    "operation_status_path = {}",
                    toml_string(status_path.to_str().expect("status path")),
                ),
                format!(
                    "install_path = {}",
                    toml_string(install_path.to_str().expect("install path")),
                ),
                "service_name = \"enoki-probe\"".to_string(),
                format!(
                    "probe_asset_public_key_sha256 = \"{}\"",
                    assets.public_key_sha256,
                ),
                String::new(),
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example/base"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path: bootstrap_config_path.clone(),
            },
            &[
                "operation_id = \"42\"",
                "target_probe_version = \"0.2.0\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("upgrade succeeds");

        assert_eq!(
            result,
            ProbeUpgraderResult {
                error_code: None,
                message: None,
                operation_id: "42".to_string(),
                status: "running".to_string(),
            },
        );
        assert!(
            fs::read_to_string(&install_path)
                .expect("binary")
                .contains("new probe")
        );
        assert_eq!(systemd.restarted, vec!["enoki-probe"]);
        assert_eq!(
            fs::read_to_string(&status_path).expect("status"),
            [
                "operation_id = \"42\"",
                "target_probe_version = \"0.2.0\"",
                "status = \"running\"",
                "",
            ]
            .join("\n"),
        );
        assert_eq!(
            transport.downloads,
            vec![
                "https://hub.example/base/api/probe/assets/manifest.json",
                "https://hub.example/base/api/probe/assets/manifest.json.sig",
                "https://hub.example/base/api/probe/assets/signing-key.pem",
                &format!(
                    "https://hub.example/base/api/probe/assets/enoki-probe-{}.tar.gz",
                    host_probe_asset_target().expect("supported test architecture"),
                ),
            ],
        );
        let bootstrap_config =
            fs::read_to_string(bootstrap_config_path).expect("bootstrap config remains");
        assert!(bootstrap_config.contains("probe_id = \"probe_01\""));
    }

    #[test]
    fn internal_probe_upgrader_renders_collector_helper_sudoers_with_newly_installed_probe_binary()
    {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let planner_log_path = temp.path().join("planner.log");
        let replacement_probe = format!(
            r#"#!/bin/sh
if [ "${{1:-}}" = "internal-render-collector-helper-sudoers" ]; then
  printf '%s\n' "$*" > '{}'
  cat <<'EOF'
# Managed by replacement Probe.
enoki-probe ALL=(root) NOPASSWD: replacement-helper-from-new-binary
EOF
  exit 0
fi
echo replacement probe
"#,
            planner_log_path.display(),
        );
        let assets = signed_assets("0.2.0", &replacement_probe, None);
        let mut install_metadata = trusted_install_metadata(
            &install_path,
            &status_path,
            assets.public_key_sha256.clone(),
        );
        let old_sudoers_path = temp.path().join("etc/sudoers.d/enoki-probe-upgrader");
        fs::create_dir_all(old_sudoers_path.parent().expect("old sudoers parent"))
            .expect("old sudoers parent");
        fs::write(&old_sudoers_path, "old mixed sudoers").expect("old sudoers");
        fs::create_dir_all(
            install_metadata
                .operation_sudoers_path
                .parent()
                .expect("operation sudoers parent"),
        )
        .expect("operation sudoers parent");
        fs::write(
            &install_metadata.operation_sudoers_path,
            "stale operation sudoers",
        )
        .expect("stale operation sudoers");
        install_metadata.old_sudoers_paths = vec![old_sudoers_path.clone()];
        write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
            .expect("write bootstrap config");
        let bootstrap_config =
            read_upgrader_bootstrap_config(&bootstrap_config_path).expect("bootstrap config");
        let operation = ProbeUpgraderOperationMetadata {
            operation_id: "42".to_string(),
            target_probe_version: "0.2.0".to_string(),
            token: "probe-operation-token".to_string(),
        };
        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        execute_probe_upgrade_with_current_version(
            &operation,
            &bootstrap_config,
            &bootstrap_config_path,
            &install_metadata,
            &mut transport,
            &mut systemd,
            "0.1.9",
        )
        .expect("upgrade succeeds");

        let operation_sudoers = fs::read_to_string(&install_metadata.operation_sudoers_path)
            .expect("operation sudoers");
        let collector_helper_sudoers =
            fs::read_to_string(&install_metadata.collector_helper_sudoers_path)
                .expect("collector-helper sudoers");
        assert!(operation_sudoers.contains("internal-upgrader --config"));
        assert!(operation_sudoers.contains("internal-uninstaller --config"));
        assert!(!operation_sudoers.contains("internal-privileged-collector-helper"));
        assert!(collector_helper_sudoers.contains("replacement-helper-from-new-binary"));
        assert!(!collector_helper_sudoers.contains("disk-health.smartctl"));
        assert!(!collector_helper_sudoers.contains("internal-upgrader --config"));
        assert_eq!(
            fs::read_to_string(planner_log_path).expect("planner invocation log"),
            "internal-render-collector-helper-sudoers --service-user enoki-probe --probe-binary "
                .to_string()
                + install_path.to_str().expect("install path")
                + "\n",
        );
        assert!(!old_sudoers_path.exists());
        assert_eq!(systemd.restarted, vec!["enoki-probe".to_string()]);
    }

    #[test]
    fn internal_probe_upgrader_deletes_collector_helper_sudoers_when_no_helper_is_exposed() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let assets = signed_assets(
            "0.2.0",
            r#"#!/bin/sh
if [ "${1:-}" = "internal-render-collector-helper-sudoers" ]; then
  exit 0
fi
echo replacement probe
"#,
            None,
        );
        let install_metadata = trusted_install_metadata(
            &install_path,
            &status_path,
            assets.public_key_sha256.clone(),
        );
        fs::create_dir_all(
            install_metadata
                .collector_helper_sudoers_path
                .parent()
                .expect("collector-helper sudoers parent"),
        )
        .expect("collector-helper sudoers parent");
        fs::write(
            &install_metadata.collector_helper_sudoers_path,
            "stale collector helper sudoers",
        )
        .expect("stale collector-helper sudoers");
        write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
            .expect("write bootstrap config");
        let bootstrap_config =
            read_upgrader_bootstrap_config(&bootstrap_config_path).expect("bootstrap config");
        let operation = ProbeUpgraderOperationMetadata {
            operation_id: "42".to_string(),
            target_probe_version: "0.2.0".to_string(),
            token: "probe-operation-token".to_string(),
        };
        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        execute_probe_upgrade_with_current_version(
            &operation,
            &bootstrap_config,
            &bootstrap_config_path,
            &install_metadata,
            &mut transport,
            &mut systemd,
            "0.1.9",
        )
        .expect("upgrade succeeds");

        let operation_sudoers = fs::read_to_string(&install_metadata.operation_sudoers_path)
            .expect("operation sudoers");
        assert!(operation_sudoers.contains("internal-upgrader --config"));
        assert!(operation_sudoers.contains("internal-uninstaller --config"));
        assert!(!operation_sudoers.contains("internal-privileged-collector-helper"));
        assert!(!install_metadata.collector_helper_sudoers_path.exists());
        assert_eq!(systemd.restarted, vec!["enoki-probe".to_string()]);
    }

    #[test]
    fn internal_probe_upgrader_rejects_checksum_mismatch_before_replacement() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let assets = signed_assets("0.2.0", "new probe", Some("0".repeat(64)));
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata = trusted_install_metadata(
            &install_path,
            &status_path,
            assets.public_key_sha256.clone(),
        );
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"".to_string(),
                "probe_id = \"probe_01\"".to_string(),
                "probe_private_key_pem = \"test-private-key\"".to_string(),
                format!(
                    "state_dir = {}",
                    toml_string(temp.path().join("state").to_str().expect("state dir")),
                ),
                format!(
                    "install_path = {}",
                    toml_string(install_path.to_str().expect("install path")),
                ),
                format!(
                    "probe_asset_public_key_sha256 = \"{}\"",
                    assets.public_key_sha256,
                ),
                String::new(),
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
            },
            &[
                "operation_id = \"42\"",
                "target_probe_version = \"0.2.0\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("checksum mismatch is reported as operation failure");

        assert_eq!(
            result,
            ProbeUpgraderResult {
                error_code: Some("checksum_failure".to_string()),
                message: Some("Probe archive sha256 verification failed".to_string()),
                operation_id: "42".to_string(),
                status: "failed".to_string(),
            },
        );
        assert_eq!(
            fs::read_to_string(&install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_rejects_untrusted_signing_key() {
        let (result, install_path, systemd) =
            run_upgrade_with_assets(signed_assets("0.2.0", "new probe", None), "0".repeat(64));

        assert_eq!(result.error_code.as_deref(), Some("signing_key_untrusted"));
        assert_eq!(
            result.message.as_deref(),
            Some("Probe asset signing key fingerprint verification failed"),
        );
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_rejects_manifest_signature_failure() {
        let mut assets = signed_assets("0.2.0", "new probe", None);
        assets.signature[0] ^= 0xff;
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

        assert_eq!(result.error_code.as_deref(), Some("signature_failure"));
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_rejects_target_version_mismatch() {
        let assets = signed_assets("0.3.0", "new probe", None);
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

        assert_eq!(result.error_code.as_deref(), Some("target_mismatch"));
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_rejects_signed_downgrade_asset_before_replacement() {
        let assets = signed_assets("0.1.9", "downgraded probe", None);
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets_and_current_version(
            assets,
            public_key_sha256,
            "0.2.0",
            "0.1.9",
        );

        assert!(matches!(
            result,
            Err(ProbeUpgraderRunError::DowngradeRejected)
        ));
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_rejects_signed_same_version_replay_before_replacement() {
        let assets = signed_assets("0.2.0", "replayed probe", None);
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets_and_current_version(
            assets,
            public_key_sha256,
            "0.2.0",
            "0.2.0",
        );

        assert!(matches!(
            result,
            Err(ProbeUpgraderRunError::DowngradeRejected)
        ));
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_accepts_signed_newer_asset_with_local_version_guard() {
        let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets_and_current_version(
            assets,
            public_key_sha256,
            "0.1.9",
            "0.2.0",
        );

        assert!(result.is_ok());
        assert!(
            fs::read_to_string(install_path)
                .expect("binary")
                .contains("new probe")
        );
        assert_eq!(systemd.restarted, vec!["enoki-probe".to_string()]);
    }

    #[test]
    fn internal_probe_upgrader_accepts_tag_prefixed_manifest_version() {
        let assets = signed_assets("v0.2.0", &replacement_probe_binary("new probe"), None);
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

        assert_eq!(result.error_code, None);
        assert!(
            fs::read_to_string(install_path)
                .expect("binary")
                .contains("new probe")
        );
        assert_eq!(systemd.restarted, vec!["enoki-probe".to_string()]);
    }

    #[test]
    fn internal_probe_upgrader_rejects_missing_architecture_asset() {
        let assets = signed_assets_for_target(
            "0.2.0",
            "new probe",
            None,
            "i686-unknown-linux-gnu",
            "enoki-probe-i686-unknown-linux-gnu.tar.gz",
        );
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

        assert_eq!(result.error_code.as_deref(), Some("architecture_missing"));
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_rejects_missing_asset_download() {
        let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
        let public_key_sha256 = assets.public_key_sha256.clone();
        let archive_file = assets.archive_file.clone();
        let (result, install_path, systemd) =
            run_upgrade_with_assets_filtering(assets, public_key_sha256, |url| {
                !url.ends_with(&archive_file)
            });

        assert_eq!(result.error_code.as_deref(), Some("asset_missing"));
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_rejects_unsafe_asset_filename() {
        let assets = signed_assets_for_target(
            "0.2.0",
            "new probe",
            None,
            host_probe_asset_target().expect("supported test architecture"),
            "../enoki-probe.tar.gz",
        );
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

        assert_eq!(result.error_code.as_deref(), Some("asset_missing"));
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn internal_probe_upgrader_reports_post_replacement_restart_failure() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
        let install_metadata = trusted_install_metadata(
            &install_path,
            &status_path,
            assets.public_key_sha256.clone(),
        );
        write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
            .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner {
            failure: Some("systemd refused restart".to_string()),
            ..RecordingSystemdRunner::default()
        };

        let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
            },
            &operation_stdin(),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("restart failure is reported as operation failure");

        assert!(
            fs::read_to_string(&install_path)
                .expect("binary")
                .contains("new probe")
        );
        assert_eq!(
            result.error_code.as_deref(),
            Some("post_replacement_restart_failure"),
        );
        assert!(
            result
                .message
                .as_deref()
                .expect("message")
                .contains("Probe binary was replaced")
        );
        assert_eq!(
            transport.status_url,
            "https://hub.example/api/probe/operations/42/status",
        );
        assert!(
            transport
                .status_body
                .contains("\"errorCode\":\"post_replacement_restart_failure\"")
        );
        assert!(transport.status_body.contains("\"status\":\"failed\""));
        assert_eq!(
            fs::read_to_string(status_path).expect("status"),
            [
                "operation_id = \"42\"",
                "target_probe_version = \"0.2.0\"",
                "status = \"failed\"",
                "error_code = \"post_replacement_restart_failure\"",
                "message = \"Probe binary was replaced, but restarting the Probe service failed: failed to restart Probe service: systemd refused restart\"",
                "",
            ]
            .join("\n"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_operation_status_preflight_rejects_existing_status_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        fs::create_dir_all(status_path.parent().expect("status dir")).expect("status dir");
        let target_path = temp.path().join("attacker-target.toml");
        fs::write(&target_path, "target").expect("target");
        symlink(&target_path, &status_path).expect("status symlink");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());

        let error = preflight_local_operation_status_writable(&install_metadata)
            .expect_err("status symlink is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "operation status path must not be a symlink"
            )
        ));
        assert_eq!(fs::read_to_string(target_path).expect("target"), "target");
    }

    #[cfg(unix)]
    #[test]
    fn local_operation_status_preflight_rejects_group_writable_status_parent() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_dir = temp.path().join("state");
        let status_path = status_dir.join("probe-operation-status.toml");
        fs::create_dir_all(&status_dir).expect("status dir");
        fs::set_permissions(&status_dir, fs::Permissions::from_mode(0o775))
            .expect("status dir perms");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());

        let error = preflight_local_operation_status_writable(&install_metadata)
            .expect_err("writable status parent is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "operation status parent must not be writable by group or other"
            )
        ));
        assert!(!status_path.exists());
    }

    #[test]
    fn internal_probe_upgrader_rejects_bootstrap_privileged_field_mismatch() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let assets = signed_assets("0.2.0", "new probe", None);
        let install_metadata = trusted_install_metadata(
            &install_path,
            &status_path,
            assets.public_key_sha256.clone(),
        );
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"".to_string(),
                "probe_id = \"probe_01\"".to_string(),
                "probe_private_key_pem = \"test-private-key\"".to_string(),
                "install_path = \"/tmp/attacker-controlled-probe\"".to_string(),
                format!(
                    "probe_asset_public_key_sha256 = \"{}\"",
                    assets.public_key_sha256,
                ),
                String::new(),
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        let error = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
            },
            &operation_stdin(),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect_err("mismatch is rejected before network calls");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidConfig(
                "install path does not match trusted install metadata"
            )
        ));
        assert_eq!(transport.url, "");
        assert!(transport.downloads.is_empty());
        assert_eq!(
            fs::read_to_string(&install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
    }

    #[test]
    fn probe_asset_target_supports_only_x86_64_and_aarch64() {
        assert_eq!(
            probe_asset_target_for_arch_and_abi("x86_64", LinuxAbi::Musl).expect("x86 target"),
            "x86_64-unknown-linux-musl",
        );
        assert_eq!(
            probe_asset_target_for_arch_and_abi("aarch64", LinuxAbi::Musl).expect("aarch64 target"),
            "aarch64-unknown-linux-musl",
        );
        assert_eq!(
            probe_asset_target_for_arch_and_abi("x86_64", LinuxAbi::Gnu).expect("x86 target"),
            "x86_64-unknown-linux-gnu",
        );
        assert_eq!(
            probe_asset_target_for_arch_and_abi("aarch64", LinuxAbi::Gnu).expect("aarch64 target"),
            "aarch64-unknown-linux-gnu",
        );
        assert!(matches!(
            probe_asset_target_for_arch_and_abi("riscv64", LinuxAbi::Gnu),
            Err(ProbeUpgraderRunError::UnsupportedArchitecture(architecture))
                if architecture == "riscv64"
        ));
    }

    #[test]
    fn probe_archive_rejects_path_traversal_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let archive = archive_with_entry("../enoki-probe", tar::EntryType::Regular);

        let error = replace_installed_probe_binary(&archive, &install_path)
            .expect_err("path traversal is rejected");

        assert!(matches!(error, ProbeUpgraderRunError::UnsafeArchive(_)));
        assert_eq!(
            fs::read_to_string(&install_path).expect("binary"),
            "old probe"
        );
    }

    #[test]
    fn probe_archive_rejects_symlink_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let archive = archive_with_entry("enoki-probe", tar::EntryType::Symlink);

        let error = replace_installed_probe_binary(&archive, &install_path)
            .expect_err("symlink is rejected");

        assert!(matches!(error, ProbeUpgraderRunError::UnsafeArchive(_)));
        assert_eq!(
            fs::read_to_string(&install_path).expect("binary"),
            "old probe"
        );
    }

    #[test]
    fn probe_archive_rejects_hardlink_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let archive = archive_with_entry("enoki-probe", tar::EntryType::Link);

        let error = replace_installed_probe_binary(&archive, &install_path)
            .expect_err("hardlink is rejected");

        assert!(matches!(error, ProbeUpgraderRunError::UnsafeArchive(_)));
        assert_eq!(
            fs::read_to_string(&install_path).expect("binary"),
            "old probe"
        );
    }

    struct SignedAssets {
        archive_file: String,
        archive: Vec<u8>,
        manifest: Vec<u8>,
        public_key: Vec<u8>,
        public_key_sha256: String,
        signature: Vec<u8>,
    }

    impl SignedAssets {
        fn for_hub(&self, hub_url: &str) -> HashMap<String, Vec<u8>> {
            HashMap::from([
                (
                    format!("{hub_url}/api/probe/assets/manifest.json"),
                    self.manifest.clone(),
                ),
                (
                    format!("{hub_url}/api/probe/assets/manifest.json.sig"),
                    self.signature.clone(),
                ),
                (
                    format!("{hub_url}/api/probe/assets/signing-key.pem"),
                    self.public_key.clone(),
                ),
                (
                    format!("{hub_url}/api/probe/assets/{}", self.archive_file),
                    self.archive.clone(),
                ),
            ])
        }
    }

    fn signed_assets(
        version: &str,
        binary_contents: &str,
        sha256_override: Option<String>,
    ) -> SignedAssets {
        let target = host_probe_asset_target().expect("supported test architecture");
        signed_assets_for_target(
            version,
            binary_contents,
            sha256_override,
            target,
            &format!("enoki-probe-{target}.tar.gz"),
        )
    }

    fn replacement_probe_binary(label: &str) -> String {
        format!(
            r#"#!/bin/sh
if [ "${{1:-}}" = "internal-render-collector-helper-sudoers" ]; then
  exit 0
fi
printf '%s\n' '{}'
"#,
            label,
        )
    }

    fn signed_assets_for_target(
        version: &str,
        binary_contents: &str,
        sha256_override: Option<String>,
        target: &str,
        archive_file: &str,
    ) -> SignedAssets {
        let archive = archive_with_probe_binary(binary_contents);
        let sha256 = sha256_override.unwrap_or_else(|| hex_sha256(&archive));
        let manifest = format!(
            "{{\"assets\":[{{\"file\":\"{}\",\"sha256\":\"{}\",\"size\":{},\"target\":\"{}\"}}],\"kind\":\"enoki-probe-assets\",\"signature\":{{\"algorithm\":\"rsa-sha256\",\"file\":\"manifest.json.sig\",\"publicKey\":\"signing-key.pem\"}},\"version\":\"{}\"}}\n",
            archive_file,
            sha256,
            archive.len(),
            target,
            version,
        )
        .into_bytes();
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("private key");
        let public_key = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("public key")
            .into_bytes();
        let signature = SigningKey::<Sha256>::new(private_key)
            .sign_with_rng(&mut rng, &manifest)
            .to_vec();
        let public_key_sha256 = hex_sha256(&public_key);

        SignedAssets {
            archive_file: archive_file.to_string(),
            archive,
            manifest,
            public_key,
            public_key_sha256,
            signature,
        }
    }

    fn trusted_install_metadata(
        install_path: &Path,
        operation_status_path: &Path,
        probe_asset_public_key_sha256: String,
    ) -> TrustedProbeInstallMetadata {
        trusted_install_metadata_for_hub(
            "https://hub.example",
            install_path,
            operation_status_path,
            probe_asset_public_key_sha256,
        )
    }

    fn run_repair_with_assets(
        assets: SignedAssets,
        pinned_key_sha256: String,
        identity_failure: Option<String>,
    ) -> (
        Result<ProbeRepairResult, ProbeRepairRunError>,
        PathBuf,
        tempfile::TempDir,
    ) {
        run_repair_with_assets_for_versions(
            assets,
            pinned_key_sha256,
            identity_failure,
            "0.2.0",
            "0.2.0",
        )
    }

    fn run_repair_with_assets_for_versions(
        assets: SignedAssets,
        pinned_key_sha256: String,
        identity_failure: Option<String>,
        current_probe_version: &str,
        failed_target_version: &str,
    ) -> (
        Result<ProbeRepairResult, ProbeRepairRunError>,
        PathBuf,
        tempfile::TempDir,
    ) {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("usr/local/bin/enoki-probe");
        let status_path = temp
            .path()
            .join("var/lib/enoki-probe/probe-operation-status.toml");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "broken candidate").expect("broken candidate");
        let mut install_metadata =
            trusted_install_metadata(&install_path, &status_path, pinned_key_sha256);
        install_metadata.identity_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
        install_metadata.service_unit_path =
            temp.path().join("etc/systemd/system/enoki-probe.service");
        fs::create_dir_all(
            install_metadata
                .identity_path
                .parent()
                .expect("identity dir"),
        )
        .expect("identity dir");
        fs::write(
            &install_metadata.identity_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "probe_private_key_pem = \"complete-private-key\"",
                "",
            ]
            .join("\n"),
        )
        .expect("identity config");
        fs::set_permissions(
            &install_metadata.identity_path,
            fs::Permissions::from_mode(0o600),
        )
        .expect("identity permissions");
        write_failed_upgrade_marker(&status_path, failed_target_version);
        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example"),
            identity_failure,
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();
        let result = run_probe_repair_with_current_version_and_systemd_runner(
            &install_metadata,
            &mut transport,
            &mut systemd,
            0,
            test_process_uid(),
            current_probe_version,
        );
        (result, install_path, temp)
    }

    fn write_failed_upgrade_marker(path: &Path, target_probe_version: &str) {
        fs::create_dir_all(path.parent().expect("marker parent")).expect("marker parent");
        fs::write(
            path,
            [
                "operation_id = \"operation_41\"".to_string(),
                format!(
                    "target_probe_version = {}",
                    toml_string(target_probe_version)
                ),
                "status = \"failed\"".to_string(),
                "error_code = \"post_replacement_restart_failure\"".to_string(),
                "message = \"systemd refused restart\"".to_string(),
                String::new(),
            ]
            .join("\n"),
        )
        .expect("failed Upgrade marker");
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
            .expect("failed Upgrade marker permissions");
    }

    fn test_process_uid() -> u32 {
        // SAFETY: `geteuid` takes no arguments and only reads the process credentials.
        unsafe { libc::geteuid() }
    }

    fn run_repair_reconstruction_case(
        assets: &SignedAssets,
        failure_step: Option<&'static str>,
        blocked_write: Option<&str>,
    ) -> (
        Result<ProbeRepairResult, ProbeRepairRunError>,
        Vec<String>,
        tempfile::TempDir,
    ) {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("usr/local/bin/enoki-probe");
        let status_path = temp
            .path()
            .join("var/lib/enoki-probe/probe-operation-status.toml");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "broken candidate").expect("candidate binary");
        let mut install_metadata = trusted_install_metadata(
            &install_path,
            &status_path,
            assets.public_key_sha256.clone(),
        );
        install_metadata.identity_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
        install_metadata.service_unit_path =
            temp.path().join("etc/systemd/system/enoki-probe.service");
        fs::create_dir_all(
            install_metadata
                .identity_path
                .parent()
                .expect("identity dir"),
        )
        .expect("identity dir");
        fs::write(
            &install_metadata.identity_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "probe_private_key_pem = \"complete-private-key\"",
                "",
            ]
            .join("\n"),
        )
        .expect("identity config");
        fs::set_permissions(
            &install_metadata.identity_path,
            fs::Permissions::from_mode(0o600),
        )
        .expect("identity mode");
        write_failed_upgrade_marker(&status_path, "0.2.0");

        if let Some(blocked_write) = blocked_write {
            let blocker = temp.path().join(format!("blocked-{blocked_write}"));
            fs::write(&blocker, "not a directory").expect("write blocker");
            match blocked_write {
                "sudoers" => install_metadata.operation_sudoers_path = blocker.join("sudoers"),
                "service-unit" => {
                    install_metadata.service_unit_path = blocker.join("enoki-probe.service")
                }
                _ => panic!("unsupported blocked write"),
            }
        }

        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner {
            failure_step,
            ..RecordingSystemdRunner::default()
        };
        let result = run_probe_repair_with_current_version_and_systemd_runner(
            &install_metadata,
            &mut transport,
            &mut systemd,
            0,
            test_process_uid(),
            "0.2.0",
        );
        (result, systemd.calls, temp)
    }

    fn trusted_install_metadata_for_hub(
        hub_url: &str,
        install_path: &Path,
        operation_status_path: &Path,
        probe_asset_public_key_sha256: String,
    ) -> TrustedProbeInstallMetadata {
        TrustedProbeInstallMetadata {
            schema_version: 0,
            hub_url: hub_url::normalized_base(hub_url).expect("valid test Hub URL"),
            identity_path: operation_status_path
                .parent()
                .expect("status parent")
                .join("probe-bootstrap.toml"),
            install_path: install_path.to_path_buf(),
            operation_status_path: operation_status_path.to_path_buf(),
            probe_asset_public_key_sha256,
            service_name: "enoki-probe".to_string(),
            service_group: "enoki-probe".to_string(),
            service_unit_path: operation_status_path
                .parent()
                .expect("status parent")
                .join("enoki-probe.service"),
            service_user: "enoki-probe".to_string(),
            state_dir: operation_status_path
                .parent()
                .expect("status parent")
                .to_path_buf(),
            operation_sudoers_path: operation_status_path
                .parent()
                .expect("status parent")
                .join("enoki-probe-operations.sudoers"),
            collector_helper_sudoers_path: operation_status_path
                .parent()
                .expect("status parent")
                .join("enoki-probe-collector-helpers.sudoers"),
            old_sudoers_paths: Vec::new(),
        }
    }

    fn fresh_split_install_metadata_contents(root: &Path) -> (String, PathBuf, PathBuf, PathBuf) {
        let operation_sudoers_path = root.join("etc/sudoers.d/enoki-probe-operations");
        let collector_helper_sudoers_path =
            root.join("etc/sudoers.d/enoki-probe-collector-helpers");
        let legacy_sudoers_path = root.join("etc/sudoers.d/enoki-probe-upgrader");
        let contents = [
            "hub_url = \"https://hub.example\"".to_string(),
            format!(
                "install_path = \"{}\"",
                root.join("usr/local/bin/enoki-probe").display()
            ),
            format!(
                "operation_status_path = \"{}\"",
                root.join("var/lib/enoki-probe/probe-operation-status.toml")
                    .display()
            ),
            format!(
                "operation_sudoers_path = \"{}\"",
                operation_sudoers_path.display()
            ),
            format!(
                "collector_helper_sudoers_path = \"{}\"",
                collector_helper_sudoers_path.display()
            ),
            format!(
                "probe_asset_public_key_sha256 = \"{}\"",
                assets_public_key_sha256()
            ),
            "service_name = \"enoki-probe\"".to_string(),
            "service_user = \"enoki-probe\"".to_string(),
            format!(
                "state_dir = \"{}\"",
                root.join("var/lib/enoki-probe").display()
            ),
            "".to_string(),
        ]
        .join("\n");

        (
            contents,
            operation_sudoers_path,
            collector_helper_sudoers_path,
            legacy_sudoers_path,
        )
    }

    fn version_one_install_metadata_contents(root: &Path) -> String {
        let (legacy, _, _, _) = fresh_split_install_metadata_contents(root);
        [
            "schema_version = 1".to_string(),
            format!(
                "identity_path = \"{}\"",
                root.join("etc/enoki/probe-bootstrap.toml").display()
            ),
            "service_group = \"enoki-probe\"".to_string(),
            format!(
                "service_unit_path = \"{}\"",
                root.join("etc/systemd/system/enoki-probe.service")
                    .display()
            ),
            legacy,
        ]
        .join("\n")
    }

    fn assets_public_key_sha256() -> String {
        "a".repeat(64)
    }

    fn run_upgrade_with_assets(
        assets: SignedAssets,
        public_key_sha256: String,
    ) -> (ProbeUpgraderResult, PathBuf, RecordingSystemdRunner) {
        run_upgrade_with_assets_filtering(assets, public_key_sha256, |_| true)
    }

    fn run_upgrade_with_assets_filtering(
        assets: SignedAssets,
        public_key_sha256: String,
        keep_asset: impl Fn(&str) -> bool,
    ) -> (ProbeUpgraderResult, PathBuf, RecordingSystemdRunner) {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, public_key_sha256);
        write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
            .expect("write bootstrap config");
        let mut hub_assets = assets.for_hub("https://hub.example");
        hub_assets.retain(|url, _| keep_asset(url));
        let mut transport = RecordingValidationTransport {
            assets: hub_assets,
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
            },
            &operation_stdin(),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("operation failure is returned");
        let persisted_install_path = temp.keep().join("bin/enoki-probe");

        (result, persisted_install_path, systemd)
    }

    fn run_upgrade_with_assets_and_current_version(
        assets: SignedAssets,
        public_key_sha256: String,
        current_probe_version: &str,
        target_probe_version: &str,
    ) -> (
        Result<(), ProbeUpgraderRunError>,
        PathBuf,
        RecordingSystemdRunner,
    ) {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, public_key_sha256);
        write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
            .expect("write bootstrap config");
        let bootstrap_config =
            read_upgrader_bootstrap_config(&bootstrap_config_path).expect("bootstrap config");
        let operation = ProbeUpgraderOperationMetadata {
            operation_id: "42".to_string(),
            target_probe_version: target_probe_version.to_string(),
            token: "probe-operation-token".to_string(),
        };
        let mut transport = RecordingValidationTransport {
            assets: assets.for_hub("https://hub.example"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        let result = execute_probe_upgrade_with_current_version(
            &operation,
            &bootstrap_config,
            &bootstrap_config_path,
            &install_metadata,
            &mut transport,
            &mut systemd,
            current_probe_version,
        );
        let persisted_install_path = temp.keep().join("bin/enoki-probe");

        (result, persisted_install_path, systemd)
    }

    fn write_test_bootstrap_config(
        bootstrap_config_path: &Path,
        install_metadata: &TrustedProbeInstallMetadata,
    ) -> Result<(), std::io::Error> {
        fs::write(
            bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"".to_string(),
                "probe_id = \"probe_01\"".to_string(),
                "probe_private_key_pem = \"test-private-key\"".to_string(),
                format!(
                    "state_dir = {}",
                    toml_string(install_metadata.state_dir.to_str().expect("state dir")),
                ),
                format!(
                    "operation_status_path = {}",
                    toml_string(
                        install_metadata
                            .operation_status_path
                            .to_str()
                            .expect("status path"),
                    ),
                ),
                format!(
                    "install_path = {}",
                    toml_string(
                        install_metadata
                            .install_path
                            .to_str()
                            .expect("install path")
                    ),
                ),
                "service_name = \"enoki-probe\"".to_string(),
                format!(
                    "probe_asset_public_key_sha256 = \"{}\"",
                    install_metadata.probe_asset_public_key_sha256,
                ),
                String::new(),
            ]
            .join("\n"),
        )
    }

    fn operation_stdin() -> String {
        [
            "operation_id = \"42\"",
            "target_probe_version = \"0.2.0\"",
            "token = \"probe-operation-token\"",
            "",
        ]
        .join("\n")
    }

    fn archive_with_probe_binary(contents: &str) -> Vec<u8> {
        let mut archive_bytes = Vec::new();
        {
            let encoder = GzEncoder::new(&mut archive_bytes, Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            archive
                .append_data(&mut header, "enoki-probe", contents.as_bytes())
                .expect("append probe binary");
            archive.finish().expect("finish archive");
        }

        archive_bytes
    }

    fn archive_with_entry(path: &str, entry_type: tar::EntryType) -> Vec<u8> {
        let mut archive_bytes = Vec::new();
        {
            let encoder = GzEncoder::new(&mut archive_bytes, Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_size(if entry_type == tar::EntryType::Regular {
                "new probe".len() as u64
            } else {
                0
            });
            header.set_mode(0o755);
            if entry_type == tar::EntryType::Symlink || entry_type == tar::EntryType::Link {
                header.set_link_name("target").expect("link name");
            }
            if path.contains("..") {
                let bytes = header.as_mut_bytes();
                bytes[..path.len()].copy_from_slice(path.as_bytes());
                bytes[path.len()] = 0;
                header.set_cksum();
                archive
                    .append(&header, "new probe".as_bytes())
                    .expect("append entry");
            } else {
                header.set_cksum();
                archive
                    .append_data(&mut header, path, "new probe".as_bytes())
                    .expect("append entry");
            }
            archive.finish().expect("finish archive");
        }

        archive_bytes
    }
}
