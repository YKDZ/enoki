use std::{
    error::Error,
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    os::unix::process::CommandExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use enoki_probe_bootstrap::{
    acquisition::{
        VerifiedUpgradeStageReceipt, open_verified_probe_upgrade_stage,
        remove_verified_probe_upgrade_stage,
    },
    generation::acquire_delegation_generation_at_owned_root,
    handoff::Handoff,
    install::{
        ConsumeBeforeOuterError, FixedInstallPaths, InstalledUpgradeBinding, SystemSystemd,
        UpgradeAttempt, UpgradeAuthorityConsumption, UpgradeRecoveryReceipt,
        VerifiedUpgradeComponents, abort_consumed_probe_upgrade_authority,
        consume_probe_repair_authority, consume_signed_before_upgrade_outer_checks,
        execute_authorized_probe_repair, finalize_probe_upgrade_stage_cleanup,
        issue_probe_repair_evidence, mark_probe_repair_unresolved,
        recover_incomplete_probe_upgrade, resume_probe_repair_intent,
        upgrade_current_probe_for_operation,
    },
    lifecycle::{
        LifecycleCompletion, LifecycleRequest, LifecycleRequestAuthority, LifecycleResponse,
        LifecycleTransition, RepairAuthorityV1, UninstallCommitPolicy, UninstallLifecycleEffects,
        UpgradeCompletion, execute_uninstall_lifecycle,
    },
    verifier::{
        VerificationPolicy, read_bundle_manifest, verify_archive_and_extract_lifecycle_roles,
        verify_metadata, verify_outer_metadata,
    },
};
use flate2::read::GzDecoder;
use prost::Message;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    signature::Verifier,
};
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
const PRODUCTION_OPERATION_SUDOERS_PATH: &str = "/etc/sudoers.d/enoki-probe-operations";
const PRODUCTION_COLLECTOR_HELPER_SUDOERS_PATH: &str =
    "/etc/sudoers.d/enoki-probe-collector-helpers";
const PRODUCTION_BOOTSTRAP_ACQUIRER_PATH: &str = "/usr/local/bin/enoki-probe-bootstrap-acquire";
const PRODUCTION_BOOTSTRAP_ACTIVATOR_PATH: &str = "/usr/local/bin/enoki-probe-bootstrap-activate";
const PRODUCTION_BOOTSTRAP_STATE_DIR: &str = "/var/lib/enoki-probe-bootstrap";
const PRODUCTION_INSTALL_STATE_DIR: &str = "/var/lib/enoki-probe";
const UNINSTALL_CAPSULE_FILE_NAME: &str = "probe-uninstall.capsule";
const MAX_UNINSTALL_CAPSULE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum UninstallCapsulePhase {
    Verified,
    Prepared,
    TerminalAcknowledged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumeDecision {
    Completed,
    RecoveryPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompanionBinaryFacts {
    regular_file: bool,
    link_count: u64,
    owner_uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PostCommitSelfFinalizeFacts {
    install_metadata_absent: bool,
    install_state_absent: bool,
    companion_binary: CompanionBinaryFacts,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UninstallRecoveryCapsule {
    schema_version: u16,
    authority_sha256: String,
    phase: UninstallCapsulePhase,
    request_json: String,
    install_metadata: TrustedProbeInstallMetadata,
}

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

pub fn run_probe_upgrader(
    input: ProbeUpgraderRunInput,
    stdin: &str,
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> Result<ProbeUpgraderResult, ProbeUpgraderRunError> {
    let mut systemd = SystemProbeUpgraderSystemdRunner;
    run_probe_upgrader_with_systemd_runner(input, stdin, transport, &mut systemd)
}

#[cfg(test)]
pub fn run_probe_repair(
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> Result<ProbeRepairResult, ProbeRepairRunError> {
    // SAFETY: `geteuid` takes no arguments and only reads the process credentials.
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProbeRepairRunError::RootRequired);
    }
    let paths = FixedInstallPaths::production();
    let mut upgrade_systemd = SystemSystemd::for_live_upgrade();
    if let Some(receipt) =
        recover_incomplete_probe_upgrade(&paths, &mut upgrade_systemd).map_err(|_| {
            ProbeRepairRunError::ServiceReconstruction {
                code: "probe_upgrade_recovery_failed",
                message: "durable Probe Upgrade recovery failed".to_owned(),
            }
        })?
    {
        remove_verified_probe_upgrade_stage(&receipt.operation_id, receipt.stage_owner_uid)
            .map_err(|_| ProbeRepairRunError::ServiceReconstruction {
                code: "probe_upgrade_stage_cleanup_failed",
                message: "verified Probe Upgrade stage cleanup failed".to_owned(),
            })?;
        finalize_probe_upgrade_stage_cleanup(&paths, &receipt).map_err(|_| {
            ProbeRepairRunError::ServiceReconstruction {
                code: "probe_upgrade_recovery_finalize_failed",
                message: "durable Probe Upgrade recovery finalization failed".to_owned(),
            }
        })?;
        return Ok(ProbeRepairResult {
            probe_id: receipt.probe_id,
            repaired_version: if receipt.activated {
                receipt.target_bundle_version
            } else {
                receipt.source_bundle_version
            },
        });
    }
    let install_metadata =
        read_trusted_probe_install_metadata(Path::new(PRODUCTION_INSTALL_METADATA_PATH), None)?;
    if install_metadata.schema_version == 2 {
        return Err(ProbeUpgraderRunError::ManualProbeReinstallRequired.into());
    }
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

fn run_authorized_probe_repair_for_invoking_admin(
    invoking_uid: u32,
    invoking_gid: u32,
) -> Result<ProbeRepairResult, ProbeRepairRunError> {
    if unsafe { libc::geteuid() } != 0 || invoking_uid == 0 || invoking_gid == 0 {
        return Err(ProbeRepairRunError::RootRequired);
    }
    let paths = FixedInstallPaths::production();
    let consumed = if let Some(consumed) = resume_probe_repair_intent(&paths)
        .map_err(|_| ProbeUpgraderRunError::ManualProbeReinstallRequired)?
    {
        consumed
    } else {
        let mut nonce = [0_u8; 16];
        fs::File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut nonce))
            .map_err(|_| repair_contract_failure("probe_repair_random_failed"))?;
        let request_nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| repair_contract_failure("probe_repair_clock_invalid"))?
            .as_millis()
            .try_into()
            .map_err(|_| repair_contract_failure("probe_repair_clock_invalid"))?;
        let signed = issue_probe_repair_evidence(
            &paths,
            now_ms,
            now_ms.saturating_add(60_000),
            &request_nonce,
        )
        .map_err(|_| ProbeUpgraderRunError::ManualProbeReinstallRequired)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RepairAuthorizationRequest<'a> {
            evidence: &'a enoki_probe_bootstrap::lifecycle::RepairEvidenceV1,
            evidence_signature: &'a str,
        }
        let request = serde_json::to_vec(&RepairAuthorizationRequest {
            evidence: &signed.evidence,
            evidence_signature: &signed.signature,
        })
        .map_err(|_| repair_contract_failure("probe_repair_request_invalid"))?;
        let mut acquirer = Command::new(PRODUCTION_BOOTSTRAP_ACQUIRER_PATH);
        acquirer.arg("--repair-authorize");
        configure_repair_acquirer_privileges(&mut acquirer, invoking_uid, invoking_gid);
        let mut child = acquirer
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| repair_contract_failure("probe_repair_authority_acquire_failed"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| repair_contract_failure("probe_repair_authority_acquire_failed"))?
            .write_all(&request)
            .map_err(|_| repair_contract_failure("probe_repair_authority_acquire_failed"))?;
        let output = child
            .wait_with_output()
            .map_err(|_| repair_contract_failure("probe_repair_authority_acquire_failed"))?;
        if output.status.code() == Some(3) {
            return Err(ProbeUpgraderRunError::ManualProbeReinstallRequired.into());
        }
        if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > 8 * 1024 {
            return Err(repair_contract_failure(
                "probe_repair_authority_acquire_failed",
            ));
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RepairAuthorizationResponse {
            authority: RepairAuthorityV1,
            signature: String,
        }
        let response: RepairAuthorizationResponse = serde_json::from_slice(&output.stdout)
            .map_err(|_| repair_contract_failure("probe_repair_authority_invalid"))?;
        consume_probe_repair_authority(
            &paths,
            &signed.evidence,
            &signed.signature,
            &response.authority,
            &response.signature,
            now_ms,
        )
        .map_err(|_| repair_contract_failure("probe_repair_authority_invalid"))?
    };
    let mut systemd = SystemSystemd::for_live_upgrade();
    let repaired = execute_authorized_probe_repair(
        &paths,
        &consumed,
        &mut systemd,
        |operation_id, owner_uid| {
            remove_verified_probe_upgrade_stage(operation_id, owner_uid)
                .map_err(|_| enoki_probe_bootstrap::install::InstallError::Io)
        },
    );
    if repaired.is_err() {
        mark_probe_repair_unresolved(&paths, &consumed)
            .map_err(|_| repair_contract_failure("probe_repair_intent_persist_failed"))?;
        return Err(repair_contract_failure("probe_repair_recovery_pending"));
    }
    Ok(ProbeRepairResult {
        probe_id: consumed.probe_id,
        repaired_version: consumed.target_bundle_version,
    })
}

fn configure_repair_acquirer_privileges(command: &mut Command, uid: u32, gid: u32) {
    command.env_clear();
    // SAFETY: this hook executes in the child after fork and before exec. It only invokes
    // async-signal-safe credential syscalls with captured scalar values.
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn repair_contract_failure(code: &'static str) -> ProbeRepairRunError {
    ProbeRepairRunError::ServiceReconstruction {
        code,
        message: "explicit Probe Repair remains unresolved".to_owned(),
    }
}

#[cfg(test)]
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

#[cfg(test)]
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
    if install_metadata.schema_version == 3 {
        return Err(ProbeUpgraderRunError::ManualProbeReinstallRequired.into());
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
    remove_legacy_collector_helper_sudoers(install_metadata)
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

#[cfg(test)]
fn probe_repair_reconstruction_error(
    code: &'static str,
    error: ProbeUpgraderRunError,
) -> ProbeRepairRunError {
    ProbeRepairRunError::ServiceReconstruction {
        code,
        message: error.to_string(),
    }
}

#[cfg(test)]
fn probe_identity_validation_url(hub_url: &str) -> Result<String, ProbeUpgraderRunError> {
    hub_url::endpoint(hub_url, "/api/probe/config")
        .map_err(|()| ProbeUpgraderRunError::InvalidConfig("invalid Hub URL"))
}

#[cfg(test)]
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
        "[Unit]\nDescription=Enoki Probe\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=notify\nNotifyAccess=main\nUser={}\nGroup={}\nExecStart={} run --config {}\nRestart=on-failure\nRestartPreventExitStatus=78\nRestartSec=5s\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\nProtectControlGroups=true\nReadWritePaths={} {}\n\n[Install]\nWantedBy=multi-user.target\n",
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
#[cfg(test)]
struct FailedProbeUpgradeMarker {
    target_probe_version: String,
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
            "post_replacement_restart_failure"
                | "post_replacement_status_write_failure"
                | "lifecycle.upgrade_repair_required"
        )
    {
        return Err(ProbeRepairRunError::FailureMarkerNotPostReplacement);
    }
    let _ = operation_id;
    Ok(FailedProbeUpgradeMarker {
        target_probe_version: normalized_probe_version(target_probe_version).to_string(),
    })
}

#[cfg(test)]
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

#[cfg(test)]
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
    if install_metadata.schema_version == 2 {
        return Err(ProbeUpgraderRunError::ManualProbeReinstallRequired);
    }
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
    if install_metadata.schema_version == 3 {
        return Err(ProbeUpgraderRunError::ManualProbeReinstallRequired);
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
        "{{\"targetAssetSetDigest\":\"{}\",\"targetProbeVersion\":\"{}\",\"token\":\"{}\"}}",
        json_string_fragment(&operation.target_asset_set_digest),
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
            let body = render_operation_status_body(
                &operation.token,
                "failed",
                Some(&failed),
                Some((
                    &operation.target_asset_set_digest,
                    &operation.target_probe_version,
                )),
            );
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

/// Lifecycle Companion 的唯一生产入口。授权事实在任何系统变更前与
/// root-owned 安装状态和当前 Probe Identity 精确比对。
pub fn run_lifecycle_companion(
    request: &LifecycleRequest,
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> LifecycleResponse {
    run_lifecycle_companion_from_peer(request, transport, None)
}

pub fn run_lifecycle_companion_from_peer(
    request: &LifecycleRequest,
    transport: &mut impl ProbeUpgraderValidationTransport,
    peer_uid: Option<u32>,
) -> LifecycleResponse {
    if unsafe { libc::geteuid() } != 0 {
        return LifecycleResponse::failed("lifecycle.root_required");
    }
    if request.transition() == LifecycleTransition::Upgrade {
        return run_probe_compatible_upgrade(request, peer_uid);
    }
    let metadata = match read_trusted_probe_install_metadata(
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        None,
    ) {
        Ok(metadata) => metadata,
        Err(_) => return LifecycleResponse::failed("lifecycle.install_state_invalid"),
    };
    let identity = match read_trusted_probe_install_preflight(
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        None,
    ) {
        Ok(identity) => identity,
        Err(_) => return LifecycleResponse::failed("lifecycle.identity_invalid"),
    };
    if request.transition() == LifecycleTransition::Repair {
        let LifecycleRequestAuthority::LocalRepair {
            probe_id,
            install_state_sha256,
            target_manifest_sha256,
            bundle_version,
            invoking_uid,
            invoking_gid,
        } = request.authority()
        else {
            return LifecycleResponse::failed("lifecycle.invalid_authority");
        };
        if peer_uid != Some(0)
            || identity.probe_id != *probe_id
            || metadata.install_state_sha256.as_deref() != Some(install_state_sha256)
            || metadata.target_manifest_sha256.as_deref() != Some(target_manifest_sha256)
            || metadata.bundle_version.as_deref() != Some(bundle_version)
        {
            return LifecycleResponse::failed("lifecycle.authority_mismatch");
        }
        return match run_authorized_probe_repair_for_invoking_admin(*invoking_uid, *invoking_gid) {
            Ok(_) => LifecycleResponse::succeeded(),
            Err(_) => LifecycleResponse::failed("lifecycle.repair_unresolved"),
        };
    }
    if request.transition() == LifecycleTransition::ReplacementMigration {
        return run_probe_replacement_migration(request, &metadata, &identity);
    }
    if request.transition() != LifecycleTransition::Uninstall {
        return LifecycleResponse::not_enabled();
    }
    if !matches!(metadata.schema_version, 4 | 5) {
        return LifecycleResponse::failed("lifecycle.replacement_required");
    }
    let (probe_id, install_state, manifest, version) = match request.authority() {
        LifecycleRequestAuthority::HubOperation {
            probe_id,
            install_state_sha256,
            target_manifest_sha256,
            bundle_version,
            ..
        }
        | LifecycleRequestAuthority::LocalRoot {
            probe_id,
            install_state_sha256,
            target_manifest_sha256,
            bundle_version,
        } => (
            probe_id,
            install_state_sha256,
            target_manifest_sha256,
            bundle_version,
        ),
        LifecycleRequestAuthority::HubUpgrade { .. }
        | LifecycleRequestAuthority::LocalRepair { .. }
        | LifecycleRequestAuthority::ReplacementEnrollment { .. } => {
            return LifecycleResponse::not_enabled();
        }
    };
    if identity.probe_id != *probe_id
        || metadata.install_state_sha256.as_deref() != Some(install_state)
        || metadata.target_manifest_sha256.as_deref() != Some(manifest)
        || metadata.bundle_version.as_deref() != Some(version)
    {
        return LifecycleResponse::failed("lifecycle.authority_mismatch");
    }
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: metadata.identity_path.clone(),
    };
    let mut systemd = SystemProbeUpgraderSystemdRunner;
    lifecycle_response_from_resume_decision(execute_lifecycle_uninstall(
        request,
        &input,
        &metadata,
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        transport,
        &mut systemd,
    ))
}

fn run_probe_compatible_upgrade(
    request: &LifecycleRequest,
    peer_uid: Option<u32>,
) -> LifecycleResponse {
    let LifecycleRequestAuthority::HubUpgrade {
        hub_origin,
        host_id,
        probe_id,
        operation_id,
        source_bundle_version,
        source_install_state_sha256,
        source_manifest_sha256,
        target_bundle_version,
        target_asset_set_digest,
        target_manifest_sha256,
        verified_stage_sha256,
        expires_at_ms,
        authority_signature,
    } = request.authority()
    else {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    };
    let Some(peer_uid) = peer_uid else {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    };
    let now_ms = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => return LifecycleResponse::failed("lifecycle.invalid_authority"),
    };
    if now_ms > u128::from(*expires_at_ms) {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    }
    let canonical_authority = match request.canonical_upgrade_authority_bytes() {
        Ok(canonical) => canonical,
        Err(_) => return LifecycleResponse::failed("lifecycle.invalid_authority"),
    };
    let paths = FixedInstallPaths::production();
    let authority = UpgradeAuthorityConsumption {
        operation_id: operation_id.clone(),
        stage_owner_uid: peer_uid,
        hub_origin: hub_origin.clone(),
        host_id: host_id.clone(),
        probe_id: probe_id.clone(),
        source_bundle_version: source_bundle_version.clone(),
        source_install_state_sha256: source_install_state_sha256.clone(),
        source_manifest_sha256: source_manifest_sha256.clone(),
        target_bundle_version: target_bundle_version.clone(),
        target_asset_set_digest: target_asset_set_digest.clone(),
        target_manifest_sha256: target_manifest_sha256.clone(),
        verified_stage_sha256: verified_stage_sha256.clone(),
    };
    let receipt = VerifiedUpgradeStageReceipt {
        operation_id: operation_id.clone(),
        target_asset_set_digest: target_asset_set_digest.clone(),
        target_manifest_sha256: target_manifest_sha256.clone(),
        target_version: target_bundle_version.clone(),
        verified_stage_sha256: verified_stage_sha256.clone(),
    };
    let outer = consume_signed_before_upgrade_outer_checks(
        &paths,
        &authority,
        &canonical_authority,
        authority_signature,
        |_| {
            let metadata = read_trusted_probe_install_metadata(
                Path::new(PRODUCTION_INSTALL_METADATA_PATH),
                None,
            )
            .map_err(|_| "lifecycle.install_state_invalid")?;
            let identity = read_trusted_probe_install_preflight(
                Path::new(PRODUCTION_INSTALL_METADATA_PATH),
                None,
            )
            .map_err(|_| "lifecycle.identity_invalid")?;
            if hub_origin != &metadata.hub_url
                || metadata.schema_version != 5
                || identity.probe_id != *probe_id
                || metadata.install_state_sha256.as_deref() != Some(source_install_state_sha256)
                || metadata.target_manifest_sha256.as_deref() != Some(source_manifest_sha256)
                || metadata.bundle_version.as_deref() != Some(source_bundle_version)
            {
                return Err("lifecycle.authority_mismatch");
            }
            let mut stage = open_verified_probe_upgrade_stage(&receipt, peer_uid)
                .map_err(|_| "lifecycle.upgrade_stage_invalid")?;
            stage
                .persist_generation_before_activation()
                .map_err(|_| "lifecycle.upgrade_stage_invalid")?;
            Ok((
                stage,
                InstalledUpgradeBinding {
                    hub_origin: metadata.hub_url.clone(),
                    probe_id: probe_id.clone(),
                    source_bundle_version: source_bundle_version.clone(),
                    source_install_state_sha256: source_install_state_sha256.clone(),
                    source_manifest_sha256: source_manifest_sha256.clone(),
                },
            ))
        },
    );
    let (consumed, (mut stage, expected_source)) = match outer {
        Ok(ready) => ready,
        Err(ConsumeBeforeOuterError::Consume(_)) => {
            return LifecycleResponse::failed("lifecycle.upgrade_authority_consumed");
        }
        Err(ConsumeBeforeOuterError::Outer { consumed, error }) => {
            return fail_consumed_upgrade_before_activation(
                &paths,
                &consumed,
                operation_id,
                peer_uid,
                error,
            );
        }
    };
    let mut systemd = SystemSystemd::for_live_upgrade();
    let result = upgrade_current_probe_for_operation(
        VerifiedUpgradeComponents {
            probe: &mut stage.probe,
            observation_runtime: &mut stage.observation_runtime,
            system_state_provider: &mut stage.system_state_provider,
            disk_health_provider: &mut stage.disk_health_provider,
            lifecycle_companion: &mut stage.lifecycle_companion,
            bootstrap_acquirer: &mut stage.bootstrap_acquirer,
            bootstrap_activator: &mut stage.bootstrap_activator,
        },
        &stage.bundle,
        &expected_source,
        &consumed,
        &paths,
        &mut systemd,
    );
    match result {
        Ok(UpgradeCompletion::Activated) => {
            let receipt = UpgradeRecoveryReceipt {
                operation_id: operation_id.clone(),
                probe_id: probe_id.clone(),
                stage_owner_uid: peer_uid,
                source_bundle_version: source_bundle_version.clone(),
                target_bundle_version: target_bundle_version.clone(),
                activated: true,
            };
            if remove_verified_probe_upgrade_stage(operation_id, peer_uid).is_ok()
                && finalize_probe_upgrade_stage_cleanup(&FixedInstallPaths::production(), &receipt)
                    .is_ok()
            {
                LifecycleResponse::succeeded()
            } else {
                LifecycleResponse::failed("lifecycle.upgrade_repair_required")
            }
        }
        Ok(UpgradeCompletion::RepairRequired) => {
            LifecycleResponse::failed("lifecycle.upgrade_repair_required")
        }
        Err(_) => {
            let paths = FixedInstallPaths::production();
            let recovered = recover_incomplete_probe_upgrade(&paths, &mut systemd);
            if let Ok(Some(receipt)) = recovered
                && !receipt.activated
                && remove_verified_probe_upgrade_stage(
                    &receipt.operation_id,
                    receipt.stage_owner_uid,
                )
                .is_ok()
                && finalize_probe_upgrade_stage_cleanup(&paths, &receipt).is_ok()
            {
                LifecycleResponse::failed("lifecycle.upgrade_failed_before_activation")
            } else {
                LifecycleResponse::failed("lifecycle.upgrade_repair_required")
            }
        }
    }
}

fn fail_consumed_upgrade_before_activation(
    paths: &FixedInstallPaths,
    consumed: &UpgradeAttempt,
    operation_id: &str,
    stage_owner_uid: u32,
    failure_code: &'static str,
) -> LifecycleResponse {
    if remove_verified_probe_upgrade_stage(operation_id, stage_owner_uid).is_ok()
        && abort_consumed_probe_upgrade_authority(paths, consumed).is_ok()
    {
        LifecycleResponse::failed(failure_code)
    } else {
        LifecycleResponse::failed("lifecycle.upgrade_repair_required")
    }
}

#[cfg(test)]
fn verify_lifecycle_upgrade_authority(
    request: &LifecycleRequest,
    metadata: &TrustedProbeInstallMetadata,
    expires_at_ms: u64,
    signature_hex: &str,
) -> Result<(), ProbeUpgraderRunError> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ProbeUpgraderRunError::InvalidInstallMetadata("system clock is invalid"))?
        .as_millis();
    if now_ms > u128::from(expires_at_ms) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "lifecycle authority expired",
        ));
    }
    let install_key_hex = metadata.lifecycle_authority_install_key.as_deref().ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority install key is missing"),
    )?;
    let install_key_bytes = decode_lower_hex(install_key_hex).ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority install key is invalid"),
    )?;
    let install_key: [u8; 32] = install_key_bytes.try_into().map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority install key is invalid")
    })?;
    let canonical = request.canonical_upgrade_authority_bytes().map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority is invalid")
    })?;
    if enoki_probe_bootstrap::lifecycle::verify_lifecycle_upgrade_authority_signature(
        &install_key,
        &canonical,
        signature_hex,
    ) {
        Ok(())
    } else {
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "lifecycle authority signature is invalid",
        ))
    }
}

fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || value.len() % 2 != 0
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

fn run_probe_replacement_migration(
    request: &LifecycleRequest,
    metadata: &TrustedProbeInstallMetadata,
    identity: &TrustedProbeInstallPreflight,
) -> LifecycleResponse {
    let LifecycleRequestAuthority::ReplacementEnrollment {
        enrollment_token,
        hub_origin,
        target_asset_set_digest,
        target_manifest_sha256: _,
        bundle_version,
    } = request.authority()
    else {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    };
    let mut registration = crate::registration::HttpRegistrationTransport;
    let inspected = crate::registration::inspect_probe_installation(
        crate::registration::ProbeInstallationInspectionInput {
            enrollment_token: enrollment_token.clone(),
            hub_url: hub_origin.clone(),
        },
        &mut registration,
    );
    let Ok(crate::registration::ProbeInstallationTarget::ManualReinstall(authority)) = inspected
    else {
        return LifecycleResponse::failed("lifecycle.authority_rejected");
    };
    let installed_probe_sha256 = match fixed_installed_probe_sha256(&metadata.install_path) {
        Ok(digest) => digest,
        Err(_) => return LifecycleResponse::failed("lifecycle.authority_invalid"),
    };
    let authority_match = replacement_authority_matches(
        hub_origin,
        target_asset_set_digest,
        bundle_version,
        &authority,
        metadata,
        identity,
        &installed_probe_sha256,
    );
    if authority_match != ReplacementAuthorityMatch::Matches {
        return LifecycleResponse::failed(match authority_match {
            ReplacementAuthorityMatch::UnprovableSource => "lifecycle.authority_invalid",
            ReplacementAuthorityMatch::Mismatch => "lifecycle.authority_mismatch",
            ReplacementAuthorityMatch::Matches => unreachable!(),
        });
    }
    match cleanup_trusted_probe_install_for_reenrollment(
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        None,
    ) {
        Ok(()) => LifecycleResponse::succeeded(),
        Err(_) => LifecycleResponse::failed("lifecycle.replacement_cleanup_failed"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InstalledProbeBinaryFacts {
    device: u64,
    inode: u64,
    is_regular_file: bool,
    is_symlink: bool,
    length: u64,
    link_count: u64,
    mode: u32,
    owner_uid: u32,
}

fn fixed_installed_probe_sha256(path: &Path) -> Result<String, std::io::Error> {
    if path != Path::new(PRODUCTION_PROBE_BINARY_PATH) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "installed Probe path is not the fixed production path",
        ));
    }
    let path_facts = installed_probe_binary_facts(&fs::symlink_metadata(path)?);
    validate_installed_probe_binary_facts(path_facts)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let opened_facts = installed_probe_binary_facts(&file.metadata()?);
    validate_installed_probe_binary_facts(opened_facts)?;
    if path_facts != opened_facts {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed Probe path and opened file do not match",
        ));
    }
    let digest = installed_probe_sha256_from_reader(&mut file, opened_facts)?;
    if installed_probe_binary_facts(&file.metadata()?) != opened_facts {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed Probe changed while it was hashed",
        ));
    }
    Ok(digest)
}

fn installed_probe_binary_facts(metadata: &fs::Metadata) -> InstalledProbeBinaryFacts {
    InstalledProbeBinaryFacts {
        device: metadata.dev(),
        inode: metadata.ino(),
        is_regular_file: metadata.file_type().is_file(),
        is_symlink: metadata.file_type().is_symlink(),
        length: metadata.len(),
        link_count: metadata.nlink(),
        mode: metadata.mode() & 0o7777,
        owner_uid: metadata.uid(),
    }
}

fn validate_installed_probe_binary_facts(
    facts: InstalledProbeBinaryFacts,
) -> Result<(), std::io::Error> {
    if facts.is_symlink
        || !facts.is_regular_file
        || facts.owner_uid != 0
        || facts.mode != 0o755
        || facts.link_count != 1
        || facts.length == 0
        || facts.length > MAX_INSTALLED_PROBE_BYTES
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed Probe file facts are invalid",
        ));
    }
    Ok(())
}

fn installed_probe_sha256_from_reader(
    mut reader: impl Read,
    facts: InstalledProbeBinaryFacts,
) -> Result<String, std::io::Error> {
    validate_installed_probe_binary_facts(facts)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "installed Probe size exceeded its bound",
            )
        })?;
        if total > facts.length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "installed Probe size changed while it was hashed",
            ));
        }
        digest.update(&buffer[..read]);
    }
    if total != facts.length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed Probe size changed while it was hashed",
        ));
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementAuthorityMatch {
    Matches,
    Mismatch,
    UnprovableSource,
}

fn replacement_authority_matches(
    hub_origin: &str,
    target_asset_set_digest: &str,
    bundle_version: &str,
    authority: &crate::registration::ProbeReplacementAuthorization,
    metadata: &TrustedProbeInstallMetadata,
    identity: &TrustedProbeInstallPreflight,
    installed_probe_sha256: &str,
) -> ReplacementAuthorityMatch {
    if authority.source_probe_sha256.is_empty() {
        return ReplacementAuthorityMatch::UnprovableSource;
    }
    if !authority
        .source_probe_sha256
        .iter()
        .any(|expected| expected == installed_probe_sha256)
    {
        return ReplacementAuthorityMatch::Mismatch;
    }
    if metadata
        .bundle_version
        .as_deref()
        .is_some_and(|installed| installed != authority.source_probe_version)
    {
        return ReplacementAuthorityMatch::Mismatch;
    }
    if authority.expected_hub_origin == hub_origin
        && identity.hub_url == hub_origin
        && metadata.hub_url == hub_origin
        && authority.expected_probe_id == identity.probe_id
        && authority.target_asset_set_digest == target_asset_set_digest
        && authority.target_probe_version == bundle_version
    {
        ReplacementAuthorityMatch::Matches
    } else {
        ReplacementAuthorityMatch::Mismatch
    }
}

fn execute_lifecycle_uninstall(
    request: &LifecycleRequest,
    input: &ProbeUninstallerRunInput,
    install_metadata: &TrustedProbeInstallMetadata,
    install_metadata_path: &Path,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<ResumeDecision, ProbeUpgraderRunError> {
    let capsule_path = uninstall_capsule_path(install_metadata_path)?;
    let authority_sha256 = lifecycle_authority_sha256(request)?;
    let capsule = read_uninstall_capsule(&capsule_path)?;
    if let Some(existing) = &capsule
        && (existing.authority_sha256 != authority_sha256
            || existing.install_metadata != *install_metadata)
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule belongs to another authority",
        ));
    }
    let plan = plan_probe_uninstall_cleanup(
        input,
        install_metadata,
        install_metadata_path,
        capsule.is_some(),
    )?;
    let hub_operation = match request.authority() {
        LifecycleRequestAuthority::HubOperation {
            operation_id,
            operation_token,
            ..
        } => Some((operation_id.as_str(), operation_token.as_str())),
        LifecycleRequestAuthority::HubUpgrade { .. }
        | LifecycleRequestAuthority::LocalRoot { .. }
        | LifecycleRequestAuthority::LocalRepair { .. } => None,
        LifecycleRequestAuthority::ReplacementEnrollment { .. } => None,
    };
    let terminal_was_acknowledged = matches!(
        capsule.as_ref().map(|capsule| capsule.phase),
        Some(UninstallCapsulePhase::TerminalAcknowledged)
    );
    let bootstrap_config = if terminal_was_acknowledged {
        None
    } else {
        validate_identity_path(&input.bootstrap_config_path, install_metadata)?;
        let config = read_upgrader_bootstrap_config(&input.bootstrap_config_path)?;
        validate_bootstrap_config_matches_trusted_install_metadata(&config, install_metadata)?;
        Some(config)
    };
    let commit_policy = if hub_operation.is_some() {
        UninstallCommitPolicy::HubTerminal
    } else {
        UninstallCommitPolicy::Local
    };
    let mut effects = ProbeUninstallLifecycleEffects {
        request,
        plan,
        capsule_path,
        capsule,
        bootstrap_config,
        terminal_is_acknowledged: terminal_was_acknowledged,
        transport,
        systemd,
    };
    execute_uninstall_lifecycle(&mut effects, commit_policy).map(|completion| match completion {
        LifecycleCompletion::Complete => ResumeDecision::Completed,
        LifecycleCompletion::RecoveryPending => ResumeDecision::RecoveryPending,
    })
}

struct ProbeUninstallLifecycleEffects<'a, T, S> {
    request: &'a LifecycleRequest,
    plan: ProbeUninstallCleanupPlan<'a>,
    capsule_path: PathBuf,
    capsule: Option<UninstallRecoveryCapsule>,
    bootstrap_config: Option<ProbeUpgraderBootstrapConfig>,
    terminal_is_acknowledged: bool,
    transport: &'a mut T,
    systemd: &'a mut S,
}

impl<T, S> ProbeUninstallLifecycleEffects<'_, T, S>
where
    T: ProbeUpgraderValidationTransport,
    S: ProbeUpgraderSystemdRunner,
{
    fn hub_operation(&self) -> Option<(&str, &str)> {
        match self.request.authority() {
            LifecycleRequestAuthority::HubOperation {
                operation_id,
                operation_token,
                ..
            } => Some((operation_id, operation_token)),
            LifecycleRequestAuthority::HubUpgrade { .. }
            | LifecycleRequestAuthority::LocalRoot { .. }
            | LifecycleRequestAuthority::LocalRepair { .. } => None,
            LifecycleRequestAuthority::ReplacementEnrollment { .. } => None,
        }
    }

    fn request_auth_material(&self) -> Result<(String, String, i64), ProbeUpgraderRunError> {
        let auth =
            probe_request_auth_from_bootstrap_config(self.bootstrap_config.as_ref().ok_or(
                ProbeUpgraderRunError::InvalidInstallMetadata(
                    "uninstall capsule lost report identity",
                ),
            )?)?;
        Ok((
            auth.probe_id.to_owned(),
            auth.probe_private_key_pem.to_owned(),
            auth.server_time_offset_ms,
        ))
    }
}

impl<T, S> UninstallLifecycleEffects for ProbeUninstallLifecycleEffects<'_, T, S>
where
    T: ProbeUpgraderValidationTransport,
    S: ProbeUpgraderSystemdRunner,
{
    type Error = ProbeUpgraderRunError;

    fn verify(&mut self) -> Result<(), Self::Error> {
        if self.capsule.is_none()
            && let Some((operation_id, operation_token)) = self.hub_operation()
        {
            let token_body = format!(
                "{{\"token\":\"{}\"}}",
                json_string_fragment(operation_token)
            );
            let (probe_id, probe_private_key_pem, server_time_offset_ms) =
                self.request_auth_material()?;
            let auth = ProbeRequestAuth {
                probe_id: &probe_id,
                probe_private_key_pem: &probe_private_key_pem,
                server_time_offset_ms,
            };
            self.transport.post_token_validation(
                &operation_token_validation_url(&self.plan.install_metadata.hub_url, operation_id)?,
                &auth,
                &token_body,
            )?;
        }
        if self.capsule.is_none() {
            persist_uninstall_capsule(
                &self.capsule_path,
                self.request,
                self.plan.install_metadata,
                UninstallCapsulePhase::Verified,
            )?;
            self.capsule = read_uninstall_capsule(&self.capsule_path)?;
        }
        Ok(())
    }

    fn clean(&mut self) -> Result<(), Self::Error> {
        if !self.terminal_is_acknowledged {
            execute_probe_uninstall_cleanup(
                &self.plan,
                self.systemd,
                UninstallCleanupExtent::Prepare,
            )?;
            persist_uninstall_capsule(
                &self.capsule_path,
                self.request,
                self.plan.install_metadata,
                UninstallCapsulePhase::Prepared,
            )?;
            self.capsule = read_uninstall_capsule(&self.capsule_path)?;
        }
        Ok(())
    }

    fn report(&mut self) -> Result<(), Self::Error> {
        if !self.terminal_is_acknowledged
            && let Some((operation_id, operation_token)) = self.hub_operation()
        {
            let body = render_operation_status_body(operation_token, "succeeded", None, None);
            let (probe_id, probe_private_key_pem, server_time_offset_ms) =
                self.request_auth_material()?;
            let auth = ProbeRequestAuth {
                probe_id: &probe_id,
                probe_private_key_pem: &probe_private_key_pem,
                server_time_offset_ms,
            };
            self.transport.post_operation_status(
                &operation_status_url(&self.plan.install_metadata.hub_url, operation_id)?,
                &auth,
                &body,
            )?;
        }
        Ok(())
    }

    fn commit(&mut self) -> Result<(), Self::Error> {
        persist_uninstall_capsule(
            &self.capsule_path,
            self.request,
            self.plan.install_metadata,
            UninstallCapsulePhase::TerminalAcknowledged,
        )?;
        self.terminal_is_acknowledged = true;
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), Self::Error> {
        let companion_binary = self
            .plan
            .install_metadata
            .lifecycle_companion_path
            .as_deref()
            .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
                "schema v4 metadata is missing lifecycle companion",
            ))?;
        execute_probe_uninstall_cleanup(
            &self.plan,
            self.systemd,
            UninstallCleanupExtent::RecoverableFinalize,
        )?;
        let _ = companion_binary;
        commit_lifecycle_capsule_with(&self.capsule_path, remove_path_if_exists)
    }
}

fn commit_lifecycle_capsule_with(
    capsule_path: &Path,
    mut remove: impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    remove(capsule_path)
}

/// 响应已经完整写出后，Companion binary unlink 是进程最后一个可失败动作。
pub fn finalize_lifecycle_companion_binary() -> bool {
    remove_path_if_exists(Path::new(LIFECYCLE_COMPANION_BINARY_PATH)).is_ok()
}

/// 固定恢复入口不接受运行时参数；它只消费安装目录中的 root-owned
/// canonical capsule。capsule 已提交删除时，唯一剩余动作是自删除固定
/// Companion binary。
pub fn resume_lifecycle_companion(
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> LifecycleResponse {
    if unsafe { libc::geteuid() } != 0 {
        return LifecycleResponse::failed("lifecycle.root_required");
    }
    lifecycle_response_from_resume_decision(resume_lifecycle_companion_at(
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        Path::new(PRODUCTION_INSTALL_STATE_DIR),
        Path::new(LIFECYCLE_COMPANION_BINARY_PATH),
        transport,
        &mut SystemProbeUpgraderSystemdRunner,
    ))
}

fn lifecycle_response_from_resume_decision(
    decision: Result<ResumeDecision, ProbeUpgraderRunError>,
) -> LifecycleResponse {
    match decision {
        Ok(ResumeDecision::Completed) => LifecycleResponse::succeeded(),
        Ok(ResumeDecision::RecoveryPending) => LifecycleResponse::recovery_pending(),
        Err(error) => LifecycleResponse::failed(error.code()),
    }
}

fn resume_lifecycle_companion_at(
    install_metadata_path: &Path,
    install_state_dir: &Path,
    companion_binary_path: &Path,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<ResumeDecision, ProbeUpgraderRunError> {
    let capsule_path = uninstall_capsule_path(install_metadata_path)?;
    let Some(capsule) = read_uninstall_capsule(&capsule_path)? else {
        let facts = read_post_commit_self_finalize_facts(
            install_metadata_path,
            install_state_dir,
            companion_binary_path,
        )?;
        return post_commit_self_finalize_policy(facts).map_err(|()| {
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "lifecycle resume is not a committed uninstall",
            )
        });
    };
    let request = LifecycleRequest::decode(capsule.request_json.as_bytes()).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule request is invalid")
    })?;
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: capsule.install_metadata.identity_path.clone(),
    };
    execute_lifecycle_uninstall(
        &request,
        &input,
        &capsule.install_metadata,
        install_metadata_path,
        transport,
        systemd,
    )
}

fn read_post_commit_self_finalize_facts(
    install_metadata_path: &Path,
    install_state_dir: &Path,
    companion_binary_path: &Path,
) -> Result<PostCommitSelfFinalizeFacts, ProbeUpgraderRunError> {
    let install_metadata_absent = path_absence_fact(install_metadata_path)?;
    let install_state_absent = path_absence_fact(install_state_dir)?;
    let binary = fs::symlink_metadata(companion_binary_path).map_err(ProbeUpgraderRunError::Io)?;
    Ok(PostCommitSelfFinalizeFacts {
        install_metadata_absent,
        install_state_absent,
        companion_binary: CompanionBinaryFacts {
            regular_file: binary.file_type().is_file(),
            link_count: binary.nlink(),
            owner_uid: binary.uid(),
            mode: binary.mode() & 0o777,
        },
    })
}

fn path_absence_fact(path: &Path) -> Result<bool, ProbeUpgraderRunError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(ProbeUpgraderRunError::Io(error)),
    }
}

fn post_commit_self_finalize_policy(
    facts: PostCommitSelfFinalizeFacts,
) -> Result<ResumeDecision, ()> {
    (facts.install_metadata_absent
        && facts.install_state_absent
        && facts.companion_binary.regular_file
        && facts.companion_binary.link_count == 1
        && facts.companion_binary.owner_uid == 0
        && facts.companion_binary.mode == 0o755)
        .then_some(ResumeDecision::Completed)
        .ok_or(())
}

pub fn run_local_lifecycle_companion(
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> LifecycleResponse {
    if unsafe { libc::geteuid() } != 0 {
        return LifecycleResponse::failed("lifecycle.root_required");
    }
    let metadata = match read_trusted_probe_install_metadata(
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        None,
    ) {
        Ok(metadata) if matches!(metadata.schema_version, 4 | 5) => metadata,
        Ok(_) => return LifecycleResponse::failed("lifecycle.replacement_required"),
        Err(_) => return LifecycleResponse::failed("lifecycle.install_state_invalid"),
    };
    let identity = match read_trusted_probe_install_preflight(
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        None,
    ) {
        Ok(identity) => identity,
        Err(_) => return LifecycleResponse::failed("lifecycle.identity_invalid"),
    };
    let Some((install_state, manifest, version)) = metadata
        .install_state_sha256
        .as_deref()
        .zip(metadata.target_manifest_sha256.as_deref())
        .zip(metadata.bundle_version.as_deref())
        .map(|((install_state, manifest), version)| (install_state, manifest, version))
    else {
        return LifecycleResponse::failed("lifecycle.install_state_invalid");
    };
    let Ok(request) =
        LifecycleRequest::local_uninstall(&identity.probe_id, install_state, manifest, version)
    else {
        return LifecycleResponse::failed("lifecycle.install_state_invalid");
    };
    run_lifecycle_companion(&request, transport)
}

#[cfg(test)]
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
        let body = render_operation_status_body(&operation.token, "failed", Some(&failed), None);
        let _ = transport.post_operation_status(&status_url, &request_auth, &body);
        return Ok(failed);
    }

    let body = render_operation_status_body(&operation.token, "succeeded", None, None);
    transport.post_operation_status(&status_url, &request_auth, &body)?;

    Ok(ProbeUpgraderResult {
        error_code: None,
        message: None,
        operation_id: operation.operation_id,
        status: "succeeded".to_string(),
    })
}

#[cfg(test)]
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

#[cfg(test)]
fn execute_probe_uninstall_with_install_metadata_path(
    input: &ProbeUninstallerRunInput,
    install_metadata: &TrustedProbeInstallMetadata,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    install_metadata_path: &Path,
) -> Result<(), ProbeUpgraderRunError> {
    let plan = plan_probe_uninstall_cleanup(input, install_metadata, install_metadata_path, false)?;
    execute_probe_uninstall_cleanup(&plan, systemd, UninstallCleanupExtent::Complete)
}

/// Runs the same trusted uninstall cleanup core used by both public and
/// Hub-authorized uninstall paths. The staged local-install candidate uses
/// this only after it has established that the complete prior installation is
/// bound to the same Hub.
pub(crate) fn cleanup_trusted_probe_install_for_reenrollment(
    install_metadata_path: &Path,
    test_root: Option<&Path>,
) -> Result<(), ProbeUpgraderRunError> {
    let install_metadata_path = preflight_rooted_path(test_root, install_metadata_path);
    let mut install_metadata =
        read_trusted_probe_install_metadata_read_only(&install_metadata_path, None)?;
    rebase_trusted_install_metadata_paths(&mut install_metadata, test_root);
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: install_metadata.identity_path.clone(),
    };
    let plan =
        plan_probe_uninstall_cleanup(&input, &install_metadata, &install_metadata_path, false)?;
    let mut systemd = SystemProbeUpgraderSystemdRunner;
    execute_probe_uninstall_cleanup(&plan, &mut systemd, UninstallCleanupExtent::Replacement)
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

#[derive(Debug)]
struct ProbeUninstallCleanupPlan<'a> {
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UninstallCleanupExtent {
    Prepare,
    RecoverableFinalize,
    #[cfg(test)]
    Complete,
    Replacement,
}

impl UninstallCleanupExtent {
    fn removes_bootstrap_state(self) -> bool {
        self != Self::Replacement
    }
}

/// Establishes every local deletion target before systemd or filesystem
/// mutation. Both the offline public command and Hub-authorized operation
/// invoke this planner through the same executor below.
fn plan_probe_uninstall_cleanup<'a>(
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
    recovery: bool,
) -> Result<ProbeUninstallCleanupPlan<'a>, ProbeUpgraderRunError> {
    ensure_absolute_path(&input.bootstrap_config_path)?;
    for path in [
        install_metadata_path,
        &install_metadata.identity_path,
        &install_metadata.install_path,
        &install_metadata.service_unit_path,
        &install_metadata.state_dir,
    ] {
        ensure_absolute_path(path)?;
    }
    for path in [
        install_metadata.operation_sudoers_path.as_deref(),
        install_metadata.collector_helper_sudoers_path.as_deref(),
        install_metadata.bootstrap_acquirer_path.as_deref(),
        install_metadata.bootstrap_activator_path.as_deref(),
        install_metadata.bootstrap_state_dir.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        ensure_absolute_path(path)?;
    }
    for path in &install_metadata.old_sudoers_paths {
        ensure_absolute_path(path)?;
    }
    for path in [
        install_metadata.observation_runtime_path.as_deref(),
        install_metadata.cpu_provider_path.as_deref(),
        install_metadata.disk_health_provider_path.as_deref(),
        install_metadata.lifecycle_companion_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        ensure_absolute_path(path)?;
    }
    for path in &install_metadata.observation_unit_paths {
        ensure_absolute_path(path)?;
    }
    if matches!(install_metadata.schema_version, 2..=5) {
        validate_owned_bootstrap_role_for_cleanup(
            install_metadata.bootstrap_acquirer_path.as_deref(),
            recovery,
        )?;
        validate_owned_bootstrap_role_for_cleanup(
            install_metadata.bootstrap_activator_path.as_deref(),
            recovery,
        )?;
        validate_owned_bootstrap_state_for_cleanup(
            install_metadata.bootstrap_state_dir.as_deref(),
            recovery,
        )?;
    }
    Ok(ProbeUninstallCleanupPlan {
        input,
        install_metadata,
        install_metadata_path,
    })
}

fn execute_probe_uninstall_cleanup(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    extent: UninstallCleanupExtent,
) -> Result<(), ProbeUpgraderRunError> {
    let input = plan.input;
    let install_metadata = plan.install_metadata;
    if matches!(install_metadata.schema_version, 3..=5) {
        for service in observation_services(install_metadata.schema_version)
            .iter()
            .copied()
            .filter(|service| !is_lifecycle_companion_service(service))
            .rev()
        {
            systemd.stop_service(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_stop_failed",
                    "stopping an observation role",
                    error,
                )
            })?;
            systemd.disable_service(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_disable_failed",
                    "disabling an observation role",
                    error,
                )
            })?;
        }
    }
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
    for path in &install_metadata.observation_unit_paths {
        if is_lifecycle_companion_path(path) {
            continue;
        }
        remove_path_if_exists(path)?;
        verify_path_absent(
            path,
            "probe_uninstall_service_unit_residue",
            "verifying an observation role unit is absent",
        )?;
    }
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
    if matches!(install_metadata.schema_version, 3..=5) {
        for service in observation_services(install_metadata.schema_version) {
            if is_lifecycle_companion_service(service) {
                continue;
            }
            systemd.reset_failed(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_reset_failed",
                    "resetting an observation role failed state",
                    error,
                )
            })?;
            systemd.verify_service_absent(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_verification_failed",
                    "verifying an observation role is absent",
                    error,
                )
            })?;
        }
    }
    remove_path_if_exists(&install_metadata.install_path)?;
    for path in [
        install_metadata.observation_runtime_path.as_deref(),
        install_metadata.cpu_provider_path.as_deref(),
        install_metadata.disk_health_provider_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        remove_path_if_exists(path)?;
    }
    if let Some(path) = &install_metadata.operation_sudoers_path {
        remove_path_if_exists(path)?;
    }
    if let Some(path) = &install_metadata.collector_helper_sudoers_path {
        remove_path_if_exists(path)?;
    }
    for path in &install_metadata.old_sudoers_paths {
        remove_path_if_exists(path)?;
    }
    if extent == UninstallCleanupExtent::Prepare {
        return Ok(());
    }
    for path in [
        install_metadata.bootstrap_acquirer_path.as_deref(),
        install_metadata.bootstrap_activator_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        remove_path_if_exists(path)?;
    }
    if extent.removes_bootstrap_state()
        && let Some(path) = install_metadata.bootstrap_state_dir.as_deref()
    {
        remove_owned_bootstrap_state(path)?;
    }
    // 在所有易失败的账户清理完成前，保留 Companion 激活资产和可信元数据。
    // 中断后管理员仍可从同一固定入口提交绑定到该安装收据的显式卸载请求。
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
    if let Some(ipc_group) = install_metadata.observation_ipc_group.as_deref() {
        systemd
            .remove_service_identity(ipc_group, ipc_group)
            .map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_group_remove_failed",
                    "removing the observation IPC group",
                    error,
                )
            })?;
    }
    if let Some((ipc_group, ownership)) = install_metadata
        .probe_ipc_group
        .as_deref()
        .zip(install_metadata.probe_ipc_group_ownership.as_deref())
    {
        systemd
            .remove_owned_ipc_group(ipc_group, ownership)
            .map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_group_remove_failed",
                    "removing the lifecycle IPC group",
                    error,
                )
            })?;
    }

    if matches!(install_metadata.schema_version, 4 | 5) {
        // 自删除是最后一个角色清理阶段；当前进程持有已打开的可执行文件，
        // 不需要第二套执行器或运行时选择的路径。
        let companion_services = if install_metadata.schema_version == 5 {
            &[
                "enoki-probe-lifecycle-upgrade.socket",
                "enoki-probe-lifecycle-companion.socket",
            ][..]
        } else {
            &["enoki-probe-lifecycle-companion.socket"][..]
        };
        for companion_service in companion_services {
            systemd.stop_service(companion_service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_stop_failed",
                    "stopping a lifecycle companion socket",
                    error,
                )
            })?;
            systemd
                .disable_service(companion_service)
                .map_err(|error| {
                    probe_uninstall_cleanup_error(
                        "probe_uninstall_service_disable_failed",
                        "disabling a lifecycle companion socket",
                        error,
                    )
                })?;
        }
        for path in install_metadata
            .observation_unit_paths
            .iter()
            .filter(|path| is_lifecycle_companion_path(path))
        {
            remove_path_if_exists(path)?;
        }
        if extent != UninstallCleanupExtent::RecoverableFinalize
            && let Some(path) = install_metadata.lifecycle_companion_path.as_deref()
        {
            remove_path_if_exists(path)?;
        }
        systemd.daemon_reload().map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_daemon_reload_failed",
                "reloading systemd after lifecycle companion removal",
                error,
            )
        })?;
        for companion_service in companion_services {
            systemd.reset_failed(companion_service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_reset_failed",
                    "resetting a lifecycle companion socket failed state",
                    error,
                )
            })?;
            systemd
                .verify_service_absent(companion_service)
                .map_err(|error| {
                    probe_uninstall_cleanup_error(
                        "probe_uninstall_service_verification_failed",
                        "verifying a lifecycle companion socket is absent",
                        error,
                    )
                })?;
        }
    }

    if extent == UninstallCleanupExtent::Replacement {
        // 手动重装必须让可信 metadata 活过全部可失败清理与核验。删除 metadata
        // 是最后一个可失败动作；成功后候选 Activator 可立即进入 fresh transaction。
        return finalize_replacement_local_state_with(
            &input.bootstrap_config_path,
            &install_metadata.state_dir,
            plan.install_metadata_path,
            remove_path_if_exists,
            || verify_probe_uninstall_cleanup(plan, systemd, extent),
        );
    }

    remove_uninstall_local_state_with(plan, remove_path_if_exists)?;
    remove_empty_parent_dir(&input.bootstrap_config_path)?;

    verify_probe_uninstall_cleanup(plan, systemd, extent)
}

fn remove_uninstall_local_state_with(
    plan: &ProbeUninstallCleanupPlan<'_>,
    mut remove: impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    remove(plan.install_metadata_path)?;
    remove(&plan.input.bootstrap_config_path)?;
    remove(&plan.install_metadata.state_dir)
}

fn finalize_replacement_local_state_with(
    bootstrap_config_path: &Path,
    state_dir: &Path,
    install_metadata_path: &Path,
    mut remove: impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
    verify: impl FnOnce() -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    remove(bootstrap_config_path)?;
    remove(state_dir)?;
    verify()?;
    remove(install_metadata_path)
}

fn verify_probe_uninstall_cleanup(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    extent: UninstallCleanupExtent,
) -> Result<(), ProbeUpgraderRunError> {
    let metadata = plan.install_metadata;
    for (path, code, action) in [
        (
            metadata.install_path.as_path(),
            "probe_uninstall_binary_residue",
            "verifying the Probe binary is absent",
        ),
        (
            metadata.identity_path.as_path(),
            "probe_uninstall_identity_residue",
            "verifying the Probe identity is absent",
        ),
        (
            plan.input.bootstrap_config_path.as_path(),
            "probe_uninstall_config_residue",
            "verifying the Probe bootstrap config is absent",
        ),
        (
            plan.install_metadata_path,
            "probe_uninstall_metadata_residue",
            "verifying install metadata is absent",
        ),
        (
            metadata.state_dir.as_path(),
            "probe_uninstall_state_residue",
            "verifying Probe state is absent",
        ),
        (
            metadata.service_unit_path.as_path(),
            "probe_uninstall_service_unit_residue",
            "verifying the service unit is absent",
        ),
    ] {
        if extent != UninstallCleanupExtent::Replacement || path != plan.install_metadata_path {
            verify_path_absent(path, code, action)?;
        }
    }
    for (path, code, action) in [
        (
            metadata.operation_sudoers_path.as_deref(),
            "probe_uninstall_operation_sudoers_residue",
            "verifying operation sudoers is absent",
        ),
        (
            metadata.collector_helper_sudoers_path.as_deref(),
            "probe_uninstall_collector_sudoers_residue",
            "verifying collector sudoers is absent",
        ),
    ] {
        if let Some(path) = path {
            verify_path_absent(path, code, action)?;
        }
    }
    for path in &metadata.old_sudoers_paths {
        verify_path_absent(
            path,
            "probe_uninstall_legacy_sudoers_residue",
            "verifying legacy sudoers is absent",
        )?;
    }
    for path in [
        metadata.observation_runtime_path.as_deref(),
        metadata.cpu_provider_path.as_deref(),
        metadata.disk_health_provider_path.as_deref(),
        metadata.lifecycle_companion_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if extent == UninstallCleanupExtent::RecoverableFinalize
            && is_lifecycle_companion_path(path)
        {
            continue;
        }
        verify_path_absent(
            path,
            "probe_uninstall_binary_residue",
            "verifying an observation role binary is absent",
        )?;
    }
    for path in &metadata.observation_unit_paths {
        verify_path_absent(
            path,
            "probe_uninstall_service_unit_residue",
            "verifying an observation role unit is absent",
        )?;
    }
    for (path, code, action) in [
        (
            metadata.bootstrap_acquirer_path.as_deref(),
            "probe_uninstall_bootstrap_acquirer_residue",
            "verifying Probe Bootstrap acquirer is absent",
        ),
        (
            metadata.bootstrap_activator_path.as_deref(),
            "probe_uninstall_bootstrap_activator_residue",
            "verifying Probe Bootstrap activator is absent",
        ),
    ] {
        if let Some(path) = path {
            verify_path_absent(path, code, action)?;
        }
    }
    if extent.removes_bootstrap_state()
        && let Some(path) = metadata.bootstrap_state_dir.as_deref()
    {
        verify_path_absent(
            path,
            "probe_uninstall_bootstrap_state_residue",
            "verifying Probe Bootstrap state is absent",
        )?;
    }
    systemd
        .verify_service_absent(&metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_verification_failed",
                "verifying the service is absent",
                error,
            )
        })
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

fn validate_owned_bootstrap_role(path: Option<&Path>) -> Result<(), ProbeUpgraderRunError> {
    let path = path.ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
        "schema v2 metadata is missing Probe Bootstrap ownership",
    ))?;
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o755
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap role is not a root-owned regular 0755 file",
        ));
    }
    Ok(())
}

fn validate_owned_bootstrap_role_for_cleanup(
    path: Option<&Path>,
    recovery: bool,
) -> Result<(), ProbeUpgraderRunError> {
    if recovery
        && path.is_some_and(|path| {
            fs::symlink_metadata(path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        })
    {
        return Ok(());
    }
    validate_owned_bootstrap_role(path)
}

fn validate_owned_bootstrap_state(path: Option<&Path>) -> Result<(), ProbeUpgraderRunError> {
    let path = path.ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
        "schema v2 metadata is missing Probe Bootstrap ownership",
    ))?;
    validate_owned_bootstrap_directory(path, 0o700)?;
    for entry in fs::read_dir(path).map_err(ProbeUpgraderRunError::Io)? {
        let entry = entry.map_err(ProbeUpgraderRunError::Io)?;
        match entry.file_name().to_str() {
            Some("trust") => {
                validate_owned_bootstrap_directory(&entry.path(), 0o700)?;
                for trust in fs::read_dir(entry.path()).map_err(ProbeUpgraderRunError::Io)? {
                    let trust = trust.map_err(ProbeUpgraderRunError::Io)?;
                    if !matches!(
                        trust.file_name().to_str(),
                        Some("delegation-generation" | ".delegation-generation.lock")
                    ) {
                        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                            "Probe Bootstrap state contains an unexpected entry",
                        ));
                    }
                    validate_owned_bootstrap_regular(&trust.path(), 0o600)?;
                }
            }
            Some("inbox") => {
                validate_owned_bootstrap_directory(&entry.path(), 0o700)?;
                if fs::read_dir(entry.path())
                    .map_err(ProbeUpgraderRunError::Io)?
                    .next()
                    .is_some()
                {
                    return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                        "Probe Bootstrap inbox is not empty",
                    ));
                }
            }
            _ => {
                return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                    "Probe Bootstrap state contains an unexpected entry",
                ));
            }
        }
    }
    Ok(())
}

fn validate_owned_bootstrap_state_for_cleanup(
    path: Option<&Path>,
    recovery: bool,
) -> Result<(), ProbeUpgraderRunError> {
    if recovery
        && path.is_some_and(|path| {
            fs::symlink_metadata(path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        })
    {
        return Ok(());
    }
    validate_owned_bootstrap_state(path)
}

fn validate_owned_bootstrap_directory(path: &Path, mode: u32) -> Result<(), ProbeUpgraderRunError> {
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap state is not a root-owned private directory",
        ));
    }
    Ok(())
}
fn validate_owned_bootstrap_regular(path: &Path, mode: u32) -> Result<(), ProbeUpgraderRunError> {
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != mode
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap state contains an unsafe entry",
        ));
    }
    Ok(())
}
fn remove_owned_bootstrap_state(path: &Path) -> Result<(), ProbeUpgraderRunError> {
    if fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) {
        return Ok(());
    }
    validate_owned_bootstrap_state(Some(path))?;
    fs::remove_dir_all(path).map_err(ProbeUpgraderRunError::Io)
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
    upgrade_target: Option<(&str, &str)>,
) -> String {
    let target_fields = upgrade_target.map_or_else(String::new, |(digest, version)| {
        format!(
            "\"targetAssetSetDigest\":\"{}\",\"targetProbeVersion\":\"{}\",",
            json_string_fragment(digest),
            json_string_fragment(version),
        )
    });
    if let Some(failure) = failure {
        return format!(
            "{{\"errorCode\":\"{}\",\"message\":\"{}\",\"status\":\"{}\",{}\"token\":\"{}\"}}",
            json_string_fragment(
                failure
                    .error_code
                    .as_deref()
                    .unwrap_or("probe_operation_failed")
            ),
            json_string_fragment(failure.message.as_deref().unwrap_or("")),
            json_string_fragment(status),
            target_fields,
            json_string_fragment(token),
        );
    }

    format!(
        "{{\"status\":\"{}\",{}\"token\":\"{}\"}}",
        json_string_fragment(status),
        target_fields,
        json_string_fragment(token),
    )
}

struct ProbeUpgraderOperationMetadata {
    operation_id: String,
    target_asset_set_digest: String,
    target_probe_version: String,
    token: String,
}

#[cfg(test)]
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
    let target_asset_set_digest = required_metadata_string(&value, "target_asset_set_digest")?;
    let target_probe_version = required_metadata_string(&value, "target_probe_version")?;
    let token = required_metadata_string(&value, "token")?;

    Ok(ProbeUpgraderOperationMetadata {
        operation_id,
        target_asset_set_digest,
        target_probe_version,
        token,
    })
}

#[cfg(test)]
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

#[cfg(test)]
fn read_trusted_probe_install_metadata_with_file_metadata(
    path: &Path,
    legacy_identity_path: Option<&Path>,
    file_metadata: TrustedFileMetadata,
) -> Result<TrustedProbeInstallMetadata, ProbeUpgraderRunError> {
    let mut metadata = read_trusted_probe_install_metadata_read_only_with_file_metadata(
        path,
        legacy_identity_path,
        file_metadata,
    )?;
    if metadata.schema_version == 0 {
        write_trusted_probe_install_metadata(path, &metadata)?;
        metadata.schema_version = 1;
    }
    Ok(metadata)
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
    if install_metadata.schema_version == 3 {
        return execute_schema_three_probe_upgrade(
            operation,
            bootstrap_config_path,
            install_metadata,
            transport,
            systemd,
            current_probe_version,
            true,
        );
    }
    let hub_url = &install_metadata.hub_url;

    let manifest_bytes = download_hub_asset(transport, hub_url, "manifest.json")?;
    let signature_bytes = download_hub_asset(transport, hub_url, "manifest.json.sig")?;
    let public_key_bytes = download_hub_asset(transport, hub_url, "signing-key.pem")?;

    if operation.target_asset_set_digest != format!("sha256:{}", hex_sha256(&manifest_bytes)) {
        return Err(ProbeUpgraderRunError::TargetMismatch);
    }
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
    remove_legacy_collector_helper_sudoers(install_metadata)?;
    remove_old_sudoers_paths(install_metadata)?;
    write_local_operation_status(operation, install_metadata).map_err(|error| {
        ProbeUpgraderRunError::PostReplacementStatusWriteFailure(error.to_string())
    })?;
    systemd
        .restart_service(&install_metadata.service_name)
        .map_err(|error| ProbeUpgraderRunError::PostReplacementRestartFailure(error.to_string()))?;

    Ok(())
}

fn execute_schema_three_probe_upgrade(
    operation: &ProbeUpgraderOperationMetadata,
    bootstrap_config_path: &Path,
    install_metadata: &TrustedProbeInstallMetadata,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    current_probe_version: &str,
    require_newer: bool,
) -> Result<(), ProbeUpgraderRunError> {
    let root_fingerprint = install_metadata
        .probe_distribution_root_sha256
        .as_deref()
        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "schema 3 distribution root fingerprint is missing",
        ))?;
    let bootstrap_state = install_metadata.bootstrap_state_dir.as_deref().ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata("schema 3 Bootstrap state is missing"),
    )?;
    let runtime_path = install_metadata.observation_runtime_path.as_deref().ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata("schema 3 Runtime path is missing"),
    )?;
    let provider_path = install_metadata.cpu_provider_path.as_deref().ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata("schema 3 Provider path is missing"),
    )?;
    let disk_health_provider_path = install_metadata
        .disk_health_provider_path
        .as_deref()
        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "schema 3 Disk Health Provider path is missing",
        ))?;
    let hub_url = &install_metadata.hub_url;
    let root_key = download_hub_asset(transport, hub_url, "root-key.pem")?;
    let provisional = Handoff {
        delegation: download_hub_asset(transport, hub_url, "trust-delegation.json")?,
        delegation_signature: download_hub_asset(transport, hub_url, "trust-delegation.json.sig")?,
        manifest: download_hub_asset(transport, hub_url, "manifest.json")?,
        manifest_signature: download_hub_asset(transport, hub_url, "manifest.json.sig")?,
        signing_key: download_hub_asset(transport, hub_url, "signing-key.pem")?,
        bundle_manifest: Vec::new(),
    };
    if require_newer
        && operation.target_asset_set_digest
            != format!("sha256:{}", hex_sha256(&provisional.manifest))
    {
        return Err(ProbeUpgraderRunError::TargetMismatch);
    }
    let target = host_probe_asset_target()?;
    let policy = VerificationPolicy {
        distribution: "enoki",
        expected_target: target,
        highest_accepted_delegation_generation: 0,
        external_root_fingerprint: root_fingerprint.to_string(),
        external_root_pem: Some(&root_key),
    };
    let outer = verify_outer_metadata(&provisional, &policy)
        .map_err(|_| ProbeUpgraderRunError::SignatureFailure)?;
    let archive_bytes = download_hub_asset(transport, hub_url, outer.archive_file())?;
    if archive_bytes.len() as u64 != outer.archive_len() {
        return Err(ProbeUpgraderRunError::ChecksumFailure);
    }
    let mut archive = tempfile::tempfile().map_err(ProbeUpgraderRunError::Io)?;
    archive
        .write_all(&archive_bytes)
        .map_err(ProbeUpgraderRunError::Io)?;
    let bundle_manifest = read_bundle_manifest(&mut archive)
        .map_err(|_| ProbeUpgraderRunError::UnsafeArchive("invalid Bundle manifest"))?;
    let handoff = Handoff {
        bundle_manifest,
        ..provisional
    };
    let metadata =
        verify_metadata(&handoff, &policy).map_err(|_| ProbeUpgraderRunError::SignatureFailure)?;
    if normalized_probe_version(&metadata.bundle().version)
        != normalized_probe_version(&operation.target_probe_version)
    {
        return Err(ProbeUpgraderRunError::TargetMismatch);
    }
    if require_newer {
        validate_probe_upgrade_target_is_newer(&metadata.bundle().version, current_probe_version)?;
    } else if normalized_probe_version(&metadata.bundle().version)
        != normalized_probe_version(current_probe_version)
    {
        return Err(ProbeUpgraderRunError::TargetMismatch);
    }
    let mut probe = Vec::new();
    let mut runtime = Vec::new();
    let mut provider = Vec::new();
    let mut disk_health_provider = Vec::new();
    let mut lifecycle_companion = Vec::new();
    let mut bootstrap_acquirer = Vec::new();
    let mut bootstrap_activator = Vec::new();
    let verified_bundle = verify_archive_and_extract_lifecycle_roles(
        &mut archive,
        &handoff,
        &metadata,
        &mut probe,
        &mut runtime,
        &mut provider,
        &mut disk_health_provider,
        &mut lifecycle_companion,
        &mut bootstrap_acquirer,
        &mut bootstrap_activator,
    )
    .map_err(|_| ProbeUpgraderRunError::UnsafeArchive("Bundle role verification failed"))?;

    preflight_local_operation_status_writable(install_metadata)?;
    if install_metadata.observation_unit_paths.len() != 6 {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "schema 3 observation unit inventory is incomplete",
        ));
    }
    let mut replacements = vec![
        (
            install_metadata.install_path.as_path(),
            probe.as_slice(),
            0o755,
        ),
        (runtime_path, runtime.as_slice(), 0o755),
        (provider_path, provider.as_slice(), 0o755),
        (
            disk_health_provider_path,
            disk_health_provider.as_slice(),
            0o755,
        ),
    ];
    let bootstrap_acquirer_path = install_metadata.bootstrap_acquirer_path.as_deref().ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata(
            "schema 3 Bootstrap Acquirer path is missing",
        ),
    )?;
    let bootstrap_activator_path = install_metadata.bootstrap_activator_path.as_deref().ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata(
            "schema 3 Bootstrap Activator path is missing",
        ),
    )?;
    let target_units =
        render_target_observation_integration(bootstrap_state, &bootstrap_activator)?;
    replacements.extend(
        install_metadata
            .observation_unit_paths
            .iter()
            .map(PathBuf::as_path)
            .zip(target_units.iter())
            .map(|(path, contents)| (path, contents.as_slice(), 0o644)),
    );
    replacements.extend([
        (
            bootstrap_acquirer_path,
            bootstrap_acquirer.as_slice(),
            0o755,
        ),
        (
            bootstrap_activator_path,
            bootstrap_activator.as_slice(),
            0o755,
        ),
    ]);

    recover_schema_three_activation(bootstrap_state, &replacements, systemd, install_metadata)?;
    // 全部目标、备份和 candidate bytes 已在 stop 之前持久化。
    let transaction = prepare_schema_three_activation(bootstrap_state, &replacements)?;
    let generation_result = acquire_delegation_generation_at_owned_root(
        bootstrap_state,
        0,
        verified_bundle.delegation_generation(),
    );
    let mut generation = match generation_result {
        Ok(generation) => generation,
        Err(_) => {
            transaction.rollback()?;
            return Err(ProbeUpgraderRunError::SignatureFailure);
        }
    };
    if generation.persist_before_mutation().is_err() {
        transaction.rollback()?;
        return Err(ProbeUpgraderRunError::SignatureFailure);
    }

    let activation = (|| {
        stop_schema_three_services(systemd, install_metadata)?;
        transaction.activate()?;
        systemd.daemon_reload()?;
        write_probe_operation_sudoers(install_metadata, bootstrap_config_path)?;
        remove_legacy_collector_helper_sudoers(install_metadata)?;
        write_local_operation_status(operation, install_metadata).map_err(|error| {
            ProbeUpgraderRunError::PostReplacementStatusWriteFailure(error.to_string())
        })?;
        restart_schema_three_services(systemd, install_metadata)?;
        Ok(())
    })();
    match activation {
        Ok(()) => transaction.commit(),
        Err(error) => {
            let rollback = transaction.rollback();
            // 旧 units 在 systemd 中仍已加载；reload 失败不能阻止恢复旧角色。
            let _reload = systemd.daemon_reload();
            let recovery = restart_schema_three_services(systemd, install_metadata);
            if rollback.is_err() || recovery.is_err() {
                return Err(ProbeUpgraderRunError::PostReplacementRestartFailure(
                    "Bundle activation rollback or service recovery failed".to_string(),
                ));
            }
            Err(match error {
                ProbeUpgraderRunError::PostReplacementStatusWriteFailure(_) => error,
                _ => ProbeUpgraderRunError::PostReplacementRestartFailure(error.to_string()),
            })
        }
    }
}

fn render_target_observation_integration(
    bootstrap_state: &Path,
    verified_activator: &[u8],
) -> Result<[Vec<u8>; 6], ProbeUpgraderRunError> {
    const MAX_INTEGRATION_BYTES: u64 = 256 * 1024;
    let mut activator =
        tempfile::NamedTempFile::new_in(bootstrap_state).map_err(ProbeUpgraderRunError::Io)?;
    activator
        .write_all(verified_activator)
        .map_err(ProbeUpgraderRunError::Io)?;
    activator
        .as_file()
        .sync_all()
        .map_err(ProbeUpgraderRunError::Io)?;
    activator
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(ProbeUpgraderRunError::Io)?;
    let activator_path = activator.into_temp_path();
    let mut output = tempfile::tempfile().map_err(ProbeUpgraderRunError::Io)?;
    let stdout = output.try_clone().map_err(ProbeUpgraderRunError::Io)?;
    let mut child = Command::new(&activator_path)
        .arg("--render-observation-integration-v1")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null())
        .spawn()
        .map_err(ProbeUpgraderRunError::Io)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(ProbeUpgraderRunError::Io)? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProbeUpgraderRunError::UnsafeArchive(
                "target Activator integration renderer exceeded its deadline",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !status.success()
        || output.metadata().map_err(ProbeUpgraderRunError::Io)?.len() > MAX_INTEGRATION_BYTES
    {
        return Err(ProbeUpgraderRunError::UnsafeArchive(
            "target Activator integration renderer failed",
        ));
    }
    output
        .seek(SeekFrom::Start(0))
        .map_err(ProbeUpgraderRunError::Io)?;
    let mut rendered = Vec::new();
    output
        .take(MAX_INTEGRATION_BYTES + 1)
        .read_to_end(&mut rendered)
        .map_err(ProbeUpgraderRunError::Io)?;
    parse_observation_integration_v1(&rendered)
}

fn parse_observation_integration_v1(bytes: &[u8]) -> Result<[Vec<u8>; 6], ProbeUpgraderRunError> {
    const MAGIC: &[u8] = b"enoki.observation-integration.v1\n";
    if !bytes.starts_with(MAGIC) {
        return Err(ProbeUpgraderRunError::UnsafeArchive(
            "target Activator integration response is malformed",
        ));
    }
    let mut offset = MAGIC.len();
    let mut units = Vec::with_capacity(6);
    for _ in 0..6 {
        let line_end = bytes[offset..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|position| offset + position)
            .ok_or(ProbeUpgraderRunError::UnsafeArchive(
                "target Activator integration response is malformed",
            ))?;
        let length = std::str::from_utf8(&bytes[offset..line_end])
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|length| *length > 0 && *length <= 64 * 1024)
            .ok_or(ProbeUpgraderRunError::UnsafeArchive(
                "target Activator integration response is malformed",
            ))?;
        offset = line_end + 1;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(ProbeUpgraderRunError::UnsafeArchive(
                "target Activator integration response is malformed",
            ))?;
        units.push(bytes[offset..end].to_vec());
        offset = end;
    }
    if offset != bytes.len() {
        return Err(ProbeUpgraderRunError::UnsafeArchive(
            "target Activator integration response has trailing bytes",
        ));
    }
    units.try_into().map_err(|_| {
        ProbeUpgraderRunError::UnsafeArchive("target Activator integration response is malformed")
    })
}

struct SchemaThreeActivation {
    directory: PathBuf,
    entries: Vec<SchemaThreeActivationEntry>,
}

struct SchemaThreeActivationEntry {
    destination: PathBuf,
    staged: PathBuf,
    backup: PathBuf,
    mode: u32,
}

struct SchemaThreePreparationGuard {
    directory: PathBuf,
    staged: Vec<PathBuf>,
    complete: bool,
}

impl Drop for SchemaThreePreparationGuard {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        for path in &self.staged {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn prepare_schema_three_activation(
    bootstrap_state: &Path,
    components: &[(&Path, &[u8], u32)],
) -> Result<SchemaThreeActivation, ProbeUpgraderRunError> {
    let directory = bootstrap_state.join("upgrade-transaction");
    fs::create_dir(&directory).map_err(ProbeUpgraderRunError::Io)?;
    let mut guard = SchemaThreePreparationGuard {
        directory: directory.clone(),
        staged: Vec::new(),
        complete: false,
    };
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(ProbeUpgraderRunError::Io)?;
    let mut entries = Vec::with_capacity(components.len());
    for (index, &(path, bytes, mode)) in components.iter().enumerate() {
        if bytes.is_empty() {
            return Err(ProbeUpgraderRunError::UnsafeArchive(
                "verified Bundle component is empty",
            ));
        }
        let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Bundle destination must be an existing regular file",
            ));
        }
        let parent = path.parent().ok_or(ProbeUpgraderRunError::InvalidConfig(
            "Bundle role path has no parent",
        ))?;
        let file_name = path.file_name().and_then(|name| name.to_str()).ok_or(
            ProbeUpgraderRunError::InvalidInstallMetadata("Bundle role filename is invalid"),
        )?;
        let staged = parent.join(format!(".{file_name}.enoki-upgrade-{index}"));
        let backup = directory.join(format!("backup-{index}"));
        write_new_synced_file(&staged, bytes, mode)?;
        guard.staged.push(staged.clone());
        write_new_synced_file(
            &backup,
            &fs::read(path).map_err(ProbeUpgraderRunError::Io)?,
            metadata.mode() & 0o777,
        )?;
        entries.push(SchemaThreeActivationEntry {
            destination: path.to_path_buf(),
            staged,
            backup,
            mode: metadata.mode() & 0o777,
        });
    }
    let journal = entries
        .iter()
        .map(|entry| entry.destination.display().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    write_new_synced_file(&directory.join("journal"), journal.as_bytes(), 0o600)?;
    sync_directory(&directory)?;
    sync_directory(bootstrap_state)?;
    guard.complete = true;
    Ok(SchemaThreeActivation { directory, entries })
}

impl SchemaThreeActivation {
    fn activate(&self) -> Result<(), ProbeUpgraderRunError> {
        for entry in &self.entries {
            fs::rename(&entry.staged, &entry.destination).map_err(ProbeUpgraderRunError::Io)?;
            sync_directory(entry.destination.parent().expect("preflighted parent"))?;
        }
        Ok(())
    }

    fn rollback(&self) -> Result<(), ProbeUpgraderRunError> {
        for entry in &self.entries {
            let bytes = fs::read(&entry.backup).map_err(ProbeUpgraderRunError::Io)?;
            let parent = entry.destination.parent().expect("preflighted parent");
            let file_name = entry
                .destination
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
                    "Bundle role filename is invalid",
                ))?;
            let rollback = parent.join(format!(".{file_name}.enoki-rollback"));
            let _ = fs::remove_file(&rollback);
            write_new_synced_file(&rollback, &bytes, entry.mode)?;
            fs::rename(&rollback, &entry.destination).map_err(ProbeUpgraderRunError::Io)?;
            sync_directory(parent)?;
            let _ = fs::remove_file(&entry.staged);
        }
        self.remove()
    }

    fn commit(self) -> Result<(), ProbeUpgraderRunError> {
        self.remove()
    }

    fn remove(&self) -> Result<(), ProbeUpgraderRunError> {
        fs::remove_dir_all(&self.directory).map_err(ProbeUpgraderRunError::Io)?;
        sync_directory(self.directory.parent().expect("transaction parent"))
    }
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

fn stop_schema_three_services(
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    for service in OBSERVATION_SERVICES_SCHEMA_THREE.into_iter().rev() {
        systemd.stop_service(service)?;
    }
    systemd.stop_service(&install_metadata.service_name)
}

fn restart_schema_three_services(
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    for service in OBSERVATION_SERVICES_SCHEMA_THREE.into_iter().rev() {
        systemd.restart_service(service)?;
        systemd.verify_service_active(service)?;
    }
    systemd.restart_service(&install_metadata.service_name)?;
    systemd.verify_service_active(&install_metadata.service_name)
}

fn recover_schema_three_activation(
    bootstrap_state: &Path,
    components: &[(&Path, &[u8], u32)],
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    let directory = bootstrap_state.join("upgrade-transaction");
    if !directory.exists() {
        return Ok(());
    }
    if !directory.join("journal").is_file() {
        // journal 发布前从未停止服务或替换目标；只清理固定 candidate 临时名。
        for (index, &(destination, _, _)) in components.iter().enumerate() {
            if let (Some(parent), Some(file_name)) = (
                destination.parent(),
                destination.file_name().and_then(|name| name.to_str()),
            ) {
                let _ = fs::remove_file(parent.join(format!(".{file_name}.enoki-upgrade-{index}")));
            }
        }
        fs::remove_dir_all(&directory).map_err(ProbeUpgraderRunError::Io)?;
        return sync_directory(bootstrap_state);
    }
    let mut entries = Vec::with_capacity(components.len());
    for (index, &(destination, _, _)) in components.iter().enumerate() {
        let backup = directory.join(format!("backup-{index}"));
        entries.push(SchemaThreeActivationEntry {
            destination: destination.to_path_buf(),
            staged: destination
                .parent()
                .expect("preflighted parent")
                .join(format!(
                    ".{}.enoki-upgrade-{index}",
                    destination
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("invalid")
                )),
            mode: fs::metadata(&backup)
                .map_err(ProbeUpgraderRunError::Io)?
                .mode()
                & 0o777,
            backup,
        });
    }
    let transaction = SchemaThreeActivation { directory, entries };
    stop_schema_three_services(systemd, install_metadata)?;
    transaction.rollback()?;
    systemd.daemon_reload()?;
    restart_schema_three_services(systemd, install_metadata)
}

fn write_probe_operation_sudoers(
    install_metadata: &TrustedProbeInstallMetadata,
    bootstrap_config_path: &Path,
) -> Result<(), ProbeUpgraderRunError> {
    let Some(sudoers_path) = &install_metadata.operation_sudoers_path else {
        return Ok(());
    };
    ensure_absolute_path(bootstrap_config_path)?;
    let lines = render_probe_operation_sudoers_lines(install_metadata, bootstrap_config_path)?;

    if let Some(parent) = sudoers_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }

    fs::write(sudoers_path, lines.join("\n")).map_err(ProbeUpgraderRunError::Io)?;
    fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o440))
        .map_err(ProbeUpgraderRunError::Io)
}

fn remove_legacy_collector_helper_sudoers(
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    let Some(sudoers_path) = &install_metadata.collector_helper_sudoers_path else {
        return Ok(());
    };
    remove_path_if_exists(sudoers_path)
}

fn remove_old_sudoers_paths(
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    for path in &install_metadata.old_sudoers_paths {
        if Some(path) != install_metadata.operation_sudoers_path.as_ref()
            && Some(path) != install_metadata.collector_helper_sudoers_path.as_ref()
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

#[cfg(test)]
fn failed_probe_uninstaller_result(
    operation: &ProbeUninstallerOperationMetadata,
    error: &ProbeUpgraderRunError,
) -> ProbeUpgraderResult {
    ProbeUpgraderResult {
        error_code: Some(probe_upgrader_error_code(error).to_string()),
        message: Some("Probe uninstall failed.".to_owned()),
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
        ProbeUpgraderRunError::ManualProbeReinstallRequired => "manual_probe_reinstall_required",
        ProbeUpgraderRunError::InvalidConfig(_)
        | ProbeUpgraderRunError::InvalidInstallMetadata(_)
        | ProbeUpgraderRunError::InvalidManifest(_)
        | ProbeUpgraderRunError::InvalidMetadata(_)
        | ProbeUpgraderRunError::InvalidSigningKey(_)
        | ProbeUpgraderRunError::IdentityValidation(_)
        | ProbeUpgraderRunError::Io(_)
        | ProbeUpgraderRunError::LocalUninstallRootRequired
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

fn uninstall_capsule_path(install_metadata_path: &Path) -> Result<PathBuf, ProbeUpgraderRunError> {
    let Some(parent) = install_metadata_path.parent() else {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "install metadata path has no parent",
        ));
    };
    Ok(parent.join(UNINSTALL_CAPSULE_FILE_NAME))
}

fn lifecycle_authority_sha256(request: &LifecycleRequest) -> Result<String, ProbeUpgraderRunError> {
    request
        .encode()
        .map(|bytes| hex_sha256(&bytes))
        .map_err(|_| ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority invalid"))
}

fn read_uninstall_capsule(
    path: &Path,
) -> Result<Option<UninstallRecoveryCapsule>, ProbeUpgraderRunError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ProbeUpgraderRunError::Io(error)),
    };
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX_UNINSTALL_CAPSULE_BYTES
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule is not a root-owned regular 0600 file",
        ));
    }
    let contents = fs::read_to_string(path).map_err(ProbeUpgraderRunError::Io)?;
    let capsule: UninstallRecoveryCapsule = toml::from_str(&contents).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule is malformed")
    })?;
    let request = LifecycleRequest::decode(capsule.request_json.as_bytes()).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule request is invalid")
    })?;
    let canonical = toml::to_string(&capsule).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule is malformed")
    })?;
    if capsule.schema_version != 1
        || canonical != contents
        || lifecycle_authority_sha256(&request)? != capsule.authority_sha256
        || !capsule_receipt_matches_request(&capsule.install_metadata, &request)
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule is malformed",
        ));
    }
    Ok(Some(capsule))
}

fn persist_uninstall_capsule(
    path: &Path,
    request: &LifecycleRequest,
    install_metadata: &TrustedProbeInstallMetadata,
    phase: UninstallCapsulePhase,
) -> Result<(), ProbeUpgraderRunError> {
    let authority_sha256 = lifecycle_authority_sha256(request)?;
    if !capsule_receipt_matches_request(install_metadata, request) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule receipt does not match authority",
        ));
    }
    if let Some(existing) = read_uninstall_capsule(path)? {
        if existing.authority_sha256 != authority_sha256 {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "uninstall capsule belongs to another authority",
            ));
        }
        if uninstall_capsule_phase_rank(phase) < uninstall_capsule_phase_rank(existing.phase) {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "uninstall capsule phase cannot move backward",
            ));
        }
    }
    let parent = path
        .parent()
        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule path has no parent",
        ))?;
    let temporary = parent.join(".probe-uninstall.capsule.tmp");
    let request_json = String::from_utf8(request.encode().map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority invalid")
    })?)
    .map_err(|_| ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority invalid"))?;
    let capsule = UninstallRecoveryCapsule {
        schema_version: 1,
        authority_sha256,
        phase,
        request_json,
        install_metadata: install_metadata.clone(),
    };
    let contents = toml::to_string(&capsule).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule is malformed")
    })?;
    if contents.len() as u64 > MAX_UNINSTALL_CAPSULE_BYTES {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule is too large",
        ));
    }
    let _ = fs::remove_file(&temporary);
    write_new_synced_file(&temporary, contents.as_bytes(), 0o600)?;
    fs::rename(&temporary, path).map_err(ProbeUpgraderRunError::Io)?;
    sync_directory(parent)
}

fn uninstall_capsule_phase_rank(phase: UninstallCapsulePhase) -> u8 {
    match phase {
        UninstallCapsulePhase::Verified => 0,
        UninstallCapsulePhase::Prepared => 1,
        UninstallCapsulePhase::TerminalAcknowledged => 2,
    }
}

fn capsule_receipt_matches_request(
    metadata: &TrustedProbeInstallMetadata,
    request: &LifecycleRequest,
) -> bool {
    let (install_state, manifest, version) = match request.authority() {
        LifecycleRequestAuthority::HubOperation {
            install_state_sha256,
            target_manifest_sha256,
            bundle_version,
            ..
        }
        | LifecycleRequestAuthority::LocalRoot {
            install_state_sha256,
            target_manifest_sha256,
            bundle_version,
            ..
        } => (install_state_sha256, target_manifest_sha256, bundle_version),
        LifecycleRequestAuthority::HubUpgrade { .. }
        | LifecycleRequestAuthority::LocalRepair { .. }
        | LifecycleRequestAuthority::ReplacementEnrollment { .. } => return false,
    };
    matches!(metadata.schema_version, 4 | 5)
        && metadata.install_state_sha256.as_deref() == Some(install_state)
        && metadata.target_manifest_sha256.as_deref() == Some(manifest)
        && metadata.bundle_version.as_deref() == Some(version)
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

    #[test]
    fn compatible_upgrade_authority_is_verified_offline_with_the_per_install_key() {
        // Independent Node/OpenSSL-compatible known vector for the canonical
        // authority below and Enrollment Token `enk_enroll_test`.
        let signature = "78118da719bf6570b40ef0ea430cc27ad581c469bccc63eb433ff44e8b8e4595";
        let request = LifecycleRequest::hub_upgrade(
            "https://hub.example",
            "7",
            "probe_01",
            "operation_01",
            "1.2.2",
            &"a".repeat(64),
            &"b".repeat(64),
            "1.2.3",
            &format!("sha256:{}", "c".repeat(64)),
            &"d".repeat(64),
            &"e".repeat(64),
            u64::MAX,
            signature,
        )
        .expect("已签authority结构有效");
        let temporary = tempfile::tempdir().expect("临时目录");
        let mut metadata = trusted_install_metadata_for_hub(
            "https://hub.example",
            &temporary.path().join("enoki-probe"),
            &temporary.path().join("operation-status"),
            "f".repeat(64),
        );
        metadata.schema_version = 5;
        metadata.lifecycle_authority_install_key =
            Some("4c23e311e87657f52c608b5fe9688e802a6968f07259e169c6433f5c3ac0cb28".to_owned());

        let LifecycleRequestAuthority::HubUpgrade {
            expires_at_ms,
            authority_signature,
            ..
        } = request.authority()
        else {
            panic!("expected upgrade authority");
        };
        verify_lifecycle_upgrade_authority(
            &request,
            &metadata,
            *expires_at_ms,
            authority_signature,
        )
        .expect("root离线验签");
    }

    #[derive(Default)]
    struct RecordingValidationTransport {
        assets: HashMap<String, Vec<u8>>,
        body: String,
        downloads: Vec<String>,
        probe_id: String,
        status_body: String,
        status_failure: bool,
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
        paths_required_during_identity_removal: Vec<PathBuf>,
        restarted: Vec<String>,
    }

    #[test]
    fn replacement_migration_requires_one_exact_hub_and_identity_authority() {
        let temporary = tempfile::tempdir().unwrap();
        let status = temporary.path().join("probe-operation-status.toml");
        let mut metadata = trusted_install_metadata_for_hub(
            "https://hub.example",
            &temporary.path().join("enoki-probe"),
            &status,
            "a".repeat(64),
        );
        metadata.schema_version = 4;
        metadata.bundle_version = Some("1.2.2".to_string());
        let identity = TrustedProbeInstallPreflight {
            hub_url: "https://hub.example".to_string(),
            probe_id: "probe_old_01".to_string(),
        };
        let authority = crate::registration::ProbeReplacementAuthorization {
            expected_hub_origin: "https://hub.example".to_string(),
            expected_probe_id: "probe_old_01".to_string(),
            source_probe_version: "1.2.2".to_string(),
            source_probe_sha256: vec!["c".repeat(64)],
            target_asset_set_digest: format!("sha256:{}", "b".repeat(64)),
            target_probe_version: "1.2.3".to_string(),
        };

        assert_eq!(
            replacement_authority_matches(
                "https://hub.example",
                &format!("sha256:{}", "b".repeat(64)),
                "1.2.3",
                &authority,
                &metadata,
                &identity,
                &"c".repeat(64),
            ),
            ReplacementAuthorityMatch::Matches
        );
        metadata.bundle_version = Some("1.2.1".to_string());
        assert_eq!(
            replacement_authority_matches(
                "https://hub.example",
                &format!("sha256:{}", "b".repeat(64)),
                "1.2.3",
                &authority,
                &metadata,
                &identity,
                &"c".repeat(64),
            ),
            ReplacementAuthorityMatch::Mismatch
        );
        metadata.schema_version = 3;
        metadata.bundle_version = None;
        assert_eq!(
            replacement_authority_matches(
                "https://hub.example",
                &format!("sha256:{}", "b".repeat(64)),
                "1.2.3",
                &authority,
                &metadata,
                &identity,
                &"c".repeat(64),
            ),
            ReplacementAuthorityMatch::Matches
        );
        let mut unprovable = authority.clone();
        unprovable.source_probe_sha256.clear();
        assert_eq!(
            replacement_authority_matches(
                "https://hub.example",
                &format!("sha256:{}", "b".repeat(64)),
                "1.2.3",
                &unprovable,
                &metadata,
                &identity,
                &"c".repeat(64),
            ),
            ReplacementAuthorityMatch::UnprovableSource
        );
    }

    #[test]
    fn root_owned_installed_probe_facts_prove_a_legacy_component_without_runner_uid() {
        let facts = InstalledProbeBinaryFacts {
            device: 11,
            inode: 22,
            is_regular_file: true,
            is_symlink: false,
            length: 22,
            link_count: 1,
            mode: 0o755,
            owner_uid: 0,
        };
        validate_installed_probe_binary_facts(facts).expect("canonical facts are accepted");
        let installed_digest = installed_probe_sha256_from_reader(
            std::io::Cursor::new(b"legacy probe component"),
            facts,
        )
        .expect("bounded component is hashed");
        assert_eq!(
            installed_digest,
            "d7f57fc65a2c73a675a0952208f072d22e3c9e65995b07753e53946e2638966e"
        );

        let temporary = tempfile::tempdir().unwrap();
        let installed_probe = temporary.path().join("enoki-probe");
        let status = temporary.path().join("probe-operation-status.toml");
        let mut metadata = trusted_install_metadata_for_hub(
            "https://hub.example",
            &installed_probe,
            &status,
            "a".repeat(64),
        );
        metadata.schema_version = 3;
        metadata.bundle_version = None;
        let identity = TrustedProbeInstallPreflight {
            hub_url: "https://hub.example".to_string(),
            probe_id: "probe_old_01".to_string(),
        };
        let authority = crate::registration::ProbeReplacementAuthorization {
            expected_hub_origin: "https://hub.example".to_string(),
            expected_probe_id: "probe_old_01".to_string(),
            source_probe_version: "1.2.2".to_string(),
            source_probe_sha256: vec![installed_digest.clone()],
            target_asset_set_digest: format!("sha256:{}", "b".repeat(64)),
            target_probe_version: "1.2.3".to_string(),
        };

        assert_eq!(
            replacement_authority_matches(
                "https://hub.example",
                &format!("sha256:{}", "b".repeat(64)),
                "1.2.3",
                &authority,
                &metadata,
                &identity,
                &installed_digest,
            ),
            ReplacementAuthorityMatch::Matches
        );
    }

    #[test]
    fn replacement_cleanup_keeps_trusted_metadata_until_every_other_check_succeeds() {
        assert!(!UninstallCleanupExtent::Replacement.removes_bootstrap_state());
        assert!(UninstallCleanupExtent::Complete.removes_bootstrap_state());
        let config = PathBuf::from("/var/lib/enoki-probe/identity/probe-bootstrap.toml");
        let state = PathBuf::from("/var/lib/enoki-probe");
        let metadata = PathBuf::from("/etc/enoki/probe-install.toml");
        let mut failed_calls = Vec::new();
        let failed = finalize_replacement_local_state_with(
            &config,
            &state,
            &metadata,
            |path| {
                failed_calls.push(format!("remove {}", path.display()));
                Ok(())
            },
            || {
                Err(ProbeUpgraderRunError::Io(std::io::Error::other(
                    "ordinary cleanup verification failure",
                )))
            },
        );
        assert!(failed.is_err());
        assert_eq!(
            failed_calls,
            [
                format!("remove {}", config.display()),
                format!("remove {}", state.display()),
            ]
        );

        let mut completed_calls = Vec::new();
        finalize_replacement_local_state_with(
            &config,
            &state,
            &metadata,
            |path| {
                completed_calls.push(format!("remove {}", path.display()));
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(
            completed_calls,
            [
                format!("remove {}", config.display()),
                format!("remove {}", state.display()),
                format!("remove {}", metadata.display()),
            ]
        );
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

            if self.status_failure {
                return Err(ProbeUpgraderRunError::UninstallStatusReportFailure(
                    "temporary report failure".to_owned(),
                ));
            }

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

        fn verify_service_active(
            &mut self,
            service_name: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("verify-active {service_name}"));
            if self.failure_step == Some("verify-active") {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "service is not active".to_string(),
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
            if self
                .paths_required_during_identity_removal
                .iter()
                .any(|path| !path.exists())
            {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "lifecycle recovery assets disappeared too early".to_string(),
                ));
            }
            if self.failure_step == Some("remove-account") {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "service account removal failed".to_string(),
                ));
            }
            Ok(())
        }
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
    fn repair_acquirer_child_has_no_supplementary_groups_and_cannot_gain_privileges() {
        // The production parent is root. Keep this contract portable for non-root developer
        // environments while exercising the real pre-exec boundary in the root CI lane.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("/usr/bin/id -G; /usr/bin/awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status");
        configure_repair_acquirer_privileges(&mut command, uid, gid);

        let output = command.output().expect("spawn constrained child");
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut lines = stdout.lines();
        let groups = lines.next().unwrap().split_whitespace().collect::<Vec<_>>();
        assert!(!groups.is_empty());
        assert!(groups.iter().all(|group| *group == gid.to_string()));
        assert_eq!(lines.next(), Some("1"));
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
        let lifecycle_marker = parse_probe_repair_failure_marker(
            "operation_id = \"operation_41\"\ntarget_probe_version = \"0.2.0\"\nstatus = \"failed\"\nerror_code = \"lifecycle.upgrade_repair_required\"\n",
        )
        .expect("schema 5 post-activation marker authorizes Repair");
        assert_eq!(lifecycle_marker.target_probe_version, "0.2.0");

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
    fn reconstructed_probe_service_waits_for_hub_acknowledged_readiness_without_a_global_timeout() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("usr/local/bin/enoki-probe");
        let status_path = temp
            .path()
            .join("var/lib/enoki-probe/probe-operation-status.toml");
        let mut metadata = trusted_install_metadata(&install_path, &status_path, "a".repeat(64));
        metadata.identity_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
        metadata.service_unit_path = temp.path().join("etc/systemd/system/enoki-probe.service");

        write_probe_systemd_service(&metadata).expect("service unit renders");

        let unit = fs::read_to_string(&metadata.service_unit_path).expect("service unit exists");
        assert!(unit.contains("Type=notify"));
        assert!(unit.contains("NotifyAccess=main"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("RestartPreventExitStatus=78"));
        assert!(!unit.contains("TimeoutStartSec="));
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
        install_metadata.operation_sudoers_path = Some(operation_sudoers_path.clone());
        install_metadata.collector_helper_sudoers_path =
            Some(collector_helper_sudoers_path.clone());
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
                "verify-service-absent enoki-probe",
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
    fn schema_two_uninstall_keeps_preexisting_legacy_sudoers_untouched() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
        let install_metadata_path = temp.path().join("etc/enoki/probe-install.toml");
        let install_path = temp.path().join("usr/local/bin/enoki-probe");
        let state_dir = temp.path().join("var/lib/enoki-probe");
        let status_path = state_dir.join("probe-operation-status.toml");
        let service_unit_path = temp.path().join("etc/systemd/system/enoki-probe.service");
        let bootstrap_acquirer_path = temp
            .path()
            .join("usr/local/bin/enoki-probe-bootstrap-acquire");
        let bootstrap_activator_path = temp
            .path()
            .join("usr/local/bin/enoki-probe-bootstrap-activate");
        let bootstrap_state_dir = temp.path().join("var/lib/enoki-probe-bootstrap");
        let legacy_sudoers_path = temp.path().join("etc/sudoers.d/enoki-probe-upgrader");
        for path in [
            bootstrap_config_path.parent().expect("config parent"),
            install_metadata_path.parent().expect("metadata parent"),
            install_path.parent().expect("binary parent"),
            service_unit_path.parent().expect("unit parent"),
            legacy_sudoers_path.parent().expect("sudoers parent"),
            &state_dir,
            &bootstrap_state_dir,
        ] {
            fs::create_dir_all(path).expect("owned parent");
        }
        fs::write(&bootstrap_config_path, "owned bootstrap config").expect("config");
        fs::write(&install_metadata_path, "owned metadata").expect("metadata");
        fs::write(&install_path, "owned probe binary").expect("binary");
        fs::write(&service_unit_path, "owned service unit").expect("unit");
        fs::write(&bootstrap_acquirer_path, "owned Bootstrap acquirer").expect("acquirer");
        fs::write(&bootstrap_activator_path, "owned Bootstrap activator").expect("activator");
        fs::set_permissions(&bootstrap_acquirer_path, fs::Permissions::from_mode(0o755))
            .expect("acquirer mode");
        fs::set_permissions(&bootstrap_activator_path, fs::Permissions::from_mode(0o755))
            .expect("activator mode");
        fs::set_permissions(&bootstrap_state_dir, fs::Permissions::from_mode(0o700))
            .expect("Bootstrap state mode");
        let bootstrap_trust_dir = bootstrap_state_dir.join("trust");
        let bootstrap_inbox_dir = bootstrap_state_dir.join("inbox");
        fs::create_dir(&bootstrap_trust_dir).expect("Bootstrap trust directory");
        fs::create_dir(&bootstrap_inbox_dir).expect("Bootstrap inbox directory");
        fs::set_permissions(&bootstrap_trust_dir, fs::Permissions::from_mode(0o700))
            .expect("Bootstrap trust mode");
        fs::set_permissions(&bootstrap_inbox_dir, fs::Permissions::from_mode(0o700))
            .expect("Bootstrap inbox mode");
        for name in ["delegation-generation", ".delegation-generation.lock"] {
            let entry = bootstrap_trust_dir.join(name);
            fs::write(&entry, "owned Bootstrap state").expect("Bootstrap state entry");
            fs::set_permissions(&entry, fs::Permissions::from_mode(0o600))
                .expect("Bootstrap state entry mode");
        }
        fs::write(state_dir.join("state"), "owned state").expect("state");
        fs::write(&legacy_sudoers_path, "preexisting legacy sudoers").expect("legacy sudoers");
        fs::set_permissions(&legacy_sudoers_path, fs::Permissions::from_mode(0o440))
            .expect("legacy mode");
        let before_bytes = fs::read(&legacy_sudoers_path).expect("legacy bytes");
        let before_metadata = fs::metadata(&legacy_sudoers_path).expect("legacy metadata");

        let install_metadata = TrustedProbeInstallMetadata {
            schema_version: 2,
            hub_url: "https://hub.example".to_string(),
            identity_path: bootstrap_config_path.clone(),
            install_path: install_path.clone(),
            operation_status_path: status_path,
            probe_asset_public_key_sha256: "a".repeat(64),
            probe_distribution_root_sha256: Some("a".repeat(64)),
            bootstrap_acquirer_path: Some(bootstrap_acquirer_path.clone()),
            bootstrap_activator_path: Some(bootstrap_activator_path.clone()),
            bootstrap_state_dir: Some(bootstrap_state_dir.clone()),
            service_name: "enoki-probe".to_string(),
            service_group: "enoki-probe".to_string(),
            service_unit_path: service_unit_path.clone(),
            service_user: "enoki-probe".to_string(),
            state_dir: state_dir.clone(),
            operation_sudoers_path: None,
            collector_helper_sudoers_path: None,
            old_sudoers_paths: Vec::new(),
            observation_runtime_path: None,
            cpu_provider_path: None,
            disk_health_provider_path: None,
            lifecycle_companion_path: None,
            observation_unit_paths: Vec::new(),
            probe_ipc_group: None,
            probe_ipc_group_ownership: None,
            observation_ipc_group: None,
            install_state_sha256: None,
            target_manifest_sha256: None,
            bundle_version: None,
            lifecycle_authority_install_key: None,
        };
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
        };
        let mut systemd = RecordingSystemdRunner::default();

        execute_probe_uninstall_with_install_metadata_path(
            &input,
            &install_metadata,
            &mut systemd,
            &install_metadata_path,
        )
        .expect("schema two uninstall succeeds");

        let after_metadata = fs::metadata(&legacy_sudoers_path).expect("legacy remains");
        assert_eq!(
            fs::read(&legacy_sudoers_path).expect("legacy bytes"),
            before_bytes
        );
        assert_eq!(
            after_metadata.mode() & 0o777,
            before_metadata.mode() & 0o777
        );
        assert_eq!(after_metadata.ino(), before_metadata.ino());
        assert!(!install_path.exists());
        assert!(!bootstrap_config_path.exists());
        assert!(!install_metadata_path.exists());
        assert!(!service_unit_path.exists());
        assert!(!state_dir.exists());
        assert!(!bootstrap_acquirer_path.exists());
        assert!(!bootstrap_activator_path.exists());
        assert!(!bootstrap_state_dir.exists());
    }

    #[test]
    fn schema_three_uninstall_removes_every_fixed_observation_role() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let state_dir = root.join("var/lib/enoki-probe");
        let identity_path = state_dir.join("identity/probe-bootstrap.toml");
        let install_path = root.join("usr/local/bin/enoki-probe");
        let metadata_path = root.join("etc/enoki/probe-install.toml");
        let service_unit_path = root.join("etc/systemd/system/enoki-probe.service");
        let runtime_path = root.join("usr/local/bin/enoki-observation-runtime");
        let provider_path = root.join("usr/local/bin/enoki-cpu-resource-provider");
        let bootstrap_acquirer = root.join("usr/local/bin/enoki-probe-bootstrap-acquire");
        let bootstrap_activator = root.join("usr/local/bin/enoki-probe-bootstrap-activate");
        let bootstrap_state = root.join("var/lib/enoki-probe-bootstrap");
        let observation_units = [
            root.join("etc/systemd/system/enoki-observation-runtime.service"),
            root.join("etc/systemd/system/enoki-observation-runtime.socket"),
            root.join("etc/systemd/system/enoki-cpu-resource-provider@.service"),
            root.join("etc/systemd/system/enoki-cpu-resource-provider.socket"),
        ];
        for path in [
            identity_path.parent().unwrap(),
            install_path.parent().unwrap(),
            metadata_path.parent().unwrap(),
            service_unit_path.parent().unwrap(),
        ] {
            fs::create_dir_all(path).unwrap();
        }
        for path in [
            &identity_path,
            &install_path,
            &metadata_path,
            &service_unit_path,
            &runtime_path,
            &provider_path,
            &bootstrap_acquirer,
            &bootstrap_activator,
        ]
        .into_iter()
        .chain(observation_units.iter())
        {
            fs::write(path, "owned").unwrap();
        }
        for path in [&bootstrap_acquirer, &bootstrap_activator] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir_all(bootstrap_state.join("trust")).unwrap();
        fs::create_dir(bootstrap_state.join("inbox")).unwrap();
        for path in [
            &bootstrap_state,
            &bootstrap_state.join("trust"),
            &bootstrap_state.join("inbox"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for entry in ["delegation-generation", ".delegation-generation.lock"] {
            let path = bootstrap_state.join("trust").join(entry);
            fs::write(&path, "owned").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let metadata = TrustedProbeInstallMetadata {
            schema_version: 3,
            hub_url: "https://hub.example".into(),
            identity_path: identity_path.clone(),
            install_path: install_path.clone(),
            operation_status_path: state_dir.join("probe-operation-status.toml"),
            probe_asset_public_key_sha256: "a".repeat(64),
            probe_distribution_root_sha256: Some("a".repeat(64)),
            bootstrap_acquirer_path: Some(bootstrap_acquirer),
            bootstrap_activator_path: Some(bootstrap_activator),
            bootstrap_state_dir: Some(bootstrap_state),
            service_name: "enoki-probe".into(),
            service_group: "enoki-probe".into(),
            service_unit_path: service_unit_path.clone(),
            service_user: "enoki-probe".into(),
            state_dir,
            operation_sudoers_path: None,
            collector_helper_sudoers_path: None,
            old_sudoers_paths: Vec::new(),
            observation_runtime_path: Some(runtime_path.clone()),
            cpu_provider_path: Some(provider_path.clone()),
            disk_health_provider_path: None,
            lifecycle_companion_path: None,
            observation_unit_paths: observation_units.to_vec(),
            probe_ipc_group: None,
            probe_ipc_group_ownership: None,
            observation_ipc_group: Some(OBSERVATION_IPC_GROUP.to_string()),
            install_state_sha256: None,
            target_manifest_sha256: None,
            bundle_version: None,
            lifecycle_authority_install_key: None,
        };
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: identity_path,
        };
        let mut systemd = RecordingSystemdRunner::default();

        execute_probe_uninstall_with_install_metadata_path(
            &input,
            &metadata,
            &mut systemd,
            &metadata_path,
        )
        .unwrap();

        for path in [install_path, runtime_path, provider_path, service_unit_path]
            .into_iter()
            .chain(observation_units)
        {
            assert!(!path.exists(), "{} remains", path.display());
        }
        for service in OBSERVATION_SERVICES_SCHEMA_THREE {
            assert!(systemd.calls.contains(&format!("stop {service}")));
            assert!(systemd.calls.contains(&format!("disable {service}")));
        }
        assert!(systemd.calls.iter().all(|call| !call.contains("@.service")));
        assert_eq!(
            systemd.calls.first().map(String::as_str),
            Some("stop enoki-disk-health-resource-provider.socket")
        );
        assert!(systemd.calls.contains(&format!(
            "remove-service-identity {OBSERVATION_IPC_GROUP}:{OBSERVATION_IPC_GROUP}"
        )));
    }

    #[test]
    fn schema_four_uninstall_removes_the_companion_and_complete_fixed_layout() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let state_dir = root.join("var/lib/enoki-probe");
        let identity_path = state_dir.join("identity/probe-bootstrap.toml");
        let metadata_path = root.join("etc/enoki/probe-install.toml");
        let binaries = [
            root.join("usr/local/bin/enoki-probe"),
            root.join("usr/local/bin/enoki-observation-runtime"),
            root.join("usr/local/bin/enoki-cpu-resource-provider"),
            root.join("usr/local/bin/enoki-disk-health-resource-provider"),
            root.join("usr/local/bin/enoki-probe-lifecycle-companion"),
        ];
        let units = [
            root.join("etc/systemd/system/enoki-probe.service"),
            root.join("etc/systemd/system/enoki-observation-runtime.service"),
            root.join("etc/systemd/system/enoki-observation-runtime.socket"),
            root.join("etc/systemd/system/enoki-cpu-resource-provider@.service"),
            root.join("etc/systemd/system/enoki-cpu-resource-provider.socket"),
            root.join("etc/systemd/system/enoki-disk-health-resource-provider@.service"),
            root.join("etc/systemd/system/enoki-disk-health-resource-provider.socket"),
            root.join("etc/systemd/system/enoki-probe-lifecycle-companion@.service"),
            root.join("etc/systemd/system/enoki-probe-lifecycle-companion.socket"),
        ];
        let bootstrap_roles = [
            root.join("usr/local/bin/enoki-probe-bootstrap-acquire"),
            root.join("usr/local/bin/enoki-probe-bootstrap-activate"),
        ];
        let bootstrap_state = root.join("var/lib/enoki-probe-bootstrap");
        for parent in [
            identity_path.parent().unwrap(),
            metadata_path.parent().unwrap(),
            binaries[0].parent().unwrap(),
            units[0].parent().unwrap(),
        ] {
            fs::create_dir_all(parent).unwrap();
        }
        for path in binaries
            .iter()
            .chain(units.iter())
            .chain(bootstrap_roles.iter())
            .chain([&identity_path, &metadata_path])
        {
            fs::write(path, "owned").unwrap();
        }
        for path in &bootstrap_roles {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir_all(bootstrap_state.join("trust")).unwrap();
        fs::create_dir(bootstrap_state.join("inbox")).unwrap();
        for path in [
            &bootstrap_state,
            &bootstrap_state.join("trust"),
            &bootstrap_state.join("inbox"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for entry in ["delegation-generation", ".delegation-generation.lock"] {
            let path = bootstrap_state.join("trust").join(entry);
            fs::write(&path, "owned").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let metadata = TrustedProbeInstallMetadata {
            schema_version: 4,
            hub_url: "https://hub.example".into(),
            identity_path: identity_path.clone(),
            install_path: binaries[0].clone(),
            operation_status_path: state_dir.join("probe-operation-status.toml"),
            probe_asset_public_key_sha256: "a".repeat(64),
            probe_distribution_root_sha256: Some("a".repeat(64)),
            bootstrap_acquirer_path: Some(bootstrap_roles[0].clone()),
            bootstrap_activator_path: Some(bootstrap_roles[1].clone()),
            bootstrap_state_dir: Some(bootstrap_state),
            service_name: "enoki-probe".into(),
            service_group: "enoki-probe".into(),
            service_unit_path: units[0].clone(),
            service_user: "enoki-probe".into(),
            state_dir,
            operation_sudoers_path: None,
            collector_helper_sudoers_path: None,
            old_sudoers_paths: Vec::new(),
            observation_runtime_path: Some(binaries[1].clone()),
            cpu_provider_path: Some(binaries[2].clone()),
            disk_health_provider_path: Some(binaries[3].clone()),
            lifecycle_companion_path: Some(binaries[4].clone()),
            observation_unit_paths: units[1..].to_vec(),
            probe_ipc_group: Some(PROBE_IPC_GROUP.to_owned()),
            probe_ipc_group_ownership: Some(format!("!enoki-bootstrap-{}", "d".repeat(32))),
            observation_ipc_group: Some(OBSERVATION_IPC_GROUP.to_owned()),
            install_state_sha256: Some("b".repeat(64)),
            target_manifest_sha256: Some("c".repeat(64)),
            bundle_version: Some("1.2.3".to_owned()),
            lifecycle_authority_install_key: None,
        };
        let mut systemd = RecordingSystemdRunner {
            paths_required_during_identity_removal: vec![
                binaries[4].clone(),
                units[7].clone(),
                units[8].clone(),
                metadata_path.clone(),
            ],
            ..RecordingSystemdRunner::default()
        };
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: identity_path.clone(),
        };
        let plan = plan_probe_uninstall_cleanup(&input, &metadata, &metadata_path, false)
            .expect("schema four cleanup plan");
        execute_probe_uninstall_cleanup(&plan, &mut systemd, UninstallCleanupExtent::Prepare)
            .expect("pre-ack cleanup succeeds");
        for path in [
            identity_path.as_path(),
            metadata_path.as_path(),
            binaries[4].as_path(),
            units[7].as_path(),
            units[8].as_path(),
        ] {
            assert!(
                path.exists(),
                "pre-ack recovery entry lost: {}",
                path.display()
            );
        }
        execute_probe_uninstall_cleanup(&plan, &mut systemd, UninstallCleanupExtent::Complete)
            .expect("schema four uninstall succeeds");

        for path in binaries.into_iter().chain(units) {
            assert!(!path.exists(), "{} remains", path.display());
        }
        for service in OBSERVATION_SERVICES_SCHEMA_FOUR {
            assert!(systemd.calls.contains(&format!("stop {service}")));
            assert!(systemd.calls.contains(&format!("disable {service}")));
        }
        let identity_removed = systemd
            .calls
            .iter()
            .position(|call| call == "remove-service-identity enoki-probe:enoki-probe")
            .expect("service identity cleanup");
        let companion_stopped = systemd
            .calls
            .iter()
            .position(|call| call == "stop enoki-probe-lifecycle-companion.socket")
            .expect("companion socket cleanup");
        assert!(identity_removed < companion_stopped);
        assert!(systemd.calls.contains(&format!(
            "remove-service-identity {PROBE_IPC_GROUP}:{PROBE_IPC_GROUP}"
        )));
        assert!(
            systemd
                .calls
                .iter()
                .all(|call| !call.contains("lifecycle-companion@"))
        );
    }

    #[test]
    fn hub_uninstall_report_failure_keeps_exact_reentry_until_acknowledged_cleanup() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path();
        let state_dir = root.join("var/lib/enoki-probe");
        let identity_path = state_dir.join("identity/probe-bootstrap.toml");
        let metadata_path = root.join("etc/enoki/probe-install.toml");
        let install_path = root.join("usr/local/bin/enoki-probe");
        let service_unit_path = root.join("etc/systemd/system/enoki-probe.service");
        let companion_path = root.join("usr/local/bin/enoki-probe-lifecycle-companion");
        let companion_service =
            root.join("etc/systemd/system/enoki-probe-lifecycle-companion@.service");
        let companion_socket =
            root.join("etc/systemd/system/enoki-probe-lifecycle-companion.socket");
        let bootstrap_acquirer = root.join("usr/local/bin/enoki-probe-bootstrap-acquire");
        let bootstrap_activator = root.join("usr/local/bin/enoki-probe-bootstrap-activate");
        let bootstrap_state = root.join("var/lib/enoki-probe-bootstrap");
        for parent in [
            identity_path.parent().expect("identity parent"),
            metadata_path.parent().expect("metadata parent"),
            install_path.parent().expect("binary parent"),
            service_unit_path.parent().expect("unit parent"),
        ] {
            fs::create_dir_all(parent).expect("fixture directory");
        }
        for path in [
            &metadata_path,
            &install_path,
            &service_unit_path,
            &companion_path,
            &companion_service,
            &companion_socket,
            &bootstrap_acquirer,
            &bootstrap_activator,
        ] {
            fs::write(path, "owned").expect("fixture file");
        }
        for path in [&bootstrap_acquirer, &bootstrap_activator] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .expect("Bootstrap role mode");
        }
        fs::create_dir_all(bootstrap_state.join("trust")).expect("trust state");
        fs::create_dir(bootstrap_state.join("inbox")).expect("inbox state");
        for path in [
            &bootstrap_state,
            &bootstrap_state.join("trust"),
            &bootstrap_state.join("inbox"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("Bootstrap state mode");
        }
        for entry in ["delegation-generation", ".delegation-generation.lock"] {
            let path = bootstrap_state.join("trust").join(entry);
            fs::write(&path, "owned").expect("trust entry");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("trust entry mode");
        }
        let metadata = TrustedProbeInstallMetadata {
            schema_version: 4,
            hub_url: "https://hub.example".to_owned(),
            identity_path: identity_path.clone(),
            install_path: install_path.clone(),
            operation_status_path: state_dir.join("probe-operation-status.toml"),
            probe_asset_public_key_sha256: "a".repeat(64),
            probe_distribution_root_sha256: Some("a".repeat(64)),
            bootstrap_acquirer_path: Some(bootstrap_acquirer),
            bootstrap_activator_path: Some(bootstrap_activator),
            bootstrap_state_dir: Some(bootstrap_state),
            service_name: "enoki-probe".to_owned(),
            service_group: "enoki-probe".to_owned(),
            service_unit_path,
            service_user: "enoki-probe".to_owned(),
            state_dir: state_dir.clone(),
            operation_sudoers_path: None,
            collector_helper_sudoers_path: None,
            old_sudoers_paths: Vec::new(),
            observation_runtime_path: None,
            cpu_provider_path: None,
            disk_health_provider_path: None,
            lifecycle_companion_path: Some(companion_path.clone()),
            observation_unit_paths: vec![companion_service.clone(), companion_socket.clone()],
            probe_ipc_group: Some(PROBE_IPC_GROUP.to_owned()),
            probe_ipc_group_ownership: Some(format!("!enoki-bootstrap-{}", "d".repeat(32))),
            observation_ipc_group: Some(OBSERVATION_IPC_GROUP.to_owned()),
            install_state_sha256: Some("b".repeat(64)),
            target_manifest_sha256: Some("c".repeat(64)),
            bundle_version: Some("1.2.3".to_owned()),
            lifecycle_authority_install_key: None,
        };
        write_test_bootstrap_config(&identity_path, &metadata).expect("identity config");
        let request = LifecycleRequest::hub_uninstall(
            "probe_01",
            "operation_42",
            "operation-token",
            &"b".repeat(64),
            &"c".repeat(64),
            "1.2.3",
        )
        .expect("bound uninstall request");
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: identity_path.clone(),
        };
        let mut systemd = RecordingSystemdRunner::default();
        let mut failed_transport = RecordingValidationTransport {
            status_failure: true,
            ..RecordingValidationTransport::default()
        };

        let first = execute_lifecycle_uninstall(
            &request,
            &input,
            &metadata,
            &metadata_path,
            &mut failed_transport,
            &mut systemd,
        );
        assert!(matches!(
            first,
            Err(ProbeUpgraderRunError::UninstallStatusReportFailure(_))
        ));
        let capsule_path = uninstall_capsule_path(&metadata_path).expect("capsule path");
        let prepared_capsule = read_uninstall_capsule(&capsule_path)
            .expect("read capsule")
            .expect("prepared capsule");
        assert_eq!(prepared_capsule.phase, UninstallCapsulePhase::Prepared);
        assert_eq!(
            LifecycleRequest::decode(prepared_capsule.request_json.as_bytes())
                .expect("capsule request"),
            request,
        );
        for path in [
            identity_path.as_path(),
            metadata_path.as_path(),
            companion_path.as_path(),
            companion_service.as_path(),
            companion_socket.as_path(),
        ] {
            assert!(path.exists(), "reentry asset lost: {}", path.display());
        }

        let mut retry_transport = RecordingValidationTransport::default();
        systemd.failure_step = Some("remove-account");
        let completed = execute_lifecycle_uninstall(
            &request,
            &input,
            &metadata,
            &metadata_path,
            &mut retry_transport,
            &mut systemd,
        )
        .expect("Hub acknowledgement stays terminal when finalization pauses");
        assert_eq!(completed, ResumeDecision::RecoveryPending);
        assert!(
            retry_transport.url.is_empty(),
            "trusted capsule skips revalidation"
        );
        assert!(
            retry_transport
                .status_body
                .contains("\"status\":\"succeeded\"")
        );
        assert_eq!(
            read_uninstall_capsule(&capsule_path)
                .expect("read acknowledged capsule")
                .expect("acknowledged capsule")
                .phase,
            UninstallCapsulePhase::TerminalAcknowledged,
        );
        assert!(metadata_path.exists());
        assert!(identity_path.exists());
        assert!(companion_path.exists());

        let recovery_plan = plan_probe_uninstall_cleanup(&input, &metadata, &metadata_path, true)
            .expect("recovery cleanup plan");
        let mut final_state_calls = Vec::new();
        let final_state_error = remove_uninstall_local_state_with(&recovery_plan, |path| {
            final_state_calls.push(path.to_path_buf());
            if path == metadata.state_dir {
                return Err(ProbeUpgraderRunError::Io(std::io::Error::other(
                    "injected ordinary state cleanup failure",
                )));
            }
            Ok(())
        });
        assert!(final_state_error.is_err());
        assert_eq!(
            final_state_calls,
            [
                metadata_path.clone(),
                identity_path.clone(),
                metadata.state_dir.clone(),
            ]
        );
        assert!(capsule_path.exists(), "commit capsule remains recoverable");
        assert!(
            companion_path.exists(),
            "fixed resume entry remains recoverable"
        );

        drop(request);
        drop(input);
        drop(metadata);
        drop(retry_transport);
        drop(systemd);
        let child = Command::new(std::env::current_exe().expect("current test process"))
            .args([
                "--exact",
                "upgrader::tests::lifecycle_resume_child_process",
                "--nocapture",
            ])
            .env("ENOKI_TEST_RESUME_METADATA", &metadata_path)
            .env("ENOKI_TEST_RESUME_STATE", &state_dir)
            .env("ENOKI_TEST_RESUME_BINARY", &companion_path)
            .status()
            .expect("start a fresh Companion recovery process");
        assert!(child.success(), "fresh recovery process failed");
        assert!(!capsule_path.exists());
        assert!(!metadata_path.exists());
        assert!(!identity_path.exists());
        assert!(!companion_path.exists());
    }

    #[test]
    fn lifecycle_resume_child_process() {
        let Ok(metadata_path) = std::env::var("ENOKI_TEST_RESUME_METADATA") else {
            return;
        };
        let binary_path =
            std::env::var("ENOKI_TEST_RESUME_BINARY").expect("fixed test recovery binary");
        let state_path =
            std::env::var("ENOKI_TEST_RESUME_STATE").expect("fixed test install state");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();
        let completed = resume_lifecycle_companion_at(
            Path::new(&metadata_path),
            Path::new(&state_path),
            Path::new(&binary_path),
            &mut transport,
            &mut systemd,
        )
        .expect("resume only from the persisted capsule");
        assert_eq!(completed, ResumeDecision::Completed);
        assert!(transport.url.is_empty());
        assert!(transport.status_url.is_empty());
        remove_path_if_exists(Path::new(&binary_path))
            .expect("fresh Companion process performs its final self-unlink");
    }

    #[test]
    fn lifecycle_commit_deletes_only_the_capsule_before_process_self_finalization() {
        let capsule = Path::new("/etc/enoki/probe-uninstall.capsule");
        let mut calls = Vec::new();
        let result = commit_lifecycle_capsule_with(capsule, |path| {
            calls.push(path.to_path_buf());
            Err(ProbeUpgraderRunError::Io(std::io::Error::other(
                "injected ordinary transaction failure",
            )))
        });
        assert!(result.is_err());
        assert_eq!(calls, [capsule]);
    }

    #[test]
    fn post_commit_self_finalize_policy_uses_explicit_trusted_facts() {
        let trusted = PostCommitSelfFinalizeFacts {
            install_metadata_absent: true,
            install_state_absent: true,
            companion_binary: CompanionBinaryFacts {
                regular_file: true,
                link_count: 1,
                owner_uid: 0,
                mode: 0o755,
            },
        };
        assert_eq!(
            post_commit_self_finalize_policy(trusted),
            Ok(ResumeDecision::Completed)
        );

        for rejected in [
            PostCommitSelfFinalizeFacts {
                install_metadata_absent: false,
                ..trusted
            },
            PostCommitSelfFinalizeFacts {
                install_state_absent: false,
                ..trusted
            },
            PostCommitSelfFinalizeFacts {
                companion_binary: CompanionBinaryFacts {
                    owner_uid: 1000,
                    ..trusted.companion_binary
                },
                ..trusted
            },
            PostCommitSelfFinalizeFacts {
                companion_binary: CompanionBinaryFacts {
                    mode: 0o775,
                    ..trusted.companion_binary
                },
                ..trusted
            },
        ] {
            assert_eq!(post_commit_self_finalize_policy(rejected), Err(()));
        }
    }

    #[test]
    fn resume_decision_maps_to_the_wire_response_at_one_boundary() {
        assert_eq!(
            lifecycle_response_from_resume_decision(Ok(ResumeDecision::Completed)),
            LifecycleResponse::succeeded()
        );
        assert_eq!(
            lifecycle_response_from_resume_decision(Ok(ResumeDecision::RecoveryPending)),
            LifecycleResponse::recovery_pending()
        );
    }

    #[test]
    fn empty_resume_rejects_a_healthy_install_without_self_finalizing() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let metadata = temporary.path().join("etc/enoki/probe-install.toml");
        let state = temporary.path().join("var/lib/enoki-probe");
        let binary = temporary
            .path()
            .join("usr/local/bin/enoki-probe-lifecycle-companion");
        for parent in [
            metadata.parent().unwrap(),
            state.as_path(),
            binary.parent().unwrap(),
        ] {
            fs::create_dir_all(parent).expect("fixture directory");
        }
        fs::write(&metadata, "healthy install metadata").expect("metadata");
        fs::write(&binary, "companion").expect("companion binary");
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let error =
            resume_lifecycle_companion_at(&metadata, &state, &binary, &mut transport, &mut systemd)
                .expect_err("healthy install is not post-commit recovery");
        assert_eq!(error.code(), "probe_uninstall_metadata_invalid");
        assert!(binary.exists());
        assert!(transport.url.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn schema_two_uninstall_rejects_a_bootstrap_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().expect("temp dir");
        let target = temp.path().join("outside-bootstrap");
        let acquirer = temp.path().join("bootstrap-acquire");
        let activator = temp.path().join("bootstrap-activate");
        fs::write(&target, "outside").expect("target");
        symlink(&target, &acquirer).expect("symlink");
        fs::write(&activator, "owned activator").expect("activator");
        fs::set_permissions(&activator, fs::Permissions::from_mode(0o755)).expect("activator mode");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&state_dir).expect("state");
        let bootstrap_state_dir = temp.path().join("bootstrap-state");
        fs::create_dir(&bootstrap_state_dir).expect("Bootstrap state");
        fs::set_permissions(&bootstrap_state_dir, fs::Permissions::from_mode(0o700))
            .expect("Bootstrap state mode");
        let metadata = TrustedProbeInstallMetadata {
            schema_version: 2,
            hub_url: "https://hub.example".to_string(),
            identity_path: temp.path().join("identity"),
            install_path: temp.path().join("probe"),
            operation_status_path: state_dir.join("status"),
            probe_asset_public_key_sha256: "a".repeat(64),
            probe_distribution_root_sha256: Some("a".repeat(64)),
            bootstrap_acquirer_path: Some(acquirer.clone()),
            bootstrap_activator_path: Some(activator.clone()),
            bootstrap_state_dir: Some(bootstrap_state_dir),
            service_name: "enoki-probe".to_string(),
            service_group: "enoki-probe".to_string(),
            service_unit_path: temp.path().join("unit"),
            service_user: "enoki-probe".to_string(),
            state_dir,
            operation_sudoers_path: None,
            collector_helper_sudoers_path: None,
            old_sudoers_paths: Vec::new(),
            observation_runtime_path: None,
            cpu_provider_path: None,
            disk_health_provider_path: None,
            lifecycle_companion_path: None,
            observation_unit_paths: Vec::new(),
            probe_ipc_group: None,
            probe_ipc_group_ownership: None,
            observation_ipc_group: None,
            install_state_sha256: None,
            target_manifest_sha256: None,
            bundle_version: None,
            lifecycle_authority_install_key: None,
        };
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let mut systemd = RecordingSystemdRunner::default();
        let error = execute_probe_uninstall_with_install_metadata_path(
            &input,
            &metadata,
            &mut systemd,
            &temp.path().join("metadata"),
        )
        .expect_err("symlinked Bootstrap role fails closed");
        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "Probe Bootstrap role is not a root-owned regular 0755 file"
            )
        ));
        assert_eq!(fs::read(&target).expect("outside target"), b"outside");
        assert!(systemd.calls.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_state_validation_rejects_symlinks_hardlinks_and_extra_entries() {
        use std::os::unix::fs::symlink;

        fn private_directory(path: &Path) {
            fs::create_dir(path).expect("private directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private directory mode");
        }
        fn owned_state(root: &Path) -> PathBuf {
            let state = root.join("bootstrap-state");
            private_directory(&state);
            private_directory(&state.join("trust"));
            private_directory(&state.join("inbox"));
            state
        }

        let symlink_temp = tempfile::tempdir().expect("symlink temp");
        let symlink_state = owned_state(symlink_temp.path());
        fs::remove_dir(symlink_state.join("inbox")).expect("remove inbox");
        let outside = symlink_temp.path().join("outside");
        private_directory(&outside);
        symlink(&outside, symlink_state.join("inbox")).expect("unsafe inbox symlink");
        assert!(matches!(
            validate_owned_bootstrap_state(Some(&symlink_state)),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
        assert!(outside.exists());

        let hardlink_temp = tempfile::tempdir().expect("hardlink temp");
        let hardlink_state = owned_state(hardlink_temp.path());
        let outside = hardlink_temp.path().join("outside-generation");
        fs::write(&outside, "outside").expect("outside state");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).expect("outside mode");
        fs::hard_link(&outside, hardlink_state.join("trust/delegation-generation"))
            .expect("unsafe hardlink");
        assert!(matches!(
            validate_owned_bootstrap_state(Some(&hardlink_state)),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
        assert_eq!(fs::read(&outside).expect("outside remains"), b"outside");

        let extra_temp = tempfile::tempdir().expect("extra entry temp");
        let extra_state = owned_state(extra_temp.path());
        fs::write(extra_state.join("unrecognised"), "extra").expect("extra entry");
        assert!(matches!(
            validate_owned_bootstrap_state(Some(&extra_state)),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
        assert!(extra_state.join("unrecognised").exists());
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
            "{\"errorCode\":\"probe_uninstall_service_disable_failed\",\"message\":\"Probe uninstall failed.\",\"status\":\"failed\",\"token\":\"probe-operation-token\"}"
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
    fn lifecycle_ipc_group_cleanup_requires_and_consumes_the_install_receipt() {
        let marker = format!("!enoki-bootstrap-{}", "d".repeat(32));
        let mut calls = Vec::new();
        remove_owned_ipc_group_with(PROBE_IPC_GROUP, &marker, &mut |program, arguments| {
            calls.push(format!("{program} {}", arguments.join(" ")));
            Ok(match (program, arguments) {
                ("getent", ["gshadow", PROBE_IPC_GROUP]) => {
                    CleanupCommandOutput::success(&format!("{PROBE_IPC_GROUP}:{marker}::\n"))
                }
                ("getent", ["group", PROBE_IPC_GROUP]) if calls.len() == 2 => {
                    CleanupCommandOutput::success("enoki-probe-ipc:x:998:\n")
                }
                ("groupdel", [PROBE_IPC_GROUP]) => CleanupCommandOutput::success(""),
                ("getent", ["group", PROBE_IPC_GROUP]) => {
                    CleanupCommandOutput::failure(Some(2), "", "")
                }
                _ => panic!("unexpected cleanup command"),
            })
        })
        .expect("owned lifecycle IPC group is removed");

        assert_eq!(
            calls,
            [
                "getent gshadow enoki-probe-ipc",
                "getent group enoki-probe-ipc",
                "groupdel enoki-probe-ipc",
                "getent group enoki-probe-ipc",
            ]
        );
    }

    #[test]
    fn lifecycle_ipc_group_cleanup_keeps_a_group_without_the_install_receipt() {
        let marker = format!("!enoki-bootstrap-{}", "d".repeat(32));
        let mut calls = Vec::new();
        let error =
            remove_owned_ipc_group_with(PROBE_IPC_GROUP, &marker, &mut |program, arguments| {
                calls.push(format!("{program} {}", arguments.join(" ")));
                Ok(CleanupCommandOutput::success(
                    "enoki-probe-ipc:!enoki-bootstrap-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee::\n",
                ))
            })
            .expect_err("unowned lifecycle IPC group remains untouched");

        assert_eq!(
            probe_upgrader_error_code(&error),
            "probe_uninstall_service_group_residue"
        );
        assert_eq!(calls, ["getent gshadow enoki-probe-ipc"]);
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
        install_metadata.operation_sudoers_path = Some(operation_sudoers_path.clone());
        install_metadata.collector_helper_sudoers_path =
            Some(collector_helper_sudoers_path.clone());
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
                "verify-service-absent enoki-probe",
            ],
        );
    }

    #[test]
    fn uninstall_cleanup_planner_rejects_unsafe_targets_before_any_systemd_or_file_mutation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let mut install_metadata = trusted_install_metadata(
            &temp.path().join("bin/enoki-probe"),
            &status_path,
            assets_public_key_sha256(),
        );
        install_metadata.install_path = PathBuf::from("relative-probe-binary");

        let error = plan_probe_uninstall_cleanup(
            &ProbeUninstallerRunInput {
                bootstrap_config_path: temp.path().join("state/probe-bootstrap.toml"),
            },
            &install_metadata,
            &temp.path().join("etc/enoki/probe-install.toml"),
            false,
        )
        .expect_err("unsafe cleanup targets are rejected before execution");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata("paths must be absolute")
        ));
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
    fn trusted_install_metadata_rejects_parent_components_before_cleanup_can_start() {
        let value = "path = \"/var/lib/enoki-probe/../outside\""
            .parse::<toml::Value>()
            .expect("metadata value");

        let error = required_install_metadata_path(&value, "path")
            .expect_err("parent traversal cannot become a cleanup target");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata("paths contain unsafe components")
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
            Some(operation_sudoers_path)
        );
        assert_eq!(
            install_metadata.collector_helper_sudoers_path,
            Some(collector_helper_sudoers_path)
        );
        assert_ne!(
            install_metadata.operation_sudoers_path,
            Some(legacy_sudoers_path)
        );
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
    fn legacy_install_metadata_preflight_keeps_bytes_mode_and_mtime_unchanged() {
        let temp = tempfile::tempdir().expect("temp dir");
        let (contents, _, _, _) = fresh_split_install_metadata_contents(temp.path());
        let metadata_path = temp.path().join("etc/enoki/probe-install.toml");
        let identity_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
        fs::create_dir_all(metadata_path.parent().expect("metadata dir")).expect("metadata dir");
        fs::write(&metadata_path, &contents).expect("legacy metadata");
        fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o644))
            .expect("legacy permissions");

        let mut metadata =
            parse_trusted_probe_install_metadata(&contents).expect("legacy metadata");
        metadata.identity_path = identity_path.clone();
        write_test_bootstrap_config(&identity_path, &metadata).expect("identity");
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
            .expect("identity permissions");

        let before_bytes = fs::read(&metadata_path).expect("metadata bytes");
        let before_metadata = fs::metadata(&metadata_path).expect("metadata stat");
        let before_mode = before_metadata.permissions().mode() & 0o777;
        let before_mtime = (before_metadata.mtime(), before_metadata.mtime_nsec());

        let preflight = read_trusted_probe_install_preflight(&metadata_path, Some(temp.path()))
            .expect("legacy preflight");

        assert_eq!(preflight.hub_url, "https://hub.example");
        assert_eq!(preflight.probe_id, "probe_01");
        let after_metadata = fs::metadata(&metadata_path).expect("metadata stat");
        assert_eq!(
            fs::read(&metadata_path).expect("metadata bytes"),
            before_bytes
        );
        assert_eq!(after_metadata.permissions().mode() & 0o777, before_mode);
        assert_eq!(
            (after_metadata.mtime(), after_metadata.mtime_nsec()),
            before_mtime
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
            "schema_version = 6",
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
    fn schema_four_metadata_closes_over_lifecycle_receipts_and_fixed_role_inventory() {
        let contents = [
            "schema_version = 4".to_owned(),
            "hub_url = \"https://hub.example\"".to_owned(),
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"".to_owned(),
            "install_path = \"/usr/local/bin/enoki-probe\"".to_owned(),
            format!("observation_runtime_path = \"{OBSERVATION_RUNTIME_BINARY_PATH}\""),
            format!("cpu_provider_path = \"{CPU_PROVIDER_BINARY_PATH}\""),
            format!("disk_health_provider_path = \"{DISK_HEALTH_PROVIDER_BINARY_PATH}\""),
            format!("lifecycle_companion_path = \"{LIFECYCLE_COMPANION_BINARY_PATH}\""),
            format!("probe_ipc_group = \"{PROBE_IPC_GROUP}\""),
            format!(
                "probe_ipc_group_ownership = \"!enoki-bootstrap-{}\"",
                "d".repeat(32)
            ),
            format!("observation_ipc_group = \"{OBSERVATION_IPC_GROUP}\""),
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"".to_owned(),
            "state_dir = \"/var/lib/enoki-probe\"".to_owned(),
            format!("probe_distribution_root_sha256 = \"{}\"", "a".repeat(64)),
            format!("install_state_sha256 = \"{}\"", "b".repeat(64)),
            format!("target_manifest_sha256 = \"{}\"", "c".repeat(64)),
            "bundle_version = \"1.2.3\"".to_owned(),
            format!("bootstrap_acquirer_path = \"{PRODUCTION_BOOTSTRAP_ACQUIRER_PATH}\""),
            format!("bootstrap_activator_path = \"{PRODUCTION_BOOTSTRAP_ACTIVATOR_PATH}\""),
            format!("bootstrap_state_dir = \"{PRODUCTION_BOOTSTRAP_STATE_DIR}\""),
            "service_name = \"enoki-probe\"".to_owned(),
            "service_user = \"enoki-probe\"".to_owned(),
            "service_group = \"enoki-probe\"".to_owned(),
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"".to_owned(),
            format!("observation_runtime_service_unit_path = \"{OBSERVATION_RUNTIME_SERVICE_UNIT_PATH}\""),
            format!("observation_runtime_socket_unit_path = \"{OBSERVATION_RUNTIME_SOCKET_UNIT_PATH}\""),
            format!("cpu_provider_service_unit_path = \"{CPU_PROVIDER_SERVICE_UNIT_PATH}\""),
            format!("cpu_provider_socket_unit_path = \"{CPU_PROVIDER_SOCKET_UNIT_PATH}\""),
            format!("disk_health_provider_service_unit_path = \"{DISK_HEALTH_PROVIDER_SERVICE_UNIT_PATH}\""),
            format!("disk_health_provider_socket_unit_path = \"{DISK_HEALTH_PROVIDER_SOCKET_UNIT_PATH}\""),
            format!("lifecycle_companion_service_unit_path = \"{LIFECYCLE_COMPANION_SERVICE_UNIT_PATH}\""),
            format!("lifecycle_companion_socket_unit_path = \"{LIFECYCLE_COMPANION_SOCKET_UNIT_PATH}\""),
            format!("collector_helper_sudoers_path = \"{PRODUCTION_COLLECTOR_HELPER_SUDOERS_PATH}\""),
        ]
        .join("\n");

        let metadata = parse_trusted_probe_install_metadata(&contents)
            .expect("schema four metadata is accepted");

        assert_eq!(metadata.schema_version, 4);
        assert_eq!(
            metadata.lifecycle_companion_path.as_deref(),
            Some(Path::new(LIFECYCLE_COMPANION_BINARY_PATH))
        );
        assert_eq!(metadata.observation_unit_paths.len(), 8);
        assert_eq!(metadata.install_state_sha256, Some("b".repeat(64)));
        assert_eq!(metadata.probe_ipc_group.as_deref(), Some(PROBE_IPC_GROUP));

        let schema_five = contents
            .replace("schema_version = 4", "schema_version = 5")
            .replace(
                &format!(
                    "lifecycle_companion_socket_unit_path = \"{LIFECYCLE_COMPANION_SOCKET_UNIT_PATH}\""
                ),
                &format!(
                    "lifecycle_companion_socket_unit_path = \"{LIFECYCLE_COMPANION_SOCKET_UNIT_PATH}\"\nlifecycle_upgrade_service_unit_path = \"{LIFECYCLE_UPGRADE_SERVICE_UNIT_PATH}\"\nlifecycle_upgrade_socket_unit_path = \"{LIFECYCLE_UPGRADE_SOCKET_UNIT_PATH}\""
                ),
            );
        let schema_five = format!(
            "{schema_five}\nlifecycle_authority_install_key = {:?}\n",
            "a".repeat(64),
        );
        let metadata = parse_trusted_probe_install_metadata(&schema_five)
            .expect("schema five metadata closes over the Upgrade Companion units");
        assert_eq!(metadata.schema_version, 5);
        assert_eq!(metadata.observation_unit_paths.len(), 10);
    }

    #[test]
    fn schema_three_and_four_metadata_fix_the_installed_probe_path() {
        for schema_version in [3, 4, 5] {
            let contents = schema_three_install_metadata_contents()
                .replace(
                    "schema_version = 3",
                    &format!("schema_version = {schema_version}"),
                )
                .replace(
                    "install_path = \"/usr/local/bin/enoki-probe\"",
                    "install_path = \"/opt/enoki-probe\"",
                );

            let error = parse_trusted_probe_install_metadata(&contents)
                .expect_err("signed install metadata cannot redirect the Probe binary");

            assert!(matches!(
                error,
                ProbeUpgraderRunError::InvalidInstallMetadata(
                    "install_path does not match the fixed production path"
                )
            ));
        }
    }

    #[test]
    fn signed_package_metadata_uses_root_trust_without_legacy_sudoers_or_daily_key() {
        let root = "a".repeat(64);
        let contents = [
            "schema_version = 2".to_string(),
            "hub_url = \"https://hub.example\"".to_string(),
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"".to_string(),
            "install_path = \"/usr/local/bin/enoki-probe\"".to_string(),
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\""
                .to_string(),
            "state_dir = \"/var/lib/enoki-probe\"".to_string(),
            format!("probe_distribution_root_sha256 = \"{root}\""),
            "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\""
                .to_string(),
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\""
                .to_string(),
            "bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\"".to_string(),
            "service_name = \"enoki-probe\"".to_string(),
            "service_user = \"enoki-probe\"".to_string(),
            "service_group = \"enoki-probe\"".to_string(),
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"".to_string(),
            String::new(),
        ]
        .join("\n");
        let metadata = parse_trusted_probe_install_metadata(&contents).expect("schema v2 parses");
        assert_eq!(metadata.schema_version, 2);
        assert_eq!(
            metadata.probe_distribution_root_sha256.as_deref(),
            Some(root.as_str())
        );
        assert_eq!(metadata.operation_sudoers_path, None);
        assert_eq!(metadata.collector_helper_sudoers_path, None);
        assert_eq!(
            metadata.bootstrap_acquirer_path.as_deref(),
            Some(Path::new(PRODUCTION_BOOTSTRAP_ACQUIRER_PATH))
        );
        assert_eq!(
            metadata.bootstrap_activator_path.as_deref(),
            Some(Path::new(PRODUCTION_BOOTSTRAP_ACTIVATOR_PATH))
        );
        assert_eq!(
            metadata.bootstrap_state_dir.as_deref(),
            Some(Path::new(PRODUCTION_BOOTSTRAP_STATE_DIR))
        );
        assert!(metadata.old_sudoers_paths.is_empty());
        assert!(!contents.contains("sudoers_path"));
        assert!(!contents.contains("probe_asset_public_key_sha256"));
    }

    #[test]
    fn schema_three_metadata_owns_the_complete_observation_role_inventory() {
        let contents = schema_three_install_metadata_contents();

        let metadata = parse_trusted_probe_install_metadata(&contents).unwrap();

        assert_eq!(metadata.schema_version, 3);
        assert_eq!(
            metadata.observation_ipc_group.as_deref(),
            Some(OBSERVATION_IPC_GROUP)
        );
        assert_eq!(
            metadata.observation_runtime_path.as_deref(),
            Some(Path::new(OBSERVATION_RUNTIME_BINARY_PATH))
        );
        assert_eq!(
            metadata.cpu_provider_path.as_deref(),
            Some(Path::new(CPU_PROVIDER_BINARY_PATH))
        );
        assert_eq!(metadata.observation_unit_paths.len(), 4);
        assert_eq!(
            metadata.operation_sudoers_path.as_deref(),
            Some(Path::new(PRODUCTION_OPERATION_SUDOERS_PATH))
        );
    }

    #[test]
    fn signed_package_metadata_requires_all_fixed_bootstrap_owned_paths() {
        let contents = [
            "schema_version = 2",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"",
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
            "service_name = \"enoki-probe\"",
            "service_user = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "",
        ]
        .join("\n");
        assert!(matches!(
            parse_trusted_probe_install_metadata(&contents),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "missing required field"
            ))
        ));
    }

    #[test]
    fn signed_package_metadata_rejects_legacy_authority_fields() {
        let contents = [
            "schema_version = 2",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "service_name = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "",
        ].join("\n");
        assert!(matches!(
            parse_trusted_probe_install_metadata(&contents),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "signed package metadata must not carry legacy sudoers or daily signing trust"
            ))
        ));
    }

    #[test]
    fn signed_package_metadata_rejects_a_nonfixed_bootstrap_role_path() {
        let contents = [
            "schema_version = 2",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "bootstrap_acquirer_path = \"/tmp/attacker-bootstrap\"",
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
            "bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\"",
            "service_name = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "",
        ]
        .join("\n");
        assert!(matches!(
            parse_trusted_probe_install_metadata(&contents),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Probe Bootstrap role path is not the fixed production path"
            ))
        ));
    }

    #[test]
    fn legacy_schema_cannot_claim_bootstrap_role_ownership() {
        let mut contents = version_one_install_metadata_contents(Path::new("/"));
        contents.push_str(
            "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"\n",
        );
        assert!(matches!(
            parse_trusted_probe_install_metadata(&contents),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "legacy metadata must not carry Probe Bootstrap ownership"
            ))
        ));
    }

    #[test]
    fn signed_package_metadata_rejects_a_nonfixed_bootstrap_state_path() {
        let contents = [
            "schema_version = 2",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"",
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
            "bootstrap_state_dir = \"/tmp/attacker-bootstrap-state\"",
            "service_name = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "",
        ]
        .join("\n");
        assert!(matches!(
            parse_trusted_probe_install_metadata(&contents),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Probe Bootstrap role path is not the fixed production path"
            ))
        ));
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
                "target_asset_set_digest = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
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
            "{\"targetAssetSetDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"targetProbeVersion\":\"0.2.0\",\"token\":\"probe-operation-token\"}",
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
                "hub_url = \"https://hub.example/base\"".to_string(),
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
    fn internal_probe_upgrader_allows_explicit_non_loopback_http_hub() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let install_path = temp.path().join("bin/enoki-probe");
        let status_path = temp.path().join("state/probe-operation-status.toml");
        let install_metadata = trusted_install_metadata_for_hub(
            "http://192.0.2.20:8787",
            &install_path,
            &status_path,
            assets_public_key_sha256(),
        );
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"http://192.0.2.20:8787\"".to_string(),
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
            "http://192.0.2.20:8787/api/probe/operations/42/token/validate",
        );
        assert_eq!(
            transport.downloads,
            vec!["http://192.0.2.20:8787/api/probe/assets/manifest.json"],
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
            "https://hub.example",
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
            assets: assets.for_hub("https://hub.example"),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path: bootstrap_config_path.clone(),
            },
            &operation_stdin_for_assets(&assets),
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
                "https://hub.example/api/probe/assets/manifest.json",
                "https://hub.example/api/probe/assets/manifest.json.sig",
                "https://hub.example/api/probe/assets/signing-key.pem",
                &format!(
                    "https://hub.example/api/probe/assets/enoki-probe-{}.tar.gz",
                    host_probe_asset_target().expect("supported test architecture"),
                ),
            ],
        );
        let bootstrap_config =
            fs::read_to_string(bootstrap_config_path).expect("bootstrap config remains");
        assert!(bootstrap_config.contains("probe_id = \"probe_01\""));
    }

    #[test]
    fn internal_probe_upgrader_removes_the_retired_collector_helper_sudoers() {
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
                .as_ref()
                .expect("legacy sudoers")
                .parent()
                .expect("operation sudoers parent"),
        )
        .expect("operation sudoers parent");
        fs::write(
            install_metadata
                .operation_sudoers_path
                .as_ref()
                .expect("legacy sudoers"),
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
            target_asset_set_digest: format!("sha256:{}", hex_sha256(&assets.manifest)),
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

        let operation_sudoers = fs::read_to_string(
            install_metadata
                .operation_sudoers_path
                .as_ref()
                .expect("legacy sudoers"),
        )
        .expect("operation sudoers");
        assert!(operation_sudoers.contains("internal-upgrader --config"));
        assert!(operation_sudoers.contains("internal-uninstaller --config"));
        assert!(!operation_sudoers.contains("internal-privileged-collector-helper"));
        assert!(
            !install_metadata
                .collector_helper_sudoers_path
                .as_ref()
                .expect("legacy sudoers")
                .exists()
        );
        assert!(!planner_log_path.exists());
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
                .as_ref()
                .expect("legacy sudoers")
                .parent()
                .expect("collector-helper sudoers parent"),
        )
        .expect("collector-helper sudoers parent");
        fs::write(
            install_metadata
                .collector_helper_sudoers_path
                .as_ref()
                .expect("legacy sudoers"),
            "stale collector helper sudoers",
        )
        .expect("stale collector-helper sudoers");
        write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
            .expect("write bootstrap config");
        let bootstrap_config =
            read_upgrader_bootstrap_config(&bootstrap_config_path).expect("bootstrap config");
        let operation = ProbeUpgraderOperationMetadata {
            operation_id: "42".to_string(),
            target_asset_set_digest: format!("sha256:{}", hex_sha256(&assets.manifest)),
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

        let operation_sudoers = fs::read_to_string(
            install_metadata
                .operation_sudoers_path
                .as_ref()
                .expect("legacy sudoers"),
        )
        .expect("operation sudoers");
        assert!(operation_sudoers.contains("internal-upgrader --config"));
        assert!(operation_sudoers.contains("internal-uninstaller --config"));
        assert!(!operation_sudoers.contains("internal-privileged-collector-helper"));
        assert!(
            !install_metadata
                .collector_helper_sudoers_path
                .as_ref()
                .expect("legacy sudoers")
                .exists()
        );
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
            &operation_stdin_for_assets(&assets),
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
            None,
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
            None,
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
            None,
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
    fn internal_probe_upgrader_rejects_a_different_asset_set_at_the_same_version() {
        let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets_and_current_version(
            assets,
            public_key_sha256,
            "0.1.9",
            "0.2.0",
            Some(&format!("sha256:{}", "b".repeat(64))),
        );

        assert!(matches!(result, Err(ProbeUpgraderRunError::TargetMismatch)));
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "old probe"
        );
        assert!(systemd.restarted.is_empty());
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
            &operation_stdin_for_assets(&assets),
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
            &operation_stdin_for_assets(&assets),
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

    struct CompleteBundleAssets {
        archive_file: String,
        files: HashMap<String, Vec<u8>>,
        manifest: Vec<u8>,
        root_fingerprint: String,
        target_units: Vec<Vec<u8>>,
    }

    fn complete_bundle_assets(version: &str) -> CompleteBundleAssets {
        let target = host_probe_asset_target().expect("supported test target");
        let mut rng = OsRng;
        let root = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
        let daily = RsaPrivateKey::new(&mut rng, 2048).expect("daily key");
        let root_pem = root
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("root PEM")
            .into_bytes();
        let daily_pem = daily
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("daily PEM")
            .into_bytes();
        let probe = b"new probe".to_vec();
        let runtime = b"new runtime".to_vec();
        let provider = b"new provider".to_vec();
        let disk_health_provider = b"new disk health provider".to_vec();
        let acquirer = b"acquirer".to_vec();
        let target_units =
            enoki_probe_bootstrap::install::fixed_observation_unit_contents().map(|mut unit| {
                unit.extend_from_slice(b"# target-version-integration\n");
                unit
            });
        let mut integration = b"enoki.observation-integration.v1\n".to_vec();
        for unit in &target_units {
            integration.extend_from_slice(unit.len().to_string().as_bytes());
            integration.push(b'\n');
            integration.extend_from_slice(unit);
        }
        let quoted = String::from_utf8(integration)
            .expect("integration UTF-8")
            .replace('\'', "'\\''");
        let activator = format!(
            "#!/bin/sh\n[ \"${{1:-}}\" = \"--render-observation-integration-v1\" ] || exit 64\nprintf '%s' '{quoted}'\n"
        )
        .into_bytes();
        let bundle_manifest = format!(
            "{{\"bootstrapAssets\":[{{\"path\":\"bootstrap/enoki-probe-bootstrap-acquire\",\"permissionProfile\":\"bootstrap-acquirer-v1\",\"role\":\"bootstrap-acquirer\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}},{{\"path\":\"bootstrap/enoki-probe-bootstrap-activate\",\"permissionProfile\":\"bootstrap-activator-v1\",\"role\":\"bootstrap-activator\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}}],\"components\":[{{\"path\":\"enoki-probe\",\"permissionProfile\":\"probe-v5\",\"resourceContract\":\"hub-reporting-v1\",\"role\":\"probe\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}},{{\"path\":\"enoki-observation-runtime\",\"permissionProfile\":\"observation-runtime-v4\",\"resourceContract\":\"official-observation-v2\",\"role\":\"observation-runtime\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}},{{\"path\":\"enoki-cpu-resource-provider\",\"permissionProfile\":\"system-state-provider-v5\",\"resourceContract\":\"system-state-v3\",\"role\":\"system-state-provider\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}},{{\"path\":\"enoki-disk-health-resource-provider\",\"permissionProfile\":\"disk-health-provider-v3\",\"resourceContract\":\"disk-health-v1\",\"role\":\"disk-health-provider\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}}],\"kind\":\"enoki-probe-bundle\",\"target\":\"{target}\",\"version\":\"{version}\"}}\n",
            hex_sha256(&acquirer),
            acquirer.len(),
            hex_sha256(&activator),
            activator.len(),
            hex_sha256(&probe),
            probe.len(),
            hex_sha256(&runtime),
            runtime.len(),
            hex_sha256(&provider),
            provider.len(),
            hex_sha256(&disk_health_provider),
            disk_health_provider.len(),
        )
        .into_bytes();
        let gzip = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive_builder = tar::Builder::new(gzip);
        for (name, bytes) in [
            ("bundle-manifest.json", bundle_manifest.clone()),
            ("enoki-probe", probe),
            ("enoki-observation-runtime", runtime),
            ("enoki-cpu-resource-provider", provider),
            ("enoki-disk-health-resource-provider", disk_health_provider),
            ("bootstrap/enoki-probe-bootstrap-acquire", acquirer),
            ("bootstrap/enoki-probe-bootstrap-activate", activator),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            archive_builder
                .append_data(&mut header, name, bytes.as_slice())
                .expect("archive entry");
        }
        let archive = archive_builder
            .into_inner()
            .expect("gzip")
            .finish()
            .expect("archive");
        let root_id = hex_sha256(&root_pem);
        let daily_id = hex_sha256(&daily_pem);
        let daily_pem_json =
            serde_json::to_string(std::str::from_utf8(&daily_pem).expect("daily PEM UTF-8"))
                .expect("daily PEM JSON");
        let delegation = format!(
            "{{\"distribution\":\"enoki\",\"generation\":1,\"kind\":\"enoki-probe-trust-delegation\",\"purpose\":\"probe-asset-signing\",\"rootKeyId\":\"{root_id}\",\"schemaVersion\":1,\"signingIdentity\":{{\"algorithm\":\"rsa-sha256\",\"keyId\":\"{daily_id}\",\"publicKeyPem\":{daily_pem_json}}}}}\n"
        )
        .into_bytes();
        let mut delegation_input = b"enoki/probe-trust-delegation/v1\0".to_vec();
        delegation_input.extend_from_slice(&delegation);
        let delegation_signature = SigningKey::<Sha256>::new(root)
            .sign_with_rng(&mut rng, &delegation_input)
            .to_vec();
        let archive_file = format!("enoki-probe-{target}.tar.gz");
        let manifest = format!(
            "{{\"assets\":[{{\"bundleManifestSha256\":\"{}\",\"file\":\"{archive_file}\",\"sha256\":\"{}\",\"size\":{},\"target\":\"{target}\"}}],\"kind\":\"enoki-probe-assets\",\"signature\":{{\"algorithm\":\"rsa-sha256\",\"delegationGeneration\":1,\"delegationKeyId\":\"{daily_id}\",\"file\":\"manifest.json.sig\",\"publicKey\":\"signing-key.pem\"}},\"version\":\"{version}\"}}\n",
            hex_sha256(&bundle_manifest),
            hex_sha256(&archive),
            archive.len(),
        )
        .into_bytes();
        let manifest_signature = SigningKey::<Sha256>::new(daily)
            .sign_with_rng(&mut rng, &manifest)
            .to_vec();
        let files = [
            ("root-key.pem".to_string(), root_pem),
            ("trust-delegation.json".to_string(), delegation),
            (
                "trust-delegation.json.sig".to_string(),
                delegation_signature,
            ),
            ("manifest.json".to_string(), manifest.clone()),
            ("manifest.json.sig".to_string(), manifest_signature),
            ("signing-key.pem".to_string(), daily_pem),
            (archive_file.clone(), archive),
        ]
        .into_iter()
        .collect();
        CompleteBundleAssets {
            archive_file,
            files,
            manifest,
            root_fingerprint: root_id,
            target_units: target_units.to_vec(),
        }
    }

    #[test]
    fn schema_three_upgrade_verifies_and_switches_the_complete_package_bundle() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let binary_dir = temporary.path().join("bin");
        let state_dir = temporary.path().join("state");
        let bootstrap_state = temporary.path().join("bootstrap-state");
        fs::create_dir_all(&binary_dir).expect("binary directory");
        fs::create_dir_all(&state_dir).expect("state directory");
        fs::create_dir_all(&bootstrap_state).expect("Bootstrap state");
        fs::set_permissions(&bootstrap_state, fs::Permissions::from_mode(0o700))
            .expect("Bootstrap state mode");
        let probe_path = binary_dir.join("enoki-probe");
        let runtime_path = binary_dir.join("enoki-observation-runtime");
        let provider_path = binary_dir.join("enoki-cpu-resource-provider");
        let disk_health_provider_path = binary_dir.join("enoki-disk-health-resource-provider");
        let bootstrap_acquirer_path = binary_dir.join("enoki-probe-bootstrap-acquire");
        let bootstrap_activator_path = binary_dir.join("enoki-probe-bootstrap-activate");
        let unit_dir = temporary.path().join("systemd");
        fs::create_dir_all(&unit_dir).expect("unit directory");
        let unit_paths = [
            "enoki-observation-runtime.service",
            "enoki-observation-runtime.socket",
            "enoki-cpu-resource-provider@.service",
            "enoki-cpu-resource-provider.socket",
            "enoki-disk-health-resource-provider@.service",
            "enoki-disk-health-resource-provider.socket",
        ]
        .map(|name| unit_dir.join(name));
        for path in [
            &probe_path,
            &runtime_path,
            &provider_path,
            &disk_health_provider_path,
            &bootstrap_acquirer_path,
            &bootstrap_activator_path,
        ] {
            fs::write(path, b"old").expect("old role");
        }
        for path in &unit_paths {
            fs::write(path, b"old unit").expect("old unit");
        }
        let status_path = state_dir.join("probe-operation-status.toml");
        let assets = complete_bundle_assets("0.2.0");
        let archive_file = assets.archive_file.clone();
        let expected_target_units = assets.target_units.clone();
        let mut install_metadata =
            trusted_install_metadata(&probe_path, &status_path, String::new());
        install_metadata.schema_version = 3;
        install_metadata.probe_distribution_root_sha256 = Some(assets.root_fingerprint.clone());
        install_metadata.bootstrap_state_dir = Some(bootstrap_state.clone());
        install_metadata.bootstrap_acquirer_path = Some(bootstrap_acquirer_path.clone());
        install_metadata.bootstrap_activator_path = Some(bootstrap_activator_path.clone());
        install_metadata.observation_runtime_path = Some(runtime_path.clone());
        install_metadata.cpu_provider_path = Some(provider_path.clone());
        install_metadata.disk_health_provider_path = Some(disk_health_provider_path.clone());
        install_metadata.observation_ipc_group = Some(OBSERVATION_IPC_GROUP.to_string());
        install_metadata.observation_unit_paths = unit_paths.to_vec();
        install_metadata.operation_sudoers_path = None;
        install_metadata.collector_helper_sudoers_path = None;
        let operation = ProbeUpgraderOperationMetadata {
            operation_id: "42".to_string(),
            target_asset_set_digest: format!("sha256:{}", hex_sha256(&assets.manifest)),
            target_probe_version: "0.2.0".to_string(),
            token: "probe-operation-token".to_string(),
        };
        let mut transport = RecordingValidationTransport {
            assets: assets
                .files
                .into_iter()
                .map(|(name, bytes)| {
                    (
                        format!("https://hub.example/api/probe/assets/{name}"),
                        bytes,
                    )
                })
                .collect(),
            ..RecordingValidationTransport::default()
        };
        let mut systemd = RecordingSystemdRunner::default();

        execute_schema_three_probe_upgrade(
            &operation,
            &temporary.path().join("identity.toml"),
            &install_metadata,
            &mut transport,
            &mut systemd,
            "0.1.0",
            true,
        )
        .expect("schema 3 upgrade");

        assert_eq!(fs::read(&probe_path).expect("probe"), b"new probe");
        assert_eq!(fs::read(&runtime_path).expect("runtime"), b"new runtime");
        assert_eq!(fs::read(&provider_path).expect("provider"), b"new provider");
        assert_eq!(
            fs::read(&disk_health_provider_path).expect("Disk Health Provider"),
            b"new disk health provider"
        );
        assert_eq!(
            fs::read(&bootstrap_acquirer_path).expect("Bootstrap Acquirer"),
            b"acquirer"
        );
        assert!(
            fs::read(&bootstrap_activator_path)
                .expect("Bootstrap Activator")
                .starts_with(b"#!/bin/sh")
        );
        for (path, expected) in unit_paths.iter().zip(expected_target_units) {
            assert_eq!(fs::read(path).expect("target integration unit"), expected);
            assert_ne!(expected.as_slice(), b"old unit");
        }
        assert!(
            fs::read_to_string(&unit_paths[3])
                .expect("Provider socket unit")
                .contains("SocketGroup=enoki-observation-ipc")
        );
        let target_provider_unit =
            fs::read_to_string(&unit_paths[2]).expect("target Provider service unit");
        assert!(target_provider_unit.contains("ReadOnlyPaths=/proc/stat"));
        assert!(!target_provider_unit.contains("ProcSubset=pid"));
        assert_eq!(
            fs::read_to_string(bootstrap_state.join("trust/delegation-generation"))
                .expect("generation"),
            "1\n"
        );
        assert!(
            transport
                .downloads
                .iter()
                .any(|url| url.ends_with(&archive_file))
        );
        assert_eq!(
            &systemd.calls[..5],
            [
                "stop enoki-disk-health-resource-provider.socket",
                "stop enoki-cpu-resource-provider.socket",
                "stop enoki-observation-runtime.socket",
                "stop enoki-observation-runtime.service",
                "stop enoki-probe",
            ]
        );
    }

    #[test]
    fn legacy_schema_three_inventory_requires_signed_replacement_before_upgrade() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let probe_path = temporary.path().join("enoki-probe");
        let status_path = temporary.path().join("status.toml");
        let mut metadata = trusted_install_metadata(&probe_path, &status_path, String::new());
        metadata.schema_version = 3;
        metadata.probe_distribution_root_sha256 = Some("a".repeat(64));
        metadata.bootstrap_state_dir = Some(temporary.path().join("bootstrap-state"));
        metadata.observation_runtime_path = Some(temporary.path().join("runtime"));
        metadata.cpu_provider_path = Some(temporary.path().join("system-state-provider"));
        metadata.disk_health_provider_path = None;
        metadata.observation_unit_paths = vec![
            temporary.path().join("runtime.service"),
            temporary.path().join("runtime.socket"),
            temporary.path().join("provider@.service"),
            temporary.path().join("provider.socket"),
        ];
        metadata.observation_ipc_group = Some(OBSERVATION_IPC_GROUP.to_string());
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let error = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path: temporary.path().join("identity.toml"),
            },
            &operation_stdin(),
            &mut transport,
            &mut systemd,
            &metadata,
        )
        .expect_err("旧闭包不能被当作同合同原地升级");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::ManualProbeReinstallRequired
        ));
        assert!(transport.downloads.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn schema_three_activation_rolls_back_every_partial_persist_and_is_retryable() {
        for failed_index in 0..9 {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let state = temporary.path().join("state");
            let targets = temporary.path().join("targets");
            fs::create_dir_all(&state).expect("state");
            fs::create_dir_all(&targets).expect("targets");
            let paths = (0..9)
                .map(|index| {
                    let path = targets.join(format!("role-{index}"));
                    fs::write(&path, format!("old-{index}")).expect("old role");
                    path
                })
                .collect::<Vec<_>>();
            let candidates = (0..9)
                .map(|index| format!("new-{index}").into_bytes())
                .collect::<Vec<_>>();
            let replacements = paths
                .iter()
                .zip(&candidates)
                .map(|(path, bytes)| (path.as_path(), bytes.as_slice(), 0o755))
                .collect::<Vec<_>>();
            let transaction =
                prepare_schema_three_activation(&state, &replacements).expect("prepared");
            fs::remove_file(&transaction.entries[failed_index].staged)
                .expect("inject persist failure");

            transaction.activate().expect_err("persist fails");
            transaction.rollback().expect("rollback succeeds");
            for (index, path) in paths.iter().enumerate() {
                assert_eq!(
                    fs::read(path).expect("restored role"),
                    format!("old-{index}").as_bytes()
                );
            }
            assert!(!state.join("upgrade-transaction").exists());
        }
    }

    #[test]
    fn schema_three_crash_recovery_restores_every_role_before_restarting_services() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let state = temporary.path().join("state");
        let targets = temporary.path().join("targets");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&targets).unwrap();
        let paths = (0..9)
            .map(|index| {
                let path = targets.join(format!("role-{index}"));
                fs::write(&path, format!("old-{index}")).unwrap();
                path
            })
            .collect::<Vec<_>>();
        let candidates = (0..9)
            .map(|index| format!("new-{index}").into_bytes())
            .collect::<Vec<_>>();
        let replacements = paths
            .iter()
            .zip(&candidates)
            .map(|(path, bytes)| (path.as_path(), bytes.as_slice(), 0o755))
            .collect::<Vec<_>>();
        let transaction = prepare_schema_three_activation(&state, &replacements).unwrap();
        transaction.activate().unwrap();
        assert_eq!(fs::read(&paths[0]).unwrap(), b"new-0");

        let status_path = temporary.path().join("operation-status.toml");
        let mut metadata = trusted_install_metadata(&paths[0], &status_path, String::new());
        metadata.service_name = "enoki-probe".into();
        let mut systemd = RecordingSystemdRunner::default();
        recover_schema_three_activation(&state, &replacements, &mut systemd, &metadata)
            .expect("recovery");

        for (index, path) in paths.iter().enumerate() {
            assert_eq!(fs::read(path).unwrap(), format!("old-{index}").as_bytes());
        }
        let first_restart = systemd
            .calls
            .iter()
            .position(|call| call.starts_with("restart "))
            .unwrap();
        assert!(
            systemd.calls[..first_restart]
                .iter()
                .any(|call| call == "stop enoki-probe")
        );
        assert!(!state.join("upgrade-transaction").exists());
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
                "sudoers" => {
                    install_metadata.operation_sudoers_path = Some(blocker.join("sudoers"))
                }
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
            probe_distribution_root_sha256: None,
            bootstrap_acquirer_path: None,
            bootstrap_activator_path: None,
            bootstrap_state_dir: None,
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
            operation_sudoers_path: Some(
                operation_status_path
                    .parent()
                    .expect("status parent")
                    .join("enoki-probe-operations.sudoers"),
            ),
            collector_helper_sudoers_path: Some(
                operation_status_path
                    .parent()
                    .expect("status parent")
                    .join("enoki-probe-collector-helpers.sudoers"),
            ),
            old_sudoers_paths: Vec::new(),
            observation_runtime_path: None,
            cpu_provider_path: None,
            disk_health_provider_path: None,
            lifecycle_companion_path: None,
            observation_unit_paths: Vec::new(),
            probe_ipc_group: None,
            probe_ipc_group_ownership: None,
            observation_ipc_group: None,
            install_state_sha256: None,
            target_manifest_sha256: None,
            bundle_version: None,
            lifecycle_authority_install_key: None,
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

    fn schema_three_install_metadata_contents() -> String {
        [
            "schema_version = 3",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "observation_runtime_path = \"/usr/local/bin/enoki-observation-runtime\"",
            "cpu_provider_path = \"/usr/local/bin/enoki-cpu-resource-provider\"",
            "observation_ipc_group = \"enoki-observation-ipc\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"",
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
            "bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\"",
            "service_name = \"enoki-probe\"",
            "service_user = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "observation_runtime_service_unit_path = \"/etc/systemd/system/enoki-observation-runtime.service\"",
            "observation_runtime_socket_unit_path = \"/etc/systemd/system/enoki-observation-runtime.socket\"",
            "cpu_provider_service_unit_path = \"/etc/systemd/system/enoki-cpu-resource-provider@.service\"",
            "cpu_provider_socket_unit_path = \"/etc/systemd/system/enoki-cpu-resource-provider.socket\"",
            "operation_sudoers_path = \"/etc/sudoers.d/enoki-probe-operations\"",
            "collector_helper_sudoers_path = \"/etc/sudoers.d/enoki-probe-collector-helpers\"",
            "",
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
            &operation_stdin_for_assets(&assets),
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
        target_asset_set_digest: Option<&str>,
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
            target_asset_set_digest: target_asset_set_digest.map_or_else(
                || format!("sha256:{}", hex_sha256(&assets.manifest)),
                str::to_string,
            ),
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
        operation_stdin_with_digest(&format!("sha256:{}", "a".repeat(64)))
    }

    fn operation_stdin_for_assets(assets: &SignedAssets) -> String {
        operation_stdin_with_digest(&format!("sha256:{}", hex_sha256(&assets.manifest)))
    }

    fn operation_stdin_with_digest(target_asset_set_digest: &str) -> String {
        [
            "operation_id = \"42\"".to_string(),
            format!(
                "target_asset_set_digest = {}",
                toml_string(target_asset_set_digest)
            ),
            "target_probe_version = \"0.2.0\"".to_string(),
            "token = \"probe-operation-token\"".to_string(),
            String::new(),
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
