use std::{
    error::Error,
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

use flate2::read::GzDecoder;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    signature::Verifier,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::probe_auth::{ProbeRequestAuth, signed_probe_request_headers};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderRunInput {
    pub bootstrap_config_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUninstallerRunInput {
    pub bootstrap_config_path: PathBuf,
}

const PRODUCTION_INSTALL_METADATA_PATH: &str = "/etc/enoki/probe-install.toml";
const PRODUCTION_SUDOERS_PATH: &str = "/etc/sudoers.d/enoki-probe-upgrader";

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
            | Self::MissingToken
            | Self::PostReplacementRestartFailure(_)
            | Self::PostReplacementStatusWriteFailure(_)
            | Self::RestartFailure(_)
            | Self::SignatureFailure
            | Self::SigningKeyUntrusted
            | Self::DowngradeRejected
            | Self::TargetMismatch
            | Self::TokenValidation(_)
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
}

pub trait ProbeUpgraderSystemdRunner {
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
}

pub struct SystemProbeUpgraderSystemdRunner;

impl ProbeUpgraderSystemdRunner for SystemProbeUpgraderSystemdRunner {
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
        run_best_effort_systemctl(["stop", service_name]);
        Ok(())
    }

    fn disable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        run_best_effort_systemctl(["disable", service_name]);
        Ok(())
    }

    fn daemon_reload(&mut self) -> Result<(), ProbeUpgraderRunError> {
        run_best_effort_systemctl(["daemon-reload"]);
        Ok(())
    }

    fn reset_failed(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        run_best_effort_systemctl(["reset-failed", service_name]);
        Ok(())
    }
}

fn run_best_effort_systemctl<const N: usize>(args: [&str; N]) {
    let _ = Command::new("systemctl").args(args).output();
}

pub fn run_probe_upgrader(
    input: ProbeUpgraderRunInput,
    stdin: &str,
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> Result<ProbeUpgraderResult, ProbeUpgraderRunError> {
    let mut systemd = SystemProbeUpgraderSystemdRunner;
    run_probe_upgrader_with_systemd_runner(input, stdin, transport, &mut systemd)
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
    let install_metadata =
        read_trusted_probe_install_metadata(Path::new(PRODUCTION_INSTALL_METADATA_PATH))?;
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

    let bootstrap_config = read_upgrader_bootstrap_config(&input.bootstrap_config_path)?;
    let hub_url = bootstrap_config
        .hub_url
        .as_ref()
        .ok_or(ProbeUpgraderRunError::InvalidConfig("missing Hub URL"))?;
    let request_auth = probe_request_auth_from_bootstrap_config(&bootstrap_config)?;
    let body = format!(
        "{{\"targetProbeVersion\":\"{}\",\"token\":\"{}\"}}",
        json_string_fragment(&operation.target_probe_version),
        json_string_fragment(&operation.token),
    );

    transport.post_token_validation(
        &format!(
            "{}/api/probe/operations/{}/token/validate",
            hub_url.trim_end_matches('/'),
            operation.operation_id,
        ),
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
    let install_metadata =
        read_trusted_probe_install_metadata(Path::new(PRODUCTION_INSTALL_METADATA_PATH))?;
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

    let bootstrap_config = read_upgrader_bootstrap_config(&input.bootstrap_config_path)?;
    let hub_url = bootstrap_config
        .hub_url
        .as_ref()
        .ok_or(ProbeUpgraderRunError::InvalidConfig("missing Hub URL"))?
        .clone();
    let request_auth = probe_request_auth_from_bootstrap_config(&bootstrap_config)?;
    validate_bootstrap_config_matches_trusted_install_metadata(
        &bootstrap_config,
        install_metadata,
    )?;

    let token_body = format!(
        "{{\"token\":\"{}\"}}",
        json_string_fragment(&operation.token)
    );
    transport.post_token_validation(
        &format!(
            "{}/api/probe/operations/{}/token/validate",
            hub_url.trim_end_matches('/'),
            operation.operation_id,
        ),
        &request_auth,
        &token_body,
    )?;

    let status_url = format!(
        "{}/api/probe/operations/{}/status",
        hub_url.trim_end_matches('/'),
        operation.operation_id,
    );

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
    ensure_absolute_path(&input.bootstrap_config_path)?;
    systemd.stop_service(&install_metadata.service_name)?;
    systemd.disable_service(&install_metadata.service_name)?;
    remove_path_if_exists(&systemd_service_path(&install_metadata.service_name))?;
    systemd.daemon_reload()?;
    systemd.reset_failed(&install_metadata.service_name)?;
    remove_path_if_exists(&install_metadata.install_path)?;
    remove_path_if_exists(&install_metadata.sudoers_path)?;
    remove_path_if_exists(Path::new(PRODUCTION_INSTALL_METADATA_PATH))?;
    remove_path_if_exists(&input.bootstrap_config_path)?;
    remove_empty_parent_dir(&input.bootstrap_config_path)?;
    remove_path_if_exists(&install_metadata.state_dir)?;
    remove_default_service_account();

    Ok(())
}

fn systemd_service_path(service_name: &str) -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/{service_name}.service"))
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

fn remove_default_service_account() {
    let _ = Command::new("userdel").arg("enoki-probe").output();
    let _ = Command::new("groupdel").arg("enoki-probe").output();
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
    install_path: PathBuf,
    operation_status_path: PathBuf,
    probe_asset_public_key_sha256: String,
    service_name: String,
    service_user: String,
    state_dir: PathBuf,
    sudoers_path: PathBuf,
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
) -> Result<TrustedProbeInstallMetadata, ProbeUpgraderRunError> {
    let metadata = fs::metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.uid() != 0 {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "metadata file is not owned by root",
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "metadata file is writable by group or other",
        ));
    }

    let contents = fs::read_to_string(path).map_err(ProbeUpgraderRunError::Io)?;
    parse_trusted_probe_install_metadata(&contents)
}

fn parse_trusted_probe_install_metadata(
    contents: &str,
) -> Result<TrustedProbeInstallMetadata, ProbeUpgraderRunError> {
    let value = contents
        .parse::<toml::Value>()
        .map_err(|_| ProbeUpgraderRunError::InvalidInstallMetadata("invalid TOML"))?;
    let install_path = required_install_metadata_path(&value, "install_path")?;
    let operation_status_path = required_install_metadata_path(&value, "operation_status_path")?;
    let state_dir = required_install_metadata_path(&value, "state_dir")?;
    let sudoers_path = optional_install_metadata_path(&value, "sudoers_path")?
        .unwrap_or_else(|| PathBuf::from(PRODUCTION_SUDOERS_PATH));
    let service_name = required_install_metadata_string(&value, "service_name")?;
    let service_user = optional_install_metadata_string(&value, "service_user")?
        .unwrap_or_else(|| "enoki-probe".to_string());
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
    if !is_sha256_hex(&probe_asset_public_key_sha256) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "trusted Probe asset signing key fingerprint is not a valid sha256 value",
        ));
    }

    Ok(TrustedProbeInstallMetadata {
        install_path,
        operation_status_path,
        probe_asset_public_key_sha256,
        service_name,
        service_user,
        state_dir,
        sudoers_path,
    })
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

    Ok(path)
}

fn optional_install_metadata_path(
    value: &toml::Value,
    key: &'static str,
) -> Result<Option<PathBuf>, ProbeUpgraderRunError> {
    let Some(raw) = optional_install_metadata_string(value, key)? else {
        return Ok(None);
    };
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "paths must be absolute",
        ));
    }

    Ok(Some(path))
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
    let hub_url = bootstrap_config
        .hub_url
        .as_deref()
        .ok_or(ProbeUpgraderRunError::InvalidConfig("missing Hub URL"))?;
    validate_bootstrap_config_matches_trusted_install_metadata(bootstrap_config, install_metadata)?;

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
    if !is_safe_sudoers_path(&install_metadata.install_path)
        || !is_safe_sudoers_path(bootstrap_config_path)
        || !is_safe_sudoers_token(&install_metadata.service_user)
        || !is_safe_sudoers_token(&install_metadata.service_name)
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "sudoers command contains unsafe values",
        ));
    }

    let sudoers_path = &install_metadata.sudoers_path;
    if let Some(parent) = sudoers_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }
    fs::write(
        sudoers_path,
        [
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
            String::new(),
        ]
        .join("\n"),
    )
    .map_err(ProbeUpgraderRunError::Io)?;
    fs::set_permissions(sudoers_path, fs::Permissions::from_mode(0o440))
        .map_err(ProbeUpgraderRunError::Io)
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

    transport.get_asset(&format!(
        "{}/api/probe/assets/{}",
        hub_url.trim_end_matches('/'),
        file_name,
    ))
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
    if let Some(parent) = status_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&status_path)
        .map_err(ProbeUpgraderRunError::Io)?;
    set_operation_status_permissions(&status_path)?;

    Ok(())
}

fn write_local_operation_status(
    operation: &ProbeUpgraderOperationMetadata,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    let status_path = operation_status_path(install_metadata);
    if let Some(parent) = status_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }
    fs::write(
        &status_path,
        [
            format!("operation_id = {}", toml_string(&operation.operation_id)),
            format!(
                "target_probe_version = {}",
                toml_string(&operation.target_probe_version),
            ),
            "status = \"running\"".to_string(),
            String::new(),
        ]
        .join("\n"),
    )
    .map_err(ProbeUpgraderRunError::Io)?;
    set_operation_status_permissions(&status_path)
}

fn write_failed_local_operation_status(
    operation: &ProbeUpgraderOperationMetadata,
    install_metadata: &TrustedProbeInstallMetadata,
    result: &ProbeUpgraderResult,
) -> Result<(), ProbeUpgraderRunError> {
    let status_path = operation_status_path(install_metadata);
    if let Some(parent) = status_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }
    fs::write(
        &status_path,
        [
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
    )
    .map_err(ProbeUpgraderRunError::Io)?;
    set_operation_status_permissions(&status_path)
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
        ProbeUpgraderRunError::UninstallStatusReportFailure(_) => "uninstall_status_report_failure",
        ProbeUpgraderRunError::UnsafeArchive(_) => "unsafe_archive",
        ProbeUpgraderRunError::UnsupportedArchitecture(_) => "unsupported_architecture",
        ProbeUpgraderRunError::InvalidConfig(_)
        | ProbeUpgraderRunError::InvalidInstallMetadata(_)
        | ProbeUpgraderRunError::InvalidManifest(_)
        | ProbeUpgraderRunError::InvalidMetadata(_)
        | ProbeUpgraderRunError::InvalidSigningKey(_)
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
    }

    #[derive(Default)]
    struct RecordingSystemdRunner {
        calls: Vec<String>,
        failure: Option<String>,
        restarted: Vec<String>,
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
    }

    impl ProbeUpgraderSystemdRunner for RecordingSystemdRunner {
        fn restart_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            if let Some(failure) = self.failure.take() {
                return Err(ProbeUpgraderRunError::RestartFailure(failure));
            }
            self.restarted.push(service_name.to_string());
            Ok(())
        }

        fn stop_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("stop {service_name}"));
            Ok(())
        }

        fn disable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("disable {service_name}"));
            Ok(())
        }

        fn daemon_reload(&mut self) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push("daemon-reload".to_string());
            Ok(())
        }

        fn reset_failed(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("reset-failed {service_name}"));
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
        fs::write(&install_path, "probe binary").expect("install binary");
        fs::write(state_dir.join("state"), "state").expect("state");
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
        let install_metadata =
            trusted_install_metadata(&install_path, &status_path, "a".repeat(64));
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
            ],
        );
        assert!(!install_path.exists());
        assert!(!bootstrap_config_path.exists());
        assert!(!state_dir.exists());
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
    fn trusted_install_metadata_rejects_unsafe_service_user_for_sudoers() {
        let contents = [
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
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
        let assets = signed_assets("0.2.0", "new probe", None);
        let install_metadata = trusted_install_metadata(
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
        assert_eq!(
            fs::read_to_string(&install_path).expect("binary"),
            "new probe"
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
        let assets = signed_assets("0.2.0", "new probe", None);
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets_and_current_version(
            assets,
            public_key_sha256,
            "0.1.9",
            "0.2.0",
        );

        assert!(result.is_ok());
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "new probe"
        );
        assert_eq!(systemd.restarted, vec!["enoki-probe".to_string()]);
    }

    #[test]
    fn internal_probe_upgrader_accepts_tag_prefixed_manifest_version() {
        let assets = signed_assets("v0.2.0", "new probe", None);
        let public_key_sha256 = assets.public_key_sha256.clone();
        let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

        assert_eq!(result.error_code, None);
        assert_eq!(
            fs::read_to_string(install_path).expect("binary"),
            "new probe"
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
        let assets = signed_assets("0.2.0", "new probe", None);
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
        let assets = signed_assets("0.2.0", "new probe", None);
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

        assert_eq!(
            fs::read_to_string(&install_path).expect("binary"),
            "new probe"
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

        let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
            },
            &operation_stdin(),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("mismatch is reported as operation failure");

        assert_eq!(result.error_code.as_deref(), Some("probe_upgrader_failed"));
        assert_eq!(
            result.message.as_deref(),
            Some(
                "invalid Probe bootstrap config: install path does not match trusted install metadata"
            ),
        );
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
        TrustedProbeInstallMetadata {
            install_path: install_path.to_path_buf(),
            operation_status_path: operation_status_path.to_path_buf(),
            probe_asset_public_key_sha256,
            service_name: "enoki-probe".to_string(),
            service_user: "enoki-probe".to_string(),
            state_dir: operation_status_path
                .parent()
                .expect("status parent")
                .to_path_buf(),
            sudoers_path: operation_status_path
                .parent()
                .expect("status parent")
                .join("enoki-probe-upgrader.sudoers"),
        }
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
