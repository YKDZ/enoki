use std::{
    error::Error,
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderRunInput {
    pub bootstrap_config_path: PathBuf,
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
    InvalidManifest(&'static str),
    InvalidMetadata(&'static str),
    Io(std::io::Error),
    MissingToken,
    RestartFailure(String),
    SignatureFailure,
    SigningKeyUntrusted,
    TargetMismatch,
    TokenValidation(String),
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
            Self::InvalidManifest(message) => {
                write!(formatter, "invalid Probe asset manifest: {message}")
            }
            Self::InvalidMetadata(message) => {
                write!(
                    formatter,
                    "invalid Probe Upgrader operation metadata: {message}"
                )
            }
            Self::Io(_) => write!(formatter, "failed to read Probe bootstrap config"),
            Self::MissingToken => write!(formatter, "missing Probe Operation Token on stdin"),
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
        }
    }
}

impl Error for ProbeUpgraderRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidConfig(_)
            | Self::ArchitectureMissing
            | Self::AssetMissing
            | Self::ChecksumFailure
            | Self::InvalidManifest(_)
            | Self::InvalidMetadata(_)
            | Self::MissingToken
            | Self::RestartFailure(_)
            | Self::SignatureFailure
            | Self::SigningKeyUntrusted
            | Self::TargetMismatch
            | Self::TokenValidation(_) => None,
        }
    }
}

impl From<std::io::Error> for ProbeUpgraderRunError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub trait ProbeUpgraderValidationTransport {
    fn get_asset(
        &mut self,
        url: &str,
        bearer_secret: &str,
    ) -> Result<Vec<u8>, ProbeUpgraderRunError>;

    fn post_token_validation(
        &mut self,
        url: &str,
        bearer_secret: &str,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError>;
}

pub struct HttpProbeUpgraderValidationTransport;

impl ProbeUpgraderValidationTransport for HttpProbeUpgraderValidationTransport {
    fn get_asset(
        &mut self,
        url: &str,
        bearer_secret: &str,
    ) -> Result<Vec<u8>, ProbeUpgraderRunError> {
        let response = ureq::get(url)
            .set("accept", "application/octet-stream")
            .set("authorization", &format!("Bearer {bearer_secret}"))
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
        bearer_secret: &str,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        ureq::post(url)
            .set("accept", "application/json")
            .set("authorization", &format!("Bearer {bearer_secret}"))
            .set("content-type", "application/json")
            .send_string(body)
            .map_err(|error| ProbeUpgraderRunError::TokenValidation(error.to_string()))?;

        Ok(())
    }
}

pub trait ProbeUpgraderSystemdRunner {
    fn restart_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError>;
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

    let bootstrap_config = read_upgrader_bootstrap_config(&input.bootstrap_config_path)?;
    let hub_url = bootstrap_config
        .hub_url
        .as_ref()
        .ok_or(ProbeUpgraderRunError::InvalidConfig("missing Hub URL"))?;
    let probe_secret =
        bootstrap_config
            .probe_secret
            .as_ref()
            .ok_or(ProbeUpgraderRunError::InvalidConfig(
                "missing Probe Identity secret",
            ))?;
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
        probe_secret,
        &body,
    )?;

    if let Err(error) = execute_probe_upgrade(&operation, &bootstrap_config, transport, systemd) {
        let failed = failed_probe_upgrader_result(&operation, &error);
        let _ = write_failed_local_operation_status(&operation, &bootstrap_config, &failed);
        return Ok(failed);
    }

    Ok(ProbeUpgraderResult {
        error_code: None,
        message: None,
        operation_id: operation.operation_id,
        status: "running".to_string(),
    })
}

struct ProbeUpgraderOperationMetadata {
    operation_id: String,
    target_probe_version: String,
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
    probe_secret: Option<String>,
    service_name: Option<String>,
    state_dir: Option<String>,
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
        probe_secret: string_value(&value, "probe_secret")?,
        service_name: string_value(&value, "service_name")?,
        state_dir: string_value(&value, "state_dir")?,
    })
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
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    let hub_url = bootstrap_config
        .hub_url
        .as_deref()
        .ok_or(ProbeUpgraderRunError::InvalidConfig("missing Hub URL"))?;
    let probe_secret =
        bootstrap_config
            .probe_secret
            .as_deref()
            .ok_or(ProbeUpgraderRunError::InvalidConfig(
                "missing Probe Identity secret",
            ))?;
    let install_path = PathBuf::from(
        bootstrap_config
            .install_path
            .as_deref()
            .ok_or(ProbeUpgraderRunError::InvalidConfig("missing install path"))?,
    );
    let trusted_key_sha256 = bootstrap_config
        .probe_asset_public_key_sha256
        .as_deref()
        .ok_or(ProbeUpgraderRunError::InvalidConfig(
            "missing trusted Probe asset signing key fingerprint",
        ))?;
    let service_name = bootstrap_config
        .service_name
        .as_deref()
        .unwrap_or("enoki-probe");

    let manifest_bytes = download_hub_asset(transport, hub_url, probe_secret, "manifest.json")?;
    let signature_bytes =
        download_hub_asset(transport, hub_url, probe_secret, "manifest.json.sig")?;
    let public_key_bytes = download_hub_asset(transport, hub_url, probe_secret, "signing-key.pem")?;

    verify_public_key_trust(&public_key_bytes, trusted_key_sha256)?;
    verify_manifest_signature(&manifest_bytes, &signature_bytes, &public_key_bytes)?;

    let manifest: ProbeAssetManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| ProbeUpgraderRunError::InvalidManifest("invalid JSON"))?;
    if manifest.version != operation.target_probe_version {
        return Err(ProbeUpgraderRunError::TargetMismatch);
    }
    if manifest.signature.algorithm != "rsa-sha256"
        || manifest.signature.file != "manifest.json.sig"
        || manifest.signature.public_key != "signing-key.pem"
    {
        return Err(ProbeUpgraderRunError::InvalidManifest(
            "unsupported signature metadata",
        ));
    }

    let target = host_probe_asset_target();
    let asset = manifest
        .assets
        .iter()
        .find(|asset| asset.target == target)
        .ok_or(ProbeUpgraderRunError::ArchitectureMissing)?;
    validate_asset_metadata(asset)?;

    let archive = download_hub_asset(transport, hub_url, probe_secret, &asset.file)?;
    verify_archive_sha256(&archive, &asset.sha256)?;
    replace_installed_probe_binary(&archive, &install_path)?;
    write_local_operation_status(operation, bootstrap_config)?;
    systemd.restart_service(service_name)?;

    Ok(())
}

fn download_hub_asset(
    transport: &mut impl ProbeUpgraderValidationTransport,
    hub_url: &str,
    probe_secret: &str,
    file_name: &str,
) -> Result<Vec<u8>, ProbeUpgraderRunError> {
    if !is_safe_asset_file_name(file_name) {
        return Err(ProbeUpgraderRunError::AssetMissing);
    }

    transport.get_asset(
        &format!(
            "{}/api/probe/assets/{}",
            hub_url.trim_end_matches('/'),
            file_name,
        ),
        probe_secret,
    )
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

    let extract_dir = work_dir.join("extract");
    fs::create_dir_all(&extract_dir).map_err(ProbeUpgraderRunError::Io)?;
    let decoder = GzDecoder::new(archive);
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(&extract_dir)
        .map_err(|_| ProbeUpgraderRunError::AssetMissing)?;

    let source_binary =
        find_extracted_probe_binary(&extract_dir).ok_or(ProbeUpgraderRunError::AssetMissing)?;
    let staged_binary = work_dir.join("enoki-probe.new");
    fs::copy(source_binary, &staged_binary).map_err(ProbeUpgraderRunError::Io)?;
    fs::set_permissions(&staged_binary, fs::Permissions::from_mode(0o755))
        .map_err(ProbeUpgraderRunError::Io)?;
    fs::rename(&staged_binary, install_path).map_err(ProbeUpgraderRunError::Io)?;
    fs::remove_dir_all(&work_dir).map_err(ProbeUpgraderRunError::Io)?;

    Ok(())
}

fn find_extracted_probe_binary(root: &Path) -> Option<PathBuf> {
    let direct = root.join("enoki-probe");
    if direct.is_file() {
        return Some(direct);
    }

    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_extracted_probe_binary(&path) {
                return Some(found);
            }
        } else if path.file_name().and_then(|name| name.to_str()) == Some("enoki-probe") {
            return Some(path);
        }
    }

    None
}

fn write_local_operation_status(
    operation: &ProbeUpgraderOperationMetadata,
    bootstrap_config: &ProbeUpgraderBootstrapConfig,
) -> Result<(), ProbeUpgraderRunError> {
    let status_path = operation_status_path(bootstrap_config)?;
    if let Some(parent) = status_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }
    fs::write(
        status_path,
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
    .map_err(ProbeUpgraderRunError::Io)
}

fn write_failed_local_operation_status(
    operation: &ProbeUpgraderOperationMetadata,
    bootstrap_config: &ProbeUpgraderBootstrapConfig,
    result: &ProbeUpgraderResult,
) -> Result<(), ProbeUpgraderRunError> {
    let status_path = operation_status_path(bootstrap_config)?;
    if let Some(parent) = status_path.parent() {
        fs::create_dir_all(parent).map_err(ProbeUpgraderRunError::Io)?;
    }
    fs::write(
        status_path,
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

fn probe_upgrader_error_code(error: &ProbeUpgraderRunError) -> &'static str {
    match error {
        ProbeUpgraderRunError::ArchitectureMissing => "architecture_missing",
        ProbeUpgraderRunError::AssetMissing => "asset_missing",
        ProbeUpgraderRunError::ChecksumFailure => "checksum_failure",
        ProbeUpgraderRunError::RestartFailure(_) => "restart_failure",
        ProbeUpgraderRunError::SignatureFailure => "signature_failure",
        ProbeUpgraderRunError::SigningKeyUntrusted => "signature_failure",
        ProbeUpgraderRunError::TargetMismatch => "target_mismatch",
        ProbeUpgraderRunError::InvalidConfig(_)
        | ProbeUpgraderRunError::InvalidManifest(_)
        | ProbeUpgraderRunError::InvalidMetadata(_)
        | ProbeUpgraderRunError::Io(_)
        | ProbeUpgraderRunError::MissingToken
        | ProbeUpgraderRunError::TokenValidation(_) => "probe_upgrader_failed",
    }
}

fn operation_status_path(
    bootstrap_config: &ProbeUpgraderBootstrapConfig,
) -> Result<PathBuf, ProbeUpgraderRunError> {
    if let Some(path) = bootstrap_config.operation_status_path.as_ref() {
        return Ok(PathBuf::from(path));
    }
    if let Some(state_dir) = bootstrap_config.state_dir.as_ref() {
        return Ok(PathBuf::from(state_dir).join("probe-operation-status.toml"));
    }

    Err(ProbeUpgraderRunError::InvalidConfig("missing state dir"))
}

fn host_probe_asset_target() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64-unknown-linux-gnu",
        _ => "x86_64-unknown-linux-gnu",
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderLaunch {
    pub bootstrap_config_path: PathBuf,
    pub install_path: PathBuf,
    pub operation_id: String,
    pub target_probe_version: String,
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
        bearer_secret: String,
        downloads: Vec<String>,
        url: String,
    }

    #[derive(Default)]
    struct RecordingSystemdRunner {
        restarted: Vec<String>,
    }

    impl ProbeUpgraderValidationTransport for RecordingValidationTransport {
        fn get_asset(
            &mut self,
            url: &str,
            bearer_secret: &str,
        ) -> Result<Vec<u8>, ProbeUpgraderRunError> {
            self.downloads.push(format!("{bearer_secret} {url}"));
            self.assets
                .get(url)
                .cloned()
                .ok_or(ProbeUpgraderRunError::AssetMissing)
        }

        fn post_token_validation(
            &mut self,
            url: &str,
            bearer_secret: &str,
            body: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.url = url.to_string();
            self.bearer_secret = bearer_secret.to_string();
            self.body = body.to_string();

            Ok(())
        }
    }

    impl ProbeUpgraderSystemdRunner for RecordingSystemdRunner {
        fn restart_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.restarted.push(service_name.to_string());
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
    fn internal_probe_upgrader_rejects_missing_stdin_token() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_secret = \"enk_probe_secret\"",
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
    fn internal_probe_upgrader_validates_stdin_token_with_hub_before_noop_result() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_secret = \"enk_probe_secret\"",
                "",
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport::default();

        let mut systemd = RecordingSystemdRunner::default();
        let result = run_probe_upgrader_with_systemd_runner(
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
        )
        .expect("missing config is reported as operation failure");

        assert_eq!(
            transport.url,
            "https://hub.example/api/probe/operations/42/token/validate",
        );
        assert_eq!(transport.bearer_secret, "enk_probe_secret");
        assert_eq!(
            transport.body,
            "{\"targetProbeVersion\":\"0.2.0\",\"token\":\"probe-operation-token\"}",
        );
        assert_eq!(
            result,
            ProbeUpgraderResult {
                error_code: Some("probe_upgrader_failed".to_string()),
                message: Some("invalid Probe bootstrap config: missing install path".to_string()),
                operation_id: "42".to_string(),
                status: "failed".to_string(),
            },
        );
        assert!(transport.downloads.is_empty());
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
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example/base\"".to_string(),
                "probe_id = \"probe_01\"".to_string(),
                "probe_secret = \"enk_probe_secret\"".to_string(),
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

        let result = run_probe_upgrader_with_systemd_runner(
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
                "enk_probe_secret https://hub.example/base/api/probe/assets/manifest.json",
                "enk_probe_secret https://hub.example/base/api/probe/assets/manifest.json.sig",
                "enk_probe_secret https://hub.example/base/api/probe/assets/signing-key.pem",
                &format!(
                    "enk_probe_secret https://hub.example/base/api/probe/assets/enoki-probe-{}.tar.gz",
                    host_probe_asset_target(),
                ),
            ],
        );
        let bootstrap_config =
            fs::read_to_string(bootstrap_config_path).expect("bootstrap config remains");
        assert!(bootstrap_config.contains("probe_id = \"probe_01\""));
        assert!(bootstrap_config.contains("probe_secret = \"enk_probe_secret\""));
    }

    #[test]
    fn internal_probe_upgrader_rejects_checksum_mismatch_before_replacement() {
        let temp = tempfile::tempdir().expect("temp dir");
        let install_path = temp.path().join("bin/enoki-probe");
        fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
        fs::write(&install_path, "old probe").expect("old probe");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let assets = signed_assets("0.2.0", "new probe", Some("0".repeat(64)));
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"".to_string(),
                "probe_secret = \"enk_probe_secret\"".to_string(),
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

        let result = run_probe_upgrader_with_systemd_runner(
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
        let archive_file = format!("enoki-probe-{}.tar.gz", host_probe_asset_target());
        let archive = archive_with_probe_binary(binary_contents);
        let sha256 = sha256_override.unwrap_or_else(|| hex_sha256(&archive));
        let manifest = format!(
            "{{\"assets\":[{{\"file\":\"{}\",\"sha256\":\"{}\",\"size\":{},\"target\":\"{}\"}}],\"kind\":\"enoki-probe-assets\",\"signature\":{{\"algorithm\":\"rsa-sha256\",\"file\":\"manifest.json.sig\",\"publicKey\":\"signing-key.pem\"}},\"version\":\"{}\"}}\n",
            archive_file,
            sha256,
            archive.len(),
            host_probe_asset_target(),
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
            archive_file,
            archive,
            manifest,
            public_key,
            public_key_sha256,
            signature,
        }
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
}
