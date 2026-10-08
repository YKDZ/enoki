mod replacement_attempt;

use replacement_attempt::InstalledRegistrationAttempt;
pub use replacement_attempt::{
    RootReplacementRegistrationAttemptInput, prepare_root_replacement_registration_attempt,
};

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use prost::Message;

use crate::{
    collectors::is_owner_configurable_collector_id,
    hub_url,
    metrics::MetricsCollectionConfig,
    protocol::enoki::v1::{
        ProbeEnrollmentTargetKind, ProbeInstallationInspection, ProbeInstallationRejection,
        ProbeRegistrationRequest, ProbeRegistrationResponse,
    },
    secure_file::{atomic_write, read_regular_file},
    transport::{HttpAttemptError, post_protobuf},
};

const SYSTEMD_STATE_DIRECTORY: &str = "/var/lib/enoki-probe";
const SYSTEMD_BOOTSTRAP_CONFIG: &str = "/var/lib/enoki-probe/identity/probe-bootstrap.toml";

#[derive(Debug, Eq, PartialEq)]
pub struct ProbeRegistrationInput {
    pub bootstrap_config_path: PathBuf,
    pub enrollment_token: String,
    pub hub_url: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProbeRegistrationOutcome {
    pub initial_probe_configuration_version: Option<String>,
    pub host_id: String,
    pub probe_id: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProbeInstallationRejectionInput {
    pub code: String,
    pub existing_probe_id: String,
    pub enrollment_token: String,
    pub hub_url: String,
    pub message: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProbeInstallationInspectionInput {
    pub enrollment_token: String,
    pub hub_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeInstallationTarget {
    NewHost,
    ExistingHost,
    ManualReinstall(ProbeReplacementAuthorization),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeReplacementAuthorization {
    pub enrollment_id: String,
    pub host_id: String,
    pub expected_hub_origin: String,
    pub expected_probe_id: String,
    pub source_probe_version: String,
    pub source_probe_sha256: Vec<String>,
    pub target_asset_set_digest: String,
    pub target_probe_version: String,
}

pub(crate) struct PreparedInstallationRejection {
    body: Vec<u8>,
    url: String,
}

pub trait RegistrationTransport {
    fn post_protobuf(&mut self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, RegistrationError>;
}

#[derive(Debug)]
pub enum RegistrationError {
    Attempt(HttpAttemptError),
    Decode(String),
    InvalidResponse(&'static str),
    Io(std::io::Error),
    KeyGeneration(String),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attempt(error) => write!(formatter, "registration request failed: {error}"),
            Self::Decode(message) => write!(
                formatter,
                "failed to decode registration response: {message}"
            ),
            Self::InvalidResponse(message) => {
                write!(formatter, "invalid registration response: {message}")
            }
            Self::Io(error) => write!(formatter, "failed to store Probe bootstrap config: {error}"),
            Self::KeyGeneration(message) => {
                write!(formatter, "failed to generate Probe signing key: {message}")
            }
        }
    }
}

impl Error for RegistrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Attempt(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Decode(_) | Self::InvalidResponse(_) | Self::KeyGeneration(_) => None,
        }
    }
}

impl From<std::io::Error> for RegistrationError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl RegistrationError {
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Attempt(error) if error.is_transient())
    }
}

pub struct HttpRegistrationTransport;

impl RegistrationTransport for HttpRegistrationTransport {
    fn post_protobuf(&mut self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, RegistrationError> {
        post_protobuf(url, &body, &[]).map_err(RegistrationError::Attempt)
    }
}

pub fn register_probe(
    input: ProbeRegistrationInput,
    transport: &mut impl RegistrationTransport,
) -> Result<ProbeRegistrationOutcome, RegistrationError> {
    let mut installer_owned_fields = read_installer_owned_fields(&input.bootstrap_config_path)?;
    let prepared = installer_owned_fields
        .registration_attempt
        .prepare(&input)?;
    installer_owned_fields
        .registration_attempt
        .remember_signed_digest(prepared.signed_attempt_sha256.clone());
    let response_body = transport.post_protobuf(
        &registration_url(&input.hub_url)?,
        prepared.request_body.clone(),
    )?;
    let response = ProbeRegistrationResponse::decode(response_body.as_slice())
        .map_err(|error| RegistrationError::Decode(error.to_string()))?;

    if response.probe_id.is_empty() || response.host_id.is_empty() {
        return Err(RegistrationError::InvalidResponse(
            "missing Probe or Host identity",
        ));
    }

    let server_time_offset_ms = response.server_time_ms as i128
        - prepared
            .server_time_reference_ms
            .unwrap_or_else(current_unix_time_ms_i128);
    store_bootstrap_config(
        &input.bootstrap_config_path,
        &BootstrapConfig {
            enabled_collector_ids: response
                .initial_configuration
                .as_ref()
                .map(|configuration| {
                    normalize_initial_enabled_collector_ids(&configuration.enabled_collector_ids)
                }),
            enrollment_id: (!response.enrollment_id.is_empty())
                .then_some(response.enrollment_id.as_str()),
            hub_url: input.hub_url,
            host_id: response.host_id.as_str(),
            metrics_collection_interval_seconds: response.initial_configuration.as_ref().and_then(
                |configuration| {
                    (configuration.metrics_collection_interval_seconds > 0)
                        .then_some(configuration.metrics_collection_interval_seconds)
                },
            ),
            probe_configuration_version: response
                .initial_configuration
                .as_ref()
                .map(|configuration| configuration.version.as_str()),
            probe_id: response.probe_id.as_str(),
            probe_private_key_pem: prepared.private_key_pem.as_str(),
            server_time_offset_ms,
            installer_owned_fields,
        },
    )?;
    Ok(ProbeRegistrationOutcome {
        initial_probe_configuration_version: response
            .initial_configuration
            .map(|configuration| configuration.version),
        host_id: response.host_id,
        probe_id: response.probe_id,
    })
}

/// Reads the Hub-owned Enrollment target before the staged installer creates
/// an identity or changes local Probe resources.
pub fn inspect_probe_installation(
    input: ProbeInstallationInspectionInput,
    transport: &mut impl RegistrationTransport,
) -> Result<ProbeInstallationTarget, RegistrationError> {
    let request = ProbeRegistrationRequest {
        candidate_signature: Vec::new(),
        canonical_attempt: Vec::new(),
        enrollment_token: input.enrollment_token,
        installation_inspection: Some(ProbeInstallationInspection {}),
        installation_rejection: None,
        probe_public_key_pem: String::new(),
        snapshots: Vec::new(),
    };
    let response_body =
        transport.post_protobuf(&registration_url(&input.hub_url)?, request.encode_to_vec())?;
    let response = ProbeRegistrationResponse::decode(response_body.as_slice())
        .map_err(|error| RegistrationError::Decode(error.to_string()))?;
    let inspection = response
        .installation_inspection
        .ok_or(RegistrationError::InvalidResponse(
            "missing installation inspection",
        ))?;
    match ProbeEnrollmentTargetKind::try_from(inspection.target_kind).ok() {
        Some(ProbeEnrollmentTargetKind::NewHost) => Ok(ProbeInstallationTarget::NewHost),
        Some(ProbeEnrollmentTargetKind::ExistingHost) => Ok(ProbeInstallationTarget::ExistingHost),
        Some(ProbeEnrollmentTargetKind::ManualReinstall)
            if valid_replacement_inspection(&inspection, &input.hub_url) =>
        {
            Ok(ProbeInstallationTarget::ManualReinstall(
                ProbeReplacementAuthorization {
                    enrollment_id: inspection.enrollment_id,
                    host_id: inspection.target_host_id,
                    expected_hub_origin: inspection.expected_hub_origin,
                    expected_probe_id: inspection.expected_probe_id,
                    source_probe_version: inspection.source_probe_version,
                    source_probe_sha256: inspection.source_probe_sha256,
                    target_asset_set_digest: inspection.target_asset_set_digest,
                    target_probe_version: inspection.target_probe_version,
                },
            ))
        }
        Some(ProbeEnrollmentTargetKind::Unspecified) | None => Err(
            RegistrationError::InvalidResponse("invalid installation inspection target"),
        ),
        Some(ProbeEnrollmentTargetKind::ManualReinstall) => Err(
            RegistrationError::InvalidResponse("invalid manual reinstall authority"),
        ),
    }
}

fn valid_replacement_inspection(
    inspection: &crate::protocol::enoki::v1::ProbeInstallationInspectionResponse,
    requested_hub_url: &str,
) -> bool {
    hub_url::normalized_base(&inspection.expected_hub_origin).ok()
        == hub_url::normalized_base(requested_hub_url).ok()
        && valid_enrollment_id(&inspection.enrollment_id)
        && inspection
            .target_host_id
            .parse::<u64>()
            .is_ok_and(|id| id > 0)
        && bounded_identifier(&inspection.expected_probe_id)
        && valid_semver(&inspection.source_probe_version)
        && (1..=4).contains(&inspection.source_probe_sha256.len())
        && inspection.source_probe_sha256.iter().all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        && valid_semver(&inspection.target_probe_version)
        && inspection
            .target_asset_set_digest
            .strip_prefix("sha256:")
            .is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
}

fn valid_enrollment_id(value: &str) -> bool {
    value.strip_prefix("enr_").is_some_and(|suffix| {
        suffix.len() >= 16
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

fn bounded_identifier(value: &str) -> bool {
    (1..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_semver(value: &str) -> bool {
    let value = value.strip_prefix('v').unwrap_or(value);
    let mut parts = value.split('.');
    parts.clone().count() == 3
        && parts.all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'))
        })
}

/// Uses the existing registration endpoint to terminate the matching pending
/// Enrollment before a local lifecycle failure can produce an identity.
pub fn reject_probe_installation(
    input: ProbeInstallationRejectionInput,
    transport: &mut impl RegistrationTransport,
) -> Result<(), RegistrationError> {
    let request = prepare_probe_installation_rejection(input)?;
    submit_prepared_installation_rejection(&request, transport)
}

pub(crate) fn prepare_probe_installation_rejection(
    input: ProbeInstallationRejectionInput,
) -> Result<PreparedInstallationRejection, RegistrationError> {
    let request = ProbeRegistrationRequest {
        candidate_signature: Vec::new(),
        canonical_attempt: Vec::new(),
        enrollment_token: input.enrollment_token,
        installation_inspection: None,
        installation_rejection: Some(ProbeInstallationRejection {
            code: input.code,
            existing_probe_id: input.existing_probe_id,
            message: input.message,
        }),
        probe_public_key_pem: String::new(),
        snapshots: Vec::new(),
    };
    Ok(PreparedInstallationRejection {
        body: request.encode_to_vec(),
        url: registration_url(&input.hub_url)?,
    })
}

pub(crate) fn submit_prepared_installation_rejection(
    request: &PreparedInstallationRejection,
    transport: &mut impl RegistrationTransport,
) -> Result<(), RegistrationError> {
    transport.post_protobuf(&request.url, request.body.clone())?;
    Ok(())
}

fn registration_url(hub_url: &str) -> Result<String, RegistrationError> {
    hub_url::endpoint(hub_url, "/api/probe/register")
        .map_err(|()| RegistrationError::InvalidResponse("invalid Hub URL"))
}

fn current_unix_time_ms_i128() -> i128 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    now.as_millis() as i128
}

struct BootstrapConfig<'a> {
    enabled_collector_ids: Option<Vec<String>>,
    enrollment_id: Option<&'a str>,
    hub_url: String,
    host_id: &'a str,
    metrics_collection_interval_seconds: Option<u32>,
    probe_configuration_version: Option<&'a str>,
    probe_id: &'a str,
    probe_private_key_pem: &'a str,
    server_time_offset_ms: i128,
    installer_owned_fields: InstallerOwnedFields,
}

#[derive(Default)]
struct InstallerOwnedFields {
    bundle_version: Option<String>,
    install_path: Option<String>,
    install_state_sha256: Option<String>,
    log_level: Option<String>,
    operation_status_path: Option<String>,
    probe_asset_public_key_sha256: Option<String>,
    probe_distribution_root_sha256: Option<String>,
    target_manifest_sha256: Option<String>,
    bootstrap_acquirer_path: Option<String>,
    bootstrap_activator_path: Option<String>,
    bootstrap_state_dir: Option<String>,
    service_name: Option<String>,
    state_dir: Option<String>,
    upgrader_launch: Option<String>,
    registration_attempt: InstalledRegistrationAttempt,
}

fn read_installer_owned_fields(path: &Path) -> Result<InstallerOwnedFields, RegistrationError> {
    let read = if path == Path::new(SYSTEMD_BOOTSTRAP_CONFIG) {
        enoki_probe_bootstrap::secure_file::read_systemd_probe_bootstrap_config()
    } else {
        read_regular_file(path)
    };
    let contents = match read {
        Ok(contents) => String::from_utf8(contents)
            .map_err(|_| RegistrationError::InvalidResponse("invalid bootstrap config TOML"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InstallerOwnedFields::default());
        }
        Err(error) => return Err(RegistrationError::Io(error)),
    };
    let value = contents
        .parse::<toml::Value>()
        .map_err(|_| RegistrationError::InvalidResponse("invalid bootstrap config TOML"))?;

    Ok(InstallerOwnedFields {
        bundle_version: string_value(&value, "bundle_version")?,
        install_path: string_value(&value, "install_path")?,
        install_state_sha256: string_value(&value, "install_state_sha256")?,
        log_level: string_value(&value, "log_level")?,
        operation_status_path: string_value(&value, "operation_status_path")?,
        probe_asset_public_key_sha256: string_value(&value, "probe_asset_public_key_sha256")?,
        probe_distribution_root_sha256: string_value(&value, "probe_distribution_root_sha256")?,
        target_manifest_sha256: string_value(&value, "target_manifest_sha256")?,
        bootstrap_acquirer_path: string_value(&value, "bootstrap_acquirer_path")?,
        bootstrap_activator_path: string_value(&value, "bootstrap_activator_path")?,
        bootstrap_state_dir: string_value(&value, "bootstrap_state_dir")?,
        service_name: string_value(&value, "service_name")?,
        state_dir: string_value(&value, "state_dir")?,
        upgrader_launch: string_value(&value, "upgrader_launch")?,
        registration_attempt: InstalledRegistrationAttempt::read(&value)?,
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn store_bootstrap_config(
    path: &Path,
    config: &BootstrapConfig<'_>,
) -> Result<(), RegistrationError> {
    if path == Path::new(SYSTEMD_BOOTSTRAP_CONFIG)
        && config.installer_owned_fields.state_dir.as_deref() == Some(SYSTEMD_STATE_DIRECTORY)
    {
        enoki_probe_bootstrap::secure_file::atomic_write_systemd_probe_bootstrap_config(
            render_bootstrap_config(config).as_bytes(),
        )?;
        return Ok(());
    }
    atomic_write(
        path,
        render_bootstrap_config(config).as_bytes(),
        0o600,
        None,
    )?;

    Ok(())
}

fn render_bootstrap_config(config: &BootstrapConfig<'_>) -> String {
    let mut output = String::new();
    output.push_str(&format!("hub_url = {}\n", toml_string(&config.hub_url)));
    output.push_str(&format!("host_id = {}\n", toml_string(config.host_id)));
    output.push_str(&format!("probe_id = {}\n", toml_string(config.probe_id)));
    output.push_str(&format!(
        "probe_private_key_pem = {}\n",
        toml_string(config.probe_private_key_pem)
    ));
    output.push_str(&format!(
        "server_time_offset_ms = {}\n",
        config.server_time_offset_ms
    ));
    push_optional_string(&mut output, "enrollment_id", config.enrollment_id);
    push_optional_string(
        &mut output,
        "state_dir",
        config.installer_owned_fields.state_dir.as_deref(),
    );
    push_optional_string(
        &mut output,
        "operation_status_path",
        config
            .installer_owned_fields
            .operation_status_path
            .as_deref(),
    );
    push_optional_string(
        &mut output,
        "install_path",
        config.installer_owned_fields.install_path.as_deref(),
    );
    push_optional_string(
        &mut output,
        "service_name",
        config.installer_owned_fields.service_name.as_deref(),
    );
    push_optional_string(
        &mut output,
        "probe_asset_public_key_sha256",
        config
            .installer_owned_fields
            .probe_asset_public_key_sha256
            .as_deref(),
    );
    push_optional_string(
        &mut output,
        "probe_distribution_root_sha256",
        config
            .installer_owned_fields
            .probe_distribution_root_sha256
            .as_deref(),
    );
    push_optional_string(
        &mut output,
        "install_state_sha256",
        config
            .installer_owned_fields
            .install_state_sha256
            .as_deref(),
    );
    push_optional_string(
        &mut output,
        "target_manifest_sha256",
        config
            .installer_owned_fields
            .target_manifest_sha256
            .as_deref(),
    );
    push_optional_string(
        &mut output,
        "bundle_version",
        config.installer_owned_fields.bundle_version.as_deref(),
    );
    push_optional_string(
        &mut output,
        "bootstrap_acquirer_path",
        config
            .installer_owned_fields
            .bootstrap_acquirer_path
            .as_deref(),
    );
    push_optional_string(
        &mut output,
        "bootstrap_activator_path",
        config
            .installer_owned_fields
            .bootstrap_activator_path
            .as_deref(),
    );
    push_optional_string(
        &mut output,
        "bootstrap_state_dir",
        config.installer_owned_fields.bootstrap_state_dir.as_deref(),
    );
    push_optional_string(
        &mut output,
        "upgrader_launch",
        config.installer_owned_fields.upgrader_launch.as_deref(),
    );
    config
        .installer_owned_fields
        .registration_attempt
        .render(&mut output);
    push_optional_string(
        &mut output,
        "log_level",
        config.installer_owned_fields.log_level.as_deref(),
    );

    if let Some(version) = config.probe_configuration_version {
        output.push_str(&format!(
            "probe_configuration_version = {}\n",
            toml_string(version)
        ));
    }

    if let Some(metrics_collection_interval_seconds) = config.metrics_collection_interval_seconds {
        output.push_str(&format!(
            "metrics_collection_interval_seconds = {metrics_collection_interval_seconds}\n",
        ));
    }

    let default_collector_ids;
    let enabled_collector_ids = match config.enabled_collector_ids.as_deref() {
        Some(collector_ids) => collector_ids,
        None => {
            default_collector_ids = default_enabled_collector_ids();
            &default_collector_ids
        }
    };
    push_collector_ids(&mut output, enabled_collector_ids);

    output
}

fn default_enabled_collector_ids() -> Vec<String> {
    MetricsCollectionConfig::all_enabled()
        .enabled_collector_config_ids()
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn normalize_initial_enabled_collector_ids(collector_ids: &[String]) -> Vec<String> {
    collector_ids
        .iter()
        .filter(|collector_id| is_owner_configurable_collector_id(collector_id))
        .cloned()
        .collect()
}

fn push_collector_ids(output: &mut String, collector_ids: &[String]) {
    output.push_str("enabled_collector_ids = [");
    for (index, collector_id) in collector_ids.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        output.push_str(&toml_string(collector_id));
    }
    output.push_str("]\n");
}

fn push_optional_string(output: &mut String, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        output.push_str(&format!("{key} = {}\n", toml_string(value)));
    }
}

fn string_value(
    value: &toml::Value,
    key: &'static str,
) -> Result<Option<String>, RegistrationError> {
    match value.get(key) {
        Some(toml::Value::String(string)) => Ok(Some(string.clone())),
        Some(_) => Err(RegistrationError::InvalidResponse(
            "expected string bootstrap config values",
        )),
        None => Ok(None),
    }
}

fn toml_string(value: &str) -> String {
    let escaped = value
        .chars()
        .flat_map(|character| character.escape_default())
        .collect::<String>();

    format!("\"{escaped}\"")
}
