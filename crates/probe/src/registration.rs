use std::{
    error::Error,
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
};

use prost::Message;
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    rand_core::OsRng,
};

use crate::{
    inventory::collect_local_inventory,
    protocol::enoki::v1::{ProbeRegistrationRequest, ProbeRegistrationResponse},
};

#[derive(Debug, Eq, PartialEq)]
pub struct ProbeRegistrationInput {
    pub bootstrap_config_path: PathBuf,
    pub enrollment_token: String,
    pub hub_url: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProbeRegistrationOutcome {
    pub initial_probe_configuration_version: Option<String>,
    pub probe_id: String,
}

pub trait RegistrationTransport {
    fn post_protobuf(&mut self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, RegistrationError>;
}

#[derive(Debug)]
pub enum RegistrationError {
    Decode(String),
    Http(String),
    InvalidResponse(&'static str),
    Io(std::io::Error),
    KeyGeneration(String),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(message) => write!(
                formatter,
                "failed to decode registration response: {message}"
            ),
            Self::Http(message) => write!(formatter, "registration request failed: {message}"),
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
            Self::Io(error) => Some(error),
            Self::Decode(_) | Self::Http(_) | Self::InvalidResponse(_) | Self::KeyGeneration(_) => {
                None
            }
        }
    }
}

impl From<std::io::Error> for RegistrationError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct HttpRegistrationTransport;

impl RegistrationTransport for HttpRegistrationTransport {
    fn post_protobuf(&mut self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, RegistrationError> {
        let response = ureq::post(url)
            .set("accept", "application/x-protobuf")
            .set("content-type", "application/x-protobuf")
            .send_bytes(&body)
            .map_err(|error| RegistrationError::Http(error.to_string()))?;
        let mut bytes = Vec::new();
        response.into_reader().read_to_end(&mut bytes)?;

        Ok(bytes)
    }
}

pub fn register_probe(
    input: ProbeRegistrationInput,
    transport: &mut impl RegistrationTransport,
) -> Result<ProbeRegistrationOutcome, RegistrationError> {
    let signing_key = generate_probe_signing_key()?;
    let request = ProbeRegistrationRequest {
        enrollment_token: input.enrollment_token,
        inventory: Some(collect_local_inventory()),
        probe_public_key_pem: signing_key.public_key_pem.clone(),
    };
    let response_body =
        transport.post_protobuf(&registration_url(&input.hub_url), request.encode_to_vec())?;
    let response = ProbeRegistrationResponse::decode(response_body.as_slice())
        .map_err(|error| RegistrationError::Decode(error.to_string()))?;

    if response.probe_id.is_empty() {
        return Err(RegistrationError::InvalidResponse("missing Probe ID"));
    }

    let server_time_offset_ms = response.server_time_ms as i128 - current_unix_time_ms_i128();
    let installer_owned_fields = read_installer_owned_fields(&input.bootstrap_config_path)?;

    store_bootstrap_config(
        &input.bootstrap_config_path,
        &BootstrapConfig {
            collect_cpu: response
                .initial_configuration
                .as_ref()
                .map(|configuration| configuration.collect_cpu),
            collect_disk: response
                .initial_configuration
                .as_ref()
                .map(|configuration| configuration.collect_disk),
            collect_load: response
                .initial_configuration
                .as_ref()
                .map(|configuration| configuration.collect_load),
            collect_memory: response
                .initial_configuration
                .as_ref()
                .map(|configuration| configuration.collect_memory),
            collect_network: response
                .initial_configuration
                .as_ref()
                .map(|configuration| configuration.collect_network),
            collect_uptime: response
                .initial_configuration
                .as_ref()
                .map(|configuration| configuration.collect_uptime),
            hub_url: input.hub_url,
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
            reporting_batch_interval_seconds: response.initial_configuration.as_ref().and_then(
                |configuration| {
                    (configuration.reporting_batch_interval_seconds > 0)
                        .then_some(configuration.reporting_batch_interval_seconds)
                },
            ),
            probe_id: response.probe_id.as_str(),
            probe_private_key_pem: signing_key.private_key_pem.as_str(),
            server_time_offset_ms,
            installer_owned_fields,
        },
    )?;

    Ok(ProbeRegistrationOutcome {
        initial_probe_configuration_version: response
            .initial_configuration
            .map(|configuration| configuration.version),
        probe_id: response.probe_id,
    })
}

struct GeneratedProbeSigningKey {
    private_key_pem: String,
    public_key_pem: String,
}

fn generate_probe_signing_key() -> Result<GeneratedProbeSigningKey, RegistrationError> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|error| RegistrationError::KeyGeneration(error.to_string()))?;
    let public_key = private_key.to_public_key();
    let private_key_pem = private_key
        .to_pkcs8_pem(Default::default())
        .map_err(|error| RegistrationError::KeyGeneration(error.to_string()))?
        .to_string();
    let public_key_pem = public_key
        .to_public_key_pem(Default::default())
        .map_err(|error| RegistrationError::KeyGeneration(error.to_string()))?;

    Ok(GeneratedProbeSigningKey {
        private_key_pem,
        public_key_pem,
    })
}

fn registration_url(hub_url: &str) -> String {
    format!("{}/api/probe/register", hub_url.trim_end_matches('/'))
}

fn current_unix_time_ms_i128() -> i128 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    now.as_millis() as i128
}

struct BootstrapConfig<'a> {
    collect_cpu: Option<bool>,
    collect_disk: Option<bool>,
    collect_load: Option<bool>,
    collect_memory: Option<bool>,
    collect_network: Option<bool>,
    collect_uptime: Option<bool>,
    hub_url: String,
    metrics_collection_interval_seconds: Option<u32>,
    probe_configuration_version: Option<&'a str>,
    probe_id: &'a str,
    probe_private_key_pem: &'a str,
    reporting_batch_interval_seconds: Option<u32>,
    server_time_offset_ms: i128,
    installer_owned_fields: InstallerOwnedFields,
}

#[derive(Default)]
struct InstallerOwnedFields {
    install_path: Option<String>,
    log_level: Option<String>,
    operation_status_path: Option<String>,
    probe_asset_public_key_sha256: Option<String>,
    service_name: Option<String>,
    state_dir: Option<String>,
    upgrader_launch: Option<String>,
}

fn read_installer_owned_fields(path: &Path) -> Result<InstallerOwnedFields, RegistrationError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InstallerOwnedFields::default());
        }
        Err(error) => return Err(RegistrationError::Io(error)),
    };
    let value = contents
        .parse::<toml::Value>()
        .map_err(|_| RegistrationError::InvalidResponse("invalid bootstrap config TOML"))?;

    Ok(InstallerOwnedFields {
        install_path: string_value(&value, "install_path")?,
        log_level: string_value(&value, "log_level")?,
        operation_status_path: string_value(&value, "operation_status_path")?,
        probe_asset_public_key_sha256: string_value(&value, "probe_asset_public_key_sha256")?,
        service_name: string_value(&value, "service_name")?,
        state_dir: string_value(&value, "state_dir")?,
        upgrader_launch: string_value(&value, "upgrader_launch")?,
    })
}

fn store_bootstrap_config(
    path: &Path,
    config: &BootstrapConfig<'_>,
) -> Result<(), RegistrationError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    write_secret_file(path, render_bootstrap_config(config).as_bytes())?;

    Ok(())
}

fn render_bootstrap_config(config: &BootstrapConfig<'_>) -> String {
    let mut output = String::new();
    output.push_str(&format!("hub_url = {}\n", toml_string(&config.hub_url)));
    output.push_str(&format!("probe_id = {}\n", toml_string(config.probe_id)));
    output.push_str(&format!(
        "probe_private_key_pem = {}\n",
        toml_string(config.probe_private_key_pem)
    ));
    output.push_str(&format!(
        "server_time_offset_ms = {}\n",
        config.server_time_offset_ms
    ));
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
        "upgrader_launch",
        config.installer_owned_fields.upgrader_launch.as_deref(),
    );
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

    if let Some(reporting_batch_interval_seconds) = config.reporting_batch_interval_seconds {
        output.push_str(&format!(
            "reporting_batch_interval_seconds = {reporting_batch_interval_seconds}\n",
        ));
    }

    if let Some(metrics_collection_interval_seconds) = config.metrics_collection_interval_seconds {
        output.push_str(&format!(
            "metrics_collection_interval_seconds = {metrics_collection_interval_seconds}\n",
        ));
    }

    push_optional_bool(&mut output, "collect_cpu", config.collect_cpu);
    push_optional_bool(&mut output, "collect_memory", config.collect_memory);
    push_optional_bool(&mut output, "collect_disk", config.collect_disk);
    push_optional_bool(&mut output, "collect_network", config.collect_network);
    push_optional_bool(&mut output, "collect_load", config.collect_load);
    push_optional_bool(&mut output, "collect_uptime", config.collect_uptime);

    output
}

fn push_optional_bool(output: &mut String, key: &str, value: Option<bool>) {
    if let Some(value) = value {
        output.push_str(&format!("{key} = {value}\n"));
    }
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

#[cfg(unix)]
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};

    let mut file = OpenOptions::new()
        .create(true)
        .mode(0o600)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(contents)
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    fs::write(path, contents)
}
