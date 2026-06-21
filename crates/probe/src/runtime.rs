use std::{collections::HashSet, error::Error, fmt, fs, io::Read, path::PathBuf, time::Duration};

use crate::registration::{
    HttpRegistrationTransport, ProbeRegistrationInput, RegistrationError, RegistrationTransport,
    register_probe,
};
use crate::{
    inventory::collect_local_inventory,
    metrics::{MetricsCollectionConfig, MetricsCollector},
    protocol::enoki::v1::{
        ProbeConfigurationError, ProbeConfigurationRequest, ProbeConfigurationResponse,
        ProbeOperationAcknowledgement, ProbeOperationFailed, ProbeOperationRunning,
        ProbeOperationStatus, ProbeReportRequest, ProbeReportResponse, probe_operation::Operation,
        probe_operation_status::Status,
    },
    report::{full_inventory_report, regular_report, startup_report},
};
use prost::Message;

#[derive(Debug, Eq, PartialEq)]
pub struct ProbeRunInput {
    pub bootstrap_config_path: PathBuf,
}

#[derive(Debug)]
pub enum ProbeRunError {
    InvalidConfig(&'static str),
    Io(std::io::Error),
    Report(ReportError),
    Registration(RegistrationError),
}

impl fmt::Display for ProbeRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid Probe bootstrap config: {message}")
            }
            Self::Io(_) => write!(formatter, "failed to read Probe bootstrap config"),
            Self::Report(error) => write!(formatter, "{error}"),
            Self::Registration(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for ProbeRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidConfig(_) => None,
            Self::Io(error) => Some(error),
            Self::Report(error) => Some(error),
            Self::Registration(error) => Some(error),
        }
    }
}

impl From<RegistrationError> for ProbeRunError {
    fn from(error: RegistrationError) -> Self {
        Self::Registration(error)
    }
}

impl From<ReportError> for ProbeRunError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

pub trait ReportTransport {
    fn post_protobuf_with_bearer(
        &mut self,
        url: &str,
        bearer_secret: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError>;
}

pub trait ProbeTransport: RegistrationTransport + ReportTransport {}

pub trait ProbeRuntimeSleeper {
    fn sleep(&mut self, duration: Duration);
}

pub struct ThreadProbeRuntimeSleeper;

impl ProbeRuntimeSleeper for ThreadProbeRuntimeSleeper {
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunLoopControl {
    pub max_reports: Option<usize>,
}

impl RunLoopControl {
    pub fn forever() -> Self {
        Self { max_reports: None }
    }
}

pub fn run_loop_control_from_environment(
    get_env: impl FnOnce(&str) -> Option<String>,
) -> Result<RunLoopControl, ProbeRunError> {
    let Some(value) = get_env("ENOKI_PROBE_MAX_REPORTS") else {
        return Ok(RunLoopControl::forever());
    };

    let max_reports = value
        .parse::<usize>()
        .ok()
        .filter(|max_reports| *max_reports > 0)
        .ok_or(ProbeRunError::InvalidConfig(
            "ENOKI_PROBE_MAX_REPORTS must be a positive integer",
        ))?;

    Ok(RunLoopControl {
        max_reports: Some(max_reports),
    })
}

#[derive(Debug)]
pub enum ReportError {
    Decode(String),
    Http(String),
    InvalidResponse(&'static str),
    Io(std::io::Error),
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(message) => {
                write!(formatter, "failed to decode report response: {message}")
            }
            Self::Http(message) => write!(formatter, "report request failed: {message}"),
            Self::InvalidResponse(message) => {
                write!(formatter, "invalid report response: {message}")
            }
            Self::Io(error) => write!(formatter, "failed to read report response: {error}"),
        }
    }
}

impl Error for ReportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Decode(_) | Self::Http(_) | Self::InvalidResponse(_) => None,
        }
    }
}

impl From<std::io::Error> for ReportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct HttpReportTransport;

impl ReportTransport for HttpReportTransport {
    fn post_protobuf_with_bearer(
        &mut self,
        url: &str,
        bearer_secret: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        let response = ureq::post(url)
            .set("accept", "application/x-protobuf")
            .set("authorization", &format!("Bearer {bearer_secret}"))
            .set("content-type", "application/x-protobuf")
            .send_bytes(&body)
            .map_err(|error| ReportError::Http(error.to_string()))?;
        let mut bytes = Vec::new();
        response.into_reader().read_to_end(&mut bytes)?;

        Ok(bytes)
    }
}

impl ReportTransport for HttpRegistrationTransport {
    fn post_protobuf_with_bearer(
        &mut self,
        url: &str,
        bearer_secret: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        let mut transport = HttpReportTransport;
        transport.post_protobuf_with_bearer(url, bearer_secret, body)
    }
}

impl ProbeTransport for HttpRegistrationTransport {}

pub fn run_probe(
    input: ProbeRunInput,
    transport: &mut impl ProbeTransport,
) -> Result<(), ProbeRunError> {
    let mut sleeper = ThreadProbeRuntimeSleeper;

    run_probe_with_loop_control(input, transport, &mut sleeper, RunLoopControl::forever())
}

pub fn run_probe_with_loop_control(
    input: ProbeRunInput,
    transport: &mut impl ProbeTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
) -> Result<(), ProbeRunError> {
    let bootstrap_config = read_bootstrap_config(&input.bootstrap_config_path)?;

    if bootstrap_config.has_probe_identity() {
        run_reporting_loop(&bootstrap_config, transport, sleeper, control)?;
        return Ok(());
    }

    let Some(enrollment_token) = bootstrap_config.enrollment_token else {
        return Err(ProbeRunError::InvalidConfig(
            "missing Probe Identity or enrollment token",
        ));
    };
    let Some(hub_url) = bootstrap_config.hub_url else {
        return Err(ProbeRunError::InvalidConfig("missing Hub URL"));
    };

    register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: input.bootstrap_config_path.clone(),
            enrollment_token,
            hub_url,
        },
        transport,
    )?;

    let bootstrap_config = read_bootstrap_config(&input.bootstrap_config_path)?;
    run_reporting_loop(&bootstrap_config, transport, sleeper, control)?;

    Ok(())
}

fn run_reporting_loop(
    bootstrap_config: &BootstrapConfig,
    transport: &mut impl ReportTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
) -> Result<(), ReportError> {
    if report_limit_reached(0, control) {
        return Ok(());
    }

    let probe_id = bootstrap_config
        .probe_id
        .as_deref()
        .ok_or(ReportError::InvalidResponse("missing Probe ID"))?;
    let probe_secret =
        bootstrap_config
            .probe_secret
            .as_deref()
            .ok_or(ReportError::InvalidResponse(
                "missing Probe Identity secret",
            ))?;
    let hub_url = bootstrap_config
        .hub_url
        .as_deref()
        .ok_or(ReportError::InvalidResponse("missing Hub URL"))?;
    let probe_configuration_version = bootstrap_config
        .probe_configuration_version
        .as_deref()
        .unwrap_or("");
    let inventory = collect_local_inventory();
    let boot_id = new_boot_id();
    let mut active_configuration =
        ActiveProbeConfiguration::from_bootstrap(bootstrap_config, probe_configuration_version);
    let mut pending_configuration_error = None;
    let mut sequence = 1;
    let mut reports_sent = 0;
    let mut metrics_collector = MetricsCollector::default();
    let mut operation_reports = ProbeOperationReportQueue::default();
    let mut operation_runner = NoopProbeOperationRunner;
    let mut pending_report_body = None;
    let request = startup_report(
        probe_id,
        &boot_id,
        sequence,
        &active_configuration.version,
        inventory.clone(),
        Vec::new(),
    );
    let response = post_report(transport, hub_url, probe_secret, request.encode_to_vec())?;
    reports_sent += 1;
    if !report_limit_reached(reports_sent, control) {
        let outcome = apply_newer_configuration_if_needed(
            transport,
            hub_url,
            probe_id,
            probe_secret,
            active_configuration,
            &response,
        )?;
        active_configuration = outcome.active_configuration;
        pending_configuration_error = outcome.configuration_error;
        operation_reports.observe_response(&response, &mut operation_runner);
    }

    if response.inventory_needed {
        if report_limit_reached(reports_sent, control) {
            return Ok(());
        }

        sequence += 1;
        let request = full_inventory_report(
            probe_id,
            &boot_id,
            sequence,
            &active_configuration.version,
            inventory.clone(),
            Vec::new(),
        );
        let response = post_report(transport, hub_url, probe_secret, request.encode_to_vec())?;
        reports_sent += 1;
        if !report_limit_reached(reports_sent, control) {
            let outcome = apply_newer_configuration_if_needed(
                transport,
                hub_url,
                probe_id,
                probe_secret,
                active_configuration,
                &response,
            )?;
            active_configuration = outcome.active_configuration;
            pending_configuration_error = outcome.configuration_error;
            operation_reports.observe_response(&response, &mut operation_runner);
        }
    }

    while !report_limit_reached(reports_sent, control) {
        let request_body = if let Some(request_body) = pending_report_body.take() {
            sleeper.sleep(active_configuration.reporting_interval);
            request_body
        } else {
            let (sequence_start, sequence_end, metrics) = collect_observation_batch(
                sleeper,
                &active_configuration,
                &mut sequence,
                &mut metrics_collector,
            );

            let request = regular_report(
                probe_id,
                &boot_id,
                sequence_start,
                sequence_end,
                &active_configuration.version,
                &inventory,
                metrics,
            );
            let request = with_configuration_error(request, pending_configuration_error.take());
            let request = operation_reports.with_operation_reports(request);

            request.encode_to_vec()
        };
        let response = match post_report(transport, hub_url, probe_secret, request_body.clone()) {
            Ok(response) => response,
            Err(_) => {
                pending_report_body = Some(request_body);
                continue;
            }
        };
        reports_sent += 1;
        if !report_limit_reached(reports_sent, control) {
            let outcome = apply_newer_configuration_if_needed(
                transport,
                hub_url,
                probe_id,
                probe_secret,
                active_configuration,
                &response,
            )?;
            active_configuration = outcome.active_configuration;
            pending_configuration_error = outcome.configuration_error;
            operation_reports.observe_response(&response, &mut operation_runner);
        }

        if response.inventory_needed && !report_limit_reached(reports_sent, control) {
            sequence += 1;
            let request = full_inventory_report(
                probe_id,
                &boot_id,
                sequence,
                &active_configuration.version,
                inventory.clone(),
                Vec::new(),
            );
            let request = with_configuration_error(request, pending_configuration_error.take());
            let request = operation_reports.with_operation_reports(request);
            let request_body = request.encode_to_vec();
            let response = match post_report(transport, hub_url, probe_secret, request_body.clone())
            {
                Ok(response) => response,
                Err(_) => {
                    pending_report_body = Some(request_body);
                    continue;
                }
            };
            reports_sent += 1;
            if !report_limit_reached(reports_sent, control) {
                let outcome = apply_newer_configuration_if_needed(
                    transport,
                    hub_url,
                    probe_id,
                    probe_secret,
                    active_configuration,
                    &response,
                )?;
                active_configuration = outcome.active_configuration;
                pending_configuration_error = outcome.configuration_error;
                operation_reports.observe_response(&response, &mut operation_runner);
            }
        }
    }

    Ok(())
}

struct ProbeUpgradeRunnerInput<'a> {
    stdin: &'a str,
    operation: ProbeUpgradeRunnerOperationMetadata<'a>,
}

struct ProbeUpgradeRunnerOperationMetadata<'a> {
    current_probe_version: &'a str,
    operation_id: &'a str,
    target_probe_version: &'a str,
}

trait ProbeOperationRunner {
    fn run_probe_upgrade(&mut self, input: ProbeUpgradeRunnerInput<'_>) -> ProbeOperationFailed;
}

struct NoopProbeOperationRunner;

impl ProbeOperationRunner for NoopProbeOperationRunner {
    fn run_probe_upgrade(&mut self, input: ProbeUpgradeRunnerInput<'_>) -> ProbeOperationFailed {
        let _ = (
            input.operation.current_probe_version,
            input.operation.operation_id,
            input.operation.target_probe_version,
            input.stdin,
        );

        ProbeOperationFailed {
            error_code: "unsupported_installation".to_string(),
            message: "Probe Upgrader is not installed in this build.".to_string(),
        }
    }
}

#[derive(Default)]
struct ProbeOperationReportQueue {
    failed: Vec<(String, ProbeOperationFailed)>,
    seen_operation_ids: HashSet<String>,
    started: Vec<String>,
}

impl ProbeOperationReportQueue {
    fn observe_response(
        &mut self,
        response: &ProbeReportResponse,
        runner: &mut impl ProbeOperationRunner,
    ) {
        let Some(operation) = response.pending_operation.as_ref() else {
            return;
        };

        if operation.id.is_empty() || !self.seen_operation_ids.insert(operation.id.clone()) {
            return;
        }

        let Some(Operation::ProbeUpgrade(probe_upgrade)) = operation.operation.as_ref() else {
            return;
        };

        let failed = runner.run_probe_upgrade(ProbeUpgradeRunnerInput {
            stdin: &probe_upgrade.operation_token,
            operation: ProbeUpgradeRunnerOperationMetadata {
                current_probe_version: &probe_upgrade.current_probe_version,
                operation_id: &operation.id,
                target_probe_version: &probe_upgrade.target_probe_version,
            },
        });
        self.started.push(operation.id.clone());
        self.failed.push((operation.id.clone(), failed));
    }

    fn with_operation_reports(&mut self, mut request: ProbeReportRequest) -> ProbeReportRequest {
        for operation_id in self.started.drain(..) {
            request
                .operation_acknowledgements
                .push(ProbeOperationAcknowledgement {
                    operation_id: operation_id.clone(),
                });
            request.operation_statuses.push(ProbeOperationStatus {
                operation_id,
                status: Some(Status::Running(ProbeOperationRunning {})),
            });
        }

        if request.operation_statuses.is_empty() {
            for (operation_id, failed) in self.failed.drain(..) {
                request.operation_statuses.push(ProbeOperationStatus {
                    operation_id,
                    status: Some(Status::Failed(failed)),
                });
            }
        }

        request
    }
}

fn report_limit_reached(reports_sent: usize, control: RunLoopControl) -> bool {
    control
        .max_reports
        .is_some_and(|max_reports| reports_sent >= max_reports)
}

fn post_report(
    transport: &mut impl ReportTransport,
    hub_url: &str,
    probe_secret: &str,
    body: Vec<u8>,
) -> Result<ProbeReportResponse, ReportError> {
    let response_body =
        transport.post_protobuf_with_bearer(&report_url(hub_url), probe_secret, body)?;

    ProbeReportResponse::decode(response_body.as_slice())
        .map_err(|error| ReportError::Decode(error.to_string()))
}

fn collect_observation_batch(
    sleeper: &mut impl ProbeRuntimeSleeper,
    active_configuration: &ActiveProbeConfiguration,
    sequence: &mut u64,
    metrics_collector: &mut MetricsCollector,
) -> (u64, u64, Vec<crate::protocol::enoki::v1::MetricSample>) {
    let sequence_start = *sequence + 1;

    if !active_configuration.metrics_config.any_enabled() {
        sleeper.sleep(active_configuration.reporting_interval);
        *sequence += 1;

        return (sequence_start, *sequence, Vec::new());
    }

    let reporting_seconds = active_configuration.reporting_interval.as_secs();
    let collection_seconds = active_configuration
        .metrics_collection_interval
        .as_secs()
        .max(1);
    let sample_count = (reporting_seconds / collection_seconds).max(1);
    let mut elapsed_seconds = 0;
    let mut metrics = Vec::new();

    for _ in 0..sample_count {
        sleeper.sleep(active_configuration.metrics_collection_interval);
        elapsed_seconds += collection_seconds;
        *sequence += 1;
        metrics.push(metrics_collector.collect(*sequence, active_configuration.metrics_config));
    }

    if elapsed_seconds < reporting_seconds {
        sleeper.sleep(Duration::from_secs(reporting_seconds - elapsed_seconds));
    }

    (sequence_start, *sequence, metrics)
}

fn apply_newer_configuration_if_needed(
    transport: &mut impl ReportTransport,
    hub_url: &str,
    probe_id: &str,
    probe_secret: &str,
    active_configuration: ActiveProbeConfiguration,
    response: &ProbeReportResponse,
) -> Result<ConfigurationApplyOutcome, ReportError> {
    if response.current_probe_configuration_version.is_empty()
        || response.current_probe_configuration_version == active_configuration.version
    {
        return Ok(ConfigurationApplyOutcome {
            active_configuration,
            configuration_error: None,
        });
    }

    let configuration = match post_probe_configuration(
        transport,
        hub_url,
        probe_id,
        probe_secret,
        &active_configuration.version,
    ) {
        Ok(configuration) => configuration,
        Err(error) => {
            return Ok(ConfigurationApplyOutcome {
                active_configuration,
                configuration_error: Some(ProbeConfigurationError {
                    error_code: "probe_configuration_fetch_failed".to_string(),
                    failed_version: response.current_probe_configuration_version.clone(),
                    message: error.to_string(),
                }),
            });
        }
    };

    match ActiveProbeConfiguration::try_from_response(configuration) {
        Ok(active_configuration) => Ok(ConfigurationApplyOutcome {
            active_configuration,
            configuration_error: None,
        }),
        Err(error) => Ok(ConfigurationApplyOutcome {
            active_configuration,
            configuration_error: Some(ProbeConfigurationError {
                error_code: "invalid_probe_configuration".to_string(),
                failed_version: response.current_probe_configuration_version.clone(),
                message: error.to_string(),
            }),
        }),
    }
}

struct ConfigurationApplyOutcome {
    active_configuration: ActiveProbeConfiguration,
    configuration_error: Option<ProbeConfigurationError>,
}

fn with_configuration_error(
    mut request: ProbeReportRequest,
    error: Option<ProbeConfigurationError>,
) -> ProbeReportRequest {
    request.probe_configuration_error = error;
    request
}

fn post_probe_configuration(
    transport: &mut impl ReportTransport,
    hub_url: &str,
    probe_id: &str,
    probe_secret: &str,
    current_version: &str,
) -> Result<ProbeConfigurationResponse, ReportError> {
    let request = ProbeConfigurationRequest {
        current_version: current_version.to_string(),
        probe_id: probe_id.to_string(),
    };
    let response_body = transport.post_protobuf_with_bearer(
        &config_url(hub_url),
        probe_secret,
        request.encode_to_vec(),
    )?;

    ProbeConfigurationResponse::decode(response_body.as_slice())
        .map_err(|error| ReportError::Decode(error.to_string()))
}

#[derive(Clone, Debug)]
struct ActiveProbeConfiguration {
    metrics_collection_interval: Duration,
    metrics_config: MetricsCollectionConfig,
    reporting_interval: Duration,
    version: String,
}

impl ActiveProbeConfiguration {
    fn from_bootstrap(bootstrap_config: &BootstrapConfig, version: &str) -> Self {
        let metrics_collection_interval = bootstrap_config
            .metrics_collection_interval_seconds
            .unwrap_or(default_metrics_collection_interval_seconds());
        let reporting_batch_interval = bootstrap_config
            .reporting_batch_interval_seconds
            .unwrap_or(default_reporting_batch_interval_seconds());

        Self {
            metrics_collection_interval: Duration::from_secs(
                metrics_collection_interval.min(reporting_batch_interval),
            ),
            metrics_config: bootstrap_config.metrics_collection_config(),
            reporting_interval: Duration::from_secs(reporting_batch_interval),
            version: version.to_string(),
        }
    }

    fn try_from_response(configuration: ProbeConfigurationResponse) -> Result<Self, &'static str> {
        if configuration.version.is_empty() {
            return Err("missing Probe Configuration version");
        }

        let metrics_collection_interval =
            u64::from(configuration.metrics_collection_interval_seconds);
        let reporting_batch_interval = u64::from(configuration.reporting_batch_interval_seconds);

        if !(1..=300).contains(&metrics_collection_interval) {
            return Err("Metrics collection interval out of range");
        }

        if !(1..=600).contains(&reporting_batch_interval) {
            return Err("reporting batch interval out of range");
        }

        if reporting_batch_interval < metrics_collection_interval {
            return Err("reporting batch interval shorter than collection interval");
        }

        Ok(Self {
            metrics_collection_interval: Duration::from_secs(metrics_collection_interval),
            metrics_config: MetricsCollectionConfig {
                collect_cpu: configuration.collect_cpu,
                collect_disk: configuration.collect_disk,
                collect_load: configuration.collect_load,
                collect_memory: configuration.collect_memory,
                collect_network: configuration.collect_network,
                collect_uptime: configuration.collect_uptime,
            },
            reporting_interval: Duration::from_secs(reporting_batch_interval),
            version: configuration.version,
        })
    }
}

struct BootstrapConfig {
    collect_cpu: Option<bool>,
    collect_disk: Option<bool>,
    collect_load: Option<bool>,
    collect_memory: Option<bool>,
    collect_network: Option<bool>,
    collect_uptime: Option<bool>,
    enrollment_token: Option<String>,
    hub_url: Option<String>,
    metrics_collection_interval_seconds: Option<u64>,
    probe_configuration_version: Option<String>,
    probe_id: Option<String>,
    probe_secret: Option<String>,
    reporting_batch_interval_seconds: Option<u64>,
}

impl BootstrapConfig {
    fn has_probe_identity(&self) -> bool {
        self.probe_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            && self
                .probe_secret
                .as_deref()
                .is_some_and(|value| !value.is_empty())
    }

    fn metrics_collection_config(&self) -> MetricsCollectionConfig {
        let defaults = MetricsCollectionConfig::all_enabled();

        MetricsCollectionConfig {
            collect_cpu: self.collect_cpu.unwrap_or(defaults.collect_cpu),
            collect_disk: self.collect_disk.unwrap_or(defaults.collect_disk),
            collect_load: self.collect_load.unwrap_or(defaults.collect_load),
            collect_memory: self.collect_memory.unwrap_or(defaults.collect_memory),
            collect_network: self.collect_network.unwrap_or(defaults.collect_network),
            collect_uptime: self.collect_uptime.unwrap_or(defaults.collect_uptime),
        }
    }
}

fn read_bootstrap_config(path: &PathBuf) -> Result<BootstrapConfig, ProbeRunError> {
    let contents = fs::read_to_string(path).map_err(ProbeRunError::Io)?;
    let value = contents
        .parse::<toml::Value>()
        .map_err(|_| ProbeRunError::InvalidConfig("invalid TOML"))?;

    Ok(BootstrapConfig {
        collect_cpu: bool_value(&value, "collect_cpu")?,
        collect_disk: bool_value(&value, "collect_disk")?,
        collect_load: bool_value(&value, "collect_load")?,
        collect_memory: bool_value(&value, "collect_memory")?,
        collect_network: bool_value(&value, "collect_network")?,
        collect_uptime: bool_value(&value, "collect_uptime")?,
        enrollment_token: string_value(&value, "enrollment_token")?,
        hub_url: string_value(&value, "hub_url")?,
        metrics_collection_interval_seconds: integer_value(
            &value,
            "metrics_collection_interval_seconds",
        )?,
        probe_configuration_version: string_value(&value, "probe_configuration_version")?,
        probe_id: string_value(&value, "probe_id")?,
        probe_secret: string_value(&value, "probe_secret")?,
        reporting_batch_interval_seconds: integer_value(
            &value,
            "reporting_batch_interval_seconds",
        )?,
    })
}

fn default_reporting_batch_interval_seconds() -> u64 {
    15
}

fn default_metrics_collection_interval_seconds() -> u64 {
    5
}

fn report_url(hub_url: &str) -> String {
    format!("{}/api/probe/report", hub_url.trim_end_matches('/'))
}

fn config_url(hub_url: &str) -> String {
    format!("{}/api/probe/config", hub_url.trim_end_matches('/'))
}

fn new_boot_id() -> String {
    let mut bytes = [0_u8; 16];

    if fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_err()
    {
        bytes = fallback_boot_entropy();
    }

    format!("boot-{}", hex_bytes(&bytes))
}

fn fallback_boot_entropy() -> [u8; 16] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    nanos.to_le_bytes()
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn string_value(value: &toml::Value, key: &'static str) -> Result<Option<String>, ProbeRunError> {
    match value.get(key) {
        Some(toml::Value::String(string)) => Ok(Some(string.clone())),
        Some(_) => Err(ProbeRunError::InvalidConfig("expected string values")),
        None => Ok(None),
    }
}

fn integer_value(value: &toml::Value, key: &'static str) -> Result<Option<u64>, ProbeRunError> {
    match value.get(key) {
        Some(toml::Value::Integer(integer)) if *integer > 0 => Ok(Some(*integer as u64)),
        Some(toml::Value::Integer(_)) => Err(ProbeRunError::InvalidConfig(
            "expected positive integer values",
        )),
        Some(_) => Err(ProbeRunError::InvalidConfig("expected integer values")),
        None => Ok(None),
    }
}

fn bool_value(value: &toml::Value, key: &'static str) -> Result<Option<bool>, ProbeRunError> {
    match value.get(key) {
        Some(toml::Value::Boolean(boolean)) => Ok(Some(*boolean)),
        Some(_) => Err(ProbeRunError::InvalidConfig("expected boolean values")),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::enoki::v1::ProbeUpgradeOperation;

    #[derive(Default)]
    struct RecordingOperationRunner {
        observed_current_probe_version: Option<String>,
        observed_operation_id: Option<String>,
        observed_stdin: Option<String>,
        observed_target_probe_version: Option<String>,
    }

    impl ProbeOperationRunner for RecordingOperationRunner {
        fn run_probe_upgrade(
            &mut self,
            input: ProbeUpgradeRunnerInput<'_>,
        ) -> ProbeOperationFailed {
            self.observed_current_probe_version =
                Some(input.operation.current_probe_version.to_string());
            self.observed_operation_id = Some(input.operation.operation_id.to_string());
            self.observed_stdin = Some(input.stdin.to_string());
            self.observed_target_probe_version =
                Some(input.operation.target_probe_version.to_string());

            ProbeOperationFailed {
                error_code: "unsupported_installation".to_string(),
                message: "not installed".to_string(),
            }
        }
    }

    #[test]
    fn probe_operation_report_queue_passes_operation_token_to_runner_stdin() {
        let mut queue = ProbeOperationReportQueue::default();
        let mut runner = RecordingOperationRunner::default();
        let response = ProbeReportResponse {
            accepted_sequence_end: 1,
            current_probe_configuration_version: "default-v1".to_string(),
            inventory_needed: false,
            pending_operation: Some(crate::protocol::enoki::v1::ProbeOperation {
                id: "operation-01".to_string(),
                operation: Some(Operation::ProbeUpgrade(ProbeUpgradeOperation {
                    current_probe_version: "0.1.0".to_string(),
                    operation_token: "operation-token-01".to_string(),
                    target_probe_version: "0.2.0".to_string(),
                })),
            }),
            server_time_ms: 1_725_000_000_000,
        };

        queue.observe_response(&response, &mut runner);

        assert_eq!(runner.observed_stdin.as_deref(), Some("operation-token-01"));
        assert_eq!(
            runner.observed_operation_id.as_deref(),
            Some("operation-01")
        );
        assert_eq!(
            runner.observed_current_probe_version.as_deref(),
            Some("0.1.0")
        );
        assert_eq!(
            runner.observed_target_probe_version.as_deref(),
            Some("0.2.0")
        );
    }
}
