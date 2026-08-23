use std::{
    collections::HashSet,
    error::Error,
    fmt, fs,
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::PathBuf,
    time::Duration,
};

use enoki_probe_bootstrap::lifecycle::{
    LifecycleRequest, LifecycleResponse, LifecycleResultStatus, MAX_LIFECYCLE_REQUEST_BYTES,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub use crate::probe_auth::ProbeRequestAuth;
use crate::probe_auth::signed_probe_request_headers;
use crate::registration::{
    HttpRegistrationTransport, ProbeRegistrationInput, RegistrationError, RegistrationTransport,
    register_probe,
};
use crate::{
    collectors::{HOST_PROFILE_COLLECTOR_ID, is_owner_configurable_collector_id},
    hub_url,
    metrics::{CollectorId, MetricsCollectionConfig},
    observation_runtime::{
        ObservationClientError, ObservationWindowClient, SystemStateResourceAcquisitionFailure,
        UnixObservationRuntimeClient,
    },
    protocol::enoki::v1::{
        HostProfileSnapshot, ProbeConfigurationError, ProbeConfigurationRequest,
        ProbeConfigurationResponse, ProbeOperationFailed, ProbeOperationRunning,
        ProbeOperationStatus, ProbeReportResponse, probe_operation::Operation,
        probe_operation_status::Status,
    },
    report::{
        ObservationBatchInput, OperationReportProgress, SnapshotReplayInput, StartupReportInput,
        observation_batch_report, snapshot_replay_report, startup_report,
    },
    transport::{HttpAttemptError, post_protobuf},
};
use prost::Message;

const REPORTING_WINDOW_TICKS: u64 = 3;
type FinalizedObservationBatch = (
    u64,
    u64,
    Vec<crate::protocol::enoki::v1::MetricSample>,
    Vec<crate::protocol::enoki::v1::CpuResourceCollectionOutcome>,
    Option<HostProfileSnapshot>,
);
pub const PERMANENT_REPORT_EXIT_STATUS: i32 = 78;
#[derive(Debug, Eq, PartialEq)]
pub struct ProbeRunInput {
    pub bootstrap_config_path: PathBuf,
}

#[derive(Debug)]
pub enum ProbeRunError {
    InvalidConfig(&'static str),
    Io(std::io::Error),
    Notify(std::io::Error),
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
            Self::Notify(error) => write!(formatter, "failed to notify systemd readiness: {error}"),
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
            Self::Notify(error) => Some(error),
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
        match error {
            ReportError::InvalidConfig(message) => Self::InvalidConfig(message),
            error => Self::Report(error),
        }
    }
}

impl ProbeRunError {
    pub fn is_permanent_report_failure(&self) -> bool {
        matches!(self, Self::Report(error) if !error.is_transient())
    }
}

pub fn probe_run_exit_status(error: &ProbeRunError) -> i32 {
    if error.is_permanent_report_failure() {
        PERMANENT_REPORT_EXIT_STATUS
    } else {
        1
    }
}

pub trait ReportTransport {
    fn post_protobuf_with_auth(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
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
    Attempt(HttpAttemptError),
    Decode(String),
    InvalidConfig(&'static str),
    InvalidResponse(&'static str),
    InvalidSigningKey(String),
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attempt(error) => write!(formatter, "report request failed: {error}"),
            Self::Decode(message) => {
                write!(formatter, "failed to decode report response: {message}")
            }
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid Probe bootstrap config: {message}")
            }
            Self::InvalidResponse(message) => {
                write!(formatter, "invalid report response: {message}")
            }
            Self::InvalidSigningKey(message) => {
                write!(formatter, "invalid Probe signing key: {message}")
            }
        }
    }
}

impl Error for ReportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Attempt(error) => Some(error),
            Self::Decode(_)
            | Self::InvalidConfig(_)
            | Self::InvalidResponse(_)
            | Self::InvalidSigningKey(_) => None,
        }
    }
}

impl ReportError {
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Attempt(error) => error.is_transient(),
            Self::Decode(_)
            | Self::InvalidConfig(_)
            | Self::InvalidResponse(_)
            | Self::InvalidSigningKey(_) => false,
        }
    }
}

pub struct HttpReportTransport;

impl ReportTransport for HttpReportTransport {
    fn post_protobuf_with_auth(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        let headers = signed_probe_request_headers("POST", url, auth, &body)
            .map_err(ReportError::InvalidSigningKey)?
            .into_iter()
            .map(|(name, value)| (name as &str, value))
            .collect::<Vec<_>>();
        post_protobuf(url, &body, &headers).map_err(ReportError::Attempt)
    }
}

impl ReportTransport for HttpRegistrationTransport {
    fn post_protobuf_with_auth(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        let mut transport = HttpReportTransport;
        transport.post_protobuf_with_auth(url, auth, body)
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
    let observation_runtime = UnixObservationRuntimeClient::production();
    run_probe_with_loop_control_and_runner_factory_and_notifier_and_observation_client(
        input,
        transport,
        sleeper,
        control,
        LifecycleCompanionOperationRunner::from_bootstrap,
        notify_systemd_ready,
        &observation_runtime,
    )
}

#[doc(hidden)]
pub fn run_probe_with_loop_control_and_observation_client(
    input: ProbeRunInput,
    transport: &mut impl ProbeTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
    observation_runtime: &impl ObservationWindowClient,
) -> Result<(), ProbeRunError> {
    run_probe_with_loop_control_and_runner_factory_and_notifier_and_observation_client(
        input,
        transport,
        sleeper,
        control,
        LifecycleCompanionOperationRunner::from_bootstrap,
        notify_systemd_ready,
        observation_runtime,
    )
}

#[cfg(test)]
fn run_probe_with_loop_control_and_runner_factory<Runner>(
    input: ProbeRunInput,
    transport: &mut impl ProbeTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
    runner_factory: impl FnMut(&BootstrapConfig, PathBuf) -> Runner,
) -> Result<(), ProbeRunError>
where
    Runner: ProbeOperationRunner,
{
    let observation_runtime = UnixObservationRuntimeClient::production();
    run_probe_with_loop_control_and_runner_factory_and_notifier_and_observation_client(
        input,
        transport,
        sleeper,
        control,
        runner_factory,
        notify_systemd_ready,
        &observation_runtime,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_probe_with_loop_control_and_runner_factory_and_notifier_and_observation_client<Runner>(
    input: ProbeRunInput,
    transport: &mut impl ProbeTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
    runner_factory: impl FnMut(&BootstrapConfig, PathBuf) -> Runner,
    notify_ready: impl FnMut() -> Result<(), std::io::Error>,
    observation_runtime: &impl ObservationWindowClient,
) -> Result<(), ProbeRunError>
where
    Runner: ProbeOperationRunner,
{
    run_probe_with_loop_control_and_runner_factory_and_notifier(
        input,
        transport,
        sleeper,
        control,
        runner_factory,
        notify_ready,
        observation_runtime,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_probe_with_loop_control_and_runner_factory_and_notifier<Runner>(
    input: ProbeRunInput,
    transport: &mut impl ProbeTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
    mut runner_factory: impl FnMut(&BootstrapConfig, PathBuf) -> Runner,
    mut notify_ready: impl FnMut() -> Result<(), std::io::Error>,
    observation_runtime: &impl ObservationWindowClient,
) -> Result<(), ProbeRunError>
where
    Runner: ProbeOperationRunner,
{
    let bootstrap_config = read_bootstrap_config(&input.bootstrap_config_path)?;

    if bootstrap_config.has_probe_identity() {
        let mut operation_runner =
            runner_factory(&bootstrap_config, input_bootstrap_path(&bootstrap_config));
        run_reporting_loop(
            &bootstrap_config,
            transport,
            sleeper,
            control,
            &mut operation_runner,
            &mut notify_ready,
            observation_runtime,
        )?;
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
    let mut operation_runner =
        runner_factory(&bootstrap_config, input_bootstrap_path(&bootstrap_config));
    run_reporting_loop(
        &bootstrap_config,
        transport,
        sleeper,
        control,
        &mut operation_runner,
        &mut notify_ready,
        observation_runtime,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_reporting_loop(
    bootstrap_config: &BootstrapConfig,
    transport: &mut impl ReportTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
    operation_runner: &mut impl ProbeOperationRunner,
    notify_ready: &mut impl FnMut() -> Result<(), std::io::Error>,
    observation_runtime: &impl ObservationWindowClient,
) -> Result<(), ProbeRunError> {
    if report_limit_reached(0, control) {
        return Ok(());
    }

    let probe_id = bootstrap_config
        .probe_id
        .as_deref()
        .ok_or(ReportError::InvalidResponse("missing Probe ID"))?;
    let mut request_auth = ProbeRequestAuth {
        probe_id,
        probe_private_key_pem: bootstrap_config
            .probe_private_key_pem
            .as_deref()
            .ok_or(ReportError::InvalidResponse("missing Probe signing key"))?,
        server_time_offset_ms: bootstrap_config.server_time_offset_ms.unwrap_or(0),
    };
    let hub_url = bootstrap_config
        .hub_url
        .as_deref()
        .ok_or(ReportError::InvalidResponse("missing Hub URL"))?;
    let probe_configuration_version = bootstrap_config
        .probe_configuration_version
        .as_deref()
        .unwrap_or("");
    let mut host_profile: Option<HostProfileSnapshot> = None;
    let mut full_host_profile_reported = false;
    let boot_id = new_boot_id();
    let local_operation_statuses = read_local_operation_statuses(bootstrap_config);
    let mut active_configuration =
        ActiveProbeConfiguration::from_bootstrap(bootstrap_config, probe_configuration_version)?;
    let mut pending_configuration_error = None;
    let mut sequence = 1;
    let mut reports_sent = 0;
    let mut operation_reports = ProbeOperationReportQueue::default();
    let request = startup_report(StartupReportInput {
        boot_id: &boot_id,
        enrollment_id: bootstrap_config
            .enrollment_id
            .as_deref()
            .unwrap_or_default(),
        operation_progress: OperationReportProgress::from_statuses(local_operation_statuses),
        probe_configuration_version: &active_configuration.version,
        probe_id,
    });
    let response = post_startup_report_until_accepted(
        transport,
        hub_url,
        &request_auth,
        request.encode_to_vec(),
        sleeper,
    )?;
    notify_ready().map_err(ProbeRunError::Notify)?;
    refresh_probe_request_auth(&mut request_auth, &response);
    reports_sent += 1;
    if !report_limit_reached(reports_sent, control) {
        let outcome = apply_newer_configuration_if_needed(
            transport,
            hub_url,
            probe_id,
            &request_auth,
            active_configuration,
            &response,
        )?;
        active_configuration = outcome.active_configuration;
        pending_configuration_error = outcome.configuration_error;
        operation_reports.observe_response(&response, operation_runner);
    }

    while !report_limit_reached(reports_sent, control) {
        let collected =
            collect_observation_batch(&active_configuration, &mut sequence, observation_runtime);
        let (
            sequence_start,
            sequence_end,
            metrics,
            cpu_resource_collection_outcomes,
            runtime_host_profile,
            observation_window_failure,
        ) = match collected {
            Ok((sequence_start, sequence_end, metrics, cpu_outcome, profile)) => (
                sequence_start,
                sequence_end,
                metrics,
                cpu_outcome,
                profile,
                None,
            ),
            Err(error) => {
                let failure_sequence = sequence.saturating_add(1);
                sequence = failure_sequence;
                let reason = match error {
                    ObservationClientError::BundleIncoherent => crate::protocol::enoki::v1::ObservationWindowFailureReason::ProbeAssetBundleIncoherent,
                    ObservationClientError::Unavailable => crate::protocol::enoki::v1::ObservationWindowFailureReason::ObservationRuntimeUnavailable,
                    ObservationClientError::InvalidRequest | ObservationClientError::InvalidResponse | ObservationClientError::WindowFailed => crate::protocol::enoki::v1::ObservationWindowFailureReason::ObservationRuntimeInvalidResponse,
                };
                (
                    failure_sequence,
                    failure_sequence,
                    Vec::new(),
                    Vec::new(),
                    None,
                    Some(crate::protocol::enoki::v1::ObservationWindowFailure {
                        reason: reason as i32,
                    }),
                )
            }
        };
        let observation_window_failed = observation_window_failure.is_some();

        if let Some(profile) = runtime_host_profile.as_ref() {
            host_profile = Some(profile.clone());
        }
        let send_full_host_profile = runtime_host_profile.is_some() && !full_host_profile_reported;

        let request = observation_batch_report(ObservationBatchInput {
            boot_id: &boot_id,
            enrollment_id: bootstrap_config
                .enrollment_id
                .as_deref()
                .unwrap_or_default(),
            cpu_resource_collection_outcomes,
            host_profile: runtime_host_profile.as_ref(),
            host_profile_is_full: send_full_host_profile,
            metrics,
            observation_window_failure,
            operation_progress: operation_reports.take_progress(),
            probe_configuration_error: pending_configuration_error.take(),
            probe_configuration_version: &active_configuration.version,
            probe_id,
            sequence_end,
            sequence_start,
        });

        let response = post_report_with_transient_retry(
            transport,
            hub_url,
            &request_auth,
            request.encode_to_vec(),
            sequence_end,
            sleeper,
            active_configuration.reporting_interval,
        )?;
        refresh_probe_request_auth(&mut request_auth, &response);
        full_host_profile_reported |= send_full_host_profile;
        reports_sent += 1;
        if !report_limit_reached(reports_sent, control) {
            let outcome = apply_newer_configuration_if_needed(
                transport,
                hub_url,
                probe_id,
                &request_auth,
                active_configuration,
                &response,
            )?;
            active_configuration = outcome.active_configuration;
            pending_configuration_error = outcome.configuration_error;
            operation_reports.observe_response(&response, operation_runner);
        }

        if host_profile_snapshot_requested(&response)
            && !report_limit_reached(reports_sent, control)
            && let Some(host_profile) = host_profile.clone()
        {
            // Replay supplements the accepted Observation Batch and preserves
            // its sequence end; the next collection advances from that batch.
            let request = snapshot_replay_report(SnapshotReplayInput {
                boot_id: &boot_id,
                host_profile,
                probe_configuration_version: &active_configuration.version,
                probe_id,
                sequence,
            });
            let response = post_report_with_transient_retry(
                transport,
                hub_url,
                &request_auth,
                request.encode_to_vec(),
                sequence,
                sleeper,
                active_configuration.reporting_interval,
            )?;
            refresh_probe_request_auth(&mut request_auth, &response);
            reports_sent += 1;
            if !report_limit_reached(reports_sent, control) {
                let outcome = apply_newer_configuration_if_needed(
                    transport,
                    hub_url,
                    probe_id,
                    &request_auth,
                    active_configuration,
                    &response,
                )?;
                active_configuration = outcome.active_configuration;
                pending_configuration_error = outcome.configuration_error;
                operation_reports.observe_response(&response, operation_runner);
            }
        }

        if observation_window_failed && !report_limit_reached(reports_sent, control) {
            sleeper.sleep(active_configuration.metrics_collection_interval);
        }
    }

    Ok(())
}

fn refresh_probe_request_auth(auth: &mut ProbeRequestAuth<'_>, response: &ProbeReportResponse) {
    if response.server_time_ms == 0 {
        return;
    }

    let Some(now_ms) = current_unix_time_ms_i128() else {
        return;
    };
    let offset = i128::from(response.server_time_ms) - now_ms;
    auth.server_time_offset_ms = offset.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
}

fn host_profile_snapshot_requested(response: &ProbeReportResponse) -> bool {
    response
        .requested_snapshot_collector_ids
        .iter()
        .any(|collector_id| collector_id == HOST_PROFILE_COLLECTOR_ID)
}

fn current_unix_time_ms_i128() -> Option<i128> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i128::try_from(duration.as_millis()).ok())
}

fn input_bootstrap_path(bootstrap_config: &BootstrapConfig) -> PathBuf {
    bootstrap_config
        .bootstrap_config_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("/var/lib/enoki-probe/identity/probe-bootstrap.toml"))
}

struct ProbeUpgradeRunnerInput<'a> {
    stdin: &'a str,
    operation: ProbeUpgradeRunnerOperationMetadata<'a>,
}

struct ProbeUpgradeRunnerOperationMetadata<'a> {
    current_probe_version: &'a str,
    host_id: &'a str,
    operation_id: &'a str,
    target_asset_set_digest: &'a str,
    target_probe_version: &'a str,
}

struct ProbeUninstallRunnerInput<'a> {
    stdin: &'a str,
    operation_id: &'a str,
}

enum ProbeUpgradeRunnerOutcome {
    Running,
    Failed(ProbeOperationFailed),
}

trait ProbeOperationRunner {
    fn run_probe_upgrade(
        &mut self,
        input: ProbeUpgradeRunnerInput<'_>,
    ) -> ProbeUpgradeRunnerOutcome;

    fn run_probe_uninstall(
        &mut self,
        input: ProbeUninstallRunnerInput<'_>,
    ) -> ProbeUpgradeRunnerOutcome;
}

const LIFECYCLE_COMPANION_SOCKET: &str = "/run/enoki-probe-lifecycle-companion.sock";
const LIFECYCLE_UPGRADE_SOCKET: &str = "/run/enoki-probe-lifecycle-upgrade.sock";

struct ProbeUpgradeAcquisitionInput<'a> {
    host_id: &'a str,
    operation_id: &'a str,
    operation_token: &'a str,
    target_asset_set_digest: &'a str,
    target_probe_version: &'a str,
}

trait ProbeUpgradeAcquisitionPort {
    fn acquire(
        &mut self,
        input: ProbeUpgradeAcquisitionInput<'_>,
    ) -> Result<enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt, &'static str>;
}

struct HttpProbeUpgradeAcquisition {
    hub_origin: String,
    probe_id: String,
    probe_private_key_pem: String,
    server_time_offset_ms: i64,
}

impl ProbeUpgradeAcquisitionPort for HttpProbeUpgradeAcquisition {
    fn acquire(
        &mut self,
        input: ProbeUpgradeAcquisitionInput<'_>,
    ) -> Result<enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt, &'static str> {
        let url = hub_url::endpoint(
            &self.hub_origin,
            &format!(
                "/api/probe/operations/{}/token/validate",
                input.operation_id
            ),
        )
        .map_err(|_| "lifecycle.invalid_authority")?;
        let body = serde_json::to_vec(&serde_json::json!({
            "hostId": input.host_id,
            "targetAssetSetDigest": input.target_asset_set_digest,
            "targetProbeVersion": input.target_probe_version,
            "token": input.operation_token,
        }))
        .map_err(|_| "lifecycle.invalid_authority")?;
        let auth = ProbeRequestAuth {
            probe_id: &self.probe_id,
            probe_private_key_pem: &self.probe_private_key_pem,
            server_time_offset_ms: self.server_time_offset_ms,
        };
        let headers = signed_probe_request_headers("POST", &url, &auth, &body)
            .map_err(|_| "lifecycle.invalid_authority")?;
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(Duration::from_secs(30))
            .build();
        let mut request = agent
            .post(&url)
            .set("accept", "application/json")
            .set("content-type", "application/json");
        for (name, value) in headers {
            request = request.set(name, &value);
        }
        let response = request
            .send_bytes(&body)
            .map_err(|_| "lifecycle.authority_rejected")?;
        if response.status() != 200 {
            return Err("lifecycle.authority_rejected");
        }
        let mut response_bytes = Vec::new();
        response
            .into_reader()
            .take(16 * 1024 + 1)
            .read_to_end(&mut response_bytes)
            .map_err(|_| "lifecycle.authority_rejected")?;
        if response_bytes.len() > 16 * 1024
            || serde_json::from_slice::<serde_json::Value>(&response_bytes)
                .ok()
                .and_then(|value| value.get("valid").and_then(serde_json::Value::as_bool))
                != Some(true)
        {
            return Err("lifecycle.authority_rejected");
        }
        enoki_probe_bootstrap::acquisition::acquire_probe_upgrade_once(
            enoki_probe_bootstrap::acquisition::ProbeUpgradeAcquisition {
                hub_origin: self.hub_origin.clone(),
                operation_id: input.operation_id.to_owned(),
                target_asset_set_digest: input.target_asset_set_digest.to_owned(),
                target_version: input.target_probe_version.to_owned(),
            },
        )
        .map_err(|failure| match failure {
            enoki_probe_bootstrap::acquisition::AcquisitionFailure::Permanent => {
                "lifecycle.upgrade_candidate_invalid"
            }
            _ => "lifecycle.upgrade_acquisition_failed",
        })
    }
}

struct DisabledProbeUpgradeAcquisition;

impl ProbeUpgradeAcquisitionPort for DisabledProbeUpgradeAcquisition {
    fn acquire(
        &mut self,
        _: ProbeUpgradeAcquisitionInput<'_>,
    ) -> Result<enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt, &'static str> {
        Err("lifecycle.install_receipt_missing")
    }
}

struct LifecycleCompanionOperationRunner {
    probe_id: Option<String>,
    install_state_sha256: Option<String>,
    target_manifest_sha256: Option<String>,
    bundle_version: Option<String>,
    socket_path: PathBuf,
    upgrade_socket_path: PathBuf,
    upgrade_acquisition: Box<dyn ProbeUpgradeAcquisitionPort>,
}

impl LifecycleCompanionOperationRunner {
    fn from_bootstrap(bootstrap_config: &BootstrapConfig, _bootstrap_config_path: PathBuf) -> Self {
        let upgrade_acquisition: Box<dyn ProbeUpgradeAcquisitionPort> = bootstrap_config
            .hub_url
            .as_deref()
            .zip(bootstrap_config.probe_id.as_deref())
            .zip(bootstrap_config.probe_private_key_pem.as_deref())
            .map_or_else(
                || {
                    Box::new(DisabledProbeUpgradeAcquisition)
                        as Box<dyn ProbeUpgradeAcquisitionPort>
                },
                |((hub_origin, probe_id), private_key)| {
                    Box::new(HttpProbeUpgradeAcquisition {
                        hub_origin: hub_origin.to_owned(),
                        probe_id: probe_id.to_owned(),
                        probe_private_key_pem: private_key.to_owned(),
                        server_time_offset_ms: bootstrap_config.server_time_offset_ms.unwrap_or(0),
                    })
                },
            );
        Self {
            probe_id: bootstrap_config.probe_id.clone(),
            install_state_sha256: bootstrap_config.install_state_sha256.clone(),
            target_manifest_sha256: bootstrap_config.target_manifest_sha256.clone(),
            bundle_version: bootstrap_config.bundle_version.clone(),
            socket_path: PathBuf::from(LIFECYCLE_COMPANION_SOCKET),
            upgrade_socket_path: PathBuf::from(LIFECYCLE_UPGRADE_SOCKET),
            upgrade_acquisition,
        }
    }
}

impl ProbeOperationRunner for LifecycleCompanionOperationRunner {
    fn run_probe_upgrade(
        &mut self,
        input: ProbeUpgradeRunnerInput<'_>,
    ) -> ProbeUpgradeRunnerOutcome {
        let Some((probe_id, install_state, source_manifest, source_version)) = self
            .probe_id
            .as_deref()
            .zip(self.install_state_sha256.as_deref())
            .zip(self.target_manifest_sha256.as_deref())
            .zip(self.bundle_version.as_deref())
            .map(|(((probe_id, install_state), manifest), version)| {
                (probe_id, install_state, manifest, version)
            })
        else {
            return lifecycle_companion_failure("lifecycle.install_receipt_missing");
        };
        if source_version != input.operation.current_probe_version {
            return lifecycle_companion_failure("lifecycle.authority_mismatch");
        }
        let stage = match self
            .upgrade_acquisition
            .acquire(ProbeUpgradeAcquisitionInput {
                host_id: input.operation.host_id,
                operation_id: input.operation.operation_id,
                operation_token: input.stdin,
                target_asset_set_digest: input.operation.target_asset_set_digest,
                target_probe_version: input.operation.target_probe_version,
            }) {
            Ok(stage) => stage,
            Err(code) => return lifecycle_companion_failure(code),
        };
        let Ok(request) = LifecycleRequest::hub_upgrade(
            input.operation.host_id,
            probe_id,
            input.operation.operation_id,
            input.stdin,
            source_version,
            install_state,
            source_manifest,
            &stage.target_version,
            &stage.target_asset_set_digest,
            &stage.target_manifest_sha256,
            &stage.verified_stage_sha256,
        ) else {
            return lifecycle_companion_failure("lifecycle.invalid_authority");
        };
        match request_lifecycle_companion_at(&self.upgrade_socket_path, &request) {
            Ok(response) if response.status() == LifecycleResultStatus::Succeeded => {
                ProbeUpgradeRunnerOutcome::Running
            }
            Ok(response) => lifecycle_companion_failure(response.code()),
            Err(()) => lifecycle_companion_failure("lifecycle.companion_unavailable"),
        }
    }

    fn run_probe_uninstall(
        &mut self,
        input: ProbeUninstallRunnerInput<'_>,
    ) -> ProbeUpgradeRunnerOutcome {
        let Some((probe_id, install_state, manifest, version)) = self
            .probe_id
            .as_deref()
            .zip(self.install_state_sha256.as_deref())
            .zip(self.target_manifest_sha256.as_deref())
            .zip(self.bundle_version.as_deref())
            .map(|(((probe_id, install_state), manifest), version)| {
                (probe_id, install_state, manifest, version)
            })
        else {
            return lifecycle_companion_failure("lifecycle.install_receipt_missing");
        };
        let Ok(request) = LifecycleRequest::hub_uninstall(
            probe_id,
            input.operation_id,
            input.stdin,
            install_state,
            manifest,
            version,
        ) else {
            return lifecycle_companion_failure("lifecycle.invalid_authority");
        };
        match request_lifecycle_companion_at(&self.socket_path, &request) {
            Ok(response) if response.status() == LifecycleResultStatus::Succeeded => {
                ProbeUpgradeRunnerOutcome::Running
            }
            Ok(response) => lifecycle_companion_failure(response.code()),
            Err(()) => lifecycle_companion_failure("lifecycle.companion_unavailable"),
        }
    }
}

fn request_lifecycle_companion_at(
    socket_path: &std::path::Path,
    request: &LifecycleRequest,
) -> Result<LifecycleResponse, ()> {
    let mut stream = UnixStream::connect(socket_path).map_err(|_| ())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(90)))
        .map_err(|_| ())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ())?;
    stream
        .write_all(&request.encode().map_err(|_| ())?)
        .map_err(|_| ())?;
    stream.shutdown(Shutdown::Write).map_err(|_| ())?;
    let mut bytes = Vec::new();
    stream
        .take(MAX_LIFECYCLE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    LifecycleResponse::decode(&bytes).map_err(|_| ())
}

pub fn request_local_probe_uninstall() -> Result<(), &'static str> {
    let config = read_bootstrap_config(&PathBuf::from(
        "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
    ))
    .map_err(|_| "lifecycle.identity_invalid")?;
    let Some((probe_id, install_state, manifest, version)) = config
        .probe_id
        .as_deref()
        .zip(config.install_state_sha256.as_deref())
        .zip(config.target_manifest_sha256.as_deref())
        .zip(config.bundle_version.as_deref())
        .map(|(((probe_id, install_state), manifest), version)| {
            (probe_id, install_state, manifest, version)
        })
    else {
        return Err("lifecycle.install_receipt_missing");
    };
    let request = LifecycleRequest::local_uninstall(probe_id, install_state, manifest, version)
        .map_err(|_| "lifecycle.invalid_authority")?;
    let response =
        request_lifecycle_companion_at(std::path::Path::new(LIFECYCLE_COMPANION_SOCKET), &request)
            .map_err(|_| "lifecycle.companion_unavailable")?;
    match response.status() {
        LifecycleResultStatus::Succeeded => Ok(()),
        LifecycleResultStatus::Failed | LifecycleResultStatus::NotEnabled => {
            Err("lifecycle.uninstall_failed")
        }
    }
}

fn lifecycle_companion_failure(code: &str) -> ProbeUpgradeRunnerOutcome {
    ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
        error_code: code.to_owned(),
        message: "The local Probe lifecycle operation failed.".to_owned(),
    })
}

#[derive(Default)]
struct ProbeOperationReportQueue {
    seen_operation_ids: HashSet<String>,
    statuses: Vec<(String, Status)>,
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

        let outcome = match operation.operation.as_ref() {
            Some(Operation::ProbeUpgrade(probe_upgrade)) => {
                runner.run_probe_upgrade(ProbeUpgradeRunnerInput {
                    stdin: &probe_upgrade.operation_token,
                    operation: ProbeUpgradeRunnerOperationMetadata {
                        current_probe_version: &probe_upgrade.current_probe_version,
                        host_id: &probe_upgrade.host_id,
                        operation_id: &operation.id,
                        target_asset_set_digest: &probe_upgrade.target_asset_set_digest,
                        target_probe_version: &probe_upgrade.target_probe_version,
                    },
                })
            }
            Some(Operation::ProbeUninstall(probe_uninstall)) => {
                runner.run_probe_uninstall(ProbeUninstallRunnerInput {
                    stdin: &probe_uninstall.operation_token,
                    operation_id: &operation.id,
                })
            }
            None => return,
        };
        self.statuses.push((
            operation.id.clone(),
            match outcome {
                ProbeUpgradeRunnerOutcome::Running => Status::Running(ProbeOperationRunning {}),
                ProbeUpgradeRunnerOutcome::Failed(failed) => Status::Failed(failed),
            },
        ));
    }

    fn take_progress(&mut self) -> OperationReportProgress {
        OperationReportProgress::from_statuses(
            self.statuses
                .drain(..)
                .map(|(operation_id, status)| ProbeOperationStatus {
                    operation_id,
                    status: Some(status),
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod operation_report_tests {
    use super::*;

    struct RecordingUpgradeAcquisition;

    impl ProbeUpgradeAcquisitionPort for RecordingUpgradeAcquisition {
        fn acquire(
            &mut self,
            input: ProbeUpgradeAcquisitionInput<'_>,
        ) -> Result<enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt, &'static str>
        {
            assert_eq!(input.host_id, "7");
            assert_eq!(input.operation_id, "operation_01");
            assert_eq!(input.operation_token, "operation-token");
            assert_eq!(input.target_probe_version, "1.2.3");
            Ok(
                enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt {
                    operation_id: input.operation_id.to_owned(),
                    target_asset_set_digest: input.target_asset_set_digest.to_owned(),
                    target_manifest_sha256: "d".repeat(64),
                    target_version: input.target_probe_version.to_owned(),
                    verified_stage_sha256: "e".repeat(64),
                },
            )
        }
    }

    #[test]
    fn successful_operation_launch_acknowledges_and_reports_running_in_one_request() {
        struct RunningRunner;

        impl ProbeOperationRunner for RunningRunner {
            fn run_probe_upgrade(
                &mut self,
                _input: ProbeUpgradeRunnerInput<'_>,
            ) -> ProbeUpgradeRunnerOutcome {
                ProbeUpgradeRunnerOutcome::Running
            }

            fn run_probe_uninstall(
                &mut self,
                _input: ProbeUninstallRunnerInput<'_>,
            ) -> ProbeUpgradeRunnerOutcome {
                ProbeUpgradeRunnerOutcome::Running
            }
        }

        let mut queue = ProbeOperationReportQueue::default();
        let mut runner = RunningRunner;
        queue.observe_response(
            &ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "default-v1".to_string(),
                pending_operation: Some(crate::protocol::enoki::v1::ProbeOperation {
                    id: "operation-01".to_string(),
                    operation: Some(Operation::ProbeUpgrade(
                        crate::protocol::enoki::v1::ProbeUpgradeOperation {
                            current_probe_version: "0.1.0".to_string(),
                            host_id: "7".to_string(),
                            operation_token: "operation-token".to_string(),
                            target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
                            target_manifest_sha256: "a".repeat(64),
                            target_probe_version: "0.2.0".to_string(),
                        },
                    )),
                }),
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1,
            },
            &mut runner,
        );

        let (acknowledgements, statuses) = queue.take_progress().into_parts();

        assert_eq!(acknowledgements.len(), 1);
        assert_eq!(statuses.len(), 1);
        assert_eq!(acknowledgements[0].operation_id, "operation-01");
        assert!(matches!(statuses[0].status, Some(Status::Running(_))));
    }

    #[test]
    fn compatible_upgrade_hands_one_verified_stage_and_bound_authority_to_companion() {
        use std::os::unix::net::UnixListener;

        let temporary = tempfile::tempdir().expect("临时目录");
        let socket = temporary.path().join("lifecycle.sock");
        let listener = UnixListener::bind(&socket).expect("绑定生命周期socket");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("接收生命周期请求");
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).expect("读取请求");
            let request = LifecycleRequest::decode(&bytes).expect("typed升级请求");
            assert_eq!(
                request.transition(),
                enoki_probe_bootstrap::lifecycle::LifecycleTransition::Upgrade
            );
            assert!(matches!(
                request.authority(),
                enoki_probe_bootstrap::lifecycle::LifecycleRequestAuthority::HubUpgrade {
                    host_id,
                    probe_id,
                    source_bundle_version,
                    source_install_state_sha256,
                    source_manifest_sha256,
                    target_bundle_version,
                    target_asset_set_digest,
                    target_manifest_sha256,
                    verified_stage_sha256,
                    ..
                } if host_id == "7"
                    && probe_id == "probe_01"
                    && source_bundle_version == "1.2.2"
                    && source_install_state_sha256 == &"a".repeat(64)
                    && source_manifest_sha256 == &"b".repeat(64)
                    && target_bundle_version == "1.2.3"
                    && target_asset_set_digest == &format!("sha256:{}", "c".repeat(64))
                    && target_manifest_sha256 == &"d".repeat(64)
                    && verified_stage_sha256 == &"e".repeat(64)
            ));
            stream
                .write_all(&LifecycleResponse::succeeded().encode())
                .expect("返回成功");
        });
        let mut runner = LifecycleCompanionOperationRunner {
            probe_id: Some("probe_01".to_owned()),
            install_state_sha256: Some("a".repeat(64)),
            target_manifest_sha256: Some("b".repeat(64)),
            bundle_version: Some("1.2.2".to_owned()),
            socket_path: PathBuf::from(LIFECYCLE_COMPANION_SOCKET),
            upgrade_socket_path: socket,
            upgrade_acquisition: Box::new(RecordingUpgradeAcquisition),
        };
        let outcome = runner.run_probe_upgrade(ProbeUpgradeRunnerInput {
            stdin: "operation-token",
            operation: ProbeUpgradeRunnerOperationMetadata {
                current_probe_version: "1.2.2",
                host_id: "7",
                operation_id: "operation_01",
                target_asset_set_digest: &format!("sha256:{}", "c".repeat(64)),
                target_probe_version: "1.2.3",
            },
        });

        assert!(matches!(outcome, ProbeUpgradeRunnerOutcome::Running));
        server.join().expect("Companion线程");
    }

    #[test]
    fn lifecycle_companion_socket_round_trips_one_bound_uninstall_request() {
        use std::os::unix::net::UnixListener;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let socket = temporary.path().join("lifecycle.sock");
        let listener = UnixListener::bind(&socket).expect("bind lifecycle socket");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept lifecycle request");
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).expect("read request");
            let request = LifecycleRequest::decode(&bytes).expect("typed request");
            assert_eq!(
                request.transition(),
                enoki_probe_bootstrap::lifecycle::LifecycleTransition::Uninstall
            );
            stream
                .write_all(&LifecycleResponse::succeeded().encode())
                .expect("write response");
        });
        let request = LifecycleRequest::hub_uninstall(
            "probe_01",
            "operation_01",
            "operation-token",
            &"a".repeat(64),
            &"b".repeat(64),
            "1.2.3",
        )
        .expect("bound request");

        let response =
            request_lifecycle_companion_at(&socket, &request).expect("companion response");

        assert_eq!(response.status(), LifecycleResultStatus::Succeeded);
        server.join().expect("server thread");
    }

    #[test]
    fn probe_forwards_one_hub_uninstall_to_companion_and_reports_running_without_retry() {
        use std::os::unix::net::UnixListener;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let socket = temporary.path().join("lifecycle.sock");
        let listener = UnixListener::bind(&socket).expect("bind lifecycle socket");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept lifecycle request");
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).expect("read request");
            let request = LifecycleRequest::decode(&bytes).expect("typed request");
            assert!(matches!(
                request.authority(),
                enoki_probe_bootstrap::lifecycle::LifecycleRequestAuthority::HubOperation {
                    operation_id,
                    operation_token,
                    ..
                } if operation_id == "operation_01" && operation_token == "operation-token"
            ));
            stream
                .write_all(&LifecycleResponse::succeeded().encode())
                .expect("write response");
        });
        let response = ProbeReportResponse {
            accepted_sequence_end: 1,
            current_probe_configuration_version: "default-v1".to_owned(),
            pending_operation: Some(crate::protocol::enoki::v1::ProbeOperation {
                id: "operation_01".to_owned(),
                operation: Some(Operation::ProbeUninstall(
                    crate::protocol::enoki::v1::ProbeUninstallOperation {
                        operation_token: "operation-token".to_owned(),
                    },
                )),
            }),
            requested_snapshot_collector_ids: Vec::new(),
            server_time_ms: 1,
        };
        let mut runner = LifecycleCompanionOperationRunner {
            probe_id: Some("probe_01".to_owned()),
            install_state_sha256: Some("a".repeat(64)),
            target_manifest_sha256: Some("b".repeat(64)),
            bundle_version: Some("1.2.3".to_owned()),
            socket_path: socket,
            upgrade_socket_path: PathBuf::from(LIFECYCLE_UPGRADE_SOCKET),
            upgrade_acquisition: Box::new(DisabledProbeUpgradeAcquisition),
        };
        let mut queue = ProbeOperationReportQueue::default();

        queue.observe_response(&response, &mut runner);
        queue.observe_response(&response, &mut runner);
        let (acknowledgements, statuses) = queue.take_progress().into_parts();

        assert_eq!(acknowledgements.len(), 1);
        assert!(matches!(statuses[0].status, Some(Status::Running(_))));
        server.join().expect("server thread");
    }

    #[test]
    fn unavailable_companion_acknowledges_once_without_retrying_the_operation() {
        let response = ProbeReportResponse {
            accepted_sequence_end: 1,
            current_probe_configuration_version: "default-v1".to_owned(),
            pending_operation: Some(crate::protocol::enoki::v1::ProbeOperation {
                id: "operation-01".to_owned(),
                operation: Some(Operation::ProbeUpgrade(
                    crate::protocol::enoki::v1::ProbeUpgradeOperation {
                        current_probe_version: "0.1.0".to_owned(),
                        host_id: "7".to_owned(),
                        operation_token: "operation-token".to_owned(),
                        target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
                        target_manifest_sha256: "a".repeat(64),
                        target_probe_version: "0.2.0".to_owned(),
                    },
                )),
            }),
            requested_snapshot_collector_ids: Vec::new(),
            server_time_ms: 1,
        };
        let mut queue = ProbeOperationReportQueue::default();
        let mut runner = LifecycleCompanionOperationRunner {
            probe_id: None,
            install_state_sha256: None,
            target_manifest_sha256: None,
            bundle_version: None,
            socket_path: PathBuf::from(LIFECYCLE_COMPANION_SOCKET),
            upgrade_socket_path: PathBuf::from(LIFECYCLE_UPGRADE_SOCKET),
            upgrade_acquisition: Box::new(DisabledProbeUpgradeAcquisition),
        };

        queue.observe_response(&response, &mut runner);
        queue.observe_response(&response, &mut runner);
        let (acknowledgements, statuses) = queue.take_progress().into_parts();

        assert_eq!(acknowledgements.len(), 1);
        assert_eq!(statuses.len(), 1);
        assert!(matches!(
            statuses[0].status,
            Some(Status::Failed(ref failure))
                if failure.error_code == "lifecycle.install_receipt_missing"
                    && failure.message == "The local Probe lifecycle operation failed."
        ));
    }

    #[test]
    fn report_queue_acknowledges_and_reports_failed_operation_in_one_request() {
        struct FailingRunner;

        impl ProbeOperationRunner for FailingRunner {
            fn run_probe_upgrade(
                &mut self,
                _input: ProbeUpgradeRunnerInput<'_>,
            ) -> ProbeUpgradeRunnerOutcome {
                ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                    error_code: "insufficient_privilege".to_string(),
                    message: "sudo denied".to_string(),
                })
            }

            fn run_probe_uninstall(
                &mut self,
                _input: ProbeUninstallRunnerInput<'_>,
            ) -> ProbeUpgradeRunnerOutcome {
                ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                    error_code: "insufficient_privilege".to_string(),
                    message: "sudo denied".to_string(),
                })
            }
        }

        let mut queue = ProbeOperationReportQueue::default();
        let mut runner = FailingRunner;
        queue.observe_response(
            &ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "default-v1".to_string(),
                pending_operation: Some(crate::protocol::enoki::v1::ProbeOperation {
                    id: "operation-01".to_string(),
                    operation: Some(Operation::ProbeUpgrade(
                        crate::protocol::enoki::v1::ProbeUpgradeOperation {
                            current_probe_version: "0.1.0".to_string(),
                            host_id: "7".to_string(),
                            operation_token: "operation-token".to_string(),
                            target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
                            target_manifest_sha256: "a".repeat(64),
                            target_probe_version: "0.2.0".to_string(),
                        },
                    )),
                }),
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1,
            },
            &mut runner,
        );

        let (acknowledgements, statuses) = queue.take_progress().into_parts();

        assert_eq!(acknowledgements.len(), 1);
        assert_eq!(statuses.len(), 1);
        assert!(matches!(
            statuses[0].status,
            Some(Status::Failed(ref failed)) if failed.error_code == "insufficient_privilege"
        ));
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
    auth: &ProbeRequestAuth<'_>,
    body: Vec<u8>,
) -> Result<ProbeReportResponse, ReportError> {
    let response_body = transport.post_protobuf_with_auth(&report_url(hub_url)?, auth, body)?;

    ProbeReportResponse::decode(response_body.as_slice())
        .map_err(|error| ReportError::Decode(error.to_string()))
}

fn post_startup_report_until_accepted(
    transport: &mut impl ReportTransport,
    hub_url: &str,
    auth: &ProbeRequestAuth<'_>,
    body: Vec<u8>,
    sleeper: &mut impl ProbeRuntimeSleeper,
) -> Result<ProbeReportResponse, ReportError> {
    post_report_with_transient_retry(
        transport,
        hub_url,
        auth,
        body,
        1,
        sleeper,
        Duration::from_secs(1),
    )
}

fn post_report_with_transient_retry(
    transport: &mut impl ReportTransport,
    hub_url: &str,
    auth: &ProbeRequestAuth<'_>,
    body: Vec<u8>,
    expected_sequence_end: u64,
    sleeper: &mut impl ProbeRuntimeSleeper,
    retry_delay: Duration,
) -> Result<ProbeReportResponse, ReportError> {
    loop {
        match post_report(transport, hub_url, auth, body.clone()) {
            Ok(response) if response.accepted_sequence_end == expected_sequence_end => {
                return Ok(response);
            }
            Ok(_) => {
                return Err(ReportError::InvalidResponse(
                    "report acknowledgement did not match expected sequence",
                ));
            }
            Err(error) if error.is_transient() => {
                // The encoded body is intentionally retained: every retry has the
                // same logical report while the HTTP transport regenerates request
                // authentication material for every attempt.
                sleeper.sleep(retry_delay);
            }
            Err(error) => return Err(error),
        }
    }
}

fn notify_systemd_ready() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixDatagram;

        let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
            return Ok(());
        };
        let socket = PathBuf::from(socket);
        if !socket.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NOTIFY_SOCKET must be an absolute path",
            ));
        }
        let datagram = UnixDatagram::unbound()?;
        datagram.send_to(b"READY=1", socket)?;
    }

    Ok(())
}

fn collect_observation_batch(
    active_configuration: &ActiveProbeConfiguration,
    sequence: &mut u64,
    observation_runtime: &impl ObservationWindowClient,
) -> Result<FinalizedObservationBatch, ObservationClientError> {
    let sequence_start = *sequence + 1;
    let runtime_window = observation_runtime.request_finalized_window(
        active_configuration.metrics_collection_interval,
        sequence_start,
    )?;
    if runtime_window.attempts.len() != REPORTING_WINDOW_TICKS as usize {
        return Err(ObservationClientError::InvalidResponse);
    }

    let host_profile = runtime_window.host_profile;
    let mut metrics = Vec::with_capacity(runtime_window.attempts.len());
    let mut outcomes = Vec::new();
    for (index, attempt) in runtime_window.attempts.into_iter().enumerate() {
        let expected_sequence = sequence_start + index as u64;
        if attempt.sequence != expected_sequence
            || attempt.sample.is_some() == attempt.cpu_resource_outcome.is_some()
        {
            return Err(ObservationClientError::InvalidResponse);
        }
        if let Some(runtime_sample) = attempt.sample {
            let mut sample = crate::protocol::enoki::v1::MetricSample {
                sequence: attempt.sequence,
                ..Default::default()
            };
            merge_runtime_metrics(
                &mut sample,
                runtime_sample,
                &active_configuration.metrics_config,
            );
            metrics.push(sample);
        } else if let Some(failure) = attempt.cpu_resource_outcome {
            outcomes.push(crate::protocol::enoki::v1::CpuResourceCollectionOutcome {
                sequence: attempt.sequence,
                reason: match failure {
                    SystemStateResourceAcquisitionFailure::Unavailable => crate::protocol::enoki::v1::CpuResourceCollectionOutcomeReason::CpuResourceUnavailable as i32,
                    SystemStateResourceAcquisitionFailure::Malformed => crate::protocol::enoki::v1::CpuResourceCollectionOutcomeReason::CpuResourceMalformed as i32,
                    SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted => crate::protocol::enoki::v1::CpuResourceCollectionOutcomeReason::CpuProviderActivationBudgetExhausted as i32,
                },
            });
        }
    }
    *sequence = sequence_start.saturating_add(REPORTING_WINDOW_TICKS - 1);
    Ok((sequence_start, *sequence, metrics, outcomes, host_profile))
}

fn merge_runtime_metrics(
    sample: &mut crate::protocol::enoki::v1::MetricSample,
    cpu_sample: crate::protocol::enoki::v1::MetricSample,
    config: &MetricsCollectionConfig,
) {
    sample.collected_at_ms = cpu_sample.collected_at_ms;
    sample.collector_outcomes = cpu_sample
        .collector_outcomes
        .into_iter()
        .filter(|outcome| {
            if outcome.collector_id == crate::collectors::HOST_PROFILE_COLLECTOR_ID {
                return true;
            }
            CollectorId::from_config_id(&outcome.collector_id)
                .is_some_and(|id| config.collector_enabled(id))
        })
        .collect();
    if config.collector_enabled(CollectorId::Cpu) {
        sample.cpu_cores = cpu_sample.cpu_cores;
        sample.cpu_percent = cpu_sample.cpu_percent;
        sample.cpu_idle_percent = cpu_sample.cpu_idle_percent;
        sample.cpu_iowait_percent = cpu_sample.cpu_iowait_percent;
        sample.cpu_steal_percent = cpu_sample.cpu_steal_percent;
        sample.cpu_system_percent = cpu_sample.cpu_system_percent;
        sample.cpu_user_percent = cpu_sample.cpu_user_percent;
    }
    if config.collector_enabled(CollectorId::Load) {
        sample.load_1 = cpu_sample.load_1;
        sample.load_5 = cpu_sample.load_5;
        sample.load_15 = cpu_sample.load_15;
    }
    if config.collector_enabled(CollectorId::Memory) {
        sample.memory_total_bytes = cpu_sample.memory_total_bytes;
        sample.memory_used_bytes = cpu_sample.memory_used_bytes;
        sample.memory_cache_bytes = cpu_sample.memory_cache_bytes;
        sample.swap_total_bytes = cpu_sample.swap_total_bytes;
        sample.swap_used_bytes = cpu_sample.swap_used_bytes;
    }
    if config.collector_enabled(CollectorId::Uptime) {
        sample.uptime_seconds = cpu_sample.uptime_seconds;
    }
    if config.collector_enabled(CollectorId::Network) {
        sample.network_interfaces = cpu_sample.network_interfaces;
    }
    if config.collector_enabled(CollectorId::Disk) {
        sample.disks = cpu_sample.disks;
    }
    if config.collector_enabled(CollectorId::Temperature) {
        sample.temperature_celsius = cpu_sample.temperature_celsius;
    }
    if config.collector_enabled(CollectorId::Battery) {
        sample.battery_percent = cpu_sample.battery_percent;
        sample.battery_state = cpu_sample.battery_state;
    }
    if config.collector_enabled(CollectorId::DiskHealth) {
        sample.disk_health = cpu_sample.disk_health;
    }
}

fn apply_newer_configuration_if_needed(
    transport: &mut impl ReportTransport,
    hub_url: &str,
    probe_id: &str,
    auth: &ProbeRequestAuth<'_>,
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
        auth,
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

fn post_probe_configuration(
    transport: &mut impl ReportTransport,
    hub_url: &str,
    probe_id: &str,
    auth: &ProbeRequestAuth<'_>,
    current_version: &str,
) -> Result<ProbeConfigurationResponse, ReportError> {
    let request = ProbeConfigurationRequest {
        current_version: current_version.to_string(),
        probe_id: probe_id.to_string(),
    };
    let response_body =
        transport.post_protobuf_with_auth(&config_url(hub_url)?, auth, request.encode_to_vec())?;

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
    fn from_bootstrap(
        bootstrap_config: &BootstrapConfig,
        version: &str,
    ) -> Result<Self, ReportError> {
        let metrics_collection_interval = bootstrap_config
            .metrics_collection_interval_seconds
            .unwrap_or(default_metrics_collection_interval_seconds());
        let reporting_batch_interval =
            derived_reporting_batch_interval_seconds(metrics_collection_interval);

        Ok(Self {
            metrics_collection_interval: Duration::from_secs(metrics_collection_interval),
            metrics_config: bootstrap_config.metrics_collection_config()?,
            reporting_interval: Duration::from_secs(reporting_batch_interval),
            version: version.to_string(),
        })
    }

    fn try_from_response(configuration: ProbeConfigurationResponse) -> Result<Self, &'static str> {
        if configuration.version.is_empty() {
            return Err("missing Probe Configuration version");
        }

        let metrics_collection_interval =
            u64::from(configuration.metrics_collection_interval_seconds);
        let reporting_batch_interval =
            derived_reporting_batch_interval_seconds(metrics_collection_interval);

        if !(1..=200).contains(&metrics_collection_interval) {
            return Err("Metrics collection interval out of range");
        }

        Ok(Self {
            metrics_collection_interval: Duration::from_secs(metrics_collection_interval),
            metrics_config: metrics_collection_config_from_config_ids(
                &configuration.enabled_collector_ids,
            )?,
            reporting_interval: Duration::from_secs(reporting_batch_interval),
            version: configuration.version,
        })
    }
}

struct BootstrapConfig {
    bootstrap_config_path: Option<PathBuf>,
    bundle_version: Option<String>,
    enabled_collector_ids: Option<Vec<String>>,
    enrollment_id: Option<String>,
    enrollment_token: Option<String>,
    hub_url: Option<String>,
    install_state_sha256: Option<String>,
    metrics_collection_interval_seconds: Option<u64>,
    operation_status_path: Option<String>,
    probe_configuration_version: Option<String>,
    probe_id: Option<String>,
    probe_private_key_pem: Option<String>,
    server_time_offset_ms: Option<i64>,
    state_dir: Option<String>,
    target_manifest_sha256: Option<String>,
}

impl BootstrapConfig {
    fn has_probe_identity(&self) -> bool {
        self.probe_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            && self
                .probe_private_key_pem
                .as_deref()
                .is_some_and(|value| !value.is_empty())
    }

    fn metrics_collection_config(&self) -> Result<MetricsCollectionConfig, ReportError> {
        match self.enabled_collector_ids.as_deref() {
            Some(collector_ids) => metrics_collection_config_from_config_ids(collector_ids)
                .map_err(ReportError::InvalidConfig),
            None => Ok(MetricsCollectionConfig::all_enabled()),
        }
    }
}

fn metrics_collection_config_from_config_ids(
    collector_ids: &[String],
) -> Result<MetricsCollectionConfig, &'static str> {
    let mut enabled_collectors = Vec::with_capacity(collector_ids.len());

    for collector_id in collector_ids {
        if !is_owner_configurable_collector_id(collector_id) {
            return Err("unknown Probe Configuration collector ID");
        }
        let collector_id = CollectorId::from_config_id(collector_id)
            .ok_or("unknown Probe Configuration collector ID")?;
        enabled_collectors.push(collector_id);
    }

    Ok(MetricsCollectionConfig::from_enabled_collectors(
        enabled_collectors,
    ))
}

fn read_bootstrap_config(path: &PathBuf) -> Result<BootstrapConfig, ProbeRunError> {
    validate_bootstrap_config_file(path)?;
    let contents = fs::read_to_string(path).map_err(ProbeRunError::Io)?;
    let value = contents
        .parse::<toml::Value>()
        .map_err(|_| ProbeRunError::InvalidConfig("invalid TOML"))?;

    Ok(BootstrapConfig {
        bootstrap_config_path: Some(path.clone()),
        bundle_version: string_value(&value, "bundle_version")?,
        enabled_collector_ids: string_array_value(&value, "enabled_collector_ids")?,
        enrollment_id: string_value(&value, "enrollment_id")?,
        enrollment_token: string_value(&value, "enrollment_token")?,
        hub_url: string_value(&value, "hub_url")?,
        install_state_sha256: string_value(&value, "install_state_sha256")?,
        metrics_collection_interval_seconds: integer_value(
            &value,
            "metrics_collection_interval_seconds",
        )?,
        operation_status_path: string_value(&value, "operation_status_path")?,
        probe_configuration_version: string_value(&value, "probe_configuration_version")?,
        probe_id: string_value(&value, "probe_id")?,
        probe_private_key_pem: string_value(&value, "probe_private_key_pem")?,
        server_time_offset_ms: signed_integer_value(&value, "server_time_offset_ms")?,
        state_dir: string_value(&value, "state_dir")?,
        target_manifest_sha256: string_value(&value, "target_manifest_sha256")?,
    })
}

#[cfg(unix)]
fn validate_bootstrap_config_file(path: &PathBuf) -> Result<(), ProbeRunError> {
    let metadata = fs::symlink_metadata(path).map_err(ProbeRunError::Io)?;

    if metadata.file_type().is_symlink() {
        return Err(ProbeRunError::InvalidConfig(
            "bootstrap config must not be a symlink",
        ));
    }

    if !metadata.file_type().is_file() {
        return Err(ProbeRunError::InvalidConfig(
            "bootstrap config must be a regular file",
        ));
    }

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ProbeRunError::InvalidConfig(
            "bootstrap config must not be accessible by group or other users",
        ));
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_bootstrap_config_file(_path: &PathBuf) -> Result<(), ProbeRunError> {
    Ok(())
}

fn read_local_operation_statuses(bootstrap_config: &BootstrapConfig) -> Vec<ProbeOperationStatus> {
    let Some(path) = local_operation_status_path(bootstrap_config) else {
        return Vec::new();
    };
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = contents.parse::<toml::Value>() else {
        return Vec::new();
    };
    let Some(operation_id) = local_status_string(&value, "operation_id") else {
        return Vec::new();
    };
    let Some(status) = local_status_string(&value, "status") else {
        return Vec::new();
    };

    match status.as_str() {
        "running" => vec![ProbeOperationStatus {
            operation_id,
            status: Some(Status::Running(ProbeOperationRunning {})),
        }],
        "failed" => vec![ProbeOperationStatus {
            operation_id,
            status: Some(Status::Failed(ProbeOperationFailed {
                error_code: local_status_string(&value, "error_code")
                    .unwrap_or_else(|| "probe_upgrader_failed".to_string()),
                message: local_status_string(&value, "message").unwrap_or_default(),
            })),
        }],
        _ => Vec::new(),
    }
}

fn local_operation_status_path(bootstrap_config: &BootstrapConfig) -> Option<PathBuf> {
    if let Some(path) = bootstrap_config.operation_status_path.as_ref() {
        return Some(PathBuf::from(path));
    }

    bootstrap_config
        .state_dir
        .as_ref()
        .map(|state_dir| PathBuf::from(state_dir).join("probe-operation-status.toml"))
}

fn local_status_string(value: &toml::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(ToString::to_string)
}

fn default_metrics_collection_interval_seconds() -> u64 {
    5
}

fn derived_reporting_batch_interval_seconds(metrics_collection_interval_seconds: u64) -> u64 {
    metrics_collection_interval_seconds.saturating_mul(REPORTING_WINDOW_TICKS)
}

fn report_url(hub_url: &str) -> Result<String, ReportError> {
    hub_url::endpoint(hub_url, "/api/probe/report")
        .map_err(|()| ReportError::InvalidConfig("invalid Hub URL"))
}

fn config_url(hub_url: &str) -> Result<String, ReportError> {
    hub_url::endpoint(hub_url, "/api/probe/config")
        .map_err(|()| ReportError::InvalidConfig("invalid Hub URL"))
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

fn string_array_value(
    value: &toml::Value,
    key: &'static str,
) -> Result<Option<Vec<String>>, ProbeRunError> {
    match value.get(key) {
        Some(toml::Value::Array(values)) => values
            .iter()
            .map(|value| match value {
                toml::Value::String(string) => Ok(string.clone()),
                _ => Err(ProbeRunError::InvalidConfig("expected string array values")),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(ProbeRunError::InvalidConfig("expected string array values")),
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

fn signed_integer_value(
    value: &toml::Value,
    key: &'static str,
) -> Result<Option<i64>, ProbeRunError> {
    match value.get(key) {
        Some(toml::Value::Integer(integer)) => Ok(Some(*integer)),
        Some(_) => Err(ProbeRunError::InvalidConfig("expected integer values")),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation_runtime::ObservationWindowResult;
    use crate::protocol::enoki::v1::{
        ProbeConfigurationResponse, ProbeRegistrationResponse, ProbeReportRequest,
        ProbeUpgradeOperation,
    };
    use std::{cell::RefCell, collections::VecDeque, rc::Rc, sync::Mutex};

    struct FakeObservationWindowClient {
        cadences: Mutex<Vec<Duration>>,
        result: ObservationWindowResult,
    }

    impl ObservationWindowClient for FakeObservationWindowClient {
        fn request_finalized_window(
            &self,
            cadence: Duration,
            _sequence_start: u64,
        ) -> Result<ObservationWindowResult, ObservationClientError> {
            self.cadences.lock().expect("cadences").push(cadence);
            Ok(self.result.clone())
        }
    }

    #[test]
    fn cpu_window_is_requested_once_and_its_authoritative_timestamps_are_reused() {
        let active_configuration = ActiveProbeConfiguration {
            metrics_collection_interval: Duration::from_secs(7),
            metrics_config: MetricsCollectionConfig::from_enabled_collectors([
                CollectorId::Cpu,
                CollectorId::Memory,
            ]),
            reporting_interval: Duration::from_secs(21),
            version: "default-v1".to_string(),
        };
        let client = FakeObservationWindowClient {
            cadences: Mutex::new(Vec::new()),
            result: ObservationWindowResult {
                host_profile: None,
                attempts: [7_000, 14_000, 21_000]
                    .into_iter()
                    .enumerate()
                    .map(|(index, collected_at_ms)| {
                        crate::observation_runtime::ObservationAttemptResult {
                            sequence: index as u64 + 1,
                            sample: Some(crate::protocol::enoki::v1::MetricSample {
                                collected_at_ms,
                                cpu_percent: Some(12.5),
                                memory_used_bytes: Some(42),
                                ..Default::default()
                            }),
                            cpu_resource_outcome: None,
                        }
                    })
                    .collect(),
            },
        };
        let mut sequence = 0;

        let (_, _, samples, outcome, _) =
            collect_observation_batch(&active_configuration, &mut sequence, &client)
                .expect("Observation Batch");

        assert_eq!(
            *client.cadences.lock().expect("cadences"),
            [Duration::from_secs(7)]
        );
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.collected_at_ms)
                .collect::<Vec<_>>(),
            [7_000, 14_000, 21_000]
        );
        assert!(
            samples
                .iter()
                .all(|sample| sample.cpu_percent == Some(12.5))
        );
        assert!(
            samples
                .iter()
                .all(|sample| sample.memory_used_bytes == Some(42))
        );
        assert!(outcome.is_empty());
    }

    struct RuntimeMetricsWindowClient;

    impl ObservationWindowClient for RuntimeMetricsWindowClient {
        fn request_finalized_window(
            &self,
            cadence: Duration,
            sequence_start: u64,
        ) -> Result<ObservationWindowResult, ObservationClientError> {
            Ok(ObservationWindowResult {
                host_profile: None,
                attempts: (0..REPORTING_WINDOW_TICKS)
                    .map(
                        |tick| crate::observation_runtime::ObservationAttemptResult {
                            sequence: sequence_start + tick,
                            sample: Some(crate::protocol::enoki::v1::MetricSample {
                                collected_at_ms: cadence.as_millis() as i64 * (tick as i64 + 1),
                                load_1: Some(1.0),
                                memory_used_bytes: Some(42),
                                ..Default::default()
                            }),
                            cpu_resource_outcome: None,
                        },
                    )
                    .collect(),
            })
        }
    }

    #[test]
    fn cpu_acquisition_outcome_keeps_other_metrics_in_the_same_window() {
        let active_configuration = ActiveProbeConfiguration {
            metrics_collection_interval: Duration::from_secs(5),
            metrics_config: MetricsCollectionConfig::from_enabled_collectors([
                CollectorId::Cpu,
                CollectorId::Memory,
            ]),
            reporting_interval: Duration::from_secs(15),
            version: "default-v1".to_string(),
        };
        let client = FakeObservationWindowClient {
            cadences: Mutex::new(Vec::new()),
            result: ObservationWindowResult {
                host_profile: None,
                attempts: (1..=3)
                    .map(
                        |sequence| crate::observation_runtime::ObservationAttemptResult {
                            sequence,
                            sample: None,
                            cpu_resource_outcome: Some(
                                SystemStateResourceAcquisitionFailure::Unavailable,
                            ),
                        },
                    )
                    .collect(),
            },
        };
        let mut sequence = 0;
        let (_, _, samples, outcome, _) =
            collect_observation_batch(&active_configuration, &mut sequence, &client)
                .expect("partial Observation Batch");

        assert!(samples.is_empty());
        assert_eq!(
            outcome.iter().map(|outcome| outcome.reason).collect::<Vec<_>>(),
            vec![
                crate::protocol::enoki::v1::CpuResourceCollectionOutcomeReason::CpuResourceUnavailable
                    as i32;
                3
            ]
        );
    }

    #[cfg(unix)]
    use std::os::unix::{fs::PermissionsExt, fs::symlink};

    #[test]
    fn observation_batch_uses_runtime_finalized_system_state_on_every_due_tick() {
        let active_configuration = ActiveProbeConfiguration {
            metrics_collection_interval: Duration::from_secs(5),
            metrics_config: MetricsCollectionConfig::from_enabled_collectors([
                CollectorId::Memory,
                CollectorId::Load,
            ]),
            reporting_interval: Duration::from_secs(15),
            version: "default-v1".to_string(),
        };
        let mut sequence = 1;
        let (_, _, metrics, _, _) = collect_observation_batch(
            &active_configuration,
            &mut sequence,
            &RuntimeMetricsWindowClient,
        )
        .expect("non-CPU Observation Batch succeeds");

        assert_eq!(
            metrics
                .iter()
                .map(|sample| sample.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3, 4],
        );
        assert!(
            metrics
                .iter()
                .all(|sample| sample.memory_used_bytes == Some(42))
        );
        assert!(metrics.iter().all(|sample| sample.load_1 == Some(1.0)));
    }

    #[test]
    fn observation_batch_does_not_reapply_probe_local_cadence_to_runtime_results() {
        let active_configuration = ActiveProbeConfiguration {
            metrics_collection_interval: Duration::from_secs(7),
            metrics_config: MetricsCollectionConfig::from_enabled_collectors([CollectorId::Load]),
            reporting_interval: Duration::from_secs(21),
            version: "default-v1".to_string(),
        };
        let mut sequence = 0;
        let (_, _, first_metrics, _, _) = collect_observation_batch(
            &active_configuration,
            &mut sequence,
            &RuntimeMetricsWindowClient,
        )
        .expect("first non-CPU Observation Batch succeeds");
        let (_, _, second_metrics, _, _) = collect_observation_batch(
            &active_configuration,
            &mut sequence,
            &RuntimeMetricsWindowClient,
        )
        .expect("second non-CPU Observation Batch succeeds");
        let (_, _, third_metrics, _, _) = collect_observation_batch(
            &active_configuration,
            &mut sequence,
            &RuntimeMetricsWindowClient,
        )
        .expect("third non-CPU Observation Batch succeeds");
        let (_, _, fourth_metrics, _, _) = collect_observation_batch(
            &active_configuration,
            &mut sequence,
            &RuntimeMetricsWindowClient,
        )
        .expect("fourth non-CPU Observation Batch succeeds");

        assert_eq!(
            [
                first_metrics.as_slice(),
                second_metrics.as_slice(),
                third_metrics.as_slice(),
                fourth_metrics.as_slice(),
            ]
            .concat()
            .iter()
            .map(|sample| sample.sequence)
            .collect::<Vec<_>>(),
            (1..=12).collect::<Vec<_>>(),
        );
        assert_eq!(
            first_metrics
                .iter()
                .chain(&second_metrics)
                .chain(&third_metrics)
                .chain(&fourth_metrics)
                .filter_map(|sample| sample.load_1)
                .collect::<Vec<_>>(),
            vec![1.0; 12],
        );
    }

    #[derive(Default)]
    struct RecordingOperationRunner {
        observed_current_probe_version: Option<String>,
        observed_operation_id: Option<String>,
        observed_stdin: Option<String>,
        observed_target_asset_set_digest: Option<String>,
        observed_target_probe_version: Option<String>,
        outcome: Option<ProbeUpgradeRunnerOutcome>,
    }

    impl ProbeOperationRunner for RecordingOperationRunner {
        fn run_probe_upgrade(
            &mut self,
            input: ProbeUpgradeRunnerInput<'_>,
        ) -> ProbeUpgradeRunnerOutcome {
            self.observed_current_probe_version =
                Some(input.operation.current_probe_version.to_string());
            self.observed_operation_id = Some(input.operation.operation_id.to_string());
            self.observed_stdin = Some(input.stdin.to_string());
            self.observed_target_asset_set_digest =
                Some(input.operation.target_asset_set_digest.to_string());
            self.observed_target_probe_version =
                Some(input.operation.target_probe_version.to_string());

            self.outcome.take().unwrap_or_else(|| {
                ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                    error_code: "unsupported_installation".to_string(),
                    message: "not installed".to_string(),
                })
            })
        }

        fn run_probe_uninstall(
            &mut self,
            input: ProbeUninstallRunnerInput<'_>,
        ) -> ProbeUpgradeRunnerOutcome {
            self.observed_operation_id = Some(input.operation_id.to_string());
            self.observed_stdin = Some(input.stdin.to_string());

            self.outcome.take().unwrap_or_else(|| {
                ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                    error_code: "unsupported_installation".to_string(),
                    message: "not installed".to_string(),
                })
            })
        }
    }

    #[test]
    #[cfg(unix)]
    fn probe_run_rejects_group_readable_bootstrap_config() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "",
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        fs::set_permissions(&bootstrap_config_path, fs::Permissions::from_mode(0o644))
            .expect("set permissions");

        let mut transport = RegistrationThenOperationTransport {
            observed_report_bodies: Vec::new(),
            registration_response: Vec::new(),
            report_responses: VecDeque::new(),
        };
        let error = run_probe_with_loop_control(
            ProbeRunInput {
                bootstrap_config_path,
            },
            &mut transport,
            &mut NoopSleeper,
            RunLoopControl {
                max_reports: Some(1),
            },
        )
        .expect_err("group-readable bootstrap config is rejected");

        assert_eq!(
            error.to_string(),
            "invalid Probe bootstrap config: bootstrap config must not be accessible by group or other users",
        );
    }

    #[test]
    #[cfg(unix)]
    fn probe_run_rejects_symlink_bootstrap_config() {
        let temp = tempfile::tempdir().expect("temp dir");
        let target_config_path = temp.path().join("target-bootstrap.toml");
        let symlink_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &target_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "",
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        fs::set_permissions(&target_config_path, fs::Permissions::from_mode(0o600))
            .expect("set permissions");
        symlink(&target_config_path, &symlink_config_path).expect("create symlink");

        let mut transport = RegistrationThenOperationTransport {
            observed_report_bodies: Vec::new(),
            registration_response: Vec::new(),
            report_responses: VecDeque::new(),
        };
        let error = run_probe_with_loop_control(
            ProbeRunInput {
                bootstrap_config_path: symlink_config_path,
            },
            &mut transport,
            &mut NoopSleeper,
            RunLoopControl {
                max_reports: Some(1),
            },
        )
        .expect_err("symlink bootstrap config is rejected");

        assert_eq!(
            error.to_string(),
            "invalid Probe bootstrap config: bootstrap config must not be a symlink",
        );
    }

    #[test]
    fn startup_report_retries_a_transient_failure_without_advancing_metrics_or_sequence() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "probe_private_key_pem = \"test-private-key\"",
                "probe_configuration_version = \"default-v1\"",
                "metrics_collection_interval_seconds = 1",
                "enabled_collector_ids = []",
                "",
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        #[cfg(unix)]
        fs::set_permissions(&bootstrap_config_path, fs::Permissions::from_mode(0o600))
            .expect("set permissions");

        let mut transport = StartupRetryTransport {
            report_attempts: Vec::new(),
            report_responses: VecDeque::from([
                Err(ReportError::Attempt(HttpAttemptError::Network(
                    "temporary network failure".to_string(),
                ))),
                Ok(ProbeReportResponse {
                    accepted_sequence_end: 1,
                    current_probe_configuration_version: "default-v1".to_string(),
                    pending_operation: None,
                    requested_snapshot_collector_ids: Vec::new(),
                    server_time_ms: 1,
                }
                .encode_to_vec()),
            ]),
        };

        run_probe_with_loop_control(
            ProbeRunInput {
                bootstrap_config_path,
            },
            &mut transport,
            &mut NoopSleeper,
            RunLoopControl {
                max_reports: Some(1),
            },
        )
        .expect("transient Startup Report failure retries");

        assert_eq!(transport.report_attempts.len(), 2);
        assert_eq!(transport.report_attempts[0], transport.report_attempts[1]);
        let startup = ProbeReportRequest::decode(transport.report_attempts[0].as_slice())
            .expect("Startup Report decodes");
        assert_eq!(startup.sequence_start, 1);
        assert_eq!(startup.sequence_end, 1);
        assert!(startup.metrics.is_empty());
        assert!(startup.snapshots.is_empty());
    }

    #[test]
    fn startup_report_rejects_a_default_sequence_ack_as_a_permanent_protocol_failure() {
        let mut transport = StartupRetryTransport {
            report_attempts: Vec::new(),
            report_responses: VecDeque::from([Ok(ProbeReportResponse {
                accepted_sequence_end: 0,
                current_probe_configuration_version: "default-v1".to_string(),
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1,
            }
            .encode_to_vec())]),
        };
        let mut sleeper = NoopSleeper;

        let error = post_startup_report_until_accepted(
            &mut transport,
            "https://hub.example",
            &ProbeRequestAuth {
                probe_id: "probe_01",
                probe_private_key_pem: "test-private-key",
                server_time_offset_ms: 0,
            },
            vec![1, 2, 3],
            &mut sleeper,
        )
        .expect_err("default acknowledgement must not establish readiness");

        assert!(matches!(
            error,
            ReportError::InvalidResponse("report acknowledgement did not match expected sequence")
        ));
    }

    #[test]
    fn response_body_read_failure_retries_the_unchanged_startup_body() {
        let mut transport = StartupRetryTransport {
            report_attempts: Vec::new(),
            report_responses: VecDeque::from([
                Err(ReportError::Attempt(HttpAttemptError::ResponseRead(
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection ended during the response body",
                    ),
                ))),
                Ok(ProbeReportResponse {
                    accepted_sequence_end: 1,
                    current_probe_configuration_version: "default-v1".to_string(),
                    pending_operation: None,
                    requested_snapshot_collector_ids: Vec::new(),
                    server_time_ms: 1,
                }
                .encode_to_vec()),
            ]),
        };
        let mut sleeper = NoopSleeper;

        post_startup_report_until_accepted(
            &mut transport,
            "https://hub.example",
            &ProbeRequestAuth {
                probe_id: "probe_01",
                probe_private_key_pem: "test-private-key",
                server_time_offset_ms: 0,
            },
            vec![1, 2, 3],
            &mut sleeper,
        )
        .expect("a response-read interruption is retryable");

        assert_eq!(transport.report_attempts, [vec![1, 2, 3], vec![1, 2, 3]]);
    }

    #[test]
    fn only_permanent_hub_report_failures_use_systemd_restart_prevention() {
        let notify_failure = ProbeRunError::Notify(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "notify socket unavailable",
        ));
        let rejected_startup = ProbeRunError::Report(ReportError::InvalidResponse(
            "Startup Report was not accepted at sequence 1",
        ));

        assert_eq!(probe_run_exit_status(&notify_failure), 1);
        assert_eq!(
            probe_run_exit_status(&rejected_startup),
            PERMANENT_REPORT_EXIT_STATUS,
        );
    }

    #[test]
    fn systemd_notify_failure_after_hub_readiness_is_a_restartable_non_ready_failure() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let bootstrap_config_path = temporary.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_id = \"probe_01\"",
                "probe_private_key_pem = \"test-private-key\"",
                "probe_configuration_version = \"default-v1\"",
                "metrics_collection_interval_seconds = 1",
                "enabled_collector_ids = []",
                "",
            ]
            .join("\n"),
        )
        .expect("bootstrap config");
        fs::set_permissions(&bootstrap_config_path, fs::Permissions::from_mode(0o600))
            .expect("bootstrap permissions");
        let mut transport = StartupRetryTransport {
            report_attempts: Vec::new(),
            report_responses: VecDeque::from([Ok(ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "default-v1".to_string(),
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1,
            }
            .encode_to_vec())]),
        };
        let result = run_probe_with_loop_control_and_runner_factory_and_notifier(
            ProbeRunInput {
                bootstrap_config_path,
            },
            &mut transport,
            &mut NoopSleeper,
            RunLoopControl {
                max_reports: Some(1),
            },
            LifecycleCompanionOperationRunner::from_bootstrap,
            || {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "notify socket unavailable",
                ))
            },
            &UnixObservationRuntimeClient::production(),
        );

        let error = result.expect_err("failed notify must prevent local readiness");
        assert!(matches!(error, ProbeRunError::Notify(_)));
        assert!(!error.is_permanent_report_failure());
        assert_eq!(transport.report_attempts.len(), 1);
    }

    #[test]
    fn probe_operation_report_queue_passes_operation_token_to_runner_stdin() {
        let mut queue = ProbeOperationReportQueue::default();
        let mut runner = RecordingOperationRunner::default();
        let response = ProbeReportResponse {
            accepted_sequence_end: 1,
            current_probe_configuration_version: "default-v1".to_string(),
            pending_operation: Some(crate::protocol::enoki::v1::ProbeOperation {
                id: "operation-01".to_string(),
                operation: Some(Operation::ProbeUpgrade(ProbeUpgradeOperation {
                    current_probe_version: "0.1.0".to_string(),
                    host_id: "7".to_string(),
                    operation_token: "operation-token-01".to_string(),
                    target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
                    target_manifest_sha256: "a".repeat(64),
                    target_probe_version: "0.2.0".to_string(),
                })),
            }),
            requested_snapshot_collector_ids: Vec::new(),
            server_time_ms: 1_725_000_000_000,
        };

        queue.observe_response(&response, &mut runner);

        assert_eq!(runner.observed_stdin.as_deref(), Some("operation-token-01"));
        assert_eq!(
            runner.observed_target_asset_set_digest.as_deref(),
            Some(&*format!("sha256:{}", "a".repeat(64)))
        );
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

    #[test]
    fn probe_operation_report_queue_reports_insufficient_privilege_launch_failure() {
        let mut queue = ProbeOperationReportQueue::default();
        let mut runner = RecordingOperationRunner {
            outcome: Some(ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                error_code: "insufficient_privilege".to_string(),
                message: "sudoers rule is missing".to_string(),
            })),
            ..RecordingOperationRunner::default()
        };
        let response = ProbeReportResponse {
            accepted_sequence_end: 1,
            current_probe_configuration_version: "default-v1".to_string(),
            pending_operation: Some(crate::protocol::enoki::v1::ProbeOperation {
                id: "operation-01".to_string(),
                operation: Some(Operation::ProbeUpgrade(ProbeUpgradeOperation {
                    current_probe_version: "0.1.0".to_string(),
                    host_id: "7".to_string(),
                    operation_token: "operation-token-01".to_string(),
                    target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
                    target_manifest_sha256: "a".repeat(64),
                    target_probe_version: "0.2.0".to_string(),
                })),
            }),
            requested_snapshot_collector_ids: Vec::new(),
            server_time_ms: 1_725_000_000_000,
        };

        queue.observe_response(&response, &mut runner);
        let (acknowledgements, statuses) = queue.take_progress().into_parts();

        assert_eq!(acknowledgements.len(), 1);
        assert!(matches!(
            &statuses[0],
            ProbeOperationStatus {
                status: Some(Status::Failed(failed)),
                ..
            } if failed.error_code == "insufficient_privilege"
                && failed.message == "sudoers rule is missing"
        ));
    }

    #[test]
    fn registration_then_operation_reports_without_lifecycle_launch_metadata() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "enrollment_token = \"enk_enroll_secret\"",
                "state_dir = \"/var/lib/enoki-probe\"",
                "log_level = \"info\"",
                "",
            ]
            .join("\n"),
        )
        .expect("write installer config");
        #[cfg(unix)]
        fs::set_permissions(&bootstrap_config_path, fs::Permissions::from_mode(0o600))
            .expect("set permissions");
        let mut transport = RegistrationThenOperationTransport {
            observed_report_bodies: Vec::new(),
            registration_response: ProbeRegistrationResponse {
                installation_inspection: None,
                enrollment_id: String::new(),
                initial_configuration: Some(ProbeConfigurationResponse {
                    enabled_collector_ids: Vec::new(),
                    metrics_collection_interval_seconds: 1,
                    version: "default-v1".to_string(),
                }),
                probe_id: "probe_01".to_string(),
                probe_secret: String::new(),
                server_time_ms: 1,
            }
            .encode_to_vec(),
            report_responses: VecDeque::from([
                ProbeReportResponse {
                    accepted_sequence_end: 1,
                    current_probe_configuration_version: "default-v1".to_string(),
                    pending_operation: Some(crate::protocol::enoki::v1::ProbeOperation {
                        id: "operation-01".to_string(),
                        operation: Some(Operation::ProbeUpgrade(ProbeUpgradeOperation {
                            current_probe_version: "0.1.0".to_string(),
                            host_id: "7".to_string(),
                            operation_token: "operation-token-01".to_string(),
                            target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
                            target_manifest_sha256: "a".repeat(64),
                            target_probe_version: "0.2.0".to_string(),
                        })),
                    }),
                    requested_snapshot_collector_ids: Vec::new(),
                    server_time_ms: 1,
                }
                .encode_to_vec(),
                ProbeReportResponse {
                    accepted_sequence_end: 2,
                    current_probe_configuration_version: "default-v1".to_string(),
                    pending_operation: None,
                    requested_snapshot_collector_ids: Vec::new(),
                    server_time_ms: 2,
                }
                .encode_to_vec(),
            ]),
        };
        let observed_launches = Rc::new(RefCell::new(Vec::new()));
        let observed_launches_for_factory = Rc::clone(&observed_launches);
        let mut sleeper = NoopSleeper;
        run_probe_with_loop_control_and_runner_factory(
            ProbeRunInput {
                bootstrap_config_path: bootstrap_config_path.clone(),
            },
            &mut transport,
            &mut sleeper,
            RunLoopControl {
                max_reports: Some(2),
            },
            move |_bootstrap_config, _bootstrap_config_path| SharedFakeOperationRunner {
                observed_launches: Rc::clone(&observed_launches_for_factory),
            },
        )
        .expect("registration then operation reporting succeeds");

        assert_eq!(
            observed_launches.borrow().as_slice(),
            &[(
                "operation-01".to_string(),
                "0.2.0".to_string(),
                "operation-token-01".to_string(),
            )],
        );
        let bootstrap_config =
            fs::read_to_string(bootstrap_config_path).expect("bootstrap config exists");
        assert!(!bootstrap_config.contains("upgrader_launch"));

        let reports = transport
            .observed_report_bodies
            .iter()
            .map(|body| ProbeReportRequest::decode(body.as_slice()).expect("report decodes"))
            .collect::<Vec<_>>();
        assert_eq!(
            reports[1].operation_acknowledgements[0].operation_id,
            "operation-01"
        );
        assert!(matches!(
            reports[1].operation_statuses[0].status,
            Some(Status::Failed(ref failed)) if failed.error_code == "probe_upgrader_noop"
        ));
    }

    struct RegistrationThenOperationTransport {
        observed_report_bodies: Vec<Vec<u8>>,
        registration_response: Vec<u8>,
        report_responses: VecDeque<Vec<u8>>,
    }

    impl RegistrationTransport for RegistrationThenOperationTransport {
        fn post_protobuf(
            &mut self,
            _url: &str,
            _body: Vec<u8>,
        ) -> Result<Vec<u8>, RegistrationError> {
            Ok(self.registration_response.clone())
        }
    }

    impl ReportTransport for RegistrationThenOperationTransport {
        fn post_protobuf_with_auth(
            &mut self,
            _url: &str,
            _auth: &ProbeRequestAuth<'_>,
            body: Vec<u8>,
        ) -> Result<Vec<u8>, ReportError> {
            self.observed_report_bodies.push(body);
            self.report_responses
                .pop_front()
                .ok_or(ReportError::InvalidResponse("missing fake report response"))
        }
    }

    impl ProbeTransport for RegistrationThenOperationTransport {}

    struct StartupRetryTransport {
        report_attempts: Vec<Vec<u8>>,
        report_responses: VecDeque<Result<Vec<u8>, ReportError>>,
    }

    impl RegistrationTransport for StartupRetryTransport {
        fn post_protobuf(
            &mut self,
            _url: &str,
            _body: Vec<u8>,
        ) -> Result<Vec<u8>, RegistrationError> {
            Err(RegistrationError::InvalidResponse(
                "registration is not expected for an established Probe",
            ))
        }
    }

    impl ReportTransport for StartupRetryTransport {
        fn post_protobuf_with_auth(
            &mut self,
            _url: &str,
            _auth: &ProbeRequestAuth<'_>,
            body: Vec<u8>,
        ) -> Result<Vec<u8>, ReportError> {
            self.report_attempts.push(body);
            self.report_responses
                .pop_front()
                .expect("a report response is configured")
        }
    }

    impl ProbeTransport for StartupRetryTransport {}

    struct NoopSleeper;

    impl ProbeRuntimeSleeper for NoopSleeper {
        fn sleep(&mut self, _duration: Duration) {}
    }

    struct SharedFakeOperationRunner {
        observed_launches: Rc<RefCell<Vec<(String, String, String)>>>,
    }

    impl ProbeOperationRunner for SharedFakeOperationRunner {
        fn run_probe_upgrade(
            &mut self,
            input: ProbeUpgradeRunnerInput<'_>,
        ) -> ProbeUpgradeRunnerOutcome {
            self.observed_launches.borrow_mut().push((
                input.operation.operation_id.to_string(),
                input.operation.target_probe_version.to_string(),
                input.stdin.to_string(),
            ));
            ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                error_code: "probe_upgrader_noop".to_string(),
                message: "fake no-op launch".to_string(),
            })
        }

        fn run_probe_uninstall(
            &mut self,
            input: ProbeUninstallRunnerInput<'_>,
        ) -> ProbeUpgradeRunnerOutcome {
            self.observed_launches.borrow_mut().push((
                input.operation_id.to_string(),
                "uninstall".to_string(),
                input.stdin.to_string(),
            ));
            ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                error_code: "probe_uninstaller_noop".to_string(),
                message: "fake no-op launch".to_string(),
            })
        }
    }
}
