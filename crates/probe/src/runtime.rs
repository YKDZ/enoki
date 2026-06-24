use std::{collections::HashSet, error::Error, fmt, fs, io::Read, path::PathBuf, time::Duration};

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
    host_profile::collect_local_host_profile,
    metrics::{CollectorCadenceSchedule, CollectorId, MetricsCollectionConfig, MetricsCollector},
    protocol::enoki::v1::{
        HostProfileSnapshot, ProbeConfigurationError, ProbeConfigurationRequest,
        ProbeConfigurationResponse, ProbeOperationAcknowledgement, ProbeOperationFailed,
        ProbeOperationRunning, ProbeOperationStatus, ProbeReportRequest, ProbeReportResponse,
        probe_operation::Operation, probe_operation_status::Status,
    },
    report::{full_host_profile_report, regular_report, startup_report},
    upgrader::{
        ProbeUninstallerLaunch, ProbeUpgraderCommandOutput, ProbeUpgraderLaunch,
        ProbeUpgraderLaunchError, SystemProbeUpgraderCommandRunner,
        launch_systemd_probe_uninstaller, launch_systemd_probe_upgrader,
        parse_probe_upgrader_result,
    },
};
use prost::Message;

const REPORTING_WINDOW_TICKS: u64 = 3;
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
        match error {
            ReportError::InvalidConfig(message) => Self::InvalidConfig(message),
            error => Self::Report(error),
        }
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

pub trait HostProfileProvider {
    fn collect_host_profile(&mut self) -> HostProfileSnapshot;
}

pub struct LocalHostProfileProvider;

impl HostProfileProvider for LocalHostProfileProvider {
    fn collect_host_profile(&mut self) -> HostProfileSnapshot {
        collect_local_host_profile()
    }
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
    InvalidConfig(&'static str),
    InvalidResponse(&'static str),
    InvalidSigningKey(String),
    Io(std::io::Error),
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(message) => {
                write!(formatter, "failed to decode report response: {message}")
            }
            Self::Http(message) => write!(formatter, "report request failed: {message}"),
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid Probe bootstrap config: {message}")
            }
            Self::InvalidResponse(message) => {
                write!(formatter, "invalid report response: {message}")
            }
            Self::InvalidSigningKey(message) => {
                write!(formatter, "invalid Probe signing key: {message}")
            }
            Self::Io(error) => write!(formatter, "failed to read report response: {error}"),
        }
    }
}

impl Error for ReportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Decode(_)
            | Self::Http(_)
            | Self::InvalidConfig(_)
            | Self::InvalidResponse(_)
            | Self::InvalidSigningKey(_) => None,
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
    fn post_protobuf_with_auth(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        let mut request = ureq::post(url)
            .set("accept", "application/x-protobuf")
            .set("content-type", "application/x-protobuf");
        for (name, value) in signed_probe_request_headers("POST", url, auth, &body)
            .map_err(ReportError::InvalidSigningKey)?
        {
            request = request.set(name, &value);
        }
        let response = request
            .send_bytes(&body)
            .map_err(|error| ReportError::Http(error.to_string()))?;
        let mut bytes = Vec::new();
        response.into_reader().read_to_end(&mut bytes)?;

        Ok(bytes)
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
    let mut host_profile_provider = LocalHostProfileProvider;

    run_probe_with_loop_control_and_host_profile_provider(
        input,
        transport,
        sleeper,
        control,
        &mut host_profile_provider,
    )
}

pub fn run_probe_with_loop_control_and_host_profile_provider(
    input: ProbeRunInput,
    transport: &mut impl ProbeTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
    host_profile_provider: &mut impl HostProfileProvider,
) -> Result<(), ProbeRunError> {
    run_probe_with_loop_control_and_runner_factory(
        input,
        transport,
        sleeper,
        control,
        host_profile_provider,
        InstalledProbeOperationRunner::from_bootstrap,
    )
}

fn run_probe_with_loop_control_and_runner_factory<Runner>(
    input: ProbeRunInput,
    transport: &mut impl ProbeTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
    host_profile_provider: &mut impl HostProfileProvider,
    mut runner_factory: impl FnMut(&BootstrapConfig, PathBuf) -> Runner,
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
            host_profile_provider,
            &mut operation_runner,
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
        host_profile_provider,
        &mut operation_runner,
    )?;

    Ok(())
}

fn run_reporting_loop(
    bootstrap_config: &BootstrapConfig,
    transport: &mut impl ReportTransport,
    sleeper: &mut impl ProbeRuntimeSleeper,
    control: RunLoopControl,
    host_profile_provider: &mut impl HostProfileProvider,
    operation_runner: &mut impl ProbeOperationRunner,
) -> Result<(), ReportError> {
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
    let mut host_profile = host_profile_provider.collect_host_profile();
    let boot_id = new_boot_id();
    let local_operation_statuses = read_local_operation_statuses(bootstrap_config);
    let mut active_configuration =
        ActiveProbeConfiguration::from_bootstrap(bootstrap_config, probe_configuration_version)?;
    let mut pending_configuration_error = None;
    let mut sequence = 1;
    let mut reports_sent = 0;
    let mut metrics_collector = MetricsCollector::default();
    let mut operation_reports = ProbeOperationReportQueue::default();
    let mut pending_report_body = None;
    let mut request = startup_report(
        probe_id,
        &boot_id,
        sequence,
        &active_configuration.version,
        host_profile.clone(),
        Vec::new(),
    );
    for status in &local_operation_statuses {
        request
            .operation_acknowledgements
            .push(ProbeOperationAcknowledgement {
                operation_id: status.operation_id.clone(),
            });
    }
    request.operation_statuses = local_operation_statuses;
    let response = post_report(transport, hub_url, &request_auth, request.encode_to_vec())?;
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

    if host_profile_snapshot_requested(&response) {
        if report_limit_reached(reports_sent, control) {
            return Ok(());
        }

        sequence += 1;
        host_profile = host_profile_provider.collect_host_profile();
        let request = full_host_profile_report(
            probe_id,
            &boot_id,
            sequence,
            sequence,
            &active_configuration.version,
            host_profile.clone(),
            Vec::new(),
        );
        let response = post_report(transport, hub_url, &request_auth, request.encode_to_vec())?;
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

            let latest_host_profile = host_profile_provider.collect_host_profile();
            let collector_capability_changed =
                latest_host_profile.collector_capabilities != host_profile.collector_capabilities;
            host_profile = latest_host_profile;

            let request = if collector_capability_changed {
                full_host_profile_report(
                    probe_id,
                    &boot_id,
                    sequence_start,
                    sequence_end,
                    &active_configuration.version,
                    host_profile.clone(),
                    metrics,
                )
            } else {
                regular_report(
                    probe_id,
                    &boot_id,
                    sequence_start,
                    sequence_end,
                    &active_configuration.version,
                    &host_profile,
                    metrics,
                )
            };
            let request = with_configuration_error(request, pending_configuration_error.take());
            let request = operation_reports.with_operation_reports(request);

            request.encode_to_vec()
        };
        let response = match post_report(transport, hub_url, &request_auth, request_body.clone()) {
            Ok(response) => response,
            Err(_) => {
                pending_report_body = Some(request_body);
                continue;
            }
        };
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

        if host_profile_snapshot_requested(&response)
            && !report_limit_reached(reports_sent, control)
        {
            sequence += 1;
            host_profile = host_profile_provider.collect_host_profile();
            let request = full_host_profile_report(
                probe_id,
                &boot_id,
                sequence,
                sequence,
                &active_configuration.version,
                host_profile.clone(),
                Vec::new(),
            );
            let request = with_configuration_error(request, pending_configuration_error.take());
            let request = operation_reports.with_operation_reports(request);
            let request_body = request.encode_to_vec();
            let response =
                match post_report(transport, hub_url, &request_auth, request_body.clone()) {
                    Ok(response) => response,
                    Err(_) => {
                        pending_report_body = Some(request_body);
                        continue;
                    }
                };
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
        .unwrap_or_else(|| PathBuf::from("/etc/enoki/probe-bootstrap.toml"))
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

struct InstalledProbeOperationRunner {
    bootstrap_config_path: PathBuf,
    install_path: Option<PathBuf>,
    launch: Option<String>,
}

impl InstalledProbeOperationRunner {
    fn from_bootstrap(bootstrap_config: &BootstrapConfig, bootstrap_config_path: PathBuf) -> Self {
        Self {
            bootstrap_config_path,
            install_path: bootstrap_config.install_path.as_ref().map(PathBuf::from),
            launch: bootstrap_config.upgrader_launch.clone(),
        }
    }
}

impl ProbeOperationRunner for InstalledProbeOperationRunner {
    fn run_probe_upgrade(
        &mut self,
        input: ProbeUpgradeRunnerInput<'_>,
    ) -> ProbeUpgradeRunnerOutcome {
        let _ = input.operation.current_probe_version;
        let Some(install_path) = self.install_path.clone() else {
            return ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                error_code: "unsupported_installation".to_string(),
                message: "Probe Upgrader launch is not configured.".to_string(),
            });
        };
        if self.launch.as_deref() != Some("systemd") {
            return ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                error_code: "unsupported_installation".to_string(),
                message: "Probe Upgrader requires a systemd installation.".to_string(),
            });
        }

        let mut runner = SystemProbeUpgraderCommandRunner;
        probe_upgrade_outcome_from_launch_result(launch_systemd_probe_upgrader(
            ProbeUpgraderLaunch {
                bootstrap_config_path: self.bootstrap_config_path.clone(),
                install_path,
                operation_id: input.operation.operation_id.to_string(),
                target_probe_version: input.operation.target_probe_version.to_string(),
                token: input.stdin.to_string(),
            },
            &mut runner,
        ))
    }

    fn run_probe_uninstall(
        &mut self,
        input: ProbeUninstallRunnerInput<'_>,
    ) -> ProbeUpgradeRunnerOutcome {
        let Some(install_path) = self.install_path.clone() else {
            return ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                error_code: "unsupported_installation".to_string(),
                message: "Probe Uninstaller launch is not configured.".to_string(),
            });
        };
        if self.launch.as_deref() != Some("systemd") {
            return ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                error_code: "unsupported_installation".to_string(),
                message: "Probe Uninstaller requires a systemd installation.".to_string(),
            });
        }

        let mut runner = SystemProbeUpgraderCommandRunner;
        probe_upgrade_outcome_from_launch_result(launch_systemd_probe_uninstaller(
            ProbeUninstallerLaunch {
                bootstrap_config_path: self.bootstrap_config_path.clone(),
                install_path,
                operation_id: input.operation_id.to_string(),
                token: input.stdin.to_string(),
            },
            &mut runner,
        ))
    }
}

fn probe_upgrade_outcome_from_launch_result(
    result: Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError>,
) -> ProbeUpgradeRunnerOutcome {
    match result {
        Ok(output) => match parse_probe_upgrader_result(&output.stdout) {
            Some(result) if result.status == "running" => ProbeUpgradeRunnerOutcome::Running,
            Some(result) if result.status == "failed" => {
                ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                    error_code: result
                        .error_code
                        .unwrap_or_else(|| "probe_upgrader_failed".to_string()),
                    message: result.message.unwrap_or_default(),
                })
            }
            _ => ProbeUpgradeRunnerOutcome::Running,
        },
        Err(ProbeUpgraderLaunchError::UnsupportedInstallation(message)) => {
            ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                error_code: "unsupported_installation".to_string(),
                message,
            })
        }
        Err(ProbeUpgraderLaunchError::InsufficientPrivilege(message)) => {
            ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                error_code: "insufficient_privilege".to_string(),
                message,
            })
        }
    }
}

#[derive(Default)]
struct ProbeOperationReportQueue {
    acknowledgements: Vec<String>,
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
                        operation_id: &operation.id,
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
        self.acknowledgements.push(operation.id.clone());
        self.statuses.push((
            operation.id.clone(),
            match outcome {
                ProbeUpgradeRunnerOutcome::Running => Status::Running(ProbeOperationRunning {}),
                ProbeUpgradeRunnerOutcome::Failed(failed) => Status::Failed(failed),
            },
        ));
    }

    fn with_operation_reports(&mut self, mut request: ProbeReportRequest) -> ProbeReportRequest {
        for operation_id in self.acknowledgements.drain(..) {
            request
                .operation_acknowledgements
                .push(ProbeOperationAcknowledgement {
                    operation_id: operation_id.clone(),
                });
        }

        for (operation_id, status) in self.statuses.drain(..) {
            request.operation_statuses.push(ProbeOperationStatus {
                operation_id,
                status: Some(status),
            });
        }

        request
    }
}

#[cfg(test)]
mod operation_report_tests {
    use super::*;

    #[test]
    fn successful_upgrader_launch_reports_running() {
        let outcome = probe_upgrade_outcome_from_launch_result(Ok(ProbeUpgraderCommandOutput {
            stdout: "Probe Upgrader result: operation=operation-01 status=running\n".to_string(),
        }));

        assert!(matches!(outcome, ProbeUpgradeRunnerOutcome::Running));
    }

    #[test]
    fn launch_insufficient_privilege_reports_failed_status() {
        let outcome = probe_upgrade_outcome_from_launch_result(Err(
            ProbeUpgraderLaunchError::InsufficientPrivilege("sudo denied".to_string()),
        ));

        assert!(matches!(
            outcome,
            ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                ref error_code,
                ref message,
            }) if error_code == "insufficient_privilege" && message == "sudo denied"
        ));
    }

    #[test]
    fn unsupported_installation_reports_failed_status() {
        let outcome = probe_upgrade_outcome_from_launch_result(Err(
            ProbeUpgraderLaunchError::UnsupportedInstallation("sudo missing".to_string()),
        ));

        assert!(matches!(
            outcome,
            ProbeUpgradeRunnerOutcome::Failed(ProbeOperationFailed {
                ref error_code,
                ref message,
            }) if error_code == "unsupported_installation" && message == "sudo missing"
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
                            operation_token: "operation-token".to_string(),
                            target_probe_version: "0.2.0".to_string(),
                        },
                    )),
                }),
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1,
            },
            &mut runner,
        );

        let request = queue.with_operation_reports(ProbeReportRequest::default());

        assert_eq!(request.operation_acknowledgements.len(), 1);
        assert_eq!(request.operation_statuses.len(), 1);
        assert!(matches!(
            request.operation_statuses[0].status,
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
    let response_body = transport.post_protobuf_with_auth(&report_url(hub_url), auth, body)?;

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

    let schedule = CollectorCadenceSchedule::for_tick_interval(
        active_configuration.metrics_collection_interval,
    );
    let mut metrics = Vec::new();

    for _ in 0..REPORTING_WINDOW_TICKS {
        sleeper.sleep(active_configuration.metrics_collection_interval);
        *sequence += 1;
        if let Some(sample) = metrics_collector.collect_after(
            *sequence,
            active_configuration.metrics_collection_interval,
            schedule,
            &active_configuration.metrics_config,
        ) {
            metrics.push(sample);
        }
    }

    (sequence_start, *sequence, metrics)
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
    auth: &ProbeRequestAuth<'_>,
    current_version: &str,
) -> Result<ProbeConfigurationResponse, ReportError> {
    let request = ProbeConfigurationRequest {
        current_version: current_version.to_string(),
        probe_id: probe_id.to_string(),
    };
    let response_body =
        transport.post_protobuf_with_auth(&config_url(hub_url), auth, request.encode_to_vec())?;

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
    enabled_collector_ids: Option<Vec<String>>,
    enrollment_token: Option<String>,
    hub_url: Option<String>,
    install_path: Option<String>,
    metrics_collection_interval_seconds: Option<u64>,
    operation_status_path: Option<String>,
    probe_configuration_version: Option<String>,
    probe_id: Option<String>,
    probe_private_key_pem: Option<String>,
    server_time_offset_ms: Option<i64>,
    state_dir: Option<String>,
    upgrader_launch: Option<String>,
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
        enabled_collector_ids: string_array_value(&value, "enabled_collector_ids")?,
        enrollment_token: string_value(&value, "enrollment_token")?,
        hub_url: string_value(&value, "hub_url")?,
        install_path: string_value(&value, "install_path")?,
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
        upgrader_launch: string_value(&value, "upgrader_launch")?,
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
    use crate::protocol::enoki::v1::{
        ProbeConfigurationResponse, ProbeRegistrationResponse, ProbeUpgradeOperation,
    };
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    #[cfg(unix)]
    use std::os::unix::{fs::PermissionsExt, fs::symlink};

    #[test]
    fn observation_batch_keeps_low_frequency_collectors_off_high_frequency_ticks() {
        let active_configuration = ActiveProbeConfiguration {
            metrics_collection_interval: Duration::from_secs(5),
            metrics_config: MetricsCollectionConfig::all_enabled(),
            reporting_interval: Duration::from_secs(15),
            version: "default-v1".to_string(),
        };
        let mut sequence = 1;
        let mut sleeper = NoopSleeper;
        let mut metrics_collector = MetricsCollector::from_registry(
            crate::metrics::CollectorRegistry::from_collectors(vec![
                Box::new(FakeMetricCollector {
                    cadence: crate::metrics::CollectorCadence::EveryTick,
                    metric_field: FakeMetricField::Cpu,
                }),
                Box::new(FakeMetricCollector {
                    cadence: crate::metrics::CollectorCadence::Every12Ticks,
                    metric_field: FakeMetricField::Load,
                }),
            ]),
        );

        let (_, _, metrics) = collect_observation_batch(
            &mut sleeper,
            &active_configuration,
            &mut sequence,
            &mut metrics_collector,
        );

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
                .all(|sample| sample.cpu_percent == Some(42.0))
        );
        assert!(metrics.iter().all(|sample| sample.load_1.is_none()));
    }

    #[test]
    fn observation_batch_collects_low_frequency_metrics_every_four_reporting_windows() {
        let active_configuration = ActiveProbeConfiguration {
            metrics_collection_interval: Duration::from_secs(7),
            metrics_config: MetricsCollectionConfig::all_enabled(),
            reporting_interval: Duration::from_secs(21),
            version: "default-v1".to_string(),
        };
        let mut sequence = 0;
        let mut sleeper = NoopSleeper;
        let mut metrics_collector =
            MetricsCollector::from_registry(crate::metrics::CollectorRegistry::from_collectors(
                vec![Box::new(FakeMetricCollector {
                    cadence: crate::metrics::CollectorCadence::Every12Ticks,
                    metric_field: FakeMetricField::Load,
                })],
            ));

        let (_, _, first_metrics) = collect_observation_batch(
            &mut sleeper,
            &active_configuration,
            &mut sequence,
            &mut metrics_collector,
        );
        let (_, _, second_metrics) = collect_observation_batch(
            &mut sleeper,
            &active_configuration,
            &mut sequence,
            &mut metrics_collector,
        );
        let (_, _, third_metrics) = collect_observation_batch(
            &mut sleeper,
            &active_configuration,
            &mut sequence,
            &mut metrics_collector,
        );
        let (_, _, fourth_metrics) = collect_observation_batch(
            &mut sleeper,
            &active_configuration,
            &mut sequence,
            &mut metrics_collector,
        );

        assert!(first_metrics.is_empty());
        assert!(second_metrics.is_empty());
        assert!(third_metrics.is_empty());
        assert_eq!(
            fourth_metrics
                .iter()
                .map(|sample| sample.sequence)
                .collect::<Vec<_>>(),
            vec![12],
        );
    }

    enum FakeMetricField {
        Cpu,
        Load,
    }

    struct FakeMetricCollector {
        cadence: crate::metrics::CollectorCadence,
        metric_field: FakeMetricField,
    }

    impl crate::metrics::MetricCollector for FakeMetricCollector {
        fn definition(&self) -> crate::metrics::CollectorDefinition {
            crate::metrics::CollectorDefinition::new(self.metric_field.collector_id(), self.cadence)
        }

        fn collect(
            &mut self,
            sample: &mut crate::protocol::enoki::v1::MetricSample,
        ) -> Result<bool, crate::metrics::CollectorError> {
            match self.metric_field {
                FakeMetricField::Cpu => sample.cpu_percent = Some(42.0),
                FakeMetricField::Load => sample.load_1 = Some(1.0),
            }

            Ok(true)
        }
    }

    impl FakeMetricField {
        fn collector_id(&self) -> crate::metrics::CollectorId {
            match self {
                FakeMetricField::Cpu => crate::metrics::CollectorId::Cpu,
                FakeMetricField::Load => crate::metrics::CollectorId::Load,
            }
        }
    }

    #[derive(Default)]
    struct RecordingOperationRunner {
        observed_current_probe_version: Option<String>,
        observed_operation_id: Option<String>,
        observed_stdin: Option<String>,
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
                    operation_token: "operation-token-01".to_string(),
                    target_probe_version: "0.2.0".to_string(),
                })),
            }),
            requested_snapshot_collector_ids: Vec::new(),
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
                    operation_token: "operation-token-01".to_string(),
                    target_probe_version: "0.2.0".to_string(),
                })),
            }),
            requested_snapshot_collector_ids: Vec::new(),
            server_time_ms: 1_725_000_000_000,
        };

        queue.observe_response(&response, &mut runner);
        let request = queue.with_operation_reports(ProbeReportRequest::default());

        assert_eq!(request.operation_acknowledgements.len(), 1);
        assert!(matches!(
            &request.operation_statuses[0],
            ProbeOperationStatus {
                status: Some(Status::Failed(failed)),
                ..
            } if failed.error_code == "insufficient_privilege"
                && failed.message == "sudoers rule is missing"
        ));
    }

    #[test]
    fn install_config_registration_then_operation_uses_preserved_fake_launch_metadata() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "enrollment_token = \"enk_enroll_secret\"",
                "state_dir = \"/var/lib/enoki-probe\"",
                "install_path = \"/usr/local/bin/enoki-probe\"",
                "upgrader_launch = \"systemd\"",
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
                            operation_token: "operation-token-01".to_string(),
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
        let mut host_profile_provider = LocalHostProfileProvider;

        run_probe_with_loop_control_and_runner_factory(
            ProbeRunInput {
                bootstrap_config_path: bootstrap_config_path.clone(),
            },
            &mut transport,
            &mut sleeper,
            RunLoopControl {
                max_reports: Some(2),
            },
            &mut host_profile_provider,
            move |bootstrap_config, _bootstrap_config_path| {
                assert_eq!(
                    bootstrap_config.install_path.as_deref(),
                    Some("/usr/local/bin/enoki-probe"),
                );
                assert_eq!(bootstrap_config.upgrader_launch.as_deref(), Some("systemd"));
                SharedFakeOperationRunner {
                    observed_launches: Rc::clone(&observed_launches_for_factory),
                }
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
        assert!(bootstrap_config.contains("install_path = \"/usr/local/bin/enoki-probe\""));
        assert!(bootstrap_config.contains("upgrader_launch = \"systemd\""));

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
