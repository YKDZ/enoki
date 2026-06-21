use std::{fs, time::Duration};

use enoki_probe::{
    protocol::enoki::v1::{
        ProbeConfigurationRequest, ProbeConfigurationResponse, ProbeOperation,
        ProbeOperationStatus, ProbeRegistrationRequest, ProbeRegistrationResponse,
        ProbeReportRequest, ProbeReportResponse, ProbeUpgradeOperation, probe_operation::Operation,
        probe_operation_status::Status,
    },
    registration::{RegistrationError, RegistrationTransport},
    runtime::{
        ProbeRunError, ProbeRunInput, ProbeRuntimeSleeper, ProbeTransport, ReportError,
        ReportTransport, RunLoopControl, run_loop_control_from_environment, run_probe,
        run_probe_with_loop_control,
    },
};
use prost::Message;

#[test]
fn probe_run_fails_when_bootstrap_config_is_missing() {
    let temp = tempfile::tempdir().expect("temp dir");
    let missing_config_path = temp.path().join("missing.toml");
    let mut transport = NoopTransport;

    let error = run_probe(
        ProbeRunInput {
            bootstrap_config_path: missing_config_path.clone(),
        },
        &mut transport,
    )
    .expect_err("missing config fails");

    assert!(matches!(error, ProbeRunError::Io(_)));
    assert_eq!(error.to_string(), "failed to read Probe bootstrap config");
}

#[test]
fn probe_run_registers_from_enrollment_token_and_removes_token_from_config() {
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
    .expect("write bootstrap config");
    let response = ProbeRegistrationResponse {
        initial_configuration: Some(ProbeConfigurationResponse {
            collect_cpu: true,
            collect_disk: true,
            collect_load: true,
            collect_memory: true,
            collect_network: true,
            collect_uptime: true,
            metrics_collection_interval_seconds: 5,
            reporting_batch_interval_seconds: 15,
            version: "default-v1".to_string(),
        }),
        probe_id: "probe_01".to_string(),
        probe_secret: "enk_probe_secret".to_string(),
        server_time_ms: 1_725_000_000_000,
    }
    .encode_to_vec();
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_report_bodies: Vec::new(),
        observed_report_url: String::new(),
        observed_url: String::new(),
        report_response: report_response(1, false),
        response,
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(1),
        },
    )
    .expect("bootstrap registration succeeds");

    assert_eq!(
        transport.observed_url,
        "https://hub.example/api/probe/register",
    );
    let request = ProbeRegistrationRequest::decode(transport.observed_body.as_slice())
        .expect("registration request decodes");
    assert_eq!(request.enrollment_token, "enk_enroll_secret");

    let bootstrap_config =
        fs::read_to_string(bootstrap_config_path).expect("bootstrap config exists");
    assert!(bootstrap_config.contains("hub_url = \"https://hub.example\""));
    assert!(bootstrap_config.contains("probe_id = \"probe_01\""));
    assert!(bootstrap_config.contains("probe_secret = \"enk_probe_secret\""));
    assert!(bootstrap_config.contains("probe_configuration_version = \"default-v1\""));
    assert!(bootstrap_config.contains("metrics_collection_interval_seconds = 5"));
    assert!(bootstrap_config.contains("reporting_batch_interval_seconds = 15"));
    assert!(bootstrap_config.contains("collect_cpu = true"));
    assert!(bootstrap_config.contains("collect_memory = true"));
    assert!(bootstrap_config.contains("collect_disk = true"));
    assert!(bootstrap_config.contains("collect_network = true"));
    assert!(bootstrap_config.contains("collect_load = true"));
    assert!(bootstrap_config.contains("collect_uptime = true"));
    assert!(!bootstrap_config.contains("enrollment_token"));
    assert!(!bootstrap_config.contains("enk_enroll_secret"));

    assert_eq!(
        transport.observed_report_url,
        "https://hub.example/api/probe/report",
    );
    let report = ProbeReportRequest::decode(transport.observed_report_bodies[0].as_slice())
        .expect("post-registration report decodes");
    assert_eq!(report.probe_id, "probe_01");
    assert_eq!(report.sequence_start, 1);
    assert_eq!(report.sequence_end, 1);
    assert!(report.inventory.is_some());
}

#[test]
fn probe_run_with_existing_identity_sends_startup_inventory_even_without_metrics() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        response: ProbeReportResponse {
            accepted_sequence_end: 1,
            current_probe_configuration_version: "default-v1".to_string(),
            inventory_needed: false,
            pending_operation: None,
            server_time_ms: 1_725_000_000_000,
        }
        .encode_to_vec(),
        ..RecordingProbeTransport::default()
    };

    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(1),
        },
    )
    .expect("startup report succeeds");

    assert_eq!(
        transport.observed_report_url,
        "https://hub.example/api/probe/report",
    );
    assert_eq!(transport.observed_bearer, "enk_probe_secret");
    let request = ProbeReportRequest::decode(transport.observed_report_bodies[0].as_slice())
        .expect("report request decodes");
    assert_eq!(request.probe_id, "probe_01");
    assert_eq!(request.boot_id.len(), "boot-".len() + 32);
    assert!(request.boot_id.starts_with("boot-"));
    assert!(
        request
            .boot_id
            .trim_start_matches("boot-")
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );
    assert_eq!(request.probe_configuration_version, "default-v1");
    assert_eq!(request.sequence_start, 1);
    assert_eq!(request.sequence_end, 1);
    let inventory = request
        .inventory
        .expect("startup report includes Inventory");
    assert!(!inventory.architecture.is_empty());
    assert!(inventory.cpu_count >= 1);
    assert!(inventory.memory_total_bytes > 0);
    assert!(!inventory.os.is_empty());
    assert!(!request.inventory_hash.is_empty());
    assert!(request.metrics.is_empty());
}

#[test]
fn probe_run_sends_full_inventory_on_the_next_report_when_the_hub_requests_it() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![
            ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "default-v1".to_string(),
                inventory_needed: true,
                pending_operation: None,
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec(),
            ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "default-v1".to_string(),
                inventory_needed: false,
                pending_operation: None,
                server_time_ms: 1_725_000_000_001,
            }
            .encode_to_vec(),
        ],
        ..RecordingProbeTransport::default()
    };

    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("startup report succeeds");

    assert_eq!(transport.observed_report_bodies.len(), 2);
    let follow_up = ProbeReportRequest::decode(transport.observed_report_bodies[1].as_slice())
        .expect("follow-up report request decodes");
    assert_eq!(follow_up.probe_id, "probe_01");
    let startup = ProbeReportRequest::decode(transport.observed_report_bodies[0].as_slice())
        .expect("startup report request decodes");
    assert_eq!(follow_up.boot_id, startup.boot_id);
    assert_eq!(follow_up.sequence_start, 2);
    assert_eq!(follow_up.sequence_end, 2);
    assert!(follow_up.inventory.is_some());
    assert!(!follow_up.inventory_hash.is_empty());
    assert!(follow_up.metrics.is_empty());
}

#[test]
fn probe_run_loop_reports_metrics_batches_on_the_configured_cadence() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "reporting_batch_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![
            report_response(1, false),
            report_response(2, false),
            report_response(3, false),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(3),
        },
    )
    .expect("run loop reports deterministically");

    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(7); 2]);
    assert!(
        transport
            .observed_calls
            .iter()
            .all(|call| call.url == "https://hub.example/api/probe/report")
    );
    assert_eq!(transport.observed_report_bodies.len(), 3);
    let reports = transport
        .observed_report_bodies
        .iter()
        .map(|body| ProbeReportRequest::decode(body.as_slice()).expect("report decodes"))
        .collect::<Vec<_>>();
    let boot_id = reports[0].boot_id.clone();
    assert_eq!(
        reports
            .iter()
            .map(|report| (report.sequence_start, report.sequence_end))
            .collect::<Vec<_>>(),
        vec![(1, 1), (2, 2), (3, 3)],
    );
    assert!(reports[0].inventory.is_some());
    assert_eq!(reports[1].boot_id, boot_id);
    assert_eq!(reports[2].boot_id, boot_id);
    assert!(reports[1].inventory.is_none());
    assert!(reports[2].inventory.is_none());
    assert!(reports[0].metrics.is_empty());
    assert_eq!(reports[1].metrics.len(), 1);
    assert_eq!(reports[1].metrics[0].sequence, 2);
    assert!(reports[1].metrics[0].collected_at_ms > 0);
    assert!(reports[1].metrics[0].cpu_percent.unwrap_or(-1.0) >= 0.0);
    assert!(reports[1].metrics[0].memory_used_bytes.unwrap_or(0) > 0);
    assert_eq!(reports[2].metrics.len(), 1);
    assert_eq!(reports[2].metrics[0].sequence, 3);
}

#[test]
fn probe_run_loop_control_can_be_limited_by_smoke_environment() {
    assert_eq!(
        run_loop_control_from_environment(|name| {
            assert_eq!(name, "ENOKI_PROBE_MAX_REPORTS");
            Some("3".to_string())
        })
        .expect("valid smoke limit parses"),
        RunLoopControl {
            max_reports: Some(3),
        },
    );
}

#[test]
fn probe_run_loop_omits_disabled_individual_metric_fields() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"memory-only-v1\"",
            "metrics_collection_interval_seconds = 7",
            "reporting_batch_interval_seconds = 7",
            "collect_cpu = false",
            "collect_memory = true",
            "collect_disk = false",
            "collect_network = false",
            "collect_load = false",
            "collect_uptime = false",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![
            report_response_with_version(1, false, "memory-only-v1"),
            report_response_with_version(2, false, "memory-only-v1"),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("run loop reports memory-only metrics");

    let report = ProbeReportRequest::decode(transport.observed_report_bodies[1].as_slice())
        .expect("report decodes");
    let sample = report.metrics.first().expect("memory sample");
    assert_eq!(sample.cpu_percent, None);
    assert_eq!(sample.load_1, None);
    assert_eq!(sample.uptime_seconds, None);
    assert!(sample.disks.is_empty());
    assert!(sample.network_interfaces.is_empty());
    assert!(sample.memory_used_bytes.unwrap_or(0) > 0);
    assert!(sample.memory_total_bytes.unwrap_or(0) > 0);
}

#[test]
fn probe_run_loop_batches_metrics_at_the_configured_collection_interval() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 2",
            "reporting_batch_interval_seconds = 6",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![report_response(1, false), report_response(4, false)],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("run loop batches metrics deterministically");

    assert_eq!(
        sleeper.observed_sleeps,
        vec![
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
        ],
    );
    let report = ProbeReportRequest::decode(transport.observed_report_bodies[1].as_slice())
        .expect("report decodes");
    assert_eq!(report.sequence_start, 2);
    assert_eq!(report.sequence_end, 4);
    assert_eq!(
        report
            .metrics
            .iter()
            .map(|sample| sample.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3, 4],
    );
}

#[test]
fn probe_run_loop_allows_equal_one_second_collection_and_reporting_intervals() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 1",
            "reporting_batch_interval_seconds = 1",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![report_response(1, false), report_response(2, false)],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("run loop allows one-second intervals");

    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(1)]);
    let report = ProbeReportRequest::decode(transport.observed_report_bodies[1].as_slice())
        .expect("report decodes");
    assert_eq!(report.sequence_start, 2);
    assert_eq!(report.sequence_end, 2);
    assert_eq!(
        report
            .metrics
            .iter()
            .map(|sample| sample.sequence)
            .collect::<Vec<_>>(),
        vec![2],
    );
}

#[test]
fn probe_run_loop_keeps_reporting_empty_batches_when_metrics_are_disabled() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"disabled-v1\"",
            "reporting_batch_interval_seconds = 7",
            "collect_cpu = false",
            "collect_memory = false",
            "collect_disk = false",
            "collect_network = false",
            "collect_load = false",
            "collect_uptime = false",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![
            report_response_with_version(1, false, "disabled-v1"),
            report_response_with_version(2, false, "disabled-v1"),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("run loop reports deterministically");

    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(7)]);
    let reports = transport
        .observed_report_bodies
        .iter()
        .map(|body| ProbeReportRequest::decode(body.as_slice()).expect("report decodes"))
        .collect::<Vec<_>>();

    assert_eq!(
        reports
            .iter()
            .map(|report| (report.sequence_start, report.sequence_end))
            .collect::<Vec<_>>(),
        vec![(1, 1), (2, 2)],
    );
    assert!(reports.iter().all(|report| report.metrics.is_empty()));
}

#[test]
fn probe_run_fetches_and_applies_new_configuration_after_ack_version_changes() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "reporting_batch_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![
            ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec(),
            ProbeConfigurationResponse {
                collect_cpu: false,
                collect_disk: false,
                collect_load: false,
                collect_memory: false,
                collect_network: false,
                collect_uptime: false,
                metrics_collection_interval_seconds: 10,
                reporting_batch_interval_seconds: 11,
                version: "global-2".to_string(),
            }
            .encode_to_vec(),
            ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                server_time_ms: 1_725_000_000_001,
            }
            .encode_to_vec(),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("run loop applies newer Probe Configuration");

    assert_eq!(
        transport
            .observed_calls
            .iter()
            .map(|call| call.url.as_str())
            .collect::<Vec<_>>(),
        vec![
            "https://hub.example/api/probe/report",
            "https://hub.example/api/probe/config",
            "https://hub.example/api/probe/report",
        ],
    );
    let config_request =
        ProbeConfigurationRequest::decode(transport.observed_calls[1].body.as_slice())
            .expect("configuration request decodes");
    assert_eq!(config_request.probe_id, "probe_01");
    assert_eq!(config_request.current_version, "default-v1");
    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(11)]);

    let reports = transport
        .observed_report_bodies
        .iter()
        .map(|body| ProbeReportRequest::decode(body.as_slice()).expect("report decodes"))
        .collect::<Vec<_>>();
    assert_eq!(reports[0].probe_configuration_version, "default-v1");
    assert_eq!(reports[1].probe_configuration_version, "global-2");
    assert!(reports[1].metrics.is_empty());
}

#[test]
fn probe_run_keeps_last_valid_configuration_and_reports_error_when_apply_fails() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "reporting_batch_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![
            ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "global-bad".to_string(),
                inventory_needed: false,
                pending_operation: None,
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec(),
            ProbeConfigurationResponse {
                collect_cpu: true,
                collect_disk: true,
                collect_load: true,
                collect_memory: true,
                collect_network: true,
                collect_uptime: true,
                metrics_collection_interval_seconds: 60,
                reporting_batch_interval_seconds: 30,
                version: "global-bad".to_string(),
            }
            .encode_to_vec(),
            ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "global-bad".to_string(),
                inventory_needed: false,
                pending_operation: None,
                server_time_ms: 1_725_000_000_001,
            }
            .encode_to_vec(),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("run loop keeps reporting after rejected Probe Configuration");

    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(7)]);
    let reports = transport
        .observed_report_bodies
        .iter()
        .map(|body| ProbeReportRequest::decode(body.as_slice()).expect("report decodes"))
        .collect::<Vec<_>>();
    assert_eq!(reports[0].probe_configuration_version, "default-v1");
    assert_eq!(reports[1].probe_configuration_version, "default-v1");
    assert_eq!(
        reports[1]
            .probe_configuration_error
            .as_ref()
            .map(|error| error.failed_version.as_str()),
        Some("global-bad"),
    );
    assert_eq!(
        reports[1]
            .probe_configuration_error
            .as_ref()
            .map(|error| error.error_code.as_str()),
        Some("invalid_probe_configuration"),
    );
}

#[test]
fn probe_run_keeps_reporting_when_configuration_fetch_fails() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "reporting_batch_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        response_results: vec![
            Ok(ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec()),
            Err(ReportError::Http("503 Service Unavailable".to_string())),
            Ok(ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                server_time_ms: 1_725_000_000_001,
            }
            .encode_to_vec()),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("run loop keeps reporting after Probe Configuration fetch failure");

    assert_eq!(
        transport
            .observed_calls
            .iter()
            .map(|call| call.url.as_str())
            .collect::<Vec<_>>(),
        vec![
            "https://hub.example/api/probe/report",
            "https://hub.example/api/probe/config",
            "https://hub.example/api/probe/report",
        ],
    );
    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(7)]);
    let reports = transport
        .observed_report_bodies
        .iter()
        .map(|body| ProbeReportRequest::decode(body.as_slice()).expect("report decodes"))
        .collect::<Vec<_>>();
    assert_eq!(reports[0].probe_configuration_version, "default-v1");
    assert_eq!(reports[1].probe_configuration_version, "default-v1");
    assert_eq!(
        reports[1]
            .probe_configuration_error
            .as_ref()
            .map(|error| error.failed_version.as_str()),
        Some("global-2"),
    );
    assert_eq!(
        reports[1]
            .probe_configuration_error
            .as_ref()
            .map(|error| error.error_code.as_str()),
        Some("probe_configuration_fetch_failed"),
    );
}

#[test]
fn probe_run_keeps_reporting_when_configuration_response_is_malformed() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "reporting_batch_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![
            ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec(),
            vec![0xff, 0xff, 0xff],
            ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                server_time_ms: 1_725_000_000_001,
            }
            .encode_to_vec(),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("run loop keeps reporting after malformed Probe Configuration response");

    let reports = transport
        .observed_report_bodies
        .iter()
        .map(|body| ProbeReportRequest::decode(body.as_slice()).expect("report decodes"))
        .collect::<Vec<_>>();
    assert_eq!(reports[1].probe_configuration_version, "default-v1");
    assert_eq!(
        reports[1]
            .probe_configuration_error
            .as_ref()
            .map(|error| error.error_code.as_str()),
        Some("probe_configuration_fetch_failed"),
    );
}

#[test]
fn probe_run_retries_regular_report_after_transient_report_failure() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 1",
            "reporting_batch_interval_seconds = 1",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        response_results: vec![
            Ok(report_response(1, false)),
            Err(ReportError::Http("connection refused".to_string())),
            Ok(report_response(2, false)),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(2),
        },
    )
    .expect("run loop retries regular report after transient failure");

    assert_eq!(
        sleeper.observed_sleeps,
        vec![Duration::from_secs(1), Duration::from_secs(1)],
    );
    assert_eq!(transport.observed_report_bodies.len(), 3);
    let reports = transport
        .observed_report_bodies
        .iter()
        .map(|body| ProbeReportRequest::decode(body.as_slice()).expect("report decodes"))
        .collect::<Vec<_>>();
    assert_eq!(
        reports
            .iter()
            .map(|report| (report.sequence_start, report.sequence_end))
            .collect::<Vec<_>>(),
        vec![(1, 1), (2, 2), (2, 2)],
    );
}

#[test]
fn probe_runtime_acknowledges_and_reports_probe_upgrade_operation_status() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_secret = \"enk_probe_secret\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 5",
            "reporting_batch_interval_seconds = 5",
            "collect_cpu = false",
            "collect_memory = false",
            "collect_disk = false",
            "collect_network = false",
            "collect_load = false",
            "collect_uptime = false",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingProbeTransport {
        responses: vec![
            report_response_with_operation("operation-01", "0.1.0", "0.2.0"),
            report_response(2, false),
            report_response(3, false),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();

    run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(3),
        },
    )
    .expect("Probe runtime reports operation status");

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
        Some(Status::Running(_))
    ));
    assert_eq!(
        reports[2].operation_statuses[0].operation_id,
        "operation-01"
    );
    assert!(matches!(
        &reports[2].operation_statuses[0],
        ProbeOperationStatus {
            status: Some(Status::Failed(failed)),
            ..
        } if failed.error_code == "unsupported_installation"
    ));
}

fn report_response(accepted_sequence_end: u64, inventory_needed: bool) -> Vec<u8> {
    report_response_with_version(accepted_sequence_end, inventory_needed, "default-v1")
}

fn report_response_with_version(
    accepted_sequence_end: u64,
    inventory_needed: bool,
    version: &str,
) -> Vec<u8> {
    ProbeReportResponse {
        accepted_sequence_end,
        current_probe_configuration_version: version.to_string(),
        inventory_needed,
        pending_operation: None,
        server_time_ms: 1_725_000_000_000,
    }
    .encode_to_vec()
}

fn report_response_with_operation(
    operation_id: &str,
    current_probe_version: &str,
    target_probe_version: &str,
) -> Vec<u8> {
    ProbeReportResponse {
        accepted_sequence_end: 1,
        current_probe_configuration_version: "default-v1".to_string(),
        inventory_needed: false,
        pending_operation: Some(ProbeOperation {
            id: operation_id.to_string(),
            operation: Some(Operation::ProbeUpgrade(ProbeUpgradeOperation {
                current_probe_version: current_probe_version.to_string(),
                operation_token: "operation-token-01".to_string(),
                target_probe_version: target_probe_version.to_string(),
            })),
        }),
        server_time_ms: 1_725_000_000_000,
    }
    .encode_to_vec()
}

struct NoopTransport;

impl RegistrationTransport for NoopTransport {
    fn post_protobuf(&mut self, _url: &str, _body: Vec<u8>) -> Result<Vec<u8>, RegistrationError> {
        panic!("missing config must fail before registration");
    }
}

impl ReportTransport for NoopTransport {
    fn post_protobuf_with_bearer(
        &mut self,
        _url: &str,
        _bearer_secret: &str,
        _body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        panic!("missing config must fail before reporting");
    }
}

impl ProbeTransport for NoopTransport {}

struct RecordingTransport {
    observed_body: Vec<u8>,
    observed_report_bodies: Vec<Vec<u8>>,
    observed_report_url: String,
    observed_url: String,
    report_response: Vec<u8>,
    response: Vec<u8>,
}

impl RegistrationTransport for RecordingTransport {
    fn post_protobuf(&mut self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, RegistrationError> {
        self.observed_url = url.to_string();
        self.observed_body = body;

        Ok(self.response.clone())
    }
}

impl ReportTransport for RecordingTransport {
    fn post_protobuf_with_bearer(
        &mut self,
        url: &str,
        _bearer_secret: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        self.observed_report_url = url.to_string();
        self.observed_report_bodies.push(body);

        Ok(self.report_response.clone())
    }
}

impl ProbeTransport for RecordingTransport {}

#[derive(Default)]
struct RecordingProbeTransport {
    observed_calls: Vec<ObservedBearerCall>,
    observed_bearer: String,
    observed_report_bodies: Vec<Vec<u8>>,
    observed_report_url: String,
    response: Vec<u8>,
    response_results: Vec<Result<Vec<u8>, ReportError>>,
    responses: Vec<Vec<u8>>,
}

struct ObservedBearerCall {
    body: Vec<u8>,
    url: String,
}

impl RegistrationTransport for RecordingProbeTransport {
    fn post_protobuf(&mut self, _url: &str, _body: Vec<u8>) -> Result<Vec<u8>, RegistrationError> {
        panic!("existing Probe Identity must not register");
    }
}

impl ReportTransport for RecordingProbeTransport {
    fn post_protobuf_with_bearer(
        &mut self,
        url: &str,
        bearer_secret: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        self.observed_report_url = url.to_string();
        self.observed_bearer = bearer_secret.to_string();
        self.observed_calls.push(ObservedBearerCall {
            body: body.clone(),
            url: url.to_string(),
        });

        if url.ends_with("/api/probe/report") {
            self.observed_report_bodies.push(body);
        }

        if !self.response_results.is_empty() {
            return self.response_results.remove(0);
        }

        if !self.responses.is_empty() {
            return Ok(self.responses.remove(0));
        }

        Ok(self.response.clone())
    }
}

impl ProbeTransport for RecordingProbeTransport {}

#[derive(Default)]
struct RecordingSleeper {
    observed_sleeps: Vec<Duration>,
}

impl ProbeRuntimeSleeper for RecordingSleeper {
    fn sleep(&mut self, duration: Duration) {
        self.observed_sleeps.push(duration);
    }
}
