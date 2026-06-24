use std::{fs, path::Path, time::Duration};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use enoki_probe::{
    metrics::CollectorId,
    protocol::enoki::v1::{
        CollectorAvailability, CollectorCapabilities, Inventory, OfficialCollectorCapabilities,
        ProbeConfigurationRequest, ProbeConfigurationResponse, ProbeOperation,
        ProbeOperationStatus, ProbeRegistrationRequest, ProbeRegistrationResponse,
        ProbeReportRequest, ProbeReportResponse, ProbeUpgradeOperation, probe_operation::Operation,
        probe_operation_status::Status, snapshot,
    },
    registration::{RegistrationError, RegistrationTransport},
    runtime::{
        InventoryProvider, ProbeRequestAuth, ProbeRunError, ProbeRunInput, ProbeRuntimeSleeper,
        ProbeTransport, ReportError, ReportTransport, RunLoopControl,
        run_loop_control_from_environment, run_probe, run_probe_with_loop_control,
        run_probe_with_loop_control_and_inventory_provider,
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

fn write_secure_bootstrap_config(path: &Path, contents: String) {
    let contents =
        if contents.contains("probe_id = ") && !contents.contains("probe_private_key_pem = ") {
            format!("{contents}probe_private_key_pem = \"test-private-key\"\n")
        } else {
            contents
        };
    fs::write(path, contents).expect("write bootstrap config");

    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set permissions");
}

fn all_collector_ids() -> Vec<String> {
    CollectorId::all_official()
        .iter()
        .map(|collector_id| collector_id.as_config_id().to_string())
        .collect()
}

#[test]
fn probe_run_registers_from_enrollment_token_and_removes_token_from_config() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "enrollment_token = \"enk_enroll_secret\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "log_level = \"info\"",
            "",
        ]
        .join("\n"),
    );
    let response = ProbeRegistrationResponse {
        initial_configuration: Some(ProbeConfigurationResponse {
            enabled_collector_ids: all_collector_ids(),
            metrics_collection_interval_seconds: 5,
            version: "default-v1".to_string(),
        }),
        probe_id: "probe_01".to_string(),
        probe_secret: String::new(),
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
    assert!(bootstrap_config.contains("probe_configuration_version = \"default-v1\""));
    assert!(bootstrap_config.contains("metrics_collection_interval_seconds = 5"));
    assert!(bootstrap_config.contains("enabled_collector_ids = ["));
    assert!(bootstrap_config.contains("\"official.cpu\""));
    assert!(bootstrap_config.contains("\"official.disk-health\""));
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
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        response: ProbeReportResponse {
            accepted_sequence_end: 1,
            current_probe_configuration_version: "default-v1".to_string(),
            inventory_needed: false,
            pending_operation: None,
            requested_snapshot_collector_ids: Vec::new(),
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
    assert_eq!(transport.observed_probe_id, "probe_01");
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
fn probe_run_rejects_host_profile_as_a_configurable_collector() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "enabled_collector_ids = [\"official.host-profile\"]",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport::default();
    let mut sleeper = RecordingSleeper::default();

    let error = run_probe_with_loop_control(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(1),
        },
    )
    .expect_err("Host Profile is not a configurable Metrics collector");

    assert_eq!(
        error.to_string(),
        "invalid Probe bootstrap config: unknown Probe Configuration collector ID",
    );
    assert!(transport.observed_report_bodies.is_empty());
}

#[test]
fn probe_run_reports_local_probe_operation_status_on_startup() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let status_path = temp.path().join("probe-operation-status.toml");
    fs::write(
        &status_path,
        [
            "operation_id = \"42\"",
            "target_probe_version = \"0.2.0\"",
            "status = \"running\"",
            "",
        ]
        .join("\n"),
    )
    .expect("write operation status");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            &format!("operation_status_path = \"{}\"", status_path.display()),
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        response: ProbeReportResponse {
            accepted_sequence_end: 1,
            current_probe_configuration_version: "default-v1".to_string(),
            inventory_needed: false,
            pending_operation: None,
            requested_snapshot_collector_ids: Vec::new(),
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

    let request = ProbeReportRequest::decode(transport.observed_report_bodies[0].as_slice())
        .expect("report request decodes");
    assert_eq!(request.operation_acknowledgements.len(), 1);
    assert_eq!(request.operation_acknowledgements[0].operation_id, "42");
    assert_eq!(request.operation_statuses.len(), 1);
    assert_eq!(request.operation_statuses[0].operation_id, "42");
    assert!(matches!(
        request.operation_statuses[0].status,
        Some(Status::Running(_))
    ));
    assert!(request.inventory.is_some());
}

#[test]
fn probe_run_reports_post_replacement_upgrade_failure_status_on_startup() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let status_path = temp.path().join("probe-operation-status.toml");
    fs::write(
        &status_path,
        [
            "operation_id = \"42\"",
            "target_probe_version = \"0.2.0\"",
            "status = \"failed\"",
            "error_code = \"post_replacement_restart_failure\"",
            "message = \"Probe binary was replaced, but restart failed\"",
            "",
        ]
        .join("\n"),
    )
    .expect("write operation status");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            &format!("operation_status_path = \"{}\"", status_path.display()),
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        response: ProbeReportResponse {
            accepted_sequence_end: 1,
            current_probe_configuration_version: "default-v1".to_string(),
            inventory_needed: false,
            pending_operation: None,
            requested_snapshot_collector_ids: Vec::new(),
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

    let request = ProbeReportRequest::decode(transport.observed_report_bodies[0].as_slice())
        .expect("report request decodes");
    assert!(matches!(
        &request.operation_statuses[0],
        enoki_probe::protocol::enoki::v1::ProbeOperationStatus {
            operation_id,
            status: Some(Status::Failed(failed)),
        } if operation_id == "42"
            && failed.error_code == "post_replacement_restart_failure"
            && failed.message == "Probe binary was replaced, but restart failed"
    ));
}

#[test]
fn probe_run_sends_full_inventory_on_the_next_report_when_the_hub_requests_it() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        responses: vec![
            ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "default-v1".to_string(),
                inventory_needed: true,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec(),
            ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "default-v1".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
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
fn probe_run_sends_full_host_profile_snapshot_when_the_hub_requests_it() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        responses: vec![
            report_response_requesting_host_profile_snapshot(1),
            report_response(2, false),
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
    assert_eq!(follow_up.sequence_start, 2);
    assert_eq!(follow_up.sequence_end, 2);
    assert_eq!(follow_up.snapshots.len(), 1);
    assert_eq!(follow_up.snapshots[0].collector_id, "official.host-profile");
    assert!(!follow_up.snapshots[0].snapshot_hash.is_empty());
    assert!(matches!(
        follow_up.snapshots[0].payload,
        Some(enoki_probe::protocol::enoki::v1::snapshot::Payload::HostProfile(_))
    ));
    assert!(follow_up.metrics.is_empty());
}

#[test]
fn probe_run_loop_sends_full_inventory_when_collector_capability_changes() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"disabled-v1\"",
            "metrics_collection_interval_seconds = 1",
            "enabled_collector_ids = []",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        responses: vec![
            report_response_with_version(1, false, "disabled-v1"),
            report_response_with_version(2, false, "disabled-v1"),
            report_response_with_version(3, false, "disabled-v1"),
        ],
        ..RecordingProbeTransport::default()
    };
    let mut sleeper = RecordingSleeper::default();
    let mut inventory_provider = RecordingInventoryProvider {
        inventories: vec![
            inventory_with_disk_capability(true),
            inventory_with_disk_capability(false),
            inventory_with_disk_capability(false),
        ],
    };

    run_probe_with_loop_control_and_inventory_provider(
        ProbeRunInput {
            bootstrap_config_path,
        },
        &mut transport,
        &mut sleeper,
        RunLoopControl {
            max_reports: Some(3),
        },
        &mut inventory_provider,
    )
    .expect("run loop refreshes Inventory facts");

    let reports = transport
        .observed_report_bodies
        .iter()
        .map(|body| ProbeReportRequest::decode(body.as_slice()).expect("report decodes"))
        .collect::<Vec<_>>();
    assert!(reports[0].inventory.is_some());
    assert_eq!(
        reports[0]
            .inventory
            .as_ref()
            .and_then(|inventory| inventory.collector_capabilities.as_ref())
            .and_then(|capabilities| capabilities.official.as_ref())
            .and_then(|official| official.disk.as_ref())
            .map(|disk| disk.available),
        Some(true),
    );
    assert_eq!(reports[1].sequence_start, 2);
    assert_eq!(reports[1].sequence_end, 2);
    assert_eq!(
        reports[1]
            .inventory
            .as_ref()
            .and_then(|inventory| inventory.collector_capabilities.as_ref())
            .and_then(|capabilities| capabilities.official.as_ref())
            .and_then(|official| official.disk.as_ref())
            .map(|disk| disk.available),
        Some(false),
    );
    assert_ne!(reports[0].inventory_hash, reports[1].inventory_hash);
    assert_eq!(reports[2].inventory, None);
    assert_eq!(reports[2].inventory_hash, reports[1].inventory_hash);
    assert!(reports.iter().all(|report| report.metrics.is_empty()));
}

#[test]
fn probe_run_loop_reports_metrics_batches_on_the_configured_cadence() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    );
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

    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(7); 6]);
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
        vec![(1, 1), (2, 4), (5, 7)],
    );
    assert!(reports[0].inventory.is_some());
    assert_eq!(reports[1].boot_id, boot_id);
    assert_eq!(reports[2].boot_id, boot_id);
    assert!(reports[1].inventory.is_none());
    assert!(reports[2].inventory.is_none());
    assert!(reports[0].metrics.is_empty());
    assert_eq!(reports[1].metrics.len(), 3);
    assert_eq!(reports[1].metrics[0].sequence, 2);
    assert!(reports[1].metrics[0].collected_at_ms > 0);
    assert!(reports[1].metrics[0].cpu_percent.unwrap_or(-1.0) >= 0.0);
    assert!(reports[1].metrics[0].memory_used_bytes.unwrap_or(0) > 0);
    assert_eq!(reports[2].metrics.len(), 3);
    assert_eq!(reports[2].metrics[0].sequence, 5);
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
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"memory-only-v1\"",
            "metrics_collection_interval_seconds = 7",
            "enabled_collector_ids = [\"official.memory\"]",
            "",
        ]
        .join("\n"),
    );
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
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 2",
            "",
        ]
        .join("\n"),
    );
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
fn probe_run_loop_uses_a_derived_three_sample_reporting_window_at_one_second_collection() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 1",
            "",
        ]
        .join("\n"),
    );
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

    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(1); 3]);
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
fn probe_run_loop_keeps_reporting_empty_batches_when_metrics_are_disabled() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"disabled-v1\"",
            "enabled_collector_ids = []",
            "",
        ]
        .join("\n"),
    );
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

    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(15)]);
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
    assert!(reports[0].inventory.is_some());
    let startup_host_profile = reports[0]
        .snapshots
        .iter()
        .find(|snapshot| snapshot.collector_id == "official.host-profile")
        .expect("startup report includes Host Profile snapshot");
    assert!(matches!(
        startup_host_profile.payload,
        Some(snapshot::Payload::HostProfile(_))
    ));
    let regular_host_profile = reports[1]
        .snapshots
        .iter()
        .find(|snapshot| snapshot.collector_id == "official.host-profile")
        .expect("regular report includes Host Profile snapshot hash");
    assert!(regular_host_profile.payload.is_none());
}

#[test]
fn probe_run_fetches_and_applies_new_configuration_after_ack_version_changes() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        responses: vec![
            ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec(),
            ProbeConfigurationResponse {
                enabled_collector_ids: Vec::new(),
                metrics_collection_interval_seconds: 10,
                version: "global-2".to_string(),
            }
            .encode_to_vec(),
            ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
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
    assert_eq!(transport.observed_calls[0].auth_server_time_offset_ms, 0);
    assert!(transport.observed_calls[1].auth_server_time_offset_ms < -1_000_000_000);
    assert!(transport.observed_calls[2].auth_server_time_offset_ms < -1_000_000_000);
    let config_request =
        ProbeConfigurationRequest::decode(transport.observed_calls[1].body.as_slice())
            .expect("configuration request decodes");
    assert_eq!(config_request.probe_id, "probe_01");
    assert_eq!(config_request.current_version, "default-v1");
    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(30)]);

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
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        responses: vec![
            ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "global-bad".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec(),
            ProbeConfigurationResponse {
                enabled_collector_ids: all_collector_ids(),
                metrics_collection_interval_seconds: 201,
                version: "global-bad".to_string(),
            }
            .encode_to_vec(),
            ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "global-bad".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
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

    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(7); 3]);
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
fn probe_run_rejects_host_profile_in_fetched_probe_configuration() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        responses: vec![
            ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "global-host-profile".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec(),
            ProbeConfigurationResponse {
                enabled_collector_ids: vec!["official.host-profile".to_string()],
                metrics_collection_interval_seconds: 10,
                version: "global-host-profile".to_string(),
            }
            .encode_to_vec(),
            ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "global-host-profile".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
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
            .map(|error| error.failed_version.as_str()),
        Some("global-host-profile"),
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
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        response_results: vec![
            Ok(ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec()),
            Err(ReportError::Http("503 Service Unavailable".to_string())),
            Ok(ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
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
    assert_eq!(sleeper.observed_sleeps, vec![Duration::from_secs(7); 3]);
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
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 7",
            "",
        ]
        .join("\n"),
    );
    let mut transport = RecordingProbeTransport {
        responses: vec![
            ProbeReportResponse {
                accepted_sequence_end: 1,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
                server_time_ms: 1_725_000_000_000,
            }
            .encode_to_vec(),
            vec![0xff, 0xff, 0xff],
            ProbeReportResponse {
                accepted_sequence_end: 2,
                current_probe_configuration_version: "global-2".to_string(),
                inventory_needed: false,
                pending_operation: None,
                requested_snapshot_collector_ids: Vec::new(),
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
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 1",
            "",
        ]
        .join("\n"),
    );
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
        vec![
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(3),
        ],
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
        vec![(1, 1), (2, 4), (2, 4)],
    );
}

#[test]
fn probe_runtime_acknowledges_and_reports_probe_upgrade_operation_status() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    write_secure_bootstrap_config(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_configuration_version = \"default-v1\"",
            "metrics_collection_interval_seconds = 5",
            "enabled_collector_ids = []",
            "",
        ]
        .join("\n"),
    );
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
    assert_eq!(
        reports[1].operation_statuses[0].operation_id,
        "operation-01"
    );
    assert!(matches!(
        &reports[1].operation_statuses[0],
        ProbeOperationStatus {
            status: Some(Status::Failed(failed)),
            ..
        } if failed.error_code == "unsupported_installation"
    ));
    assert!(reports[2].operation_statuses.is_empty());
}

fn report_response(accepted_sequence_end: u64, inventory_needed: bool) -> Vec<u8> {
    report_response_with_version(accepted_sequence_end, inventory_needed, "default-v1")
}

fn report_response_requesting_host_profile_snapshot(accepted_sequence_end: u64) -> Vec<u8> {
    ProbeReportResponse {
        accepted_sequence_end,
        current_probe_configuration_version: "default-v1".to_string(),
        inventory_needed: false,
        pending_operation: None,
        requested_snapshot_collector_ids: vec!["official.host-profile".to_string()],
        server_time_ms: 1_725_000_000_000,
    }
    .encode_to_vec()
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
        requested_snapshot_collector_ids: Vec::new(),
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
        requested_snapshot_collector_ids: Vec::new(),
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
    fn post_protobuf_with_auth(
        &mut self,
        _url: &str,
        _auth: &ProbeRequestAuth<'_>,
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
    fn post_protobuf_with_auth(
        &mut self,
        url: &str,
        _auth: &ProbeRequestAuth<'_>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        self.observed_report_url = url.to_string();
        self.observed_report_bodies.push(body);

        Ok(self.report_response.clone())
    }
}

impl ProbeTransport for RecordingTransport {}

struct RecordingInventoryProvider {
    inventories: Vec<Inventory>,
}

impl InventoryProvider for RecordingInventoryProvider {
    fn collect_inventory(&mut self) -> Inventory {
        if self.inventories.len() > 1 {
            return self.inventories.remove(0);
        }

        self.inventories
            .first()
            .cloned()
            .expect("Inventory provider has a snapshot")
    }
}

fn inventory_with_disk_capability(available: bool) -> Inventory {
    Inventory {
        architecture: "x86_64".to_string(),
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                cpu: Some(CollectorAvailability { available: true }),
                disk: Some(CollectorAvailability { available }),
                load: Some(CollectorAvailability { available: true }),
                memory: Some(CollectorAvailability { available: true }),
                network: Some(CollectorAvailability { available: true }),
                uptime: Some(CollectorAvailability { available: true }),
                ..OfficialCollectorCapabilities::default()
            }),
        }),
        cpu_count: 2,
        hostname: "managed-host-01".to_string(),
        kernel: "6.8.0".to_string(),
        memory_total_bytes: 8_589_934_592,
        os: "linux".to_string(),
        probe_version: "test".to_string(),
        ..Inventory::default()
    }
}

#[derive(Default)]
struct RecordingProbeTransport {
    observed_calls: Vec<ObservedProbeCall>,
    observed_probe_id: String,
    observed_report_bodies: Vec<Vec<u8>>,
    observed_report_url: String,
    response: Vec<u8>,
    response_results: Vec<Result<Vec<u8>, ReportError>>,
    responses: Vec<Vec<u8>>,
}

struct ObservedProbeCall {
    auth_server_time_offset_ms: i64,
    body: Vec<u8>,
    url: String,
}

impl RegistrationTransport for RecordingProbeTransport {
    fn post_protobuf(&mut self, _url: &str, _body: Vec<u8>) -> Result<Vec<u8>, RegistrationError> {
        panic!("existing Probe Identity must not register");
    }
}

impl ReportTransport for RecordingProbeTransport {
    fn post_protobuf_with_auth(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ReportError> {
        self.observed_report_url = url.to_string();
        self.observed_probe_id = auth.probe_id.to_string();
        self.observed_calls.push(ObservedProbeCall {
            auth_server_time_offset_ms: auth.server_time_offset_ms,
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
