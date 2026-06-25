use enoki_probe::protocol::enoki::v1::{
    CollectorCapabilities, DiskHealthCollectorCapability, DiskHealthCollectorCapabilityStatus,
    DiskHealthMetric, HostProfileSnapshot, MetricSample, OfficialCollectorCapabilities,
    ProbeConfigurationResponse, ProbeOperation, ProbeOperationAcknowledgement,
    ProbeOperationFailed, ProbeOperationStatus, ProbeRegistrationRequest, ProbeReportRequest,
    ProbeReportResponse, ProbeUpgradeOperation, Snapshot, probe_operation::Operation,
    probe_operation_status::Status, snapshot,
};
use prost::Message;

fn disk_health_capability(
    status: DiskHealthCollectorCapabilityStatus,
) -> DiskHealthCollectorCapability {
    DiskHealthCollectorCapability {
        status: status as i32,
        diagnostic: String::new(),
    }
}

#[test]
fn generated_rust_protocol_encodes_probe_registration() {
    let host_profile = HostProfileSnapshot {
        architecture: "x86_64".to_string(),
        cpu_base_frequency_mhz: 2_100,
        cpu_cache_l3_bytes: 36 * 1024 * 1024,
        cpu_count: 2,
        cpu_model: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz".to_string(),
        cpu_physical_count: 1,
        cpu_socket_count: 1,
        collector_capabilities: None,
        filesystems: Vec::new(),
        hostname: "managed-host-01".to_string(),
        kernel: "6.8.0".to_string(),
        memory_total_bytes: 2_147_483_648,
        network_interfaces: Vec::new(),
        os: "linux".to_string(),
        process_count: 123,
        probe_version: "0.1.0".to_string(),
        thread_count: 456,
    };
    let request = ProbeRegistrationRequest {
        enrollment_token: "enrollment-token".to_string(),
        probe_public_key_pem: "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n"
            .to_string(),
        snapshots: vec![Snapshot {
            collector_id: "official.host-profile".to_string(),
            snapshot_hash: "host-profile-hash".to_string(),
            payload: Some(snapshot::Payload::HostProfile(host_profile)),
        }],
    };

    let encoded = request.encode_to_vec();
    let decoded = ProbeRegistrationRequest::decode(encoded.as_slice())
        .expect("generated Probe registration should decode");

    assert_eq!(decoded.enrollment_token, "enrollment-token");
    assert!(decoded.probe_public_key_pem.contains("BEGIN PUBLIC KEY"));
    let host_profile = match decoded.snapshots[0].payload.as_ref() {
        Some(snapshot::Payload::HostProfile(host_profile)) => host_profile,
        None => panic!("Host Profile payload is missing"),
    };
    assert_eq!(host_profile.hostname, "managed-host-01");
    assert_eq!(
        host_profile.cpu_model,
        "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz"
    );
    assert_eq!(host_profile.process_count, 123);
    assert_eq!(host_profile.thread_count, 456);
}

#[test]
fn generated_rust_protocol_encodes_collector_capabilities_as_host_profile() {
    let host_profile = HostProfileSnapshot {
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                disk_health: Some(disk_health_capability(
                    DiskHealthCollectorCapabilityStatus::UnsupportedSmartData,
                )),
            }),
        }),
        hostname: "managed-host-01".to_string(),
        ..HostProfileSnapshot::default()
    };

    let decoded = HostProfileSnapshot::decode(host_profile.encode_to_vec().as_slice())
        .expect("generated HostProfileSnapshot should decode");

    let official = decoded
        .collector_capabilities
        .and_then(|capabilities| capabilities.official)
        .expect("official collector capabilities");
    assert_eq!(
        official
            .disk_health
            .expect("disk health capability")
            .status(),
        DiskHealthCollectorCapabilityStatus::UnsupportedSmartData
    );
}

#[test]
fn generated_rust_protocol_encodes_repeated_metric_samples() {
    let request = ProbeReportRequest {
        boot_id: "boot-01".to_string(),
        metrics: vec![
            MetricSample {
                collected_at_ms: 1_710_000_000_000,
                cpu_percent: Some(42.5),
                memory_used_bytes: Some(1_048_576),
                sequence: 7,
                ..MetricSample::default()
            },
            MetricSample {
                collected_at_ms: 1_710_000_005_000,
                cpu_percent: Some(51.25),
                memory_used_bytes: Some(2_097_152),
                sequence: 8,
                ..MetricSample::default()
            },
        ],
        operation_acknowledgements: Vec::new(),
        operation_statuses: Vec::new(),
        probe_configuration_error: None,
        probe_configuration_version: "config-v1".to_string(),
        probe_id: "probe-01".to_string(),
        sequence_end: 8,
        sequence_start: 7,
        snapshots: Vec::new(),
    };

    let encoded = request.encode_to_vec();
    let decoded = ProbeReportRequest::decode(encoded.as_slice())
        .expect("generated Probe report should decode");

    assert_eq!(decoded.metrics.len(), 2);
    assert_eq!(decoded.metrics[0].sequence, 7);
    assert_eq!(decoded.metrics[0].collected_at_ms, 1_710_000_000_000);
    assert_eq!(decoded.metrics[1].cpu_percent, Some(51.25));
}

#[test]
fn generated_rust_protocol_encodes_disk_health_metrics_and_capability() {
    let request = ProbeReportRequest {
        boot_id: "boot-01".to_string(),
        metrics: vec![MetricSample {
            collected_at_ms: 1_710_000_000_000,
            disk_health: vec![DiskHealthMetric {
                device_name: "/dev/sda".to_string(),
                model: "Samsung SSD 870 EVO 1TB".to_string(),
                passed: true,
                power_on_hours: Some(12_345),
                role: String::new(),
                serial_number: "S6PTEST".to_string(),
                temperature_celsius: Some(31.0),
                total_bytes: None,
                usage_mount_point: String::new(),
                used_bytes: None,
            }],
            sequence: 7,
            ..MetricSample::default()
        }],
        probe_configuration_version: "config-v1".to_string(),
        probe_id: "probe-01".to_string(),
        sequence_end: 7,
        sequence_start: 7,
        ..ProbeReportRequest::default()
    };
    let host_profile = HostProfileSnapshot {
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                disk_health: Some(disk_health_capability(
                    DiskHealthCollectorCapabilityStatus::Available,
                )),
            }),
        }),
        ..HostProfileSnapshot::default()
    };

    let decoded_request = ProbeReportRequest::decode(request.encode_to_vec().as_slice())
        .expect("generated Probe report should decode Disk Health");
    let decoded_host_profile = HostProfileSnapshot::decode(host_profile.encode_to_vec().as_slice())
        .expect("host_profile decodes");

    assert_eq!(
        decoded_request.metrics[0].disk_health[0].device_name,
        "/dev/sda"
    );
    assert_eq!(
        decoded_request.metrics[0].disk_health[0].power_on_hours,
        Some(12_345)
    );
    assert!(
        decoded_host_profile
            .collector_capabilities
            .and_then(|capabilities| capabilities.official)
            .and_then(|official| official.disk_health)
            .expect("disk health capability")
            .status()
            == DiskHealthCollectorCapabilityStatus::Available
    );
}

#[test]
fn generated_rust_protocol_encodes_probe_operation_delivery_and_status() {
    let response = ProbeReportResponse {
        accepted_sequence_end: 8,
        current_probe_configuration_version: "default-v1".to_string(),
        pending_operation: Some(ProbeOperation {
            id: "operation-01".to_string(),
            operation: Some(Operation::ProbeUpgrade(ProbeUpgradeOperation {
                current_probe_version: "0.1.0".to_string(),
                operation_token: "operation-token-01".to_string(),
                target_probe_version: "0.2.0".to_string(),
            })),
        }),
        requested_snapshot_collector_ids: Vec::new(),
        server_time_ms: 1_710_000_005_000,
    };

    let decoded_response = ProbeReportResponse::decode(response.encode_to_vec().as_slice())
        .expect("generated Probe report response should decode");
    let operation = decoded_response
        .pending_operation
        .expect("pending operation");
    assert_eq!(operation.id, "operation-01");
    assert!(matches!(
        operation.operation,
        Some(Operation::ProbeUpgrade(ProbeUpgradeOperation {
            operation_token,
            target_probe_version,
            ..
        })) if target_probe_version == "0.2.0" && operation_token == "operation-token-01"
    ));

    let request = ProbeReportRequest {
        boot_id: "boot-01".to_string(),
        metrics: Vec::new(),
        operation_acknowledgements: vec![ProbeOperationAcknowledgement {
            operation_id: "operation-01".to_string(),
        }],
        operation_statuses: vec![ProbeOperationStatus {
            operation_id: "operation-01".to_string(),
            status: Some(Status::Failed(ProbeOperationFailed {
                error_code: "unsupported_installation".to_string(),
                message: "systemd is unavailable".to_string(),
            })),
        }],
        probe_configuration_error: None,
        probe_configuration_version: "default-v1".to_string(),
        probe_id: "probe-01".to_string(),
        sequence_end: 1,
        sequence_start: 1,
        snapshots: Vec::new(),
    };

    let decoded_request = ProbeReportRequest::decode(request.encode_to_vec().as_slice())
        .expect("generated Probe report request should decode");
    assert_eq!(
        decoded_request.operation_acknowledgements[0].operation_id,
        "operation-01"
    );
    assert!(matches!(
        &decoded_request.operation_statuses[0].status,
        Some(Status::Failed(failed)) if failed.error_code == "unsupported_installation"
    ));
}

#[test]
fn generated_rust_protocol_encodes_all_probe_configuration_toggles() {
    let enabled_collector_ids = vec!["official.cpu".to_string(), "official.memory".to_string()];
    let configuration = ProbeConfigurationResponse {
        enabled_collector_ids: enabled_collector_ids.clone(),
        metrics_collection_interval_seconds: 5,
        version: "default-v1".to_string(),
    };

    let encoded = configuration.encode_to_vec();
    let decoded = ProbeConfigurationResponse::decode(encoded.as_slice())
        .expect("generated Probe Configuration should decode");

    assert_eq!(decoded.enabled_collector_ids, enabled_collector_ids);
}
