use enoki_probe::protocol::enoki::v1::{
    CollectorAvailability, CollectorCapabilities, DiskHealthMetric, Inventory, MetricSample,
    OfficialCollectorCapabilities, ProbeConfigurationResponse, ProbeOperation,
    ProbeOperationAcknowledgement, ProbeOperationFailed, ProbeOperationStatus,
    ProbeRegistrationRequest, ProbeReportRequest, ProbeReportResponse, ProbeUpgradeOperation,
    probe_operation::Operation, probe_operation_status::Status,
};
use prost::Message;

#[test]
fn generated_rust_protocol_encodes_probe_registration() {
    let request = ProbeRegistrationRequest {
        enrollment_token: "enrollment-token".to_string(),
        inventory: Some(Inventory {
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
        }),
        probe_public_key_pem: "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n"
            .to_string(),
    };

    let encoded = request.encode_to_vec();
    let decoded = ProbeRegistrationRequest::decode(encoded.as_slice())
        .expect("generated Probe registration should decode");

    assert_eq!(decoded.enrollment_token, "enrollment-token");
    assert!(decoded.probe_public_key_pem.contains("BEGIN PUBLIC KEY"));
    let inventory = decoded.inventory.expect("inventory");
    assert_eq!(inventory.hostname, "managed-host-01");
    assert_eq!(
        inventory.cpu_model,
        "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz"
    );
    assert_eq!(inventory.process_count, 123);
    assert_eq!(inventory.thread_count, 456);
}

#[test]
fn generated_rust_protocol_encodes_collector_capabilities_as_inventory() {
    let inventory = Inventory {
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                cpu: Some(CollectorAvailability { available: true }),
                disk: Some(CollectorAvailability { available: false }),
                memory: Some(CollectorAvailability { available: true }),
                network: Some(CollectorAvailability { available: true }),
                ..OfficialCollectorCapabilities::default()
            }),
        }),
        hostname: "managed-host-01".to_string(),
        ..Inventory::default()
    };

    let decoded = Inventory::decode(inventory.encode_to_vec().as_slice())
        .expect("generated Inventory should decode");

    let official = decoded
        .collector_capabilities
        .and_then(|capabilities| capabilities.official)
        .expect("official collector capabilities");
    assert!(official.cpu.expect("cpu capability").available);
    assert!(!official.disk.expect("disk capability").available);
}

#[test]
fn generated_rust_protocol_encodes_repeated_metric_samples() {
    let request = ProbeReportRequest {
        boot_id: "boot-01".to_string(),
        inventory_hash: "inventory-hash".to_string(),
        inventory: None,
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
    let inventory = Inventory {
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                disk_health: Some(CollectorAvailability { available: true }),
                ..OfficialCollectorCapabilities::default()
            }),
        }),
        ..Inventory::default()
    };

    let decoded_request = ProbeReportRequest::decode(request.encode_to_vec().as_slice())
        .expect("generated Probe report should decode Disk Health");
    let decoded_inventory =
        Inventory::decode(inventory.encode_to_vec().as_slice()).expect("inventory decodes");

    assert_eq!(
        decoded_request.metrics[0].disk_health[0].device_name,
        "/dev/sda"
    );
    assert_eq!(
        decoded_request.metrics[0].disk_health[0].power_on_hours,
        Some(12_345)
    );
    assert!(
        decoded_inventory
            .collector_capabilities
            .and_then(|capabilities| capabilities.official)
            .and_then(|official| official.disk_health)
            .expect("disk health capability")
            .available
    );
}

#[test]
fn generated_rust_protocol_encodes_probe_operation_delivery_and_status() {
    let response = ProbeReportResponse {
        accepted_sequence_end: 8,
        current_probe_configuration_version: "default-v1".to_string(),
        inventory_needed: false,
        pending_operation: Some(ProbeOperation {
            id: "operation-01".to_string(),
            operation: Some(Operation::ProbeUpgrade(ProbeUpgradeOperation {
                current_probe_version: "0.1.0".to_string(),
                operation_token: "operation-token-01".to_string(),
                target_probe_version: "0.2.0".to_string(),
            })),
        }),
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
        inventory: None,
        inventory_hash: "inventory-hash".to_string(),
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
