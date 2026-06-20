use enoki_probe::protocol::enoki::v1::{
    Inventory, MetricSample, ProbeConfigurationResponse, ProbeRegistrationRequest,
    ProbeReportRequest,
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
    };

    let encoded = request.encode_to_vec();
    let decoded = ProbeRegistrationRequest::decode(encoded.as_slice())
        .expect("generated Probe registration should decode");

    assert_eq!(decoded.enrollment_token, "enrollment-token");
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
fn generated_rust_protocol_encodes_all_probe_configuration_toggles() {
    let configuration = ProbeConfigurationResponse {
        collect_cpu: true,
        collect_disk: true,
        collect_load: true,
        collect_memory: true,
        collect_network: true,
        collect_uptime: true,
        metrics_collection_interval_seconds: 5,
        reporting_batch_interval_seconds: 15,
        version: "default-v1".to_string(),
    };

    let encoded = configuration.encode_to_vec();
    let decoded = ProbeConfigurationResponse::decode(encoded.as_slice())
        .expect("generated Probe Configuration should decode");

    assert!(decoded.collect_cpu);
    assert!(decoded.collect_load);
    assert!(decoded.collect_memory);
    assert!(decoded.collect_disk);
    assert!(decoded.collect_network);
    assert!(decoded.collect_uptime);
}
