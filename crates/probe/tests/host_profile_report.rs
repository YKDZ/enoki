use enoki_probe::{
    host_profile::{collect_local_host_profile, host_profile_hash, stable_host_profile},
    protocol::enoki::v1::{
        CollectorCapabilities, DiskHealthCollectorCapability, DiskHealthCollectorCapabilityStatus,
        FilesystemProfile, HostProfileSnapshot, MetricSample, NetworkInterfaceProfile,
        OfficialCollectorCapabilities, ProbeConfigurationError, ProbeOperationRunning,
        ProbeOperationStatus, probe_operation_status::Status, snapshot,
    },
    report::{
        ObservationBatchInput, OperationReportProgress, SnapshotReplayInput, StartupReportInput,
        observation_batch_report, snapshot_replay_report, startup_report,
    },
};
use prost::Message;

#[test]
fn probe_report_startup_sends_full_host_profile_and_regular_reports_send_hash_only() {
    let host_profile = sample_host_profile();
    let expected_hash = host_profile_hash(&host_profile);

    let startup = startup_report(StartupReportInput {
        boot_id: "boot_01",
        enrollment_id: "",
        host_profile: host_profile.clone(),
        operation_progress: OperationReportProgress::default(),
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
    });

    assert_eq!(startup.snapshots[0].snapshot_hash, expected_hash);
    let startup_host_profile = match startup.snapshots[0].payload.as_ref() {
        Some(snapshot::Payload::HostProfile(host_profile)) => host_profile,
        None => panic!("startup report includes full Host Profile"),
    };
    assert_eq!(startup_host_profile.hostname, "managed-host-01");
    assert!(startup.metrics.is_empty());

    let regular = observation_batch_report(ObservationBatchInput {
        boot_id: "boot_01",
        host_profile: &host_profile,
        metrics: vec![MetricSample {
            cpu_percent: Some(12.5),
            collected_at_ms: 1_725_000_000_000,
            memory_used_bytes: Some(1024),
            sequence: 2,
            ..MetricSample::default()
        }],
        observation_window_failure: None,
        operation_progress: OperationReportProgress::default(),
        probe_configuration_error: None,
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
        sequence_end: 2,
        sequence_start: 2,
    });

    assert_eq!(regular.snapshots[0].snapshot_hash, expected_hash);
    assert!(regular.snapshots[0].payload.is_none());
    assert_eq!(regular.metrics.len(), 1);
}

#[test]
fn startup_report_is_sequence_one_metric_free_full_profile_with_deduplicated_local_operations() {
    let startup = startup_report(StartupReportInput {
        boot_id: "boot_01",
        enrollment_id: "enrollment-01",
        host_profile: sample_host_profile(),
        operation_progress: OperationReportProgress::from_statuses(vec![
            ProbeOperationStatus {
                operation_id: "operation-01".to_string(),
                status: Some(Status::Running(ProbeOperationRunning {})),
            },
            ProbeOperationStatus {
                operation_id: "operation-01".to_string(),
                status: Some(Status::Running(ProbeOperationRunning {})),
            },
        ]),
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
    });

    assert_eq!((startup.sequence_start, startup.sequence_end), (1, 1));
    assert!(startup.metrics.is_empty());
    assert_eq!(startup.snapshots.len(), 1);
    assert!(matches!(
        startup.snapshots[0].payload,
        Some(snapshot::Payload::HostProfile(_))
    ));
    assert_eq!(startup.operation_acknowledgements.len(), 1);
    assert_eq!(startup.operation_statuses.len(), 1);
    assert_eq!(
        startup.operation_acknowledgements[0].operation_id,
        "operation-01"
    );
    assert_eq!(startup.operation_statuses[0].operation_id, "operation-01");
}

#[test]
fn observation_batch_sends_host_profile_snapshot_hash_without_payload() {
    let host_profile = sample_host_profile();
    let expected_hash = host_profile_hash(&host_profile);

    let report = observation_batch_report(ObservationBatchInput {
        boot_id: "boot_01",
        host_profile: &host_profile,
        metrics: vec![MetricSample {
            cpu_percent: Some(12.5),
            collected_at_ms: 1_725_000_000_000,
            memory_used_bytes: Some(1024),
            sequence: 2,
            ..MetricSample::default()
        }],
        observation_window_failure: None,
        operation_progress: OperationReportProgress::default(),
        probe_configuration_error: None,
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
        sequence_end: 2,
        sequence_start: 2,
    });

    assert_eq!(report.snapshots.len(), 1);
    assert_eq!(report.snapshots[0].collector_id, "official.host-profile");
    assert_eq!(report.snapshots[0].snapshot_hash, expected_hash);
    assert!(report.snapshots[0].payload.is_none());
    assert_eq!(report.metrics.len(), 1);
}

#[test]
fn snapshot_replay_contains_only_the_hub_requested_full_snapshot() {
    let replay = snapshot_replay_report(SnapshotReplayInput {
        boot_id: "boot_01",
        host_profile: sample_host_profile(),
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
        sequence: 2,
    });

    assert_eq!((replay.sequence_start, replay.sequence_end), (2, 2));
    assert!(replay.metrics.is_empty());
    assert!(replay.operation_acknowledgements.is_empty());
    assert!(replay.operation_statuses.is_empty());
    assert!(replay.probe_configuration_error.is_none());
    assert!(matches!(
        replay.snapshots[0].payload,
        Some(snapshot::Payload::HostProfile(_))
    ));
}

#[test]
fn observation_batch_keeps_metrics_and_incremental_state_compact() {
    let host_profile = sample_host_profile();
    let observation = observation_batch_report(ObservationBatchInput {
        boot_id: "boot_01",
        host_profile: &host_profile,
        metrics: vec![MetricSample {
            collected_at_ms: 1_725_000_000_000,
            cpu_percent: Some(12.5),
            sequence: 2,
            ..MetricSample::default()
        }],
        observation_window_failure: None,
        operation_progress: OperationReportProgress::from_statuses(vec![
            ProbeOperationStatus {
                operation_id: "operation-01".to_string(),
                status: Some(Status::Running(ProbeOperationRunning {})),
            },
            ProbeOperationStatus {
                operation_id: "operation-01".to_string(),
                status: Some(Status::Running(ProbeOperationRunning {})),
            },
        ]),
        probe_configuration_error: Some(ProbeConfigurationError {
            error_code: "probe_configuration_fetch_failed".to_string(),
            failed_version: "global-2".to_string(),
            message: "temporary Hub failure".to_string(),
        }),
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
        sequence_end: 2,
        sequence_start: 2,
    });

    assert_eq!(
        (observation.sequence_start, observation.sequence_end),
        (2, 2)
    );
    assert_eq!(observation.metrics.len(), 1);
    assert!(observation.snapshots[0].payload.is_none());
    assert!(observation.probe_configuration_error.is_some());
    assert_eq!(observation.operation_acknowledgements.len(), 1);
    assert_eq!(observation.operation_statuses.len(), 1);
}

#[test]
fn recurring_observation_payload_is_materially_smaller_than_lifecycle_frames() {
    let host_profile = sample_host_profile();
    let startup = startup_report(StartupReportInput {
        boot_id: "boot_01",
        enrollment_id: "enrollment-01",
        host_profile: host_profile.clone(),
        operation_progress: OperationReportProgress::default(),
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
    });
    let replay = snapshot_replay_report(SnapshotReplayInput {
        boot_id: "boot_01",
        host_profile: host_profile.clone(),
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
        sequence: 3,
    });
    let observation = observation_batch_report(ObservationBatchInput {
        boot_id: "boot_01",
        host_profile: &host_profile,
        metrics: vec![MetricSample {
            collected_at_ms: 1_725_000_000_000,
            cpu_percent: Some(12.5),
            memory_used_bytes: Some(1024),
            sequence: 2,
            ..MetricSample::default()
        }],
        observation_window_failure: None,
        operation_progress: OperationReportProgress::default(),
        probe_configuration_error: None,
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
        sequence_end: 2,
        sequence_start: 2,
    });

    let observation_bytes = observation.encode_to_vec().len();
    assert!(observation.snapshots[0].payload.is_none());
    assert!(observation_bytes * 2 < startup.encode_to_vec().len());
    assert!(observation_bytes * 2 < replay.encode_to_vec().len());
}

#[test]
fn host_profile_hash_uses_stable_repeated_field_ordering() {
    let host_profile = sample_host_profile();
    let reordered = HostProfileSnapshot {
        filesystems: host_profile.filesystems.iter().cloned().rev().collect(),
        network_interfaces: host_profile
            .network_interfaces
            .iter()
            .cloned()
            .rev()
            .collect(),
        ..host_profile.clone()
    };

    assert_eq!(
        stable_host_profile(reordered.clone()).network_interfaces[0].addresses,
        vec!["10.0.0.10".to_string(), "2001:db8::10".to_string()],
    );
    assert_eq!(
        host_profile_hash(&host_profile),
        host_profile_hash(&reordered)
    );
}

#[test]
fn collector_capability_changes_are_host_profile_changes_not_metric_samples() {
    let available_host_profile = HostProfileSnapshot {
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                disk_health: Some(disk_health_capability(
                    DiskHealthCollectorCapabilityStatus::Available,
                )),
            }),
        }),
        ..sample_host_profile()
    };
    let unavailable_host_profile = HostProfileSnapshot {
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                disk_health: Some(disk_health_capability(
                    DiskHealthCollectorCapabilityStatus::UnsupportedSmartData,
                )),
            }),
        }),
        ..sample_host_profile()
    };

    assert_ne!(
        host_profile_hash(&available_host_profile),
        host_profile_hash(&unavailable_host_profile)
    );

    let report = startup_report(StartupReportInput {
        boot_id: "boot_01",
        enrollment_id: "",
        host_profile: unavailable_host_profile,
        operation_progress: OperationReportProgress::default(),
        probe_configuration_version: "default-v1",
        probe_id: "probe_01",
    });

    assert_eq!(
        report
            .snapshots
            .first()
            .and_then(|snapshot| snapshot.payload.as_ref())
            .and_then(|payload| match payload {
                snapshot::Payload::HostProfile(host_profile) => {
                    host_profile.collector_capabilities.as_ref()
                }
            })
            .and_then(|capabilities| capabilities.official.as_ref())
            .and_then(|official| official.disk_health.as_ref())
            .expect("disk health capability")
            .status(),
        DiskHealthCollectorCapabilityStatus::UnsupportedSmartData
    );
    assert!(report.metrics.is_empty());
}

#[test]
fn host_profile_hash_matches_the_cross_runtime_canonical_fixture() {
    let host_profile = HostProfileSnapshot {
        filesystems: vec![
            FilesystemProfile {
                available_bytes: 20_000,
                filesystem_type: "zfs".to_string(),
                mount_point: "/a".to_string(),
                total_bytes: 70_000,
            },
            FilesystemProfile {
                available_bytes: 30_000,
                filesystem_type: "ext4".to_string(),
                mount_point: "/B".to_string(),
                total_bytes: 80_000,
            },
            FilesystemProfile {
                available_bytes: 40_000,
                filesystem_type: "xfs".to_string(),
                mount_point: "/😀".to_string(),
                total_bytes: 90_000,
            },
            FilesystemProfile {
                available_bytes: 10_000,
                filesystem_type: "apfs".to_string(),
                mount_point: "/B".to_string(),
                total_bytes: 60_000,
            },
        ],
        hostname: "fixture-host".to_string(),
        network_interfaces: vec![
            NetworkInterfaceProfile {
                addresses: vec![
                    "fd00::2".to_string(),
                    "10.0.0.2".to_string(),
                    "10.0.0.2".to_string(),
                    "2001:db8::2".to_string(),
                ],
                name: "eth1".to_string(),
            },
            NetworkInterfaceProfile {
                addresses: vec!["fe80::1".to_string()],
                name: "Éth0".to_string(),
            },
            NetworkInterfaceProfile {
                addresses: vec!["192.0.2.10".to_string()],
                name: "Eth0".to_string(),
            },
            NetworkInterfaceProfile {
                addresses: vec!["203.0.113.10".to_string()],
                name: "😀0".to_string(),
            },
        ],
        ..sample_host_profile()
    };

    assert_eq!(
        host_profile_hash(&host_profile),
        "22843eb296c1643cd0a9b40706f3609fecbaec0ae0114a041923c9adaef07da3",
    );
}

#[test]
fn local_host_profile_snapshot_contains_host_capacity_and_probe_version() {
    let host_profile = collect_local_host_profile();

    assert_eq!(host_profile.probe_version, "dev");
    assert!(!host_profile.architecture.is_empty());
    assert!(host_profile.cpu_count >= 1);
    assert!(host_profile.memory_total_bytes > 0);
    assert!(host_profile.process_count >= 1);
    assert!(host_profile.thread_count >= host_profile.process_count);
    assert!(
        host_profile
            .network_interfaces
            .iter()
            .flat_map(|network_interface| &network_interface.addresses)
            .any(|address| !address.is_empty())
    );
    assert!(
        !host_profile
            .network_interfaces
            .iter()
            .any(|network_interface| network_interface.name == "lo")
    );
}

fn sample_host_profile() -> HostProfileSnapshot {
    HostProfileSnapshot {
        architecture: "x86_64".to_string(),
        cpu_base_frequency_mhz: 2_100,
        cpu_cache_l3_bytes: 36 * 1024 * 1024,
        cpu_count: 2,
        cpu_model: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz".to_string(),
        cpu_physical_count: 1,
        cpu_socket_count: 1,
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                disk_health: Some(disk_health_capability(
                    DiskHealthCollectorCapabilityStatus::Available,
                )),
            }),
        }),
        filesystems: vec![
            FilesystemProfile {
                available_bytes: 50_000,
                filesystem_type: "ext4".to_string(),
                mount_point: "/var".to_string(),
                total_bytes: 100_000,
            },
            FilesystemProfile {
                available_bytes: 500_000,
                filesystem_type: "ext4".to_string(),
                mount_point: "/".to_string(),
                total_bytes: 1_000_000,
            },
        ],
        hostname: "managed-host-01".to_string(),
        kernel: "6.8.0".to_string(),
        memory_total_bytes: 2_147_483_648,
        network_interfaces: vec![
            NetworkInterfaceProfile {
                addresses: vec!["2001:db8::10".to_string(), "10.0.0.10".to_string()],
                name: "eth0".to_string(),
            },
            NetworkInterfaceProfile {
                addresses: vec!["127.0.0.1".to_string()],
                name: "lo".to_string(),
            },
        ],
        os: "linux".to_string(),
        process_count: 123,
        probe_version: "0.1.0".to_string(),
        thread_count: 456,
    }
}

fn disk_health_capability(
    status: DiskHealthCollectorCapabilityStatus,
) -> DiskHealthCollectorCapability {
    DiskHealthCollectorCapability {
        status: status as i32,
        diagnostic: String::new(),
    }
}
