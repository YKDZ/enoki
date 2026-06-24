use enoki_probe::{
    host_profile::{collect_local_host_profile, host_profile_hash, stable_host_profile},
    protocol::enoki::v1::{
        CollectorAvailability, CollectorCapabilities, FilesystemProfile, HostProfileSnapshot,
        MetricSample, NetworkInterfaceProfile, OfficialCollectorCapabilities, snapshot,
    },
    report::{full_host_profile_report, regular_report, startup_report},
};

#[test]
fn probe_report_startup_sends_full_host_profile_and_regular_reports_send_hash_only() {
    let host_profile = sample_host_profile();
    let expected_hash = host_profile_hash(&host_profile);

    let startup = startup_report(
        "probe_01",
        "boot_01",
        1,
        "default-v1",
        host_profile.clone(),
        Vec::new(),
    );

    assert_eq!(startup.snapshots[0].snapshot_hash, expected_hash);
    let startup_host_profile = match startup.snapshots[0].payload.as_ref() {
        Some(snapshot::Payload::HostProfile(host_profile)) => host_profile,
        None => panic!("startup report includes full Host Profile"),
    };
    assert_eq!(startup_host_profile.hostname, "managed-host-01");
    assert!(startup.metrics.is_empty());

    let regular = regular_report(
        "probe_01",
        "boot_01",
        2,
        2,
        "default-v1",
        &host_profile,
        vec![MetricSample {
            cpu_percent: Some(12.5),
            collected_at_ms: 1_725_000_000_000,
            memory_used_bytes: Some(1024),
            sequence: 2,
            ..MetricSample::default()
        }],
    );

    assert_eq!(regular.snapshots[0].snapshot_hash, expected_hash);
    assert!(regular.snapshots[0].payload.is_none());
    assert_eq!(regular.metrics.len(), 1);
}

#[test]
fn regular_probe_report_sends_host_profile_snapshot_hash_without_payload() {
    let host_profile = sample_host_profile();
    let expected_hash = host_profile_hash(&host_profile);

    let report = regular_report(
        "probe_01",
        "boot_01",
        2,
        2,
        "default-v1",
        &host_profile,
        vec![MetricSample {
            cpu_percent: Some(12.5),
            collected_at_ms: 1_725_000_000_000,
            memory_used_bytes: Some(1024),
            sequence: 2,
            ..MetricSample::default()
        }],
    );

    assert_eq!(report.snapshots.len(), 1);
    assert_eq!(report.snapshots[0].collector_id, "official.host-profile");
    assert_eq!(report.snapshots[0].snapshot_hash, expected_hash);
    assert!(report.snapshots[0].payload.is_none());
    assert_eq!(report.metrics.len(), 1);
}

#[test]
fn full_host_profile_report_preserves_the_reported_sequence_range() {
    let host_profile = sample_host_profile();
    let report = full_host_profile_report(
        "probe_01",
        "boot_01",
        2,
        4,
        "default-v1",
        host_profile,
        vec![
            MetricSample {
                sequence: 2,
                ..MetricSample::default()
            },
            MetricSample {
                sequence: 3,
                ..MetricSample::default()
            },
            MetricSample {
                sequence: 4,
                ..MetricSample::default()
            },
        ],
    );

    assert_eq!(report.sequence_start, 2);
    assert_eq!(report.sequence_end, 4);
    assert_eq!(report.metrics.len(), 3);
    assert!(matches!(
        report.snapshots[0].payload,
        Some(snapshot::Payload::HostProfile(_))
    ));
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
                disk: Some(CollectorAvailability { available: true }),
                ..OfficialCollectorCapabilities::default()
            }),
        }),
        ..sample_host_profile()
    };
    let unavailable_host_profile = HostProfileSnapshot {
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                disk: Some(CollectorAvailability { available: false }),
                ..OfficialCollectorCapabilities::default()
            }),
        }),
        ..sample_host_profile()
    };

    assert_ne!(
        host_profile_hash(&available_host_profile),
        host_profile_hash(&unavailable_host_profile)
    );

    let report = startup_report(
        "probe_01",
        "boot_01",
        1,
        "default-v1",
        unavailable_host_profile,
        vec![MetricSample {
            collected_at_ms: 1_725_000_000_000,
            disks: Vec::new(),
            sequence: 1,
            ..MetricSample::default()
        }],
    );

    assert!(
        !report
            .snapshots
            .first()
            .and_then(|snapshot| snapshot.payload.as_ref())
            .and_then(|payload| match payload {
                snapshot::Payload::HostProfile(host_profile) => {
                    host_profile.collector_capabilities
                }
            })
            .and_then(|capabilities| capabilities.official)
            .and_then(|official| official.disk)
            .expect("disk capability")
            .available
    );
    assert_eq!(report.metrics.len(), 1);
    assert!(report.metrics[0].disks.is_empty());
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
        "928378a1b8ba549304607f856b21f97c6ddc06f43bcbebe86f3dc5f9cb44bb06",
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
                cpu: Some(CollectorAvailability { available: true }),
                disk: Some(CollectorAvailability { available: true }),
                load: Some(CollectorAvailability { available: true }),
                memory: Some(CollectorAvailability { available: true }),
                network: Some(CollectorAvailability { available: true }),
                uptime: Some(CollectorAvailability { available: true }),
                ..OfficialCollectorCapabilities::default()
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
